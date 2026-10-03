//! Fixed workers return bounded replies; no peer data is formatted or logged.
use crate::{
    Error, Result, auth,
    delivery::{SealedSecret, transport},
    memory::{LockedBytes, MemoryBudget, ProtectedThread},
    service::Service,
    storage::*,
};
use mio::{Token, Waker};
use prost::Message;
use rustix::fd::OwnedFd;
use secretsd_protocol::*;
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender},
    },
    time::{Duration, Instant},
};

pub(super) struct Job {
    pub token: Token,
    pub socket: OwnedFd,
    pub admin: bool,
    pub packet: LockedBytes,
    pub length: usize,
    pub received: transport::Received,
}

pub(super) struct Completion {
    pub token: Token,
    pub bytes: Vec<u8>,
    pub secret: Option<SealedSecret>,
}

impl Drop for Completion {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.bytes);
    }
}

pub(super) struct Pool {
    jobs: Option<SyncSender<Job>>,
    pub replies: Receiver<Completion>,
    threads: Vec<ProtectedThread<()>>,
    stopping: Arc<AtomicBool>,
    pub failed: Arc<AtomicBool>,
}

impl Pool {
    pub(super) fn start(
        count: usize,
        queue: usize,
        connections: usize,
        waker: Arc<Waker>,
        service: Arc<Mutex<Service>>,
        admin_uids: Arc<[u32]>,
        budget: &Arc<MemoryBudget>,
    ) -> Result<Self> {
        let (sender, jobs) = mpsc::sync_channel(queue);

        let (complete, replies) = mpsc::sync_channel(connections);

        let receiver = Arc::new(Mutex::new(jobs));

        let mut pool = Self {
            jobs: Some(sender),
            replies,
            threads: Vec::with_capacity(count),
            stopping: Arc::new(AtomicBool::new(false)),
            failed: Arc::new(AtomicBool::new(false)),
        };

        let (ready, acknowledgements) = mpsc::sync_channel(count);

        for index in 0..count {
            let (receiver, complete, waker, service, admin_uids) = (
                Arc::clone(&receiver),
                complete.clone(),
                Arc::clone(&waker),
                Arc::clone(&service),
                Arc::clone(&admin_uids),
            );

            let (stopping, failed, ready) = (
                Arc::clone(&pool.stopping),
                Arc::clone(&pool.failed),
                ready.clone(),
            );

            pool.threads.push(ProtectedThread::spawn(budget, move || {
                if ready.send(()).is_err() {
                    return;
                }

                let mut maintenance = Instant::now();

                while !stopping.load(Ordering::Acquire) {
                    // Schedule maintenance even while the work queue stays busy.
                    if index == 0 && maintenance.elapsed() >= Duration::from_millis(250) {
                        if service
                            .lock()
                            .map_err(|_| Error::Protection)
                            .and_then(|mut service| service.maintenance())
                            .is_err()
                        {
                            failed.store(true, Ordering::Release);

                            let _ = waker.wake();

                            break;
                        }

                        maintenance = Instant::now();
                    }

                    let job = match receiver.lock() {
                        Ok(rx) => rx.recv_timeout(Duration::from_millis(250)),
                        Err(_) => break,
                    };

                    let job = match job {
                        Ok(job) => job,
                        Err(mpsc::RecvTimeoutError::Timeout) => {
                            continue;
                        }
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    };

                    let token = job.token;

                    // Every admitted job completes, even when its frame cannot
                    // carry a valid response ID. Empty bytes request socket close.
                    let completion =
                        execute(job, &service, &admin_uids).unwrap_or_else(|_| Completion {
                            token,
                            bytes: Vec::new(),
                            secret: None,
                        });

                    // Each admitted job retains its connection slot, so the
                    // connection-sized channel can hold every outstanding reply.
                    // An invariant/channel failure must not orphan a live job.
                    if complete.try_send(completion).is_err() || waker.wake().is_err() {
                        failed.store(true, Ordering::Release);

                        let _ = waker.wake();

                        break;
                    }
                }
            })?);
        }

        drop(ready);

        for _ in 0..count {
            acknowledgements.recv().map_err(|_| Error::Protection)?;
        }

        Ok(pool)
    }

    #[expect(
        clippy::expect_used,
        reason = "The sender exists for every live Pool; only exclusive Drop takes it."
    )]
    pub(super) fn submit(&self, job: Job) -> std::result::Result<(), mpsc::TrySendError<Job>> {
        self.jobs
            .as_ref()
            .expect("live pool owns sender")
            .try_send(job)
    }
}

impl Drop for Pool {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Release);

        self.jobs.take();

        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}

fn execute(mut job: Job, service: &Mutex<Service>, admin_uids: &[u32]) -> Result<Completion> {
    let frame = Frame::decode(&job.packet.as_slice()[..job.length])?;

    let token = job.token;

    let request_id = frame.request_id;

    let result = (|| {
        let credentials = job.received.credentials.as_ref().ok_or(Error::Denied)?;

        let process = match auth::authenticate(&job.socket, credentials) {
            Ok(process) => process,
            Err(error) => {
                service
                    .lock()
                    .map_err(|_| Error::Protection)?
                    .store
                    .commit(
                        AuditEvent::new(
                            if job.admin {
                                EventKind::AdminReject
                            } else {
                                EventKind::CapabilityReject
                            },
                            &[],
                            &[],
                            credentials.uid.as_raw(),
                            credentials.pid.as_raw_nonzero().get() as u32,
                        ),
                        &[],
                        None,
                    )?;

                return Err(error);
            }
        };

        let mut service = service.lock().map_err(|_| Error::Protection)?;

        if job.admin {
            if !admin_uids.contains(&process.peer.uid) {
                service.store.commit(
                    AuditEvent::new(
                        EventKind::AdminReject,
                        &[],
                        &[],
                        process.peer.uid,
                        process.peer.pid,
                    ),
                    &[],
                    None,
                )?;

                return Err(Error::Denied);
            }

            if frame.message_type != ADMIN_REQUEST {
                return Err(Error::Invalid);
            }

            let request = decode_canonical::<AdminRequest>(frame.payload)?;

            service.admin(request, job.received.fd.take(), process.peer)
        } else {
            if job.received.fd.is_some() {
                return Err(Error::Invalid);
            }

            let redeem = Redeem::decode(&frame)?;

            let sealed = service.redeem(redeem.token(), &process)?;

            Ok(crate::service::Reply {
                response: Response {
                    fd_length: sealed.length as u64,
                    ..Response::default()
                },
                secret: Some(sealed),
            })
        }
    })();

    let (response, secret) = match result {
        Ok(reply) => (reply.response, reply.secret),
        Err(error) => (
            Response {
                error: error.code() as i32,
                ..Response::default()
            },
            None,
        ),
    };

    let kind = if job.admin {
        ADMIN_RESPONSE
    } else {
        DELIVERY_RESPONSE
    };

    let payload = zeroize::Zeroizing::new(response.encode_to_vec());

    let bytes = encode_frame(request_id, kind, &payload)?;

    Ok(Completion {
        token,
        bytes,
        secret,
    })
}
