//! mio/epoll, two listeners, finite connections, one request per connection.
mod sockets;
mod worker;

use crate::{
    Error, Result, config::Config, delivery::transport, filesystem::SecureDir, memory::LockedBytes,
    service::Service,
};
use mio::{Events, Interest, Poll, Token, Waker, unix::SourceFd};
use rustix::{
    fd::{AsRawFd, OwnedFd},
    net::{self, SocketFlags},
};
use sockets::Sockets;
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::TrySendError,
    },
    time::{Duration, Instant},
};
use worker::{Completion, Job};

struct Connection {
    socket: OwnedFd,
    admin: bool,
    created: Instant,
    inflight: bool,
    reply: Option<Completion>,
}

pub struct Runtime {
    poll: Poll,
    sockets: Sockets,
    connections: HashMap<Token, Connection>,
    accept_pending: [bool; 2],
    accept_after: Instant,
    next: usize,
    service: Arc<Mutex<Service>>,
    stop: Arc<AtomicBool>,
    config: Config,
}

impl Runtime {
    pub fn bind(config: Config, service: Service, stop: Arc<AtomicBool>) -> Result<Self> {
        config.validate()?;

        let (probe, _) = net::socketpair(
            net::AddressFamily::UNIX,
            net::SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )?;

        drop(crate::auth::peer_pidfd(&probe)?);

        drop(probe);

        let directory = SecureDir::open(&config.runtime, 0o755)?;

        let sockets = Sockets::bind(directory)?;

        let poll = Poll::new()?;

        for (fd, token) in [(&sockets.admin, Token(0)), (&sockets.deliver, Token(1))] {
            poll.registry()
                .register(&mut SourceFd(&fd.as_raw_fd()), token, Interest::READABLE)?;
        }

        Ok(Self {
            poll,
            sockets,
            connections: HashMap::new(),
            accept_pending: [false; 2],
            accept_after: Instant::now(),
            next: 3,
            service: Arc::new(Mutex::new(service)),
            stop,
            config,
        })
    }

    pub fn run(self) -> Result<()> {
        self.run_with_ready(|| Ok(()))
    }

    pub fn run_with_ready(mut self, ready: impl FnOnce() -> Result<()>) -> Result<()> {
        let waker = Arc::new(Waker::new(self.poll.registry(), Token(2))?);

        let budget = {
            Arc::clone(
                &self
                    .service
                    .lock()
                    .map_err(|_| Error::Protection)?
                    .store
                    .keys()
                    .budget,
            )
        };

        let pool = worker::Pool::start(
            self.config.limits.workers,
            self.config.limits.work_queue,
            self.config.limits.connections,
            waker,
            Arc::clone(&self.service),
            Arc::from(self.config.admin_uids.clone()),
            &budget,
        )?;

        ready()?;

        let mut events = Events::with_capacity(128);

        while !self.stop.load(Ordering::Acquire) {
            // mio readiness is edge-triggered. A bounded accept batch must be
            // resumed until EAGAIN, while still servicing existing connections.
            for listener in 0..2 {
                if self.accept_pending[listener] && Instant::now() >= self.accept_after {
                    let pending = self.accept(Token(listener))?;

                    self.accept_pending[listener] = pending;
                }
            }

            let timeout = if self.accept_pending.iter().any(|pending| *pending) {
                self.accept_after.saturating_duration_since(Instant::now())
            } else {
                Duration::from_secs(1)
            };

            match self.poll.poll(&mut events, Some(timeout)) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            }

            if pool.failed.load(Ordering::Acquire) {
                return Err(Error::Protection);
            }

            let mut close = Vec::new();

            for completion in pool.replies.try_iter() {
                if let Some(conn) = self.connections.get_mut(&completion.token) {
                    if completion.bytes.is_empty() {
                        close.push(completion.token);

                        continue;
                    }

                    // The bounded reply deadline begins after processing, not
                    // at accept. Kernel I/O cannot be safely cancelled mid-commit.
                    conn.created = Instant::now();

                    self.poll.registry().register(
                        &mut SourceFd(&conn.socket.as_raw_fd()),
                        completion.token,
                        Interest::WRITABLE,
                    )?;

                    conn.reply = Some(completion);
                }
            }

            for event in &events {
                let token = event.token();

                if token.0 <= 1 {
                    self.accept_pending[token.0] = true;

                    if Instant::now() >= self.accept_after {
                        self.accept_pending[token.0] = self.accept(token)?;
                    }

                    continue;
                }

                if token.0 == 2 {
                    continue;
                }

                let Some(conn) = self.connections.get_mut(&token) else {
                    continue;
                };

                if event.is_writable() {
                    if let Some(reply) = &conn.reply {
                        match transport::send(
                            &conn.socket,
                            &reply.bytes,
                            reply.secret.as_ref().map(|s| &s.fd),
                        ) {
                            Err(Error::Sys(rustix::io::Errno::AGAIN)) => {}
                            Ok(()) | Err(_) => close.push(token),
                        }
                    }
                } else if event.is_readable() && !conn.inflight {
                    let Ok(mut packet) = LockedBytes::new(secretsd_protocol::MAX_FRAME, &budget)
                    else {
                        close.push(token);

                        continue;
                    };

                    let received = match transport::receive(&conn.socket, packet.as_mut_slice()) {
                        Ok(message) if message.bytes > 0 => message,
                        Err(Error::Sys(rustix::io::Errno::AGAIN)) => continue,
                        _ => {
                            close.push(token);

                            continue;
                        }
                    };

                    let Ok(socket) = rustix::io::dup(&conn.socket) else {
                        close.push(token);

                        continue;
                    };

                    let length = received.bytes;

                    match pool.submit(Job {
                        token,
                        socket,
                        admin: conn.admin,
                        packet,
                        length,
                        received,
                    }) {
                        Ok(()) => {
                            self.poll
                                .registry()
                                .deregister(&mut SourceFd(&conn.socket.as_raw_fd()))?;

                            conn.inflight = true;
                        }
                        Err(TrySendError::Full(_)) => close.push(token),
                        Err(TrySendError::Disconnected(_)) => return Err(Error::Protection),
                    }
                }

                if (!conn.inflight || conn.reply.is_some())
                    && (event.is_error() || event.is_read_closed() || event.is_write_closed())
                {
                    close.push(token);
                }
            }

            let now = Instant::now();

            close.extend(self.connections.iter().filter_map(|(token, c)| {
                // Admitted jobs retain their bounded connection slot until
                // completion, including malformed frames and disconnected peers.
                ((!c.inflight || c.reply.is_some())
                    && now.duration_since(c.created) > Duration::from_secs(5))
                .then_some(*token)
            }));

            for token in close {
                if let Some(conn) = self.connections.remove(&token) {
                    let _ = self
                        .poll
                        .registry()
                        .deregister(&mut SourceFd(&conn.socket.as_raw_fd()));
                }
            }
        }

        Ok(())
    }

    fn accept(&mut self, token: Token) -> Result<bool> {
        let listener = if token.0 == 0 {
            &self.sockets.admin
        } else {
            &self.sockets.deliver
        };

        for _ in 0..16 {
            let socket =
                match net::accept_with(listener, SocketFlags::CLOEXEC | SocketFlags::NONBLOCK) {
                    Ok(socket) => socket,
                    Err(rustix::io::Errno::AGAIN) => return Ok(false),
                    Err(rustix::io::Errno::MFILE | rustix::io::Errno::NFILE) => {
                        // Keep the readiness edge pending without spinning or
                        // losing it. Existing clients can finish/expire and free
                        // descriptors before the bounded accept retry.
                        self.accept_after = Instant::now() + Duration::from_millis(100);

                        return Ok(true);
                    }
                    Err(rustix::io::Errno::INTR | rustix::io::Errno::CONNABORTED) => continue,
                    Err(e) => return Err(e.into()),
                };

            if self.connections.len() >= self.config.limits.connections {
                continue;
            }

            net::sockopt::set_socket_passcred(&socket, true)?;

            let token = Token(self.next);

            self.next = self.next.checked_add(1).ok_or(Error::Limit)?;

            self.poll.registry().register(
                &mut SourceFd(&socket.as_raw_fd()),
                token,
                Interest::READABLE,
            )?;

            self.connections.insert(
                token,
                Connection {
                    socket,
                    admin: token_is_admin(listener, &self.sockets),
                    created: Instant::now(),
                    inflight: false,
                    reply: None,
                },
            );
        }

        Ok(true)
    }
}

fn token_is_admin(listener: &OwnedFd, sockets: &Sockets) -> bool {
    listener.as_raw_fd() == sockets.admin.as_raw_fd()
}
