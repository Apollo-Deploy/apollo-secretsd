#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "Integration fixtures and assertions deliberately fail the test on error."
)]
#![cfg(target_os = "linux")]
mod support;

use apollo_secretsd::{
    auth,
    client::Client,
    config::{Config, Limits},
    delivery::transport,
    memory::MemoryBudget,
    runtime::Runtime,
};
use prost::Message;
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    fd::{AsRawFd, OwnedFd},
    net::{self, AddressFamily, SocketAddrUnix, SocketFlags, SocketType},
};
use secretsd_protocol::*;
use std::{
    io::{Read, Write},
    os::{fd::FromRawFd, unix::process::CommandExt},
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

const CONTROL_FD: i32 = 3;

fn helper_command(test_name: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());

    command
        .args(["--ignored", "--exact", test_name, "--nocapture"])
        .env("RUST_TEST_THREADS", "1");

    command
}

fn inherit_as_control_fd(command: &mut Command, source: i32) {
    // SAFETY: The child callback performs only dup2/fcntl and returns an OS error;
    // it does not allocate or touch Rust state after fork.
    unsafe {
        command.pre_exec(move || {
            if source != CONTROL_FD && libc::dup2(source, CONTROL_FD) < 0 {
                return Err(std::io::Error::last_os_error());
            }

            if libc::fcntl(CONTROL_FD, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }

            Ok(())
        });
    }
}

fn receive_with_timeout(socket: &OwnedFd) -> transport::Received {
    let mut fds = [PollFd::new(socket, PollFlags::IN)];

    assert_eq!(
        poll(
            &mut fds,
            Some(&Timespec {
                tv_sec: 3,
                tv_nsec: 0,
            })
        )
        .unwrap(),
        1,
        "helper must send its packet"
    );

    let mut bytes = [0; 8];

    transport::receive(socket, &mut bytes).unwrap()
}

#[test]
fn connected_socket_handoff_is_rejected_by_per_packet_identity() {
    let (server, client) = net::socketpair(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )
    .unwrap();

    net::sockopt::set_socket_passcred(&server, true).unwrap();

    let mut command = helper_command("forked_child_sends_handoff_packet");

    command.env("APOLLO_CONTROL_FD", CONTROL_FD.to_string());

    inherit_as_control_fd(&mut command, client.as_raw_fd());

    let mut child = command.spawn().unwrap();

    drop(client);

    let received = receive_with_timeout(&server);

    assert_eq!(received.bytes, 1);

    let credentials = received.credentials.expect("SO_PASSCRED supplies sender");

    let original_peer = net::sockopt::socket_peercred(&server).unwrap();

    assert_ne!(
        credentials.pid, original_peer.pid,
        "fork-exec child is distinct from the socketpair's original creator"
    );

    assert!(
        auth::authenticate(&server, &credentials).is_err(),
        "a transferred connection cannot authenticate a different packet sender"
    );

    assert!(child.wait().unwrap().success());
}

#[test]
fn dead_original_socket_peer_cannot_authenticate_after_exit() {
    let directory = tempfile::tempdir().unwrap();

    let socket_path = directory.path().join("peer.sock");

    let listener = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();

    let mut command = helper_command("child_connects_waits_sends_then_exits");

    command.env("APOLLO_PEER_SOCKET", &socket_path);

    let mut child = command.spawn().unwrap();

    let (mut accepted, _) = listener.accept().unwrap();

    let accepted_fd: OwnedFd = accepted.try_clone().unwrap().into();

    net::sockopt::set_socket_passcred(&accepted_fd, true).unwrap();

    accepted.write_all(b"g").unwrap();

    let mut received = [0; 8];

    let size = accepted.read(&mut received).unwrap();

    assert_eq!(&received[..size], b"x");

    assert!(child.wait().unwrap().success());

    let original_pidfd = auth::peer_pidfd(&accepted_fd).unwrap();

    let mut ready = [PollFd::new(&original_pidfd, PollFlags::IN)];

    assert_eq!(
        poll(
            &mut ready,
            Some(&Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            })
        )
        .unwrap(),
        1,
        "pidfd from SO_PEERPIDFD remains tied to the exited original peer"
    );

    let creds = net::sockopt::socket_peercred(&accepted_fd).unwrap();

    assert!(
        auth::authenticate(&accepted_fd, &creds).is_err(),
        "the captured original-peer pidfd is dead after the peer exits"
    );
}

#[test]
fn admin_socket_handoff_denial_is_durably_audited() {
    let state = tempfile::tempdir().unwrap();

    let sockets = tempfile::tempdir().unwrap();

    let stop = Arc::new(AtomicBool::new(false));

    let uid = rustix::process::geteuid().as_raw();

    let config = Config {
        state: state.path().into(),
        runtime: sockets.path().into(),
        admin_uids: vec![uid],
        limits: Limits::default(),
    };

    let service = support::service(state.path(), &[72; 32]).unwrap();

    let daemon = Runtime::bind(config, service, Arc::clone(&stop)).unwrap();

    let thread = std::thread::spawn(move || daemon.run());

    let path = sockets.path().join("admin.sock");

    let client = net::socket_with(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )
    .unwrap();

    net::connect(&client, &SocketAddrUnix::new(&path).unwrap()).unwrap();

    let mut command = helper_command("forked_child_sends_handoff_packet");

    command
        .env("APOLLO_CONTROL_FD", CONTROL_FD.to_string())
        .env("APOLLO_ADMIN_HANDOFF", "1");

    inherit_as_control_fd(&mut command, client.as_raw_fd());

    let mut child = command.spawn().unwrap();

    drop(client);

    let child_result = child.wait().unwrap();

    let audit = Client::connect(&path, uid, MemoryBudget::new(128 * 1024))
        .unwrap()
        .admin(
            AdminRequest {
                action: Some(admin_request::Action::Audit(AuditQuery {
                    verify: true,
                    after: 0,
                    limit: 32,
                })),
            },
            None,
        );

    stop.store(true, Ordering::Release);

    thread.join().unwrap().unwrap();

    assert!(
        child_result.success(),
        "handoff request must be denied without a returned secret"
    );

    let (audit, fd) = audit.unwrap();

    assert!(fd.is_none());

    assert!(
        audit
            .entries
            .iter()
            .any(|entry| entry.name == "AdminReject"),
        "kernel peer authentication rejection must appear in the durable authenticated audit"
    );
}

#[test]
#[ignore = "subprocess helper invoked by peer identity integration tests"]
fn forked_child_sends_handoff_packet() {
    let Ok(raw) = std::env::var("APOLLO_CONTROL_FD") else {
        return;
    };

    let raw: i32 = raw.parse().unwrap();

    // SAFETY: This helper is exec'd with exactly this inherited control descriptor.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };

    if std::env::var_os("APOLLO_ADMIN_HANDOFF").is_some() {
        let request = AdminRequest {
            action: Some(admin_request::Action::Status(Empty {})),
        };

        let frame = encode_frame(
            OperationId([74; 16]),
            ADMIN_REQUEST,
            &request.encode_to_vec(),
        )
        .unwrap();

        transport::send(&fd, &frame, None).unwrap();

        let mut ready = [PollFd::new(&fd, PollFlags::IN)];

        assert_eq!(
            poll(
                &mut ready,
                Some(&Timespec {
                    tv_sec: 3,
                    tv_nsec: 0
                })
            )
            .unwrap(),
            1
        );

        let mut bytes = [0; 1024];

        let received = transport::receive(&fd, &mut bytes).unwrap();

        assert!(received.fd.is_none());

        let frame = Frame::decode(&bytes[..received.bytes]).unwrap();

        assert_eq!(frame.message_type, ADMIN_RESPONSE);

        let response = decode_canonical::<Response>(frame.payload).unwrap();

        assert_eq!(response.error, ErrorCode::Denied as i32);
    } else {
        rustix::io::write(&fd, b"x").unwrap();
    }
}

#[test]
#[ignore = "subprocess helper invoked by peer identity integration tests"]
fn child_connects_waits_sends_then_exits() {
    let Ok(path) = std::env::var("APOLLO_PEER_SOCKET") else {
        return;
    };

    let mut stream = std::os::unix::net::UnixStream::connect(path).unwrap();

    let mut gate = [0];

    stream.read_exact(&mut gate).unwrap();

    assert_eq!(gate, *b"g");

    stream.write_all(b"x").unwrap();
}
