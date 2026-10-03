#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "Integration fixtures and assertions deliberately fail the test on error."
)]
#![cfg(target_os = "linux")]
use apollo_secretsd::{auth, delivery::transport};
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    fd::{AsRawFd, OwnedFd},
    net::{self, AddressFamily, SocketFlags, SocketType},
};
use std::{
    io::Write,
    os::{fd::FromRawFd, unix::process::CommandExt},
    process::Command,
};

const SOCKET_FD: i32 = 3;

const RELEASE_FD: i32 = 4;

fn helper_command(test_name: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());

    command
        .args(["--ignored", "--exact", test_name, "--nocapture"])
        .env("RUST_TEST_THREADS", "1");

    command
}

fn inherit_one_fd(command: &mut Command, source: i32, target: i32) {
    let source = duplicate_for_exec(source);

    // SAFETY: The callback only performs dup2/fcntl on already-open descriptors.
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(source.as_raw_fd(), target) < 0 {
                return Err(std::io::Error::last_os_error());
            }

            if libc::fcntl(target, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }

            Ok(())
        });
    }
}

fn inherit_two_fds(command: &mut Command, socket: i32, release: i32) {
    let socket = duplicate_for_exec(socket);

    let release = duplicate_for_exec(release);

    // SAFETY: The callback only performs dup2/fcntl on already-open descriptors.
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(socket.as_raw_fd(), SOCKET_FD) < 0
                || libc::dup2(release.as_raw_fd(), RELEASE_FD) < 0
            {
                return Err(std::io::Error::last_os_error());
            }

            if libc::fcntl(SOCKET_FD, libc::F_SETFD, 0) < 0
                || libc::fcntl(RELEASE_FD, libc::F_SETFD, 0) < 0
            {
                return Err(std::io::Error::last_os_error());
            }

            Ok(())
        });
    }
}

fn duplicate_for_exec(source: i32) -> OwnedFd {
    // Keep pre_exec sources away from the child descriptor numbers so dup2
    // ordering cannot clobber another source descriptor.
    // SAFETY: fcntl duplicates this live borrowed descriptor and takes no pointer.
    let duplicate = unsafe { libc::fcntl(source, libc::F_DUPFD_CLOEXEC, 10) };

    assert!(duplicate >= 0, "duplicate inherited descriptor");

    // SAFETY: F_DUPFD_CLOEXEC returned this newly-owned descriptor.
    unsafe { OwnedFd::from_raw_fd(duplicate) }
}

fn receive_with_timeout(socket: &OwnedFd) -> (transport::Received, [u8; 32]) {
    let mut fds = [PollFd::new(socket, PollFlags::IN)];

    assert_eq!(
        poll(
            &mut fds,
            Some(&Timespec {
                tv_sec: 5,
                tv_nsec: 0,
            })
        )
        .unwrap(),
        1,
        "child must send its handoff packet"
    );

    let mut bytes = [0; 32];

    let received = transport::receive(socket, &mut bytes).unwrap();

    (received, bytes)
}

fn assert_rootful_private_pid_namespace() {
    // SAFETY: geteuid takes no arguments and returns the current effective UID.
    let uid = unsafe { libc::geteuid() };

    assert_eq!(uid, 0, "must run as container root");

    assert_eq!(
        std::env::var("APOLLO_ALLOW_PID_REUSE_QUALIFICATION").as_deref(),
        Ok("1"),
        "only run in an explicitly designated disposable privileged container"
    );

    let current_namespace = std::fs::read_link("/proc/self/ns/pid").unwrap();

    let init_namespace = std::fs::read_link("/proc/1/ns/pid").unwrap();

    assert_eq!(
        current_namespace, init_namespace,
        "qualification process and PID 1 must share the private container PID namespace"
    );

    let sysctl = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/proc/sys/kernel/ns_last_pid");

    assert!(
        sysctl.is_ok(),
        "disposable namespace must expose writable ns_last_pid: {sysctl:?}"
    );
}

#[test]
#[ignore = "requires isolated rootful Podman --privileged and writable private ns_last_pid"]
fn controlled_numeric_pid_reuse_does_not_authenticate_original_socket_peer() {
    assert_rootful_private_pid_namespace();

    let directory = tempfile::tempdir().unwrap();

    let socket_path = directory.path().join("peer.sock");

    let listener = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();

    let (original_control, original_release) = net::socketpair(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )
    .unwrap();

    let mut original_command = helper_command("pid_reuse_original_connects_and_hands_off");

    original_command
        .env("APOLLO_PID_REUSE_SOCKET", &socket_path)
        .env("APOLLO_CONTROL_FD", SOCKET_FD.to_string());

    inherit_one_fd(
        &mut original_command,
        original_release.as_raw_fd(),
        SOCKET_FD,
    );

    let mut original = original_command.spawn().unwrap();

    drop(original_release);

    let (accepted_stream, _) = listener.accept().unwrap();

    let server: OwnedFd = accepted_stream.try_clone().unwrap().into();

    net::sockopt::set_socket_passcred(&server, true).unwrap();

    let (handoff, handoff_bytes) = receive_with_timeout(&original_control);

    assert_eq!(handoff.bytes, b"connected".len());

    assert_eq!(&handoff_bytes[..handoff.bytes], b"connected");

    let initial_peer = net::sockopt::socket_peercred(&server).unwrap();

    assert_eq!(
        initial_peer.pid.as_raw_nonzero().get() as u32,
        original.id(),
        "SO_PEERCRED records the process that created the connection"
    );

    let client = handoff
        .fd
        .expect("original process transfers its connected socket");

    rustix::io::write(&original_control, b"x").unwrap();

    assert_eq!(
        original.wait().unwrap().code(),
        Some(0),
        "original peer exits"
    );

    let original_pid = original.id();

    let sysctl_path = "/proc/sys/kernel/ns_last_pid";

    let reset_value = original_pid.checked_sub(1).expect("valid reused PID");

    let mut sysctl = std::fs::OpenOptions::new()
        .write(true)
        .open(sysctl_path)
        .expect("private namespace ns_last_pid is writable");

    writeln!(sysctl, "{reset_value}").unwrap();

    drop(sysctl);

    let (replacement_control, replacement_release) = net::socketpair(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )
    .unwrap();

    let mut replacement_command = helper_command("pid_reuse_replacement_sends_on_old_socket");

    replacement_command.env("APOLLO_CONTROL_FD", RELEASE_FD.to_string());

    inherit_two_fds(
        &mut replacement_command,
        client.as_raw_fd(),
        replacement_release.as_raw_fd(),
    );

    let mut replacement = replacement_command.spawn().unwrap();

    drop(replacement_release);

    assert_eq!(
        replacement.id(),
        original_pid,
        "the kernel must allocate the exact numeric PID just vacated by the original"
    );

    let (message, message_bytes) = receive_with_timeout(&server);

    assert_eq!(message.bytes, b"replacement".len());

    assert_eq!(&message_bytes[..message.bytes], b"replacement");

    let sent_credentials = message
        .credentials
        .expect("SO_PASSCRED supplies kernel credentials for replacement packet");

    let peer_credentials = net::sockopt::socket_peercred(&server).unwrap();

    assert_eq!(
        peer_credentials.pid.as_raw_nonzero().get() as u32,
        initial_peer.pid.as_raw_nonzero().get() as u32,
        "SO_PEERCRED remains bound to the original numeric identity"
    );

    assert_eq!(
        peer_credentials.pid.as_raw_nonzero().get() as u32,
        replacement.id(),
        "SO_PEERCRED numeric PID equals the live replacement PID"
    );

    assert_eq!(
        peer_credentials.uid.as_raw(),
        initial_peer.uid.as_raw(),
        "SO_PEERCRED UID remains the original connection UID"
    );

    assert_eq!(
        peer_credentials.gid.as_raw(),
        initial_peer.gid.as_raw(),
        "SO_PEERCRED GID remains the original connection GID"
    );

    assert_eq!(
        peer_credentials.uid.as_raw(),
        sent_credentials.uid.as_raw(),
        "SO_PEERCRED UID matches the replacement packet credentials"
    );

    assert_eq!(
        peer_credentials.gid.as_raw(),
        sent_credentials.gid.as_raw(),
        "SO_PEERCRED GID matches the replacement packet credentials"
    );

    assert_eq!(
        sent_credentials.pid.as_raw_nonzero().get() as u32,
        replacement.id(),
        "SCM_CREDENTIALS contains the replacement's real live PID"
    );

    let live_replacement = auth::Process::capture(replacement.id()).unwrap();

    assert!(
        live_replacement.alive().unwrap(),
        "replacement remains live while gated"
    );

    let pinned_original = auth::peer_pidfd(&server).unwrap();

    let mut original_ready = [PollFd::new(&pinned_original, PollFlags::IN)];

    assert_eq!(
        poll(
            &mut original_ready,
            Some(&Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            })
        )
        .unwrap(),
        1,
        "SO_PEERPIDFD remains readable for the exited original incarnation"
    );

    assert!(
        auth::authenticate(&server, &sent_credentials).is_err(),
        "matching numeric PID/UID/GID cannot authenticate the dead original peer incarnation"
    );

    eprintln!(
        "controlled reuse verified: PID {} -> {}, UID {}, GID {}; SO_PEERPIDFD is dead and authenticate denied",
        original_pid,
        replacement.id(),
        sent_credentials.uid.as_raw(),
        sent_credentials.gid.as_raw()
    );

    rustix::io::write(&replacement_control, b"x").unwrap();

    assert!(replacement.wait().unwrap().success());
}

#[test]
#[ignore = "helper subprocess for controlled PID reuse qualification"]
fn pid_reuse_original_connects_and_hands_off() {
    let Ok(path) = std::env::var("APOLLO_PID_REUSE_SOCKET") else {
        return;
    };

    let raw: i32 = std::env::var("APOLLO_CONTROL_FD").unwrap().parse().unwrap();

    // SAFETY: This helper is exec'd with exactly this inherited control descriptor.
    let control = unsafe { OwnedFd::from_raw_fd(raw) };

    let stream = std::os::unix::net::UnixStream::connect(path).unwrap();

    let client: OwnedFd = stream.try_clone().unwrap().into();

    transport::send(&control, b"connected", Some(&client)).unwrap();

    let mut release = [0; 1];

    rustix::io::read(&control, &mut release).unwrap();

    assert_eq!(release, *b"x");
}

#[test]
#[ignore = "helper subprocess for controlled PID reuse qualification"]
fn pid_reuse_replacement_sends_on_old_socket() {
    let raw: i32 = std::env::var("APOLLO_CONTROL_FD").unwrap().parse().unwrap();

    // SAFETY: This helper is exec'd with exactly these inherited descriptors.
    let socket = unsafe { OwnedFd::from_raw_fd(SOCKET_FD) };

    // SAFETY: The inherited release descriptor is distinct and owned by this helper.
    let release = unsafe { OwnedFd::from_raw_fd(raw) };

    rustix::io::write(&socket, b"replacement").unwrap();

    let mut gate = [0; 1];

    rustix::io::read(&release, &mut gate).unwrap();

    assert_eq!(gate, *b"x");
}
