#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "Integration fixtures and assertions deliberately fail the test on error."
)]
#![cfg(target_os = "linux")]
mod support;

use apollo_secretsd::{
    Error,
    client::Client,
    config::{Config, Limits},
    memory::MemoryBudget,
    runtime::Runtime,
};
use secretsd_protocol::*;
use std::{
    os::unix::fs::PermissionsExt,
    process::{Command, Stdio},
    sync::{
        Arc, Barrier,
        atomic::{AtomicBool, Ordering},
    },
};
use support::*;

#[test]
fn concurrent_namespace_tokens_deliver_only_their_exact_payloads() {
    const PER_NAMESPACE: usize = 8;

    let state = tempfile::tempdir().unwrap();

    let sockets = tempfile::tempdir().unwrap();

    std::fs::set_permissions(sockets.path(), std::fs::Permissions::from_mode(0o755)).unwrap();

    let peer = process();

    let mut service = service(state.path(), &[83; 32]).unwrap();

    let namespace_a = service.namespace_create(peer.peer).unwrap();

    let namespace_b = service.namespace_create(peer.peer).unwrap();

    let (secret_a, _) = service
        .secret_put(
            namespace_a,
            None,
            "DATABASE_PASSWORD",
            &input(b"namespace-A-authorized-payload"),
            peer.peer,
        )
        .unwrap();

    let (secret_b, _) = service
        .secret_put(
            namespace_b,
            None,
            "DATABASE_PASSWORD",
            &input(b"namespace-B-authorized-payload"),
            peer.peer,
        )
        .unwrap();

    // Tokens are issued independently from each namespace. Redeem's public
    // protocol carries only the token; expected payloads below bind each token
    // to its authorized namespace and version.
    let mut calls = Vec::new();

    for index in 0..PER_NAMESPACE {
        for (namespace, secret, payload) in [
            (
                namespace_a,
                secret_a,
                b"namespace-A-authorized-payload".as_slice(),
            ),
            (
                namespace_b,
                secret_b,
                b"namespace-B-authorized-payload".as_slice(),
            ),
        ] {
            let (_, sealed) = service
                .issue(
                    grant(namespace, secret, RecipientId([index as u8 + 1; 16]), 1),
                    peer.peer,
                )
                .unwrap();

            calls.push((Arc::new(token(sealed)), payload.to_vec()));
        }
    }

    let stop = Arc::new(AtomicBool::new(false));

    let config = Config {
        state: state.path().into(),
        runtime: sockets.path().into(),
        admin_uids: vec![peer.peer.uid],
        limits: Limits::default(),
    };

    let daemon = Runtime::bind(config, service, Arc::clone(&stop)).unwrap();

    let daemon_thread = std::thread::spawn(move || daemon.run());

    let path = sockets.path().join("deliver.sock");

    let barrier = Arc::new(Barrier::new(calls.len()));

    let mut clients = Vec::new();

    for (token, expected) in calls {
        let (path, barrier) = (path.clone(), Arc::clone(&barrier));

        let server_uid = peer.peer.uid;

        clients.push(std::thread::spawn(move || {
            barrier.wait();

            let client = Client::connect(&path, server_uid, MemoryBudget::new(128 * 1024))
                .expect("connect to delivery socket");

            let fd = client
                .redeem(token.key().unwrap())
                .expect("redeem issued token");

            assert_eq!(
                read_fd(fd),
                expected,
                "token must return its own namespace payload"
            );
        }));
    }

    for client in clients {
        client.join().unwrap();
    }

    stop.store(true, Ordering::Release);

    daemon_thread.join().unwrap().unwrap();
}

#[test]
fn capability_bound_to_another_live_pid_is_denied_over_public_client() {
    let state = tempfile::tempdir().unwrap();

    let sockets = tempfile::tempdir().unwrap();

    std::fs::set_permissions(sockets.path(), std::fs::Permissions::from_mode(0o755)).unwrap();

    let peer = process();

    let mut service = service(state.path(), &[84; 32]).unwrap();

    let namespace = service.namespace_create(peer.peer).unwrap();

    let (secret, _) = service
        .secret_put(
            namespace,
            None,
            "PID_BOUND",
            &input(b"pid-bound-payload"),
            peer.peer,
        )
        .unwrap();

    let mut other_process = Command::new("sleep")
        .arg("30")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start a second live process");

    let mut request = grant(namespace, secret, RecipientId([99; 16]), 1);

    request.pid = other_process.id();

    let (_, sealed) = service.issue(request, peer.peer).unwrap();

    let token = token(sealed);

    let stop = Arc::new(AtomicBool::new(false));

    let daemon = Runtime::bind(
        Config {
            state: state.path().into(),
            runtime: sockets.path().into(),
            admin_uids: vec![peer.peer.uid],
            limits: Limits::default(),
        },
        service,
        Arc::clone(&stop),
    )
    .unwrap();

    let daemon_thread = std::thread::spawn(move || daemon.run());

    let client = Client::connect(
        &sockets.path().join("deliver.sock"),
        peer.peer.uid,
        MemoryBudget::new(128 * 1024),
    )
    .unwrap();

    assert!(matches!(
        client.redeem(token.key().unwrap()),
        Err(Error::Denied)
    ));

    let _ = other_process.kill();

    let _ = other_process.wait();

    stop.store(true, Ordering::Release);

    daemon_thread.join().unwrap().unwrap();
}
