#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "Integration fixtures and assertions deliberately fail the test on error."
)]
#![cfg(target_os = "linux")]
mod support;

use apollo_secretsd::{
    client::Client,
    config::{Config, Limits},
    memory::MemoryBudget,
    runtime::Runtime,
};
use secretsd_protocol::*;
use std::{
    os::unix::fs::PermissionsExt,
    sync::{
        Arc, Barrier,
        atomic::{AtomicBool, Ordering},
    },
};
use support::*;

#[test]
fn one_hundred_socket_redeemers_have_exactly_one_winner_and_admin_stays_separate() {
    let state = tempfile::tempdir().unwrap();

    let sockets = tempfile::tempdir().unwrap();

    std::fs::set_permissions(sockets.path(), std::fs::Permissions::from_mode(0o755)).unwrap();

    let mut service = service(state.path(), &[52; 32]).unwrap();

    let peer = process();

    let namespace = service.namespace_create(peer.peer).unwrap();

    let (secret, _) = service
        .secret_put(
            namespace,
            None,
            "RACE",
            &input(b"atomic-race-canary"),
            peer.peer,
        )
        .unwrap();

    let (_, fd) = service
        .issue(
            grant(namespace, secret, RecipientId([11; 16]), 1),
            peer.peer,
        )
        .unwrap();

    let token = Arc::new(token(fd));

    let stop = Arc::new(AtomicBool::new(false));

    let config = Config {
        state: state.path().into(),
        runtime: sockets.path().into(),
        admin_uids: vec![peer.peer.uid],
        limits: Limits::default(),
    };

    let daemon = Runtime::bind(config, service, Arc::clone(&stop)).unwrap();

    let thread = std::thread::spawn(move || daemon.run());

    let path = sockets.path().join("deliver.sock");

    let server_uid = peer.peer.uid;

    let barrier = Arc::new(Barrier::new(100));

    let mut clients = Vec::new();

    for _ in 0..100 {
        let (path, token, barrier) = (path.clone(), Arc::clone(&token), Arc::clone(&barrier));

        clients.push(std::thread::spawn(move || {
            barrier.wait();

            let client = Client::connect(&path, server_uid, MemoryBudget::new(128 * 1024));

            match client.and_then(|client| client.redeem(token.key().unwrap())) {
                Ok(fd) => {
                    assert!(
                        read_fd(fd) == b"atomic-race-canary",
                        "winning payload must be exact"
                    );

                    true
                }
                Err(_) => false,
            }
        }));
    }

    let successes = clients
        .into_iter()
        .filter_map(|h| h.join().ok())
        .filter(|success| *success)
        .count();

    assert_eq!(
        successes, 1,
        "atomic one-shot scope admits exactly one process request"
    );

    let client = Client::connect(&path, server_uid, MemoryBudget::new(128 * 1024)).unwrap();

    assert!(
        client
            .admin(
                AdminRequest {
                    action: Some(admin_request::Action::NamespaceCreate(Empty {}))
                },
                None
            )
            .is_err(),
        "delivery socket cannot administer"
    );

    let client = Client::connect(
        &sockets.path().join("admin.sock"),
        server_uid,
        MemoryBudget::new(128 * 1024),
    )
    .unwrap();

    let (status, fd) = client
        .admin(
            AdminRequest {
                action: Some(admin_request::Action::Status(Empty {})),
            },
            None,
        )
        .unwrap();

    assert!(fd.is_none());

    assert_eq!(status.minimum_protocol, 1);

    assert!(!status.daemon_version.is_empty());

    stop.store(true, Ordering::Release);

    thread.join().unwrap().unwrap();
}
