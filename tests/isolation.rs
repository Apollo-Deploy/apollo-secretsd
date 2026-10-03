#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "Integration fixtures and assertions deliberately fail the test on error."
)]
#![cfg(target_os = "linux")]
mod support;

use apollo_secretsd::Error;
use secretsd_protocol::*;
use support::*;

#[test]
fn identical_names_same_uid_exact_pinning_and_revocation() {
    let state = tempfile::tempdir().unwrap();

    let mut service = service(state.path(), &[17; 32]).unwrap();

    let peer = process();

    let a = service.namespace_create(peer.peer).unwrap();

    let b = service.namespace_create(peer.peer).unwrap();

    let (sa, _) = service
        .secret_put(
            a,
            None,
            "DATABASE_PASSWORD",
            &input(b"namespace-a-canary-v1"),
            peer.peer,
        )
        .unwrap();

    let (sb, _) = service
        .secret_put(
            b,
            None,
            "DATABASE_PASSWORD",
            &input(b"namespace-b-canary-v1"),
            peer.peer,
        )
        .unwrap();

    let recipient = RecipientId([3; 16]);

    let (_, sealed) = service
        .issue(grant(a, sa, recipient, 1), peer.peer)
        .unwrap();

    let old = token(sealed);

    service
        .secret_put(
            a,
            Some(sa),
            "DATABASE_PASSWORD",
            &input(b"namespace-a-canary-v2"),
            peer.peer,
        )
        .unwrap();

    let delivered = service.redeem(old.key().unwrap(), &peer).unwrap();

    assert!(
        read_fd(delivered.fd) == b"namespace-a-canary-v1",
        "pinned version must remain exact"
    );

    assert!(
        matches!(
            service.redeem(old.key().unwrap(), &peer),
            Err(Error::Denied)
        ),
        "consumed token must fail"
    );

    let (_, sealed) = service
        .issue(grant(b, sb, RecipientId([4; 16]), 1), peer.peer)
        .unwrap();

    let bt = token(sealed);

    assert!(
        read_fd(service.redeem(bt.key().unwrap(), &peer).unwrap().fd) == b"namespace-b-canary-v1",
        "namespace B has exact bytes"
    );

    let (_, sealed) = service
        .issue(grant(a, sa, recipient, 1), peer.peer)
        .unwrap();

    let stale = token(sealed);

    let (_, sealed) = service
        .issue(grant(a, sa, recipient, 2), peer.peer)
        .unwrap();

    let fresh = token(sealed);

    assert!(
        service.redeem(stale.key().unwrap(), &peer).is_err(),
        "older incarnation must fail"
    );

    assert!(
        read_fd(service.redeem(fresh.key().unwrap(), &peer).unwrap().fd)
            == b"namespace-a-canary-v2"
    );

    let (capability, sealed) = service
        .issue(grant(a, sa, recipient, 2), peer.peer)
        .unwrap();

    let revoked = token(sealed);

    service
        .revoke(
            Revoke {
                kind: RevocationKind::Capability as i32,
                id: capability.0.into(),
                next_generation: 0,
            },
            peer.peer,
        )
        .unwrap();

    assert!(service.redeem(revoked.key().unwrap(), &peer).is_err());

    let (_, sealed) = service
        .issue(grant(a, sa, recipient, 2), peer.peer)
        .unwrap();

    let deleted = token(sealed);

    service.namespace_delete(a, peer.peer).unwrap();

    assert!(service.redeem(deleted.key().unwrap(), &peer).is_err());

    assert!(
        service
            .issue(grant(b, sa, recipient, 2), peer.peer)
            .is_err(),
        "cross-namespace secret ID cannot be issued"
    );
}

#[test]
fn process_constraints_expiry_and_restart_fail_closed() {
    let state = tempfile::tempdir().unwrap();

    let key = [29; 32];

    let mut service = service(state.path(), &key).unwrap();

    let peer = process();

    let namespace = service.namespace_create(peer.peer).unwrap();

    let (secret, _) = service
        .secret_put(
            namespace,
            None,
            "TOKEN",
            &input(b"restart-canary"),
            peer.peer,
        )
        .unwrap();

    let request = grant(namespace, secret, RecipientId([6; 16]), 1);

    let mut wrong = request.clone();

    wrong.uid = wrong.uid.checked_add(1).unwrap();

    assert!(service.issue(wrong, peer.peer).is_err());

    let mut wrong = request.clone();

    wrong.gid = wrong.gid.checked_add(1).unwrap();

    assert!(service.issue(wrong, peer.peer).is_err());

    let mut wrong = request.clone();

    wrong.cgroup = "/wrong-cgroup".into();

    assert!(service.issue(wrong, peer.peer).is_err());

    let mut expiring = request.clone();

    expiring.ttl_ms = 1;

    let (_, sealed) = service.issue(expiring, peer.peer).unwrap();

    let expired = token(sealed);

    std::thread::sleep(std::time::Duration::from_millis(3));

    assert!(service.redeem(expired.key().unwrap(), &peer).is_err());

    let (_, sealed) = service.issue(request, peer.peer).unwrap();

    let old = token(sealed);

    drop(service);

    let mut recovered = support::service(state.path(), &key).unwrap();

    assert!(
        recovered.redeem(old.key().unwrap(), &peer).is_err(),
        "restart cannot resurrect capabilities"
    );
}
