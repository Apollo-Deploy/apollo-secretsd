#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "Integration fixtures and assertions deliberately fail the test on error."
)]
#![cfg(target_os = "linux")]
mod support;

use apollo_secretsd::Error;
use rusqlite::Connection;
use secretsd_protocol::*;
use support::*;

#[test]
fn copied_state_tampering_and_wrong_root_fail_before_delivery() {
    for attack in [
        "record-body",
        "record-key",
        "audit-body",
        "audit-truncate",
        "active-pointer",
    ] {
        let directory = tempfile::tempdir().unwrap();

        let key = [33; 32];

        let mut service = service(directory.path(), &key).unwrap();

        let peer = process();

        let namespace = service.namespace_create(peer.peer).unwrap();

        service
            .secret_put(
                namespace,
                None,
                "STRIPE_SECRET_KEY",
                &input(b"disk-canary"),
                peer.peer,
            )
            .unwrap();

        drop(service);

        let db = Connection::open(directory.path().join("state.sqlite3")).unwrap();

        match attack {
            "record-body" => db
                .execute(
                    "UPDATE records SET body=zeroblob(length(body)) WHERE kind=3",
                    [],
                )
                .unwrap(),
            "record-key" => db
                .execute(
                    "UPDATE records SET key=zeroblob(length(key)) WHERE kind=3",
                    [],
                )
                .unwrap(),
            "audit-body" => db
                .execute(
                    "UPDATE audit SET body=zeroblob(length(body)) WHERE sequence=1",
                    [],
                )
                .unwrap(),
            "audit-truncate" => db
                .execute(
                    "DELETE FROM audit WHERE sequence=(SELECT max(sequence) FROM audit)",
                    [],
                )
                .unwrap(),
            _ => db
                .execute(
                    "UPDATE records SET body=zeroblob(length(body)) WHERE kind=2",
                    [],
                )
                .unwrap(),
        };

        drop(db);

        assert!(
            matches!(
                support::service(directory.path(), &key),
                Err(Error::Integrity)
            ),
            "tampered copied state cannot become ready"
        );
    }

    let directory = tempfile::tempdir().unwrap();

    drop(service(directory.path(), &[44; 32]).unwrap());

    assert!(
        matches!(service(directory.path(), &[45; 32]), Err(Error::Integrity)),
        "wrong-root restore must fail closed"
    );
}

#[test]
fn live_audit_deletion_fails_both_tail_and_verify_even_outside_requested_page() {
    for delete in ["sequence=2", "sequence=(SELECT max(sequence) FROM audit)"] {
        for after in [0, 1000] {
            let directory = tempfile::tempdir().unwrap();

            let mut service = service(directory.path(), &[63; 32]).unwrap();

            let peer = process();

            service.namespace_create(peer.peer).unwrap();

            service.namespace_create(peer.peer).unwrap();

            let query = |verify| AdminRequest {
                action: Some(admin_request::Action::Audit(AuditQuery {
                    verify,
                    after,
                    limit: 1,
                })),
            };

            let healthy = service.admin(query(false), None, peer.peer).unwrap();

            assert_eq!(healthy.response.entries.len(), usize::from(after == 0));

            let db = Connection::open(directory.path().join("state.sqlite3")).unwrap();

            assert_eq!(
                db.execute(&format!("DELETE FROM audit WHERE {delete}"), [])
                    .unwrap(),
                1
            );

            for verify in [false, true] {
                assert!(
                    matches!(
                        service.admin(query(verify), None, peer.peer),
                        Err(Error::Integrity)
                    ),
                    "online gap/truncation must reject audit inspection, including an empty page"
                );
            }
        }
    }
}

#[test]
fn interrupted_rewrapping_resumes_without_reencrypting_payloads_or_resurrecting_grants() {
    let directory = tempfile::tempdir().unwrap();

    let key = [64; 32];

    let mut service = service(directory.path(), &key).unwrap();

    let peer = process();

    let namespace = service.namespace_create(peer.peer).unwrap();

    let (secret, _) = service
        .secret_put(
            namespace,
            None,
            "ROTATION",
            &input(b"rotation-canary-v1"),
            peer.peer,
        )
        .unwrap();

    service
        .secret_put(
            namespace,
            Some(secret),
            "ROTATION",
            &input(b"rotation-canary-v2"),
            peer.peer,
        )
        .unwrap();

    // Public admin protocol begins durable online rotation.
    service
        .admin(
            AdminRequest {
                action: Some(admin_request::Action::KeyRotate(Empty {})),
            },
            None,
            peer.peer,
        )
        .unwrap();

    service.maintenance().unwrap(); // one committed version batch
    drop(service);

    let mut recovered = support::service(directory.path(), &key).unwrap();

    for _ in 0..4 {
        recovered.maintenance().unwrap();
    }

    let result = recovered
        .admin(
            AdminRequest {
                action: Some(admin_request::Action::KeyStatus(Empty {})),
            },
            None,
            peer.peer,
        )
        .unwrap();

    assert!(
        result
            .response
            .capabilities
            .iter()
            .any(|v| v == "rotation-complete")
    );

    for (version, expected) in [(1, b"rotation-canary-v1"), (2, b"rotation-canary-v2")] {
        let mut issue = grant(namespace, secret, RecipientId([91; 16]), 1);

        issue.scope.as_mut().unwrap().version = version;

        let (_, sealed) = recovered.issue(issue, peer.peer).unwrap();

        let capability = token(sealed);

        let delivered = recovered.redeem(capability.key().unwrap(), &peer).unwrap();

        assert!(
            read_fd(delivered.fd) == expected,
            "every committed DEK remains recoverable"
        );
    }

    recovered
        .admin(
            AdminRequest {
                action: Some(admin_request::Action::Audit(AuditQuery {
                    verify: true,
                    after: 0,
                    limit: 1,
                })),
            },
            None,
            peer.peer,
        )
        .unwrap();
}

#[test]
fn required_audit_failure_rolls_back_the_security_mutation() {
    let directory = tempfile::tempdir().unwrap();

    let mut service = service(directory.path(), &[72; 32]).unwrap();

    let peer = process();

    let db = Connection::open(directory.path().join("state.sqlite3")).unwrap();

    db.execute_batch("CREATE TRIGGER audit_failure BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'injected audit unavailable'); END;").unwrap();

    assert!(service.namespace_create(peer.peer).is_err());

    let count: i64 = db
        .query_row("SELECT count(*) FROM records WHERE kind=1", [], |r| {
            r.get(0)
        })
        .unwrap();

    assert_eq!(
        count, 0,
        "no state change without its mandatory durable audit"
    );
}
