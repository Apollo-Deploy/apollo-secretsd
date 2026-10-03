#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "Integration fixtures and assertions deliberately fail the test on error."
)]
#![cfg(target_os = "linux")]
mod support;

use apollo_secretsd::Error;
use rusqlite::{Connection, params};
use secretsd_protocol::*;
use support::*;

#[test]
fn valid_old_active_pointer_and_deleted_record_are_detected_online_and_after_restart() {
    for delete in [false, true] {
        let directory = tempfile::tempdir().unwrap();

        let key = [91; 32];

        let mut broker = service(directory.path(), &key).unwrap();

        let peer = process();

        let ns = broker.namespace_create(peer.peer).unwrap();

        let (secret, _) = broker
            .secret_put(ns, None, "REPLAY", &input(b"old"), peer.peer)
            .unwrap();

        let db = Connection::open(directory.path().join("state.sqlite3")).unwrap();

        let (body, tag): (Vec<u8>, Vec<u8>) = db
            .query_row("SELECT body,mac FROM records WHERE kind=2", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();

        broker
            .secret_put(ns, Some(secret), "REPLAY", &input(b"new"), peer.peer)
            .unwrap();

        if delete {
            db.execute("DELETE FROM records WHERE kind=2", []).unwrap();
        } else {
            db.execute(
                "UPDATE records SET body=?1,mac=?2 WHERE kind=2",
                params![body, tag],
            )
            .unwrap();
        }

        assert!(
            matches!(
                broker.issue(grant(ns, secret, RecipientId([98; 16]), 1), peer.peer),
                Err(Error::Integrity)
            ),
            "a valid old MAC is not current authorization"
        );

        drop(db);

        drop(broker);

        assert!(
            matches!(service(directory.path(), &key), Err(Error::Integrity)),
            "the authenticated audit transition detects removed and replayed records"
        );
    }
}

#[test]
fn replayed_recipient_generation_cannot_restore_revoked_authority() {
    let directory = tempfile::tempdir().unwrap();

    let key = [92; 32];

    let mut broker = service(directory.path(), &key).unwrap();

    let peer = process();

    let ns = broker.namespace_create(peer.peer).unwrap();

    let (secret, _) = broker
        .secret_put(ns, None, "GEN", &input(b"generation"), peer.peer)
        .unwrap();

    let recipient = RecipientId([99; 16]);

    let (_, fd) = broker
        .issue(grant(ns, secret, recipient, 1), peer.peer)
        .unwrap();

    let token = token(fd);

    let db = Connection::open(directory.path().join("state.sqlite3")).unwrap();

    let (body, tag): (Vec<u8>, Vec<u8>) = db
        .query_row("SELECT body,mac FROM records WHERE kind=4", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();

    broker
        .admin(
            AdminRequest {
                action: Some(admin_request::Action::Revoke(Revoke {
                    kind: RevocationKind::Recipient as i32,
                    id: recipient.0.into(),
                    next_generation: 2,
                })),
            },
            None,
            peer.peer,
        )
        .unwrap();

    db.execute(
        "UPDATE records SET body=?1,mac=?2 WHERE kind=4",
        params![body, tag],
    )
    .unwrap();

    assert!(broker.redeem(token.key().unwrap(), &peer).is_err());

    assert!(
        broker
            .issue(grant(ns, secret, recipient, 1), peer.peer)
            .is_err()
    );
}
