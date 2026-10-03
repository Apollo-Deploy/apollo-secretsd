//! Process-death qualification for `SQLite`'s authenticated multi-record commit.
//! These tests use `SQLite` hooks only in this test module; production code has no fault points.
mod rotation;

use super::*;
use crate::{
    capability::Peer,
    config::Limits,
    crypto::{self, Keys, Scope},
    filesystem::SecureDir,
    memory::{LockedBytes, MemoryBudget},
    service::Service,
};
use rusqlite::Connection;
use secretsd_protocol::{NamespaceId, SecretId, SecretVersion};
use std::{
    os::unix::fs::PermissionsExt,
    os::unix::process::ExitStatusExt,
    path::Path,
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

const ROOT: [u8; 32] = [0x5a; 32];

const PAYLOAD_OLD: &[u8] = b"crash-qualification-old-payload";

const PAYLOAD_NEW: &[u8] = b"crash-qualification-new-payload";

const CHILD: &str = "storage::crash_tests::crash_child";

const ROTATION_CHILD: &str = "storage::crash_tests::rotation_crash_child";

fn service(path: &Path) -> crate::Result<Service> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;

    let budget = MemoryBudget::new(4 * 1024 * 1024);

    let root = LockedBytes::from_slice(&ROOT, &budget)?;

    let keys = Keys::new(root, budget)?;

    let directory = SecureDir::open(path, 0o700)?;

    let store = Store::open(directory, keys, 1_000_000)?;

    Service::new(store, Limits::default())
}

fn peer() -> Peer {
    let process = crate::auth::Process::capture(std::process::id()).unwrap();

    process.peer
}

fn input(value: &[u8]) -> LockedBytes {
    LockedBytes::from_slice(value, &MemoryBudget::new(4096)).unwrap()
}

fn install_faults(db: &Connection, stage: i64) {
    let audit_marker = if stage == 5 { 5 } else { 4 };

    db.execute_batch(&format!(
        "CREATE TABLE fault_marker(id INTEGER PRIMARY KEY);
         CREATE TRIGGER fault_after_version AFTER INSERT ON records
           WHEN NEW.kind=3 BEGIN INSERT INTO fault_marker VALUES(2); END;
         CREATE TRIGGER fault_before_secret BEFORE UPDATE ON records
           WHEN NEW.kind=2 BEGIN INSERT INTO fault_marker VALUES(3); END;
         CREATE TRIGGER fault_after_audit AFTER INSERT ON audit
           BEGIN INSERT INTO fault_marker VALUES({audit_marker}); END;"
    ))
    .unwrap();

    let armed = Arc::new(AtomicBool::new(false));

    let update_armed = Arc::clone(&armed);

    db.update_hook(Some(
        move |_: rusqlite::hooks::Action, _: &str, table: &str, rowid: i64| {
            if table == "fault_marker" && rowid == stage {
                if stage == 5 {
                    update_armed.store(true, Ordering::SeqCst);
                } else {
                    // SAFETY: the callback deliberately terminates only this qualification child
                    // process at the requested SQLite trigger boundary; no later code may run.
                    unsafe {
                        libc::kill(libc::getpid(), libc::SIGKILL);
                    }
                }
            }
        },
    ))
    .unwrap();

    db.commit_hook(Some(move || {
        if armed.load(Ordering::SeqCst) {
            // SAFETY: this commit hook runs in the isolated child and intentionally kills it
            // before SQLite can commit the transaction.
            unsafe {
                libc::kill(libc::getpid(), libc::SIGKILL);
            }
        }

        false
    }))
    .unwrap();
}

#[test]
fn sqlite_crash_boundaries_recover_whole_authenticated_secret_versions() {
    for (stage, committed) in [
        (1, false),
        (2, false),
        (3, false),
        (4, false),
        (5, false),
        (6, true),
    ] {
        let temp = tempfile::tempdir().unwrap();

        let mut broker = service(temp.path()).unwrap();

        let namespace = broker.namespace_create(peer()).unwrap();

        let (secret, version) = broker
            .secret_put(namespace, None, "CRASH-TEST", &input(PAYLOAD_OLD), peer())
            .unwrap();

        assert_eq!(version.0, 1);

        drop(broker);

        let status = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", CHILD, "--ignored", "--nocapture"])
            .env("APOLLO_CRASH_DIR", temp.path())
            .env("APOLLO_CRASH_NAMESPACE", hex(&namespace.0))
            .env("APOLLO_CRASH_SECRET", hex(&secret.0))
            .env("APOLLO_CRASH_STAGE", stage.to_string())
            .status()
            .unwrap();

        assert_eq!(
            status.signal(),
            Some(libc::SIGKILL),
            "stage {stage}: {status}"
        );

        let recovered = service(temp.path()).unwrap();

        recovered.store.verify_audit().unwrap();

        let key = secret_key(&namespace.0, &secret.0);

        let meta: SecretRecord = recovered.store.record(super::SECRET, &key).unwrap();

        assert_eq!(meta.active, if committed { 2 } else { 1 }, "stage {stage}");

        assert_eq!(meta.latest, if committed { 2 } else { 1 }, "stage {stage}");

        for (number, expected) in if committed {
            vec![(1, PAYLOAD_OLD), (2, PAYLOAD_NEW)]
        } else {
            vec![(1, PAYLOAD_OLD)]
        } {
            let plaintext = recovered
                .secret_material(
                    Scope {
                        namespace,
                        secret,
                        version: SecretVersion(number),
                    },
                    false,
                )
                .unwrap();

            assert_eq!(
                plaintext.as_slice(),
                expected,
                "stage {stage}, version {number}"
            );
        }

        let version_two = recovered
            .store
            .record::<crypto::EncryptedVersion>(VERSION, &version_key(&namespace.0, &secret.0, 2));

        if committed {
            assert!(version_two.is_ok(), "committed v2 record is present");
        } else {
            assert!(matches!(version_two, Err(crate::Error::NotFound)));
        }
    }
}

/// Spawned only by the parent test with --exact. Environment carries opaque identifiers and
/// a stage number, never key, auth, plaintext, or grant material.
#[test]
#[ignore]
fn crash_child() {
    let Ok(path) = std::env::var("APOLLO_CRASH_DIR") else {
        return;
    };

    let stage: i64 = std::env::var("APOLLO_CRASH_STAGE")
        .unwrap()
        .parse()
        .unwrap();

    let namespace = NamespaceId::try_from(
        unhex::<16>(&std::env::var("APOLLO_CRASH_NAMESPACE").unwrap()).as_slice(),
    )
    .unwrap();

    let secret =
        SecretId::try_from(unhex::<16>(&std::env::var("APOLLO_CRASH_SECRET").unwrap()).as_slice())
            .unwrap();

    let mut broker = service(Path::new(&path)).unwrap();

    if stage == 1 {
        // SAFETY: stage 1 is the intentional pretransaction process-death point in this child.
        unsafe {
            libc::kill(libc::getpid(), libc::SIGKILL);
        }
    }

    if stage <= 5 {
        install_faults(&broker.store.db, stage);
    }

    broker
        .secret_put(
            namespace,
            Some(secret),
            "CRASH-TEST",
            &input(PAYLOAD_NEW),
            peer(),
        )
        .unwrap();

    // Kill after SQLite's commit returned, before this helper could report success.
    if stage == 6 {
        // SAFETY: this child models death immediately after durable commit and before response.
        unsafe {
            libc::kill(libc::getpid(), libc::SIGKILL);
        }
    }

    panic!("requested crash point was not reached: {stage}");
}

#[test]
#[ignore]
fn rotation_crash_child() {
    let Ok(path) = std::env::var("APOLLO_CRASH_DIR") else {
        return;
    };

    let stage = std::env::var("APOLLO_ROTATION_STAGE").unwrap();

    let mut broker = service(Path::new(&path)).unwrap();

    let precommit = stage.ends_with("precommit");

    if precommit {
        let trigger = match stage.as_str() {
            "begin_precommit" => {
                "CREATE TRIGGER fault_rotation_begin AFTER INSERT ON records
                   WHEN NEW.kind=5 BEGIN INSERT INTO fault_marker VALUES(1); END;"
            }
            "batch_precommit" => {
                "CREATE TRIGGER fault_rotation_batch AFTER UPDATE ON records
                   WHEN NEW.kind=3 BEGIN INSERT INTO fault_marker VALUES(1); END;"
            }
            "retire_precommit" => {
                "CREATE TRIGGER fault_rotation_retire AFTER DELETE ON records
                   WHEN OLD.kind=5 BEGIN INSERT INTO fault_marker VALUES(1); END;"
            }
            _ => panic!("unexpected precommit stage {stage}"),
        };

        broker
            .store
            .db
            .execute_batch(&format!(
                "CREATE TABLE fault_marker(id INTEGER PRIMARY KEY); {trigger}"
            ))
            .unwrap();

        broker
            .store
            .db
            .update_hook(Some(
                move |_: rusqlite::hooks::Action, _: &str, table: &str, rowid: i64| {
                    if table == "fault_marker" && rowid == 1 {
                        // SAFETY: terminate this isolated child after a rotation change inside
                        // the transaction and before SQLite can commit it.
                        unsafe {
                            libc::kill(libc::getpid(), libc::SIGKILL);
                        }
                    }
                },
            ))
            .unwrap();
    }

    match stage.as_str() {
        "begin_precommit" | "begin_postcommit" => {
            broker.store.begin_rotation(peer().uid, peer().pid).unwrap();
        }
        "batch_precommit" | "batch_postcommit" => {
            let finished = broker.store.rotate_batch(1).unwrap();

            assert!(!finished, "first bounded batch must leave rotation pending");
        }
        "retire_precommit" | "retire_postcommit" => {
            for _ in 0..8 {
                if broker.store.rotate_batch(1).unwrap() {
                    break;
                }
            }

            assert!(!broker.store.rotation_pending(), "retirement must commit");
        }
        _ => panic!("unexpected rotation stage {stage}"),
    }

    // SAFETY: postcommit cases model process death after the operation returned successfully.
    unsafe {
        libc::kill(libc::getpid(), libc::SIGKILL);
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex<const N: usize>(s: &str) -> [u8; N] {
    assert_eq!(s.len(), N * 2);

    let mut out = [0; N];

    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }

    out
}
