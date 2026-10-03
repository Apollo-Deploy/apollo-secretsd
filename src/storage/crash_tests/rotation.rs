//! KEK rotation process-death matrix and authenticated recovery assertions.
use super::*;

#[test]
fn keystore_rotation_sigkill_matrix_recovers_and_resumes() {
    for stage in [
        "begin_precommit",
        "begin_postcommit",
        "batch_precommit",
        "batch_postcommit",
        "retire_precommit",
        "retire_postcommit",
    ] {
        let temp = tempfile::tempdir().unwrap();

        let mut broker = service(temp.path()).unwrap();

        let namespace = broker.namespace_create(peer()).unwrap();

        let (secret, _) = broker
            .secret_put(
                namespace,
                None,
                "ROTATION-CRASH",
                &input(PAYLOAD_OLD),
                peer(),
            )
            .unwrap();

        broker
            .secret_put(
                namespace,
                Some(secret),
                "ROTATION-CRASH",
                &input(PAYLOAD_NEW),
                peer(),
            )
            .unwrap();

        let old_kek = broker.store.active_kek().unwrap().0;

        if stage.starts_with("batch_") || stage.starts_with("retire_") {
            broker.store.begin_rotation(peer().uid, peer().pid).unwrap();
        }

        drop(broker);

        let status = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", ROTATION_CHILD, "--ignored", "--nocapture"])
            .env("APOLLO_CRASH_DIR", temp.path())
            .env("APOLLO_ROTATION_STAGE", stage)
            .env("APOLLO_CRASH_NAMESPACE", hex(&namespace.0))
            .env("APOLLO_CRASH_SECRET", hex(&secret.0))
            .status()
            .unwrap();

        assert_eq!(status.signal(), Some(libc::SIGKILL), "{stage}: {status}");

        let mut recovered = service(temp.path()).unwrap();

        recovered.store.verify_audit().unwrap();

        let should_be_pending = !matches!(stage, "begin_precommit" | "retire_postcommit");

        assert_eq!(
            recovered.store.rotation_pending(),
            should_be_pending,
            "{stage}"
        );

        assert_rotation_status(&mut recovered, should_be_pending);

        assert_versions_decrypt(&recovered, namespace, secret);

        let active_kek = recovered.store.active_kek().unwrap().0;

        for version in [1, 2] {
            let encrypted: crypto::EncryptedVersion = recovered
                .store
                .record(VERSION, &version_key(&namespace.0, &secret.0, version))
                .unwrap();

            let expected_kek: &[u8] = match stage {
                "batch_postcommit" if version == 1 => &active_kek,
                "retire_precommit" | "retire_postcommit" => &active_kek,
                _ => &old_kek,
            };

            assert_eq!(encrypted.kek_id, expected_kek, "{stage}, v{version}");
        }

        let old_key_record = recovered.store.record::<KeyRecord>(KEK, &old_kek);

        assert_eq!(
            old_key_record.is_ok(),
            stage != "retire_postcommit",
            "old KEK retirement at {stage}"
        );

        // Test-only triggers persist in SQLite schema; remove them before real resume work.
        recovered
            .store
            .db
            .execute_batch(
                "DROP TRIGGER IF EXISTS fault_rotation_begin;
             DROP TRIGGER IF EXISTS fault_rotation_batch;
             DROP TRIGGER IF EXISTS fault_rotation_retire;
             DROP TABLE IF EXISTS fault_marker;",
            )
            .unwrap();

        for _ in 0..8 {
            if recovered.store.rotate_batch(1).unwrap() {
                break;
            }
        }

        assert!(!recovered.store.rotation_pending(), "{stage}");

        assert_rotation_status(&mut recovered, false);

        assert_versions_decrypt(&recovered, namespace, secret);

        let retired_old_key = recovered.store.record::<KeyRecord>(KEK, &old_kek);

        assert_eq!(
            retired_old_key.is_ok(),
            stage == "begin_precommit",
            "old KEK retirement after resuming {stage}"
        );

        if stage != "begin_precommit" {
            assert!(matches!(retired_old_key, Err(crate::Error::NotFound)));
        }

        recovered.store.verify_audit().unwrap();
    }
}

fn assert_versions_decrypt(service: &Service, namespace: NamespaceId, secret: SecretId) {
    for (number, expected) in [(1, PAYLOAD_OLD), (2, PAYLOAD_NEW)] {
        let plaintext = service
            .secret_material(
                Scope {
                    namespace,
                    secret,
                    version: SecretVersion(number),
                },
                false,
            )
            .unwrap();

        assert_eq!(plaintext.as_slice(), expected, "version {number}");
    }
}

fn assert_rotation_status(service: &mut Service, pending: bool) {
    let response = service
        .admin(
            secretsd_protocol::AdminRequest {
                action: Some(secretsd_protocol::admin_request::Action::KeyStatus(
                    secretsd_protocol::Empty {},
                )),
            },
            None,
            peer(),
        )
        .unwrap();

    assert!(response.response.capabilities.iter().any(|capability| {
        capability
            == if pending {
                "rotation-pending"
            } else {
                "rotation-complete"
            }
    }));
}
