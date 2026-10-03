#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "Integration fixtures and assertions deliberately fail the test on error."
)]
#![cfg(target_os = "linux")]
use apollo_secretsd::{
    crypto::{self, Scope},
    memory::{LockedBytes, MemoryBudget},
};
use secretsd_protocol::*;

#[test]
fn every_identity_and_record_component_is_authenticated() {
    let budget = MemoryBudget::new(1024 * 1024);

    let kek = LockedBytes::random(32, &budget).unwrap();

    let plaintext = LockedBytes::from_slice(b"crypto-canary", &budget).unwrap();

    let scope = Scope {
        namespace: NamespaceId([1; 16]),
        secret: SecretId([2; 16]),
        version: SecretVersion(17),
    };

    let encrypted =
        crypto::encrypt_version(scope, &[7; 16], &kek, &plaintext, "ROOT_TOKEN", &budget).unwrap();

    assert!(
        crypto::decrypt_version(scope, &encrypted, &kek, false, &budget)
            .unwrap()
            .as_slice()
            == b"crypto-canary"
    );

    for changed in [
        Scope {
            namespace: NamespaceId([3; 16]),
            ..scope
        },
        Scope {
            secret: SecretId([4; 16]),
            ..scope
        },
        Scope {
            version: SecretVersion(18),
            ..scope
        },
    ] {
        assert!(
            crypto::decrypt_version(changed, &encrypted, &kek, false, &budget).is_err(),
            "scope substitution must authenticate"
        );
    }

    for field in 0..8 {
        let mut changed = encrypted.clone();

        match field {
            0 => changed.kek_id[0] ^= 1,
            1 => changed.payload.as_mut().unwrap().nonce[0] ^= 1,
            2 => changed.payload.as_mut().unwrap().ciphertext[0] ^= 1,
            3 => changed.payload.as_mut().unwrap().tag[0] ^= 1,
            4 => changed.wrapped_dek.as_mut().unwrap().nonce[0] ^= 1,
            5 => changed.wrapped_dek.as_mut().unwrap().ciphertext[0] ^= 1,
            6 => changed.wrapped_dek.as_mut().unwrap().tag[0] ^= 1,
            _ => {
                changed.payload = changed.metadata.clone();
            }
        }

        assert!(
            crypto::decrypt_version(scope, &changed, &kek, false, &budget).is_err(),
            "tampered component must not release plaintext"
        );
    }

    let replacement = LockedBytes::random(32, &budget).unwrap();

    let mut rewrapped = encrypted.clone();

    crypto::rewrap(scope, &mut rewrapped, &kek, &[8; 16], &replacement, &budget).unwrap();

    assert!(
        rewrapped.payload == encrypted.payload && rewrapped.metadata == encrypted.metadata,
        "rotation only rewrites the envelope"
    );

    assert!(
        crypto::decrypt_version(scope, &rewrapped, &replacement, false, &budget)
            .unwrap()
            .as_slice()
            == plaintext.as_slice()
    );

    assert!(crypto::decrypt_version(scope, &rewrapped, &kek, false, &budget).is_err());
}
