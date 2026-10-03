//! Domain-separated keys live only in locked memory. No Clone or key Debug.
use crate::{
    Error, Result,
    memory::{LockedBytes, MemoryBudget},
};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::sync::Arc;
use zeroize::Zeroize;

pub struct Keys {
    #[cfg_attr(
        not(target_os = "linux"),
        allow(
            dead_code,
            reason = "Root ownership is retained; the keyring is Linux-only."
        )
    )]
    pub(crate) root: LockedBytes,
    pub(crate) state: LockedBytes,
    pub(crate) audit: LockedBytes,
    pub(crate) index: LockedBytes,
    pub(crate) grant: LockedBytes,
    pub budget: Arc<MemoryBudget>,
}

impl Keys {
    pub fn new(root: LockedBytes, budget: Arc<MemoryBudget>) -> Result<Self> {
        let state = derive(&root, b"apollo-secretsd/state-auth", &budget)?;

        let audit = derive(&root, b"apollo-secretsd/audit-chain", &budget)?;

        let index = derive(&root, b"apollo-secretsd/name-index", &budget)?;

        // Grant digests are deliberately boot-specific as well as domain separated.
        let seed = LockedBytes::random(32, &budget)?;

        let mut grant = derive(&root, b"apollo-secretsd/grant-digest", &budget)?;

        let (mut prk, hk) = Hkdf::<Sha256>::extract(Some(seed.as_slice()), grant.as_slice());

        prk.zeroize();

        hk.expand(b"boot", grant.as_mut_slice())
            .map_err(|_| Error::Integrity)?;

        Ok(Self {
            root,
            state,
            audit,
            index,
            grant,
            budget,
        })
    }

    pub fn name_index(&self, namespace: &[u8; 16], name: &str) -> Result<[u8; 32]> {
        if name.is_empty()
            || name.len() > 256
            || !name.is_ascii()
            || name.bytes().any(|b| !matches!(b, b' '..=b'~'))
        {
            return Err(Error::Invalid);
        }

        mac(
            self.index.key()?,
            &[
                namespace,
                &(name.len() as u32).to_be_bytes(),
                name.as_bytes(),
            ],
        )
    }

    pub fn grant_digest(&self, token: &[u8; 32]) -> Result<[u8; 32]> {
        mac(self.grant.key()?, &[token])
    }

    pub fn state_mac(&self, parts: &[&[u8]]) -> Result<[u8; 32]> {
        mac(self.state.key()?, parts)
    }

    pub fn audit_mac(&self, parts: &[&[u8]]) -> Result<[u8; 32]> {
        mac(self.audit.key()?, parts)
    }

    pub fn verify_state(&self, parts: &[&[u8]], tag: &[u8]) -> Result<()> {
        verify_mac(self.state.key()?, parts, tag)
    }

    pub fn verify_audit(&self, parts: &[&[u8]], tag: &[u8]) -> Result<()> {
        verify_mac(self.audit.key()?, parts, tag)
    }
}

fn derive(root: &LockedBytes, domain: &[u8], budget: &Arc<MemoryBudget>) -> Result<LockedBytes> {
    let mut key = LockedBytes::new(32, budget)?;

    let (mut prk, hk) =
        Hkdf::<Sha256>::extract(Some(b"apollo-secretsd/storage-format/1"), root.key()?);

    prk.zeroize();

    hk.expand(domain, key.as_mut_slice())
        .map_err(|_| Error::Integrity)?;

    Ok(key)
}

pub fn mac(key: &[u8; 32], parts: &[&[u8]]) -> Result<[u8; 32]> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| Error::Integrity)?;

    for part in parts {
        mac.update(&(part.len() as u64).to_be_bytes());

        mac.update(part);
    }

    Ok(mac.finalize().into_bytes().into())
}

pub fn verify_mac(key: &[u8; 32], parts: &[&[u8]], tag: &[u8]) -> Result<()> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| Error::Integrity)?;

    for part in parts {
        mac.update(&(part.len() as u64).to_be_bytes());

        mac.update(part);
    }

    mac.verify_slice(tag).map_err(|_| Error::Integrity)
}
