//! Detached AEAD decryption writes only to protected memory, after authorization.
use crate::{
    Error, Result,
    memory::{LockedBytes, MemoryBudget},
};
use chacha20poly1305::{KeyInit, Tag, XChaCha20Poly1305, XNonce, aead::AeadInOut};
use secretsd_protocol::{NamespaceId, SecretId, SecretVersion};
use std::sync::Arc;

#[derive(Clone, Copy, Debug)]
pub struct Scope {
    pub namespace: NamespaceId,
    pub secret: SecretId,
    pub version: SecretVersion,
}

impl Scope {
    fn aad(&self, kind: u8, key_id: &[u8; 16]) -> Vec<u8> {
        let mut out = Vec::with_capacity(80);

        out.extend_from_slice(b"apollo-secretsd\0");

        out.extend_from_slice(&1u32.to_be_bytes()); // storage format
        out.extend_from_slice(&self.namespace.0);

        out.extend_from_slice(&self.secret.0);

        out.extend_from_slice(&self.version.0.to_be_bytes());

        out.push(kind); // payload, metadata or wrapped DEK
        out.push(1); // XChaCha20Poly1305
        out.extend_from_slice(key_id);

        out
    }
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Blob {
    #[prost(bytes = "vec", tag = "1")]
    pub nonce: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub ciphertext: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub tag: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct EncryptedVersion {
    #[prost(bytes = "vec", tag = "1")]
    pub kek_id: Vec<u8>,
    #[prost(message, optional, tag = "2")]
    pub wrapped_dek: Option<Blob>,
    #[prost(message, optional, tag = "3")]
    pub payload: Option<Blob>,
    #[prost(message, optional, tag = "4")]
    pub metadata: Option<Blob>,
}

pub(crate) fn seal(
    key: &LockedBytes,
    input: &[u8],
    aad: &[u8],
    budget: &Arc<MemoryBudget>,
) -> Result<Blob> {
    let mut nonce = vec![0; 24];

    getrandom::fill(&mut nonce).map_err(|_| Error::Protection)?;

    let mut protected = LockedBytes::from_slice(input, budget)?;

    let cipher = XChaCha20Poly1305::new(key.key()?.into());

    let tag = cipher
        .encrypt_inout_detached(
            <&XNonce>::try_from(nonce.as_slice()).map_err(|_| Error::Integrity)?,
            aad,
            protected.as_mut_slice().into(),
        )
        .map_err(|_| Error::Integrity)?;

    Ok(Blob {
        nonce,
        ciphertext: protected.as_slice().to_vec(),
        tag: tag.to_vec(),
    })
}

pub(crate) fn open(
    key: &LockedBytes,
    blob: &Blob,
    aad: &[u8],
    budget: &Arc<MemoryBudget>,
) -> Result<LockedBytes> {
    if blob.nonce.len() != 24
        || blob.tag.len() != 16
        || blob.ciphertext.is_empty()
        || blob.ciphertext.len() > 4 * 1024 * 1024
    {
        return Err(Error::Integrity);
    }

    let mut plaintext = LockedBytes::from_slice(&blob.ciphertext, budget)?;

    XChaCha20Poly1305::new(key.key()?.into())
        .decrypt_inout_detached(
            <&XNonce>::try_from(blob.nonce.as_slice()).map_err(|_| Error::Integrity)?,
            aad,
            plaintext.as_mut_slice().into(),
            <&Tag>::try_from(blob.tag.as_slice()).map_err(|_| Error::Integrity)?,
        )
        .map_err(|_| Error::Integrity)?;

    Ok(plaintext)
}

pub fn encrypt_version(
    scope: Scope,
    kek_id: &[u8; 16],
    kek: &LockedBytes,
    payload: &LockedBytes,
    name: &str,
    budget: &Arc<MemoryBudget>,
) -> Result<EncryptedVersion> {
    if scope.version.0 == 0 || name.is_empty() || name.len() > 256 {
        return Err(Error::Invalid);
    }

    let dek = LockedBytes::random(32, budget)?;

    // Payload/metadata AAD excludes KEK identity so only the envelope needs rotation.
    let payload = seal(&dek, payload.as_slice(), &scope.aad(1, &[0; 16]), budget)?;

    let metadata = seal(&dek, name.as_bytes(), &scope.aad(2, &[0; 16]), budget)?;

    let wrapped_dek = seal(kek, dek.as_slice(), &scope.aad(3, kek_id), budget)?;

    Ok(EncryptedVersion {
        kek_id: kek_id.to_vec(),
        wrapped_dek: Some(wrapped_dek),
        payload: Some(payload),
        metadata: Some(metadata),
    })
}

pub fn decrypt_version(
    scope: Scope,
    record: &EncryptedVersion,
    kek: &LockedBytes,
    metadata: bool,
    budget: &Arc<MemoryBudget>,
) -> Result<LockedBytes> {
    let key_id = record
        .kek_id
        .as_slice()
        .try_into()
        .map_err(|_| Error::Integrity)?;

    let dek = open(
        kek,
        record.wrapped_dek.as_ref().ok_or(Error::Integrity)?,
        &scope.aad(3, key_id),
        budget,
    )?;

    let (kind, blob) = if metadata {
        (2, &record.metadata)
    } else {
        (1, &record.payload)
    };

    open(
        &dek,
        blob.as_ref().ok_or(Error::Integrity)?,
        &scope.aad(kind, &[0; 16]),
        budget,
    )
}

pub fn rewrap(
    scope: Scope,
    record: &mut EncryptedVersion,
    old: &LockedBytes,
    new_id: &[u8; 16],
    new: &LockedBytes,
    budget: &Arc<MemoryBudget>,
) -> Result<()> {
    let old_id = record
        .kek_id
        .as_slice()
        .try_into()
        .map_err(|_| Error::Integrity)?;

    let dek = open(
        old,
        record.wrapped_dek.as_ref().ok_or(Error::Integrity)?,
        &scope.aad(3, old_id),
        budget,
    )?;

    record.wrapped_dek = Some(seal(new, dek.as_slice(), &scope.aad(3, new_id), budget)?);

    record.kek_id = new_id.to_vec();

    Ok(())
}
