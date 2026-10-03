//! `RustCrypto` envelope encryption; no custom cryptographic primitives.
pub(crate) mod envelope;
mod keys;

use crate::{Error, Result};
pub use envelope::{Blob, EncryptedVersion, Scope, decrypt_version, encrypt_version, rewrap};
pub use keys::{Keys, mac, verify_mac};

pub fn random_id() -> Result<[u8; 16]> {
    let mut id = [0; 16];

    getrandom::fill(&mut id).map_err(|_| Error::Protection)?;

    if id == [0; 16] {
        return Err(Error::Protection);
    }

    Ok(id)
}
