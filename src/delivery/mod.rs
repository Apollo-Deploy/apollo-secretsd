//! Sealed anonymous FD transfer and locked import; plaintext has no named file.
mod sealed;
pub mod transport;

pub use sealed::{SealedSecret, import, validate};
