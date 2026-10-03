//! Durable ciphertext and authenticated control state. Mutations include audit.
mod records;

pub use records::*;

#[cfg(target_os = "linux")]
mod counts;
#[cfg(target_os = "linux")]
mod database;
#[cfg(target_os = "linux")]
mod journal;
#[cfg(target_os = "linux")]
mod keyring;
#[cfg(target_os = "linux")]
mod queries;

#[cfg(target_os = "linux")]
pub use database::{Change, Store};

#[cfg(all(test, target_os = "linux"))]
mod crash_tests;
