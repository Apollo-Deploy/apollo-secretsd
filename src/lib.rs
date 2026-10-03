#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "Unit fixtures and assertions deliberately fail the test on error."
    )
)]
//! Standalone Linux-local secrets broker. No Apollo runtime dependencies.
#![deny(unsafe_op_in_unsafe_fn)]
#[cfg(target_os = "linux")]
pub mod auth;
pub mod capability;
#[cfg(target_os = "linux")]
pub mod client;
pub mod config;
pub mod crypto;
#[cfg(target_os = "linux")]
pub mod delivery;
pub mod error;
#[cfg(target_os = "linux")]
pub mod filesystem;
#[cfg(target_os = "linux")]
pub mod key_provider;
pub mod memory;
#[cfg(target_os = "linux")]
pub mod runtime;
#[cfg(target_os = "linux")]
pub mod service;
pub mod storage;

pub use error::{Error, Result};
