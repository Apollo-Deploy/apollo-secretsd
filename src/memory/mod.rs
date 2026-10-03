//! Page-owned secret buffers: bounded, locked, excluded from dumps, erased on drop.
mod locked;
#[cfg(target_os = "linux")]
mod stack;
#[cfg(target_os = "linux")]
mod thread;

pub use locked::{LockedBytes, MemoryBudget};
#[cfg(target_os = "linux")]
pub use thread::ProtectedThread;

use crate::{Error, Result};

/// Protect temporary allocations made by protocol and native provider libraries,
/// including sensitive names. Kernel `RLIMIT_MEMLOCK` bounds current/future mappings.
#[cfg(target_os = "linux")]
pub fn lock_address_space() -> Result<()> {
    #[cfg(target_env = "gnu")]
    // SAFETY: Scalar glibc tuning before workers; one arena avoids reserving
    // a large locked heap per thread. This does not alter ownership or erasure.
    if unsafe { libc::mallopt(libc::M_ARENA_MAX, 1) } != 1 {
        return Err(Error::Protection);
    }

    // SAFETY: mlockall takes scalar flags. Failure prevents key loading/readiness.
    if unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) } != 0 {
        return Err(Error::Protection);
    }

    Ok(())
}

/// Apply before reading any key or accepting any request. No downgrade is available.
#[cfg(target_os = "linux")]
pub fn harden_process() -> Result<()> {
    use rustix::process::{DumpableBehavior, Resource, Rlimit};

    rustix::process::set_dumpable_behavior(DumpableBehavior::NotDumpable)?;

    rustix::process::setrlimit(
        Resource::Core,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )?;

    if rustix::process::dumpable_behavior()? != DumpableBehavior::NotDumpable
        || rustix::process::getrlimit(Resource::Core).current != Some(0)
    {
        return Err(Error::Protection);
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn harden_process() -> Result<()> {
    Err(Error::Protection)
}
