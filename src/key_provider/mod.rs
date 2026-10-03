//! Provider boundary loads exactly 32 bytes directly into protected memory.
mod credential;

pub use credential::SystemdCredential;

#[cfg(feature = "tpm2")]
mod tpm2;

use crate::{
    Error, Result,
    memory::{LockedBytes, MemoryBudget},
};
use rustix::{
    fd::OwnedFd,
    fs::{self, Mode, OFlags, ResolveFlags},
};
use std::{path::PathBuf, sync::Arc};
#[cfg(feature = "tpm2")]
pub use tpm2::Tpm2;

pub trait KeyProvider: Send {
    fn load(&mut self, budget: &Arc<MemoryBudget>) -> Result<LockedBytes>;

    fn name(&self) -> &'static str;
}

pub struct ProtectedFd {
    fd: Option<OwnedFd>,
}

impl ProtectedFd {
    pub fn new(fd: OwnedFd) -> Self {
        Self { fd: Some(fd) }
    }
}

impl KeyProvider for ProtectedFd {
    fn load(&mut self, budget: &Arc<MemoryBudget>) -> Result<LockedBytes> {
        let fd = self.fd.take().ok_or(Error::Protection)?;

        // Protected-FD mode requires immutable memfd, or an already-open strict
        // system credential file. Pipes/sockets/devices are deliberately rejected.
        let stat = fs::fstat(&fd)?;

        if fs::FileType::from_raw_mode(stat.st_mode) != fs::FileType::RegularFile
            || stat.st_size != 32
        {
            return Err(Error::Protection);
        }

        let immutable = fs::fcntl_get_seals(&fd).is_ok_and(|seals| {
            seals.contains(
                fs::SealFlags::WRITE
                    | fs::SealFlags::GROW
                    | fs::SealFlags::SHRINK
                    | fs::SealFlags::SEAL,
            )
        });

        let credential = stat.st_uid == rustix::process::geteuid().as_raw()
            && matches!(stat.st_mode & 0o777, 0o400 | 0o600)
            && stat.st_nlink == 1;

        if !immutable && !credential {
            return Err(Error::Protection);
        }

        read_key(fd, budget)
    }

    fn name(&self) -> &'static str {
        "protected-fd"
    }
}

pub struct RootFile {
    pub path: PathBuf,
}

impl KeyProvider for RootFile {
    fn load(&mut self, budget: &Arc<MemoryBudget>) -> Result<LockedBytes> {
        let fd = fs::openat2(
            fs::CWD,
            &self.path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )?;

        let stat = fs::fstat(&fd)?;

        if stat.st_uid != 0
            || !matches!(stat.st_mode & 0o777, 0o400 | 0o600)
            || stat.st_nlink != 1
            || stat.st_size != 32
            || fs::FileType::from_raw_mode(stat.st_mode) != fs::FileType::RegularFile
        {
            return Err(Error::Protection);
        }

        read_key(fd, budget)
    }

    fn name(&self) -> &'static str {
        "strict-root-file"
    }
}

fn read_key(fd: OwnedFd, budget: &Arc<MemoryBudget>) -> Result<LockedBytes> {
    let mut key = LockedBytes::new(32, budget)?;

    let mut offset = 0;

    while offset < 32 {
        let n = rustix::io::pread(&fd, &mut key.as_mut_slice()[offset..], offset as u64)?;

        if n == 0 {
            return Err(Error::Protection);
        }

        offset += n;
    }

    Ok(key)
}
