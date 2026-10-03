//! Descriptor-relative Linux filesystem operations. No symlink fallback.
use crate::{Error, Result};
use rustix::{
    fd::{AsRawFd, OwnedFd},
    fs::{self, Mode, OFlags, ResolveFlags},
};
use std::path::Path;

pub struct SecureDir {
    fd: OwnedFd,
}

impl SecureDir {
    pub fn open(path: &Path, mode: u32) -> Result<Self> {
        let fd = fs::openat2(
            fs::CWD,
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )?;

        let stat = fs::fstat(&fd)?;

        if fs::FileType::from_raw_mode(stat.st_mode) != fs::FileType::Directory
            || stat.st_uid != rustix::process::geteuid().as_raw()
            || stat.st_mode & 0o777 != mode
        {
            return Err(Error::Protection);
        }

        Ok(Self { fd })
    }

    pub fn file(&self, name: &str, create: bool) -> Result<OwnedFd> {
        if name.is_empty() || name.contains('/') || name == "." || name == ".." {
            return Err(Error::Invalid);
        }

        let flags = OFlags::RDWR
            | OFlags::CLOEXEC
            | OFlags::NOFOLLOW
            | if create {
                OFlags::CREATE
            } else {
                OFlags::empty()
            };

        let fd = fs::openat2(
            &self.fd,
            name,
            flags,
            if create {
                Mode::RUSR | Mode::WUSR
            } else {
                Mode::empty()
            },
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )?;

        validate_file(&fd, rustix::process::geteuid().as_raw(), 0o600)?;

        Ok(fd)
    }

    pub fn lock(&self, name: &str) -> Result<OwnedFd> {
        let fd = self.file(name, true)?;

        fs::flock(&fd, fs::FlockOperation::NonBlockingLockExclusive)?;

        Ok(fd)
    }

    pub fn fd(&self) -> &OwnedFd {
        &self.fd
    }

    /// `SQLite` must resolve all sidecars relative to the pinned directory inode.
    pub fn proc_path(&self, name: &str) -> Result<std::path::PathBuf> {
        if name.contains('/') || name.is_empty() {
            return Err(Error::Invalid);
        }

        Ok(format!("/proc/self/fd/{}/{}", self.fd.as_raw_fd(), name).into())
    }

    pub fn sync(&self) -> Result<()> {
        fs::fsync(&self.fd)?;

        Ok(())
    }
}

pub fn validate_file(fd: &OwnedFd, owner: u32, mode: u32) -> Result<()> {
    let stat = fs::fstat(fd)?;

    if fs::FileType::from_raw_mode(stat.st_mode) != fs::FileType::RegularFile
        || stat.st_uid != owner
        || stat.st_mode & 0o777 != mode
        || stat.st_nlink != 1
    {
        return Err(Error::Protection);
    }

    Ok(())
}
