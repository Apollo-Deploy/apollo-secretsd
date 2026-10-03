//! systemd's read-only RAM credential mount, including its dedicated-user ACL.
use super::{KeyProvider, read_key};
use crate::{
    Error, Result,
    memory::{LockedBytes, MemoryBudget},
};
use rustix::{
    fd::OwnedFd,
    fs::{self, Mode, OFlags, ResolveFlags},
};
use std::{path::Path, sync::Arc};

pub struct SystemdCredential {
    fd: Option<OwnedFd>,
    _directory: OwnedFd,
}

impl SystemdCredential {
    pub fn open(directory: &Path, name: &str) -> Result<Self> {
        if name.is_empty()
            || name.len() > 64
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(Error::Invalid);
        }

        let directory = fs::openat2(
            fs::CWD,
            directory,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )?;

        validate_mount(&directory, false)?;

        let fd = fs::openat2(
            &directory,
            name,
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )?;

        validate_mount(&fd, true)?;

        Ok(Self {
            fd: Some(fd),
            _directory: directory,
        })
    }
}

impl KeyProvider for SystemdCredential {
    fn load(&mut self, budget: &Arc<MemoryBudget>) -> Result<LockedBytes> {
        let fd = self.fd.take().ok_or(Error::Protection)?;

        validate_mount(&fd, true)?;

        read_key(fd, budget)
    }

    fn name(&self) -> &'static str {
        "systemd-credential"
    }
}

fn validate_mount(fd: &OwnedFd, file: bool) -> Result<()> {
    let stat = fs::fstat(fd)?;

    let uid = rustix::process::geteuid().as_raw();

    let permissions = if file { 4 } else { 5 };

    let private_mode = permissions << 6;

    let acl_mode = private_mode | (permissions << 3);

    let kind = if file {
        fs::FileType::RegularFile
    } else {
        fs::FileType::Directory
    };

    // RAMFS_MAGIC is specified by Linux include/uapi/linux/magic.h.
    let magic = fs::fstatfs(fd)?.f_type as u64;

    if fs::FileType::from_raw_mode(stat.st_mode) != kind
        || (stat.st_uid != 0 && stat.st_uid != uid)
        || (file && (stat.st_size != 32 || stat.st_nlink != 1))
        || !fs::fstatvfs(fd)?
            .f_flag
            .contains(fs::StatVfsMountFlags::RDONLY)
        || ![libc::TMPFS_MAGIC as u64, 0x8584_58f6].contains(&magic)
    {
        return Err(Error::Protection);
    }

    match stat.st_mode & 0o7777 {
        mode if mode == private_mode && stat.st_uid == uid => Ok(()),
        mode if mode == acl_mode && stat.st_uid == 0 => {
            let mut bytes = [0; 44];

            let length = fs::fgetxattr(fd, "system.posix_acl_access", &mut bytes[..])?;

            validate_acl(&bytes[..length], uid, permissions as u16)
        }
        _ => Err(Error::Protection),
    }
}

fn validate_acl(bytes: &[u8], uid: u32, permissions: u16) -> Result<()> {
    // Linux POSIX ACL xattr: version 2, followed by little-endian 8-byte entries.
    // Accept only owner, this service UID, empty owning group, mask and empty other.
    if bytes.len() != 44 || bytes[..4] != 2u32.to_le_bytes() {
        return Err(Error::Protection);
    }

    let mut seen = 0u16;

    for entry in bytes[4..].chunks_exact(8) {
        let tag = u16::from_le_bytes(entry[..2].try_into().map_err(|_| Error::Protection)?);

        let access = u16::from_le_bytes(entry[2..4].try_into().map_err(|_| Error::Protection)?);

        let id = u32::from_le_bytes(entry[4..].try_into().map_err(|_| Error::Protection)?);

        let valid = match tag {
            1 | 16 => id == u32::MAX && access == permissions,
            2 => id == uid && access == permissions,
            4 | 32 => id == u32::MAX && access == 0,
            _ => false,
        };

        if !valid || seen & tag != 0 {
            return Err(Error::Protection);
        }

        seen |= tag;
    }

    if seen != 1 | 2 | 4 | 16 | 32 {
        return Err(Error::Protection);
    }

    Ok(())
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn credential_acl_rejects_another_principal_or_group_read_access() {
        let mut bytes = 2u32.to_le_bytes().to_vec();

        for (tag, access, id) in [
            (1u16, 4u16, u32::MAX),
            (2, 4, 500),
            (4, 0, u32::MAX),
            (16, 4, u32::MAX),
            (32, 0, u32::MAX),
        ] {
            bytes.extend(tag.to_le_bytes());

            bytes.extend(access.to_le_bytes());

            bytes.extend(id.to_le_bytes());
        }

        assert!(validate_acl(&bytes, 500, 4).is_ok());

        assert!(validate_acl(&bytes, 501, 4).is_err());

        bytes[22..24].copy_from_slice(&4u16.to_le_bytes());

        assert!(validate_acl(&bytes, 500, 4).is_err());

        assert!(validate_acl(&bytes[..43], 500, 4).is_err());
    }
}
