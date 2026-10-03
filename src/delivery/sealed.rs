//! Keep memfd pages locked continuously until ownership transfers to the recipient.
use crate::{
    Error, Result,
    memory::{LockedBytes, MemoryBudget},
};
use rustix::{
    fd::{AsRawFd, OwnedFd},
    fs::{self, MemfdFlags, SealFlags},
};
use std::{ptr::NonNull, sync::Arc};

const SEALS: SealFlags = SealFlags::WRITE
    .union(SealFlags::GROW)
    .union(SealFlags::SHRINK)
    .union(SealFlags::SEAL);

struct Mapping {
    ptr: NonNull<u8>,
    len: usize,
    charged: usize,
    budget: Arc<MemoryBudget>,
}

// SAFETY: Mapping owns its mmap and only exposes immutable access after creation.
// Its descriptor remains owned alongside it; no external unmapping API is exposed.
unsafe impl Send for Mapping {}

impl Mapping {
    fn new(fd: &OwnedFd, len: usize, write: bool, budget: &Arc<MemoryBudget>) -> Result<Self> {
        // SAFETY: sysconf with a scalar constant has no pointer operands.
        let page = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })
            .map_err(|_| Error::Protection)?;

        let charged = len.checked_add(page - 1).ok_or(Error::Limit)? / page * page;

        budget.reserve(charged)?;

        let prot = libc::PROT_READ | if write { libc::PROT_WRITE } else { 0 };

        // SAFETY: Map exactly the ftruncate-established object extent; fd is live.
        let raw = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                prot,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                0,
            )
        };

        if raw == libc::MAP_FAILED {
            budget.release(charged);

            return Err(Error::Protection);
        }

        // SAFETY: raw is a valid mapping of len bytes, owned locally.
        if unsafe {
            libc::mlock(raw, len) != 0 || libc::madvise(raw, len, libc::MADV_DONTDUMP) != 0
        } {
            // SAFETY: This failed mapping has not escaped.
            unsafe {
                libc::munmap(raw, len);
            }

            budget.release(charged);

            return Err(Error::Protection);
        }

        Ok(Self {
            ptr: NonNull::new(raw.cast()).ok_or(Error::Protection)?,
            len,
            charged,
            budget: Arc::clone(budget),
        })
    }

    fn fill(&mut self, bytes: &[u8]) {
        // SAFETY: Called only on the writable mapping, with exact-length input;
        // &mut self ensures unique mutable access, mappings do not overlap input.
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), self.ptr.as_ptr(), self.len);
        }
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: The owned mapping is still valid; no references are exposed.
        unsafe {
            libc::munlock(self.ptr.as_ptr().cast(), self.len);

            libc::munmap(self.ptr.as_ptr().cast(), self.len);
        }

        self.budget.release(self.charged);
    }
}

pub struct SealedSecret {
    pub fd: OwnedFd,
    pub length: usize,
    _locked: Mapping,
}

impl SealedSecret {
    pub fn new(bytes: &LockedBytes) -> Result<Self> {
        let fd = fs::memfd_create(
            "secretsd-delivery",
            MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
        )?;

        fs::ftruncate(&fd, bytes.len() as u64)?;

        let mut writable = Mapping::new(&fd, bytes.len(), true, bytes.budget())?;

        writable.fill(bytes.as_slice());

        // Reopen read-only through procfs to remove VM_MAYWRITE. Both mappings
        // overlap during transition, so backing pages never lose their mlock.
        let path = format!("/proc/self/fd/{}", fd.as_raw_fd());

        let readonly = fs::open(
            path,
            fs::OFlags::RDONLY | fs::OFlags::CLOEXEC,
            fs::Mode::empty(),
        )?;

        let locked = Mapping::new(&readonly, bytes.len(), false, bytes.budget())?;

        drop(writable);

        fs::fcntl_add_seals(&fd, SEALS)?;

        if !fs::fcntl_get_seals(&fd)?.contains(SEALS) {
            return Err(Error::Protection);
        }

        drop(fd);

        Ok(Self {
            fd: readonly,
            length: bytes.len(),
            _locked: locked,
        })
    }
}

pub fn import(
    fd: OwnedFd,
    length: usize,
    maximum: usize,
    budget: &Arc<MemoryBudget>,
) -> Result<LockedBytes> {
    if length > maximum {
        return Err(Error::Invalid);
    }

    validate(&fd, length)?;

    let mut out = LockedBytes::new(length, budget)?;

    let mut offset = 0;

    while offset < length {
        let n = rustix::io::pread(&fd, &mut out.as_mut_slice()[offset..], offset as u64)?;

        if n == 0 {
            return Err(Error::Invalid);
        }

        offset += n;
    }

    Ok(out)
}

pub fn validate(fd: &OwnedFd, length: usize) -> Result<()> {
    let stat = fs::fstat(fd)?;

    if length == 0
        || length > 4 * 1024 * 1024
        || stat.st_size != length as i64
        || fs::FileType::from_raw_mode(stat.st_mode) != fs::FileType::RegularFile
        || !fs::fcntl_get_seals(fd)?.contains(SEALS)
    {
        return Err(Error::Invalid);
    }

    Ok(())
}
