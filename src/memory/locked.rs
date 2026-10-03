//! All raw mapping operations are isolated here. Mappings never move or resize.
use crate::{Error, Result};
use std::{
    ptr::NonNull,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use zeroize::Zeroize;

pub struct MemoryBudget {
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "Protected allocations fail closed outside Linux.")
    )]
    maximum: usize,
    used: AtomicUsize,
}

impl MemoryBudget {
    pub fn new(maximum: usize) -> Arc<Self> {
        Arc::new(Self {
            maximum,
            used: AtomicUsize::new(0),
        })
    }

    pub fn used(&self) -> usize {
        self.used.load(Ordering::Relaxed)
    }

    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "Only Linux protected mappings reserve memory.")
    )]
    pub(crate) fn reserve(&self, bytes: usize) -> Result<()> {
        self.used
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes).filter(|n| *n <= self.maximum)
            })
            .map_err(|_| Error::Limit)?;

        Ok(())
    }

    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "Only Linux protected mappings release memory.")
    )]
    pub(crate) fn release(&self, bytes: usize) {
        self.used.fetch_sub(bytes, Ordering::AcqRel);
    }
}

pub struct LockedBytes {
    pointer: NonNull<u8>,
    length: usize,
    mapped: usize,
    budget: Arc<MemoryBudget>,
    #[cfg(target_os = "linux")]
    secret_fd: Option<rustix::fd::OwnedFd>,
}

// SAFETY: This uniquely owns its mapping. Mutation requires &mut; immutable access
// creates only shared slices. Drop cannot run while Rust borrows remain live.
unsafe impl Send for LockedBytes {}

// SAFETY: Shared references expose immutable bytes only, and the OS does not mutate
// the private anonymous mapping. The accounting member uses atomics.
unsafe impl Sync for LockedBytes {}

impl LockedBytes {
    #[cfg(target_os = "linux")]
    pub fn new(length: usize, budget: &Arc<MemoryBudget>) -> Result<Self> {
        if length == 0 {
            return Err(Error::Invalid);
        }

        // SAFETY: sysconf with this constant has no pointer operands.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };

        let page = usize::try_from(page).map_err(|_| Error::Protection)?;

        let mapped = length.checked_add(page - 1).ok_or(Error::Limit)? / page * page;

        budget.reserve(mapped)?;

        // SAFETY: Anonymous private RW mapping, no existing address and no file.
        let raw = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                mapped,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };

        if raw == libc::MAP_FAILED {
            budget.used.fetch_sub(mapped, Ordering::AcqRel);

            return Err(Error::Protection);
        }

        // SAFETY: raw is a valid, page-aligned mapping of exactly mapped bytes.
        let protected = unsafe {
            libc::mlock(raw, mapped) == 0
                && libc::madvise(raw, mapped, libc::MADV_DONTDUMP) == 0
                && libc::madvise(raw, mapped, libc::MADV_WIPEONFORK) == 0
        };

        if !protected {
            // SAFETY: The just-created mapping has not escaped; unmap it on failure.
            unsafe {
                libc::munmap(raw, mapped);
            }

            budget.used.fetch_sub(mapped, Ordering::AcqRel);

            return Err(Error::Protection);
        }

        let pointer = NonNull::new(raw.cast()).ok_or(Error::Protection)?;

        Ok(Self {
            pointer,
            length,
            mapped,
            budget: Arc::clone(budget),
            secret_fd: None,
        })
    }

    #[cfg(not(target_os = "linux"))]
    pub fn new(_length: usize, _budget: &Arc<MemoryBudget>) -> Result<Self> {
        Err(Error::Protection)
    }

    pub fn from_slice(bytes: &[u8], budget: &Arc<MemoryBudget>) -> Result<Self> {
        let mut out = Self::new(bytes.len(), budget)?;

        out.as_mut_slice().copy_from_slice(bytes);

        Ok(out)
    }

    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: pointer owns mapped >= length initialized bytes for self's lifetime.
        unsafe { std::slice::from_raw_parts(self.pointer.as_ptr(), self.length) }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: &mut self guarantees exclusive access to this owned mapping.
        unsafe { std::slice::from_raw_parts_mut(self.pointer.as_ptr(), self.length) }
    }

    pub fn len(&self) -> usize {
        self.length
    }

    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    #[cfg_attr(
        not(target_os = "linux"),
        allow(
            dead_code,
            reason = "Budget ownership is used by Linux mapping operations."
        )
    )]
    pub(crate) fn budget(&self) -> &Arc<MemoryBudget> {
        &self.budget
    }

    pub fn truncate(&mut self, length: usize) -> Result<()> {
        if length == 0 || length > self.length {
            return Err(Error::Invalid);
        }

        self.as_mut_slice()[length..].zeroize();

        self.length = length;

        Ok(())
    }

    pub fn key(&self) -> Result<&[u8; 32]> {
        self.as_slice().try_into().map_err(|_| Error::Invalid)
    }

    pub fn random(length: usize, budget: &Arc<MemoryBudget>) -> Result<Self> {
        let mut out = Self::new(length, budget)?;

        getrandom::fill(out.as_mut_slice()).map_err(|_| Error::Protection)?;

        Ok(out)
    }

    pub fn is_secret_memory(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            self.secret_fd.is_some()
        }

        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }

    /// Use secretmem for root material when supported; required mode never falls
    /// back. Only ENOSYS means the kernel explicitly lacks this facility.
    #[cfg(target_os = "linux")]
    pub fn protect_root(self, required: bool) -> Result<Self> {
        use rustix::fd::{AsRawFd, FromRawFd, OwnedFd};

        // SAFETY: This syscall takes scalar flags and returns a newly owned FD.
        let raw = unsafe { libc::syscall(libc::SYS_memfd_secret, libc::O_CLOEXEC) };

        if raw < 0 {
            let errno = std::io::Error::last_os_error();

            if errno.raw_os_error() == Some(libc::ENOSYS) && !required {
                return Ok(self);
            }

            return Err(Error::Protection);
        }

        // SAFETY: Successful memfd_secret returns a live descriptor we own.
        let fd = unsafe { OwnedFd::from_raw_fd(raw as i32) };

        rustix::fs::ftruncate(&fd, self.mapped as u64)?;

        self.budget.reserve(self.mapped)?;

        // SAFETY: Map the owned secretmem object's initialized exact extent.
        let raw = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                self.mapped,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                0,
            )
        };

        if raw == libc::MAP_FAILED {
            self.budget.release(self.mapped);

            return Err(Error::Protection);
        }

        // Secretmem is kernel-locked automatically. DONTFORK prevents inherited
        // root mappings and DONTDUMP is explicit even with dumpability disabled.
        // SAFETY: Mapping is page aligned, live, uniquely owned and not exposed.
        if unsafe {
            libc::madvise(raw, self.mapped, libc::MADV_DONTDUMP) != 0
                || libc::madvise(raw, self.mapped, libc::MADV_DONTFORK) != 0
        } {
            // SAFETY: The failed mapping has no aliases.
            unsafe {
                libc::munmap(raw, self.mapped);
            }

            self.budget.release(self.mapped);

            return Err(Error::Protection);
        }

        let mut out = Self {
            pointer: NonNull::new(raw.cast()).ok_or(Error::Protection)?,
            length: self.length,
            mapped: self.mapped,
            budget: Arc::clone(&self.budget),
            secret_fd: Some(fd),
        };

        // Copy in userspace: kernel read/getrandom/write cannot address secretmem.
        out.as_mut_slice().copy_from_slice(self.as_slice());

        Ok(out) // dropping self erases the temporary ordinary locked mapping
    }
}

impl std::fmt::Debug for LockedBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LockedBytes([REDACTED])")
    }
}

impl Drop for LockedBytes {
    fn drop(&mut self) {
        // SAFETY: The entire private mapping is initialized, valid and exclusively
        // owned until munmap; erase padding too before releasing page protections.
        unsafe {
            std::slice::from_raw_parts_mut(self.pointer.as_ptr(), self.mapped).zeroize();

            libc::munlock(self.pointer.as_ptr().cast(), self.mapped);

            libc::munmap(self.pointer.as_ptr().cast(), self.mapped);
        }

        self.budget.used.fetch_sub(self.mapped, Ordering::AcqRel);
    }
}
