//! Owned pthread stacks: guard pages, locked RAM, no dumps, erased after join.
use super::MemoryBudget;
use crate::{Error, Result};
use std::{ptr::NonNull, sync::Arc};
use zeroize::Zeroize;

pub(super) struct Stack {
    allocation: NonNull<libc::c_void>,
    pub pointer: *mut libc::c_void,
    pub length: usize,
    total: usize,
    budget: Arc<MemoryBudget>,
}

// SAFETY: This mapping is uniquely owned. Its only borrower is the associated
// pthread; Thread always joins that pthread before releasing or erasing it.
unsafe impl Send for Stack {}

impl Stack {
    pub(super) fn new(budget: &Arc<MemoryBudget>) -> Result<Self> {
        // SAFETY: sysconf has no pointer operands for this query.
        let page = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })
            .map_err(|_| Error::Protection)?;

        let length = 512 * 1024;

        let total = length + 2 * page;

        budget.reserve(length)?;

        // SAFETY: Anonymous page-aligned inaccessible mapping, without aliases.
        let raw = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                total,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };

        if raw == libc::MAP_FAILED {
            budget.release(length);

            return Err(Error::Protection);
        }

        // SAFETY: The interior is page aligned and leaves one guard page at each
        // end. Establish all protections before any pthread uses this memory.
        let pointer = unsafe { raw.cast::<u8>().add(page).cast() };

        // SAFETY: pointer/length describe the interior pages of this live
        // anonymous mapping; the guard pages are excluded from this range.
        let protected = unsafe {
            libc::mprotect(pointer, length, libc::PROT_READ | libc::PROT_WRITE) == 0
                && libc::mlock(pointer, length) == 0
                && libc::madvise(pointer, length, libc::MADV_DONTDUMP) == 0
                && libc::madvise(pointer, length, libc::MADV_WIPEONFORK) == 0
        };

        if !protected {
            // SAFETY: No pthread has borrowed the failed mapping.
            unsafe {
                libc::munmap(raw, total);
            }

            budget.release(length);

            return Err(Error::Protection);
        }

        Ok(Self {
            allocation: NonNull::new(raw).ok_or(Error::Protection)?,
            pointer,
            length,
            total,
            budget: Arc::clone(budget),
        })
    }
}

impl Drop for Stack {
    fn drop(&mut self) {
        // SAFETY: The pthread was joined. Its stack is exclusively owned again;
        // guards remain inaccessible and are excluded from the erase slice.
        unsafe {
            std::slice::from_raw_parts_mut(self.pointer.cast::<u8>(), self.length).zeroize();

            libc::munlock(self.pointer, self.length);

            libc::munmap(self.allocation.as_ptr(), self.total);
        }

        self.budget.release(self.length);
    }
}
