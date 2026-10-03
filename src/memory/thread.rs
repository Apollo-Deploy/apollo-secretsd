//! Small joinable threads whose entire owned stack has secret-memory protection.
use super::{MemoryBudget, stack::Stack};
use crate::{Error, Result};
use std::{
    mem::MaybeUninit,
    sync::{Arc, Mutex},
};

struct Start<T> {
    work: Box<dyn FnOnce() -> T + Send>,
    result: Arc<Mutex<Option<std::thread::Result<T>>>>,
}

pub struct ProtectedThread<T> {
    id: Option<libc::pthread_t>,
    result: Arc<Mutex<Option<std::thread::Result<T>>>>,
    _stack: Stack,
}

// SAFETY: pthread_join may be called by a different thread. The stack remains
// uniquely owned and the return value is moved only after successful join.
unsafe impl<T: Send> Send for ProtectedThread<T> {}

impl<T: Send + 'static> ProtectedThread<T> {
    pub fn spawn(
        budget: &Arc<MemoryBudget>,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> Result<Self> {
        let stack = Stack::new(budget)?;

        let result = Arc::new(Mutex::new(None));

        let start = Box::new(Start {
            work: Box::new(work),
            result: Arc::clone(&result),
        });

        let mut attr = MaybeUninit::<libc::pthread_attr_t>::uninit();

        // SAFETY: pthread_attr_init initializes the correctly sized out parameter.
        if unsafe { libc::pthread_attr_init(attr.as_mut_ptr()) } != 0 {
            return Err(Error::Protection);
        }

        // SAFETY: attr is initialized; stack owns a protected page-aligned region
        // at least PTHREAD_STACK_MIN. Our guard pages replace libc guard allocation.
        let mut attr = unsafe { attr.assume_init() };

        // SAFETY: The owned page-aligned stack meets the minimum size and
        // remains allocated until this thread has been joined.
        let setup = unsafe { libc::pthread_attr_setstack(&mut attr, stack.pointer, stack.length) };

        if setup != 0 {
            // SAFETY: Initialized attr; no thread borrows it.
            unsafe {
                libc::pthread_attr_destroy(&mut attr);
            }

            return Err(Error::Protection);
        }

        let raw = Box::into_raw(start);

        let mut id = MaybeUninit::uninit();

        // SAFETY: The boxed argument is transferred exactly once to entry on
        // success; on failure we recover it. The owned stack outlives pthread_join.
        let created =
            unsafe { libc::pthread_create(id.as_mut_ptr(), &attr, entry::<T>, raw.cast()) };

        // SAFETY: pthread_create copies attributes before it returns.
        unsafe {
            libc::pthread_attr_destroy(&mut attr);
        }

        if created != 0 {
            // SAFETY: pthread_create failed, so entry never acquired the argument.
            unsafe {
                drop(Box::from_raw(raw));
            }

            return Err(Error::Protection);
        }

        // SAFETY: Successful create initialized this pthread identifier.
        let id = unsafe { id.assume_init() };

        Ok(Self {
            id: Some(id),
            result,
            _stack: stack,
        })
    }

    pub fn join(mut self) -> Result<T> {
        self.finish();

        self.result
            .lock()
            .map_err(|_| Error::Protection)?
            .take()
            .ok_or(Error::Protection)?
            .map_err(|_| Error::Protection)
    }
}

impl<T> ProtectedThread<T> {
    fn finish(&mut self) {
        if let Some(id) = self.id.take() {
            // SAFETY: This is the unique join owner of a successfully created,
            // joinable pthread. No stack access happens until join returns.
            if unsafe { libc::pthread_join(id, std::ptr::null_mut()) } != 0 {
                // Releasing a potentially live stack would be unsound.
                std::process::abort();
            }
        }
    }
}

impl<T> Drop for ProtectedThread<T> {
    fn drop(&mut self) {
        self.finish();
    }
}

extern "C" fn entry<T: Send + 'static>(argument: *mut libc::c_void) -> *mut libc::c_void {
    // SAFETY: A successful pthread_create transferred this unique Start<T> box.
    let start = unsafe { Box::from_raw(argument.cast::<Start<T>>()) };

    let value = std::panic::catch_unwind(std::panic::AssertUnwindSafe(start.work));

    if let Ok(mut result) = start.result.lock() {
        *result = Some(value);
    }

    std::ptr::null_mut()
}
