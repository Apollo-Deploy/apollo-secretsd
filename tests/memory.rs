#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "Integration fixtures and assertions deliberately fail the test on error."
)]
#![cfg(target_os = "linux")]
use apollo_secretsd::memory::{MemoryBudget, ProtectedThread};

#[test]
fn root_secretmem_uses_the_actual_kernel_mapping_and_releases_its_budget() {
    use apollo_secretsd::memory::LockedBytes;

    // SAFETY: Scalar availability probe; no secret is passed to the kernel.
    let fd = unsafe { libc::syscall(libc::SYS_memfd_secret, 0) };

    let available = fd >= 0;

    let denied = if available {
        None
    } else {
        std::io::Error::last_os_error().raw_os_error()
    };

    if available {
        // SAFETY: The availability probe uniquely owns this descriptor.
        unsafe {
            libc::close(fd as i32);
        }
    }

    let budget = MemoryBudget::new(8192);

    let root = LockedBytes::from_slice(&[0x79; 32], &budget).unwrap();

    if available {
        let root = root.protect_root(true).unwrap();

        assert!(root.is_secret_memory());

        assert_eq!(root.as_slice(), &[0x79; 32]);

        assert_eq!(budget.used(), 4096);

        drop(root);
    } else if denied == Some(libc::ENOSYS) {
        let root = root.protect_root(false).unwrap();

        assert!(!root.is_secret_memory());

        assert!(
            LockedBytes::from_slice(&[0x79; 32], &budget)
                .unwrap()
                .protect_root(true)
                .is_err()
        );

        drop(root);
    } else {
        // A container policy denial or resource failure is never mistaken for
        // unsupported-kernel ENOSYS. Both required and automatic mode fail closed.
        assert!(root.protect_root(false).is_err());

        assert!(
            LockedBytes::from_slice(&[0x79; 32], &budget)
                .unwrap()
                .protect_root(true)
                .is_err()
        );
    }

    assert_eq!(budget.used(), 0);
}

#[test]
fn crypto_stack_pages_are_locked_excluded_from_dumps_and_released_after_join() {
    let budget = MemoryBudget::new(1024 * 1024);

    let thread = ProtectedThread::spawn(&budget, || {
        let probe = [0x71u8; 256];

        std::hint::black_box(&probe);

        let address = probe.as_ptr() as usize;

        let smaps = std::fs::read_to_string("/proc/self/smaps").unwrap();

        let mut matching = false;

        let mut locked = false;

        let mut dump_excluded = false;

        for line in smaps.lines() {
            if let Some(range) = line.split_whitespace().next()
                && let Some((lo, hi)) = range.split_once('-')
                && let (Ok(lo), Ok(hi)) =
                    (usize::from_str_radix(lo, 16), usize::from_str_radix(hi, 16))
            {
                matching = (lo..hi).contains(&address);
            }

            if matching && line.starts_with("Locked:") {
                locked = line.split_whitespace().nth(1).is_none_or(|n| n != "0");
            }

            if matching && line.starts_with("VmFlags:") {
                dump_excluded = line.split_whitespace().any(|f| f == "dd");

                break;
            }
        }

        (locked, dump_excluded)
    })
    .unwrap();

    assert!(budget.used() == 512 * 1024);

    assert_eq!(thread.join().unwrap(), (true, true));

    assert_eq!(budget.used(), 0);
}

#[test]
fn protection_failure_prevents_starting_a_crypto_worker() {
    let budget = MemoryBudget::new(4096);

    assert!(ProtectedThread::spawn(&budget, || panic!("must never start")).is_err());

    assert_eq!(budget.used(), 0);
}
