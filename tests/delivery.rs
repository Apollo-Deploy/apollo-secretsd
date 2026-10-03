#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "Integration fixtures and assertions deliberately fail the test on error."
)]
#![cfg(target_os = "linux")]
use apollo_secretsd::{
    delivery::{SealedSecret, transport},
    memory::{LockedBytes, MemoryBudget},
};
use rustix::{
    fs,
    net::{self, AddressFamily, SocketFlags, SocketType},
};

#[test]
fn sealed_fd_transfers_exact_bytes_and_rejects_all_mutations() {
    let budget = MemoryBudget::new(1024 * 1024);

    let bytes = LockedBytes::from_slice(b"sealed-fd-canary", &budget).unwrap();

    let sealed = SealedSecret::new(&bytes).unwrap();

    let (a, b) = net::socketpair(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )
    .unwrap();

    net::sockopt::set_socket_passcred(&b, true).unwrap();

    transport::send(&a, b"fd", Some(&sealed.fd)).unwrap();

    let mut header = [0; 16];

    let delivered = transport::receive(&b, &mut header).unwrap().fd.unwrap();

    drop(sealed);

    let mut received = [0; 16];

    let length = rustix::io::pread(&delivered, &mut received, 0).unwrap();

    assert!(&received[..length] == b"sealed-fd-canary");

    assert!(rustix::io::pwrite(&delivered, b"x", 0).is_err());

    assert!(fs::ftruncate(&delivered, 1).is_err());

    assert!(fs::ftruncate(&delivered, 100).is_err());

    assert!(fs::fcntl_add_seals(&delivered, fs::SealFlags::empty()).is_err());

    let seals = fs::fcntl_get_seals(&delivered).unwrap();

    assert!(seals.contains(
        fs::SealFlags::WRITE | fs::SealFlags::GROW | fs::SealFlags::SHRINK | fs::SealFlags::SEAL
    ));

    drop(delivered);

    drop(bytes);

    assert!(
        budget.used() == 0,
        "protected mappings must release accounting"
    );
}
