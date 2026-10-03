#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "Integration fixtures and assertions deliberately fail the test on error."
)]
#![cfg(target_os = "linux")]
use apollo_secretsd::{
    Result,
    capability::Peer,
    config::Limits,
    crypto::Keys,
    filesystem::SecureDir,
    key_provider::{KeyProvider, ProtectedFd, RootFile},
    memory::{LockedBytes, MemoryBudget},
    service::Service,
    storage::Store,
};
use rusqlite::{Connection, TransactionBehavior};
use rustix::{
    fd::OwnedFd,
    fs::{self, MemfdFlags, SealFlags},
    io,
};
use std::{
    fs::OpenOptions,
    os::unix::fs::PermissionsExt,
    path::Path,
    time::{Duration, Instant},
};

const ROOT: [u8; 32] = [0x5a; 32];

const PAGE_BUDGET: usize = 64 * 1024;

fn sealed_key(bytes: &[u8]) -> OwnedFd {
    let fd = fs::memfd_create(
        "provider-fixture",
        MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
    )
    .unwrap();

    io::write(&fd, bytes).unwrap();

    fs::fcntl_add_seals(
        &fd,
        SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK | SealFlags::SEAL,
    )
    .unwrap();

    fd
}

fn protected_file(directory: &Path) -> std::fs::File {
    let path = directory.join("credential");

    let mut file = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();

    use std::io::Write;

    file.write_all(&ROOT).unwrap();

    drop(file);

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();

    OpenOptions::new().read(true).open(path).unwrap()
}

#[test]
fn protected_fd_accepts_sealed_memfd_and_strict_credential_file() {
    let budget = MemoryBudget::new(PAGE_BUDGET);

    let mut provider = ProtectedFd::new(sealed_key(&ROOT));

    let key = provider.load(&budget).unwrap();

    assert_eq!(key.key().unwrap(), &ROOT);

    drop(key);

    assert_eq!(budget.used(), 0);

    let directory = tempfile::tempdir().unwrap();

    let file = protected_file(directory.path());

    let budget = MemoryBudget::new(PAGE_BUDGET);

    let mut provider = ProtectedFd::new(file.into());

    let key = provider.load(&budget).unwrap();

    assert_eq!(key.key().unwrap(), &ROOT);

    drop(key);

    assert_eq!(budget.used(), 0);
}

#[test]
fn protected_fd_rejects_pipe_mutable_memfd_and_wrong_lengths() {
    let budget = MemoryBudget::new(PAGE_BUDGET);

    let unsealed =
        fs::memfd_create("mutable", MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING).unwrap();

    io::write(&unsealed, &ROOT).unwrap();

    let mut provider = ProtectedFd::new(unsealed);

    assert!(provider.load(&budget).is_err());

    assert_eq!(budget.used(), 0);

    let mut provider = ProtectedFd::new(sealed_key(&ROOT[..31]));

    assert!(provider.load(&budget).is_err());

    assert_eq!(budget.used(), 0);

    let (reader, _writer) = std::os::unix::net::UnixStream::pair().unwrap();

    let mut provider = ProtectedFd::new(reader.into());

    assert!(provider.load(&budget).is_err());

    assert_eq!(budget.used(), 0);
}

#[test]
fn root_file_provider_rejects_symlink_without_reading_target() {
    let directory = tempfile::tempdir().unwrap();

    let target = directory.path().join("target");

    std::fs::write(&target, ROOT).unwrap();

    let link = directory.path().join("key-link");

    std::os::unix::fs::symlink(&target, &link).unwrap();

    let budget = MemoryBudget::new(PAGE_BUDGET);

    let mut provider = RootFile { path: link };

    assert!(provider.load(&budget).is_err());

    assert_eq!(std::fs::read(target).unwrap(), ROOT);

    assert_eq!(budget.used(), 0);
}

#[test]
fn secure_directory_rejects_symlink_components_and_file_leaves() {
    let parent = tempfile::tempdir().unwrap();

    let real = parent.path().join("real");

    std::fs::create_dir(&real).unwrap();

    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();

    let dir_link = parent.path().join("dir-link");

    std::os::unix::fs::symlink(&real, &dir_link).unwrap();

    assert!(SecureDir::open(&dir_link, 0o700).is_err());

    let directory = SecureDir::open(&real, 0o700).unwrap();

    let outside = parent.path().join("outside");

    std::fs::write(&outside, b"keep").unwrap();

    std::os::unix::fs::symlink(&outside, real.join("state.sqlite3")).unwrap();

    assert!(directory.file("state.sqlite3", false).is_err());

    assert_eq!(std::fs::read(outside).unwrap(), b"keep");
}

#[test]
fn store_open_rejects_database_and_wal_symlinks() {
    for leaf in ["state.sqlite3", "state.sqlite3-wal"] {
        let parent = tempfile::tempdir().unwrap();

        let state = parent.path().join("state");

        std::fs::create_dir(&state).unwrap();

        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();

        let target = parent.path().join("outside");

        std::fs::write(&target, b"external-state").unwrap();

        std::os::unix::fs::symlink(&target, state.join(leaf)).unwrap();

        let budget = MemoryBudget::new(PAGE_BUDGET);

        let root = LockedBytes::from_slice(&ROOT, &budget).unwrap();

        let keys = Keys::new(root, budget).unwrap();

        assert!(Store::open(SecureDir::open(&state, 0o700).unwrap(), keys, 1000).is_err());

        assert_eq!(std::fs::read(target).unwrap(), b"external-state");
    }
}

fn service_for(directory: SecureDir) -> Result<Service> {
    let budget = MemoryBudget::new(PAGE_BUDGET);

    let root = LockedBytes::from_slice(&ROOT, &budget)?;

    let keys = Keys::new(root, budget)?;

    Service::new(Store::open(directory, keys, 10_000)?, Limits::default())
}

#[test]
fn open_state_directory_remains_pinned_after_rename_and_path_replacement() {
    let parent = tempfile::tempdir().unwrap();

    let configured = parent.path().join("state");

    let moved = parent.path().join("state-moved");

    let attacker = parent.path().join("attacker");

    std::fs::create_dir(&configured).unwrap();

    std::fs::create_dir(&attacker).unwrap();

    std::fs::set_permissions(&configured, std::fs::Permissions::from_mode(0o700)).unwrap();

    std::fs::set_permissions(&attacker, std::fs::Permissions::from_mode(0o700)).unwrap();

    let directory = SecureDir::open(&configured, 0o700).unwrap();

    std::fs::rename(&configured, &moved).unwrap();

    std::os::unix::fs::symlink(&attacker, &configured).unwrap();

    let mut service = service_for(directory).unwrap();

    service
        .namespace_create(Peer {
            uid: rustix::process::geteuid().as_raw(),
            gid: rustix::process::getegid().as_raw(),
            pid: std::process::id(),
            start_time: 1,
        })
        .unwrap();

    assert!(moved.join("state.sqlite3").exists());

    assert!(!attacker.join("state.sqlite3").exists());
}

#[test]
fn sqlite_contention_fails_mutation_within_busy_timeout_then_recovers() {
    let parent = tempfile::tempdir().unwrap();

    let configured = parent.path().join("state");

    let moved = parent.path().join("state-moved");

    let attacker = parent.path().join("attacker");

    std::fs::create_dir(&configured).unwrap();

    std::fs::create_dir(&attacker).unwrap();

    std::fs::set_permissions(&configured, std::fs::Permissions::from_mode(0o700)).unwrap();

    std::fs::set_permissions(&attacker, std::fs::Permissions::from_mode(0o700)).unwrap();

    let directory = SecureDir::open(&configured, 0o700).unwrap();

    std::fs::rename(&configured, &moved).unwrap();

    std::os::unix::fs::symlink(&attacker, &configured).unwrap();

    let mut service = service_for(directory).unwrap();

    let mut blocker = Connection::open(moved.join("state.sqlite3")).unwrap();

    let tx = blocker
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();

    let before: i64 = tx
        .query_row("SELECT count(*) FROM records WHERE kind=1", [], |row| {
            row.get(0)
        })
        .unwrap();

    let peer = Peer {
        uid: rustix::process::geteuid().as_raw(),
        gid: rustix::process::getegid().as_raw(),
        pid: std::process::id(),
        start_time: 1,
    };

    let started = Instant::now();

    assert!(service.namespace_create(peer).is_err());

    assert!(started.elapsed() >= Duration::from_millis(150));

    assert!(started.elapsed() < Duration::from_secs(3));

    let during: i64 = tx
        .query_row("SELECT count(*) FROM records WHERE kind=1", [], |row| {
            row.get(0)
        })
        .unwrap();

    assert_eq!(during, before, "failed mutation must not become visible");

    tx.rollback().unwrap();

    service.namespace_create(peer).unwrap();

    drop(service);

    let rows: i64 = Connection::open(moved.join("state.sqlite3"))
        .unwrap()
        .query_row("SELECT count(*) FROM records WHERE kind=1", [], |row| {
            row.get(0)
        })
        .unwrap();

    assert_eq!(rows, 1);

    assert!(!attacker.join("state.sqlite3").exists());

    drop(service_for(SecureDir::open(&moved, 0o700).unwrap()).unwrap());
}
