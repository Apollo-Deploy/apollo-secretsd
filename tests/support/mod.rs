#![allow(
    dead_code,
    reason = "Each integration crate uses a different subset of shared fixtures."
)]
use apollo_secretsd::{
    Result,
    auth::Process,
    config::Limits,
    crypto::Keys,
    filesystem::SecureDir,
    memory::{LockedBytes, MemoryBudget},
    service::Service,
    storage::Store,
};
use secretsd_protocol::*;
use std::{os::unix::fs::PermissionsExt, path::Path};

pub(crate) fn service(path: &Path, key: &[u8; 32]) -> Result<Service> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;

    let budget = MemoryBudget::new(4 * 1024 * 1024);

    let root = LockedBytes::from_slice(key, &budget)?;

    let keys = Keys::new(root, budget)?;

    let directory = SecureDir::open(path, 0o700)?;

    let store = Store::open(directory, keys, 1000000)?;

    Service::new(store, Limits::default())
}

pub(crate) fn process() -> std::sync::Arc<Process> {
    Process::capture(std::process::id()).expect("current process identity")
}

pub(crate) fn input(value: &[u8]) -> LockedBytes {
    LockedBytes::from_slice(value, &MemoryBudget::new(4 * 1024 * 1024)).expect("locked input")
}

pub(crate) fn grant(
    namespace: NamespaceId,
    secret: SecretId,
    recipient: RecipientId,
    generation: u64,
) -> IssueGrant {
    let peer = process().peer;

    IssueGrant {
        scope: Some(SecretRef {
            namespace: namespace.0.into(),
            secret: secret.0.into(),
            version: 0,
        }),
        recipient: recipient.0.into(),
        generation,
        uid: peer.uid,
        gid: peer.gid,
        pid: peer.pid,
        ttl_ms: 0,
        max_uses: 0,
        cgroup: String::new(),
    }
}

pub(crate) fn token(sealed: apollo_secretsd::delivery::SealedSecret) -> LockedBytes {
    apollo_secretsd::delivery::import(sealed.fd, 32, 32, &MemoryBudget::new(4096))
        .expect("sealed grant")
}

pub(crate) fn read_fd(fd: rustix::fd::OwnedFd) -> Vec<u8> {
    use std::io::Read;

    let mut out = Vec::new();

    std::fs::File::from(fd)
        .read_to_end(&mut out)
        .expect("authorized buffer");

    out
}
