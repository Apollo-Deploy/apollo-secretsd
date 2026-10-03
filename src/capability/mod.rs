//! Boot-local opaque capability table; no tokens, plaintext or DEKs are cached.
use crate::{Error, Result, config::Limits, crypto::Keys};
use secretsd_protocol::*;
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Peer {
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
    pub start_time: u64,
}

pub struct Grant {
    pub id: CapabilityId,
    pub namespace: NamespaceId,
    pub namespace_generation: NamespaceGeneration,
    pub secret: SecretId,
    pub version: SecretVersion,
    pub recipient: RecipientId,
    pub generation: RecipientGeneration,
    pub peer: Peer,
    pub cgroup: Option<String>,
    pub expires: Instant,
    pub remaining: u32,
    #[cfg(target_os = "linux")]
    pub process: std::sync::Arc<crate::auth::Process>,
}

pub struct Grants {
    entries: HashMap<[u8; 32], Grant>,
    maximum: usize,
    rate_limit: u32,
    rate_window: Instant,
    issued: u32,
    next_expiry: Option<Instant>,
}

impl Grants {
    pub fn new(limits: &Limits) -> Self {
        Self {
            entries: HashMap::new(),
            maximum: limits.grants,
            rate_limit: limits.grants_per_second,
            rate_window: Instant::now(),
            issued: 0,
            next_expiry: None,
        }
    }

    pub fn insert(&mut self, digest: [u8; 32], grant: Grant) -> Result<()> {
        self.expire();

        let now = Instant::now();

        if now.duration_since(self.rate_window) >= Duration::from_secs(1) {
            self.rate_window = now;

            self.issued = 0;
        }

        if self.entries.len() >= self.maximum || self.issued >= self.rate_limit {
            return Err(Error::Limit);
        }

        if grant.remaining == 0 || grant.expires <= now {
            return Err(Error::Invalid);
        }

        if self.entries.contains_key(&digest) {
            return Err(Error::Conflict);
        }

        self.next_expiry = Some(
            self.next_expiry
                .map_or(grant.expires, |next| next.min(grant.expires)),
        );

        self.entries.insert(digest, grant);

        self.issued += 1;

        Ok(())
    }

    /// Caller serializes this operation with durable state verification and audit.
    /// Consumed uses stay consumed even if subsequent audit, decrypt or send fails.
    pub fn consume(
        &mut self,
        keys: &Keys,
        token: &[u8; 32],
        peer: Peer,
        namespace: impl FnOnce(NamespaceId) -> Result<NamespaceGeneration>,
        recipient: impl FnOnce(RecipientId) -> Result<RecipientGeneration>,
        cgroup: Option<&str>,
    ) -> Result<Grant> {
        let digest = keys.grant_digest(token)?;

        let grant = self.entries.get_mut(&digest).ok_or(Error::Denied)?;

        #[cfg(target_os = "linux")]
        if !grant.process.alive()? {
            return Err(Error::Denied);
        }

        if grant.expires <= Instant::now()
            || grant.remaining == 0
            || grant.peer != peer
            || grant.namespace_generation != namespace(grant.namespace)?
            || grant.generation != recipient(grant.recipient)?
            || grant
                .cgroup
                .as_deref()
                .is_some_and(|expected| Some(expected) != cgroup)
        {
            return Err(Error::Denied);
        }

        grant.remaining -= 1;

        let authorized = Grant {
            id: grant.id,
            namespace: grant.namespace,
            namespace_generation: grant.namespace_generation,
            secret: grant.secret,
            version: grant.version,
            recipient: grant.recipient,
            generation: grant.generation,
            peer: grant.peer,
            cgroup: grant.cgroup.clone(),
            expires: grant.expires,
            remaining: grant.remaining,
            #[cfg(target_os = "linux")]
            process: std::sync::Arc::clone(&grant.process),
        };

        if grant.remaining == 0 {
            self.entries.remove(&digest);
        }

        Ok(authorized)
    }

    pub fn revoke_capability(&mut self, id: CapabilityId) {
        self.entries.retain(|_, g| g.id != id);
    }

    pub fn revoke_recipient(&mut self, id: RecipientId) {
        self.entries.retain(|_, g| g.recipient != id);
    }

    pub fn revoke_namespace(&mut self, id: NamespaceId) {
        self.entries.retain(|_, g| g.namespace != id);
    }

    pub fn expire(&mut self) {
        let now = Instant::now();

        if self.next_expiry.is_none_or(|expiry| expiry > now) {
            return;
        }

        self.entries.retain(|_, g| g.expires > now);

        self.next_expiry = self.entries.values().map(|g| g.expires).min();
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}
