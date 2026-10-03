//! Checked resource policy; no configurable authentication or durability bypass.
use crate::{Error, Result};
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct Limits {
    pub secret_bytes: usize,
    pub secrets_per_namespace: usize,
    pub versions_per_secret: usize,
    pub ciphertext_bytes: u64,
    pub namespaces: usize,
    pub recipients: usize,
    pub grants: usize,
    pub grant_ttl_ms: u32,
    pub grant_uses: u32,
    pub grants_per_second: u32,
    pub connections: usize,
    pub work_queue: usize,
    pub workers: usize,
    pub locked_bytes: usize,
    pub audit_records: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            secret_bytes: 1024 * 1024,
            secrets_per_namespace: 10000,
            versions_per_secret: 25000,
            ciphertext_bytes: 1024 * 1024 * 1024,
            namespaces: 10000,
            recipients: 10000,
            grants: 10000,
            grant_ttl_ms: 30000,
            grant_uses: 1,
            grants_per_second: 1000,
            connections: 128,
            work_queue: 32,
            workers: 2,
            locked_bytes: 16 * 1024 * 1024,
            audit_records: 10000000,
        }
    }
}

impl Limits {
    pub fn set(&mut self, name: &str, value: u64) -> Result<()> {
        macro_rules! size {
            ($field:ident) => {
                self.$field = usize::try_from(value).map_err(|_| Error::Invalid)?
            };
        }

        macro_rules! small {
            ($field:ident) => {
                self.$field = u32::try_from(value).map_err(|_| Error::Invalid)?
            };
        }

        match name {
            "secret-bytes" => size!(secret_bytes),
            "secrets-per-namespace" => size!(secrets_per_namespace),
            "versions-per-secret" => size!(versions_per_secret),
            "ciphertext-bytes" => self.ciphertext_bytes = value,
            "namespaces" => size!(namespaces),
            "recipients" => size!(recipients),
            "grants" => size!(grants),
            "grant-ttl-ms" => small!(grant_ttl_ms),
            "grant-uses" => small!(grant_uses),
            "grants-per-second" => small!(grants_per_second),
            "connections" => size!(connections),
            "work-queue" => size!(work_queue),
            "workers" => size!(workers),
            "locked-bytes" => size!(locked_bytes),
            "audit-records" => self.audit_records = value,
            _ => return Err(Error::Invalid),
        }

        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        if self.secret_bytes == 0
            || self.secret_bytes > 4 * 1024 * 1024
            || self.secrets_per_namespace == 0
            || self.versions_per_secret == 0
            || self.ciphertext_bytes < self.secret_bytes as u64
            || self.namespaces == 0
            || self.recipients == 0
            || self.grants == 0
            || self.grant_ttl_ms == 0
            || self.grant_ttl_ms > 300000
            || self.grant_uses == 0
            || self.grant_uses > 100
            || self.grants_per_second == 0
            || !(1..=512).contains(&self.connections)
            || !(1..=128).contains(&self.work_queue)
            || !(1..=4).contains(&self.workers)
            || self.locked_bytes < self.secret_bytes + 65536
            || self.audit_records == 0
            || self.namespaces > 10000
            || self.secrets_per_namespace > 100000
            || self.versions_per_secret > 100000
            || self.recipients > 20000
            || self.grants > 20000
            || self.grants_per_second > 100000
            || self.locked_bytes > 64 * 1024 * 1024
            || self.audit_records > 100000000
            || self.ciphertext_bytes > 1024 * 1024 * 1024 * 1024
        {
            return Err(Error::Invalid);
        }

        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct Config {
    pub state: PathBuf,
    pub runtime: PathBuf,
    pub admin_uids: Vec<u32>,
    pub limits: Limits,
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        self.limits.validate()?;

        if !self.state.is_absolute()
            || !self.runtime.is_absolute()
            || self.state == self.runtime
            || self.admin_uids.is_empty()
            || self.admin_uids.len() > 16
        {
            return Err(Error::Invalid);
        }

        Ok(())
    }
}
