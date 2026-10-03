//! Immutable encrypted versions, durably activated in the same audited transaction.
use super::Service;
use crate::{
    Error, Result,
    capability::Peer,
    crypto::{self, EncryptedVersion, Scope},
    memory::LockedBytes,
    storage::*,
};
use prost::Message;
use secretsd_protocol::*;

impl Service {
    pub fn secret_put(
        &mut self,
        namespace: NamespaceId,
        id: Option<SecretId>,
        name: &str,
        payload: &LockedBytes,
        peer: Peer,
    ) -> Result<(SecretId, SecretVersion)> {
        self.namespace(namespace)?;

        if payload.is_empty() || payload.len() > self.limits.secret_bytes {
            return Err(Error::Limit);
        }

        let index = self.store.keys().name_index(&namespace.0, name)?;

        let is_update = id.is_some();

        let id = id.unwrap_or(SecretId(crypto::random_id()?));

        let key = secret_key(&namespace.0, &id.0);

        let existing = self.store.record::<SecretRecord>(SECRET, &key);

        let (mut meta, event) = match existing {
            Ok(meta) => {
                if meta.deleted {
                    return Err(Error::Denied);
                }

                if meta.name_index != index {
                    return Err(Error::Conflict);
                }

                (meta, EventKind::SecretVersion)
            }
            Err(Error::NotFound) => {
                if is_update {
                    return Err(Error::NotFound);
                }

                if self.store.count(SECRET, Some(&namespace.0)) >= self.limits.secrets_per_namespace
                {
                    return Err(Error::Limit);
                }

                let index_key = [namespace.0.as_slice(), index.as_slice()].concat();

                match self.store.record::<NameRecord>(NAME_INDEX, &index_key) {
                    Ok(_) => return Err(Error::Conflict),
                    Err(Error::NotFound) => {}
                    Err(e) => return Err(e),
                }

                (
                    SecretRecord {
                        latest: 0,
                        active: 0,
                        enabled: true,
                        name_index: index.to_vec(),
                        deleted: false,
                    },
                    EventKind::SecretCreate,
                )
            }
            Err(e) => return Err(e),
        };

        if meta.latest >= self.limits.versions_per_secret as u64 {
            return Err(Error::Limit);
        }

        let version = SecretVersion(meta.latest.checked_add(1).ok_or(Error::Limit)?);

        let (kek_id, kek) = self.store.active_kek()?;

        let encrypted = crypto::encrypt_version(
            Scope {
                namespace,
                secret: id,
                version,
            },
            &kek_id,
            kek,
            payload,
            name,
            &self.store.keys().budget,
        )?;

        let bytes = encrypted.encoded_len() as u64;

        if self
            .store
            .ciphertext_bytes()?
            .checked_add(bytes)
            .ok_or(Error::Limit)?
            > self.limits.ciphertext_bytes
        {
            return Err(Error::Limit);
        }

        meta.latest = version.0;

        meta.active = version.0;

        meta.enabled = true;

        self.store.commit(
            AuditEvent::new(event, &namespace.0, &id.0, peer.uid, peer.pid),
            &[
                Change::put(
                    VERSION,
                    &version_key(&namespace.0, &id.0, version.0),
                    &encrypted,
                ),
                Change::put(SECRET, &key, &meta),
                Change::put(
                    NAME_INDEX,
                    &[namespace.0.as_slice(), index.as_slice()].concat(),
                    &NameRecord {
                        secret: id.0.into(),
                    },
                ),
            ],
            None,
        )?;

        Ok((id, version))
    }

    pub fn resolve(&self, namespace: NamespaceId, id: SecretId, version: u64) -> Result<Scope> {
        self.namespace(namespace)?;

        let meta: SecretRecord = self
            .store
            .record(SECRET, &secret_key(&namespace.0, &id.0))?;

        if !meta.enabled || meta.deleted {
            return Err(Error::Denied);
        }

        let version = if version == 0 { meta.active } else { version };

        if version == 0 || version > meta.latest {
            return Err(Error::NotFound);
        }

        let _: EncryptedVersion = self
            .store
            .record(VERSION, &version_key(&namespace.0, &id.0, version))?;

        Ok(Scope {
            namespace,
            secret: id,
            version: SecretVersion(version),
        })
    }

    pub(crate) fn secret_material(&self, scope: Scope, metadata: bool) -> Result<LockedBytes> {
        let record: EncryptedVersion = self.store.record(
            VERSION,
            &version_key(&scope.namespace.0, &scope.secret.0, scope.version.0),
        )?;

        let kek = self.store.kek(&record.kek_id)?;

        crypto::decrypt_version(scope, &record, kek, metadata, &self.store.keys().budget)
    }

    pub fn secret_metadata(&self, namespace: NamespaceId, id: SecretId) -> Result<Entry> {
        self.namespace(namespace)?;

        let meta: SecretRecord = self
            .store
            .record(SECRET, &secret_key(&namespace.0, &id.0))?;

        let name = self.secret_material(
            Scope {
                namespace,
                secret: id,
                version: SecretVersion(meta.active),
            },
            true,
        )?;

        let name = std::str::from_utf8(name.as_slice())
            .map_err(|_| Error::Integrity)?
            .to_owned();

        Ok(Entry {
            id: id.0.to_vec(),
            version: meta.active,
            name,
            enabled: meta.enabled,
        })
    }

    pub fn secret_list(
        &self,
        namespace: NamespaceId,
        after: Option<SecretId>,
        limit: usize,
    ) -> Result<Vec<Entry>> {
        self.namespace(namespace)?;

        let mut entries = Vec::new();

        let after = after
            .map(|id| secret_key(&namespace.0, &id.0))
            .unwrap_or_default();

        for key in self.store.page(SECRET, &namespace.0, &after, limit)? {
            if key.len() != 32 {
                return Err(Error::Integrity);
            }

            entries.push(self.secret_metadata(namespace, SecretId::try_from(&key[16..])?)?);
        }

        Ok(entries)
    }

    pub fn secret_change(&mut self, scope: Scope, action: EventKind, peer: Peer) -> Result<()> {
        self.namespace(scope.namespace)?;

        let key = secret_key(&scope.namespace.0, &scope.secret.0);

        let mut meta: SecretRecord = self.store.record(SECRET, &key)?;

        if meta.deleted {
            return Err(Error::Denied);
        }

        match action {
            EventKind::SecretActivate => {
                let _: EncryptedVersion = self.store.record(
                    VERSION,
                    &version_key(&scope.namespace.0, &scope.secret.0, scope.version.0),
                )?;

                if scope.version.0 == 0 {
                    return Err(Error::Invalid);
                }

                meta.active = scope.version.0;

                meta.enabled = true;
            }
            EventKind::SecretDisable => meta.enabled = false,
            EventKind::SecretDelete => {
                meta.enabled = false;

                meta.deleted = true;
            }
            _ => return Err(Error::Invalid),
        }

        self.store.commit(
            AuditEvent::new(
                action,
                &scope.namespace.0,
                &scope.secret.0,
                peer.uid,
                peer.pid,
            ),
            &[Change::put(SECRET, &key, &meta)],
            None,
        )?;

        // Pinned grants are checked against enablement again on every redemption.
        Ok(())
    }
}
