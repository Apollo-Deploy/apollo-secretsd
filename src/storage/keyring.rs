//! Durable random KEKs wrapped by the provider root; batched resumable rewrapping.
use super::*;
use crate::{
    Error, Result,
    crypto::{self, EncryptedVersion, Scope},
    memory::LockedBytes,
};
use prost::Message;
use secretsd_protocol::{NamespaceId, SecretId, SecretVersion};

fn aad(id: &[u8; 16]) -> Vec<u8> {
    [b"apollo-secretsd/kek/1/xchacha20poly1305/".as_slice(), id].concat()
}

impl Store {
    pub(super) fn initialize_keyring(&mut self) -> Result<()> {
        let id = crypto::random_id()?;

        let kek = LockedBytes::random(32, &self.keys.budget)?;

        let wrapped = crypto::envelope::seal(
            &self.keys.root,
            kek.as_slice(),
            &aad(&id),
            &self.keys.budget,
        )?;

        let record = KeyRecord {
            wrapped: Some(wrapped),
        };

        let mut header = self.header.clone();

        header.active_kek = id.to_vec();

        self.commit(
            AuditEvent::new(EventKind::KeyLoad, &[], &id, 0, 0),
            &[Change::put(KEK, &id, &record)],
            Some(header),
        )?;

        Ok(())
    }

    pub(super) fn load_keyring(&mut self) -> Result<()> {
        for (id, body) in self.scan(KEK, &[], 2)? {
            let id: [u8; 16] = id.as_slice().try_into().map_err(|_| Error::Integrity)?;

            let record = KeyRecord::decode(body.as_slice()).map_err(|_| Error::Integrity)?;

            let kek = crypto::envelope::open(
                &self.keys.root,
                record.wrapped.as_ref().ok_or(Error::Integrity)?,
                &aad(&id),
                &self.keys.budget,
            )?;

            if kek.len() != 32 {
                return Err(Error::Integrity);
            }

            self.keks.insert(id, kek);
        }

        let active: [u8; 16] = self
            .header
            .active_kek
            .as_slice()
            .try_into()
            .map_err(|_| Error::Integrity)?;

        if !self.keks.contains_key(&active) {
            return Err(Error::Integrity);
        }

        if !self.header.rotating_from.is_empty() {
            let old: [u8; 16] = self
                .header
                .rotating_from
                .as_slice()
                .try_into()
                .map_err(|_| Error::Integrity)?;

            if old == active || !self.keks.contains_key(&old) {
                return Err(Error::Integrity);
            }
        }

        Ok(())
    }

    pub fn active_kek(&self) -> Result<([u8; 16], &LockedBytes)> {
        let id = self
            .header
            .active_kek
            .as_slice()
            .try_into()
            .map_err(|_| Error::Integrity)?;

        Ok((id, self.keks.get(&id).ok_or(Error::Integrity)?))
    }

    pub fn kek(&self, id: &[u8]) -> Result<&LockedBytes> {
        let id: [u8; 16] = id.try_into().map_err(|_| Error::Integrity)?;

        self.keks.get(&id).ok_or(Error::Integrity)
    }

    pub fn rotation_pending(&self) -> bool {
        !self.header.rotating_from.is_empty()
    }

    pub fn begin_rotation(&mut self, uid: u32, pid: u32) -> Result<[u8; 16]> {
        if self.rotation_pending() {
            return Err(Error::Conflict);
        }

        let id = crypto::random_id()?;

        let kek = LockedBytes::random(32, &self.keys.budget)?;

        let wrapped = crypto::envelope::seal(
            &self.keys.root,
            kek.as_slice(),
            &aad(&id),
            &self.keys.budget,
        )?;

        let mut header = self.header.clone();

        header.rotating_from = std::mem::replace(&mut header.active_kek, id.to_vec());

        header.rotation_cursor.clear();

        self.commit(
            AuditEvent::new(EventKind::RotationBegin, &[], &id, uid, pid),
            &[Change::put(
                KEK,
                &id,
                &KeyRecord {
                    wrapped: Some(wrapped),
                },
            )],
            Some(header),
        )?;

        self.keks.insert(id, kek);

        Ok(id)
    }

    /// One bounded batch per call. Service schedules this between ordinary requests.
    pub fn rotate_batch(&mut self, limit: usize) -> Result<bool> {
        if !self.rotation_pending() {
            return Ok(true);
        }

        if limit == 0 || limit > 64 {
            return Err(Error::Invalid);
        }

        let old_id: [u8; 16] = self
            .header
            .rotating_from
            .as_slice()
            .try_into()
            .map_err(|_| Error::Integrity)?;

        let (new_id, new) = self.active_kek()?;

        let old = self.kek(&old_id)?;

        let mut changes = Vec::new();

        let mut header = self.header.clone();

        let mut visited = 0;

        // Stream rows; only at most limit ciphertext records enter memory.
        let mut statement = self.db.prepare(
            "SELECT key,body,mac FROM records WHERE kind=3 AND key>?1 ORDER BY key LIMIT ?2",
        )?;

        let mut rows =
            statement.query(rusqlite::params![self.header.rotation_cursor, limit as i64])?;

        while let Some(row) = rows.next()? {
            let key: Vec<u8> = row.get(0)?;

            let body: Vec<u8> = row.get(1)?;

            let tag: Vec<u8> = row.get(2)?;

            self.check_expected(VERSION, &key, Some(&tag))?;

            self.keys
                .verify_state(&[&VERSION.to_be_bytes(), &key, &body], &tag)?;

            let mut record =
                EncryptedVersion::decode(body.as_slice()).map_err(|_| Error::Integrity)?;

            if key.len() != 40 {
                return Err(Error::Integrity);
            }

            header.rotation_cursor = key.clone();

            visited += 1;

            if record.kek_id == new_id {
                continue;
            }

            if record.kek_id != old_id {
                return Err(Error::Integrity);
            }

            let scope = Scope {
                namespace: NamespaceId::try_from(&key[..16])?,
                secret: SecretId::try_from(&key[16..32])?,
                version: SecretVersion(u64::from_be_bytes(
                    key[32..].try_into().map_err(|_| Error::Integrity)?,
                )),
            };

            crypto::rewrap(scope, &mut record, old, &new_id, new, &self.keys.budget)?;

            changes.push(Change::put(VERSION, &key, &record));
        }

        drop(rows);

        drop(statement);

        if visited != 0 {
            self.commit(
                AuditEvent::new(EventKind::RotationBatch, &[], &new_id, 0, 0),
                &changes,
                Some(header),
            )?;

            return Ok(false);
        }

        let mut header = self.header.clone();

        header.rotating_from.clear();

        header.rotation_cursor.clear();

        self.commit(
            AuditEvent::new(EventKind::RotationComplete, &[], &new_id, 0, 0),
            &[Change::delete(KEK, &old_id)],
            Some(header),
        )?;

        self.keks.remove(&old_id);

        Ok(true)
    }
}
