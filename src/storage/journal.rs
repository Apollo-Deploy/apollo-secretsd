//! Metadata-only authenticated audit; state and journal share one FULL transaction.
use super::*;
use crate::{Error, Result, crypto::Keys};
use prost::Message;
use rusqlite::{Connection, params};
use std::time::{SystemTime, UNIX_EPOCH};

pub(super) fn append(
    db: &Connection,
    keys: &Keys,
    header: &mut Header,
    mut event: AuditEvent,
    maximum: u64,
) -> Result<()> {
    if header.audit_sequence >= maximum {
        return Err(Error::Limit);
    }

    event.sequence = header.audit_sequence.checked_add(1).ok_or(Error::Limit)?;

    event.timestamp_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Invalid)?
        .as_nanos()
        .try_into()
        .map_err(|_| Error::Limit)?;

    event.previous = header.audit_tip.clone();

    if event.namespace.len() > 16 || event.object.len() > 40 {
        return Err(Error::Invalid);
    }

    let body = event.encode_to_vec();

    let tag = keys.audit_mac(&[&event.sequence.to_be_bytes(), &body])?;

    let sql_sequence = i64::try_from(event.sequence).map_err(|_| Error::Limit)?;

    db.execute(
        "INSERT INTO audit VALUES(?1,?2,?3)",
        params![sql_sequence, body, tag.as_slice()],
    )?;

    header.audit_sequence = event.sequence;

    header.audit_tip = tag.to_vec();

    Ok(())
}

impl Store {
    pub fn verify_audit(&self) -> Result<()> {
        if self.authenticated_state()? != self.expected {
            return Err(Error::Integrity);
        }

        Ok(())
    }

    pub(super) fn authenticated_state(&self) -> Result<super::database::RecordTags> {
        let mut expected = super::database::RecordTags::new();

        let mut statement = self
            .db
            .prepare("SELECT sequence,body,mac FROM audit ORDER BY sequence")?;

        let mut rows = statement.query([])?;

        let mut previous = vec![0; 32];

        let mut sequence = 0u64;

        while let Some(row) = rows.next()? {
            let seq = u64::try_from(row.get::<_, i64>(0)?).map_err(|_| Error::Integrity)?;

            let body: Vec<u8> = row.get(1)?;

            let tag: Vec<u8> = row.get(2)?;

            sequence = sequence.checked_add(1).ok_or(Error::Integrity)?;

            if seq != sequence {
                return Err(Error::Integrity);
            }

            self.keys.verify_audit(&[&seq.to_be_bytes(), &body], &tag)?;

            let event = AuditEvent::decode(body.as_slice()).map_err(|_| Error::Integrity)?;

            if event.sequence != seq
                || event.previous != previous
                || EventKind::try_from(event.kind).is_err()
            {
                return Err(Error::Integrity);
            }

            previous = tag;

            if event.changes.len() > 64 {
                return Err(Error::Integrity);
            }

            for change in event.changes {
                if !(NAMESPACE..=NAME_INDEX).contains(&change.kind)
                    || change.key.is_empty()
                    || change.key.len() > 48
                    || (!change.tag.is_empty() && change.tag.len() != 32)
                {
                    return Err(Error::Integrity);
                }

                let key = (change.kind, change.key);

                if change.tag.is_empty() {
                    expected.remove(&key);
                } else {
                    expected.insert(key, change.tag);
                }

                if expected.len() > super::database::MAX_RECORDS {
                    return Err(Error::Limit);
                }
            }
        }

        if sequence != self.header.audit_sequence || previous != self.header.audit_tip {
            return Err(Error::Integrity);
        }

        Ok(expected)
    }

    pub fn audit_tail(&self, after: u64, limit: usize) -> Result<Vec<AuditEvent>> {
        if limit == 0 || limit > 128 {
            return Err(Error::Invalid);
        }

        // Verify the complete chain and read the page in one SQLite snapshot.
        // A gap outside this page must fail closed; concurrent writers cannot
        // replace rows between verification and the bounded page query.
        let _snapshot = self.db.unchecked_transaction()?;

        self.verify_audit()?;

        let mut statement = self.db.prepare(
            "SELECT sequence,body,mac FROM audit WHERE sequence>?1 ORDER BY sequence LIMIT ?2",
        )?;

        let after = i64::try_from(after).map_err(|_| Error::Invalid)?;

        let limit = i64::try_from(limit).map_err(|_| Error::Limit)?;

        let mut rows = statement.query(params![after, limit])?;

        let mut events = Vec::new();

        while let Some(row) = rows.next()? {
            let seq = u64::try_from(row.get::<_, i64>(0)?).map_err(|_| Error::Integrity)?;

            let body: Vec<u8> = row.get(1)?;

            let tag: Vec<u8> = row.get(2)?;

            self.keys.verify_audit(&[&seq.to_be_bytes(), &body], &tag)?;

            events.push(AuditEvent::decode(body.as_slice()).map_err(|_| Error::Integrity)?);
        }

        Ok(events)
    }
}
