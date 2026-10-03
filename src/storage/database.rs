//! `SQLite` FULL transactions authenticate state and append mandatory audit together.
use super::*;
use crate::{Error, Result, crypto::Keys, filesystem::SecureDir, memory::LockedBytes};
use prost::Message;
use rusqlite::{Connection, OptionalExtension, params};
use rustix::fd::OwnedFd;
use std::{
    collections::{BTreeMap, HashMap},
    time::Duration,
};

pub(super) const MAX_RECORDS: usize = 100_000;

pub(super) type RecordTags = HashMap<(i32, Vec<u8>), Vec<u8>>;

pub struct Change {
    pub kind: i32,
    pub key: Vec<u8>,
    pub body: Option<Vec<u8>>,
}

impl Change {
    pub fn put(kind: i32, key: &[u8], value: &impl Message) -> Self {
        Self {
            kind,
            key: key.into(),
            body: Some(value.encode_to_vec()),
        }
    }

    pub fn delete(kind: i32, key: &[u8]) -> Self {
        Self {
            kind,
            key: key.into(),
            body: None,
        }
    }
}

pub struct Store {
    pub(crate) db: Connection,
    pub(crate) keys: Keys,
    pub(crate) header: Header,
    pub(crate) keks: BTreeMap<[u8; 16], LockedBytes>,
    pub(crate) audit_maximum: u64,
    pub(super) expected: RecordTags,
    pub(super) counts: super::counts::Counts,
    directory: SecureDir,
    _lock: OwnedFd,
}

impl Store {
    pub fn open(directory: SecureDir, keys: Keys, audit_maximum: u64) -> Result<Self> {
        let lock = directory.lock("daemon.lock")?;

        let _database = directory.file("state.sqlite3", true)?;

        for name in ["state.sqlite3-wal", "state.sqlite3-shm"] {
            // Reject existing unsafe sidecars before SQLite can open them.
            match directory.file(name, false) {
                Ok(_) | Err(Error::Sys(rustix::io::Errno::NOENT)) => {}
                Err(e) => return Err(e),
            }
        }

        let db = Connection::open(directory.proc_path("state.sqlite3")?)?;

        // Cap hostile on-disk columns before SQLite/Rust allocate their bodies.
        db.set_limit(
            rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH,
            4 * 1024 * 1024 + 4096,
        )?;

        db.busy_timeout(Duration::from_millis(250))?;

        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
            PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF; PRAGMA mmap_size=0;
            PRAGMA cache_size=-1024; PRAGMA temp_store=MEMORY;
            CREATE TABLE IF NOT EXISTS records(kind INTEGER NOT NULL,key BLOB NOT NULL,
                body BLOB NOT NULL,mac BLOB NOT NULL,PRIMARY KEY(kind,key)) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS audit(sequence INTEGER PRIMARY KEY,body BLOB NOT NULL,mac BLOB NOT NULL);
            CREATE INDEX IF NOT EXISTS record_namespace ON records(kind,substr(key,1,16));")?;

        let check: String = db.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;

        if check != "ok" {
            return Err(Error::Integrity);
        }

        let header = read::<Header>(&db, &keys, HEADER, b"header");

        let mut store = match header {
            Ok(header) if header.format == FORMAT => Self {
                db,
                keys,
                header,
                keks: BTreeMap::new(),
                audit_maximum,
                expected: HashMap::new(),
                counts: HashMap::new(),
                directory,
                _lock: lock,
            },
            Err(Error::NotFound) => {
                let count: i64 = db.query_row(
                    "SELECT (SELECT count(*) FROM records)+(SELECT count(*) FROM audit)",
                    [],
                    |r| r.get(0),
                )?;

                if count != 0 {
                    return Err(Error::Integrity);
                }

                let header = Header {
                    format: FORMAT,
                    audit_tip: vec![0; 32],
                    ..Header::default()
                };

                Self {
                    db,
                    keys,
                    header,
                    keks: BTreeMap::new(),
                    audit_maximum,
                    expected: HashMap::new(),
                    counts: HashMap::new(),
                    directory,
                    _lock: lock,
                }
            }
            _ => return Err(Error::Integrity),
        };

        if store.header.active_kek.is_empty() {
            store.initialize_keyring()?;
        }

        store.expected = store.authenticated_state()?;

        store.load_counts();

        store.verify_all()?;

        store.load_keyring()?;

        store.commit(
            AuditEvent::new(EventKind::Startup, &[], &[], 0, 0),
            &[],
            None,
        )?;

        store.directory.sync()?;

        Ok(store)
    }

    pub fn commit(
        &mut self,
        mut event: AuditEvent,
        changes: &[Change],
        header: Option<Header>,
    ) -> Result<()> {
        if changes.len() > 64 || !event.changes.is_empty() {
            return Err(Error::Invalid);
        }

        let mut transitions = Vec::with_capacity(changes.len());

        for change in changes {
            let tag = match &change.body {
                Some(body) => self
                    .keys
                    .state_mac(&[&change.kind.to_be_bytes(), &change.key, body])?
                    .to_vec(),
                None => Vec::new(),
            };

            transitions.push(StateChange {
                kind: change.kind,
                key: change.key.clone(),
                tag,
            });
        }

        event.changes = transitions.clone();

        let tx = self
            .db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

        let mut next = header.unwrap_or_else(|| self.header.clone());

        // The caller cannot alter the authenticated quota checkpoint.
        if next.ciphertext_bytes != self.header.ciphertext_bytes {
            return Err(Error::Invalid);
        }

        // Detect live tampering of the authenticated checkpoint too.
        match read::<Header>(&tx, &self.keys, HEADER, b"header") {
            Ok(current) if current == self.header => {}
            Err(Error::NotFound) if self.header.audit_sequence == 0 => {}
            _ => return Err(Error::Integrity),
        }

        for change in changes {
            if change.kind == HEADER {
                return Err(Error::Invalid);
            }

            let old: Option<(Vec<u8>, Vec<u8>)> = tx
                .query_row(
                    "SELECT body,mac FROM records WHERE kind=?1 AND key=?2",
                    params![change.kind, change.key],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;

            let expected = self
                .expected
                .get(&(change.kind, change.key.clone()))
                .map(Vec::as_slice);

            if expected != old.as_ref().map(|(_, tag)| tag.as_slice()) {
                return Err(Error::Integrity);
            }

            if let Some((body, tag)) = &old {
                self.keys
                    .verify_state(&[&change.kind.to_be_bytes(), &change.key, body], tag)?;
            }

            if change.kind == VERSION {
                next.ciphertext_bytes = next
                    .ciphertext_bytes
                    .checked_sub(old.as_ref().map_or(0, |(body, _)| body.len() as u64))
                    .and_then(|n| {
                        n.checked_add(change.body.as_ref().map_or(0, |body| body.len() as u64))
                    })
                    .ok_or(Error::Integrity)?;
            }

            if old.is_none()
                && change.body.is_some()
                && self.expected.len() + changes.len() > MAX_RECORDS
            {
                return Err(Error::Limit);
            }

            if let Some(body) = &change.body {
                write(&tx, &self.keys, change.kind, &change.key, body)?;
            } else {
                tx.execute(
                    "DELETE FROM records WHERE kind=?1 AND key=?2",
                    params![change.kind, change.key],
                )?;
            }
        }

        super::journal::append(&tx, &self.keys, &mut next, event, self.audit_maximum)?;

        write(&tx, &self.keys, HEADER, b"header", &next.encode_to_vec())?;

        tx.commit()?;

        self.header = next;

        for change in transitions {
            let key = (change.kind, change.key);

            if change.tag.is_empty() {
                if self.expected.remove(&key).is_some() {
                    super::counts::adjust(&mut self.counts, key.0, &key.1, false);
                }
            } else {
                if self.expected.insert(key.clone(), change.tag).is_none() {
                    super::counts::adjust(&mut self.counts, key.0, &key.1, true);
                }
            }
        }

        Ok(())
    }

    pub fn verify_all(&self) -> Result<()> {
        let mut stmt = self
            .db
            .prepare("SELECT kind,key,body,mac FROM records ORDER BY kind,key")?;

        let mut rows = stmt.query([])?;

        let mut count = 0;

        let mut ciphertext_bytes = 0u64;

        while let Some(row) = rows.next()? {
            let kind: i32 = row.get(0)?;

            let key: Vec<u8> = row.get(1)?;

            let body: Vec<u8> = row.get(2)?;

            let tag: Vec<u8> = row.get(3)?;

            if kind != HEADER {
                self.check_expected(kind, &key, Some(&tag))?;

                count += 1;
            }

            self.keys
                .verify_state(&[&kind.to_be_bytes(), &key, &body], &tag)?;

            if !(HEADER..=NAME_INDEX).contains(&kind) {
                return Err(Error::Integrity);
            }

            if kind == VERSION {
                ciphertext_bytes = ciphertext_bytes
                    .checked_add(body.len() as u64)
                    .ok_or(Error::Integrity)?;
            }
        }

        if count != self.expected.len() || ciphertext_bytes != self.header.ciphertext_bytes {
            return Err(Error::Integrity);
        }

        self.verify_audit()
    }
}

pub(crate) fn read<T: Message + Default>(
    db: &Connection,
    keys: &Keys,
    kind: i32,
    key: &[u8],
) -> Result<T> {
    let row: Option<(Vec<u8>, Vec<u8>)> = db
        .query_row(
            "SELECT body,mac FROM records WHERE kind=?1 AND key=?2",
            params![kind, key],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;

    let (body, tag) = row.ok_or(Error::NotFound)?;

    keys.verify_state(&[&kind.to_be_bytes(), key, &body], &tag)?;

    T::decode(body.as_slice()).map_err(|_| Error::Integrity)
}

fn write(db: &Connection, keys: &Keys, kind: i32, key: &[u8], body: &[u8]) -> Result<()> {
    let tag = keys.state_mac(&[&kind.to_be_bytes(), key, body])?;

    db.execute("INSERT INTO records VALUES(?1,?2,?3,?4) ON CONFLICT(kind,key) DO UPDATE SET body=excluded.body,mac=excluded.mac",
        params![kind,key,body,tag.as_slice()])?;

    Ok(())
}
