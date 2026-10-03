//! Indexed authenticated reads; no plaintext or token cache.
use super::*;
use crate::{Error, Result, crypto::Keys};
use prost::Message;
use rusqlite::{OptionalExtension, params};

impl Store {
    pub fn keys(&self) -> &Keys {
        &self.keys
    }

    pub fn record<T: Message + Default>(&self, kind: i32, key: &[u8]) -> Result<T> {
        let row: Option<(Vec<u8>, Vec<u8>)> = self
            .db
            .query_row(
                "SELECT body,mac FROM records WHERE kind=?1 AND key=?2",
                params![kind, key],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;

        self.check_expected(kind, key, row.as_ref().map(|(_, tag)| tag.as_slice()))?;

        let (body, tag) = row.ok_or(Error::NotFound)?;

        self.keys
            .verify_state(&[&kind.to_be_bytes(), key, &body], &tag)?;

        T::decode(body.as_slice()).map_err(|_| Error::Integrity)
    }

    pub(super) fn check_expected(&self, kind: i32, key: &[u8], tag: Option<&[u8]>) -> Result<()> {
        if kind == HEADER {
            return Ok(());
        }

        let expected = self.expected.get(&(kind, key.to_vec())).map(Vec::as_slice);

        if expected != tag {
            return Err(Error::Integrity);
        }

        Ok(())
    }

    pub fn scan(&self, kind: i32, prefix: &[u8], limit: usize) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let mut stmt=self.db.prepare("SELECT key,body,mac FROM records WHERE kind=?1 AND substr(key,1,?2)=?3 ORDER BY key LIMIT ?4")?;

        let prefix_len = i64::try_from(prefix.len()).map_err(|_| Error::Limit)?;

        let row_limit =
            i64::try_from(limit.checked_add(1).ok_or(Error::Limit)?).map_err(|_| Error::Limit)?;

        let mut rows = stmt.query(params![kind, prefix_len, prefix, row_limit])?;

        let mut output = Vec::new();

        while let Some(row) = rows.next()? {
            if output.len() == limit {
                return Err(Error::Limit);
            }

            let key: Vec<u8> = row.get(0)?;

            let body: Vec<u8> = row.get(1)?;

            let tag: Vec<u8> = row.get(2)?;

            self.check_expected(kind, &key, Some(&tag))?;

            self.keys
                .verify_state(&[&kind.to_be_bytes(), &key, &body], &tag)?;

            output.push((key, body));
        }

        Ok(output)
    }

    pub fn ciphertext_bytes(&self) -> Result<u64> {
        Ok(self.header.ciphertext_bytes)
    }

    pub fn page(
        &self,
        kind: i32,
        prefix: &[u8],
        after: &[u8],
        limit: usize,
    ) -> Result<Vec<Vec<u8>>> {
        if limit == 0 || limit > 128 {
            return Err(Error::Invalid);
        }

        let mut statement=self.db.prepare("SELECT key,body,mac FROM records WHERE kind=?1 AND substr(key,1,?2)=?3 AND key>?4 ORDER BY key LIMIT ?5")?;

        let mut rows = statement.query(params![
            kind,
            prefix.len() as i64,
            prefix,
            after,
            limit as i64
        ])?;

        let mut keys = Vec::new();

        while let Some(row) = rows.next()? {
            let key: Vec<u8> = row.get(0)?;

            let body: Vec<u8> = row.get(1)?;

            let tag: Vec<u8> = row.get(2)?;

            self.check_expected(kind, &key, Some(&tag))?;

            self.keys
                .verify_state(&[&kind.to_be_bytes(), &key, &body], &tag)?;

            keys.push(key);
        }

        Ok(keys)
    }
}
