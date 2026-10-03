//! Quota counters derived only from authenticated committed record transitions.
use super::*;
use std::collections::HashMap;

pub(super) type Counts = HashMap<(i32, [u8; 16]), usize>;

pub(super) fn adjust(counts: &mut Counts, kind: i32, key: &[u8], add: bool) {
    let mut prefixes = vec![[0; 16]];

    if matches!(kind, SECRET | VERSION | NAME_INDEX) && key.len() >= 16 {
        let mut namespace = [0; 16];

        namespace.copy_from_slice(&key[..16]);

        prefixes.push(namespace);
    }

    for prefix in prefixes {
        let count = counts.entry((kind, prefix)).or_default();

        if add {
            *count += 1;
        } else {
            *count -= 1;
        }

        if *count == 0 {
            counts.remove(&(kind, prefix));
        }
    }
}

impl Store {
    pub fn count(&self, kind: i32, namespace: Option<&[u8; 16]>) -> usize {
        self.counts
            .get(&(kind, namespace.copied().unwrap_or([0; 16])))
            .copied()
            .unwrap_or(0)
    }

    pub(super) fn load_counts(&mut self) {
        self.counts.clear();

        for (kind, key) in self.expected.keys() {
            adjust(&mut self.counts, *kind, key, true);
        }
    }
}
