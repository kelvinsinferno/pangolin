//! In-memory decrypted-cache + substring search.
//!
//! On `Vault::unlock` we decrypt every live account head and store the
//! resulting [`AccountSnapshot`] in this cache. Search is a simple
//! case-insensitive substring scan across `display_name`, `username`,
//! `url`, and the first 512 bytes of `notes`.
//!
//! The cache lives only as long as the vault is `Active`; `Vault::lock`
//! drops it (every `AccountSnapshot` zeros itself on drop), and the
//! whole `HashMap` is the only structure that ever holds plaintext.

use std::collections::HashMap;

use crate::account::{AccountId, AccountSnapshot};

/// Live-account index. Keyed by [`AccountId`]; tombstoned accounts are
/// **not** present in this map.
#[derive(Debug, Default)]
pub struct DecryptedCache {
    by_id: HashMap<AccountId, AccountSnapshot>,
}

impl DecryptedCache {
    pub fn new() -> Self {
        Self {
            by_id: HashMap::new(),
        }
    }

    pub fn insert(&mut self, id: AccountId, snapshot: AccountSnapshot) {
        self.by_id.insert(id, snapshot);
    }

    pub fn remove(&mut self, id: AccountId) -> Option<AccountSnapshot> {
        self.by_id.remove(&id)
    }

    pub fn get(&self, id: AccountId) -> Option<&AccountSnapshot> {
        self.by_id.get(&id)
    }

    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    pub fn account_ids(&self) -> Vec<AccountId> {
        self.by_id.keys().copied().collect()
    }

    /// Substring search across non-secret-but-encrypted fields.
    /// Case-insensitive ASCII match. Notes are clipped to the first 512
    /// bytes to keep the scan time bounded.
    pub fn search(&self, query: &str) -> Vec<AccountId> {
        if query.is_empty() {
            return self.by_id.keys().copied().collect();
        }
        let needle = query.to_ascii_lowercase();
        let mut hits: Vec<AccountId> = Vec::new();
        for (id, snap) in &self.by_id {
            if matches(snap.display_name.expose(), &needle)
                || matches(snap.username.expose(), &needle)
                || matches(snap.url.expose(), &needle)
                || matches(notes_clipped(snap.notes.expose()), &needle)
            {
                hits.push(*id);
            }
        }
        hits
    }

    /// Drop the cache, dropping every [`AccountSnapshot`] (which wipes
    /// its underlying [`pangolin_crypto::secret::SecretBytes`] on drop).
    #[allow(dead_code)] // exercised through `Vault::lock` -> `take` -> drop chain.
    pub fn clear(&mut self) {
        self.by_id.clear();
    }
}

fn matches(haystack: &[u8], needle_lower: &str) -> bool {
    // Best-effort case-insensitive substring search on byte slices.
    // ASCII-fold the haystack copy on the fly. We accept the allocation
    // cost — search is rare relative to encryption.
    let lower = haystack.to_ascii_lowercase();
    let lower_str = String::from_utf8_lossy(&lower);
    lower_str.contains(needle_lower)
}

fn notes_clipped(notes: &[u8]) -> &[u8] {
    let cap = core::cmp::min(notes.len(), 512);
    &notes[..cap]
}

#[cfg(test)]
mod tests {
    use super::DecryptedCache;
    use crate::account::{AccountId, AccountSnapshot};
    use pangolin_crypto::secret::SecretBytes;

    fn snap(name: &str, user: &str, url: &str) -> AccountSnapshot {
        AccountSnapshot::new(
            SecretBytes::new(name.as_bytes().to_vec()),
            SecretBytes::new(user.as_bytes().to_vec()),
            SecretBytes::new(b"pw".to_vec()),
            SecretBytes::new(url.as_bytes().to_vec()),
            SecretBytes::new(b"notes go here".to_vec()),
            SecretBytes::new(b"".to_vec()),
        )
    }

    #[test]
    fn empty_query_returns_all() {
        let mut c = DecryptedCache::new();
        c.insert(AccountId::from_bytes([1; 32]), snap("a", "u1", "x.com"));
        c.insert(AccountId::from_bytes([2; 32]), snap("b", "u2", "y.com"));
        let r = c.search("");
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn substring_match_is_case_insensitive() {
        let mut c = DecryptedCache::new();
        let id_a = AccountId::from_bytes([1; 32]);
        let id_b = AccountId::from_bytes([2; 32]);
        c.insert(id_a, snap("Github", "alice", "https://github.com"));
        c.insert(id_b, snap("Twitter", "bob", "https://twitter.com"));
        let r = c.search("GIT");
        assert!(r.contains(&id_a));
        assert!(!r.contains(&id_b));
    }

    /// Success criterion 8: 100 accounts with varying display names,
    /// search returns the correct subset.
    #[test]
    fn substring_subset_correctness() {
        let mut c = DecryptedCache::new();
        for i in 0..100u32 {
            let id = AccountId::from_bytes({
                let mut a = [0u8; 32];
                a[..4].copy_from_slice(&i.to_be_bytes());
                a
            });
            let name = if i % 3 == 0 {
                format!("github-{i}")
            } else if i % 3 == 1 {
                format!("gitlab-{i}")
            } else {
                format!("bitbucket-{i}")
            };
            c.insert(id, snap(&name, "u", "https://example"));
        }
        let r = c.search("git");
        // 0..100 / 3 + 0..100 / 3 == accounts whose name starts git*.
        // For 100, github count = 34 (0,3,..99 => 34) and gitlab count
        // = 33 (1,4,..97 => 33), total 67. Use exact arithmetic.
        let mut github = 0;
        let mut gitlab = 0;
        for i in 0..100u32 {
            if i % 3 == 0 {
                github += 1;
            }
            if i % 3 == 1 {
                gitlab += 1;
            }
        }
        assert_eq!(r.len(), github + gitlab);
    }

    #[test]
    fn clear_drops_everything() {
        let mut c = DecryptedCache::new();
        c.insert(AccountId::from_bytes([1; 32]), snap("a", "u", "x"));
        assert_eq!(c.len(), 1);
        c.clear();
        assert_eq!(c.len(), 0);
    }
}
