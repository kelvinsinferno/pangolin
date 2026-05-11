// SPDX-License-Identifier: AGPL-3.0-or-later
//! Search plumbing — the `:memory:` FTS5 index (MVP-1 issue 1.3) plus
//! the legacy in-memory `DecryptedCache` substring scan still used by
//! the V0 read paths.
//!
//! ## The `:memory:` FTS5 index ([`SearchIndex`])
//!
//! Per `docs/issue-plans/1.3.md` Q2 (locked), the searchable plaintext
//! projection of every live account — `display_name`, the canonical
//! `tags`, and the `host_str()`-derived `hostnames` of each URL — lives
//! **only in RAM** for the lifetime of an unlocked session. It is built
//! from the decrypted account blobs on `Vault::unlock`, kept in sync
//! from `account_add` / `account_update` / `delete_account` (and the V0
//! shims), and dropped (`SQLite` frees the memory) on `lock()` /
//! `close()`. Nothing extra hits disk — the persisted blob payload stays
//! AEAD-sealed, so the existing `no_plaintext_on_disk` proptest is
//! unaffected.
//!
//! **Whitelist (structural, NOT policy).** The FTS5 schema has columns
//! for `display_name`, `tags`, and `hostnames` only. `usernames`, full
//! URLs, `notes`, `password_history`, and `totp_secret` are **never**
//! written to the index — they are not columns, so a future refactor
//! cannot accidentally start indexing them without an obvious schema
//! change. Master plan §4 row 1.3: "FTS5 on non-secret fields only —
//! name, tags, hostnames; never on usernames/passwords." Do NOT add a
//! column for any of those fields.
//!
//! **Accepted limitation.** `SQLite`'s internal FTS5 buffers hold the
//! lowercased projection strings in plaintext and cannot be zeroized;
//! that is intrinsic to using `SQLite` for the index. The intermediate
//! Rust `String`s we build are zeroized after they are handed to the
//! connection. Tearing down the `:memory:` connection on lock frees the
//! whole arena.
//!
//! **Tokenizer = `trigram`** (Q1). Gives true arbitrary-substring match
//! (`"ithu"` finds `"github.com"`). Queries shorter than 3 chars fall
//! back to a `LIKE` scan over the (tiny) projection columns. The
//! projection strings and the query are both lowercased so matching is
//! case-insensitive across Unicode.

use std::collections::HashMap;

use zeroize::Zeroize;

use crate::account::{AccountId, AccountSnapshot, ACCOUNT_ID_LEN};
use crate::error::{Result, StoreError};

/// Result cap for [`crate::vault::Vault::account_search`].
///
/// Generous for any human's search; bounds the per-result blob-decrypt
/// cost and the FFI marshalling cost. Exposed so binding generators /
/// docs can surface the same ceiling.
pub const ACCOUNT_SEARCH_RESULT_CAP: usize = 200;

/// FTS schema-version slot stamped into the `:memory:` index.
///
/// Written into the `meta_fts` row. 1.3 sets this to `1`; the
/// reject/migrate policy (e.g. on a future tokenizer change) is 1.6's
/// per master plan §18.7 — 1.3 only stamps the slot.
pub const FTS_SCHEMA_VERSION: i64 = 1;

/// The non-secret searchable projection of one account identity.
///
/// Built from the *already-NFC-normalised* fields the 1.2 validator
/// produces (`display_name`, the lowercased+deduped `tags`, and the
/// `host_str()`-derived hostnames of the validated URLs). Every string
/// is additionally lowercased here so the `trigram` index (raw
/// codepoints) matches case-insensitively. Zeroized on drop.
pub struct SearchProjection {
    pub display_name: String,
    pub tags_joined: String,
    pub hostnames_joined: String,
}

impl Drop for SearchProjection {
    fn drop(&mut self) {
        self.display_name.zeroize();
        self.tags_joined.zeroize();
        self.hostnames_joined.zeroize();
    }
}

impl SearchProjection {
    /// Build the projection from the V1 identity's whitelisted fields.
    pub fn from_identity(identity: &crate::account::AccountIdentity) -> Self {
        use pangolin_crypto::secret::SecretBytes;
        let display_name = bytes_to_lower_string(identity.display_name.expose());
        let tags_joined = join_lower(identity.tags.iter().map(SecretBytes::expose));
        let hostnames_joined = extract_hostnames(identity.urls.iter().map(SecretBytes::expose));
        Self {
            display_name,
            tags_joined,
            hostnames_joined,
        }
    }

    /// Build the projection from a V0 snapshot (the legacy `add_account`
    /// / `update_account` shim path). V0 has no tags; the single `url`
    /// field is host-extracted like a V1 URL.
    pub fn from_snapshot(snapshot: &AccountSnapshot) -> Self {
        let display_name = bytes_to_lower_string(snapshot.display_name.expose());
        let url = snapshot.url.expose();
        let hostnames_joined = if url.is_empty() {
            String::new()
        } else {
            extract_hostnames(std::iter::once(url))
        };
        Self {
            display_name,
            tags_joined: String::new(),
            hostnames_joined,
        }
    }
}

fn bytes_to_lower_string(b: &[u8]) -> String {
    String::from_utf8_lossy(b).to_lowercase()
}

fn join_lower<'a, I: Iterator<Item = &'a [u8]>>(items: I) -> String {
    let mut out = String::new();
    for item in items {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(&String::from_utf8_lossy(item).to_lowercase());
    }
    out
}

/// Extract a space-joined list of `host_str()` values for the supplied
/// URL byte slices. For schemes with no host (`mailto:`, `app://settings`,
/// …) fall back to the raw serialised URL so non-http URLs stay
/// searchable (matching 1.2's Q3 note). All lowercased.
pub fn extract_hostnames<'a, I: Iterator<Item = &'a [u8]>>(urls: I) -> String {
    let mut out = String::new();
    for raw in urls {
        let s = String::from_utf8_lossy(raw);
        let token = url::Url::parse(&s).map_or_else(
            |_| s.to_string(),
            |parsed| {
                parsed
                    .host_str()
                    .map_or_else(|| s.to_string(), str::to_owned)
            },
        );
        let token = token.to_lowercase();
        if token.is_empty() {
            continue;
        }
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(&token);
    }
    out
}

/// One match-term as understood by the FTS5 `MATCH` expression: a
/// double-quoted phrase containing the lowercased token with embedded
/// double-quotes doubled.
fn fts_quote(token: &str) -> String {
    let mut s = String::with_capacity(token.len() + 2);
    s.push('"');
    for ch in token.chars() {
        if ch == '"' {
            s.push('"');
        }
        s.push(ch);
    }
    s.push('"');
    s
}

/// Outcome of sanitising a raw user query into something the `:memory:`
/// index can be asked.
pub enum SanitisedQuery {
    /// `query.trim()` was empty — caller returns all live accounts.
    Empty,
    /// An FTS5 `MATCH` expression: default-AND over the quoted tokens
    /// (`"git" "main"` ⇒ accounts matching both substrings).
    Fts(String),
    /// At least one token was shorter than the `trigram` 3-char minimum
    /// — fall back to a `LIKE '%token%'` scan, AND-joined across tokens.
    Like(Vec<String>),
}

/// Split the raw query on whitespace into lowercased tokens, decide
/// between an FTS5 `MATCH` expression and a `LIKE` fallback (any token
/// shorter than 3 codepoints forces the `LIKE` path because `trigram`
/// cannot match short substrings), and quote/escape accordingly. Never
/// passes raw user input to FTS5 unescaped.
pub fn sanitise_query(raw: &str) -> SanitisedQuery {
    let tokens: Vec<String> = raw
        .split_whitespace()
        .map(str::to_lowercase)
        .filter(|t| !t.is_empty())
        .collect();
    if tokens.is_empty() {
        return SanitisedQuery::Empty;
    }
    if tokens.iter().any(|t| t.chars().count() < 3) {
        return SanitisedQuery::Like(tokens);
    }
    let expr = tokens
        .iter()
        .map(|t| fts_quote(t))
        .collect::<Vec<_>>()
        .join(" ");
    SanitisedQuery::Fts(expr)
}

// ---------------------------------------------------------------------
// The `:memory:` FTS5 index.
// ---------------------------------------------------------------------

const FTS_SCHEMA_DDL: &str = r"
CREATE TABLE meta_fts (
    id                  INTEGER PRIMARY KEY CHECK (id = 0),
    fts_schema_version  INTEGER NOT NULL
);

CREATE TABLE accounts (
    rowid       INTEGER PRIMARY KEY,
    account_id  BLOB    NOT NULL UNIQUE,
    updated_at  INTEGER NOT NULL
);

CREATE VIRTUAL TABLE account_fts USING fts5(
    display_name,
    tags,
    hostnames,
    tokenize = 'trigram'
);
";

/// An in-RAM FTS5 search index over the non-secret searchable projection
/// of every live account. Owns a `:memory:` `rusqlite::Connection`;
/// dropping it frees the `SQLite` arena.
pub struct SearchIndex {
    conn: rusqlite::Connection,
    /// Next surrogate rowid to assign. FTS5 needs an integer rowid;
    /// `account_id` is a 32-byte BLOB, so we map it onto a monotonic
    /// counter held here.
    next_rowid: i64,
    /// Reverse map `account_id -> rowid` so `account_update` /
    /// `delete_account` can find the FTS5 row to rewrite/remove without
    /// a SQL round-trip.
    rowid_by_account: HashMap<AccountId, i64>,
}

impl std::fmt::Debug for SearchIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SearchIndex")
            .field("rows", &self.rowid_by_account.len())
            .finish_non_exhaustive()
    }
}

impl SearchIndex {
    /// Create an empty `:memory:` FTS5 index. Stamps `meta_fts` with
    /// [`FTS_SCHEMA_VERSION`].
    pub fn new_empty() -> Result<Self> {
        let conn = rusqlite::Connection::open_in_memory()?;
        conn.execute_batch(FTS_SCHEMA_DDL)?;
        conn.execute(
            "INSERT INTO meta_fts (id, fts_schema_version) VALUES (0, ?1)",
            rusqlite::params![FTS_SCHEMA_VERSION],
        )?;
        Ok(Self {
            conn,
            next_rowid: 1,
            rowid_by_account: HashMap::new(),
        })
    }

    /// Borrow the connection (for the schema-availability probe).
    #[cfg(test)]
    pub fn connection(&self) -> &rusqlite::Connection {
        &self.conn
    }

    /// Number of accounts currently indexed.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.rowid_by_account.len()
    }

    /// Insert a fresh account into the index. Allocates a new surrogate
    /// rowid. Panics in debug if `account_id` is already present (the
    /// caller — `account_add` — derives a fresh id).
    pub fn insert(
        &mut self,
        account_id: AccountId,
        updated_at: i64,
        projection: &SearchProjection,
    ) -> Result<()> {
        debug_assert!(!self.rowid_by_account.contains_key(&account_id));
        let rowid = self.next_rowid;
        self.next_rowid += 1;
        self.conn.execute(
            "INSERT INTO accounts (rowid, account_id, updated_at) VALUES (?1, ?2, ?3)",
            rusqlite::params![rowid, account_id.as_bytes().as_slice(), updated_at],
        )?;
        self.conn.execute(
            "INSERT INTO account_fts (rowid, display_name, tags, hostnames)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                rowid,
                projection.display_name,
                projection.tags_joined,
                projection.hostnames_joined,
            ],
        )?;
        self.rowid_by_account.insert(account_id, rowid);
        Ok(())
    }

    /// Update an indexed account's projection + recency stamp. If the
    /// account is unknown to the index (shouldn't happen — an update
    /// implies the account was added/loaded earlier) this falls through
    /// to an insert.
    pub fn update(
        &mut self,
        account_id: AccountId,
        updated_at: i64,
        projection: &SearchProjection,
    ) -> Result<()> {
        let Some(&rowid) = self.rowid_by_account.get(&account_id) else {
            return self.insert(account_id, updated_at, projection);
        };
        // Regular (non-external-content) FTS5 tables support DELETE/INSERT
        // by rowid directly — no `'delete'`-command dance needed.
        self.conn.execute(
            "DELETE FROM account_fts WHERE rowid = ?1",
            rusqlite::params![rowid],
        )?;
        self.conn.execute(
            "INSERT INTO account_fts (rowid, display_name, tags, hostnames)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                rowid,
                projection.display_name,
                projection.tags_joined,
                projection.hostnames_joined,
            ],
        )?;
        self.conn.execute(
            "UPDATE accounts SET updated_at = ?1 WHERE rowid = ?2",
            rusqlite::params![updated_at, rowid],
        )?;
        Ok(())
    }

    /// Remove an account from the index (tombstone path). No-op if the
    /// account is not indexed.
    pub fn remove(&mut self, account_id: AccountId) -> Result<()> {
        let Some(rowid) = self.rowid_by_account.remove(&account_id) else {
            return Ok(());
        };
        self.conn.execute(
            "DELETE FROM account_fts WHERE rowid = ?1",
            rusqlite::params![rowid],
        )?;
        self.conn.execute(
            "DELETE FROM accounts WHERE rowid = ?1",
            rusqlite::params![rowid],
        )?;
        Ok(())
    }

    /// Run a search, returning `(account_id, updated_at)` pairs in
    /// result order (relevance for the FTS path, recency for the
    /// `LIKE` and empty-query paths), capped at
    /// [`ACCOUNT_SEARCH_RESULT_CAP`].
    pub fn search(&self, raw_query: &str) -> Result<Vec<(AccountId, i64)>> {
        let cap = i64::try_from(ACCOUNT_SEARCH_RESULT_CAP).unwrap_or(i64::MAX);
        match sanitise_query(raw_query) {
            SanitisedQuery::Empty => self.collect_query(
                "SELECT account_id, updated_at FROM accounts
                 ORDER BY updated_at DESC, rowid DESC LIMIT ?1",
                rusqlite::params![cap],
            ),
            SanitisedQuery::Fts(expr) => self.collect_query(
                "SELECT a.account_id, a.updated_at
                 FROM account_fts f JOIN accounts a ON a.rowid = f.rowid
                 WHERE account_fts MATCH ?1
                 ORDER BY bm25(account_fts), a.updated_at DESC, a.rowid DESC
                 LIMIT ?2",
                rusqlite::params![expr, cap],
            ),
            SanitisedQuery::Like(tokens) => {
                // ANDed LIKE across the (whitelisted) projection columns.
                // FTS5 stores the column content, so we can LIKE it
                // directly. `\` is the escape char for the literal
                // `%` / `_` / `\` a token might contain.
                let mut sql = String::from(
                    "SELECT a.account_id, a.updated_at
                     FROM account_fts f JOIN accounts a ON a.rowid = f.rowid
                     WHERE ",
                );
                let mut bound: Vec<String> = Vec::new();
                for (i, tok) in tokens.iter().enumerate() {
                    if i > 0 {
                        sql.push_str(" AND ");
                    }
                    let pat = format!("%{}%", like_escape(tok));
                    sql.push_str(
                        "(f.display_name LIKE ?  ESCAPE '\\' \
                          OR f.tags LIKE ? ESCAPE '\\' \
                          OR f.hostnames LIKE ? ESCAPE '\\')",
                    );
                    bound.push(pat.clone());
                    bound.push(pat.clone());
                    bound.push(pat);
                }
                sql.push_str(" ORDER BY a.updated_at DESC, a.rowid DESC LIMIT ?");
                let mut stmt = self.conn.prepare(&sql)?;
                let mut params: Vec<&dyn rusqlite::ToSql> =
                    bound.iter().map(|s| s as &dyn rusqlite::ToSql).collect();
                params.push(&cap);
                let rows = stmt.query_map(params.as_slice(), Self::row_to_pair)?;
                Self::collect_rows(rows)
            }
        }
    }

    fn collect_query(
        &self,
        sql: &str,
        params: impl rusqlite::Params,
    ) -> Result<Vec<(AccountId, i64)>> {
        let mut stmt = self.conn.prepare(sql)?;
        let rows = stmt.query_map(params, Self::row_to_pair)?;
        Self::collect_rows(rows)
    }

    fn row_to_pair(row: &rusqlite::Row<'_>) -> rusqlite::Result<(Vec<u8>, i64)> {
        Ok((row.get(0)?, row.get(1)?))
    }

    fn collect_rows<I>(rows: I) -> Result<Vec<(AccountId, i64)>>
    where
        I: Iterator<Item = rusqlite::Result<(Vec<u8>, i64)>>,
    {
        let mut out = Vec::new();
        for r in rows {
            let (blob, updated_at) = r?;
            let arr: [u8; ACCOUNT_ID_LEN] = blob.as_slice().try_into().map_err(|_| {
                StoreError::Corrupted("search index account_id not 32 bytes".into())
            })?;
            out.push((AccountId::from_bytes(arr), updated_at));
        }
        Ok(out)
    }
}

/// Escape `%`, `_`, and `\` for a SQL `LIKE` pattern using `\` as the
/// escape character.
fn like_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        if matches!(ch, '%' | '_' | '\\') {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

// ---------------------------------------------------------------------
// Legacy in-memory decrypted-cache substring scan (V0 read paths).
// ---------------------------------------------------------------------

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
    use super::{
        extract_hostnames, sanitise_query, DecryptedCache, SanitisedQuery, SearchIndex,
        SearchProjection,
    };
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

    fn proj(display: &str, tags: &str, hosts: &str) -> SearchProjection {
        SearchProjection {
            display_name: display.to_lowercase(),
            tags_joined: tags.to_lowercase(),
            hostnames_joined: hosts.to_lowercase(),
        }
    }

    fn id(n: u8) -> AccountId {
        AccountId::from_bytes([n; 32])
    }

    #[test]
    fn fts5_is_available_in_bundled_sqlite() {
        // Constructing the index requires `CREATE VIRTUAL TABLE … USING
        // fts5(...)` to succeed — that is the FTS5-availability probe.
        let idx = SearchIndex::new_empty().expect("FTS5 must be compiled into bundled SQLite");
        let v: i64 = idx
            .connection()
            .query_row(
                "SELECT fts_schema_version FROM meta_fts WHERE id = 0",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(v, 1);
    }

    #[test]
    fn fts_schema_has_only_whitelisted_columns() {
        let idx = SearchIndex::new_empty().unwrap();
        // The FTS5 shadow content is exposed via the virtual table's
        // own columns; `PRAGMA table_info(account_fts)` lists exactly
        // the indexed columns.
        let mut stmt = idx
            .connection()
            .prepare("SELECT name FROM pragma_table_info('account_fts')")
            .unwrap();
        let cols: Vec<String> = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .map(std::result::Result::unwrap)
            .collect();
        assert_eq!(cols, vec!["display_name", "tags", "hostnames"]);
        for forbidden in [
            "username",
            "usernames",
            "url",
            "urls",
            "password",
            "notes",
            "totp",
        ] {
            assert!(
                !cols.iter().any(|c| c == forbidden),
                "FTS5 schema must not have a `{forbidden}` column"
            );
        }
    }

    #[test]
    fn insert_search_update_remove_round_trip() {
        let mut idx = SearchIndex::new_empty().unwrap();
        idx.insert(id(1), 10, &proj("github main", "work shared", "github.com"))
            .unwrap();
        idx.insert(id(2), 20, &proj("gitlab", "work", "gitlab.com"))
            .unwrap();

        // Substring (trigram) match.
        let hits = idx.search("ithu").unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].0, id(1));

        // Tag match.
        let hits = idx.search("shared").unwrap();
        assert_eq!(hits.iter().map(|h| h.0).collect::<Vec<_>>(), vec![id(1)]);

        // Hostname match — both have a `git*` host.
        let hits = idx.search("git").unwrap();
        assert_eq!(hits.len(), 2);

        // Update: account 2 loses the `work` tag and becomes `personal`.
        idx.update(
            id(2),
            30,
            &proj("gitlab personal", "personal", "gitlab.com"),
        )
        .unwrap();
        assert!(idx.search("work").unwrap().iter().all(|h| h.0 != id(2)));
        assert_eq!(idx.search("personal").unwrap()[0].0, id(2));

        // Remove account 1.
        idx.remove(id(1)).unwrap();
        assert!(idx.search("github").unwrap().is_empty());
        assert_eq!(idx.len(), 1);
    }

    #[test]
    fn multi_term_is_and() {
        let mut idx = SearchIndex::new_empty().unwrap();
        idx.insert(id(1), 1, &proj("github main", "", "github.com"))
            .unwrap();
        idx.insert(id(2), 2, &proj("github work", "", "github.com"))
            .unwrap();
        let hits = idx.search("github main").unwrap();
        assert_eq!(hits.iter().map(|h| h.0).collect::<Vec<_>>(), vec![id(1)]);
    }

    #[test]
    fn empty_query_returns_all_by_recency() {
        let mut idx = SearchIndex::new_empty().unwrap();
        idx.insert(id(1), 100, &proj("a", "", "")).unwrap();
        idx.insert(id(2), 300, &proj("b", "", "")).unwrap();
        idx.insert(id(3), 200, &proj("c", "", "")).unwrap();
        let hits = idx.search("   ").unwrap();
        assert_eq!(
            hits.iter().map(|h| h.0).collect::<Vec<_>>(),
            vec![id(2), id(3), id(1)]
        );
    }

    #[test]
    fn short_query_uses_like_fallback() {
        let mut idx = SearchIndex::new_empty().unwrap();
        idx.insert(id(1), 1, &proj("ab cd", "", "")).unwrap();
        idx.insert(id(2), 2, &proj("xy", "", "")).unwrap();
        // "ab" is < 3 chars so trigram cannot index it; LIKE fallback.
        let hits = idx.search("ab").unwrap();
        assert_eq!(hits.iter().map(|h| h.0).collect::<Vec<_>>(), vec![id(1)]);
    }

    #[test]
    fn search_is_case_insensitive() {
        let mut idx = SearchIndex::new_empty().unwrap();
        idx.insert(id(1), 1, &proj("GitHub", "Work", "GitHub.com"))
            .unwrap();
        assert_eq!(idx.search("github").unwrap()[0].0, id(1));
        assert_eq!(idx.search("WORK").unwrap()[0].0, id(1));
    }

    #[test]
    fn nfc_form_is_what_gets_indexed() {
        // 1.2's validator produces the NFC (precomposed) form; the
        // projection lowercases it. "café" precomposed should match.
        let mut idx = SearchIndex::new_empty().unwrap();
        idx.insert(id(1), 1, &proj("Caf\u{00e9} Bar", "", ""))
            .unwrap();
        assert_eq!(idx.search("café").unwrap()[0].0, id(1));
    }

    #[test]
    fn extract_hostnames_handles_schemes() {
        let urls: Vec<&[u8]> = vec![
            b"https://github.com/foo".as_slice(),
            b"mailto:alice@example.com".as_slice(),
            b"app://settings".as_slice(),
        ];
        let joined = extract_hostnames(urls.into_iter());
        assert!(joined.contains("github.com"));
        // mailto: has no host -> falls back to the raw serialised URL.
        assert!(joined.contains("mailto:alice@example.com"));
        assert!(joined.contains("app://settings") || joined.contains("settings"));
    }

    #[test]
    fn sanitise_query_classification() {
        assert!(matches!(sanitise_query("   "), SanitisedQuery::Empty));
        assert!(matches!(sanitise_query("ab"), SanitisedQuery::Like(_)));
        assert!(matches!(sanitise_query("github"), SanitisedQuery::Fts(_)));
        // A stray quote must not break things — it gets escaped.
        if let SanitisedQuery::Fts(expr) = sanitise_query("git\"hub") {
            assert!(expr.contains("\"\""));
        } else {
            panic!("expected Fts");
        }
    }

    #[test]
    fn projection_from_snapshot_extracts_host() {
        let p =
            SearchProjection::from_snapshot(&snap("My GitHub", "alice", "https://github.com/x"));
        assert_eq!(p.display_name, "my github");
        assert_eq!(p.tags_joined, "");
        assert_eq!(p.hostnames_joined, "github.com");
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
