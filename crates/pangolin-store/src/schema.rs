//! `SQLite` schema DDL + migration runner.
//!
//! `pangolin-store` keeps the schema deliberately tiny. Every table is
//! `CREATE TABLE IF NOT EXISTS` so the same routine runs on a freshly
//! created vault and on an already-populated one without distinction.
//!
//! Pragmas (`journal_mode = WAL`, `synchronous = FULL`, `foreign_keys =
//! ON`) are applied first; the schema is created next; the magic header
//! and `format_version` row in `meta` is the responsibility of
//! [`crate::meta`] (separate module so the PRAGMA wiring here stays
//! purely structural).

use rusqlite::Connection;

use crate::error::{Result, StoreError};

/// SQL statement bundle for the schema. Idempotent — every statement is
/// `IF NOT EXISTS`.
///
/// Why each table looks the way it does:
///
/// - `meta` is single-row by construction: it carries the magic, format
///   version, vault id, KDF params, salt, and the `WrappedVdk` triple.
///   We use `INSERT OR REPLACE` keyed on `id = 0` so the row is overwritten
///   by `Vault::create` and read by `Vault::open`.
/// - `account_identities` carries no sensitive fields: every secret-bearing
///   column lives in `revisions.enc_payload`. The `tombstoned` flag is
///   an optimization — a tombstone revision is still emitted as a
///   sentinel `{ "deleted": true }` payload (P2-2), and the flag here is
///   the index that lets `list_accounts` skip them in O(1) per row.
/// - `revisions` is append-only by *convention*; no `UPDATE` statement
///   ever runs against it except the `chain_anchor` columns once
///   `mark_published` lands a tx. The `chain_anchor_*` columns are
///   nullable until P7 fills them.
/// - `devices` is a stub; full device-key plumbing arrives in MVP-1.
const SCHEMA_DDL: &str = r"
CREATE TABLE IF NOT EXISTS meta (
    id                INTEGER PRIMARY KEY CHECK (id = 0),
    magic             BLOB    NOT NULL,
    format_version    INTEGER NOT NULL,
    vault_id          BLOB    NOT NULL,
    created_at        INTEGER NOT NULL,
    kdf_memory_kib    INTEGER NOT NULL,
    kdf_time_cost     INTEGER NOT NULL,
    kdf_parallelism   INTEGER NOT NULL,
    kdf_salt          BLOB    NOT NULL,
    schema_version    INTEGER NOT NULL,
    wrapped_ct        BLOB    NOT NULL,
    wrapped_nonce     BLOB    NOT NULL
);

CREATE TABLE IF NOT EXISTS account_identities (
    account_id        BLOB PRIMARY KEY,
    created_at        INTEGER NOT NULL,
    last_modified_at  INTEGER NOT NULL,
    tombstoned        INTEGER NOT NULL DEFAULT 0,
    head_revision_id  BLOB    NOT NULL
);

CREATE TABLE IF NOT EXISTS revisions (
    revision_id          BLOB PRIMARY KEY,
    account_id           BLOB    NOT NULL,
    parent_revision_id   BLOB    NOT NULL,
    device_id            BLOB    NOT NULL,
    schema_version       INTEGER NOT NULL,
    created_at           INTEGER NOT NULL,
    enc_payload          BLOB    NOT NULL,
    enc_nonce            BLOB    NOT NULL,
    is_tombstone         INTEGER NOT NULL DEFAULT 0,
    chain_tx_hash        BLOB,
    chain_block_number   INTEGER,
    chain_log_index      INTEGER,
    FOREIGN KEY (account_id) REFERENCES account_identities(account_id)
);

CREATE INDEX IF NOT EXISTS idx_revisions_account ON revisions(account_id);
CREATE INDEX IF NOT EXISTS idx_revisions_parent  ON revisions(parent_revision_id);
CREATE INDEX IF NOT EXISTS idx_revisions_unpub   ON revisions(chain_tx_hash) WHERE chain_tx_hash IS NULL;

CREATE TABLE IF NOT EXISTS devices (
    device_id   BLOB PRIMARY KEY,
    label       TEXT    NOT NULL DEFAULT '',
    added_at    INTEGER NOT NULL,
    revoked_at  INTEGER
);

-- P7: single-row sync-state table for the `last_pulled_block`
-- checkpoint that `Vault::sync_pull` (P8) will advance.  Idempotent
-- `CREATE TABLE IF NOT EXISTS` so existing P2/P3/P4 vaults pick it up
-- on next open without a format-version bump.  The CHECK (id = 0)
-- constraint enforces single-row by construction; INSERT OR REPLACE
-- in `Vault::advance_last_pulled_block` is what writes the value.
CREATE TABLE IF NOT EXISTS sync_state (
    id                  INTEGER PRIMARY KEY CHECK (id = 0),
    last_pulled_block   INTEGER NOT NULL DEFAULT 0
);
";

/// Apply all pragmas and the schema DDL on the supplied connection.
///
/// Idempotent. Safe to call on every `open`. The pragmas are applied
/// outside the schema transaction because some of them
/// (`journal_mode = WAL`) cannot run inside a transaction.
///
/// # Errors
///
/// Surfaces the underlying [`rusqlite::Error`] on the first failing
/// statement, wrapped as [`StoreError::Sqlite`].
pub fn apply_pragmas_and_schema(conn: &Connection) -> Result<()> {
    // Foreign keys are off by default in SQLite; flip them on.
    conn.pragma_update(None, "foreign_keys", "ON")?;

    // P2-4: WAL gives us crash-resistant writes; FULL gives durability.
    // `journal_mode` is queried separately — `pragma_update` returns
    // `Err` on the result-emitting `journal_mode` pragma in some
    // rusqlite versions, so we route through `query_row` and discard
    // the returned mode string (assertion happens in `Vault::open`).
    let mut stmt = conn.prepare("PRAGMA journal_mode = WAL")?;
    let _: String = stmt.query_row([], |row| row.get(0))?;
    drop(stmt);
    conn.pragma_update(None, "synchronous", "FULL")?;

    // Schema runs in a single transaction so a partial creation cannot
    // leave us with some-but-not-all tables on a fresh-vault path.
    conn.execute_batch(&format!("BEGIN IMMEDIATE; {SCHEMA_DDL} COMMIT;"))?;

    Ok(())
}

/// Confirms the connection is in WAL journal mode. Used by
/// `vault_test::wal_mode_set` (success criterion 10).
///
/// # Errors
///
/// Returns [`StoreError::Corrupted`] if the journal mode is not WAL,
/// otherwise propagates [`rusqlite::Error`].
pub fn assert_wal_mode(conn: &Connection) -> Result<()> {
    let mode: String = conn.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
    if mode.eq_ignore_ascii_case("wal") {
        Ok(())
    } else {
        Err(StoreError::Corrupted(format!(
            "journal_mode is {mode}, expected wal"
        )))
    }
}

/// Run `PRAGMA integrity_check` and surface a `Corrupted` error if the
/// result is anything other than the single literal "ok" row.
pub fn assert_integrity(conn: &Connection) -> Result<()> {
    let mut stmt = conn.prepare("PRAGMA integrity_check")?;
    let mut rows = stmt.query([])?;
    let mut messages: Vec<String> = Vec::new();
    while let Some(row) = rows.next()? {
        let s: String = row.get(0)?;
        if !s.eq_ignore_ascii_case("ok") {
            messages.push(s);
        }
    }
    if messages.is_empty() {
        Ok(())
    } else {
        Err(StoreError::Corrupted(messages.join("; ")))
    }
}
