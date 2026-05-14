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
/// - `devices` is the local trust list (MVP-1 issue 1.5). One row per
///   device that has ever opened+unlocked this `.pvf`; `device_id` is
///   the Ed25519 verifying-key bytes of the device's `DeviceKey`. The
///   `capabilities` column is `INTEGER` (`0 = Full`; the enum grows in
///   MVP-2/3). `last_sync_at` is a dormant column (always `NULL` in
///   MVP-1; MVP-2's chain sync fills it). `public_key` is the 32-byte
///   verifying key (non-secret; nullable for legacy rows). `revoked_at`
///   is the MVP-2/3 revocation hook — never written in MVP-1 (the trust
///   list is add-only). Legacy P2 vaults pick up the four new columns
///   via `migrate_devices_columns`. `schema_version` is the §18.7 slot.
/// - `device_key` is a single-row table holding the device's Ed25519
///   secret seed, AEAD-sealed under the VDK (`enc_seed` ciphertext +
///   `enc_nonce`; AAD binds the `device_id` — anti-transplant). Written
///   on the first unlock that registers a device; read on subsequent
///   unlocks. Unlike `pending_merges.device_secret` (ephemeral, stored
///   un-sealed by the P9 plan's bounded-marginal-exposure argument), the
///   device key is long-lived (the MVP-2 on-chain signing identity /
///   gas wallet) so it gets the AEAD layer the `no_plaintext_on_disk`
///   proptest enforces for every other secret. `schema_version` is the
///   §18.7 slot.
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
    wrapped_nonce     BLOB    NOT NULL,
    -- MVP-1 issue 1.4: configurable idle-timeout choice (Session spec
    -- 7.2). NULL means the 15-min default for vaults that predate 1.4;
    -- otherwise one of {300, 900, 1800, 3600, 14400} seconds, or -1 for
    -- until-device-lock. Additive column; absence is a valid (default)
    -- state -- same doctrine as the sync_state / dirty_accounts additive
    -- tables (no format_version bump). Legacy vault files get the column
    -- via migrate_session_idle_secs_column at open time.
    session_idle_secs INTEGER
);

CREATE TABLE IF NOT EXISTS account_identities (
    account_id              BLOB PRIMARY KEY,
    created_at              INTEGER NOT NULL,
    last_modified_at        INTEGER NOT NULL,
    tombstoned              INTEGER NOT NULL DEFAULT 0,
    head_revision_id        BLOB    NOT NULL,
    -- P8 fix CRIT-1: defensive sentinel set to 1 inside
    -- Vault::ingest_chain_revision when a foreign-device chain event
    -- lands via the genuine-foreign-INSERT path (none of the three
    -- idempotency-merge arms matched). User-facing reads and edits
    -- refuse on this account until the upcoming pangolin-cli resolve
    -- (P9) clears the flag. Existing vault files predating this
    -- column have it added via migrate_frozen_pending_resolve_column
    -- at open time; default 0 so pre-migration accounts are unfrozen.
    frozen_pending_resolve  INTEGER NOT NULL DEFAULT 0
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
    -- MVP-1 issue 1.6: when a fork is resolved, the merge revision is
    -- parented at the kept leaf; every OTHER leaf of the fork gets its
    -- superseded_by set to the merge revision id, recording that the
    -- branch was closed in favour of the merge. Append-only preserved
    -- (a losing branch row is never deleted — Q5); this is a metadata
    -- column like the chain-anchor columns. The head detector
    -- (account_heads / is_forked / all_forked_accounts) excludes
    -- superseded rows so a resolved fork reports a single canonical
    -- head. NULL = not superseded (the normal case). Legacy vaults
    -- pick up the column via migrate_revision_superseded_by_column.
    superseded_by        BLOB,
    FOREIGN KEY (account_id) REFERENCES account_identities(account_id)
);

CREATE INDEX IF NOT EXISTS idx_revisions_account ON revisions(account_id);
CREATE INDEX IF NOT EXISTS idx_revisions_parent  ON revisions(parent_revision_id);
CREATE INDEX IF NOT EXISTS idx_revisions_unpub   ON revisions(chain_tx_hash) WHERE chain_tx_hash IS NULL;

CREATE TABLE IF NOT EXISTS devices (
    device_id      BLOB PRIMARY KEY,
    label          TEXT    NOT NULL DEFAULT '',
    added_at       INTEGER NOT NULL,
    revoked_at     INTEGER,
    -- MVP-1 issue 1.5 additive columns. Legacy P2 vaults get these via
    -- migrate_devices_columns at open time. `capabilities` 0 = Full;
    -- `last_sync_at` dormant (MVP-2 chain sync fills it); `public_key`
    -- 32-byte Ed25519 verifying key (nullable for legacy rows);
    -- `schema_version` is the §18.7 slot (1.6 locks the policy).
    capabilities   INTEGER NOT NULL DEFAULT 0,
    last_sync_at   INTEGER,
    public_key     BLOB,
    schema_version INTEGER NOT NULL DEFAULT 1,
    -- MVP-2 issue 3.2 additive column. The device's per-device EVM
    -- wallet *address* — 20 bytes (the public Ethereum address derived
    -- deterministically from this device's Ed25519 `DeviceKey` via
    -- `pangolin_chain::derive_evm_address`). NON-secret per D-006's
    -- known mitigation (the address is on-chain-observable). The
    -- secp256k1 *scalar* is NEVER persisted — it is re-derived on every
    -- `Vault::unlock` from the AEAD-sealed Ed25519 seed (R-a:
    -- vault-sealed-only; the single source of secrecy is the 1.5 seed).
    -- Nullable for legacy 1.5-era rows pre-dating 3.2; back-filled on
    -- the first 3.2-era unlock (idempotent thereafter). §18.7 slot is
    -- the existing `devices.schema_version = 1` — additive-column
    -- doctrine (no format_version bump).
    evm_address    BLOB
);

-- MVP-1 issue 1.5: single-row device-key table. Holds the device's
-- Ed25519 secret seed AEAD-sealed under the VDK. `id = 0` CHECK
-- enforces single-row by construction; INSERT OR REPLACE keyed on
-- `id = 0` is what writes it (Vault::unlock's register branch).
-- Additive `CREATE TABLE IF NOT EXISTS` (no format_version bump);
-- legacy vaults pick it up on next open via migrate_device_key_table.
CREATE TABLE IF NOT EXISTS device_key (
    id             INTEGER PRIMARY KEY CHECK (id = 0),
    enc_seed       BLOB    NOT NULL,
    enc_nonce      BLOB    NOT NULL,
    schema_version INTEGER NOT NULL
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

-- P8-2: per-(account, revision) dirty marker so `pangolin-cli publish`
-- never loses track of an unpublished revision across restarts. Same
-- additive `CREATE TABLE IF NOT EXISTS` posture as `sync_state` above
-- (no `format_version` bump; existing P0..P7 vaults pick this up on
-- next open). See `docs/issue-plans/P8.md` §A1+A2 for the rationale
-- and the composite-primary-key (`account_id`, `revision_id`)
-- discipline that protects against duplicate-publish on re-run.
CREATE TABLE IF NOT EXISTS dirty_accounts (
    account_id   BLOB NOT NULL,
    revision_id  BLOB NOT NULL,
    marked_at    INTEGER NOT NULL,
    PRIMARY KEY (account_id, revision_id)
);
CREATE INDEX IF NOT EXISTS dirty_accounts_marked_at_idx
    ON dirty_accounts (marked_at);

-- P9 fix-pass HIGH-1: per-(account, target_head_id) stash for the
-- ephemeral merge-revision build state.  Persisted BEFORE
-- adapter.publish so a kill mid-publish is recoverable on retry by
-- reconstructing the SAME DeviceKey (same AEAD nonce, same ciphertext
-- ⇒ same canonical hash every run).  Without this stash, each retry
-- generates a fresh ephemeral DeviceKey + AEAD nonce, the canonical
-- hash differs every run, and the chain event from the prior run
-- cannot be matched on retry — leaving the user permanently stuck
-- with a frozen account.  Stash row deleted after `clear_frozen`
-- succeeds.  See THREAT_MODEL row #13 + DEVLOG P9 fix-pass entry +
-- `Vault::stash_pending_merge` / `take_pending_merge` /
-- `clear_pending_merge`.
--
-- Privacy posture: `device_secret` is an Ed25519 secret seed at rest
-- in the vault file, NOT additionally AEAD-sealed.  At-rest exposure
-- of the .pvf file already compromises the VDK and worse, so the
-- marginal exposure of an ephemeral merge-signing key is bounded.
-- `enc_payload` is the AEAD-sealed merge revision ciphertext (NOT
-- plaintext — the seal happened before the stash).  `aead_nonce`
-- pairs with `enc_payload` for the merge revision's AEAD identity;
-- it is NOT secret in the same sense as the seed.
CREATE TABLE IF NOT EXISTS pending_merges (
    account_id            BLOB NOT NULL,    -- 32 bytes
    target_head_id        BLOB NOT NULL,    -- 32 bytes (the user's --keep)
    device_secret         BLOB NOT NULL,    -- 32 bytes Ed25519 secret seed
    aead_nonce            BLOB NOT NULL,    -- 24 bytes (XChaCha20-Poly1305 nonce)
    enc_payload           BLOB NOT NULL,    -- the merge revision AEAD ciphertext
    schema_version        INTEGER NOT NULL,
    created_at_ms         INTEGER NOT NULL,
    PRIMARY KEY (account_id, target_head_id)
);

-- MVP-1 issue 1.11 / Browser-Ext spec §2.3 / Threat Model invariant #8.
-- Vault-level registry of which component (desktop / browser-ext /
-- mobile-OS autofill) owns credential capture per context. At most one
-- row per (context_kind, platform_hint) — the PRIMARY KEY makes the
-- exclusivity invariant structural. All fields non-secret: closed-enum
-- discriminator + identifier strings + version string + timestamp +
-- per-row §18.7 schema_version. Additive CREATE TABLE IF NOT EXISTS
-- (no format_version bump); legacy 1.10 vaults pick it up on next
-- open via the existing apply_pragmas_and_schema mechanism. NULL
-- platform_hint is coalesced to empty string so the PRIMARY KEY treats
-- it as a distinct value -- a (kind, None) registration is different
-- from a (kind, Some(chrome)) registration.
CREATE TABLE IF NOT EXISTS capture_authorities (
    context_kind        INTEGER NOT NULL,
    platform_hint       TEXT    NOT NULL DEFAULT '',
    authority_kind      INTEGER NOT NULL,
    component_id        TEXT    NOT NULL,
    component_version   TEXT    NOT NULL,
    registered_at       INTEGER NOT NULL,
    schema_version      INTEGER NOT NULL,
    PRIMARY KEY (context_kind, platform_hint)
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

    // P8 fix-pass migration: the `frozen_pending_resolve` column on
    // `account_identities` was added to address CRIT-1 (tombstone-flag
    // non-propagation). Existing vault files predating this fix have
    // an `account_identities` table that does NOT include the column;
    // we ALTER TABLE … ADD COLUMN at open if it's missing so legacy
    // files keep opening cleanly. The default 0 means pre-migration
    // accounts are unfrozen — exactly the right semantics, since they
    // had no opportunity to be foreign-ingested under the old code
    // path (the old `ingest_chain_revision` had no flag to set).
    migrate_frozen_pending_resolve_column(conn)?;

    // P9 fix-pass HIGH-1 migration: the `pending_merges` table was
    // added to address the audit's "partial-failure recovery is
    // structurally non-functional" finding. The schema DDL above
    // already includes `CREATE TABLE IF NOT EXISTS pending_merges`
    // so a fresh-vault path picks it up trivially; this migration is
    // belt + suspenders for legacy vaults where `apply_pragmas_and_schema`
    // ran under an older build and the DDL string did not yet contain
    // the table. Idempotent — checks `sqlite_master` first.
    migrate_pending_merges_table(conn)?;

    // MVP-1 issue 1.4 migration: add `session_idle_secs` to `meta` on
    // vaults written before 1.4. Idempotent — `PRAGMA table_info` check
    // first. Nullable, no default → existing rows pick up NULL, which
    // `SessionDuration::from_meta_secs(None)` maps to the 15-min default.
    migrate_session_idle_secs_column(conn)?;

    // MVP-1 issue 1.5 migrations: the `devices` table grows four
    // additive columns (`capabilities`, `last_sync_at`, `public_key`,
    // `schema_version`) on legacy P2 vaults, and the new single-row
    // `device_key` table is ensured to exist. Both idempotent (the
    // column migration does a `PRAGMA table_info` check; the table
    // migration uses `CREATE TABLE IF NOT EXISTS`). No `format_version`
    // bump — same additive doctrine as the four migrations above.
    migrate_devices_columns(conn)?;
    migrate_device_key_table(conn)?;

    // MVP-2 issue 3.2 migration: the `devices` table gains a nullable
    // `evm_address` BLOB column (20 bytes when present; NULL for
    // legacy 1.5-era rows pre-dating 3.2). Idempotent — `PRAGMA
    // table_info` check first. Back-fill (NULL → derived address) is
    // a runtime concern handled inside `Vault::unlock`, not here.
    // Additive column; no `format_version` bump.
    migrate_devices_evm_address_column(conn)?;

    // MVP-1 issue 1.6 migration: add the nullable `superseded_by` column
    // to `revisions` on vaults that predate 1.6. Idempotent —
    // `PRAGMA table_info` check first. Additive; no `format_version`
    // bump (same doctrine as the migrations above). The column is
    // recomputed implicitly — a legacy vault with an unresolved fork
    // simply has all rows `superseded_by IS NULL` until the user runs
    // `resolve_fork`.
    migrate_revision_superseded_by_column(conn)?;

    Ok(())
}

/// **MVP-1 issue 1.6 migration.** Add the nullable `superseded_by`
/// column to `revisions` on vaults that predate 1.6. Idempotent —
/// checks `PRAGMA table_info(revisions)` first.
fn migrate_revision_superseded_by_column(conn: &Connection) -> Result<()> {
    let mut stmt = conn.prepare("PRAGMA table_info(revisions)")?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(1))?;
    let mut has_column = false;
    for r in rows {
        if r? == "superseded_by" {
            has_column = true;
            break;
        }
    }
    drop(stmt);
    if !has_column {
        conn.execute("ALTER TABLE revisions ADD COLUMN superseded_by BLOB", [])?;
    }
    Ok(())
}

/// Add the `frozen_pending_resolve` column to `account_identities` on
/// vaults that predate the P8 fix-pass schema. Idempotent — checks
/// `PRAGMA table_info` first and only runs the `ALTER TABLE` when the
/// column is absent. Existing rows pick up the column's
/// `DEFAULT 0`.
fn migrate_frozen_pending_resolve_column(conn: &Connection) -> Result<()> {
    let mut stmt = conn.prepare("PRAGMA table_info(account_identities)")?;
    let rows = stmt.query_map([], |row| {
        let name: String = row.get(1)?;
        Ok(name)
    })?;
    let mut has_column = false;
    for r in rows {
        let name = r?;
        if name == "frozen_pending_resolve" {
            has_column = true;
            break;
        }
    }
    drop(stmt);
    if !has_column {
        conn.execute(
            "ALTER TABLE account_identities
             ADD COLUMN frozen_pending_resolve INTEGER NOT NULL DEFAULT 0",
            [],
        )?;
    }
    Ok(())
}

/// **MVP-1 issue 1.4 migration.** Add the nullable `session_idle_secs`
/// column to `meta` on vaults that predate 1.4. Idempotent — checks
/// `PRAGMA table_info(meta)` first. Existing rows pick up NULL, which
/// the read path ([`crate::session::SessionDuration::from_meta_secs`])
/// maps to the 15-min Session spec §7.1 default.
fn migrate_session_idle_secs_column(conn: &Connection) -> Result<()> {
    let mut stmt = conn.prepare("PRAGMA table_info(meta)")?;
    let rows = stmt.query_map([], |row| {
        let name: String = row.get(1)?;
        Ok(name)
    })?;
    let mut has_column = false;
    for r in rows {
        if r? == "session_idle_secs" {
            has_column = true;
            break;
        }
    }
    drop(stmt);
    if !has_column {
        conn.execute("ALTER TABLE meta ADD COLUMN session_idle_secs INTEGER", [])?;
    }
    Ok(())
}

/// **P9 fix-pass HIGH-1 migration.** Ensure the `pending_merges`
/// table exists on legacy vault files.  Idempotent — uses
/// `CREATE TABLE IF NOT EXISTS` directly so re-running it on an
/// already-up-to-date file is a no-op.  The schema DDL string above
/// already contains the same `CREATE TABLE IF NOT EXISTS` statement,
/// so for new-build vaults this is structurally redundant; the value
/// is in pinning the migration intent for legacy files where an
/// older build's DDL did not include this table.
fn migrate_pending_merges_table(conn: &Connection) -> Result<()> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS pending_merges (
            account_id            BLOB NOT NULL,
            target_head_id        BLOB NOT NULL,
            device_secret         BLOB NOT NULL,
            aead_nonce            BLOB NOT NULL,
            enc_payload           BLOB NOT NULL,
            schema_version        INTEGER NOT NULL,
            created_at_ms         INTEGER NOT NULL,
            PRIMARY KEY (account_id, target_head_id)
        )",
        [],
    )?;
    Ok(())
}

/// **MVP-1 issue 1.5 migration.** Add the four additive `devices`
/// columns (`capabilities`, `last_sync_at`, `public_key`,
/// `schema_version`) to legacy P2 vaults. Idempotent — checks
/// `PRAGMA table_info(devices)` first and only runs each `ALTER TABLE`
/// when its column is absent. Existing (legacy) rows pick up the
/// `DEFAULT 0` / `DEFAULT 1` / `NULL` per column. The SQL column
/// `added_at` is reused as the `DeviceIdentity` view's `registered_at`
/// (no rename — needless churn).
fn migrate_devices_columns(conn: &Connection) -> Result<()> {
    let mut stmt = conn.prepare("PRAGMA table_info(devices)")?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(1))?;
    let mut have: std::collections::HashSet<String> = std::collections::HashSet::new();
    for r in rows {
        have.insert(r?);
    }
    drop(stmt);
    if !have.contains("capabilities") {
        conn.execute(
            "ALTER TABLE devices ADD COLUMN capabilities INTEGER NOT NULL DEFAULT 0",
            [],
        )?;
    }
    if !have.contains("last_sync_at") {
        conn.execute("ALTER TABLE devices ADD COLUMN last_sync_at INTEGER", [])?;
    }
    if !have.contains("public_key") {
        conn.execute("ALTER TABLE devices ADD COLUMN public_key BLOB", [])?;
    }
    if !have.contains("schema_version") {
        conn.execute(
            "ALTER TABLE devices ADD COLUMN schema_version INTEGER NOT NULL DEFAULT 1",
            [],
        )?;
    }
    Ok(())
}

/// **MVP-1 issue 1.5 migration.** Ensure the single-row `device_key`
/// table exists on legacy vaults. Idempotent — `CREATE TABLE IF NOT
/// EXISTS` directly so re-running on an up-to-date file is a no-op. The
/// `SCHEMA_DDL` string above already contains the same statement, so
/// for new-build vaults this is structurally redundant; the value is
/// pinning the migration intent for legacy files (same pattern as
/// `migrate_pending_merges_table`).
fn migrate_device_key_table(conn: &Connection) -> Result<()> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS device_key (
            id             INTEGER PRIMARY KEY CHECK (id = 0),
            enc_seed       BLOB    NOT NULL,
            enc_nonce      BLOB    NOT NULL,
            schema_version INTEGER NOT NULL
        )",
        [],
    )?;
    Ok(())
}

/// **MVP-2 issue 3.2 migration.** Add the nullable `evm_address` BLOB
/// column to `devices` on vaults that predate 3.2 (1.5-era rows that
/// were registered before this column existed). Idempotent — checks
/// `PRAGMA table_info(devices)` first and only runs the `ALTER TABLE`
/// when the column is absent. Existing legacy rows pick up `NULL`,
/// which `Vault::unlock` back-fills on the first 3.2-era unlock by
/// deriving the address via `pangolin_chain::derive_evm_address` from
/// the sealed `DeviceKey` seed. Additive column; no `format_version`
/// bump (same doctrine as the migrations above).
///
/// **Why a separate helper.** The 1.5-era `migrate_devices_columns`
/// helper is the historical migration that landed the four 1.5
/// columns; the 3.2 column is a *later* additive amendment with its
/// own audit trail, so it gets its own helper (mirroring the
/// 1.4 `migrate_session_idle_secs_column` / 1.6
/// `migrate_revision_superseded_by_column` pattern — one migration
/// helper per additive amendment). Splitting also lets the
/// `devices_migration_evm_address_idempotent` test target this
/// migration in isolation.
fn migrate_devices_evm_address_column(conn: &Connection) -> Result<()> {
    let mut stmt = conn.prepare("PRAGMA table_info(devices)")?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(1))?;
    let mut has_column = false;
    for r in rows {
        if r? == "evm_address" {
            has_column = true;
            break;
        }
    }
    drop(stmt);
    if !has_column {
        conn.execute("ALTER TABLE devices ADD COLUMN evm_address BLOB", [])?;
    }
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

#[cfg(test)]
mod tests {
    use super::apply_pragmas_and_schema;
    use rusqlite::Connection;

    fn column_names(conn: &Connection, table: &str) -> Vec<String> {
        let mut stmt = conn
            .prepare(&format!("PRAGMA table_info({table})"))
            .unwrap();
        let rows = stmt.query_map([], |row| row.get::<_, String>(1)).unwrap();
        rows.map(Result::unwrap).collect()
    }

    fn table_exists(conn: &Connection, table: &str) -> bool {
        conn.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?1",
            [table],
            |row| row.get::<_, i64>(0),
        )
        .unwrap()
            > 0
    }

    /// MVP-1 issue 1.5 success criterion 9b: `apply_pragmas_and_schema`
    /// is idempotent — running it twice does not error and the new
    /// `devices` columns appear exactly once. Extended in 3.2 to
    /// include `evm_address`.
    #[test]
    fn devices_migration_is_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        apply_pragmas_and_schema(&conn).unwrap();
        // Second run is a no-op.
        apply_pragmas_and_schema(&conn).unwrap();
        let cols = column_names(&conn, "devices");
        for needed in [
            "device_id",
            "label",
            "added_at",
            "revoked_at",
            "capabilities",
            "last_sync_at",
            "public_key",
            "schema_version",
            "evm_address",
        ] {
            assert_eq!(
                cols.iter().filter(|c| c.as_str() == needed).count(),
                1,
                "column {needed} should appear exactly once in devices"
            );
        }
        assert!(table_exists(&conn, "device_key"));
    }

    /// MVP-2 issue 3.2: the `evm_address` column migration is
    /// idempotent on its own — repeated calls do not duplicate the
    /// column, and a fresh DB still ends up with exactly one
    /// `evm_address` column after the full schema run.
    #[test]
    fn devices_migration_evm_address_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        // First full run lands the column via the SCHEMA_DDL path.
        apply_pragmas_and_schema(&conn).unwrap();
        let cols_after_first = column_names(&conn, "devices");
        assert_eq!(
            cols_after_first
                .iter()
                .filter(|c| c.as_str() == "evm_address")
                .count(),
            1,
            "evm_address should appear exactly once after first apply_pragmas_and_schema"
        );
        // Second full run is a no-op (the column-exists check in the
        // migration helper short-circuits the ALTER TABLE).
        apply_pragmas_and_schema(&conn).unwrap();
        let cols_after_second = column_names(&conn, "devices");
        assert_eq!(
            cols_after_second
                .iter()
                .filter(|c| c.as_str() == "evm_address")
                .count(),
            1,
            "evm_address column must remain singular after idempotent re-run"
        );
    }

    /// A legacy-shaped `devices` table (the P2 stub: `device_id, label,
    /// added_at, revoked_at` only, and no `device_key` table) gets the
    /// four new columns + the new table on the next
    /// `apply_pragmas_and_schema` run. Extended in 3.2: the
    /// `evm_address` column also lands on legacy tables.
    #[test]
    fn legacy_devices_table_is_migrated() {
        let conn = Connection::open_in_memory().unwrap();
        // Hand-build the P2-era schema (the subset that matters here).
        conn.execute_batch(
            "CREATE TABLE devices (
                device_id   BLOB PRIMARY KEY,
                label       TEXT    NOT NULL DEFAULT '',
                added_at    INTEGER NOT NULL,
                revoked_at  INTEGER
            );",
        )
        .unwrap();
        assert!(!table_exists(&conn, "device_key"));
        apply_pragmas_and_schema(&conn).unwrap();
        let cols = column_names(&conn, "devices");
        for needed in [
            "capabilities",
            "last_sync_at",
            "public_key",
            "schema_version",
            "evm_address",
        ] {
            assert!(
                cols.iter().any(|c| c.as_str() == needed),
                "column {needed} missing after migration"
            );
        }
        assert!(table_exists(&conn, "device_key"));
    }

    /// MVP-2 issue 3.2: a 1.5-era `devices` table that already carries
    /// the four 1.5 columns but lacks the new `evm_address` column
    /// (i.e. a vault written by a pre-3.2 build) gets the column added
    /// on the next `apply_pragmas_and_schema` run with no data loss.
    #[test]
    fn legacy_1_5_devices_table_gets_evm_address() {
        let conn = Connection::open_in_memory().unwrap();
        // Hand-build the 1.5-era schema (every 1.5 column present
        // except `evm_address`).
        conn.execute_batch(
            "CREATE TABLE devices (
                device_id      BLOB PRIMARY KEY,
                label          TEXT    NOT NULL DEFAULT '',
                added_at       INTEGER NOT NULL,
                revoked_at     INTEGER,
                capabilities   INTEGER NOT NULL DEFAULT 0,
                last_sync_at   INTEGER,
                public_key     BLOB,
                schema_version INTEGER NOT NULL DEFAULT 1
            );",
        )
        .unwrap();
        // Seed a row so we can verify the existing data survives.
        conn.execute(
            "INSERT INTO devices (device_id, label, added_at) VALUES (?1, 'legacy', 100)",
            [&[0xAAu8; 32] as &[u8]],
        )
        .unwrap();
        apply_pragmas_and_schema(&conn).unwrap();
        let cols = column_names(&conn, "devices");
        assert!(
            cols.iter().any(|c| c.as_str() == "evm_address"),
            "evm_address column must be added to a legacy 1.5-era devices table"
        );
        // The pre-migration row is preserved with a NULL evm_address.
        let (label, evm): (String, Option<Vec<u8>>) = conn
            .query_row(
                "SELECT label, evm_address FROM devices WHERE device_id = ?1",
                [&[0xAAu8; 32] as &[u8]],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(label, "legacy");
        assert!(
            evm.is_none(),
            "legacy row's evm_address must be NULL pre-backfill"
        );
    }
}
