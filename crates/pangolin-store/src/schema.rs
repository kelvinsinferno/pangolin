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
    session_idle_secs INTEGER,
    -- MVP-2 issue 4.4: three-state sync-mode preference. NULL means
    -- Auto (default behavior: first-sync-on-device offers fast,
    -- else slow); the two string values 'always_slow' and
    -- 'always_fast' force the corresponding SyncMode regardless of
    -- the first-sync heuristic. Additive column; absence is a valid
    -- (default) state -- same doctrine as the session_idle_secs row
    -- above (no format_version bump). Legacy vault files get the
    -- column via migrate_sync_mode_preference_column at open time.
    -- This is UX state, not secret material; lives in plaintext
    -- alongside session_idle_secs by precedent.
    sync_mode_preference TEXT,
    -- MVP-3 issue #106c2: the per-vault v1/v2 RevisionLog binding (the
    -- sync-loop + publish routing signal). INTEGER 1 = RevisionLogV1,
    -- 2 = RevisionLogV2. NULL / absence ⇒ V1 (legacy vaults predating
    -- #106c2 route to the V1 path verbatim — no behaviour change). NEW
    -- vaults are seeded V1 explicitly (Q-a: the V2 path is testnet-only
    -- until a Base Sepolia V2 deploy + pinned address land). Additive
    -- column; absence is a valid (default) state — same doctrine as the
    -- session_idle_secs / sync_mode_preference rows above (no
    -- format_version bump, §18.7). Plaintext routing state, not secret
    -- material. Legacy vault files get the column via
    -- migrate_revisionlog_version_column at open time.
    revisionlog_version INTEGER
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
    -- MVP-3 issue #106b-2: the per-entry VDK epoch tag (Q-a). After a
    -- device-revoke rotation mints a new VDK epoch, NEW writes encrypt
    -- under the new-epoch VDK while OLD entries stay under their original
    -- epoch's VDK; the read path decrypts each entry under
    -- `chain[vdk_epoch]`. DEFAULT 0 so every existing / legacy / never-
    -- rotated row reads as epoch 0 (the single meta VDK) — additive, no
    -- format_version bump. The tag is recorded here (a local-row column)
    -- rather than on chain: RevisionLogV2's encPayload is immutable, so
    -- we must not need a v3 to carry it. Legacy vaults pick the column
    -- up via migrate_revision_vdk_epoch_column.
    vdk_epoch            INTEGER NOT NULL DEFAULT 0,
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

-- MVP-2 issue 4.1: per-vault checkpoint table for the v1 slow-mode
-- chain sync read path (R-a). Distinct from the v0-era `sync_state`
-- table above so v0 read-back and v1 chain sync can advance
-- independently. Single row (CHECK id = 0); INSERT OR REPLACE keyed on
-- id = 0 is what `Vault::update_last_synced_block_v1` writes.
-- Additive `CREATE TABLE IF NOT EXISTS` (no format_version bump);
-- legacy P0..3.6 vaults pick it up on next open through
-- `apply_pragmas_and_schema`. `chain_env_tag` carries which env the
-- checkpoint binds to so a future cross-env build can store separate
-- cursors without colliding (in MVP-2 only `BaseSepolia` is wired;
-- the tag is `1`).
CREATE TABLE IF NOT EXISTS chain_sync_v1_state (
    id                  INTEGER PRIMARY KEY CHECK (id = 0),
    chain_env_tag       INTEGER NOT NULL DEFAULT 1,
    last_synced_block   INTEGER NOT NULL DEFAULT 0,
    last_synced_at      INTEGER,
    schema_version      INTEGER NOT NULL DEFAULT 1
);

-- MVP-3 issue #106c2: the SEPARATE V2 read-path checkpoint (Q-e). A
-- V2-bound vault advances its own cursor here, never touching the V1
-- `chain_sync_v1_state` row, so a vault that ever held both never
-- cross-contaminates cursors (the L-no-regression invariant). Same
-- single-row (CHECK id = 0) shape + INSERT OR REPLACE keyed on id = 0
-- as `chain_sync_v1_state`. Additive `CREATE TABLE IF NOT EXISTS` (no
-- format_version bump); legacy vaults pick it up on next open through
-- `apply_pragmas_and_schema`.
CREATE TABLE IF NOT EXISTS chain_sync_v2_state (
    id                  INTEGER PRIMARY KEY CHECK (id = 0),
    chain_env_tag       INTEGER NOT NULL DEFAULT 1,
    last_synced_block   INTEGER NOT NULL DEFAULT 0,
    last_synced_at      INTEGER,
    schema_version      INTEGER NOT NULL DEFAULT 1
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

-- MVP-3 issue #104b: single-row recovery-escrow state table. Holds the
-- VDK second-wrapped under the threshold-shared RWK (`wrapped_ct` +
-- `wrapped_nonce` + `wrap_schema_version`), the guardian-set parameters
-- (`threshold` = on-chain t, `guardian_count` = on-chain M — the L2
-- equality), and the monotonic recovery `epoch` (GAP FLAG 2 — the
-- big-endian counter baked into each sealed share's domain header,
-- advanced on onboarding + each recovery re-split). ALL columns are
-- non-secret at rest (the recovery wrapper is AEAD ciphertext keyed by
-- the threshold-shared RWK; the epoch + t/M are public) → plain BLOBs,
-- same idiom as `meta.wrapped_ct` (plan §5a Q-g / L9). `id = 0` CHECK
-- enforces single-row; INSERT OR REPLACE keyed on id = 0 writes it.
-- Additive `CREATE TABLE IF NOT EXISTS` (no format_version bump); legacy
-- vaults pick it up on next open via migrate_recovery_escrow_tables.
CREATE TABLE IF NOT EXISTS recovery_escrow (
    id                  INTEGER PRIMARY KEY CHECK (id = 0),
    wrapped_ct          BLOB    NOT NULL,
    wrapped_nonce       BLOB    NOT NULL,
    wrap_schema_version INTEGER NOT NULL,
    threshold           INTEGER NOT NULL,
    guardian_count      INTEGER NOT NULL,
    epoch               INTEGER NOT NULL,
    schema_version      INTEGER NOT NULL
);

-- MVP-3 issue #104b: per-guardian recovery-escrow rows. `guardian_index`
-- is the ordinal (0..M) that L2-joins the X25519-sealed guardian to the
-- secp256k1 merkle-committed guardian at the same position.
-- `guardian_x25519_pub` is the guardian's 32-byte X25519 public key
-- (non-secret). `enc_sealed_share` is the locally-retained copy of the
-- guardian's SealedShare, ADDITIONALLY double-wrapped under the VDK
-- column-AEAD (plan §5a Q-g — defence in depth, matching the `device_key`
-- discipline; the AEAD AAD binds vault_id + epoch + guardian_index so a
-- row cannot be transplanted across vault/epoch/slot). `enc_nonce` pairs
-- with it. The `no_plaintext_on_disk`-style assertion holds for
-- `enc_sealed_share`. Additive table; legacy vaults pick it up via
-- migrate_recovery_escrow_tables.
CREATE TABLE IF NOT EXISTS recovery_guardians (
    guardian_index      INTEGER PRIMARY KEY,
    guardian_x25519_pub BLOB    NOT NULL,
    enc_sealed_share    BLOB    NOT NULL,
    enc_nonce           BLOB    NOT NULL,
    schema_version      INTEGER NOT NULL
);

-- MVP-3 issue #106b-2: single-row VDK-chain pointer. current_epoch is
-- the shared monotonic per-vault epoch (Q-f) whose VDK encrypts NEW
-- writes; it lives in meta.wrapped_ct (the password anchor) + the
-- guardian escrow. Absent row = a legacy / never-rotated vault = single
-- epoch 0 (the meta VDK) -- the additive default, no format_version
-- bump. id = 0 CHECK enforces single-row; INSERT OR REPLACE keyed on
-- id = 0 (Vault::commit_vdk_rotation) advances it. Legacy vaults pick
-- the table up via migrate_vdk_chain_tables.
CREATE TABLE IF NOT EXISTS vdk_chain_state (
    id             INTEGER PRIMARY KEY CHECK (id = 0),
    current_epoch  INTEGER NOT NULL,
    schema_version INTEGER NOT NULL
);

-- MVP-3 issue #106b-2: epoch-keyed retained-old VDK chain. One row per
-- RETAINED (non-current) epoch — the VDKs a SURVIVING device keeps
-- read-only to decrypt PRE-rotation entries (on-chain history is
-- immutable, so old entries stay under their original epoch's VDK).
-- Each row holds that epoch's VDK wrapped two ways: under the password
-- authority (`anchor_*`, recoverable on unlock by re-deriving the
-- authority from the password) and under the LOCAL device key
-- (`device_*`, biometric fast-unlock). Both are AEAD ciphertext keyed by
-- secrets that never touch disk, so they are non-secret at rest -> plain
-- BLOBs, the `meta.wrapped_ct` idiom (L9). The CURRENT epoch's VDK is
-- NEVER duplicated here (it is the meta VDK). Additive table; legacy
-- vaults pick it up via migrate_vdk_chain_tables.
CREATE TABLE IF NOT EXISTS vdk_chain (
    epoch              INTEGER PRIMARY KEY,
    anchor_ct          BLOB    NOT NULL,
    anchor_nonce       BLOB    NOT NULL,
    anchor_wrap_schema INTEGER NOT NULL,
    device_ct          BLOB    NOT NULL,
    device_nonce       BLOB    NOT NULL,
    device_wrap_schema INTEGER NOT NULL,
    schema_version     INTEGER NOT NULL
);

-- MVP-3 issue #106c (GAP A): the LOCAL survivor-pubkey directory. The
-- on-chain authorized set stores secp256k1 ADDRESSES; rotation needs each
-- survivor's X25519 PAIRING pubkey, and there is no on-chain mapping
-- (correct — no VDK-adjacent contract slots). This table maps each known
-- device's 20-byte secp256k1 `signer` → its stable 32-byte `device_id`
-- (GAP B) + its 32-byte X25519 `pairing_pub`. Populated at device-add (when
-- the existing device learns the new device's full triple) + opportunistic
-- completion as survivors come online. All three columns are NON-SECRET
-- (the signer + pairing pubkey are public; the seal binds the recipient
-- pubkey, not these rows) → plain BLOBs. Additive `CREATE TABLE IF NOT
-- EXISTS`; legacy vaults pick it up via migrate_device_directory_table.
CREATE TABLE IF NOT EXISTS device_directory (
    signer          BLOB    PRIMARY KEY,
    device_id       BLOB    NOT NULL,
    pairing_pub     BLOB    NOT NULL,
    discovered_at   INTEGER NOT NULL,
    schema_version  INTEGER NOT NULL
);

-- MVP-3 issue #106c: the crash-durable, RESUMABLE rotation-pending state.
-- When a `DeviceRemoved` is detected (event-decode or set-diff), a row is
-- persisted so a closed app RESUMES the pending state on next open (the
-- removed device is already OUT of the on-chain set, so access-control is
-- closed; the LOCAL VDK gap is what the password-gated rotation closes).
-- One row per (removed_signer) outstanding; idempotent re-observe is a
-- no-op (INSERT OR IGNORE on the PK). The engine NEVER auto-rotates (L3):
-- it only PERSISTS + SURFACES; the HOST re-prompts the master password and
-- drives `rotate_vdk_for_survivors` + `commit_vdk_rotation`, which clears
-- the row. `observed_epoch` is the vault epoch at detection; `resolved` is
-- 0 (pending) / 1 (completed). Additive `CREATE TABLE IF NOT EXISTS`;
-- legacy vaults pick it up via migrate_rotation_pending_table — a legacy
-- vault opens with the table absent → clean empty default (no pending).
CREATE TABLE IF NOT EXISTS rotation_pending (
    removed_signer  BLOB    PRIMARY KEY,
    observed_epoch  INTEGER NOT NULL,
    observed_at     INTEGER NOT NULL,
    resolved        INTEGER NOT NULL DEFAULT 0,
    schema_version  INTEGER NOT NULL
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

    // MVP-2 issue 4.4 migration: add `sync_mode_preference` to `meta` on
    // vaults written before 4.4. Idempotent — `PRAGMA table_info` check
    // first. Nullable, no default → existing rows pick up NULL, which
    // `SyncModePreference::from_meta_str(None)` maps to `Auto` (the
    // first-sync-on-device heuristic). Same additive-nullable-column
    // doctrine as 1.4 above (no `format_version` bump).
    migrate_sync_mode_preference_column(conn)?;

    // MVP-3 issue #106c2 migration: add `revisionlog_version` to `meta`
    // on vaults that predate #106c2. Idempotent — PRAGMA table_info
    // guard. Existing rows pick up NULL, which the read path
    // (`Vault::revisionlog_version`) maps to `RevisionLogVersion::V1`
    // (the no-regression default). Additive; no `format_version` bump
    // (§18.7), same doctrine as the sync_mode_preference precedent.
    migrate_revisionlog_version_column(conn)?;

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

    // MVP-2 issue 4.1 migrations:
    // - `revisions.revision_status` (TEXT, DEFAULT 'finalized') — R-c
    //   two-stage status. Pre-4.1 rows default to 'finalized' so
    //   existing graphs survive the schema bump as-is.
    // - `revisions.observed_at_block` (INTEGER, nullable) — block
    //   height the revision was observed at; populated only for
    //   chain-sync-ingested rows in `Pending` status.
    // - `revisions.observed_block_hash` (BLOB, nullable) — same row
    //   companion field for reorg detection.
    // - `devices.discovered_via_chain_sync` (INTEGER, DEFAULT 0) —
    //   R-d audit flag.
    // - `devices.discovered_at_block` (INTEGER, nullable) — block
    //   height the device was first observed publishing.
    // - `chain_sync_v1_state` table — R-a checkpoint persistence.
    //   Belt + suspenders against legacy files where `apply_*` runs
    //   under an older DDL string.
    migrate_revision_chain_sync_columns(conn)?;
    migrate_devices_chain_sync_columns(conn)?;
    migrate_chain_sync_v1_state_table(conn)?;
    // MVP-3 issue #106c2: the SEPARATE V2 read-path checkpoint (Q-e),
    // additive — never touches the V1 cursor.
    migrate_chain_sync_v2_state_table(conn)?;

    // MVP-3 issue #104b migration: ensure the additive `recovery_escrow`
    // + `recovery_guardians` tables exist on legacy vaults. The SCHEMA_DDL
    // string above already contains both `CREATE TABLE IF NOT EXISTS`
    // statements, so for fresh-build vaults this is structurally
    // redundant; the value is in pinning the migration intent for legacy
    // files whose `apply_pragmas_and_schema` ran under an older DDL.
    // Belt + suspenders, same pattern as migrate_chain_sync_v1_state_table.
    // Additive; no `format_version` bump. A legacy vault that has never
    // onboarded guardians simply has the tables present-but-empty, which
    // `recovery_escrow::read_recovery_escrow` reads back as `None`.
    migrate_recovery_escrow_tables(conn)?;

    // MVP-3 issue #106b-2 migrations: the additive `vdk_chain_state` +
    // `vdk_chain` tables (the epoch-keyed retained-VDK chain) and the
    // additive `revisions.vdk_epoch` per-entry tag column. The SCHEMA_DDL
    // string above already contains the `CREATE TABLE IF NOT EXISTS` for
    // both tables, so for fresh-build vaults the table migration is
    // structurally redundant; the value is pinning the migration intent
    // for legacy files whose `apply_pragmas_and_schema` ran under an older
    // DDL. The column migration is the load-bearing one — a legacy
    // `revisions` table predating #106b-2 gets the `vdk_epoch` column
    // (DEFAULT 0) so every existing row reads as the single epoch-0 VDK.
    // Additive; no `format_version` bump.
    migrate_vdk_chain_tables(conn)?;
    migrate_revision_vdk_epoch_column(conn)?;

    // MVP-3 issue #106c migrations: ensure the additive `device_directory`
    // (GAP A survivor-pubkey directory) + `rotation_pending` (the
    // crash-durable DeviceRemoved→rotation state) tables exist on legacy
    // vaults. The SCHEMA_DDL string above already contains both
    // `CREATE TABLE IF NOT EXISTS` statements, so for fresh-build vaults
    // these are structurally redundant; the value is pinning the migration
    // intent for legacy files whose `apply_pragmas_and_schema` ran under an
    // older DDL. Belt + suspenders, same pattern as
    // migrate_recovery_escrow_tables. Additive; no `format_version` bump. A
    // legacy vault opens with both tables present-but-empty → clean default
    // (no known directory entries, no pending rotation).
    migrate_device_directory_table(conn)?;
    migrate_rotation_pending_table(conn)?;

    Ok(())
}

/// **MVP-3 issue #106c migration (GAP A).** Ensure the `device_directory`
/// table exists on legacy vaults. Idempotent — `CREATE TABLE IF NOT
/// EXISTS` directly. Same belt + suspenders pattern as
/// [`migrate_recovery_escrow_tables`].
fn migrate_device_directory_table(conn: &Connection) -> Result<()> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS device_directory (
            signer          BLOB    PRIMARY KEY,
            device_id       BLOB    NOT NULL,
            pairing_pub     BLOB    NOT NULL,
            discovered_at   INTEGER NOT NULL,
            schema_version  INTEGER NOT NULL
        )",
        [],
    )?;
    Ok(())
}

/// **MVP-3 issue #106c migration.** Ensure the `rotation_pending` table
/// exists on legacy vaults. Idempotent — `CREATE TABLE IF NOT EXISTS`
/// directly.
fn migrate_rotation_pending_table(conn: &Connection) -> Result<()> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS rotation_pending (
            removed_signer  BLOB    PRIMARY KEY,
            observed_epoch  INTEGER NOT NULL,
            observed_at     INTEGER NOT NULL,
            resolved        INTEGER NOT NULL DEFAULT 0,
            schema_version  INTEGER NOT NULL
        )",
        [],
    )?;
    Ok(())
}

/// **MVP-3 issue #106b-2 migration.** Ensure the `vdk_chain_state` +
/// `vdk_chain` tables exist on legacy vaults. Idempotent — `CREATE TABLE
/// IF NOT EXISTS` directly. Same belt + suspenders pattern as
/// [`migrate_recovery_escrow_tables`].
fn migrate_vdk_chain_tables(conn: &Connection) -> Result<()> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS vdk_chain_state (
            id             INTEGER PRIMARY KEY CHECK (id = 0),
            current_epoch  INTEGER NOT NULL,
            schema_version INTEGER NOT NULL
        )",
        [],
    )?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS vdk_chain (
            epoch              INTEGER PRIMARY KEY,
            anchor_ct          BLOB    NOT NULL,
            anchor_nonce       BLOB    NOT NULL,
            anchor_wrap_schema INTEGER NOT NULL,
            device_ct          BLOB    NOT NULL,
            device_nonce       BLOB    NOT NULL,
            device_wrap_schema INTEGER NOT NULL,
            schema_version     INTEGER NOT NULL
        )",
        [],
    )?;
    Ok(())
}

/// **MVP-3 issue #106b-2 migration.** Add the additive `vdk_epoch` column
/// to `revisions` on vaults that predate #106b-2. Idempotent — checks
/// `PRAGMA table_info(revisions)` first. Existing rows pick up the
/// `DEFAULT 0`, so every pre-rotation entry reads as the single epoch-0
/// VDK (the meta VDK). Additive; no `format_version` bump.
fn migrate_revision_vdk_epoch_column(conn: &Connection) -> Result<()> {
    let mut stmt = conn.prepare("PRAGMA table_info(revisions)")?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(1))?;
    let mut has_column = false;
    for r in rows {
        if r? == "vdk_epoch" {
            has_column = true;
            break;
        }
    }
    drop(stmt);
    if !has_column {
        conn.execute(
            "ALTER TABLE revisions ADD COLUMN vdk_epoch INTEGER NOT NULL DEFAULT 0",
            [],
        )?;
    }
    Ok(())
}

/// **MVP-3 issue #104b migration.** Ensure the `recovery_escrow` +
/// `recovery_guardians` tables exist on legacy vaults. Idempotent — uses
/// `CREATE TABLE IF NOT EXISTS` directly. Same belt + suspenders pattern
/// as [`migrate_chain_sync_v1_state_table`] / [`migrate_device_key_table`].
fn migrate_recovery_escrow_tables(conn: &Connection) -> Result<()> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS recovery_escrow (
            id                  INTEGER PRIMARY KEY CHECK (id = 0),
            wrapped_ct          BLOB    NOT NULL,
            wrapped_nonce       BLOB    NOT NULL,
            wrap_schema_version INTEGER NOT NULL,
            threshold           INTEGER NOT NULL,
            guardian_count      INTEGER NOT NULL,
            epoch               INTEGER NOT NULL,
            schema_version      INTEGER NOT NULL
        )",
        [],
    )?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS recovery_guardians (
            guardian_index      INTEGER PRIMARY KEY,
            guardian_x25519_pub BLOB    NOT NULL,
            enc_sealed_share    BLOB    NOT NULL,
            enc_nonce           BLOB    NOT NULL,
            schema_version      INTEGER NOT NULL
        )",
        [],
    )?;
    Ok(())
}

/// **MVP-2 issue 4.1 migration.** Add the three `revisions` columns
/// (`revision_status`, `observed_at_block`, `observed_block_hash`)
/// required by R-c (two-stage rollback). Idempotent — each column
/// gated by a `PRAGMA table_info(revisions)` check.
fn migrate_revision_chain_sync_columns(conn: &Connection) -> Result<()> {
    let mut stmt = conn.prepare("PRAGMA table_info(revisions)")?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(1))?;
    let mut have: std::collections::HashSet<String> = std::collections::HashSet::new();
    for r in rows {
        have.insert(r?);
    }
    drop(stmt);
    if !have.contains("revision_status") {
        conn.execute(
            "ALTER TABLE revisions ADD COLUMN revision_status TEXT NOT NULL DEFAULT 'finalized'",
            [],
        )?;
    }
    if !have.contains("observed_at_block") {
        conn.execute(
            "ALTER TABLE revisions ADD COLUMN observed_at_block INTEGER",
            [],
        )?;
    }
    if !have.contains("observed_block_hash") {
        conn.execute(
            "ALTER TABLE revisions ADD COLUMN observed_block_hash BLOB",
            [],
        )?;
    }
    Ok(())
}

/// **MVP-2 issue 4.1 migration.** Add the two `devices` columns
/// (`discovered_via_chain_sync`, `discovered_at_block`) required by
/// R-d (permissive auto-register). Idempotent.
fn migrate_devices_chain_sync_columns(conn: &Connection) -> Result<()> {
    let mut stmt = conn.prepare("PRAGMA table_info(devices)")?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(1))?;
    let mut have: std::collections::HashSet<String> = std::collections::HashSet::new();
    for r in rows {
        have.insert(r?);
    }
    drop(stmt);
    if !have.contains("discovered_via_chain_sync") {
        conn.execute(
            "ALTER TABLE devices ADD COLUMN discovered_via_chain_sync INTEGER NOT NULL DEFAULT 0",
            [],
        )?;
    }
    if !have.contains("discovered_at_block") {
        conn.execute(
            "ALTER TABLE devices ADD COLUMN discovered_at_block INTEGER",
            [],
        )?;
    }
    Ok(())
}

/// **MVP-2 issue 4.1 migration.** Ensure the `chain_sync_v1_state`
/// table exists on legacy vaults. Same pattern as
/// `migrate_pending_merges_table` — the `SCHEMA_DDL` string above
/// already contains the `CREATE TABLE IF NOT EXISTS`; this helper is
/// belt + suspenders for files whose `apply_pragmas_and_schema` ran
/// under an older DDL.
fn migrate_chain_sync_v1_state_table(conn: &Connection) -> Result<()> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS chain_sync_v1_state (
            id                  INTEGER PRIMARY KEY CHECK (id = 0),
            chain_env_tag       INTEGER NOT NULL DEFAULT 1,
            last_synced_block   INTEGER NOT NULL DEFAULT 0,
            last_synced_at      INTEGER,
            schema_version      INTEGER NOT NULL DEFAULT 1
        )",
        [],
    )?;
    Ok(())
}

/// **MVP-3 issue #106c2 migration.** Ensure the `chain_sync_v2_state`
/// table exists on legacy vaults. Same belt + suspenders pattern as
/// [`migrate_chain_sync_v1_state_table`]. Additive; no `format_version`
/// bump (§18.7). A legacy vault that has never run a V2 sync simply has
/// the table present-but-empty → the V2 cursor reads as `None` → first
/// V2 sync replays from genesis.
fn migrate_chain_sync_v2_state_table(conn: &Connection) -> Result<()> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS chain_sync_v2_state (
            id                  INTEGER PRIMARY KEY CHECK (id = 0),
            chain_env_tag       INTEGER NOT NULL DEFAULT 1,
            last_synced_block   INTEGER NOT NULL DEFAULT 0,
            last_synced_at      INTEGER,
            schema_version      INTEGER NOT NULL DEFAULT 1
        )",
        [],
    )?;
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

/// **MVP-2 issue 4.4 migration.** Add the nullable
/// `sync_mode_preference` TEXT column to `meta` on vaults that predate
/// 4.4. Idempotent — checks `PRAGMA table_info(meta)` first. Existing
/// rows pick up NULL, which the read path
/// ([`crate::vault::SyncModePreference::from_meta_str`]) maps to
/// `SyncModePreference::Auto` (the default first-sync-on-device
/// heuristic). Mirrors the 1.4 `session_idle_secs` precedent
/// byte-for-byte; no `format_version` bump per the additive-
/// nullable-column doctrine (§18.7).
fn migrate_sync_mode_preference_column(conn: &Connection) -> Result<()> {
    let mut stmt = conn.prepare("PRAGMA table_info(meta)")?;
    let rows = stmt.query_map([], |row| {
        let name: String = row.get(1)?;
        Ok(name)
    })?;
    let mut has_column = false;
    for r in rows {
        if r? == "sync_mode_preference" {
            has_column = true;
            break;
        }
    }
    drop(stmt);
    if !has_column {
        conn.execute("ALTER TABLE meta ADD COLUMN sync_mode_preference TEXT", [])?;
    }
    Ok(())
}

/// **MVP-3 issue #106c2 migration.** Add the nullable
/// `revisionlog_version` INTEGER column to `meta` on vaults that predate
/// #106c2. Idempotent — checks `PRAGMA table_info(meta)` first. Existing
/// rows pick up NULL, which the read path
/// ([`crate::vault::RevisionLogVersion::from_meta_int`]) maps to
/// `RevisionLogVersion::V1` (the no-regression default — a legacy vault
/// keeps routing to the V1 path verbatim). Mirrors the 4.4
/// `sync_mode_preference` precedent byte-for-byte; no `format_version`
/// bump per the additive-nullable-column doctrine (§18.7).
fn migrate_revisionlog_version_column(conn: &Connection) -> Result<()> {
    let mut stmt = conn.prepare("PRAGMA table_info(meta)")?;
    let rows = stmt.query_map([], |row| {
        let name: String = row.get(1)?;
        Ok(name)
    })?;
    let mut has_column = false;
    for r in rows {
        if r? == "revisionlog_version" {
            has_column = true;
            break;
        }
    }
    drop(stmt);
    if !has_column {
        conn.execute(
            "ALTER TABLE meta ADD COLUMN revisionlog_version INTEGER",
            [],
        )?;
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

    /// MVP-2 issue 4.1: the chain-sync columns (`revision_status`,
    /// `observed_at_block`, `observed_block_hash` on `revisions`;
    /// `discovered_via_chain_sync`, `discovered_at_block` on
    /// `devices`) land via `apply_pragmas_and_schema` and stay
    /// singular under idempotent re-run.
    #[test]
    fn chain_sync_columns_migration_is_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        apply_pragmas_and_schema(&conn).unwrap();
        apply_pragmas_and_schema(&conn).unwrap();
        let rev_cols = column_names(&conn, "revisions");
        for needed in [
            "revision_status",
            "observed_at_block",
            "observed_block_hash",
        ] {
            assert_eq!(
                rev_cols.iter().filter(|c| c.as_str() == needed).count(),
                1,
                "revisions.{needed} should appear exactly once"
            );
        }
        let dev_cols = column_names(&conn, "devices");
        for needed in ["discovered_via_chain_sync", "discovered_at_block"] {
            assert_eq!(
                dev_cols.iter().filter(|c| c.as_str() == needed).count(),
                1,
                "devices.{needed} should appear exactly once"
            );
        }
        assert!(table_exists(&conn, "chain_sync_v1_state"));
    }

    /// MVP-2 issue 4.1: a legacy `revisions` table lacking the
    /// chain-sync columns gets them added on next migration; the
    /// `revision_status` column defaults to 'finalized' so existing
    /// (pre-4.1) rows continue to read as finalized.
    #[test]
    fn legacy_revisions_table_gets_chain_sync_columns_with_finalized_default() {
        let conn = Connection::open_in_memory().unwrap();
        // Hand-build a pre-4.1 revisions table (the columns 1.6
        // baseline carries — including `superseded_by` so the legacy
        // 1.6 schema doesn't trip migrations above).
        conn.execute_batch(
            "CREATE TABLE account_identities (account_id BLOB PRIMARY KEY, created_at INTEGER NOT NULL, last_modified_at INTEGER NOT NULL, tombstoned INTEGER NOT NULL DEFAULT 0, head_revision_id BLOB NOT NULL);
             CREATE TABLE revisions (
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
                superseded_by        BLOB,
                FOREIGN KEY (account_id) REFERENCES account_identities(account_id)
             );",
        )
        .unwrap();
        // Seed a pre-4.1 row.
        conn.execute(
            "INSERT INTO account_identities (account_id, created_at, last_modified_at, head_revision_id) VALUES (?1, 0, 0, ?2)",
            [&[0xAAu8; 32] as &[u8], &[0xBBu8; 32] as &[u8]],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO revisions
                (revision_id, account_id, parent_revision_id, device_id, schema_version,
                 created_at, enc_payload, enc_nonce)
             VALUES (?1, ?2, ?3, ?4, 1, 0, ?5, ?6)",
            [
                &[0xBBu8; 32] as &[u8],
                &[0xAAu8; 32] as &[u8],
                &[0x00u8; 32] as &[u8],
                &[0xCCu8; 32] as &[u8],
                &[0xDEu8; 4] as &[u8],
                &[0xEEu8; 24] as &[u8],
            ],
        )
        .unwrap();
        apply_pragmas_and_schema(&conn).unwrap();
        let status: String = conn
            .query_row(
                "SELECT revision_status FROM revisions WHERE revision_id = ?1",
                [&[0xBBu8; 32] as &[u8]],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            status, "finalized",
            "pre-4.1 rows must default to 'finalized' under the new column"
        );
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

    /// MVP-3 issue #104b: the `recovery_escrow` + `recovery_guardians`
    /// tables land via `apply_pragmas_and_schema` and survive an
    /// idempotent re-run. A legacy vault (one that predates #104b — here
    /// emulated by a DB whose schema was applied under the historical DDL
    /// then re-run) opens cleanly with the tables present-but-empty.
    #[test]
    fn recovery_escrow_tables_migration_is_idempotent_and_additive() {
        let conn = Connection::open_in_memory().unwrap();
        // Emulate a legacy vault: build the pre-#104b table set by hand
        // (just the device_key + meta minimum) WITHOUT the recovery
        // tables, then run the full migration runner.
        conn.execute_batch(
            "CREATE TABLE device_key (
                id INTEGER PRIMARY KEY CHECK (id = 0),
                enc_seed BLOB NOT NULL, enc_nonce BLOB NOT NULL,
                schema_version INTEGER NOT NULL
            );",
        )
        .unwrap();
        assert!(!table_exists(&conn, "recovery_escrow"));
        assert!(!table_exists(&conn, "recovery_guardians"));
        // First migration run lands both tables.
        apply_pragmas_and_schema(&conn).unwrap();
        assert!(table_exists(&conn, "recovery_escrow"));
        assert!(table_exists(&conn, "recovery_guardians"));
        // Both empty for a never-onboarded legacy vault → read_recovery_escrow
        // returns None (verified in recovery_escrow.rs tests); here just
        // confirm the rows are absent.
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM recovery_escrow", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0);
        // Idempotent re-run: tables still present, single-row CHECK intact.
        apply_pragmas_and_schema(&conn).unwrap();
        let cols = column_names(&conn, "recovery_escrow");
        for needed in [
            "id",
            "wrapped_ct",
            "wrapped_nonce",
            "wrap_schema_version",
            "threshold",
            "guardian_count",
            "epoch",
            "schema_version",
        ] {
            assert_eq!(
                cols.iter().filter(|c| c.as_str() == needed).count(),
                1,
                "recovery_escrow.{needed} should appear exactly once"
            );
        }
    }

    /// MVP-3 issue #106b-2: the `vdk_chain_state` + `vdk_chain` tables land
    /// via `apply_pragmas_and_schema`, survive an idempotent re-run, and a
    /// legacy vault (emulated by a DB without them) opens cleanly with the
    /// tables present-but-empty (the single-epoch-0 default).
    #[test]
    fn vdk_chain_tables_migration_is_idempotent_and_additive() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE device_key (
                id INTEGER PRIMARY KEY CHECK (id = 0),
                enc_seed BLOB NOT NULL, enc_nonce BLOB NOT NULL,
                schema_version INTEGER NOT NULL
            );",
        )
        .unwrap();
        assert!(!table_exists(&conn, "vdk_chain"));
        assert!(!table_exists(&conn, "vdk_chain_state"));
        apply_pragmas_and_schema(&conn).unwrap();
        assert!(table_exists(&conn, "vdk_chain"));
        assert!(table_exists(&conn, "vdk_chain_state"));
        // Empty for a never-rotated vault.
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM vdk_chain", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0);
        let s: i64 = conn
            .query_row("SELECT COUNT(*) FROM vdk_chain_state", [], |r| r.get(0))
            .unwrap();
        assert_eq!(s, 0, "no current-epoch pointer row -> defaults to epoch 0");
        // Idempotent re-run: columns intact.
        apply_pragmas_and_schema(&conn).unwrap();
        let cols = column_names(&conn, "vdk_chain");
        for needed in [
            "epoch",
            "anchor_ct",
            "anchor_nonce",
            "anchor_wrap_schema",
            "device_ct",
            "device_nonce",
            "device_wrap_schema",
            "schema_version",
        ] {
            assert_eq!(
                cols.iter().filter(|c| c.as_str() == needed).count(),
                1,
                "vdk_chain.{needed} should appear exactly once"
            );
        }
    }

    /// MVP-3 issue #106b-2: a legacy `revisions` table lacking the
    /// `vdk_epoch` column (a vault written before #106b-2) gets the column
    /// added on the next migration; the pre-existing row reads as epoch 0
    /// (the single meta VDK), so legacy entries decrypt under the current
    /// epoch exactly as before.
    #[test]
    fn legacy_revisions_table_gets_vdk_epoch_column_defaulting_zero() {
        let conn = Connection::open_in_memory().unwrap();
        // Hand-build a pre-#106b-2 revisions table (1.6 + 4.1 columns, no
        // vdk_epoch).
        conn.execute_batch(
            "CREATE TABLE account_identities (account_id BLOB PRIMARY KEY, created_at INTEGER NOT NULL, last_modified_at INTEGER NOT NULL, tombstoned INTEGER NOT NULL DEFAULT 0, head_revision_id BLOB NOT NULL);
             CREATE TABLE revisions (
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
                superseded_by        BLOB,
                FOREIGN KEY (account_id) REFERENCES account_identities(account_id)
             );",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO account_identities (account_id, created_at, last_modified_at, head_revision_id) VALUES (?1, 0, 0, ?2)",
            [&[0xAAu8; 32] as &[u8], &[0xBBu8; 32] as &[u8]],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO revisions
                (revision_id, account_id, parent_revision_id, device_id, schema_version,
                 created_at, enc_payload, enc_nonce)
             VALUES (?1, ?2, ?3, ?4, 1, 0, ?5, ?6)",
            [
                &[0xBBu8; 32] as &[u8],
                &[0xAAu8; 32] as &[u8],
                &[0x00u8; 32] as &[u8],
                &[0xCCu8; 32] as &[u8],
                &[0xDEu8; 4] as &[u8],
                &[0xEEu8; 24] as &[u8],
            ],
        )
        .unwrap();
        apply_pragmas_and_schema(&conn).unwrap();
        let epoch: i64 = conn
            .query_row(
                "SELECT vdk_epoch FROM revisions WHERE revision_id = ?1",
                [&[0xBBu8; 32] as &[u8]],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            epoch, 0,
            "pre-#106b-2 rows must default to epoch 0 (the single meta VDK)"
        );
    }

    /// MVP-2 issue 4.4: the `meta.sync_mode_preference` column lands
    /// via `apply_pragmas_and_schema` and stays singular under
    /// idempotent re-run.
    #[test]
    fn migrate_sync_mode_preference_column_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        apply_pragmas_and_schema(&conn).unwrap();
        apply_pragmas_and_schema(&conn).unwrap();
        let cols = column_names(&conn, "meta");
        assert_eq!(
            cols.iter()
                .filter(|c| c.as_str() == "sync_mode_preference")
                .count(),
            1,
            "meta.sync_mode_preference should appear exactly once \
             after idempotent re-run"
        );
    }

    /// MVP-2 issue 4.4: a legacy `meta` table lacking the
    /// `sync_mode_preference` column (a vault written before 4.4)
    /// gets the column added on the next migration; the pre-existing
    /// row's value reads as NULL (= `SyncModePreference::Auto`).
    #[test]
    fn migrate_sync_mode_preference_column_on_legacy_vault() {
        let conn = Connection::open_in_memory().unwrap();
        // Hand-build a pre-4.4 meta table (every column 1.4 carries
        // present except sync_mode_preference). The PRIMARY KEY check
        // mirrors the production DDL exactly.
        conn.execute_batch(
            "CREATE TABLE meta (
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
                session_idle_secs INTEGER
            );",
        )
        .unwrap();
        // Seed a pre-4.4 row.
        conn.execute(
            "INSERT INTO meta (
                id, magic, format_version, vault_id, created_at,
                kdf_memory_kib, kdf_time_cost, kdf_parallelism, kdf_salt,
                schema_version, wrapped_ct, wrapped_nonce
            ) VALUES (
                0, ?1, 0, ?2, 0,
                65536, 3, 1, ?3,
                0, ?4, ?5
            )",
            rusqlite::params![
                &[0u8; 8] as &[u8],
                &[0u8; 32] as &[u8],
                &[0u8; 16] as &[u8],
                &[0u8; 32] as &[u8],
                &[0u8; 24] as &[u8],
            ],
        )
        .unwrap();
        // Pre-migration: the column does not exist.
        let cols_before = column_names(&conn, "meta");
        assert!(
            !cols_before
                .iter()
                .any(|c| c.as_str() == "sync_mode_preference"),
            "pre-migration meta must lack sync_mode_preference"
        );
        // Run the full migration runner.
        apply_pragmas_and_schema(&conn).unwrap();
        let cols_after = column_names(&conn, "meta");
        assert!(
            cols_after
                .iter()
                .any(|c| c.as_str() == "sync_mode_preference"),
            "sync_mode_preference column must be added to a legacy meta table"
        );
        // The existing row's column reads NULL.
        let pref: Option<String> = conn
            .query_row(
                "SELECT sync_mode_preference FROM meta WHERE id = 0",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            pref.is_none(),
            "legacy row's sync_mode_preference must read as NULL pre-backfill"
        );
    }

    /// MVP-3 issue #106c2: the `meta.revisionlog_version` column lands via
    /// `apply_pragmas_and_schema` and stays singular under idempotent
    /// re-run.
    #[test]
    fn migrate_revisionlog_version_column_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        apply_pragmas_and_schema(&conn).unwrap();
        apply_pragmas_and_schema(&conn).unwrap();
        let cols = column_names(&conn, "meta");
        assert_eq!(
            cols.iter()
                .filter(|c| c.as_str() == "revisionlog_version")
                .count(),
            1,
            "meta.revisionlog_version should appear exactly once after idempotent re-run"
        );
    }

    /// MVP-3 issue #106c2: a legacy `meta` table lacking the
    /// `revisionlog_version` column (a vault written before #106c2) gets
    /// the column added on the next migration; the pre-existing row's
    /// value reads as NULL (= `RevisionLogVersion::V1`, no regression).
    #[test]
    fn migrate_revisionlog_version_column_on_legacy_vault() {
        let conn = Connection::open_in_memory().unwrap();
        // Hand-build a pre-#106c2 meta table (carries session_idle_secs +
        // sync_mode_preference but NOT revisionlog_version).
        conn.execute_batch(
            "CREATE TABLE meta (
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
                session_idle_secs INTEGER,
                sync_mode_preference TEXT
            );",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO meta (
                id, magic, format_version, vault_id, created_at,
                kdf_memory_kib, kdf_time_cost, kdf_parallelism, kdf_salt,
                schema_version, wrapped_ct, wrapped_nonce
            ) VALUES (
                0, ?1, 0, ?2, 0,
                65536, 3, 1, ?3,
                0, ?4, ?5
            )",
            rusqlite::params![
                &[0u8; 8] as &[u8],
                &[0u8; 32] as &[u8],
                &[0u8; 16] as &[u8],
                &[0u8; 32] as &[u8],
                &[0u8; 24] as &[u8],
            ],
        )
        .unwrap();
        let cols_before = column_names(&conn, "meta");
        assert!(
            !cols_before
                .iter()
                .any(|c| c.as_str() == "revisionlog_version"),
            "pre-migration meta must lack revisionlog_version"
        );
        apply_pragmas_and_schema(&conn).unwrap();
        let cols_after = column_names(&conn, "meta");
        assert!(
            cols_after
                .iter()
                .any(|c| c.as_str() == "revisionlog_version"),
            "revisionlog_version column must be added to a legacy meta table"
        );
        let ver: Option<i64> = conn
            .query_row(
                "SELECT revisionlog_version FROM meta WHERE id = 0",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            ver.is_none(),
            "legacy row's revisionlog_version must read as NULL (→ V1)"
        );
    }

    /// MVP-3 issue #106c2: the SEPARATE `chain_sync_v2_state` table lands
    /// via `apply_pragmas_and_schema`.
    #[test]
    fn migrate_chain_sync_v2_state_table_present() {
        let conn = Connection::open_in_memory().unwrap();
        apply_pragmas_and_schema(&conn).unwrap();
        assert!(table_exists(&conn, "chain_sync_v2_state"));
    }
}
