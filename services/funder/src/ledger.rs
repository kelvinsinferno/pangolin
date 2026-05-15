// SPDX-License-Identifier: AGPL-3.0-or-later
//! `SQLite`-backed payment ledger.
//!
//! Per R-b verbatim: rate-limit state is in-memory (resets clean on
//! restart, conservative posture); the payment ledger lives in `SQLite`
//! so the **off-chain replay defense survives restart**. A leaked
//! Credit attestation cannot be processed twice — the first processing
//! lands an `attestation_hash UNIQUE` row, the second insert errors
//! out with [`LedgerError::AlreadyExists`].
//!
//! ## Schema (v2, audit fix-pass 2026-05-15)
//!
//! ```sql
//! CREATE TABLE IF NOT EXISTS payments (
//!     id                     INTEGER PRIMARY KEY AUTOINCREMENT,
//!     attestation_hash       BLOB    NOT NULL UNIQUE,
//!     user_id                BLOB    NOT NULL,
//!     device_address         BLOB    NOT NULL,
//!     credit_amount          BLOB    NOT NULL,   -- 32-byte big-endian U256
//!     redemption_tx_hash     BLOB,               -- populated post-redeem-submit
//!     state                  TEXT NOT NULL DEFAULT 'pre_redeem',
//!     eth_transfer_tx_hash   BLOB,               -- populated post-transfer-submit
//!     eth_transfer_block     INTEGER,            -- populated post-transfer-mine
//!     eth_transferred_wei    BLOB,               -- 32-byte big-endian U256
//!     created_at             INTEGER NOT NULL    -- unix seconds
//! );
//!
//! CREATE TABLE IF NOT EXISTS schema_version (
//!     version    INTEGER PRIMARY KEY,
//!     applied_at INTEGER NOT NULL
//! );
//! ```
//!
//! ## Lifecycle states (L-payment-order per plan-doc)
//!
//! The `state` column tracks the two-leg redeem→eth-transfer flow:
//!
//! ```text
//! PreRedeem
//!   └─→ RedeemSubmitted (eth_sendRawTransaction returned; tx hash known)
//!       └─→ RedeemMined (redeem receipt status=1; balance debited)
//!           └─→ EthTransferSubmitted (transfer tx broadcast)
//!               └─→ EthTransferMined (transfer receipt status=1; ETH delivered)
//!
//! From any RedeemMined / EthTransferSubmitted state, a failure
//! advances to EthTransferFailed (terminal; manual reconciliation).
//! ```
//!
//! ## Schema version
//!
//! Current version is `2` (audit fix-pass adds the lifecycle columns).
//! The migration path is forward-only + idempotent: opening a v1 db
//! adds the new columns with their defaults (`state = 'pre_redeem'`
//! for existing rows). Unknown future versions (binary older than db)
//! fail closed with [`LedgerError::FutureSchemaVersion`].
//!
//! ## Threading
//!
//! `rusqlite::Connection` is `Sync` only behind `Mutex` since `SQLite`
//! itself serialises writers. We wrap a single connection in a
//! `tokio::sync::Mutex` — for the funder's expected QPS (bounded by
//! the rate limiter at ~200/hour) a single connection is plenty. The
//! mutex is async so axum handlers don't block the executor on a
//! contended write.

use core::fmt;
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use alloy::primitives::{Address, B256, U256};
use rusqlite::{params, Connection, OptionalExtension};
use thiserror::Error;
use tokio::sync::Mutex;

/// Current funder ledger schema version. Bump + ship a migration for
/// every breaking change to the table layouts. v2 (audit fix-pass)
/// adds the `state` / `eth_transfer_*` columns.
pub const CURRENT_SCHEMA_VERSION: i64 = 2;

/// Lifecycle states for the two-leg redeem→eth-transfer flow.
///
/// Encoded as a TEXT column in the ledger using the lowercase snake-
/// case variant name (`pre_redeem` / `redeem_submitted` / ...). New
/// variants in future schema bumps MUST also append to
/// [`PaymentState::as_db_str`] + [`PaymentState::parse_db_str`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaymentState {
    /// Ledger row inserted; redemption tx not yet broadcast.
    PreRedeem,
    /// Redemption tx submitted via `eth_sendRawTransaction`; awaiting
    /// receipt.
    RedeemSubmitted,
    /// Redemption tx mined with status=1; user balance debited on
    /// chain. ETH transfer not yet attempted.
    RedeemMined,
    /// ETH-transfer tx submitted; awaiting receipt.
    EthTransferSubmitted,
    /// ETH-transfer tx mined with status=1; flow complete.
    EthTransferMined,
    /// Terminal failure state: redeem succeeded but the ETH-transfer
    /// leg failed (RPC timeout, insufficient hot-wallet balance,
    /// transfer reverted). Manual reconciliation required.
    EthTransferFailed,
}

impl PaymentState {
    /// On-disk encoding (TEXT column value).
    #[must_use]
    pub const fn as_db_str(self) -> &'static str {
        match self {
            Self::PreRedeem => "pre_redeem",
            Self::RedeemSubmitted => "redeem_submitted",
            Self::RedeemMined => "redeem_mined",
            Self::EthTransferSubmitted => "eth_transfer_submitted",
            Self::EthTransferMined => "eth_transfer_mined",
            Self::EthTransferFailed => "eth_transfer_failed",
        }
    }

    /// Inverse of [`Self::as_db_str`]. Unknown strings return `None`
    /// so the caller can fail closed with [`LedgerError::Sqlite`].
    #[must_use]
    pub fn parse_db_str(s: &str) -> Option<Self> {
        match s {
            "pre_redeem" => Some(Self::PreRedeem),
            "redeem_submitted" => Some(Self::RedeemSubmitted),
            "redeem_mined" => Some(Self::RedeemMined),
            "eth_transfer_submitted" => Some(Self::EthTransferSubmitted),
            "eth_transfer_mined" => Some(Self::EthTransferMined),
            "eth_transfer_failed" => Some(Self::EthTransferFailed),
            _ => None,
        }
    }
}

/// Errors surfaced by [`PaymentLedger`] operations.
#[derive(Debug, Error)]
pub enum LedgerError {
    /// Underlying `SQLite` error. The wrapped message is the
    /// `rusqlite::Error::Display` — no user-payload content.
    #[error("ledger SQLite error: {0}")]
    Sqlite(String),

    /// Attempt to insert a row whose `attestation_hash` is already in
    /// the ledger. This is the off-chain replay defense (R-c +
    /// L-credit-attestation-replay): a duplicate Credit attestation
    /// returns this so the handler can answer HTTP 409 without
    /// touching the chain.
    #[error("payment with attestation_hash {0} already exists in the ledger")]
    AlreadyExists(B256),

    /// The on-disk schema version is newer than the binary supports.
    /// The funder fails closed: an operator running a downgraded
    /// binary against a forward-migrated DB would otherwise corrupt
    /// the ledger.
    #[error("ledger schema version {found} is newer than this binary supports ({supported})")]
    FutureSchemaVersion {
        /// Schema version recorded in the on-disk DB.
        found: i64,
        /// Maximum schema version this binary supports.
        supported: i64,
    },
}

impl From<rusqlite::Error> for LedgerError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Sqlite(e.to_string())
    }
}

/// Row shape returned by [`PaymentLedger::get_by_attestation_hash`].
///
/// `credit_amount` is reconstructed from the on-disk 32-byte big-endian
/// representation so callers don't have to know the storage layout.
#[derive(Clone, PartialEq, Eq)]
pub struct PaymentRow {
    /// Attestation hash (primary replay key).
    pub attestation_hash: B256,
    /// userId from the Credit attestation.
    pub user_id: [u8; 32],
    /// EVM address that received the ETH transfer.
    pub device_address: Address,
    /// Amount of credits in the Credit attestation.
    pub credit_amount: U256,
    /// Redemption tx hash, or `None` if the redemption hasn't been
    /// submitted yet (the handler inserts the row first, then submits
    /// the redeem tx, then updates this column).
    pub redemption_tx_hash: Option<B256>,
    /// Lifecycle state in the two-leg flow.
    pub state: PaymentState,
    /// ETH-transfer tx hash, or `None` if the transfer has not been
    /// submitted yet.
    pub eth_transfer_tx_hash: Option<B256>,
    /// ETH-transfer block number, or `None` if the transfer has not
    /// mined yet.
    pub eth_transfer_block: Option<u64>,
    /// Wei value of the dispatched ETH transfer, or `None` if the
    /// transfer has not been submitted yet.
    pub eth_transferred_wei: Option<U256>,
    /// Unix seconds of row creation.
    pub created_at: u64,
}

impl fmt::Debug for PaymentRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // L12: PaymentRow has user-identifying fields; redact at the
        // `Debug` layer so accidental `dbg!()` / `tracing::error!("{row:?}")`
        // calls don't surface them.
        f.debug_struct("PaymentRow")
            .field("attestation_hash", &self.attestation_hash)
            .field("user_id", &"<redacted>")
            .field("device_address", &"<redacted>")
            .field("credit_amount", &"<redacted>")
            .field("redemption_tx_hash", &self.redemption_tx_hash)
            .field("state", &self.state)
            .field("eth_transfer_tx_hash", &self.eth_transfer_tx_hash)
            .field("eth_transfer_block", &self.eth_transfer_block)
            .field("eth_transferred_wei", &"<redacted>")
            .field("created_at", &self.created_at)
            .finish()
    }
}

/// `SQLite`-backed payment ledger.
///
/// Cloning shares the underlying connection via `Arc`; concurrent
/// callers serialise on the `Mutex`. The mutex is intentional — `SQLite`
/// serialises writers anyway; the mutex just makes the contention
/// happen at the Rust layer rather than at the SQL layer.
#[derive(Debug, Clone)]
pub struct PaymentLedger {
    conn: Arc<Mutex<Connection>>,
}

impl PaymentLedger {
    /// Open a ledger at `path` (creating the file if absent). Runs
    /// the schema migration to the current version on first open.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, LedgerError> {
        let conn = Connection::open(path)?;
        // Apply migration synchronously at open time, BEFORE wrapping
        // the connection in the async mutex — this avoids
        // `Mutex::blocking_lock` (which panics under an active
        // tokio runtime per tokio 1.x rules) while still keeping
        // the migration eagerly idempotent.
        Self::migrate_owned(&conn)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Open an in-memory ledger. Used in tests + as a fallback
    /// configuration the operator can use for ephemeral runs (NOT
    /// recommended for production — defeats the cross-restart
    /// replay defense).
    pub fn open_in_memory() -> Result<Self, LedgerError> {
        let conn = Connection::open_in_memory()?;
        Self::migrate_owned(&conn)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Apply pending migrations on an owned connection (pre-wrap).
    /// Idempotent — running on an already-migrated DB is a no-op.
    fn migrate_owned(conn: &Connection) -> Result<(), LedgerError> {
        // v1 baseline: tables exist with the original column set.
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_version (
                version    INTEGER PRIMARY KEY,
                applied_at INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS payments (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                attestation_hash    BLOB    NOT NULL UNIQUE,
                user_id             BLOB    NOT NULL,
                device_address      BLOB    NOT NULL,
                credit_amount       BLOB    NOT NULL,
                redemption_tx_hash  BLOB,
                created_at          INTEGER NOT NULL
             );",
        )?;

        // Read the latest applied version; if absent, install the
        // initial version. `MAX(version)` returns `NULL` on an empty
        // table, which `rusqlite` surfaces as `Option<i64>`.
        let current: Option<i64> =
            conn.query_row("SELECT MAX(version) FROM schema_version", [], |row| {
                row.get::<_, Option<i64>>(0)
            })?;

        match current {
            None => {
                // Fresh database: create at the current schema
                // version directly with all v2 columns.
                Self::apply_v2_columns(conn)?;
                conn.execute(
                    "INSERT INTO schema_version (version, applied_at) VALUES (?1, ?2)",
                    params![CURRENT_SCHEMA_VERSION, now_unix_seconds_i64()],
                )?;
                Ok(())
            }
            Some(v) if v == CURRENT_SCHEMA_VERSION => {
                // Same version + idempotent column adds: a previous
                // crash between the `ALTER TABLE` and the version
                // insert would leave us here legitimately. Re-running
                // the column adds is a no-op (IF NOT EXISTS would be
                // nice but SQLite < 3.35 doesn't support it for
                // `ADD COLUMN`; we instead detect-or-add).
                Self::apply_v2_columns(conn)?;
                Ok(())
            }
            Some(v) if v < CURRENT_SCHEMA_VERSION => {
                // v1 → v2: add the lifecycle columns. Defaults match
                // the audit-fix-pass plan: existing rows inherit
                // `state = 'pre_redeem'` (the safe default — the
                // resume-scan re-classifies them when it sees the
                // redemption_tx_hash NULL → still PreRedeem; non-NULL
                // → operator intervention since the row pre-dates
                // the state column).
                Self::apply_v2_columns(conn)?;
                // Promote any v1 rows that already have a
                // redemption_tx_hash populated to RedeemSubmitted so
                // the resume-scan picks them up. A v1 row could not
                // have advanced further than that.
                conn.execute(
                    "UPDATE payments SET state = 'redeem_submitted' \
                     WHERE redemption_tx_hash IS NOT NULL AND state = 'pre_redeem'",
                    [],
                )?;
                conn.execute(
                    "INSERT INTO schema_version (version, applied_at) VALUES (?1, ?2)",
                    params![CURRENT_SCHEMA_VERSION, now_unix_seconds_i64()],
                )?;
                Ok(())
            }
            Some(v) => Err(LedgerError::FutureSchemaVersion {
                found: v,
                supported: CURRENT_SCHEMA_VERSION,
            }),
        }
    }

    /// Add the v2 lifecycle columns to the `payments` table if absent.
    /// `SQLite` < 3.35 has no `ADD COLUMN IF NOT EXISTS` syntax, so we
    /// probe the column list via `PRAGMA table_info` first.
    fn apply_v2_columns(conn: &Connection) -> Result<(), LedgerError> {
        let mut stmt = conn.prepare("PRAGMA table_info(payments)")?;
        let cols: Vec<String> = stmt
            .query_map([], |r| r.get::<_, String>(1))?
            .filter_map(Result::ok)
            .collect();
        let has = |name: &str| cols.iter().any(|c| c == name);
        if !has("state") {
            conn.execute(
                "ALTER TABLE payments ADD COLUMN state TEXT NOT NULL DEFAULT 'pre_redeem'",
                [],
            )?;
        }
        if !has("eth_transfer_tx_hash") {
            conn.execute(
                "ALTER TABLE payments ADD COLUMN eth_transfer_tx_hash BLOB",
                [],
            )?;
        }
        if !has("eth_transfer_block") {
            conn.execute(
                "ALTER TABLE payments ADD COLUMN eth_transfer_block INTEGER",
                [],
            )?;
        }
        if !has("eth_transferred_wei") {
            conn.execute(
                "ALTER TABLE payments ADD COLUMN eth_transferred_wei BLOB",
                [],
            )?;
        }
        Ok(())
    }

    /// Insert a new payment row. Returns `Ok(true)` on a fresh
    /// insert, `Ok(false)` if the `attestation_hash` already exists
    /// (the L-credit-attestation-replay 409 path).
    ///
    /// The `redemption_tx_hash` column is `NULL` at insert time; the
    /// caller calls [`Self::update_redemption_tx_hash`] after a
    /// successful submit.
    pub async fn try_insert(
        &self,
        attestation_hash: B256,
        user_id: [u8; 32],
        device_address: Address,
        credit_amount: U256,
    ) -> Result<bool, LedgerError> {
        let conn = self.conn.lock().await;
        let now = now_unix_seconds_i64();
        let res = conn.execute(
            "INSERT INTO payments (attestation_hash, user_id, device_address, credit_amount, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                attestation_hash.as_slice(),
                user_id.as_slice(),
                device_address.as_slice(),
                credit_amount.to_be_bytes::<32>().as_slice(),
                now,
            ],
        );
        match res {
            Ok(_) => Ok(true),
            Err(rusqlite::Error::SqliteFailure(err, _))
                if err.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                Ok(false)
            }
            Err(e) => Err(LedgerError::from(e)),
        }
    }

    /// Update the `redemption_tx_hash` column for a row identified by
    /// `attestation_hash`. Returns `Ok(true)` on update,
    /// `Ok(false)` if the row was not found. Also advances the
    /// lifecycle state to `redeem_submitted`.
    pub async fn update_redemption_tx_hash(
        &self,
        attestation_hash: B256,
        tx_hash: B256,
    ) -> Result<bool, LedgerError> {
        let conn = self.conn.lock().await;
        let n = conn.execute(
            "UPDATE payments SET redemption_tx_hash = ?1, state = 'redeem_submitted' \
             WHERE attestation_hash = ?2",
            params![tx_hash.as_slice(), attestation_hash.as_slice()],
        )?;
        Ok(n > 0)
    }

    /// Atomic state transition. Updates the `state` column for the
    /// row identified by `attestation_hash`. Returns `Ok(true)` on
    /// update, `Ok(false)` if no row was affected (caller decides
    /// whether to treat that as an error).
    pub async fn transition_state(
        &self,
        attestation_hash: B256,
        new_state: PaymentState,
    ) -> Result<bool, LedgerError> {
        let conn = self.conn.lock().await;
        let n = conn.execute(
            "UPDATE payments SET state = ?1 WHERE attestation_hash = ?2",
            params![new_state.as_db_str(), attestation_hash.as_slice()],
        )?;
        Ok(n > 0)
    }

    /// Mark the ETH-transfer submission: stamp the tx hash + the
    /// `eth_transferred_wei` value, advance the state to
    /// `eth_transfer_submitted`. The block number stays NULL until the
    /// receipt confirms.
    pub async fn mark_eth_transfer_submitted(
        &self,
        attestation_hash: B256,
        eth_transfer_tx_hash: B256,
        eth_transferred_wei: U256,
    ) -> Result<bool, LedgerError> {
        let conn = self.conn.lock().await;
        let n = conn.execute(
            "UPDATE payments \
             SET eth_transfer_tx_hash = ?1, \
                 eth_transferred_wei  = ?2, \
                 state                = 'eth_transfer_submitted' \
             WHERE attestation_hash = ?3",
            params![
                eth_transfer_tx_hash.as_slice(),
                eth_transferred_wei.to_be_bytes::<32>().as_slice(),
                attestation_hash.as_slice(),
            ],
        )?;
        Ok(n > 0)
    }

    /// Mark the ETH-transfer as mined: stamp the block number, advance
    /// the state to `eth_transfer_mined`.
    pub async fn mark_eth_transfer_mined(
        &self,
        attestation_hash: B256,
        eth_transfer_block: u64,
    ) -> Result<bool, LedgerError> {
        let conn = self.conn.lock().await;
        let block_i64 = i64::try_from(eth_transfer_block).unwrap_or(i64::MAX);
        let n = conn.execute(
            "UPDATE payments \
             SET eth_transfer_block = ?1, \
                 state              = 'eth_transfer_mined' \
             WHERE attestation_hash = ?2",
            params![block_i64, attestation_hash.as_slice()],
        )?;
        Ok(n > 0)
    }

    /// Find rows in resumable in-flight states. Used at startup by
    /// [`crate::resume`] to pick up in-flight transactions left by a
    /// previous run (per L-payment-order — the restart-scan resume
    /// closes the user-paid-for-nothing window).
    ///
    /// Returns rows with `state IN ('redeem_submitted', 'redeem_mined',
    /// 'eth_transfer_submitted')`. Rows in `pre_redeem` are NOT
    /// resumed — the redemption tx was never broadcast, so the user
    /// can simply retry. Rows in `eth_transfer_mined` or
    /// `eth_transfer_failed` are terminal.
    pub async fn find_resumable_entries(&self) -> Result<Vec<PaymentRow>, LedgerError> {
        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare(
            "SELECT attestation_hash, user_id, device_address, credit_amount, \
                    redemption_tx_hash, state, eth_transfer_tx_hash, \
                    eth_transfer_block, eth_transferred_wei, created_at \
             FROM payments \
             WHERE state IN ('redeem_submitted', 'redeem_mined', 'eth_transfer_submitted')",
        )?;
        let rows = stmt
            .query_map([], |r| {
                let ah: Vec<u8> = r.get(0)?;
                let uid: Vec<u8> = r.get(1)?;
                let da: Vec<u8> = r.get(2)?;
                let ca: Vec<u8> = r.get(3)?;
                let rtx: Option<Vec<u8>> = r.get(4)?;
                let state_s: String = r.get(5)?;
                let etx: Option<Vec<u8>> = r.get(6)?;
                let eblock: Option<i64> = r.get(7)?;
                let ew: Option<Vec<u8>> = r.get(8)?;
                let created: i64 = r.get(9)?;
                Ok((ah, uid, da, ca, rtx, state_s, etx, eblock, ew, created))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let mut out = Vec::with_capacity(rows.len());
        for (ah, uid, da, ca, rtx, state_s, etx, eblock, ew, created) in rows {
            let attestation_hash = vec_to_b256(&ah)?;
            let user_id = vec_to_array32(&uid)?;
            let device_address = vec_to_address(&da)?;
            let credit_amount = U256::from_be_slice(&ca);
            let redemption_tx_hash = match rtx {
                Some(bytes) => Some(vec_to_b256(&bytes)?),
                None => None,
            };
            let state = PaymentState::parse_db_str(&state_s)
                .ok_or_else(|| LedgerError::Sqlite(format!("unknown payment state {state_s:?}")))?;
            let eth_transfer_tx_hash = match etx {
                Some(bytes) => Some(vec_to_b256(&bytes)?),
                None => None,
            };
            let eth_transfer_block = eblock.map(|v| u64::try_from(v).unwrap_or(0));
            let eth_transferred_wei = ew.as_ref().map(|b| U256::from_be_slice(b));
            let created_at = u64::try_from(created).unwrap_or(0);
            out.push(PaymentRow {
                attestation_hash,
                user_id,
                device_address,
                credit_amount,
                redemption_tx_hash,
                state,
                eth_transfer_tx_hash,
                eth_transfer_block,
                eth_transferred_wei,
                created_at,
            });
        }
        Ok(out)
    }

    /// Retrieve a payment row by attestation hash. Returns `None` if
    /// not present.
    pub async fn get_by_attestation_hash(
        &self,
        attestation_hash: B256,
    ) -> Result<Option<PaymentRow>, LedgerError> {
        let conn = self.conn.lock().await;
        let row = conn
            .query_row(
                "SELECT attestation_hash, user_id, device_address, credit_amount, \
                        redemption_tx_hash, state, eth_transfer_tx_hash, \
                        eth_transfer_block, eth_transferred_wei, created_at \
                 FROM payments WHERE attestation_hash = ?1",
                params![attestation_hash.as_slice()],
                |r| {
                    let ah: Vec<u8> = r.get(0)?;
                    let uid: Vec<u8> = r.get(1)?;
                    let da: Vec<u8> = r.get(2)?;
                    let ca: Vec<u8> = r.get(3)?;
                    let rtx: Option<Vec<u8>> = r.get(4)?;
                    let state_s: String = r.get(5)?;
                    let etx: Option<Vec<u8>> = r.get(6)?;
                    let eblock: Option<i64> = r.get(7)?;
                    let ew: Option<Vec<u8>> = r.get(8)?;
                    let created: i64 = r.get(9)?;
                    Ok((ah, uid, da, ca, rtx, state_s, etx, eblock, ew, created))
                },
            )
            .optional()?;
        let Some((ah, uid, da, ca, rtx, state_s, etx, eblock, ew, created)) = row else {
            return Ok(None);
        };
        let attestation_hash = vec_to_b256(&ah)?;
        let user_id = vec_to_array32(&uid)?;
        let device_address = vec_to_address(&da)?;
        let credit_amount = U256::from_be_slice(&ca);
        let redemption_tx_hash = match rtx {
            Some(bytes) => Some(vec_to_b256(&bytes)?),
            None => None,
        };
        let state = PaymentState::parse_db_str(&state_s)
            .ok_or_else(|| LedgerError::Sqlite(format!("unknown payment state {state_s:?}")))?;
        let eth_transfer_tx_hash = match etx {
            Some(bytes) => Some(vec_to_b256(&bytes)?),
            None => None,
        };
        let eth_transfer_block = eblock.map(|v| u64::try_from(v).unwrap_or(0));
        let eth_transferred_wei = ew.as_ref().map(|b| U256::from_be_slice(b));
        let created_at = u64::try_from(created).unwrap_or(0);
        Ok(Some(PaymentRow {
            attestation_hash,
            user_id,
            device_address,
            credit_amount,
            redemption_tx_hash,
            state,
            eth_transfer_tx_hash,
            eth_transfer_block,
            eth_transferred_wei,
            created_at,
        }))
    }
}

fn now_unix_seconds_i64() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

fn vec_to_b256(v: &[u8]) -> Result<B256, LedgerError> {
    if v.len() != 32 {
        return Err(LedgerError::Sqlite(format!(
            "blob length {} != 32 for B256 column",
            v.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(v);
    Ok(B256::from(arr))
}

fn vec_to_array32(v: &[u8]) -> Result<[u8; 32], LedgerError> {
    if v.len() != 32 {
        return Err(LedgerError::Sqlite(format!(
            "blob length {} != 32 for [u8; 32] column",
            v.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(v);
    Ok(arr)
}

fn vec_to_address(v: &[u8]) -> Result<Address, LedgerError> {
    if v.len() != 20 {
        return Err(LedgerError::Sqlite(format!(
            "blob length {} != 20 for Address column",
            v.len()
        )));
    }
    let mut arr = [0u8; 20];
    arr.copy_from_slice(v);
    Ok(Address::from(arr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{address, b256, U256};
    use tempfile::tempdir;

    fn sample_user_id() -> [u8; 32] {
        [0xAAu8; 32]
    }

    fn sample_addr() -> Address {
        address!("0x0000000000000000000000000000000000001234")
    }

    #[tokio::test]
    async fn open_in_memory_initialises_schema() {
        let ledger = PaymentLedger::open_in_memory().expect("open");
        // Sanity: a fresh ledger answers None for a random hash.
        let absent = ledger
            .get_by_attestation_hash(b256!(
                "0x0101010101010101010101010101010101010101010101010101010101010101"
            ))
            .await
            .expect("query");
        assert!(absent.is_none());
    }

    #[tokio::test]
    async fn try_insert_then_duplicate_returns_false() {
        let ledger = PaymentLedger::open_in_memory().expect("open");
        let h = b256!("0x0202020202020202020202020202020202020202020202020202020202020202");
        let first = ledger
            .try_insert(h, sample_user_id(), sample_addr(), U256::from(100u64))
            .await
            .expect("insert");
        assert!(first, "first insert should be fresh");
        let second = ledger
            .try_insert(h, sample_user_id(), sample_addr(), U256::from(100u64))
            .await
            .expect("insert");
        assert!(!second, "duplicate insert should report not-fresh");
    }

    #[tokio::test]
    async fn update_redemption_tx_hash_round_trip() {
        let ledger = PaymentLedger::open_in_memory().expect("open");
        let h = b256!("0x0303030303030303030303030303030303030303030303030303030303030303");
        let amount = U256::from(123u64);
        ledger
            .try_insert(h, sample_user_id(), sample_addr(), amount)
            .await
            .expect("insert");
        let tx = b256!("0x0404040404040404040404040404040404040404040404040404040404040404");
        let updated = ledger
            .update_redemption_tx_hash(h, tx)
            .await
            .expect("update");
        assert!(updated);
        let row = ledger
            .get_by_attestation_hash(h)
            .await
            .expect("query")
            .expect("present");
        assert_eq!(row.attestation_hash, h);
        assert_eq!(row.user_id, sample_user_id());
        assert_eq!(row.device_address, sample_addr());
        assert_eq!(row.credit_amount, amount);
        assert_eq!(row.redemption_tx_hash, Some(tx));
    }

    #[tokio::test]
    async fn cold_restart_preserves_duplicate_detection() {
        // Open a temp-file ledger; insert a row; drop the handle;
        // re-open the file; assert the duplicate-detection still
        // fires.
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("funder-ledger.sqlite");
        let h = b256!("0x0505050505050505050505050505050505050505050505050505050505050505");
        {
            let ledger = PaymentLedger::open(&path).expect("open");
            let first = ledger
                .try_insert(h, sample_user_id(), sample_addr(), U256::from(7u64))
                .await
                .expect("insert");
            assert!(first);
        }
        // Re-open; insert the same hash; must report not-fresh.
        let ledger = PaymentLedger::open(&path).expect("reopen");
        let second = ledger
            .try_insert(h, sample_user_id(), sample_addr(), U256::from(7u64))
            .await
            .expect("insert");
        assert!(!second, "cold restart should preserve duplicate-detection");
    }

    #[tokio::test]
    async fn state_transitions_pre_redeem_to_redeem_mined() {
        let ledger = PaymentLedger::open_in_memory().expect("open");
        let h = b256!("0x1010101010101010101010101010101010101010101010101010101010101010");
        ledger
            .try_insert(h, sample_user_id(), sample_addr(), U256::from(50u64))
            .await
            .expect("insert");
        // Fresh row starts in PreRedeem.
        let row = ledger
            .get_by_attestation_hash(h)
            .await
            .expect("query")
            .expect("present");
        assert_eq!(row.state, PaymentState::PreRedeem);

        // Stamping the redeem tx hash advances to RedeemSubmitted.
        let tx = b256!("0x2020202020202020202020202020202020202020202020202020202020202020");
        ledger
            .update_redemption_tx_hash(h, tx)
            .await
            .expect("update");
        let row = ledger
            .get_by_attestation_hash(h)
            .await
            .expect("query")
            .expect("present");
        assert_eq!(row.state, PaymentState::RedeemSubmitted);
        assert_eq!(row.redemption_tx_hash, Some(tx));

        // Explicit transition to RedeemMined.
        let did = ledger
            .transition_state(h, PaymentState::RedeemMined)
            .await
            .expect("transition");
        assert!(did);
        let row = ledger
            .get_by_attestation_hash(h)
            .await
            .expect("query")
            .expect("present");
        assert_eq!(row.state, PaymentState::RedeemMined);
    }

    #[tokio::test]
    async fn state_transitions_redeem_mined_to_eth_transfer_mined() {
        let ledger = PaymentLedger::open_in_memory().expect("open");
        let h = b256!("0x3030303030303030303030303030303030303030303030303030303030303030");
        ledger
            .try_insert(h, sample_user_id(), sample_addr(), U256::from(50u64))
            .await
            .expect("insert");
        ledger
            .transition_state(h, PaymentState::RedeemMined)
            .await
            .expect("transition");

        let eth_tx = b256!("0x4040404040404040404040404040404040404040404040404040404040404040");
        let value = U256::from(10_000_000_000_000_000u128);
        ledger
            .mark_eth_transfer_submitted(h, eth_tx, value)
            .await
            .expect("mark submitted");
        let row = ledger
            .get_by_attestation_hash(h)
            .await
            .expect("query")
            .expect("present");
        assert_eq!(row.state, PaymentState::EthTransferSubmitted);
        assert_eq!(row.eth_transfer_tx_hash, Some(eth_tx));
        assert_eq!(row.eth_transferred_wei, Some(value));

        ledger
            .mark_eth_transfer_mined(h, 1_234)
            .await
            .expect("mark mined");
        let row = ledger
            .get_by_attestation_hash(h)
            .await
            .expect("query")
            .expect("present");
        assert_eq!(row.state, PaymentState::EthTransferMined);
        assert_eq!(row.eth_transfer_block, Some(1_234));
    }

    #[tokio::test]
    async fn find_resumable_entries_returns_in_flight_states() {
        let ledger = PaymentLedger::open_in_memory().expect("open");
        // Three rows: one PreRedeem (NOT resumable), one RedeemMined,
        // one EthTransferSubmitted.
        let h_pre = b256!("0x5050505050505050505050505050505050505050505050505050505050505050");
        let h_mined = b256!("0x6060606060606060606060606060606060606060606060606060606060606060");
        let h_sub = b256!("0x7070707070707070707070707070707070707070707070707070707070707070");
        for h in &[h_pre, h_mined, h_sub] {
            ledger
                .try_insert(*h, sample_user_id(), sample_addr(), U256::from(1u64))
                .await
                .expect("insert");
        }
        ledger
            .transition_state(h_mined, PaymentState::RedeemMined)
            .await
            .expect("transition");
        ledger
            .transition_state(h_sub, PaymentState::EthTransferSubmitted)
            .await
            .expect("transition");

        let rows = ledger.find_resumable_entries().await.expect("scan");
        let mut got: Vec<B256> = rows.iter().map(|r| r.attestation_hash).collect();
        got.sort();
        let mut want = [h_mined, h_sub];
        want.sort();
        assert_eq!(got, want);
        // PreRedeem must NOT be in the resumable set.
        assert!(rows.iter().all(|r| r.attestation_hash != h_pre));
    }

    #[tokio::test]
    async fn migration_idempotent() {
        // Opening the same file twice must succeed; the v2 column
        // adds are guarded by the PRAGMA-table-info probe.
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("funder-ledger.sqlite");
        let h = b256!("0x8080808080808080808080808080808080808080808080808080808080808080");
        {
            let ledger = PaymentLedger::open(&path).expect("open");
            ledger
                .try_insert(h, sample_user_id(), sample_addr(), U256::from(1u64))
                .await
                .expect("insert");
        }
        // Re-open: migration should be a no-op + the row preserved
        // with the default state.
        let ledger = PaymentLedger::open(&path).expect("reopen");
        let row = ledger
            .get_by_attestation_hash(h)
            .await
            .expect("query")
            .expect("present");
        assert_eq!(row.state, PaymentState::PreRedeem);
        // Third open: still idempotent.
        drop(ledger);
        let _ledger = PaymentLedger::open(&path).expect("reopen again");
    }
}
