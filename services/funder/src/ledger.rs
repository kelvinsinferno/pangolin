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
//! ## Schema (initial)
//!
//! ```sql
//! CREATE TABLE IF NOT EXISTS payments (
//!     id                  INTEGER PRIMARY KEY AUTOINCREMENT,
//!     attestation_hash    BLOB    NOT NULL UNIQUE,
//!     user_id             BLOB    NOT NULL,
//!     device_address      BLOB    NOT NULL,
//!     credit_amount       BLOB    NOT NULL,      -- 32-byte big-endian U256
//!     redemption_tx_hash  BLOB,                  -- populated post-submit
//!     created_at          INTEGER NOT NULL       -- unix seconds
//! );
//!
//! CREATE TABLE IF NOT EXISTS schema_version (
//!     version    INTEGER PRIMARY KEY,
//!     applied_at INTEGER NOT NULL
//! );
//! ```
//!
//! ## Schema version
//!
//! Initial version is `1`. Future migrations bump this; the open path
//! reads the current version + applies any pending migrations in
//! order. Unknown future versions (binary older than db) fail closed
//! with [`LedgerError::FutureSchemaVersion`].
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
/// every breaking change to the table layouts.
pub const CURRENT_SCHEMA_VERSION: i64 = 1;

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
                conn.execute(
                    "INSERT INTO schema_version (version, applied_at) VALUES (?1, ?2)",
                    params![CURRENT_SCHEMA_VERSION, now_unix_seconds_i64()],
                )?;
                Ok(())
            }
            Some(v) if v == CURRENT_SCHEMA_VERSION => Ok(()),
            Some(v) if v < CURRENT_SCHEMA_VERSION => {
                // Apply migrations v..CURRENT here. No migrations
                // beyond the initial schema today; this arm is the
                // structural slot for the next bump.
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
    /// `Ok(false)` if the row was not found.
    pub async fn update_redemption_tx_hash(
        &self,
        attestation_hash: B256,
        tx_hash: B256,
    ) -> Result<bool, LedgerError> {
        let conn = self.conn.lock().await;
        let n = conn.execute(
            "UPDATE payments SET redemption_tx_hash = ?1 WHERE attestation_hash = ?2",
            params![tx_hash.as_slice(), attestation_hash.as_slice()],
        )?;
        Ok(n > 0)
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
                "SELECT attestation_hash, user_id, device_address, credit_amount, redemption_tx_hash, created_at \
                 FROM payments WHERE attestation_hash = ?1",
                params![attestation_hash.as_slice()],
                |r| {
                    let ah: Vec<u8> = r.get(0)?;
                    let uid: Vec<u8> = r.get(1)?;
                    let da: Vec<u8> = r.get(2)?;
                    let ca: Vec<u8> = r.get(3)?;
                    let rtx: Option<Vec<u8>> = r.get(4)?;
                    let created: i64 = r.get(5)?;
                    Ok((ah, uid, da, ca, rtx, created))
                },
            )
            .optional()?;
        let Some((ah, uid, da, ca, rtx, created)) = row else {
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
        let created_at = u64::try_from(created).unwrap_or(0);
        Ok(Some(PaymentRow {
            attestation_hash,
            user_id,
            device_address,
            credit_amount,
            redemption_tx_hash,
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
}
