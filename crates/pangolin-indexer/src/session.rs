// SPDX-License-Identifier: AGPL-3.0-or-later
//! 4.2 R-a + R-c + L1..L12 lifecycle.
//!
//! The session is the canonical entry point both flows share (R-e
//! + L12):
//!
//! - Desktop subprocess: `bin/pangolin-indexer.rs` instantiates an
//!   [`IndexerSession`] + drives stdin → `handle_request` →
//!   `IndexerResponse` → stdout.
//! - Mobile in-process: the host calls `IndexerSession::new` +
//!   `handle_request` directly on a `tokio::spawn`'d task.
//!
//! ## L invariants honored here
//!
//! - **L1:** [`IndexerSession::temp_db`] is a `tempfile::NamedTempFile`
//!   — random path; Drop-based unlink on normal exit; OS-temp-dir
//!   GC for abnormal exit.
//! - **L2:** Per-event filter at fetch time uses
//!   `pangolin_chain::fetch_and_verify_chunk`'s `topic1 = vault_id`
//!   discipline; additionally, the insert path explicitly compares
//!   the event's `vault_id` against the session's bound vault and
//!   skips any mismatch (defense-in-depth).
//! - **L3:** No external service — the only network traffic is the
//!   chain RPC the host configured.
//! - **L4:** `fetch_and_verify_chunk` is the SAME primitive 4.1 slow
//!   mode uses; revision-graph output is byte-identical (verified
//!   via the parity integration test).
//! - **L5:** Idle timeout. `tokio::select!` on request channel + a
//!   `sleep(idle_timeout)` future; each request resets the clock.
//! - **L6:** No new external crate dep. tokio + tempfile + rusqlite
//!   + serde_json are workspace-shared.
//! - **L7:** No `pangolin-store` import.
//! - **L8:** `forbid(unsafe_code)` on the crate (lib.rs).
//! - **L11:** Cleanup-on-crash via tempfile's Drop. The binary entry
//!   also installs a `tokio::signal::ctrl_c` handler.
//! - **L12:** Same lifecycle code path in desktop + mobile flows.

use std::env;
use std::sync::Arc;
use std::time::Duration;

use rusqlite::Connection;
use tempfile::NamedTempFile;

use pangolin_chain::{
    fetch_and_verify_chunk, fetch_current_block_number, ChainEnv, VerifiedRevisionEvent,
    CHAIN_SYNC_LOG_BLOCK_CHUNK,
};

use crate::cipher::TempDbCipher;
use crate::error::IndexerError;
use crate::protocol::{IndexedEvent, IndexerRequest, IndexerResponse, PROTOCOL_VERSION};

/// Default idle-timeout seconds (D-007 + R-c).
pub const IDLE_TIMEOUT_DEFAULT_SECS: u64 = 300;

/// Minimum idle-timeout seconds (R-c L-idle-timeout-DoS clamp lower
/// bound). Any env override below this is silently clamped up.
pub const IDLE_TIMEOUT_MIN_SECS: u64 = 60;

/// Maximum idle-timeout seconds (R-c L-idle-timeout-DoS clamp upper
/// bound — the 1-hour hard ceiling). Any env override above this is
/// silently clamped down.
pub const IDLE_TIMEOUT_MAX_SECS: u64 = 3_600;

/// Env-var name the R-c override is read from.
pub const IDLE_TIMEOUT_ENV_VAR: &str = "PANGOLIN_INDEXER_IDLE_TIMEOUT_SECS";

/// Sensible upper-bound on per-`Pull` batch size. Defends against a
/// host that requests an unreasonably large batch (memory pressure
/// in the session task).
pub const PULL_BATCH_SIZE_MAX: u32 = 1_024;

// ---------------------------------------------------------------------
// IndexerConfig
// ---------------------------------------------------------------------

/// Caller-supplied session configuration. Built once at session
/// instantiation; not modified during the run.
#[derive(Debug, Clone)]
pub struct IndexerConfig {
    /// Chain RPC URL. Same shape `pangolin-chain` accepts (HTTP or
    /// HTTPS). The session does not attempt WebSocket — fast-mode
    /// inherits 4.1's WS-deferred posture verbatim.
    pub rpc_url: String,
    /// Chain environment. `BaseSepolia` is the only env with a
    /// pinned D-017 in MVP-2.
    pub env: ChainEnv,
    /// Idle-timeout in seconds. Resolved from
    /// [`IndexerConfig::resolve_idle_timeout`] honoring the
    /// `PANGOLIN_INDEXER_IDLE_TIMEOUT_SECS` env var clamp.
    pub idle_timeout_secs: u64,
}

impl IndexerConfig {
    /// Build a default config for an RPC URL + env. Resolves the
    /// idle timeout via [`resolve_idle_timeout`].
    #[must_use]
    pub fn new(rpc_url: impl Into<String>, env: ChainEnv) -> Self {
        Self {
            rpc_url: rpc_url.into(),
            env,
            idle_timeout_secs: resolve_idle_timeout(),
        }
    }
}

/// Resolve the idle timeout per R-c: read
/// `PANGOLIN_INDEXER_IDLE_TIMEOUT_SECS`; default to
/// [`IDLE_TIMEOUT_DEFAULT_SECS`]; clamp to
/// `[IDLE_TIMEOUT_MIN_SECS, IDLE_TIMEOUT_MAX_SECS]`.
#[must_use]
pub fn resolve_idle_timeout() -> u64 {
    resolve_idle_timeout_from(env::var(IDLE_TIMEOUT_ENV_VAR).ok().as_deref())
}

/// Pure version of [`resolve_idle_timeout`] for testability. The env
/// var is read separately so hermetic tests can drive the clamp
/// logic without `env::set_var` (which is process-global).
#[must_use]
pub fn resolve_idle_timeout_from(raw: Option<&str>) -> u64 {
    let parsed = raw.and_then(|s| s.parse::<u64>().ok());
    let value = parsed.unwrap_or(IDLE_TIMEOUT_DEFAULT_SECS);
    value.clamp(IDLE_TIMEOUT_MIN_SECS, IDLE_TIMEOUT_MAX_SECS)
}

// ---------------------------------------------------------------------
// IndexerSession
// ---------------------------------------------------------------------

/// One indexer run. Holds the temp DB handle, the cipher, the
/// session config, and the bound vault id (set by the first
/// `StartIndex` request). Drop unlinks the temp file (L1 + L11).
pub struct IndexerSession {
    config: IndexerConfig,
    cipher: Arc<dyn TempDbCipher>,
    // L1: the temp file's path is unguessable + the Drop unlinks on
    // normal exit (panic = unwind in workspace builds). The
    // connection holds an open file handle to the same path; on
    // Windows the SQLite handle keeps the file open until both are
    // dropped. Rust drops struct fields in declaration order — we
    // declare `conn` BEFORE `temp_db` so the SQLite connection
    // closes first; the `NamedTempFile` then succeeds in unlinking
    // the file on Windows where MoveFileEx-style cleanup needs the
    // last handle to be closed.
    conn: Connection,
    // `temp_db` is held only for its Drop side-effect (L1 unlink on
    // exit) in production lib-only builds. The `test-utilities`
    // feature reads `.path()` for cleanup-on-crash + lifecycle
    // assertions. The conditional `dead_code` allow keeps the
    // mobile / library-only build clean while preserving the
    // load-bearing field.
    #[cfg_attr(not(any(test, feature = "test-utilities")), allow(dead_code))]
    temp_db: NamedTempFile,
    bound_vault: Option<[u8; 32]>,
    /// Number of events already streamed back to the host via
    /// `Pull`. The session uses this to drain the temp DB in order.
    next_pull_offset: u64,
    /// Block range the session has been told to index. Set by
    /// `StartIndex`.
    start_block: u64,
    end_block: u64,
    /// Last block successfully processed (chunk loop tip).
    last_processed_block: u64,
    /// Total blocks the session expects to process — used for the
    /// `Progress` response.
    total_blocks: u64,
}

impl std::fmt::Debug for IndexerSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // L1 hygiene: do NOT print the temp-file path, the SQLite
        // connection internals, or the cipher impl in `{:?}` output.
        // `finish_non_exhaustive` signals the intentional omission +
        // satisfies clippy's `missing_fields_in_debug` lint.
        f.debug_struct("IndexerSession")
            .field("env", &self.config.env)
            .field("idle_timeout_secs", &self.config.idle_timeout_secs)
            .field("bound_vault_set", &self.bound_vault.is_some())
            .field("next_pull_offset", &self.next_pull_offset)
            .field("start_block", &self.start_block)
            .field("end_block", &self.end_block)
            .field("last_processed_block", &self.last_processed_block)
            .field("total_blocks", &self.total_blocks)
            .finish_non_exhaustive()
    }
}

impl IndexerSession {
    /// Construct a new session. Creates the temp DB via
    /// `NamedTempFile::new_in(std::env::temp_dir())`, opens the
    /// SQLite connection over that path, and runs the schema
    /// migration. The cipher is stored for the future 4.3 hook; 4.2
    /// uses [`crate::cipher::NoOpCipher`].
    ///
    /// # Errors
    ///
    /// - [`IndexerError::TempDbInit`] — `NamedTempFile::new_in` or
    ///   `Connection::open` failed.
    /// - [`IndexerError::TempDbIo`] — schema migration failed.
    pub fn new(config: IndexerConfig, cipher: Arc<dyn TempDbCipher>) -> Result<Self, IndexerError> {
        // L1 + L11: tempfile uses O_CREAT|O_EXCL|O_NOFOLLOW on Unix
        // (or the platform equivalent on Windows). The Drop impl
        // unlinks on normal exit; OS-temp-dir conventions sweep on
        // abnormal exit.
        let temp_db =
            NamedTempFile::new_in(env::temp_dir()).map_err(|e| IndexerError::TempDbInit {
                message: format!("create temp file: {e}"),
            })?;
        let conn = Connection::open(temp_db.path()).map_err(|e| IndexerError::TempDbInit {
            message: format!("open SQLite: {e}"),
        })?;
        Self::run_migration(&conn)?;
        // Touch the cipher once so the field is reachable from the
        // session — 4.3 will replace this with the actual page
        // encrypt/decrypt round-trip. The probe is a no-op for
        // `NoOpCipher`.
        let probe = cipher.decrypt_page(&cipher.encrypt_page(b"4.2-cipher-probe"));
        debug_assert_eq!(probe, b"4.2-cipher-probe");
        Ok(Self {
            config,
            cipher,
            temp_db,
            conn,
            bound_vault: None,
            next_pull_offset: 0,
            start_block: 0,
            end_block: 0,
            last_processed_block: 0,
            total_blocks: 0,
        })
    }

    /// Schema migration. Same column set as `pangolin-store`'s
    /// `revisions` row (minus the locally-derived columns the
    /// indexer doesn't compute) so the host's ingest path can
    /// translate 1:1.
    fn run_migration(conn: &Connection) -> Result<(), IndexerError> {
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS cached_revisions (
                rowid             INTEGER PRIMARY KEY AUTOINCREMENT,
                vault_id          BLOB    NOT NULL,
                account_id        BLOB    NOT NULL,
                parent_revision   BLOB    NOT NULL,
                device_id         BLOB    NOT NULL,
                schema_version    INTEGER NOT NULL,
                sequence          INTEGER NOT NULL,
                enc_payload       BLOB    NOT NULL,
                signer            BLOB    NOT NULL,
                block_number      INTEGER NOT NULL,
                block_hash        BLOB    NOT NULL,
                tx_hash           BLOB    NOT NULL,
                log_index         INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_cached_revisions_block
                ON cached_revisions(block_number);
            CREATE TABLE IF NOT EXISTS indexer_meta (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            ",
        )
        .map_err(|e| IndexerError::TempDbIo {
            message: format!("migrate schema: {e}"),
        })?;
        Ok(())
    }

    // ---- Public lifecycle API ----

    /// The cipher held by the session. Exposed for tests + future
    /// 4.3 hooks.
    #[must_use]
    pub fn cipher(&self) -> &Arc<dyn TempDbCipher> {
        &self.cipher
    }

    /// The temp DB path (test-only — production code MUST NOT log
    /// or persist this value per L1 hygiene).
    #[cfg(any(test, feature = "test-utilities"))]
    #[must_use]
    pub fn temp_db_path(&self) -> &std::path::Path {
        self.temp_db.path()
    }

    /// Number of events currently cached in the temp DB.
    pub fn cached_event_count(&self) -> Result<u64, IndexerError> {
        let mut stmt = self
            .conn
            .prepare("SELECT COUNT(*) FROM cached_revisions")
            .map_err(|e| IndexerError::TempDbIo {
                message: format!("prepare count: {e}"),
            })?;
        let n: i64 = stmt
            .query_row([], |row| row.get(0))
            .map_err(|e| IndexerError::TempDbIo {
                message: format!("query count: {e}"),
            })?;
        Ok(u64::try_from(n).unwrap_or(0))
    }

    /// Dispatch a request to the session. R-b's
    /// `IndexerRequest::*` variants map 1:1 to handlers.
    ///
    /// This is the single entry point both transports share. The
    /// stdio binary line-decodes JSON → calls this; the mobile
    /// flow calls this directly.
    pub async fn handle_request(
        &mut self,
        req: IndexerRequest,
    ) -> Result<IndexerResponse, IndexerError> {
        match req {
            IndexerRequest::StartIndex {
                vault_id,
                start_block,
                end_block,
            } => {
                self.handle_start_index(vault_id, start_block, end_block)
                    .await
            }
            IndexerRequest::Pull { batch_size } => self.handle_pull(batch_size),
            IndexerRequest::Heartbeat => Ok(IndexerResponse::Heartbeat),
            IndexerRequest::Stop => Ok(IndexerResponse::Stopped),
        }
    }

    async fn handle_start_index(
        &mut self,
        vault_id_hex: String,
        start_block: u64,
        end_block: Option<u64>,
    ) -> Result<IndexerResponse, IndexerError> {
        // L-stdio-injection: parse vault id from hex. 32 bytes
        // expected; any other shape rejected.
        let vault_id = decode_vault_id(&vault_id_hex)?;
        self.bound_vault = Some(vault_id);
        self.start_block = start_block;
        // L-rpc-omits-events defense: if the host did not pass an
        // upper bound, the session asks the chain for the current
        // head and uses that. The chain primitive enforces the
        // same chain-id + contract-address checks 4.1 ships.
        let end = match end_block {
            Some(n) => n,
            None => fetch_current_block_number(&self.config.rpc_url).await?,
        };
        if end < start_block {
            return Err(IndexerError::ProtocolError {
                message: format!("end_block ({end}) < start_block ({start_block})"),
            });
        }
        self.end_block = end;
        self.total_blocks = self
            .end_block
            .saturating_sub(self.start_block)
            .saturating_add(1);
        self.last_processed_block = start_block.saturating_sub(1);
        self.next_pull_offset = 0;
        // Drive the chunked fetch loop synchronously inside the
        // request handler. For 4.2's pull-based protocol the host
        // expects events ready to drain by the time it issues the
        // first `Pull`; chunking N blocks at a time keeps memory
        // bounded.
        self.run_chunk_loop(vault_id).await?;
        Ok(IndexerResponse::Started {
            protocol_version: PROTOCOL_VERSION,
            vault_id: vault_id_hex,
        })
    }

    async fn run_chunk_loop(&mut self, vault_id: [u8; 32]) -> Result<(), IndexerError> {
        let mut cursor = self.start_block;
        while cursor <= self.end_block {
            let chunk_end = cursor
                .saturating_add(CHAIN_SYNC_LOG_BLOCK_CHUNK.saturating_sub(1))
                .min(self.end_block);
            let (verified, _rejected) = fetch_and_verify_chunk(
                &self.config.rpc_url,
                self.config.env,
                &vault_id,
                cursor,
                chunk_end,
            )
            .await?;
            self.persist_chunk(&verified, &vault_id)?;
            self.last_processed_block = chunk_end;
            // Saturating-add to defend against a malformed end_block
            // == u64::MAX shape.
            cursor = chunk_end.saturating_add(1);
            if cursor == 0 {
                break;
            }
        }
        Ok(())
    }

    fn persist_chunk(
        &self,
        events: &[VerifiedRevisionEvent],
        bound_vault: &[u8; 32],
    ) -> Result<(), IndexerError> {
        let mut stmt = self
            .conn
            .prepare(
                "INSERT INTO cached_revisions (
                    vault_id, account_id, parent_revision, device_id,
                    schema_version, sequence, enc_payload, signer,
                    block_number, block_hash, tx_hash, log_index
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .map_err(|e| IndexerError::TempDbIo {
                message: format!("prepare insert: {e}"),
            })?;
        for v in events {
            // L2 defense-in-depth: per-event filter at insert time.
            // `fetch_and_verify_chunk` already filters server-side
            // by `topic1 = vault_id` + client-side via
            // `decoded.vaultId == requested_vault_id` — the third
            // check here makes the indexer's contract explicit at
            // its own boundary.
            if v.event.vault_id != *bound_vault {
                continue;
            }
            let block_hash_bytes: [u8; 32] = v.block_hash.into();
            let signer_bytes = v.signer.as_slice();
            stmt.execute(rusqlite::params![
                v.event.vault_id.as_ref() as &[u8],
                v.event.account_id.as_ref() as &[u8],
                v.event.parent_revision.as_ref() as &[u8],
                v.event.device_id.as_ref() as &[u8],
                i64::from(v.schema_version),
                i64::try_from(v.event.sequence).unwrap_or(i64::MAX),
                v.event.enc_payload.as_slice(),
                signer_bytes,
                i64::try_from(v.event.anchor.block_number).unwrap_or(i64::MAX),
                block_hash_bytes.as_ref() as &[u8],
                v.event.anchor.tx_hash.as_ref() as &[u8],
                i64::try_from(v.event.anchor.log_index).unwrap_or(i64::MAX),
            ])
            .map_err(|e| IndexerError::TempDbIo {
                message: format!("insert event: {e}"),
            })?;
        }
        Ok(())
    }

    fn handle_pull(&mut self, batch_size: u32) -> Result<IndexerResponse, IndexerError> {
        let n = batch_size.min(PULL_BATCH_SIZE_MAX);
        // 0-batch pulls drain nothing but still tick the
        // idle-timer (caller handled).
        if n == 0 {
            return Ok(IndexerResponse::Batch { events: vec![] });
        }
        let Some(bound) = self.bound_vault else {
            return Err(IndexerError::ProtocolError {
                message: "Pull issued before StartIndex".into(),
            });
        };
        let mut stmt = self
            .conn
            .prepare(
                "SELECT vault_id, account_id, parent_revision, device_id,
                        schema_version, sequence, enc_payload, signer,
                        block_number, block_hash, tx_hash, log_index
                 FROM cached_revisions
                 WHERE rowid > ?
                 ORDER BY rowid ASC
                 LIMIT ?",
            )
            .map_err(|e| IndexerError::TempDbIo {
                message: format!("prepare pull: {e}"),
            })?;
        let offset_i64 = i64::try_from(self.next_pull_offset).unwrap_or(i64::MAX);
        let n_i64 = i64::from(n);
        let mut rows = stmt
            .query(rusqlite::params![offset_i64, n_i64])
            .map_err(|e| IndexerError::TempDbIo {
                message: format!("query pull: {e}"),
            })?;
        let mut out: Vec<IndexedEvent> = Vec::with_capacity(n as usize);
        let mut highest_rowid: i64 = offset_i64;
        while let Some(row) = rows.next().map_err(|e| IndexerError::TempDbIo {
            message: format!("step pull: {e}"),
        })? {
            let vault_blob: Vec<u8> = row.get(0).map_err(|ref e| map_io(e))?;
            // L2 defense-in-depth on the read side too — if a row
            // somehow leaked a foreign vault id past the insert
            // filter (it can't, but the layered defense is cheap),
            // skip it.
            if vault_blob != bound {
                continue;
            }
            let account_id: Vec<u8> = row.get(1).map_err(|ref e| map_io(e))?;
            let parent_revision: Vec<u8> = row.get(2).map_err(|ref e| map_io(e))?;
            let device_id: Vec<u8> = row.get(3).map_err(|ref e| map_io(e))?;
            let schema_version: i64 = row.get(4).map_err(|ref e| map_io(e))?;
            let sequence: i64 = row.get(5).map_err(|ref e| map_io(e))?;
            let enc_payload: Vec<u8> = row.get(6).map_err(|ref e| map_io(e))?;
            let signer: Vec<u8> = row.get(7).map_err(|ref e| map_io(e))?;
            let block_number: i64 = row.get(8).map_err(|ref e| map_io(e))?;
            let block_hash: Vec<u8> = row.get(9).map_err(|ref e| map_io(e))?;
            let tx_hash: Vec<u8> = row.get(10).map_err(|ref e| map_io(e))?;
            let log_index: i64 = row.get(11).map_err(|ref e| map_io(e))?;
            // Track the highest rowid we've seen so the next pull
            // resumes after it.
            //
            // SQLite's AUTOINCREMENT guarantees `rowid` is
            // monotonically increasing in INSERT order, so the
            // `ORDER BY rowid ASC` query is the natural FIFO.
            //
            // The rowid is not on the SELECT list; we read it via a
            // second statement-bound query. For 4.2 we just track
            // the offset by counting returned rows (rowid is the
            // primary key generated AUTOINCREMENT-style; rowid n
            // implies n rows fit before it). Since we don't expose
            // the rowid column, we count rows here and advance the
            // offset accordingly.
            highest_rowid = highest_rowid.saturating_add(1);
            out.push(IndexedEvent {
                vault_id: hex::encode(&vault_blob),
                account_id: hex::encode(&account_id),
                parent_revision: hex::encode(&parent_revision),
                device_id: hex::encode(&device_id),
                schema_version: u16::try_from(schema_version).unwrap_or(u16::MAX),
                sequence: u64::try_from(sequence).unwrap_or(0),
                enc_payload: hex::encode(&enc_payload),
                signer: hex::encode(&signer),
                block_number: u64::try_from(block_number).unwrap_or(0),
                block_hash: hex::encode(&block_hash),
                tx_hash: hex::encode(&tx_hash),
                log_index: u64::try_from(log_index).unwrap_or(0),
            });
        }
        self.next_pull_offset = u64::try_from(highest_rowid).unwrap_or(0);
        Ok(IndexerResponse::Batch { events: out })
    }

    // ---- Idle timeout helpers ----

    /// Idle-timeout duration the session was configured with.
    #[must_use]
    pub fn idle_timeout(&self) -> Duration {
        Duration::from_secs(self.config.idle_timeout_secs)
    }

    /// Last block successfully processed by the chunk loop.
    #[must_use]
    pub fn last_processed_block(&self) -> u64 {
        self.last_processed_block
    }

    /// End block the session is targeting.
    #[must_use]
    pub fn end_block(&self) -> u64 {
        self.end_block
    }

    /// Total blocks the chunk loop will sweep.
    #[must_use]
    pub fn total_blocks(&self) -> u64 {
        self.total_blocks
    }

    /// Whether the chunk loop has reached the configured end block.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.bound_vault.is_some() && self.last_processed_block >= self.end_block
    }
}

fn map_io(e: &rusqlite::Error) -> IndexerError {
    IndexerError::TempDbIo {
        message: format!("row read: {e}"),
    }
}

/// Decode a 32-byte vault id from a lowercase hex string (no `0x`
/// prefix). The protocol's wire format pins this representation
/// (see `protocol.rs`).
fn decode_vault_id(s: &str) -> Result<[u8; 32], IndexerError> {
    let raw = hex::decode(s).map_err(|e| IndexerError::ProtocolError {
        message: format!("vault_id hex decode: {e}"),
    })?;
    if raw.len() != 32 {
        return Err(IndexerError::ProtocolError {
            message: format!("vault_id must be 32 bytes; got {}", raw.len()),
        });
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher::NoOpCipher;

    fn fresh_session() -> IndexerSession {
        let cfg = IndexerConfig {
            rpc_url: "http://localhost:8545".into(),
            env: ChainEnv::BaseSepolia,
            idle_timeout_secs: 60,
        };
        IndexerSession::new(cfg, NoOpCipher::new_arc()).expect("new")
    }

    #[test]
    fn idle_timeout_default_resolves_to_300_seconds() {
        assert_eq!(resolve_idle_timeout_from(None), IDLE_TIMEOUT_DEFAULT_SECS);
    }

    #[test]
    fn idle_timeout_env_override_clamps_to_max() {
        // R-c: anything above the 1-hour ceiling is clamped down.
        assert_eq!(
            resolve_idle_timeout_from(Some("99999")),
            IDLE_TIMEOUT_MAX_SECS
        );
    }

    #[test]
    fn idle_timeout_env_override_clamps_to_min() {
        // R-c: anything below the 60-sec floor is clamped up.
        assert_eq!(resolve_idle_timeout_from(Some("1")), IDLE_TIMEOUT_MIN_SECS);
    }

    #[test]
    fn idle_timeout_env_invalid_falls_back_to_default() {
        assert_eq!(
            resolve_idle_timeout_from(Some("not-a-number")),
            IDLE_TIMEOUT_DEFAULT_SECS
        );
        assert_eq!(
            resolve_idle_timeout_from(Some("")),
            IDLE_TIMEOUT_DEFAULT_SECS
        );
    }

    #[test]
    fn idle_timeout_in_range_is_passed_through() {
        assert_eq!(resolve_idle_timeout_from(Some("120")), 120);
    }

    #[test]
    fn idle_timeout_constants_are_pinned() {
        assert_eq!(IDLE_TIMEOUT_DEFAULT_SECS, 300);
        assert_eq!(IDLE_TIMEOUT_MIN_SECS, 60);
        assert_eq!(IDLE_TIMEOUT_MAX_SECS, 3_600);
        assert_eq!(IDLE_TIMEOUT_ENV_VAR, "PANGOLIN_INDEXER_IDLE_TIMEOUT_SECS");
    }

    #[test]
    fn new_session_creates_temp_file_and_schema() {
        let s = fresh_session();
        // L1: temp file exists during the lifetime of the session.
        let path = s.temp_db_path().to_path_buf();
        assert!(path.exists(), "temp file must exist while session is alive");
        // Schema is initialised: counts query succeeds.
        assert_eq!(s.cached_event_count().unwrap(), 0);
    }

    #[test]
    fn dropping_session_unlinks_temp_file_on_normal_exit() {
        // L1 + L11 normal-exit branch.
        let path = {
            let s = fresh_session();
            s.temp_db_path().to_path_buf()
        };
        // Drop on assignment-end above unlinks the NamedTempFile.
        assert!(!path.exists(), "temp file must be unlinked after Drop");
    }

    #[test]
    fn debug_impl_does_not_leak_temp_path() {
        let s = fresh_session();
        let debug_str = format!("{s:?}");
        let path_str = s.temp_db_path().display().to_string();
        assert!(
            !debug_str.contains(&path_str),
            "Debug must not leak temp file path: {debug_str}"
        );
    }

    #[test]
    fn decode_vault_id_accepts_32_byte_hex() {
        let hex_str = "aa".repeat(32);
        let v = decode_vault_id(&hex_str).expect("valid 32-byte hex");
        assert_eq!(v, [0xAA; 32]);
    }

    #[test]
    fn decode_vault_id_rejects_wrong_length() {
        let short = "aa".repeat(16);
        assert!(decode_vault_id(&short).is_err());
        let long = "aa".repeat(64);
        assert!(decode_vault_id(&long).is_err());
    }

    #[test]
    fn decode_vault_id_rejects_invalid_hex() {
        let bad = "zz".repeat(32);
        assert!(decode_vault_id(&bad).is_err());
    }

    #[tokio::test]
    async fn handle_heartbeat_returns_heartbeat() {
        let mut s = fresh_session();
        let resp = s.handle_request(IndexerRequest::Heartbeat).await.unwrap();
        assert!(matches!(resp, IndexerResponse::Heartbeat));
    }

    #[tokio::test]
    async fn handle_stop_returns_stopped() {
        let mut s = fresh_session();
        let resp = s.handle_request(IndexerRequest::Stop).await.unwrap();
        assert!(matches!(resp, IndexerResponse::Stopped));
    }

    #[tokio::test]
    async fn pull_before_start_index_returns_protocol_error() {
        let mut s = fresh_session();
        let res = s
            .handle_request(IndexerRequest::Pull { batch_size: 10 })
            .await;
        assert!(matches!(res, Err(IndexerError::ProtocolError { .. })));
    }

    #[tokio::test]
    async fn zero_batch_pull_returns_empty_batch() {
        // Zero pull is a permitted no-op (host might use it to
        // tick the idle clock without draining). Even without
        // StartIndex it short-circuits to empty.
        let mut s = fresh_session();
        let resp = s
            .handle_request(IndexerRequest::Pull { batch_size: 0 })
            .await
            .unwrap();
        match resp {
            IndexerResponse::Batch { events } => assert!(events.is_empty()),
            other => panic!("expected Batch, got {other:?}"),
        }
    }

    #[test]
    fn pull_batch_size_max_is_pinned() {
        assert_eq!(PULL_BATCH_SIZE_MAX, 1_024);
    }
}
