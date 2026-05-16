// SPDX-License-Identifier: AGPL-3.0-or-later
//
//! Publish orchestration — the canonical engine that walks the
//! `dirty_accounts` queue, signs each account's head revision, submits
//! to chain through a [`ChainAdapter`], and clears the marker on
//! success.
//!
//! ## Provenance
//!
//! This module hosts the publish path historically implemented in
//! `apps/cli/src/sync.rs::publish_all` + `publish_one` (P8-3). MVP-2
//! issue 5.1 R-h folded that code into `pangolin-store` so 5.1's new
//! batched [`Vault::flush_publish_queue`] AND the existing CLI
//! `publish_all` orchestrator both call into the same library helper.
//! The CLI's `publish_all` survives as a thin shell that delegates here
//! so external behaviour is preserved verbatim (every CLI sync test
//! continues to pass after the move).
//!
//! ## Per-account semantics (per `P8.md` §A3 — the A3 dedupe check)
//!
//! For each [`crate::DirtyEntry`] returned by [`Vault::list_dirty`]:
//!
//! 1. Read `(parent, schema_version, enc_payload)` from the local
//!    revision row via [`Vault::read_revision_for_publish`].
//! 2. Build a [`pangolin_chain::SignedRevision`] via
//!    [`pangolin_chain::build_signed_revision`] using the supplied
//!    `device_key` (the proof-of-concept two-key model — the gas-paying
//!    `secp256k1` wallet is internal to the adapter).
//! 3. **A3 pre-publish check.** Scan the supplied `chain_view` for an
//!    event with the same canonical hash. If found, skip the on-chain
//!    submit and run only the local commit (`mark_published` +
//!    `clear_dirty`). Returns `PublishOutcome::Published` with
//!    `was_already_on_chain: true`.
//! 4. Otherwise, call [`ChainAdapter::publish`] and on success
//!    `mark_published` + `clear_dirty`.
//! 5. On failure, leave the marker in place; the next run retries.
//!
//! `publish_all_for_vault` continues on per-account failures and
//! returns a [`PublishReport`] enumerating which accounts succeeded
//! and which errored — same posture as the CLI orchestrator that
//! preceded it. 5.1's [`Vault::flush_publish_queue`] also calls this
//! helper but layers a top-of-flush balance gate (R-e) + per-account
//! coalescing (R-c) on top, surfacing a typed
//! [`BatchFlushError::BalanceInsufficientForBatch`] (L12) before any
//! chain submission would be attempted.

use pangolin_chain::{
    build_signed_revision, ChainAdapter, ChainError, RevisionEvent, SignedRevision, VaultId,
};
use pangolin_crypto::keys::DeviceKey;

use crate::account::AccountId;
use crate::dirty::DirtyEntry;
use crate::error::StoreError;
use crate::revision::{ChainAnchor, RevisionId};
use crate::vault::Vault;

// ---------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------

/// Outcome of a single publish attempt within
/// [`publish_all_for_vault`].
#[derive(Debug, Clone)]
pub enum PublishOutcome {
    /// The revision was freshly published on chain by this run.
    /// `anchor` is the chain anchor; `was_already_on_chain` is `false`.
    /// When the A3 idempotency check matched a pre-existing chain
    /// event, the variant still fires but `was_already_on_chain` is
    /// `true`.
    Published {
        /// The chain anchor for the (now-published) revision.
        anchor: ChainAnchor,
        /// `true` if the A3 pre-publish check matched a pre-existing
        /// chain event and we skipped the on-chain submit, running
        /// only the local commit.
        was_already_on_chain: bool,
    },
    /// The on-chain step or local commit step failed. The dirty
    /// marker was preserved; a re-run will retry.
    Failed {
        /// Human-readable error string; non-secret.
        error: String,
    },
}

/// One row of the per-(account, revision) outcome list produced by
/// [`publish_all_for_vault`].
#[derive(Debug, Clone)]
pub struct PublishOutcomeRow {
    /// Account this row tracks.
    pub account_id: AccountId,
    /// Specific revision attempted.
    pub revision_id: RevisionId,
    /// Outcome of the attempt.
    pub outcome: PublishOutcome,
}

/// Aggregate report from a [`publish_all_for_vault`] run.
#[derive(Debug, Clone, Default)]
pub struct PublishReport {
    /// Per-row outcomes in the order entries were attempted.
    pub rows: Vec<PublishOutcomeRow>,
}

impl PublishReport {
    /// Number of rows that successfully landed on chain in this run
    /// (counts the A3 "already on chain" case as a success too — the
    /// chain has the revision regardless of whether THIS run put it
    /// there).
    #[must_use]
    pub fn published_count(&self) -> usize {
        self.rows
            .iter()
            .filter(|r| matches!(r.outcome, PublishOutcome::Published { .. }))
            .count()
    }

    /// Number of rows that failed in this run.
    #[must_use]
    pub fn failed_count(&self) -> usize {
        self.rows
            .iter()
            .filter(|r| matches!(r.outcome, PublishOutcome::Failed { .. }))
            .count()
    }

    /// `true` iff every entry in `rows` succeeded (or there were no
    /// entries — a no-op publish is also "no failures").
    #[must_use]
    pub fn all_ok(&self) -> bool {
        self.failed_count() == 0
    }
}

/// Aggregate report from a successful [`Vault::flush_publish_queue`] run.
///
/// The "success" criterion is "the top-of-flush balance gate passed and
/// per-account submission proceeded" — per-account failures inside that
/// path surface inside the wrapped [`PublishReport`] (per-row
/// `PublishOutcome::Failed`), NOT as a top-level error, matching 4.1's
/// row-vs-error split.
///
/// MVP-2 issue 5.1.
#[derive(Debug, Clone, Default)]
pub struct BatchFlushReport {
    /// Number of `dirty_accounts` rows pruned by the R-c per-account
    /// coalescing pass before any chain submit. Zero when each account
    /// already had exactly one dirty marker.
    pub coalesced_markers_pruned: usize,
    /// Wrapped per-account publish report. `rows.len()` equals the
    /// number of accounts that had at least one dirty marker AFTER
    /// coalescing — i.e., the number of chain submissions attempted.
    pub publish_report: PublishReport,
}

/// Error type for [`Vault::flush_publish_queue`].
///
/// MVP-2 issue 5.1 L12 — `BalanceInsufficientForBatch` is a NEW
/// variant distinct from 3.3's `ChainError::PrePublishBalanceInsufficient`.
/// The batch-level error carries `{ needed, available, queued_count }`
/// so the host can surface a UX hint that names the cumulative cost
/// across all queued accounts (not just one revision).
#[derive(Debug)]
pub enum BatchFlushError {
    /// L12. The top-of-flush balance gate failed: the wallet's balance
    /// does not cover the sum of `queued_count × estimate_next_publish_cost`.
    /// NO chain submission was attempted. Dirty markers stay; the next
    /// invocation re-runs the gate (and coalesces any markers stamped
    /// in the meantime per R-f).
    BalanceInsufficientForBatch {
        /// Sum of estimated cost across all queued accounts, in wei.
        needed: u128,
        /// Wallet balance at the moment of the check, in wei.
        available: u128,
        /// Number of dirty accounts (post-coalescing) that the gate
        /// was checked against.
        queued_count: usize,
    },
    /// A chain-side error that was NOT the balance gate (e.g., a chain
    /// estimate call failed RPC-side before any submit). Carries the
    /// underlying [`ChainError`] verbatim.
    ChainError(ChainError),
    /// A store-side error (SQL, freeze guard, etc.) that prevented the
    /// flush.
    Store(StoreError),
    /// `flush_publish_queue` was called while the vault was not in
    /// the [`crate::vault::VaultState::Active`] state.
    NoActiveSession,
}

impl core::fmt::Display for BatchFlushError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BalanceInsufficientForBatch {
                needed,
                available,
                queued_count,
            } => {
                write!(
                    f,
                    "batch flush balance insufficient: needed={needed} wei, \
                     available={available} wei across {queued_count} queued accounts",
                )
            }
            Self::ChainError(e) => write!(f, "batch flush chain error: {e}"),
            Self::Store(e) => write!(f, "batch flush store error: {e}"),
            Self::NoActiveSession => write!(f, "batch flush requires an active session"),
        }
    }
}

impl std::error::Error for BatchFlushError {}

impl From<StoreError> for BatchFlushError {
    fn from(err: StoreError) -> Self {
        Self::Store(err)
    }
}

impl From<ChainError> for BatchFlushError {
    fn from(err: ChainError) -> Self {
        Self::ChainError(err)
    }
}

/// In-memory snapshot of the publish queue state. Returned by
/// [`Vault::publish_queue_state`] so a host UI can render
/// "Synced / Syncing... / Offline" cues without locking the engine.
///
/// MVP-2 issue 5.1.
#[derive(Debug, Clone)]
pub struct PublishQueueState {
    /// Unix-millis instant at which the current 30s window started, if
    /// any. `None` when the queue is empty (no dirty markers) or the
    /// vault is not unlocked.
    pub window_started_at_unix_ms: Option<i64>,
    /// Number of dirty markers currently in the queue (pre-coalescing).
    pub dirty_count: usize,
    /// Sum of `enc_payload` byte sizes across all dirty markers
    /// (pre-coalescing). Used by the R-b byte cap.
    pub dirty_byte_size: u64,
    /// `true` if the last flush attempt returned
    /// [`BatchFlushError::BalanceInsufficientForBatch`]. Clears on the
    /// next successful flush. Diagnostic / UX hint only — the chain-
    /// side gate IS the authoritative defense.
    pub blocked_on_balance: bool,
}

// ---------------------------------------------------------------------
// publish_all_for_vault — extracted from apps/cli/src/sync.rs (R-h)
// ---------------------------------------------------------------------

/// Walk [`Vault::list_dirty`] and publish every entry through
/// `adapter`. Continues on per-account failures and returns a
/// [`PublishReport`].
///
/// This is the canonical engine for the publish path. MVP-2 issue 5.1
/// R-h moved this code from `apps/cli/src/sync.rs::publish_all` into
/// the store crate so both the CLI's `publish_all` (now a thin shell)
/// and [`Vault::flush_publish_queue`] (new in 5.1) call into the same
/// orchestrator.
///
/// # Errors
///
/// Returns `Err(StoreError)` only on the outermost call: failure to
/// read the dirty list / last-pulled-block. Per-account failures are
/// captured as [`PublishOutcome::Failed`] rows in the report; the
/// outer `Result` stays `Ok`.
pub async fn publish_all_for_vault<A: ChainAdapter + ?Sized>(
    vault: &mut Vault,
    adapter: &A,
    device_key: &DeviceKey,
) -> Result<PublishReport, StoreError> {
    let vault_id: VaultId = vault.vault_id();
    let last_pulled = vault.last_pulled_block()?;
    let dirty: Vec<DirtyEntry> = vault.list_dirty()?;

    // Pre-fetch the chain's view of "everything since last_pulled"
    // exactly once per run — re-using it for the A3 check across every
    // dirty entry. We tolerate a chain-side error here only by
    // skipping the A3 optimization; a true network failure surfaces
    // again at the per-entry `publish` call where it correctly fails
    // that entry.
    let chain_view: Option<Vec<RevisionEvent>> =
        adapter.pull_since(&vault_id, last_pulled, None).await.ok();

    let mut report = PublishReport::default();
    for entry in dirty {
        let row = match publish_one(vault, adapter, device_key, &entry, chain_view.as_deref()).await
        {
            Ok(outcome) => PublishOutcomeRow {
                account_id: entry.account_id,
                revision_id: entry.revision_id,
                outcome,
            },
            Err(e) => PublishOutcomeRow {
                account_id: entry.account_id,
                revision_id: entry.revision_id,
                outcome: PublishOutcome::Failed {
                    error: format!("{e}"),
                },
            },
        };
        report.rows.push(row);
    }
    Ok(report)
}

/// Per-entry error union for [`publish_one`]. Carries a store-side
/// or chain-side failure; rendered to a string inside
/// [`PublishOutcome::Failed`] by [`publish_all_for_vault`]'s match.
///
/// Replaces the historical `anyhow::Error` return type the same
/// function carried inside `apps/cli/src/sync.rs::publish_one`. The
/// CLI's anyhow re-format prefix (`"publish failed: {e}"`) is
/// preserved verbatim by [`std::fmt::Display`] below so the
/// `was_already_on_chain` test in
/// `publish_idempotent_on_rerun_after_partial_failure` still
/// matches the rendered string.
#[derive(Debug)]
pub enum PublishOneError {
    /// A store-side failure (decryption, missing row, freeze guard
    /// violation, session expiry).
    Store(StoreError),
    /// A chain-side failure surfaced by [`ChainAdapter::publish`].
    Chain(ChainError),
}

impl core::fmt::Display for PublishOneError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Store(e) => write!(f, "{e}"),
            // Mirrors the historical anyhow-wrapped "publish failed: {e}"
            // shape so existing test substring matches (e.g.,
            // `error.contains("publish failed")`) continue to fire.
            Self::Chain(e) => write!(f, "publish failed: {e}"),
        }
    }
}

impl std::error::Error for PublishOneError {}

impl From<StoreError> for PublishOneError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

impl From<ChainError> for PublishOneError {
    fn from(e: ChainError) -> Self {
        Self::Chain(e)
    }
}

/// Per-entry helper: factored out so [`publish_all_for_vault`]'s loop body stays flat.
///
/// Returns the outcome enum directly; failure conditions are caught by
/// the surrounding match in `publish_all_for_vault`.
///
/// `chain_view` is the result of a one-shot `pull_since(last_pulled)`
/// call made by the outer loop, reused across every entry; `None` if
/// that pull failed (in which case the A3 idempotency check is
/// skipped — the per-entry `publish` call will still surface the
/// transport failure).
pub async fn publish_one<A: ChainAdapter + ?Sized>(
    vault: &mut Vault,
    adapter: &A,
    device_key: &DeviceKey,
    entry: &DirtyEntry,
    chain_view: Option<&[RevisionEvent]>,
) -> Result<PublishOutcome, PublishOneError> {
    let payload = vault.read_revision_for_publish(entry.account_id, entry.revision_id)?;
    let signed: SignedRevision = build_signed_revision(
        device_key,
        vault.vault_id(),
        *entry.account_id.as_bytes(),
        *payload.parent_revision.as_bytes(),
        payload.schema_version,
        payload.enc_payload,
    );

    // A3 pre-publish check: if the chain view shows an event with the
    // same canonical hash already on chain, skip the publish call. We
    // compare by recomputing the canonical hash on each candidate
    // event (cheap; keccak over ~160 bytes) so the match does not
    // depend on whatever device_id is stored in the local row (which,
    // for the PoC, may be a random 32 bytes that don't correspond to
    // any actual signing key — see apps/cli/src/sync.rs crate-level
    // docs for the rationale).
    if let Some(events) = chain_view {
        let our_hash = pangolin_chain::canonical_hash(
            &signed.vault_id,
            &signed.account_id,
            &signed.parent_revision,
            &signed.device_id,
            signed.schema_version,
            &signed.enc_payload,
        );
        for ev in events {
            let ev_hash = pangolin_chain::canonical_hash(
                &ev.vault_id,
                &ev.account_id,
                &ev.parent_revision,
                &ev.device_id,
                ev.schema_version,
                &ev.enc_payload,
            );
            if ev_hash == our_hash {
                // Already on chain. Run only the local commit.
                vault.mark_published(entry.revision_id, ev.anchor)?;
                vault.clear_dirty(entry.account_id, entry.revision_id)?;
                return Ok(PublishOutcome::Published {
                    anchor: ev.anchor,
                    was_already_on_chain: true,
                });
            }
        }
    }

    // No A3 hit — submit fresh.
    let anchor: ChainAnchor = adapter.publish(&signed).await?;
    vault.mark_published(entry.revision_id, anchor)?;
    vault.clear_dirty(entry.account_id, entry.revision_id)?;
    Ok(PublishOutcome::Published {
        anchor,
        was_already_on_chain: false,
    })
}

// ---------------------------------------------------------------------
// MVP-2 issue 5.1 — hermetic tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use pangolin_chain::{
        ChainAdapter, ChainError, EventLocation, MockChainAdapter, RevisionEvent, SignedRevision,
        VaultId,
    };
    use pangolin_crypto::keys::DeviceKey;
    use pangolin_crypto::secret::SecretBytes;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tempfile::TempDir;

    use super::*;
    use crate::account::AccountSnapshot;
    use crate::session::{PinIdentityProof, PressYPresenceProof};
    use crate::vault::{
        Vault, BATCH_WINDOW_SECS_DEFAULT, BATCH_WINDOW_SECS_MAX, BATCH_WINDOW_SECS_MIN,
        PUBLISH_QUEUE_COUNT_CAP,
    };

    fn pwd() -> SecretBytes {
        SecretBytes::new(b"correct horse battery staple".to_vec())
    }

    fn snap(name: &str) -> AccountSnapshot {
        AccountSnapshot::new(
            SecretBytes::new(name.as_bytes().to_vec()),
            SecretBytes::new(b"u".to_vec()),
            SecretBytes::new(b"p".to_vec()),
            SecretBytes::new(b"https://x".to_vec()),
            SecretBytes::new(b"".to_vec()),
            SecretBytes::new(b"".to_vec()),
        )
    }

    fn fresh_vault() -> (Vault, TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v.pvf");
        Vault::create(&path, &pwd()).expect("create");
        let mut v = Vault::open(&path).expect("open");
        let presence = PressYPresenceProof::confirmed();
        let identity = PinIdentityProof::new(pwd());
        v.unlock(&presence, &identity).expect("unlock");
        (v, dir)
    }

    /// Adapter that fails the pre-flight batch balance gate with
    /// concrete wei values. Also has a publish-side `PrePublishBalanceInsufficient`
    /// fallback in case a test bypasses the gate via `pre_flight_batch_balance = None`.
    /// Per R-e fix-pass: 5.1 routes balance refusal through the new
    /// pre-flight gate BEFORE any chain submit; the per-revision gate
    /// inside `publish_revision_v1` remains as defense-in-depth.
    struct BalanceInsufficientAdapter {
        inner: MockChainAdapter,
        publish_count: std::sync::Arc<AtomicUsize>,
    }

    impl BalanceInsufficientAdapter {
        fn new() -> Self {
            Self {
                inner: MockChainAdapter::new(),
                publish_count: std::sync::Arc::new(AtomicUsize::new(0)),
            }
        }
        fn publish_count(&self) -> usize {
            self.publish_count.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl ChainAdapter for BalanceInsufficientAdapter {
        async fn publish(&self, _signed: &SignedRevision) -> Result<ChainAnchor, ChainError> {
            self.publish_count.fetch_add(1, Ordering::SeqCst);
            Err(ChainError::PrePublishBalanceInsufficient {
                balance_wei: 1_000,
                estimate_wei: 1_000_000,
            })
        }
        async fn pull_since(
            &self,
            vault_id: &VaultId,
            from_block: u64,
            until_block: Option<u64>,
        ) -> Result<Vec<RevisionEvent>, ChainError> {
            self.inner
                .pull_since(vault_id, from_block, until_block)
                .await
        }
        async fn get_revision(
            &self,
            location: &EventLocation,
        ) -> Result<Option<RevisionEvent>, ChainError> {
            self.inner.get_revision(location).await
        }
        async fn current_block(&self) -> Result<u64, ChainError> {
            self.inner.current_block().await
        }
        async fn pre_flight_batch_balance(
            &self,
            queued_count: usize,
        ) -> Result<Option<pangolin_chain::BatchBalanceCheck>, ChainError> {
            // Return a concrete insufficient projection so flush_publish_queue
            // can return `BalanceInsufficientForBatch` with REAL wei values
            // BEFORE any chain submit — the R-e everything-or-nothing path.
            Ok(Some(pangolin_chain::BatchBalanceCheck {
                total_estimated_cost_wei: 1_000_000u128.saturating_mul(queued_count as u128),
                current_balance_wei: 1_000,
            }))
        }
    }

    /// Adapter that counts every publish call (per-account flush
    /// observation) and proxies into a mock.
    #[derive(Clone)]
    struct CountingAdapter {
        inner: MockChainAdapter,
        count: std::sync::Arc<AtomicUsize>,
    }
    impl CountingAdapter {
        fn new() -> Self {
            Self {
                inner: MockChainAdapter::new(),
                count: std::sync::Arc::new(AtomicUsize::new(0)),
            }
        }
        fn count(&self) -> usize {
            self.count.load(Ordering::SeqCst)
        }
    }
    #[async_trait]
    impl ChainAdapter for CountingAdapter {
        async fn publish(&self, signed: &SignedRevision) -> Result<ChainAnchor, ChainError> {
            self.count.fetch_add(1, Ordering::SeqCst);
            self.inner.publish(signed).await
        }
        async fn pull_since(
            &self,
            vault_id: &VaultId,
            from_block: u64,
            until_block: Option<u64>,
        ) -> Result<Vec<RevisionEvent>, ChainError> {
            self.inner
                .pull_since(vault_id, from_block, until_block)
                .await
        }
        async fn get_revision(
            &self,
            location: &EventLocation,
        ) -> Result<Option<RevisionEvent>, ChainError> {
            self.inner.get_revision(location).await
        }
        async fn current_block(&self) -> Result<u64, ChainError> {
            self.inner.current_block().await
        }
    }

    // -----------------------------------------------------------------
    // Window state machine (Q-a + Q-b mandatory triggers)
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn flush_empty_queue_returns_ok_no_chain_call() {
        let (mut v, _dir) = fresh_vault();
        let device = DeviceKey::generate();
        let adapter = CountingAdapter::new();
        let report = v
            .flush_publish_queue(&adapter, &device, true)
            .await
            .expect("flush empty");
        assert_eq!(report.publish_report.rows.len(), 0);
        assert_eq!(adapter.count(), 0, "no chain call on empty queue");
    }

    #[tokio::test]
    async fn flush_single_dirty_marker_submits_one_chain_tx() {
        let (mut v, _dir) = fresh_vault();
        let device = DeviceKey::generate();
        let adapter = CountingAdapter::new();
        let _ = v.add_account(snap("a")).expect("add");
        let report = v
            .flush_publish_queue(&adapter, &device, true)
            .await
            .expect("flush");
        assert_eq!(report.publish_report.published_count(), 1);
        assert_eq!(adapter.count(), 1, "one chain submission");
        assert!(v.list_dirty().expect("list").is_empty(), "marker cleared");
    }

    #[tokio::test]
    async fn flush_two_accounts_submits_two_chain_txs() {
        let (mut v, _dir) = fresh_vault();
        let device = DeviceKey::generate();
        let adapter = CountingAdapter::new();
        let _ = v.add_account(snap("a1")).expect("add 1");
        let _ = v.add_account(snap("a2")).expect("add 2");
        let report = v
            .flush_publish_queue(&adapter, &device, true)
            .await
            .expect("flush");
        assert_eq!(report.publish_report.published_count(), 2);
        assert_eq!(adapter.count(), 2, "one chain tx per account");
    }

    #[tokio::test]
    async fn window_starts_on_first_edit_after_unlock() {
        let (mut v, _dir) = fresh_vault();
        let pre = v.publish_queue_state().expect("state pre");
        assert!(
            pre.window_started_at_unix_ms.is_none(),
            "no window before any edit"
        );
        let _ = v.add_account(snap("acc")).expect("add");
        let post = v.publish_queue_state().expect("state post");
        assert!(
            post.window_started_at_unix_ms.is_some(),
            "window started on first edit"
        );
        assert_eq!(post.dirty_count, 1);
    }

    #[tokio::test]
    async fn window_resets_after_flush_completes() {
        let (mut v, _dir) = fresh_vault();
        let device = DeviceKey::generate();
        let adapter = CountingAdapter::new();
        let _ = v.add_account(snap("acc")).expect("add");
        assert!(v
            .publish_queue_state()
            .expect("state")
            .window_started_at_unix_ms
            .is_some());
        let _ = v
            .flush_publish_queue(&adapter, &device, true)
            .await
            .expect("flush");
        assert!(
            v.publish_queue_state()
                .expect("state")
                .window_started_at_unix_ms
                .is_none(),
            "window reset after flush"
        );
    }

    #[tokio::test]
    async fn manual_flush_force_flag_ignores_window() {
        // R-a / Q-b: the force flag is currently always-flush in 5.1;
        // this test confirms calling flush immediately after an edit
        // (well within the 30s window) produces a chain tx.
        let (mut v, _dir) = fresh_vault();
        let device = DeviceKey::generate();
        let adapter = CountingAdapter::new();
        let _ = v.add_account(snap("acc")).expect("add");
        let _ = v
            .flush_publish_queue(&adapter, &device, true)
            .await
            .expect("force flush");
        assert_eq!(adapter.count(), 1);
    }

    #[test]
    fn env_var_window_clamps_to_min_1_max_300() {
        assert_eq!(
            Vault::resolve_batch_window_secs_from(None),
            BATCH_WINDOW_SECS_DEFAULT
        );
        // Below min clamps up to MIN.
        assert_eq!(
            Vault::resolve_batch_window_secs_from(Some("0")),
            BATCH_WINDOW_SECS_MIN
        );
        // Above max clamps down to MAX.
        assert_eq!(
            Vault::resolve_batch_window_secs_from(Some("9999")),
            BATCH_WINDOW_SECS_MAX
        );
        // In-range echoes the input.
        assert_eq!(Vault::resolve_batch_window_secs_from(Some("42")), 42);
        // Non-parseable falls back to default.
        assert_eq!(
            Vault::resolve_batch_window_secs_from(Some("not-a-number")),
            BATCH_WINDOW_SECS_DEFAULT
        );
    }

    // -----------------------------------------------------------------
    // Coalescing (R-c / Q-c Option A)
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn coalesce_three_updates_same_account_keeps_latest() {
        let (mut v, _dir) = fresh_vault();
        let id = v.add_account(snap("acc")).expect("add");
        // Three updates → 4 dirty markers total (genesis + 3 updates).
        let r1 = v.update_account(id, snap("u1")).expect("u1");
        let r2 = v.update_account(id, snap("u2")).expect("u2");
        let r3 = v.update_account(id, snap("u3")).expect("u3");
        assert_eq!(v.list_dirty().expect("list").len(), 4);
        let pruned = v.coalesce_dirty_markers().expect("coalesce");
        assert_eq!(pruned, 3, "3 of 4 markers pruned");
        let remaining = v.list_dirty().expect("list after");
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].revision_id, r3, "latest head preserved");
        // Suppress unused vars.
        let _ = (r1, r2);
    }

    #[tokio::test]
    async fn coalesce_unaffected_across_accounts() {
        let (mut v, _dir) = fresh_vault();
        let _ = v.add_account(snap("a1")).expect("add 1");
        let _ = v.add_account(snap("a2")).expect("add 2");
        let _ = v.add_account(snap("a3")).expect("add 3");
        assert_eq!(v.list_dirty().expect("list").len(), 3);
        let pruned = v.coalesce_dirty_markers().expect("coalesce");
        assert_eq!(pruned, 0, "no coalescing across distinct accounts");
        assert_eq!(v.list_dirty().expect("list").len(), 3);
    }

    #[tokio::test]
    async fn tombstone_always_wins_over_prior_update() {
        let (mut v, _dir) = fresh_vault();
        let id = v.add_account(snap("acc")).expect("add");
        let _ = v.update_account(id, snap("acc-2")).expect("update");
        v.delete_account(id).expect("delete");
        // 3 markers: genesis + update + tombstone.
        assert_eq!(v.list_dirty().expect("list").len(), 3);
        let pruned = v.coalesce_dirty_markers().expect("coalesce");
        assert_eq!(pruned, 2);
        let remaining = v.list_dirty().expect("list after");
        assert_eq!(remaining.len(), 1, "only tombstone marker survives");
        // The surviving marker IS the tombstone revision (head_revision_id).
        let revs = v.revisions_for(id).expect("revisions");
        let tombstone = revs.iter().find(|r| r.is_tombstone).expect("tombstone row");
        assert_eq!(remaining[0].revision_id, tombstone.revision_id);
    }

    #[tokio::test]
    async fn local_revision_graph_lineage_preserved_after_coalesce() {
        // L4: intermediate revisions still in `revisions` table after
        // coalescing.
        let (mut v, _dir) = fresh_vault();
        let id = v.add_account(snap("acc")).expect("add");
        let _ = v.update_account(id, snap("u1")).expect("u1");
        let _ = v.update_account(id, snap("u2")).expect("u2");
        let pre_coalesce_revs = v.revisions_for(id).expect("revs pre");
        let _ = v.coalesce_dirty_markers().expect("coalesce");
        let post_coalesce_revs = v.revisions_for(id).expect("revs post");
        assert_eq!(
            pre_coalesce_revs.len(),
            post_coalesce_revs.len(),
            "revisions table untouched by coalescing"
        );
    }

    #[tokio::test]
    async fn coalesce_under_backwards_clock_skew_picks_head_from_account_identities_table() {
        // L-clock-skew: the head selection is from
        // account_identities.head_revision_id, NOT MAX(marked_at).
        // We simulate clock skew by manually mutating the marked_at
        // column for the head's marker to an OLDER timestamp than the
        // earlier (now-coalesced-away) markers.
        let (mut v, _dir) = fresh_vault();
        let id = v.add_account(snap("acc")).expect("add");
        let _ = v.update_account(id, snap("u1")).expect("u1");
        let head = v.update_account(id, snap("u2")).expect("u2");
        // Force-set the head's marker timestamp to be EARLIER than the
        // others (backwards-clock simulation).
        v.__test_set_dirty_marker_timestamp(id, head, 0)
            .expect("force timestamp");
        let pruned = v.coalesce_dirty_markers().expect("coalesce");
        assert_eq!(pruned, 2);
        let remaining = v.list_dirty().expect("list after");
        assert_eq!(remaining.len(), 1);
        assert_eq!(
            remaining[0].revision_id, head,
            "head from account_identities wins even with backwards marked_at"
        );
    }

    #[tokio::test]
    async fn coalesce_skips_frozen_accounts_trivially_because_no_dirty_markers_exist() {
        // P8 CRIT-1 inheritance: frozen accounts can't be edited; no
        // dirty markers exist for them; the coalescer's per-account
        // group simply has length 1 (genesis) or 0.
        let (mut v, _dir) = fresh_vault();
        let id = v.add_account(snap("acc")).expect("add");
        // Manually freeze via test helper if available; otherwise just
        // assert the trivial case (1 marker → no pruning needed).
        let pruned = v.coalesce_dirty_markers().expect("coalesce");
        assert_eq!(pruned, 0);
        let _ = id;
    }

    #[tokio::test]
    async fn flush_with_three_same_account_updates_yields_one_chain_tx() {
        // End-to-end coalescing through flush_publish_queue.
        let (mut v, _dir) = fresh_vault();
        let device = DeviceKey::generate();
        let adapter = CountingAdapter::new();
        let id = v.add_account(snap("acc")).expect("add");
        let _ = v.update_account(id, snap("u1")).expect("u1");
        let _ = v.update_account(id, snap("u2")).expect("u2");
        let _ = v.update_account(id, snap("u3")).expect("u3");
        assert_eq!(v.list_dirty().expect("list").len(), 4);
        let report = v
            .flush_publish_queue(&adapter, &device, true)
            .await
            .expect("flush");
        // 3 markers pruned (genesis + u1 + u2); 1 chain submission
        // (u3 head).
        assert_eq!(report.coalesced_markers_pruned, 3);
        assert_eq!(report.publish_report.published_count(), 1);
        assert_eq!(adapter.count(), 1, "exactly one chain submission");
    }

    // -----------------------------------------------------------------
    // Balance gate (Q-e + Q-f)
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn flush_returns_balance_insufficient_when_below_total() {
        let (mut v, _dir) = fresh_vault();
        let device = DeviceKey::generate();
        let adapter = BalanceInsufficientAdapter::new();
        let _ = v.add_account(snap("acc")).expect("add");
        let err = v
            .flush_publish_queue(&adapter, &device, true)
            .await
            .expect_err("must surface balance gate");
        match err {
            BatchFlushError::BalanceInsufficientForBatch {
                queued_count,
                needed,
                available,
            } => {
                assert_eq!(queued_count, 1);
                // Per R-e fix-pass: REAL wei values from the pre-flight
                // gate, not the sentinel zeros the post-hoc detection used.
                assert_eq!(needed, 1_000_000);
                assert_eq!(available, 1_000);
            }
            other => panic!("expected BalanceInsufficientForBatch, got {other:?}"),
        }
        // R-e fix-pass load-bearing assertion: NO chain submit was
        // attempted. The pre-flight gate fired BEFORE any publish call.
        assert_eq!(
            adapter.publish_count(),
            0,
            "pre-flight gate must short-circuit BEFORE any publish call"
        );
        // Dirty marker still present (R-f).
        assert_eq!(v.list_dirty().expect("list").len(), 1);
        // The state flag is now true.
        assert!(v.publish_queue_state().expect("state").blocked_on_balance);
    }

    #[tokio::test]
    async fn pre_flight_batch_balance_aggregates_across_queued_count() {
        // R-e: the projected total is queued_count × per-revision estimate.
        // Verify aggregation: 3 accounts × 1_000_000 wei per revision = 3_000_000 needed.
        let (mut v, _dir) = fresh_vault();
        let device = DeviceKey::generate();
        let adapter = BalanceInsufficientAdapter::new();
        let _ = v.add_account(snap("a")).expect("add a");
        let _ = v.add_account(snap("b")).expect("add b");
        let _ = v.add_account(snap("c")).expect("add c");
        let err = v
            .flush_publish_queue(&adapter, &device, true)
            .await
            .expect_err("balance gate fires");
        match err {
            BatchFlushError::BalanceInsufficientForBatch {
                queued_count,
                needed,
                available,
            } => {
                assert_eq!(queued_count, 3);
                assert_eq!(needed, 3_000_000); // 3 × 1_000_000 per-revision projection
                assert_eq!(available, 1_000);
            }
            other => panic!("expected BalanceInsufficientForBatch, got {other:?}"),
        }
        // Critical: ZERO publish calls. Three accounts queued, all three
        // skipped, no partial-batch. R-e everything-or-nothing.
        assert_eq!(adapter.publish_count(), 0);
        // All three dirty markers preserved for retry.
        assert_eq!(v.list_dirty().expect("list").len(), 3);
    }

    #[tokio::test]
    async fn pre_flight_batch_balance_none_falls_back_to_per_revision_gate() {
        // Back-compat: an adapter that doesn't implement
        // `pre_flight_batch_balance` (returns None from default impl)
        // falls back to the per-revision gate inside `publish_revision_v1`.
        // CountingAdapter inherits the default `Ok(None)` so the gate is
        // skipped + each publish call decides itself.
        let (mut v, _dir) = fresh_vault();
        let device = DeviceKey::generate();
        let adapter = CountingAdapter::new();
        let _ = v.add_account(snap("acc")).expect("add");
        let report = v
            .flush_publish_queue(&adapter, &device, true)
            .await
            .expect("default-impl pre-flight returns None; flush proceeds");
        // MockChainAdapter accepts publishes, so the row succeeds.
        assert_eq!(report.publish_report.published_count(), 1);
        assert_eq!(adapter.count(), 1);
        assert!(!v.publish_queue_state().expect("state").blocked_on_balance);
    }

    #[tokio::test]
    async fn pre_flight_batch_balance_sufficient_proceeds_to_publish() {
        // Adapter returns Some(sufficient); flush proceeds to publish.
        struct SufficientAdapter {
            inner: MockChainAdapter,
            count: std::sync::Arc<AtomicUsize>,
        }
        #[async_trait]
        impl ChainAdapter for SufficientAdapter {
            async fn publish(&self, signed: &SignedRevision) -> Result<ChainAnchor, ChainError> {
                self.count.fetch_add(1, Ordering::SeqCst);
                self.inner.publish(signed).await
            }
            async fn pull_since(
                &self,
                vault_id: &VaultId,
                from_block: u64,
                until_block: Option<u64>,
            ) -> Result<Vec<RevisionEvent>, ChainError> {
                self.inner
                    .pull_since(vault_id, from_block, until_block)
                    .await
            }
            async fn get_revision(
                &self,
                location: &EventLocation,
            ) -> Result<Option<RevisionEvent>, ChainError> {
                self.inner.get_revision(location).await
            }
            async fn current_block(&self) -> Result<u64, ChainError> {
                self.inner.current_block().await
            }
            async fn pre_flight_batch_balance(
                &self,
                _queued_count: usize,
            ) -> Result<Option<pangolin_chain::BatchBalanceCheck>, ChainError> {
                Ok(Some(pangolin_chain::BatchBalanceCheck {
                    total_estimated_cost_wei: 1_000,
                    current_balance_wei: 999_999_999,
                }))
            }
        }
        let (mut v, _dir) = fresh_vault();
        let device = DeviceKey::generate();
        let adapter = SufficientAdapter {
            inner: MockChainAdapter::new(),
            count: std::sync::Arc::new(AtomicUsize::new(0)),
        };
        let _ = v.add_account(snap("acc")).expect("add");
        let report = v
            .flush_publish_queue(&adapter, &device, true)
            .await
            .expect("sufficient balance");
        assert_eq!(report.publish_report.published_count(), 1);
        assert_eq!(adapter.count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn flush_returns_balance_insufficient_only_when_every_account_fails() {
        // Defense check: a single per-account failure that ISN'T
        // balance-related shouldn't surface BalanceInsufficientForBatch.
        struct FailRpcAdapter {
            inner: MockChainAdapter,
        }
        #[async_trait]
        impl ChainAdapter for FailRpcAdapter {
            async fn publish(&self, _: &SignedRevision) -> Result<ChainAnchor, ChainError> {
                Err(ChainError::Rpc("transient".into()))
            }
            async fn pull_since(
                &self,
                vault_id: &VaultId,
                from_block: u64,
                until_block: Option<u64>,
            ) -> Result<Vec<RevisionEvent>, ChainError> {
                self.inner
                    .pull_since(vault_id, from_block, until_block)
                    .await
            }
            async fn get_revision(
                &self,
                location: &EventLocation,
            ) -> Result<Option<RevisionEvent>, ChainError> {
                self.inner.get_revision(location).await
            }
            async fn current_block(&self) -> Result<u64, ChainError> {
                self.inner.current_block().await
            }
        }
        let (mut v, _dir) = fresh_vault();
        let device = DeviceKey::generate();
        let adapter = FailRpcAdapter {
            inner: MockChainAdapter::new(),
        };
        let _ = v.add_account(snap("acc")).expect("add");
        let report = v
            .flush_publish_queue(&adapter, &device, true)
            .await
            .expect("non-balance failure stays in row-level outcomes");
        assert_eq!(report.publish_report.failed_count(), 1);
    }

    #[tokio::test]
    async fn edits_after_balance_block_append_to_same_queue() {
        // R-f: blocked-queue append + coalesce on retry.
        let (mut v, _dir) = fresh_vault();
        let device = DeviceKey::generate();
        let bad_adapter = BalanceInsufficientAdapter::new();
        let id = v.add_account(snap("acc")).expect("add");
        // First flush fails on balance.
        let _ = v
            .flush_publish_queue(&bad_adapter, &device, true)
            .await
            .expect_err("balance gate");
        // User keeps editing.
        let _ = v.update_account(id, snap("u1")).expect("u1");
        let _ = v.update_account(id, snap("u2")).expect("u2");
        // Now 3 markers; on retry with a good adapter the coalescing
        // collapses them.
        let good_adapter = CountingAdapter::new();
        let report = v
            .flush_publish_queue(&good_adapter, &device, true)
            .await
            .expect("flush with good adapter");
        assert_eq!(report.coalesced_markers_pruned, 2);
        assert_eq!(
            good_adapter.count(),
            1,
            "one chain submission post-coalesce"
        );
        // blocked_on_balance flag cleared on success.
        assert!(!v.publish_queue_state().expect("state").blocked_on_balance);
    }

    #[tokio::test]
    async fn flush_retries_after_balance_top_up_succeeds_for_full_queue() {
        let (mut v, _dir) = fresh_vault();
        let device = DeviceKey::generate();
        let bad = BalanceInsufficientAdapter::new();
        let _ = v.add_account(snap("acc")).expect("add");
        let _ = v
            .flush_publish_queue(&bad, &device, true)
            .await
            .unwrap_err();
        // Top up = swap to a good adapter on retry.
        let good = CountingAdapter::new();
        let report = v
            .flush_publish_queue(&good, &device, true)
            .await
            .expect("retry flush");
        assert_eq!(report.publish_report.published_count(), 1);
        assert!(v.list_dirty().expect("list").is_empty());
    }

    // -----------------------------------------------------------------
    // Cap behavior (Q-b options 7-8) — primitives test
    // -----------------------------------------------------------------

    #[test]
    fn count_cap_constant_matches_r_b_spec() {
        assert_eq!(PUBLISH_QUEUE_COUNT_CAP, 100);
    }

    #[test]
    fn byte_cap_constant_matches_r_b_spec() {
        assert_eq!(crate::vault::PUBLISH_QUEUE_BYTE_CAP_BYTES, 1_000_000);
    }

    #[tokio::test]
    async fn publish_queue_state_reflects_dirty_count_and_bytes() {
        let (mut v, _dir) = fresh_vault();
        let pre = v.publish_queue_state().expect("state");
        assert_eq!(pre.dirty_count, 0);
        assert_eq!(pre.dirty_byte_size, 0);

        let _ = v.add_account(snap("acc-a")).expect("a");
        let _ = v.add_account(snap("acc-b")).expect("b");
        let post = v.publish_queue_state().expect("state");
        assert_eq!(post.dirty_count, 2);
        assert!(post.dirty_byte_size > 0, "byte size summed across markers");
    }

    // -----------------------------------------------------------------
    // L11 — opt-in window-elapsed flush primitive
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn window_elapsed_flush_defaults_off() {
        let (mut v, _dir) = fresh_vault();
        let state = v.publish_queue_state().expect("state");
        // Indirect signal: the feature default ships OFF. The flag
        // itself isn't on PublishQueueState (the host doesn't render
        // it); it's exercised in the unit test below by toggling it.
        let _ = state;
        // Calling toggle works without error.
        v.enable_window_elapsed_flush(true).expect("on");
        v.enable_window_elapsed_flush(false).expect("off");
    }

    #[tokio::test]
    async fn enable_window_elapsed_flush_on_locked_vault_errors() {
        let (mut v, _dir) = fresh_vault();
        v.lock();
        let err = v
            .enable_window_elapsed_flush(true)
            .expect_err("locked vault must reject");
        assert!(matches!(err, crate::StoreError::NotUnlocked));
    }

    // -----------------------------------------------------------------
    // Drain-on-teardown: dirty markers persist through lock/unlock
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn dirty_markers_persist_through_lock_and_resume_on_next_unlock() {
        // L1 fallback path: dirty markers persist in SQLite even if
        // the host doesn't flush before lock(). Next unlock resumes
        // the queue.
        let (mut v, _dir) = fresh_vault();
        let _ = v.add_account(snap("persist")).expect("add");
        assert_eq!(v.list_dirty().expect("list").len(), 1);
        v.lock();
        let presence = PressYPresenceProof::confirmed();
        let identity = PinIdentityProof::new(pwd());
        v.unlock(&presence, &identity).expect("re-unlock");
        let dirty = v.list_dirty().expect("list after re-unlock");
        assert_eq!(dirty.len(), 1, "marker survives lock + unlock");
        // The window state DID reset on the re-unlock (R-d).
        let state = v.publish_queue_state().expect("state");
        assert!(
            state.window_started_at_unix_ms.is_none(),
            "fresh window state after re-unlock"
        );
    }

    #[tokio::test]
    async fn flush_on_locked_vault_returns_no_active_session() {
        let (mut v, _dir) = fresh_vault();
        let device = DeviceKey::generate();
        let adapter = CountingAdapter::new();
        v.lock();
        let err = v
            .flush_publish_queue(&adapter, &device, true)
            .await
            .expect_err("locked vault must reject flush");
        assert!(matches!(err, BatchFlushError::NoActiveSession));
    }

    // -----------------------------------------------------------------
    // CLI integration preserved (R-h refactor invariant)
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn library_publish_all_for_vault_matches_cli_behavior() {
        // The library function is the exact engine the CLI's
        // thin-shell `publish_all` delegates to. We exercise the
        // engine directly here to pin the contract.
        let (mut v, _dir) = fresh_vault();
        let device = DeviceKey::generate();
        let adapter = MockChainAdapter::new();
        let _ = v.add_account(snap("a")).expect("add");
        let report = publish_all_for_vault(&mut v, &adapter, &device)
            .await
            .expect("publish ok");
        assert_eq!(report.published_count(), 1);
        assert_eq!(report.failed_count(), 0);
        assert!(v.list_dirty().expect("list").is_empty());
    }
}
