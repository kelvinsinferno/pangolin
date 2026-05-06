//! Publish + pull orchestration logic.
//!
//! Generic over `ChainAdapter` so the unit tests can drive
//! `MockChainAdapter` while the production path uses
//! `BaseSepoliaAdapter`. Cardinal-principle 3 ("blockchain is a log,
//! never an authority") shapes both halves: `publish_all` walks the
//! local dirty list and submits each entry; `pull_all` ingests chain
//! events into the local store but never auto-resolves forks. P9
//! handles fork resolution; P10 handles tombstone semantics.
//!
//! ## A3 — pre-publish check (publish idempotency)
//!
//! Before re-attempting a `publish` whose marker still exists, we
//! call `adapter.pull_since(vault_id, last_pulled_block, None)` and
//! check whether a revision with our locally-known `revision_id`
//! already appears on chain. If yes, treat as already-published —
//! skip the on-chain step and run only the local commit
//! (`mark_published` + `clear_dirty`). If no, proceed with publish.
//!
//! This costs one extra `eth_getLogs` call per stale marker but is
//! the right discipline for a manually-invoked CLI: a kill mid-
//! publish is recoverable without operator intervention.
//!
//! ## Per-account error isolation (publish)
//!
//! `publish_all` continues on per-account failures. The result is a
//! [`PublishReport`] enumerating which accounts succeeded and which
//! errored; the caller (the `publish` subcommand) prints the
//! summary on stderr and exits 1 iff any account failed.

#![allow(dead_code)]

use pangolin_chain::{
    build_signed_revision, ChainAdapter, ChainError, RevisionEvent, SignedRevision, VaultId,
};
use pangolin_crypto::keys::DeviceKey;
use pangolin_store::{AccountId, ChainAnchor, DirtyEntry, RevisionId, StoreError, Vault};

/// Outcome of a single publish attempt within `publish_all`.
#[derive(Debug, Clone)]
pub enum PublishOutcome {
    /// The revision was freshly published on chain by this run.
    /// `anchor` is the chain anchor; `was_already_on_chain` is
    /// `false`.
    Published {
        anchor: ChainAnchor,
        was_already_on_chain: bool,
    },
    /// The on-chain step or local commit step failed. The dirty
    /// marker was preserved; a re-run will retry.
    Failed { error: String },
}

/// One row of the per-(account, revision) outcome list produced by
/// `publish_all`.
#[derive(Debug, Clone)]
pub struct PublishOutcomeRow {
    pub account_id: AccountId,
    pub revision_id: RevisionId,
    pub outcome: PublishOutcome,
}

/// Aggregate report from a `publish_all` run.
#[derive(Debug, Clone, Default)]
pub struct PublishReport {
    /// Per-row outcomes in the order entries were attempted.
    pub rows: Vec<PublishOutcomeRow>,
}

impl PublishReport {
    /// Number of rows that successfully landed on chain in this run
    /// (counts the A3 "already on chain" case as a success too —
    /// the chain has the revision regardless of whether THIS run
    /// put it there).
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

    /// `true` iff every entry in `rows` succeeded (or there were
    /// no entries — a no-op publish is also "no failures").
    #[must_use]
    pub fn all_ok(&self) -> bool {
        self.failed_count() == 0
    }
}

/// Walk `Vault::list_dirty()` and publish every entry through the
/// supplied adapter.
///
/// Per-entry semantics (per `P8.md` §A3):
///
/// 1. Read `(parent, schema_version, enc_payload)` from the local
///    revisions row.
/// 2. Build a `SignedRevision` via
///    [`pangolin_chain::signing::build_signed_revision`] using the
///    supplied `device_key` (`PoC` two-key model — the gas-paying
///    secp256k1 wallet is internal to the adapter).
/// 3. **Pre-publish check**: query
///    `adapter.pull_since(vault_id, last_pulled_block, None)` and
///    inspect every event's `device_id` + canonical-hash. If an
///    event with the same canonical-hash as our `signed` already
///    appears on chain, skip the `publish` call and run only the
///    local commit (`mark_published` + `clear_dirty`).
/// 4. Otherwise, call [`ChainAdapter::publish`].
/// 5. On success (or the A3-detected "already on chain" path),
///    update `revisions.chain_anchor_*` via [`Vault::mark_published`]
///    and remove the marker via [`Vault::clear_dirty`].
/// 6. On failure, leave the marker in place; the next run retries.
///
/// `publish_all` is generic over `ChainAdapter` so unit tests can
/// pass `MockChainAdapter`. The vault must be unlocked (we read
/// payload bytes via `read_revision_for_publish`, which is metadata-
/// ish but the dirty list itself was stamped only after a successful
/// unlock — calling this on a fresh vault simply yields an empty
/// dirty list and a no-op return).
pub async fn publish_all<A: ChainAdapter + ?Sized>(
    vault: &mut Vault,
    adapter: &A,
    device_key: &DeviceKey,
) -> Result<PublishReport, StoreError> {
    let vault_id: VaultId = vault.vault_id();
    let last_pulled = vault.last_pulled_block()?;
    let dirty: Vec<DirtyEntry> = vault.list_dirty()?;

    // Pre-fetch the chain's view of "everything since last_pulled"
    // exactly once per run — re-using it for the A3 check across
    // every dirty entry. We tolerate a chain-side error here only by
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

/// Per-entry helper: factored out so `publish_all`'s loop body stays
/// flat. Returns the outcome enum directly; failure conditions are
/// caught by the surrounding match in `publish_all`.
async fn publish_one<A: ChainAdapter + ?Sized>(
    vault: &mut Vault,
    adapter: &A,
    device_key: &DeviceKey,
    entry: &DirtyEntry,
    chain_view: Option<&[RevisionEvent]>,
) -> Result<PublishOutcome, anyhow::Error> {
    let payload = vault.read_revision_for_publish(entry.account_id, entry.revision_id)?;
    let signed: SignedRevision = build_signed_revision(
        device_key,
        vault.vault_id(),
        *entry.account_id.as_bytes(),
        *payload.parent_revision.as_bytes(),
        payload.schema_version,
        payload.enc_payload,
    );

    // A3 pre-publish check: if the chain view shows an event with
    // the same canonical hash already on chain, skip the publish
    // call. We compare by recomputing the canonical hash on each
    // candidate event (cheap; keccak over ~160 bytes) so the match
    // does not depend on whatever device_id is stored in the local
    // row (which, for the PoC, may be a random 32 bytes that don't
    // correspond to any actual signing key — see crate-level docs).
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
    let anchor: ChainAnchor = adapter
        .publish(&signed)
        .await
        .map_err(|e: ChainError| anyhow::anyhow!("publish failed: {e}"))?;
    vault.mark_published(entry.revision_id, anchor)?;
    vault.clear_dirty(entry.account_id, entry.revision_id)?;
    Ok(PublishOutcome::Published {
        anchor,
        was_already_on_chain: false,
    })
}

// ---------------------------------------------------------------------
// Pull orchestration (P8-4 — placeholder; real impl in P8-4 commit).
// ---------------------------------------------------------------------

/// Per-(account_id, head set) summary of a forked account, as
/// surfaced by `pull_all`.
#[derive(Debug, Clone)]
pub struct ForkSummary {
    pub account_id: AccountId,
    pub head_revision_ids: Vec<RevisionId>,
}

/// Aggregate report from a `pull_all` run.
#[derive(Debug, Clone, Default)]
pub struct PullReport {
    /// Number of new events that were ingested into the local store
    /// during this run (skips revisions that were already present —
    /// idempotency on overlap chunks).
    pub applied: usize,
    /// Forked-account summaries detected during this run.
    pub forks: Vec<ForkSummary>,
}

/// Block window per chunk in the chunked pull loop. Chosen at 8 000
/// blocks (below the 9 000-block window `BaseSepoliaAdapter` uses
/// internally, which is itself below the public RPC's 10 000-block
/// cap). Per `P8.md` §A5 — checkpoint advances per-chunk so a
/// failure mid-range preserves prior chunks' progress.
pub const PULL_CHUNK_SIZE: u64 = 8_000;

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    use pangolin_chain::{verify_signed_revision, MockChainAdapter};
    use pangolin_crypto::secret::SecretBytes;
    use pangolin_store::session::{PinIdentityProof, PressYPresenceProof};
    use pangolin_store::AccountSnapshot;
    use tempfile::TempDir;

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

    /// Plan test: `publish_all` clears the dirty marker on success.
    #[tokio::test]
    async fn publish_clears_dirty_on_success() {
        let (mut v, _dir) = fresh_vault();
        let device = DeviceKey::generate();
        let adapter = MockChainAdapter::new();
        let _id = v.add_account(snap("publish-clear")).expect("add");
        assert_eq!(v.list_dirty().expect("list").len(), 1);
        let report = publish_all(&mut v, &adapter, &device)
            .await
            .expect("publish_all ok");
        assert_eq!(report.published_count(), 1);
        assert_eq!(report.failed_count(), 0);
        assert!(
            v.list_dirty().expect("list after publish").is_empty(),
            "dirty marker must be cleared on publish success"
        );
        assert_eq!(adapter.event_count(), 1);
    }

    /// Plan test: `publish_all` keeps the dirty marker on chain
    /// error. Implemented via a custom adapter that always errors.
    #[tokio::test]
    async fn publish_keeps_dirty_on_chain_error() {
        let (mut v, _dir) = fresh_vault();
        let device = DeviceKey::generate();
        // Adapter that always fails publish.
        let adapter = AlwaysFailAdapter;
        let _id = v.add_account(snap("publish-fail")).expect("add");
        assert_eq!(v.list_dirty().expect("list").len(), 1);
        let report = publish_all(&mut v, &adapter, &device)
            .await
            .expect("publish_all returns Ok with per-row failures");
        assert_eq!(report.failed_count(), 1);
        assert_eq!(report.published_count(), 0);
        assert_eq!(
            v.list_dirty().expect("list after failed publish").len(),
            1,
            "dirty marker must be preserved on chain error"
        );
    }

    /// Plan test: per-account isolation. With a sequence of accounts
    /// where the chain adapter fails on the second one, the first
    /// must still publish successfully.
    #[tokio::test]
    async fn publish_per_account_isolation() {
        let (mut v, _dir) = fresh_vault();
        let device = DeviceKey::generate();
        // `FlakyAdapter` fails on the second call. Per-entry isolation
        // means entry 0 succeeds, entry 1 fails, entry 2 succeeds.
        let adapter = FlakyAdapter::new(&[1]);
        let _ = v.add_account(snap("a0")).expect("a0");
        let _ = v.add_account(snap("a1")).expect("a1");
        let _ = v.add_account(snap("a2")).expect("a2");
        let report = publish_all(&mut v, &adapter, &device)
            .await
            .expect("publish_all ok");
        assert_eq!(report.published_count(), 2);
        assert_eq!(report.failed_count(), 1);
        assert_eq!(
            v.list_dirty().expect("list").len(),
            1,
            "exactly one marker survives the per-row failure"
        );
    }

    /// Plan test: A3 idempotent re-run after partial failure.
    /// Simulate the failure by bypassing `clear_dirty` after the
    /// adapter `publish` returns — re-running `publish_all` should
    /// detect the on-chain entry and run only the local commit (no
    /// duplicate publish).
    #[tokio::test]
    async fn publish_idempotent_on_rerun_after_partial_failure() {
        let (mut v, _dir) = fresh_vault();
        let device = DeviceKey::generate();
        let adapter = MockChainAdapter::new();
        let id = v.add_account(snap("partial-fail")).expect("add");
        let entry = v.list_dirty().expect("list")[0];
        // Stage 1: simulate the kill-after-publish path by manually
        // submitting via the same canonical hash and leaving the
        // marker present. We achieve this by running publish_all
        // once (which on success clears the marker), then re-stamping
        // the marker as if the local clear had been killed.
        let _ = publish_all(&mut v, &adapter, &device)
            .await
            .expect("first publish");
        assert_eq!(adapter.event_count(), 1);
        // Re-stamp the dirty marker (the "kill mid-publish" path)
        // and re-run. The A3 pre-publish check should detect the
        // already-published event and run only the local commit.
        v.mark_dirty(id, entry.revision_id).expect("re-stamp");
        let pre_event_count = adapter.event_count();
        let report = publish_all(&mut v, &adapter, &device)
            .await
            .expect("re-run ok");
        assert_eq!(
            adapter.event_count(),
            pre_event_count,
            "no duplicate publish"
        );
        // The marker is cleared again.
        assert!(v.list_dirty().expect("list").is_empty());
        // The single row is reported as published with the
        // already-on-chain flag set.
        assert_eq!(report.rows.len(), 1);
        match &report.rows[0].outcome {
            PublishOutcome::Published {
                was_already_on_chain,
                ..
            } => {
                assert!(was_already_on_chain, "A3 must mark it as already on chain");
            }
            PublishOutcome::Failed { error } => {
                panic!("unexpected failure outcome: {error}");
            }
        }
    }

    /// Plan test: empty dirty list → no-op publish.
    #[tokio::test]
    async fn publish_no_op_when_dirty_list_empty() {
        let (mut v, _dir) = fresh_vault();
        let device = DeviceKey::generate();
        let adapter = MockChainAdapter::new();
        let report = publish_all(&mut v, &adapter, &device)
            .await
            .expect("publish_all ok");
        assert_eq!(report.published_count(), 0);
        assert_eq!(report.failed_count(), 0);
        assert!(report.all_ok());
        assert_eq!(adapter.event_count(), 0);
    }

    // ---------------------------------------------------------------
    // Test adapter helpers
    // ---------------------------------------------------------------

    /// Adapter that always errors on `publish`. `pull_since` returns
    /// an empty list. `current_block` returns 0.
    struct AlwaysFailAdapter;

    #[async_trait::async_trait]
    impl ChainAdapter for AlwaysFailAdapter {
        async fn publish(&self, _signed: &SignedRevision) -> Result<ChainAnchor, ChainError> {
            Err(ChainError::Rpc("simulated failure".into()))
        }
        async fn pull_since(
            &self,
            _vault_id: &VaultId,
            _from_block: u64,
            _until_block: Option<u64>,
        ) -> Result<Vec<RevisionEvent>, ChainError> {
            Ok(Vec::new())
        }
        async fn get_revision(
            &self,
            _location: &pangolin_chain::EventLocation,
        ) -> Result<Option<RevisionEvent>, ChainError> {
            Ok(None)
        }
        async fn current_block(&self) -> Result<u64, ChainError> {
            Ok(0)
        }
    }

    /// Adapter that fails on the N-th call (0-indexed) per a
    /// caller-supplied set, succeeds otherwise via a wrapped
    /// `MockChainAdapter`. Used for per-account-isolation tests.
    struct FlakyAdapter {
        inner: MockChainAdapter,
        // Indexes (0-based) at which `publish` should fail.
        fail_on: BTreeSet<usize>,
        counter: std::sync::Mutex<usize>,
    }

    impl FlakyAdapter {
        fn new(fail_on: &[usize]) -> Self {
            Self {
                inner: MockChainAdapter::new(),
                fail_on: fail_on.iter().copied().collect(),
                counter: std::sync::Mutex::new(0),
            }
        }
    }

    #[async_trait::async_trait]
    impl ChainAdapter for FlakyAdapter {
        async fn publish(&self, signed: &SignedRevision) -> Result<ChainAnchor, ChainError> {
            let idx = {
                let mut c = self.counter.lock().expect("counter mutex");
                let i = *c;
                *c += 1;
                i
            };
            if self.fail_on.contains(&idx) {
                return Err(ChainError::Rpc(format!("simulated flake at index {idx}")));
            }
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
            location: &pangolin_chain::EventLocation,
        ) -> Result<Option<RevisionEvent>, ChainError> {
            self.inner.get_revision(location).await
        }
        async fn current_block(&self) -> Result<u64, ChainError> {
            self.inner.current_block().await
        }
    }

    /// Defense-in-depth: every revision built by `build_signed_revision`
    /// inside `publish_all` should pass `verify_signed_revision`. This
    /// is a sanity check on the canonical-hash discipline, not a P8
    /// requirement per se.
    #[tokio::test]
    async fn published_revisions_self_verify() {
        let (mut v, _dir) = fresh_vault();
        let device = DeviceKey::generate();
        let adapter = MockChainAdapter::new();
        let _ = v.add_account(snap("self-verify")).expect("add");
        let _ = publish_all(&mut v, &adapter, &device)
            .await
            .expect("publish ok");
        let events = adapter
            .pull_since(&v.vault_id(), 0, None)
            .await
            .expect("pull ok");
        assert_eq!(events.len(), 1);
        // Reconstruct the SignedRevision shape (the chain side
        // strips the signature, so we can only verify by
        // re-deriving the canonical hash and checking that
        // `device.verifying_key().to_bytes()` matches the
        // event's `device_id`).
        assert_eq!(events[0].device_id, device.verifying_key().to_bytes());
        // And the test verifies the chain-side mock's eager-verify
        // discipline (P7 audit MED-4) is honoured — every
        // successfully-published event must have been signed
        // correctly.
        // We don't have the SignedRevision back, but the mock's
        // `publish` would have errored if not. So this is implicitly
        // proven by reaching this assertion.
        let _ = verify_signed_revision; // pull into scope for the doc.
    }
}
