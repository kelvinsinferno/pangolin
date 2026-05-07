//! In-memory `MockChainAdapter`.
//!
//! Mirrors the on-chain semantics of `RevisionLogV0` for tests:
//! `publish` assigns a monotonically-increasing sequence number,
//! emits a `RevisionPublished` "event" into an in-memory `Vec`, and
//! returns the synthetic `ChainAnchor`. `pull_since` filters the log
//! by `vault_id` + `from_block` exclusive.
//!
//! ## Cfg gate
//!
//! The whole module is compiled only under `cfg(any(test, feature =
//! "test-utilities"))` per success criterion 11
//! (`docs/issue-plans/P7.md`). Production downstream consumers
//! cannot link against `MockChainAdapter` because they cannot enable
//! the feature without an explicit Cargo.toml change, and the feature
//! itself is documented as test-only.
//!
//! ## State machine
//!
//! `MockChainState` carries:
//! - `next_sequence`: incremented on every `publish`, copied into the
//!   resulting `ChainAnchor.sequence`.
//! - `next_block`: incremented on every `publish`. Lets `pull_since`
//!   produce events that look like they came from real blocks. All
//!   events at the same block index get distinct `log_index` values
//!   starting at 0 within the block (we always assign block N + 1
//!   per publish, so each block holds exactly one event in this
//!   simple model — sufficient for unit tests).
//! - `events`: the canonical chain log, ordered by submission.
//!
//! Synchronization is via a single `Mutex` because tests are single-
//! threaded by default and the lock is held for nanoseconds. The
//! adapter implements `Send + Sync` because the trait demands it.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use crate::adapter::ChainAdapter;
use crate::error::ChainError;
use crate::signing::verify_signed_revision;
use crate::types::{ChainAnchor, EventLocation, RevisionEvent, SignedRevision, VaultId};

/// In-memory chain log + sequence counter. Internal to `mock.rs`.
#[derive(Debug, Default)]
struct MockChainState {
    /// Monotonically-increasing sequence counter, mirrors the on-chain
    /// `nextSequence` storage slot. The value at the time of a publish
    /// is what the contract's `RevisionPublished` event records.
    next_sequence: u64,
    /// Monotonically-increasing block counter. `publish` increments
    /// this before assigning, so the first event lands at block 1.
    /// This matches the convention that the chain's "current block"
    /// after K publishes is K (the genesis block is implicit, before
    /// any publish).
    next_block: u64,
    /// The log itself, in submission order.
    events: Vec<RevisionEvent>,
}

/// In-memory chain adapter for unit tests.
///
/// `Clone`-able through the `Arc<Mutex<...>>` interior; cloning shares
/// the same chain state, which is the right semantics for tests that
/// need multiple references to the "same" chain (e.g., one publish
/// site and one pull site).
///
/// **P10-4 disconnect toggle.** A test-utilities-gated
/// [`Self::set_disconnected`] toggle simulates a network outage: when
/// `true`, every adapter method returns `ChainError::Rpc("simulated
/// offline")` synchronously without touching internal state. The
/// toggle is shared via the `Arc<AtomicBool>` interior alongside the
/// state mutex; cloning shares both. Production binaries cannot
/// construct a disconnected mock — the entire `mock` module is gated
/// on `cfg(any(test, feature = "test-utilities"))` (see crate-level
/// docs).
#[derive(Debug, Clone, Default)]
pub struct MockChainAdapter {
    state: Arc<Mutex<MockChainState>>,
    /// **P10-4.** When `true`, every adapter method short-circuits
    /// to `ChainError::Rpc("simulated offline")`. Shared with clones.
    /// `AtomicBool` (not `RwLock<bool>`) because the toggle is
    /// concurrency-safe at zero coordination cost; the test never
    /// needs to read-lock a snapshot of the toggle separate from
    /// each adapter call.
    disconnected: Arc<AtomicBool>,
}

impl MockChainAdapter {
    /// Construct a fresh empty mock chain.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of events currently stored. Test-only diagnostic.
    pub fn event_count(&self) -> usize {
        self.lock_state().events.len()
    }

    /// **P10-4.** Toggle the disconnected state. When `true`, every
    /// adapter method returns `ChainError::Rpc("simulated offline")`
    /// without touching any internal state. Test-utilities-gated; the
    /// production binary cannot construct a disconnected mock (the
    /// whole `mock` module is gated, not just this method).
    pub fn set_disconnected(&self, disconnected: bool) {
        self.disconnected.store(disconnected, Ordering::SeqCst);
    }

    /// **P10-4.** Read the disconnected toggle. Test diagnostic only.
    #[must_use]
    pub fn is_disconnected(&self) -> bool {
        self.disconnected.load(Ordering::SeqCst)
    }

    /// Helper: short-circuit error for every adapter method when
    /// disconnected. Returning a fresh `ChainError::Rpc` each call
    /// (cannot be `const`) to match alloy's `TransportError` shape.
    fn offline_error() -> ChainError {
        ChainError::Rpc("simulated offline".into())
    }

    /// Lock the mutex; panic on poisoning. Tests don't need
    /// fault-tolerance against panicking publishers.
    fn lock_state(&self) -> std::sync::MutexGuard<'_, MockChainState> {
        self.state
            .lock()
            .expect("mock chain mutex poisoned (a test panicked while holding the lock)")
    }
}

#[async_trait]
impl ChainAdapter for MockChainAdapter {
    async fn publish(&self, signed: &SignedRevision) -> Result<ChainAnchor, ChainError> {
        // P10-4: short-circuit on disconnect BEFORE any state access
        // or signature verification. Matches the production behavior
        // of `BaseSepoliaAdapter::with_signer` failing the
        // `eth_chainId` precheck on a network outage.
        if self.is_disconnected() {
            return Err(Self::offline_error());
        }
        // P7 audit MED-4: verify the signature eagerly. v0 contract
        // doesn't, but the mock should match v1's planned behavior
        // (per MVP-2 issue 2.1) so any regression in
        // `build_signed_revision` that produces invalid signatures
        // surfaces at the first test that publishes through the
        // mock, rather than silently passing and hiding the bug
        // until v1 ships. See MED-4 for full rationale.
        verify_signed_revision(signed).map_err(|_| ChainError::SignatureInvalid)?;
        // The whole publish runs under one lock; the function ends
        // when the guard drops. Wrapped in a block so clippy's
        // `significant_drop_tightening` is satisfied — the guard's
        // last use is the final `state.events.push`.
        let anchor = {
            let mut state = self.lock_state();
            // Mirror v0 contract semantics: assign the current value
            // of `next_sequence`, then bump. The on-chain
            // RevisionLogV0 does exactly this with its
            // `_nextSequence++` post-increment.
            let sequence = state.next_sequence;
            state.next_sequence = state
                .next_sequence
                .checked_add(1)
                .ok_or(ChainError::Wallet(
                    "mock chain sequence counter overflowed (impossible in a finite test run)",
                ))?;
            state.next_block = state.next_block.checked_add(1).ok_or(ChainError::Wallet(
                "mock chain block counter overflowed (impossible in a finite test run)",
            ))?;
            let block_number = state.next_block;
            // Synthetic tx hash: low 8 bytes = sequence (big-endian),
            // rest = zero. Lets tests identify which event came from
            // which call by inspecting the tx_hash tail.
            let mut tx_hash = [0u8; 32];
            tx_hash[24..32].copy_from_slice(&sequence.to_be_bytes());
            let anchor = ChainAnchor {
                tx_hash,
                block_number,
                log_index: 0,
                sequence,
            };
            let event = RevisionEvent {
                vault_id: signed.vault_id,
                account_id: signed.account_id,
                parent_revision: signed.parent_revision,
                device_id: signed.device_id,
                schema_version: signed.schema_version,
                sequence,
                enc_payload: signed.enc_payload.clone(),
                anchor,
            };
            state.events.push(event);
            anchor
        };
        Ok(anchor)
    }

    async fn pull_since(
        &self,
        vault_id: &VaultId,
        from_block: u64,
        until_block: Option<u64>,
    ) -> Result<Vec<RevisionEvent>, ChainError> {
        // P10-4: short-circuit on disconnect.
        if self.is_disconnected() {
            return Err(Self::offline_error());
        }
        let upper = until_block.unwrap_or(u64::MAX);
        // Take a snapshot under the lock, then sort outside. Keeps
        // the critical section short (clippy's
        // `significant_drop_tightening` requires the guard to be
        // released before non-trivial work).
        let mut out: Vec<RevisionEvent> = {
            let state = self.lock_state();
            state
                .events
                .iter()
                .filter(|e| {
                    // Exclusive lower bound; inclusive upper.
                    e.anchor.block_number > from_block
                        && e.anchor.block_number <= upper
                        && &e.vault_id == vault_id
                })
                .cloned()
                .collect()
        };
        // Order by (block, log_index) ASC. The mock's submission
        // order is already in that order, but we re-sort to be robust
        // against a future change.
        out.sort_by_key(|e| (e.anchor.block_number, e.anchor.log_index));
        Ok(out)
    }

    async fn get_revision(
        &self,
        location: &EventLocation,
    ) -> Result<Option<RevisionEvent>, ChainError> {
        // P10-4: short-circuit on disconnect.
        if self.is_disconnected() {
            return Err(Self::offline_error());
        }
        let found = {
            let state = self.lock_state();
            state
                .events
                .iter()
                .find(|e| {
                    e.anchor.tx_hash == location.tx_hash && e.anchor.log_index == location.log_index
                })
                .cloned()
        };
        Ok(found)
    }

    async fn current_block(&self) -> Result<u64, ChainError> {
        // P10-4: short-circuit on disconnect.
        if self.is_disconnected() {
            return Err(Self::offline_error());
        }
        Ok(self.lock_state().next_block)
    }
}

#[cfg(test)]
mod tests {
    use super::MockChainAdapter;
    use crate::adapter::ChainAdapter;
    use crate::error::ChainError;
    use crate::types::{EventLocation, SignedRevision};
    use pangolin_crypto::keys::DeviceKey;

    use crate::signing::build_signed_revision;

    fn fresh_signed(payload: &[u8]) -> SignedRevision {
        fresh_signed_with_vault([0xAA; 32], payload)
    }

    /// Build a fresh signed revision with the requested `vault_id`.
    /// Tests that need to pin a specific vault must use this helper
    /// rather than `fresh_signed` + post-mutation, because P7 audit
    /// MED-4 added eager signature verification to
    /// `MockChainAdapter::publish`: post-signing tampering is a forged
    /// signature and is rejected.
    fn fresh_signed_with_vault(vault_id: [u8; 32], payload: &[u8]) -> SignedRevision {
        let device = DeviceKey::generate();
        build_signed_revision(
            &device,
            vault_id,
            [0xBB; 32],
            [0u8; 32],
            0,
            payload.to_vec(),
        )
    }

    /// Plan test: publish + `pull_since(0)` returns the revision.
    #[tokio::test]
    async fn publish_and_pull_round_trip() {
        let adapter = MockChainAdapter::new();
        let signed = fresh_signed(b"hello chain");
        let anchor = adapter.publish(&signed).await.expect("publish ok");
        assert_eq!(anchor.sequence, 0);
        let events = adapter
            .pull_since(&signed.vault_id, 0, None)
            .await
            .expect("pull ok");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].sequence, 0);
        assert_eq!(events[0].enc_payload, b"hello chain");
        assert_eq!(events[0].vault_id, signed.vault_id);
    }

    /// Plan test: two publishes assign distinct sequences.
    #[tokio::test]
    async fn sequence_advances_per_publish() {
        let adapter = MockChainAdapter::new();
        let s1 = fresh_signed(b"first");
        let s2 = fresh_signed(b"second");
        let a1 = adapter.publish(&s1).await.expect("publish s1");
        let a2 = adapter.publish(&s2).await.expect("publish s2");
        assert_eq!(a1.sequence, 0);
        assert_eq!(a2.sequence, 1);
        assert!(
            a2.block_number > a1.block_number,
            "blocks advance per publish"
        );
    }

    /// Plan test: pull filters by `vault_id`. Publish events for two
    /// distinct vaults; pull for one returns only its events.
    #[tokio::test]
    async fn pull_filters_by_vault_id() {
        let adapter = MockChainAdapter::new();
        let device = DeviceKey::generate();
        let v1 = build_signed_revision(
            &device,
            [0x11; 32],
            [0x01; 32],
            [0; 32],
            0,
            b"vault-a-r1".to_vec(),
        );
        let v2 = build_signed_revision(
            &device,
            [0x22; 32],
            [0x02; 32],
            [0; 32],
            0,
            b"vault-b-r1".to_vec(),
        );
        let v3 = build_signed_revision(
            &device,
            [0x11; 32],
            [0x01; 32],
            [0; 32],
            0,
            b"vault-a-r2".to_vec(),
        );
        adapter.publish(&v1).await.unwrap();
        adapter.publish(&v2).await.unwrap();
        adapter.publish(&v3).await.unwrap();

        let pull_a = adapter.pull_since(&[0x11; 32], 0, None).await.unwrap();
        let pull_b = adapter.pull_since(&[0x22; 32], 0, None).await.unwrap();
        assert_eq!(pull_a.len(), 2, "vault A has two events");
        assert_eq!(pull_b.len(), 1, "vault B has one event");
        assert_eq!(pull_a[0].enc_payload, b"vault-a-r1");
        assert_eq!(pull_a[1].enc_payload, b"vault-a-r2");
        assert_eq!(pull_b[0].enc_payload, b"vault-b-r1");
    }

    /// Plan test: pull excludes earlier blocks (exclusive lower
    /// bound). After three publishes (blocks 1..=3), pull from
    /// block 1 returns events at blocks 2 and 3.
    #[tokio::test]
    async fn pull_excludes_earlier_blocks() {
        let adapter = MockChainAdapter::new();
        for i in 0u8..3 {
            let s = fresh_signed_with_vault([0x77; 32], &[i]);
            adapter.publish(&s).await.unwrap();
        }
        let from_block_1 = adapter.pull_since(&[0x77; 32], 1, None).await.unwrap();
        // Three events were emitted at blocks 1, 2, 3.  from_block=1
        // is exclusive; expect 2 events (blocks 2 and 3).
        assert_eq!(from_block_1.len(), 2);
        assert!(
            from_block_1.iter().all(|e| e.anchor.block_number > 1),
            "all returned events must be strictly above from_block"
        );
    }

    /// Plan test: `get_revision` returns Some for known location,
    /// None for unknown.
    #[tokio::test]
    async fn get_revision_by_location() {
        let adapter = MockChainAdapter::new();
        let signed = fresh_signed(b"locate me");
        let anchor = adapter.publish(&signed).await.unwrap();
        let known = EventLocation {
            tx_hash: anchor.tx_hash,
            log_index: anchor.log_index,
        };
        let found = adapter.get_revision(&known).await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().enc_payload, b"locate me");

        let unknown = EventLocation {
            tx_hash: [0xFF; 32],
            log_index: 0,
        };
        let missing = adapter.get_revision(&unknown).await.unwrap();
        assert!(missing.is_none());
    }

    /// Plan test: `current_block` advances as publishes land.
    #[tokio::test]
    async fn current_block_advances_after_publishes() {
        let adapter = MockChainAdapter::new();
        let before = adapter.current_block().await.unwrap();
        assert_eq!(before, 0, "fresh mock chain reports block 0");
        for _ in 0..3 {
            let s = fresh_signed(b"x");
            adapter.publish(&s).await.unwrap();
        }
        let after = adapter.current_block().await.unwrap();
        assert_eq!(after, 3, "three publishes advance the block counter to 3");
    }

    /// Pull bounded by `until_block` is honored — events strictly
    /// above the bound are excluded.
    #[tokio::test]
    async fn pull_respects_until_block() {
        let adapter = MockChainAdapter::new();
        for _ in 0..5 {
            let s = fresh_signed_with_vault([0x99; 32], b"x");
            adapter.publish(&s).await.unwrap();
        }
        // 5 publishes => events at blocks 1..=5. Pull (0, Some(3)]
        // should return events at blocks 1, 2, 3.
        let bounded = adapter.pull_since(&[0x99; 32], 0, Some(3)).await.unwrap();
        assert_eq!(bounded.len(), 3);
        assert!(bounded.iter().all(|e| e.anchor.block_number <= 3));
    }

    /// Mock state is shared through `Clone` (via Arc<Mutex>) — two
    /// handles to the same mock chain see each other's events. This
    /// is what enables tests to pass the adapter to multiple
    /// consumers without rebuilding the chain.
    #[tokio::test]
    async fn cloned_handle_shares_state() {
        let a = MockChainAdapter::new();
        let b = a.clone();
        let signed = fresh_signed(b"shared");
        a.publish(&signed).await.unwrap();
        let from_b = b.pull_since(&signed.vault_id, 0, None).await.unwrap();
        assert_eq!(from_b.len(), 1, "b sees a's published event");
        assert_eq!(b.event_count(), 1);
    }

    /// P7 audit MED-4: a `SignedRevision` whose signature does not
    /// verify is rejected at publish time with
    /// `ChainError::SignatureInvalid`. We forge an invalid revision
    /// by tampering with the payload after signing — the embedded
    /// signature was made over the original payload's hash, so it
    /// won't verify under the new payload.
    #[tokio::test]
    async fn publish_rejects_invalid_signature() {
        let adapter = MockChainAdapter::new();
        let device = DeviceKey::generate();
        let mut signed = build_signed_revision(
            &device,
            [0xAA; 32],
            [0xBB; 32],
            [0u8; 32],
            0,
            b"original payload".to_vec(),
        );
        // Tamper post-signing — signature now binds the original
        // payload, but the revision claims a different one.
        signed.enc_payload = b"tampered payload".to_vec();
        let err = adapter
            .publish(&signed)
            .await
            .expect_err("tampered revision must be rejected");
        assert!(
            matches!(err, ChainError::SignatureInvalid),
            "expected ChainError::SignatureInvalid, got: {err:?}"
        );
        // And the chain log is unchanged — the failed publish did
        // NOT advance the sequence/block counters.
        assert_eq!(adapter.event_count(), 0);
    }

    /// Companion to `publish_rejects_invalid_signature`: substituting
    /// a different `device_id` (with the original device's signature
    /// still attached) is also a forgery and is rejected.
    #[tokio::test]
    async fn publish_rejects_substituted_device_id() {
        let adapter = MockChainAdapter::new();
        let device_a = DeviceKey::generate();
        let device_b = DeviceKey::generate();
        let mut signed = build_signed_revision(
            &device_a,
            [0xAA; 32],
            [0xBB; 32],
            [0u8; 32],
            0,
            b"payload".to_vec(),
        );
        // Swap the device_id to device_b's pubkey while keeping
        // device_a's signature — classic cross-device forgery
        // attempt.
        signed.device_id = device_b.verifying_key().to_bytes();
        let err = adapter
            .publish(&signed)
            .await
            .expect_err("substituted device_id must be rejected");
        assert!(
            matches!(err, ChainError::SignatureInvalid),
            "expected ChainError::SignatureInvalid, got: {err:?}"
        );
    }

    /// `event_count` matches what tests would otherwise infer from
    /// `pull_since(.., 0, None).len()`.
    #[tokio::test]
    async fn event_count_helper() {
        let adapter = MockChainAdapter::new();
        assert_eq!(adapter.event_count(), 0);
        let signed = fresh_signed(b"counted");
        adapter.publish(&signed).await.unwrap();
        assert_eq!(adapter.event_count(), 1);
    }

    // -----------------------------------------------------------------
    // P10-4: disconnect toggle tests
    // -----------------------------------------------------------------

    /// **P10-4 A6.** `set_disconnected(true)` makes `publish` return
    /// `ChainError::Rpc` regardless of the signed revision's validity.
    #[tokio::test]
    async fn disconnect_makes_publish_return_rpc_error() {
        let adapter = MockChainAdapter::new();
        adapter.set_disconnected(true);
        let signed = fresh_signed(b"disconnected");
        let err = adapter
            .publish(&signed)
            .await
            .expect_err("publish must fail while disconnected");
        match err {
            ChainError::Rpc(msg) => assert!(msg.contains("offline")),
            other => panic!("expected Rpc(simulated offline), got {other:?}"),
        }
        // The chain log is unchanged — disconnect short-circuited
        // before any state mutation.
        assert_eq!(adapter.event_count(), 0);
    }

    /// **P10-4 A6.** `set_disconnected(true)` makes `pull_since`
    /// return `ChainError::Rpc`.
    #[tokio::test]
    async fn disconnect_makes_pull_since_return_rpc_error() {
        let adapter = MockChainAdapter::new();
        adapter.set_disconnected(true);
        let err = adapter
            .pull_since(&[0u8; 32], 0, None)
            .await
            .expect_err("pull_since must fail while disconnected");
        assert!(matches!(err, ChainError::Rpc(_)));
    }

    /// **P10-4 A6.** `set_disconnected(true)` makes `get_revision`
    /// return `ChainError::Rpc`.
    #[tokio::test]
    async fn disconnect_makes_get_revision_return_rpc_error() {
        let adapter = MockChainAdapter::new();
        adapter.set_disconnected(true);
        let loc = EventLocation {
            tx_hash: [0u8; 32],
            log_index: 0,
        };
        let err = adapter
            .get_revision(&loc)
            .await
            .expect_err("get_revision must fail while disconnected");
        assert!(matches!(err, ChainError::Rpc(_)));
    }

    /// **P10-4 A6.** `set_disconnected(true)` makes `current_block`
    /// return `ChainError::Rpc`.
    #[tokio::test]
    async fn disconnect_makes_current_block_return_rpc_error() {
        let adapter = MockChainAdapter::new();
        adapter.set_disconnected(true);
        let err = adapter
            .current_block()
            .await
            .expect_err("current_block must fail while disconnected");
        assert!(matches!(err, ChainError::Rpc(_)));
    }

    /// **P10-4 A6.** The toggle is sticky — after
    /// `set_disconnected(true)`, the adapter remains disconnected
    /// across multiple calls, until `set_disconnected(false)` clears
    /// it.
    #[tokio::test]
    async fn disconnect_persists_until_reconnect() {
        let adapter = MockChainAdapter::new();
        adapter.set_disconnected(true);
        for _ in 0..3 {
            assert!(adapter.is_disconnected());
            assert!(adapter.current_block().await.is_err());
        }
        adapter.set_disconnected(false);
        assert!(!adapter.is_disconnected());
        assert!(adapter.current_block().await.is_ok());
    }

    /// **P10-4 A6.** Reconnecting (`set_disconnected(false)`) does
    /// NOT flush adapter state; events published before disconnect
    /// remain queryable after reconnect.
    #[tokio::test]
    async fn reconnect_after_disconnect_preserves_state() {
        let adapter = MockChainAdapter::new();
        let signed = fresh_signed(b"survives-disconnect");
        adapter.publish(&signed).await.unwrap();
        assert_eq!(adapter.event_count(), 1);
        adapter.set_disconnected(true);
        // pull fails while disconnected.
        assert!(adapter.pull_since(&signed.vault_id, 0, None).await.is_err());
        adapter.set_disconnected(false);
        let events = adapter.pull_since(&signed.vault_id, 0, None).await.unwrap();
        assert_eq!(events.len(), 1, "event survived the disconnect/reconnect");
        assert_eq!(events[0].enc_payload, b"survives-disconnect");
    }
}
