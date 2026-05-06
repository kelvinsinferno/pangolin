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

use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use crate::adapter::ChainAdapter;
use crate::error::ChainError;
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
#[derive(Debug, Clone, Default)]
pub struct MockChainAdapter {
    state: Arc<Mutex<MockChainState>>,
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
        Ok(self.lock_state().next_block)
    }
}

#[cfg(test)]
mod tests {
    use super::MockChainAdapter;
    use crate::adapter::ChainAdapter;
    use crate::types::{EventLocation, SignedRevision};
    use pangolin_crypto::keys::DeviceKey;

    use crate::signing::build_signed_revision;

    fn fresh_signed(payload: &[u8]) -> SignedRevision {
        let device = DeviceKey::generate();
        build_signed_revision(
            &device,
            [0xAA; 32],
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
            let s = fresh_signed(&[i]);
            let mut s = s;
            s.vault_id = [0x77; 32]; // pin same vault so the pull sees them
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
            let mut s = fresh_signed(b"x");
            s.vault_id = [0x99; 32];
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
}
