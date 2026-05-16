// SPDX-License-Identifier: AGPL-3.0-or-later
//! Reorg detection for the R-c two-stage rollback path.
//!
//! Maintains a small in-memory cache of `(block_number → block_hash)`
//! pairs observed at event-decode time. On every poll iteration the
//! orchestrator calls [`ReorgDetector::detect_reorg`] which queries
//! the canonical chain's block hash at each cached height and reports
//! mismatches; the orchestrator then calls
//! [`pangolin_store::Vault::rollback_pending_revisions_in_range`] for
//! the affected window.

use std::collections::BTreeMap;

use alloy::eips::BlockNumberOrTag;
use alloy::primitives::B256;
use alloy::providers::Provider;

use crate::error::ChainError;

/// Tracks observed `(block_number, block_hash)` pairs so a subsequent
/// canonical-chain query can detect a reorg that moved an event from
/// one block to another.
///
/// Bounded: the detector evicts entries older than
/// `CONFIRMATION_DEPTH_FOR_FINALIZATION * 2` blocks behind the
/// observation tip, since once a revision is `Finalized` (depth ≥ 12)
/// a reorg that flips its block hash would require a reorg longer
/// than 12 blocks, which is beyond the slow-mode 4.1 contract — and
/// even if it happens, the revision is `Finalized` and not subject to
/// rollback (R-c boundary). Future MVP-3 work can lift this bound if
/// stronger guarantees are needed.
#[derive(Debug, Clone, Default)]
pub struct ReorgDetector {
    /// Observed block_hash per block_number. BTreeMap so eviction can
    /// walk by ascending block number cheaply.
    observed: BTreeMap<u64, B256>,
    /// Highest block number ever observed; used by the eviction
    /// helper.
    tip: u64,
}

/// Report from [`ReorgDetector::detect_reorg`] — the affected block
/// window. The orchestrator passes `(affected_block_low,
/// affected_block_high)` to
/// `Vault::rollback_pending_revisions_in_range`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReorgInfo {
    /// Lowest block number whose observed hash diverged from canonical.
    pub affected_block_low: u64,
    /// Highest block number whose observed hash diverged from canonical
    /// (inclusive).
    pub affected_block_high: u64,
}

impl ReorgDetector {
    /// Record a `(block_number, block_hash)` observation. Called by
    /// the orchestrator after each successful event-decode.
    pub fn record(&mut self, block_number: u64, block_hash: B256) {
        self.observed.insert(block_number, block_hash);
        if block_number > self.tip {
            self.tip = block_number;
        }
        self.maybe_evict();
    }

    /// Query the canonical chain's block hash at each observed height
    /// and return a [`ReorgInfo`] describing the affected window if any
    /// hash diverged.
    ///
    /// Returns `Ok(None)` when every observed pair still matches
    /// canonical. Returns `Ok(Some(info))` with the contiguous-range
    /// shape (low = min divergent, high = max divergent) so the caller
    /// can issue a single `rollback_pending_revisions_in_range` op.
    ///
    /// # Errors
    ///
    /// Surfaces `ChainError::Rpc` if any `eth_getBlockByNumber`
    /// returns a transport error. Block-missing (RPC returns `null`
    /// for a number above its tip) is treated as a soft signal
    /// ("canonical chain has no block at that height yet — wait for
    /// it on next poll") and silently skipped.
    pub async fn detect_reorg<P: Provider>(
        &self,
        provider: &P,
    ) -> Result<Option<ReorgInfo>, ChainError> {
        let mut low: Option<u64> = None;
        let mut high: Option<u64> = None;

        for (&block_number, observed_hash) in &self.observed {
            let canonical = provider
                .get_block_by_number(BlockNumberOrTag::Number(block_number))
                .await
                .map_err(|e| {
                    ChainError::Rpc(format!("eth_getBlockByNumber({block_number}): {e}"))
                })?;
            let Some(block) = canonical else {
                // Block missing from the canonical chain at this
                // height — either the RPC is mid-reorg with the new
                // block not yet propagated, or our observed block was
                // re-orphaned and the chain is shorter than we
                // thought. Treat the latter as a reorg signal: the
                // observed block does not exist on canonical, so we
                // can't compare hashes; conservatively flag it as
                // affected so the orchestrator rolls back the pending
                // rows in that window.
                Self::extend_window(&mut low, &mut high, block_number);
                continue;
            };
            let canonical_hash = block.header.hash;
            if canonical_hash != *observed_hash {
                Self::extend_window(&mut low, &mut high, block_number);
            }
        }

        match (low, high) {
            (Some(l), Some(h)) => Ok(Some(ReorgInfo {
                affected_block_low: l,
                affected_block_high: h,
            })),
            _ => Ok(None),
        }
    }

    /// Drop observed entries for the affected window after the
    /// orchestrator has rolled back the corresponding pending rows.
    /// The next sync iteration will re-record them under the new
    /// canonical hashes.
    pub fn forget_window(&mut self, info: ReorgInfo) {
        let keys: Vec<u64> = self
            .observed
            .range(info.affected_block_low..=info.affected_block_high)
            .map(|(&k, _)| k)
            .collect();
        for k in keys {
            self.observed.remove(&k);
        }
    }

    /// Returns the current size of the observation cache. Diagnostic
    /// only.
    #[must_use]
    pub fn len(&self) -> usize {
        self.observed.len()
    }

    /// Returns true iff there are no observed entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.observed.is_empty()
    }

    /// Hash observed for the given block_number, if any. Useful for
    /// tests asserting the cache state.
    #[must_use]
    pub fn observed_at(&self, block_number: u64) -> Option<B256> {
        self.observed.get(&block_number).copied()
    }

    fn extend_window(low: &mut Option<u64>, high: &mut Option<u64>, block_number: u64) {
        match low {
            None => *low = Some(block_number),
            Some(existing) if block_number < *existing => *low = Some(block_number),
            _ => {}
        }
        match high {
            None => *high = Some(block_number),
            Some(existing) if block_number > *existing => *high = Some(block_number),
            _ => {}
        }
    }

    fn maybe_evict(&mut self) {
        // Keep at most a window of 2 * CONFIRMATION_DEPTH_FOR_FINALIZATION
        // blocks behind tip; everything older has either been finalized
        // (and is no longer subject to rollback) or is beyond the
        // realistic reorg horizon on Base Sepolia.
        let window = super::CONFIRMATION_DEPTH_FOR_FINALIZATION * 2;
        let evict_below = self.tip.saturating_sub(window);
        let keys: Vec<u64> = self
            .observed
            .range(..evict_below)
            .map(|(&k, _)| k)
            .collect();
        for k in keys {
            self.observed.remove(&k);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ReorgDetector;
    use alloy::primitives::B256;

    fn h(byte: u8) -> B256 {
        B256::from([byte; 32])
    }

    #[test]
    fn record_then_observed_at_returns_inserted() {
        let mut det = ReorgDetector::default();
        det.record(100, h(0xAA));
        assert_eq!(det.observed_at(100), Some(h(0xAA)));
        assert!(det.observed_at(101).is_none());
    }

    #[test]
    fn forget_window_removes_affected_range() {
        let mut det = ReorgDetector::default();
        det.record(100, h(1));
        det.record(101, h(2));
        det.record(102, h(3));
        det.forget_window(super::ReorgInfo {
            affected_block_low: 101,
            affected_block_high: 102,
        });
        assert!(det.observed_at(100).is_some());
        assert!(det.observed_at(101).is_none());
        assert!(det.observed_at(102).is_none());
    }

    #[test]
    fn eviction_drops_old_entries() {
        let mut det = ReorgDetector::default();
        // Window is 2 * 12 = 24 blocks. tip = 100, evict below 76.
        det.record(50, h(1));
        det.record(75, h(2));
        det.record(100, h(3));
        assert!(det.observed_at(50).is_none(), "old entry should be evicted");
        assert!(det.observed_at(75).is_none(), "edge entry evicted");
        assert!(det.observed_at(100).is_some(), "fresh entry kept");
    }
}
