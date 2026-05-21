// SPDX-License-Identifier: AGPL-3.0-or-later
//! Social-recovery client domain types (MVP-3 issue #103, chain-client
//! control plane).
//!
//! Per **R-where** / **Q3** (`docs/issue-plans/103-recovery-client.md`):
//! the on-chain control-plane mechanics (merkle building, EIP-712
//! `Approve` signing, the five lifecycle broadcasts) live in
//! `pangolin-chain` (alloy/chain territory). This module holds only the
//! PURE, no-secret, no-chain domain types that mirror the contract's
//! state model — a thin vocabulary the FFI / UX layers can name without
//! pulling alloy into `pangolin-core`. NO `uniffi` (Q3). NO secret
//! material. NO network. NO VDK / escrow (Workstream B / #103-B,
//! deferred).
//!
//! The substantive Option-2 threshold-VDK-recovery crypto (the
//! cryptographic heart) is Workstream B / #104a (the
//! `pangolin_crypto::escrow` primitive). The PURE orchestration that
//! sequences that primitive into the onboarding + recovery flows lives in
//! the [`orchestration`] submodule (#104b); revocation-on-read is #103-C.

pub mod orchestration;

pub use orchestration::{
    onboard_guardian_escrow, recover_vdk_from_shares, GuardianAssignment, OnboardingArtifacts,
    RecoveryArtifacts, RecoveryEpoch, RecoveryOrchestrationError,
};

/// Lifecycle status of a vault's recovery slot, mirroring
/// `RecoveryV1.sol`'s `Status` enum (`uint8`-backed, same ordinals).
///
/// Pure mirror: the `u8` repr matches the contract so a client decoding
/// the `recovery(vaultId).status` view can map it 1:1 via
/// [`RecoveryStatus::from_u8`]. The width is future-proofed (a v2 may
/// add statuses) per the contract's L7.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RecoveryStatus {
    /// No recovery has ever been initiated for this attempt slot (the
    /// zero value).
    None = 0,
    /// A recovery attempt is in flight; guardians may approve, the
    /// authority may cancel, finalize is gated on threshold + delay.
    Pending = 1,
    /// The attempt rotated `vaultAuthority` (terminal for the attempt).
    Finalized = 2,
    /// The authority aborted the attempt (terminal for the attempt).
    Canceled = 3,
}

impl RecoveryStatus {
    /// Map the contract's `uint8` status ordinal to a [`RecoveryStatus`].
    /// Returns `None` for an unknown future ordinal (a v2 status the
    /// client does not understand) so callers can fail closed rather
    /// than mis-interpret.
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::None),
            1 => Some(Self::Pending),
            2 => Some(Self::Finalized),
            3 => Some(Self::Canceled),
            _ => None,
        }
    }

    /// The `uint8` ordinal the contract uses for this status.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// `true` when an attempt is in flight (guardians may approve).
    #[must_use]
    pub const fn is_pending(self) -> bool {
        matches!(self, Self::Pending)
    }

    /// `true` when the attempt reached a terminal state (finalized or
    /// canceled).
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Finalized | Self::Canceled)
    }
}

/// The contract's pinned bounds on a guardian set + the mandatory
/// observation delay (`RecoveryV1.sol` constants).
///
/// Mirrored here so the client / UX can validate a proposed guardian
/// set BEFORE constructing a doomed `setGuardianSet` tx (the contract
/// enforces the same bounds and reverts otherwise).
pub mod bounds {
    /// Mandatory recovery observation delay, in seconds (72 hours;
    /// `RecoveryV1.sol:296` `MIN_DELAY`). Fixed, not configurable in v1.
    pub const MIN_DELAY_SECS: u64 = 72 * 60 * 60;

    /// Threshold lower bound (`MIN_THRESHOLD`): no 1-of-N / 0-of-N vault.
    pub const MIN_THRESHOLD: u8 = 2;
    /// Threshold upper bound (`MAX_THRESHOLD`).
    pub const MAX_THRESHOLD: u8 = 9;
    /// Guardian-count lower bound (`MIN_GUARDIANS`).
    pub const MIN_GUARDIANS: u8 = 3;
    /// Guardian-count upper bound (`MAX_GUARDIANS`).
    pub const MAX_GUARDIANS: u8 = 15;
}

/// A proposed guardian-set configuration the client validates before
/// committing on chain. Pure data — no addresses, no secrets, no chain
/// handle (the merkle root + the broadcast live in `pangolin-chain`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuardianSetConfig {
    /// N-of-M approval threshold.
    pub threshold: u8,
    /// M — the guardian-set size.
    pub guardian_count: u8,
}

/// Why a [`GuardianSetConfig`] is invalid (mirrors the contract's
/// `setGuardianSet` revert conditions — `RecoveryV1.sol:467-475`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardianSetError {
    /// `guardian_count` outside `[MIN_GUARDIANS, MAX_GUARDIANS]`.
    GuardianCountOutOfBounds,
    /// `threshold` outside `[MIN_THRESHOLD, MAX_THRESHOLD]`, or
    /// `threshold > guardian_count`.
    ThresholdOutOfBounds,
}

impl GuardianSetConfig {
    /// Validate against the contract's bounds. Returns `Ok(())` iff the
    /// contract's `setGuardianSet` would accept this `(threshold,
    /// guardian_count)` pair — a pure pre-flight that lets the UX reject
    /// a bad config without a round-trip.
    ///
    /// # Errors
    ///
    /// [`GuardianSetError`] matching the contract's revert condition.
    pub const fn validate(self) -> Result<(), GuardianSetError> {
        if self.guardian_count < bounds::MIN_GUARDIANS
            || self.guardian_count > bounds::MAX_GUARDIANS
        {
            return Err(GuardianSetError::GuardianCountOutOfBounds);
        }
        if self.threshold < bounds::MIN_THRESHOLD
            || self.threshold > bounds::MAX_THRESHOLD
            || self.threshold > self.guardian_count
        {
            return Err(GuardianSetError::ThresholdOutOfBounds);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_round_trips_u8() {
        for v in 0u8..=3 {
            let s = RecoveryStatus::from_u8(v).expect("known ordinal");
            assert_eq!(s.as_u8(), v);
        }
        assert_eq!(RecoveryStatus::from_u8(4), None);
        assert_eq!(RecoveryStatus::from_u8(255), None);
    }

    #[test]
    fn status_predicates() {
        assert!(RecoveryStatus::Pending.is_pending());
        assert!(!RecoveryStatus::None.is_pending());
        assert!(RecoveryStatus::Finalized.is_terminal());
        assert!(RecoveryStatus::Canceled.is_terminal());
        assert!(!RecoveryStatus::Pending.is_terminal());
    }

    #[test]
    fn min_delay_is_72_hours() {
        assert_eq!(bounds::MIN_DELAY_SECS, 259_200);
    }

    #[test]
    fn guardian_set_config_validation_mirrors_contract_bounds() {
        // Valid: 2-of-3.
        assert!(GuardianSetConfig {
            threshold: 2,
            guardian_count: 3
        }
        .validate()
        .is_ok());
        // 1-of-N rejected (below MIN_THRESHOLD).
        assert_eq!(
            GuardianSetConfig {
                threshold: 1,
                guardian_count: 3
            }
            .validate(),
            Err(GuardianSetError::ThresholdOutOfBounds)
        );
        // count below MIN_GUARDIANS.
        assert_eq!(
            GuardianSetConfig {
                threshold: 2,
                guardian_count: 2
            }
            .validate(),
            Err(GuardianSetError::GuardianCountOutOfBounds)
        );
        // threshold > count.
        assert_eq!(
            GuardianSetConfig {
                threshold: 5,
                guardian_count: 4
            }
            .validate(),
            Err(GuardianSetError::ThresholdOutOfBounds)
        );
        // count above MAX_GUARDIANS.
        assert_eq!(
            GuardianSetConfig {
                threshold: 2,
                guardian_count: 16
            }
            .validate(),
            Err(GuardianSetError::GuardianCountOutOfBounds)
        );
    }
}
