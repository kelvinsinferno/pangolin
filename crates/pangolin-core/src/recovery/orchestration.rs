// SPDX-License-Identifier: AGPL-3.0-or-later
//! Pure Option-2 social-recovery orchestration (#104b).
//!
//! This module sequences the merged #104a [`pangolin_crypto::escrow`]
//! primitive into the two end-to-end flows — **onboarding** (generate an
//! RWK, second-wrap the VDK, threshold-split, seal a share to each
//! guardian) and **recovery** (reconstruct the RWK from `>= t` opened
//! shares, unwrap the byte-identical VDK, then re-split for forward
//! security). It is the glue between the #104a crypto core and the #103
//! on-chain control plane.
//!
//! ## Purity discipline (L1 — LOAD-BEARING)
//!
//! - **No chain.** The on-chain merkle root + the five lifecycle
//!   broadcasts live in `pangolin-chain`; the caller (CLI / host app)
//!   drives them. These drivers take the *resolved* guardian set as
//!   input and emit the *inputs* the caller pushes on-chain (the guardian
//!   identities the merkle root commits) — exactly as #103 keeps the
//!   broadcasts in `pangolin-chain`.
//! - **No `uniffi`.** Deferred to 6.x (plan Q-i).
//! - **No `serde` on secret-bearing types.** The orchestration
//!   structs carry only public context (epoch, t/M, `vault_id`, guardian
//!   X25519 pubkeys) plus the escrow's own opaque secret-discipline types
//!   ([`WrappedVdkRecovery`], [`SealedShare`], [`Share`]) — none of which
//!   derive `serde`. The persistence encoding lives in `pangolin-store`.
//! - **No re-implemented crypto.** Every secret operation delegates to a
//!   #104a `escrow` fn; this module never touches a field element, a
//!   nonce, or an AEAD directly.
//!
//! ## The two-key guardian join (L2)
//!
//! A guardian is one identity with two derived public keys: an X25519
//! share-opener ([`pangolin_crypto::guardian::derive_x25519_sealing_key`])
//! and a secp256k1 Approve-signer (`pangolin_chain::evm::derive_evm_wallet`).
//! Onboarding seals share `i` to guardian `i`'s X25519 pubkey AND records
//! guardian `i`'s position so the caller can commit the SAME guardians'
//! secp256k1 addresses in the merkle root. The
//! [`GuardianAssignment::index`] field is the ordering contract that ties
//! the sealed set to the merkle-committed set.

use pangolin_crypto::escrow::{
    reconstruct_rwk, seal_share, split_rwk, unwrap_vdk_under_rwk, wrap_vdk_under_rwk, EscrowError,
    RecoveryWrapKey, SealedShare, Share, WrappedVdkRecovery, EPOCH_LEN, X25519_KEY_LEN,
};
use pangolin_crypto::keys::{VdkKey, WrapContext, VAULT_ID_LEN};

use super::{GuardianSetConfig, GuardianSetError};

/// Errors from the pure recovery orchestration drivers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryOrchestrationError {
    /// The `(threshold, guardian_count)` pair is outside the on-chain
    /// bounds (mirrors [`GuardianSetError`] / the contract's
    /// `setGuardianSet` reverts). The escrow split would also reject it.
    InvalidGuardianSet(GuardianSetError),
    /// The number of supplied guardian X25519 pubkeys did not equal
    /// `guardian_count` (`M`). Onboarding seals exactly one share per
    /// guardian, so the pubkey count is load-bearing (L2).
    GuardianCountMismatch {
        /// The `guardian_count` (`M`) the config declares.
        expected: u8,
        /// The number of pubkeys actually supplied.
        got: usize,
    },
    /// Fewer than `threshold` opened shares were supplied to recovery, so
    /// reconstruction can never reach the quorum.
    InsufficientShares {
        /// The reconstruction threshold (`t`).
        threshold: u8,
        /// The number of opened shares actually supplied.
        got: usize,
    },
    /// A delegated #104a escrow operation failed (split / seal /
    /// reconstruct / wrap-unwrap). Carries the underlying typed cause.
    Escrow(EscrowError),
}

impl core::fmt::Display for RecoveryOrchestrationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidGuardianSet(e) => write!(f, "invalid guardian set: {e:?}"),
            Self::GuardianCountMismatch { expected, got } => write!(
                f,
                "guardian pubkey count {got} != declared guardian_count {expected}"
            ),
            Self::InsufficientShares { threshold, got } => write!(
                f,
                "{got} opened shares supplied but threshold is {threshold}"
            ),
            Self::Escrow(e) => write!(f, "escrow operation failed: {e}"),
        }
    }
}

impl std::error::Error for RecoveryOrchestrationError {}

impl From<EscrowError> for RecoveryOrchestrationError {
    fn from(e: EscrowError) -> Self {
        Self::Escrow(e)
    }
}

/// A monotonic recovery epoch (GAP FLAG 2 / L7).
///
/// The epoch tags share *generations*: it advances on every onboarding +
/// every recovery re-split, and is bound into each [`SealedShare`]'s
/// authenticated header so a share from epoch `n` is rejected when
/// presented for epoch `n+1` (forward-security domain separation). It is
/// **independent** of the on-chain `attemptNonce` (plan Q-f): a
/// cancelled on-chain attempt does NOT bump the epoch.
///
/// The 16-byte [`pangolin_crypto::escrow::EPOCH_LEN`] form is the
/// big-endian encoding of a `u64` counter in its low 8 bytes (the high 8
/// bytes are reserved zero). `pangolin-store` owns the persisted counter;
/// this type is the pure value the drivers thread through the escrow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RecoveryEpoch(pub u64);

impl RecoveryEpoch {
    /// The genesis epoch written at first onboarding.
    pub const GENESIS: Self = Self(0);

    /// The next epoch (used by the recovery re-split). Saturates at
    /// `u64::MAX` — at one recovery per second that ceiling is ~585
    /// billion years away, so saturation is purely a totality guard.
    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }

    /// Encode into the 16-byte escrow epoch form: 8 reserved zero bytes
    /// followed by the big-endian `u64` counter.
    #[must_use]
    pub fn to_escrow_bytes(self) -> [u8; EPOCH_LEN] {
        let mut out = [0u8; EPOCH_LEN];
        out[8..].copy_from_slice(&self.0.to_be_bytes());
        out
    }

    /// Decode from the 16-byte escrow epoch form (the inverse of
    /// [`Self::to_escrow_bytes`]). The high 8 bytes are ignored (reserved).
    #[must_use]
    pub fn from_escrow_bytes(bytes: &[u8; EPOCH_LEN]) -> Self {
        let mut low = [0u8; 8];
        low.copy_from_slice(&bytes[8..]);
        Self(u64::from_be_bytes(low))
    }
}

/// One guardian's sealed share + the join metadata tying it to the
/// on-chain merkle-committed identity (L2).
///
/// `index` is the guardian's position in the onboarding set: the caller
/// MUST commit the secp256k1 address of the guardian at the same `index`
/// (whose X25519 pubkey is [`Self::guardian_x25519_pub`]) into the merkle
/// root. A mismatch silently strands recovery (the wrong quorum gates
/// rotation, or the opened shares don't match the committed guardians).
#[derive(Debug)]
pub struct GuardianAssignment {
    /// The guardian's ordinal position in the set (`0..M`). The same
    /// ordinal selects the guardian's secp256k1 merkle-committed address.
    pub index: u8,
    /// The guardian's 32-byte X25519 public key the share was sealed to.
    pub guardian_x25519_pub: [u8; X25519_KEY_LEN],
    /// The sealed share for this guardian (non-secret — encrypted to the
    /// guardian's X25519 key + bound to `vault_id` + `epoch`).
    pub sealed_share: SealedShare,
}

/// The full output of [`onboard_guardian_escrow`] — everything the caller
/// persists (via `pangolin-store`) and pushes on-chain (via
/// `pangolin-chain`).
///
/// Carries no live RWK or plaintext share: the RWK and the `Share`s are
/// consumed inside the driver and dropped (zeroized) before this returns.
#[derive(Debug)]
pub struct OnboardingArtifacts {
    /// The VDK wrapped under the (now-dropped) RWK — the recovery-path
    /// peer of the daily password-`WrappedVdk`. Persisted as a non-secret
    /// BLOB (L9).
    pub wrapped_recovery: WrappedVdkRecovery,
    /// The guardian set parameters (`t`, `M`) — equal to the on-chain
    /// `threshold` / `guardianCount` (L2).
    pub config: GuardianSetConfig,
    /// The recovery epoch this generation of shares is tagged with (L7).
    pub epoch: RecoveryEpoch,
    /// Per-guardian sealed shares + their join metadata, ordered by
    /// `index` (`0..M`). Exactly `M` entries.
    pub assignments: Vec<GuardianAssignment>,
}

/// The full output of [`recover_vdk_from_shares`] — the recovered VDK
/// plus the forward-security re-split (L6).
///
/// The recovered `vdk` is byte-identical to the original (L3); the caller
/// re-wraps the daily `WrappedVdk` under the new password authority and
/// persists `re_split` as the new recovery-escrow state, then bumps the
/// stored epoch to `re_split.epoch`.
#[derive(Debug)]
pub struct RecoveryArtifacts {
    /// The recovered VDK — `ct_eq`s the original bit-for-bit (L3). NOT
    /// re-derived; unwrapped from the recovery wrapper under the
    /// reconstructed RWK.
    pub vdk: VdkKey,
    /// The forward-security re-split: a FRESH RWK', a FRESH
    /// `WrappedVdkRecovery` under RWK', fresh sealed shares to ALL `M`
    /// guardians, and a bumped epoch. The old shares + old RWK are dead
    /// (L6). Always present — re-split is mandatory on every successful
    /// recovery (plan Q-c).
    pub re_split: OnboardingArtifacts,
}

/// Drive the **onboarding** flow (plan §3): generate a fresh RWK,
/// second-wrap the VDK under it, threshold-split the RWK into `M` shares,
/// and seal share `i` to guardian `i`'s X25519 pubkey.
///
/// `guardian_x25519_pubs` must contain exactly `config.guardian_count`
/// (`M`) pubkeys, ordered so that index `i` is the guardian whose
/// secp256k1 address the caller will commit at merkle position `i` (L2).
/// `epoch` tags this share generation (L7).
///
/// The RWK and the plaintext `Share`s are consumed inside the driver and
/// dropped (zeroized via the escrow types' `!Clone` zeroizing discipline)
/// before this returns — only the sealed, non-secret artifacts escape.
///
/// # Errors
///
/// - [`RecoveryOrchestrationError::InvalidGuardianSet`] if `(t, M)` is out
///   of the on-chain bounds.
/// - [`RecoveryOrchestrationError::GuardianCountMismatch`] if the pubkey
///   count != `M`.
/// - [`RecoveryOrchestrationError::Escrow`] if a delegated split / seal /
///   wrap fails.
pub fn onboard_guardian_escrow(
    vdk: &VdkKey,
    vault_id: &[u8; VAULT_ID_LEN],
    config: GuardianSetConfig,
    guardian_x25519_pubs: &[[u8; X25519_KEY_LEN]],
    epoch: RecoveryEpoch,
) -> Result<OnboardingArtifacts, RecoveryOrchestrationError> {
    config
        .validate()
        .map_err(RecoveryOrchestrationError::InvalidGuardianSet)?;
    if guardian_x25519_pubs.len() != usize::from(config.guardian_count) {
        return Err(RecoveryOrchestrationError::GuardianCountMismatch {
            expected: config.guardian_count,
            got: guardian_x25519_pubs.len(),
        });
    }

    // 1. Fresh RWK; 2. second-wrap the VDK under it (the same WrapContext
    //    the daily wrap uses — vault binding). Delegated entirely to the
    //    audited escrow primitive.
    let rwk = RecoveryWrapKey::generate();
    let ctx = WrapContext::new(*vault_id);
    let wrapped_recovery = wrap_vdk_under_rwk(vdk, &rwk, &ctx)?;

    // 3. Threshold-split. t/M are revalidated inside split_rwk against the
    //    same on-chain bounds (L2 belt-and-suspenders).
    let shares = split_rwk(&rwk, config.threshold, config.guardian_count)?;
    // The RWK is no longer needed; drop it now so it zeroizes before any
    // sealing work (the wrapper + shares are all we keep).
    drop(rwk);

    // 4. Seal share i -> guardian i. Record the join metadata (index +
    //    pubkey) so the caller commits the matching secp256k1 guardian at
    //    merkle position i (L2). The plaintext `Share`s drop at end of the
    //    map's iteration scope (zeroizing).
    let epoch_bytes = epoch.to_escrow_bytes();
    let mut assignments = Vec::with_capacity(shares.len());
    for (i, (share, pubkey)) in shares.iter().zip(guardian_x25519_pubs).enumerate() {
        let sealed = seal_share(share, pubkey, vault_id, &epoch_bytes)?;
        assignments.push(GuardianAssignment {
            // `i < M <= MAX_GUARDIANS (15)`, always fits u8.
            index: u8::try_from(i).expect("guardian index <= 15 fits u8"),
            guardian_x25519_pub: *pubkey,
            sealed_share: sealed,
        });
    }
    // `shares` (the plaintext Shares) drop here, zeroizing.
    drop(shares);

    Ok(OnboardingArtifacts {
        wrapped_recovery,
        config,
        epoch,
        assignments,
    })
}

/// Drive the **recovery** flow (plan §3).
///
/// Reconstruct the RWK from `>= t` opened shares, unwrap the
/// byte-identical VDK, then perform the mandatory forward-security
/// re-split (L6) producing a FRESH RWK', a FRESH `WrappedVdkRecovery`,
/// fresh sealed shares to ALL `M` guardians, and a bumped epoch.
///
/// `opened_shares` are the raw [`Share`]s each guardian released after
/// opening their own sealed share (plan Q-a custody). At least
/// `config.threshold` distinct shares are required.
///
/// `guardian_x25519_pubs` are the `M` guardians' X25519 pubkeys for the
/// re-seal — the SAME guardian set (R-e immutable in v1), supplied by the
/// caller (recovered guardian-set backup + participating guardians'
/// pubkeys; plan Q-c build sub-detail). `current_epoch` is the epoch the
/// recovered shares belong to; the re-split is tagged `current_epoch.next()`.
///
/// L3: the recovered VDK is unwrapped (never re-derived); `VdkKey::generate`
/// is never on this path. L6: the re-split regenerates a FRESH
/// `WrappedVdkRecovery` under RWK' — the old wrapper is never reused
/// (GAP FLAG 3).
///
/// # Caller persistence ordering (L6 at-rest)
///
/// The returned `re_split` artifacts and the new-password re-wrap of the
/// daily `WrappedVdk` MUST be persisted together: write the re-split escrow
/// (`write_recovery_escrow`, which REPLACEs the prior generation) before — or
/// in the same transaction as — the password rotation. A crash *between* the
/// two leaves a re-keyed daily wrap alongside stale escrow rows whose OLD
/// shares still reconstruct the OLD RWK, defeating forward security until the
/// next successful re-split. The pure driver cannot enforce this (it spans two
/// crates); it is the recovery caller's contract.
///
/// # Errors
///
/// - [`RecoveryOrchestrationError::InsufficientShares`] if fewer than
///   `threshold` shares were supplied.
/// - [`RecoveryOrchestrationError::InvalidGuardianSet`] /
///   [`RecoveryOrchestrationError::GuardianCountMismatch`] from the
///   re-split's onboarding call.
/// - [`RecoveryOrchestrationError::Escrow`] if reconstruction / unwrap /
///   the re-split fails (e.g. `< t` real shares, wrong shares, tampered
///   wrapper).
pub fn recover_vdk_from_shares(
    wrapped_recovery: &WrappedVdkRecovery,
    opened_shares: Vec<Share>,
    vault_id: &[u8; VAULT_ID_LEN],
    config: GuardianSetConfig,
    guardian_x25519_pubs: &[[u8; X25519_KEY_LEN]],
    current_epoch: RecoveryEpoch,
) -> Result<RecoveryArtifacts, RecoveryOrchestrationError> {
    // Pre-flight the threshold so a too-small set fails with a precise
    // typed error rather than the undifferentiated escrow ReconstructFailed.
    if opened_shares.len() < usize::from(config.threshold) {
        return Err(RecoveryOrchestrationError::InsufficientShares {
            threshold: config.threshold,
            got: opened_shares.len(),
        });
    }

    // 1. Reconstruct the RWK from the opened shares (delegated). 2. Unwrap
    //    the byte-identical VDK (L3 — re-wrapped never re-derived; the
    //    wrapper carries its own bound context).
    let rwk = reconstruct_rwk(&opened_shares)?;
    // The opened shares are spent; drop them so they zeroize before the
    // re-split mints a fresh generation.
    drop(opened_shares);
    let vdk = unwrap_vdk_under_rwk(wrapped_recovery, &rwk)?;
    // The reconstructed RWK is dead post-recovery (forward security); drop
    // it before re-splitting under a fresh RWK'.
    drop(rwk);

    // 3. Forward-security re-split (L6, mandatory, AUTOMATIC). Reuse the
    //    onboarding driver against the recovered VDK with a bumped epoch:
    //    it generates RWK', a FRESH WrappedVdkRecovery under RWK' (GAP
    //    FLAG 3 — never reuse the old wrapper), and fresh sealed shares to
    //    ALL M guardians.
    let re_split = onboard_guardian_escrow(
        &vdk,
        vault_id,
        config,
        guardian_x25519_pubs,
        current_epoch.next(),
    )?;

    Ok(RecoveryArtifacts { vdk, re_split })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pangolin_crypto::guardian::derive_x25519_sealing_key;
    use pangolin_crypto::keys::DeviceKey;

    const VAULT_A: [u8; VAULT_ID_LEN] = [0xAA; VAULT_ID_LEN];

    /// Build `M` guardian keypairs from deterministic seeds; return their
    /// X25519 secret-scalar (for opening) + public (for sealing) bytes.
    fn guardians(m: u8) -> Vec<([u8; X25519_KEY_LEN], [u8; X25519_KEY_LEN])> {
        (0..m)
            .map(|i| {
                let dev = DeviceKey::from_seed([0xC0 + i; 32]);
                let k = derive_x25519_sealing_key(&dev);
                (*k.secret_bytes(), *k.public_bytes())
            })
            .collect()
    }

    fn pubs(gs: &[([u8; X25519_KEY_LEN], [u8; X25519_KEY_LEN])]) -> Vec<[u8; X25519_KEY_LEN]> {
        gs.iter().map(|(_, p)| *p).collect()
    }

    #[test]
    fn epoch_encoding_round_trips() {
        for e in [0u64, 1, 42, u64::MAX] {
            let ep = RecoveryEpoch(e);
            assert_eq!(RecoveryEpoch::from_escrow_bytes(&ep.to_escrow_bytes()), ep);
        }
        // The encoding lives in the low 8 bytes; high 8 are reserved zero.
        let bytes = RecoveryEpoch(1).to_escrow_bytes();
        assert_eq!(&bytes[..8], &[0u8; 8]);
        assert_eq!(bytes[15], 1);
        // next() advances and saturates.
        assert_eq!(RecoveryEpoch(5).next(), RecoveryEpoch(6));
        assert_eq!(RecoveryEpoch(u64::MAX).next(), RecoveryEpoch(u64::MAX));
    }

    /// Onboard → open ≥t shares → recover → byte-identical VDK (L3), and
    /// the re-split is a fresh generation at epoch+1 (L6).
    #[test]
    fn onboard_then_recover_round_trip() {
        let vdk = VdkKey::generate();
        let config = GuardianSetConfig {
            threshold: 3,
            guardian_count: 5,
        };
        let gs = guardians(5);
        let gpubs = pubs(&gs);

        let onboarding =
            onboard_guardian_escrow(&vdk, &VAULT_A, config, &gpubs, RecoveryEpoch::GENESIS)
                .unwrap();
        assert_eq!(onboarding.assignments.len(), 5);
        assert_eq!(onboarding.epoch, RecoveryEpoch::GENESIS);
        // Each assignment's index + pubkey track the input order (L2).
        for (i, a) in onboarding.assignments.iter().enumerate() {
            assert_eq!(usize::from(a.index), i);
            assert_eq!(a.guardian_x25519_pub, gpubs[i]);
        }

        // Guardians 0,2,4 open their own shares (Q-a custody).
        let epoch_bytes = onboarding.epoch.to_escrow_bytes();
        let opened: Vec<Share> = [0usize, 2, 4]
            .iter()
            .map(|&i| {
                pangolin_crypto::escrow::open_sealed_share(
                    &onboarding.assignments[i].sealed_share,
                    &gs[i].0,
                    &VAULT_A,
                    &epoch_bytes,
                )
                .unwrap()
            })
            .collect();

        let recovered = recover_vdk_from_shares(
            &onboarding.wrapped_recovery,
            opened,
            &VAULT_A,
            config,
            &gpubs,
            onboarding.epoch,
        )
        .unwrap();
        assert!(
            bool::from(vdk.ct_eq(&recovered.vdk)),
            "recovered VDK must be byte-identical (L3)"
        );
        // L6: the re-split is a fresh generation at epoch+1, M fresh shares.
        assert_eq!(recovered.re_split.epoch, RecoveryEpoch(1));
        assert_eq!(recovered.re_split.assignments.len(), 5);
    }

    /// L6 forward security: the OLD shares cannot recover the
    /// POST-recovery vault (the re-split wrapper is under a fresh RWK').
    #[test]
    fn old_shares_cannot_recover_post_recovery_vault() {
        let vdk = VdkKey::generate();
        let config = GuardianSetConfig {
            threshold: 2,
            guardian_count: 3,
        };
        let gs = guardians(3);
        let gpubs = pubs(&gs);
        let onboarding =
            onboard_guardian_escrow(&vdk, &VAULT_A, config, &gpubs, RecoveryEpoch::GENESIS)
                .unwrap();

        let e0 = onboarding.epoch.to_escrow_bytes();
        let open = |i: usize| {
            pangolin_crypto::escrow::open_sealed_share(
                &onboarding.assignments[i].sealed_share,
                &gs[i].0,
                &VAULT_A,
                &e0,
            )
            .unwrap()
        };
        let recovered = recover_vdk_from_shares(
            &onboarding.wrapped_recovery,
            vec![open(0), open(1)],
            &VAULT_A,
            config,
            &gpubs,
            onboarding.epoch,
        )
        .unwrap();

        // Open the OLD epoch-0 shares again, and try them against the
        // NEW (post-recovery) wrapper. The new wrapper is under RWK', so
        // the OLD shares reconstruct the OLD (dead) RWK — unwrap fails.
        let stale = vec![open(0), open(1)];
        let rwk_old = reconstruct_rwk(&stale).unwrap();
        let attempt = unwrap_vdk_under_rwk(&recovered.re_split.wrapped_recovery, &rwk_old);
        assert_eq!(
            attempt.unwrap_err(),
            EscrowError::WrapFailed,
            "old shares must NOT recover the post-recovery vault (L6)"
        );

        // And the NEW shares DO recover it (re-split is functional).
        let e1 = recovered.re_split.epoch.to_escrow_bytes();
        let open_new = |i: usize| {
            pangolin_crypto::escrow::open_sealed_share(
                &recovered.re_split.assignments[i].sealed_share,
                &gs[i].0,
                &VAULT_A,
                &e1,
            )
            .unwrap()
        };
        let re_recovered = recover_vdk_from_shares(
            &recovered.re_split.wrapped_recovery,
            vec![open_new(0), open_new(1)],
            &VAULT_A,
            config,
            &gpubs,
            recovered.re_split.epoch,
        )
        .unwrap();
        assert!(bool::from(vdk.ct_eq(&re_recovered.vdk)));
    }

    /// L7 epoch domain separation: an epoch-n sealed share is rejected
    /// when opened for epoch n+1 (the escrow header check).
    #[test]
    fn epoch_mismatch_share_rejected() {
        let vdk = VdkKey::generate();
        let config = GuardianSetConfig {
            threshold: 2,
            guardian_count: 3,
        };
        let gs = guardians(3);
        let gpubs = pubs(&gs);
        let onboarding =
            onboard_guardian_escrow(&vdk, &VAULT_A, config, &gpubs, RecoveryEpoch(7)).unwrap();
        // Open with the WRONG epoch (8 instead of 7).
        let wrong_epoch = RecoveryEpoch(8).to_escrow_bytes();
        let res = pangolin_crypto::escrow::open_sealed_share(
            &onboarding.assignments[0].sealed_share,
            &gs[0].0,
            &VAULT_A,
            &wrong_epoch,
        );
        assert_eq!(res.unwrap_err(), EscrowError::OpenFailed);
    }

    /// Threshold guard: out-of-bounds (t,M) is rejected with a typed
    /// error before any crypto runs.
    #[test]
    fn invalid_guardian_set_rejected() {
        let vdk = VdkKey::generate();
        // t=1 below MIN_THRESHOLD.
        let bad = GuardianSetConfig {
            threshold: 1,
            guardian_count: 3,
        };
        let gs = guardians(3);
        let err = onboard_guardian_escrow(&vdk, &VAULT_A, bad, &pubs(&gs), RecoveryEpoch::GENESIS)
            .unwrap_err();
        assert!(matches!(
            err,
            RecoveryOrchestrationError::InvalidGuardianSet(_)
        ));
    }

    /// Guardian-count guard: the pubkey count must equal M (L2 — one
    /// share per guardian).
    #[test]
    fn guardian_count_mismatch_rejected() {
        let vdk = VdkKey::generate();
        let config = GuardianSetConfig {
            threshold: 2,
            guardian_count: 5,
        };
        // Supply only 3 pubkeys for an M=5 config.
        let gs = guardians(3);
        let err =
            onboard_guardian_escrow(&vdk, &VAULT_A, config, &pubs(&gs), RecoveryEpoch::GENESIS)
                .unwrap_err();
        assert_eq!(
            err,
            RecoveryOrchestrationError::GuardianCountMismatch {
                expected: 5,
                got: 3
            }
        );
    }

    /// Insufficient shares: fewer than t opened shares fails with the
    /// precise typed error.
    #[test]
    fn insufficient_shares_rejected() {
        let vdk = VdkKey::generate();
        let config = GuardianSetConfig {
            threshold: 3,
            guardian_count: 5,
        };
        let gs = guardians(5);
        let gpubs = pubs(&gs);
        let onboarding =
            onboard_guardian_escrow(&vdk, &VAULT_A, config, &gpubs, RecoveryEpoch::GENESIS)
                .unwrap();
        let e0 = onboarding.epoch.to_escrow_bytes();
        // Only 2 shares for a t=3 config.
        let opened: Vec<Share> = [0usize, 1]
            .iter()
            .map(|&i| {
                pangolin_crypto::escrow::open_sealed_share(
                    &onboarding.assignments[i].sealed_share,
                    &gs[i].0,
                    &VAULT_A,
                    &e0,
                )
                .unwrap()
            })
            .collect();
        let err = recover_vdk_from_shares(
            &onboarding.wrapped_recovery,
            opened,
            &VAULT_A,
            config,
            &gpubs,
            onboarding.epoch,
        )
        .unwrap_err();
        assert_eq!(
            err,
            RecoveryOrchestrationError::InsufficientShares {
                threshold: 3,
                got: 2
            }
        );
    }

    // Proptest: random (t,M,vault_id,VDK) onboard→recover round-trip,
    // ≥1024 cases (mirrors keys.rs / escrow tests.rs discipline).
    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig {
            cases: 1024,
            ..proptest::prelude::ProptestConfig::default()
        })]

        #[test]
        fn proptest_onboard_recover_round_trip(
            t in 2u8..=9u8,
            extra in 0u8..=12u8,
            vault_id in proptest::prelude::any::<[u8; VAULT_ID_LEN]>(),
            epoch_lo in proptest::prelude::any::<u64>(),
            pick_seed in proptest::prelude::any::<u64>(),
        ) {
            // M = clamp(t+extra) into [max(t,3), 15].
            let m = (t + extra).clamp(3, 15).max(t);
            let config = GuardianSetConfig { threshold: t, guardian_count: m };
            let vdk = VdkKey::generate();
            // Saturate the epoch so next() never overflows the assertion.
            let epoch = RecoveryEpoch(epoch_lo.min(u64::MAX - 1));

            let gs = guardians(m);
            let gpubs = pubs(&gs);
            let onboarding =
                onboard_guardian_escrow(&vdk, &vault_id, config, &gpubs, epoch).unwrap();
            proptest::prop_assert_eq!(onboarding.assignments.len(), usize::from(m));

            // Deterministic pseudo-random t-subset (LCG Fisher-Yates).
            let mut order: Vec<usize> = (0..usize::from(m)).collect();
            let mut state = pick_seed | 1;
            for i in (1..order.len()).rev() {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                let j = (state >> 33) as usize % (i + 1);
                order.swap(i, j);
            }
            let e_bytes = epoch.to_escrow_bytes();
            let opened: Vec<Share> = order[..usize::from(t)]
                .iter()
                .map(|&i| {
                    pangolin_crypto::escrow::open_sealed_share(
                        &onboarding.assignments[i].sealed_share,
                        &gs[i].0,
                        &vault_id,
                        &e_bytes,
                    )
                    .unwrap()
                })
                .collect();

            let recovered = recover_vdk_from_shares(
                &onboarding.wrapped_recovery,
                opened,
                &vault_id,
                config,
                &gpubs,
                epoch,
            )
            .unwrap();
            proptest::prop_assert!(
                bool::from(vdk.ct_eq(&recovered.vdk)),
                "L3 byte-identical VDK broken for t={}, m={}", t, m
            );
            proptest::prop_assert_eq!(recovered.re_split.epoch, epoch.next());
        }
    }
}
