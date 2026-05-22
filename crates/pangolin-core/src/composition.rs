// SPDX-License-Identifier: AGPL-3.0-or-later
//! **MVP-3 issue #106e-0: the store/core COMPOSITION LAYER.**
//!
//! The missing middle slice between the merged-and-audited drivers/commits
//! and the (LOCKED-but-unbuilt) #106e-1 FFI: two public composition entry
//! points that pull together the pure `pangolin-core` drivers
//! (`resolve_survivors`, `rotate_vdk_for_survivors`,
//! `recover_vdk_from_shares`) and the already-audited atomic `pangolin-store`
//! commits, so the thin #106e-1 FFI never juggles a secret.
//!
//! ## Why these are FREE FUNCTIONS over `&mut Vault`, not `Vault` methods
//!
//! The workspace dependency arrow is one-way: `pangolin-core` →
//! `pangolin-store` (core deps on store; store has NO core dep, to avoid a
//! Cargo cycle). The composition needs to call BOTH the core drivers AND
//! the store's pub commits, so it can only live in `pangolin-core`. A
//! `Vault` method (physically in `pangolin-store`) could not reach the core
//! drivers. The third composition entry point —
//! [`pangolin_store::Vault::guardian_open_sealed_share`] — needs ONLY
//! `pangolin-crypto` (upstream of store) and therefore stays a store
//! `Vault` method (see the 0a-CORRECTION in the locked plan).
//!
//! ## Secret hygiene (Q-d — the audit's central check)
//!
//! - `old_vdk` / `device_key` NEVER cross into `pangolin-core`: they are
//!   read inside the store wrapper
//!   [`pangolin_store::Vault::commit_vdk_rotation_from_active`] only.
//! - `new_vdk` (rotation) and the recovered VDK (recovery) are minted /
//!   reconstructed by the core drivers and handed to the store commits as
//!   VALUES — they are consumed + dropped (zeroized) inside the commits.
//! - These two functions return NON-secret outcomes. The only secret out of
//!   the whole composition layer is the guardian `Share` from
//!   `guardian_open_sealed_share` (a store method, not here).
//! - No new crypto, no new deps: every op delegates to a merged-and-audited
//!   driver / commit.

use pangolin_crypto::escrow::{Share, WrappedVdkRecovery};
use pangolin_crypto::keys::VAULT_ID_LEN;
use pangolin_crypto::secret::SecretBytes;
use pangolin_store::{GuardianRecord, Vault};

use crate::device_add::{resolve_survivors, SurvivorDirectoryEntry};
use crate::recovery::orchestration::{recover_vdk_from_shares, RecoveryArtifacts, RecoveryEpoch};
use crate::recovery::GuardianSetConfig;
use crate::rotation::{rotate_vdk_for_survivors, RotationArtifacts};

/// The NON-secret result of [`complete_rotation`].
///
/// GAP-A: `unknown_survivors` surfaces in-set survivors whose pairing
/// pubkey the LOCAL directory does not yet know — they are NEVER silently
/// stranded; the host re-keys them opportunistically when they next present
/// their triple.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationOutcome {
    /// The advanced shared per-vault epoch the rotation landed at.
    pub new_epoch: u64,
    /// In-set survivors (20-byte secp256k1 signers) whose pairing pubkey the
    /// local directory does not know — surfaced, never stranded (GAP-A).
    pub unknown_survivors: Vec<[u8; 20]>,
}

/// The NON-secret result of [`recover_from_shares`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryOutcome {
    /// The new recovery epoch the post-recovery re-split was tagged with.
    pub new_epoch: u64,
}

/// The host-supplied guardian roster for a LOST-EVERYTHING recovery.
///
/// A fresh device has NO active VDK, so it CANNOT read its own escrow
/// (`read_recovery_escrow` needs the VDK's column-AEAD — a chicken-and-egg).
/// The guardian set shape `(t, M)` + the `M` guardian X25519 SEALING
/// pubkeys therefore travel in the backup the host hands us. The backup
/// FORMAT itself stays deferred (#106e Q-g); here it is just method input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardianRoster {
    /// The reconstruction threshold (`t`).
    pub threshold: u8,
    /// The guardian count (`M`).
    pub guardian_count: u8,
    /// The `M` guardians' 32-byte X25519 SEALING pubkeys, ordered by index
    /// (`0..M`). The re-split re-seals to the SAME guardian set.
    pub x25519_pubs: Vec<[u8; 32]>,
}

/// Errors from the composition layer.
#[derive(Debug)]
pub enum CompositionError {
    /// A `pangolin-store` operation failed (escrow read, the atomic commit,
    /// the pending-rotation glue, the directory read).
    Store(pangolin_store::StoreError),
    /// The pure rotation driver failed (no survivors, a survivor seal, or
    /// the escrow re-split).
    Rotation(crate::rotation::RotationError),
    /// The pure recovery driver failed (insufficient / wrong shares,
    /// invalid guardian set, or a delegated escrow op).
    Recovery(crate::recovery::orchestration::RecoveryOrchestrationError),
    /// `complete_rotation` requires a recovery escrow to re-point, but the
    /// vault has none onboarded yet. A rotation cannot proceed without the
    /// guardian set to re-split against.
    NoRecoveryEscrow,
}

impl core::fmt::Display for CompositionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Store(e) => write!(f, "store error: {e}"),
            Self::Rotation(e) => write!(f, "rotation driver error: {e}"),
            Self::Recovery(e) => write!(f, "recovery driver error: {e}"),
            Self::NoRecoveryEscrow => {
                f.write_str("cannot rotate: no recovery escrow is onboarded to re-point")
            }
        }
    }
}

impl std::error::Error for CompositionError {}

impl From<pangolin_store::StoreError> for CompositionError {
    fn from(e: pangolin_store::StoreError) -> Self {
        Self::Store(e)
    }
}
impl From<crate::rotation::RotationError> for CompositionError {
    fn from(e: crate::rotation::RotationError) -> Self {
        Self::Rotation(e)
    }
}
impl From<crate::recovery::orchestration::RecoveryOrchestrationError> for CompositionError {
    fn from(e: crate::recovery::orchestration::RecoveryOrchestrationError) -> Self {
        Self::Recovery(e)
    }
}

/// Result alias for the composition layer.
pub type Result<T> = core::result::Result<T, CompositionError>;

/// Decompose a re-split's [`crate::recovery::orchestration::OnboardingArtifacts`]
/// `assignments` into the borrowed `&[GuardianRecord]` the store commits
/// take — exactly the mapping the anvil E2E performs inline (#106c). Pure;
/// no secret crosses (the `SealedShare`s are non-secret, sealed to the
/// guardians).
fn re_split_records(
    re_split: &crate::recovery::orchestration::OnboardingArtifacts,
) -> Vec<GuardianRecord<'_>> {
    re_split
        .assignments
        .iter()
        .map(|a| GuardianRecord {
            index: a.index,
            guardian_x25519_pub: a.guardian_x25519_pub,
            sealed_share: &a.sealed_share,
        })
        .collect()
}

/// **Complete a VDK rotation after a device revoke** — the production twin
/// of the anvil E2E's rotation half.
///
/// An EXISTING unlocked device (the one driving the revoke) re-keys the
/// vault to the SURVIVING devices and re-points the guardian escrow at a
/// FRESH VDK, then resolves every outstanding rotation-pending row the
/// survivor set retires.
///
/// Steps:
/// 1. Read the local survivor directory (`vault.device_directory`) →
///    [`resolve_survivors`] against the host-supplied `current_onchain_set`
///    → `(survivors, unknown)`. `unknown` flows into
///    [`RotationOutcome::unknown_survivors`] (GAP-A).
/// 2. Read the NON-secret escrow params `(t, M)` + guardian pubkeys +
///    current epoch via `vault.recovery_escrow_params()` (the store opens
///    the escrow with the active VDK internally; the VDK never crosses the
///    crate boundary — Q-d).
/// 3. [`rotate_vdk_for_survivors`] MINTS the FRESH `new_vdk` and re-splits
///    the escrow at the bumped epoch (pure; non-secret inputs only).
/// 4. `vault.commit_vdk_rotation_from_active(new_vdk, …)` — the store pulls
///    `old_vdk` / `device_key` from the active session INSIDE the commit and
///    runs the audited single-transaction `commit_vdk_rotation` (#106b-2
///    L4). The fresh `new_vdk` is consumed + dropped there.
/// 5. Resolve ALL pending-rotation rows whose removed signer is ABSENT from
///    `current_onchain_set` (Q-e — one rotation retires the whole survivor
///    set).
///
/// `current_onchain_set` is the live `RevisionLogV2` authorized set the host
/// read on-chain.
///
/// # Errors
///
/// - [`CompositionError::NoRecoveryEscrow`] if the vault has no escrow to
///   re-point.
/// - [`CompositionError::Rotation`] if the pure driver fails (no survivors,
///   a survivor seal, or the re-split).
/// - [`CompositionError::Store`] if the escrow read, the atomic commit, or
///   the pending-rotation glue fails (e.g. `StoreError::NotUnlocked` if no
///   session is active).
pub fn complete_rotation(
    vault: &mut Vault,
    master_password: &SecretBytes,
    current_onchain_set: &[[u8; 20]],
) -> Result<RotationOutcome> {
    let vault_id = vault.vault_id();

    // 1. Resolve survivors from the local directory (GAP-A surfaces unknowns).
    let directory: Vec<SurvivorDirectoryEntry> = vault
        .device_directory()?
        .into_iter()
        .map(|e| SurvivorDirectoryEntry {
            signer: e.signer,
            device_id: e.device_id,
            x25519_pairing_pub: e.pairing_pub,
        })
        .collect();
    let (survivors, unknown) = resolve_survivors(current_onchain_set, &directory);

    // 2. Read the NON-secret escrow params (the store opens the escrow with
    //    the active VDK internally; only (t,M)+pubs+epoch come back — Q-d).
    let params = vault
        .recovery_escrow_params()?
        .ok_or(CompositionError::NoRecoveryEscrow)?;
    let config = GuardianSetConfig {
        threshold: params.threshold,
        guardian_count: params.guardian_count,
    };

    // 3. Pure rotation driver MINTS the fresh VDK + re-splits the escrow.
    let RotationArtifacts {
        new_vdk,
        re_split,
        new_epoch,
        ..
    } = rotate_vdk_for_survivors(
        &survivors,
        &vault_id,
        config,
        &params.guardian_x25519_pubs,
        RecoveryEpoch(params.current_epoch),
    )?;

    // 4. The audited single-tx commit. The store reads old_vdk/device_key
    //    from the active session INSIDE; the fresh new_vdk is consumed there.
    let records = re_split_records(&re_split);
    vault.commit_vdk_rotation_from_active(
        new_vdk,
        master_password,
        new_epoch.0,
        &re_split.wrapped_recovery,
        re_split.config.threshold,
        re_split.config.guardian_count,
        re_split.epoch.0,
        &records,
    )?;

    // 5. Retire every pending row whose removed signer is no longer in the
    //    live set (Q-e — the rotation re-keyed against the whole survivor
    //    set, so it clears all outstanding removals at once). Idempotent.
    for pending in vault.pending_rotations()? {
        if !current_onchain_set.contains(&pending.removed_signer) {
            vault.resolve_rotation_pending(&pending.removed_signer)?;
        }
    }

    Ok(RotationOutcome {
        new_epoch: new_epoch.0,
        unknown_survivors: unknown,
    })
}

/// **Recover a vault from guardian shares on a LOST-EVERYTHING device.**
///
/// The user lost every device and is starting fresh. There is NO active
/// session and NO local escrow to read (the chicken-and-egg: you cannot read
/// the escrow without the VDK you are trying to recover). So
/// `wrapped_recovery` + `roster` (`(t, M)` + the `M` guardian X25519 pubs) +
/// `current_epoch` + `vault_id` are ALL HOST-SUPPLIED from a backup. This
/// function pulls NOTHING from `self.active`.
///
/// Steps:
/// 1. [`recover_vdk_from_shares`] reconstructs the byte-identical VDK from
///    `>= t` opened shares and re-splits the escrow at the bumped epoch.
/// 2. `vault.commit_recovery_rekey(vdk, new_password, …)` — the EXISTING
///    audited single-transaction commit (#105a L2). The recovered VDK is
///    consumed + dropped (zeroized) inside it.
///
/// `opened_shares` are the raw [`Share`]s collected from `>= t` guardians
/// (each opened via `guardian_open_sealed_share`). The backup FORMAT itself
/// stays deferred (#106e Q-g) — these are just method parameters.
///
/// # Errors
///
/// - [`CompositionError::Recovery`] if reconstruction / unwrap / the
///   re-split fails (too few or wrong shares, invalid guardian set).
/// - [`CompositionError::Store`] if the atomic commit fails.
pub fn recover_from_shares(
    vault: &mut Vault,
    wrapped_recovery: &WrappedVdkRecovery,
    opened_shares: Vec<Share>,
    roster: &GuardianRoster,
    new_password: &SecretBytes,
    current_epoch: u64,
    vault_id: [u8; VAULT_ID_LEN],
) -> Result<RecoveryOutcome> {
    let config = GuardianSetConfig {
        threshold: roster.threshold,
        guardian_count: roster.guardian_count,
    };

    // 1. Pure recovery driver: reconstruct the byte-identical VDK + re-split.
    let RecoveryArtifacts { vdk, re_split } = recover_vdk_from_shares(
        wrapped_recovery,
        opened_shares,
        &vault_id,
        config,
        &roster.x25519_pubs,
        RecoveryEpoch(current_epoch),
    )?;

    // 2. The audited single-tx atomic commit. The recovered VDK is consumed
    //    + dropped (zeroized) inside; nothing was pulled from self.active.
    let records = re_split_records(&re_split);
    let new_epoch = re_split.epoch.0;
    vault.commit_recovery_rekey(
        vdk,
        new_password,
        &re_split.wrapped_recovery,
        re_split.config.threshold,
        re_split.config.guardian_count,
        re_split.epoch.0,
        &records,
    )?;

    Ok(RecoveryOutcome { new_epoch })
}
