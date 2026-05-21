// SPDX-License-Identifier: AGPL-3.0-or-later
//! Pure VDK-rotation-on-revoke orchestration (#106b-2) — the
//! cryptographic device-kill driver.
//!
//! This module is the peer of
//! [`crate::recovery::orchestration::recover_vdk_from_shares`]: a PURE
//! driver (zero chain, zero `uniffi`, zero serde-on-secrets) that, when a
//! device is removed from the on-chain set (#106a `removeDevice`), mints a
//! FRESH VDK for the next epoch and re-keys the SURVIVING devices + the
//! guardian recovery escrow to it — never the removed device. The result
//! is forward secrecy on all POST-revoke data:
//!
//! - the new-epoch VDK is pairing-sealed ([`seal_vdk_to_device`]) to each
//!   SURVIVOR's X25519 pairing pubkey, so each survivor can open the new
//!   epoch with its own pairing secret and then re-wrap it under its own
//!   [`DeviceKey`] ([`wrap_vdk_for_device`]) for biometric fast-unlock;
//! - it is NEVER sealed to the removed device, so the removed device —
//!   which keeps its pre-revoke VDK epochs and the immutable on-chain
//!   ciphertext forever — can never open anything written after the revoke
//!   (L1);
//! - the guardian recovery escrow is RE-POINTED at the new VDK (Q-d=(a):
//!   re-split a fresh RWK' to all `M` guardians, MIRRORING #104b's audited
//!   recovery re-split verbatim via [`onboard_guardian_escrow`]) so a
//!   future guardian recovery restores the LIVE key, not the dead old one
//!   (L2/L8). A skipped re-point would silently strand recovery on the
//!   dead VDK — TESTED, must turn the gate RED.
//!
//! ## No new crypto (L6)
//!
//! Every byte is composition over already-audited #106b-1 / #104a / #104b
//! surfaces. The ONE net-new operation is the legitimate
//! [`VdkKey::generate`] re-create — gated strictly to this device-revoke
//! path and explicitly DISTINCT from recovery (which re-wraps the SAME
//! VDK, never re-creates it; L9). ZERO new HKDF info strings, ZERO new
//! sealed-box, ZERO new external deps.
//!
//! ## Purity discipline (mirrors `orchestration.rs` L1)
//!
//! The driver carries only public context across its boundary (epoch,
//! `vault_id`, survivor `device_id`s + X25519 pairing pubkeys, guardian
//! X25519 pubkeys, `t`/`M`). The new VDK leaves only inside
//! [`RotationArtifacts`] (so the store can write the new-epoch password
//! anchor + the LOCAL device's per-device wrap + the column-AEAD
//! double-wrap of the re-split shares) and is consumed/dropped by the
//! store after the atomic commit. The re-split's transient RWK + plaintext
//! shares never escape — they are consumed/zeroized inside
//! [`onboard_guardian_escrow`].
//!
//! ## The two survivor wrap forms (why the driver emits only the seal)
//!
//! #106b-1 provides TWO at-rest/handoff forms of the VDK on a device:
//!
//! - [`seal_vdk_to_device`] — an ANONYMOUS pairing seal keyed to a
//!   survivor's X25519 PUBLIC pairing key; the driver can produce it for
//!   EVERY survivor from public inputs alone (no survivor secret needed).
//! - [`wrap_vdk_for_device`] — the per-device at-rest wrap keyed by that
//!   device's OWN [`DeviceKey`] SEED; only the device holding the seed can
//!   produce it.
//!
//! The pure driver holds NO survivor `DeviceKey`s, so it emits the pairing
//! SEAL for every survivor (the handoff form). Each survivor — including
//! the local device driving the revoke — opens its seal and re-wraps the
//! new VDK under its own `DeviceKey` to get its fast-unlock
//! [`DeviceWrappedVdk`]. The store (`Vault::commit_vdk_rotation`), which
//! DOES hold the local device's `DeviceKey`, produces the LOCAL device's
//! `DeviceWrappedVdk` at commit time and persists it alongside the seals
//! for the remote survivors — exactly the #104b division where the pure
//! core driver produces the escrow and the store produces the
//! password-derived material.
//!
//! ## Where the password anchor is written (prompt-on-revoke, §0a)
//!
//! Per §0a "Password-anchor on rotation → (1) PROMPT", the new epoch's
//! password-anchor [`WrappedVdk`] is written by the store
//! (`Vault::commit_vdk_rotation`) under an `AuthorityKey` freshly derived
//! from the re-prompted master password — mirroring how
//! `commit_recovery_rekey` takes `new_password`. The KDF (Argon2id) lives
//! in `pangolin-store`, so — exactly as the recovery split keeps the
//! new-password re-wrap store-side — this PURE driver does NOT take the
//! password. The anchor is always current after a rotation (no
//! anchor-behind-current-epoch window).

use pangolin_crypto::escrow::X25519_KEY_LEN;
use pangolin_crypto::keys::{VdkKey, VAULT_ID_LEN};
use pangolin_crypto::pairing::{
    seal_vdk_to_device, PairingError, SealedVdkForDevice, DEVICE_ID_LEN,
};

use crate::recovery::orchestration::{
    onboard_guardian_escrow, OnboardingArtifacts, RecoveryEpoch, RecoveryOrchestrationError,
};
use crate::recovery::GuardianSetConfig;

/// A surviving device's public pairing inputs — the join the driver
/// re-keys the new-epoch VDK to.
///
/// Pure data: a stable 32-byte `device_id` (bound into the pairing seal
/// header, Q-e) plus the device's 32-byte X25519 pairing PUBLIC key
/// (`pangolin_crypto::pairing::derive_x25519_pairing_key(..).public_bytes()`,
/// resolved by the orchestration layer from the surviving authorized set).
/// NO secret material crosses this boundary.
#[derive(Debug, Clone, Copy)]
pub struct SurvivingDevice {
    /// The device's stable 32-byte identifier (bound into the pairing
    /// seal header).
    pub device_id: [u8; DEVICE_ID_LEN],
    /// The device's 32-byte X25519 pairing PUBLIC key — what
    /// [`seal_vdk_to_device`] seals the new VDK to.
    pub x25519_pairing_pub: [u8; X25519_KEY_LEN],
}

/// One survivor's new-epoch pairing seal — the FRESH VDK sealed to that
/// survivor's X25519 pairing pubkey, bound to its `device_id` + the new
/// epoch.
///
/// Non-secret at rest (the VDK is sealed to the recipient). The removed
/// device's `device_id` NEVER appears here (L1).
#[derive(Debug)]
pub struct SurvivorSeal {
    /// The survivor's stable 32-byte identifier (bound into the seal
    /// header, re-checked on open).
    pub device_id: [u8; DEVICE_ID_LEN],
    /// The new-epoch VDK sealed to the survivor's X25519 pairing pubkey.
    pub sealed: SealedVdkForDevice,
}

/// The full output of [`rotate_vdk_for_survivors`] — everything the store
/// persists atomically (via `Vault::commit_vdk_rotation`).
///
/// Mirrors [`crate::recovery::orchestration::RecoveryArtifacts`]. Carries
/// the FRESH VDK (so the store can write the new-epoch password anchor +
/// the LOCAL device's per-device wrap + the column-AEAD double-wrap of the
/// re-split sealed shares), the per-survivor pairing seals, the re-pointed
/// escrow (`re_split`), and the advanced epoch. The new VDK is consumed +
/// dropped (zeroized) by the store after the commit.
#[derive(Debug)]
pub struct RotationArtifacts {
    /// The FRESH VDK minted for the new epoch (the ONE legitimate
    /// `VdkKey::generate` re-create, gated to revoke; L9). Consumed by the
    /// store: it writes the new-epoch password anchor + the LOCAL device's
    /// per-device wrap + the column-AEAD double-wrap of the re-split
    /// shares, then drops it.
    pub new_vdk: VdkKey,
    /// Per-surviving-device new-epoch pairing seals, ordered as the
    /// survivor set was supplied. The removed device is NEVER in this set
    /// (L1).
    pub survivor_seals: Vec<SurvivorSeal>,
    /// The re-pointed guardian escrow: a FRESH RWK', a FRESH
    /// `WrappedVdkRecovery` under RWK' of the NEW VDK, fresh sealed shares
    /// to ALL `M` guardians, at the bumped epoch — produced by
    /// [`onboard_guardian_escrow`] verbatim (Q-d=(a), mirrors #104b's
    /// re-split). Old shares are dead against the new wrapper (L2/L8).
    pub re_split: OnboardingArtifacts,
    /// The advanced shared per-vault epoch (`current_epoch.next()`) — the
    /// new epoch the new VDK chain entry is keyed by AND the escrow re-split
    /// is tagged with (one shared monotonic clock, L5/Q-f).
    pub new_epoch: RecoveryEpoch,
}

/// Errors from the pure rotation driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationError {
    /// No surviving devices were supplied. A rotation with an empty
    /// survivor set would mint a VDK that NO device can open — a vault
    /// nobody can unlock. The on-chain set always retains at least the
    /// device driving the revoke, so an empty set is a caller bug.
    NoSurvivors,
    /// Re-keying the new VDK to a survivor (the pairing seal) failed.
    Pairing(PairingError),
    /// The guardian escrow re-split failed (invalid `(t, M)`, guardian
    /// pubkey count != `M`, or a delegated escrow op). Carries the typed
    /// recovery-orchestration cause.
    EscrowRePoint(RecoveryOrchestrationError),
}

impl core::fmt::Display for RotationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoSurvivors => f.write_str("rotation requires at least one surviving device"),
            Self::Pairing(e) => write!(f, "re-keying the new VDK to a survivor failed: {e}"),
            Self::EscrowRePoint(e) => write!(f, "guardian escrow re-point failed: {e}"),
        }
    }
}

impl std::error::Error for RotationError {}

impl From<PairingError> for RotationError {
    fn from(e: PairingError) -> Self {
        Self::Pairing(e)
    }
}

impl From<RecoveryOrchestrationError> for RotationError {
    fn from(e: RecoveryOrchestrationError) -> Self {
        Self::EscrowRePoint(e)
    }
}

/// Drive the **VDK-rotation-on-revoke** flow (plan §3.3).
///
/// Mints a fresh VDK for the next epoch, re-keys it to every SURVIVING
/// device, and re-points the guardian recovery escrow at it — never the
/// removed device.
///
/// Steps (PURE — every secret op delegates to a #106b-1 / #104a / #104b
/// fn; this driver never touches a nonce, an AEAD, or a field element):
///
/// 1. `VdkKey::generate()` → the NEW VDK for epoch `current_epoch.next()`
///    (the ONE legitimate re-create, gated to revoke; L9).
/// 2. For each survivor: `seal_vdk_to_device` (the pairing handoff),
///    bound to the survivor's `device_id` + the new epoch. The removed
///    device is never in the survivor set, so the new VDK is never
///    re-keyed to it (L1).
/// 3. Re-point the escrow: `onboard_guardian_escrow(&new_vdk, …,
///    new_epoch)` — a FRESH RWK', a FRESH `WrappedVdkRecovery` under RWK'
///    of the NEW VDK, fresh sealed shares to ALL `M` guardians (Q-d=(a),
///    #104b re-split verbatim; L2/L8). The transient RWK never escapes.
/// 4. Emit [`RotationArtifacts`] (the new VDK, survivor seals, re-split,
///    new epoch). The store writes the new-epoch PASSWORD ANCHOR under the
///    re-prompted-password authority and the LOCAL device's per-device
///    wrap inside the same atomic commit (prompt-on-revoke, §0a).
///
/// `survivors` must be non-empty (the device driving the revoke is always
/// a survivor). `guardian_x25519_pubs` must contain exactly
/// `guardian_config.guardian_count` (`M`) pubkeys (the escrow re-split
/// reuses the SAME guardian set; the on-chain guardian set is unchanged by
/// a device revoke).
///
/// The new VDK is moved into [`RotationArtifacts::new_vdk`]; the caller
/// (store) drops it after the atomic commit. The re-split's transient RWK
/// and plaintext shares are consumed and zeroized inside
/// [`onboard_guardian_escrow`].
///
/// # Errors
///
/// - [`RotationError::NoSurvivors`] if `survivors` is empty.
/// - [`RotationError::Pairing`] if a survivor seal fails.
/// - [`RotationError::EscrowRePoint`] if the escrow re-split fails
///   (invalid `(t, M)`, guardian pubkey count != `M`, or a delegated
///   escrow op).
pub fn rotate_vdk_for_survivors(
    survivors: &[SurvivingDevice],
    vault_id: &[u8; VAULT_ID_LEN],
    guardian_config: GuardianSetConfig,
    guardian_x25519_pubs: &[[u8; X25519_KEY_LEN]],
    current_epoch: RecoveryEpoch,
) -> Result<RotationArtifacts, RotationError> {
    if survivors.is_empty() {
        return Err(RotationError::NoSurvivors);
    }

    // 1. Mint the FRESH VDK for the next epoch. This is the ONE legitimate
    //    `VdkKey::generate` re-create — gated strictly to this revoke path,
    //    explicitly distinct from recovery (which re-wraps the SAME VDK;
    //    L9). The shared per-vault epoch advances monotonically (L5/Q-f).
    let new_vdk = VdkKey::generate();
    let new_epoch = current_epoch.next();
    let epoch_bytes = new_epoch.to_escrow_bytes();

    // 2. Re-key the NEW VDK to each SURVIVOR via the pairing seal (never
    //    the removed device, L1). The seal is the anonymous handoff form a
    //    survivor opens with its X25519 pairing secret; the per-device wrap
    //    (which needs the device's own DeviceKey seed) is produced by each
    //    survivor — including the local device, by the store — at commit /
    //    sync time.
    let mut survivor_seals = Vec::with_capacity(survivors.len());
    for s in survivors {
        let sealed = seal_vdk_to_device(
            &new_vdk,
            &s.x25519_pairing_pub,
            vault_id,
            &s.device_id,
            &epoch_bytes,
        )?;
        survivor_seals.push(SurvivorSeal {
            device_id: s.device_id,
            sealed,
        });
    }

    // 3. Re-point the guardian escrow at the NEW VDK (Q-d=(a)): reuse the
    //    #104b onboarding/re-split path verbatim against the new VDK at the
    //    bumped epoch — a FRESH RWK', a FRESH WrappedVdkRecovery under RWK',
    //    fresh sealed shares to ALL M guardians. The transient RWK +
    //    plaintext shares are consumed + zeroized inside the call (L2/L8).
    //    MANDATORY — a skipped re-point silently strands a future recovery
    //    on the dead old VDK (TESTED).
    let re_split = onboard_guardian_escrow(
        &new_vdk,
        vault_id,
        guardian_config,
        guardian_x25519_pubs,
        new_epoch,
    )?;

    Ok(RotationArtifacts {
        new_vdk,
        survivor_seals,
        re_split,
        new_epoch,
    })
}

#[cfg(test)]
mod tests;
