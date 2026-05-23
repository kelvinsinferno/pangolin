// SPDX-License-Identifier: AGPL-3.0-or-later
//! Pure device-add (pairing) orchestration + the `DeviceRemoved`→rotation
//! detection types (#106c).
//!
//! This module is the peer of [`crate::recovery::orchestration`] and
//! [`crate::rotation`]: a PURE driver (zero chain, zero `uniffi`, zero
//! serde-on-secrets) that sequences the merged #106b-1
//! [`pangolin_crypto::pairing`] handoff into the two halves of the
//! device-add handshake plus the device-remove rotation TRIGGER detection.
//!
//! ## The device-add handshake (§3.2)
//!
//! ```text
//! New device B (fresh install):
//!   - derives its secp256k1 signer (pangolin-chain, host-side)
//!   - derives its X25519 pairing pubkey (pairing::derive_x25519_pairing_key)
//!   - derives its stable 32-byte device_id ([`device_id_from_device_key`], GAP B)
//!   - presents (device_id, signer_addr, x25519_pairing_pub) to A out-of-band
//!     (the QR/short-code SCANNING is #106e; #106c consumes the verified triple)
//!
//! Existing unlocked device A (holds the live VDK, is the manager):
//!   a. reads live deviceNonce + signs AddDevice on-chain (pangolin-chain, host)
//!   b. [`seal_vdk_to_new_device`] → SealedVdkForDevice (the pure driver's job)
//!
//! New device B:
//!   c. [`open_vdk_for_new_device`] (ct_eq) → byte-identical VDK
//!   d. wrap_vdk_for_device + persist (pangolin-store)
//! ```
//!
//! The driver carries ONLY public context across its boundary (`device_id`,
//! pairing pubkey, `vault_id`, epoch), never key material — exactly like
//! `recovery::orchestration` (L4). The VDK reaches the new device ONLY as a
//! `SealedVdkForDevice` to that device's X25519 pairing pubkey, domain-bound
//! to `vault_id‖device_id‖epoch`.
//!
//! ## The `DeviceRemoved`→rotation TRIGGER detection (§3.3)
//!
//! [`detect_removed_devices`] folds a sequence of device-management events
//! (decoded engine-side by `pangolin-chain::decode_device_mgmt_events`) into
//! the CURRENT authorized set, then diffs it against the locally-known set
//! to surface which signers were removed. This is the PURE detection half;
//! the store persists a crash-durable rotation-pending row and the HOST
//! drives the password-gated completion (`pangolin-core` never auto-rotates
//! — it holds no master password; L3).

use pangolin_crypto::escrow::{EPOCH_LEN, X25519_KEY_LEN};
use pangolin_crypto::keys::{DeviceKey, VdkKey, VAULT_ID_LEN};
use pangolin_crypto::pairing::{
    open_vdk_from_pairing, seal_vdk_to_device, PairingError, SealedVdkForDevice, DEVICE_ID_LEN,
};

/// The verified public triple a new device presents to the existing
/// unlocked device A (the #106c/#106e line, Q-d).
///
/// #106c's driver takes this as an ALREADY-RESOLVED triple (the QR /
/// short-code SCANNING + presence proof that physically + securely
/// delivers it to A is #106e). It carries only public context. The new
/// device's 20-byte secp256k1 `signer` (the on-chain authorized-set key
/// the manager's `addDevice` authorizes) travels OUTSIDE the handshake
/// (it lives on the wire-form [`crate::pairing_transport::PairingPayload`]
/// the host moves; the #106e-2 manager FFI passes it as its own argument
/// to `add_device_v2`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NewDeviceHandshake {
    /// The new device's stable 32-byte identifier (GAP B — see
    /// [`device_id_from_device_key`]). Bound into the pairing seal header.
    pub device_id: [u8; DEVICE_ID_LEN],
    /// The new device's 32-byte X25519 pairing PUBLIC key — what
    /// [`seal_vdk_to_new_device`] seals the VDK to.
    pub x25519_pairing_pub: [u8; X25519_KEY_LEN],
}

/// The canonical stable 32-byte `device_id` derivation (GAP B).
///
/// Derived one-way from the device's [`DeviceKey`] as its Ed25519
/// verifying-key bytes — the SAME value `pangolin-store`'s
/// `device_id_from_key` uses for the local `DeviceId`, so the seal header
/// `device_id`, the on-chain publish `deviceId` field, and the store's
/// device-row id all agree byte-for-byte. The derivation is one-way (the
/// verifying key reveals nothing about the secret seed) and stable (same
/// `DeviceKey` → same `device_id`), and is exactly 32 bytes per
/// [`DEVICE_ID_LEN`].
#[must_use]
pub fn device_id_from_device_key(device: &DeviceKey) -> [u8; DEVICE_ID_LEN] {
    device.verifying_key().to_bytes()
}

/// Encode a `u64` vault epoch into the 16-byte
/// [`pangolin_crypto::escrow::EPOCH_LEN`] form the pairing seal binds.
///
/// Mirrors [`crate::recovery::orchestration::RecoveryEpoch::to_escrow_bytes`]
/// (8 reserved zero bytes ‖ big-endian `u64`) so a device-add seal and a
/// rotation seal at the same epoch use the SAME 16-byte epoch encoding (one
/// shared monotonic clock, L5/Q-f).
#[must_use]
pub fn epoch_to_pairing_bytes(epoch: u64) -> [u8; EPOCH_LEN] {
    let mut out = [0u8; EPOCH_LEN];
    out[8..].copy_from_slice(&epoch.to_be_bytes());
    out
}

/// **Device A (existing unlocked) side.** Seal the live VDK to the new
/// device's X25519 pairing pubkey, bound to `vault_id ‖ device_id ‖ epoch`.
///
/// This is the pure driver's job in the handshake (step b): A already holds
/// the unlocked VDK; the on-chain `addDevice` broadcast + the live-nonce
/// read live in `pangolin-chain` (driven by the host). The returned
/// [`SealedVdkForDevice`] is non-secret at rest (sealed to the recipient)
/// and is delivered to B over the untrusted pairing channel.
///
/// `epoch` is the vault's CURRENT epoch on a clean add (no rotation); A
/// reads it from local state.
///
/// # Errors
///
/// [`PairingError::SealFailed`] if the underlying sealed-box op fails.
pub fn seal_vdk_to_new_device(
    vdk: &VdkKey,
    new_device: &NewDeviceHandshake,
    vault_id: &[u8; VAULT_ID_LEN],
    epoch: u64,
) -> Result<SealedVdkForDevice, PairingError> {
    let epoch_bytes = epoch_to_pairing_bytes(epoch);
    seal_vdk_to_device(
        vdk,
        &new_device.x25519_pairing_pub,
        vault_id,
        &new_device.device_id,
        &epoch_bytes,
    )
}

/// **New device B side.** Open the [`SealedVdkForDevice`] and return the VDK.
///
/// Opens with B's X25519 pairing secret, verifies the bound context, and
/// returns the byte-identical VDK (`ct_eq` the original A held — L4: pairing
/// hands the VDK over, never re-derives it).
///
/// After this returns the host calls
/// [`pangolin_crypto::pairing::wrap_vdk_for_device`] to produce B's own
/// `DeviceWrappedVdk` and persists it (`pangolin-store`). A wrong recipient
/// key, tampered ciphertext, or `vault_id`/`device_id`/`epoch` mismatch all
/// collapse to a single undifferentiated [`PairingError::OpenFailed`].
///
/// # Errors
///
/// [`PairingError::OpenFailed`] — undifferentiated — for any open/verify
/// failure.
pub fn open_vdk_for_new_device(
    sealed: &SealedVdkForDevice,
    recipient_x25519_secret: &[u8; X25519_KEY_LEN],
    vault_id: &[u8; VAULT_ID_LEN],
    device_id: &[u8; DEVICE_ID_LEN],
    epoch: u64,
) -> Result<VdkKey, PairingError> {
    let epoch_bytes = epoch_to_pairing_bytes(epoch);
    open_vdk_from_pairing(
        sealed,
        recipient_x25519_secret,
        vault_id,
        device_id,
        &epoch_bytes,
    )
}

// ---------------------------------------------------------------------
// The DeviceRemoved -> rotation TRIGGER detection (pure, §3.3)
// ---------------------------------------------------------------------

/// A device-management event the detection driver folds into the authorized
/// set.
///
/// Mirrors `pangolin_chain::DeviceMgmtEvent` but with the chain crate's
/// `alloy::Address` collapsed to a 20-byte signer so this stays a PURE,
/// chain-free type (the engine glue maps the chain enum into this).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetMgmtEvent {
    /// Genesis: `first_signer` enters the set.
    Bootstrapped {
        /// The genesis device's 20-byte signer address.
        first_signer: [u8; 20],
    },
    /// `signer` added to the set.
    Added {
        /// The added device's 20-byte signer address.
        signer: [u8; 20],
    },
    /// `signer` removed from the set.
    Removed {
        /// The removed device's 20-byte signer address.
        signer: [u8; 20],
    },
}

/// Fold a chronological sequence of [`SetMgmtEvent`]s into the resulting
/// authorized-signer set (deduplicated, order-independent of address).
///
/// This is the client-side mirror of the on-chain `authorizedDevice` set
/// (the honor source of truth, L5). The live on-chain read is authoritative
/// — this fold is the catch-up/anti-staleness anchor when reconstructing the
/// set from events.
#[must_use]
pub fn fold_authorized_set(events: &[SetMgmtEvent]) -> Vec<[u8; 20]> {
    let mut set: Vec<[u8; 20]> = Vec::new();
    for ev in events {
        match ev {
            SetMgmtEvent::Bootstrapped { first_signer } => {
                if !set.contains(first_signer) {
                    set.push(*first_signer);
                }
            }
            SetMgmtEvent::Added { signer } => {
                if !set.contains(signer) {
                    set.push(*signer);
                }
            }
            SetMgmtEvent::Removed { signer } => {
                set.retain(|s| s != signer);
            }
        }
    }
    set
}

/// **The `DeviceRemoved`→rotation TRIGGER detection (pure half, §3.3).**
///
/// Given the device-management events folded into the CURRENT on-chain
/// authorized set and the set of signers the local app believed were
/// honored, return the signers that are LOCALLY-KNOWN but NO LONGER in the
/// on-chain set — i.e. the removals the app may have missed (a closed app, a
/// dropped event). Each is a removal that should queue a rotation-pending
/// state.
///
/// The live on-chain set is the source of truth (the #106a honor rule, L5).
/// This is a PURE set-diff; it NEVER rotates, persists, or holds a password
/// (L3) — the engine glue persists the crash-durable rotation-pending row
/// and the HOST drives the password-gated completion.
#[must_use]
pub fn detect_removed_devices(
    current_onchain_set: &[[u8; 20]],
    locally_known_signers: &[[u8; 20]],
) -> Vec<[u8; 20]> {
    locally_known_signers
        .iter()
        .filter(|s| !current_onchain_set.contains(s))
        .copied()
        .collect()
}

/// Resolve the surviving devices' pairing inputs for a rotation from the
/// CURRENT on-chain authorized set, using the local
/// `signer → (device_id, x25519_pairing_pub)` directory (GAP A).
///
/// Returns the survivors' [`crate::rotation::SurvivingDevice`]s for every
/// in-set signer whose pairing pubkey the directory knows, plus the list of
/// in-set signers whose pubkey is NOT yet known locally (the opportunistic-
/// completion gap — those survivors are re-keyed when they next come online
/// and present their triple, the same shape #104b accepted for non-
/// participant guardian pubkeys). The removed signer is, by construction,
/// not in `current_onchain_set`, so it can never appear in the survivor set
/// (L1 / forward secrecy).
///
/// `directory` is the persisted local map (resolved by `pangolin-store`).
#[must_use]
pub fn resolve_survivors(
    current_onchain_set: &[[u8; 20]],
    directory: &[SurvivorDirectoryEntry],
) -> (Vec<crate::rotation::SurvivingDevice>, Vec<[u8; 20]>) {
    let mut survivors = Vec::new();
    let mut unknown = Vec::new();
    for signer in current_onchain_set {
        match directory.iter().find(|e| &e.signer == signer) {
            Some(entry) => survivors.push(crate::rotation::SurvivingDevice {
                device_id: entry.device_id,
                x25519_pairing_pub: entry.x25519_pairing_pub,
            }),
            None => unknown.push(*signer),
        }
    }
    (survivors, unknown)
}

/// One entry of the local `signer → (device_id, x25519_pairing_pub)`
/// directory (GAP A). Pure data; the persisted form lives in
/// `pangolin-store`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SurvivorDirectoryEntry {
    /// The device's 20-byte secp256k1 signer (the on-chain set key).
    pub signer: [u8; 20],
    /// The device's stable 32-byte identifier (GAP B).
    pub device_id: [u8; DEVICE_ID_LEN],
    /// The device's 32-byte X25519 pairing pubkey (what rotation seals to).
    pub x25519_pairing_pub: [u8; X25519_KEY_LEN],
}

#[cfg(test)]
mod tests {
    use super::*;
    use pangolin_crypto::keys::WrapContext;
    use pangolin_crypto::pairing::{derive_x25519_pairing_key, wrap_vdk_for_device};

    const VAULT_A: [u8; VAULT_ID_LEN] = [0xAA; VAULT_ID_LEN];

    fn addr(b: u8) -> [u8; 20] {
        [b; 20]
    }

    /// GAP B: the `device_id` is the Ed25519 verifying-key bytes, stable for
    /// a fixed seed and exactly 32 bytes.
    #[test]
    fn device_id_is_stable_verifying_key_bytes() {
        let dk = DeviceKey::from_seed([0x07; 32]);
        let id1 = device_id_from_device_key(&dk);
        let id2 = device_id_from_device_key(&DeviceKey::from_seed([0x07; 32]));
        assert_eq!(id1, id2, "same seed -> same device_id");
        assert_eq!(id1.len(), DEVICE_ID_LEN);
        assert_eq!(id1, dk.verifying_key().to_bytes());
        // Distinct seed -> distinct id.
        let other = device_id_from_device_key(&DeviceKey::from_seed([0x08; 32]));
        assert_ne!(id1, other);
    }

    /// The epoch encoding matches the recovery-orchestration form (one
    /// shared clock, L5/Q-f).
    #[test]
    fn epoch_encoding_matches_recovery_form() {
        for e in [0u64, 1, 42, u64::MAX] {
            let pairing = epoch_to_pairing_bytes(e);
            let recovery = crate::recovery::orchestration::RecoveryEpoch(e).to_escrow_bytes();
            assert_eq!(pairing, recovery);
        }
    }

    /// The full device-add handshake round-trips: A seals the VDK to B; B
    /// opens it; the recovered VDK is byte-identical (`ct_eq`, L4); B can
    /// then wrap it under its own device key.
    #[test]
    fn device_add_handshake_round_trips() {
        let vdk = VdkKey::generate();
        let b_device = DeviceKey::from_seed([0xB0; 32]);
        let b_pairing = derive_x25519_pairing_key(&b_device);
        let b_device_id = device_id_from_device_key(&b_device);
        let handshake = NewDeviceHandshake {
            device_id: b_device_id,
            x25519_pairing_pub: *b_pairing.public_bytes(),
        };
        let epoch = 0u64;

        // A seals the live VDK to B.
        let sealed = seal_vdk_to_new_device(&vdk, &handshake, &VAULT_A, epoch).unwrap();

        // B opens it -> byte-identical VDK.
        let b_secret = b_pairing.secret_bytes();
        let recovered =
            open_vdk_for_new_device(&sealed, &b_secret, &VAULT_A, &b_device_id, epoch).unwrap();
        assert!(
            bool::from(vdk.ct_eq(&recovered)),
            "recovered VDK must be byte-identical (L4)"
        );

        // B can wrap the recovered VDK under its own device key.
        let ctx = WrapContext::new(VAULT_A);
        let _wrapped = wrap_vdk_for_device(&recovered, &b_device, &ctx).unwrap();
    }

    /// A seal minted for device B cannot be opened by a different device C
    /// (the `device_id`/recipient binding defends the handoff).
    #[test]
    fn seal_to_b_rejected_by_c() {
        let vdk = VdkKey::generate();
        let b_device = DeviceKey::from_seed([0xB1; 32]);
        let b_pairing = derive_x25519_pairing_key(&b_device);
        let handshake = NewDeviceHandshake {
            device_id: device_id_from_device_key(&b_device),
            x25519_pairing_pub: *b_pairing.public_bytes(),
        };
        let sealed = seal_vdk_to_new_device(&vdk, &handshake, &VAULT_A, 0).unwrap();

        let c_device = DeviceKey::from_seed([0xC1; 32]);
        let c_pairing = derive_x25519_pairing_key(&c_device);
        let c_secret = c_pairing.secret_bytes();
        let res = open_vdk_for_new_device(
            &sealed,
            &c_secret,
            &VAULT_A,
            &device_id_from_device_key(&c_device),
            0,
        );
        assert_eq!(res.unwrap_err(), PairingError::OpenFailed);
    }

    /// The set fold mirrors the on-chain authorized set across bootstrap /
    /// add / remove, order-independent of address.
    #[test]
    fn fold_authorized_set_tracks_membership() {
        let a = addr(0xA1);
        let b = addr(0xB2);
        let c = addr(0xC3);
        let events = [
            SetMgmtEvent::Bootstrapped { first_signer: a },
            SetMgmtEvent::Added { signer: b },
            SetMgmtEvent::Added { signer: c },
            SetMgmtEvent::Removed { signer: b },
        ];
        let set = fold_authorized_set(&events);
        assert!(set.contains(&a));
        assert!(set.contains(&c));
        assert!(!set.contains(&b), "removed device is out of the set (L5)");
        assert_eq!(set.len(), 2);
    }

    /// The trigger detection surfaces a locally-known signer that is no
    /// longer in the on-chain set (a removal to queue), and NEVER an in-set
    /// signer.
    #[test]
    fn detect_removed_devices_diffs_against_onchain_set() {
        let a = addr(0xA1);
        let b = addr(0xB2);
        let onchain = [a]; // b was removed on-chain
        let locally_known = [a, b];
        let removed = detect_removed_devices(&onchain, &locally_known);
        assert_eq!(removed, vec![b]);

        // No false positive when everyone is still in the set.
        let none = detect_removed_devices(&[a, b], &[a, b]);
        assert!(none.is_empty());
    }

    /// `resolve_survivors` returns survivors whose pairing pubkey the
    /// directory knows + the unknown-pubkey gap, and NEVER the removed
    /// device (it is absent from the on-chain set by construction, L1).
    #[test]
    fn resolve_survivors_uses_directory_and_flags_unknown() {
        let a = addr(0xA1);
        let b = addr(0xB2);
        let c = addr(0xC3); // in set but pubkey unknown locally
        let dk_a = DeviceKey::from_seed([0x0A; 32]);
        let dk_b = DeviceKey::from_seed([0x0B; 32]);
        let dir = [
            SurvivorDirectoryEntry {
                signer: a,
                device_id: device_id_from_device_key(&dk_a),
                x25519_pairing_pub: *derive_x25519_pairing_key(&dk_a).public_bytes(),
            },
            SurvivorDirectoryEntry {
                signer: b,
                device_id: device_id_from_device_key(&dk_b),
                x25519_pairing_pub: *derive_x25519_pairing_key(&dk_b).public_bytes(),
            },
        ];
        // On-chain set = {a, b, c}; removed device is absent by construction.
        let (survivors, unknown) = resolve_survivors(&[a, b, c], &dir);
        assert_eq!(survivors.len(), 2);
        assert_eq!(unknown, vec![c]);
    }
}
