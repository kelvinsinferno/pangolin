// SPDX-License-Identifier: AGPL-3.0-or-later
//! #106e-0 HERMETIC composition test — the PUBLIC `complete_rotation`
//! orchestration glue (GAP-A surfacing + the Q-e pending-rotation loop)
//! driven WITHOUT a live chain.
//!
//! `complete_rotation` makes NO chain calls: it takes the live authorized set
//! as a plain `&[[u8; 20]]` parameter and only touches the local DB (the
//! survivor directory, the recovery-escrow params, the audited
//! `commit_vdk_rotation_from_active`, and the rotation-pending rows). So its
//! GAP-A list mechanics and the Q-e "resolve only signers absent from the live
//! set" loop are pure local logic that can — and must — be regression-gated
//! hermetically. The coupled anvil E2E
//! (`anvil_device_e2e::complete_rotation_public_composition_e2e_against_anvil`)
//! still exercises the same path against a live on-chain set, but it is
//! `#[ignore]`'d, so without these tests a regression to this glue (e.g.
//! clearing ALL pending rows unconditionally) would pass the default suite.

use pangolin_core::composition::complete_rotation;
use pangolin_core::device_add::device_id_from_device_key;
use pangolin_crypto::guardian::derive_x25519_sealing_key;
use pangolin_crypto::keys::DeviceKey;
use pangolin_crypto::pairing::derive_x25519_pairing_key;
use pangolin_crypto::secret::SecretBytes;
use pangolin_store::{PinIdentityProof, PressYPresenceProof, Vault, VaultState};

// Synthetic 20-byte secp256k1 signers — `resolve_survivors` / the Q-e loop key
// purely on these opaque bytes (the directory maps signer -> pairing inputs), so
// no real EVM-wallet derivation is needed for the local logic.
const A_SIGNER: [u8; 20] = [0xA1; 20];
const B_SIGNER: [u8; 20] = [0xB2; 20];
const C_SIGNER: [u8; 20] = [0xC3; 20];

const PWD: &[u8] = b"rotation hermetic master pw";

fn create_unlocked_vault(dir: &tempfile::TempDir) -> Vault {
    let path = dir.path().join("rotation.pvf");
    let pwd = SecretBytes::new(PWD.to_vec());
    Vault::create(&path, &pwd).expect("create vault");
    let mut vault = Vault::open(&path).expect("open vault");
    vault
        .unlock(
            &PressYPresenceProof::confirmed(),
            &PinIdentityProof::new(SecretBytes::new(PWD.to_vec())),
        )
        .expect("unlock");
    vault
}

/// Record `signer -> (device_id, pairing_pub)` for a real device key, so the
/// signer resolves to a survivor with a valid X25519 pairing pubkey to seal to.
fn record_known_device(vault: &Vault, signer: [u8; 20], seed: [u8; 32]) {
    let device = DeviceKey::from_seed(seed);
    vault
        .record_device_directory_entry(
            signer,
            device_id_from_device_key(&device),
            *derive_x25519_pairing_key(&device).public_bytes(),
        )
        .expect("record directory entry");
}

/// Mint a 2-of-3 recovery escrow over the active VDK so `complete_rotation`
/// can read its params + re-point it.
fn onboard_escrow(vault: &mut Vault, epoch: u64) {
    let guardian_pubs: Vec<[u8; 32]> = (0u8..3)
        .map(|i| {
            let g = DeviceKey::from_seed([0xE0_u8.wrapping_add(i); 32]);
            *derive_x25519_sealing_key(&g).public_bytes()
        })
        .collect();
    vault
        .__test_onboard_recovery_escrow(2, &guardian_pubs, epoch)
        .expect("onboard escrow over active VDK");
}

/// GAP-A + Q-e (positive): A is a known survivor, C is in-set but its pairing
/// pubkey is unknown locally (must surface in `unknown_survivors`), B was
/// removed (absent from the live set) and its pending row must clear.
#[test]
fn complete_rotation_surfaces_unknown_survivor_and_clears_retired_pending() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let mut vault = create_unlocked_vault(&dir);

    // The local directory knows A but NOT C.
    record_known_device(&vault, A_SIGNER, [0x0A; 32]);
    onboard_escrow(&mut vault, 0);

    // The live set after a revoke of B: A + C (B gone).
    let current_onchain_set = vec![A_SIGNER, C_SIGNER];

    // The DeviceRemoved trigger queues a rotation-pending row for B (absent).
    let queued = vault
        .process_device_removed_trigger(&current_onchain_set, &[A_SIGNER, B_SIGNER, C_SIGNER], 0)
        .expect("process DeviceRemoved trigger");
    assert_eq!(queued, 1, "exactly one removal queued (B)");
    assert_eq!(vault.pending_rotations().expect("pending").len(), 1);

    let new_password = SecretBytes::new(b"post-revoke master pw".to_vec());
    let outcome = complete_rotation(&mut vault, &new_password, &current_onchain_set)
        .expect("complete_rotation");

    assert_eq!(
        outcome.new_epoch, 1,
        "the shared epoch advances on rotation"
    );
    // GAP-A: C is in-set but locally-unknown — surfaced, never silently stranded.
    assert_eq!(
        outcome.unknown_survivors,
        vec![C_SIGNER],
        "the in-set-but-unknown survivor C surfaces in unknown_survivors (GAP-A)"
    );
    assert_eq!(vault.state(), VaultState::Locked);
    // Q-e: B's pending row (B absent from the live set) is retired.
    assert!(
        vault.pending_rotations().expect("pending").is_empty(),
        "the retired removal (B) clears after complete_rotation (Q-e)"
    );

    // prompt-on-revoke: the OLD password no longer opens; the NEW one does.
    let old_err = vault
        .unlock(
            &PressYPresenceProof::confirmed(),
            &PinIdentityProof::new(SecretBytes::new(PWD.to_vec())),
        )
        .unwrap_err();
    assert!(matches!(
        old_err,
        pangolin_store::StoreError::AuthenticationFailed
    ));
    vault
        .unlock(
            &PressYPresenceProof::confirmed(),
            &PinIdentityProof::new(SecretBytes::new(b"post-revoke master pw".to_vec())),
        )
        .expect("NEW password opens the rotated vault");
    assert_eq!(vault.state(), VaultState::Active);
}

/// Q-e (the DANGEROUS direction — discrimination): a pending row whose signer
/// is STILL in the live authorized set must NOT be cleared by a rotation. If
/// the loop ever "simplifies" to clear all pending rows unconditionally, this
/// goes RED — guarding against an under-revocation echo of the #106d MEDIUM
/// (a removal marked resolved without actually being rotated against).
#[test]
fn complete_rotation_keeps_pending_for_still_in_set_signer() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let mut vault = create_unlocked_vault(&dir);

    // A and B are both known survivors.
    record_known_device(&vault, A_SIGNER, [0x0A; 32]);
    record_known_device(&vault, B_SIGNER, [0x0B; 32]);
    onboard_escrow(&mut vault, 0);

    // Queue a pending row for B while B is absent (a transient earlier state).
    let queued = vault
        .process_device_removed_trigger(&[A_SIGNER], &[A_SIGNER, B_SIGNER], 0)
        .expect("queue pending for B");
    assert_eq!(queued, 1);
    assert_eq!(vault.pending_rotations().expect("pending").len(), 1);

    // Now B is BACK in the live set (re-added). A rotation against [A, B] must
    // leave B's pending row UNTOUCHED — B is honored again.
    let current_onchain_set = vec![A_SIGNER, B_SIGNER];
    let new_password = SecretBytes::new(b"post-rotation master pw".to_vec());
    let outcome = complete_rotation(&mut vault, &new_password, &current_onchain_set)
        .expect("complete_rotation");
    assert_eq!(outcome.new_epoch, 1);

    let pending = vault.pending_rotations().expect("pending");
    assert_eq!(
        pending.len(),
        1,
        "a pending row for a signer STILL in the live set must NOT be cleared"
    );
    assert_eq!(
        pending[0].removed_signer, B_SIGNER,
        "B's pending row survives because B is back in the authorized set"
    );
}
