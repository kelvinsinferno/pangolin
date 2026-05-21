// SPDX-License-Identifier: AGPL-3.0-or-later
//! Exhaustive adversarial tests for the pure VDK-rotation-on-revoke driver
//! (#106b-2).
//!
//! The in-house adversarial audit is the ONLY review before testnet, so
//! these carry the full weight. Load-bearing properties (the L-invariants
//! the gate guards — each "must turn the gate RED if broken"):
//!
//! - **L1 forward secrecy (centerpiece):** after rotation, a SURVIVOR
//!   opens the new-epoch VDK from its seal; the REMOVED device CANNOT (its
//!   pairing key was never sealed to), and a payload under the new VDK does
//!   NOT open under the old VDK.
//! - **L2/L8 escrow re-point:** a guardian recovery off the re-split
//!   reconstructs the NEW VDK (`ct_eq`); the OLD shares reconstruct the OLD
//!   (dead) RWK and FAIL against the new wrapper; a SKIPPED re-point would
//!   recover the OLD VDK (proven by the negative-control test).
//! - **L9 distinct-from-recovery:** rotation mints a NEW VDK (chain grows);
//!   the epoch advances monotonically across multi-rotation n→n+1→n+2.
//! - **Guards:** empty survivor set + guardian-count mismatch are typed
//!   errors before any catastrophic half-rotation.
//! - **Proptest ≥1024** over random `vault_id` / survivor-set / guardian-set /
//!   epoch: every survivor opens the new VDK byte-equal, the removed device
//!   never appears in the seal set, and the escrow recovers the new VDK.

use super::*;
use pangolin_crypto::escrow::{
    open_sealed_share, reconstruct_rwk, unwrap_vdk_under_rwk, EscrowError, Share,
};
use pangolin_crypto::keys::DeviceKey;
use pangolin_crypto::pairing::{derive_x25519_pairing_key, open_vdk_from_pairing};

const VAULT_A: [u8; VAULT_ID_LEN] = [0xAA; VAULT_ID_LEN];

/// Build a surviving device from a deterministic seed: its `device_id`,
/// its X25519 pairing pubkey (the public input the driver seals to), and
/// its pairing secret scalar (for opening, test-side only).
fn survivor(seed: u8) -> (SurvivingDevice, [u8; X25519_KEY_LEN]) {
    let dev = DeviceKey::from_seed([seed; 32]);
    let pairing = derive_x25519_pairing_key(&dev);
    let device_id = [seed; DEVICE_ID_LEN];
    (
        SurvivingDevice {
            device_id,
            x25519_pairing_pub: *pairing.public_bytes(),
        },
        *pairing.secret_bytes(),
    )
}

/// Build `M` guardian keypairs from deterministic seeds; return their
/// X25519 (secret, public) byte pairs. Mirrors the orchestration test
/// helper.
fn guardians(m: u8) -> Vec<([u8; X25519_KEY_LEN], [u8; X25519_KEY_LEN])> {
    use pangolin_crypto::guardian::derive_x25519_sealing_key;
    (0..m)
        .map(|i| {
            let dev = DeviceKey::from_seed([0xC0 + i; 32]);
            let k = derive_x25519_sealing_key(&dev);
            (*k.secret_bytes(), *k.public_bytes())
        })
        .collect()
}

fn gpubs(gs: &[([u8; X25519_KEY_LEN], [u8; X25519_KEY_LEN])]) -> Vec<[u8; X25519_KEY_LEN]> {
    gs.iter().map(|(_, p)| *p).collect()
}

const CFG_3_5: GuardianSetConfig = GuardianSetConfig {
    threshold: 3,
    guardian_count: 5,
};

// =========================================================================
// L1 — forward secrecy (the centerpiece)
// =========================================================================

/// Mint `VDK_n`'s set {A,B,C}, revoke C, rotate to {A,B}: A and B open the
/// new-epoch VDK from their seals (byte-identical), C CANNOT open the new
/// VDK (its pairing key was never sealed to), and a value under the new VDK
/// does not appear in the old VDK's bytes. Re-keying to C would break this.
#[test]
fn forward_secrecy_survivors_open_removed_device_locked_out() {
    let (a, a_sec) = survivor(0x0A);
    let (b, b_sec) = survivor(0x0B);
    // The REMOVED device C: build it as a would-be survivor only to derive
    // its pairing secret for the negative assertion — it is NOT passed to
    // the driver.
    let (c, c_sec) = survivor(0x0C);

    let gs = guardians(5);
    let art = rotate_vdk_for_survivors(&[a, b], &VAULT_A, CFG_3_5, &gpubs(&gs), RecoveryEpoch(4))
        .expect("rotation");

    assert_eq!(art.new_epoch, RecoveryEpoch(5), "epoch advances n->n+1");
    assert_eq!(art.survivor_seals.len(), 2, "exactly the two survivors");

    let epoch_bytes = art.new_epoch.to_escrow_bytes();

    // A and B open the new VDK byte-identically from their seals.
    for (dev, sec) in [(&a, &a_sec), (&b, &b_sec)] {
        let seal = art
            .survivor_seals
            .iter()
            .find(|s| s.device_id == dev.device_id)
            .expect("survivor has a seal");
        let opened =
            open_vdk_from_pairing(&seal.sealed, sec, &VAULT_A, &dev.device_id, &epoch_bytes)
                .expect("survivor opens its seal");
        assert!(
            bool::from(art.new_vdk.ct_eq(&opened)),
            "survivor must recover the byte-identical new VDK (L1)"
        );
    }

    // The removed device C is NEVER in the seal set (L1, structural).
    assert!(
        !art.survivor_seals
            .iter()
            .any(|s| s.device_id == c.device_id),
        "the removed device must NEVER appear in the survivor seal set"
    );

    // C cannot open ANY survivor's seal with its own pairing secret — the
    // seals are sealed to A's/B's X25519 pubkeys, not C's.
    for s in &art.survivor_seals {
        let attempt =
            open_vdk_from_pairing(&s.sealed, &c_sec, &VAULT_A, &s.device_id, &epoch_bytes);
        assert!(
            attempt.is_err(),
            "removed device C must NOT open any survivor's new-epoch seal (L1)"
        );
    }
}

/// A payload encrypted under the NEW VDK does not decrypt under an OLD
/// VDK (the rotation genuinely produced a fresh key, not a re-wrap).
#[test]
fn new_vdk_payload_does_not_open_under_old_vdk() {
    use pangolin_crypto::aead::Nonce;
    let old_vdk = VdkKey::generate();
    let (a, _a_sec) = survivor(0x0A);
    let gs = guardians(5);
    let art =
        rotate_vdk_for_survivors(&[a], &VAULT_A, CFG_3_5, &gpubs(&gs), RecoveryEpoch::GENESIS)
            .expect("rotation");

    // The new VDK is a fresh key, distinct from the old.
    assert!(
        !bool::from(old_vdk.ct_eq(&art.new_vdk)),
        "rotation must mint a FRESH VDK distinct from the pre-revoke one"
    );

    // Encrypt a payload under the new VDK; it must NOT open under the old.
    let nonce = Nonce::random();
    let aad = b"rotation-fwd-secrecy-test";
    let ct = art
        .new_vdk
        .aead_key()
        .seal(&nonce, b"post-revoke secret", aad)
        .unwrap();
    assert!(
        old_vdk.aead_key().open(&nonce, &ct, aad).is_err(),
        "a post-revoke payload must NOT open under the pre-revoke VDK (forward secrecy)"
    );
    // Sanity: it DOES open under the new VDK.
    assert_eq!(
        art.new_vdk.aead_key().open(&nonce, &ct, aad).unwrap(),
        b"post-revoke secret"
    );
}

// =========================================================================
// L2/L8 — escrow re-point (THE crux)
// =========================================================================

/// After rotation, reconstruct the RWK from `t` FRESH shares and unwrap
/// the new wrapper → the NEW VDK byte-identical. The escrow now recovers
/// the live key, not the dead pre-revoke one.
#[test]
fn escrow_repoint_recovers_new_vdk_from_fresh_shares() {
    let (a, _a_sec) = survivor(0x0A);
    let gs = guardians(5);
    let art = rotate_vdk_for_survivors(&[a], &VAULT_A, CFG_3_5, &gpubs(&gs), RecoveryEpoch(1))
        .expect("rotation");

    let e = art.new_epoch.to_escrow_bytes();
    // Guardians 0,2,4 release their fresh shares (t=3).
    let opened: Vec<Share> = [0usize, 2, 4]
        .iter()
        .map(|&i| {
            open_sealed_share(
                &art.re_split.assignments[i].sealed_share,
                &gs[i].0,
                &VAULT_A,
                &e,
            )
            .unwrap()
        })
        .collect();
    let rwk = reconstruct_rwk(&opened).unwrap();
    let recovered = unwrap_vdk_under_rwk(&art.re_split.wrapped_recovery, &rwk).unwrap();
    assert!(
        bool::from(art.new_vdk.ct_eq(&recovered)),
        "the re-pointed escrow must recover the NEW VDK (L2/L8)"
    );
}

/// NEGATIVE CONTROL (the guarded catastrophe): if a rotation SKIPPED the
/// re-point, a guardian recovery off the OLD escrow generation would
/// recover the OLD (dead) VDK. We simulate this by building the OLD escrow
/// against the OLD VDK and showing it recovers the OLD VDK — i.e. a skipped
/// re-point strands the user. The genuine path's re-split (proven above)
/// recovers the NEW VDK, AND the OLD shares fail against the NEW wrapper
/// (proven here), so skipping the re-point is detectably wrong.
#[test]
fn skipped_repoint_would_recover_old_vdk_and_old_shares_fail_against_new() {
    // The pre-revoke escrow generation: onboard the OLD VDK at the old epoch.
    let old_vdk = VdkKey::generate();
    let gs = guardians(5);
    let old_escrow =
        onboard_guardian_escrow(&old_vdk, &VAULT_A, CFG_3_5, &gpubs(&gs), RecoveryEpoch(1))
            .unwrap();

    // The genuine rotation re-points at the NEW VDK at the bumped epoch.
    let (a, _a_sec) = survivor(0x0A);
    let art = rotate_vdk_for_survivors(&[a], &VAULT_A, CFG_3_5, &gpubs(&gs), RecoveryEpoch(1))
        .expect("rotation");

    // Had the re-point been SKIPPED (old escrow left in place), recovery off
    // the OLD shares recovers the OLD (dead) VDK — the catastrophe.
    let e_old = old_escrow.epoch.to_escrow_bytes();
    let old_opened: Vec<Share> = [0usize, 1, 2]
        .iter()
        .map(|&i| {
            open_sealed_share(
                &old_escrow.assignments[i].sealed_share,
                &gs[i].0,
                &VAULT_A,
                &e_old,
            )
            .unwrap()
        })
        .collect();
    let rwk_old = reconstruct_rwk(&old_opened).unwrap();
    let recovered_old = unwrap_vdk_under_rwk(&old_escrow.wrapped_recovery, &rwk_old).unwrap();
    assert!(
        bool::from(old_vdk.ct_eq(&recovered_old)),
        "skipped re-point would recover the OLD VDK (the guarded catastrophe)"
    );
    assert!(
        !bool::from(art.new_vdk.ct_eq(&recovered_old)),
        "the OLD escrow recovers the OLD VDK, NOT the new one — a skipped re-point strands the user"
    );

    // And the OLD shares (reconstructing the OLD RWK) FAIL against the NEW
    // (re-pointed) wrapper — old guardian releases can't open the new VDK.
    let attempt = unwrap_vdk_under_rwk(&art.re_split.wrapped_recovery, &rwk_old);
    assert_eq!(
        attempt.unwrap_err(),
        EscrowError::WrapFailed,
        "OLD shares must NOT unwrap the re-pointed (new-VDK) escrow (L2/L8)"
    );
}

// =========================================================================
// L9 / L5 — distinct from recovery; monotonic epoch over multi-rotation
// =========================================================================

/// Multi-rotation n→n+1→n+2: each rotation mints a DISTINCT new VDK and
/// advances the shared epoch monotonically; each generation's escrow
/// recovers ITS new VDK.
#[test]
fn multi_rotation_advances_epoch_and_mints_distinct_vdks() {
    let gs = guardians(5);
    let (a, _a) = survivor(0x0A);

    let r1 = rotate_vdk_for_survivors(&[a], &VAULT_A, CFG_3_5, &gpubs(&gs), RecoveryEpoch(7))
        .expect("rotation 1");
    let r2 = rotate_vdk_for_survivors(&[a], &VAULT_A, CFG_3_5, &gpubs(&gs), r1.new_epoch)
        .expect("rotation 2");

    assert_eq!(r1.new_epoch, RecoveryEpoch(8));
    assert_eq!(
        r2.new_epoch,
        RecoveryEpoch(9),
        "epoch advances monotonically"
    );
    assert!(
        !bool::from(r1.new_vdk.ct_eq(&r2.new_vdk)),
        "each rotation mints a DISTINCT new VDK (chain grows; L9)"
    );

    // r2's escrow recovers r2's VDK.
    let e = r2.new_epoch.to_escrow_bytes();
    let opened: Vec<Share> = [0usize, 1, 2]
        .iter()
        .map(|&i| {
            open_sealed_share(
                &r2.re_split.assignments[i].sealed_share,
                &gs[i].0,
                &VAULT_A,
                &e,
            )
            .unwrap()
        })
        .collect();
    let rwk = reconstruct_rwk(&opened).unwrap();
    let recovered = unwrap_vdk_under_rwk(&r2.re_split.wrapped_recovery, &rwk).unwrap();
    assert!(bool::from(r2.new_vdk.ct_eq(&recovered)));
}

// =========================================================================
// Guards
// =========================================================================

/// An empty survivor set is a typed error (a vault nobody can open) — never
/// a half-rotation.
#[test]
fn empty_survivor_set_rejected() {
    let gs = guardians(5);
    let err = rotate_vdk_for_survivors(&[], &VAULT_A, CFG_3_5, &gpubs(&gs), RecoveryEpoch::GENESIS)
        .unwrap_err();
    assert_eq!(err, RotationError::NoSurvivors);
}

/// A guardian pubkey count != M is a typed escrow-re-point error.
#[test]
fn guardian_count_mismatch_rejected() {
    let (a, _a) = survivor(0x0A);
    let gs = guardians(3); // only 3 pubkeys for an M=5 config
    let err =
        rotate_vdk_for_survivors(&[a], &VAULT_A, CFG_3_5, &gpubs(&gs), RecoveryEpoch::GENESIS)
            .unwrap_err();
    assert!(
        matches!(
            err,
            RotationError::EscrowRePoint(RecoveryOrchestrationError::GuardianCountMismatch {
                expected: 5,
                got: 3
            })
        ),
        "expected guardian-count mismatch, got {err:?}"
    );
}

/// An invalid (t, M) is a typed escrow-re-point error before any seal.
#[test]
fn invalid_guardian_set_rejected() {
    let (a, _a) = survivor(0x0A);
    let bad = GuardianSetConfig {
        threshold: 1, // below MIN_THRESHOLD
        guardian_count: 5,
    };
    let gs = guardians(5);
    let err = rotate_vdk_for_survivors(&[a], &VAULT_A, bad, &gpubs(&gs), RecoveryEpoch::GENESIS)
        .unwrap_err();
    assert!(matches!(
        err,
        RotationError::EscrowRePoint(RecoveryOrchestrationError::InvalidGuardianSet(_))
    ));
}

/// `RotationError` Display is non-empty for every variant (log hygiene).
#[test]
fn rotation_error_display_is_populated() {
    for e in [
        RotationError::NoSurvivors,
        RotationError::Pairing(pangolin_crypto::pairing::PairingError::SealFailed),
        RotationError::EscrowRePoint(RecoveryOrchestrationError::InsufficientShares {
            threshold: 3,
            got: 1,
        }),
    ] {
        assert!(!format!("{e}").is_empty());
    }
}

// =========================================================================
// Proptest ≥1024 — random vault_id / survivor-set / guardian-set / epoch
// =========================================================================

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig {
        cases: 1024,
        ..proptest::prelude::ProptestConfig::default()
    })]

    #[test]
    fn proptest_rotation_round_trip(
        vault_id in proptest::prelude::any::<[u8; VAULT_ID_LEN]>(),
        n_survivors in 1usize..=6usize,
        survivor_seed in proptest::prelude::any::<u8>(),
        removed_seed in proptest::prelude::any::<u8>(),
        t in 2u8..=9u8,
        extra in 0u8..=12u8,
        epoch_lo in proptest::prelude::any::<u64>(),
        pick_seed in proptest::prelude::any::<u64>(),
    ) {
        // Build n DISTINCT survivors from spread-out seeds (avoid colliding
        // with the removed-device seed). Each seed maps to a distinct
        // device_id + pairing key.
        let mut survivors = Vec::new();
        let mut secrets = Vec::new();
        for k in 0..n_survivors {
            let seed = survivor_seed.wrapping_add(u8::try_from(k).unwrap().wrapping_mul(7)).wrapping_add(1);
            // Skip a seed equal to the removed device's so the removed
            // device is genuinely outside the survivor set.
            let seed = if seed == removed_seed { seed.wrapping_add(101) } else { seed };
            let (s, sec) = survivor(seed);
            survivors.push(s);
            secrets.push(sec);
        }
        // The removed device: NOT in the survivor set.
        let (removed, removed_sec) = survivor(removed_seed);

        // M = clamp(t+extra) into [max(t,3), 15].
        let m = (t + extra).clamp(3, 15).max(t);
        let cfg = GuardianSetConfig { threshold: t, guardian_count: m };
        let gs = guardians(m);
        // Saturate the epoch so next() never overflows the assertion.
        let epoch = RecoveryEpoch(epoch_lo.min(u64::MAX - 1));

        let art = rotate_vdk_for_survivors(&survivors, &vault_id, cfg, &gpubs(&gs), epoch).unwrap();

        proptest::prop_assert_eq!(art.new_epoch, epoch.next());
        proptest::prop_assert_eq!(art.survivor_seals.len(), n_survivors);

        let e = art.new_epoch.to_escrow_bytes();

        // Every survivor opens its seal byte-equal to the new VDK.
        for (s, sec) in survivors.iter().zip(secrets.iter()) {
            let seal = art.survivor_seals.iter().find(|x| x.device_id == s.device_id).unwrap();
            let opened = open_vdk_from_pairing(&seal.sealed, sec, &vault_id, &s.device_id, &e).unwrap();
            proptest::prop_assert!(bool::from(art.new_vdk.ct_eq(&opened)));
        }

        // The removed device is never in the seal set, and (if its seed is
        // distinct from every survivor) cannot open any seal.
        let removed_is_distinct = !survivors.iter().any(|s| s.device_id == removed.device_id);
        if removed_is_distinct {
            proptest::prop_assert!(!art.survivor_seals.iter().any(|s| s.device_id == removed.device_id));
            for s in &art.survivor_seals {
                proptest::prop_assert!(
                    open_vdk_from_pairing(&s.sealed, &removed_sec, &vault_id, &s.device_id, &e).is_err()
                );
            }
        }

        // The escrow re-point recovers the new VDK from a pseudo-random
        // t-subset of fresh shares.
        let mut order: Vec<usize> = (0..usize::from(m)).collect();
        let mut state = pick_seed | 1;
        for i in (1..order.len()).rev() {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let j = (state >> 33) as usize % (i + 1);
            order.swap(i, j);
        }
        let opened: Vec<Share> = order[..usize::from(t)]
            .iter()
            .map(|&i| {
                open_sealed_share(&art.re_split.assignments[i].sealed_share, &gs[i].0, &vault_id, &e).unwrap()
            })
            .collect();
        let rwk = reconstruct_rwk(&opened).unwrap();
        let recovered = unwrap_vdk_under_rwk(&art.re_split.wrapped_recovery, &rwk).unwrap();
        proptest::prop_assert!(bool::from(art.new_vdk.ct_eq(&recovered)));
    }
}
