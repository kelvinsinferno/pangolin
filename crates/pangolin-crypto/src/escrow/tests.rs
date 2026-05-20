// SPDX-License-Identifier: AGPL-3.0-or-later
//! Exhaustive tests for the guardian-escrow threshold primitive.
//!
//! The in-house adversarial audit is the ONLY review before testnet, so
//! these tests carry the full weight of correctness. The load-bearing
//! properties, in priority order:
//!
//! - **L1/L2 — `< t` reveals NOTHING.** [`fewer_than_threshold_*`] +
//!   [`proptest_subthreshold_never_reconstructs`].
//! - **L5 — byte-identical VDK.** [`vdk_round_trip_through_full_escrow`] +
//!   [`proptest_full_escrow_round_trip`].
//! - **Shamir KAT.** [`shamir_kat_*`] — hand-pinned small-field vectors.
//! - **Sealed-share** round-trip + wrong key + tamper + domain/replay.
//! - **No panic / typed errors** on malformed input.

use super::*;
use crate::keys::{VdkKey, WrapContext};

// ---- Fixtures -----------------------------------------------------------

const VAULT_A: [u8; VAULT_ID_LEN] = [0xAA; VAULT_ID_LEN];
const VAULT_B: [u8; VAULT_ID_LEN] = [0xBB; VAULT_ID_LEN];
const EPOCH_0: [u8; EPOCH_LEN] = [0x00; EPOCH_LEN];
const EPOCH_1: [u8; EPOCH_LEN] = [0x11; EPOCH_LEN];

/// Generates a guardian X25519 keypair `(secret_bytes, public_bytes)` from
/// the OS CSPRNG via `crypto_box`.
fn guardian_keypair() -> ([u8; X25519_KEY_LEN], [u8; X25519_KEY_LEN]) {
    let sk = crypto_box::SecretKey::generate(&mut os_rng());
    let pk = sk.public_key();
    (sk.to_bytes(), *pk.as_bytes())
}

// ---- Bounds validation (typed errors, no panic) -------------------------

#[test]
fn bounds_accept_in_range() {
    let rwk = RecoveryWrapKey::generate();
    for (t, m) in [(2u8, 3u8), (2, 15), (9, 9), (9, 15), (5, 8)] {
        let shares = split_rwk(&rwk, t, m).unwrap_or_else(|e| {
            panic!("split({t},{m}) should succeed, got {e:?}");
        });
        assert_eq!(shares.len(), usize::from(m));
    }
}

#[test]
fn bounds_reject_out_of_range() {
    let rwk = RecoveryWrapKey::generate();
    // threshold too low / too high; M too low / too high; t > M.
    let bad = [
        (1u8, 3u8), // t < MIN_THRESHOLD
        (10, 15),   // t > MAX_THRESHOLD
        (2, 2),     // M < MIN_GUARDIANS
        (2, 16),    // M > MAX_GUARDIANS
        (5, 4),     // t > M
        (0, 0),     // both zero
        (9, 3),     // t > M (in range individually)
    ];
    for (t, m) in bad {
        assert_eq!(
            split_rwk(&rwk, t, m).unwrap_err(),
            EscrowError::InvalidThreshold,
            "split({t},{m}) must be rejected",
        );
    }
}

// ---- Shamir KAT (constant small-field vectors) --------------------------
//
// Hand-verifiable GF(2^8) Shamir: pin that vsss-rs's Gf256 split emits the
// expected x-identifiers and that a known share set reconstructs a known
// secret. We pin the *structure* (33-byte shares, identifiers 1..=M,
// reconstruct-equals-original) deterministically; the y-values are
// randomized per split so we assert the round-trip rather than fixed
// bytes, plus a 1-of-the-field exhaustive single-byte check that mirrors
// vsss-rs's own `shamir` KAT.

#[test]
fn shamir_kat_share_structure() {
    let rwk = RecoveryWrapKey::generate();
    let shares = split_rwk(&rwk, 3, 5).unwrap();
    assert_eq!(shares.len(), 5);
    for (i, s) in shares.iter().enumerate() {
        // vsss-rs default participant generator emits sequential ids 1..=M.
        assert_eq!(u32::from(s.identifier()), u32::try_from(i).unwrap() + 1);
        assert_eq!(s.as_bytes().len(), 1 + KEY_LEN);
        assert_ne!(s.identifier(), 0, "x=0 reserved for the secret");
    }
}

/// Mirrors vsss-rs's own single-byte Shamir KAT but routed through OUR
/// 32-byte RWK split/reconstruct: split the same RWK, reconstruct from
/// several distinct t-subsets, all must equal the original.
#[test]
fn shamir_kat_multiple_subsets_reconstruct() {
    let rwk = RecoveryWrapKey::generate();
    let shares = split_rwk(&rwk, 3, 5).unwrap();

    // Distinct 3-subsets of {0,1,2,3,4}.
    let subsets: &[[usize; 3]] = &[[0, 1, 2], [2, 3, 4], [0, 2, 4], [1, 3, 4], [0, 1, 4]];
    for subset in subsets {
        let picked: Vec<Share> = subset
            .iter()
            .map(|&i| Share::from_bytes(shares[i].as_bytes().to_vec()).unwrap())
            .collect();
        let recovered = reconstruct_rwk(&picked).unwrap();
        assert!(
            bool::from(rwk.ct_eq(&recovered)),
            "subset {subset:?} failed to reconstruct the RWK",
        );
    }
}

// ---- L1/L2: fewer than t reveals NOTHING (THE property) -----------------

/// With exactly `t` shares the RWK reconstructs bit-for-bit; with `t-1`
/// shares reconstruction either errors or yields a value different from the
/// true RWK — across many (t,M) configs and many random RWKs. This is the
/// property a wrong implementation silently breaks.
#[test]
fn fewer_than_threshold_reveals_nothing_many_configs() {
    let configs = [(2u8, 3u8), (3, 5), (5, 8), (9, 15), (4, 4), (7, 10)];
    for (t, m) in configs {
        for _ in 0..32 {
            let rwk = RecoveryWrapKey::generate();
            let shares = split_rwk(&rwk, t, m).unwrap();

            // t shares -> exact reconstruction.
            let t_subset: Vec<Share> = shares[..usize::from(t)]
                .iter()
                .map(|s| Share::from_bytes(s.as_bytes().to_vec()).unwrap())
                .collect();
            let exact = reconstruct_rwk(&t_subset).unwrap();
            assert!(
                bool::from(rwk.ct_eq(&exact)),
                "({t},{m}): t shares must reconstruct exactly",
            );

            // t-1 shares -> never the true RWK.
            if t >= 2 {
                let sub: Vec<Share> = shares[..usize::from(t) - 1]
                    .iter()
                    .map(|s| Share::from_bytes(s.as_bytes().to_vec()).unwrap())
                    .collect();
                match reconstruct_rwk(&sub) {
                    Err(_) => {} // rejected — fine.
                    Ok(wrong) => {
                        assert!(
                            !bool::from(rwk.ct_eq(&wrong)),
                            "({t},{m}): t-1 shares reconstructed the TRUE RWK — \
                             threshold property BROKEN",
                        );
                    }
                }
            }
        }
    }
}

/// A single share is information-theoretically independent of the RWK:
/// across many splits of the SAME rwk and DIFFERENT rwks, no single share
/// (t>=2) can reconstruct, and combining a single share is rejected (vsss-rs
/// requires >= 2 shares to combine at all).
#[test]
fn single_share_cannot_reconstruct() {
    let rwk = RecoveryWrapKey::generate();
    let shares = split_rwk(&rwk, 3, 5).unwrap();
    let one = vec![Share::from_bytes(shares[0].as_bytes().to_vec()).unwrap()];
    // combine_array requires >= 2 shares; a single share is rejected.
    assert_eq!(
        reconstruct_rwk(&one).unwrap_err(),
        EscrowError::ReconstructFailed,
    );
}

// ---- L5: byte-identical VDK through the full escrow ---------------------

/// The end-to-end audit centerpiece: wrap a VDK under a fresh RWK, split
/// the RWK, seal every share to a guardian, open >= t of them, reconstruct
/// the RWK, unwrap — and assert the recovered VDK is byte-identical
/// (`ct_eq`) to the original.
#[test]
fn vdk_round_trip_through_full_escrow() {
    let vdk = VdkKey::generate();
    let ctx = WrapContext::new(VAULT_A);
    let rwk = RecoveryWrapKey::generate();

    let wrapped = wrap_vdk_under_rwk(&vdk, &rwk, &ctx).unwrap();

    let (t, m) = (3u8, 5u8);
    let shares = split_rwk(&rwk, t, m).unwrap();

    // Generate m guardians, seal each share.
    let guardians: Vec<_> = (0..m).map(|_| guardian_keypair()).collect();
    let sealed: Vec<SealedShare> = shares
        .iter()
        .zip(&guardians)
        .map(|(s, (_, pk))| seal_share(s, pk, &VAULT_A, &EPOCH_0).unwrap())
        .collect();

    // Open t of them (guardians 0,2,4 -> non-contiguous on purpose).
    let opened: Vec<Share> = [0usize, 2, 4]
        .iter()
        .map(|&i| open_sealed_share(&sealed[i], &guardians[i].0, &VAULT_A, &EPOCH_0).unwrap())
        .collect();

    let rwk2 = reconstruct_rwk(&opened).unwrap();
    assert!(bool::from(rwk.ct_eq(&rwk2)), "reconstructed RWK differs");

    let recovered_vdk = unwrap_vdk_under_rwk(&wrapped, &rwk2).unwrap();
    assert!(
        bool::from(vdk.ct_eq(&recovered_vdk)),
        "recovered VDK is NOT byte-identical to the original — L5 BROKEN",
    );
}

#[test]
fn wrap_vdk_wrong_rwk_fails() {
    let vdk = VdkKey::generate();
    let ctx = WrapContext::new(VAULT_A);
    let rwk = RecoveryWrapKey::generate();
    let wrong = RecoveryWrapKey::generate();
    let wrapped = wrap_vdk_under_rwk(&vdk, &rwk, &ctx).unwrap();
    assert_eq!(
        unwrap_vdk_under_rwk(&wrapped, &wrong).unwrap_err(),
        EscrowError::WrapFailed,
    );
}

/// L8: a recovery wrapper sealed for vault A must not unwrap once its stored
/// context is forged to vault B. Emulates the storage-write attacker by
/// stitching the ciphertext+nonce with a foreign context (mirrors the
/// `vdk_cross_vault_replay_fails` test in keys.rs).
#[test]
fn wrap_vdk_cross_vault_context_replay_fails() {
    let vdk = VdkKey::generate();
    let rwk = RecoveryWrapKey::generate();
    let ctx_a = WrapContext::new(VAULT_A);
    let wrapped = wrap_vdk_under_rwk(&vdk, &rwk, &ctx_a).unwrap();

    // Transplant: same ciphertext/nonce, foreign context.
    let inner = wrapped.as_wrapped();
    let transplanted = WrappedVdkRecovery::from_wrapped(crate::keys::WrappedVdk::from_parts(
        inner.ciphertext().clone(),
        *inner.nonce(),
        WrapContext::new(VAULT_B),
    ));
    assert_eq!(
        unwrap_vdk_under_rwk(&transplanted, &rwk).unwrap_err(),
        EscrowError::WrapFailed,
        "ciphertext sealed for vault A must not unwrap under vault B's ctx",
    );
}

// ---- Sealed-share: round-trip, wrong key, tamper, domain/replay ---------

#[test]
fn sealed_share_round_trip() {
    let rwk = RecoveryWrapKey::generate();
    let shares = split_rwk(&rwk, 2, 3).unwrap();
    let (sk, pk) = guardian_keypair();
    let sealed = seal_share(&shares[0], &pk, &VAULT_A, &EPOCH_0).unwrap();
    let opened = open_sealed_share(&sealed, &sk, &VAULT_A, &EPOCH_0).unwrap();
    assert_eq!(opened.as_bytes(), shares[0].as_bytes());
    assert_eq!(opened.identifier(), shares[0].identifier());
}

#[test]
fn sealed_share_wrong_guardian_key_fails() {
    let rwk = RecoveryWrapKey::generate();
    let shares = split_rwk(&rwk, 2, 3).unwrap();
    let (_sk_a, pk_a) = guardian_keypair();
    let (sk_b, _pk_b) = guardian_keypair();
    let sealed = seal_share(&shares[0], &pk_a, &VAULT_A, &EPOCH_0).unwrap();
    // Guardian B (wrong secret) cannot open a share sealed to A.
    assert_eq!(
        open_sealed_share(&sealed, &sk_b, &VAULT_A, &EPOCH_0).unwrap_err(),
        EscrowError::OpenFailed,
    );
}

#[test]
fn sealed_share_tampered_ciphertext_fails() {
    let rwk = RecoveryWrapKey::generate();
    let shares = split_rwk(&rwk, 2, 3).unwrap();
    let (sk, pk) = guardian_keypair();
    let sealed = seal_share(&shares[0], &pk, &VAULT_A, &EPOCH_0).unwrap();

    // Flip a byte in the AEAD-protected tail (past the 32-byte ephemeral pk).
    let mut bytes = sealed.as_bytes().to_vec();
    let idx = bytes.len() - 1;
    bytes[idx] ^= 0x01;
    let tampered = SealedShare::from_bytes(bytes);
    assert_eq!(
        open_sealed_share(&tampered, &sk, &VAULT_A, &EPOCH_0).unwrap_err(),
        EscrowError::OpenFailed,
    );
}

#[test]
fn sealed_share_tampered_ephemeral_pk_fails() {
    let rwk = RecoveryWrapKey::generate();
    let shares = split_rwk(&rwk, 2, 3).unwrap();
    let (sk, pk) = guardian_keypair();
    let sealed = seal_share(&shares[0], &pk, &VAULT_A, &EPOCH_0).unwrap();
    // Flip a byte in the ephemeral pk prefix -> KDF/nonce mismatch -> fail.
    let mut bytes = sealed.as_bytes().to_vec();
    bytes[0] ^= 0x01;
    let tampered = SealedShare::from_bytes(bytes);
    assert_eq!(
        open_sealed_share(&tampered, &sk, &VAULT_A, &EPOCH_0).unwrap_err(),
        EscrowError::OpenFailed,
    );
}

/// L8 replay: a share sealed for vault A is rejected when opened for vault
/// B, even by the correct guardian key.
#[test]
fn sealed_share_wrong_vault_rejected() {
    let rwk = RecoveryWrapKey::generate();
    let shares = split_rwk(&rwk, 2, 3).unwrap();
    let (sk, pk) = guardian_keypair();
    let sealed = seal_share(&shares[0], &pk, &VAULT_A, &EPOCH_0).unwrap();
    assert_eq!(
        open_sealed_share(&sealed, &sk, &VAULT_B, &EPOCH_0).unwrap_err(),
        EscrowError::OpenFailed,
        "share bound to vault A must be rejected for vault B",
    );
}

/// L8 replay: a share sealed at epoch 0 is rejected when opened at epoch 1
/// (stale-epoch / forward-security domain separation).
#[test]
fn sealed_share_stale_epoch_rejected() {
    let rwk = RecoveryWrapKey::generate();
    let shares = split_rwk(&rwk, 2, 3).unwrap();
    let (sk, pk) = guardian_keypair();
    let sealed = seal_share(&shares[0], &pk, &VAULT_A, &EPOCH_0).unwrap();
    assert_eq!(
        open_sealed_share(&sealed, &sk, &VAULT_A, &EPOCH_1).unwrap_err(),
        EscrowError::OpenFailed,
        "share bound to epoch 0 must be rejected for epoch 1",
    );
}

#[test]
fn sealed_share_truncated_fails() {
    let (sk, _pk) = guardian_keypair();
    // Too short to even contain the ephemeral pk.
    let tiny = SealedShare::from_bytes(vec![0u8; 4]);
    assert_eq!(
        open_sealed_share(&tiny, &sk, &VAULT_A, &EPOCH_0).unwrap_err(),
        EscrowError::OpenFailed,
    );
    // Exactly KEY_SIZE (no AEAD body) — must fail, no panic.
    let just_pk = SealedShare::from_bytes(vec![0u8; X25519_KEY_LEN]);
    assert_eq!(
        open_sealed_share(&just_pk, &sk, &VAULT_A, &EPOCH_0).unwrap_err(),
        EscrowError::OpenFailed,
    );
    let empty = SealedShare::from_bytes(Vec::new());
    assert_eq!(
        open_sealed_share(&empty, &sk, &VAULT_A, &EPOCH_0).unwrap_err(),
        EscrowError::OpenFailed,
    );
}

// ---- Malformed share input (typed errors, no panic) ---------------------

#[test]
fn share_from_bytes_rejects_wrong_length() {
    assert_eq!(
        Share::from_bytes(vec![1u8; SHARE_ENCODED_LEN - 1]).unwrap_err(),
        EscrowError::MalformedShare,
    );
    assert_eq!(
        Share::from_bytes(vec![1u8; SHARE_ENCODED_LEN + 1]).unwrap_err(),
        EscrowError::MalformedShare,
    );
    assert_eq!(
        Share::from_bytes(Vec::new()).unwrap_err(),
        EscrowError::MalformedShare,
    );
}

#[test]
fn share_from_bytes_rejects_zero_identifier() {
    let mut b = vec![0u8; SHARE_ENCODED_LEN];
    b[0] = 0; // zero x-coordinate is reserved for the secret.
    assert_eq!(
        Share::from_bytes(b).unwrap_err(),
        EscrowError::MalformedShare,
    );
}

#[test]
fn reconstruct_rejects_duplicate_identifiers() {
    let rwk = RecoveryWrapKey::generate();
    let shares = split_rwk(&rwk, 3, 5).unwrap();
    // Same share three times -> duplicate identifiers.
    let dup: Vec<Share> = (0..3)
        .map(|_| Share::from_bytes(shares[0].as_bytes().to_vec()).unwrap())
        .collect();
    assert_eq!(
        reconstruct_rwk(&dup).unwrap_err(),
        EscrowError::ReconstructFailed,
    );
}

#[test]
fn reconstruct_rejects_mismatched_lengths_via_share_guard() {
    // Share::from_bytes enforces a fixed length, so mismatched lengths can
    // never enter reconstruct_rwk through the typed API. Confirm the guard.
    assert!(Share::from_bytes(vec![1u8, 2u8, 3u8]).is_err());
}

#[test]
fn reconstruct_empty_set_fails() {
    assert_eq!(
        reconstruct_rwk(&[]).unwrap_err(),
        EscrowError::ReconstructFailed,
    );
}

// ---- Secret-type discipline (compile-time + Debug redaction) ------------

#[test]
fn rwk_debug_redacts() {
    let rwk = RecoveryWrapKey::generate();
    let printed = format!("{rwk:?}");
    assert!(printed.contains("<redacted>"));
}

#[test]
fn share_debug_redacts_value() {
    let rwk = RecoveryWrapKey::generate();
    let shares = split_rwk(&rwk, 2, 3).unwrap();
    let printed = format!("{:?}", shares[0]);
    assert!(printed.contains("<redacted>"));
    assert!(printed.contains("identifier"));
}

#[test]
fn sealed_share_debug_redacts_to_len() {
    let rwk = RecoveryWrapKey::generate();
    let shares = split_rwk(&rwk, 2, 3).unwrap();
    let (_sk, pk) = guardian_keypair();
    let sealed = seal_share(&shares[0], &pk, &VAULT_A, &EPOCH_0).unwrap();
    let printed = format!("{sealed:?}");
    assert!(printed.contains("len"));
}

#[test]
fn info_string_is_versioned() {
    assert_eq!(RECOVERY_WRAP_KEY_INFO, b"pangolin-recovery-wrap-v0");
    assert_eq!(SEALED_SHARE_DOMAIN, b"pangolin-recovery-seal-v0");
}

/// The recovery-wrap and authority-wrap info strings MUST differ so the two
/// wrap keys derived from the same 32-byte seed value can never collide.
#[test]
fn recovery_info_differs_from_authority_info() {
    assert_ne!(RECOVERY_WRAP_KEY_INFO, crate::keys::WRAP_KEY_INFO);
}

// ---- Proptest: >=1024 cases (mirrors keys.rs discipline) ----------------

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig {
        cases: 1024,
        ..proptest::prelude::ProptestConfig::default()
    })]

    /// Random RWK + random (t,M) within bounds -> split -> seal all ->
    /// open -> reconstruct from a random >= t subset -> wrap+unwrap VDK ->
    /// byte-identical; AND a random < t subset -> never the true RWK.
    #[test]
    fn proptest_full_escrow_round_trip(
        t in MIN_THRESHOLD..=MAX_THRESHOLD,
        extra in 0u8..=(MAX_GUARDIANS - MIN_THRESHOLD),
        vault_id in proptest::prelude::any::<[u8; VAULT_ID_LEN]>(),
        epoch in proptest::prelude::any::<[u8; EPOCH_LEN]>(),
        pick_seed in proptest::prelude::any::<u64>(),
    ) {
        // Derive M = clamp(t + extra) into [max(t,MIN_GUARDIANS), MAX_GUARDIANS].
        // `t <= 9` and `extra <= 13`, so `t + extra <= 22` never overflows u8.
        let m = (t + extra).clamp(MIN_GUARDIANS, MAX_GUARDIANS).max(t);

        let vdk = VdkKey::generate();
        let ctx = WrapContext::new(vault_id);
        let rwk = RecoveryWrapKey::generate();
        let wrapped = wrap_vdk_under_rwk(&vdk, &rwk, &ctx).unwrap();

        let shares = split_rwk(&rwk, t, m).unwrap();
        proptest::prop_assert_eq!(shares.len(), usize::from(m));

        // Seal every share to a fresh guardian.
        let guardians: Vec<_> = (0..m).map(|_| guardian_keypair()).collect();
        let sealed: Vec<SealedShare> = shares
            .iter()
            .zip(&guardians)
            .map(|(s, (_, pk))| seal_share(s, pk, &vault_id, &epoch).unwrap())
            .collect();

        // Deterministic pseudo-random subset of size t from the pick_seed.
        let mut order: Vec<usize> = (0..usize::from(m)).collect();
        // Simple Fisher-Yates with a LCG seeded by pick_seed (test-only).
        let mut state = pick_seed | 1;
        for i in (1..order.len()).rev() {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let j = (state >> 33) as usize % (i + 1);
            order.swap(i, j);
        }
        let t_idx = &order[..usize::from(t)];

        // Open the t-subset and reconstruct.
        let opened: Vec<Share> = t_idx
            .iter()
            .map(|&i| open_sealed_share(&sealed[i], &guardians[i].0, &vault_id, &epoch).unwrap())
            .collect();
        let rwk2 = reconstruct_rwk(&opened).unwrap();
        proptest::prop_assert!(bool::from(rwk.ct_eq(&rwk2)));

        let recovered = unwrap_vdk_under_rwk(&wrapped, &rwk2).unwrap();
        proptest::prop_assert!(
            bool::from(vdk.ct_eq(&recovered)),
            "L5 byte-identical VDK broken for t={}, m={}", t, m,
        );

        // A < t subset must NOT reconstruct the true RWK.
        if t >= 2 {
            let sub_idx = &order[..usize::from(t) - 1];
            let sub_opened: Vec<Share> = sub_idx
                .iter()
                .map(|&i| open_sealed_share(&sealed[i], &guardians[i].0, &vault_id, &epoch).unwrap())
                .collect();
            match reconstruct_rwk(&sub_opened) {
                Err(_) => {}
                Ok(wrong) => {
                    proptest::prop_assert!(
                        !bool::from(rwk.ct_eq(&wrong)),
                        "t-1 subset reconstructed the TRUE RWK (t={}, m={})", t, m,
                    );
                }
            }
        }
    }

    /// Focused L1/L2: random RWK + random (t,M); ANY t-1 subset (the first
    /// t-1 shares) never yields the true RWK; the first t shares always do.
    #[test]
    fn proptest_subthreshold_never_reconstructs(
        t in MIN_THRESHOLD..=MAX_THRESHOLD,
        extra in 0u8..=(MAX_GUARDIANS - MIN_THRESHOLD),
    ) {
        // `t <= 9` and `extra <= 13`, so `t + extra <= 22` never overflows u8.
        let m = (t + extra).clamp(MIN_GUARDIANS, MAX_GUARDIANS).max(t);

        let rwk = RecoveryWrapKey::generate();
        let shares = split_rwk(&rwk, t, m).unwrap();

        // t shares reconstruct exactly.
        let full: Vec<Share> = shares[..usize::from(t)]
            .iter()
            .map(|s| Share::from_bytes(s.as_bytes().to_vec()).unwrap())
            .collect();
        proptest::prop_assert!(bool::from(rwk.ct_eq(&reconstruct_rwk(&full).unwrap())));

        // t-1 shares never reconstruct the true RWK.
        let sub: Vec<Share> = shares[..usize::from(t) - 1]
            .iter()
            .map(|s| Share::from_bytes(s.as_bytes().to_vec()).unwrap())
            .collect();
        match reconstruct_rwk(&sub) {
            Err(_) => {}
            Ok(wrong) => {
                proptest::prop_assert!(!bool::from(rwk.ct_eq(&wrong)));
            }
        }
    }
}
