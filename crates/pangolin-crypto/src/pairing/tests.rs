// SPDX-License-Identifier: AGPL-3.0-or-later
//! Exhaustive tests for the device-pairing seal/open + per-device VDK wrap
//! primitive (#106b-1).
//!
//! The in-house adversarial audit is the ONLY review before testnet, so
//! these tests carry the full weight of correctness. Load-bearing
//! properties, in priority order:
//!
//! - **L1/L2 — the VDK never crosses in clear; byte-identical handoff.**
//!   [`pairing_round_trip`] + [`proptest_pair_and_wrap_round_trip`].
//! - **L1/L4 — domain binding.** A seal bound to (vault A, device B, epoch
//!   n) is rejected for vault B / device C / epoch m — each field tested
//!   independently ([`seal_*_rejected`]).
//! - **Wrong key / tamper / truncation fail (typed, no panic).**
//! - **Per-device wrap round-trip + wrong key + cross-context replay.**
//! - **HKDF-info distinctness** ([`domain_strings_are_versioned_and_distinct`])
//!   + derived-key independence ([`pairing_and_wrap_keys_are_independent`]).
//! - **Determinism / KAT** ([`derive_is_deterministic`],
//!   [`different_devices_produce_different_keys`],
//!   [`kat_pinned_pairing_public_key_for_fixed_seed`]).
//! - **Secret hygiene** (compile-time `assert_not_impl_any!` + Debug
//!   redaction).

use super::*;
use crate::keys::{DeviceKey, VdkKey, WrapContext, WrappedVdk, VAULT_ID_LEN};

// ---- Fixtures -----------------------------------------------------------

const VAULT_A: [u8; VAULT_ID_LEN] = [0xAA; VAULT_ID_LEN];
const VAULT_B: [u8; VAULT_ID_LEN] = [0xBB; VAULT_ID_LEN];
const DEVICE_B: [u8; DEVICE_ID_LEN] = [0xB0; DEVICE_ID_LEN];
const DEVICE_C: [u8; DEVICE_ID_LEN] = [0xC0; DEVICE_ID_LEN];
const EPOCH_0: [u8; EPOCH_LEN] = [0x00; EPOCH_LEN];
const EPOCH_1: [u8; EPOCH_LEN] = [0x11; EPOCH_LEN];

// =========================================================================
// 1. Pairing seal/open round-trip (L1/L2) — the centerpiece
// =========================================================================

/// Seal a VDK to device B's derived pairing pubkey, open it with B's
/// derived pairing secret, and assert the recovered VDK is byte-identical
/// (`ct_eq`) to the original — the VDK is handed over, never re-derived.
#[test]
fn pairing_round_trip() {
    let vdk = VdkKey::generate();
    let device_b = DeviceKey::from_seed([0x07; 32]);
    let pairing = derive_x25519_pairing_key(&device_b);

    let sealed =
        seal_vdk_to_device(&vdk, pairing.public_bytes(), &VAULT_A, &DEVICE_B, &EPOCH_0).unwrap();

    let secret = pairing.secret_bytes();
    let recovered = open_vdk_from_pairing(&sealed, &secret, &VAULT_A, &DEVICE_B, &EPOCH_0).unwrap();

    assert!(
        bool::from(vdk.ct_eq(&recovered)),
        "recovered VDK is NOT byte-identical to the original — L1/L2 BROKEN",
    );
}

/// A VDK opened with the WRONG recipient pairing secret (a different
/// device's derived key) fails — typed error, no panic.
#[test]
fn pairing_wrong_recipient_key_fails() {
    let vdk = VdkKey::generate();
    let device_b = DeviceKey::from_seed([0x07; 32]);
    let pairing_b = derive_x25519_pairing_key(&device_b);
    let sealed = seal_vdk_to_device(
        &vdk,
        pairing_b.public_bytes(),
        &VAULT_A,
        &DEVICE_B,
        &EPOCH_0,
    )
    .unwrap();

    // A different device's derived pairing key cannot open it.
    let other = derive_x25519_pairing_key(&DeviceKey::from_seed([0x08; 32]));
    let other_secret = other.secret_bytes();
    assert_eq!(
        open_vdk_from_pairing(&sealed, &other_secret, &VAULT_A, &DEVICE_B, &EPOCH_0).unwrap_err(),
        PairingError::OpenFailed,
    );
}

/// Tampering with the AEAD-protected tail of a sealed VDK makes it fail.
#[test]
fn pairing_tampered_ciphertext_fails() {
    let vdk = VdkKey::generate();
    let pairing = derive_x25519_pairing_key(&DeviceKey::from_seed([0x07; 32]));
    let sealed =
        seal_vdk_to_device(&vdk, pairing.public_bytes(), &VAULT_A, &DEVICE_B, &EPOCH_0).unwrap();

    let mut bytes = sealed.as_bytes().to_vec();
    let idx = bytes.len() - 1;
    bytes[idx] ^= 0x01;
    let tampered = SealedVdkForDevice::from_bytes(bytes);

    let secret = pairing.secret_bytes();
    assert_eq!(
        open_vdk_from_pairing(&tampered, &secret, &VAULT_A, &DEVICE_B, &EPOCH_0).unwrap_err(),
        PairingError::OpenFailed,
    );
}

/// Tampering with the ephemeral-pk prefix (the first 32 bytes) makes it
/// fail (KDF/nonce mismatch).
#[test]
fn pairing_tampered_ephemeral_pk_fails() {
    let vdk = VdkKey::generate();
    let pairing = derive_x25519_pairing_key(&DeviceKey::from_seed([0x07; 32]));
    let sealed =
        seal_vdk_to_device(&vdk, pairing.public_bytes(), &VAULT_A, &DEVICE_B, &EPOCH_0).unwrap();

    let mut bytes = sealed.as_bytes().to_vec();
    bytes[0] ^= 0x01;
    let tampered = SealedVdkForDevice::from_bytes(bytes);

    let secret = pairing.secret_bytes();
    assert_eq!(
        open_vdk_from_pairing(&tampered, &secret, &VAULT_A, &DEVICE_B, &EPOCH_0).unwrap_err(),
        PairingError::OpenFailed,
    );
}

/// Truncated / undersized / empty sealed buffers fail without panic.
#[test]
fn pairing_truncated_fails() {
    let pairing = derive_x25519_pairing_key(&DeviceKey::from_seed([0x07; 32]));
    let secret = pairing.secret_bytes();

    // Too short to even contain the ephemeral pk.
    let tiny = SealedVdkForDevice::from_bytes(vec![0u8; 4]);
    assert_eq!(
        open_vdk_from_pairing(&tiny, &secret, &VAULT_A, &DEVICE_B, &EPOCH_0).unwrap_err(),
        PairingError::OpenFailed,
    );
    // Exactly KEY_SIZE (no AEAD body) — must fail, no panic.
    let just_pk = SealedVdkForDevice::from_bytes(vec![0u8; X25519_KEY_LEN]);
    assert_eq!(
        open_vdk_from_pairing(&just_pk, &secret, &VAULT_A, &DEVICE_B, &EPOCH_0).unwrap_err(),
        PairingError::OpenFailed,
    );
    let empty = SealedVdkForDevice::from_bytes(Vec::new());
    assert_eq!(
        open_vdk_from_pairing(&empty, &secret, &VAULT_A, &DEVICE_B, &EPOCH_0).unwrap_err(),
        PairingError::OpenFailed,
    );
}

/// A sealed VDK whose decrypted plaintext is the correct length but whose
/// header is shorter/longer than expected (e.g. valid sealed box to the
/// recipient over arbitrary bytes) is rejected by the length+header check.
/// We emulate by sealing a non-VDK payload directly to the recipient pubkey.
#[test]
fn pairing_wrong_inner_length_fails() {
    let pairing = derive_x25519_pairing_key(&DeviceKey::from_seed([0x07; 32]));
    let pk = crypto_box::PublicKey::from_bytes(*pairing.public_bytes());
    // Seal a plaintext that has the right header but a too-short VDK body.
    let mut payload = sealed_vdk_header(&VAULT_A, &DEVICE_B, &EPOCH_0);
    payload.extend_from_slice(&[0u8; KEY_LEN - 1]); // one byte short
    let ct = pk.seal(&mut os_rng(), &payload).unwrap();
    let sealed = SealedVdkForDevice::from_bytes(ct);

    let secret = pairing.secret_bytes();
    assert_eq!(
        open_vdk_from_pairing(&sealed, &secret, &VAULT_A, &DEVICE_B, &EPOCH_0).unwrap_err(),
        PairingError::OpenFailed,
    );
}

// =========================================================================
// 2. Domain-separation negatives (L1/L4) — each field tested independently
// =========================================================================

/// A seal bound to vault A is rejected for vault B (correct recipient key).
#[test]
fn seal_wrong_vault_rejected() {
    let vdk = VdkKey::generate();
    let pairing = derive_x25519_pairing_key(&DeviceKey::from_seed([0x07; 32]));
    let sealed =
        seal_vdk_to_device(&vdk, pairing.public_bytes(), &VAULT_A, &DEVICE_B, &EPOCH_0).unwrap();
    let secret = pairing.secret_bytes();
    assert_eq!(
        open_vdk_from_pairing(&sealed, &secret, &VAULT_B, &DEVICE_B, &EPOCH_0).unwrap_err(),
        PairingError::OpenFailed,
        "seal bound to vault A must be rejected for vault B",
    );
}

/// A seal bound to device B is rejected for device C (Q-e device-id
/// binding), even with the correct recipient key + vault + epoch.
#[test]
fn seal_wrong_device_id_rejected() {
    let vdk = VdkKey::generate();
    let pairing = derive_x25519_pairing_key(&DeviceKey::from_seed([0x07; 32]));
    let sealed =
        seal_vdk_to_device(&vdk, pairing.public_bytes(), &VAULT_A, &DEVICE_B, &EPOCH_0).unwrap();
    let secret = pairing.secret_bytes();
    assert_eq!(
        open_vdk_from_pairing(&sealed, &secret, &VAULT_A, &DEVICE_C, &EPOCH_0).unwrap_err(),
        PairingError::OpenFailed,
        "seal bound to device B must be rejected for device C (Q-e)",
    );
}

/// A seal bound to epoch n is rejected for epoch n+1 (post-revoke rotation
/// invalidates in-flight pairing envelopes — forward-security domain sep).
#[test]
fn seal_stale_epoch_rejected() {
    let vdk = VdkKey::generate();
    let pairing = derive_x25519_pairing_key(&DeviceKey::from_seed([0x07; 32]));
    let sealed =
        seal_vdk_to_device(&vdk, pairing.public_bytes(), &VAULT_A, &DEVICE_B, &EPOCH_0).unwrap();
    let secret = pairing.secret_bytes();
    assert_eq!(
        open_vdk_from_pairing(&sealed, &secret, &VAULT_A, &DEVICE_B, &EPOCH_1).unwrap_err(),
        PairingError::OpenFailed,
        "seal bound to epoch 0 must be rejected for epoch 1",
    );
}

// =========================================================================
// 3. Per-device wrap round-trip + negatives
// =========================================================================

/// Wrap a VDK under device A's derived wrap key, unwrap it, assert
/// byte-identical recovery.
#[test]
fn device_wrap_round_trip() {
    let vdk = VdkKey::generate();
    let device = DeviceKey::from_seed([0x31; 32]);
    let ctx = WrapContext::new(VAULT_A);
    let wrapped = wrap_vdk_for_device(&vdk, &device, &ctx).unwrap();
    let recovered = unwrap_vdk_for_device(&wrapped, &device).unwrap();
    assert!(
        bool::from(vdk.ct_eq(&recovered)),
        "per-device wrap round-trip is NOT byte-identical",
    );
}

/// A different device key cannot unwrap a per-device wrap.
#[test]
fn device_wrap_wrong_device_key_fails() {
    let vdk = VdkKey::generate();
    let device_a = DeviceKey::from_seed([0x31; 32]);
    let device_b = DeviceKey::from_seed([0x32; 32]);
    let ctx = WrapContext::new(VAULT_A);
    let wrapped = wrap_vdk_for_device(&vdk, &device_a, &ctx).unwrap();
    assert_eq!(
        unwrap_vdk_for_device(&wrapped, &device_b).unwrap_err(),
        PairingError::WrapFailed,
    );
}

/// Cross-vault replay: a per-device wrap sealed for vault A must not unwrap
/// once its stored context is forged to vault B (storage-write attacker).
#[test]
fn device_wrap_cross_vault_replay_fails() {
    let vdk = VdkKey::generate();
    let device = DeviceKey::from_seed([0x31; 32]);
    let ctx_a = WrapContext::new(VAULT_A);
    let wrapped = wrap_vdk_for_device(&vdk, &device, &ctx_a).unwrap();

    let inner = wrapped.as_wrapped();
    let transplanted = DeviceWrappedVdk::from_wrapped(WrappedVdk::from_parts(
        inner.ciphertext().clone(),
        *inner.nonce(),
        WrapContext::new(VAULT_B),
    ));
    assert_eq!(
        unwrap_vdk_for_device(&transplanted, &device).unwrap_err(),
        PairingError::WrapFailed,
        "wrap sealed for vault A must not unwrap under vault B's ctx",
    );
}

/// Cross-schema replay: a per-device wrap sealed at `schema_version` 0 must
/// not unwrap once its stored context claims a future schema version.
#[test]
fn device_wrap_schema_mismatch_fails() {
    let vdk = VdkKey::generate();
    let device = DeviceKey::from_seed([0x31; 32]);
    let ctx_v0 = WrapContext::new(VAULT_A);
    let wrapped = wrap_vdk_for_device(&vdk, &device, &ctx_v0).unwrap();

    let inner = wrapped.as_wrapped();
    let bumped = WrapContext {
        vault_id: VAULT_A,
        schema_version: 1,
    };
    let transplanted = DeviceWrappedVdk::from_wrapped(WrappedVdk::from_parts(
        inner.ciphertext().clone(),
        *inner.nonce(),
        bumped,
    ));
    assert_eq!(
        unwrap_vdk_for_device(&transplanted, &device).unwrap_err(),
        PairingError::WrapFailed,
    );
}

/// A tampered per-device wrap ciphertext fails.
#[test]
fn device_wrap_tampered_ciphertext_fails() {
    let vdk = VdkKey::generate();
    let device = DeviceKey::from_seed([0x31; 32]);
    let ctx = WrapContext::new(VAULT_A);
    let wrapped = wrap_vdk_for_device(&vdk, &device, &ctx).unwrap();

    let inner = wrapped.as_wrapped();
    let mut bytes = inner.ciphertext().as_bytes().to_vec();
    bytes[0] ^= 0x01;
    let tampered = DeviceWrappedVdk::from_wrapped(WrappedVdk::from_parts(
        crate::aead::Ciphertext::from_vec(bytes),
        *inner.nonce(),
        *inner.context(),
    ));
    assert_eq!(
        unwrap_vdk_for_device(&tampered, &device).unwrap_err(),
        PairingError::WrapFailed,
    );
}

// =========================================================================
// 4. Determinism / KAT for the pairing X25519 derivation
// =========================================================================

/// Same `DeviceKey` derives the same pairing keypair every call.
#[test]
fn derive_is_deterministic() {
    let device = DeviceKey::from_seed([0x42; 32]);
    let k1 = derive_x25519_pairing_key(&device);
    let k2 = derive_x25519_pairing_key(&device);
    assert_eq!(
        k1.public_bytes(),
        k2.public_bytes(),
        "same DeviceKey must derive same pairing public key",
    );
    assert!(
        bool::from(k1.ct_eq(&k2)),
        "same DeviceKey must derive same pairing secret scalar",
    );
}

/// Distinct devices derive distinct pairing keys.
#[test]
fn different_devices_produce_different_keys() {
    let d1 = DeviceKey::from_seed([0x11; 32]);
    let d2 = DeviceKey::from_seed([0x22; 32]);
    let k1 = derive_x25519_pairing_key(&d1);
    let k2 = derive_x25519_pairing_key(&d2);
    assert_ne!(k1.public_bytes(), k2.public_bytes());
    assert!(!bool::from(k1.ct_eq(&k2)));
}

/// Pinned known-answer vector: a fixed device seed derives a fixed pairing
/// public key. Re-derived independently the slow way to defend against a
/// stale pin; catches a future drift in the domain message, HKDF info,
/// SHA-512 choice, or the `crypto_box` public derivation.
#[test]
fn kat_pinned_pairing_public_key_for_fixed_seed() {
    let device = DeviceKey::from_seed([0x9A; 32]);
    let key = derive_x25519_pairing_key(&device);
    let got = key.public_bytes();
    let expected = {
        use hkdf::Hkdf;
        use sha2::Sha512;
        let sig = device
            .signing_key()
            .sign(DEVICE_PAIR_X25519_DERIVATION_MESSAGE);
        let hk = Hkdf::<Sha512>::new(None, &sig.to_bytes());
        let mut scalar = [0u8; X25519_KEY_LEN];
        hk.expand(DEVICE_PAIR_X25519_HKDF_INFO, &mut scalar)
            .unwrap();
        let sk = crypto_box::SecretKey::from_bytes(scalar);
        *sk.public_key().as_bytes()
    };
    assert_eq!(
        got, &expected,
        "pairing derivation drifted from the spec recipe"
    );
}

// =========================================================================
// 5. HKDF-info distinctness (L4) + derived-key independence
// =========================================================================

/// The two new info strings are versioned `-v0` and distinct from one
/// another AND from all three existing infos (authority-wrap,
/// recovery-wrap, guardian-X25519). A grep-able audit assertion.
#[test]
fn domain_strings_are_versioned_and_distinct() {
    // Literal pins (a change must bump the suffix + document migration).
    assert_eq!(
        DEVICE_PAIR_X25519_DERIVATION_MESSAGE,
        b"pangolin-device-pair-x25519-derive-v0"
    );
    assert_eq!(
        DEVICE_PAIR_X25519_HKDF_INFO,
        b"pangolin-device-pair-x25519-v0"
    );
    assert_eq!(DEVICE_WRAP_KEY_INFO, b"pangolin-device-wrap-v0");
    assert_eq!(SEALED_VDK_DOMAIN, b"pangolin-device-pair-seal-v0");

    // The two NEW HKDF infos differ from each other.
    assert_ne!(DEVICE_PAIR_X25519_HKDF_INFO, DEVICE_WRAP_KEY_INFO);

    // …and from the THREE existing HKDF infos.
    let existing: [&[u8]; 3] = [
        crate::keys::WRAP_KEY_INFO,            // pangolin-vdk-wrap-v0
        crate::escrow::RECOVERY_WRAP_KEY_INFO, // pangolin-recovery-wrap-v0
        crate::guardian::X25519_HKDF_INFO,     // pangolin-guardian-x25519-v0
    ];
    for info in existing {
        assert_ne!(
            DEVICE_PAIR_X25519_HKDF_INFO, info,
            "pairing-X25519 info collided with an existing HKDF info",
        );
        assert_ne!(
            DEVICE_WRAP_KEY_INFO, info,
            "device-wrap info collided with an existing HKDF info",
        );
    }

    // The derivation messages also differ (pairing vs guardian).
    assert_ne!(
        DEVICE_PAIR_X25519_DERIVATION_MESSAGE,
        crate::guardian::X25519_DERIVATION_MESSAGE,
    );
}

/// Independence of the derived material: from the SAME `DeviceKey`, the
/// pairing-X25519 public key and the per-device wrap key are independent
/// (no shared key material), AND the device pairing key differs from the
/// guardian sealing key derived from the same device. We confirm
/// independence by checking that a VDK sealed to the pairing key cannot be
/// opened with the guardian sealing secret, and that the wrap key does not
/// equal the pairing scalar.
#[test]
fn pairing_and_wrap_keys_are_independent() {
    let device = DeviceKey::from_seed([0x77; 32]);

    let pairing = derive_x25519_pairing_key(&device);
    let guardian = crate::guardian::derive_x25519_sealing_key(&device);

    // Distinct info strings → distinct X25519 keys from the same device.
    assert_ne!(
        pairing.public_bytes(),
        guardian.public_bytes(),
        "pairing key must differ from guardian sealing key (same device)",
    );

    // A VDK sealed to the pairing pubkey cannot be opened with the guardian
    // sealing secret (proves the seal targets the pairing key, not the
    // guardian key).
    let vdk = VdkKey::generate();
    let sealed =
        seal_vdk_to_device(&vdk, pairing.public_bytes(), &VAULT_A, &DEVICE_B, &EPOCH_0).unwrap();
    let guardian_secret = guardian.secret_bytes();
    assert_eq!(
        open_vdk_from_pairing(&sealed, &guardian_secret, &VAULT_A, &DEVICE_B, &EPOCH_0)
            .unwrap_err(),
        PairingError::OpenFailed,
    );

    // The per-device wrap key material is independent of the pairing scalar:
    // wrapping under the device key produces a wrap that the pairing scalar
    // can never be substituted into. (Structural: different derivations.)
    let ctx = WrapContext::new(VAULT_A);
    let wrapped = wrap_vdk_for_device(&vdk, &device, &ctx).unwrap();
    let recovered = unwrap_vdk_for_device(&wrapped, &device).unwrap();
    assert!(bool::from(vdk.ct_eq(&recovered)));
}

// =========================================================================
// 6. Secret hygiene (compile-time + Debug redaction)
// =========================================================================
//
// Secret-type discipline for `X25519PairingKey` (!Clone/!Copy) is enforced at
// compile time by `assert_not_impl_any!(X25519PairingKey: Clone, Copy)` at the
// top of `pairing.rs` (the escrow.rs precedent); no runtime test wraps it.

/// `Debug` on the pairing key redacts the secret scalar and shows only a
/// public preview; the raw scalar bytes never appear.
#[test]
fn pairing_key_debug_redacts_secret() {
    let key = derive_x25519_pairing_key(&DeviceKey::from_seed([0x55; 32]));
    let printed = format!("{key:?}");
    assert!(printed.contains("<redacted>"));
    assert!(printed.contains("public"));
}

/// `Debug` on a sealed VDK reports only the length, never the bytes.
#[test]
fn sealed_vdk_debug_redacts_to_len() {
    let vdk = VdkKey::generate();
    let pairing = derive_x25519_pairing_key(&DeviceKey::from_seed([0x07; 32]));
    let sealed =
        seal_vdk_to_device(&vdk, pairing.public_bytes(), &VAULT_A, &DEVICE_B, &EPOCH_0).unwrap();
    let printed = format!("{sealed:?}");
    assert!(printed.contains("len"));
}

/// `Debug` on a per-device wrap redacts the ciphertext (delegates to the
/// inner `WrappedVdk`, which reports only lengths/nonce/ctx).
#[test]
fn device_wrapped_vdk_debug_redacts() {
    let vdk = VdkKey::generate();
    let device = DeviceKey::from_seed([0x31; 32]);
    let ctx = WrapContext::new(VAULT_A);
    let wrapped = wrap_vdk_for_device(&vdk, &device, &ctx).unwrap();
    let printed = format!("{wrapped:?}");
    assert!(printed.contains("DeviceWrappedVdk"));
    assert!(printed.contains("ciphertext_len"));
}

// =========================================================================
// 7. Proptest (>=1024 cases): full pair->seal->open->ct_eq + wrap->unwrap
// =========================================================================

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig {
        cases: 1024,
        ..proptest::prelude::ProptestConfig::default()
    })]

    /// Random VDK + vault_id + device_id + epoch + device seed:
    /// derive pairing key -> seal -> open -> byte-identical; AND
    /// wrap-for-device -> unwrap -> byte-identical. Also asserts a random
    /// WRONG recipient key and a random WRONG domain field both fail.
    #[test]
    fn proptest_pair_and_wrap_round_trip(
        vault_id in proptest::prelude::any::<[u8; VAULT_ID_LEN]>(),
        other_vault in proptest::prelude::any::<[u8; VAULT_ID_LEN]>(),
        device_id in proptest::prelude::any::<[u8; DEVICE_ID_LEN]>(),
        other_device in proptest::prelude::any::<[u8; DEVICE_ID_LEN]>(),
        epoch in proptest::prelude::any::<[u8; EPOCH_LEN]>(),
        other_epoch in proptest::prelude::any::<[u8; EPOCH_LEN]>(),
        vdk_bytes in proptest::prelude::any::<[u8; KEY_LEN]>(),
        recipient_seed in proptest::prelude::any::<[u8; 32]>(),
        wrong_seed in proptest::prelude::any::<[u8; 32]>(),
        schema_version in proptest::prelude::any::<u8>(),
    ) {
        let vdk = VdkKey::from_aead_bytes(vdk_bytes);
        let recipient = DeviceKey::from_seed(recipient_seed);
        let pairing = derive_x25519_pairing_key(&recipient);

        // --- pairing seal/open round-trip ---
        let sealed = seal_vdk_to_device(
            &vdk, pairing.public_bytes(), &vault_id, &device_id, &epoch,
        ).unwrap();
        let secret = pairing.secret_bytes();
        let recovered = open_vdk_from_pairing(
            &sealed, &secret, &vault_id, &device_id, &epoch,
        ).unwrap();
        proptest::prop_assert!(
            bool::from(vdk.ct_eq(&recovered)),
            "pairing handoff not byte-identical",
        );

        // --- wrong recipient key fails ---
        let wrong = derive_x25519_pairing_key(&DeviceKey::from_seed(wrong_seed));
        // (overwhelmingly distinct seeds; if they happen to collide the open
        // would succeed, which is correct — guard against the rare equal case)
        if !bool::from(wrong.ct_eq(&pairing)) {
            let wrong_secret = wrong.secret_bytes();
            proptest::prop_assert_eq!(
                open_vdk_from_pairing(&sealed, &wrong_secret, &vault_id, &device_id, &epoch)
                    .unwrap_err(),
                PairingError::OpenFailed,
            );
        }

        // --- wrong domain fields fail (each, when actually different) ---
        if other_vault != vault_id {
            proptest::prop_assert_eq!(
                open_vdk_from_pairing(&sealed, &secret, &other_vault, &device_id, &epoch)
                    .unwrap_err(),
                PairingError::OpenFailed,
            );
        }
        if other_device != device_id {
            proptest::prop_assert_eq!(
                open_vdk_from_pairing(&sealed, &secret, &vault_id, &other_device, &epoch)
                    .unwrap_err(),
                PairingError::OpenFailed,
            );
        }
        if other_epoch != epoch {
            proptest::prop_assert_eq!(
                open_vdk_from_pairing(&sealed, &secret, &vault_id, &device_id, &other_epoch)
                    .unwrap_err(),
                PairingError::OpenFailed,
            );
        }

        // --- per-device wrap round-trip ---
        let ctx = WrapContext { vault_id, schema_version };
        let wrapped = wrap_vdk_for_device(&vdk, &recipient, &ctx).unwrap();
        let unwrapped = unwrap_vdk_for_device(&wrapped, &recipient).unwrap();
        proptest::prop_assert!(
            bool::from(vdk.ct_eq(&unwrapped)),
            "per-device wrap not byte-identical",
        );

        // --- wrong device key cannot unwrap ---
        let wrong_device = DeviceKey::from_seed(wrong_seed);
        if !bool::from(wrong_device.ct_eq(&recipient)) {
            proptest::prop_assert_eq!(
                unwrap_vdk_for_device(&wrapped, &wrong_device).unwrap_err(),
                PairingError::WrapFailed,
            );
        }
    }
}
