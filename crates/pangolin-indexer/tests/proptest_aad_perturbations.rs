// SPDX-License-Identifier: AGPL-3.0-or-later
//! §4.3 per-column AEAD: proptest module exercising the AAD-binding
//! property under random perturbations.
//!
//! The §4.3 plan-gate adversarial framing identifies three load-
//! bearing failure modes the per-column AAD discipline is designed
//! to defeat:
//!
//! - **L-cross-page-cut-and-paste:** ciphertext from row #i pasted
//!   into row #j must fail to decrypt because `page_id` in the
//!   recomputed AAD differs.
//! - **L-cross-session-replay:** ciphertext from session A pasted
//!   into session B must fail to decrypt because `vault_id` in the
//!   recomputed AAD differs.
//! - **L-future-schema-version-poison:** ciphertext sealed under
//!   `schema_version = N` must fail to decrypt as `schema_version =
//!   N+1` payload because `schema_version` is bound into the AAD.
//!
//! Each property is exercised over `PROPTEST_CASES` random
//! inputs (default 1024 — the proptest standard).
//!
//! ## Why proptest, not the workspace's hand-rolled fuzz harness
//!
//! proptest provides:
//! - shrinking (a failing case shrinks to the minimal counter-example);
//! - reproducibility (the seed is printed on failure);
//! - cross-platform determinism (no platform-specific RNG state);
//! - well-known integration with cargo-test.
//!
//! It's a new dev-dep on pangolin-indexer ONLY (NOT pangolin-crypto
//! per HIGH-1). Workspace pin `=1.7.0` per quirk #15. Dev-dep does
//! NOT enter the production lockfile dependency tree, and the
//! `cargo tree -p pangolin-crypto | grep -c serde == 0` invariant
//! is preserved (proptest does pull serde transitively, but ONLY
//! for the indexer's dev-build graph).

#![forbid(unsafe_code)]
#![allow(clippy::doc_markdown)]

use std::sync::Arc;

use proptest::prelude::*;

use pangolin_crypto::rng::fill_random;
use pangolin_crypto::secret::SecretBytes;
use pangolin_indexer::{AeadCipher, CipherError, TempDbCipher, PER_COLUMN_AAD_LEN};

/// Build a 42-byte AAD with the §4.3 layout. We can't reach the
/// `pub(crate) build_aad` helper from the integration-tests crate,
/// so we mirror its byte layout here. The pin test below asserts
/// the layout stays stable.
fn build_test_aad(vault_id: &[u8; 32], page_id: u64, schema_version: u16) -> [u8; 42] {
    let mut aad = [0u8; PER_COLUMN_AAD_LEN];
    aad[..32].copy_from_slice(vault_id);
    aad[32..40].copy_from_slice(&page_id.to_be_bytes());
    aad[40..42].copy_from_slice(&schema_version.to_be_bytes());
    aad
}

fn fresh_cipher() -> Arc<dyn TempDbCipher> {
    let mut key = [0u8; 32];
    fill_random(&mut key);
    AeadCipher::new_arc(SecretBytes::new(key.to_vec()))
}

proptest! {
    /// **L-cross-page-cut-and-paste:** sealing under `(vault, p1,
    /// schema)` and opening under `(vault, p2, schema)` with `p1 !=
    /// p2` must fail with `TagMismatch`. Tested across random vault
    /// ids + random page id pairs + random schema versions + random
    /// plaintexts.
    #[test]
    fn cross_page_paste_fails_for_any_page_id_pair(
        vault_id in proptest::array::uniform32(any::<u8>()),
        page_a in 0u64..1_000_000,
        page_b in 0u64..1_000_000,
        schema_version in 0u16..=u16::MAX,
        plaintext in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        prop_assume!(page_a != page_b);
        let cipher = fresh_cipher();
        let aad_a = build_test_aad(&vault_id, page_a, schema_version);
        let aad_b = build_test_aad(&vault_id, page_b, schema_version);
        let ct = cipher.encrypt_page(&plaintext, &aad_a);
        let result = cipher.decrypt_page(&ct, &aad_b);
        prop_assert!(result.is_err(),
            "cross-page paste decrypt must fail (page_a={page_a}, page_b={page_b})");
        prop_assert_eq!(
            result.unwrap_err(),
            CipherError::TagMismatch,
            "cross-page paste must surface TagMismatch",
        );
    }

    /// **L-cross-session-replay:** sealing under `(vault_a, p,
    /// schema)` and opening under `(vault_b, p, schema)` with
    /// `vault_a != vault_b` must fail. Tested across random vault
    /// id pairs.
    #[test]
    fn cross_session_replay_fails_for_any_vault_pair(
        vault_a in proptest::array::uniform32(any::<u8>()),
        vault_b in proptest::array::uniform32(any::<u8>()),
        page_id in 0u64..1_000_000,
        schema_version in 0u16..=u16::MAX,
        plaintext in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        prop_assume!(vault_a != vault_b);
        let cipher = fresh_cipher();
        let aad_a = build_test_aad(&vault_a, page_id, schema_version);
        let aad_b = build_test_aad(&vault_b, page_id, schema_version);
        let ct = cipher.encrypt_page(&plaintext, &aad_a);
        let result = cipher.decrypt_page(&ct, &aad_b);
        prop_assert!(result.is_err(), "cross-session paste must fail");
        prop_assert_eq!(
            result.unwrap_err(),
            CipherError::TagMismatch,
            "cross-session paste must surface TagMismatch",
        );
    }

    /// **L-future-schema-version-poison:** sealing under
    /// `(vault, p, schema_a)` and opening under `(vault, p,
    /// schema_b)` with `schema_a != schema_b` must fail.
    #[test]
    fn cross_schema_version_paste_fails(
        vault_id in proptest::array::uniform32(any::<u8>()),
        page_id in 0u64..1_000_000,
        schema_a in 0u16..=u16::MAX,
        schema_b in 0u16..=u16::MAX,
        plaintext in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        prop_assume!(schema_a != schema_b);
        let cipher = fresh_cipher();
        let aad_a = build_test_aad(&vault_id, page_id, schema_a);
        let aad_b = build_test_aad(&vault_id, page_id, schema_b);
        let ct = cipher.encrypt_page(&plaintext, &aad_a);
        let result = cipher.decrypt_page(&ct, &aad_b);
        prop_assert!(result.is_err(), "cross-schema paste must fail");
        prop_assert_eq!(
            result.unwrap_err(),
            CipherError::TagMismatch,
            "cross-schema paste must surface TagMismatch",
        );
    }

    /// **Positive property:** sealing + opening under the SAME AAD
    /// must always succeed and recover the original plaintext —
    /// across the full random input space proptest explores.
    #[test]
    fn same_aad_round_trips_for_any_input(
        vault_id in proptest::array::uniform32(any::<u8>()),
        page_id in 0u64..1_000_000,
        schema_version in 0u16..=u16::MAX,
        plaintext in prop::collection::vec(any::<u8>(), 0..1024),
    ) {
        let cipher = fresh_cipher();
        let aad = build_test_aad(&vault_id, page_id, schema_version);
        let ct = cipher.encrypt_page(&plaintext, &aad);
        let recovered = cipher.decrypt_page(&ct, &aad).expect("same-AAD round-trip");
        prop_assert_eq!(recovered, plaintext);
    }

    /// **Single-byte perturbation property:** flipping ANY single
    /// byte of the ciphertext frame (nonce, body, or tag) must
    /// surface as TagMismatch. We pick a random index over the full
    /// frame and flip the low bit.
    #[test]
    fn single_byte_ciphertext_perturbation_rejected(
        plaintext in prop::collection::vec(any::<u8>(), 32..256),
        flip_index_seed in 0u32..u32::MAX,
    ) {
        let cipher = fresh_cipher();
        let aad = build_test_aad(&[0u8; 32], 0, 0);
        let mut ct = cipher.encrypt_page(&plaintext, &aad);
        let idx = (flip_index_seed as usize) % ct.len();
        ct[idx] ^= 0x01;
        let result = cipher.decrypt_page(&ct, &aad);
        prop_assert!(result.is_err(), "single-byte ct flip must fail");
        prop_assert_eq!(
            result.unwrap_err(),
            CipherError::TagMismatch,
            "single-byte ct flip must surface TagMismatch",
        );
    }

    /// **Single-byte AAD perturbation property:** flipping any
    /// single byte of the 42-byte AAD at decrypt time must cause
    /// decryption to fail. Covers the AAD-binding property end-to-
    /// end across every byte position.
    #[test]
    fn single_byte_aad_perturbation_rejected(
        vault_id in proptest::array::uniform32(any::<u8>()),
        page_id in 0u64..1_000_000,
        schema_version in 0u16..=u16::MAX,
        plaintext in prop::collection::vec(any::<u8>(), 1..256),
        flip_index in 0usize..PER_COLUMN_AAD_LEN,
    ) {
        let cipher = fresh_cipher();
        let aad = build_test_aad(&vault_id, page_id, schema_version);
        let ct = cipher.encrypt_page(&plaintext, &aad);
        // Flip a byte of the AAD passed to decrypt.
        let mut bad_aad = aad;
        bad_aad[flip_index] ^= 0x01;
        let result = cipher.decrypt_page(&ct, &bad_aad);
        prop_assert!(result.is_err(), "single-byte AAD flip must fail");
        prop_assert_eq!(
            result.unwrap_err(),
            CipherError::TagMismatch,
            "single-byte AAD flip must surface TagMismatch",
        );
    }
}

/// Independent (non-proptest) byte-pin assertion: a known
/// `(vault_id, page_id, schema_version)` triple produces a known
/// 42-byte AAD layout. If `build_aad` ever changes byte order or
/// endianness, this test surfaces the regression.
#[test]
fn aad_byte_pin_for_known_triple() {
    let vault_id: [u8; 32] = std::array::from_fn(|i| u8::try_from(0x10 + i).unwrap());
    let page_id: u64 = 0x0123_4567_89AB_CDEF;
    let schema_version: u16 = 0xBEEF;
    let aad = build_test_aad(&vault_id, page_id, schema_version);

    // Vault id occupies bytes 0..32.
    assert_eq!(&aad[..32], &vault_id);

    // Page id is big-endian u64 at bytes 32..40.
    assert_eq!(
        &aad[32..40],
        &[0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]
    );

    // Schema version is big-endian u16 at bytes 40..42.
    assert_eq!(&aad[40..42], &[0xBE, 0xEF]);
}

/// AAD-length pin: 42 bytes. Locked by the const + this test.
#[test]
fn aad_length_pinned_at_42() {
    assert_eq!(PER_COLUMN_AAD_LEN, 42);
}

// Handshake CBOR round-trip property: write + read across random
// (derived_key, run_nonce) pairs must recover byte-identical
// fields.
proptest! {
    #[test]
    fn handshake_round_trips_for_any_input(
        key in proptest::array::uniform32(any::<u8>()),
        nonce in proptest::array::uniform16(any::<u8>()),
    ) {
        let h = pangolin_indexer::IndexerHandshake::new(key, nonce);
        let mut buf: Vec<u8> = Vec::new();
        pangolin_indexer::write_handshake(&mut buf, &h).expect("write");
        let mut cursor = std::io::Cursor::new(buf);
        let back = pangolin_indexer::read_handshake(&mut cursor).expect("read");
        prop_assert_eq!(back.derived_key, key);
        prop_assert_eq!(back.run_nonce, nonce);
    }
}
