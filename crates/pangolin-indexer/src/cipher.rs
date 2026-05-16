// SPDX-License-Identifier: AGPL-3.0-or-later
//! Temp-DB page cipher — trait surface + production [`AeadCipher`].
//!
//! 4.2 shipped the [`TempDbCipher`] trait + a passthrough
//! [`NoOpCipher`] stub. **4.3 ships [`AeadCipher`]**: the production
//! `XChaCha20-Poly1305` impl with a per-page random 24-byte nonce,
//! a [`SecretBytes`]-wrapped 32-byte ephemeral key, and tag-tamper
//! propagation via the new typed [`CipherError`] variant.
//!
//! ## Trait signature change vs 4.2
//!
//! 4.2's trait was:
//!
//! ```ignore
//! fn decrypt_page(&self, ciphertext: &[u8]) -> Vec<u8>;
//! ```
//!
//! 4.3 changes the return type to `Result<Vec<u8>, CipherError>` so
//! that AEAD tag-mismatch (a tampered ciphertext) propagates as a
//! typed error rather than panicking or silently returning corrupt
//! plaintext. Per L-tampered-ciphertext (4.3 plan-gate adversarial
//! framing): tampering MUST surface as a typed error, never silently
//! accepted.
//!
//! [`NoOpCipher`] — the test-only passthrough — is updated to match
//! the new signature (its `decrypt_page` always returns
//! `Ok(ciphertext.to_vec())`). Production builds construct
//! [`AeadCipher`] exclusively (4.3 L10).
//!
//! ## L invariants honored here (from 4.3 plan-gate)
//!
//! - **L1:** AEAD primitive is `XChaCha20-Poly1305` from
//!   `pangolin_crypto::aead`. No new crypto crate dep.
//! - **L2:** Per-page random 24-byte nonce via
//!   `pangolin_crypto::rng::fill_random`. The 192-bit nonce makes
//!   collision probability ~2^-96 per call — negligible for
//!   ≤ 2^32 calls.
//! - **L3:** The ephemeral key is held in
//!   [`pangolin_crypto::secret::SecretBytes`] (heap-allocated;
//!   zeroed on Drop). Never serialized; never logged.
//! - **L7:** `forbid(unsafe_code)` (crate-wide via `lib.rs`).
//! - **L10:** [`AeadCipher`] is the ONLY production cipher.
//!   [`NoOpCipher`] stays behind `#[cfg(any(test,
//!   feature = "test-utilities"))]` so a production build cannot
//!   accidentally instantiate it.
//!
//! ## Wire framing — `nonce ‖ ciphertext_with_tag`
//!
//! Each call to `AeadCipher::encrypt_page(plaintext)` returns a
//! buffer of layout
//!
//! ```text
//! [nonce: 24 bytes][ciphertext: plaintext.len() bytes][tag: 16 bytes]
//! ```
//!
//! totalling `24 + plaintext.len() + 16` bytes. `decrypt_page`
//! reverses the framing: peels off the 24-byte nonce prefix, opens
//! the AEAD, returns the original plaintext. Any input shorter than
//! 40 bytes (`24 + 16` — the minimum frame for empty plaintext)
//! decrypts to [`CipherError::FramingTooShort`]; any tag-mismatch
//! (or nonce-tamper, body-tamper, AAD-mismatch) decrypts to
//! [`CipherError::TagMismatch`].

use std::sync::Arc;

use pangolin_crypto::aead::{AeadError, AeadKey, Ciphertext, Nonce, NONCE_LEN, TAG_LEN};
use pangolin_crypto::rng::fill_random;
use pangolin_crypto::secret::SecretBytes;

/// Length of the AEAD key (32 bytes) the [`AeadCipher`] wraps. Must
/// match `pangolin_crypto::aead::KEY_LEN` (the underlying AeadKey
/// length).
pub const AEAD_KEY_LEN: usize = 32;

/// Errors returned by the [`TempDbCipher::decrypt_page`] path.
///
/// Per L-tampered-ciphertext (4.3): all authentication failures
/// collapse to [`CipherError::TagMismatch`] so callers cannot
/// distinguish nonce-tamper from body-tamper from AAD-mismatch — same
/// discipline `pangolin_crypto::aead::AeadError::Tampered` already
/// uses (LOW-12).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherError {
    /// AEAD authentication failed — wrong key, modified ciphertext,
    /// modified nonce, or modified AAD. The opaque single-variant
    /// shape prevents callers from constructing a distinguishing
    /// oracle on the failure mode.
    TagMismatch,
    /// Input buffer is shorter than `NONCE_LEN + TAG_LEN`
    /// (= 40 bytes). An empty plaintext seals to exactly 40 bytes;
    /// anything shorter cannot possibly authenticate. Caught
    /// deterministically before the AEAD primitive is invoked so we
    /// never hand a nonsense buffer to `AeadKey::open`.
    FramingTooShort,
}

impl core::fmt::Display for CipherError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TagMismatch => f.write_str("AEAD tag mismatch (page tampered or wrong key)"),
            Self::FramingTooShort => f.write_str("ciphertext frame shorter than nonce+tag"),
        }
    }
}

impl std::error::Error for CipherError {}

impl From<AeadError> for CipherError {
    fn from(_: AeadError) -> Self {
        // All AeadError variants collapse to TagMismatch at the
        // cipher boundary — see module-doc on the
        // distinguishing-oracle defense. The other AeadError
        // variants (`InvalidKey`, `Internal`) are unreachable on the
        // open path with a 32-byte key, so this collapse is sound.
        Self::TagMismatch
    }
}

/// Per-page block cipher used by the temp DB. `encrypt_page` is
/// called before each page write; `decrypt_page` is called after
/// each page read. The trait is `Send + Sync` so it can be shared
/// across the lifecycle task in both the desktop subprocess and
/// mobile in-process flows (4.2 L12).
///
/// **4.3 signature change:** `decrypt_page` now returns
/// `Result<Vec<u8>, CipherError>` so AEAD tag-mismatch surfaces as a
/// typed error rather than silently returning corrupt plaintext.
/// 4.2's `NoOpCipher` is updated to match (always returns
/// `Ok(ciphertext.to_vec())`).
pub trait TempDbCipher: Send + Sync + std::fmt::Debug {
    /// Transform a plaintext page into the ciphertext to write on
    /// disk. The production [`AeadCipher`] returns
    /// `nonce ‖ ciphertext_with_tag` (length =
    /// `NONCE_LEN + plaintext.len() + TAG_LEN`); the test-only
    /// [`NoOpCipher`] returns `plaintext.to_vec()`.
    fn encrypt_page(&self, plaintext: &[u8]) -> Vec<u8>;

    /// Transform a ciphertext page read off disk back into
    /// plaintext.
    ///
    /// # Errors
    ///
    /// - [`CipherError::TagMismatch`] when the AEAD tag does not
    ///   verify (tampered nonce, tampered body, tampered tag, wrong
    ///   key, or wrong AAD).
    /// - [`CipherError::FramingTooShort`] when the input is shorter
    ///   than `NONCE_LEN + TAG_LEN` (impossible for any output of
    ///   `encrypt_page`).
    fn decrypt_page(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CipherError>;
}

// ---------------------------------------------------------------------
// AeadCipher — production impl (4.3 R-b)
// ---------------------------------------------------------------------

/// Production `XChaCha20-Poly1305` page cipher (4.3 R-b).
///
/// Holds a [`SecretBytes`]-wrapped 32-byte ephemeral key. Each
/// [`Self::encrypt_page`] call generates a fresh random 24-byte
/// nonce via [`fill_random`] and seals the plaintext via the
/// `pangolin_crypto::aead::AeadKey::seal` primitive. The output
/// frame is `nonce ‖ ciphertext_with_tag`. Decrypt splits the
/// nonce off + opens the AEAD.
///
/// **No state between calls** — every `encrypt_page` is a self-
/// contained operation; the underlying `AeadKey` is `Send + Sync`
/// (heap-allocated through `BoxedSecret`); the `SecretBytes`
/// wrapper around the key is held by reference inside the cipher.
pub struct AeadCipher {
    key: SecretBytes,
}

impl AeadCipher {
    /// Construct an [`AeadCipher`] from a 32-byte ephemeral key.
    ///
    /// # Panics
    ///
    /// Panics in debug builds if `key.expose().len() != 32`. In
    /// release builds the key length is enforced indirectly by the
    /// underlying `AeadKey::from_bytes` constructor — a mismatched
    /// length would surface as `CipherError::TagMismatch` at the
    /// first decrypt. Callers SHOULD use the typed
    /// [`pangolin_chain::derive_indexer_key`] helper which always
    /// returns a 32-byte `SecretBytes`.
    #[must_use]
    pub fn new(key: SecretBytes) -> Self {
        debug_assert_eq!(
            key.expose().len(),
            AEAD_KEY_LEN,
            "AeadCipher requires a 32-byte key (XChaCha20-Poly1305 KEY_LEN)",
        );
        Self { key }
    }

    /// Construct an [`AeadCipher`] wrapped in
    /// `Arc<dyn TempDbCipher>` for the session lifecycle's expected
    /// shape. Mirrors [`NoOpCipher::new_arc`].
    #[must_use]
    pub fn new_arc(key: SecretBytes) -> Arc<dyn TempDbCipher> {
        Arc::new(Self::new(key))
    }

    /// Build the underlying `AeadKey` from the held key bytes.
    ///
    /// `AeadKey::from_bytes` consumes a `[u8; 32]` and zeroes the
    /// stack copy on entry; we copy the SecretBytes-held bytes into
    /// a stack array, hand them to `AeadKey::from_bytes`, then let
    /// the stack array drop. The key bytes inside `self.key` remain
    /// untouched (held in heap-allocated `SecretBytes` for the life
    /// of the cipher).
    fn aead_key(&self) -> AeadKey {
        let exposed = self.key.expose();
        // Length-check at debug time; the constructor's debug_assert
        // already covers this, but defense-in-depth here costs
        // nothing in release.
        debug_assert_eq!(exposed.len(), AEAD_KEY_LEN);
        let mut buf = [0u8; AEAD_KEY_LEN];
        buf.copy_from_slice(&exposed[..AEAD_KEY_LEN]);
        AeadKey::from_bytes(buf)
    }
}

impl std::fmt::Debug for AeadCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // L3 hygiene: never print the key bytes in `{:?}` output.
        // Mirrors `pangolin_crypto::aead::AeadKey`'s `<redacted>`
        // debug shape.
        f.debug_struct("AeadCipher")
            .field("key", &"<redacted>")
            .finish()
    }
}

impl TempDbCipher for AeadCipher {
    fn encrypt_page(&self, plaintext: &[u8]) -> Vec<u8> {
        // L2: fresh random 24-byte nonce per call. The 192-bit
        // XChaCha20 nonce makes collision negligible.
        let mut nonce_bytes = [0u8; NONCE_LEN];
        fill_random(&mut nonce_bytes);
        let nonce = Nonce::from_storage_bytes(nonce_bytes);

        // Seal under the held key with empty AAD. (The temp DB has
        // no per-page binding context; future hardening could mix
        // page_id + vault_id into AAD per L-tampered-ciphertext (c)
        // but 4.3 ships the minimal seal as the load-bearing step;
        // the AAD discipline is per-call hardening that can be added
        // additively without a wire-format break.)
        let key = self.aead_key();
        let ct = key
            .seal(&nonce, plaintext, &[])
            .expect("XChaCha20-Poly1305 seal cannot fail for a 32-byte key + 24-byte nonce");
        let ct_bytes = ct.into_vec();

        // Frame: nonce_bytes ‖ ciphertext_with_tag
        let mut out = Vec::with_capacity(NONCE_LEN + ct_bytes.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ct_bytes);
        out
    }

    fn decrypt_page(&self, input: &[u8]) -> Result<Vec<u8>, CipherError> {
        // Framing check: any input shorter than NONCE_LEN + TAG_LEN
        // cannot possibly authenticate. Caught deterministically
        // before the AEAD primitive is invoked.
        if input.len() < NONCE_LEN + TAG_LEN {
            return Err(CipherError::FramingTooShort);
        }
        let mut nonce_bytes = [0u8; NONCE_LEN];
        nonce_bytes.copy_from_slice(&input[..NONCE_LEN]);
        let nonce = Nonce::from_storage_bytes(nonce_bytes);
        let ct = Ciphertext::from_vec(input[NONCE_LEN..].to_vec());

        let key = self.aead_key();
        // Any AeadError -> CipherError::TagMismatch via the From
        // impl. The opaque single-variant shape on tamper failures
        // is the L-tampered-ciphertext discipline.
        Ok(key.open(&nonce, &ct, &[])?)
    }
}

// ---------------------------------------------------------------------
// NoOpCipher — test-only passthrough (4.3 L10)
// ---------------------------------------------------------------------

/// 4.2 R-d no-op cipher — identity functions on both sides.
///
/// **Test-only (4.3 L10).** Production builds cannot reach this
/// type; it lives behind `#[cfg(any(test, feature = "test-utilities"))]`
/// to enforce the discipline that the production `bin/` entry
/// constructs [`AeadCipher`] exclusively. Hermetic round-trip tests
/// in the indexer crate still use it for backward compatibility
/// with the 4.2 lifecycle assertions.
#[cfg(any(test, feature = "test-utilities"))]
#[derive(Debug, Clone, Copy, Default)]
pub struct NoOpCipher;

#[cfg(any(test, feature = "test-utilities"))]
impl NoOpCipher {
    /// Constructor convenience. Returns an `Arc<dyn TempDbCipher>`
    /// in the shape the session expects.
    #[must_use]
    pub fn new_arc() -> Arc<dyn TempDbCipher> {
        Arc::new(Self)
    }
}

#[cfg(any(test, feature = "test-utilities"))]
impl TempDbCipher for NoOpCipher {
    fn encrypt_page(&self, plaintext: &[u8]) -> Vec<u8> {
        plaintext.to_vec()
    }

    fn decrypt_page(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CipherError> {
        // Passthrough — never fails. Round-trip identity for the
        // 4.2 lifecycle probe + scaffolding tests.
        Ok(ciphertext.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pangolin_crypto::aead::{NONCE_LEN, TAG_LEN};

    // ---------- 4.2 NoOpCipher regression tests ----------

    #[test]
    fn noop_encrypt_is_identity_on_empty_input() {
        let c = NoOpCipher;
        assert_eq!(c.encrypt_page(&[]), Vec::<u8>::new());
    }

    #[test]
    fn noop_encrypt_is_identity_on_arbitrary_input() {
        let c = NoOpCipher;
        let plaintext = b"the temp DB is full of pancakes";
        assert_eq!(c.encrypt_page(plaintext), plaintext.to_vec());
    }

    #[test]
    fn noop_decrypt_is_identity() {
        let c = NoOpCipher;
        let ciphertext = vec![1, 2, 3, 4, 5];
        assert_eq!(c.decrypt_page(&ciphertext).unwrap(), ciphertext);
    }

    #[test]
    fn noop_round_trips() {
        // 4.2 R-d test contract: NoOpCipher must round-trip
        // identically. 4.3's AeadCipher must also satisfy this
        // contract (with the ephemeral key threaded through).
        let c = NoOpCipher;
        for n in [0usize, 1, 16, 4096, 1 << 16] {
            let buf: Vec<u8> = (0..n).map(|i| u8::try_from(i & 0xFF).unwrap()).collect();
            let enc = c.encrypt_page(&buf);
            let dec = c.decrypt_page(&enc).unwrap();
            assert_eq!(buf, dec, "round-trip failed for n = {n}");
        }
    }

    #[test]
    fn noop_cipher_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<NoOpCipher>();
        // The Arc<dyn TempDbCipher> shape the session uses.
        let arc: Arc<dyn TempDbCipher> = NoOpCipher::new_arc();
        assert_eq!(arc.encrypt_page(b"x"), b"x".to_vec());
        assert_eq!(arc.decrypt_page(b"x").unwrap(), b"x".to_vec());
    }

    // ---------- 4.3 R-e: AeadCipher round-trip across input sizes ----------

    /// Produce a fresh AeadCipher with a known key (derived
    /// in-test, not from a real DeviceKey — this test is a pure
    /// AEAD round-trip exercise; the key-derivation tests live in
    /// `pangolin-chain::evm::tests`).
    fn fresh_cipher() -> AeadCipher {
        let mut key_bytes = [0u8; AEAD_KEY_LEN];
        fill_random(&mut key_bytes);
        AeadCipher::new(SecretBytes::new(key_bytes.to_vec()))
    }

    #[test]
    fn aead_cipher_round_trip_zero_bytes() {
        let c = fresh_cipher();
        let pt: &[u8] = &[];
        let ct = c.encrypt_page(pt);
        // Frame layout: nonce (24) ‖ tag (16) for empty plaintext.
        assert_eq!(ct.len(), NONCE_LEN + TAG_LEN);
        let recovered = c.decrypt_page(&ct).unwrap();
        assert_eq!(recovered, pt);
    }

    #[test]
    fn aead_cipher_round_trip_one_byte() {
        let c = fresh_cipher();
        let pt = b"X";
        let ct = c.encrypt_page(pt);
        assert_eq!(ct.len(), NONCE_LEN + 1 + TAG_LEN);
        let recovered = c.decrypt_page(&ct).unwrap();
        assert_eq!(recovered, pt.to_vec());
    }

    #[test]
    fn aead_cipher_round_trip_100_bytes() {
        let c = fresh_cipher();
        let pt: Vec<u8> = (0u8..100).collect();
        let ct = c.encrypt_page(&pt);
        assert_eq!(ct.len(), NONCE_LEN + pt.len() + TAG_LEN);
        let recovered = c.decrypt_page(&ct).unwrap();
        assert_eq!(recovered, pt);
    }

    #[test]
    fn aead_cipher_round_trip_4kb() {
        // Typical SQLite page size — pinned to ensure the framing
        // overhead doesn't regress for the most common payload.
        let c = fresh_cipher();
        let pt: Vec<u8> = (0..4096).map(|i| u8::try_from(i & 0xFF).unwrap()).collect();
        let ct = c.encrypt_page(&pt);
        assert_eq!(ct.len(), NONCE_LEN + pt.len() + TAG_LEN);
        let recovered = c.decrypt_page(&ct).unwrap();
        assert_eq!(recovered, pt);
    }

    #[test]
    fn aead_cipher_round_trip_64kb() {
        // Large payload — ensures the seal + open cost scales
        // linearly without quadratic regression in framing logic.
        let c = fresh_cipher();
        let pt: Vec<u8> = (0..65_536)
            .map(|i| u8::try_from(i & 0xFF).unwrap())
            .collect();
        let ct = c.encrypt_page(&pt);
        assert_eq!(ct.len(), NONCE_LEN + pt.len() + TAG_LEN);
        let recovered = c.decrypt_page(&ct).unwrap();
        assert_eq!(recovered, pt);
    }

    // ---------- 4.3 R-e + L2: nonce-distinctness across many calls ----------

    #[test]
    fn aead_cipher_nonce_distinct_across_1000_calls() {
        // L2 (the load-bearing crypto property): per-page random
        // 24-byte nonces must never collide. 1000 encryptions of
        // the same plaintext under the same key MUST produce 1000
        // distinct ciphertext frames (the nonce prefix is fresh
        // every call). If this fails, XChaCha20 leaks both
        // plaintexts on the colliding pair — catastrophic.
        let c = fresh_cipher();
        let pt = b"identical plaintext across all 1000 calls";
        let mut nonces = std::collections::HashSet::with_capacity(1000);
        for _ in 0..1000 {
            let frame = c.encrypt_page(pt);
            let mut nonce = [0u8; NONCE_LEN];
            nonce.copy_from_slice(&frame[..NONCE_LEN]);
            assert!(
                nonces.insert(nonce),
                "nonce collision detected across 1000 calls — XChaCha20 catastrophe",
            );
        }
        assert_eq!(nonces.len(), 1000);
    }

    // ---------- 4.3 R-e + L-tampered-ciphertext: adversarial decode ----------

    #[test]
    fn aead_cipher_tag_tamper_rejects() {
        // Flip a bit in the LAST byte (the Poly1305 tag tail) —
        // must surface as TagMismatch.
        let c = fresh_cipher();
        let pt = b"plaintext to seal";
        let mut ct = c.encrypt_page(pt);
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        let result = c.decrypt_page(&ct);
        assert_eq!(
            result.unwrap_err(),
            CipherError::TagMismatch,
            "tag tamper must surface as TagMismatch",
        );
    }

    #[test]
    fn aead_cipher_nonce_tamper_rejects() {
        // Flip a bit in the FIRST byte (the nonce prefix) — must
        // surface as TagMismatch (the nonce is part of the AEAD
        // computation, so any flip propagates to the tag).
        let c = fresh_cipher();
        let pt = b"plaintext to seal";
        let mut ct = c.encrypt_page(pt);
        ct[0] ^= 0x01;
        let result = c.decrypt_page(&ct);
        assert_eq!(
            result.unwrap_err(),
            CipherError::TagMismatch,
            "nonce tamper must surface as TagMismatch",
        );
    }

    #[test]
    fn aead_cipher_body_tamper_rejects() {
        // Flip a bit in the MIDDLE (the ciphertext body, after
        // nonce, before tag) — must surface as TagMismatch.
        let c = fresh_cipher();
        let pt: Vec<u8> = (0u8..64).collect();
        let mut ct = c.encrypt_page(&pt);
        let middle = NONCE_LEN + 8; // 8 bytes into the body
        ct[middle] ^= 0x01;
        let result = c.decrypt_page(&ct);
        assert_eq!(
            result.unwrap_err(),
            CipherError::TagMismatch,
            "body tamper must surface as TagMismatch",
        );
    }

    #[test]
    fn aead_cipher_truncated_frame_rejects() {
        // Anything shorter than NONCE_LEN + TAG_LEN cannot
        // authenticate — surface as FramingTooShort
        // deterministically (don't even invoke the AEAD).
        let c = fresh_cipher();
        for short_len in 0..(NONCE_LEN + TAG_LEN) {
            let buf = vec![0u8; short_len];
            let result = c.decrypt_page(&buf);
            assert_eq!(
                result.unwrap_err(),
                CipherError::FramingTooShort,
                "input length {short_len} must surface as FramingTooShort",
            );
        }
    }

    #[test]
    fn aead_cipher_wrong_key_rejects() {
        // Encrypt under key A, decrypt under key B → TagMismatch.
        let c1 = fresh_cipher();
        let c2 = fresh_cipher();
        let pt = b"sensitive metadata";
        let ct = c1.encrypt_page(pt);
        let result = c2.decrypt_page(&ct);
        assert_eq!(
            result.unwrap_err(),
            CipherError::TagMismatch,
            "wrong-key decrypt must surface as TagMismatch",
        );
    }

    #[test]
    fn aead_cipher_debug_redacts_key() {
        let c = fresh_cipher();
        let printed = format!("{c:?}");
        assert!(printed.contains("<redacted>"));
        // The key bytes must not appear in any form. We don't have
        // direct access to the key from the test, but `<redacted>`
        // is the documented marker.
        assert!(printed.contains("AeadCipher"));
    }

    #[test]
    fn aead_cipher_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<AeadCipher>();
        let mut k = [0u8; AEAD_KEY_LEN];
        fill_random(&mut k);
        let arc: Arc<dyn TempDbCipher> = AeadCipher::new_arc(SecretBytes::new(k.to_vec()));
        let pt = b"sample";
        let ct = arc.encrypt_page(pt);
        let recovered = arc.decrypt_page(&ct).unwrap();
        assert_eq!(recovered, pt);
    }

    // ---------- CipherError shape ----------

    #[test]
    fn cipher_error_display_renders_human_strings() {
        assert!(CipherError::TagMismatch
            .to_string()
            .contains("tag mismatch"));
        assert!(CipherError::FramingTooShort.to_string().contains("frame"));
    }

    #[test]
    fn cipher_error_from_aead_error_collapses_to_tag_mismatch() {
        let e: CipherError = AeadError::Tampered.into();
        assert_eq!(e, CipherError::TagMismatch);
        let e: CipherError = AeadError::InvalidKey.into();
        assert_eq!(e, CipherError::TagMismatch);
        let e: CipherError = AeadError::Internal.into();
        assert_eq!(e, CipherError::TagMismatch);
    }
}
