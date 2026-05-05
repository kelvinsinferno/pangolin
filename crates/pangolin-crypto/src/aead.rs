//! Authenticated encryption with associated data — `XChaCha20-Poly1305`.
//!
//! XChaCha20-Poly1305 is preferred over the original RFC 8439
//! ChaCha20-Poly1305 because its 24-byte nonce makes random-nonce
//! collisions cryptographically negligible for our usage profile (vault
//! revisions produced concurrently across many devices).
//!
//! AAD usage: every revision encryption MUST bind a context blob
//! containing `vault_id || account_id || parent_revision_id ||
//! schema_version` so a ciphertext from one context cannot be replayed in
//! another. This crate exposes the AAD as an opaque `&[u8]`; defining the
//! framing is the responsibility of `pangolin-store`.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::rng::{CryptoRng, OsRng, RngCore};

/// Length of an [`AeadKey`] in bytes.
pub const KEY_LEN: usize = 32;

/// Length of a [`Nonce`] in bytes (`XChaCha20` uses a 192-bit nonce).
pub const NONCE_LEN: usize = 24;

/// Length of the Poly1305 authentication tag in bytes.
pub const TAG_LEN: usize = 16;

/// 256-bit symmetric key for `XChaCha20-Poly1305`.
///
/// Zeroes its memory on drop; never implements [`Clone`], [`Copy`], or
/// [`PartialEq`]. Use [`AeadKey::ct_eq`] for constant-time equality.
pub struct AeadKey {
    /// Inner buffer is `Zeroizing<[u8; 32]>` — `[u8; N]` implements
    /// [`Zeroize`] for any `N`, and the wrapper guarantees `zeroize` runs
    /// on every drop path including panic unwinding.
    inner: Zeroizing<[u8; KEY_LEN]>,
}

impl AeadKey {
    /// Generates a fresh random key from the OS CSPRNG.
    #[must_use]
    pub fn generate() -> Self {
        Self::generate_with(&mut OsRng)
    }

    /// Generates a fresh random key from a caller-supplied CSPRNG.
    ///
    /// Used by tests that need reproducibility.
    pub fn generate_with<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut bytes = [0u8; KEY_LEN];
        rng.fill_bytes(&mut bytes);
        let inner = Zeroizing::new(bytes);
        bytes.zeroize();
        Self { inner }
    }

    /// Wraps caller-supplied key bytes.
    ///
    /// The caller's array is moved in, then zeroed on the stack via
    /// [`Zeroize`] so a stale stack frame cannot leak the key.
    #[must_use]
    pub fn from_bytes(mut bytes: [u8; KEY_LEN]) -> Self {
        let inner = Zeroizing::new(bytes);
        bytes.zeroize();
        Self { inner }
    }

    /// Constant-time equality with another key.
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> subtle::Choice {
        let a: &[u8] = &*self.inner;
        let b: &[u8] = &*other.inner;
        a.ct_eq(b)
    }

    /// Encrypts and authenticates `plaintext` under this key, binding `aad`.
    ///
    /// The returned [`Ciphertext`] includes the 16-byte Poly1305 tag at the
    /// tail of its byte buffer (`RustCrypto` convention).
    pub fn seal(
        &self,
        nonce: &Nonce,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Ciphertext, AeadError> {
        let cipher =
            XChaCha20Poly1305::new_from_slice(&*self.inner).map_err(|_| AeadError::InvalidKey)?;
        let payload = Payload {
            msg: plaintext,
            aad,
        };
        let ct = cipher
            .encrypt(chacha20poly1305::XNonce::from_slice(&nonce.0), payload)
            .map_err(|_| AeadError::Internal)?;
        Ok(Ciphertext(ct))
    }

    /// Decrypts and verifies `ciphertext` under this key, requiring `aad`
    /// to match what was used during sealing.
    ///
    /// Returns [`AeadError::Tampered`] for any authentication failure —
    /// wrong key, wrong nonce, modified ciphertext, modified AAD, or a
    /// truncated buffer all produce the same error so that callers cannot
    /// distinguish them.
    pub fn open(
        &self,
        nonce: &Nonce,
        ciphertext: &Ciphertext,
        aad: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        let cipher =
            XChaCha20Poly1305::new_from_slice(&*self.inner).map_err(|_| AeadError::InvalidKey)?;
        let payload = Payload {
            msg: ciphertext.as_bytes(),
            aad,
        };
        cipher
            .decrypt(chacha20poly1305::XNonce::from_slice(&nonce.0), payload)
            .map_err(|_| AeadError::Tampered)
    }
}

impl core::fmt::Debug for AeadKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AeadKey")
            .field("data", &"<redacted>")
            .finish()
    }
}

/// 192-bit nonce for `XChaCha20-Poly1305`.
///
/// Random nonces from a CSPRNG are collision-resistant for our usage profile
/// (≪ 2^96 messages per key); deterministic-nonce constructors are
/// deliberately not exposed.
#[derive(Clone, Copy)]
pub struct Nonce([u8; NONCE_LEN]);

impl Nonce {
    /// Generates a random nonce from the OS CSPRNG.
    #[must_use]
    pub fn random() -> Self {
        Self::random_with(&mut OsRng)
    }

    /// Generates a random nonce from a caller-supplied CSPRNG.
    pub fn random_with<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut n = [0u8; NONCE_LEN];
        rng.fill_bytes(&mut n);
        Self(n)
    }

    /// Wraps caller-supplied nonce bytes. Used only for known-answer test
    /// vectors; production code should always use [`Nonce::random`].
    #[must_use]
    pub const fn from_bytes(bytes: [u8; NONCE_LEN]) -> Self {
        Self(bytes)
    }

    /// Returns the raw nonce bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; NONCE_LEN] {
        &self.0
    }
}

impl core::fmt::Debug for Nonce {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Nonces aren't secret, but a hex blob is more useful than the array
        // form for log diffs.
        write!(f, "Nonce(")?;
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        write!(f, ")")
    }
}

/// Sealed ciphertext including the trailing Poly1305 authentication tag.
///
/// Wraps a `Vec<u8>` for ergonomics; the caller is responsible for
/// transporting the associated nonce alongside it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ciphertext(Vec<u8>);

impl Ciphertext {
    /// Wraps existing ciphertext bytes (e.g., loaded from disk).
    #[must_use]
    pub const fn from_vec(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Returns a borrow over the raw `ciphertext || tag` bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consumes the wrapper and returns the underlying byte vector.
    #[must_use]
    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }

    /// Returns the byte length of the sealed buffer (plaintext + tag).
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` when the buffer is empty. An empty buffer can never
    /// authenticate — even an empty plaintext seals to at least `TAG_LEN`
    /// bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Errors returned by AEAD seal/open.
///
/// Authentication failures collapse to a single [`AeadError::Tampered`]
/// variant so callers cannot distinguish the cause and inadvertently leak
/// information through error-handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadError {
    /// Authentication failed — wrong key, wrong nonce, wrong AAD, or the
    /// ciphertext was modified.
    Tampered,
    /// The supplied key bytes were the wrong length. Should be impossible
    /// from public APIs (constructors enforce length); kept for defense
    /// in depth.
    InvalidKey,
    /// Internal AEAD error during sealing — e.g., plaintext exceeded the
    /// `2^32 - 1` block limit. In practice this is unreachable for the
    /// sizes of payloads Pangolin handles.
    Internal,
}

impl core::fmt::Display for AeadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Tampered => f.write_str("AEAD authentication failed"),
            Self::InvalidKey => f.write_str("AEAD key was the wrong length"),
            Self::Internal => f.write_str("AEAD internal error"),
        }
    }
}

impl std::error::Error for AeadError {}

#[cfg(test)]
mod tests {
    use super::{AeadError, AeadKey, Ciphertext, Nonce, KEY_LEN, NONCE_LEN, TAG_LEN};
    use proptest::prelude::*;

    // ---------- Round-trip property test (≥1000 cases) ---------------

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 1024,
            ..ProptestConfig::default()
        })]

        #[test]
        fn round_trip(
            plaintext in proptest::collection::vec(any::<u8>(), 0..512),
            aad in proptest::collection::vec(any::<u8>(), 0..128),
            key_bytes in any::<[u8; KEY_LEN]>(),
            nonce_bytes in any::<[u8; NONCE_LEN]>(),
        ) {
            let key = AeadKey::from_bytes(key_bytes);
            let nonce = Nonce::from_bytes(nonce_bytes);
            let ct = key.seal(&nonce, &plaintext, &aad).unwrap();
            let pt = key.open(&nonce, &ct, &aad).unwrap();
            prop_assert_eq!(pt, plaintext);
        }

        #[test]
        fn tamper_ciphertext_fails(
            plaintext in proptest::collection::vec(any::<u8>(), 1..256),
            aad in proptest::collection::vec(any::<u8>(), 0..64),
            key_bytes in any::<[u8; KEY_LEN]>(),
            nonce_bytes in any::<[u8; NONCE_LEN]>(),
            flip_index in any::<usize>(),
            flip_bit in 0u8..8,
        ) {
            let key = AeadKey::from_bytes(key_bytes);
            let nonce = Nonce::from_bytes(nonce_bytes);
            let ct = key.seal(&nonce, &plaintext, &aad).unwrap();
            let mut bytes = ct.into_vec();
            let idx = flip_index % bytes.len();
            bytes[idx] ^= 1u8 << flip_bit;
            let tampered = Ciphertext::from_vec(bytes);
            let result = key.open(&nonce, &tampered, &aad);
            prop_assert_eq!(result.unwrap_err(), AeadError::Tampered);
        }

        #[test]
        fn tamper_aad_fails(
            plaintext in proptest::collection::vec(any::<u8>(), 0..256),
            aad in proptest::collection::vec(any::<u8>(), 1..64),
            key_bytes in any::<[u8; KEY_LEN]>(),
            nonce_bytes in any::<[u8; NONCE_LEN]>(),
            flip_index in any::<usize>(),
            flip_bit in 0u8..8,
        ) {
            let key = AeadKey::from_bytes(key_bytes);
            let nonce = Nonce::from_bytes(nonce_bytes);
            let ct = key.seal(&nonce, &plaintext, &aad).unwrap();
            let mut tampered_aad = aad;
            let idx = flip_index % tampered_aad.len();
            tampered_aad[idx] ^= 1u8 << flip_bit;
            let result = key.open(&nonce, &ct, &tampered_aad);
            prop_assert_eq!(result.unwrap_err(), AeadError::Tampered);
        }

        #[test]
        fn tamper_nonce_fails(
            plaintext in proptest::collection::vec(any::<u8>(), 1..256),
            aad in proptest::collection::vec(any::<u8>(), 0..64),
            key_bytes in any::<[u8; KEY_LEN]>(),
            nonce_bytes in any::<[u8; NONCE_LEN]>(),
            flip_index in 0usize..NONCE_LEN,
            flip_bit in 0u8..8,
        ) {
            let key = AeadKey::from_bytes(key_bytes);
            let nonce = Nonce::from_bytes(nonce_bytes);
            let ct = key.seal(&nonce, &plaintext, &aad).unwrap();
            let mut wrong = nonce_bytes;
            wrong[flip_index] ^= 1u8 << flip_bit;
            let wrong_nonce = Nonce::from_bytes(wrong);
            let result = key.open(&wrong_nonce, &ct, &aad);
            prop_assert_eq!(result.unwrap_err(), AeadError::Tampered);
        }
    }

    // ---------- Adversarial unit tests --------------------------------

    #[test]
    fn truncated_ciphertext_fails() {
        let key = AeadKey::from_bytes([0x42; KEY_LEN]);
        let nonce = Nonce::from_bytes([0x07; NONCE_LEN]);
        let ct = key.seal(&nonce, b"payload", b"context").unwrap();
        let mut bytes = ct.into_vec();
        bytes.pop(); // remove one byte from the tag
        let truncated = Ciphertext::from_vec(bytes);
        assert_eq!(
            key.open(&nonce, &truncated, b"context").unwrap_err(),
            AeadError::Tampered,
        );
    }

    #[test]
    fn empty_aad_when_seal_used_aad_fails() {
        let key = AeadKey::from_bytes([0x99; KEY_LEN]);
        let nonce = Nonce::from_bytes([0x11; NONCE_LEN]);
        let ct = key.seal(&nonce, b"payload", b"vault-id-1").unwrap();
        // Open with empty AAD must fail because seal bound a non-empty AAD.
        assert_eq!(key.open(&nonce, &ct, b"").unwrap_err(), AeadError::Tampered,);
    }

    #[test]
    fn wrong_key_fails() {
        let k1 = AeadKey::from_bytes([0x01; KEY_LEN]);
        let k2 = AeadKey::from_bytes([0x02; KEY_LEN]);
        let nonce = Nonce::from_bytes([0x55; NONCE_LEN]);
        let ct = k1.seal(&nonce, b"hello", b"aad").unwrap();
        assert_eq!(
            k2.open(&nonce, &ct, b"aad").unwrap_err(),
            AeadError::Tampered,
        );
    }

    #[test]
    fn ciphertext_includes_tag() {
        let key = AeadKey::from_bytes([0u8; KEY_LEN]);
        let nonce = Nonce::from_bytes([0u8; NONCE_LEN]);
        let pt = b"abc";
        let ct = key.seal(&nonce, pt, b"").unwrap();
        assert_eq!(ct.len(), pt.len() + TAG_LEN);
    }

    #[test]
    fn debug_redacts_aead_key() {
        let key = AeadKey::from_bytes([0xAB; KEY_LEN]);
        let printed = format!("{key:?}");
        assert!(printed.contains("<redacted>"));
        assert!(!printed.contains("ab"));
    }

    #[test]
    fn aead_key_ct_eq() {
        let a = AeadKey::from_bytes([0x33; KEY_LEN]);
        let b = AeadKey::from_bytes([0x33; KEY_LEN]);
        let c = AeadKey::from_bytes([0x34; KEY_LEN]);
        assert!(bool::from(a.ct_eq(&b)));
        assert!(!bool::from(a.ct_eq(&c)));
    }

    // ---------- RFC test vectors --------------------------------------

    /// IETF XChaCha20-Poly1305 reference vector, from
    /// `draft-irtf-cfrg-xchacha-03` Appendix A.3.1. This is the canonical
    /// known-answer test for the construction.
    #[test]
    fn rfc_xchacha20_poly1305_kat() {
        let plaintext = hex::decode(concat!(
            "4c616469657320616e642047656e746c656d656e206f662074686520636c6173",
            "73206f66202739393a204966204920636f756c64206f6666657220796f75206f",
            "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73",
            "637265656e20776f756c642062652069742e",
        ))
        .unwrap();
        let aad = hex::decode("50515253c0c1c2c3c4c5c6c7").unwrap();
        let key_bytes: [u8; KEY_LEN] =
            hex::decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
                .unwrap()
                .try_into()
                .unwrap();
        let nonce_bytes: [u8; NONCE_LEN] =
            hex::decode("404142434445464748494a4b4c4d4e4f5051525354555657")
                .unwrap()
                .try_into()
                .unwrap();
        let expected = hex::decode(concat!(
            "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb",
            "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452",
            "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9",
            "21f9664c97637da9768812f615c68b13b52e",
            // 16-byte Poly1305 tag:
            "c0875924c1c7987947deafd8780acf49",
        ))
        .unwrap();

        let key = AeadKey::from_bytes(key_bytes);
        let nonce = Nonce::from_bytes(nonce_bytes);
        let got = key.seal(&nonce, &plaintext, &aad).unwrap();
        assert_eq!(
            hex::encode(got.as_bytes()),
            hex::encode(&expected),
            "XChaCha20-Poly1305 KAT mismatch — algorithm or wiring is wrong"
        );

        // And the inverse direction:
        let recovered = key
            .open(&nonce, &Ciphertext::from_vec(expected), &aad)
            .unwrap();
        assert_eq!(recovered, plaintext);
    }

    /// Negative control: flipping a byte of the KAT ciphertext must fail.
    #[test]
    fn rfc_xchacha20_kat_tamper_fails() {
        let key = AeadKey::from_bytes(
            hex::decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
                .unwrap()
                .try_into()
                .unwrap(),
        );
        let nonce = Nonce::from_bytes(
            hex::decode("404142434445464748494a4b4c4d4e4f5051525354555657")
                .unwrap()
                .try_into()
                .unwrap(),
        );
        let aad = hex::decode("50515253c0c1c2c3c4c5c6c7").unwrap();
        let mut bytes = hex::decode(concat!(
            "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb",
            "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452",
            "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9",
            "21f9664c97637da9768812f615c68b13b52e",
            "c0875924c1c7987947deafd8780acf49",
        ))
        .unwrap();
        bytes[0] ^= 0x01;
        assert_eq!(
            key.open(&nonce, &Ciphertext::from_vec(bytes), &aad)
                .unwrap_err(),
            AeadError::Tampered,
        );
    }
}
