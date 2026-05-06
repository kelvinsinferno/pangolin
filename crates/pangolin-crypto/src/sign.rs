//! Ed25519 signing and verification.
//!
//! Backed by `ed25519-dalek` v2 (the audited, hardened branch). Every
//! verification path uses [`ed25519_dalek::VerifyingKey::verify_strict`] so
//! that non-canonical signatures and small-subgroup keys are rejected,
//! matching the RFC 8032 §5.1.7 conformance profile.
//!
//! Per D-006, on Pangolin a [`SigningKey`] is *both* the revision-signing
//! identity and the gas-paying wallet for a single device — the same
//! keypair backs both purposes. Higher-level abstractions
//! ([`crate::keys::AuthorityKey`], [`crate::keys::DeviceKey`]) wrap this
//! module; consumers outside `pangolin-crypto` should prefer those.

use ed25519_dalek::ed25519::signature::Signer;
use ed25519_dalek::{SigningKey as DalekSigningKey, VerifyingKey as DalekVerifyingKey};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::rng::{CryptoRng, OsRng, RngCore};

/// Length of an Ed25519 public key in bytes.
pub const PUBLIC_KEY_LEN: usize = 32;

/// Length of an Ed25519 secret seed in bytes.
pub const SECRET_KEY_LEN: usize = 32;

/// Length of an Ed25519 signature in bytes.
pub const SIGNATURE_LEN: usize = 64;

/// Ed25519 signing key.
///
/// Wraps `ed25519_dalek::SigningKey`, which itself zeroizes on drop. The
/// public surface here suppresses [`PartialEq`], [`Clone`], [`Copy`], and
/// [`serde::Serialize`] so that secret material cannot be cloned, compared
/// with timing leakage, or serialized without an explicit caller request.
pub struct SigningKey {
    inner: DalekSigningKey,
}

impl SigningKey {
    /// Generates a fresh keypair from the OS CSPRNG.
    #[must_use]
    pub fn generate() -> Self {
        Self::generate_with(&mut OsRng)
    }

    /// Generates a fresh keypair from a caller-supplied CSPRNG.
    ///
    /// Crate-private: production callers must use
    /// [`SigningKey::generate`] (which always pulls from `OsRng`) so an
    /// external caller cannot inject a deterministic / weak RNG. See
    /// MEDIUM-11.
    pub(crate) fn generate_with<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut seed = [0u8; SECRET_KEY_LEN];
        rng.fill_bytes(&mut seed);
        let inner = DalekSigningKey::from_bytes(&seed);
        seed.zeroize();
        Self { inner }
    }

    /// Wraps a 32-byte secret seed.
    ///
    /// Used for RFC 8032 known-answer tests. The caller's array is moved
    /// in and zeroed on the stack after the dalek key consumes it.
    #[must_use]
    pub fn from_seed(mut seed: [u8; SECRET_KEY_LEN]) -> Self {
        let inner = DalekSigningKey::from_bytes(&seed);
        seed.zeroize();
        Self { inner }
    }

    /// Returns the public verifying half of this keypair.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey {
            inner: self.inner.verifying_key(),
        }
    }

    /// Signs `message` and returns a detached 64-byte signature.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> Signature {
        Signature {
            inner: self.inner.sign(message),
        }
    }

    /// Constant-time equality with another signing key.
    ///
    /// The temporary byte copies of both seeds are wrapped in
    /// [`zeroize::Zeroizing`] so they are wiped before this function
    /// returns.
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> subtle::Choice {
        let a = zeroize::Zeroizing::new(self.inner.to_bytes());
        let b = zeroize::Zeroizing::new(other.inner.to_bytes());
        let a_slice: &[u8] = &*a;
        let b_slice: &[u8] = &*b;
        a_slice.ct_eq(b_slice)
    }

    /// Crate-internal accessor returning a zeroizing copy of the 32-byte
    /// secret seed.
    ///
    /// Used by [`crate::keys::AuthorityKey`] to derive the VDK-wrap AEAD
    /// key via HKDF-SHA512. **Not exposed beyond the crate.** The returned
    /// buffer wipes itself on drop.
    pub(crate) fn seed_bytes(&self) -> zeroize::Zeroizing<[u8; SECRET_KEY_LEN]> {
        zeroize::Zeroizing::new(self.inner.to_bytes())
    }
}

impl core::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SigningKey")
            .field("data", &"<redacted>")
            .finish()
    }
}

/// Ed25519 public verifying key.
///
/// Public material — derives [`Clone`], [`Copy`], and a real [`Debug`].
/// Equality and (future) serialization through `Serialize` are safe to
/// implement; this version exposes the raw 32-byte representation only.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct VerifyingKey {
    inner: DalekVerifyingKey,
}

impl VerifyingKey {
    /// Reconstructs a verifying key from its 32-byte canonical encoding.
    ///
    /// # Errors
    ///
    /// Returns [`SignatureError::InvalidPublicKey`] if the supplied bytes
    /// are not a valid compressed Edwards point (e.g., out of subgroup,
    /// non-canonical encoding).
    pub fn from_bytes(bytes: [u8; PUBLIC_KEY_LEN]) -> Result<Self, SignatureError> {
        let inner =
            DalekVerifyingKey::from_bytes(&bytes).map_err(|_| SignatureError::InvalidPublicKey)?;
        Ok(Self { inner })
    }

    /// Returns the canonical 32-byte encoding of this public key.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.inner.to_bytes()
    }

    /// Verifies a signature against `message` using strict mode.
    ///
    /// Strict mode (RFC 8032 §5.1.7) rejects:
    /// - non-canonical encodings of `s` or `R`,
    /// - small-subgroup public keys,
    /// - signatures whose `R` lies in a torsion subgroup.
    ///
    /// # Errors
    ///
    /// [`SignatureError::Invalid`] for any verification failure — wrong
    /// key, wrong message, or non-canonical signature. The error variant
    /// does not distinguish causes so callers cannot construct a timing
    /// oracle on the failure mode.
    pub fn verify(&self, message: &[u8], sig: &Signature) -> Result<(), SignatureError> {
        // `verify_strict` is the production verification path; it is
        // strictly stronger than dalek's plain `verify` and is what the
        // RFC 8032 §5.1.7 conformance profile mandates.
        self.inner
            .verify_strict(message, &sig.inner)
            .map_err(|_| SignatureError::Invalid)
    }
}

impl core::fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "VerifyingKey(")?;
        for b in self.inner.to_bytes() {
            write!(f, "{b:02x}")?;
        }
        write!(f, ")")
    }
}

/// Ed25519 detached signature (64 bytes).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature {
    inner: ed25519_dalek::Signature,
}

impl Signature {
    /// Reconstructs a signature from its 64-byte canonical encoding.
    ///
    /// **No validation is performed here** — non-canonical signatures are
    /// rejected at verification time by `verify_strict`. This mirrors how
    /// signatures arrive from the network or chain.
    #[must_use]
    pub fn from_bytes(bytes: [u8; SIGNATURE_LEN]) -> Self {
        Self {
            inner: ed25519_dalek::Signature::from_bytes(&bytes),
        }
    }

    /// Returns the canonical 64-byte encoding.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; SIGNATURE_LEN] {
        self.inner.to_bytes()
    }
}

impl core::fmt::Debug for Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Signature(")?;
        for b in self.inner.to_bytes() {
            write!(f, "{b:02x}")?;
        }
        write!(f, ")")
    }
}

/// Errors returned by signing/verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureError {
    /// Signature failed strict-mode verification.
    Invalid,
    /// Verifying-key bytes did not decode as a canonical Edwards point.
    InvalidPublicKey,
}

impl core::fmt::Display for SignatureError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Invalid => f.write_str("Ed25519 signature verification failed"),
            Self::InvalidPublicKey => f.write_str("Ed25519 public key was not canonical"),
        }
    }
}

impl std::error::Error for SignatureError {}

#[cfg(test)]
mod tests {
    use super::{
        Signature, SignatureError, SigningKey, VerifyingKey, PUBLIC_KEY_LEN, SECRET_KEY_LEN,
        SIGNATURE_LEN,
    };

    // ---------- Round-trip basics -----------------------------------

    #[test]
    fn sign_then_verify_round_trip() {
        let sk = SigningKey::generate();
        let pk = sk.verifying_key();
        let msg = b"hello world";
        let sig = sk.sign(msg);
        assert!(pk.verify(msg, &sig).is_ok());
    }

    #[test]
    fn debug_redacts_signing_key() {
        let sk = SigningKey::from_seed([0x77; SECRET_KEY_LEN]);
        let printed = format!("{sk:?}");
        assert!(printed.contains("<redacted>"));
        assert!(!printed.contains("77"));
    }

    #[test]
    fn signing_key_ct_eq() {
        let a = SigningKey::from_seed([0x11; SECRET_KEY_LEN]);
        let b = SigningKey::from_seed([0x11; SECRET_KEY_LEN]);
        let c = SigningKey::from_seed([0x12; SECRET_KEY_LEN]);
        assert!(bool::from(a.ct_eq(&b)));
        assert!(!bool::from(a.ct_eq(&c)));
    }

    // ---------- Tamper rejection ------------------------------------

    #[test]
    fn tampered_signature_rejected() {
        let sk = SigningKey::generate();
        let pk = sk.verifying_key();
        let msg = b"a message";
        let sig = sk.sign(msg);
        let mut bytes = sig.to_bytes();
        bytes[0] ^= 0x01;
        let bad = Signature::from_bytes(bytes);
        assert_eq!(pk.verify(msg, &bad).unwrap_err(), SignatureError::Invalid,);
    }

    #[test]
    fn tampered_message_rejected() {
        let sk = SigningKey::generate();
        let pk = sk.verifying_key();
        let sig = sk.sign(b"original");
        assert_eq!(
            pk.verify(b"different", &sig).unwrap_err(),
            SignatureError::Invalid,
        );
    }

    #[test]
    fn wrong_public_key_rejected() {
        let sk1 = SigningKey::generate();
        let sk2 = SigningKey::generate();
        let pk2 = sk2.verifying_key();
        let sig = sk1.sign(b"m");
        assert_eq!(pk2.verify(b"m", &sig).unwrap_err(), SignatureError::Invalid,);
    }

    #[test]
    fn zero_length_signature_round_trip_via_bytes() {
        // A length-mismatch can't happen because the public surface is
        // typed `[u8; 64]`; this is more of a regression guard against an
        // accidental future API change accepting `&[u8]`. It also asserts
        // that decoding the all-zero "signature" doesn't panic — it
        // simply fails verification.
        let bad = Signature::from_bytes([0u8; SIGNATURE_LEN]);
        let pk = SigningKey::generate().verifying_key();
        assert_eq!(
            pk.verify(b"any", &bad).unwrap_err(),
            SignatureError::Invalid,
        );
    }

    #[test]
    fn non_canonical_or_small_subgroup_public_key_rejected() {
        // A non-canonical y-coordinate (y >= p) or a small-subgroup point
        // must either fail to decode (`InvalidPublicKey`) or, if dalek
        // accepts it lazily, fail at strict-mode verification.
        // We use y = 2^255 - 1, which is greater than p = 2^255 - 19.
        let mut bytes = [0xffu8; PUBLIC_KEY_LEN];
        bytes[31] = 0x7f; // clear sign bit so y is interpreted as 2^255 - 1
        let arbitrary = SigningKey::generate();
        let sig = arbitrary.sign(b"probe");
        match VerifyingKey::from_bytes(bytes) {
            Err(SignatureError::InvalidPublicKey) => {} // ideal: rejected at decode
            Err(other) => panic!("unexpected error variant from decode: {other:?}"),
            Ok(pk) => {
                // Lazy decode — strict verification must reject any
                // signature against this key.
                assert_eq!(
                    pk.verify(b"probe", &sig).unwrap_err(),
                    SignatureError::Invalid,
                );
            }
        }
    }

    // ---------- Non-canonical signature rejection -------------------

    /// Crafts a signature with `s >= L` (the curve's group order). RFC 8032
    /// §5.1.7 requires strict-mode verifiers to reject such signatures
    /// because they admit malleability attacks. We construct one by
    /// adding the order `L` to the `s` half of a valid signature; the
    /// resulting `s' = s + L mod 2^252` decodes to the same scalar but
    /// fails the canonical-encoding check.
    #[test]
    fn non_canonical_s_rejected_by_verify_strict() {
        let sk = SigningKey::from_seed([0x09; SECRET_KEY_LEN]);
        let pk = sk.verifying_key();
        let msg = b"strict-mode test";
        let sig = sk.sign(msg);
        let mut sig_bytes = sig.to_bytes();

        // Add the curve order L to the lower 32 bytes (the `s` half) in
        // little-endian. L = 2^252 + 27742317777372353535851937790883648493.
        // Source: RFC 8032 §5.1.
        let l: [u8; 32] = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x10,
        ];
        let mut carry: u16 = 0;
        for i in 0..32 {
            let sum = u16::from(sig_bytes[32 + i]) + u16::from(l[i]) + carry;
            sig_bytes[32 + i] = (sum & 0xff) as u8;
            carry = sum >> 8;
        }
        // If carry overflowed past byte 32+31, this construction failed —
        // re-roll with a different message. For our fixed seed and
        // message the carry stays within bounds.
        assert_eq!(
            carry, 0,
            "non-canonical s construction overflowed; try a different test seed/message"
        );

        let non_canonical = Signature::from_bytes(sig_bytes);
        assert_eq!(
            pk.verify(msg, &non_canonical).unwrap_err(),
            SignatureError::Invalid,
            "verify_strict should reject signatures with s >= L",
        );
    }

    // ---------- RFC 8032 §7.1 known-answer tests --------------------

    /// RFC 8032 §7.1 "Test 1" — empty message.
    ///
    /// secret  = `9d61b19deffd5a60ba844af492ec2cc4
    ///            4449c5697b326919703bac031cae7f60`
    /// public  = `d75a980182b10ab7d54bfed3c964073a
    ///            0ee172f3daa62325af021a68f707511a`
    /// message = (empty)
    /// sig     = `e5564300c360ac729086e2cc806e828a
    ///            84877f1eb8e5d974d873e06522490155
    ///            5fb8821590a33bacc61e39701cf9b46b
    ///            d25bf5f0595bbe24655141438e7a100b`
    #[test]
    fn rfc_8032_test_1_empty_message() {
        let seed: [u8; SECRET_KEY_LEN] =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap()
                .try_into()
                .unwrap();
        let pk_bytes: [u8; PUBLIC_KEY_LEN] =
            hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
                .unwrap()
                .try_into()
                .unwrap();
        let expected_sig: [u8; SIGNATURE_LEN] = hex::decode(concat!(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8",
            "821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        ))
        .unwrap()
        .try_into()
        .unwrap();

        let sk = SigningKey::from_seed(seed);
        let pk = sk.verifying_key();
        assert_eq!(pk.to_bytes(), pk_bytes);
        let sig = sk.sign(b"");
        assert_eq!(sig.to_bytes(), expected_sig);
        assert!(pk.verify(b"", &sig).is_ok());

        // And a tampered KAT must fail strict verification.
        let mut bad = expected_sig;
        bad[0] ^= 0x01;
        let bad_sig = Signature::from_bytes(bad);
        assert_eq!(
            pk.verify(b"", &bad_sig).unwrap_err(),
            SignatureError::Invalid,
        );
    }

    /// RFC 8032 §7.1 "Test 2" — single-byte message `0x72`.
    #[test]
    fn rfc_8032_test_2_single_byte() {
        let seed: [u8; SECRET_KEY_LEN] =
            hex::decode("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
                .unwrap()
                .try_into()
                .unwrap();
        let pk_bytes: [u8; PUBLIC_KEY_LEN] =
            hex::decode("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
                .unwrap()
                .try_into()
                .unwrap();
        let msg = hex::decode("72").unwrap();
        let expected_sig: [u8; SIGNATURE_LEN] = hex::decode(concat!(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da",
            "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        ))
        .unwrap()
        .try_into()
        .unwrap();

        let sk = SigningKey::from_seed(seed);
        let pk = sk.verifying_key();
        assert_eq!(pk.to_bytes(), pk_bytes);
        let sig = sk.sign(&msg);
        assert_eq!(sig.to_bytes(), expected_sig);
        assert!(pk.verify(&msg, &sig).is_ok());
    }
}
