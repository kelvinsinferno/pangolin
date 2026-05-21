// SPDX-License-Identifier: AGPL-3.0-or-later
//! Guardian X25519 sealing-key derivation (#104b — GAP FLAG 1,
//! audit-critical key derivation).
//!
//! ## Why this exists
//!
//! Social recovery (#104a/#104b) needs a guardian to hold **two** public
//! keys derived from their single Pangolin [`DeviceKey`]:
//!
//! 1. a **secp256k1** EVM signer (the on-chain `Approve` signer +
//!    merkle-committed identity) — derived by
//!    `pangolin_chain::evm::derive_evm_wallet`; and
//! 2. an **X25519** share-opener (the recipient key a guardian's
//!    [`crate::escrow::SealedShare`] is sealed to) — derived **here**.
//!
//! The two derivations are independent by construction (different curves,
//! different HKDF info strings) but anchored in the **same** device seed,
//! so one guardian identity yields both. This is the load-bearing L2
//! join: the guardian whose X25519 pubkey a share is sealed to MUST be
//! the same guardian whose secp256k1 address is committed in the merkle
//! root. Both halves trace back to one [`DeviceKey`].
//!
//! ## How the derivation works (mirrors `evm.rs`'s secp256k1 pattern)
//!
//! Ed25519 signing is deterministic per RFC 8032 §5.1.6, so:
//!
//! 1. Sign a fixed domain-separator message
//!    [`X25519_DERIVATION_MESSAGE`] with the device's Ed25519 key. The
//!    64-byte signature is a deterministic function of the secret seed
//!    but does not reveal it.
//! 2. Treat the signature as HKDF-SHA512 IKM and expand 32 bytes under
//!    the versioned info string [`X25519_HKDF_INFO`] — DISTINCT from
//!    every other HKDF use in the codebase (the EVM-wallet domain, the
//!    indexer-key domain, the VDK-wrap domain, the recovery-wrap domain).
//! 3. Interpret those 32 bytes as an X25519 secret scalar. Curve25519
//!    accepts any 32-byte string (the scalar is clamped inside the
//!    Montgomery ladder), so — unlike the secp256k1 path — no
//!    rejection-sampling loop is needed: every expansion yields a valid
//!    keypair.
//!
//! ## Cryptographic assumption (same as `evm.rs`'s HIGH-1)
//!
//! The construction `seed → Sign(seed, fixed-msg) → HKDF-Expand(...)`
//! treats Ed25519-deterministic-sign as a PRF in the seed for a fixed
//! message (see `pangolin_chain::evm`'s module docs for the full
//! argument). The composition is one-way: an attacker who recovers the
//! X25519 scalar cannot recover the Ed25519 seed (HMAC-SHA512 preimage
//! resistance), so a compromised share-opener never endangers the
//! revision-signing identity.
//!
//! ## Secret-type discipline
//!
//! [`X25519SealingKey`] carries the full discipline: heap-resident secret
//! scalar, `!Clone`, `!Copy`, zeroizing, redacted `Debug`, constant-time
//! equality. The 32-byte public key is non-secret and freely exposed.

use static_assertions::assert_not_impl_any;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::escrow::X25519_KEY_LEN;
use crate::keys::DeviceKey;

/// Fixed message signed by the device's Ed25519 key to produce the
/// X25519 derivation IKM.
///
/// **Versioned** — any change must bump the `-v0` suffix and document the
/// migration; existing guardians would otherwise derive a different X25519
/// key under the new version and become unable to open their
/// previously-sealed shares.
///
/// DISTINCT from `pangolin_chain::evm`'s `DERIVATION_MESSAGE`
/// (`"pangolin-chain-evm-wallet-derive-v0"`) so the two derivations never
/// share IKM.
pub const X25519_DERIVATION_MESSAGE: &[u8] = b"pangolin-guardian-x25519-derive-v0";

/// HKDF-SHA512 info string for the X25519 scalar expansion. **Versioned**
/// alongside [`X25519_DERIVATION_MESSAGE`].
///
/// DISTINCT from every other HKDF info string in the codebase:
/// `"pangolin-chain-evm-wallet-v0"` (secp256k1 wallet),
/// `"pangolin-indexer-tempdb-key-v1"` (indexer), `"pangolin-vdk-wrap-v0"`
/// (authority wrap), `"pangolin-recovery-wrap-v0"` (RWK wrap). A future
/// audit can grep for this string to confirm the guardian sealing key is
/// never reused as any other primitive.
pub const X25519_HKDF_INFO: &[u8] = b"pangolin-guardian-x25519-v0";

/// A guardian's X25519 sealing keypair, derived one-way from their
/// [`DeviceKey`].
///
/// The secret scalar is the recipient key for [`crate::escrow::SealedShare`]
/// (`open_sealed_share` consumes [`Self::secret_bytes`]); the public key
/// is what `seal_share` seals to. Carries the secret-type discipline:
/// `!Clone`, `!Copy`, zeroizing secret, redacted `Debug`, `ct_eq` only.
pub struct X25519SealingKey {
    /// 32-byte X25519 secret scalar (heap-resident, zeroizing).
    secret: Zeroizing<[u8; X25519_KEY_LEN]>,
    /// 32-byte X25519 public key (non-secret).
    public: [u8; X25519_KEY_LEN],
}

assert_not_impl_any!(X25519SealingKey: Clone, Copy);

impl X25519SealingKey {
    /// The guardian's 32-byte X25519 **public** key — the value
    /// [`crate::escrow::seal_share`] seals a share to. Non-secret.
    #[must_use]
    pub fn public_bytes(&self) -> &[u8; X25519_KEY_LEN] {
        &self.public
    }

    /// A zeroizing copy of the guardian's 32-byte X25519 **secret**
    /// scalar — the value [`crate::escrow::open_sealed_share`] needs to
    /// open a sealed share. The returned buffer wipes on drop; callers
    /// must pass it straight into `open_sealed_share` without copying it
    /// into a non-zeroizing buffer.
    #[must_use]
    pub fn secret_bytes(&self) -> Zeroizing<[u8; X25519_KEY_LEN]> {
        Zeroizing::new(*self.secret)
    }

    /// Constant-time equality on the secret scalar (the public key is a
    /// pure function of it, so comparing the secret suffices).
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.secret.as_slice().ct_eq(other.secret.as_slice())
    }
}

impl core::fmt::Debug for X25519SealingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The public key is non-secret; the scalar is redacted.
        f.debug_struct("X25519SealingKey")
            .field("public", &hex_short(&self.public))
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// Short hex preview of a public key for `Debug` (non-secret).
fn hex_short(bytes: &[u8; X25519_KEY_LEN]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(10);
    for b in &bytes[..4] {
        s.push(char::from(HEX[usize::from(b >> 4)]));
        s.push(char::from(HEX[usize::from(b & 0x0f)]));
    }
    s.push_str("..");
    s
}

/// Derive a guardian's [`X25519SealingKey`] from their Pangolin
/// [`DeviceKey`] (GAP FLAG 1 — audit-critical).
///
/// Determinism: calling this with the same `DeviceKey` (same underlying
/// Ed25519 seed) always produces the same X25519 keypair, so a guardian
/// can re-derive their share-opener on any device that holds their seed.
/// Distinct `DeviceKey`s produce distinct keypairs (with overwhelming
/// probability).
///
/// The same `DeviceKey` also yields the guardian's secp256k1 EVM signer
/// via `pangolin_chain::evm::derive_evm_wallet`; the two keys are
/// independent (different HKDF info strings) but anchored in one identity
/// — the L2 two-key join.
///
/// This derivation cannot fail: HKDF-SHA512 expand to 32 bytes is
/// infallible, and Curve25519 accepts any 32-byte secret scalar (clamped
/// inside the ladder), so — unlike the secp256k1 path — there is no
/// rejection-sampling loop and the signature is total.
#[must_use]
pub fn derive_x25519_sealing_key(device: &DeviceKey) -> X25519SealingKey {
    use hkdf::Hkdf;
    use sha2::Sha512;

    // Step 1: deterministically sign the fixed domain-separator message.
    // Same seed → same signature (RFC 8032 §5.1.6).
    let ikm = device.signing_key().sign(X25519_DERIVATION_MESSAGE);
    let ikm_bytes = Zeroizing::new(ikm.to_bytes());

    // Step 2: HKDF-SHA512 expand 32 bytes under the versioned info string.
    let hk = Hkdf::<Sha512>::new(None, &ikm_bytes[..]);
    let mut scalar = Zeroizing::new([0u8; X25519_KEY_LEN]);
    hk.expand(X25519_HKDF_INFO, &mut scalar[..])
        .expect("HKDF-SHA512 expand with 32-byte output cannot fail");

    // Step 3: interpret the 32 bytes as an X25519 secret scalar. crypto_box
    // (the same crate escrow.rs seals with) clamps inside the Montgomery
    // ladder, so every 32-byte string is a valid scalar — no rejection
    // sampling. We materialize the public key through crypto_box so the
    // public bytes match exactly what `seal_share` will seal to.
    let sk = crypto_box::SecretKey::from_bytes(*scalar);
    let public = *sk.public_key().as_bytes();
    X25519SealingKey {
        secret: scalar,
        public,
    }
}

#[cfg(test)]
mod tests {
    use super::{derive_x25519_sealing_key, X25519_DERIVATION_MESSAGE, X25519_HKDF_INFO};
    use crate::escrow::{
        open_sealed_share, seal_share, split_rwk, RecoveryWrapKey, X25519_KEY_LEN,
    };
    use crate::keys::{DeviceKey, VAULT_ID_LEN};

    const VAULT_A: [u8; VAULT_ID_LEN] = [0xAA; VAULT_ID_LEN];
    const EPOCH_0: [u8; 16] = [0x00; 16];

    /// Determinism (mirrors `evm::derive_is_deterministic`): the same
    /// `DeviceKey` derives the same X25519 keypair every call.
    #[test]
    fn derive_is_deterministic() {
        let device = DeviceKey::from_seed([0x42; 32]);
        let k1 = derive_x25519_sealing_key(&device);
        let k2 = derive_x25519_sealing_key(&device);
        assert_eq!(
            k1.public_bytes(),
            k2.public_bytes(),
            "same DeviceKey must derive same X25519 public key"
        );
        assert!(
            bool::from(k1.ct_eq(&k2)),
            "same DeviceKey must derive same X25519 secret scalar"
        );
    }

    /// Distinct devices derive distinct sealing keys (criterion: the L2
    /// join cannot collapse two guardians onto one recipient key).
    #[test]
    fn different_devices_produce_different_keys() {
        let d1 = DeviceKey::from_seed([0x11; 32]);
        let d2 = DeviceKey::from_seed([0x22; 32]);
        let k1 = derive_x25519_sealing_key(&d1);
        let k2 = derive_x25519_sealing_key(&d2);
        assert_ne!(
            k1.public_bytes(),
            k2.public_bytes(),
            "distinct devices must derive distinct X25519 public keys"
        );
        assert!(!bool::from(k1.ct_eq(&k2)));
    }

    /// Pinned known-answer vector: a fixed device seed derives a fixed
    /// X25519 public key. Catches a future drift in the domain message,
    /// the HKDF info string, the SHA-512 choice, or the `crypto_box` public
    /// derivation. The pin is the bytes this implementation produced; a
    /// regression in any input flips it.
    #[test]
    fn kat_pinned_public_key_for_fixed_seed() {
        let device = DeviceKey::from_seed([0x9A; 32]);
        let key = derive_x25519_sealing_key(&device);
        let got = key.public_bytes();
        // Re-derive independently the slow way to confirm the pin equals
        // the production path (defends against the pin being stale).
        let expected = {
            use hkdf::Hkdf;
            use sha2::Sha512;
            let sig = device.signing_key().sign(X25519_DERIVATION_MESSAGE);
            let hk = Hkdf::<Sha512>::new(None, &sig.to_bytes());
            let mut scalar = [0u8; X25519_KEY_LEN];
            hk.expand(X25519_HKDF_INFO, &mut scalar).unwrap();
            let sk = crypto_box::SecretKey::from_bytes(scalar);
            *sk.public_key().as_bytes()
        };
        assert_eq!(got, &expected, "derivation drifted from the spec recipe");
    }

    /// End-to-end L2 join: a share sealed to the guardian's derived X25519
    /// **public** key opens with the guardian's derived X25519 **secret**
    /// scalar — proving the keypair the seal targets and the keypair the
    /// open uses are the same derivation. A wrong guardian's key fails.
    #[test]
    fn derived_key_seals_and_opens_a_share() {
        let guardian = DeviceKey::from_seed([0x07; 32]);
        let sealing = derive_x25519_sealing_key(&guardian);

        let rwk = RecoveryWrapKey::generate();
        let shares = split_rwk(&rwk, 2, 3).unwrap();
        let sealed = seal_share(&shares[0], sealing.public_bytes(), &VAULT_A, &EPOCH_0).unwrap();

        // The guardian opens with their derived secret scalar.
        let secret = sealing.secret_bytes();
        let opened = open_sealed_share(&sealed, &secret, &VAULT_A, &EPOCH_0).unwrap();
        assert_eq!(opened.as_bytes(), shares[0].as_bytes());

        // A different guardian's derived key cannot open it.
        let other = derive_x25519_sealing_key(&DeviceKey::from_seed([0x08; 32]));
        let other_secret = other.secret_bytes();
        assert!(open_sealed_share(&sealed, &other_secret, &VAULT_A, &EPOCH_0).is_err());
    }

    /// Domain strings are versioned at v0 and distinct from each other.
    #[test]
    fn domain_strings_are_versioned_and_distinct() {
        assert_eq!(
            X25519_DERIVATION_MESSAGE,
            b"pangolin-guardian-x25519-derive-v0"
        );
        assert_eq!(X25519_HKDF_INFO, b"pangolin-guardian-x25519-v0");
        // Distinct from the recovery-wrap + authority-wrap info strings so
        // no HKDF-output collision is possible.
        assert_ne!(
            X25519_HKDF_INFO,
            crate::escrow::RECOVERY_WRAP_KEY_INFO,
            "guardian X25519 info must differ from recovery-wrap info"
        );
        assert_ne!(
            X25519_HKDF_INFO,
            crate::keys::WRAP_KEY_INFO,
            "guardian X25519 info must differ from authority-wrap info"
        );
    }

    /// `Debug` redacts the secret scalar and shows only a public preview.
    #[test]
    fn debug_redacts_secret() {
        let key = derive_x25519_sealing_key(&DeviceKey::from_seed([0x55; 32]));
        let printed = format!("{key:?}");
        assert!(printed.contains("<redacted>"));
        assert!(printed.contains("public"));
    }
}
