//! Cryptographic primitives for Pangolin.
//!
//! AEAD (`XChaCha20-Poly1305`), KDF (Argon2id), signing (Ed25519), and key
//! wrapping live here. This crate **reuses vetted libraries**; it never
//! invents new primitives.
//!
//! Every secret-bearing type implements [`zeroize::Zeroize`] on drop, exposes
//! a redacted [`core::fmt::Debug`] impl, and never derives [`PartialEq`] —
//! equality on secret material goes through [`subtle::ConstantTimeEq`].
//!
//! See `docs/issue-plans/P1.md` for the full specification.

#![forbid(unsafe_code)]

pub mod aead;
pub mod escrow;
pub mod guardian;
pub mod kdf;
pub mod keys;
pub mod pairing;
pub mod rng;
pub mod secret;
/// **MVP-4-L L-0a-2 (G-1 off-chain).** Recovery opened-share TRANSPORT
/// primitive: re-seal a guardian's opened Shamir piece to the recovering
/// user's ephemeral X25519 pubkey, bound to the recovery-attempt context
/// (vault_id + attempt_nonce + recoverer_pub + share_identifier).
/// Structurally identical to [`pairing::seal_vdk_to_device`] /
/// [`escrow::seal_share`] — same `crypto_box` sealed-box primitive,
/// different recipient role, different payload, new domain string.
pub mod share_transport;
pub mod sign;

/// Returns the crate name. Useful for diagnostics and version reporting.
#[must_use]
pub fn name() -> &'static str {
    "pangolin-crypto"
}

#[cfg(test)]
mod tests {
    use super::name;

    #[test]
    fn crate_name_is_set() {
        assert_eq!(name(), "pangolin-crypto");
    }
}
