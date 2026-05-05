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

#![cfg_attr(not(test), forbid(unsafe_code))]

pub mod aead;
pub mod kdf;
pub mod rng;
pub mod secret;

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
