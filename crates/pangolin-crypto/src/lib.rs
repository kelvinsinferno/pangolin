//! Cryptographic primitives for Pangolin.
//!
//! AEAD (XChaCha20-Poly1305), KDF (Argon2id), signing (Ed25519), and key
//! wrapping live here. This crate **reuses vetted libraries**; it never
//! invents new primitives. Real implementations land in the P1 series.

#![cfg_attr(not(test), forbid(unsafe_code))]

/// Returns the crate name. Placeholder for P0-1.
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
