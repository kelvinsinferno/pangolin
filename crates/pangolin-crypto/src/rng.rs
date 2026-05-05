//! Cryptographically secure RNG accessor.
//!
//! All randomness in `pangolin-crypto` flows through this module so that
//! tests and audits have a single chokepoint. The default RNG is
//! [`rand_core::OsRng`], which delegates to the host OS's CSPRNG
//! (`getrandom(2)` on Linux, `BCryptGenRandom` on Windows, `getentropy(3)`
//! on macOS/BSD).
//!
//! Higher-level primitives in this crate accept any `RngCore + CryptoRng`
//! to enable property-test reproducibility, but the public, parameter-less
//! constructors (`AeadKey::generate`, `Nonce::random`, etc.) always pull
//! from [`OsRng`].

pub use rand_core::{CryptoRng, OsRng, RngCore};

/// Returns a fresh handle to the operating-system CSPRNG.
///
/// `OsRng` is a zero-sized type; calling this is free.
#[must_use]
pub fn os_rng() -> OsRng {
    OsRng
}

/// Fills `buf` with cryptographically secure random bytes from the OS.
///
/// This is a small convenience shim over `OsRng::fill_bytes`; consumers
/// that need to specify a custom RNG should use the `rng` parameter on
/// the relevant primitive directly.
pub fn fill_random(buf: &mut [u8]) {
    OsRng.fill_bytes(buf);
}

#[cfg(test)]
mod tests {
    use super::fill_random;

    #[test]
    fn fill_random_is_not_all_zero() {
        // Astronomically unlikely to be all-zero; if it is, OS RNG is broken.
        let mut buf = [0u8; 32];
        fill_random(&mut buf);
        assert_ne!(buf, [0u8; 32]);
    }

    #[test]
    fn distinct_calls_produce_distinct_output() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        fill_random(&mut a);
        fill_random(&mut b);
        assert_ne!(a, b);
    }
}
