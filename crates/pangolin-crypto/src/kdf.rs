//! Key derivation — Argon2id.
//!
//! Argon2id is the hybrid mode that combines Argon2i's side-channel
//! resistance with Argon2d's GPU/ASIC resistance — see RFC 9106 §3.1.
//!
//! Pangolin locks a single parameter set ([`KdfParams::RECOMMENDED`]):
//! 256 MiB memory cost, 3 iterations, parallelism 1, 32-byte output. These
//! values were chosen on 2026-05 for a target 2-3 s derive time on commodity
//! mobile and desktop hardware. **Future bumps require a new issue and
//! plan revision** — silent weakening is prevented by the
//! [`KdfParams::validate`] floor check.
//!
//! See `docs/issue-plans/P1.md` §P1-2 for the full rationale.

use argon2::{Algorithm, Argon2, Params, Version};

use crate::aead::{AeadKey, KEY_LEN};
use crate::secret::SecretBytes;

/// Length of a [`KdfSalt`] in bytes. RFC 9106 §3.1 mandates ≥ 8 bytes;
/// 16 is the standard "safe-by-default" length.
pub const SALT_LEN: usize = 16;

/// Minimum memory cost (KiB) accepted by [`KdfParams::validate`].
///
/// 64 MiB is well above OWASP's 2025 mobile-baseline recommendation; the
/// recommended setting is 256 MiB.
pub const MIN_MEMORY_KIB: u32 = 64 * 1024;

/// Minimum time cost (iterations) accepted by [`KdfParams::validate`].
pub const MIN_TIME_COST: u32 = 1;

/// Minimum parallelism accepted by [`KdfParams::validate`].
pub const MIN_PARALLELISM: u32 = 1;

/// 16-byte salt for Argon2id derivation.
///
/// Stored alongside the wrapped vault data; not secret, but must be unique
/// per-derivation to prevent multi-target precomputation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfSalt([u8; SALT_LEN]);

impl KdfSalt {
    /// Wraps existing salt bytes (e.g., loaded from disk).
    #[must_use]
    pub const fn from_bytes(bytes: [u8; SALT_LEN]) -> Self {
        Self(bytes)
    }

    /// Generates a fresh random salt from the OS CSPRNG.
    #[must_use]
    pub fn random() -> Self {
        let mut s = [0u8; SALT_LEN];
        crate::rng::fill_random(&mut s);
        Self(s)
    }

    /// Returns the raw salt bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SALT_LEN] {
        &self.0
    }
}

/// Argon2id parameters.
///
/// Pangolin pins a single recommended set ([`KdfParams::RECOMMENDED`]).
/// Custom params are supported only for cross-implementation test
/// vectors and must pass [`KdfParams::validate`] before use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory cost in KiB. Must satisfy `>= MIN_MEMORY_KIB` for `validate`.
    pub memory_kib: u32,
    /// Number of iterations. Must satisfy `>= MIN_TIME_COST`.
    pub time_cost: u32,
    /// Degree of parallelism. Must satisfy `>= MIN_PARALLELISM`.
    pub parallelism: u32,
}

impl KdfParams {
    /// The locked Pangolin Argon2id parameter set: 256 MiB, t=3, p=1.
    ///
    /// Output length is fixed at 32 bytes — see [`AeadKey`] / [`KEY_LEN`].
    pub const RECOMMENDED: Self = Self {
        memory_kib: 256 * 1024,
        time_cost: 3,
        parallelism: 1,
    };

    /// Rejects parameter sets that fall below the conservative floor
    /// declared in this module.
    ///
    /// Use this on any caller-supplied `KdfParams` before passing them to
    /// [`derive_key`]. `KdfParams::RECOMMENDED` always validates.
    pub fn validate(&self) -> Result<(), KdfError> {
        if self.memory_kib < MIN_MEMORY_KIB {
            return Err(KdfError::ParamsTooWeak);
        }
        if self.time_cost < MIN_TIME_COST {
            return Err(KdfError::ParamsTooWeak);
        }
        if self.parallelism < MIN_PARALLELISM {
            return Err(KdfError::ParamsTooWeak);
        }
        Ok(())
    }
}

/// Errors returned by KDF operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfError {
    /// Salt was shorter than [`SALT_LEN`].
    SaltTooShort,
    /// Parameters fell below the [`KdfParams::validate`] floor.
    ParamsTooWeak,
    /// Underlying Argon2 implementation rejected the parameters or input
    /// (e.g., output buffer length unsupported by the version).
    Internal,
}

impl core::fmt::Display for KdfError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SaltTooShort => f.write_str("KDF salt was shorter than the required length"),
            Self::ParamsTooWeak => f.write_str("KDF parameters fell below the minimum floor"),
            Self::Internal => f.write_str("KDF internal error"),
        }
    }
}

impl std::error::Error for KdfError {}

/// Derives an [`AeadKey`] from a password, salt, and parameter set using
/// Argon2id.
///
/// `params` is validated against the minimum floor before any work is done.
///
/// # Errors
///
/// Returns [`KdfError::ParamsTooWeak`] if the supplied params are below the
/// validation floor; [`KdfError::Internal`] if the upstream Argon2 crate
/// rejects them at the protocol level.
pub fn derive_key(
    password: &SecretBytes,
    salt: &KdfSalt,
    params: &KdfParams,
) -> Result<AeadKey, KdfError> {
    params.validate()?;
    let argon_params = Params::new(
        params.memory_kib,
        params.time_cost,
        params.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|_| KdfError::Internal)?;
    let ctx = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut out = [0u8; KEY_LEN];
    ctx.hash_password_into(password.expose(), salt.as_bytes(), &mut out)
        .map_err(|_| KdfError::Internal)?;
    Ok(AeadKey::from_bytes(out))
}

/// Internal derivation helper for callers (e.g., RFC test vectors) that
/// need raw bytes rather than a typed [`AeadKey`].
///
/// Not exposed publicly — production code must round-trip through the typed
/// [`derive_key`] surface.
#[cfg(test)]
pub(crate) fn derive_raw(
    password: &[u8],
    salt: &[u8],
    params: &Params,
    out: &mut [u8],
) -> Result<(), KdfError> {
    let ctx = Argon2::new(Algorithm::Argon2id, Version::V0x13, params.clone());
    ctx.hash_password_into(password, salt, out)
        .map_err(|_| KdfError::Internal)
}

#[cfg(test)]
mod tests {
    use super::{
        derive_key, derive_raw, KdfError, KdfParams, KdfSalt, MIN_MEMORY_KIB, MIN_PARALLELISM,
        MIN_TIME_COST, SALT_LEN,
    };
    use crate::secret::SecretBytes;
    use argon2::Params;

    // ---------- Min-params validation --------------------------------

    #[test]
    fn recommended_params_validate() {
        assert!(KdfParams::RECOMMENDED.validate().is_ok());
    }

    #[test]
    fn below_floor_memory_rejected() {
        let p = KdfParams {
            memory_kib: MIN_MEMORY_KIB - 1,
            time_cost: 3,
            parallelism: 1,
        };
        assert_eq!(p.validate().unwrap_err(), KdfError::ParamsTooWeak);
    }

    #[test]
    fn below_floor_time_cost_rejected() {
        let p = KdfParams {
            memory_kib: MIN_MEMORY_KIB,
            time_cost: MIN_TIME_COST - 1,
            parallelism: 1,
        };
        assert_eq!(p.validate().unwrap_err(), KdfError::ParamsTooWeak);
    }

    #[test]
    fn below_floor_parallelism_rejected() {
        let p = KdfParams {
            memory_kib: MIN_MEMORY_KIB,
            time_cost: 3,
            parallelism: MIN_PARALLELISM - 1,
        };
        assert_eq!(p.validate().unwrap_err(), KdfError::ParamsTooWeak);
    }

    #[test]
    fn derive_key_rejects_below_floor() {
        let pw = SecretBytes::new(b"hunter2".to_vec());
        let salt = KdfSalt::from_bytes([0u8; SALT_LEN]);
        let weak = KdfParams {
            memory_kib: 1024,
            time_cost: 1,
            parallelism: 1,
        };
        assert_eq!(
            derive_key(&pw, &salt, &weak).unwrap_err(),
            KdfError::ParamsTooWeak,
        );
    }

    // ---------- Determinism: same input -> same key -----------------

    /// Sanity test using a small, fast parameter set (16 MiB) — proves the
    /// upstream `argon2` crate is being driven correctly. Below the floor,
    /// so we use `derive_raw` to bypass `validate`.
    #[test]
    fn derive_is_deterministic_at_fast_params() {
        let params = Params::new(16 * 1024, 2, 1, Some(32)).unwrap();
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        derive_raw(
            b"correct horse battery staple",
            b"some-fixed-salt!",
            &params,
            &mut a,
        )
        .unwrap();
        derive_raw(
            b"correct horse battery staple",
            b"some-fixed-salt!",
            &params,
            &mut b,
        )
        .unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn derive_changes_with_different_salt() {
        let params = Params::new(16 * 1024, 2, 1, Some(32)).unwrap();
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        derive_raw(b"pw", b"salt-A-fixed-x16", &params, &mut a).unwrap();
        derive_raw(b"pw", b"salt-B-fixed-x16", &params, &mut b).unwrap();
        assert_ne!(a, b);
    }

    // ---------- RFC 9106 known-answer test ---------------------------

    /// Argon2id v1.3 reference KAT — no-secret, no-AD form.
    ///
    /// Parameters: `password = b"password"`, `salt = b"somesalt"`, t=2,
    /// m = 2^16 KiB (64 MiB), p=1, output = 32 bytes.
    /// Expected tag (well-known reference vector from the
    /// P-H-C/phc-winner-argon2 reference implementation, which is cited
    /// from RFC 9106 / `draft-irtf-cfrg-argon2-12` Appendix A as the test
    /// suite for cross-implementation validation):
    ///
    /// `09 31 61 15 d5 cf 24 ed 5a 15 a3 1a 3b a3 26 e5
    ///  cf 32 ed c2 47 02 98 7c 02 b6 56 6f 61 91 3c f7`
    ///
    /// We use the "no secret, no AD" form because Pangolin's typed public
    /// surface ([`derive_key`]) does not accept those optional inputs —
    /// they would only complicate the API for a use case we don't have
    /// (HMAC-style keying of the KDF). The bytes here pin our wiring of
    /// algorithm + version + parameters to the canonical Argon2id v1.3
    /// reference implementation.
    #[test]
    fn rfc_9106_argon2id_kat() {
        let password = b"password";
        let salt = b"somesalt";
        let params = Params::new(64 * 1024, 2, 1, Some(32)).unwrap();
        let mut out = [0u8; 32];
        derive_raw(password, salt, &params, &mut out).unwrap();
        let expected =
            hex::decode("09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7")
                .unwrap();
        assert_eq!(
            hex::encode(out),
            hex::encode(expected),
            "Argon2id v1.3 reference KAT mismatch — algorithm or wiring is wrong",
        );
    }

    /// End-to-end derive at the LOCKED Pangolin parameters (256 MiB / t=3).
    ///
    /// Gated behind the `slow-tests` feature because a single derive
    /// allocates 256 MiB and runs for 1-3 seconds on commodity hardware,
    /// which exceeds the default `cargo test` budget.
    #[cfg(feature = "slow-tests")]
    #[test]
    fn derive_at_locked_params_is_deterministic() {
        let pw = SecretBytes::new(b"correct horse battery staple".to_vec());
        let salt = KdfSalt::from_bytes([0xA5; SALT_LEN]);
        let k1 = derive_key(&pw, &salt, &KdfParams::RECOMMENDED).unwrap();
        let k2 = derive_key(&pw, &salt, &KdfParams::RECOMMENDED).unwrap();
        assert!(bool::from(k1.ct_eq(&k2)));
    }
}
