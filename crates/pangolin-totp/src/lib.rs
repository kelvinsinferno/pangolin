// SPDX-License-Identifier: AGPL-3.0-or-later
//! TOTP (RFC 6238) code generation + `otpauth://` / base32 parsing.
//!
//! Per MVP-1 issue 1.1 (Q4), the TOTP implementation lives in its own
//! crate so the per-crate `forbid(unsafe_code)` and per-crate `deny.toml`
//! scopes can be the tightest possible: any RFC 6238 implementation bug
//! is blast-contained, the HMAC-SHA1 dependency surface never reaches
//! `pangolin-core`, and `pangolin-crypto`'s zero-serde audit boundary is
//! preserved (the dependency arrow is `pangolin-ffi`/`pangolin-store` →
//! `pangolin-totp`; nothing points back).
//!
//! # Access classes
//!
//! Generating a *code* ([`totp_at`]) is session-class — it only needs an
//! unlocked vault; the seed never crosses the FFI, only the digit string
//! does. Revealing the raw *seed* is reveal-class (§5.4 — `pangolin-ffi`'s
//! `reveal_totp_secret`, presence-gated). The transient plaintext seed in
//! this crate is wrapped in [`zeroize::Zeroizing`] / its HMAC output is
//! zeroized after use.

#![cfg_attr(not(test), forbid(unsafe_code))]

mod parse;

pub use parse::{decode_base32, parse_otpauth_uri, parse_totp_secret, ParsedTotpSecret};

use hmac::{Hmac, Mac};
use zeroize::Zeroizing;

/// Maximum stored TOTP secret length in bytes.
///
/// Must equal `pangolin_store::account::limits::TOTP_SECRET_MAX_BYTES`
/// (256). `pangolin-totp` defines it locally to avoid a `pangolin-store`
/// dependency; a cross-check unit test in `pangolin-store` /
/// `pangolin-ffi` keeps the two in sync.
pub const MAX_SECRET_BYTES: usize = 256;

/// HMAC hash algorithm for the TOTP HOTP step. RFC 6238 defaults to
/// SHA-1; SHA-256 / SHA-512 are also defined (Steam, some banks).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TotpAlgorithm {
    /// HMAC-SHA1 — the interoperability default.
    #[default]
    Sha1,
    /// HMAC-SHA256.
    Sha256,
    /// HMAC-SHA512.
    Sha512,
}

impl TotpAlgorithm {
    /// Parse the `algorithm=` query value from an `otpauth://` URI.
    /// Case-insensitive; accepts `SHA1` / `SHA256` / `SHA512`.
    ///
    /// # Errors
    /// [`TotpError::UnsupportedAlgorithm`] for anything else.
    pub fn parse(s: &str) -> Result<Self, TotpError> {
        match s.to_ascii_uppercase().as_str() {
            "SHA1" => Ok(Self::Sha1),
            "SHA256" => Ok(Self::Sha256),
            "SHA512" => Ok(Self::Sha512),
            other => Err(TotpError::UnsupportedAlgorithm(other.to_owned())),
        }
    }

    /// Canonical uppercase name, as written in an `otpauth://` URI.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        }
    }

    /// Small integer wire encoding for the V2 CBOR `totp` map.
    #[must_use]
    pub fn to_wire(&self) -> u8 {
        match self {
            Self::Sha1 => 0,
            Self::Sha256 => 1,
            Self::Sha512 => 2,
        }
    }

    /// Decode the V2 CBOR wire integer.
    ///
    /// # Errors
    /// [`TotpError::UnsupportedAlgorithm`] for an out-of-range value.
    pub fn from_wire(v: u8) -> Result<Self, TotpError> {
        match v {
            0 => Ok(Self::Sha1),
            1 => Ok(Self::Sha256),
            2 => Ok(Self::Sha512),
            other => Err(TotpError::UnsupportedAlgorithm(format!("wire {other}"))),
        }
    }
}

/// Configurable TOTP parameters stored alongside the secret. The
/// [`Default`] is the RFC 6238 baseline: SHA-1, 6 digits, 30 s period.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TotpParams {
    /// HMAC hash algorithm.
    pub algorithm: TotpAlgorithm,
    /// Number of digits in the generated code. RFC values in use: 6, 7, 8.
    pub digits: u8,
    /// Time step / window length in seconds. RFC default 30; must be > 0.
    pub period_seconds: u32,
}

impl Default for TotpParams {
    fn default() -> Self {
        Self {
            algorithm: TotpAlgorithm::Sha1,
            digits: 6,
            period_seconds: 30,
        }
    }
}

impl TotpParams {
    /// Validate the parameter ranges: `digits ∈ {6, 7, 8}` and
    /// `period_seconds ∈ 1..=3600`.
    ///
    /// # Errors
    /// [`TotpError::InvalidDigits`] / [`TotpError::InvalidPeriod`].
    pub fn validate(&self) -> Result<(), TotpError> {
        if !matches!(self.digits, 6..=8) {
            return Err(TotpError::InvalidDigits(self.digits));
        }
        if self.period_seconds == 0 || self.period_seconds > 3600 {
            return Err(TotpError::InvalidPeriod(self.period_seconds));
        }
        Ok(())
    }
}

/// A generated TOTP code plus its window metadata.
///
/// `Debug` is redacting — the code is a live second factor; treat it
/// like a password in logs. The code string is held in
/// [`zeroize::Zeroizing`] so it wipes on drop.
pub struct TotpCode {
    code: Zeroizing<String>,
    /// Seconds remaining in the current window.
    pub seconds_remaining: u32,
    /// The window length the code was generated with.
    pub period_seconds: u32,
}

impl TotpCode {
    /// The decimal code string, left-zero-padded to the configured digit
    /// count. Callers should hand it straight to the UI / clipboard and
    /// not log it.
    #[must_use]
    pub fn code(&self) -> &str {
        self.code.as_str()
    }

    /// Clone the code string into a caller-owned [`String`]. The original
    /// copy in `self` still wipes when dropped.
    #[must_use]
    pub fn code_owned(&self) -> String {
        self.code.as_str().to_owned()
    }
}

impl core::fmt::Debug for TotpCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TotpCode")
            .field("code", &"<redacted>")
            .field("seconds_remaining", &self.seconds_remaining)
            .field("period_seconds", &self.period_seconds)
            .finish()
    }
}

/// Errors from the TOTP engine and parsers. `Debug` / `Display` never
/// echo seed bytes.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TotpError {
    /// The secret was empty — distinct from "no TOTP configured".
    #[error("TOTP secret must not be empty")]
    EmptySecret,
    /// The secret exceeded [`MAX_SECRET_BYTES`].
    #[error("TOTP secret exceeds {max} bytes (was {len})")]
    SecretTooLong {
        /// Observed length.
        len: usize,
        /// Maximum allowed.
        max: usize,
    },
    /// `digits` was not 6, 7, or 8.
    #[error("TOTP digits must be 6, 7, or 8 (was {0})")]
    InvalidDigits(u8),
    /// `period_seconds` was 0 or out of the accepted range.
    #[error("TOTP period must be between 1 and 3600 seconds (was {0})")]
    InvalidPeriod(u32),
    /// The base32 secret contained an invalid character or length.
    #[error("invalid base32: {reason}")]
    InvalidBase32 {
        /// Human-readable reason (never contains decoded secret bytes).
        reason: String,
    },
    /// The `otpauth://` URI was malformed.
    #[error("malformed otpauth:// URI: {reason}")]
    MalformedUri {
        /// Human-readable reason.
        reason: String,
    },
    /// An `otpauth://hotp/...` (counter-based) URI was supplied; only
    /// time-based TOTP is supported.
    #[error("HOTP (counter-based) is not supported; only otpauth://totp/")]
    HotpNotSupported,
    /// An unrecognised `algorithm=` value.
    #[error("unsupported TOTP algorithm: {0}")]
    UnsupportedAlgorithm(String),
    /// The supplied timestamp was negative (Unix timestamps must be ≥ 0).
    #[error("negative Unix timestamp not supported")]
    NegativeTime,
}

/// Generate the RFC 6238 TOTP code for `secret` at Unix time
/// `at_unix_secs` with the given [`TotpParams`].
///
/// `T0 = 0`. The counter is `at_unix_secs / params.period_seconds`; the
/// HOTP value is the dynamic-truncation of `HMAC-<algorithm>(secret,
/// counter.to_be_bytes())` taken modulo `10^digits` and left-zero-padded.
///
/// # Errors
/// [`TotpError::EmptySecret`] / [`TotpError::SecretTooLong`] /
/// [`TotpError::InvalidDigits`] / [`TotpError::InvalidPeriod`].
pub fn totp_at(
    secret: &[u8],
    at_unix_secs: u64,
    params: &TotpParams,
) -> Result<TotpCode, TotpError> {
    if secret.is_empty() {
        return Err(TotpError::EmptySecret);
    }
    if secret.len() > MAX_SECRET_BYTES {
        return Err(TotpError::SecretTooLong {
            len: secret.len(),
            max: MAX_SECRET_BYTES,
        });
    }
    params.validate()?;

    let period = u64::from(params.period_seconds);
    let counter = at_unix_secs / period;
    let counter_be = counter.to_be_bytes();

    let bin_code = match params.algorithm {
        TotpAlgorithm::Sha1 => hotp_truncate::<Hmac<sha1::Sha1>>(secret, &counter_be),
        TotpAlgorithm::Sha256 => hotp_truncate::<Hmac<sha2::Sha256>>(secret, &counter_be),
        TotpAlgorithm::Sha512 => hotp_truncate::<Hmac<sha2::Sha512>>(secret, &counter_be),
    };

    let modulus = 10u32.pow(u32::from(params.digits));
    let value = bin_code % modulus;
    let code = Zeroizing::new(format!("{value:0width$}", width = params.digits as usize));

    let seconds_remaining =
        params.period_seconds - u32::try_from(at_unix_secs % period).unwrap_or(0);

    Ok(TotpCode {
        code,
        seconds_remaining,
        period_seconds: params.period_seconds,
    })
}

/// Run HMAC-`H` over `msg` keyed by `secret`, then apply RFC 4226 §5.3
/// dynamic truncation, returning the 31-bit binary code.
fn hotp_truncate<M: Mac + hmac::digest::KeyInit>(secret: &[u8], msg: &[u8]) -> u32 {
    let mut mac = <M as Mac>::new_from_slice(secret).expect("HMAC accepts a key of any length");
    mac.update(msg);
    let tag = Zeroizing::new(mac.finalize().into_bytes().to_vec());
    let len = tag.len();
    let offset = (tag[len - 1] & 0x0f) as usize;
    (u32::from(tag[offset] & 0x7f) << 24)
        | (u32::from(tag[offset + 1]) << 16)
        | (u32::from(tag[offset + 2]) << 8)
        | u32::from(tag[offset + 3])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The RFC 6238 Appendix B test secrets (ASCII).
    const SECRET_SHA1: &[u8] = b"12345678901234567890";
    const SECRET_SHA256: &[u8] = b"12345678901234567890123456789012";
    const SECRET_SHA512: &[u8] =
        b"1234567890123456789012345678901234567890123456789012345678901234";

    /// The six RFC 6238 Appendix B timestamps.
    const TIMES: [u64; 6] = [
        59,
        1_111_111_109,
        1_111_111_111,
        1_234_567_890,
        2_000_000_000,
        20_000_000_000,
    ];

    fn params(alg: TotpAlgorithm, digits: u8) -> TotpParams {
        TotpParams {
            algorithm: alg,
            digits,
            period_seconds: 30,
        }
    }

    #[test]
    fn rfc6238_sha1_8digit() {
        let expected = [
            "94287082", "07081804", "14050471", "89005924", "69279037", "65353130",
        ];
        for (t, exp) in TIMES.iter().zip(expected) {
            let c = totp_at(SECRET_SHA1, *t, &params(TotpAlgorithm::Sha1, 8)).unwrap();
            assert_eq!(c.code(), exp, "SHA1 t={t}");
        }
    }

    #[test]
    fn rfc6238_sha256_8digit() {
        let expected = [
            "46119246", "68084774", "67062674", "91819424", "90698825", "77737706",
        ];
        for (t, exp) in TIMES.iter().zip(expected) {
            let c = totp_at(SECRET_SHA256, *t, &params(TotpAlgorithm::Sha256, 8)).unwrap();
            assert_eq!(c.code(), exp, "SHA256 t={t}");
        }
    }

    #[test]
    fn rfc6238_sha512_8digit() {
        let expected = [
            "90693936", "25091201", "99943326", "93441116", "38618901", "47863826",
        ];
        for (t, exp) in TIMES.iter().zip(expected) {
            let c = totp_at(SECRET_SHA512, *t, &params(TotpAlgorithm::Sha512, 8)).unwrap();
            assert_eq!(c.code(), exp, "SHA512 t={t}");
        }
    }

    #[test]
    fn rfc6238_sha1_6digit_is_last_six() {
        // The 8-digit SHA-1 @ T=59 is 94287082 → 6-digit is 287082.
        let c = totp_at(SECRET_SHA1, 59, &params(TotpAlgorithm::Sha1, 6)).unwrap();
        assert_eq!(c.code(), "287082");
        // And the default params (SHA1/6/30) agree.
        let d = totp_at(SECRET_SHA1, 59, &TotpParams::default()).unwrap();
        assert_eq!(d.code(), "287082");
    }

    #[test]
    fn seconds_remaining_and_window_boundary() {
        let p = TotpParams::default();
        let at_zero = totp_at(SECRET_SHA1, 0, &p).unwrap();
        assert_eq!(at_zero.seconds_remaining, 30);
        let near_end = totp_at(SECRET_SHA1, 29, &p).unwrap();
        assert_eq!(near_end.seconds_remaining, 1);
        let next_window = totp_at(SECRET_SHA1, 30, &p).unwrap();
        assert_eq!(next_window.seconds_remaining, 30);
        // Same window 0:
        assert_eq!(at_zero.code(), near_end.code());
        // Different window:
        assert_ne!(at_zero.code(), next_window.code());
    }

    #[test]
    fn rejects_empty_and_oversized_and_bad_params() {
        assert_eq!(
            totp_at(b"", 0, &TotpParams::default()).unwrap_err(),
            TotpError::EmptySecret
        );
        let big = vec![0u8; MAX_SECRET_BYTES + 1];
        assert!(matches!(
            totp_at(&big, 0, &TotpParams::default()),
            Err(TotpError::SecretTooLong { .. })
        ));
        assert_eq!(
            totp_at(b"x", 0, &params(TotpAlgorithm::Sha1, 5)).unwrap_err(),
            TotpError::InvalidDigits(5)
        );
        assert_eq!(
            totp_at(
                b"x",
                0,
                &TotpParams {
                    algorithm: TotpAlgorithm::Sha1,
                    digits: 6,
                    period_seconds: 0
                }
            )
            .unwrap_err(),
            TotpError::InvalidPeriod(0)
        );
    }

    #[test]
    fn code_debug_is_redacted() {
        let c = totp_at(SECRET_SHA1, 59, &TotpParams::default()).unwrap();
        let printed = format!("{c:?}");
        assert!(!printed.contains("287082"));
        assert!(printed.contains("<redacted>"));
    }

    #[test]
    fn algorithm_wire_roundtrip() {
        for a in [
            TotpAlgorithm::Sha1,
            TotpAlgorithm::Sha256,
            TotpAlgorithm::Sha512,
        ] {
            assert_eq!(TotpAlgorithm::from_wire(a.to_wire()).unwrap(), a);
            assert_eq!(TotpAlgorithm::parse(a.as_str()).unwrap(), a);
        }
        assert!(TotpAlgorithm::parse("md5").is_err());
        assert!(TotpAlgorithm::from_wire(7).is_err());
    }
}
