// SPDX-License-Identifier: AGPL-3.0-or-later
//! TOTP FFI surface (MVP-1 issue 1.7), backed by `pangolin-totp`.
//!
//! `totp_generate` (1.1-frozen signature) is **session-class** (Q3): it
//! needs only an unlocked, non-expired vault — no presence proof. The
//! raw seed stays reveal-class (`reveal_totp_secret`, 1.4-gated); the
//! generator decrypts it transiently inside `pangolin-store` /
//! `pangolin-totp` and only the digit string crosses out.
//!
//! `parse_totp_secret` is an additive amendment: the shell calls it on
//! the user's pasted `otpauth://` URI / bare base32 string, then passes
//! the parsed `{ secret, algorithm, digits, period }` into
//! `account_add` / `account_update` (whose `totp_params` field carries
//! the params alongside the secret bytes).

use std::sync::Arc;

use crate::error::FfiError;
use crate::identity::{AccountId, TotpSecret};
use crate::session::{UnixTimestamp, VaultHandle};

/// HMAC hash algorithm for the TOTP HOTP step. Mirrors
/// [`pangolin_totp::TotpAlgorithm`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum TotpAlgorithm {
    /// HMAC-SHA1 — the RFC 6238 default.
    Sha1,
    /// HMAC-SHA256.
    Sha256,
    /// HMAC-SHA512.
    Sha512,
}

impl From<pangolin_totp::TotpAlgorithm> for TotpAlgorithm {
    fn from(a: pangolin_totp::TotpAlgorithm) -> Self {
        match a {
            pangolin_totp::TotpAlgorithm::Sha1 => Self::Sha1,
            pangolin_totp::TotpAlgorithm::Sha256 => Self::Sha256,
            pangolin_totp::TotpAlgorithm::Sha512 => Self::Sha512,
        }
    }
}

impl From<TotpAlgorithm> for pangolin_totp::TotpAlgorithm {
    fn from(a: TotpAlgorithm) -> Self {
        match a {
            TotpAlgorithm::Sha1 => Self::Sha1,
            TotpAlgorithm::Sha256 => Self::Sha256,
            TotpAlgorithm::Sha512 => Self::Sha512,
        }
    }
}

/// TOTP parameters (algorithm / digits / period).
///
/// Carried on [`crate::identity::AccountDraft`] /
/// [`crate::identity::AccountPatch`] alongside the secret bytes. `None`
/// on those records (when a secret is present) means "use the RFC 6238
/// defaults" — SHA-1 / 6 / 30.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct TotpParamsFfi {
    /// Schema-version slot.
    pub schema_version: u16,
    /// HMAC hash algorithm.
    pub algorithm: TotpAlgorithm,
    /// Code length in digits (6, 7, or 8).
    pub digits: u8,
    /// Time step / window length in seconds (> 0; default 30).
    pub period_seconds: u32,
}

impl TotpParamsFfi {
    /// Build from a `pangolin-totp` params value.
    #[must_use]
    pub fn from_core(p: pangolin_totp::TotpParams) -> Self {
        Self {
            schema_version: pangolin_core::ACCOUNT_IDENTITY_SCHEMA_VERSION,
            algorithm: p.algorithm.into(),
            digits: p.digits,
            period_seconds: p.period_seconds,
        }
    }

    /// Convert to a `pangolin-totp` params value (no validation here —
    /// the store-side `validate::totp_params` runs on write).
    #[must_use]
    pub fn into_core(self) -> pangolin_totp::TotpParams {
        pangolin_totp::TotpParams {
            algorithm: self.algorithm.into(),
            digits: self.digits,
            period_seconds: self.period_seconds,
        }
    }
}

/// A 6-or-8-digit TOTP code wrapped with its time-window so the UI can
/// render a countdown. `code` is plain digits (no punctuation).
#[derive(Debug, Clone, uniffi::Record)]
pub struct TotpCode {
    /// Issue 1.1 schema-version slot.
    pub schema_version: u16,
    /// The decimal code (e.g., `"123456"`), left-zero-padded to the
    /// configured digit count.
    pub code: String,
    /// Number of seconds remaining in the current TOTP window.
    pub seconds_remaining: u16,
}

/// The result of parsing a user- or KDBX-supplied TOTP string.
#[derive(Debug, uniffi::Record)]
pub struct ParsedTotpSecretFfi {
    /// Schema-version slot.
    pub schema_version: u16,
    /// The raw shared-secret seed bytes (zeroizing object handle).
    pub secret: Arc<TotpSecret>,
    /// The parsed TOTP parameters.
    pub params: TotpParamsFfi,
    /// Optional `otpauth://` label (informational; the shell may use it
    /// to pre-fill a display name).
    pub label: Option<String>,
    /// Optional `issuer=` value (informational).
    pub issuer: Option<String>,
}

fn store_into_ffi(err: pangolin_store::StoreError) -> FfiError {
    FfiError::from(pangolin_core::Error::from(err))
}

fn totp_into_ffi(err: pangolin_totp::TotpError) -> FfiError {
    // All `TotpError` variants are user-facing validation failures.
    FfiError::Validation {
        kind: "totp".into(),
        message: err.to_string(),
    }
}

/// Generate a TOTP code for the given account at the given Unix-second
/// timestamp. **Session-class** — requires only an unlocked, non-expired
/// vault (no presence proof). Backed by `pangolin-totp`.
///
/// # Errors
///
/// `FfiError::Session` for a locked / expired session or a frozen /
/// requires-upgrade account; `FfiError::Validation` with `kind = "totp"`
/// for a negative timestamp; `FfiError::Validation` with
/// `kind = "totp_not_configured"` when the account has no TOTP secret;
/// `FfiError::Store` for an unknown / tombstoned account.
#[allow(clippy::significant_drop_tightening)]
#[uniffi::export]
pub fn totp_generate(
    handle: Arc<VaultHandle>,
    id: AccountId,
    at: UnixTimestamp,
) -> Result<TotpCode, FfiError> {
    let mut guard = handle.lock_vault();
    let vault = guard.as_mut()?;
    let store_id = crate::identity_bridge::account_id_from_ffi(&id)?;
    let at_secs = u64::try_from(at).map_err(|_| FfiError::Validation {
        kind: "totp".into(),
        message: "timestamp must be a non-negative Unix second count".into(),
    })?;
    let code = vault
        .totp_generate(store_id, at_secs)
        .map_err(store_into_ffi)?;
    Ok(TotpCode {
        schema_version: pangolin_core::ACCOUNT_IDENTITY_SCHEMA_VERSION,
        code: code.code_owned(),
        seconds_remaining: u16::try_from(code.seconds_remaining).unwrap_or(u16::MAX),
    })
}

/// Parse either a full `otpauth://totp/...` URI or a bare base32 secret
/// into `{ secret, params, label, issuer }`. The shell calls this before
/// `account_add` / `account_update`. No vault access.
///
/// # Errors
///
/// `FfiError::Validation` with `kind = "totp"` for any malformed input
/// (bad base32, malformed URI, HOTP URI, unknown algorithm, out-of-range
/// digits/period, empty secret).
#[uniffi::export]
pub fn parse_totp_secret(input: String) -> Result<ParsedTotpSecretFfi, FfiError> {
    let parsed = pangolin_totp::parse_totp_secret(&input).map_err(totp_into_ffi)?;
    let mut bytes = zeroize::Zeroizing::new(parsed.secret_bytes.to_vec());
    Ok(ParsedTotpSecretFfi {
        schema_version: pangolin_core::ACCOUNT_IDENTITY_SCHEMA_VERSION,
        secret: TotpSecret::new(std::mem::take(&mut *bytes)),
        params: TotpParamsFfi::from_core(parsed.params),
        label: parsed.label,
        issuer: parsed.issuer,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn algorithm_round_trip() {
        for a in [
            TotpAlgorithm::Sha1,
            TotpAlgorithm::Sha256,
            TotpAlgorithm::Sha512,
        ] {
            let core: pangolin_totp::TotpAlgorithm = a.into();
            assert_eq!(TotpAlgorithm::from(core), a);
        }
    }

    #[test]
    fn parse_totp_secret_round_trips() {
        let p = parse_totp_secret("JBSWY3DPEHPK3PXP".to_string()).unwrap();
        assert_eq!(p.params.digits, 6);
        assert_eq!(p.params.algorithm, TotpAlgorithm::Sha1);
        assert_eq!(p.secret.byte_length(), 10);
        let uri = parse_totp_secret(
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256&digits=8&period=60".into(),
        )
        .unwrap();
        assert_eq!(uri.params.algorithm, TotpAlgorithm::Sha256);
        assert_eq!(uri.params.digits, 8);
        assert_eq!(uri.params.period_seconds, 60);
        assert!(parse_totp_secret("!!!".into()).is_err());
    }
}
