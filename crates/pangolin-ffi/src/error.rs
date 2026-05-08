//! `FfiError` — the FFI-side error taxonomy.
//!
//! Mirrors master plan §18.8 (Error / Result Type Taxonomy): variants
//! are `Crypto`, `Store`, `Session`, `Sync`, `Chain`, `Recovery`,
//! `Validation`, `Internal`. The taxonomy is locked at MVP-1 issue 1.1;
//! variant *contents* are filled in as later issues land their domain
//! errors (1.4 owns `Session::*`, 1.6 owns `Sync::*`, etc.).
//!
//! ## Invariants
//!
//! 1. **No plaintext leak through `Debug`/`Display`.** Per Design Spec
//!    §15, the only string a UI ever sees is [`FfiError::message`]'s
//!    output, which is an opaque category label. The `Debug` derive is
//!    safe because the inner strings are also UI-safe by construction.
//! 2. **Total `From<pangolin_core::Error>` mapping.** Every
//!    `pangolin_core::Error` variant maps to a non-`Internal`
//!    `FfiError` variant. Verified by `tests/error_taxonomy.rs`.
//! 3. **Authentication-class failures collapse.** Wrong password,
//!    tampered ciphertext, KDF tamper, presence-proof replay all map
//!    to `FfiError::Validation { kind: "authentication" }` so a caller
//!    cannot oracle the cause.

use crate::session::SecretPassword;

/// Top-level FFI error type.
///
/// Carried across the `UniFFI` / cbindgen boundary. Variants intentionally
/// use simple `String` payloads (not nested error types) so the foreign-
/// language bindings see plain enums with no associated-type complexity.
#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum FfiError {
    /// Cryptographic failure — AEAD authentication, signature verify,
    /// KDF parameter rejection.  Message is opaque.
    #[error("crypto error: {message}")]
    Crypto { message: String },

    /// Storage failure — `SQLite` open, blob read/write, schema-version
    /// mismatch on read.
    #[error("store error: {message}")]
    Store { message: String },

    /// Session-state failure — vault not unlocked, session expired,
    /// presence proof required, prompt-state in flight. Distinct from
    /// `Validation` because the failure is structural (caller called
    /// the wrong op for the current vault state) rather than
    /// authentication-class.
    #[error("session error: {message}")]
    Session { message: String },

    /// Sync / chain-event failure — chain RPC, ingest, fork detection.
    /// MVP-1 owns `pull` + `publish` only; `Chain` is the dormant
    /// MVP-2 cousin.
    #[error("sync error: {message}")]
    Sync { message: String },

    /// EVM chain failure — RPC, signature submission, gas estimation.
    /// Dormant for MVP-1 but the variant is reserved.
    #[error("chain error: {message}")]
    Chain { message: String },

    /// Social-recovery failure — guardian threshold, share decode,
    /// transcript replay. Reserved for MVP-3.
    #[error("recovery error: {message}")]
    Recovery { message: String },

    /// Caller-input validation failure — bad path, bad UTF-8 in a
    /// password (rare; we accept arbitrary bytes via [`SecretPassword`]),
    /// out-of-range query argument. **Authentication-class failures
    /// collapse here** with `kind = "authentication"` so a caller
    /// cannot distinguish "wrong password" from "tampered ciphertext"
    /// from "KDF parameter tamper".
    #[error("validation error ({kind}): {message}")]
    Validation { kind: String, message: String },

    /// Internal-state failure — non-recoverable runtime condition that
    /// a caller cannot meaningfully act on. `tests/error_taxonomy.rs`
    /// asserts no `pangolin_core::Error` variant maps here so this
    /// variant catches only genuine "this should never happen" paths.
    #[error("internal error: {message}")]
    Internal { message: String },
}

impl FfiError {
    /// UI-safe message string. Per Design Spec §15, this is the only
    /// string a UI ever shows from the FFI surface; `Debug`/`Display`
    /// outputs are for logging only and are also UI-safe by
    /// construction.
    #[must_use]
    pub fn message(&self) -> String {
        self.to_string()
    }

    /// Convenience constructor for the authentication-class collapse.
    /// MVP-1 issue 1.4 (Session) routes every wrong-password / tampered-
    /// ciphertext / KDF-tamper / presence-replay path through this so
    /// the FFI surface cannot become a distinguishing oracle.
    #[must_use]
    pub fn authentication_failed() -> Self {
        Self::Validation {
            kind: "authentication".to_owned(),
            message: "authentication failed".to_owned(),
        }
    }
}

// `SecretPassword` is referenced in this module's docstring; importing
// it here keeps rustc's intra-doc-link checker happy without forcing a
// cross-module use in callers.
const _: fn() = || {
    let _: Option<&SecretPassword> = None;
};

/// Total mapping from `pangolin_core::Error` to `FfiError`.
///
/// Every variant must map to a non-`Internal` `FfiError` variant per
/// `tests/error_taxonomy.rs`. As 1.4 / 1.6 / etc. land richer variants
/// in `pangolin_core::Error`, this `From` impl gains arms; the
/// exhaustive-match test ensures it stays total.
impl From<pangolin_core::Error> for FfiError {
    fn from(err: pangolin_core::Error) -> Self {
        match err {
            pangolin_core::Error::Crypto(message) => Self::Crypto { message },
            pangolin_core::Error::Store(message) => Self::Store { message },
            pangolin_core::Error::Session(message) => Self::Session { message },
            pangolin_core::Error::Sync(message) => Self::Sync { message },
            pangolin_core::Error::Chain(message) => Self::Chain { message },
            pangolin_core::Error::Recovery(message) => Self::Recovery { message },
            pangolin_core::Error::Validation { kind, message } => {
                Self::Validation { kind, message }
            }
            pangolin_core::Error::Authentication => Self::authentication_failed(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::FfiError;

    #[test]
    fn authentication_failed_collapses_to_validation() {
        let e = FfiError::authentication_failed();
        match e {
            FfiError::Validation { kind, message } => {
                assert_eq!(kind, "authentication");
                assert_eq!(message, "authentication failed");
            }
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn message_is_non_empty_for_every_variant() {
        let cases = [
            FfiError::Crypto {
                message: "x".into(),
            },
            FfiError::Store {
                message: "x".into(),
            },
            FfiError::Session {
                message: "x".into(),
            },
            FfiError::Sync {
                message: "x".into(),
            },
            FfiError::Chain {
                message: "x".into(),
            },
            FfiError::Recovery {
                message: "x".into(),
            },
            FfiError::Validation {
                kind: "k".into(),
                message: "x".into(),
            },
            FfiError::Internal {
                message: "x".into(),
            },
        ];
        for c in cases {
            assert!(!c.message().is_empty(), "message empty for {c:?}");
        }
    }
}
