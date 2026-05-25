// SPDX-License-Identifier: AGPL-3.0-or-later
//! `DesktopError` — the typed Tauri-side error envelope.
//!
//! Maps every [`pangolin_ffi::FfiError`] variant to a serde-serializable
//! variant the React side discriminates on. Per MVP-4-B plan §3.3:
//!
//! - `AuthenticationFailed` is surfaced **inline under the password field**
//!   on the unlock screen (the lone exception to the "red toast" policy).
//! - Every other variant becomes a danger toast at the bottom-right via
//!   `useToast.danger(...)`.
//!
//! ## Invariants
//!
//! - **L1.** `message` strings are **opaque category labels** (the same
//!   strings `FfiError::message()` already returns). No secret material
//!   ever lands here. The `From<FfiError>` mapping is total.
//! - **L3.** Every `FfiError` variant has an explicit mapping; an
//!   unrecognized variant (impossible today, the enum is closed) would
//!   collapse to `Internal` — fail-closed, not fail-open.

#![forbid(unsafe_code)]

use pangolin_ffi::FfiError;
use serde::Serialize;

/// Top-level Tauri command error.
///
/// Serializes through Tauri's `Result<T, E>` invoke envelope. The
/// `#[serde(tag = "kind", content = "message")]` shape gives the React
/// side a typed discriminator (`{kind: "Session", message: "..."}`).
#[derive(Debug, Clone, Serialize, thiserror::Error)]
#[serde(tag = "kind", content = "message")]
pub enum DesktopError {
    /// Vault not unlocked / session expired / placeholder handle.
    #[error("session error: {0}")]
    Session(String),

    /// Caller-input validation failure. The inner `kind` mirrors the
    /// `FfiError::Validation` `kind` slot (e.g. `"export_io"`,
    /// `"password_policy"`); the inner `message` is UI-safe.
    ///
    /// The `kind = "authentication"` arm of `FfiError::Validation` is
    /// the LONE `FfiError` variant that this enum does NOT collapse here;
    /// it's promoted to [`DesktopError::AuthenticationFailed`] so the
    /// React side can render the inline-on-unlock-screen treatment per
    /// the plan §3.3.
    #[error("validation error ({kind}): {message}")]
    Validation { kind: String, message: String },

    /// EVM chain failure (RPC, transaction submission, fee estimation).
    /// No chain-touching command lands in this slice, but the variant
    /// is reserved so the mapping is total.
    #[error("chain error: {0}")]
    Chain(String),

    /// Storage failure — `SQLite` open, blob read/write, schema-version
    /// mismatch on read, file already exists, etc.
    #[error("store error: {0}")]
    Store(String),

    /// Social-recovery failure. Reserved for the MVP-4 back-half
    /// recovery UX.
    #[error("recovery error: {0}")]
    Recovery(String),

    /// Sync / chain-event failure (chain RPC, ingest, fork detection).
    /// Reserved for the MVP-4 back-half sync UX.
    #[error("sync error: {0}")]
    Sync(String),

    /// Cryptographic failure — AEAD authentication, signature verify,
    /// KDF parameter rejection. Reserved; `FfiError::Crypto` flows here
    /// for completeness even though MVP-4-B's surface does not exercise
    /// it directly.
    #[error("crypto error: {0}")]
    Crypto(String),

    /// Internal-state failure — non-recoverable runtime condition the
    /// caller cannot meaningfully act on.
    #[error("internal error: {0}")]
    Internal(String),

    /// Wrong master password — collapsed authentication-class failure
    /// per Design Spec §15 + Session spec §5.4 (MEDIUM-1
    /// indistinguishability: wrong password / tampered ciphertext / KDF
    /// tamper / replayed presence all look identical from the outside).
    ///
    /// The React side renders this **inline under the password field**
    /// on the unlock screen, NOT as a toast (per plan §3.3 — a
    /// critical-action failure should not vanish after 4 seconds).
    #[error("authentication failed")]
    AuthenticationFailed,
}

impl From<FfiError> for DesktopError {
    fn from(err: FfiError) -> Self {
        match err {
            FfiError::Session { message } => Self::Session(message),
            FfiError::Validation { kind, message } => {
                // The 1.4 authentication-class collapse uses
                // `kind = "authentication"`. Promote that one arm to
                // the dedicated inline-treatment variant.
                if kind == "authentication" {
                    Self::AuthenticationFailed
                } else {
                    Self::Validation { kind, message }
                }
            }
            FfiError::Chain { message } => Self::Chain(message),
            FfiError::Store { message } => Self::Store(message),
            FfiError::Recovery { message } => Self::Recovery(message),
            FfiError::Sync { message } => Self::Sync(message),
            FfiError::Crypto { message } => Self::Crypto(message),
            FfiError::Internal { message } => Self::Internal(message),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::DesktopError;
    use pangolin_ffi::FfiError;

    #[test]
    fn authentication_validation_promotes_to_authentication_failed() {
        let ffi = FfiError::authentication_failed();
        let desktop: DesktopError = ffi.into();
        assert!(matches!(desktop, DesktopError::AuthenticationFailed));
    }

    #[test]
    fn non_authentication_validation_stays_validation() {
        let ffi = FfiError::Validation {
            kind: "password_policy".into(),
            message: "length out of range".into(),
        };
        let desktop: DesktopError = ffi.into();
        match desktop {
            DesktopError::Validation { kind, message } => {
                assert_eq!(kind, "password_policy");
                assert_eq!(message, "length out of range");
            }
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn session_maps_to_session() {
        let ffi = FfiError::Session {
            message: "no vault open".into(),
        };
        let desktop: DesktopError = ffi.into();
        match desktop {
            DesktopError::Session(m) => assert_eq!(m, "no vault open"),
            other => panic!("expected Session, got {other:?}"),
        }
    }

    #[test]
    fn store_maps_to_store() {
        let ffi = FfiError::Store {
            message: "sqlite open".into(),
        };
        let desktop: DesktopError = ffi.into();
        match desktop {
            DesktopError::Store(m) => assert_eq!(m, "sqlite open"),
            other => panic!("expected Store, got {other:?}"),
        }
    }

    #[test]
    fn chain_maps_to_chain() {
        let ffi = FfiError::Chain {
            message: "rpc".into(),
        };
        let desktop: DesktopError = ffi.into();
        assert!(matches!(desktop, DesktopError::Chain(_)));
    }

    #[test]
    fn recovery_maps_to_recovery() {
        let ffi = FfiError::Recovery {
            message: "guardian".into(),
        };
        let desktop: DesktopError = ffi.into();
        assert!(matches!(desktop, DesktopError::Recovery(_)));
    }

    #[test]
    fn sync_maps_to_sync() {
        let ffi = FfiError::Sync {
            message: "ingest".into(),
        };
        let desktop: DesktopError = ffi.into();
        assert!(matches!(desktop, DesktopError::Sync(_)));
    }

    #[test]
    fn crypto_maps_to_crypto() {
        let ffi = FfiError::Crypto {
            message: "aead".into(),
        };
        let desktop: DesktopError = ffi.into();
        assert!(matches!(desktop, DesktopError::Crypto(_)));
    }

    #[test]
    fn internal_maps_to_internal() {
        let ffi = FfiError::Internal {
            message: "boom".into(),
        };
        let desktop: DesktopError = ffi.into();
        assert!(matches!(desktop, DesktopError::Internal(_)));
    }

    /// L1: the serialized envelope is `{kind, message}` and the message
    /// is a non-empty UI-safe string. Never embeds raw bytes.
    #[test]
    fn serialized_shape_is_kind_plus_message() {
        let desktop = DesktopError::Session("locked".into());
        let json = serde_json::to_value(&desktop).expect("serialize");
        assert_eq!(json["kind"], "Session");
        assert_eq!(json["message"], "locked");
    }

    #[test]
    fn authentication_failed_serializes_with_unit_payload() {
        let desktop = DesktopError::AuthenticationFailed;
        let json = serde_json::to_value(&desktop).expect("serialize");
        assert_eq!(json["kind"], "AuthenticationFailed");
        // Unit variant serializes with no `message` field; the React
        // side discriminates on `kind` alone.
        assert!(json.get("message").is_none() || json["message"].is_null());
    }
}
