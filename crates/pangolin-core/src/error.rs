//! `pangolin-core` unified error taxonomy.
//!
//! Per master plan §18.8, MVP-1 freezes the *categories* an FFI consumer
//! can branch on; per-domain enums (`Session::*`, `Sync::*`, etc.) land
//! in their respective issues (1.4 owns Session, 1.6 owns Sync, etc.).
//! This enum is the FFI-bound categorization that MVP-1 issue 1.1
//! commits to.
//!
//! ## Invariants
//!
//! 1. **No plaintext leak through `Debug`/`Display`.** Each variant
//!    carries a non-secret `String` that is safe to render in a UI.
//! 2. **`Authentication` collapses every authentication-class
//!    failure** — wrong password, tampered ciphertext, KDF parameter
//!    tamper, presence-proof replay. Callers MUST NOT branch further
//!    on the cause; doing so reintroduces an oracle.
//! 3. **`From<pangolin_store::StoreError>` is total** so today's
//!    code paths can ride the namespace; future per-domain enums
//!    (1.4's `Session::Error`, 1.6's `Sync::Error`) extend the mapping
//!    rather than replace it.

use pangolin_store::StoreError;

/// Top-level error type for `pangolin-core`.
///
/// Variants mirror the §18.8 FFI-side taxonomy 1:1. `pangolin-ffi`'s
/// `FfiError` is a thin re-categorization that downstream callers see;
/// the mapping there is verified to be total by an exhaustive-match
/// integration test.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Cryptographic failure — AEAD authentication, KDF rejection,
    /// signature verify. Inner string is a non-secret category label.
    #[error("crypto error: {0}")]
    Crypto(String),

    /// Storage failure — `SQLite` open / read / write, blob-format
    /// mismatch, schema-version too new.
    #[error("store error: {0}")]
    Store(String),

    /// Session-state failure — vault not unlocked, session expired,
    /// presence proof required, prompt-state in flight.
    #[error("session error: {0}")]
    Session(String),

    /// Sync / chain-event failure — pull / publish flow.
    #[error("sync error: {0}")]
    Sync(String),

    /// EVM chain failure — RPC, signature submission, gas estimation.
    /// Reserved for MVP-2 (chain code dormant for MVP-1).
    #[error("chain error: {0}")]
    Chain(String),

    /// Social-recovery failure — guardian threshold, share decode,
    /// transcript replay. Reserved for MVP-3.
    #[error("recovery error: {0}")]
    Recovery(String),

    /// Caller-input validation failure — bad path, out-of-range
    /// argument, mis-shaped record. `kind` lets the FFI side carry a
    /// stable category label (e.g., `"path"`, `"argument"`).
    #[error("validation error ({kind}): {message}")]
    Validation { kind: String, message: String },

    /// Authentication-class failure — wrong password, tampered
    /// ciphertext, KDF parameter tamper, presence-proof replay. **All**
    /// authentication-class failures collapse here so a caller cannot
    /// branch on the cause and turn the variant set into an oracle.
    /// See `pangolin_store::StoreError::AuthenticationFailed` for the
    /// equivalent discipline at the storage layer.
    #[error("authentication failed")]
    Authentication,
}

impl From<StoreError> for Error {
    fn from(err: StoreError) -> Self {
        // The mapping is intentionally conservative: every store-level
        // error becomes a `Store(...)` or `Authentication` variant.
        // Per-domain refinement (e.g., session-state errors mapping to
        // `Session(...)`) happens in 1.4's session rewrite — at that
        // point the store's session module is gone and the mapping
        // shifts to the new per-domain enum.
        match err {
            StoreError::AuthenticationFailed => Self::Authentication,
            StoreError::SessionExpired
            | StoreError::SessionPending
            | StoreError::PresenceProofRequired
            | StoreError::NotUnlocked => Self::Session(err.to_string()),
            StoreError::Validation { kind, message } => Self::Validation { kind, message },
            other => Self::Store(other.to_string()),
        }
    }
}
