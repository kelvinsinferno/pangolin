//! `pangolin-store` error taxonomy.
//!
//! A single typed enum that exposes the failure modes downstream callers
//! need to distinguish. Authentication failures (wrong password, tampered
//! ciphertext, transplanted row, schema-version mismatch) ALL collapse
//! into [`StoreError::AuthenticationFailed`] so a caller cannot turn the
//! variant set into an oracle. This mirrors the
//! [`pangolin_crypto::aead::AeadError::Tampered`] discipline in the
//! cryptographic layer.

use pangolin_crypto::aead::AeadError;
use pangolin_crypto::kdf::KdfError;

/// Convenience alias used across the crate.
pub type Result<T> = core::result::Result<T, StoreError>;

/// Top-level error type for `pangolin-store`.
///
/// Variants carry only non-sensitive context (file paths, format-version
/// numbers). Authentication-class failures collapse into a single
/// [`Self::AuthenticationFailed`] variant so the failure cause is not
/// distinguishable to a caller.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// I/O error from the OS layer (file open/read/write/rename).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Underlying `SQLite` error mapped from `rusqlite`.
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    /// The vault file's magic header bytes do not match
    /// [`crate::meta::MAGIC`]. Either not a Pangolin vault file or the
    /// file was truncated below 8 bytes.
    #[error("not a Pangolin vault file (bad magic header)")]
    BadMagic,

    /// `format_version` byte read from the meta header is newer than
    /// this build of `pangolin-store` understands.
    ///
    /// Per master plan §18.7 schema-versioning policy, future versions
    /// must accept all old versions read-only and produce a stable error
    /// on unknown future versions — this is that error.
    #[error("unsupported vault format version: {0} (this build supports {1})")]
    UnsupportedFormatVersion(u32, u32),

    /// CBOR encoding/decoding failure on a sensitive payload.
    ///
    /// Typically indicates an `AccountSnapshot` whose stored bytes were
    /// either truncated in transit or corrupted on disk. The variant is
    /// distinct from [`Self::AuthenticationFailed`] because a CBOR error
    /// after a successful AEAD authentication is structurally a corrupt
    /// store, not an attacker, and the caller may want to differentiate
    /// for telemetry. The CBOR cause string is opaque (no plaintext is
    /// included by construction).
    #[error("CBOR codec error: {0}")]
    Cbor(String),

    /// Authentication-class failure. Wrong password, tampered ciphertext,
    /// transplanted row, schema-version mismatch — all collapse here.
    /// Callers MUST NOT branch on the underlying cause.
    #[error("authentication failed")]
    AuthenticationFailed,

    /// `unlock`, `add_account`, etc. were called while the vault was not
    /// in the [`crate::vault::VaultState::Active`] state.
    #[error("operation requires the vault to be unlocked (active)")]
    NotUnlocked,

    /// `lock` or `add_account` was called on a closed vault handle.
    #[error("vault handle is closed")]
    Closed,

    /// `Vault::open` was called on a path that another live `Vault`
    /// instance already holds. Implemented via a sidecar lock file in
    /// [`crate::vault`].
    #[error("vault file is already open by another handle")]
    AlreadyOpen,

    /// `get_account`/`update_account`/`delete_account` was given an
    /// `AccountId` that does not appear in `account_identities`.
    #[error("account not found")]
    AccountNotFound,

    /// `update_account` / `delete_account` was called on an account that
    /// has already been tombstoned. Tombstoned accounts may still be
    /// queried via [`crate::vault::Vault::revisions_for`] but cannot be
    /// edited further.
    #[error("account has been deleted (tombstoned)")]
    AccountTombstoned,

    /// `mark_published` was called for a `revision_id` not present in
    /// the local revision log.
    #[error("revision not found")]
    RevisionNotFound,

    /// Catch-all for storage-level integrity violations (e.g.,
    /// `PRAGMA integrity_check` returning anything other than "ok").
    #[error("storage corruption detected: {0}")]
    Corrupted(String),

    /// KDF parameter rejection from `pangolin-crypto`. Most often
    /// surfaces when the on-disk meta KDF params have been edited below
    /// the validation floor. Treated as a tamper signal — opening a
    /// vault file with weakened params is indistinguishable from any
    /// other meta-tamper from the user's POV.
    #[error("KDF parameters rejected by pangolin-crypto")]
    KdfRejected,
}

impl From<AeadError> for StoreError {
    fn from(_: AeadError) -> Self {
        // Per the docstring on `AuthenticationFailed`: every AEAD failure
        // collapses into a single variant so a caller cannot oracle the
        // cause. We deliberately discard the inner variant (which is
        // already `Tampered` by `pangolin-crypto`'s own collapsing) so
        // there is no path back to a distinguishing factor.
        Self::AuthenticationFailed
    }
}

impl From<KdfError> for StoreError {
    fn from(_: KdfError) -> Self {
        // Same reasoning as `AeadError`: weakened on-disk KDF params or
        // an internal Argon2 rejection should not turn into separate
        // user-visible errors. Map to `KdfRejected` so test code can
        // observe the structural class without distinguishing the cause.
        Self::KdfRejected
    }
}
