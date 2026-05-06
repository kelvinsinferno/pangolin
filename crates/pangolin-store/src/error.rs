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

use crate::session::AuthError;

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
    /// transplanted row, schema-version mismatch, weakened-on-disk KDF
    /// parameters, internal Argon2 rejection — **all** collapse here.
    /// Callers MUST NOT branch on the underlying cause.
    ///
    /// MEDIUM-1 of the P2 audit: a previously-distinct `KdfRejected`
    /// variant let an attacker who tampered with `kdf_memory_kib` /
    /// `time_cost` / `parallelism` distinguish "I weakened the KDF
    /// params" from "I tampered with the salt or wrapped ciphertext."
    /// Both now collapse here.
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

    /// The session was active but its idle timer or absolute-max ceiling
    /// fired. The cache is zeroized at the moment of expiry; the next
    /// op must re-supply both proofs (presence + identity) per Session
    /// spec §3 invariant 3.
    ///
    /// `with_session` callers can recover by running the supplied
    /// re-auth callback and re-running the original op.
    #[error("session expired; both proofs are required to resume")]
    SessionExpired,

    /// The session is in the [`crate::session::SessionState::PendingAuthorization`]
    /// state — a re-auth flow is in progress and the host UI has not yet
    /// gathered both proofs. Operations are deferred. Distinct from
    /// `NotUnlocked` so callers can distinguish "vault was never
    /// unlocked" from "vault entered the prompt-state and is waiting on
    /// the host UI".
    #[error("session is awaiting authorization (proofs in flight)")]
    SessionPending,

    /// A high-risk operation (`reveal_password`, `export_payload`,
    /// future recovery-changes / device-approvals) was called without
    /// the explicit fresh presence proof Session spec §5.3 requires.
    /// Distinct from `AuthenticationFailed` because the failure mode
    /// is structural ("you didn't supply the proof") rather than
    /// cryptographic ("the proof failed to verify"). Callers should
    /// prompt the user for an explicit presence confirmation and retry.
    #[error("operation requires a fresh presence proof")]
    PresenceProofRequired,
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
        // MEDIUM-1: Same reasoning as `AeadError`. Weakened on-disk KDF
        // params or an internal Argon2 rejection collapse into the same
        // `AuthenticationFailed` variant so an attacker who tampers
        // with the meta row's KDF parameters cannot distinguish that
        // tamper from a salt or ciphertext tamper. Indistinguishability
        // is the explicit promise of `THREAT_MODEL.md` row #7.
        Self::AuthenticationFailed
    }
}

impl From<AuthError> for StoreError {
    fn from(_: AuthError) -> Self {
        // P4: every proof-verification failure (PIN empty, presence
        // already consumed, presence stale, generic "Failed") collapses
        // into `AuthenticationFailed`. Same MEDIUM-1 indistinguishability
        // discipline as the AEAD/KDF paths: a caller MUST NOT be able
        // to tell "you supplied an empty PIN" from "your presence proof
        // was replayed" from "the KDF derivation rejected" — those are
        // all "authentication failed" from the user's perspective.
        //
        // Note: `SessionExpired`, `SessionPending`, and
        // `PresenceProofRequired` are STRUCTURAL conditions detected
        // before any proof verify runs and are surfaced via their own
        // distinct variants. They cannot be confused with proof-
        // verification failure because they happen at a different point
        // in the call chain (state-machine check vs. crypto check).
        Self::AuthenticationFailed
    }
}
