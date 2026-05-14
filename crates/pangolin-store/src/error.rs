//! `pangolin-store` error taxonomy.
//!
//! A single typed enum that exposes the failure modes downstream callers
//! need to distinguish. Authentication failures (wrong password, tampered
//! ciphertext, transplanted row, schema-version mismatch) ALL collapse
//! into [`StoreError::AuthenticationFailed`] so a caller cannot turn the
//! variant set into an oracle. This mirrors the
//! [`pangolin_crypto::aead::AeadError::Tampered`] discipline in the
//! cryptographic layer.

use pangolin_chain::ChainError;
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

    /// **P9 fix-pass MED-3.** [`crate::vault::Vault::clear_frozen`]
    /// was called with a `chosen_revision_id` that exists in the
    /// `revisions` table for the account but is NOT a current head
    /// of the account's revision graph at the time of the SQL
    /// transaction. This catches the bug class where the resolve
    /// flow passes the old chosen-revision-id (a non-head, demoted
    /// by the merge revision's INSERT) instead of the merge
    /// revision's id. Distinct from `RevisionNotFound` because the
    /// row exists; it just isn't a current head.
    #[error(
        "supplied revision_id is not a current head at the time of the clear_frozen \
         transaction"
    )]
    NotAHead {
        /// The account id that was being cleared.
        account_id: crate::account::AccountId,
        /// The non-head revision id supplied by the caller.
        chosen: crate::revision::RevisionId,
        /// The actual head set at the time of the transaction.
        current_heads: Vec<crate::revision::RevisionId>,
    },

    /// **MVP-1 issue 1.6 — §18.7 schema-versioning policy.** A revision
    /// blob carries a `schema_version` (the `revisions.schema_version`
    /// row column, or the `payload_version` discriminator inside the V1
    /// CBOR body) newer than this build understands
    /// ([`crate::revision::REVISION_SCHEMA_VERSION_MAX`]).
    ///
    /// Distinct from [`Self::UnsupportedFormatVersion`] (which gates the
    /// *whole vault*): this is per-account / per-revision granularity —
    /// the affected account surfaces a "requires upgrade" status,
    /// metadata-only reads keep working where possible, but
    /// reveals/edits/head-decryption on that account are blocked; the
    /// rest of the vault is fully usable. Surfacing this rather than
    /// silently skipping the future-versioned revision is deliberate: a
    /// head with a future version *is* the account's current state, so
    /// "skip" would show stale data with no signal (a correctness bug).
    ///
    /// A bare on-disk byte-flip of the `revisions.schema_version` column
    /// collapses to [`Self::AuthenticationFailed`] first: that byte is
    /// bound into the AEAD AAD, and the `> MAX` reject runs *after* the
    /// AEAD open (audit L1, fix-pass 2) — a flipped byte yields an AAD
    /// this build never sealed under, so the open fails before the
    /// reject can fire. Only a *legitimately* future-versioned revision
    /// — one a newer Pangolin sealed with that byte in its AAD — opens
    /// successfully and reaches this check. (Same shape as the
    /// `payload_version`-inside-the-body case: a tampered body fails the
    /// open; a genuine future body authenticates and then trips the
    /// `payload_version` / map-arity check in `blob.rs`.)
    #[error(
        "revision schema version {found} is newer than this build supports ({supported}); \
         this account requires a newer Pangolin"
    )]
    UnsupportedRevisionSchemaVersion {
        /// The account whose revision is from the future.
        account_id: crate::account::AccountId,
        /// The future-versioned revision id.
        revision_id: crate::revision::RevisionId,
        /// The schema version found on disk.
        found: u32,
        /// The maximum this build supports.
        supported: u32,
    },

    /// Catch-all for storage-level integrity violations (e.g.,
    /// `PRAGMA integrity_check` returning anything other than "ok").
    #[error("storage corruption detected: {0}")]
    Corrupted(String),

    /// **P10-3 / A4.** Internal-state failure that is not a corruption
    /// of the on-disk store but a transient runtime condition the
    /// caller cannot meaningfully recover from. The current sole user
    /// is `Vault::add_account`'s anti-resurrection retry loop: after
    /// `ADD_ACCOUNT_RETRY_BUDGET` (4) consecutive collisions between
    /// the randomly-derived `account_id` and an existing tombstoned
    /// row, the loop surfaces this rather than spinning indefinitely
    /// or silently skipping. The probability of a 4-attempt collision
    /// is bounded at `4 * N / 2^256` where N is the tombstone count;
    /// for any plausible vault size the bound is negligible
    /// (vanishingly less than 1-in-2^200), so this variant only fires
    /// under a pathological RNG (e.g., a broken `SQLite randomblob`
    /// implementation). Distinct from `Corrupted` because the on-disk
    /// store is not necessarily damaged.
    #[error("internal failure: {reason}")]
    Internal {
        /// Human-readable cause string. Non-secret.
        reason: String,
    },

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

    /// **MVP-1 issue 1.4 — Session spec §7.7.** A presence prompt
    /// surfaced for a high-risk action expired before it was answered:
    /// the supplied presence proof's construction timestamp is already
    /// older than [`crate::session::PRESENCE_FRESHNESS`] / equivalently
    /// past [`crate::session::PROMPT_TIMEOUT`] by the time it reaches a
    /// reveal-class call site. Spec §8.2 mandates prompts never silently
    /// fail; this is the loud, typed failure. Distinct from
    /// `AuthenticationFailed` because a timed-out prompt is a UX signal
    /// ("re-run the command"), not a content-class authentication
    /// failure — it reveals nothing about any secret. The `PressYPresenceProof`
    /// (CLI tier) models the timeout as a proof whose `created_at` has
    /// aged past the freshness window.
    #[error("presence prompt timed out; re-run the action")]
    PromptTimedOut,

    /// **MVP-1 issue 1.2.** A draft / patch failed validation at the
    /// public-API boundary (e.g., empty display name, unparseable URL,
    /// over-long username list). The `kind` is a stable category
    /// label drawn from the `docs/issue-plans/1.2.md` §E table; the
    /// `message` is a UI-safe description.
    #[error("validation error ({kind}): {message}")]
    Validation {
        /// Stable category label.
        kind: String,
        /// UI-safe description.
        message: String,
    },

    /// **P8 fix CRIT-1.** A user-facing read or edit was attempted
    /// against an account whose `account_identities.frozen_pending_resolve`
    /// flag is set. The flag is set by [`crate::vault::Vault::ingest_chain_revision`]
    /// when a foreign-device chain event lands on an existing account
    /// (the ingest takes the "INSERT new row" path rather than any of
    /// the three idempotency-merge arms — see CRIT-1 in the P8 audit
    /// fix-pass plan). It signals "this account was modified on
    /// chain by another device under your handle's nose; you must run
    /// `pangolin-cli resolve` (P9) before reading or editing".
    ///
    /// Distinct from `AccountTombstoned` because tombstone is a
    /// terminal state visible to every consumer in the same way; the
    /// frozen state is per-vault and clears once resolve runs.
    /// Distinct from `AccountNotFound` because the row exists — it's
    /// just not safe to read until the user reconciles.
    #[error("account is frozen pending conflict resolution; run `pangolin-cli resolve` (P9)")]
    AccountFrozenPendingResolve {
        account_id: crate::account::AccountId,
    },

    /// **MVP-1 issue 1.11 / Browser-Ext spec §2.3 / Threat Model
    /// invariant #8.** A [`crate::Vault::capture_authority_register`]
    /// call was made for a `(context_kind, platform_hint)` key that
    /// already has a different registration AND `replace_existing` was
    /// `false`. Defence-in-depth against silent double-registration.
    ///
    /// The message names the *context kind only* — no info-leak on the
    /// existing `component_id` (a curious caller cannot probe the
    /// registry by exclusivity errors; the legitimate read path is
    /// [`crate::Vault::capture_authority_query`]).
    #[error(
        "capture authority for context {context} already registered; \
         pass replace_existing=true with a fresh presence proof to overwrite"
    )]
    CaptureAuthorityExclusivity {
        /// Stable lowercase context-kind label (`"desktop"`, `"browser"`,
        /// `"mobile_os"`) — no info-leak on the existing payload.
        context: String,
    },

    /// **MVP-1 issue 1.11.** A capture-authority payload failed
    /// validation (empty / overlong / non-NFC / control-char /
    /// not-on-the-allowlist for `platform_hint`; future
    /// `schema_version`). UI-safe message.
    #[error("capture authority validation failed: {reason}")]
    CaptureAuthorityValidation {
        /// UI-safe rejection reason.
        reason: String,
    },

    /// **MVP-2 issue 3.1.** A chain-side signing operation
    /// ([`crate::vault::Vault::sign_revision_v1`]) failed. The wrapped
    /// [`ChainError`] carries the underlying cause (deployment file
    /// missing / malformed, pinned-address mismatch, wallet error).
    /// Distinct from authentication-class failures because chain
    /// signing happens AFTER the session gate succeeds — so a failure
    /// here is structural (config / build / chain-state), not
    /// proof-class.
    #[error("chain signing error: {0}")]
    ChainSignError(ChainError),
}

impl StoreError {
    /// **MVP-1 issue 1.6.** If `self` is an
    /// [`Self::UnsupportedRevisionSchemaVersion`] whose ids are the
    /// blob-layer placeholder zeros, re-decorate it with the real
    /// `account_id` / `revision_id` known at the storage-row layer.
    /// Any other variant passes through unchanged.
    #[must_use]
    pub fn with_revision_context(
        self,
        account_id: crate::account::AccountId,
        revision_id: crate::revision::RevisionId,
    ) -> Self {
        match self {
            Self::UnsupportedRevisionSchemaVersion {
                found, supported, ..
            } => Self::UnsupportedRevisionSchemaVersion {
                account_id,
                revision_id,
                found,
                supported,
            },
            other => other,
        }
    }
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
