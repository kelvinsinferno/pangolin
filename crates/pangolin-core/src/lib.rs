//! Pangolin core vault engine.
//!
//! This crate is the single source of truth for security-critical logic:
//! account identity, encryption + key management, immutable revision model,
//! conflict detection, sync orchestration, session policy, and social
//! recovery client logic.
//!
//! Per master plan §0 cardinal principle 1: clients are thin shells that
//! ask this crate for decisions. They never reimplement security logic.
//!
//! ## MVP-1 issue 1.1 layout
//!
//! Per Q2 (deferred to issue 1.4), the Vault / session / account /
//! revision types still **physically** live in `pangolin-store`; this
//! crate re-exports them so the FFI surface (`pangolin-ffi`) can name
//! them under `pangolin_core::*`. Issue 1.4's session rewrite is the
//! commit that physically relocates the types; the FFI namespace
//! freezes today either way.
//!
//! Per master plan §16.8 (amended for MVP-1 issue 1.1), the per-domain
//! submodules below are scaffolded in this issue. Bodies arrive in:
//!
//! | Submodule  | Issue | What lands |
//! |------------|-------|------------|
//! | `identity` | 1.2   | `AccountIdentity` model + draft / patch builders |
//! | `session`  | 1.4   | Session state machine (rewrite of P4 / `pangolin-store`) |
//! | `revision` | 1.6   | Production revision lineage (was P3 / pangolin-store) |
//! | `sync`     | 1.6/2.x | Production sync orchestration |
//! | `recovery` | 3.x   | Social-recovery client logic (MVP-3) |
//!
//! TOTP and KDBX and the FFI surface have been moved out of
//! `pangolin-core` into sibling crates per Q3/Q4 of issue 1.1:
//! `pangolin-totp`, `pangolin-kdbx`, `pangolin-ffi`.

#![cfg_attr(not(test), forbid(unsafe_code))]

pub mod composition;
pub mod device;
pub mod device_add;
pub mod error;
/// **MVP-4-L L-0b (gap G-2).** The guardian-invite TRANSPORT codec — the
/// shareable payload a guardian's device exports so a vault owner can collect
/// the guardian's X25519 sealing pubkey + EVM address for onboarding. Mirrors
/// `pairing_transport`'s zero-serde / fixed-layout / version-gated discipline
/// and re-uses its public text codec. The FFI surface in
/// `pangolin-ffi::guardian_identity` is a thin wrapper.
pub mod guardian_invite;
pub mod identity;
/// **MVP-3 issue #106e-2.** The pairing-payload TRANSPORT codec (the byte
/// form the host renders as a QR + the copy-pasteable text form). Zero
/// serde, fixed-layout, length-strict, version-gated; the FFI surface in
/// `pangolin-ffi::pairing` is a thin wrapper.
pub mod pairing_transport;
pub mod pwgen;
pub mod recovery;
pub mod revision;
pub mod rotation;
pub mod session;
pub mod sync;

pub use error::Error;

// Re-exports from `pangolin-store` so the FFI surface can name these
// types under `pangolin_core::*`. Q2 (issue 1.1 plan-gate) defers the
// physical relocation to 1.4; the namespace freezes today.
pub use pangolin_store::{
    compute_next_status, decode_archive, AccountId, AccountIdentity, AccountIdentityDraft,
    AccountIdentityPatch, AccountIdentitySummary, AccountSelection, AccountSnapshot, AccountStatus,
    ArchiveSnapshot, AuthError, BatchFlushErrorKind, CaptureAuthority, CaptureAuthorityEntry,
    CaptureAuthorityKind, CaptureContext, CaptureContextKind, Clock, ConflictBranchSummary,
    ConflictDelta, ConflictReport, ConflictSnapshot, DeviceCapabilities, DeviceId, DeviceIdentity,
    IdentityProof, LastFlushOutcome, LastPullOutcome, PasswordEntry, PasswordHistorySummaryEntry,
    PendingMerge, PinIdentityProof, PlaintextExportConfirmationData, PresenceProof,
    PressYPresenceProof, PullErrorKind, RecoveryEscrowParams, RegistrationOutcome, RevisionGraph,
    RevisionId, RevisionMeta, SessionDuration, SessionState, SyncStatus, SyncStatusInputs,
    SystemClock, TotpAlgorithm, TotpParams, Vault, VaultState, ABSOLUTE_MAX_DEFAULT,
    ACCOUNT_IDENTITY_SCHEMA_VERSION, ARCHIVE_FORMAT_VERSION, ARCHIVE_SNAPSHOT_SCHEMA_VERSION,
    CAPTURE_AUTHORITY_SCHEMA_VERSION_MAX, DEVICE_IDENTITY_SCHEMA_VERSION, EVM_ADDRESS_LEN,
    IDLE_TIMEOUT_DEFAULT, OFFLINE_THRESHOLD_FAILURES, PAYLOAD_VERSION_V0, PAYLOAD_VERSION_V1,
    PAYLOAD_VERSION_V2, PLAINTEXT_EXPORT_BANNER, PRESENCE_FRESHNESS, PROMPT_TIMEOUT,
    REVISION_SCHEMA_VERSION_MAX, SESSION_IDLE_UNTIL_DEVICE_LOCK, SYNCED_STALENESS_THRESHOLD_MS,
};

/// Returns the crate name. Useful for diagnostics and version reporting.
#[must_use]
pub fn name() -> &'static str {
    "pangolin-core"
}

#[cfg(test)]
mod tests {
    use super::name;

    #[test]
    fn crate_name_is_set() {
        assert_eq!(name(), "pangolin-core");
    }

    /// MVP-1 issue 1.4 (Q1 = no physical move): the session engine is
    /// reachable through the canonical `pangolin_core::session::*`
    /// import path. This smoke test pins that the re-export modules
    /// resolve so the §16.8 namespace intent is satisfied without the
    /// physical relocation. It also touches the new 1.4 surface
    /// (`SessionDuration`, `PROMPT_TIMEOUT`) via that path.
    #[test]
    fn session_module_resolves() {
        use crate::session::{SessionDuration, SessionState, PROMPT_TIMEOUT};
        assert_eq!(SessionDuration::DEFAULT, SessionDuration::Min15);
        assert!(!SessionState::Locked.is_active());
        assert_eq!(PROMPT_TIMEOUT, core::time::Duration::from_secs(60));
        // Also reachable at the crate root.
        let _ = crate::SessionDuration::Hour4;
        // identity module re-exports resolve too.
        let _ = crate::identity::ACCOUNT_IDENTITY_SCHEMA_VERSION;
    }
}
