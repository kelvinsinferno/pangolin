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

pub mod error;
pub mod identity;
pub mod recovery;
pub mod revision;
pub mod session;
pub mod sync;

pub use error::Error;

// Re-exports from `pangolin-store` so the FFI surface can name these
// types under `pangolin_core::*`. Q2 (issue 1.1 plan-gate) defers the
// physical relocation to 1.4; the namespace freezes today.
pub use pangolin_store::{
    AccountId, AccountIdentity, AccountIdentityDraft, AccountIdentityPatch, AccountIdentitySummary,
    AccountSnapshot, Clock, ConflictReport, DeviceId, IdentityProof, PasswordEntry,
    PasswordHistorySummaryEntry, PendingMerge, PinIdentityProof, PresenceProof,
    PressYPresenceProof, RevisionGraph, RevisionId, RevisionMeta, SessionState, SystemClock, Vault,
    VaultState, ACCOUNT_IDENTITY_SCHEMA_VERSION, PAYLOAD_VERSION_V0, PAYLOAD_VERSION_V1,
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
}
