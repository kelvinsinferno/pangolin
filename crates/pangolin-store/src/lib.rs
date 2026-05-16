//! Encrypted local store for Pangolin.
//!
//! `SQLite` + encrypted blobs. Corruption-safe writes (WAL +
//! transactional schema). Per cardinal principle 2: no plaintext at
//! rest. The full design is documented in `docs/issue-plans/P2.md`.
//!
//! ## Public surface
//!
//! `Vault` is the only credential-bearing public type — every other
//! module is plumbing for it. Snapshots ([`account::AccountSnapshot`])
//! and identifiers ([`account::AccountId`], [`revision::RevisionId`]) are
//! the value types you'll feed in and read back.
//!
//! ```no_run
//! use std::path::Path;
//! use pangolin_crypto::secret::SecretBytes;
//! use pangolin_store::{
//!     Vault, AccountSnapshot, PinIdentityProof, PressYPresenceProof,
//! };
//!
//! let pwd = SecretBytes::new(b"correct horse battery staple".to_vec());
//! Vault::create(Path::new("./vault.pvf"), &pwd)?;
//! let mut v = Vault::open(Path::new("./vault.pvf"))?;
//! // P4 session policy: 2 proofs at unlock (presence + identity).
//! let presence = PressYPresenceProof::confirmed();
//! let identity = PinIdentityProof::new(
//!     SecretBytes::new(b"correct horse battery staple".to_vec()),
//! );
//! v.unlock(&presence, &identity)?;
//! // … add_account / search / update_account / lock / close …
//! # Ok::<(), pangolin_store::StoreError>(())
//! ```

#![cfg_attr(not(test), forbid(unsafe_code))]
#![cfg_attr(test, deny(unsafe_code))]

pub mod account;
pub mod capture_authority;
pub mod conflict;
pub mod device;
pub mod dirty;
pub mod error;
pub mod export;
pub mod pending;
pub mod revision;
pub mod session;
pub mod vault;

pub(crate) mod blob;
pub(crate) mod meta;
pub(crate) mod schema;
pub(crate) mod search;

pub use account::{
    AccountId, AccountIdentity, AccountIdentityDraft, AccountIdentityPatch, AccountIdentitySummary,
    AccountSnapshot, PasswordEntry, PasswordHistorySummaryEntry, TotpAlgorithm, TotpParams,
    ACCOUNT_IDENTITY_SCHEMA_VERSION, PAYLOAD_VERSION_V0, PAYLOAD_VERSION_V1, PAYLOAD_VERSION_V2,
};
pub use blob::TombstonePayload;
pub use capture_authority::{
    CaptureAuthority, CaptureAuthorityEntry, CaptureAuthorityKind, CaptureContext,
    CaptureContextKind, CapturedCaptureAuthority, RegistrationOutcome,
    CAPTURE_AUTHORITY_SCHEMA_VERSION_MAX,
};
pub use conflict::ConflictReport;
pub use device::{
    DeviceCapabilities, DeviceIdentity, DEVICE_IDENTITY_SCHEMA_VERSION, EVM_ADDRESS_LEN,
};
pub use dirty::{DirtyEntry, IngestOutcome, RevisionPublishPayload};
pub use error::{Result, StoreError};
pub use export::{
    decode_archive, decode_snapshot, encode_snapshot, render_plaintext, AccountSelection,
    ArchiveHeader, ArchiveSnapshot, ArchivedAccount, ArchivedDevice, ArchivedPasswordEntry,
    PlaintextExportConfirmationData, ARCHIVE_FORMAT_VERSION, ARCHIVE_MAGIC,
    ARCHIVE_SNAPSHOT_SCHEMA_VERSION, PLAINTEXT_EXPORT_BANNER,
};
// MVP-2 issue 3.1 (R-b convenience re-export): downstream callers
// (apps/cli, the eventual sync transport in 3.3) get the v1 signing
// types from `pangolin-store` directly so they don't have to dep on
// `pangolin-chain` just to name the input/output types. The
// `pangolin-store -> pangolin-chain` dep direction (L8) is preserved.
pub use pangolin_chain::{ChainEnv, RevisionFieldsV1, SignedRevisionV1};
pub use pending::{PendingMerge, PENDING_MERGE_NONCE_LEN, PENDING_MERGE_SECRET_LEN};
pub use revision::{
    ChainAnchor, DeviceId, RevisionGraph, RevisionId, RevisionMeta, REVISION_SCHEMA_VERSION_MAX,
};
pub use search::{ACCOUNT_SEARCH_RESULT_CAP, FTS_SCHEMA_VERSION};
pub use session::{
    AuthError, Clock, IdentityProof, PinIdentityProof, PresenceProof, PressYPresenceProof,
    SessionDuration, SessionState, SystemClock, ABSOLUTE_MAX_DEFAULT, IDLE_TIMEOUT_DEFAULT,
    PRESENCE_FRESHNESS, PROMPT_TIMEOUT, SESSION_IDLE_UNTIL_DEVICE_LOCK,
};
pub use vault::{AccountStatus, SyncMode, SyncModePreference, Vault, VaultState};

/// Returns the crate name. Useful for diagnostics and version reporting.
#[must_use]
pub fn name() -> &'static str {
    "pangolin-store"
}

#[cfg(test)]
mod tests {
    use super::name;

    #[test]
    fn crate_name_is_set() {
        assert_eq!(name(), "pangolin-store");
    }
}
