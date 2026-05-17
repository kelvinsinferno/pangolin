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
pub mod publish;
pub mod pull;
pub mod revision;
pub mod session;
pub mod sync_status;
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
pub use conflict::{ConflictBranchSummary, ConflictDelta, ConflictReport, ConflictSnapshot};
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
// MVP-2 issue 5.1: publish-queue orchestration. `publish_all_for_vault`
// + `publish_one` were moved out of `apps/cli/src/sync.rs` so the CLI's
// thin-shell `publish_all` AND 5.1's batched `Vault::flush_publish_queue`
// share one engine. The batch-flush types live alongside.
pub use publish::{
    publish_all_for_vault, publish_one, BatchFlushError, BatchFlushReport, PublishOutcome,
    PublishOutcomeRow, PublishQueueState, PublishReport,
};
// MVP-2 issue 5.2: pull-loop primitive types. `Vault::pull_once` is
// defined alongside `flush_publish_queue` in `vault.rs`; the report /
// error types + cadence constants live in `pull.rs`.
pub use pull::{
    PullError, PullReport, PULL_INTERVAL_SECS_DEFAULT, PULL_INTERVAL_SECS_ENV_VAR,
    PULL_INTERVAL_SECS_MAX, PULL_INTERVAL_SECS_MIN,
};
pub use revision::{
    ChainAnchor, DeviceId, RevisionGraph, RevisionId, RevisionMeta, REVISION_SCHEMA_VERSION_MAX,
};
pub use search::{ACCOUNT_SEARCH_RESULT_CAP, FTS_SCHEMA_VERSION};
pub use session::{
    AuthError, Clock, IdentityProof, PinIdentityProof, PresenceProof, PressYPresenceProof,
    SessionDuration, SessionState, SystemClock, ABSOLUTE_MAX_DEFAULT, IDLE_TIMEOUT_DEFAULT,
    PRESENCE_FRESHNESS, PROMPT_TIMEOUT, SESSION_IDLE_UNTIL_DEVICE_LOCK,
};
// MVP-2 issue 5.4: sync orchestrator state machine. `SyncStatus` enum +
// pure `compute_next_status` transition function + type-erased outcome
// shapes for the host's loop. The bundling accessor lives on `Vault`
// (`Vault::sync_status_inputs`); the pre-lock drain method
// (`Vault::lock_with_drain`) closes the 5.1 L1 deviation. Per R-a the
// engine ships ZERO new tokio surface; the host owns the loop.
pub use sync_status::{
    compute_next_status, BatchFlushErrorKind, LastFlushOutcome, LastPullOutcome, PullErrorKind,
    SyncStatus, SyncStatusInputs, OFFLINE_THRESHOLD_FAILURES, SYNCED_STALENESS_THRESHOLD_MS,
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
