//! Account-identity FFI shapes (MVP-1 issue 1.2).
//!
//! Scaffolding-only at issue 1.1: signatures lock the FFI consumer's
//! expected slots; bodies arrive in 1.2.

use std::sync::Arc;

use crate::error::FfiError;
use crate::revision::{RevisionId, RevisionMeta};
use crate::session::VaultHandle;

/// Account identifier. 32-byte type stable across the wire as a
/// `Vec<u8>`. `UniFFI` emits this as `Data` on Swift / `ByteArray` on
/// Kotlin / `Vec<u8>` on the C ABI.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AccountId {
    /// Issue 1.1 schema-version slot. The 32 bytes themselves don't
    /// carry a version (they're a hash output) but the wrapper does in
    /// case the wire format gains framing in 1.6.
    pub schema_version: u16,
    /// 32 bytes of account-id hash.
    pub bytes: Vec<u8>,
}

/// Draft of a new account at create-time. Body lands in 1.2.
#[derive(Debug, Clone, uniffi::Record)]
pub struct AccountDraft {
    /// Issue 1.1 schema-version slot.
    pub schema_version: u16,
    /// User-visible display name (e.g., "GitHub"). Non-secret.
    pub display_name: String,
    /// Username for the account. Treated as non-secret for indexing
    /// purposes; never logged with the password.
    pub username: String,
    /// Login URL or canonical site identifier. Optional.
    pub url: Option<String>,
    /// Free-form notes. Plaintext at the FFI surface but encrypted at
    /// rest by `pangolin-store`.
    pub notes: Option<String>,
    /// Initial password bytes. Crosses FFI as a `Vec<u8>` so it can be
    /// arbitrary bytes; UI shells should zero the buffer after the
    /// call returns.
    pub password: Vec<u8>,
}

/// Patch applied via `account_update`. Each field is `Option`; `None`
/// means "leave unchanged". Body lands in 1.2.
#[derive(Debug, Clone, uniffi::Record)]
pub struct AccountPatch {
    /// Issue 1.1 schema-version slot.
    pub schema_version: u16,
    /// New display name, or `None` to leave unchanged.
    pub display_name: Option<String>,
    /// New username, or `None` to leave unchanged.
    pub username: Option<String>,
    /// New URL, or `None` to leave unchanged.
    pub url: Option<String>,
    /// New notes, or `None` to leave unchanged.
    pub notes: Option<String>,
    /// New password bytes, or `None` to leave unchanged.
    pub password: Option<Vec<u8>>,
}

/// Read-only account snapshot returned from `account_get` / search / list.
///
/// Sensitive fields (the password) require a fresh presence proof per
/// Session spec §5.3 — the search / list paths return snapshots WITHOUT
/// the password.
#[derive(Debug, Clone, uniffi::Record)]
pub struct AccountSnapshot {
    /// Issue 1.1 schema-version slot.
    pub schema_version: u16,
    /// The account's id.
    pub id: AccountId,
    /// User-visible display name.
    pub display_name: String,
    /// Username.
    pub username: String,
    /// URL.
    pub url: Option<String>,
    /// Notes.
    pub notes: Option<String>,
    /// Most recent revision id for this account.
    pub head_revision_id: RevisionId,
}

// -- Locked-in-1.1 entry points ---------------------------------------

/// Add a new account from a draft. Body lands in 1.2.
///
/// # Panics
/// Panics with `todo!()` until 1.2 lands.
#[uniffi::export]
pub fn account_add(handle: Arc<VaultHandle>, draft: AccountDraft) -> Result<AccountId, FfiError> {
    let _ = (handle, draft);
    todo!("account_add body lands in MVP-1 issue 1.2")
}

/// Apply a patch to an existing account. Body lands in 1.2.
///
/// # Panics
/// Panics with `todo!()` until 1.2 lands.
#[uniffi::export]
pub fn account_update(
    handle: Arc<VaultHandle>,
    id: AccountId,
    patch: AccountPatch,
) -> Result<RevisionId, FfiError> {
    let _ = (handle, id, patch);
    todo!("account_update body lands in MVP-1 issue 1.2")
}

/// Search the account directory. Body lands in 1.2.
///
/// # Panics
/// Panics with `todo!()` until 1.2 lands.
#[uniffi::export]
pub fn account_search(
    handle: Arc<VaultHandle>,
    query: String,
) -> Result<Vec<AccountSnapshot>, FfiError> {
    let _ = (handle, query);
    todo!("account_search body lands in MVP-1 issue 1.2")
}

/// Fetch a single account by id. Body lands in 1.2.
///
/// # Panics
/// Panics with `todo!()` until 1.2 lands.
#[uniffi::export]
pub fn account_get(handle: Arc<VaultHandle>, id: AccountId) -> Result<AccountSnapshot, FfiError> {
    let _ = (handle, id);
    todo!("account_get body lands in MVP-1 issue 1.2")
}

/// Read the revision history for an account. Body lands in 1.2 / 1.6.
///
/// # Panics
/// Panics with `todo!()` until 1.2 lands.
#[uniffi::export]
pub fn account_history(
    handle: Arc<VaultHandle>,
    id: AccountId,
) -> Result<Vec<RevisionMeta>, FfiError> {
    let _ = (handle, id);
    todo!("account_history body lands in MVP-1 issue 1.2")
}
