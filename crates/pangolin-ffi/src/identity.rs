// SPDX-License-Identifier: AGPL-3.0-or-later
//! Account-identity FFI shapes (MVP-1 issue 1.2).
//!
//! Bodies for `account_add` / `account_update` / `account_get` /
//! `account_search` / `account_history` land here in 1.2 alongside the
//! widened-shape amendment Q1 of `docs/issue-plans/1.2.md` authorises:
//! `AccountDraft` / `AccountPatch` / `AccountSnapshot` carry the
//! production multi-username, multi-URL, tags, password-history, TOTP
//! shape that Whitepaper §6 mandates.

use std::sync::Arc;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::FfiError;
use crate::revision::{RevisionId, RevisionMeta};
use crate::session::{SecretPassword, UnixTimestamp, VaultHandle};

/// Account identifier. 32-byte type stable across the wire as a
/// `Vec<u8>`. `UniFFI` emits this as `Data` on Swift / `ByteArray` on
/// Kotlin / `Vec<u8>` on the C ABI.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AccountId {
    /// Schema-version slot. 1.2 sets this to `1`; 1.6 locks the policy.
    pub schema_version: u16,
    /// 32 bytes of account-id hash.
    pub bytes: Vec<u8>,
}

/// Stable opaque device identifier. 32 bytes. Carried on
/// `PasswordHistoryEntry` to record which device authored each
/// historical password.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct DeviceId {
    /// Schema-version slot.
    pub schema_version: u16,
    /// 32 bytes of device id.
    pub bytes: Vec<u8>,
}

/// Opaque TOTP secret bytes. Crosses FFI as a value record carrying the
/// raw shared-secret byte slice; the actual RFC-6238 generator lands in
/// 1.7. Bytes zero on drop.
#[derive(uniffi::Object)]
pub struct TotpSecret {
    bytes: zeroizing_vec::SecretBuf,
}

impl std::fmt::Debug for TotpSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TotpSecret")
            .field("len", &self.bytes.as_slice().len())
            .field("bytes", &"<redacted>")
            .finish()
    }
}

impl TotpSecret {
    /// Construct a `TotpSecret` from raw bytes.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Arc<Self> {
        Arc::new(Self {
            bytes: zeroizing_vec::SecretBuf::new(bytes),
        })
    }

    /// Borrow the raw bytes. Crate-private — external readers route
    /// through presence-gated reveal entry points (1.4).
    #[allow(dead_code)]
    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    /// Crate-private bridge accessor for the identity FFI bodies.
    pub(crate) fn bytes_for_bridge(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    /// Returns the byte length of the secret. Length-only is non-secret.
    #[must_use]
    pub fn len(&self) -> u32 {
        u32::try_from(self.bytes.as_slice().len()).unwrap_or(u32::MAX)
    }

    /// Whether the secret is empty (i.e., no TOTP configured).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.as_slice().is_empty()
    }
}

#[uniffi::export]
impl TotpSecret {
    #[uniffi::method(name = "byte_length")]
    pub fn byte_length(&self) -> u32 {
        self.len()
    }
}

mod zeroizing_vec {
    use super::{Zeroize, ZeroizeOnDrop};

    pub struct SecretBuf {
        inner: Vec<u8>,
    }

    impl SecretBuf {
        pub fn new(bytes: Vec<u8>) -> Self {
            Self { inner: bytes }
        }

        pub fn as_slice(&self) -> &[u8] {
            &self.inner
        }
    }

    impl Drop for SecretBuf {
        fn drop(&mut self) {
            self.inner.zeroize();
        }
    }

    impl Zeroize for SecretBuf {
        fn zeroize(&mut self) {
            self.inner.zeroize();
        }
    }

    impl ZeroizeOnDrop for SecretBuf {}
}

/// One historical password entry.
///
/// The HEAD entry of a snapshot's `password_history` is the current
/// password; older entries are previous values, retained for forensics
/// + the "I just rotated; let me copy the old one" flow.
#[derive(Debug, uniffi::Record)]
pub struct PasswordHistoryEntry {
    /// Schema-version slot.
    pub schema_version: u16,
    /// The password bytes for this entry. Crosses as `Arc<SecretPassword>`
    /// so foreign-language sides see a reference type and cannot copy
    /// the bytes onto the GC heap.
    pub password: Arc<SecretPassword>,
    /// Wall-clock unix-second timestamp at which this password was set.
    pub set_at: UnixTimestamp,
    /// 32-byte authoring device id.
    pub originating_device: DeviceId,
}

impl Clone for PasswordHistoryEntry {
    fn clone(&self) -> Self {
        Self {
            schema_version: self.schema_version,
            password: Arc::clone(&self.password),
            set_at: self.set_at,
            originating_device: self.originating_device.clone(),
        }
    }
}

/// Draft of a new account at create-time.
///
/// Widened in 1.2 per Q1 of `docs/issue-plans/1.2.md`. The 1.1
/// scaffolding shape (single `username`/`url`/`password`) is replaced
/// by the production shape: multi-username, multi-URL, tags, optional
/// notes + TOTP, and an initial password.
#[derive(Debug, uniffi::Record)]
pub struct AccountDraft {
    /// Schema-version slot. 1.2 expects `1`.
    pub schema_version: u16,
    /// User-visible display name (e.g., "GitHub – Main"). Non-empty,
    /// trimmed, ≤ 256 chars after NFC normalisation.
    pub display_name: String,
    /// Tags (e.g., `["work", "shared"]`). Each ≤ 64 chars; ≤ 32
    /// entries; trimmed + lowercased + deduplicated by the validator.
    pub tags: Vec<String>,
    /// Usernames / emails. ≥ 1 entry; ≤ 16 entries; each ≤ 320 chars.
    pub usernames: Vec<String>,
    /// Associated URLs. Each must parse via the `url` crate; any
    /// scheme (Q3 of 1.2). ≤ 32 entries.
    pub urls: Vec<String>,
    /// Free-form notes. ≤ 65 536 chars. `None` means no notes.
    pub notes: Option<String>,
    /// Initial password. Crosses FFI as `Arc<SecretPassword>`; bytes
    /// zero on drop after the call returns.
    pub current_password: Arc<SecretPassword>,
    /// Optional TOTP secret slot. `None` means no TOTP configured. The
    /// 1.7 RFC-6238 generator consumes these bytes; 1.2 only stores
    /// + reveals.
    pub totp_secret: Option<Arc<TotpSecret>>,
}

impl Clone for AccountDraft {
    fn clone(&self) -> Self {
        Self {
            schema_version: self.schema_version,
            display_name: self.display_name.clone(),
            tags: self.tags.clone(),
            usernames: self.usernames.clone(),
            urls: self.urls.clone(),
            notes: self.notes.clone(),
            current_password: Arc::clone(&self.current_password),
            totp_secret: self.totp_secret.as_ref().map(Arc::clone),
        }
    }
}

/// Patch applied via `account_update`.
///
/// Each scalar field is `Option` (`None` = leave unchanged). For
/// collection fields (`tags`, `usernames`, `urls`), `Some(vec)`
/// replaces the whole collection. For `notes` the outer `Option` is
/// "set or leave unchanged"; setting to an empty string clears the
/// notes.
///
/// `current_password`-bump path: setting `current_password = Some(_)`
/// triggers a password-history append — the previous head password is
/// moved into history with the operation's timestamp + this device's
/// id.
///
/// `totp_secret` uses a doubled `Option` (`Option<Option<...>>`):
/// outer `None` = leave unchanged; outer `Some(None)` = clear the slot;
/// outer `Some(Some(secret))` = set/replace.
#[derive(Debug, uniffi::Record)]
pub struct AccountPatch {
    /// Schema-version slot.
    pub schema_version: u16,
    /// New display name, or `None` to leave unchanged.
    pub display_name: Option<String>,
    /// New tag set, or `None` to leave unchanged. Empty `Some(vec![])`
    /// clears all tags.
    pub tags: Option<Vec<String>>,
    /// New username set, or `None` to leave unchanged. Must be non-
    /// empty when supplied.
    pub usernames: Option<Vec<String>>,
    /// New URL set, or `None` to leave unchanged. `Some(vec![])`
    /// clears all URLs.
    pub urls: Option<Vec<String>>,
    /// New notes, or `None` to leave unchanged. `Some("")` clears.
    pub notes: Option<String>,
    /// New password, or `None` to leave unchanged. `Some(_)` triggers a
    /// password-history append — the previous head moves into history.
    pub current_password: Option<Arc<SecretPassword>>,
    /// TOTP slot operation: `None` = leave unchanged; `Some(None)` =
    /// clear; `Some(Some(secret))` = set/replace.
    pub totp_secret: Option<Option<Arc<TotpSecret>>>,
}

impl Clone for AccountPatch {
    fn clone(&self) -> Self {
        Self {
            schema_version: self.schema_version,
            display_name: self.display_name.clone(),
            tags: self.tags.clone(),
            usernames: self.usernames.clone(),
            urls: self.urls.clone(),
            notes: self.notes.clone(),
            current_password: self.current_password.as_ref().map(Arc::clone),
            totp_secret: self
                .totp_secret
                .as_ref()
                .map(|inner| inner.as_ref().map(Arc::clone)),
        }
    }
}

/// Read-only account snapshot returned from `account_get` / search.
///
/// Widened in 1.2: carries multi-* fields and a non-empty
/// `password_history`. Per the presence-escalation discipline (spec
/// §5.4), the `password` bytes never appear directly — callers must
/// route through presence-gated `reveal_*` entry points (landing in
/// 1.4) for plaintext password access. The `password_history` field
/// here records timestamps + originating-device ids only; the actual
/// password bytes are wrapped as `Arc<SecretPassword>` so binding-side
/// shells can pass them back into a presence-gated reveal flow without
/// the bytes ever appearing as a plain `Vec<u8>` on the wire.
///
/// **Notes are not exposed.** Per spec §5.4, free-form notes can carry
/// recovery-class secrets (security-question answers, recovery
/// phrases) and therefore fall under the same reveal-class umbrella as
/// the password bytes. The `notes` field is deliberately absent here;
/// the presence-gated `reveal_notes` entry point lands in MVP-1
/// issue 1.4 (audit C-1 / plan §D).
#[derive(Debug, uniffi::Record)]
pub struct AccountSnapshot {
    /// Schema-version slot. 1.2 returns `1`.
    pub schema_version: u16,
    /// The account's id.
    pub id: AccountId,
    /// User-visible display name.
    pub display_name: String,
    /// Tags.
    pub tags: Vec<String>,
    /// Usernames / emails.
    pub usernames: Vec<String>,
    /// Associated URLs.
    pub urls: Vec<String>,
    /// Current password (head of `password_history`). Wrapped as
    /// `Arc<SecretPassword>`; bytes zero on drop. Set on every
    /// snapshot — even when the caller is not in a presence-gated
    /// reveal context, the *handle* travels so it can be passed into
    /// 1.4's reveal flow.
    pub current_password: Arc<SecretPassword>,
    /// Full password history (newest first). Each entry carries its
    /// own `Arc<SecretPassword>` + timestamp + originating device.
    pub password_history: Vec<PasswordHistoryEntry>,
    /// Optional TOTP secret slot.
    pub totp_secret: Option<Arc<TotpSecret>>,
    /// Most recent revision id for this account.
    pub head_revision_id: RevisionId,
}

impl Clone for AccountSnapshot {
    fn clone(&self) -> Self {
        Self {
            schema_version: self.schema_version,
            id: self.id.clone(),
            display_name: self.display_name.clone(),
            tags: self.tags.clone(),
            usernames: self.usernames.clone(),
            urls: self.urls.clone(),
            current_password: Arc::clone(&self.current_password),
            password_history: self.password_history.clone(),
            totp_secret: self.totp_secret.as_ref().map(Arc::clone),
            head_revision_id: self.head_revision_id.clone(),
        }
    }
}

// -- Locked-in-1.1 entry points ---------------------------------------

/// Add a new account from a draft. The vault must be unlocked.
#[allow(clippy::significant_drop_tightening)]
#[uniffi::export]
pub fn account_add(handle: Arc<VaultHandle>, draft: AccountDraft) -> Result<AccountId, FfiError> {
    let mut guard = handle.lock_vault();
    let vault = guard.as_mut()?;
    let store_draft = crate::identity_bridge::draft_into_store(draft)?;
    let id = vault.account_add(store_draft).map_err(store_into_ffi)?;
    Ok(crate::identity_bridge::account_id_to_ffi(id))
}

/// Apply a patch to an existing account.
#[allow(clippy::significant_drop_tightening)]
#[uniffi::export]
pub fn account_update(
    handle: Arc<VaultHandle>,
    id: AccountId,
    patch: AccountPatch,
) -> Result<RevisionId, FfiError> {
    let mut guard = handle.lock_vault();
    let vault = guard.as_mut()?;
    let store_id = crate::identity_bridge::account_id_from_ffi(&id)?;
    let store_patch = crate::identity_bridge::patch_into_store(patch)?;
    let rev = vault
        .account_update(store_id, store_patch)
        .map_err(store_into_ffi)?;
    Ok(crate::identity_bridge::revision_id_to_ffi(rev))
}

/// Search the account directory by display name / tags / urls
/// (substring, case-insensitive).
#[allow(clippy::significant_drop_tightening)]
#[uniffi::export]
pub fn account_search(
    handle: Arc<VaultHandle>,
    query: String,
) -> Result<Vec<AccountSnapshot>, FfiError> {
    let mut guard = handle.lock_vault();
    let vault = guard.as_mut()?;
    let summaries = vault.account_search(&query).map_err(store_into_ffi)?;
    summaries
        .into_iter()
        .map(crate::identity_bridge::summary_to_ffi)
        .collect::<Result<Vec<_>, _>>()
}

/// Fetch a single account snapshot by id.
#[allow(clippy::significant_drop_tightening)]
#[uniffi::export]
pub fn account_get(handle: Arc<VaultHandle>, id: AccountId) -> Result<AccountSnapshot, FfiError> {
    let mut guard = handle.lock_vault();
    let vault = guard.as_mut()?;
    let store_id = crate::identity_bridge::account_id_from_ffi(&id)?;
    let summary = vault.account_get(store_id).map_err(store_into_ffi)?;
    crate::identity_bridge::summary_to_ffi(summary)
}

/// Read the revision history for an account.
#[allow(clippy::significant_drop_tightening)]
#[uniffi::export]
pub fn account_history(
    handle: Arc<VaultHandle>,
    id: AccountId,
) -> Result<Vec<RevisionMeta>, FfiError> {
    let mut guard = handle.lock_vault();
    let vault = guard.as_mut()?;
    let store_id = crate::identity_bridge::account_id_from_ffi(&id)?;
    let metas = vault.account_history(store_id).map_err(store_into_ffi)?;
    Ok(metas
        .into_iter()
        .map(crate::identity_bridge::revision_meta_to_ffi)
        .collect())
}

fn store_into_ffi(err: pangolin_store::StoreError) -> FfiError {
    FfiError::from(pangolin_core::Error::from(err))
}
