// SPDX-License-Identifier: AGPL-3.0-or-later
//! MVP-1 issue 1.2: FFI ↔ `pangolin_core` identity-shape bridge.
//!
//! Pure value-level conversion functions. No I/O; no panics on
//! correctly-shaped input. Validation errors surface as
//! [`FfiError::Validation`] with the same `kind` labels the
//! `pangolin_core::Error::Validation` arm uses.

use std::sync::Arc;

use pangolin_crypto::secret::SecretBytes;

use crate::error::FfiError;
use crate::identity::{
    AccountDraft, AccountId, AccountPatch, AccountSnapshot, DeviceId, PasswordHistoryEntry,
    TotpSecret,
};
use crate::revision::{RevisionId, RevisionMeta};
use crate::session::SecretPassword;

/// Wire-form length of an [`AccountId`]. Must be 32 bytes.
const ACCOUNT_ID_BYTES: usize = 32;

/// Convert an FFI [`AccountId`] to a `pangolin_core::AccountId`.
pub fn account_id_from_ffi(id: &AccountId) -> Result<pangolin_core::AccountId, FfiError> {
    let arr: [u8; ACCOUNT_ID_BYTES] =
        id.bytes
            .as_slice()
            .try_into()
            .map_err(|_| FfiError::Validation {
                kind: "argument".into(),
                message: format!(
                    "AccountId.bytes must be {ACCOUNT_ID_BYTES} bytes (got {})",
                    id.bytes.len()
                ),
            })?;
    Ok(pangolin_core::AccountId::from_bytes(arr))
}

/// Convert a `pangolin_core::AccountId` to its FFI shape.
pub fn account_id_to_ffi(id: pangolin_core::AccountId) -> AccountId {
    AccountId {
        schema_version: pangolin_core::ACCOUNT_IDENTITY_SCHEMA_VERSION,
        bytes: id.as_bytes().to_vec(),
    }
}

/// Convert a `pangolin_core::RevisionId` to its FFI shape.
pub fn revision_id_to_ffi(id: pangolin_core::RevisionId) -> RevisionId {
    RevisionId {
        schema_version: pangolin_core::ACCOUNT_IDENTITY_SCHEMA_VERSION,
        bytes: id.as_bytes().to_vec(),
    }
}

/// Convert a `pangolin_core::RevisionMeta` to its FFI shape.
pub fn revision_meta_to_ffi(meta: pangolin_core::RevisionMeta) -> RevisionMeta {
    let parent = if meta.parent_revision_id == pangolin_core::RevisionId::GENESIS_PARENT {
        None
    } else {
        Some(revision_id_to_ffi(meta.parent_revision_id))
    };
    RevisionMeta {
        schema_version: pangolin_core::ACCOUNT_IDENTITY_SCHEMA_VERSION,
        id: revision_id_to_ffi(meta.revision_id),
        created_at_unix: meta.created_at,
        parent_id: parent,
        device_id: meta.device_id.0.to_vec(),
    }
}

/// Convert a core `DeviceId` to its FFI shape.
fn device_id_to_ffi(id: pangolin_core::DeviceId) -> DeviceId {
    DeviceId {
        schema_version: pangolin_core::ACCOUNT_IDENTITY_SCHEMA_VERSION,
        bytes: id.0.to_vec(),
    }
}

/// Convert an FFI [`AccountDraft`] into a
/// `pangolin_core::AccountIdentityDraft`.
///
/// Consumes the FFI draft; the wrapped `Arc<SecretPassword>` and
/// `Arc<TotpSecret>` payloads are read at this boundary and dropped
/// (their `ZeroizeOnDrop` discipline applies at the underlying buffer).
/// Returns a `Result` so the FFI surface can grow validation-failure
/// arms in 1.6 (Q4) without breaking the caller.
#[allow(clippy::unnecessary_wraps)]
pub fn draft_into_store(
    draft: AccountDraft,
) -> Result<pangolin_core::AccountIdentityDraft, FfiError> {
    let password_bytes = secret_password_bytes(&draft.current_password);
    let totp_bytes = draft
        .totp_secret
        .as_ref()
        .map_or_else(Vec::new, totp_secret_bytes);
    Ok(pangolin_core::AccountIdentityDraft {
        schema_version: draft.schema_version,
        display_name: draft.display_name,
        tags: draft.tags,
        usernames: draft.usernames,
        urls: draft.urls,
        notes: draft.notes.unwrap_or_default(),
        password: SecretBytes::new(password_bytes),
        totp_secret: SecretBytes::new(totp_bytes),
    })
}

/// Convert an FFI [`AccountPatch`] into a
/// `pangolin_core::AccountIdentityPatch`.
#[allow(clippy::unnecessary_wraps)]
pub fn patch_into_store(
    patch: AccountPatch,
) -> Result<pangolin_core::AccountIdentityPatch, FfiError> {
    let new_password = patch.current_password.as_ref().map(|p| {
        let bytes = secret_password_bytes(p);
        SecretBytes::new(bytes)
    });
    let totp = patch.totp_secret.map(|outer| {
        outer.map(|secret| {
            let bytes = totp_secret_bytes(&secret);
            SecretBytes::new(bytes)
        })
    });
    Ok(pangolin_core::AccountIdentityPatch {
        schema_version: patch.schema_version,
        display_name: patch.display_name,
        tags: patch.tags,
        usernames: patch.usernames,
        urls: patch.urls,
        notes: patch.notes,
        password: new_password,
        totp_secret: totp,
    })
}

/// Convert a `pangolin_core::AccountIdentitySummary` into the FFI
/// [`AccountSnapshot`] shape.
#[allow(clippy::unnecessary_wraps)]
pub fn summary_to_ffi(
    summary: pangolin_core::AccountIdentitySummary,
) -> Result<AccountSnapshot, FfiError> {
    // The summary already contains UTF-8 strings + SecretBytes;
    // wrap secret-bearing fields in the FFI envelopes.
    let pangolin_core::AccountIdentitySummary {
        id,
        head_revision_id,
        display_name,
        tags,
        usernames,
        urls,
        notes,
        password_history,
        totp_secret,
        ..
    } = summary;

    let current_password = password_history.first().map_or_else(
        || SecretPassword::new(Vec::new()),
        |e| SecretPassword::new(e.password.expose().to_vec()),
    );

    let history_ffi: Vec<PasswordHistoryEntry> = password_history
        .into_iter()
        .map(|entry| {
            let bytes = entry.password.expose().to_vec();
            PasswordHistoryEntry {
                schema_version: pangolin_core::ACCOUNT_IDENTITY_SCHEMA_VERSION,
                password: SecretPassword::new(bytes),
                set_at: entry.set_at_ms / 1000,
                originating_device: device_id_to_ffi(entry.originating_device),
            }
        })
        .collect();

    let totp_arc = totp_secret.map(|sb| TotpSecret::new(sb.expose().to_vec()));

    Ok(AccountSnapshot {
        schema_version: pangolin_core::ACCOUNT_IDENTITY_SCHEMA_VERSION,
        id: account_id_to_ffi(id),
        display_name,
        tags,
        usernames,
        urls,
        notes,
        current_password,
        password_history: history_ffi,
        totp_secret: totp_arc,
        head_revision_id: revision_id_to_ffi(head_revision_id),
    })
}

/// Borrow the raw bytes of a [`SecretPassword`] across the FFI bridge
/// boundary. The returned `Vec<u8>` is a copy that the caller owns and
/// is responsible for dropping (which zero-on-drop wipes).
fn secret_password_bytes(p: &Arc<SecretPassword>) -> Vec<u8> {
    p.bytes_for_bridge().to_vec()
}

fn totp_secret_bytes(s: &Arc<TotpSecret>) -> Vec<u8> {
    s.bytes_for_bridge().to_vec()
}
