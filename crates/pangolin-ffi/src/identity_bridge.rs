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

/// Wire-form length of a [`RevisionId`]. Must be 32 bytes.
const REVISION_ID_BYTES: usize = 32;

/// Convert an FFI [`RevisionId`] to a `pangolin_core::RevisionId`.
pub fn revision_id_from_ffi(id: &RevisionId) -> Result<pangolin_core::RevisionId, FfiError> {
    let arr: [u8; REVISION_ID_BYTES] =
        id.bytes
            .as_slice()
            .try_into()
            .map_err(|_| FfiError::Validation {
                kind: "argument".into(),
                message: format!(
                    "RevisionId.bytes must be {REVISION_ID_BYTES} bytes (got {})",
                    id.bytes.len()
                ),
            })?;
    Ok(pangolin_core::RevisionId::from_bytes(arr))
}

/// **MVP-1 issue 1.6.** Convert a `pangolin_core::RevisionMeta` to its
/// FFI shape, tagging the graph-derived bits (`is_head` /
/// `is_canonical_head` / `on_canonical_chain`) from the supplied
/// [`pangolin_core::RevisionGraph`].
#[must_use]
pub fn revision_meta_to_ffi_tagged(
    meta: pangolin_core::RevisionMeta,
    graph: &pangolin_core::RevisionGraph,
) -> RevisionMeta {
    let parent = if meta.parent_revision_id == pangolin_core::RevisionId::GENESIS_PARENT {
        None
    } else {
        Some(revision_id_to_ffi(meta.parent_revision_id))
    };
    let canonical = graph.canonical_head().copied();
    // `is_head` follows the graph's head set (which excludes a
    // superseded losing-branch leaf — a resolved fork's losing tip is
    // not a head).
    let is_head = graph.heads().contains(&meta.revision_id);
    RevisionMeta {
        schema_version: pangolin_core::ACCOUNT_IDENTITY_SCHEMA_VERSION,
        id: revision_id_to_ffi(meta.revision_id),
        created_at_unix: meta.created_at,
        parent_id: parent,
        device_id: meta.device_id.0.to_vec(),
        is_tombstone: meta.is_tombstone,
        is_head,
        is_canonical_head: canonical == Some(meta.revision_id),
        on_canonical_chain: graph.is_on_canonical_chain(&meta.revision_id),
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
///
/// # Audit L-2: zeroising intermediate buffers
///
/// The intermediate `Vec<u8>` produced by `to_vec()` between the
/// `bytes_for_bridge()` borrow and `SecretBytes::new(...)` is wrapped
/// in `zeroize::Zeroizing` for the lifetime of that window. The
/// wrapper zeroises its allocation on drop, so a panic between the
/// `to_vec()` call and the `SecretBytes::new(...)` consumption does
/// NOT leak plaintext bytes onto the unwound stack frame. We hand off
/// to `SecretBytes::new` by `std::mem::take`-ing the inner `Vec` —
/// the now-emptied `Zeroizing<Vec<u8>>` drops harmlessly (zeroising a
/// zero-capacity Vec is a no-op).
#[allow(clippy::unnecessary_wraps)]
pub fn draft_into_store(
    draft: AccountDraft,
) -> Result<pangolin_core::AccountIdentityDraft, FfiError> {
    let mut password_bytes =
        zeroize::Zeroizing::new(secret_password_bytes(&draft.current_password));
    let mut totp_bytes = zeroize::Zeroizing::new(
        draft
            .totp_secret
            .as_ref()
            .map_or_else(Vec::new, totp_secret_bytes),
    );
    // Move the inner Vec out of the Zeroizing wrapper directly into
    // SecretBytes (which itself wraps the Vec in its own
    // Zeroizing<Vec<u8>>). The Zeroizing wrappers we just emptied
    // drop harmlessly at end of scope.
    let password = SecretBytes::new(std::mem::take(&mut *password_bytes));
    let totp_secret = SecretBytes::new(std::mem::take(&mut *totp_bytes));
    Ok(pangolin_core::AccountIdentityDraft {
        schema_version: draft.schema_version,
        display_name: draft.display_name,
        tags: draft.tags,
        usernames: draft.usernames,
        urls: draft.urls,
        notes: draft.notes.unwrap_or_default(),
        password,
        totp_secret,
    })
}

/// Convert an FFI [`AccountPatch`] into a
/// `pangolin_core::AccountIdentityPatch`.
///
/// Audit L-2: intermediate `Vec<u8>` plaintext between `to_vec()` and
/// `SecretBytes::new(...)` is held in `zeroize::Zeroizing` so a panic
/// in that window cannot leak the allocation onto the unwound stack.
#[allow(clippy::unnecessary_wraps)]
pub fn patch_into_store(
    patch: AccountPatch,
) -> Result<pangolin_core::AccountIdentityPatch, FfiError> {
    let new_password = patch.current_password.as_ref().map(|p| {
        let mut bytes = zeroize::Zeroizing::new(secret_password_bytes(p));
        SecretBytes::new(std::mem::take(&mut *bytes))
    });
    let totp = patch.totp_secret.map(|outer| {
        outer.map(|secret| {
            let mut bytes = zeroize::Zeroizing::new(totp_secret_bytes(&secret));
            SecretBytes::new(std::mem::take(&mut *bytes))
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
///
/// **MVP-1 issue 1.4 (Q5b):** the summary already carries zero secret
/// material (the `pangolin-store` projection was tightened too), so
/// this is a pure metadata copy — no `SecretBytes` is exposed, no
/// `SecretPassword` / `TotpSecret` handle is constructed. The
/// password / history / notes / TOTP-seed bytes are reachable only
/// through the presence-gated `reveal_*` FFI entry points.
#[allow(clippy::unnecessary_wraps)]
pub fn summary_to_ffi(
    summary: pangolin_core::AccountIdentitySummary,
) -> Result<AccountSnapshot, FfiError> {
    let pangolin_core::AccountIdentitySummary {
        id,
        head_revision_id,
        display_name,
        tags,
        usernames,
        urls,
        password_history_count,
        has_totp,
        current_password_changed_at_ms,
        ..
    } = summary;

    Ok(AccountSnapshot {
        schema_version: pangolin_core::ACCOUNT_IDENTITY_SCHEMA_VERSION,
        id: account_id_to_ffi(id),
        display_name,
        tags,
        usernames,
        urls,
        head_revision_id: revision_id_to_ffi(head_revision_id),
        password_history_count,
        has_totp,
        // ms → s, integer-truncated (matches the pre-1.4 PasswordHistoryEntry
        // conversion discipline; audit L-4).
        current_password_changed_at: current_password_changed_at_ms / 1000,
    })
}

/// Convert a `pangolin_core::PasswordHistorySummaryEntry` (the reveal
/// result) into the FFI [`PasswordHistoryEntry`] shape. Used by the
/// presence-gated `reveal_password_history` entry point. Audit L-2:
/// the intermediate `Vec<u8>` plaintext between `expose().to_vec()`
/// and the `SecretPassword` constructor is held in `zeroize::Zeroizing`
/// so a panic in that window cannot leak the allocation.
#[must_use]
pub fn password_history_entry_to_ffi(
    entry: pangolin_core::PasswordHistorySummaryEntry,
) -> PasswordHistoryEntry {
    let mut bytes = zeroize::Zeroizing::new(entry.password.expose().to_vec());
    PasswordHistoryEntry {
        schema_version: pangolin_core::ACCOUNT_IDENTITY_SCHEMA_VERSION,
        password: SecretPassword::new(std::mem::take(&mut *bytes)),
        set_at: entry.set_at_ms / 1000,
        originating_device: device_id_to_ffi(entry.originating_device),
    }
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

#[cfg(test)]
mod tests {
    //! MVP-1 issue 1.4 (Q5b): `summary_to_ffi` is now a pure
    //! metadata copy — the FFI `AccountSnapshot` carries zero secret
    //! material. These tests pin (a) the `current_password_changed_at`
    //! ms→s conversion (audit L-4 discipline), (b) that no secret
    //! handle is constructed, and (c) `password_history_entry_to_ffi`'s
    //! `set_at` ms→s conversion (used by `reveal_password_history`).

    use super::*;
    use pangolin_core::{
        AccountId as CoreAccountId, AccountIdentitySummary, DeviceId as CoreDeviceId,
        PasswordHistorySummaryEntry, RevisionId as CoreRevisionId,
    };

    fn fixture_summary(
        history_count: u32,
        changed_at_ms: i64,
        has_totp: bool,
    ) -> AccountIdentitySummary {
        AccountIdentitySummary {
            schema_version: pangolin_core::ACCOUNT_IDENTITY_SCHEMA_VERSION,
            id: CoreAccountId::from_bytes([0x11u8; 32]),
            head_revision_id: CoreRevisionId::from_bytes([0x22u8; 32]),
            display_name: "X".into(),
            tags: vec!["work".into()],
            usernames: vec!["u".into()],
            urls: vec!["https://example.com".into()],
            password_history_count: history_count,
            has_totp,
            current_password_changed_at_ms: changed_at_ms,
        }
    }

    #[test]
    fn summary_to_ffi_is_metadata_only_and_converts_timestamp() {
        // 500 ms past the unix-second boundary; integer division by
        // 1000 must yield the floored second.
        let changed_at_ms: i64 = 1_700_000_000_500;
        let snap = summary_to_ffi(fixture_summary(3, changed_at_ms, true)).expect("summary_to_ffi");
        assert_eq!(snap.password_history_count, 3);
        assert!(snap.has_totp);
        assert_eq!(snap.current_password_changed_at, 1_700_000_000_i64);
        assert_eq!(snap.display_name, "X");
        assert_eq!(snap.tags, vec!["work".to_string()]);
        // The FFI AccountSnapshot has no secret-bearing fields — this
        // construction would not compile if it did (struct literal in
        // `summary_to_ffi` lists every field). Belt + suspenders: the
        // type carries no `Arc<SecretPassword>` / `Arc<TotpSecret>`.
    }

    #[test]
    fn summary_to_ffi_handles_exact_second_and_empty_history() {
        let snap = summary_to_ffi(fixture_summary(0, 1_700_000_000_000, false)).expect("ok");
        assert_eq!(snap.current_password_changed_at, 1_700_000_000_i64);
        assert_eq!(snap.password_history_count, 0);
        assert!(!snap.has_totp);
    }

    #[test]
    fn password_history_entry_to_ffi_converts_timestamp_and_carries_bytes() {
        let entry = PasswordHistorySummaryEntry {
            password: pangolin_crypto::secret::SecretBytes::new(b"hunter2".to_vec()),
            set_at_ms: 1_700_000_000_750,
            originating_device: CoreDeviceId([0xABu8; 32]),
        };
        let ffi = password_history_entry_to_ffi(entry);
        assert_eq!(ffi.set_at, 1_700_000_000_i64);
        assert_eq!(ffi.password.byte_length(), 7);
        assert_eq!(ffi.originating_device.bytes, vec![0xABu8; 32]);
    }
}
