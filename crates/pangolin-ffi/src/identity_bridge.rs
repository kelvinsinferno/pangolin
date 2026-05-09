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
#[allow(clippy::unnecessary_wraps)]
pub fn summary_to_ffi(
    summary: pangolin_core::AccountIdentitySummary,
) -> Result<AccountSnapshot, FfiError> {
    // The summary already contains UTF-8 strings + SecretBytes;
    // wrap secret-bearing fields in the FFI envelopes.
    //
    // `notes` are deliberately NOT surfaced here — recovery-class per
    // spec §5.4, presence-gated `reveal_notes` lands in 1.4
    // (audit C-1 / plan §D).
    let pangolin_core::AccountIdentitySummary {
        id,
        head_revision_id,
        display_name,
        tags,
        usernames,
        urls,
        password_history,
        totp_secret,
        ..
    } = summary;

    // Audit L-2: each `to_vec()` of plaintext password / totp bytes
    // is held in `zeroize::Zeroizing` until ownership transfers into
    // the FFI secret-handle constructor. A panic in the narrow window
    // between the borrow and the constructor call cannot leak the
    // intermediate Vec onto the unwound stack.
    let current_password = password_history.first().map_or_else(
        || SecretPassword::new(Vec::new()),
        |e| {
            let mut bytes = zeroize::Zeroizing::new(e.password.expose().to_vec());
            SecretPassword::new(std::mem::take(&mut *bytes))
        },
    );

    let history_ffi: Vec<PasswordHistoryEntry> = password_history
        .into_iter()
        .map(|entry| {
            let mut bytes = zeroize::Zeroizing::new(entry.password.expose().to_vec());
            PasswordHistoryEntry {
                schema_version: pangolin_core::ACCOUNT_IDENTITY_SCHEMA_VERSION,
                password: SecretPassword::new(std::mem::take(&mut *bytes)),
                set_at: entry.set_at_ms / 1000,
                originating_device: device_id_to_ffi(entry.originating_device),
            }
        })
        .collect();

    let totp_arc = totp_secret.map(|sb| {
        let mut bytes = zeroize::Zeroizing::new(sb.expose().to_vec());
        TotpSecret::new(std::mem::take(&mut *bytes))
    });

    Ok(AccountSnapshot {
        schema_version: pangolin_core::ACCOUNT_IDENTITY_SCHEMA_VERSION,
        id: account_id_to_ffi(id),
        display_name,
        tags,
        usernames,
        urls,
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

#[cfg(test)]
mod tests {
    //! Audit L-4: pin the `set_at` ms→s conversion done in
    //! `summary_to_ffi`. The summary carries `set_at_ms`
    //! (unix-milliseconds, `i64`); the FFI `PasswordHistoryEntry.set_at`
    //! is `UnixTimestamp` (unix-seconds, `i64`). The bridge divides by
    //! 1000 — this test exercises a value with a sub-second remainder
    //! to verify integer-division truncation matches `set_at_ms / 1000`.

    use super::*;
    use pangolin_core::{
        AccountId as CoreAccountId, AccountIdentitySummary, DeviceId as CoreDeviceId,
        PasswordHistorySummaryEntry, RevisionId as CoreRevisionId,
    };

    #[test]
    fn set_at_ms_to_seconds_conversion_truncates_remainder() {
        // 500 ms past the unix-second boundary; integer division by
        // 1000 must yield the floored second.
        let set_at_ms: i64 = 1_700_000_000_500;
        let expected_set_at_s: i64 = set_at_ms / 1000;
        assert_eq!(expected_set_at_s, 1_700_000_000_i64);

        let summary = AccountIdentitySummary {
            schema_version: pangolin_core::ACCOUNT_IDENTITY_SCHEMA_VERSION,
            id: CoreAccountId::from_bytes([0x11u8; 32]),
            head_revision_id: CoreRevisionId::from_bytes([0x22u8; 32]),
            display_name: "X".into(),
            tags: vec![],
            usernames: vec!["u".into()],
            urls: vec![],
            password_history: vec![PasswordHistorySummaryEntry {
                password: pangolin_crypto::secret::SecretBytes::new(b"p".to_vec()),
                set_at_ms,
                originating_device: CoreDeviceId([0u8; 32]),
            }],
            totp_secret: None,
        };

        let snap = summary_to_ffi(summary).expect("summary_to_ffi");
        assert_eq!(snap.password_history.len(), 1);
        assert_eq!(snap.password_history[0].set_at, expected_set_at_s);
        assert_eq!(snap.password_history[0].set_at, 1_700_000_000_i64);
    }

    #[test]
    fn set_at_ms_to_seconds_conversion_handles_exact_second() {
        // Exact-second boundary: no remainder.
        let set_at_ms: i64 = 1_700_000_000_000;
        let summary = AccountIdentitySummary {
            schema_version: pangolin_core::ACCOUNT_IDENTITY_SCHEMA_VERSION,
            id: CoreAccountId::from_bytes([0x11u8; 32]),
            head_revision_id: CoreRevisionId::from_bytes([0x22u8; 32]),
            display_name: "X".into(),
            tags: vec![],
            usernames: vec!["u".into()],
            urls: vec![],
            password_history: vec![PasswordHistorySummaryEntry {
                password: pangolin_crypto::secret::SecretBytes::new(b"p".to_vec()),
                set_at_ms,
                originating_device: CoreDeviceId([0u8; 32]),
            }],
            totp_secret: None,
        };
        let snap = summary_to_ffi(summary).expect("summary_to_ffi");
        assert_eq!(snap.password_history[0].set_at, 1_700_000_000_i64);
    }
}
