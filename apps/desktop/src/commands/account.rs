// SPDX-License-Identifier: AGPL-3.0-or-later
//! Account-list + reveal-class Tauri commands.
//!
//! See MVP-4-B plan §3.2:
//!
//! - `accounts_list` wraps `pangolin_ffi::identity::account_search("")`
//!   (empty query = list-all). The plan flagged the binding name as
//!   builder-verify; the FFI's actual list-everything affordance is the
//!   empty-query branch of `account_search`, not a dedicated `list`
//!   binding. Audit-trail in §0 of this file's tests.
//! - `account_show` wraps `pangolin_ffi::identity::account_get`.
//! - `reveal_password` wraps `pangolin_ffi::reveal::reveal_current_password`
//!   (the plan flagged it as "verify the closest equivalent name"; the
//!   1.4-locked entry is `reveal_current_password`).
//! - `copy_to_clipboard` uses `tauri-plugin-clipboard-manager`'s
//!   `write_text` API.
//!
//! ## Q-a (clipboard-clear timer) — builder's call
//!
//! Decided: **option (i) — no host-side clear timer this slice.** The
//! plan §5 Q-a explicitly admits both choices; the real timer-with-
//! cancellation + user-configurable duration is MVP-4 back-half work.
//! The JS-side `useEffect` on the `AccountDetail` screen already clears
//! the *revealed plaintext from the React state* within 10 s per the
//! Browser-Ext spec §4.7 memory-hygiene rule; clearing the OS
//! clipboard requires a separate timer + a cancel-on-rewrite policy
//! that would balloon scope.
//!
//! The host side currently has no `clear_clipboard` Tauri command
//! exposed (the capability allow-list permits only `write-text`).
//! Adding the timer is therefore additive next slice; the React side
//! shows a one-time "password copied" toast as user feedback.

#![forbid(unsafe_code)]

use std::sync::Arc;

use serde::Serialize;
use tauri::State;
use tauri_plugin_clipboard_manager::ClipboardExt;

use crate::error::DesktopError;
use crate::state::VaultState;

/// JS-facing account summary.
///
/// A thin slim of the FFI's `AccountSnapshot` with the binary fields
/// hex-encoded so the JS bridge sees plain strings (avoids the
/// `{schema_version, bytes: number[]}` shape on every list cell).
#[derive(Debug, Clone, Serialize)]
pub struct AccountSummaryDto {
    /// 64-character lowercase hex of the 32-byte account id.
    pub id: String,
    /// User-visible display name. Non-secret.
    pub display_name: String,
    /// Non-secret tags.
    pub tags: Vec<String>,
    /// Non-secret usernames.
    pub usernames: Vec<String>,
    /// Non-secret associated URLs.
    pub urls: Vec<String>,
    /// Count of password-history entries. The bytes themselves come
    /// from `reveal_password` (presence-gated).
    pub password_history_count: u32,
    /// Whether a TOTP secret is configured. The seed comes from a
    /// dedicated reveal entry (not exposed in this slice).
    pub has_totp: bool,
    /// Wall-clock unix-second timestamp the current head password was
    /// last set (`0` if the history is somehow empty).
    pub current_password_changed_at: i64,
}

impl From<pangolin_ffi::identity::AccountSnapshot> for AccountSummaryDto {
    fn from(snap: pangolin_ffi::identity::AccountSnapshot) -> Self {
        Self {
            id: hex_encode(&snap.id.bytes),
            display_name: snap.display_name,
            tags: snap.tags,
            usernames: snap.usernames,
            urls: snap.urls,
            password_history_count: snap.password_history_count,
            has_totp: snap.has_totp,
            current_password_changed_at: snap.current_password_changed_at,
        }
    }
}

/// Lowercase-hex encoder. Pure-stdlib so the desktop crate gains no
/// `hex` dep (the workspace already has one but adding it just for this
/// would broaden the dep arrow needlessly).
fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Public alias of [`account_id_from_hex`] for the IPC dispatch path
/// in `crate::ipc::dispatch`. Identical body; exists only so the
/// crate-private helper stays out of the Tauri-command-only surface
/// while the IPC dispatch can reuse the validation.
pub(crate) fn account_id_from_hex_for_ipc(
    hex: &str,
) -> Result<pangolin_ffi::identity::AccountId, DesktopError> {
    account_id_from_hex(hex)
}

/// Decode a 64-character lowercase-hex string into a 32-byte
/// `AccountId`. Wraps the validation as `DesktopError::Validation` so
/// the React side surfaces a typed toast.
fn account_id_from_hex(hex: &str) -> Result<pangolin_ffi::identity::AccountId, DesktopError> {
    if hex.len() != 64 {
        return Err(DesktopError::Validation {
            kind: "account_id".into(),
            message: "account id must be 64 hex characters".into(),
        });
    }
    let mut bytes = Vec::with_capacity(32);
    for chunk in hex.as_bytes().chunks_exact(2) {
        let hi = decode_nibble(chunk[0])?;
        let lo = decode_nibble(chunk[1])?;
        bytes.push((hi << 4) | lo);
    }
    Ok(pangolin_ffi::identity::AccountId {
        schema_version: 1,
        bytes,
    })
}

fn decode_nibble(b: u8) -> Result<u8, DesktopError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(DesktopError::Validation {
            kind: "account_id".into(),
            message: "account id contains a non-hex character".into(),
        }),
    }
}

/// Build a CLI-tier presence proof.
fn cli_presence_proof() -> pangolin_ffi::PresenceProof {
    pangolin_ffi::PresenceProof {
        schema_version: 1,
        bytes: Vec::new(),
    }
}

/// Inner accounts-list helper.
///
/// Bodies of the `#[tauri::command]` wrapper [`accounts_list`] AND
/// the IPC dispatch path (`crate::ipc::dispatch::vault_list_accounts`)
/// share the SAME pure-async function. Keeps the two surfaces in lock-
/// step so a future change to the FFI binding choice only edits one
/// place.
///
/// # Errors
///
/// `DesktopError::Session` for a locked / closed vault.
pub(crate) async fn accounts_list_inner(
    state: &VaultState,
) -> Result<Vec<AccountSummaryDto>, DesktopError> {
    let handle = state.require_open()?;
    let snapshots = pangolin_ffi::identity::account_search(handle, String::new())
        .map_err(DesktopError::from)?;
    Ok(snapshots.into_iter().map(AccountSummaryDto::from).collect())
}

/// List every account in the open vault.
///
/// Wraps `pangolin_ffi::identity::account_search("")` (the empty-query
/// list-all branch of the index, per `pangolin-store::Vault::search`'s
/// `SanitisedQuery::Empty` arm). Returns a slim DTO with binary fields
/// already hex-encoded.
///
/// # Errors
///
/// `DesktopError::Session` for a locked / closed vault.
#[tauri::command]
pub async fn accounts_list(
    state: State<'_, VaultState>,
) -> Result<Vec<AccountSummaryDto>, DesktopError> {
    accounts_list_inner(&state).await
}

/// Inner account-show helper shared by the Tauri command + IPC
/// dispatch. See [`accounts_list_inner`] for the rationale.
pub(crate) async fn account_show_inner(
    state: &VaultState,
    id: String,
) -> Result<AccountSummaryDto, DesktopError> {
    let account_id = account_id_from_hex(&id)?;
    let handle = state.require_open()?;
    let snap =
        pangolin_ffi::identity::account_get(handle, account_id).map_err(DesktopError::from)?;
    Ok(snap.into())
}

/// Fetch a single account's metadata.
///
/// # Errors
///
/// `DesktopError::Validation { kind = "account_id", .. }` for a bad
/// hex; `DesktopError::Session` for a locked vault; `DesktopError::Store`
/// for an unknown / tombstoned account.
#[tauri::command]
pub async fn account_show(
    id: String,
    state: State<'_, VaultState>,
) -> Result<AccountSummaryDto, DesktopError> {
    account_show_inner(&state, id).await
}

/// Reveal the current head-of-history plaintext password for an
/// account.
///
/// **L1 carve-out (the LOAD-BEARING one for this slice).** The
/// password byte string crosses FFI as a `String` solely for the
/// reveal flow. Per Browser-Ext spec §4.7 the React side MUST clear
/// the local state slot within 10 s; the [`AccountDetailScreen`]'s
/// `useEffect` enforces that contract on the host side. The Rust path
/// here keeps the bytes in a `Zeroizing<Vec<u8>>` while transcoding to
/// UTF-8, so the only un-zeroized copy is the one Tauri's JSON
/// serializer writes to the IPC channel — which Tauri's own internals
/// drop as soon as the response frame is dispatched.
///
/// # Errors
///
/// As `pangolin_ffi::reveal::reveal_current_password`: `Session` for a
/// locked / expired vault or a frozen account; `Store` for an unknown
/// account.
#[tauri::command]
pub async fn reveal_password(
    id: String,
    state: State<'_, VaultState>,
) -> Result<String, DesktopError> {
    let account_id = account_id_from_hex(&id)?;
    let handle = state.require_open()?;
    let presence = cli_presence_proof();
    let revealed = pangolin_ffi::reveal::reveal_current_password(handle, account_id, presence)
        .map_err(DesktopError::from)?;

    // `RevealedSecret::expose_bytes_for_host()` returns
    // `Zeroizing<Vec<u8>>` (audit M-1 hardening); the buffer is
    // type-system-zeroed on drop. We only need to transcode to UTF-8
    // and return; the `bytes` binding drops at end-of-scope.
    let bytes = revealed.expose_bytes_for_host();
    let s = std::str::from_utf8(&bytes)
        .map_err(|_| DesktopError::Internal("revealed password is not valid utf-8".into()))?
        .to_owned();
    Ok(s)
}

/// Inner copy-password helper.
///
/// Performs the reveal + clipboard-write entirely Rust-side; the
/// `bytes` binding is `Zeroizing<Vec<u8>>` and zeroes on drop. Used
/// by BOTH the Tauri command wrapper [`copy_password_to_clipboard`]
/// AND the IPC dispatch path
/// (`crate::ipc::dispatch::vault_copy_password`). The generic
/// `clipboard_write` closure abstracts over the two concrete
/// clipboard backends:
///
/// - Tauri command path: `app.clipboard().write_text(s)` via the
///   `tauri-plugin-clipboard-manager` plugin.
/// - IPC dispatch path: same plugin via a held `tauri::AppHandle`
///   (the IPC server holds the handle from the `setup` callback).
///
/// L1: the `revealed` plaintext NEVER leaves Rust. The clipboard
/// path is the documented H-1 carve-out from MVP-4-B; this slice
/// preserves it verbatim.
pub(crate) async fn copy_password_via<F>(
    state: &VaultState,
    id: String,
    clipboard_write: F,
) -> Result<(), DesktopError>
where
    F: FnOnce(String) -> Result<(), DesktopError>,
{
    let account_id = account_id_from_hex(&id)?;
    let handle = state.require_open()?;
    let presence = cli_presence_proof();
    let revealed = pangolin_ffi::reveal::reveal_current_password(handle, account_id, presence)
        .map_err(DesktopError::from)?;

    let bytes = revealed.expose_bytes_for_host();
    let s = std::str::from_utf8(&bytes)
        .map_err(|_| DesktopError::Internal("revealed password is not valid utf-8".into()))?
        .to_owned();
    clipboard_write(s)
}

/// **Copy the current head-of-history plaintext password directly
/// to the OS clipboard, NEVER crossing the FFI boundary back into
/// JS.**
///
/// Audit HIGH H-1 hardening (2026-05-25). Before this command
/// existed, the "copy password" flow went `reveal_password (FFI) →
/// String → JS → invoke copy_to_clipboard (FFI) → String → Rust →
/// clipboard` — the plaintext crossed V8 TWICE per copy click + sat
/// in two JS strings until GC. This command collapses the path:
/// the plaintext stays in Rust the entire time + the clipboard
/// write happens in the same `tauri::command` body that holds the
/// `Zeroizing` buffer. The plaintext never touches V8.
///
/// The reveal-to-view flow ([`reveal_password`]) still crosses the
/// L1 carve-out boundary because the user has to SEE the password
/// before copying isn't always the chosen action (sometimes they
/// just want to verify the value). For the COPY intent, prefer this
/// command; the React side wires this to the "Copy" button on
/// `AccountDetailScreen` so the most common user action skips the
/// JS round-trip entirely.
///
/// # Errors
///
/// As [`reveal_password`]'s underlying FFI: `Session` for a locked
/// vault, `Store` for an unknown account, `Internal` for a UTF-8
/// or clipboard-write failure.
#[tauri::command]
pub async fn copy_password_to_clipboard(
    id: String,
    state: State<'_, VaultState>,
    app: tauri::AppHandle,
) -> Result<(), DesktopError> {
    copy_password_via(&state, id, |s| {
        app.clipboard()
            .write_text(s)
            .map_err(|e| DesktopError::Internal(format!("clipboard write failed: {e}")))
    })
    .await
}

/// Write arbitrary `text` to the OS clipboard.
///
/// Retained for any non-secret string the host UI needs to copy
/// (e.g. an account username); for password copy use
/// [`copy_password_to_clipboard`] which never crosses the plaintext
/// through V8 (audit H-1). Per Q-a no host-side clear timer is
/// wired this slice; the React side renders a one-time
/// "password copied" toast.
///
/// # Errors
///
/// `DesktopError::Internal` if the clipboard plugin's write fails (the
/// plugin returns an opaque `tauri::Error`; mapped to a non-secret
/// string for the UI).
#[tauri::command]
pub async fn copy_to_clipboard(text: String, app: tauri::AppHandle) -> Result<(), DesktopError> {
    app.clipboard()
        .write_text(text)
        .map_err(|e| DesktopError::Internal(format!("clipboard write failed: {e}")))?;
    Ok(())
}

// Helper to keep the Send-future shape of the async handlers explicit
// for the maintainer — every command body clones the `Arc<VaultHandle>`
// out of `VaultState` before any potential `.await`, so the Tauri
// runtime's `Send` requirement is satisfied without needing a custom
// runtime config.
#[allow(dead_code)]
fn assert_handle_is_send_sync()
where
    Arc<pangolin_ffi::VaultHandle>: Send + Sync,
{
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_encode_round_trip() {
        let bytes = vec![0xde, 0xad, 0xbe, 0xef, 0x01, 0x02];
        let s = hex_encode(&bytes);
        assert_eq!(s, "deadbeef0102");
    }

    #[test]
    fn account_id_from_hex_rejects_wrong_length() {
        let err = account_id_from_hex("deadbeef").expect_err("too short");
        match err {
            DesktopError::Validation { kind, .. } => assert_eq!(kind, "account_id"),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn account_id_from_hex_rejects_non_hex() {
        let bad = "z".repeat(64);
        let err = account_id_from_hex(&bad).expect_err("non-hex");
        match err {
            DesktopError::Validation { kind, .. } => assert_eq!(kind, "account_id"),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn account_id_from_hex_accepts_uppercase() {
        let id = account_id_from_hex(&"A".repeat(64)).expect("uppercase ok");
        assert_eq!(id.bytes.len(), 32);
        assert_eq!(id.bytes[0], 0xaa);
    }

    #[test]
    fn account_id_round_trip_lowercase() {
        let mut bytes = vec![0u8; 32];
        bytes[0] = 0xab;
        bytes[31] = 0xcd;
        let hex = hex_encode(&bytes);
        let id = account_id_from_hex(&hex).expect("round-trip ok");
        assert_eq!(id.bytes, bytes);
    }

    /// L1: `AccountSummaryDto` is a metadata-only DTO; it carries no
    /// secret material.
    #[test]
    fn account_summary_dto_is_metadata_only() {
        let snap = pangolin_ffi::identity::AccountSnapshot {
            schema_version: 1,
            id: pangolin_ffi::identity::AccountId {
                schema_version: 1,
                bytes: vec![0xaa; 32],
            },
            display_name: "Acme".into(),
            tags: vec!["work".into()],
            usernames: vec!["alice@acme".into()],
            urls: vec!["https://acme.example".into()],
            head_revision_id: pangolin_ffi::revision::RevisionId {
                schema_version: 1,
                bytes: vec![0; 32],
            },
            password_history_count: 3,
            has_totp: true,
            current_password_changed_at: 1_700_000_000,
        };
        let dto: AccountSummaryDto = snap.into();
        assert_eq!(dto.id, "a".repeat(64));
        assert_eq!(dto.display_name, "Acme");
        assert!(dto.has_totp);
        assert_eq!(dto.password_history_count, 3);
    }
}
