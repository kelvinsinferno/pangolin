// SPDX-License-Identifier: AGPL-3.0-or-later
//! **MVP-4-H Layer 2: `*_via_secure_prompt` Tauri commands.**
//!
//! For each existing command that accepts a `password: String` arg,
//! this module exposes a sibling `*_via_secure_prompt` command that
//! opens the native OS password dialog instead. The password bytes
//! flow directly from the native widget into `SecretPassword::new`
//! without ever entering the V8 heap.
//!
//! ## Pattern
//!
//! ```ignore
//! #[tauri::command]
//! pub async fn X_via_secure_prompt(app, ...non-password args..., state) -> Result<...> {
//!     let handle = state.require_open()?;
//!     let secret = prompt_secret(&app, TITLE, BODY)?;
//!     // ... call the same FFI op the legacy `X` command calls
//! }
//! ```
//!
//! ## Status
//!
//! This file lands `vault_unlock_via_secure_prompt` first as the L2
//! wiring template. The remaining eight `*_via_secure_prompt` commands
//! (pairing_open_and_join, pairing_chain_bootstrap, pairing_add_device,
//! pairing_complete_rotation, recovery_create_backup,
//! recovery_set_guardian_set, recovery_initiate, recovery_complete)
//! follow the same pattern and ship in subsequent commits before
//! Layer 3 wires up the React side.
//!
//! ## L-invariants
//!
//! - **L1.** Bytes from the native dialog land in a
//!   `Zeroizing<Vec<u8>>` that's moved (via `mem::take`) into
//!   `SecretPassword::new` — no copy through V8, no copy through
//!   Tauri's serde bridge.
//! - **L3.** [`SecureInputError`] → [`DesktopError::Validation`]
//!   collapses cancel + unavailable + internal into the typed
//!   envelope the React side already knows how to surface as a
//!   toast.
//! - **L4.** Each command first calls `state.require_open()` so a
//!   locked / closed vault fails BEFORE the native dialog spawns
//!   (UX: no point asking for a password when the FFI will refuse).

#![forbid(unsafe_code)]
#![allow(clippy::doc_markdown)]

use std::sync::Arc;

use pangolin_ffi::SecretPassword;
use tauri::State;
use zeroize::Zeroizing;

use crate::error::DesktopError;
use crate::secure_input::{self, SecureInputError};
use crate::state::VaultState;

/// **Open the OS password dialog + wrap the bytes in `SecretPassword`.**
/// Helper used by every `*_via_secure_prompt` command in this module.
///
/// Maps [`SecureInputError`] to [`DesktopError::Validation`] so the
/// React side gets a typed envelope (`{kind, message}`) it already
/// knows how to surface.
fn prompt_secret(
    app: &tauri::AppHandle,
    title: &str,
    body: &str,
) -> Result<Arc<SecretPassword>, DesktopError> {
    let mut bytes: Zeroizing<Vec<u8>> = secure_input::prompt_password(app, title, body)
        .map_err(|e| secure_input_err_to_desktop(&e))?;
    // Move the inner Vec<u8> out of the Zeroizing wrapper into
    // SecretPassword::new; the wrapper drops with an empty Vec
    // (no-op zero), the bytes now live in SecretPassword's own
    // zeroize-on-drop discipline.
    let raw: Vec<u8> = std::mem::take(&mut *bytes);
    Ok(SecretPassword::new(raw))
}

fn secure_input_err_to_desktop(e: &SecureInputError) -> DesktopError {
    DesktopError::Validation {
        kind: e.kind().to_string(),
        message: e.to_string(),
    }
}

// ---------------------------------------------------------------------------
// 1 / 9 — vault_unlock_via_secure_prompt
// ---------------------------------------------------------------------------

/// Unlock the currently-open vault via the OS native password dialog.
///
/// Drives [`pangolin_ffi::session::vault_unlock`] after collecting the
/// master password from the native widget. The password bytes never
/// cross V8 / Tauri's serde bridge.
///
/// # Errors
///
/// - [`DesktopError::Session`] if no vault is open.
/// - [`DesktopError::Validation`] (`kind = "secure_input_cancelled"`)
///   if the user dismissed the dialog without typing.
/// - [`DesktopError::Validation`] (`kind = "secure_input_unavailable"`)
///   if the native widget couldn't load.
/// - [`DesktopError::AuthenticationFailed`] for the collapsed
///   wrong-password / tampered-ciphertext class.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn vault_unlock_via_secure_prompt(
    app: tauri::AppHandle,
    state: State<'_, VaultState>,
) -> Result<(), DesktopError> {
    let handle = state.require_open()?;
    let secret = prompt_secret(&app, "Unlock vault", "Enter your master password")?;
    let presence = crate::commands::vault::cli_presence_proof();
    let _session_info = pangolin_ffi::session::vault_unlock(Arc::clone(&handle), secret, presence)
        .map_err(DesktopError::from)?;
    Ok(())
}
