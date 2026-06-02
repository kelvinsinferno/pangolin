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

use crate::commands::pairing::{
    chain_config, vault_id_from_hex, RotationResultDto, SealedEnvelopeDto,
};
use crate::commands::recovery::{
    bytes_from_hex, BackupDto, RecoveryCompleteResultDto, TxOutcomeDto,
};
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

// ---------------------------------------------------------------------------
// 1b / 10 — vault_create_via_secure_prompt
// ---------------------------------------------------------------------------

/// **Create a new vault file at `path` via the OS native password dialog.**
///
/// First-launch flow: the welcome screen's "Create new vault" button
/// calls this AFTER a native save-dialog has picked `path`. We open the
/// secure-input dialog to collect the master password, then call
/// `pangolin_ffi::session::vault_create(path, password)`.
///
/// Unlike the other `*_via_secure_prompt` commands this one is NOT
/// gated on `state.require_open()` — the whole point is that no vault
/// is open yet. After a successful create, the caller must:
///
/// 1. Call `vault_open(path)` to install the new file as the active
///    handle (sets stage = Locked).
/// 2. Call `vault_unlock_via_secure_prompt()` to unlock (sets stage =
///    Active). The user types the same password they just chose;
///    `vault_create` and `vault_unlock` derive the authority from the
///    password independently, so the password isn't cached anywhere.
///
/// We intentionally do NOT auto-unlock after create — the user just
/// chose a password; making them type it twice catches typos before
/// they're locked out of a freshly-created vault. (UX trade: one extra
/// password entry vs. permanent lockout from a fat-fingered initial
/// password.)
///
/// # Errors
///
/// - [`DesktopError::Validation`] (`kind = "secure_input_cancelled"`)
///   if the user dismissed the password dialog.
/// - [`DesktopError::Store`] for an I/O failure (e.g. the file already
///   exists, or the parent directory is read-only).
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn vault_create_via_secure_prompt(
    app: tauri::AppHandle,
    path: String,
) -> Result<(), DesktopError> {
    let secret = prompt_secret(
        &app,
        "Create new vault",
        "Choose a master password for the new vault",
    )?;
    pangolin_ffi::session::vault_create(path, secret).map_err(DesktopError::from)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// 2 / 9 — pairing_open_and_join_via_secure_prompt
// ---------------------------------------------------------------------------

/// **Join a vault (new device) via the OS native password dialog.**
/// JoinVaultWizard's submit path. The user is choosing a NEW master
/// password for this device's local store; the prompt body reflects that.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn pairing_open_and_join_via_secure_prompt(
    app: tauri::AppHandle,
    sealed_bytes: Vec<u8>,
    vault_id: String,
    epoch: u64,
    state: State<'_, VaultState>,
) -> Result<(), DesktopError> {
    let handle = state.require_open()?;
    let vault_id_bytes = vault_id_from_hex(&vault_id)?;
    let pw = prompt_secret(
        &app,
        "Set vault password",
        "Choose a master password for this device",
    )?;
    pangolin_ffi::pairing::pairing_open_and_join(handle, sealed_bytes, vault_id_bytes, epoch, pw)
        .map_err(DesktopError::from)
}

// ---------------------------------------------------------------------------
// 3 / 9 — pairing_chain_bootstrap_via_secure_prompt
// ---------------------------------------------------------------------------

/// **Bootstrap the vault's on-chain authorized-device set via the OS
/// native password dialog.** Manager's genesis `addDevice` @ nonce 0.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn pairing_chain_bootstrap_via_secure_prompt(
    app: tauri::AppHandle,
    state: State<'_, VaultState>,
) -> Result<(), DesktopError> {
    let handle = state.require_open()?;
    let config = chain_config()?;
    let pw = prompt_secret(
        &app,
        "Confirm master password",
        "Authorizing this device on-chain",
    )?;
    tokio::task::spawn_blocking(move || {
        pangolin_ffi::pairing::vault_bootstrap_chain(handle, pw, config)
    })
    .await
    .map_err(|e| DesktopError::Internal(format!("bootstrap task join failed: {e}")))?
    .map_err(DesktopError::from)
}

// ---------------------------------------------------------------------------
// 4 / 9 — pairing_add_device_via_secure_prompt
// ---------------------------------------------------------------------------

/// **Authorize a new device (B) on-chain via the OS native password
/// dialog.** Manager confirms after SAS match in AddDeviceWizard.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn pairing_add_device_via_secure_prompt(
    app: tauri::AppHandle,
    their_bytes: Vec<u8>,
    state: State<'_, VaultState>,
) -> Result<SealedEnvelopeDto, DesktopError> {
    let handle = state.require_open()?;
    let their_payload =
        pangolin_ffi::pairing::pairing_decode_bytes(their_bytes).map_err(DesktopError::from)?;
    let config = chain_config()?;
    let pw = prompt_secret(
        &app,
        "Confirm master password",
        "Authorizing the new device on-chain",
    )?;
    let envelope = tokio::task::spawn_blocking(move || {
        pangolin_ffi::pairing::vault_add_device(handle, pw, config, their_payload)
    })
    .await
    .map_err(|e| DesktopError::Internal(format!("add-device task join failed: {e}")))?
    .map_err(DesktopError::from)?;
    Ok(envelope.into())
}

// ---------------------------------------------------------------------------
// 5 / 9 — pairing_complete_rotation_via_secure_prompt
// ---------------------------------------------------------------------------

/// **Re-key the vault after a device removal via the OS native
/// password dialog.** Existing device drives the rotation in
/// RemoveDeviceWizard.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn pairing_complete_rotation_via_secure_prompt(
    app: tauri::AppHandle,
    state: State<'_, VaultState>,
) -> Result<RotationResultDto, DesktopError> {
    let handle = state.require_open()?;
    let config = chain_config()?;
    let pw = prompt_secret(
        &app,
        "Confirm master password",
        "Re-keying this vault after a device removal",
    )?;
    let result = tokio::task::spawn_blocking(move || {
        pangolin_ffi::vault_complete_rotation(handle, pw, config)
    })
    .await
    .map_err(|e| DesktopError::Internal(format!("complete-rotation task join failed: {e}")))?
    .map_err(DesktopError::from)?;
    Ok(result.into())
}

// ---------------------------------------------------------------------------
// 6 / 9 — recovery_create_backup_via_secure_prompt
// ---------------------------------------------------------------------------

/// **Create the 24-word recovery backup via the OS native password
/// dialog.** RecoveryScreen's backup-create flow.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn recovery_create_backup_via_secure_prompt(
    app: tauri::AppHandle,
    state: State<'_, VaultState>,
) -> Result<BackupDto, DesktopError> {
    let handle = state.require_open()?;
    let pw = prompt_secret(
        &app,
        "Confirm master password",
        "Creating an encrypted recovery backup",
    )?;
    let backup = pangolin_ffi::vault_create_backup(handle, pw).map_err(DesktopError::from)?;
    Ok(backup.into())
}

// ---------------------------------------------------------------------------
// 7 / 9 — recovery_set_guardian_set_via_secure_prompt
// ---------------------------------------------------------------------------

/// **Commit the on-chain guardian set via the OS native password
/// dialog.** SetupGuardiansWizard step 2 (broadcast the merkle root
/// over guardian EVM addresses + the threshold).
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn recovery_set_guardian_set_via_secure_prompt(
    app: tauri::AppHandle,
    evm_addrs: Vec<String>,
    threshold: u8,
    state: State<'_, VaultState>,
) -> Result<TxOutcomeDto, DesktopError> {
    let handle = state.require_open()?;
    let mut addr_bytes = Vec::with_capacity(evm_addrs.len());
    for (idx, hex) in evm_addrs.iter().enumerate() {
        addr_bytes.push(
            bytes_from_hex(hex, "guardian EVM address", 20).map_err(|e| match e {
                DesktopError::Validation { kind, message } => DesktopError::Validation {
                    kind,
                    message: format!("guardian #{idx}: {message}"),
                },
                other => other,
            })?,
        );
    }
    let config = chain_config()?;
    let pw = prompt_secret(
        &app,
        "Confirm master password",
        "Committing your guardian set on-chain",
    )?;
    let outcome = tokio::task::spawn_blocking(move || {
        pangolin_ffi::vault_set_guardian_set(handle, pw, config, addr_bytes, threshold)
    })
    .await
    .map_err(|e| DesktopError::Internal(format!("set-guardian-set task join failed: {e}")))?
    .map_err(DesktopError::from)?;
    Ok(outcome.into())
}

// ---------------------------------------------------------------------------
// 8 / 9 — recovery_initiate_via_secure_prompt
// ---------------------------------------------------------------------------

/// **Broadcast the on-chain recovery initiation via the OS native
/// password dialog.** RecoverVaultWizard's init-recovery step.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn recovery_initiate_via_secure_prompt(
    app: tauri::AppHandle,
    target_vault_id: String,
    proposed_authority: String,
    expires_at: u64,
    state: State<'_, VaultState>,
) -> Result<TxOutcomeDto, DesktopError> {
    let handle = state.require_open()?;
    let vault_id_bytes = bytes_from_hex(&target_vault_id, "target_vault_id", 32)?;
    let proposed_authority_bytes = bytes_from_hex(&proposed_authority, "proposed_authority", 20)?;
    let config = chain_config()?;
    let pw = prompt_secret(
        &app,
        "Confirm master password",
        "Broadcasting the recovery attempt to Base Sepolia",
    )?;
    let outcome = tokio::task::spawn_blocking(move || {
        pangolin_ffi::vault_initiate_recovery(
            handle,
            pw,
            config,
            vault_id_bytes,
            proposed_authority_bytes,
            expires_at,
        )
    })
    .await
    .map_err(|e| DesktopError::Internal(format!("recovery-initiate task join failed: {e}")))?
    .map_err(DesktopError::from)?;
    Ok(outcome.into())
}

// ---------------------------------------------------------------------------
// 9 / 9 — recovery_complete_via_secure_prompt
// ---------------------------------------------------------------------------

/// **Finalize + rebuild the vault via the OS native password
/// dialog.** RecoverVaultWizard's finalize step — the user picks a
/// NEW master password for the recovered vault.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn recovery_complete_via_secure_prompt(
    app: tauri::AppHandle,
    target_vault_id: String,
    backup_text: String,
    phrase: Vec<String>,
    state: State<'_, VaultState>,
) -> Result<RecoveryCompleteResultDto, DesktopError> {
    let handle = state.require_open()?;
    let vault_id_bytes = bytes_from_hex(&target_vault_id, "target_vault_id", 32)?;
    let backup_bytes = backup_text.trim().as_bytes().to_vec();
    if backup_bytes.is_empty() {
        return Err(DesktopError::Validation {
            kind: "argument".into(),
            message: "backup envelope must not be empty".into(),
        });
    }
    let new_pw = prompt_secret(
        &app,
        "Choose new master password",
        "Pick a new master password for the recovered vault",
    )?;
    let config = chain_config()?;
    // Drain the accumulator BEFORE spawn_blocking so a failure routes
    // the user to "retry rebuild" by re-ingesting (matches the legacy
    // recovery_complete posture).
    let opened_shares = state.take_opened_shares()?;
    let outcome = tokio::task::spawn_blocking(move || {
        let handle_clone = handle.clone();
        let _finalize_outcome =
            pangolin_ffi::vault_finalize_recovery(handle_clone, config, vault_id_bytes.clone())?;
        pangolin_ffi::vault_recover_from_backup(handle, backup_bytes, phrase, opened_shares, new_pw)
    })
    .await
    .map_err(|e| DesktopError::Internal(format!("recovery-complete task join failed: {e}")))?
    .map_err(DesktopError::from)?;
    Ok(RecoveryCompleteResultDto {
        new_epoch: outcome.new_epoch,
    })
}
