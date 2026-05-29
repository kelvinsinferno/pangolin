// SPDX-License-Identifier: AGPL-3.0-or-later
//! Recovery Tauri commands (MVP-4-L, slice L-D).
//!
//! Thin wrappers over the already-built recovery FFI for the gap-free
//! slice: create a recovery backup (24-word phrase + envelope) and a
//! read-only recovery-health panel (current on-chain authority + any
//! in-flight recovery). NO guardian onboarding, NO recovery wizard, NO new
//! crypto — those are deferred behind the share-transport design (plan-LOCK
//! docs/issue-plans/mvp4-l-recovery-ux.md §1/§2). A backup ALWAYS requires
//! guardians to actually recover (Q-c) — the phrase is an aid, not a key.
//!
//! ## L-invariants
//!
//! - **L1.** The ONE secret that crosses here is the 24-word seed phrase
//!   (the backup's wrap authority) — it crosses out at create time exactly
//!   as designed (`vault_create_backup`), and the master password crosses
//!   in via the same `SecretPassword::new` path as `vault_unlock`. The VDK
//!   never crosses. The health-panel reads carry only non-secret on-chain
//!   addresses + status.
//! - **L3.** Fail-closed: the health-panel chain reads surface a typed
//!   `DesktopError` (the UX shows "unavailable / not set up") rather than
//!   fabricating a state.
//! - **L4.** Handle-bearing commands are session-gated FFI-side.
//!
//! Chain reads (`recovery_health`) run via `spawn_blocking` (the FFI drives
//! a nested current-thread runtime that would panic inline — same trap as
//! the pairing chain commands). `recovery_create_backup` is local crypto
//! (no chain) and runs inline.

#![forbid(unsafe_code)]
// Documented recovery module; doc-style pedantic lints allowed at module
// level, matching commands/pairing.rs. Substantive lints stay enforced.
#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]

use serde::Serialize;
use tauri::State;

use pangolin_ffi::SecretPassword;

use crate::commands::pairing::chain_config;
use crate::error::DesktopError;
use crate::state::VaultState;

/// Lowercase-hex encoder (mirrors commands::account / commands::pairing).
fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// A freshly-created recovery backup. The seed phrase is the ONE secret —
/// the user records it offline; we do NOT store it.
#[derive(Debug, Clone, Serialize)]
pub struct BackupDto {
    /// The 24 BIP-39 words, shown to the user ONCE.
    pub seed_phrase_words: Vec<String>,
    /// The encrypted envelope, byte form (save to a file / QR).
    pub bytes: Vec<u8>,
    /// The encrypted envelope, copy-paste text form.
    pub text: String,
}

impl From<pangolin_ffi::FfiBackup> for BackupDto {
    fn from(b: pangolin_ffi::FfiBackup) -> Self {
        Self {
            seed_phrase_words: b.seed_phrase_words,
            bytes: b.bytes,
            text: b.text,
        }
    }
}

/// Read-only recovery-health summary for THIS vault.
#[derive(Debug, Clone, Serialize)]
pub struct RecoveryHealthDto {
    /// 40-char hex of the current on-chain vault authority (the
    /// recovery-control owner); all-zero / empty when none is set.
    pub authority: String,
    /// 0=None, 1=Pending, 2=Finalized, 3=Canceled (`FfiRecoveryStatus`).
    pub recovery_status: u8,
    /// 40-char hex of the proposed authority of an in-flight recovery, if
    /// any (empty otherwise).
    pub proposed_authority: String,
    /// The in-flight attempt nonce (0 when none).
    pub attempt_nonce: u64,
}

/// **Create a recovery backup** — generate the 24-word seed phrase + the
/// encrypted envelope. Local crypto (no chain). Requires guardians to have
/// been onboarded first (else the FFI returns a Validation error). The
/// phrase is shown ONCE + never stored.
///
/// # Errors
/// `DesktopError::Session` (locked) / `DesktopError::Validation` (no
/// recovery escrow onboarded yet — set up guardians first).
#[tauri::command]
pub async fn recovery_create_backup(
    password: String,
    state: State<'_, VaultState>,
) -> Result<BackupDto, DesktopError> {
    let handle = state.require_open()?;
    let pw = SecretPassword::new(password.into_bytes());
    let backup = pangolin_ffi::vault_create_backup(handle, pw).map_err(DesktopError::from)?;
    Ok(backup.into())
}

/// **Read-only recovery health** for this vault — the current on-chain
/// authority + any in-flight recovery. Chain reads → `spawn_blocking`.
///
/// # Errors
/// `DesktopError::Session` (locked) / `DesktopError::Chain` (the vault is
/// not set up on-chain for recovery, or the read failed — the UX shows
/// "recovery status unavailable").
#[tauri::command]
pub async fn recovery_health(
    state: State<'_, VaultState>,
) -> Result<RecoveryHealthDto, DesktopError> {
    let handle = state.require_open()?;
    let vault_id =
        pangolin_ffi::vault_current_vault_id(handle.clone()).map_err(DesktopError::from)?;
    let config = chain_config()?;
    tokio::task::spawn_blocking(move || {
        let authority = pangolin_ffi::vault_read_vault_authority(
            handle.clone(),
            config.clone(),
            vault_id.clone(),
        )
        .map_err(DesktopError::from)?;
        let status = pangolin_ffi::vault_read_recovery_status(handle, config, vault_id)
            .map_err(DesktopError::from)?;
        Ok::<RecoveryHealthDto, DesktopError>(RecoveryHealthDto {
            authority: hex_encode(&authority.address),
            recovery_status: status.status,
            proposed_authority: hex_encode(&status.proposed_authority),
            attempt_nonce: status.attempt_nonce,
        })
    })
    .await
    .map_err(|e| DesktopError::Internal(format!("recovery-health task join failed: {e}")))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_dto_projects_phrase_and_envelope() {
        let ffi = pangolin_ffi::FfiBackup {
            schema_version: 1,
            bytes: vec![1, 2, 3],
            text: "envelope-text".into(),
            seed_phrase_words: vec!["alpha".into(), "bravo".into()],
        };
        let dto: BackupDto = ffi.into();
        assert_eq!(dto.seed_phrase_words, vec!["alpha", "bravo"]);
        assert_eq!(dto.bytes, vec![1, 2, 3]);
        assert_eq!(dto.text, "envelope-text");
    }

    #[test]
    fn hex_encode_round_trip() {
        assert_eq!(hex_encode(&[0xab, 0xcd]), "abcd");
        assert_eq!(hex_encode(&[]), "");
    }
}
