// SPDX-License-Identifier: AGPL-3.0-or-later
//! `install-native-host` / `uninstall-native-host` subcommands +
//! Tauri commands.
//!
//! Per MVP-4-E plan §1 — this slice ships a CLI subcommand on the
//! `pangolin-desktop` binary that the eventual first-run wizard will
//! call. The end-to-end install path:
//!
//! 1. Generate a random 32-byte handshake token via
//!    `pangolin_crypto::rng::fill_random`.
//! 2. Store the token (base64url no-pad) in the OS keychain via
//!    `keyring` AND write a sibling-file fallback under the per-OS
//!    user data dir.
//! 3. Write the native-messaging manifest JSON at the per-user
//!    Chrome/Chromium/Brave/Edge locations (Linux + macOS) OR
//!    `%APPDATA%\Pangolin\native-host\` (Windows; the registry value
//!    write is delegated to the install-wizard's Windows-only branch
//!    in a follow-on slice).
//!
//! Uninstall reverses each step (idempotent: missing files / missing
//! keychain entries are not an error).
//!
//! ## Extension ID
//!
//! The manifest's `allowed_origins` field gates which Chromium
//! extension is allowed to spawn the host. The actual extension ID
//! lands at MVP-4-G when the extension is loaded; this slice writes
//! a documented placeholder. **MUST be replaced before closed beta**;
//! the placeholder is intentionally an invalid 32-char a/z string so
//! a real install attempt by a user produces a clean "extension not
//! allowed" error from Chrome rather than silently working.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use zeroize::Zeroize;

use pangolin_native_messaging_host::manifest::{
    install_manifests, uninstall_manifests, InstallOutcome, PLACEHOLDER_EXTENSION_ID,
};
use pangolin_native_messaging_host::paths::{token_file_path, KEYRING_ACCOUNT, KEYRING_SERVICE};

use crate::error::DesktopError;

/// Token length per plan §3.4.
const TOKEN_LEN: usize = 32;

/// Outcome of an install run.
#[derive(Debug, Clone)]
pub struct InstallReport {
    pub token_written_keychain: bool,
    pub token_written_file: bool,
    pub token_file_path: PathBuf,
    pub manifests: Vec<InstallOutcome>,
}

/// Outcome of an uninstall run.
#[derive(Debug, Clone)]
pub struct UninstallReport {
    pub token_removed_keychain: bool,
    pub token_removed_file: bool,
    pub manifests: Vec<InstallOutcome>,
}

/// Run the install path.
///
/// `binary_path` is the absolute filesystem path to the
/// `pangolin-native-messaging-host` binary; the install code writes
/// this into every per-browser manifest's `path` field.
///
/// `home_override` is `None` in production; tests pass
/// `Some(temp_dir)` to drive a hermetic round-trip.
///
/// # Errors
///
/// `DesktopError::Internal` for any I/O failure (mkdir, write,
/// keychain set). The error is surfaced as a typed envelope; the
/// callsite (CLI subcommand or future wizard) renders it.
pub fn install(
    binary_path: &Path,
    allowed_extension_ids: &[&str],
    home_override: Option<&Path>,
) -> Result<InstallReport, DesktopError> {
    // Audit MEDIUM M-1 fix (2026-05-26): Windows install is non-
    // functional this slice — Chrome reads native-messaging host
    // locations from `HKCU\Software\<Vendor>\<Product>\
    // NativeMessagingHosts\<host-name>` (registry value), not from
    // disk paths. Writing the manifest JSON file under %APPDATA% is
    // a no-op without the corresponding registry entry. Adding a
    // `winreg` dep + writing the four browsers' registry paths is
    // not in MVP-4-E scope (deferred to MVP-4-G's per-OS installer
    // experience work).
    //
    // Until then: fail fast on Windows with a clear error rather than
    // silently writing dead manifests. This matches the audit's
    // recommended "explicit Internal error" path; closed-beta on
    // Windows is BLOCKED until MVP-4-G ships the registry-write.
    #[cfg(target_os = "windows")]
    {
        // The `home_override` path is taken only by tests; allow
        // the test path through so the round-trip test still
        // exercises the per-platform path resolution code.
        if home_override.is_none() {
            return Err(DesktopError::Internal(
                "Windows install not yet supported — MVP-4-G adds the \
                 Chrome registry write (HKCU\\Software\\...\\NativeMessagingHosts). \
                 Use Linux or macOS for closed beta."
                    .into(),
            ));
        }
    }

    // Generate random 32-byte token via the workspace OsRng
    // chokepoint.
    let mut raw = [0u8; TOKEN_LEN];
    pangolin_crypto::rng::fill_random(&mut raw);
    let b64 = URL_SAFE_NO_PAD.encode(raw);

    // Primary: keychain. Production-mode only; tests skip.
    let token_written_keychain = if home_override.is_none() {
        match keyring::Entry::new(KEYRING_SERVICE, KEYRING_ACCOUNT)
            .and_then(|e| e.set_password(&b64))
        {
            Ok(()) => true,
            Err(_) => false, // not fatal — fallback file is the safety net
        }
    } else {
        false
    };

    // Sibling-file fallback. ALWAYS written so the host has a path
    // that works even in a keyring-agent-locked Chrome subprocess
    // (plan §3.4 rationale).
    let token_file = token_file_path(home_override);
    if let Some(parent) = token_file.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            DesktopError::Internal(format!("mkdir {parent}: {e}", parent = parent.display()))
        })?;
    }
    write_token_file(&token_file, &b64)?;
    let token_written_file = true;

    // Manifests.
    let manifests = install_manifests(binary_path, allowed_extension_ids, home_override);

    // Zero the raw token bytes (the b64 String is dropped at end of
    // scope; we can't zero a `String` without unsafe, so the
    // raw-bytes zero is the discipline we CAN enforce).
    let mut zeroize_buf = raw;
    zeroize_buf.zeroize();

    Ok(InstallReport {
        token_written_keychain,
        token_written_file,
        token_file_path: token_file,
        manifests,
    })
}

/// Run the uninstall path. Idempotent: missing files / missing
/// keychain entries are not an error.
pub fn uninstall(home_override: Option<&Path>) -> Result<UninstallReport, DesktopError> {
    // Keychain entry.
    let token_removed_keychain = if home_override.is_none() {
        keyring::Entry::new(KEYRING_SERVICE, KEYRING_ACCOUNT)
            .and_then(|e| e.delete_credential())
            .is_ok()
    } else {
        false
    };

    // Token file: overwrite with zeros THEN unlink. The overwrite
    // is best-effort (some filesystems COW the original); the unlink
    // is what actually removes the path. Per plan §3.4 the discipline
    // is "zero + unlink" even if the zero is partial protection.
    let token_file = token_file_path(home_override);
    let token_removed_file = match std::fs::metadata(&token_file) {
        Ok(_) => {
            let _ = overwrite_with_zeros(&token_file);
            std::fs::remove_file(&token_file).is_ok()
        }
        Err(_) => false,
    };

    // Manifests.
    let manifests = uninstall_manifests(home_override);

    Ok(UninstallReport {
        token_removed_keychain,
        token_removed_file,
        manifests,
    })
}

fn write_token_file(path: &Path, b64: &str) -> Result<(), DesktopError> {
    // Plain write first.
    std::fs::write(path, b64.as_bytes())
        .map_err(|e| DesktopError::Internal(format!("write token: {e}")))?;

    // Tighten the mode to 0600 on Unix.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        let _ = std::fs::set_permissions(path, perms);
    }
    Ok(())
}

fn overwrite_with_zeros(path: &Path) -> Result<(), std::io::Error> {
    let len = std::fs::metadata(path)?.len();
    let len_usize = usize::try_from(len).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "token file too large")
    })?;
    let zeros = vec![0u8; len_usize];
    std::fs::write(path, zeros)
}

/// `#[tauri::command]` wrapper for the install path.
///
/// The React UI's first-run wizard (MVP-4-G) calls this. The current
/// implementation passes the [`PLACEHOLDER_EXTENSION_ID`]; once the
/// extension is loaded in MVP-4-G, the wizard will prompt the user
/// for the real ID and forward it through this command.
#[tauri::command]
pub async fn install_native_host(binary_path: String) -> Result<(), DesktopError> {
    let path = std::path::PathBuf::from(binary_path);
    install(&path, &[PLACEHOLDER_EXTENSION_ID], None)?;
    Ok(())
}

/// `#[tauri::command]` wrapper for uninstall.
#[tauri::command]
pub async fn uninstall_native_host() -> Result<(), DesktopError> {
    uninstall(None)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn install_round_trip_lands_manifests_and_token() {
        let tmp = TempDir::new().expect("tmp");
        let bin = tmp.path().join("pangolin-native-messaging-host");
        std::fs::write(&bin, b"#!/bin/sh\n").unwrap();

        let report =
            install(&bin, &[PLACEHOLDER_EXTENSION_ID], Some(tmp.path())).expect("install ok");
        assert!(report.token_written_file);
        assert!(report.token_file_path.exists());
        assert_eq!(report.manifests.len(), 4);
        for m in &report.manifests {
            assert!(m.written, "{:?}", m.error);
            assert!(m.path.exists());
        }

        // The token file contains a valid base64url-no-pad encoding
        // of 32 bytes.
        let txt = std::fs::read_to_string(&report.token_file_path).unwrap();
        let decoded = URL_SAFE_NO_PAD.decode(txt.trim().as_bytes()).expect("b64");
        assert_eq!(decoded.len(), TOKEN_LEN);
    }

    #[test]
    fn uninstall_removes_token_and_manifests_and_is_idempotent() {
        let tmp = TempDir::new().expect("tmp");
        let bin = tmp.path().join("pangolin-native-messaging-host");
        std::fs::write(&bin, b"#!/bin/sh\n").unwrap();

        install(&bin, &[PLACEHOLDER_EXTENSION_ID], Some(tmp.path())).unwrap();
        // Now uninstall.
        let report = uninstall(Some(tmp.path())).expect("uninstall ok");
        assert!(report.token_removed_file);
        let token_file = token_file_path(Some(tmp.path()));
        assert!(!token_file.exists());
        for m in &report.manifests {
            assert!(m.error.is_none());
            assert!(m.written);
            assert!(!m.path.exists());
        }

        // Second uninstall is a no-op.
        let report2 = uninstall(Some(tmp.path())).expect("uninstall idempotent");
        assert!(!report2.token_removed_file);
        for m in &report2.manifests {
            assert!(m.error.is_none());
            assert!(!m.written);
        }
    }

    /// Two install runs in a row produce different tokens (RNG is
    /// pulled from `OsRng` each call).
    #[test]
    fn two_installs_produce_different_tokens() {
        let tmp1 = TempDir::new().expect("tmp1");
        let tmp2 = TempDir::new().expect("tmp2");
        let bin = tmp1.path().join("pangolin-native-messaging-host");
        std::fs::write(&bin, b"#!/bin/sh\n").unwrap();
        install(&bin, &[PLACEHOLDER_EXTENSION_ID], Some(tmp1.path())).unwrap();
        install(&bin, &[PLACEHOLDER_EXTENSION_ID], Some(tmp2.path())).unwrap();

        let t1 = std::fs::read_to_string(token_file_path(Some(tmp1.path()))).unwrap();
        let t2 = std::fs::read_to_string(token_file_path(Some(tmp2.path()))).unwrap();
        assert_ne!(t1.trim(), t2.trim(), "two installs produced same token");
    }

    /// Plan §3.4: the token file is mode 0600 on Unix.
    #[cfg(unix)]
    #[test]
    fn token_file_is_mode_0600_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().expect("tmp");
        let bin = tmp.path().join("pangolin-native-messaging-host");
        std::fs::write(&bin, b"#!/bin/sh\n").unwrap();
        install(&bin, &[PLACEHOLDER_EXTENSION_ID], Some(tmp.path())).unwrap();
        let token_file = token_file_path(Some(tmp.path()));
        let mode = std::fs::metadata(&token_file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "token file should be 0600, got {mode:o}");
    }

    /// Plan §3.4: the manifest is JSON with the documented Chrome
    /// required-fields shape.
    #[test]
    fn manifest_has_chrome_required_fields() {
        let tmp = TempDir::new().expect("tmp");
        let bin = tmp.path().join("pangolin-native-messaging-host");
        std::fs::write(&bin, b"#!/bin/sh\n").unwrap();
        let report = install(&bin, &[PLACEHOLDER_EXTENSION_ID], Some(tmp.path())).unwrap();
        for m in &report.manifests {
            let txt = std::fs::read_to_string(&m.path).unwrap();
            let v: serde_json::Value = serde_json::from_str(&txt).unwrap();
            assert!(v["name"].is_string());
            assert!(v["description"].is_string());
            assert!(v["path"].is_string());
            assert_eq!(v["type"], "stdio");
            assert!(v["allowed_origins"].is_array());
        }
    }
}
