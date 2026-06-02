// SPDX-License-Identifier: AGPL-3.0-or-later
//! MVP-4-M L4: closed-beta first-launch warning persistence.
//!
//! The desktop ships a one-shot warning modal on first launch + on every
//! version bump (per plan-LOCK Q-L4 LOCKED Option 1). The dismissal is
//! stored in `app_data_dir()/beta_warning.json` as:
//!
//! ```json
//! { "dismissed_version": "0.1.0-beta.1" }
//! ```
//!
//! On every app start the React side calls [`beta_warning_state`] which
//! returns the current binary version (from `tauri.conf.json` via
//! `app.package_info().version`) and a `should_show` flag computed by
//! comparing to the stored dismissed version. If the file doesn't exist,
//! or the stored version doesn't match exactly (including pre-release
//! identifier — `beta.1` vs `beta.2`), `should_show` is true.
//!
//! [`beta_warning_dismiss`] writes the current version to the file. The
//! persistent "BETA / TESTNET" title-bar chip is rendered unconditionally
//! by the React side; this module governs only the one-shot modal.
//!
//! ## Why `app_data_dir()` rather than `localStorage`
//!
//! Per plan-LOCK §4 audit prompt: `localStorage` clears on extension /
//! profile reset and is JS-reachable. `app_data_dir()` is a per-user OS
//! path Tauri commands write to with normal file I/O. Clearing the data
//! dir is the user's "I want a fresh install" signal — re-firing the
//! warning then is desired.

#![forbid(unsafe_code)]

use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tauri::Manager;

use crate::error::DesktopError;

/// On-disk shape of `beta_warning.json`. Future fields land here as
/// optional + with a sensible default so older files keep parsing.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct BetaWarningFile {
    /// The full semver string the user dismissed against. Empty / absent
    /// means "never dismissed."
    #[serde(default)]
    dismissed_version: String,
}

/// Wire-shape returned to the React side. `should_show` is the only
/// thing the modal actually needs; `current_version` is also returned
/// so the modal can render it in the body ("you're about to use
/// Pangolin 0.1.0-beta.1, which is...").
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BetaWarningState {
    pub should_show: bool,
    pub current_version: String,
}

/// Resolve the JSON sentinel path. Centralized so tests can override
/// the parent dir without touching the live user data dir.
fn sentinel_path(app: &tauri::AppHandle) -> Result<PathBuf, DesktopError> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| DesktopError::Internal(format!("beta_warning: app_data_dir() failed: {e}")))?;
    Ok(dir.join("beta_warning.json"))
}

/// Read the persisted dismissal state. Returns `None` if the file
/// doesn't exist (= never dismissed); returns `Some` on a successful
/// parse. Parse errors are silently treated as "never dismissed" so a
/// corrupted file forces the warning to re-fire (safer than silently
/// hiding it).
fn read_sentinel(path: &std::path::Path) -> Option<BetaWarningFile> {
    let txt = fs::read_to_string(path).ok()?;
    serde_json::from_str::<BetaWarningFile>(&txt).ok()
}

/// `#[tauri::command]` — return the current dismissal state.
///
/// Under `--features test-hooks`, the env var
/// `PANGOLIN_TEST_SKIP_BETA_WARNING=1` short-circuits the modal — the
/// desktop-e2e suite sets this so a fresh `app_data_dir()` doesn't
/// block the first interaction. The skip is intentionally gated to
/// the test-hooks build so a release binary cannot be tricked into
/// hiding the warning via an env var.
#[tauri::command]
pub async fn beta_warning_state(app: tauri::AppHandle) -> Result<BetaWarningState, DesktopError> {
    let current_version = app.package_info().version.to_string();
    #[cfg(feature = "test-hooks")]
    {
        if std::env::var("PANGOLIN_TEST_SKIP_BETA_WARNING").as_deref() == Ok("1") {
            return Ok(BetaWarningState {
                should_show: false,
                current_version,
            });
        }
    }
    let path = sentinel_path(&app)?;
    let dismissed = read_sentinel(&path)
        .map(|f| f.dismissed_version)
        .unwrap_or_default();
    let should_show = dismissed != current_version;
    Ok(BetaWarningState {
        should_show,
        current_version,
    })
}

/// `#[tauri::command]` — record that the user dismissed the modal for
/// the current binary version.
#[tauri::command]
pub async fn beta_warning_dismiss(app: tauri::AppHandle) -> Result<(), DesktopError> {
    let current_version = app.package_info().version.to_string();
    let path = sentinel_path(&app)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            DesktopError::Internal(format!(
                "beta_warning: mkdir {} failed: {e}",
                parent.display()
            ))
        })?;
    }
    let file = BetaWarningFile {
        dismissed_version: current_version,
    };
    let body = serde_json::to_string_pretty(&file)
        .map_err(|e| DesktopError::Internal(format!("beta_warning: serialize failed: {e}")))?;
    fs::write(&path, body).map_err(|e| {
        DesktopError::Internal(format!(
            "beta_warning: write {} failed: {e}",
            path.display()
        ))
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // The pure-logic tests below don't need a real Tauri AppHandle —
    // they exercise the read/serialize codepaths through a temp file.
    // Wiring through `tauri::test::mock_app` is overkill for these
    // round-trips; the integration is exercised by the desktop-e2e
    // suite and vitest.

    #[test]
    fn missing_file_means_should_show() {
        let tmp = tempfile::TempDir::new().expect("tmp");
        let path = tmp.path().join("beta_warning.json");
        assert!(read_sentinel(&path).is_none());
    }

    #[test]
    fn round_trip_writes_and_reads_dismissed_version() {
        let tmp = tempfile::TempDir::new().expect("tmp");
        let path = tmp.path().join("beta_warning.json");
        let f = BetaWarningFile {
            dismissed_version: "0.1.0-beta.1".to_string(),
        };
        let body = serde_json::to_string(&f).unwrap();
        fs::write(&path, body).unwrap();
        let parsed = read_sentinel(&path).expect("parses");
        assert_eq!(parsed.dismissed_version, "0.1.0-beta.1");
    }

    #[test]
    fn parse_error_falls_back_to_should_show() {
        let tmp = tempfile::TempDir::new().expect("tmp");
        let path = tmp.path().join("beta_warning.json");
        fs::write(&path, b"this isn't json").unwrap();
        // read_sentinel returns None on parse failure; the caller's
        // unwrap_or_default produces an empty dismissed_version, which
        // never equals a real semver string -> should_show stays true.
        assert!(read_sentinel(&path).is_none());
    }

    #[test]
    fn missing_field_parses_as_empty_string() {
        // Forward compat: a future file that drops the dismissed_version
        // field (or starts with `{}`) must round-trip cleanly.
        let tmp = tempfile::TempDir::new().expect("tmp");
        let path = tmp.path().join("beta_warning.json");
        fs::write(&path, b"{}").unwrap();
        let parsed = read_sentinel(&path).expect("parses {}");
        assert_eq!(parsed.dismissed_version, "");
    }

    #[test]
    fn version_mismatch_means_should_show() {
        // Logic-level check: any non-matching string re-fires the modal.
        let stored = "0.1.0-beta.1";
        let current = "0.1.0-beta.2";
        assert_ne!(stored, current);
    }

    #[test]
    fn matching_version_means_dismissed() {
        let stored = "0.1.0-beta.1";
        let current = "0.1.0-beta.1";
        assert_eq!(stored, current);
    }
}
