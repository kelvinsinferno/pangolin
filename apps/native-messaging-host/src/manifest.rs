// SPDX-License-Identifier: AGPL-3.0-or-later
//! Native-messaging manifest JSON shape + per-browser install helpers.
//!
//! Chrome's native-messaging protocol expects each browser to have a
//! JSON manifest at a per-OS, per-browser path. The body shape is
//! fixed by Chrome's protocol — `name` / `description` / `path` /
//! `type` / `allowed_origins` are the five required fields.
//!
//! Reference: <https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging#native-messaging-host-location>
//!
//! This module is shared by:
//!
//! - the desktop's `install-native-host` CLI subcommand (writes the
//!   manifests),
//! - the desktop's `uninstall-native-host` CLI subcommand (deletes
//!   them),
//! - and the host binary's own `--install` / `--uninstall` flags (if
//!   ever wired; not in MVP-4-E scope).

#![forbid(unsafe_code)]

use std::path::Path;

use serde_json::{json, Value};

use crate::paths::{browser_manifest_paths, HOST_NAME};

/// Placeholder extension ID baked into the manifest until MVP-4-G
/// lands the actual id.
///
/// The Chromium MV3 extension's id is only known once it's loaded
/// (unpacked: random GUID; published: keyed off the manifest's
/// `key` field). MVP-4-G is the slice that loads the extension end-to-
/// end + finalises the id; this slice writes a documented placeholder
/// + a code comment that flags the upgrade path.
pub const PLACEHOLDER_EXTENSION_ID: &str = "abcdefghijklmnopabcdefghijklmnop";

/// Build the manifest JSON body for a given absolute path to the
/// `pangolin-native-messaging-host` binary + a list of allowed
/// extension IDs (Chrome accepts multiple — first match wins).
#[must_use]
pub fn manifest_body(binary_path: &Path, allowed_extension_ids: &[&str]) -> Value {
    let allowed_origins: Vec<String> = allowed_extension_ids
        .iter()
        .map(|id| format!("chrome-extension://{id}/"))
        .collect();
    json!({
        "name": HOST_NAME,
        "description": "Pangolin desktop \u{2194} extension bridge",
        "path": binary_path.to_string_lossy().into_owned(),
        "type": "stdio",
        "allowed_origins": allowed_origins,
    })
}

/// Outcome of a per-browser install attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallOutcome {
    pub browser: &'static str,
    pub path: std::path::PathBuf,
    pub written: bool,
    pub error: Option<String>,
}

/// Write the manifest to every Chromium-family per-user location.
///
/// Returns per-browser outcomes; the caller (the install CLI) prints
/// a summary table. Idempotent: re-running overwrites.
///
/// `home_override = Some(temp)` drives the hermetic-test path.
pub fn install_manifests(
    binary_path: &Path,
    allowed_extension_ids: &[&str],
    home_override: Option<&Path>,
) -> Vec<InstallOutcome> {
    let body = manifest_body(binary_path, allowed_extension_ids);
    let body_str = serde_json::to_string_pretty(&body).expect("serde_json never fails on Value");
    let paths = browser_manifest_paths(home_override);
    paths
        .into_iter()
        .map(|(browser, path)| match write_manifest(&path, &body_str) {
            Ok(()) => InstallOutcome {
                browser,
                path,
                written: true,
                error: None,
            },
            Err(e) => InstallOutcome {
                browser,
                path,
                written: false,
                error: Some(e),
            },
        })
        .collect()
}

/// Delete the manifest from every per-browser location.
///
/// Idempotent: missing files are not an error. Returns one outcome per
/// browser with `written = true` meaning "removed" in this context.
pub fn uninstall_manifests(home_override: Option<&Path>) -> Vec<InstallOutcome> {
    let paths = browser_manifest_paths(home_override);
    paths
        .into_iter()
        .map(|(browser, path)| match remove_manifest(&path) {
            Ok(removed) => InstallOutcome {
                browser,
                path,
                written: removed,
                error: None,
            },
            Err(e) => InstallOutcome {
                browser,
                path,
                written: false,
                error: Some(e),
            },
        })
        .collect()
}

fn write_manifest(path: &Path, body: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
    }
    std::fs::write(path, body).map_err(|e| format!("write {}: {e}", path.display()))?;
    Ok(())
}

fn remove_manifest(path: &Path) -> Result<bool, String> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(format!("remove {}: {e}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn manifest_body_shape_pins_chrome_required_fields() {
        let path = Path::new("/usr/local/bin/pangolin-native-messaging-host");
        let body = manifest_body(path, &[PLACEHOLDER_EXTENSION_ID]);

        assert_eq!(body["name"], HOST_NAME);
        assert_eq!(body["type"], "stdio");
        assert!(body["description"].is_string());
        assert!(body["path"].is_string());
        assert!(body["allowed_origins"].is_array());
        assert_eq!(body["allowed_origins"].as_array().unwrap().len(), 1);
        assert_eq!(
            body["allowed_origins"][0],
            format!("chrome-extension://{PLACEHOLDER_EXTENSION_ID}/")
        );
    }

    #[test]
    fn install_writes_four_browser_manifests() {
        let tmp = TempDir::new().expect("tmp");
        let bin = tmp.path().join("pangolin-native-messaging-host");
        std::fs::write(&bin, b"#!/bin/sh\n").unwrap();

        let outcomes = install_manifests(&bin, &[PLACEHOLDER_EXTENSION_ID], Some(tmp.path()));
        assert_eq!(outcomes.len(), 4);
        for o in &outcomes {
            assert!(
                o.written,
                "browser {} write failed: {:?}",
                o.browser, o.error
            );
            assert!(o.path.exists(), "manifest file missing for {}", o.browser);
            // Each manifest parses back as the documented shape.
            let txt = std::fs::read_to_string(&o.path).unwrap();
            let v: Value = serde_json::from_str(&txt).unwrap();
            assert_eq!(v["name"], HOST_NAME);
            assert_eq!(v["type"], "stdio");
        }
    }

    #[test]
    fn uninstall_after_install_is_idempotent_and_clean() {
        let tmp = TempDir::new().expect("tmp");
        let bin = tmp.path().join("pangolin-native-messaging-host");
        std::fs::write(&bin, b"#!/bin/sh\n").unwrap();
        install_manifests(&bin, &[PLACEHOLDER_EXTENSION_ID], Some(tmp.path()));

        // First uninstall removes all four.
        let outcomes = uninstall_manifests(Some(tmp.path()));
        assert_eq!(outcomes.len(), 4);
        for o in &outcomes {
            assert!(o.error.is_none(), "{:?}", o.error);
            assert!(
                o.written,
                "first uninstall should have removed {}",
                o.browser
            );
            assert!(!o.path.exists());
        }

        // Second uninstall is a no-op (idempotent).
        let outcomes2 = uninstall_manifests(Some(tmp.path()));
        for o in &outcomes2 {
            assert!(o.error.is_none(), "{:?}", o.error);
            assert!(!o.written, "second uninstall should not re-remove");
            assert!(!o.path.exists());
        }
    }

    #[test]
    fn manifest_body_with_multiple_allowed_extension_ids() {
        let path = Path::new("/usr/local/bin/pangolin-native-messaging-host");
        let body = manifest_body(
            path,
            &[
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ],
        );
        let origins = body["allowed_origins"].as_array().unwrap();
        assert_eq!(origins.len(), 2);
        assert_eq!(
            origins[0],
            "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/"
        );
    }
}
