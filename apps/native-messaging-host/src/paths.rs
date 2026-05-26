// SPDX-License-Identifier: AGPL-3.0-or-later
//! Per-OS path resolution for the handshake token + IPC socket/pipe +
//! native-messaging manifest install locations.
//!
//! All paths follow Chrome's per-user (no-admin) convention. See plan
//! §3.3 + §3.4. The `home_override` parameter on each helper exists so
//! tests can drive the install/uninstall round-trip against a tempdir
//! without poisoning the developer's real `$HOME`.

#![forbid(unsafe_code)]

use std::path::PathBuf;

/// Service / account names for the OS keychain entry. Re-exported so
/// the desktop's install code uses identical strings (any drift
/// between writer + reader would mean the host can't load the token).
pub const KEYRING_SERVICE: &str = "studio.kelvinsinferno.pangolin";
pub const KEYRING_ACCOUNT: &str = "native-messaging-host-token";

/// Native-messaging host name. MUST match the extension's
/// `chrome.runtime.connectNative('<this name>')` argument AND the
/// `name` field inside every manifest JSON file the install code
/// writes.
pub const HOST_NAME: &str = "studio.kelvinsinferno.pangolin.host";

/// Per-user data directory.
///
/// - Linux: `$XDG_DATA_HOME/pangolin` (defaults to `~/.local/share/pangolin`).
/// - macOS: `~/Library/Application Support/Pangolin`.
/// - Windows: `%APPDATA%\Pangolin`.
///
/// The `home_override` parameter is the test-mode entry point: when
/// `Some(p)`, treat `p` as the user's HOME / APPDATA / Library root.
#[must_use]
pub fn pangolin_data_dir(home_override: Option<&std::path::Path>) -> PathBuf {
    if let Some(home) = home_override {
        // For hermetic test use, `home_override` is treated as a
        // generic user-data root. We DO NOT branch on OS inside the
        // test path — tests must work cross-platform on the CI matrix.
        return home.join("Pangolin");
    }
    #[cfg(target_os = "windows")]
    {
        if let Some(appdata) = std::env::var_os("APPDATA") {
            return PathBuf::from(appdata).join("Pangolin");
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join("Library/Application Support/Pangolin");
        }
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Some(xdg) = std::env::var_os("XDG_DATA_HOME") {
            return PathBuf::from(xdg).join("pangolin");
        }
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(".local/share/pangolin");
        }
    }
    // Final fallback — relative path. Should never fire on a normal
    // workstation; if it does the install code surfaces a clear error
    // up the stack.
    PathBuf::from("pangolin")
}

/// Sibling-file fallback path for the handshake token (per plan §3.4).
///
/// On Unix the install code chmods this to 0600; on Windows the
/// default user-only DACL applies (the file lives under
/// `%APPDATA%\Pangolin\` which the OS already restricts to the
/// account owner).
#[must_use]
pub fn token_file_path(home_override: Option<&std::path::Path>) -> PathBuf {
    pangolin_data_dir(home_override).join("native-host-token")
}

/// Per-user IPC channel path (named-pipe on Win; Unix-domain-socket
/// elsewhere).
///
/// Per plan §0a:
///
/// - Linux: `$XDG_RUNTIME_DIR/pangolin/native-host.sock`
///   (falls back to `pangolin_data_dir()/native-host.sock` if
///   `$XDG_RUNTIME_DIR` is unset).
/// - macOS: `pangolin_data_dir()/native-host.sock`.
/// - Windows: `\\.\pipe\studio.kelvinsinferno.pangolin\<user>`. The
///   `<user>` segment is the current `USERNAME` env var; the
///   per-user-pipe + same-EUID-only ACL is what the OS enforces by
///   default when creating a pipe with no explicit security
///   descriptor.
#[must_use]
pub fn ipc_channel_path(home_override: Option<&std::path::Path>) -> PathBuf {
    if let Some(home) = home_override {
        // For test mode we always use a file path (UDS-style) so
        // hermetic tests don't need OS-specific pipe naming.
        return home.join("native-host.sock");
    }
    #[cfg(target_os = "windows")]
    {
        let user = std::env::var("USERNAME").unwrap_or_else(|_| "default".to_string());
        PathBuf::from(format!(r"\\.\pipe\studio.kelvinsinferno.pangolin\{user}"))
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR") {
            return PathBuf::from(runtime)
                .join("pangolin")
                .join("native-host.sock");
        }
        pangolin_data_dir(None).join("native-host.sock")
    }
    #[cfg(target_os = "macos")]
    {
        pangolin_data_dir(None).join("native-host.sock")
    }
}

/// Manifest file names for the four Chromium-family browsers.
///
/// All four manifests share the same JSON body (the `name` is
/// [`HOST_NAME`]); only the install path differs. Returns
/// `(browser_label, install_path)` pairs.
///
/// The `home_override` parameter is for tests; when `None`, real
/// per-OS paths are returned per plan §3.3.
#[must_use]
pub fn browser_manifest_paths(
    home_override: Option<&std::path::Path>,
) -> Vec<(&'static str, PathBuf)> {
    let filename = format!("{HOST_NAME}.json");
    let mut out: Vec<(&'static str, PathBuf)> = Vec::with_capacity(4);

    if let Some(home) = home_override {
        // Test mode: synthesize per-browser dirs under `home` so the
        // round-trip test can assert all four landed without
        // depending on the host OS.
        out.push((
            "chrome",
            home.join("chrome")
                .join("NativeMessagingHosts")
                .join(&filename),
        ));
        out.push((
            "chromium",
            home.join("chromium")
                .join("NativeMessagingHosts")
                .join(&filename),
        ));
        out.push((
            "brave",
            home.join("brave")
                .join("NativeMessagingHosts")
                .join(&filename),
        ));
        out.push((
            "edge",
            home.join("edge")
                .join("NativeMessagingHosts")
                .join(&filename),
        ));
        return out;
    }

    #[cfg(target_os = "linux")]
    {
        if let Some(home) = std::env::var_os("HOME") {
            let home = PathBuf::from(home);
            out.push((
                "chrome",
                home.join(".config/google-chrome/NativeMessagingHosts")
                    .join(&filename),
            ));
            out.push((
                "chromium",
                home.join(".config/chromium/NativeMessagingHosts")
                    .join(&filename),
            ));
            out.push((
                "brave",
                home.join(".config/BraveSoftware/Brave-Browser/NativeMessagingHosts")
                    .join(&filename),
            ));
            out.push((
                "edge",
                home.join(".config/microsoft-edge/NativeMessagingHosts")
                    .join(&filename),
            ));
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Some(home) = std::env::var_os("HOME") {
            let home = PathBuf::from(home);
            let base = home.join("Library/Application Support");
            out.push((
                "chrome",
                base.join("Google/Chrome/NativeMessagingHosts")
                    .join(&filename),
            ));
            out.push((
                "chromium",
                base.join("Chromium/NativeMessagingHosts").join(&filename),
            ));
            out.push((
                "brave",
                base.join("BraveSoftware/Brave-Browser/NativeMessagingHosts")
                    .join(&filename),
            ));
            out.push((
                "edge",
                base.join("Microsoft Edge/NativeMessagingHosts")
                    .join(&filename),
            ));
        }
    }
    #[cfg(target_os = "windows")]
    {
        // Per plan §3.3 the Windows install uses the registry, but the
        // JSON manifest still lives on disk; we put it under
        // `%APPDATA%\Pangolin\native-host\manifest-<browser>.json`. The
        // CLI's install path writes the registry value separately (see
        // commands/install_native_host.rs in the desktop crate).
        let base = pangolin_data_dir(None).join("native-host");
        out.push(("chrome", base.join(format!("manifest-chrome-{filename}"))));
        out.push((
            "chromium",
            base.join(format!("manifest-chromium-{filename}")),
        ));
        out.push(("brave", base.join(format!("manifest-brave-{filename}"))));
        out.push(("edge", base.join(format!("manifest-edge-{filename}"))));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn pangolin_data_dir_uses_override() {
        let tmp = TempDir::new().expect("tmp");
        let p = pangolin_data_dir(Some(tmp.path()));
        assert!(p.ends_with("Pangolin"));
        assert!(p.starts_with(tmp.path()));
    }

    #[test]
    fn token_file_path_is_under_data_dir() {
        let tmp = TempDir::new().expect("tmp");
        let token = token_file_path(Some(tmp.path()));
        let data = pangolin_data_dir(Some(tmp.path()));
        assert!(token.starts_with(&data));
        assert!(token.ends_with("native-host-token"));
    }

    #[test]
    fn ipc_channel_path_in_test_mode_is_a_file() {
        let tmp = TempDir::new().expect("tmp");
        let p = ipc_channel_path(Some(tmp.path()));
        assert!(p.starts_with(tmp.path()));
        assert!(p.ends_with("native-host.sock"));
    }

    #[test]
    fn browser_manifest_paths_in_test_mode_returns_four() {
        let tmp = TempDir::new().expect("tmp");
        let paths = browser_manifest_paths(Some(tmp.path()));
        assert_eq!(paths.len(), 4);
        let labels: Vec<&str> = paths.iter().map(|(l, _)| *l).collect();
        assert!(labels.contains(&"chrome"));
        assert!(labels.contains(&"chromium"));
        assert!(labels.contains(&"brave"));
        assert!(labels.contains(&"edge"));
        // Filename is host-name suffixed with .json.
        for (_, p) in &paths {
            let name = p.file_name().unwrap().to_string_lossy().into_owned();
            assert!(
                name.ends_with(&format!("{HOST_NAME}.json")),
                "filename {name} should end with the host-name JSON"
            );
        }
    }
}
