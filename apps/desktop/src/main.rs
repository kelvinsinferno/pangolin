// SPDX-License-Identifier: AGPL-3.0-or-later
//! Binary entry for .
//!
//! Thin shim that dispatches between:
//!
//! - the regular Tauri UI launch (no subcommand, the default),
//! - the  CLI subcommand which writes the
//!   native-messaging manifests + token AND prints the token to
//!   stdout for the user to paste into the extension popup (per
//!   MVP-4-G plan-LOCK section 3.2 Q-a Option 1),
//! - the  CLI subcommand which reverses the
//!   install path.
//!
//! The
//! attribute keeps a release build from popping a console window on
//! Windows for the Tauri UI launch; the CLI subcommands always run
//! against a debug build (-spawned) so the subsystem
//! attribute does not constrain stdout there either.

#![forbid(unsafe_code)]
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use pangolin_native_messaging_host::manifest::PLACEHOLDER_EXTENSION_ID;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    // args[0] is the binary path; args[1] is the optional subcommand.
    match args.get(1).map(String::as_str) {
        Some("install-native-host") => run_install(&args),
        Some("uninstall-native-host") => run_uninstall(),
        _ => {
            pangolin_desktop_lib::build_app()
                .run(tauri::generate_context!())
                .expect("error while running pangolin-desktop");
        }
    }
}

/// Run the install subcommand.
///
/// Optional positional argument: the absolute path to the
///  binary. Defaults to the path
/// alongside this very binary (CWD/pangolin-native-messaging-host).
///
/// Optional flag:  (repeatable). When
/// omitted, the placeholder ID baked into the host crate is used --
/// suitable for tests but NOT for production installs (the install
/// MUST be re-run with the real extension ID before any non-test
/// extension can actually talk to the host; Chrome will refuse
///  from any extension whose id is
/// not in ).
///
/// Prints the generated 32-byte token (URL-safe base64, no padding)
/// to stdout as  so the user can paste it into
/// the extension popup. Per MVP-4-G plan-LOCK section 3.2 Q-a
/// Option 1.
fn run_install(args: &[String]) {
    // Parse positional binary path + repeatable --allowed-extension-id.
    let mut bin_path: Option<std::path::PathBuf> = None;
    let mut allowed: Vec<String> = Vec::new();
    let mut i = 2;
    while i < args.len() {
        let a = &args[i];
        if a == "--allowed-extension-id" {
            i += 1;
            if i < args.len() {
                allowed.push(args[i].clone());
            } else {
                eprintln!("install-native-host: --allowed-extension-id requires a value");
                std::process::exit(2);
            }
        } else if bin_path.is_none() {
            bin_path = Some(std::path::PathBuf::from(a));
        } else {
            eprintln!("install-native-host: unexpected positional argument: {a}");
            std::process::exit(2);
        }
        i += 1;
    }
    let bin = bin_path.unwrap_or_else(default_host_binary_path);
    if !bin.exists() {
        eprintln!(
            "install-native-host: host binary not found at {} -- pass an absolute path as the first positional arg",
            bin.display(),
        );
        std::process::exit(2);
    }
    let owned: Vec<String> = if allowed.is_empty() {
        vec![PLACEHOLDER_EXTENSION_ID.to_string()]
    } else {
        allowed
    };
    let ids_ref: Vec<&str> = owned.iter().map(String::as_str).collect();
    match pangolin_desktop_lib::commands::install_native_host::install(&bin, &ids_ref, None) {
        Ok(report) => {
            // Print the token to stdout. We read it back from the
            // sibling file the install just wrote so the binary path
            // remains the single source of truth.
            match std::fs::read_to_string(&report.token_file_path) {
                Ok(b64) => {
                    // Validate the base64 we are about to print
                    // decodes to 32 bytes (defence in depth -- the
                    // install path already wrote a valid token).
                    let trimmed = b64.trim();
                    let ok = URL_SAFE_NO_PAD
                        .decode(trimmed.as_bytes())
                        .map(|v| v.len() == 32)
                        .unwrap_or(false);
                    if !ok {
                        eprintln!("install-native-host: token file did not contain a 32-byte base64url value");
                        std::process::exit(1);
                    }
                    println!("EXTENSION_TOKEN={trimmed}");
                    eprintln!(
                        "install-native-host: wrote token to {} and {} manifests",
                        report.token_file_path.display(),
                        report.manifests.len(),
                    );
                }
                Err(e) => {
                    eprintln!("install-native-host: failed to read back token file: {e}");
                    std::process::exit(1);
                }
            }
        }
        Err(e) => {
            eprintln!("install-native-host: {e:?}");
            std::process::exit(1);
        }
    }
}

/// Run the uninstall subcommand.
fn run_uninstall() {
    match pangolin_desktop_lib::commands::install_native_host::uninstall(None) {
        Ok(report) => {
            eprintln!(
                "uninstall-native-host: removed token={} manifests={}",
                report.token_removed_file,
                report.manifests.iter().filter(|m| m.written).count(),
            );
        }
        Err(e) => {
            eprintln!("uninstall-native-host: {e:?}");
            std::process::exit(1);
        }
    }
}

/// Default path to the native-messaging-host binary: alongside this
///  binary.
fn default_host_binary_path() -> std::path::PathBuf {
    let mut p = std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("."));
    p.pop();
    p.push("pangolin-native-messaging-host");
    #[cfg(windows)]
    p.set_extension("exe");
    p
}
