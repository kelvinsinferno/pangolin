// SPDX-License-Identifier: AGPL-3.0-or-later
//! Test-only command-invocation log + force-unlock for the E2E gates.
//!
//! Compiled in under the test-hooks feature (CI desktop-e2e +
//! extension-e2e jobs enable it; production release builds DO NOT).
//! Records the name of every privileged Tauri command that fires so
//! the E2E suites can assert that H-1 (Rust-side clipboard) held.
//!
//! Plan-LOCKs: docs/issue-plans/mvp4-f-desktop-e2e.md sec 3.2,
//! docs/issue-plans/mvp4-g-extension-e2e.md sec 6.
//!
//! Side-channel (MVP-4-G addition): the MVP-4-F suite reads the
//! invocation log via the `__test__commands_invoked` Tauri command
//! from the renderer; the MVP-4-G Node integration gate drives the
//! popup-side `NativeHostClient` directly (not the rendered popup),
//! so it can NOT reach Tauri commands. To bridge that, `record()`
//! ALSO appends the command name to a file when the env var
//! `PANGOLIN_TEST_HOOKS_LOG_PATH` is set. The integration harness
//! sets that env var to a `TempDir` path before spawning
//! `pangolin-desktop`; specs read the file to assert on H-1.
//!
//! L7: the file contains command NAMES only -- same content as the
//! in-process INVOCATIONS vec; no params, no return values, no
//! secrets.

#![cfg(feature = "test-hooks")]
#![forbid(unsafe_code)]

use std::io::Write;
use std::sync::{Arc, Mutex};

use pangolin_ffi::{PresenceProof, SecretPassword};
use tauri::State;

use crate::error::DesktopError;
use crate::state::VaultState;

const SIDE_CHANNEL_ENV: &str = "PANGOLIN_TEST_HOOKS_LOG_PATH";

static INVOCATIONS: Mutex<Vec<String>> = Mutex::new(Vec::new());

pub fn record(command_name: &'static str) {
    if let Ok(mut g) = INVOCATIONS.lock() {
        g.push(command_name.to_string());
    }
    if let Ok(path) = std::env::var(SIDE_CHANNEL_ENV) {
        if !path.is_empty() {
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
            {
                let _ = writeln!(f, "{command_name}");
                let _ = f.flush();
            }
        }
    }
}

#[allow(non_snake_case)]
#[tauri::command]
pub fn __test__commands_invoked() -> Vec<String> {
    INVOCATIONS.lock().map(|g| g.clone()).unwrap_or_default()
}

#[allow(non_snake_case)]
#[tauri::command]
pub fn __test__clear_invocations() {
    if let Ok(mut g) = INVOCATIONS.lock() {
        g.clear();
    }
}

#[allow(non_snake_case)]
#[tauri::command]
pub async fn __test__force_unlock(
    path: String,
    password: String,
    state: State<'_, VaultState>,
) -> Result<(), DesktopError> {
    let handle = pangolin_ffi::session::vault_open(path).map_err(DesktopError::from)?;
    state.install(Arc::clone(&handle))?;
    let secret = SecretPassword::new(password.into_bytes());
    let presence = PresenceProof {
        schema_version: 1,
        bytes: Vec::new(),
    };
    let _ = pangolin_ffi::session::vault_unlock(Arc::clone(&handle), secret, presence)
        .map_err(DesktopError::from)?;
    Ok(())
}

/// **MVP-4-H Layer 4: queue a password for the next secure-input call.**
///
/// Pushes `password` onto the [`crate::secure_input::stub`] queue so the
/// next `*_via_secure_prompt` invocation pops it out instead of spawning
/// the OS native dialog. The wdio harness calls this immediately BEFORE
/// clicking the `SecurePasswordButton` for a flow it needs to drive.
///
/// **L1 (secret hygiene):** the `String` is consumed into bytes by
/// [`crate::secure_input::stub::inject`] (`String::into_bytes()` is a
/// move, not a copy); the original `String` drops at the end of this
/// function body. The bytes live in the stub queue inside a `Vec<u8>`,
/// which the [`crate::secure_input::stub::pop_one`] consumer wraps in
/// `Zeroizing<Vec<u8>>` before returning. This matches the per-OS
/// widget hygiene posture (Layer 1 invariant L1).
///
/// **Cfg:** gated on `feature = "secure-input-stub"` (in addition to
/// the file-level `feature = "test-hooks"`) because the stub module
/// itself only compiles in when the stub feature is on. Calling this
/// in a build that has `test-hooks` but NOT `secure-input-stub` (the
/// Layer-5 OS-automation integration build) would be a no-op anyway —
/// the real per-OS widget is the input source, the stub queue is
/// nonexistent.
#[cfg(feature = "secure-input-stub")]
#[allow(non_snake_case)]
#[tauri::command]
pub fn __test__secure_input_inject(password: String) {
    crate::secure_input::stub::inject(password);
}

/// **MVP-4-H Layer 4: drain the secure-input stub queue.**
///
/// Called between wdio specs so a leaked previously-queued password
/// doesn't bleed into the next test. Idempotent (clearing an empty
/// queue is a no-op). Same `secure-input-stub` feature gate as the
/// inject command above.
#[cfg(feature = "secure-input-stub")]
#[allow(non_snake_case)]
#[tauri::command]
pub fn __test__secure_input_clear() {
    crate::secure_input::stub::clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn record_and_read_round_trip() {
        __test__clear_invocations();
        record("smoke_test_record");
        let entries = __test__commands_invoked();
        assert!(
            entries.iter().any(|s| s == "smoke_test_record"),
            "expected smoke_test_record in {entries:?}",
        );
    }

    #[test]
    fn clear_empties_the_log() {
        record("pre_clear_marker");
        __test__clear_invocations();
        let entries = __test__commands_invoked();
        assert!(
            !entries.iter().any(|s| s == "pre_clear_marker"),
            "expected log cleared but found pre_clear_marker in {entries:?}",
        );
    }

    #[test]
    fn side_channel_writes_to_env_pointed_file() {
        let tmp = TempDir::new().expect("tmp");
        let log = tmp.path().join("hooks.log");
        std::env::set_var(SIDE_CHANNEL_ENV, &log);
        record("side_channel_smoke");
        std::env::remove_var(SIDE_CHANNEL_ENV);
        let body = std::fs::read_to_string(&log).expect("log file written");
        assert!(
            body.lines().any(|l| l == "side_channel_smoke"),
            "expected side_channel_smoke in {body:?}",
        );
    }
}
