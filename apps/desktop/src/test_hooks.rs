// SPDX-License-Identifier: AGPL-3.0-or-later
//! Test-only command-invocation log for the E2E gate.
//!
//! Compiled in under the `test-hooks` feature (CI's `desktop-e2e` job
//! enables it; production release builds DO NOT). Records the name of
//! every privileged Tauri command that fires so the `WebDriverIO` suite
//! can assert that scenario 5 (`copy_password_via_rust_command`) took
//! the Rust-side clipboard path instead of routing plaintext through
//! V8 (the H-1 invariant from MVP-4-B).
//!
//! Plan-LOCK: docs/issue-plans/mvp4-f-desktop-e2e.md §3.2.
//!
//! L7 (errors carry no secret): the log records command **names** only.
//! No params, no return values, no plaintext. Even with the feature
//! flag accidentally on in a release build the log carries zero
//! privileged data.

#![cfg(feature = "test-hooks")]
#![forbid(unsafe_code)]

use std::sync::Mutex;

/// Process-global log of test-hook command invocations.
///
/// `Mutex<Vec<String>>` is the simplest shape that satisfies the
/// `Send + Sync` requirement Tauri's command dispatcher imposes; the
/// `'static` storage duration matches the lifetime of the desktop
/// process. The mutex is only contended from inside `#[tauri::command]`
/// bodies + the two `__test__*` reader/clearer commands — all of which
/// are async-fn-in-trait dispatched serially on the Tauri runtime.
static INVOCATIONS: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// Push the name of a Tauri command onto the invocation log.
///
/// Called from `commands::account::copy_password_to_clipboard` and
/// `commands::account::reveal_password` (the two privileged-secret
/// flows under E2E assertion). The poisoned-mutex case silently drops
/// the record — the test-hooks log is non-load-bearing for production
/// correctness; failing-closed by losing a record is the right trade.
pub fn record(command_name: &'static str) {
    if let Ok(mut g) = INVOCATIONS.lock() {
        g.push(command_name.to_string());
    }
}

/// Return the full, ordered list of command names that have fired
/// since the process started (or since the last
/// `__test__clear_invocations()` call).
///
/// Exposed as a Tauri command so the `WebDriverIO` spec can read the log
/// via `invoke('__test__commands_invoked')` from the renderer side.
///
/// The double-underscore prefix is a deliberate sentinel marking this
/// as a TEST-ONLY surface — `non_snake_case` is allowed here because
/// the JS-side invoke string is what the spec authors against, and
/// renaming to a single-underscore form would silently break the
/// `WebDriverIO` specs the moment the feature gate is misconfigured.
#[allow(non_snake_case)]
#[tauri::command]
pub fn __test__commands_invoked() -> Vec<String> {
    INVOCATIONS.lock().map(|g| g.clone()).unwrap_or_default()
}

/// Clear the invocation log.
///
/// Used by specs that need to assert on a fresh window of activity
/// (e.g. "after I click Copy, exactly one new invocation appears").
/// Same `non_snake_case` rationale as `__test__commands_invoked`.
#[allow(non_snake_case)]
#[tauri::command]
pub fn __test__clear_invocations() {
    if let Ok(mut g) = INVOCATIONS.lock() {
        g.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sanity: a `record()` round-trips through the reader.
    ///
    /// The static log is process-global so this test interleaves with
    /// any other `test-hooks`-feature test in the crate; we therefore
    /// clear first + assert a single specific name appears, not "the
    /// list has exactly one entry".
    #[test]
    fn record_and_read_round_trip() {
        __test__clear_invocations();
        record("smoke_test_record");
        let entries = __test__commands_invoked();
        assert!(
            entries.iter().any(|s| s == "smoke_test_record"),
            "expected 'smoke_test_record' in {entries:?}",
        );
    }

    /// Sanity: `__test__clear_invocations()` empties the log.
    #[test]
    fn clear_empties_the_log() {
        record("pre_clear_marker");
        __test__clear_invocations();
        let entries = __test__commands_invoked();
        assert!(
            !entries.iter().any(|s| s == "pre_clear_marker"),
            "expected log to be cleared but found 'pre_clear_marker' in {entries:?}",
        );
    }
}
