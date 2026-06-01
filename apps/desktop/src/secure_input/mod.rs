// SPDX-License-Identifier: AGPL-3.0-or-later
//! **MVP-4-H secure-input plugin — module entry point.**
//!
//! Wraps a per-OS native password dialog so plaintext passwords never
//! enter the V8 heap. The single public entry point is
//! [`prompt_password`], which:
//!
//! - Compiles to the per-OS native widget in release builds
//!   (`windows.rs` / `macos.rs` / `linux.rs`, picked by `cfg(target_os)`).
//! - Compiles to the test stub ([`stub::pop_one`]) under `cfg(test)`
//!   or `feature = "test-hooks"`, returning whatever the wdio harness
//!   queued via `stub::inject` (the `__test__secure_input_inject`
//!   Tauri command exposes this to the test runner).
//!
//! The returned bytes are wrapped in [`Zeroizing<Vec<u8>>`] so the
//! buffer zeroes on drop. The caller's first move should be
//! `pangolin_ffi::SecretPassword::new(bytes)` so the bytes flow into
//! the engine without ever copying to a non-zeroizing buffer.
//!
//! ## L-invariants
//!
//! - **L1.** Bytes NEVER cross the Tauri bridge (no command in this
//!   module returns `Vec<u8>` to JS). The Layer-2 `*_via_secure_prompt`
//!   commands call `prompt_password` + immediately feed the result to
//!   the matching FFI op; their return type is the FFI op's
//!   non-secret result.
//! - **L3.** Plugin-load / OS-call failure → typed
//!   [`SecureInputError`] → typed [`crate::DesktopError`] at the
//!   command layer. NO silent fallback to the option-1 invoke path
//!   (Q-c locked, plan §0a).
//! - **L4.** No session gating here — the active-session check stays
//!   in the inner FFI op (e.g. `vault_unlock` rejects on Locked
//!   placeholder); secure-input runs before the gate but supplies the
//!   secret that gates use.
//! - **L6.** `forbid(unsafe_code)` at module level; the per-OS native
//!   widgets that need FFI calls override this scoped to the unsafe
//!   region with a justifying comment.

#![forbid(unsafe_code)]
#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]

pub mod error;

// Test stub: compiled when running the test suite OR when the
// test-hooks feature is enabled (so the wdio harness can inject
// passwords without spawning a real dialog).
#[cfg(any(test, feature = "secure-input-stub"))]
pub mod stub;

// Per-OS native widget impls. Each lives in its own file, gated by
// target_os so unused OS code never compiles. The cfg-dispatched
// [`prompt_password`] picks at compile time.
#[cfg(all(target_os = "linux", not(any(test, feature = "secure-input-stub"))))]
pub mod linux;

#[cfg(all(target_os = "macos", not(any(test, feature = "secure-input-stub"))))]
pub mod macos;

#[cfg(all(target_os = "windows", not(any(test, feature = "secure-input-stub"))))]
pub mod windows;

#[cfg(test)]
mod tests;

pub use error::SecureInputError;
use zeroize::Zeroizing;

/// **Open a native OS password dialog and return the typed bytes.**
///
/// `app` is the Tauri app handle whose main-thread GUI loop will drive
/// the native dialog. The per-OS impls dispatch the dialog onto
/// `app.run_on_main_thread(...)` so GTK / Cocoa / Win32 calls always
/// happen on the GUI thread, even when the caller is a Tokio async
/// command on the blocking pool.
///
/// `title` is the dialog window title (shown in the title bar / sheet);
/// `body` is the prompt text above the password field. Both are
/// non-secret + safe to log.
///
/// The returned `Zeroizing<Vec<u8>>` holds the UTF-8 bytes of the
/// password the user typed. The buffer zeroes on drop; the caller's
/// first move should be `pangolin_ffi::SecretPassword::new(bytes)` so
/// the bytes flow into the engine via the existing
/// zero-copy-zeroize-on-drop path.
///
/// # Errors
///
/// - [`SecureInputError::Cancelled`] — user closed the dialog without
///   typing.
/// - [`SecureInputError::Unavailable`] — plugin failed to load
///   (missing OS support, sandbox restriction, library symbol not
///   resolvable, main thread unreachable). Per Q-c (plan §0a) this
///   surfaces as a hard fail; no silent fallback.
/// - [`SecureInputError::Internal`] — unrecoverable OS error from the
///   widget itself.
/// - [`SecureInputError::TestHookEmpty`] — stub builds only; raised
///   when `prompt_password` is called without a queued password (test
///   bug).
#[cfg(any(test, feature = "secure-input-stub"))]
#[allow(clippy::needless_pass_by_value)]
pub fn prompt_password(
    _app: &tauri::AppHandle,
    _title: &str,
    _body: &str,
) -> Result<Zeroizing<Vec<u8>>, SecureInputError> {
    stub::pop_one()
}

#[cfg(all(target_os = "linux", not(any(test, feature = "secure-input-stub"))))]
pub fn prompt_password(
    app: &tauri::AppHandle,
    title: &str,
    body: &str,
) -> Result<Zeroizing<Vec<u8>>, SecureInputError> {
    linux::prompt_password(app, title, body)
}

#[cfg(all(target_os = "macos", not(any(test, feature = "secure-input-stub"))))]
pub fn prompt_password(
    app: &tauri::AppHandle,
    title: &str,
    body: &str,
) -> Result<Zeroizing<Vec<u8>>, SecureInputError> {
    macos::prompt_password(app, title, body)
}

#[cfg(all(target_os = "windows", not(any(test, feature = "secure-input-stub"))))]
pub fn prompt_password(
    app: &tauri::AppHandle,
    title: &str,
    body: &str,
) -> Result<Zeroizing<Vec<u8>>, SecureInputError> {
    windows::prompt_password(app, title, body)
}

// Any other OS: fail closed (plan §0a Q-c). No silent fallback.
#[cfg(not(any(
    test,
    feature = "secure-input-stub",
    target_os = "linux",
    target_os = "macos",
    target_os = "windows",
)))]
#[allow(clippy::needless_pass_by_value)]
pub fn prompt_password(
    _app: &tauri::AppHandle,
    _title: &str,
    _body: &str,
) -> Result<Zeroizing<Vec<u8>>, SecureInputError> {
    Err(SecureInputError::Unavailable {
        reason: "secure_input: unsupported target OS".into(),
    })
}
