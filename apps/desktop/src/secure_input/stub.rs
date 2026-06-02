// SPDX-License-Identifier: AGPL-3.0-or-later
//! **Test stub for the secure-input plugin.**
//!
//! Compiled when `cfg(test)` OR `feature = "test-hooks"`. Bypasses the
//! per-OS native widgets so the wdio E2E suite can drive the wizards
//! without spawning a real dialog (which CI's headless runners can't
//! interact with anyway).
//!
//! ## Usage from a wdio spec
//!
//! 1. `__test__secure_input_inject("master-pw")` — queues a password
//!    via the Tauri test-hook command (Layer 4).
//! 2. Trigger the wizard's password-protected action — the
//!    `*_via_secure_prompt` Tauri command calls
//!    [`crate::secure_input::prompt_password`], which dispatches to
//!    [`pop_one`] here and returns the queued bytes.
//!
//! ## Usage from a Rust unit test
//!
//! Unit tests can't construct a `tauri::AppHandle` cheaply, so they
//! exercise the queue mechanics directly:
//!
//! ```ignore
//! use crate::secure_input::stub;
//! stub::clear();
//! stub::inject("hunter2".to_string());
//! let bytes = stub::pop_one().expect("queued password");
//! assert_eq!(bytes.as_slice(), b"hunter2");
//! ```
//!
//! ## L1
//!
//! The test-stub still wraps the bytes in `Zeroizing<Vec<u8>>` so the
//! injection path mirrors release-build secret hygiene. The injected
//! `String` from the test-hook command is consumed via
//! `String::into_bytes()` (move, not copy); the original `String`
//! drops at the end of the command body.

use std::collections::VecDeque;
use std::sync::{Mutex, OnceLock};

use super::SecureInputError;
use zeroize::Zeroizing;

/// Queued passwords waiting to be returned by the next [`pop_one`]
/// call(s). FIFO so a wizard that triggers two prompts in sequence
/// (e.g. RecoverVaultWizard's init + finalize) receives them in order.
fn queue() -> &'static Mutex<VecDeque<Vec<u8>>> {
    static QUEUE: OnceLock<Mutex<VecDeque<Vec<u8>>>> = OnceLock::new();
    QUEUE.get_or_init(|| Mutex::new(VecDeque::new()))
}

/// **Pop the next queued password.** Returns it wrapped in
/// `Zeroizing<Vec<u8>>`, or [`SecureInputError::TestHookEmpty`] if the
/// queue is empty.
///
/// This is the function the cfg-dispatched
/// [`crate::secure_input::prompt_password`] calls under
/// `cfg(test) || feature = "test-hooks"`.
pub fn pop_one() -> Result<Zeroizing<Vec<u8>>, SecureInputError> {
    queue()
        .lock()
        .expect("secure_input stub queue mutex poisoned")
        .pop_front()
        .map_or_else(
            || Err(SecureInputError::TestHookEmpty),
            |bytes| Ok(Zeroizing::new(bytes)),
        )
}

/// **Push a password onto the test-stub queue.** The next call to
/// [`pop_one`] will pop + return these bytes.
///
/// Called by the `__test__secure_input_inject` Tauri command (Layer 4).
/// Also callable from `#[cfg(test)]` Rust unit tests directly.
pub fn inject(password: String) {
    queue()
        .lock()
        .expect("secure_input stub queue mutex poisoned")
        .push_back(password.into_bytes());
}

/// **Drain the queue.** Called between test runs so a leaked
/// previously-queued password doesn't bleed into the next test.
pub fn clear() {
    queue()
        .lock()
        .expect("secure_input stub queue mutex poisoned")
        .clear();
}
