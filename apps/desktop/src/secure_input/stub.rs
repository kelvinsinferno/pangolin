// SPDX-License-Identifier: AGPL-3.0-or-later
//! **Test stub for the secure-input plugin.**
//!
//! Compiled when `cfg(test)` OR `feature = "test-hooks"`. Bypasses the
//! per-OS native widgets so the wdio E2E suite can drive the wizards
//! without spawning a real dialog (which CI's headless runners can't
//! interact with anyway).
//!
//! Usage in a wdio spec:
//! 1. `__test__secure_input_inject("master-pw")` — queues a password
//! 2. Trigger the wizard's "Unlock" button — the
//!    `vault_unlock_via_secure_prompt` handler calls
//!    `secure_input::prompt_password`, which pops the queued password
//!    + returns it.
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

/// Queued passwords waiting to be returned by the next
/// [`prompt_password`] call(s). FIFO so a wizard that triggers two
/// prompts in sequence (e.g. RecoverVaultWizard's init + finalize)
/// receives them in order.
fn queue() -> &'static Mutex<VecDeque<Vec<u8>>> {
    static QUEUE: OnceLock<Mutex<VecDeque<Vec<u8>>>> = OnceLock::new();
    QUEUE.get_or_init(|| Mutex::new(VecDeque::new()))
}

/// **Stub `prompt_password`.** Pops the next queued password from the
/// FIFO queue + returns it wrapped in `Zeroizing<Vec<u8>>`. Returns
/// [`SecureInputError::TestHookEmpty`] if no password was queued.
///
/// `title` + `body` are ignored — they're inputs to the real native
/// dialog only. The stub doesn't render any UI.
#[allow(clippy::needless_pass_by_value)]
pub fn prompt_password(_title: &str, _body: &str) -> Result<Zeroizing<Vec<u8>>, SecureInputError> {
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
/// [`prompt_password`] will pop + return these bytes.
///
/// Called by the [`__test__secure_input_inject`] Tauri command. Also
/// callable from `#[cfg(test)]` Rust unit tests directly (no Tauri
/// runtime needed).
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
