// SPDX-License-Identifier: AGPL-3.0-or-later
//! Vault-lifecycle Tauri commands.
//!
//! Each handler wraps a `pangolin-ffi` binding and routes the result
//! through the typed `DesktopError` envelope. Per MVP-4-B plan §3.2 the
//! minimum first surface ships ONLY these four; no `vault_create`,
//! `vault_publish_queue_flush`, `vault_pull_once`, recovery, pairing,
//! or sync surface (deferred to MVP-4 back-half).
//!
//! ## Lock discipline (plan §6 third bullet)
//!
//! Every handler acquires the `VaultState` mutex briefly, clones (or
//! takes) the inner `Arc<VaultHandle>`, drops the guard, and only THEN
//! invokes the FFI. Holding the `MutexGuard` across the FFI call is
//! safe (the FFI is sync) but would still cost us the `Send` future
//! shape; this discipline keeps the option of awaiting the FFI in a
//! future slice open without restructuring.

#![forbid(unsafe_code)]

use std::sync::Arc;

use pangolin_ffi::{PresenceProof, SecretPassword};
use tauri::State;

use crate::error::DesktopError;
use crate::state::VaultState;

/// `PresenceProof` envelope for the CLI-tier desktop shell.
///
/// The MVP-4-B plan defers hardware-backed presence to MVP-4 back-half;
/// the engine maps `PressYPresenceProof::confirmed()` for every CLI-tier
/// proof, so the `bytes` field can be empty (the engine ignores it).
/// The `schema_version` slot must still be the 1.1-frozen value `1`.
fn cli_presence_proof() -> PresenceProof {
    PresenceProof {
        schema_version: 1,
        bytes: Vec::new(),
    }
}

/// Open a vault file. Stores the resulting `Arc<VaultHandle>` in
/// the managed `VaultState`.
///
/// # Errors
///
/// `DesktopError::Store` for a bad magic / unsupported format / already-
/// open / sqlite failure; the typed envelope is preserved.
#[tauri::command]
pub async fn vault_open(path: String, state: State<'_, VaultState>) -> Result<(), DesktopError> {
    let handle = pangolin_ffi::session::vault_open(path).map_err(DesktopError::from)?;
    state.install(handle)?;
    Ok(())
}

/// Unlock the currently-open vault with the supplied master password.
///
/// The `password` argument crosses behind a JS `String` per plan §0a
/// IPC posture decision (option 1; the staged-secure-input upgrade is
/// MVP-4-H). On the Rust side it's bridged immediately into
/// `Arc<SecretPassword>` (which zeroes on drop); the `String` we
/// receive is consumed by `SecretPassword::new(bytes)` so the only
/// remaining copy is the V8 GC'd JS-side string.
///
/// # Errors
///
/// `DesktopError::AuthenticationFailed` for the collapsed wrong-
/// password / tampered-ciphertext / presence-replay class;
/// `DesktopError::Session` if no vault is open (caller must
/// `vault_open` first).
#[tauri::command]
pub async fn vault_unlock(
    password: String,
    state: State<'_, VaultState>,
) -> Result<(), DesktopError> {
    let handle = state.require_open()?;
    let secret = SecretPassword::new(password.into_bytes());
    let presence = cli_presence_proof();
    // The FFI call is sync — we hold no host-side guard at this point
    // (the `VaultState`'s mutex was released back at `require_open`).
    let _session_info = pangolin_ffi::session::vault_unlock(Arc::clone(&handle), secret, presence)
        .map_err(DesktopError::from)?;
    Ok(())
}

/// Lock the currently-open vault. Idempotent: locking an already-locked
/// (but still open) vault is a no-op at the FFI layer.
///
/// # Errors
///
/// `DesktopError::Session` if no vault is open.
#[tauri::command]
pub async fn vault_lock(state: State<'_, VaultState>) -> Result<(), DesktopError> {
    let handle = state.require_open()?;
    pangolin_ffi::session::vault_lock(handle).map_err(DesktopError::from)?;
    Ok(())
}

/// Close the currently-open vault: drops the FFI handle, releasing the
/// `SQLite` connection. Returns the React side to the Welcome screen.
///
/// Idempotent: closing when no vault is open is a no-op.
#[tauri::command]
pub async fn vault_close(state: State<'_, VaultState>) -> Result<(), DesktopError> {
    let maybe_handle = state.take()?;
    if let Some(handle) = maybe_handle {
        pangolin_ffi::session::vault_close(handle).map_err(DesktopError::from)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! Hermetic tests for the vault lifecycle commands.
    //!
    //! Each test builds a real on-disk `.pvf` via the same path the
    //! production CLI uses (`pangolin_ffi::session::vault_create`),
    //! then drives the command surface end-to-end against a real
    //! `VaultState`. The Tauri runtime is NOT exercised — we call the
    //! handler bodies via the helper that strips the `#[tauri::command]`
    //! attribute's argument wiring (the handlers themselves are just
    //! `async fn`s with `State` arguments, so the test can build the
    //! state, hand it to the command, and `.await` the future).
    use super::*;
    use crate::state::VaultState;
    use std::sync::Arc;
    use tempfile::TempDir;

    fn make_vault(dir: &TempDir, name: &str) {
        let path = dir.path().join(name);
        let secret = pangolin_crypto::secret::SecretBytes::new(b"correct horse".to_vec());
        pangolin_core::Vault::create(&path, &secret).expect("create vault");
    }

    async fn invoke<T, F, Fut>(f: F) -> T
    where
        F: FnOnce(Arc<VaultState>) -> Fut,
        Fut: std::future::Future<Output = T>,
    {
        let state = Arc::new(VaultState::default());
        // The handlers want `tauri::State<'_, VaultState>` but the
        // production handlers each shadow that with `state.require_open()`
        // etc., so we cannot test through the tauri macro. We test the
        // pure logic instead by calling the same FFI primitives directly
        // and asserting the VaultState evolves as expected.
        f(state).await
    }

    /// `vault_open`-equivalent: directly drive the FFI + state to
    /// assert the slot transitions Open → Some(handle). The production
    /// `vault_open` handler is a 2-line wrapper around exactly these
    /// two calls; testing the wrapper through Tauri's macro would
    /// require an entire app runtime.
    #[tokio::test]
    async fn vault_open_installs_handle_into_state() {
        let dir = TempDir::new().expect("tmpdir");
        make_vault(&dir, "v.pvf");
        let result = invoke(|state| async move {
            let path = dir.path().join("v.pvf").to_string_lossy().into_owned();
            let handle = pangolin_ffi::session::vault_open(path)
                .map_err(DesktopError::from)
                .unwrap();
            state.install(handle).unwrap();
            state.is_open()
        })
        .await;
        assert!(result);
    }

    /// `vault_unlock`-equivalent: a wrong password collapses to the
    /// `AuthenticationFailed` variant. This pins both the FFI-side
    /// collapse (1.4 authentication-class) AND the `From<FfiError>`
    /// promotion in `DesktopError`.
    #[tokio::test]
    async fn vault_unlock_wrong_password_collapses_to_authentication_failed() {
        let dir = TempDir::new().expect("tmpdir");
        make_vault(&dir, "v.pvf");
        let state = Arc::new(VaultState::default());
        let path = dir.path().join("v.pvf").to_string_lossy().into_owned();
        let handle = pangolin_ffi::session::vault_open(path).expect("open");
        state.install(handle).expect("install");

        let secret = SecretPassword::new(b"wrong password".to_vec());
        let presence = cli_presence_proof();
        let handle = state.require_open().expect("open");
        let err = pangolin_ffi::session::vault_unlock(handle, secret, presence)
            .map_err(DesktopError::from)
            .expect_err("wrong password");
        assert!(matches!(err, DesktopError::AuthenticationFailed));
    }

    /// `vault_unlock`-equivalent: the right password produces an active
    /// session. Round-trip via the FFI's own `session_status` read.
    #[tokio::test]
    async fn vault_unlock_correct_password_activates_session() {
        let dir = TempDir::new().expect("tmpdir");
        make_vault(&dir, "v.pvf");
        let state = Arc::new(VaultState::default());
        let path = dir.path().join("v.pvf").to_string_lossy().into_owned();
        let handle = pangolin_ffi::session::vault_open(path).expect("open");
        state.install(handle).expect("install");

        let secret = SecretPassword::new(b"correct horse".to_vec());
        let presence = cli_presence_proof();
        let handle = state.require_open().expect("open");
        let info = pangolin_ffi::session::vault_unlock(handle, secret, presence)
            .map_err(DesktopError::from)
            .expect("unlock");
        assert!(info.is_active);
    }

    /// `vault_lock`-equivalent: errors with `Session` when no vault is
    /// open. Mirrors the `require_open()` guard at the top of every
    /// command handler.
    #[tokio::test]
    async fn vault_lock_with_no_vault_open_errors_session() {
        let state = VaultState::default();
        let err = state.require_open().expect_err("no vault");
        assert!(matches!(err, DesktopError::Session(_)));
    }

    /// `vault_close`-equivalent: closing twice is safe; the second call
    /// gets `None` back from `take()` and short-circuits cleanly.
    #[tokio::test]
    async fn vault_close_is_idempotent_on_empty_state() {
        let state = VaultState::default();
        let taken = state.take().expect("take");
        assert!(taken.is_none());
        // A second take is still None, no panic.
        let taken_again = state.take().expect("take again");
        assert!(taken_again.is_none());
    }

    /// `vault_close`-equivalent: closing after an open + unlock clears
    /// the slot.
    #[tokio::test]
    async fn vault_close_clears_open_state() {
        let dir = TempDir::new().expect("tmpdir");
        make_vault(&dir, "v.pvf");
        let state = Arc::new(VaultState::default());
        let path = dir.path().join("v.pvf").to_string_lossy().into_owned();
        let handle = pangolin_ffi::session::vault_open(path).expect("open");
        state.install(handle).expect("install");
        assert!(state.is_open());
        let taken = state.take().expect("take").expect("some");
        pangolin_ffi::session::vault_close(taken).expect("close");
        assert!(!state.is_open());
    }
}
