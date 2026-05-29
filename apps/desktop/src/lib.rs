// SPDX-License-Identifier: AGPL-3.0-or-later
//! `pangolin-desktop` library crate.
//!
//! Hosts the Tauri command surface + the managed-state types. The
//! binary entry (`src/main.rs`) is a thin shim that wires Tauri's
//! `Builder` against the surface here. Splitting lib + bin makes the
//! command handlers testable without an active Tauri runtime (see the
//! per-module `#[cfg(test)]` blocks).
//!
//! See [`docs/issue-plans/mvp4-b-desktop-shell.md`](../../../docs/issue-plans/mvp4-b-desktop-shell.md)
//! for the full plan.
//!
//! # Architecture
//!
//! ```text
//! React 19 (apps/desktop/src/ui/)        ←  imports @pangolin/component-library + @tauri-apps/api
//!         │  invoke('vault_unlock', {password})
//!         ▼
//! Tauri v2 bridge  ──────────────────►  pangolin_desktop_lib::commands::*
//!                                              │
//!                                              ▼
//!                                       pangolin_ffi::session::vault_unlock
//!                                              │
//!                                              ▼
//!                                       pangolin_core::Vault + pangolin_store
//! ```

#![forbid(unsafe_code)]
#![deny(unused_must_use)]

pub mod commands;
pub mod error;
pub mod ipc;
pub mod state;

// MVP-4-F: feature-gated test-hook module + `__test__*` commands.
// The module's own `#![cfg(feature = "test-hooks")]` attribute compiles
// the body out of release builds; this `pub mod` line is feature-gated
// in lockstep so a stray reference in non-test-hooks code is a build
// error (defence in depth).
//
// Plan-LOCK: docs/issue-plans/mvp4-f-desktop-e2e.md §3.2.
#[cfg(feature = "test-hooks")]
pub mod test_hooks;

pub use error::DesktopError;
pub use state::VaultState;

/// Construct the default `tauri::Builder` with managed state + the
/// clipboard plugin + the invoke-handler registry.
///
/// Exposed so the binary entry (`src/main.rs`) AND future integration-
/// test harnesses can spawn the same wired app.
///
/// The invoke-handler registry is the SOLE Tauri-side allow-list of
/// commands the React frontend can call (mirrored by
/// `capabilities/default.json`'s permission allow-list). Adding a
/// command requires both (a) registering it here and (b) listing its
/// permission slug in `capabilities/`.
pub fn build_app() -> tauri::Builder<tauri::Wry> {
    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        .manage(VaultState::default())
        // MVP-4-E: spawn the IPC server task that the native-
        // messaging host bridge connects to. The server holds a
        // clone of the Tauri `AppHandle`; per-request dispatch
        // looks up `VaultState` via `app.state()` (coherent with
        // the Tauri command path) and reaches the OS clipboard via
        // `app.clipboard()` (the H-1 L1 carve-out path; the
        // plaintext NEVER crosses the IPC channel — only an OK or
        // typed-error signal does).
        //
        // Bind failures are logged to stderr; they do NOT prevent
        // the desktop UI from coming up. The extension popup will
        // surface "Desktop not connected" until the user re-runs
        // the install wizard.
        .setup(|app| {
            let app_handle = app.handle().clone();
            #[cfg(feature = "test-hooks")]
            {
                // `Manager` brings `app.state::<T>()` into scope; only
                // the test-hooks auto-unlock path needs it, so the
                // import is gated to avoid an unused-import error in
                // production builds.
                use tauri::Manager;
                if let (Ok(vault_path), Ok(password)) = (
                    std::env::var("PANGOLIN_TEST_AUTO_UNLOCK_PATH"),
                    std::env::var("PANGOLIN_TEST_AUTO_UNLOCK_PASSWORD"),
                ) {
                    if !vault_path.is_empty() && !password.is_empty() {
                        let state = app.state::<VaultState>();
                        if let Err(e) = auto_unlock_for_e2e(&state, vault_path, password) {
                            eprintln!("[pangolin-desktop] auto-unlock failed: {e:?}");
                        }
                    }
                }
            }
            ipc::spawn_with_app_handle(app_handle);
            Ok(())
        });

    // MVP-4-F: invoke-handler registration uses per-entry `#[cfg]`
    // attributes on the test-hook command paths so the production
    // command list appears ONCE, not duplicated across two cfg arms.
    // Audit M-2 hardening (2026-05-26): the earlier two-arm shape
    // could silently drift if a new production command was added to
    // one arm but not the other. `tauri::generate_handler!` is a
    // proc-macro that accepts standard Rust attributes on its
    // path-list elements (verified at build time); the two
    // `#[cfg(feature = "test-hooks")]`-gated lines compile out of
    // release builds, matching the prior two-arm semantics exactly
    // without the duplication risk.
    builder.invoke_handler(tauri::generate_handler![
        commands::vault::vault_open,
        commands::vault::vault_unlock,
        commands::vault::vault_lock,
        commands::vault::vault_close,
        commands::account::accounts_list,
        commands::account::account_show,
        commands::account::reveal_password,
        commands::account::copy_password_to_clipboard,
        commands::account::copy_to_clipboard,
        commands::install_native_host::install_native_host,
        commands::install_native_host::uninstall_native_host,
        // MVP-4-I: multi-device pairing (add-device) command surface.
        commands::pairing::pairing_begin_new_device,
        commands::pairing::pairing_decode_bytes,
        commands::pairing::pairing_local_payload,
        commands::pairing::pairing_derive_sas,
        commands::pairing::pairing_open_and_join,
        commands::pairing::pairing_device_list,
        commands::pairing::pairing_chain_bootstrap,
        commands::pairing::pairing_add_device,
        // MVP-4-J: device removal + authorized-set / rotation.
        commands::pairing::pairing_list_authorized_devices,
        commands::pairing::pairing_remove_device,
        commands::pairing::pairing_pending_rotations,
        commands::pairing::pairing_complete_rotation,
        // MVP-4-K: manager handoff / promotion.
        commands::pairing::pairing_propose_promotion,
        commands::pairing::pairing_finalize_promotion,
        commands::pairing::pairing_cancel_promotion,
        commands::pairing::pairing_pending_promotion,
        #[cfg(feature = "test-hooks")]
        test_hooks::__test__commands_invoked,
        #[cfg(feature = "test-hooks")]
        test_hooks::__test__clear_invocations,
        #[cfg(feature = "test-hooks")]
        test_hooks::__test__force_unlock,
    ])
}

#[cfg(feature = "test-hooks")]
fn auto_unlock_for_e2e(
    state: &VaultState,
    vault_path: String,
    password: String,
) -> Result<(), DesktopError> {
    use pangolin_ffi::{PresenceProof, SecretPassword};
    use std::sync::Arc;
    let handle = pangolin_ffi::session::vault_open(vault_path).map_err(DesktopError::from)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time guarantee that `build_app()`'s signature stays
    /// stable. This is a smoke check; the actual `tauri::Builder::run`
    /// requires a windowing context that the test harness does not
    /// provide (and that the per-OS image cannot reliably produce in
    /// CI), so we DO NOT call `.run()` from tests.
    #[test]
    fn build_app_returns_a_builder() {
        let _b = build_app();
    }

    /// Compile-time check that `VaultState` is the type the registry
    /// expects (`Default + Send + Sync + 'static`).
    #[test]
    fn vault_state_is_send_sync() {
        fn assert_send_sync<T: Send + Sync + 'static>() {}
        assert_send_sync::<VaultState>();
    }
}
