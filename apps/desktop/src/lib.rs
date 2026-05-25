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
pub mod state;

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
    tauri::Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        .manage(VaultState::default())
        .invoke_handler(tauri::generate_handler![
            commands::vault::vault_open,
            commands::vault::vault_unlock,
            commands::vault::vault_lock,
            commands::vault::vault_close,
            commands::account::accounts_list,
            commands::account::account_show,
            commands::account::reveal_password,
            commands::account::copy_password_to_clipboard,
            commands::account::copy_to_clipboard,
        ])
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
