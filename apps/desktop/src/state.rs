// SPDX-License-Identifier: AGPL-3.0-or-later
//! `VaultState` — the Tauri-managed slot that holds the currently-open
//! `Arc<VaultHandle>`.
//!
//! Per MVP-4-B plan §3.2 + §0a, the desktop shell stores the FFI vault
//! handle in `tauri::State<VaultState>`. Every command acquires the
//! mutex, reads or replaces the slot, and routes the handle to the
//! `pangolin-ffi` binding. The handle itself never crosses the FFI
//! boundary back into JS (L1) — it lives entirely in Rust.
//!
//! ## Async + lock discipline (plan §6 third bullet)
//!
//! The `tauri::command` async handlers must NEVER hold a `MutexGuard`
//! across an `.await`. `MutexGuard` is `!Send`, and Tauri's async
//! handler infrastructure requires `Send` futures. Helpers on this
//! type therefore acquire the lock briefly, clone the inner
//! `Arc<VaultHandle>` (or take it out, for `close`), drop the guard,
//! and only THEN call back into `pangolin-ffi`. The FFI calls
//! themselves are sync (the FFI's own mutex lives inside the
//! `VaultHandle` Object), so there is no nested-`.await` risk.

#![forbid(unsafe_code)]

use std::sync::{Arc, Mutex};

use pangolin_ffi::VaultHandle;

use crate::error::DesktopError;

/// Tauri-managed slot for the open vault handle.
///
/// Constructed once at app start by `tauri::Builder::manage(...)`. The
/// inner `Option` is `Some` between `vault_open` and `vault_close` and
/// `None` either side; a `vault_close` call leaves the slot empty.
#[derive(Default)]
pub struct VaultState {
    inner: Mutex<Option<Arc<VaultHandle>>>,
}

impl std::fmt::Debug for VaultState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never log the handle's pointer or content; only its presence.
        let has = self
            .inner
            .lock()
            .map(|guard| guard.is_some())
            .unwrap_or(false);
        f.debug_struct("VaultState").field("open", &has).finish()
    }
}

impl VaultState {
    /// Borrow the currently-open vault handle.
    ///
    /// Acquires the mutex, clones the `Arc`, drops the guard. The
    /// returned handle is suitable for an immediate FFI call. Returns
    /// `DesktopError::Session` if no vault is open.
    #[allow(clippy::significant_drop_tightening)]
    pub fn require_open(&self) -> Result<Arc<VaultHandle>, DesktopError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| DesktopError::Internal("vault state lock poisoned".into()))?;
        guard
            .as_ref()
            .cloned()
            .ok_or_else(|| DesktopError::Session("no vault open".into()))
    }

    /// Install a freshly-opened vault handle, replacing any prior one.
    ///
    /// Mirrors the `vault_open` command's terminal step; if a prior
    /// vault was open it is replaced (the old `Arc` drops; the FFI
    /// `VaultHandle` zeroizes its internals via the engine's own lock
    /// path on drop).
    #[allow(clippy::significant_drop_tightening)]
    pub fn install(&self, handle: Arc<VaultHandle>) -> Result<(), DesktopError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| DesktopError::Internal("vault state lock poisoned".into()))?;
        *guard = Some(handle);
        Ok(())
    }

    /// Remove the currently-open vault handle, returning whatever was
    /// in the slot. Used by `vault_close`.
    #[allow(clippy::significant_drop_tightening)]
    pub fn take(&self) -> Result<Option<Arc<VaultHandle>>, DesktopError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| DesktopError::Internal("vault state lock poisoned".into()))?;
        Ok(guard.take())
    }

    /// Returns `true` when a vault is currently open. Diagnostic only.
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.inner
            .lock()
            .map(|guard| guard.is_some())
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::VaultState;
    use pangolin_ffi::VaultHandle;

    #[test]
    fn default_is_closed() {
        let state = VaultState::default();
        assert!(!state.is_open());
        let err = state.require_open().expect_err("should be closed");
        assert!(matches!(err, crate::error::DesktopError::Session(_)));
    }

    #[test]
    fn install_then_require_open_returns_handle() {
        let state = VaultState::default();
        let h = VaultHandle::new_placeholder();
        state.install(h).expect("install");
        assert!(state.is_open());
        let _ = state.require_open().expect("require_open");
    }

    #[test]
    fn take_clears_slot() {
        let state = VaultState::default();
        let h = VaultHandle::new_placeholder();
        state.install(h).expect("install");
        let taken = state.take().expect("take").expect("some");
        // The Arc we got back is the same Arc we installed; the slot is
        // empty afterwards.
        assert!(!state.is_open());
        drop(taken);
    }

    #[test]
    fn take_on_empty_is_none() {
        let state = VaultState::default();
        let taken = state.take().expect("take");
        assert!(taken.is_none());
    }

    #[test]
    fn install_replaces_prior() {
        let state = VaultState::default();
        let h1 = VaultHandle::new_placeholder();
        let h2 = VaultHandle::new_placeholder();
        state.install(h1).expect("install h1");
        state.install(h2).expect("install h2 replaces h1");
        assert!(state.is_open());
    }
}
