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

use pangolin_ffi::{FfiOpenedShare, VaultHandle};

use crate::error::DesktopError;

/// Tauri-managed slot for the open vault handle.
///
/// Constructed once at app start by `tauri::Builder::manage(...)`. The
/// inner `Option` is `Some` between `vault_open` and `vault_close` and
/// `None` either side; a `vault_close` call leaves the slot empty.
///
/// ## Recovery opened-share accumulator (MVP-4-L L-B, Q-a)
///
/// `recovery_opened_shares` is the Rust-side accumulator for the
/// in-flight L-B (recoverer wizard) flow. Each `recovery_ingest_share`
/// command pushes an `Arc<FfiOpenedShare>` here; `recovery_complete`
/// takes them out and feeds them to `vault_recover_from_backup`. The
/// opened-share bytes NEVER cross the FFI back into JS — the `Arc`
/// handles are opaque from uniffi's POV (L1). Cleared on
/// `vault_close` + on any "start over" path in the wizard to avoid
/// stranded secret material across vault-close boundaries.
#[derive(Default)]
pub struct VaultState {
    inner: Mutex<Option<Arc<VaultHandle>>>,
    recovery_opened_shares: Mutex<Vec<Arc<FfiOpenedShare>>>,
}

impl std::fmt::Debug for VaultState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never log the handle's pointer or content; only its presence.
        let has = self
            .inner
            .lock()
            .map(|guard| guard.is_some())
            .unwrap_or(false);
        // The recovery accumulator count is non-secret + diagnostic-only.
        let opened = self.opened_share_count();
        f.debug_struct("VaultState")
            .field("open", &has)
            .field("recovery_opened_shares", &opened)
            .finish()
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

    // -----------------------------------------------------------------
    // Recovery opened-share accumulator (L-B Q-a)
    // -----------------------------------------------------------------

    /// Push a freshly-ingested opened share into the recovery
    /// accumulator. Returns the new total count so the host can render
    /// "X of t collected".
    #[allow(clippy::significant_drop_tightening)]
    pub fn push_opened_share(&self, share: Arc<FfiOpenedShare>) -> Result<usize, DesktopError> {
        let mut guard = self
            .recovery_opened_shares
            .lock()
            .map_err(|_| DesktopError::Internal("opened-shares lock poisoned".into()))?;
        guard.push(share);
        Ok(guard.len())
    }

    /// Move the accumulator contents out (replacing with an empty Vec).
    /// Used by `recovery_complete` immediately before driving
    /// `vault_recover_from_backup`; the Vec is consumed by the FFI in
    /// the same `spawn_blocking`.
    #[allow(clippy::significant_drop_tightening)]
    pub fn take_opened_shares(&self) -> Result<Vec<Arc<FfiOpenedShare>>, DesktopError> {
        let mut guard = self
            .recovery_opened_shares
            .lock()
            .map_err(|_| DesktopError::Internal("opened-shares lock poisoned".into()))?;
        Ok(std::mem::take(&mut *guard))
    }

    /// Drop all collected shares without consuming them. Called from
    /// `vault_close` (defense-in-depth: wipes stranded secret material
    /// when the vault is locked / handed off) and from any wizard
    /// "start over" path.
    #[allow(clippy::significant_drop_tightening)]
    pub fn clear_opened_shares(&self) -> Result<(), DesktopError> {
        let mut guard = self
            .recovery_opened_shares
            .lock()
            .map_err(|_| DesktopError::Internal("opened-shares lock poisoned".into()))?;
        guard.clear();
        Ok(())
    }

    /// Return the current accumulator count. Used by the wizard's
    /// resume path to render "X already collected" without disturbing
    /// the contents.
    #[must_use]
    pub fn opened_share_count(&self) -> usize {
        self.recovery_opened_shares
            .lock()
            .map(|g| g.len())
            .unwrap_or(0)
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

    // -----------------------------------------------------------------
    // Recovery opened-share accumulator tests (L-B Q-a)
    // -----------------------------------------------------------------

    /// Build an opaque opened-share for tests. The contents don't matter
    /// (the wizard's count + lifecycle don't read them); we just need
    /// distinct Arcs that round-trip through the accumulator API.
    fn fake_share() -> std::sync::Arc<pangolin_ffi::FfiOpenedShare> {
        pangolin_ffi::FfiOpenedShare::__test_placeholder()
    }

    #[test]
    fn opened_shares_starts_empty() {
        let state = VaultState::default();
        assert_eq!(state.opened_share_count(), 0);
    }

    #[test]
    fn push_opened_share_increments_count() {
        let state = VaultState::default();
        assert_eq!(state.push_opened_share(fake_share()).expect("push"), 1);
        assert_eq!(state.push_opened_share(fake_share()).expect("push"), 2);
        assert_eq!(state.opened_share_count(), 2);
    }

    #[test]
    fn take_opened_shares_empties_accumulator() {
        let state = VaultState::default();
        state.push_opened_share(fake_share()).expect("push");
        state.push_opened_share(fake_share()).expect("push");
        let drained = state.take_opened_shares().expect("take");
        assert_eq!(drained.len(), 2);
        assert_eq!(state.opened_share_count(), 0);
    }

    #[test]
    fn clear_opened_shares_drops_all() {
        let state = VaultState::default();
        state.push_opened_share(fake_share()).expect("push");
        state.push_opened_share(fake_share()).expect("push");
        state.clear_opened_shares().expect("clear");
        assert_eq!(state.opened_share_count(), 0);
    }
}
