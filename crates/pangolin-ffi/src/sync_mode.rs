// SPDX-License-Identifier: AGPL-3.0-or-later
//! Sync-mode FFI bindings (CLI-V1 R-g).
//!
//! Wires the 4.4 sync-mode picker + preference accessors across the
//! FFI boundary for the host UI:
//!
//! - [`vault_select_sync_mode`] — run the picker once and return
//!   the dispatch decision.
//! - [`vault_sync_mode_preference`] — read the persisted
//!   preference.
//! - [`vault_set_sync_mode_preference`] — persist a preference.
//!
//! Like the 5.4 sync-status FFI, these are stateless: the engine
//! itself never spawns the indexer (L1 inherited); on `AlwaysFast`
//! / `OfferFast` the host owns the indexer-spawn decision per
//! D-007.

#![forbid(unsafe_code)]

use std::sync::Arc;

use core::future::Future as _;

use pangolin_chain::ChainEnv;
use pangolin_store::{SyncMode, SyncModePreference};

use crate::error::FfiError;
use crate::session::VaultHandle;
use crate::sync_status::FfiSyncMode;

// ---------------------------------------------------------------------
// FfiSyncModePreference — UniFFI mirror of pangolin_store::SyncModePreference
// ---------------------------------------------------------------------

/// FFI mirror of [`pangolin_store::SyncModePreference`].
///
/// Three variants mirror the 4.4 R-b lock verbatim: `Auto` (the
/// default — engine runs the first-sync heuristic), `AlwaysSlow`
/// (force in-process slow-mode), `AlwaysFast` (pre-elected
/// fast-mode; host spawns the indexer without prompting).
///
/// CLI-V1 (R-g).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiSyncModePreference {
    /// Default — engine runs the first-sync heuristic.
    Auto,
    /// User pre-elected "never offer fast-mode".
    AlwaysSlow,
    /// User pre-elected "skip the prompt, always go fast-mode".
    AlwaysFast,
}

impl From<SyncModePreference> for FfiSyncModePreference {
    fn from(pref: SyncModePreference) -> Self {
        match pref {
            SyncModePreference::Auto => Self::Auto,
            SyncModePreference::AlwaysSlow => Self::AlwaysSlow,
            SyncModePreference::AlwaysFast => Self::AlwaysFast,
        }
    }
}

impl From<FfiSyncModePreference> for SyncModePreference {
    fn from(pref: FfiSyncModePreference) -> Self {
        match pref {
            FfiSyncModePreference::Auto => Self::Auto,
            FfiSyncModePreference::AlwaysSlow => Self::AlwaysSlow,
            FfiSyncModePreference::AlwaysFast => Self::AlwaysFast,
        }
    }
}

// ---------------------------------------------------------------------
// FFI entry points
// ---------------------------------------------------------------------

fn store_into_ffi(err: pangolin_store::StoreError) -> FfiError {
    FfiError::from(pangolin_core::Error::from(err))
}

/// Run the [`pangolin_store::Vault::select_sync_mode`] picker
/// once and return the decision.
///
/// Pure picker — does NOT spawn the indexer (L1). Returns the
/// `FfiSyncMode` the engine would dispatch on; the host renders
/// the D-007 prompt on `OfferFast` and spawns the indexer on
/// `AlwaysFast` (or on user-accept after the prompt).
///
/// The 4.4 picker's heuristic only reads vault-local state (the
/// v1 checkpoint + the preference column) so the call is sync —
/// `rpc_url` is unused but reserved per 4.4 R-c. We use
/// [`futures::executor::block_on`]-equivalent (the
/// [`pollster`]-style poll-once dance) instead of `async` because
/// `Vault` is `!Send` (it holds an `RefCell`-bearing connection)
/// and `UniFFI` requires futures to be `Send` for `async fn`
/// exports. The engine's `select_sync_mode` body never actually
/// awaits (4.4 R-c reserved-for-future-use clause), so polling
/// the future to completion is a safe no-op.
///
/// # Errors
///
/// `FfiError::Session` for a locked / placeholder handle;
/// `FfiError::Store` for a database / preference corruption.
#[allow(clippy::significant_drop_tightening)]
#[uniffi::export]
pub fn vault_select_sync_mode(
    handle: Arc<VaultHandle>,
    rpc_url: String,
) -> Result<FfiSyncMode, FfiError> {
    let mode = {
        let mut guard = handle.lock_vault();
        let vault = guard.as_mut()?;
        // L5 active-session gate: refuse the call on a Locked
        // vault. The 4.4 picker itself reads metadata only; the
        // policy at this layer is to require Active.
        if !matches!(vault.state(), pangolin_core::VaultState::Active) {
            return Err(FfiError::Session {
                message: "vault is not unlocked".into(),
            });
        }
        // The engine's `select_sync_mode` never awaits in CLI-V1
        // (4.4 R-c reserved-for-future-use clause); we poll once
        // via `noop_waker` + `pin!` — a fast-path equivalent of a
        // single-threaded executor that completes the future
        // without spawning. This sidesteps the `!Send` Vault
        // limitation that blocks `async fn` UniFFI exports.
        let fut = vault.select_sync_mode(&rpc_url, ChainEnv::BaseSepolia);
        let pinned = core::pin::pin!(fut);
        match pinned.poll(&mut core::task::Context::from_waker(
            core::task::Waker::noop(),
        )) {
            core::task::Poll::Ready(r) => r.map_err(store_into_ffi)?,
            core::task::Poll::Pending => {
                return Err(FfiError::Internal {
                    message:
                        "vault_select_sync_mode awaited unexpectedly; this build's heuristic must \
                         be sync-completable (see 4.4 R-c reserved clause)"
                            .to_string(),
                });
            }
        }
    };
    let ffi_mode: FfiSyncMode = match mode {
        SyncMode::Slow => FfiSyncMode::Slow,
        SyncMode::OfferFast => FfiSyncMode::OfferFast,
        SyncMode::AlwaysFast => FfiSyncMode::AlwaysFast,
    };
    Ok(ffi_mode)
}

/// Read the persisted sync-mode preference.
///
/// Works on a Locked vault (the column is metadata-only). The L5
/// FFI policy collapses to a no-op here — the preference is NOT
/// secret material (it's a UI hint persisted cleartext per 4.4 R-b
/// L2); reading it on a Locked vault is fine.
///
/// # Errors
///
/// `FfiError::Session` if the handle has no vault installed;
/// `FfiError::Store` on a database / corrupted-column failure.
#[allow(clippy::significant_drop_tightening)]
#[uniffi::export]
pub fn vault_sync_mode_preference(
    handle: Arc<VaultHandle>,
) -> Result<FfiSyncModePreference, FfiError> {
    let mut guard = handle.lock_vault();
    let vault = guard.as_mut()?;
    let pref = vault.sync_mode_preference().map_err(store_into_ffi)?;
    Ok(FfiSyncModePreference::from(pref))
}

/// Persist the sync-mode preference.
///
/// **Active-session-gated** (L5 FFI policy + L-sync-mode-set-
/// without-presence): even though the preference is a UI hint
/// (NOT secret material), the FFI binding requires an active
/// session so the host UI cannot stamp a preference on a fresh
/// launch before unlock. The threat-model row notes this is
/// acceptable per 4.4 R-b — `select_sync_mode` re-runs every
/// session, so a tampered preference column degrades UX but not
/// security.
///
/// # Errors
///
/// `FfiError::Session` for a locked / placeholder handle;
/// `FfiError::Store` on a write failure.
#[allow(clippy::significant_drop_tightening)]
#[uniffi::export]
pub fn vault_set_sync_mode_preference(
    handle: Arc<VaultHandle>,
    pref: FfiSyncModePreference,
) -> Result<(), FfiError> {
    let mut guard = handle.lock_vault();
    let vault = guard.as_mut()?;
    if !matches!(vault.state(), pangolin_core::VaultState::Active) {
        return Err(FfiError::Session {
            message: "vault is not unlocked".into(),
        });
    }
    vault
        .set_sync_mode_preference(SyncModePreference::from(pref))
        .map_err(store_into_ffi)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::VaultHandle;
    use pangolin_core::{PinIdentityProof, PressYPresenceProof, Vault};
    use pangolin_crypto::secret::SecretBytes;

    fn pwd() -> SecretBytes {
        SecretBytes::new(b"correct horse battery staple".to_vec())
    }

    fn unlocked_handle(dir: &tempfile::TempDir, name: &str) -> Arc<VaultHandle> {
        let path = dir.path().join(name);
        Vault::create(&path, &pwd()).unwrap();
        let mut v = Vault::open(&path).unwrap();
        v.unlock(
            &PressYPresenceProof::confirmed(),
            &PinIdentityProof::new(pwd()),
        )
        .unwrap();
        VaultHandle::from_vault(v)
    }

    /// Default preference on a fresh vault is `Auto`.
    #[test]
    fn default_preference_is_auto() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        let pref = vault_sync_mode_preference(h).expect("read pref");
        assert_eq!(pref, FfiSyncModePreference::Auto);
    }

    /// `set` then `get` round-trips through every variant.
    #[test]
    fn set_then_get_round_trips_every_variant() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        for variant in [
            FfiSyncModePreference::AlwaysSlow,
            FfiSyncModePreference::AlwaysFast,
            FfiSyncModePreference::Auto,
        ] {
            vault_set_sync_mode_preference(Arc::clone(&h), variant).expect("set");
            let read = vault_sync_mode_preference(Arc::clone(&h)).expect("get");
            assert_eq!(read, variant);
        }
    }

    /// `vault_select_sync_mode` returns `OfferFast` on a fresh
    /// vault with Auto preference (4.4 R-a heuristic).
    #[test]
    fn select_sync_mode_returns_offer_fast_on_fresh_vault() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        let mode = vault_select_sync_mode(h, "http://localhost:1".into()).expect("select");
        assert_eq!(mode, FfiSyncMode::OfferFast);
    }

    /// Locked vault → `FfiError::Session` from
    /// `vault_set_sync_mode_preference` (session-discipline parity).
    #[test]
    fn set_preference_rejects_locked_vault_with_session_error() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        {
            let mut g = h.lock_vault();
            g.as_mut().unwrap().lock();
        }
        let err = vault_set_sync_mode_preference(h, FfiSyncModePreference::AlwaysFast).unwrap_err();
        assert!(
            matches!(err, FfiError::Session { .. }),
            "expected FfiError::Session, got {err:?}"
        );
    }

    /// Placeholder handle → `FfiError::Session` from
    /// `vault_sync_mode_preference`.
    #[test]
    fn read_preference_rejects_placeholder_with_session_error() {
        let empty = VaultHandle::new_placeholder();
        let err = vault_sync_mode_preference(empty).unwrap_err();
        assert!(matches!(err, FfiError::Session { .. }));
    }
}
