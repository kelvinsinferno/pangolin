// SPDX-License-Identifier: AGPL-3.0-or-later
//! Publish-queue FFI bindings (CLI-V1 R-g).
//!
//! Wires the 5.1 publish-queue engine surface across the FFI
//! boundary for the host UI:
//!
//! - [`vault_flush_publish_queue`] — drain dirty markers in one
//!   batched call. Mirrors [`pangolin_store::Vault::flush_publish_queue`].
//! - [`vault_publish_queue_state`] — read-only snapshot for the
//!   indicator chip.
//! - [`vault_enable_window_elapsed_flush`] — toggle the
//!   auto-flush slot (inert in 5.1; reserved for hosts that
//!   register an adapter).
//! - [`vault_coalesce_dirty_markers`] — manual coalesce pass for
//!   diagnostic / GC purposes.
//!
//! L5: every entry point is active-session-gated at the FFI
//! boundary. **MVP-3 issue #100** wires the chain-adapter-bearing
//! `vault_flush_publish_queue` body: the binding builds a
//! `BaseSepoliaAdapter` engine-side from the unlocked vault's gas
//! wallet (no secret crosses FFI — L1) + the host-supplied
//! [`crate::chain_config::FfiChainConfig`], then drives the `!Send`
//! `Vault::flush_publish_queue` future on a local current-thread
//! runtime. The CLI consumes the engine method directly (no FFI
//! involved); this binding is for the host UI's use.

#![forbid(unsafe_code)]

use std::path::Path;
use std::sync::Arc;

use pangolin_chain::BaseSepoliaAdapter;
use pangolin_crypto::keys::DeviceKey;

use crate::chain_config::{batch_flush_into_ffi, block_on_local, chain_into_ffi, FfiChainConfig};
use crate::error::FfiError;
use crate::session::VaultHandle;

// ---------------------------------------------------------------------
// FfiPublishQueueState
// ---------------------------------------------------------------------

/// FFI mirror of [`pangolin_store::PublishQueueState`].
///
/// `window_started_at_unix_ms` is `None` on a Locked vault even if
/// dirty markers exist; the next unlock will start a fresh window
/// if the queue is non-empty.
///
/// CLI-V1 (R-g).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiPublishQueueState {
    /// Schema-version slot.
    pub schema_version: u16,
    /// Number of dirty markers currently in the queue
    /// (pre-coalescing).
    pub dirty_count: u32,
    /// Sum of `enc_payload` byte sizes across all dirty markers
    /// (pre-coalescing).
    pub dirty_byte_size: u64,
    /// Unix-ms instant at which the current 30 s window started,
    /// if any.
    pub window_started_at_unix_ms: Option<i64>,
    /// `true` if the last flush attempt returned
    /// [`pangolin_store::BatchFlushError::BalanceInsufficientForBatch`].
    /// Diagnostic / UX hint only — the chain-side gate IS the
    /// authoritative defense.
    pub blocked_on_balance: bool,
}

impl From<pangolin_store::PublishQueueState> for FfiPublishQueueState {
    fn from(state: pangolin_store::PublishQueueState) -> Self {
        Self {
            schema_version: 1,
            dirty_count: u32::try_from(state.dirty_count).unwrap_or(u32::MAX),
            dirty_byte_size: state.dirty_byte_size,
            window_started_at_unix_ms: state.window_started_at_unix_ms,
            blocked_on_balance: state.blocked_on_balance,
        }
    }
}

// ---------------------------------------------------------------------
// FfiBatchFlushReport (placeholder for the chain-adapter-bearing
// vault_flush_publish_queue body that lands in MVP-3 once the adapter
// FFI surface ships).
// ---------------------------------------------------------------------

/// FFI mirror of [`pangolin_store::BatchFlushReport`].
///
/// CLI-V1 (R-g). The host invokes this via
/// [`vault_flush_publish_queue`] AFTER the chain-adapter FFI surface
/// lands in MVP-3; in CLI-V1 the binding is a typed-error stub so
/// the surface is locked.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiBatchFlushReport {
    /// Schema-version slot.
    pub schema_version: u16,
    /// Number of dirty markers pruned by the R-c per-account
    /// coalescing pass before any chain submit.
    pub coalesced_markers_pruned: u32,
    /// Per-row published count (the post-flight wrapped report).
    pub published_count: u32,
    /// Per-row failed count.
    pub failed_count: u32,
}

fn store_into_ffi(err: pangolin_store::StoreError) -> FfiError {
    FfiError::from(pangolin_core::Error::from(err))
}

// ---------------------------------------------------------------------
// vault_flush_publish_queue
// ---------------------------------------------------------------------

/// Drain the publish queue.
///
/// **MVP-3 issue #100.** Builds a `BaseSepoliaAdapter` engine-side
/// from the unlocked vault's per-device gas wallet (the signer is
/// read via `Vault::evm_wallet().signer()` and cloned engine-side —
/// **no secret material crosses FFI**, L1) plus the host-supplied
/// non-secret `config` (`rpc_url` + `deployment_path`), then drives
/// the `!Send` [`pangolin_store::Vault::flush_publish_queue`] future
/// to completion on a local current-thread runtime. `force = true`
/// bypasses the 30 s window.
///
/// # Errors
///
/// `FfiError::Session` for a locked / placeholder handle (the L4
/// session gate, before any chain primitive); `FfiError::Store` /
/// `FfiError::Chain` for adapter-construction or flush failures.
#[allow(clippy::significant_drop_tightening, clippy::needless_pass_by_value)]
#[uniffi::export]
pub fn vault_flush_publish_queue(
    handle: Arc<VaultHandle>,
    config: FfiChainConfig,
    force: bool,
) -> Result<FfiBatchFlushReport, FfiError> {
    // Active-session gate at the FFI boundary (L4), BEFORE any chain
    // primitive — a locked / placeholder vault errors here.
    let mut guard = handle.lock_vault();
    let vault = guard.as_mut()?;
    // L1: read the gas-paying signer engine-side from the unlocked
    // vault and clone it. Never crosses FFI.
    let signer = vault.evm_wallet().map_err(store_into_ffi)?.signer().clone();
    // The flush engine method takes a `device_key: &DeviceKey` that the
    // CLI satisfies with a throwaway `DeviceKey::generate()` — the gas
    // wallet is internal to the adapter (two-key PoC model). Mint the
    // same ephemeral throwaway here; it is NOT a host input and is
    // SEPARATE from the gas wallet sourced above.
    let throwaway_device_key = DeviceKey::generate();
    // `Vault` is `!Send`; build the adapter AND run the flush inside one
    // local-runtime `block_on` so the `!Send` future never leaves this
    // thread (see chain_config.rs module doc).
    block_on_local(async {
        let adapter = BaseSepoliaAdapter::new_with_signer(
            &config.rpc_url,
            Path::new(&config.deployment_path),
            signer,
        )
        .await
        .map_err(chain_into_ffi)?;
        let report = vault
            .flush_publish_queue(&adapter, &throwaway_device_key, force)
            .await
            .map_err(batch_flush_into_ffi)?;
        Ok(FfiBatchFlushReport {
            schema_version: 1,
            coalesced_markers_pruned: u32::try_from(report.coalesced_markers_pruned)
                .unwrap_or(u32::MAX),
            published_count: u32::try_from(report.publish_report.published_count())
                .unwrap_or(u32::MAX),
            failed_count: u32::try_from(report.publish_report.failed_count()).unwrap_or(u32::MAX),
        })
    })?
}

// ---------------------------------------------------------------------
// vault_publish_queue_state
// ---------------------------------------------------------------------

/// Read-only snapshot of the publish-queue state.
///
/// Works on a Locked vault (metadata-only) for the dirty count +
/// byte size; the in-session `window_started_at_unix_ms` field is
/// `None` on a Locked vault.
///
/// # Errors
///
/// `FfiError::Session` if the handle has no vault installed;
/// `FfiError::Store` on a database failure.
#[allow(clippy::significant_drop_tightening)]
#[uniffi::export]
pub fn vault_publish_queue_state(
    handle: Arc<VaultHandle>,
) -> Result<FfiPublishQueueState, FfiError> {
    let mut guard = handle.lock_vault();
    let vault = guard.as_mut()?;
    let state = vault.publish_queue_state().map_err(store_into_ffi)?;
    Ok(FfiPublishQueueState::from(state))
}

// ---------------------------------------------------------------------
// vault_enable_window_elapsed_flush
// ---------------------------------------------------------------------

/// Toggle the auto-flush slot. **Active-session-gated** — locked
/// vault returns `FfiError::Session`.
///
/// # Errors
///
/// `FfiError::Session` for a locked / placeholder handle;
/// `FfiError::Store` on a propagated `StoreError::NotUnlocked`.
#[allow(clippy::significant_drop_tightening)]
#[uniffi::export]
pub fn vault_enable_window_elapsed_flush(
    handle: Arc<VaultHandle>,
    on: bool,
) -> Result<(), FfiError> {
    let mut guard = handle.lock_vault();
    let vault = guard.as_mut()?;
    vault
        .enable_window_elapsed_flush(on)
        .map_err(store_into_ffi)?;
    Ok(())
}

// ---------------------------------------------------------------------
// vault_coalesce_dirty_markers
// ---------------------------------------------------------------------

/// Run the R-c per-account coalescing pass manually.
///
/// Returns the number of markers pruned. **Active-session-gated**
/// at the FFI boundary even though the engine method works on a
/// locked vault — the host UI should never invoke this on a
/// fresh-launch locked vault (the next unlock will run coalesce
/// automatically inside `flush_publish_queue`).
///
/// # Errors
///
/// `FfiError::Session` for a locked / placeholder handle;
/// `FfiError::Store` on a database failure.
#[allow(clippy::significant_drop_tightening)]
#[uniffi::export]
pub fn vault_coalesce_dirty_markers(handle: Arc<VaultHandle>) -> Result<u32, FfiError> {
    let mut guard = handle.lock_vault();
    let vault = guard.as_mut()?;
    let pruned = vault.coalesce_dirty_markers().map_err(store_into_ffi)?;
    Ok(u32::try_from(pruned).unwrap_or(u32::MAX))
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

    /// A non-secret chain config pointing at an unreachable RPC + a
    /// non-existent deployment path. Used to exercise the REAL flush
    /// path: the binding builds the adapter engine-side (which fails
    /// fast on the bad config) so the error-mapping path is asserted
    /// hermetically without a live network.
    fn bogus_config() -> FfiChainConfig {
        FfiChainConfig {
            schema_version: 1,
            rpc_url: "http://127.0.0.1:1".into(),
            deployment_path: "/no/such/path/base-sepolia.json".into(),
            prefer_websocket: false,
        }
    }

    /// `vault_publish_queue_state` on a fresh vault returns
    /// `dirty_count=0` and the empty queue shape.
    #[test]
    fn publish_queue_state_zero_on_fresh_vault() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        let state = vault_publish_queue_state(h).expect("publish_queue_state");
        assert_eq!(state.dirty_count, 0);
        assert_eq!(state.dirty_byte_size, 0);
        assert!(state.window_started_at_unix_ms.is_none());
        assert!(!state.blocked_on_balance);
    }

    /// Locked vault → `FfiError::Session` from
    /// `vault_publish_queue_state`. Session discipline parity.
    #[test]
    fn publish_queue_state_rejects_placeholder_with_session_error() {
        let empty = VaultHandle::new_placeholder();
        let err = vault_publish_queue_state(empty).unwrap_err();
        assert!(
            matches!(err, FfiError::Session { .. }),
            "expected FfiError::Session, got {err:?}"
        );
    }

    /// `vault_coalesce_dirty_markers` on a fresh vault returns 0.
    #[test]
    fn coalesce_dirty_markers_returns_zero_on_empty_queue() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        let pruned = vault_coalesce_dirty_markers(h).expect("coalesce");
        assert_eq!(pruned, 0);
    }

    /// `vault_enable_window_elapsed_flush` toggles cleanly.
    #[test]
    fn enable_window_elapsed_flush_toggles_cleanly() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        vault_enable_window_elapsed_flush(Arc::clone(&h), true).expect("on");
        vault_enable_window_elapsed_flush(h, false).expect("off");
    }

    /// **MVP-3 #100 (R-f) — REAL-path stub-parity flip.** With an
    /// empty publish queue + a bogus chain config, the REAL flush path
    /// runs: the binding sources the gas signer engine-side, mints the
    /// throwaway device key, and attempts to build the adapter — which
    /// fails fast on the missing deployment file. The error maps to
    /// `FfiError::Chain` (NOT the old `Internal` stub), proving the
    /// body is wired to the engine method.
    #[test]
    fn flush_publish_queue_real_path_maps_adapter_error_to_chain() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        let err = vault_flush_publish_queue(h, bogus_config(), true).unwrap_err();
        assert!(
            matches!(err, FfiError::Chain { .. }),
            "expected FfiError::Chain from adapter construction, got {err:?}"
        );
    }

    /// **MVP-3 #100 (R-f) — per-binding session gate (L4).** A locked
    /// vault errors `FfiError::Session` BEFORE any chain primitive
    /// (adapter construction never runs), even with a config present.
    #[test]
    fn flush_publish_queue_rejects_locked_vault_before_chain() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        {
            let mut g = h.lock_vault();
            g.as_mut().unwrap().lock();
        }
        let err = vault_flush_publish_queue(h, bogus_config(), true).unwrap_err();
        assert!(
            matches!(err, FfiError::Session { .. }),
            "expected FfiError::Session (L4 gate before chain), got {err:?}"
        );
    }

    /// **MVP-3 #100 (R-f) — per-binding session gate (placeholder).**
    /// A placeholder handle (no vault installed) errors
    /// `FfiError::Session`.
    #[test]
    fn flush_publish_queue_rejects_placeholder() {
        let empty = VaultHandle::new_placeholder();
        let err = vault_flush_publish_queue(empty, bogus_config(), true).unwrap_err();
        assert!(
            matches!(err, FfiError::Session { .. }),
            "expected FfiError::Session, got {err:?}"
        );
    }
}
