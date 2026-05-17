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
//! boundary. The chain adapter is NOT yet FFI-exposed; this
//! module's `vault_flush_publish_queue` is a placeholder that
//! returns `FfiError::Internal { ... }` until the chain-adapter
//! FFI surface lands in MVP-3. The CLI consumes the engine
//! method directly (no FFI involved); this binding is for the
//! host UI's eventual use.

#![forbid(unsafe_code)]

use std::sync::Arc;

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
/// **CLI-V1 (R-g) stub.** The full call requires a
/// [`pangolin_chain::ChainAdapter`] handle + a
/// [`pangolin_crypto::keys::DeviceKey`] handle, neither of which has
/// an FFI surface in CLI-V1. The binding is exposed here for surface-
/// freeze purposes — MVP-3 ships the chain-adapter handle and wires
/// the body. Returns `FfiError::Internal { kind: "ffi_not_wired" }`
/// at call time.
///
/// # Errors
///
/// Always returns
/// `FfiError::Internal { message: "vault_flush_publish_queue requires chain-adapter FFI (MVP-3)" }`
/// in CLI-V1.
#[allow(
    clippy::significant_drop_tightening,
    clippy::needless_pass_by_value,
    unused_variables
)]
#[uniffi::export]
pub fn vault_flush_publish_queue(
    handle: Arc<VaultHandle>,
    force: bool,
) -> Result<FfiBatchFlushReport, FfiError> {
    // Active-session gate at the FFI boundary (L5).
    let mut guard = handle.lock_vault();
    let _vault = guard.as_mut()?;
    Err(FfiError::Internal {
        message:
            "vault_flush_publish_queue requires chain-adapter FFI (MVP-3); use the CLI for now"
                .to_string(),
    })
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

    /// `vault_flush_publish_queue` returns the documented
    /// `FfiError::Internal` stub for CLI-V1.
    #[test]
    fn flush_publish_queue_stub_returns_internal_in_cli_v1() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        let err = vault_flush_publish_queue(h, true).unwrap_err();
        assert!(
            matches!(err, FfiError::Internal { .. }),
            "expected FfiError::Internal (CLI-V1 stub), got {err:?}"
        );
    }
}
