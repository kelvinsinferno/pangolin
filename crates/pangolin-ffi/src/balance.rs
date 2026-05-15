// SPDX-License-Identifier: AGPL-3.0-or-later
//! Gas-balance FFI shapes + entry points (MVP-2 issue 3.5, R-d).
//!
//! Wires [`pangolin_chain::BalanceMonitor`] across the FFI boundary so
//! the host can:
//!
//! 1. Start the background-poll task at session-open with
//!    [`balance_monitor_start`].
//! 2. Read the cached state via [`gas_balance_state`] (non-blocking
//!    sync call from the host thread).
//! 3. Stop the task at session-close with [`balance_monitor_stop`].
//!
//! Active-session policy lives HERE at the FFI boundary (L5 nuance):
//! the chain-crate balance helper is policy-agnostic, but locked-vault
//! callers crossing FFI get `FfiError::Session`.
//!
//! ## Surface vocabulary (L4 + §8.1.5)
//!
//! [`GasBalanceStateFfi`]'s variant names mirror
//! [`pangolin_chain::GasBalanceState`] verbatim — `Sufficient` /
//! `RequiresActiveAccount` / `TopUpInFlight` / `Unknown`. NEVER pricing
//! copy. Wei values cross as **hex strings** (`String`) to preserve
//! u128 fidelity through uniffi (u64 max is only ~18.4 ETH in wei,
//! which is small enough to overflow on a funded mainnet wallet).

use std::sync::Arc;

use alloy::primitives::Address;
use pangolin_chain::{BalanceMonitor, ChainEnv, GasBalanceState};

use crate::error::FfiError;
use crate::session::VaultHandle;

// ---------------------------------------------------------------------
// FFI-friendly mirror of GasBalanceState
// ---------------------------------------------------------------------

/// FFI-mirror of [`pangolin_chain::GasBalanceState`].
///
/// Variant names follow the §8.1.5 entitlement-state vocabulary
/// verbatim. Wei values cross as hex strings (`"0x..."`) so a 100 ETH
/// wallet (above u64 max wei) doesn't truncate.
///
/// **NEVER renamed** to a pricing-copy variant — the variant strings
/// are user-facing through host rendering and §8.1.5 forbids
/// `InsufficientFunds` / `LowBalance` / `OutOfGas` / `Upgrade` /
/// pricing copy.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum GasBalanceStateFfi {
    /// Wallet balance covers `MIN_BUFFER_REVISIONS = 3` future
    /// revisions at the currently-observed gas price.
    Sufficient {
        /// `"0x..."` hex string of the wallet balance in wei.
        balance_wei_hex: String,
        /// `"0x..."` hex string of the next-publish cost estimate in wei.
        estimate_wei_hex: String,
    },
    /// Wallet balance does NOT cover the 3-revision threshold; host
    /// renders the §8.1.5 `RequiresActiveAccount` flow.
    RequiresActiveAccount {
        balance_wei_hex: String,
        estimate_wei_hex: String,
    },
    /// A top-up flow is in flight; the next poll will observe the new
    /// balance.
    TopUpInFlight {
        /// Unix-second timestamp when the top-up was initiated.
        initiated_at_unix: u64,
    },
    /// State could not be determined (RPC failure, locked vault,
    /// monitor not yet polled, etc.).
    Unknown {
        /// Non-secret human description of the unknown cause.
        reason: String,
    },
}

impl From<GasBalanceState> for GasBalanceStateFfi {
    fn from(state: GasBalanceState) -> Self {
        match state {
            GasBalanceState::Sufficient {
                balance_wei,
                estimate_wei,
            } => Self::Sufficient {
                balance_wei_hex: format!("0x{balance_wei:x}"),
                estimate_wei_hex: format!("0x{estimate_wei:x}"),
            },
            GasBalanceState::RequiresActiveAccount {
                balance_wei,
                estimate_wei,
            } => Self::RequiresActiveAccount {
                balance_wei_hex: format!("0x{balance_wei:x}"),
                estimate_wei_hex: format!("0x{estimate_wei:x}"),
            },
            GasBalanceState::TopUpInFlight { initiated_at_unix } => {
                Self::TopUpInFlight { initiated_at_unix }
            }
            GasBalanceState::Unknown { reason } => Self::Unknown { reason },
        }
    }
}

// ---------------------------------------------------------------------
// MonitorHandle (FFI Object)
// ---------------------------------------------------------------------

/// Opaque handle to a running [`pangolin_chain::BalanceMonitor`].
///
/// The host obtains one via [`balance_monitor_start`], reads cached
/// state via [`gas_balance_state`], and disposes via
/// [`balance_monitor_stop`]. Cloning the `Arc` is cheap; the underlying
/// background task runs on the active tokio runtime.
#[derive(uniffi::Object)]
pub struct MonitorHandle {
    inner: BalanceMonitor,
}

impl std::fmt::Debug for MonitorHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MonitorHandle").finish()
    }
}

// ---------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------

fn store_into_ffi(err: pangolin_store::StoreError) -> FfiError {
    FfiError::from(pangolin_core::Error::from(err))
}

/// Active-session gate: borrow the vault `&mut`, error
/// `FfiError::Session` on locked / placeholder.
///
/// L5 FFI policy: balance reads require an active session at this
/// boundary (the chain-crate helper is policy-agnostic; the policy
/// lives here). `as_mut` errors on a placeholder; we also want to
/// reject a LOCKED-but-previously-unlocked vault. The `evm_wallet`
/// accessor handles that: locked vault → `StoreError::NotUnlocked`.
#[allow(clippy::significant_drop_tightening)]
fn require_unlocked(handle: &Arc<VaultHandle>) -> Result<(), FfiError> {
    let mut guard = handle.lock_vault();
    let vault = guard.as_mut()?;
    let _ = vault.evm_wallet().map_err(store_into_ffi)?;
    Ok(())
}

// ---------------------------------------------------------------------
// FFI entry points
// ---------------------------------------------------------------------

/// Start the background-poll balance monitor.
///
/// The host calls this once at session-open (or whenever it wants to
/// begin observing balance), stashes the returned handle, and reads
/// state via [`gas_balance_state`] until calling
/// [`balance_monitor_stop`] at teardown.
///
/// **Active-session gate** (L5 FFI policy): a locked vault errors
/// `FfiError::Session`. The chain-crate helper is policy-agnostic; the
/// policy lives at the FFI boundary.
///
/// # Arguments
///
/// - `handle` — the vault handle. Must be unlocked. Used to read the
///   cached `devices.evm_address` (sync), then released.
/// - `rpc_url` — RPC endpoint URL.
/// - `poll_interval_secs` — interval between background polls. Pass
///   `pangolin_chain::BALANCE_POLL_INTERVAL_SECS` (= 30) for the
///   default cadence.
///
/// # Errors
///
/// `FfiError::Session` for a locked / placeholder handle;
/// `FfiError::Store` if the device row's `evm_address` column is
/// missing (legacy pre-3.2 row); `FfiError::Validation` for an
/// out-of-range `poll_interval_secs` of `0`.
#[allow(clippy::significant_drop_tightening)]
#[uniffi::export]
pub fn balance_monitor_start(
    handle: Arc<VaultHandle>,
    rpc_url: String,
    poll_interval_secs: u64,
) -> Result<Arc<MonitorHandle>, FfiError> {
    if poll_interval_secs == 0 {
        return Err(FfiError::Validation {
            kind: "argument".into(),
            message: "poll_interval_secs must be > 0".into(),
        });
    }
    // Read the address with the vault guard held only briefly so the
    // monitor's tokio spawn doesn't keep the mutex.
    let address_bytes = {
        let mut guard = handle.lock_vault();
        let vault = guard.as_mut()?;
        // Active-session gate at the FFI boundary (L5): require a live
        // session before starting the monitor. Locked vault →
        // FfiError::Session.
        let _ = vault.evm_wallet().map_err(store_into_ffi)?;
        vault.evm_wallet_address().map_err(store_into_ffi)?
    };
    let address = Address::from(address_bytes);
    // 3.5 ships against Base Sepolia only (master plan §5 row 3.5).
    let env = ChainEnv::BaseSepolia;
    let poll_interval = core::time::Duration::from_secs(poll_interval_secs);
    let monitor = BalanceMonitor::start(rpc_url, address, env, poll_interval);
    Ok(Arc::new(MonitorHandle { inner: monitor }))
}

/// Stop a running balance monitor. Idempotent: a second stop is a
/// no-op.
#[uniffi::export]
pub async fn balance_monitor_stop(monitor: Arc<MonitorHandle>) -> Result<(), FfiError> {
    monitor.inner.stop().await;
    Ok(())
}

/// Read the cached gas-balance state.
///
/// **Active-session gate** (L5 FFI policy): a locked vault errors
/// `FfiError::Session`.
///
/// Returns a [`GasBalanceStateFfi`] that mirrors the chain crate's
/// `GasBalanceState`. The wei fields cross as hex strings so a 100 ETH
/// balance doesn't truncate.
///
/// # Errors
///
/// `FfiError::Session` for a locked / placeholder handle.
#[allow(clippy::significant_drop_tightening)]
#[uniffi::export]
pub fn gas_balance_state(
    handle: Arc<VaultHandle>,
    monitor: Arc<MonitorHandle>,
) -> Result<GasBalanceStateFfi, FfiError> {
    require_unlocked(&handle)?;
    let state = monitor.inner.current();
    Ok(GasBalanceStateFfi::from(state))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::VaultHandle;
    use pangolin_core::{PinIdentityProof, PressYPresenceProof, Vault};
    use pangolin_crypto::secret::SecretBytes;
    use std::sync::Arc;

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

    /// Locked vault → `FfiError::Session` from `gas_balance_state`.
    #[tokio::test]
    async fn ffi_gas_balance_state_requires_active_session() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        // Start a monitor while unlocked.
        let monitor = balance_monitor_start(Arc::clone(&h), "http://127.0.0.1:1".to_string(), 60)
            .expect("monitor start while unlocked");
        // Now lock the vault.
        {
            let mut guard = h.lock_vault();
            guard.as_mut().unwrap().lock();
        }
        // gas_balance_state must error.
        let err = gas_balance_state(Arc::clone(&h), Arc::clone(&monitor)).unwrap_err();
        assert!(
            matches!(err, FfiError::Session { .. }),
            "expected FfiError::Session, got {err:?}"
        );
        // Teardown.
        balance_monitor_stop(monitor).await.unwrap();
    }

    /// Full lifecycle: start, read, stop. The sync `gas_balance_state`
    /// accessor uses `tokio::sync::RwLock::blocking_read` internally;
    /// production FFI callers invoke it from the HOST's main thread
    /// (NOT from inside the runtime). The test harness simulates that
    /// via `spawn_blocking` on a multi-threaded runtime — calling
    /// `blocking_read` directly from a worker thread of a current-
    /// thread runtime panics with "Cannot block the current thread
    /// from within a runtime".
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ffi_balance_monitor_start_stop_lifecycle() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        let monitor = balance_monitor_start(Arc::clone(&h), "http://127.0.0.1:1".to_string(), 60)
            .expect("monitor start");
        let h_clone = Arc::clone(&h);
        let m_clone = Arc::clone(&monitor);
        let _state =
            tokio::task::spawn_blocking(move || gas_balance_state(h_clone, m_clone).unwrap())
                .await
                .unwrap();
        balance_monitor_stop(Arc::clone(&monitor)).await.unwrap();
        // Idempotent.
        balance_monitor_stop(monitor).await.unwrap();
    }

    /// An unlocked vault returns SOME state from `gas_balance_state`
    /// (likely `Unknown` since the bogus `rpc_url` errors).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ffi_gas_balance_state_returns_state_when_unlocked() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        let monitor = balance_monitor_start(Arc::clone(&h), "http://127.0.0.1:1".to_string(), 60)
            .expect("monitor start");
        let h_clone = Arc::clone(&h);
        let m_clone = Arc::clone(&monitor);
        let state =
            tokio::task::spawn_blocking(move || gas_balance_state(h_clone, m_clone).unwrap())
                .await
                .unwrap();
        // Any of the variants is valid for the initial / first-poll
        // window. We only assert it doesn't panic + we got a typed
        // shape.
        match state {
            GasBalanceStateFfi::Sufficient { .. }
            | GasBalanceStateFfi::RequiresActiveAccount { .. }
            | GasBalanceStateFfi::TopUpInFlight { .. }
            | GasBalanceStateFfi::Unknown { .. } => {}
        }
        balance_monitor_stop(monitor).await.unwrap();
    }

    /// Placeholder handle → `FfiError::Session` from
    /// `balance_monitor_start`.
    #[test]
    fn ffi_balance_monitor_start_rejects_placeholder_handle() {
        let empty = VaultHandle::new_placeholder();
        let err = balance_monitor_start(empty, "http://127.0.0.1:1".to_string(), 60).unwrap_err();
        assert!(
            matches!(err, FfiError::Session { .. }),
            "expected FfiError::Session, got {err:?}"
        );
    }

    /// Zero poll interval rejected as `Validation`.
    #[test]
    fn ffi_balance_monitor_start_rejects_zero_interval() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        let err = balance_monitor_start(h, "http://127.0.0.1:1".to_string(), 0).unwrap_err();
        assert!(
            matches!(&err, FfiError::Validation { kind, .. } if kind == "argument"),
            "expected FfiError::Validation, got {err:?}"
        );
    }
}
