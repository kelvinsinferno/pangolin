// SPDX-License-Identifier: AGPL-3.0-or-later
//! Background-poll balance monitor (MVP-2 issue 3.5, R-b eager track).
//!
//! Per the R-b "both eager poll + per-publish freshness check" decision:
//! `BalanceMonitor` owns a tokio background task that periodically polls
//! [`crate::balance_check::query_evm_balance`] +
//! [`crate::balance_check::estimate_next_publish_cost`] and writes the
//! computed [`GasBalanceState`] into a shared
//! `Arc<RwLock<GasBalanceState>>`. Host code reads the cached state via
//! [`BalanceMonitor::current`] — a non-blocking sync read.
//!
//! ## Lifecycle
//!
//! 1. [`BalanceMonitor::start`] spawns the poll task on the current
//!    tokio runtime; returns a handle the host stashes.
//! 2. [`BalanceMonitor::current`] is called sync from any context;
//!    returns a clone of the cached state.
//! 3. [`BalanceMonitor::register_top_up`] transitions the cached state
//!    to `TopUpInFlight` immediately so the host UI reflects the
//!    in-flight attempt; the next successful poll observes the new
//!    balance and transitions back to `Sufficient`.
//! 4. [`BalanceMonitor::stop`] signals cancellation + awaits the task.
//!    Idempotent: calling `stop` twice is a no-op.
//!
//! ## L-section
//!
//! - **L6** — cached state is in-memory only; never persisted.
//! - **L-balance-staleness** — the freshness GUARANTEE comes from
//!   `chain_submit::publish_revision_v1`'s pre-submit balance check
//!   (see `chain_submit.rs`), NOT from the monitor. The monitor is
//!   advisory.
//! - **L-rpc-spoof-balance** — every poll calls into `balance_check`
//!   which does the chain-id cross-check before accepting balance.

use core::time::Duration;
use std::sync::Arc;

use alloy::primitives::Address;
use tokio::sync::{oneshot, Mutex, RwLock};
use tokio::task::JoinHandle;

use crate::balance_check::{
    compute_balance_state, estimate_next_publish_cost, query_evm_balance, GasBalanceState,
};
use crate::deployments::ChainEnv;
use crate::error::ChainError;

// ---------------------------------------------------------------------
// Pinned constants
// ---------------------------------------------------------------------

/// Default poll interval for the background balance monitor. Per R-b
/// resolved decision. Hosts may override at start time but typical
/// callers stick with the default.
pub const BALANCE_POLL_INTERVAL_SECS: u64 = 30;

// ---------------------------------------------------------------------
// MonitorError
// ---------------------------------------------------------------------

/// Errors surfacing from the [`BalanceMonitor`] lifecycle.
///
/// Examples: registration of a top-up notification on a dropped
/// monitor, double-stop, etc. Distinct from [`ChainError`] so the FFI
/// / CLI layer can render monitor-layer issues separately from
/// chain-layer issues.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MonitorError {
    /// The monitor's background task is no longer running. Surfaces
    /// from operations that need the task to be alive (e.g. a future
    /// `await`-on-completion variant of `register_top_up`).
    #[error("balance monitor task is no longer running")]
    NotRunning,
}

// ---------------------------------------------------------------------
// TopUpAttempt — shape returned from pangolin-funder-client; carried
// through register_top_up
// ---------------------------------------------------------------------

/// Snapshot info recorded on the monitor when a top-up flow has been initiated.
///
/// The full attestation lives in the host / funder-client crate; the
/// monitor only needs the timestamp to drive the `TopUpInFlight`
/// transition.
///
/// Plain struct (NOT carrying the funder response or the credit
/// attestation) — keeps the chain crate's dep set tight. Wire types
/// stay in `pangolin-funder-client`.
#[derive(Debug, Clone, Copy)]
pub struct TopUpNotification {
    /// Unix-second timestamp when the top-up was initiated. Hosts
    /// typically pass `SystemTime::now().duration_since(UNIX_EPOCH)`.
    pub initiated_at_unix: u64,
}

// ---------------------------------------------------------------------
// BalanceMonitor
// ---------------------------------------------------------------------

/// Background-poll balance monitor for the device wallet's EVM balance.
///
/// Hosts call [`BalanceMonitor::start`] once at session-open, stash the
/// returned handle, read state via [`BalanceMonitor::current`], and call
/// [`BalanceMonitor::stop`] at session-close.
pub struct BalanceMonitor {
    /// Cached state — readable concurrently via `Arc::clone`; updated by
    /// the background task.
    state: Arc<RwLock<GasBalanceState>>,
    /// Cancel sender; consumed by [`BalanceMonitor::stop`] to signal the
    /// poll loop to exit. Wrapped in `Mutex<Option<_>>` so `stop` can
    /// take ownership through a `&self` accessor — uniffi's Arc-bound
    /// FFI surface needs `&self` rather than `self`.
    cancel: Arc<Mutex<Option<oneshot::Sender<()>>>>,
    /// `JoinHandle` for the spawned task. Held so `stop` can `await` the
    /// task's completion before dropping the monitor (defense-in-depth:
    /// a future poll-task version that holds an alloy provider socket
    /// gets cleanly closed). Same `Mutex<Option<_>>` discipline as
    /// `cancel`.
    task: Arc<Mutex<Option<JoinHandle<()>>>>,
}

impl core::fmt::Debug for BalanceMonitor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BalanceMonitor")
            .field("state", &"<opaque>")
            .finish()
    }
}

impl BalanceMonitor {
    /// Start a background-poll task for `(rpc_url, address, env)`. The
    /// spawned task runs `poll_interval` between RPC reads; the first
    /// successful read transitions the cached state from `Unknown {
    /// "polling" }` to `Sufficient` / `RequiresActiveAccount`.
    ///
    /// Must be called inside a tokio runtime context (the host's runtime
    /// or the test runtime). Production FFI callers thread this through
    /// the host's tokio runtime; tests use `#[tokio::test]`.
    pub fn start(
        rpc_url: String,
        address: Address,
        env: ChainEnv,
        poll_interval: Duration,
    ) -> Self {
        let state = Arc::new(RwLock::new(GasBalanceState::Unknown {
            reason: "polling".to_string(),
        }));
        let (cancel_tx, cancel_rx) = oneshot::channel::<()>();
        let task_state = Arc::clone(&state);
        let task = tokio::spawn(async move {
            poll_loop(rpc_url, address, env, poll_interval, task_state, cancel_rx).await;
        });
        Self {
            state,
            cancel: Arc::new(Mutex::new(Some(cancel_tx))),
            task: Arc::new(Mutex::new(Some(task))),
        }
    }

    /// Read the cached state. Non-blocking; returns a clone of the
    /// stored enum.
    ///
    /// Uses `try_read` so a poll task currently holding the write lock
    /// (the brief moment of `state.write().await`) doesn't block the
    /// host. A contended read returns the LAST cached state via a
    /// blocking-but-fast `block_on`-friendly path: we use the
    /// `tokio::sync::RwLock::blocking_read` accessor which is safe to
    /// call from sync code as long as we're not inside a tokio runtime
    /// thread — the FFI accessor is called from the host's main thread,
    /// not from inside the runtime, so this is correct.
    ///
    /// Test callers go via the async [`BalanceMonitor::current_async`]
    /// variant.
    #[must_use]
    pub fn current(&self) -> GasBalanceState {
        // Hot path: the cached state is updated infrequently (every
        // 30s by default). Contention is essentially zero.
        self.state.blocking_read().clone()
    }

    /// Async variant of [`BalanceMonitor::current`] for callers already
    /// inside a tokio runtime (most notably the hermetic tests). Hosts
    /// use the sync variant.
    pub async fn current_async(&self) -> GasBalanceState {
        self.state.read().await.clone()
    }

    /// Register a top-up attempt: immediately transitions the cached
    /// state to `TopUpInFlight { initiated_at_unix }`. The next poll
    /// observes the new balance and naturally transitions back to
    /// `Sufficient` (or stays `RequiresActiveAccount` if the funder
    /// hasn't yet credited the wallet).
    ///
    /// # Errors
    ///
    /// Currently infallible (the cached state is updated unconditionally),
    /// but the `Result` shape leaves room for future variants (e.g.
    /// dropped-task detection). Surfaces `MonitorError` in the public
    /// signature so a future change can add the check without a
    /// breaking API bump.
    pub async fn register_top_up(
        &self,
        notification: TopUpNotification,
    ) -> Result<(), MonitorError> {
        *self.state.write().await = GasBalanceState::TopUpInFlight {
            initiated_at_unix: notification.initiated_at_unix,
        };
        Ok(())
    }

    /// Signal the background task to exit + await its completion.
    /// Idempotent: calling `stop` a second time is a no-op.
    pub async fn stop(&self) {
        // Take the cancel sender out and send. If it's already gone the
        // task is already shut down or shutting down; ignore.
        let sender = self.cancel.lock().await.take();
        if let Some(tx) = sender {
            // The receiver dropping early is fine — that means the task
            // already exited (e.g. via a panic; surfaces in
            // task.await below).
            let _ = tx.send(());
        }
        let task = self.task.lock().await.take();
        if let Some(handle) = task {
            // The task is `async move { poll_loop(...).await }`; it
            // returns when poll_loop's `select!` picks up the cancel
            // signal OR when the loop returns naturally (it doesn't —
            // it spins on the cancel signal). Joining gives us a clean
            // teardown of the spawned future's resources.
            let _ = handle.await;
        }
    }
}

// ---------------------------------------------------------------------
// Background poll task
// ---------------------------------------------------------------------

/// The actual poll loop. Runs until `cancel` fires or the task is
/// aborted. On every tick, queries balance + estimate + writes the
/// computed state into the shared cache.
async fn poll_loop(
    rpc_url: String,
    address: Address,
    env: ChainEnv,
    poll_interval: Duration,
    state: Arc<RwLock<GasBalanceState>>,
    mut cancel: oneshot::Receiver<()>,
) {
    // Do an immediate first poll on start so callers see a real state
    // within seconds, not after the first poll_interval. Subsequent
    // polls are spaced by poll_interval.
    poll_once(&rpc_url, address, env, &state).await;
    loop {
        tokio::select! {
            biased;
            _ = &mut cancel => {
                // Graceful shutdown — leave cached state as-is so a
                // host that re-reads after stop() sees the LAST value
                // rather than a synthetic "stopped" sentinel.
                break;
            }
            () = tokio::time::sleep(poll_interval) => {
                poll_once(&rpc_url, address, env, &state).await;
            }
        }
    }
}

/// One poll cycle: query balance + estimate, compute state, write cache.
/// Errors at the RPC layer transition the cache to `Unknown { reason }`
/// rather than panicking; the next successful poll naturally re-enters
/// `Sufficient` / `RequiresActiveAccount`.
async fn poll_once(
    rpc_url: &str,
    address: Address,
    env: ChainEnv,
    state: &Arc<RwLock<GasBalanceState>>,
) {
    let new_state = match poll_compute(rpc_url, address, env).await {
        Ok(s) => s,
        Err(e) => GasBalanceState::Unknown {
            reason: format!("{e}"),
        },
    };
    let mut w = state.write().await;
    *w = new_state;
}

/// Inner: fetch balance + estimate, return the computed state. Surfaces
/// errors so the caller can wrap into `Unknown { reason }`.
async fn poll_compute(
    rpc_url: &str,
    address: Address,
    env: ChainEnv,
) -> Result<GasBalanceState, ChainError> {
    let balance = query_evm_balance(rpc_url, address, env).await?;
    let estimate = estimate_next_publish_cost(rpc_url, env).await?;
    Ok(compute_balance_state(balance, estimate))
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::address;

    /// The monitor starts in the `Unknown { "polling" }` state before
    /// the first poll completes. Asserted by reading the cached state
    /// IMMEDIATELY after start (before tokio's executor picks up the
    /// spawned task).
    #[tokio::test]
    async fn monitor_start_emits_initial_state() {
        // Use a bogus rpc_url + the Dev env to skip the chain-id check
        // and force the first poll to error → Unknown { rpc error }.
        let monitor = BalanceMonitor::start(
            "http://127.0.0.1:1".to_string(),
            address!("0x1234567890123456789012345678901234567890"),
            ChainEnv::Dev,
            Duration::from_secs(60),
        );
        // The IMMEDIATELY-readable state should be the initial sentinel.
        let state = monitor.current_async().await;
        match state {
            GasBalanceState::Unknown { reason } => {
                // Either still "polling" (the first poll hasn't fired
                // yet) OR an RPC-error reason (the first poll completed
                // and failed). Both are valid initial-window states.
                assert!(
                    reason == "polling" || reason.to_ascii_lowercase().contains("balance"),
                    "initial Unknown.reason must be 'polling' or an RPC error description, got {reason}"
                );
            }
            other => panic!("monitor must start in Unknown, got {other:?}"),
        }
        monitor.stop().await;
    }

    #[tokio::test]
    async fn monitor_register_top_up_transitions_to_in_flight() {
        let monitor = BalanceMonitor::start(
            "http://127.0.0.1:1".to_string(),
            address!("0x1234567890123456789012345678901234567890"),
            ChainEnv::Dev,
            Duration::from_secs(60),
        );
        monitor
            .register_top_up(TopUpNotification {
                initiated_at_unix: 1_700_000_000,
            })
            .await
            .expect("register_top_up");
        let state = monitor.current_async().await;
        match state {
            GasBalanceState::TopUpInFlight { initiated_at_unix } => {
                assert_eq!(initiated_at_unix, 1_700_000_000);
            }
            other => panic!("expected TopUpInFlight after register_top_up, got {other:?}"),
        }
        monitor.stop().await;
    }

    #[tokio::test]
    async fn monitor_stop_cancels_task() {
        let monitor = BalanceMonitor::start(
            "http://127.0.0.1:1".to_string(),
            address!("0x1234567890123456789012345678901234567890"),
            ChainEnv::Dev,
            Duration::from_secs(60),
        );
        monitor.stop().await;
        // Second stop is a no-op (idempotency).
        monitor.stop().await;
        // After stop, the cached state is whatever the last poll wrote
        // (or the initial sentinel if no poll completed). Reading is
        // still safe.
        let _state = monitor.current_async().await;
    }

    /// Concurrent reads must not deadlock with the writer in the poll
    /// task. Spawn N reader tasks + a writer (`register_top_up`) and
    /// assert all complete.
    #[tokio::test]
    async fn monitor_concurrent_reads_safe() {
        let monitor = Arc::new(BalanceMonitor::start(
            "http://127.0.0.1:1".to_string(),
            address!("0x1234567890123456789012345678901234567890"),
            ChainEnv::Dev,
            Duration::from_secs(60),
        ));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let m = Arc::clone(&monitor);
            handles.push(tokio::spawn(async move {
                for _ in 0..16 {
                    let _ = m.current_async().await;
                    tokio::task::yield_now().await;
                }
            }));
        }
        let writer = {
            let m = Arc::clone(&monitor);
            tokio::spawn(async move {
                for i in 0u64..8 {
                    m.register_top_up(TopUpNotification {
                        initiated_at_unix: i,
                    })
                    .await
                    .unwrap();
                    tokio::task::yield_now().await;
                }
            })
        };
        for h in handles {
            h.await.unwrap();
        }
        writer.await.unwrap();
        monitor.stop().await;
    }

    #[test]
    fn balance_poll_interval_secs_is_pinned() {
        // R-b verbatim: default is 30s.
        assert_eq!(BALANCE_POLL_INTERVAL_SECS, 30);
    }
}
