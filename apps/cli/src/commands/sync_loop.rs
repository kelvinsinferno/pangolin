// SPDX-License-Identifier: AGPL-3.0-or-later
//! `pangolin-cli sync loop` — canonical host scheduler loop body.
//!
//! Implements the template from
//! `docs/architecture/sync-orchestrator.md` lines 55-180 with
//! CLI-specific wrapping:
//!
//! - `tokio::select!` with two timer arms (pull interval + flush
//!   window).
//! - `tokio::signal::ctrl_c()` for graceful shutdown.
//! - Pre-lock drain on shutdown via `Vault::lock_with_drain`
//!   (R-h + L3).
//! - `tokio::sync::watch::channel` carrying the freshly-computed
//!   `SyncStatus` per tick.
//! - Per-tick status logging — JSON-Lines on stdout if `--json`;
//!   human-readable line on stderr otherwise (R-e Option A).

#![forbid(unsafe_code)]

use core::time::Duration;
use std::sync::Arc;

use alloy::primitives::Address;
use anyhow::{Context, Result};
use pangolin_chain::{BalanceMonitor, BaseSepoliaAdapter, ChainEnv};
use pangolin_crypto::keys::DeviceKey;
use pangolin_crypto::secret::SecretBytes;
use pangolin_store::{
    compute_next_status, BatchFlushError, BatchFlushErrorKind, ConflictSnapshot, LastFlushOutcome,
    LastPullOutcome, PullError, PullErrorKind, SyncMode, SyncStatus, Vault,
};
use tokio::sync::{watch, Mutex};

use crate::cli::{GlobalArgs, SyncLoopArgs};
use crate::config::ResolvedConfig;
use crate::keystore::{read_keystore_password, resolve_keystore_path};
use crate::vault_open::open_and_unlock;

/// Run `sync loop`.
#[allow(clippy::too_many_lines, clippy::future_not_send)]
// `Vault` is intentionally `!Send` (P4 audit M-3: holds RefCell +
// dyn Clock); the runtime is single-threaded by design (host CLI
// main thread). Same posture as `select_sync_mode` / `pull_once`.
pub async fn run(global: &GlobalArgs, args: SyncLoopArgs) -> Result<()> {
    let cfg = ResolvedConfig::from_args(global)?;
    let deployment_path = cfg.require_deployment_file()?.clone();

    let keystore_path = resolve_keystore_path(
        args.account.as_deref(),
        args.keystore_dir.as_deref(),
        args.keystore_path.as_deref(),
    )?;

    let mut vault = open_and_unlock(&args.vault_path, args.vault_password.as_deref())
        .context("vault open + unlock failed")?;

    let keystore_password =
        read_keystore_password(&keystore_path, args.keystore_password.as_deref())?;
    let password_secret = SecretBytes::new(keystore_password.as_bytes().to_vec());
    drop(keystore_password);

    let rpc_url_default = read_deployment_default_rpc(&deployment_path)?;
    let rpc_url = cfg.rpc_url_or_default(&rpc_url_default);
    cfg.enforce_rpc_scheme(&rpc_url)?;
    let adapter = BaseSepoliaAdapter::new_with_keystore(
        &rpc_url,
        &deployment_path,
        &keystore_path,
        &password_secret,
    )
    .await
    .context("failed to construct BaseSepoliaAdapter")?;
    drop(password_secret);

    let device_key = DeviceKey::generate();

    // Start the balance monitor — read the per-device address from
    // the vault, then thread it into a `BalanceMonitor::start`.
    let address_bytes = vault
        .evm_wallet_address()
        .context("evm_wallet_address failed")?;
    let address = Address::from(address_bytes);
    let balance_monitor = std::sync::Arc::new(BalanceMonitor::start(
        rpc_url.clone(),
        address,
        ChainEnv::BaseSepolia,
        Duration::from_secs(30),
    ));

    let vault_id = vault.vault_id();
    let outcome = run_loop_body(
        &mut vault,
        &adapter,
        &device_key,
        &balance_monitor,
        vault_id,
        ChainEnv::BaseSepolia,
        &rpc_url,
        cfg.json,
        args.once,
        args.pull_interval_secs,
        args.flush_window_secs,
    )
    .await;

    // R-e (5.4): pre-lock drain on shutdown via `lock_with_drain`
    // — closes the 5.1 L1 deviation in the canonical host loop.
    // Best-effort: a non-fatal flush error is logged + we still
    // transition to Locked.
    let drain_result = vault.lock_with_drain(&adapter, &device_key).await;
    balance_monitor.stop().await;
    if let Err(e) = drain_result {
        if cfg.json {
            let value = serde_json::json!({
                "event": "shutdown_drain_error",
                "error": format!("{e}"),
            });
            eprintln!("{value}");
        } else {
            eprintln!("shutdown drain error (dirty markers persist): {e}");
        }
    }

    outcome
}

/// The canonical-host scheduler loop body. Factored out of `run`
/// so the integration tests can drive it directly through the
/// library entry point.
///
/// Returns `Ok(())` for a clean exit (SIGINT / once-mode / session
/// teardown via `NoActiveSession`) or surfaces a fatal store-side
/// error.
#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::future_not_send
)]
pub async fn run_loop_body<A: pangolin_chain::ChainAdapter>(
    vault: &mut Vault,
    adapter: &A,
    device_key: &DeviceKey,
    balance_monitor: &std::sync::Arc<BalanceMonitor>,
    vault_id: [u8; 32],
    env: ChainEnv,
    rpc_url: &str,
    json: bool,
    once: bool,
    pull_interval_override: Option<u64>,
    flush_window_override: Option<u64>,
) -> Result<()> {
    let pull_interval_secs =
        pull_interval_override.unwrap_or_else(Vault::resolve_pull_interval_secs);
    let flush_window_secs = flush_window_override.unwrap_or_else(Vault::resolve_batch_window_secs);
    let mut pull_interval = tokio::time::interval(Duration::from_secs(pull_interval_secs));
    let mut flush_interval = tokio::time::interval(Duration::from_secs(flush_window_secs));
    // Skip the immediate first-tick from `interval` so a `--once`
    // run doesn't double-fire.
    pull_interval.tick().await;
    flush_interval.tick().await;

    let (status_tx, _status_rx) = watch::channel(SyncStatus::Syncing {
        mode: SyncMode::Slow,
    });
    let mut last_pull_outcome: Option<LastPullOutcome> = None;
    let mut last_flush_outcome: Option<LastFlushOutcome> = None;
    let mut consecutive_pull_failures: u32 = 0;
    let mut prior_conflict_snapshot: ConflictSnapshot = vault
        .snapshot_conflicts()
        .context("initial snapshot_conflicts failed")?;
    let mut prev_status = SyncStatus::Syncing {
        mode: SyncMode::Slow,
    };
    let mut iterations: u32 = 0;

    // SIGINT handler — sets a shared flag the select! loop reads on
    // every iteration. Use a Mutex<bool> for cooperative shutdown
    // (Arc::new(false)+notify dance is overkill for this).
    let shutdown_flag = Arc::new(Mutex::new(false));
    let shutdown_flag_clone = Arc::clone(&shutdown_flag);
    let _sigint_task = tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            let mut f = shutdown_flag_clone.lock().await;
            *f = true;
        }
    });

    loop {
        // Bail early on SIGINT — checked at the top of every
        // iteration so the loop never hangs longer than one tick.
        {
            let f = shutdown_flag.lock().await;
            if *f {
                emit_event(json, &serde_json::json!({ "event": "shutdown_sigint" }));
                break;
            }
        }
        let break_on_pull;
        let break_on_flush;
        tokio::select! {
            _ = pull_interval.tick() => {
                let (b, outcome) =
                    do_pull_tick(vault, rpc_url, env, &vault_id).await;
                break_on_pull = b;
                if let Some((delta_failures, lpo)) = outcome {
                    consecutive_pull_failures =
                        consecutive_pull_failures.saturating_add(delta_failures);
                    if matches!(lpo, LastPullOutcome::Success { .. }) {
                        // L4: reset on ANY Ok (including signal-only
                        // modes). Mirror sync-orchestrator.md.
                        consecutive_pull_failures = 0;
                    }
                    last_pull_outcome = Some(lpo);
                }
                break_on_flush = false;
            }
            _ = flush_interval.tick() => {
                let (b, outcome) = do_flush_tick(vault, adapter, device_key).await;
                break_on_pull = false;
                break_on_flush = b;
                if let Some(lfo) = outcome {
                    last_flush_outcome = Some(lfo);
                }
            }
        }
        if break_on_pull || break_on_flush {
            emit_event(
                json,
                &serde_json::json!({ "event": "session_expired_break_loop" }),
            );
            break;
        }

        // Compute next status — fresh snapshot each tick per
        // sync-orchestrator.md.
        let now_unix_ms = current_unix_ms();
        // `BalanceMonitor::current` uses `RwLock::blocking_read`
        // internally; calling it from a worker thread inside the
        // runtime panics. Use `spawn_blocking` to read the cached
        // value on a dedicated blocking worker.
        let balance_state = read_balance_state_blocking(balance_monitor).await;
        let inputs = vault
            .sync_status_inputs(
                &prior_conflict_snapshot,
                last_pull_outcome.clone(),
                last_flush_outcome.clone(),
                consecutive_pull_failures,
                balance_state,
                now_unix_ms,
            )
            .context("sync_status_inputs failed")?;
        prev_status = compute_next_status(&prev_status, &inputs);
        let _ = status_tx.send(prev_status.clone());

        // Per-tick status emission (R-e Option A).
        emit_status(json, &prev_status, consecutive_pull_failures);

        // Post-tick conflict snapshot for the next iteration's
        // delta computation.
        prior_conflict_snapshot = vault
            .snapshot_conflicts()
            .context("post-tick snapshot_conflicts failed")?;

        iterations = iterations.saturating_add(1);
        if once {
            emit_event(
                json,
                &serde_json::json!({
                    "event": "once_mode_exit",
                    "iterations": iterations,
                }),
            );
            break;
        }
    }

    Ok(())
}

/// One pull-tick of the canonical loop. Returns `(break_loop,
/// outcome)`.
#[allow(clippy::future_not_send)]
async fn do_pull_tick(
    vault: &mut Vault,
    rpc_url: &str,
    env: ChainEnv,
    vault_id: &[u8; 32],
) -> (bool, Option<(u32, LastPullOutcome)>) {
    match vault.pull_once(rpc_url, env, vault_id).await {
        Ok(report) => {
            let outcome = LastPullOutcome::Success {
                mode: report.mode,
                newly_frozen_count: u32::try_from(report.newly_frozen_accounts.len())
                    .unwrap_or(u32::MAX),
                newly_resolved_count: u32::try_from(report.newly_resolved_accounts.len())
                    .unwrap_or(u32::MAX),
            };
            (false, Some((0, outcome)))
        }
        Err(PullError::NoActiveSession) => (true, None),
        Err(PullError::Chain(_)) => (
            false,
            Some((1, LastPullOutcome::Failure(PullErrorKind::Chain))),
        ),
        Err(PullError::Store(_)) => (
            false,
            Some((0, LastPullOutcome::Failure(PullErrorKind::Store))),
        ),
    }
}

/// One flush-tick of the canonical loop. Returns `(break_loop,
/// outcome)`.
#[allow(clippy::future_not_send)]
async fn do_flush_tick<A: pangolin_chain::ChainAdapter>(
    vault: &mut Vault,
    adapter: &A,
    device_key: &DeviceKey,
) -> (bool, Option<LastFlushOutcome>) {
    let dirty = vault
        .publish_queue_state()
        .map(|s| s.dirty_count)
        .unwrap_or(0);
    if dirty == 0 {
        return (false, None);
    }
    match vault.flush_publish_queue(adapter, device_key, false).await {
        Ok(_) => (false, Some(LastFlushOutcome::Success)),
        Err(BatchFlushError::NoActiveSession) => (true, None),
        Err(BatchFlushError::BalanceInsufficientForBatch {
            needed,
            available,
            queued_count,
        }) => (
            false,
            Some(LastFlushOutcome::Failure(
                BatchFlushErrorKind::BalanceInsufficient {
                    needed_wei: needed,
                    available_wei: available,
                    queued_count,
                },
            )),
        ),
        Err(BatchFlushError::ChainError(_)) => (
            false,
            Some(LastFlushOutcome::Failure(BatchFlushErrorKind::Chain)),
        ),
        Err(BatchFlushError::Store(_)) => (
            false,
            Some(LastFlushOutcome::Failure(BatchFlushErrorKind::Store)),
        ),
    }
}

fn emit_status(json: bool, status: &SyncStatus, failures: u32) {
    if json {
        let label = sync_status_label(status);
        let value = serde_json::json!({
            "event": "tick",
            "status": label,
            "consecutive_pull_failures": failures,
        });
        println!("{value}");
    } else {
        eprintln!(
            "tick: status={} failures={failures}",
            sync_status_label(status)
        );
    }
}

fn emit_event(json: bool, value: &serde_json::Value) {
    if json {
        println!("{value}");
    } else {
        eprintln!("{value}");
    }
}

fn sync_status_label(status: &SyncStatus) -> String {
    match status {
        SyncStatus::Synced => "synced".to_string(),
        SyncStatus::Syncing { mode } => format!("syncing:{mode:?}"),
        SyncStatus::Offline {
            consecutive_failures,
        } => format!("offline:{consecutive_failures}"),
        SyncStatus::ConflictsPending { count } => format!("conflicts:{count}"),
        SyncStatus::BlockedOnBalance { .. } => "blocked_on_balance".to_string(),
        SyncStatus::ActionRequired { reason } => format!("action_required:{reason}"),
    }
}

/// Read the cached balance state on a dedicated blocking worker.
///
/// [`BalanceMonitor::current`] uses `RwLock::blocking_read` so it
/// must NOT run on the tokio worker thread that's driving the
/// loop. We spawn-blocking onto the runtime's blocking pool +
/// await the join handle. The cache read is cheap (one mutex);
/// the overhead is a few microseconds per tick.
async fn read_balance_state_blocking(
    monitor: &std::sync::Arc<BalanceMonitor>,
) -> pangolin_chain::GasBalanceState {
    let m_clone = std::sync::Arc::clone(monitor);
    tokio::task::spawn_blocking(move || m_clone.current())
        .await
        .unwrap_or_else(|_| pangolin_chain::GasBalanceState::Unknown {
            reason: "spawn_blocking join failed".to_string(),
        })
}

fn current_unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// Pluck `chain.rpc_default` from the deployment file. Duplicated
/// across commands.
fn read_deployment_default_rpc(path: &std::path::Path) -> Result<String> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read deployment file at {}", path.display()))?;
    let value: serde_json::Value = serde_json::from_str(&raw)
        .with_context(|| format!("deployment file {} is not valid JSON", path.display()))?;
    let s = value
        .pointer("/chain/rpc_default")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("deployment file missing /chain/rpc_default (string)"))?;
    Ok(s.to_owned())
}
