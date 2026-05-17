# Sync orchestrator (MVP-2 issue 5.4)

The "Synced / Syncing… / Offline" indicator state machine that the
host UI renders. Fuses 5.1's `flush_publish_queue` (write-side
drain), 5.2's `pull_once` (read-side cycle), 5.3's `PullReport`
conflict-delta signal + `Vault::list_conflicts_since` (conflict-
surface diff), 4.4's `SyncMode` picker (dispatch decision), and
3.5's `BalanceMonitor` (`GasBalanceState` steady-state hint) into
a single 6-variant pill that the host UI consumes.

## What 5.4 ships

- **`SyncStatus` enum** (`pangolin-store::sync_status`) — the 6-variant
  single-pill state: `Synced` / `Syncing { mode }` /
  `Offline { consecutive_failures }` /
  `ConflictsPending { count }` /
  `BlockedOnBalance { needed_wei, available_wei }` /
  `ActionRequired { reason }`.
- **`compute_next_status` pure transition function** —
  `compute_next_status(prev: &SyncStatus, inputs: &SyncStatusInputs) -> SyncStatus`.
  PURE per L11: no I/O, no clock read, no SQL; the host calls it
  per tick.
- **`Vault::sync_status_inputs` bundling accessor** — reads the
  engine-side metadata (`publish_queue_state` + `snapshot_conflicts`
  + `list_conflicts_since` + `last_pull_at_unix_ms`) and combines
  with host-supplied between-tick state into a single
  `SyncStatusInputs` snapshot.
- **`Vault::lock_with_drain` async method (R-e)** — pre-lock drain
  primitive that closes the 5.1 L1 deviation. Runs
  `flush_publish_queue(force = true)` BEFORE `self.lock()`;
  best-effort per L3 (flush errors do NOT block teardown; the
  error is returned to the caller AFTER lock runs).
- **`vault_sync_status` FFI binding** — thin wrapper that lifts
  host-supplied inputs, invokes the bundling accessor + the pure
  transition function, returns a `FfiSyncStatusSnapshot` for the
  host UI.

## R-a Option C — host-owned loop rationale

`Vault` is intentionally `!Sync` (P4 audit M-3: the inner
`rusqlite::Connection` holds a `RefCell`; `dyn Clock` is also
`!Sync`). Any engine-side `tokio::spawn` orchestrator would
require wrapping `Vault` in `Arc<Mutex<Vault>>` and reworking
every `&mut Vault` callsite — that is a substantial structural
change well out of scope for an MVP-2 tail-end issue. R-a Option
C ships the smallest §5.x cycle: the engine ships the pure state
machine + the bundling accessor; the host owns the
`tokio::interval` timer + the optional `tokio::sync::watch`
channel.

This matches 5.2 R-a verbatim (the pull loop is also host-owned)
and keeps the engine free of new tokio surface beyond what 4.4 /
5.1 / 5.2 already added.

## The canonical host scheduler loop body

The host implementation pattern (CLI / Tauri / mobile). Two
tokio timers run on different cadences (5.1 R-a 30s flush window
+ 5.2 R-b 60s pull interval); the state-machine update fires on
either timer. The `tokio::sync::watch` channel lives in HOST
code (under R-a Option C); the host UI subscribes and re-renders
on every status change.

```rust
use std::time::Duration;
use tokio::sync::watch;
use pangolin_store::{
    compute_next_status, BatchFlushErrorKind, LastFlushOutcome,
    LastPullOutcome, PullErrorKind, SyncMode, SyncStatus, Vault,
    BatchFlushError, PullError,
};

async fn run_sync_orchestrator(
    mut vault: Vault,
    rpc_url: String,
    env: pangolin_chain::ChainEnv,
    vault_id: [u8; 32],
    adapter: impl pangolin_chain::ChainAdapter,
    device_key: pangolin_crypto::keys::DeviceKey,
    balance_monitor: pangolin_chain::BalanceMonitor,
) {
    let (status_tx, _status_rx) = watch::channel(
        SyncStatus::Syncing { mode: SyncMode::Slow },
    );
    let mut pull_interval = tokio::time::interval(
        Duration::from_secs(Vault::resolve_pull_interval_secs()),
    );
    let mut flush_interval = tokio::time::interval(
        Duration::from_secs(Vault::resolve_batch_window_secs()),
    );
    let mut last_pull_outcome: Option<LastPullOutcome> = None;
    let mut last_flush_outcome: Option<LastFlushOutcome> = None;
    let mut consecutive_pull_failures: u32 = 0;
    let mut prior_conflict_snapshot = vault.snapshot_conflicts()
        .expect("initial snapshot");
    let mut prev_status = SyncStatus::Syncing { mode: SyncMode::Slow };

    loop {
        tokio::select! {
            _ = pull_interval.tick() => {
                match vault.pull_once(&rpc_url, env, &vault_id).await {
                    Ok(report) => {
                        last_pull_outcome = Some(LastPullOutcome::Success {
                            mode: report.mode,
                            newly_frozen_count: report.newly_frozen_accounts.len() as u32,
                            newly_resolved_count: report.newly_resolved_accounts.len() as u32,
                        });
                        // L4: reset on ANY Ok (including signal-only modes).
                        consecutive_pull_failures = 0;
                    }
                    Err(PullError::NoActiveSession) => break,
                    Err(PullError::Chain(_)) => {
                        consecutive_pull_failures = consecutive_pull_failures
                            .saturating_add(1);
                        last_pull_outcome = Some(
                            LastPullOutcome::Failure(PullErrorKind::Chain),
                        );
                    }
                    Err(PullError::Store(_)) => {
                        last_pull_outcome = Some(
                            LastPullOutcome::Failure(PullErrorKind::Store),
                        );
                    }
                }
            }
            _ = flush_interval.tick() => {
                if vault.publish_queue_state().map(|s| s.dirty_count).unwrap_or(0) > 0 {
                    match vault.flush_publish_queue(&adapter, &device_key, false).await {
                        Ok(_) => {
                            last_flush_outcome = Some(LastFlushOutcome::Success);
                        }
                        Err(BatchFlushError::NoActiveSession) => break,
                        Err(BatchFlushError::BalanceInsufficientForBatch {
                            needed, available, queued_count,
                        }) => {
                            last_flush_outcome = Some(LastFlushOutcome::Failure(
                                BatchFlushErrorKind::BalanceInsufficient {
                                    needed_wei: needed,
                                    available_wei: available,
                                    queued_count,
                                },
                            ));
                        }
                        Err(BatchFlushError::ChainError(_)) => {
                            last_flush_outcome = Some(LastFlushOutcome::Failure(
                                BatchFlushErrorKind::Chain,
                            ));
                        }
                        Err(BatchFlushError::Store(_)) => {
                            last_flush_outcome = Some(LastFlushOutcome::Failure(
                                BatchFlushErrorKind::Store,
                            ));
                        }
                    }
                }
            }
        }
        // Compute next status after either timer fires.
        let now_unix_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        let inputs = vault.sync_status_inputs(
            &prior_conflict_snapshot,
            last_pull_outcome.clone(),
            last_flush_outcome.clone(),
            consecutive_pull_failures,
            balance_monitor.current(),
            now_unix_ms,
        ).expect("inputs");
        prev_status = compute_next_status(&prev_status, &inputs);
        let _ = status_tx.send(prev_status.clone());
        prior_conflict_snapshot = vault.snapshot_conflicts()
            .expect("post-tick snapshot");
    }

    // Pre-lock drain on graceful shutdown (R-e).
    let _ = vault.lock_with_drain(&adapter, &device_key).await;
}
```

## SyncStatus transition table

| Prior signal                                     | `compute_next_status` returns         |
|--------------------------------------------------|---------------------------------------|
| `last_pull_outcome = NoActiveSession`            | `ActionRequired { reason: "vault locked" }` |
| `last_pull_outcome = Failure(Store)`             | `ActionRequired { reason: "store error during sync" }` |
| `last_flush_outcome = Failure(BalanceInsufficient { needed, available, .. })` | `BlockedOnBalance { needed_wei: needed, available_wei: available }` |
| `consecutive_pull_failures >= 3`                 | `Offline { consecutive_failures }`    |
| `conflicts_count > 0`                            | `ConflictsPending { count: conflicts_count }` |
| `last_pull_outcome = Success { mode = Slow, .. }` | `Synced`                              |
| `last_pull_outcome = Success { mode = OfferFast | AlwaysFast, .. }` | `Syncing { mode }`     |
| `last_pull_at_unix_ms.is_some()` + within 5 min  | `Synced`                              |
| `last_pull_at_unix_ms.is_some()` + >5 min stale  | `Syncing { Slow }`                    |
| Bootstrap (no prior pull)                        | `Syncing { Slow }`                    |

The transition order is load-bearing (see the inline doc on
`compute_next_status` for the exact sequence). Fresh flush
errors PREFER the cached BalanceMonitor state (defends
L-balance-state-stale-vs-flush-error).

## Pre-lock drain contract (R-e)

`Vault::lock_with_drain` is the close-the-5.1-L1-deviation
primitive. The 5.1 `flush_publish_queue` requires `&mut Vault`
and is async; the synchronous `Vault::lock` cannot await. R-e
introduces a single async wrapper that:

1. Returns `BatchFlushError::NoActiveSession` BEFORE touching
   state if the vault is already locked. The guard prevents a
   spurious double-lock + matches 5.1 / 5.2 posture verbatim.
2. Calls `flush_publish_queue(adapter, device_key, true)` —
   `force = true` bypasses the 30s window gate so graceful
   shutdown drains whatever is queued regardless of cadence.
3. Calls `self.lock()` REGARDLESS of whether the flush succeeded
   (L3 — best-effort drain; teardown wins). Dirty markers
   persist in SQLite; the next unlock resumes the queue.
4. Surfaces the flush error AFTER lock so the caller sees the
   typed `BatchFlushError` for any logging / retry — but the
   post-condition (vault is Locked) is the same regardless of
   error.

The existing sync `Vault::lock()` is untouched and remains the
emergency / `device_locked` path; hosts that don't need the
drain (or are tearing down for security reasons) still use it
directly.

## Relationship to 5.1 / 5.2 / 5.3 / 4.4 / 3.5

| Upstream | What 5.4 consumes |
|----------|-------------------|
| **5.1** `BatchFlushReport` + `BatchFlushError` + `_force` param + `publish_queue_state` | `last_flush_outcome` input + `force=true` in `lock_with_drain` + `PublishQueueState` in `SyncStatusInputs` |
| **5.2** `PullReport` (with `mode`) + `PullError` + `last_pull_at_unix_ms` + `PULL_INTERVAL_SECS_DEFAULT` | `last_pull_outcome` input + offline counter + staleness check + canonical host loop cadence |
| **5.3** `ConflictSnapshot` + `ConflictDelta` + `list_conflicts_since` + `snapshot_conflicts` | `conflict_delta` input + `conflicts_count` for `ConflictsPending` |
| **4.4** `SyncMode { Slow, OfferFast, AlwaysFast }` | `SyncStatus::Syncing { mode }` payload + signal-only L4 reset |
| **3.5** `GasBalanceState` + `BalanceMonitor` | `balance_state` input (steady-state hint; fresh flush errors PREFERRED per L-balance-state-stale-vs-flush-error) |

## Threat-model cross-ref

See `THREAT_MODEL.md` row "Sync orchestrator (5.4)" for:

- L-offline-flapping (mitigated by 3-consecutive-failures threshold)
- L-status-leaks-balance-detail (mitigated by §8.1.5 vocabulary discipline + same info already exposed via 5.1 `BatchFlushError`)
- L-orchestrator-leaks-past-lock (mitigated by `NoActiveSession` short-circuit + canonical host loop body that breaks on the variant)
- L-conflict-pill-flashes-on-self-publish (mitigated by 5.3 round-trip regression test guaranteeing empty `newly_frozen` on self-publish)
- L-balance-state-stale-vs-flush-error (mitigated by fresh flush error preferred in transition function)

## Files

- `crates/pangolin-store/src/sync_status.rs` — NEW: `SyncStatus`
  enum + `compute_next_status` + `SyncStatusInputs` +
  type-erased outcome shapes + hermetic tests.
- `crates/pangolin-store/src/vault.rs::sync_status_inputs` —
  bundling accessor.
- `crates/pangolin-store/src/vault.rs::lock_with_drain` —
  pre-lock drain primitive.
- `crates/pangolin-store/src/lib.rs` — `pub mod sync_status` +
  re-exports.
- `crates/pangolin-ffi/src/sync_status.rs` — NEW: `vault_sync_status`
  + `FfiSyncStatus` enum + `FfiSyncMode` mirror +
  `FfiSyncStatusInputs` / `FfiSyncStatusSnapshot` records.
- `crates/pangolin-ffi/src/lib.rs` — `pub mod sync_status` +
  re-exports.
- `crates/pangolin-store/tests/sync_status_live.rs` — R-g
  `#[ignore]`'d live test (fixture-capture follow-up; same
  posture as 5.1 / 5.2 / 5.3 live tests).
