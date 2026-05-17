# Pull loop (MVP-2 issue 5.2)

## What it is

A **per-cycle async primitive** — `Vault::pull_once(rpc_url, env,
&vault_id) -> Result<PullReport, PullError>` — that re-runs the 4.4
sync-mode picker (`Vault::select_sync_mode`) and dispatches the cycle:
`Slow` delegates to 4.1's `Vault::sync_from_chain` (pulls + ingests
new D-017 `RevisionPublished` events into the local revision graph,
advances the per-vault checkpoint); `OfferFast` / `AlwaysFast` return
signal-only (the engine NEVER spawns the indexer — host owns that
decision per 4.4 L1).

Master plan §5 row 5.2 verbatim: *"On unlock + periodic (every 60s
while session active). Apply non-conflicted heads automatically."*

5.2 ships:

- `Vault::pull_once(rpc_url, env, &vault_id) -> Result<PullReport, PullError>`
- `Vault::resolve_pull_interval_secs()` + `resolve_pull_interval_secs_from(env_value)` (env-var-clamped cadence)
- `Vault::last_pull_at_unix_ms() -> Option<i64>` (diagnostic accessor)
- `pangolin_store::pull::{PullReport, PullError}` (Ok / Err report types)
- Constants `PULL_INTERVAL_SECS_{DEFAULT,MIN,MAX,ENV_VAR}` (60s default; clamped `5..=3600`)
- New `ActiveState.last_pull_at_unix_ms: Option<i64>` field (in-memory; not persisted)

5.2 does NOT ship:

- The 60-second `tokio::time::interval` scheduler — host territory per R-a
- Conflict detection + resolution (5.3)
- "Synced / Syncing… / Offline" indicator state machine (5.4)
- Always-on auto-flush of the publish queue (5.4)
- FFI exposure (`pangolin-cli pull`, FFI binding) — CLI-V1 batch
- Backoff state-machine (R-d flat retry; host concern)
- WebSocket subscription path (deferred to MVP-3 per 4.1 R-b)
- Indexer spawn orchestration (host territory)

## R-a host-owned timer rationale

The plan-gate considered three shapes for who holds the 60-second
timer:

- **Option A: Vault-owned timer.** `Vault::unlock` spawns a background
  `tokio::task` that fires every 60s; cancellation handle in
  `ActiveState`. Rejected because (a) introduces `tokio::spawn` surface
  inside `pangolin-store` where today there are ZERO (verified by Grep);
  (b) `Vault` is `!Sync` so the spawned task would have to be
  `!Send` and pin to a `LocalSet` — forces a `LocalSet` shape on every
  host.
- **Option B: Host-owned timer (chosen, R-a).** Vault exposes the
  per-cycle primitive (`pull_once`); the host (CLI / Tauri shell /
  mobile UI) owns the `tokio::time::interval` scheduler. Preserves the
  zero-`tokio::spawn` discipline; mirrors 5.1's `flush_publish_queue`
  posture verbatim; the `&mut self` borrow compile-time-prevents
  concurrent flush / edit / pull on a single `Vault` handle.
- **Option C: Both.** Doubles the API surface AND inherits Option A's
  complications for the convenience path. Rejected.

Kelvin signed R-a Option B 2026-05-16. 5.4 will wire the host-side
`SyncOrchestrator` (CLI / Tauri / mobile each owning their event loop)
that fuses pull + flush behind one cadence; 5.2 ships only the
per-cycle primitive.

## Canonical host scheduler loop body

The recommended pattern for any host (CLI, Tauri shell, mobile UI):

```rust
use std::time::Duration;
use pangolin_chain::{ChainEnv, SyncMode};
use pangolin_store::{PullError, PullReport, Vault};

async fn run_pull_loop(vault: &mut Vault, rpc_url: &str, env: ChainEnv, vault_id: [u8; 32]) {
    let interval_secs = Vault::resolve_pull_interval_secs();
    let mut tick = tokio::time::interval(Duration::from_secs(interval_secs));
    // "On unlock + every 60s" — the first tick is immediate.
    loop {
        tick.tick().await;
        match vault.pull_once(rpc_url, env, &vault_id).await {
            Ok(PullReport { mode: SyncMode::Slow, sync_report: Some(rep), .. }) => {
                // Checkpoint advanced; render "Synced N min ago" hint.
                tracing::info!(?rep, "slow-mode pull cycle completed");
            }
            Ok(PullReport { mode: SyncMode::OfferFast, .. }) => {
                // Host UX policy: prompt the user, OR (recommended L-offer-fast-not-acted-on
                // mitigation) auto-fall-through to Slow after 2 unacknowledged ticks.
                prompt_user_or_fall_through_to_slow();
            }
            Ok(PullReport { mode: SyncMode::AlwaysFast, .. }) => {
                // User pre-elected fast-mode; spawn the ephemeral pangolin-indexer
                // subprocess (host machinery; 4.2/4.3).
                spawn_indexer();
            }
            Err(PullError::NoActiveSession) => {
                // Session torn down (lock / idle-expire / 4h-absolute / device_locked).
                // Exit the scheduler. The host re-arms on next unlock.
                break;
            }
            Err(PullError::Chain(e)) => {
                // R-d flat retry: log + retry on the next regular tick.
                // 5.4 will own the "Offline" indicator state machine.
                tracing::warn!(error = %e, "pull cycle hit chain error; retrying next tick");
            }
            Err(PullError::Store(e)) => {
                // Typically unrecoverable (corrupted SQLite cache, etc.). Break;
                // surface the error to the host's top-level error UX.
                tracing::error!(error = %e, "pull cycle hit fatal store error; exiting loop");
                break;
            }
        }
    }
}
# fn prompt_user_or_fall_through_to_slow() {}
# fn spawn_indexer() {}
```

The loop ends naturally on `NoActiveSession` — the worst-case
lock→exit latency is bounded by the interval (≤60s by default; ≤5s if
the host has set `PANGOLIN_PULL_INTERVAL_SECS=5`). The post-lock
`pull_once` call returns immediately without any RPC attempt
(L-pull-after-lock-races defense — see [Threat model](#threat-model)
below).

## SyncMode dispatch table

| Picker result      | Engine action inside `pull_once`             | Host action on `Ok(PullReport)`                        |
|--------------------|----------------------------------------------|--------------------------------------------------------|
| `SyncMode::Slow`        | Delegate to `Vault::sync_from_chain`         | Render "Synced N min ago" using `sync_report` stats    |
| `SyncMode::OfferFast`   | Return signal-only (`sync_report = None`)    | Prompt user; auto-fall-through to Slow after 2 ticks   |
| `SyncMode::AlwaysFast`  | Return signal-only (`sync_report = None`)    | Spawn the `pangolin-indexer` ephemeral subprocess      |

The picker is invoked **per cycle** (R-c re-pick per cycle): preference
flips take effect on the next tick without any cache-invalidation
surface. The 4.4 first-sync heuristic naturally degrades to `Slow` once
the first cycle's slow-mode pass has advanced the checkpoint past
`None`.

## R-b env-var override + clamp

| Constant                          | Value  | Purpose                                                       |
|-----------------------------------|--------|---------------------------------------------------------------|
| `PULL_INTERVAL_SECS_DEFAULT`      | 60     | Master plan §5 row 5.2 verbatim                               |
| `PULL_INTERVAL_SECS_MIN`          | 5      | L-pull-flood defense (12 pulls/min ceiling)                   |
| `PULL_INTERVAL_SECS_MAX`          | 3600   | Caps staleness a malicious host wrapper could push            |
| `PULL_INTERVAL_SECS_ENV_VAR`      | `"PANGOLIN_PULL_INTERVAL_SECS"` | Mirror 4.2 / 5.1 env-var precedent  |

Resolved by `Vault::resolve_pull_interval_secs()` (reads the env var
process-globally) or `Vault::resolve_pull_interval_secs_from(env_value)`
(pure function for hermetic tests). Non-parseable / negative inputs
fall back to default 60.

## R-c diagnostic stamp

Every successful `pull_once` cycle — including the signal-only
`OfferFast` / `AlwaysFast` branches — stamps the current Unix-ms
instant into `ActiveState.last_pull_at_unix_ms`. The host reads it via
`Vault::last_pull_at_unix_ms() -> Option<i64>`. 5.4 will consume this
as the "Synced N min ago" / "Syncing…" / "Offline" indicator state
machine's primary input; 5.2 ships only the stamp.

Not persisted across `lock()` / unlock cycles. 5.4 may revisit if the
indicator needs a "Synced N hours ago" display after re-unlock.

## Drain triggers + cancellation discipline

The pull loop is canceled implicitly via `PullError::NoActiveSession`
on every session-teardown path:

| Teardown trigger      | Mechanism                                                       | Loop exit latency      |
|-----------------------|-----------------------------------------------------------------|------------------------|
| `Vault::lock()`        | Drops `ActiveState`; next `pull_once` returns `NoActiveSession` | ≤ one interval tick    |
| Idle-expire            | `check_session_freshness` drops `ActiveState`                    | ≤ one interval tick    |
| 4-hour absolute        | `check_session_freshness` drops `ActiveState`                    | ≤ one interval tick    |
| `Vault::device_locked()` | Drops `ActiveState`; flips to `Expired`                        | ≤ one interval tick    |

No new tokio primitive; no new accessor. Mirrors 5.1's
`BatchFlushError::NoActiveSession` posture verbatim. The post-teardown
`pull_once` call returns immediately without any RPC attempt — the
early-return short-circuit fires BEFORE the picker or any chain call.

## R-d offline backoff: host scheduler concern

On `Err(PullError::Chain(_))`, the canonical loop just retries on the
next regular interval. **Flat retry at 60s** is the default — Kelvin
sign-off 2026-05-16 (Q-d default). One failed-RPC ping per minute is
negligible cost; offline detection is 5.4's job (the indicator state
machine reads recent-pull failure state + transitions to "Offline"
after N consecutive failures).

If a host wants exponential backoff or a longer interval during
outages, the host scheduler implements it on top of the per-cycle
primitive — the engine itself never schedules.

## UX contract for OfferFast (L-offer-fast-not-acted-on mitigation)

When the picker returns `OfferFast`, the user is asked "Spin up faster
sync? (uses temporary local indexer that auto-deletes)" per D-007. If
the user is AFK and never responds, 60s later the next `pull_once`
runs the picker again + returns `OfferFast` again. The user's vault
stays un-synced indefinitely.

**Recommended host policy:** auto-fall-through to `Slow` after the
third consecutive `OfferFast` tick without an acknowledgment (the host
treats two ticks of unacked OfferFast as an implicit decline; the
third tick is dispatched to Slow via the host calling
`Vault::set_sync_mode_preference(SyncModePreference::AlwaysSlow)` if
the user has explicitly declined the prompt; otherwise the host
re-renders the prompt + dispatches slow-mode anyway so the vault stays
fresh).

This is HOST policy; 5.2 ships only the signal. Documented here so the
three downstream hosts (CLI, Tauri, mobile) implement it consistently.

## Relationship to 5.1 (`flush_publish_queue`) and 5.4 (`SyncOrchestrator`)

5.1's `Vault::flush_publish_queue` (write-side drain) and 5.2's
`Vault::pull_once` (read-side cycle) are **orthogonal** in 5.2:

- Both take `&mut self` — Rust's borrow checker compile-time-prevents
  concurrent invocation on a single `Vault` handle.
- 5.4 will introduce the host-side `SyncOrchestrator` that fuses them
  under one cadence — pull on tick N, flush on tick N+0.5 (or
  whatever the orchestrator's policy is), all sequenced through the
  same single-threaded executor the host owns.
- 5.4 also wires the "Synced / Syncing… / Offline" indicator state
  machine on top of (5.1's) `publish_queue_state()` +
  (5.2's) `last_pull_at_unix_ms()`.

The 5.2 / 5.1 orthogonality is intentional: it lets each primitive
land cleanly with a minimal test surface before 5.4 fuses them. Hosts
that want both today (e.g., the CLI's `pangolin sync` smoke test) can
sequence them explicitly: `vault.flush_publish_queue(&adapter,
&device, force=true).await; vault.pull_once(rpc, env, &vid).await;`.

## Adapter-less API shape (builder discretion)

The 5.2 plan-gate left the choice between adapter-less and
adapter-threaded `pull_once` shapes to the builder. The builder
shipped adapter-less because:

- Slow-mode delegates to `Vault::sync_from_chain` which takes raw
  `rpc_url` + `env` + `vault_id` (NOT a `ChainAdapter`).
- `OfferFast` / `AlwaysFast` return signal-only — the host invokes
  the indexer with its own adapter machinery on accept.
- The minimal API surface mirrors 5.1's `flush_publish_queue` shape
  (which DOES take an adapter, but only because it submits to chain;
  the pull cycle doesn't).

If a future cycle needs an adapter (e.g., 5.4's `SyncOrchestrator`
threads one through for a unified pull + flush API), the additive
change is to introduce a second method that threads it through; the
5.2 primitive stays minimal.

## Threat model

`THREAT_MODEL.md` carries the full "Pull loop (5.2)" row. Summary:

| Threat                                       | Defense                                                                 |
|----------------------------------------------|-------------------------------------------------------------------------|
| L-pull-flood (env-var floods RPC)            | Env-var clamp `5..=3600` (`PULL_INTERVAL_SECS_MIN/MAX`)                |
| L-host-scheduler-leak (loop outlives session) | `NoActiveSession` early-return + documented canonical loop body         |
| L-offer-fast-not-acted-on (user AFK)         | Documented host UX policy: auto-fall-through to Slow after 2 ticks       |
| L-revision-replay-via-stale-RPC              | 4.1 inheritance — `ingest_pending_chain_revision` is idempotent          |
| L-checkpoint-corruption-during-pull          | 4.1 inheritance — L12 monotonic checkpoint + reorg rollback             |
| L-pull-after-lock-races                      | `if self.active.is_none() { return NoActiveSession; }` BEFORE any RPC   |
| L-pull-during-flush-race                     | Rust borrow checker — `&mut self` rejects concurrent invocation         |

## File layout

- `crates/pangolin-store/src/pull.rs` — module root, constants
  (`PULL_INTERVAL_SECS_DEFAULT/MIN/MAX/ENV_VAR`), `PullReport`,
  `PullError`, hermetic tests (14).
- `crates/pangolin-store/src/vault.rs::pull_once` — async primitive
  body (R-a host-owned timer means this is the only Vault-side
  surface; no `start_pull_loop` convenience).
- `crates/pangolin-store/src/vault.rs::resolve_pull_interval_secs` /
  `resolve_pull_interval_secs_from` — env-var-clamped cadence
  helpers (R-b).
- `crates/pangolin-store/src/vault.rs::last_pull_at_unix_ms` —
  diagnostic accessor (R-c).
- `crates/pangolin-store/src/vault.rs::ActiveState.last_pull_at_unix_ms`
  — in-memory stamp field (R-c).
- `crates/pangolin-store/src/lib.rs` — `pub mod pull` +
  `pub use pull::{PullError, PullReport, PULL_INTERVAL_SECS_*}`.
- `crates/pangolin-store/tests/pull_live.rs` — R-f `#[ignore]`'d live
  test against D-017 (deferred to fixture-capture follow-up; same
  posture as 4.1 / 4.2 / 4.3 / 5.1 live tests).

## Sync-orchestrator cross-ref (MVP-2 issue 5.4)

The 5.4 sync orchestrator (`docs/architecture/sync-orchestrator.md`)
consumes `pull_once` + `PullReport` + `PullError` + the
`last_pull_at_unix_ms` diagnostic stamp as the read-side input to
its 6-variant `SyncStatus` state machine. The canonical host loop
body fires `pull_once` on the 60s pull-interval tick and maps:

- `Ok(PullReport { mode, newly_frozen_accounts, newly_resolved_accounts, .. })`
  into `LastPullOutcome::Success { mode, newly_frozen_count, newly_resolved_count }`
  + resets the host's consecutive-failure counter to 0 (L4
  applies — signal-only `OfferFast` / `AlwaysFast` cycles reset
  too).
- `Err(PullError::Chain(_))` into
  `LastPullOutcome::Failure(PullErrorKind::Chain)` + increments
  the counter; at 3 consecutive failures the transition
  function returns `SyncStatus::Offline`.
- `Err(PullError::Store(_))` into
  `LastPullOutcome::Failure(PullErrorKind::Store)` + the
  transition function returns `SyncStatus::ActionRequired`.
- `Err(PullError::NoActiveSession)` is terminal — the host
  loop breaks.

The `last_pull_at_unix_ms` stamp is the load-bearing staleness
input: 5 minutes after the last successful pull, the transition
function downgrades `Synced` to `Syncing { Slow }` (an active
host running on schedule never trips this; only a wedged
scheduler does).
