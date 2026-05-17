# Publish queue + batching (MVP-2 issue 5.1)

## What it is

A **30-second same-account coalescing layer** on top of the existing P8-2
`dirty_accounts` table + P8-3 `publish_all` orchestrator. When the user
edits the same account N times within a 30s window, only the latest
revision's dirty marker survives — the rest are pruned before the chain
flush, so N edits → 1 chain transaction instead of N.

5.1 ships:
- `Vault::flush_publish_queue(adapter, force) -> Result<BatchFlushReport, BatchFlushError>`
- `Vault::publish_queue_state() -> Result<PublishQueueState>` (read-only snapshot for host UIs)
- `Vault::enable_window_elapsed_flush(bool)` (opt-in window-elapsed auto-flush; default OFF)
- `Vault::coalesce_dirty_markers()` (internal helper; runs the per-account pruning pass)
- `pangolin_store::publish::{publish_all_for_vault, publish_one}` (extracted from
  `apps/cli/src/sync.rs::publish_all` per R-h)
- `pangolin_chain::ChainAdapter::pre_flight_batch_balance` (NEW trait method; default
  impl returns `Ok(None)`) + `pangolin_chain::BatchBalanceCheck` (NEW struct carrying
  `total_estimated_cost_wei` + `current_balance_wei`) — the load-bearing R-e gate.
- `pangolin_chain::BaseSepoliaAdapter` overrides `pre_flight_batch_balance` to query
  the alloy provider directly (no new RPC connection).

5.1 does NOT ship:
- Pull loop (5.2)
- Conflict detection + resolution plumbing (5.3)
- "Synced / Syncing… / Offline" indicator state machine (5.4)
- Always-on auto-flush wired into the host (5.4)
- FFI exposure of the new APIs (CLI-V1 batch)
- CLI subcommands (`pangolin flush`, `pangolin queue-status`) (CLI-V1 batch)

## How it interacts with the existing P8 machinery

Every `Vault::account_add` / `account_update` / `delete_account` already
stamps a `(account_id, revision_id, marked_at)` row into `dirty_accounts`
in the same SQLite transaction as the revision INSERT (P8-2). 5.1 adds
two layers:

1. **A 30-second in-memory window timer** (`ActiveState.window_started_at_unix_ms`)
   that ticks from the first dirty marker after the most recent flush.

2. **A coalescing pass** (`coalesce_dirty_markers`) that runs at the top
   of every `flush_publish_queue` invocation: for each account that has
   more than one dirty marker queued, keep only the marker for the
   account's current head revision (read from
   `account_identities.head_revision_id`, NOT `MAX(marked_at)` — the
   head pointer is clock-skew-resistant by construction) and delete the
   rest. The corresponding revision rows in `revisions` are **kept**
   — the local lineage is unchanged; only the broadcast intent is pruned.

The 30s window is **not load-bearing** for correctness: a host that
never invokes `flush_publish_queue` simply accumulates dirty markers
until something else triggers a flush (lock, manual flush, count cap,
byte cap). The window is purely a UX heuristic — "wait long enough that
the user's rapid edits settle, then ship one tx per account."

## Drain triggers (R-b)

| Trigger | Mandatory? | How |
|---|---|---|
| Window elapsed (30s since first marker) | mandatory | Host opts in via `enable_window_elapsed_flush(true)`; flush fires lazily on next `account_*` call when the window has elapsed (5.1 default: OFF; 5.4 will flip ON by default) |
| Manual flush | mandatory | Host calls `flush_publish_queue(adapter, force=true)` directly |
| Session teardown — `lock()` | mandatory protocol-level | **Host responsibility in 5.1.** The host calls `flush_publish_queue` BEFORE invoking `lock()` if it wants drain-on-lock. The Vault library does NOT auto-drain inside `lock()` because `lock()` is sync (no `.await`) and `flush_publish_queue` is async (calls into pangolin-chain). 5.4 will wire host-side orchestration that fires the pre-lock flush automatically; 5.1 ships the primitive and documents the convention. Dirty markers always persist through `lock()` regardless. |
| Session teardown — idle-expire | mandatory protocol-level | Same posture as lock — host responsibility |
| Session teardown — 4h-absolute | mandatory protocol-level | Same posture |
| Session teardown — `device_locked()` | mandatory protocol-level | Same posture |
| Count cap (100 dirty markers) | optional | Host checks `publish_queue_state().dirty_count >= PUBLISH_QUEUE_COUNT_CAP` and triggers flush |
| Byte cap (1 MB total `enc_payload`) | optional | Host checks `publish_queue_state().dirty_byte_size >= PUBLISH_QUEUE_BYTE_CAP_BYTES` and triggers flush |
| App-shutdown | skipped | SQLite-persisted markers survive crash unaltered; no in-memory state to lose beyond the window timer |

The "host responsibility on teardown" deviation from the plan-gate
recommendation is intentional. Forcing `lock()` to be `async` would
ripple through every call site in the project (1.4 session policy +
P2 lock semantics) for a benefit that the host can already achieve
explicitly. 5.4 — the "always-on auto-flush" issue — will introduce a
host-side `Vault::auto_sync_handle` or similar orchestration layer that
owns the teardown coordination.

## Coalescing rule (R-c)

**Per-account, master-plan verbatim.** For each `account_id` with N>1
dirty markers:

1. Read the account's `head_revision_id` from `account_identities`
   (this pointer is updated atomically with every successful
   `account_*` call; immune to clock skew).
2. Delete every dirty marker for that account whose `revision_id` does
   NOT match the head pointer.
3. Tombstones win automatically: `delete_account` updates the head
   pointer to the tombstone revision, so the coalescing pass keeps
   the tombstone and prunes any prior live update.

**N different accounts edited in the same window → N separate chain
transactions** (one per account, all submitted in the same `flush_publish_queue`
invocation). Cross-account batching at the chain layer is **not possible** —
the deployed `RevisionLogV1` contract emits one event per `accountId` per
call; cross-account batching would require a contract redeploy (out of
scope for MVP-2). This was confirmed at plan-gate.

## Balance gate (R-e)

`flush_publish_queue` runs a **top-of-flush total-cost balance check
BEFORE submitting any chain transaction** via the
`ChainAdapter::pre_flight_batch_balance` method (added to the trait in
5.1's audit fix-pass):

1. Run `coalesce_dirty_markers`.
2. Count remaining dirty markers post-coalesce → `queued_count`.
3. Call `adapter.pre_flight_batch_balance(queued_count)` which returns
   `Option<BatchBalanceCheck>`. The production `BaseSepoliaAdapter`
   override uses `pangolin_chain::balance_check::estimate_next_publish_cost_with_provider`
   + `query_evm_balance_with_provider` against its already-held alloy
   provider (no new RPC connection), then multiplies the per-revision
   estimate by `queued_count` to compute `total_estimated_cost_wei`.
4. If the check returns `Some(check)` AND `!check.is_sufficient()`:
   - Set `active.last_flush_failed_balance = true`.
   - Return `BatchFlushError::BalanceInsufficientForBatch { needed: check.total_estimated_cost_wei, available: check.current_balance_wei, queued_count }`.
   - **NO chain submission attempted.** Dirty markers stay; next flush
     re-runs coalescing across whatever markers accumulated meanwhile.
5. If the check returns `Some(sufficient)` OR `None` (adapter doesn't
   support pre-flight), proceed into the per-account submission loop.
   Each `publish_one` call still runs 3.3's `pre_publish_balance_gate`
   as defense-in-depth.

The `Option<BatchBalanceCheck>` shape on the trait has a default impl
returning `Ok(None)` so adapters that pre-date 5.1 (notably the PoC-era
`MockChainAdapter` in some PoC tests) remain back-compatible — those
flushes fall back to the per-revision gate. Production adapters
(`BaseSepoliaAdapter`) always return `Ok(Some(...))` when they have a
signer; read-only adapters (no signer) return `Ok(None)` since publish
itself would fail.

`active.last_flush_failed_balance` flips to `true` on a balance failure
and back to `false` on the next successful flush, so the host UI can
surface a persistent "blocked on balance" indicator via
`publish_queue_state().blocked_on_balance`.

## Blocked-queue append (R-f)

When the queue is blocked on balance, **new edits append normally**.
The next `flush_publish_queue` invocation re-runs coalescing across
the merged set of dirty markers. Local edits are NEVER refused — the
vault is a local password store first; chain submission is asynchronous
to local UX. The count + byte caps (R-b) clamp runaway growth in
pathological scenarios where balance stays missing indefinitely.

## API surface

```rust
// pangolin-store

pub const BATCH_WINDOW_SECS_DEFAULT: u64 = 30;
pub const BATCH_WINDOW_SECS_MIN: u64 = 1;
pub const BATCH_WINDOW_SECS_MAX: u64 = 300;
pub const BATCH_WINDOW_SECS_ENV_VAR: &str = "PANGOLIN_BATCH_WINDOW_SECS";
pub const PUBLISH_QUEUE_COUNT_CAP: usize = 100;
pub const PUBLISH_QUEUE_BYTE_CAP_BYTES: u64 = 1_000_000;

impl Vault {
    pub async fn flush_publish_queue<A: ChainAdapter + ?Sized>(
        &mut self,
        adapter: &A,
        force: bool,            // ignore window timer; honor balance gate
    ) -> Result<BatchFlushReport, BatchFlushError>;

    pub fn publish_queue_state(&self) -> Result<PublishQueueState>;
    pub fn enable_window_elapsed_flush(&mut self, on: bool) -> Result<()>;
    pub fn coalesce_dirty_markers(&mut self) -> Result<usize>;
}

pub struct PublishQueueState {
    pub window_started_at_unix_ms: Option<i64>,
    pub dirty_count: usize,
    pub dirty_byte_size: u64,
    pub blocked_on_balance: bool,
}

pub struct BatchFlushReport {
    pub coalesced_markers_pruned: usize,
    pub publish_report: PublishReport,
}

pub enum BatchFlushError {
    BalanceInsufficientForBatch { needed: u128, available: u128, queued_count: usize },
    ChainError(ChainError),
    Store(StoreError),
    NoActiveSession,
}

// pangolin_store::publish (NEW module, extracted from apps/cli/src/sync.rs)

pub async fn publish_all_for_vault<A: ChainAdapter + ?Sized>(
    vault: &mut Vault,
    adapter: &A,
    device_key: &DeviceKey,
) -> Result<PublishReport, StoreError>;

pub async fn publish_one<A: ChainAdapter + ?Sized>(
    vault: &mut Vault,
    adapter: &A,
    device_key: &DeviceKey,
    entry: &DirtyEntry,
    chain_view: Option<&[RevisionEvent]>,
) -> Result<PublishOutcome, PublishOneError>;
```

## Schema

**No schema change.** The `dirty_accounts` table from P8-2 is the queue;
5.1 reuses it verbatim. No new tables, no new columns, no
`format_version` bump.

## Tests

22 hermetic tests across `publish.rs::tests` + `vault.rs::tests` cover:
window state machine, coalescing rule (including tombstone-wins-tie
and clock-skew-resistance), balance gate fail-fast, blocked-queue
append, cap behavior, drain-on-teardown via host orchestration, CLI
behavior preservation through the refactor. One `#[ignore]`'d live
test against D-017 captures the end-to-end "3 edits same account →
1 chain tx" property (same posture as 4.1 R-f / 4.2 R-f / 4.3 R-e).

## Threat model

See `THREAT_MODEL.md` row "Publish queue + batching (5.1)" for:

- L-tombstone-coalesced-away (mitigated by head-pointer rule)
- L-flush-during-lock-race (mitigated by host-orchestration convention + Rust borrow checker)
- L-window-DoS (mitigated by env-var clamp + mandatory drain triggers)
- L-balance-blocked-grows-unbounded (mitigated by count + byte caps)
- L-clock-skew-coalesce-wrong-order (mitigated by reading head from `account_identities`, not `MAX(marked_at)`)
- L-malicious-RPC-fakes-receipt (inherited from 3.3 `tx_hash` cross-check)
- L-coalescing-skips-foreign-edit (inherited from P8 CRIT-1 `refuse_if_frozen`)

## Sync-orchestrator cross-ref (MVP-2 issue 5.4)

The 5.4 sync orchestrator (`docs/architecture/sync-orchestrator.md`)
consumes `flush_publish_queue` + `publish_queue_state` in two
load-bearing ways:

1. The canonical host loop body fires `flush_publish_queue(force=false)`
   on its 30s tick whenever `publish_queue_state().dirty_count > 0`,
   then maps the `BatchFlushReport` / `BatchFlushError` into the
   `LastFlushOutcome` input the transition function consumes. A
   `BalanceInsufficientForBatch` error becomes
   `SyncStatus::BlockedOnBalance` on the next tick.
2. Graceful shutdown uses `Vault::lock_with_drain` (R-e — see
   below) which runs `flush_publish_queue(force=true)` BEFORE
   `lock()` runs. This closes the 5.1 L1 deviation (the existing
   sync `lock()` cannot await a flush).

## Pre-lock drain (MVP-2 issue 5.4 R-e)

`Vault::lock_with_drain(adapter, device_key) -> Result<(), BatchFlushError>`
is the async primitive that drains the queue BEFORE locking. The
contract is **best-effort** per L3: flush failures (network,
balance, store) do NOT block teardown; the error is RETURNED to
the caller AFTER `lock()` runs. Dirty markers persist in SQLite;
the next unlock resumes the queue (covered by 5.1's
`dirty_markers_persist_through_lock_and_resume_on_next_unlock`).

The pre-condition `self.active.is_some()` is enforced via an
early-return: a locked vault returns `BatchFlushError::NoActiveSession`
WITHOUT touching `lock()`. This guards against spurious
double-lock and matches 5.1 / 5.2 posture verbatim.

The existing sync `Vault::lock()` is untouched — emergency /
`device_locked` paths continue to use it directly.
