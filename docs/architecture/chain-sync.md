# Slow-mode chain sync (MVP-2 issue 4.1)

> **Status:** shipped 2026-05-15 under `issue/4.1-chain-sync` worktree.
> See [`docs/issue-plans/4.1.md`](../issue-plans/4.1.md) for the
> plan-gate, the L1..L12 invariants, and the L-section
> adversarial-framing rows.

## Scope

Issue 4.1 ships the first MVP-2 path that **reads from chain**. It
consumes `RevisionPublished` events from D-017 (`RevisionLogV1` at
`0x179362Ad7fb7dA664312aEFDdaa53431eb748E42` on Base Sepolia,
`chainId = 84_532`), filters by the caller's `vault_id`, per-event
recovers the secp256k1 signer via the production v1 verifier, feeds
verified events into `Vault::ingest_pending_chain_revision`, and
advances a per-vault `last_synced_block` checkpoint.

NO publish path lands in 4.1. NO indexer. NO background scheduler. The
caller invokes `Vault::sync_from_chain(...)` periodically (or on user
action); the chain-sync orchestrator is invoke-and-return.

## R-a..R-f resolutions (summary)

See [`DECISIONS.md`](../../DECISIONS.md) for the canonical narrative.
Concrete consequences in-tree:

| Resolution | Implementation |
|---|---|
| **R-a** (`.pvf` checkpoint) | `chain_sync_v1_state` table (single-row, CHECK id = 0); `Vault::last_synced_block_v1()` / `update_last_synced_block_v1()` accessors. `SyncOptions { from_genesis: true }` for the user-facing re-sync escape. |
| **R-b** (WS preferred + HTTP fallback) | Issue #99 (2026-05-18) flipped alloy's `provider-ws` + `pubsub` features and shipped the WS-preferred branch. `chain_sync::ws::open_subscription` opens a real `eth_subscribe("logs", filter)` WS subscription; `Vault::sync_from_chain` runs HTTP backfill first (cursor → head), then enters a WS recv loop at tip per Q-a Option A. WS open-fail / mid-session-drop never aborts the sync (L10); circuit breaker at `WS_CIRCUIT_BREAKER_THRESHOLD = 5` consecutive failures falls through to HTTP polling. `SyncReport.event_source` is honest (L9); `SyncReport.ws_drops` carries the reconnect telemetry. |
| **R-c** (two-stage rollback) | `RevisionStatus::Pending { observed_at_block, block_hash }` → `Finalized` at depth ≥ 12. Three additive `revisions` columns (`revision_status`, `observed_at_block`, `observed_block_hash`). `ReorgDetector` caches observed hashes; `Vault::rollback_pending_revisions_in_range` + `promote_finalized_revisions` drive the state-machine. |
| **R-d** (permissive auto-register) | `device::auto_register_device_from_chain_sync` inserts a row keyed on the EVM address (left-padded `device_id`); two additive `devices` columns (`discovered_via_chain_sync`, `discovered_at_block`). Idempotent via `INSERT OR IGNORE`. |
| **R-e** (async on `pangolin-store::Vault`) | `Vault::sync_from_chain(&mut self, rpc_url, env, vault_id, options) -> Result<SyncReport, StoreError>` lives on the Vault side (NOT on `pangolin-chain`) — preserves L7. Primitives (signer recovery, event-decode, reorg detector) live on `pangolin-chain`. |
| **R-f** (hermetic + reorg simulator) | 30 hermetic tests in `chain_sync::tests` (round-trip verifier, chain-id check, fetch_chunk happy + reject paths, reorg simulator shallow + deep). Live `#[ignore]`'d test deferred pending captured-event hex pin (env-quirk #14). |

## The verifier (L1) — what survives round-trip

`recover_signer_v1` + `recover_signer_v1_raw` (in
`crates/pangolin-chain/src/secp256k1_signing.rs`) reuse the SAME
private helpers (`struct_hash`, `eip712_digest`, `build_domain`,
`is_canonical_s`) the signing-side `build_signed_revision_v1` uses.
Byte-identical digest construction is the load-bearing property that
lets the round-trip test (sign with 3.1 → recover with 4.1 → assert
identity) fire.

The helpers were promoted from `fn` (private) to `pub(crate) fn` in
4.1; they remain crate-internal so the `secp256k1_signing` module's
public API surface stays minimal.

LOW#3 defense-in-depth: the recovery side asserts `s ≤ secp256k1n/2`
BEFORE attempting `recover_address_from_prehash` — a high-s sig from a
misbehaving publisher / RPC is rejected with `SignerRecoveryFailed`
rather than silently malleating to a different recovered address.

The `v` byte sanity gate (must be 27 or 28) is the second defense:
EIP-712 binds `v ∈ {27, 28}` (chain id is in the domain separator,
not in `v`); anything else is rejected.

## The fetch path — WS-preferred + HTTP-fallback state machine

```text
sync_from_chain(rpc_url, env, vault_id, options)
│
├── resolve cursor (last_synced_block_v1 || d017_deploy_block(env))
├── fetch head (eth_blockNumber)
├── L-checkpoint-corruption check: cursor > head ⇒ fail
│
└── loop while cursor < head:
    │
    ├── chunk_end = min(cursor + LOG_BLOCK_CHUNK, head)    # L6: chunked at 9000
    │
    ├── fetch_and_verify_chunk(rpc_url, env, vault_id, cursor+1, chunk_end)
    │       │
    │       ├── build_read_provider (HTTP)
    │       ├── check_chain_id_matches (L3 — eth_chainId pinned to env.chain_id())
    │       ├── resolve_and_check_contract (L4 — load + pinned-address cross-check)
    │       │
    │       └── poll::fetch_chunk (the per-chunk eth_getLogs)
    │               ├── filter: address + topic0(RevisionPublished) + topic1(vault_id)
    │               ├── decode via reused alloy sol! binding (L2)
    │               ├── reject foreign emitter (defense-in-depth past server-side filter)
    │               ├── reject wrong vault_id (L-malicious-vault-id-substitution)
    │               ├── reject future schemaVersion (L-schemaVersion-future-poison)
    │               └── emit VerifiedRevisionEvent {event, signer, block_hash, schema_version}
    │
    ├── for each event:
    │       ├── auto_register_device_from_chain_sync (R-d; idempotent)
    │       ├── ingest_pending_chain_revision (R-c; status = 'pending')
    │       └── ReorgDetector.record(block_number, block_hash)
    │
    ├── detect_reorg_via_rpc (compare observed hashes to canonical chain)
    │       └── if reorg detected: rollback_pending_revisions_in_range + forget_window
    │
    ├── promote_finalized_revisions(head)
    │       └── pending rows at depth ≥ 12 → finalized
    │
    └── update_last_synced_block_v1(chunk_end)               # R-a + L12 atomic fence
```

### WS-preferred branch (issue #99 — 2026-05-18)

The R-b "WebSocket preferred" branch is fully shipped. The workspace
`Cargo.toml` selects alloy's `provider-ws` + `pubsub` features (which
transitively bring `tokio-tungstenite` + `tungstenite` + `alloy-pubsub`
+ `rustls` with `aws-lc-rs` — `ring` remains BANNED via `deny.toml`
and verified zero in the dep tree by `scripts/check-no-ring.sh`).

The orchestrator topology (Q-a Option A, locked 2026-05-18):

```text
sync_from_chain(rpc_url, env, vault_id, options)
    │
    ├── Stage 1 — HTTP backfill (always runs)
    │     ├── Chunked eth_getLogs at LOG_BLOCK_CHUNK = 9_000
    │     ├── verify_alloy_log per event (L2 byte-identical to WS)
    │     ├── ingest_pending_chain_revision + reorg check
    │     └── advance last_synced_block_v1 atomically
    │
    └── Stage 2 — WS tip-follow (when prefer_websocket && until_block.is_none())
          │
          ├── resolve_ws_url(rpc_url, env, ws_default)
          │     ├── if pinned: use chain.ws_default from base-sepolia.json
          │     └── else: derive from HTTP URL (https→wss / http→ws)
          │
          ├── check_ws_scheme — L-ws-tls-downgrade defence
          │     ├── BaseSepolia/BaseMainnet refuse ws:// (only wss://)
          │     └── Dev permits ws:// (hermetic mock + anvil)
          │
          ├── open_subscription(ws_url, env, vault_id, contract_address)
          │     ├── ProviderBuilder + connect_ws (WsConnect)
          │     │     └── keepalive = WS_KEEPALIVE_INTERVAL_SECS = 30s
          │     ├── check_chain_id_matches (issue #99 F-3 fix-pass:
          │     │     L3 defence against asymmetric-host topology
          │     │     where ws_default + rpc_default resolve to
          │     │     different chains; soft-fails on mismatch →
          │     │     WsOpenError::ChainIdMismatch counts toward the
          │     │     breaker per L10)
          │     └── subscribe_logs(filter:
          │             address=D-017
          │             topic0=RevisionPublished
          │             topic1=vault_id)
          │
          └── recv loop (bounded by WS_TIP_FOLLOW_WINDOW_SECS = 30s)
                ├── per-event: verify_alloy_log → ingest →
                │     advance checkpoint
                └── on SubscriptionClosed:
                      ├── ws_drops++
                      ├── exponential backoff via
                      │     next_reconnect_backoff_ms
                      └── retry up to WS_CIRCUIT_BREAKER_THRESHOLD = 5
                          consecutive failures, then fall through to
                          HTTP polling at HTTP_POLL_INTERVAL_SECS
                          cadence for the rest of the session
```

L10: WS open-fail / mid-session-drop NEVER fails the sync.
**Chain-id mismatch on the WS provider** (issue #99 F-3 fix-pass:
`WsOpenError::ChainIdMismatch`, surfaced when an asymmetric-host
topology — `chain.ws_default` pointing at a different RPC host than
`chain.rpc_default` — exposes a foreign-chain WS) is also treated as
an open-fail: counts toward the breaker, advances backoff, degrades to
HTTP polling per L10. The load-bearing L3 chain-id pin remains
enforced on the HTTP path (`check_chain_id_matches` inside
`build_read_provider`); the HTTP provider's check is what would HARD
abort the sync via `ChainError::ChainIdMismatch`. Only HARD failures
on the HTTP path (chain-id mismatch, contract-address mismatch,
unrecoverable RPC) abort.

L9: `SyncReport.event_source` is set to `WebSocket` only if at least
one WS-delivered event was successfully ingested; otherwise stays at
`HttpPolling` (the path actually taken at exit).

## Documented limitation — alloy's pubsub transparent reconnect (issue #99 F-4 re-audit)

**alloy 2.0.4's `alloy-pubsub` layer transparently reconnects on WS
post-handshake drops and does NOT surface this to the orchestrator's
`recv_next_event`.** Empirically verified during the issue #99 F-4
re-audit fix-pass: against the `accept_then_drop_subscribe` hermetic
mock, `recv_next_event` blocked for 10 seconds without surfacing
`WsRecvOutcome::SubscriptionClosed`, while the mock accepted 1809
TCP connections in that window (alloy reconnecting ~180/sec).

**Root cause.** Reading `alloy-pubsub-2.0.4/src/service.rs::reconnect_with_retries`:
`max_retries` (default 10) only counts FAILED reconnect attempts.
The accept-then-drop pattern causes every reconnect to "succeed"
at the WS-handshake + eth_subscribe level (the server's response
arrives before the close), so the retry counter never trips.
`WsConnect::with_max_retries(0)` does NOT help — the underlying
counter still observes "success" on each cycle. The cap is on
consecutive failures, not on connection thrashing.

**What this means for the orchestrator's L10 circuit breaker.** The
breaker has two trigger paths:

| Path | Triggered when | Status |
|---|---|---|
| `open_subscription` Err (TCP refuse, scheme reject, chain-id mismatch, eth_subscribe RPC error) | initial connection or its first RPC fails | **WORKS — breaker increments + falls to HTTP** |
| `recv_next_event` → `SubscriptionClosed` (alloy gives up reconnecting) | alloy's `max_retries` × backoff exhausts (≈ minutes of FAILED reconnects) | **WORKS — SLOW-failure mode only; the F-2 recv-loop-exit gate fires here** |
| `recv_next_event` blocks indefinitely (alloy transparently reconnects on every drop) | accept-then-drop storm post-handshake | **MASKED — orchestrator never sees the drop signal** |

The third path is the gap. A malicious or buggy RPC that accepts WS
connections + replies to `eth_subscribe` + immediately drops can spin
alloy's pubsub layer indefinitely without the orchestrator falling
back to HTTP. The user's sync would APPEAR to succeed (no error
returned) but no events would land. This is a DoS-style failure mode.

**Mitigation in place.** The HTTP path's L3 chain-id pin
(`check_chain_id_matches` inside `build_read_provider`) still HARD
aborts the sync if the HTTP RPC is on the wrong chain — so an
adversarial RPC can't silently swap chains. The Stage 1 HTTP
backfill still runs on every `sync_from_chain` call, so any events
the WS path missed during the storm are caught on the next cycle.
**Net behaviour: the storm reduces WS to "best-effort tip-follow"
without breaking HTTP-backed sync correctness.** Catch-up cadence
degrades from "real-time WS push" to "next pull-cycle HTTP poll" —
i.e., from ~seconds to ~60s (the `pull_once` interval).

**Architectural follow-up (deferred from #99).** A direct WS
transport that bypasses `alloy-pubsub` — using `tokio-tungstenite` +
hand-written JSON-RPC framing (same shape the WS hermetic mock uses)
— would let the orchestrator see every drop in real time. This was
weighed against a heuristic wrapper (timing-based; vulnerable to
adversarial threading of the keepalive signal) and an alloy fork
(maintenance + drift burden). The direct-transport path is the
project's hand-roll-security-critical pattern (KDBX parser, TOTP
engine, encrypted-export format, ciborium-ll handshake) applied to
the WS-sync surface. Tracked as a follow-up — see the issue
backlog.

## Two-stage rollback state machine (R-c)

```text
       1-conf insert                     depth >= 12 promotion
              ↓                                  ↓
   ┌─────────────────────┐    ┌─────────────────────────────┐
   │  RevisionStatus     │ →  │  RevisionStatus::Finalized  │
   │  ::Pending {         │    │  (no longer subject to       │
   │    observed_at_block,│    │   rollback)                  │
   │    block_hash        │    └─────────────────────────────┘
   │  }                   │              ↑
   └─────────────────────┘              │
              ↓                          │
   reorg detection (block_hash mismatch  │
   on canonical chain at observed height)│
              ↓                          │
   rollback_pending_revisions_in_range   │
   (DELETE from revisions where status=  │
    'pending' AND observed_at_block in   │
    [low, high])                         │
              │                          │
              ↓                          │
   ReorgDetector.forget_window(info) ────┘
   (next sync re-records under new       │
    canonical hashes)                    │
```

**Safety invariant:** only `Pending` revisions are rolled back;
`Finalized` revisions are NEVER touched (R-c boundary). The
`rollback_pending_revisions_in_range` SQL has `WHERE revision_status =
'pending'` baked in; the `rollback_pending_revisions_in_range_skips_finalized`
test pins this.

## Per-vault checkpoint persistence (R-a)

Single-row `chain_sync_v1_state` table:

```sql
CREATE TABLE IF NOT EXISTS chain_sync_v1_state (
    id                  INTEGER PRIMARY KEY CHECK (id = 0),
    chain_env_tag       INTEGER NOT NULL DEFAULT 1,
    last_synced_block   INTEGER NOT NULL DEFAULT 0,
    last_synced_at      INTEGER,
    schema_version      INTEGER NOT NULL DEFAULT 1
);
```

Distinct from the v0-era `sync_state` table so the v0 readback path +
v1 chain sync advance independently. Additive `CREATE TABLE IF NOT
EXISTS` (no `format_version` bump); legacy P0..3.6 vaults pick it up
on next open via `apply_pragmas_and_schema`.

Accessors:

- `Vault::last_synced_block_v1() -> Result<Option<u64>>` — `None` for
  a fresh vault; orchestrator defaults to `d017_deploy_block(env)`.
- `Vault::update_last_synced_block_v1(new_block: u64) -> Result<()>` —
  monotonic; refuses backward moves with `StoreError::Corrupted`.

## Sync-mode selector (MVP-2 issue 4.4)

> **Status:** shipped 2026-05-16 under `issue/4.4-sync-mode-selector`
> worktree. See [`docs/issue-plans/4.4.md`](../issue-plans/4.4.md)
> for the plan-gate, L1..L7 invariants, and the L-section
> adversarial-framing rows. R-a..R-e resolved decisions
> ([`DECISIONS.md`](../../DECISIONS.md)).

Issue 4.4 ships the **client-side picker** that decides whether to
invoke 4.1's in-process slow-mode sync (`Vault::sync_from_chain`) or to
surface a "Spin up faster sync? (uses temporary local indexer that
auto-deletes)" prompt that — on user assent — spawns 4.2/4.3's
ephemeral `pangolin-indexer`. 4.4 is **read-only logic + a vault-stored
UX preference**; it does NOT spawn the indexer (the host owns that on
user assent — L1) and does NOT change either underlying sync path.

### What the picker decides

[`Vault::select_sync_mode`](../../crates/pangolin-store/src/vault.rs)
returns one of three `SyncMode` variants:

- **`SyncMode::Slow`** — host runs `Vault::sync_from_chain` in-process
  (the 4.1 R-e path).
- **`SyncMode::OfferFast`** — host renders the D-007 prompt; on user
  accept, spawn `pangolin-indexer` (4.2 + 4.3); on user decline, fall
  through to slow-mode.
- **`SyncMode::AlwaysFast`** — host spawns `pangolin-indexer` directly
  without a per-session prompt. This is the only path where the host
  spawns without per-session assent — the user pre-assented when they
  set `SyncModePreference::AlwaysFast`.

### The first-sync heuristic (R-a)

| `last_synced_block_v1` | `sync_mode_preference` (Auto) | returns |
|---|---|---|
| `Some(_)` | Auto | `Slow` |
| `None` | Auto | `OfferFast` |

Single-axis: did this vault, on this device, ever complete a slow-mode
sync? If yes → slow-mode is good enough. If no → offer the user the
fast path because a brand-new vault (or one restored on a fresh device)
faces a potentially long first-sync window.

The plan-gate's master-plan-§5 wording ("<100 unsynced revisions →
slow-mode; ≥100 → offer fast") was reframed by Kelvin during
sign-off: the only realistic ≥100-revisions case is a first sync on
this device. Long-offline-catchup users still get slow-mode (a
"tolerable UX cost" per the resolved-decisions narrative). NO
threshold value lives in code; NO env-var override; NO `eth_getLogs`
revision count.

### The three-state preference flag (R-b)

`meta.sync_mode_preference TEXT` column on the vault file. Three
states:

- `NULL` (=`SyncModePreference::Auto`; the default for all existing
  vaults) — defer to the heuristic.
- `'always_slow'` — force `SyncMode::Slow` regardless of checkpoint.
- `'always_fast'` — force `SyncMode::AlwaysFast` regardless of
  checkpoint.

Cleartext column by design (L2 — UX state, not secret material;
mirrors the 1.4 `session_idle_secs` precedent). A filesystem-tamperer
who flips the value causes a UX degrade (denied fast-mode UX, or
forced indexer spawn — both no worse than the underlying surfaces
already exposed in 4.2/4.3). The user retains the ability to flip via
`Vault::set_sync_mode_preference` at any time.

Migration: `migrate_sync_mode_preference_column` in
`crates/pangolin-store/src/schema.rs` — additive
nullable-column on `meta`. NO `format_version` bump. Legacy
vaults open on new code and read the column as NULL → `Auto`.

### The host's responsibility

Per L1, the picker NEVER auto-spawns the indexer. The host (CLI,
Tauri shell, mobile UI) owns:

1. Calling `vault.select_sync_mode(rpc_url, env).await` at the
   sync-trigger boundary.
2. Rendering the D-007 "Spin up faster sync? (uses temporary local
   indexer that auto-deletes)" prompt on `SyncMode::OfferFast`.
3. On `OfferFast→accept` or `AlwaysFast`, spawning the
   `pangolin-indexer` binary (4.2 lifecycle) + draining its output into
   `Vault::ingest_pending_chain_revision`.
4. On `OfferFast→decline` or `Slow`, invoking
   `Vault::sync_from_chain` directly.
5. Surfacing `Vault::set_sync_mode_preference` as a user-settable knob
   (Settings page; CLI subcommand; FFI — deferred to a CLI-V1 batch
   per the plan-gate's "Out of scope" boundary).

### The `async fn` signature

`select_sync_mode` is `async` even though the current implementation
never awaits — the R-c plan-gate signature reserves the option to
call a chain RPC (`pangolin_chain::fetch_current_block_number`) from
future heuristics without breaking the public API. The `rpc_url` +
`env` parameters are placeholders for that future refinement. Today
the body only reads `self.last_synced_block_v1()?` +
`self.sync_mode_preference()?` and dispatches on the combined table.

## Threat-model touch-points

See [`THREAT_MODEL.md`](../../THREAT_MODEL.md) "Slow-mode chain sync
(read path + v1 verifier)" row for the per-surface enumeration of
L-rpc-spoof-events, L-rpc-omits-events, L-reorg-rollback,
L-checkpoint-corruption, L-malicious-vault-id-substitution,
L-schemaVersion-future-poison, L-verifier-domain-binding-drift, and
L-permissive-auto-register-could-add-spam (R-d trade-off).

4.4's three L-rows (L-malicious-RPC-fakes-chain-head,
L-vault-state-staleness, L-preference-flag-tamper) are tracked in the
new "Sync-mode selector (4.4)" row. All three are UX-degrade-only —
the load-bearing security defenses live in 4.1's verifier + chain-id
check + 4.2/4.3's ephemeral indexer + temp-DB cipher.

## Pull loop (5.2)

**MVP-2 issue 5.2** wraps the 4.4 picker + 4.1 slow-mode delegate in a
per-cycle async primitive `Vault::pull_once(rpc_url, env, &vault_id)`
that the host scheduler drives every 60 seconds while a session is
active. Master plan §5 row 5.2 verbatim: *"On unlock + periodic (every
60s while session active). Apply non-conflicted heads automatically."*

5.2 is **host-owned timer** (R-a) — `pangolin-store` exposes only the
primitive; the host (CLI / Tauri / mobile) owns the
`tokio::time::interval` scheduler. The engine never spawns the loop,
which preserves the zero-`tokio::spawn` discipline inside the store
crate. The loop is implicitly canceled by every session-teardown path
via `PullError::NoActiveSession` (R-e — mirrors 5.1's
`BatchFlushError::NoActiveSession` posture verbatim).

`OfferFast` / `AlwaysFast` cycles return signal-only (the engine
NEVER spawns the indexer subprocess per L2); the host owns the
indexer-spawn decision. `Slow` cycles delegate to 4.1's
`Vault::sync_from_chain` verbatim (L4 — no duplicate logic; inherits
the full L1..L12 defensive surface).

Full design + canonical host scheduler loop body + threat model in
[`pull-loop.md`](pull-loop.md).

## Conflict surface (5.3)

**MVP-2 issue 5.3** ships the FFI-side conflict-surfacing plumbing
that the existing 1.6 + P8 + P9 machinery had built up but never
exposed: the `vault_list_conflicts` FFI binding, the
[`ConflictReport`](../../crates/pangolin-store/src/conflict.rs)
enrichment (per-branch `device_id` / `observed_at_block` /
`schema_version` / `is_tombstone` / `on_canonical_chain`), the
[`PullReport`](../../crates/pangolin-store/src/pull.rs) extension
(`newly_frozen_accounts` / `newly_forked_accounts` /
`newly_resolved_accounts` per-tick deltas), and the
`Vault::snapshot_conflicts` + `Vault::list_conflicts_since` accessor
pair for the 5.4 indicator state machine. ZERO change to
`ingest_chain_revision` / `refuse_if_frozen` / canonical-head
election — 5.3 surfaces existing state; it does not re-elect.

Full design in [`conflict-surface.md`](conflict-surface.md).

## File layout

- `crates/pangolin-chain/src/chain_sync.rs` — module root, constants,
  `SyncReport`, `RevisionStatus`, `ChainEventSource`, `SyncOptions`,
  `VerifiedRevisionEvent`, `fetch_and_verify_chunk`,
  `fetch_current_block_number`, `detect_reorg_via_rpc`,
  `resolve_and_check_contract`, `check_chain_id_matches`,
  `build_read_provider`, `d017_deploy_block`.
- `crates/pangolin-chain/src/chain_sync/poll.rs` — `fetch_chunk` (HTTP
  per-chunk fetcher), `verify_signed_event` (synthetic-event verifier
  for the test path).
- `crates/pangolin-chain/src/chain_sync/ws.rs` — WS state machine
  (issue #99): `open_subscription`, `WsHandle`, `WsOpenError`,
  `WsRecvOutcome`, `recv_next_event`, `resolve_ws_url`,
  `check_ws_scheme`, `build_ws_read_provider`,
  `next_reconnect_backoff_ms`.
- `crates/pangolin-chain/src/chain_sync/reorg.rs` — `ReorgDetector`,
  `ReorgInfo`.
- `crates/pangolin-chain/src/chain_sync/tests.rs` — 30 hermetic tests.
- `crates/pangolin-chain/src/secp256k1_signing.rs` — `recover_signer_v1`
  + `recover_signer_v1_raw` (R-d production primitives; were
  `recover_v1_for_test` in 3.1).
- `crates/pangolin-store/src/vault.rs::sync_from_chain` — async
  orchestrator (R-e on the Vault side).
- `crates/pangolin-store/src/vault.rs` — `last_synced_block_v1`,
  `update_last_synced_block_v1`, `rollback_pending_revisions_in_range`,
  `promote_finalized_revisions`, `ingest_pending_chain_revision`,
  `count_chain_sync_discovered_devices` accessors.
- `crates/pangolin-store/src/device.rs::auto_register_device_from_chain_sync`
  — R-d helper.
- `crates/pangolin-store/src/schema.rs` — additive migrations for
  `revisions.{revision_status, observed_at_block, observed_block_hash}` +
  `devices.{discovered_via_chain_sync, discovered_at_block}` +
  `chain_sync_v1_state` table + (4.4) `meta.sync_mode_preference`
  via `migrate_sync_mode_preference_column`.
- `crates/pangolin-store/src/vault.rs` — **(4.4)** `SyncMode` +
  `SyncModePreference` + `Vault::select_sync_mode` (async picker) +
  `Vault::sync_mode_preference` (read) + `Vault::set_sync_mode_preference`
  (write).
- `crates/pangolin-store/src/meta.rs` — **(4.4)** `read_sync_mode_preference`
  + `write_sync_mode_preference` (mirror `read_session_idle_secs` /
  `write_session_idle_secs` byte-for-byte in shape).
