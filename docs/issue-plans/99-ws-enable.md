# Issue 99: WS-enable (alloy ws feature flip)

> **One-line scope:** flip alloy's `ws` feature on in the workspace `Cargo.toml`, replace `chain_sync::ws::open_subscription`'s `WsOpenError::Unavailable` stub with a real `ProviderBuilder` + `eth_subscribe("logs", filter)` subscription, wire `Vault::sync_from_chain` to honor the existing `SyncOptions.prefer_websocket = true` default by attempting WS first and falling back to the already-shipped HTTP-polling loop on WS-open-fail / mid-session-drop. Closes the L8 deferral the 4.1 plan-gate explicitly forecast as "MVP-3 4.1.x feature-flag flip." Most of the structural surface is ALREADY in tree at `be7fe30` — this cycle adds the live transport + orchestrator branch that consumes it.
>
> **Status:** Plan-gate DRAFT 2026-05-18 awaiting Kelvin sign-off on Q-a..Q-h.
>
> **Security-critical: MEDIUM.** Does NOT close a known cryptographic gap. DOES (a) introduce new transport surface for malicious-RPC injection (same risk class as HTTP — L-rpc-spoof-events from 4.1 — but re-asserted across new code path), (b) add new transitive crates to the workspace dep tree (env-quirk #15 + HIGH-1 audit + `ring`-ban tripwire), (c) introduce stateful reconnect loop whose silent-disconnect failure mode is the load-bearing risk.
>
> **Depends on:** main tip `be7fe30` (post-#98); 4.1 R-b scaffolding in `crates/pangolin-chain/src/chain_sync/ws.rs` + `ChainEventSource` enum + `SyncOptions.prefer_websocket`; `Vault::sync_from_chain` orchestrator (today writes `ChainEventSource::HttpPolling` unconditionally at vault.rs:7549).
>
> **Out of scope:**
> - MVP-3-host-FFI-handles (#100). Host can't toggle `prefer_websocket` from FFI today; ships there if needed.
> - WS-based publish path. R-b WS surface is READ-only (subscription); broadcast stays HTTP. 4.1 L11 preserved.
> - Anvil-fork CI for WS. Hermetic uses mock WS server (Q-d K); WS-against-live is residue `#[ignore]` per #98 posture.
> - Funder client + chaincli WS migration. Both HTTP; not in scope.
> - Indexer's chain-touching surface (consumes alloy primitives only; no provider construction).
> - Per-event WS replay-protection beyond existing idempotency (4.1 L12 — canonical-hash + chain-anchor match handles duplicates).

## Resolved decisions (Kelvin sign-off PENDING)

| Decision | Resolution | Notes |
|---|---|---|
| **R-a Transport posture** | TBD | Plan-gate recommends Option A (WS-only-for-tip-following; HTTP for historical backfill). |
| **R-b Reconnect strategy** | TBD | Plan-gate recommends Option β (exponential backoff cap 30s + circuit breaker N=5). |
| **R-c WS endpoint URL** | TBD | Plan-gate recommends Option I+III hybrid (pin `chain.ws_default` in deployment JSON; derive from HTTP URL as fallback). |
| **R-d Test posture** | TBD | Plan-gate recommends Option K (hermetic mock-server + 1 live `#[ignore]`). |
| **R-e Feature gating** | TBD | Plan-gate recommends Option P (always-on; runtime decides via `prefer_websocket`). |
| **R-f WS event ingest** | TBD | Plan-gate recommends Option T (per-event advance + ingest; no HTTP re-confirm). |
| **R-g WS replay-protection** | TBD | Plan-gate recommends Option Σ (trust 4.1 L12 idempotency). |
| **R-h WS reorg detection** | TBD | Plan-gate recommends Option Ω (timer-based at 12-block finality cadence). |

---

## Critical inventory finding

**4.1 R-b ALREADY shipped the WS state-machine scaffolding.** Already in tree at `be7fe30`:
- `ChainEventSource` enum (HttpPolling, WebSocket discriminants)
- `WsHandle` (unit placeholder; grows alloy subscription receiver on flip)
- `WsOpenError { Unavailable, UnsupportedScheme, ConnectFailed }`
- `next_reconnect_backoff_ms(prev_ms)` — exponential 250ms → 30s, doubling. Already tested.
- `WS_RECONNECT_INITIAL_BACKOFF_MS = 250` + `WS_RECONNECT_MAX_BACKOFF_MS = 30_000` + `HTTP_POLL_INTERVAL_SECS`
- `SyncOptions.prefer_websocket: bool` (defaults true)
- `chain_sync::ws::open_subscription(rpc_url)` returns `Err(WsOpenError::Unavailable)` — the L8 stub branch this cycle replaces.

**Surprise:** Only ONE call site is the load-bearing change (`build_read_provider` in `chain_sync.rs:448` — currently `ProviderBuilder::new().network::<Ethereum>().connect(rpc_url)`, wired HTTP-only because alloy's `ws` feature is OFF in workspace `Cargo.toml:87`).

`Vault::sync_from_chain` (vault.rs:7436-7551) IGNORES `options.prefer_websocket` today — writes `ChainEventSource::HttpPolling` unconditionally at lines 7477 + 7549-7550. This cycle wires it.

**Critical hazard: `ring` ban in `deny.toml:127`.** Alloy 2.x `ws` feature defaults to `rustls + aws-lc-rs` (the same posture `pangolin-funder-client` already uses), but if the transitive selection ever lands `ring`, CI's `cargo deny check` fails fast. Builder MUST verify `cargo tree -i ring` returns 0 rows post-flip BEFORE writing any other code (per L5 below).

---

## Plain-English glossary for Kelvin

- **WebSocket (WS)** — long-lived two-way connection; server pushes messages when something happens (vs HTTP where client asks every N seconds and discovers events up to 30s late).
- **`eth_subscribe('logs', filter)`** — standard JSON-RPC method that opens a subscription on an Ethereum WebSocket. Server pushes every new log matching the filter (contract address + event topic + indexed vault_id) until we close it.
- **`alloy::providers::ws` feature** — Cargo feature flag. When ON, alloy compiles in the WebSocket client. Currently OFF — that's why our stub returns `Unavailable`.
- **Reconnect-on-drop** — WS connections aren't bulletproof. Network blips, RPC servers restart, OS kills idle sockets. Code must detect death + reopen without losing sync state + without re-ingesting events we already saw.
- **Backoff** — when reconnect fails, wait before retrying. Exponential (250ms, 500ms, 1s, 2s, ..., cap 30s) prevents a dead-RPC from becoming a CPU-spinning hot loop.
- **Fallback to HTTP polling** — if WS unavailable (feature off, server doesn't support, drops repeatedly), orchestrator switches to the already-shipped `eth_getLogs` chunked path. User still syncs; just at polling latency.
- **Trusted RPC** — both HTTP and WS share trust posture: the RPC server CAN inject fake events. Our existing defenses (address filter + topic filter + chain-id pin + contract-address pin + contract-side `ecrecover` at publish time) apply equally to both transports.
- **`ring` vs `aws-lc-rs`** — both are TLS crypto libraries. `ring` is BANNED in our deny.toml (the project chose `aws-lc-rs` for the production tree). Alloy's WS feature MUST land with `aws-lc-rs`, not `ring`, or CI fails.

---

## Q's for Kelvin (LOAD-BEARING)

### Q-a · Transport posture

The 4.1 plan-gate locked R-b as "WS-preferred with HTTP-fallback." This cycle decides specifics:

**Option A (recommend): WS-only-for-tip-following; HTTP for historical backfill.** Chunked `eth_getLogs` loop runs first to catch up `last_synced_block → head`. THEN open WS subscription for new events at tip. Reasoning: WS subscriptions deliver only NEW events from subscription time forward — they cannot replay history. Backfill via WS forces a polling layer on top of WS anyway.

**Option B: WS-primary with HTTP fallback on disconnect.** Open WS first; on open-fail or drop, fall back to HTTP polling. Simplest but provides zero value on fresh-vault first-sync (still does HTTP chunk loop in the fallback branch).

**Option C: WS-only.** Reject — RPC without WS support → user can't sync.

**Option D: Runtime-toggle (host picks).** Defer to MVP-3-host-FFI-handles. For this cycle, fix policy at Rust default.

### Q-b · Reconnect strategy

**Option α: Exponential backoff + retry forever (cap 30s).** User's app stays "trying to sync" indefinitely. Con: on permanently-bad RPC, never see error — just slow sync.

**Option β (recommend): Exponential backoff + circuit breaker (N=5 consecutive failures → disable WS for the session; fall through to HTTP polling).** Bounded recovery time; surfaces `SyncReport.ws_drops` for UX telemetry; resets on next `sync_from_chain` call.

**Option γ: Single retry then HTTP fallback.** Simplest; transient blips (server restart 2s) waste WS benefit for rest of session.

### Q-c · WS endpoint URL source

`build_read_provider` takes one `rpc_url`. WS needs different URL (`https://` vs `wss://`).

**Option I: Derive from HTTP URL (replace scheme).** Zero new config. Works for most public RPCs including `sepolia.base.org`. Breaks for asymmetric provider topologies.

**Option II: Add `ws_url: Option<&str>` on `SyncOptions`.** Explicit. One more config knob; today's callers need updates.

**Option III: Add `chain.ws_default` to `base-sepolia.json`.** Mirrors existing `chain.rpc_default`. Pinning at deployment-record layer (same source-of-truth as #98 L1). Requires updating `deployment_json_pins_match_rust_constants` test.

**Plan-gate recommends Option I + III hybrid:** pin `wss://sepolia.base.org` in JSON (Option III for source-of-truth); derive at runtime when not pinned (Option I for dev/unpinned envs).

### Q-d · Test surface

**Option K (recommend): Hermetic mock-WS-server + 1 residue `#[ignore]` live test.** Mock uses local `tokio-tungstenite` server emitting canned `eth_subscribe` responses (~150-250 LoC, `#[cfg(test)]`-gated). Live residue tests `wss://sepolia.base.org` against D-017. Mirrors #98 R-a Option D.

**Option L: Hermetic only.** Misses env-quirk #14-class drift on the live WSS endpoint.

**Option M: Anvil-fork WS.** New CI infra cost #98 explicitly deferred.

### Q-e · Feature gating

**Option P (recommend): Always-on.** alloy `ws` feature unconditional in workspace Cargo.toml; runtime decides via `SyncOptions.prefer_websocket`. One binary across all environments; CI exercises every code path. ~600 KB binary-size cost (acceptable for mobile).

**Option Q: Feature-gated `#[cfg(feature = "ws")]` blocks.** env-quirk #11 (feature unification) gotchas — if ANY crate enables it, transitives land workspace-wide anyway. Maintenance burden for no real benefit.

### Q-f · WS event ingest mechanics

**Option T (recommend): Per-event advance + ingest.** Treat WS events as authoritative for tip-following. Existing defenses (filter + chain-id pin + ecrecover) apply identically.

**Option U: Re-query via HTTP `eth_getLogs` to confirm, then ingest.** Defense-in-depth idea. But kills the latency win — HTTP confirm round-trip adds back polling-class delay. Also: malicious-WS-RPC and malicious-HTTP-RPC are same trust class.

**Option V: Batch WS events on a timer.** Amortizes ingest cost; defeats latency win; complicates reorg detection.

### Q-g · WS replay-protection across reconnect

**Option Σ (recommend): Trust 4.1 L12 idempotency.** `Vault::ingest_chain_revision` is idempotent (canonical-hash + chain-anchor match). Duplicate WS-delivered events are storage-layer no-ops.

**Option Τ: Per-session WS-seen-event set in memory.** New state. Bounded-memory concern.

### Q-h · WS reorg detection cadence

**Option Ω (recommend): Timer at 12-block finality cadence (~24s).** Matches `CONFIRMATION_DEPTH_FOR_FINALIZATION`. Same `detect_reorg_via_rpc` helper.

**Option Φ: Per-event.** High RPC volume; defeats latency win.

**Option Χ: Never (only on WS-drop fallback).** Violates R-c — reorg detection is load-bearing for pending → finalized.

---

## Locked invariants (L1..L12)

| # | Invariant | Rationale |
|---|---|---|
| **L1** | 4.1 R-b scaffolding (`ChainEventSource`, `WsHandle`, `WsOpenError`, `next_reconnect_backoff_ms`, backoff constants, `HTTP_POLL_INTERVAL_SECS`, `prefer_websocket`) is the contract. Renames out of scope; FILL IN the stub, don't redesign. | Plan-gate discipline. |
| **L2** | All 4.1 L1..L12 defenses apply to WS-delivered events with NO weakening: address-filter + topic-filter + decoded via reused `sol!` binding + cross-check `vaultId` topic + reject foreign emitter + reject future schemaVersion + chain-id pin + contract-address pin. WS only changes TRANSPORT; verification is byte-identical. | L-rpc-spoof-events from 4.1 stays at same strength. |
| **L3** | NO WS path on the publish surface. R-b WS branch is READ-only. All broadcast via HTTP per existing chain_submit.rs. 4.1 L11 ("ZERO on-chain broadcast on sync path") preserved. | Out-of-scope discipline. |
| **L4** | `pangolin-crypto` HIGH-1 (zero-serde) preserved. WS transitives land in `pangolin-chain`'s tree; pangolin-crypto is UPSTREAM of pangolin-chain. Adding deps downstream cannot affect pangolin-crypto's tree. CI `check-no-serde-in-crypto.sh` continues to return 0. | Structural defense via dep direction. |
| **L5** | NO `ring` selection across new WS transitives. MUST select `rustls + aws-lc-rs` (same posture as `pangolin-funder-client`). Builder verifies `cargo tree -i ring` returns 0 rows post-flip. `deny.toml`'s `ring` ban is the tripwire. | env-quirk #15 + existing denylist. |
| **L6** | Reorg detection on WS branch runs at finality-depth cadence (every 12 blocks ≈ 24s) per Q-h Option Ω. NOT per-event. Uses SAME `detect_reorg_via_rpc` helper. | RPC budget bounded; matches finality semantics. |
| **L7** | Idempotency at ingest (4.1 L12) is the load-bearing defense against WS-duplicate-events-across-reconnect. NO new dedupe layer. | Avoids parallel state. |
| **L8** | `Vault::sync_from_chain` continues to be SINGLE entry point. WS recv loop lives inside it. No new public surface in `pangolin-store` / `pangolin-chain` beyond existing R-b scaffolding. | Surface discipline. |
| **L9** | `SyncReport.event_source` honestly reflects path: `WebSocket` if tip-following ran via WS; `HttpPolling` if WS never opened or fell back. Observable from host for UX telemetry. | R-b decision honored. |
| **L10** | WS open-fail / mid-session-drop NEVER fails the sync. Orchestrator ALWAYS reaches `Ok(SyncReport)` — WS-down degrades to HTTP polling silently with `ws_drops` counter for telemetry. Only HARD failures (chain-id mismatch, contract-address mismatch, unrecoverable RPC) abort. | Defense against L-ws-silent-disconnect. |
| **L11** | `forbid(unsafe_code)` preserved across all new code. AGPL-3.0-or-later SPDX header on every modified `.rs` file. | Same since 1.1. |
| **L12** | Circuit-breaker policy per Q-b Option β: 5 consecutive WS reconnect failures within single `sync_from_chain` invocation → WS disabled for remainder; fall through to HTTP polling. Resets on next call. | Bounded recovery + UX telemetry. |

## Adversarial framing — L-section

### L-ws-silent-disconnect
WS drops silently (TCP RST swallowed); recv loop blocks forever; user thinks sync is happening; no events arrive.
**Defense:** TCP keep-alive (tokio-tungstenite default) + WS-level ping/pong per RFC 6455. On ping timeout, close + reconnect per Q-b. Feeds circuit breaker (L12).
**Tests:** `hermetic_ws_recv_loop_detects_silent_socket_close_within_keepalive_window`; `hermetic_ws_circuit_breaker_degrades_to_http_after_5_consecutive_open_failures`.

### L-ws-reconnect-storm
RPC hits rate limit (HTTP 429 over upgrade handshake or TCP-level flood limiter); client retries every 250ms; gets IP-banned.
**Defense:** Exponential backoff (already in `next_reconnect_backoff_ms`); circuit breaker (L12); reset per-`sync_from_chain` so transient ban doesn't permanently block.
**Tests:** `hermetic_ws_backoff_doubles_on_consecutive_open_failures`; `hermetic_ws_reconnect_storm_caps_at_30s_then_circuit_breaks`.

### L-ws-event-replay
WS reconnects; server re-emits events client already saw.
**Defense:** L7 — idempotency at ingest (4.1 L12). Storage-layer no-op.
**Test:** `hermetic_ws_duplicate_event_across_reconnect_is_noop_at_ingest`.

### L-ws-out-of-order
WS pushes events out of block order (server-side queuing).
**Defense:** Block-order NOT load-bearing — each event carries `(block_number, log_index, sequence)`; `ingest_chain_revision` keys on `(vault_id, sequence)` not insert order. Reorg detector uses `BTreeMap` (sorted on read).
**Test:** `hermetic_ws_out_of_order_events_ingest_in_canonical_order`.

### L-ws-trusted-rpc
Malicious RPC server (same risk class as HTTP from 4.1).
**Defense:** L2 — all 4.1 defenses byte-identical. Filter + chain-id pin + contract-address pin + contract-side ecrecover.
**Tests:** `hermetic_ws_malicious_foreign_address_event_rejected`; `hermetic_ws_malicious_wrong_chain_id_at_open_fails_closed`.

### L-ws-tls-downgrade
Server advertises only `ws://` (cleartext); RPC traffic observable on wire (vault_id leak).
**Defense:** Refuse `ws://` in production envs (`BaseSepolia`, future `BaseMainnet`); accept only `wss://`. Dev may use `ws://` against anvil. Q-c URL resolver enforces; deployment-pin test (#98 `deployment_json_pins_match_rust_constants`) extended for scheme check.
**Test:** `hermetic_ws_rejects_ws_scheme_for_base_sepolia`.

### L-ws-feature-leak-into-crypto
WS transitives introduce serde into pangolin-crypto's tree, breaking HIGH-1.
**Defense:** Dep-direction (L4). pangolin-crypto upstream of pangolin-chain. Verified by CI `check-no-serde-in-crypto.sh`.

### L-ws-feature-leak-pulls-ring
alloy `ws` feature transitively selects `ring` instead of `aws-lc-rs`.
**Defense:** L5. Builder verifies `cargo tree -i ring` returns 0 pre-merge. `deny.toml`'s `ring` ban is tripwire; CI gates fresh PRs.
**Test:** NEW CI step `cargo tree -i ring` (or extract to `scripts/check-no-ring.sh`).

## Affected crates / files

**MODIFIED:**
- `Cargo.toml` (workspace, line 87) — add `"ws"` to alloy `features = [...]`.
- `crates/pangolin-chain/src/chain_sync/ws.rs` — primary build target. Replace stub with real `open_subscription` + `WsHandle` carrying alloy `Subscription<Log>` + WS-event recv loop + circuit-breaker counter + Q-c WS-URL resolver + Q-h reorg timer + L-ws-tls-downgrade scheme check.
- `crates/pangolin-chain/src/chain_sync.rs` — `build_read_provider` sibling `build_ws_read_provider`. New constants `WS_KEEPALIVE_INTERVAL_SECS = 30` + `WS_CIRCUIT_BREAKER_THRESHOLD = 5`. `SyncReport.ws_drops: u32` for telemetry.
- `crates/pangolin-chain/src/lib.rs` — re-export new constants.
- `crates/pangolin-store/src/vault.rs::sync_from_chain` — orchestrator branch per Q-a Option A. HTTP chunk loop backfills `cursor → head`; if `prefer_websocket && cursor == head`, attempt `open_subscription(ws_url)`; on success enter WS recv loop with periodic reorg-check timer + finalization timer; on open-fail or circuit-breaker fall back to HTTP polling at `HTTP_POLL_INTERVAL_SECS` cadence. `SyncReport.event_source` written honestly at exit.
- `contracts/deployments/base-sepolia.json` — add `chain.ws_default = "wss://sepolia.base.org"` per Q-c Option III.
- `crates/pangolin-chain/tests/deployment_json_pins_match_rust_constants.rs` — extend to assert `ws_default` is `wss://` for `BaseSepolia` (L-ws-tls-downgrade).
- `crates/pangolin-chain/src/chain_sync/poll.rs` — extract reusable `verify_alloy_log(log, vault_id, contract_address, env)` helper so WS branch reuses identical decode/verify (L2).
- `docs/architecture/chain-sync.md` — remove "WS deferral note (L8)" section; replace with "WS-preferred branch (issue #99)" describing as-shipped state machine + Q-a Option A topology.
- `THREAT_MODEL.md` — NEW rows: L-ws-silent-disconnect, L-ws-reconnect-storm, L-ws-event-replay, L-ws-out-of-order, L-ws-tls-downgrade, L-ws-feature-leak-pulls-ring. L-rpc-spoof-events UPDATED for "applies equally to HTTP + WS."
- `DECISIONS.md` + `DEVLOG.md` — append.
- `.github/workflows/ci.yml` — NEW step `cargo tree -i ring` must return 0 (or extract to script).
- `deny.toml` — if `cargo audit` surfaces NEW unmaintained advisories post-flip, add ignore entries with the same justification shape as `RUSTSEC-2024-0436`.

**NEW:**
- `crates/pangolin-chain/tests/ws_mock_server.rs` — Q-d Option K hermetic test harness. Local `tokio-tungstenite` WS server with canned `eth_subscribe` responses. ~150-250 LoC; `#[cfg(test)]`-gated.
- `crates/pangolin-chain/tests/hermetic_ws.rs` — 15-20 hermetic tests against mock server.
- `crates/pangolin-chain/tests/integration.rs` (EXTEND) — add ONE `#[ignore]` residue `live_ws_subscribe_against_d017`.
- `scripts/check-no-ring.sh` (NEW) or inline CI step.

## Schema migration
None. Same `RevisionPublished` events, same `ingest_pending_chain_revision` path, same `chain_sync_v1_state` row. No `.pvf` change.

## Test plan

| Test | Category | Criterion |
|---|---|---|
| `hermetic_ws_open_subscription_against_mock_server_returns_handle` | basic | L1 |
| `hermetic_ws_recv_loop_emits_events_in_order` | recv path | basic |
| `hermetic_ws_event_passes_verification_with_same_defenses_as_http` | L2 | reuse |
| `hermetic_ws_recv_loop_detects_silent_socket_close_within_keepalive_window` | L-ws-silent-disconnect | L10 + L12 |
| `hermetic_ws_circuit_breaker_degrades_to_http_after_5_consecutive_open_failures` | L-ws-reconnect-storm | L12 |
| `hermetic_ws_backoff_doubles_on_consecutive_open_failures` | extension | existing |
| `hermetic_ws_reconnect_storm_caps_at_30s_then_circuit_breaks` | L-ws-reconnect-storm | L12 |
| `hermetic_ws_duplicate_event_across_reconnect_is_noop_at_ingest` | L-ws-event-replay | L7 |
| `hermetic_ws_out_of_order_events_ingest_in_canonical_order` | L-ws-out-of-order | sequence |
| `hermetic_ws_malicious_foreign_address_event_rejected` | L-ws-trusted-rpc | L2 |
| `hermetic_ws_malicious_wrong_chain_id_at_open_fails_closed` | L-ws-trusted-rpc | L2 |
| `hermetic_ws_rejects_ws_scheme_for_base_sepolia` | L-ws-tls-downgrade | typed error |
| `hermetic_ws_periodic_reorg_check_runs_at_12_block_cadence` | L6 | Q-h |
| `hermetic_sync_from_chain_uses_ws_when_prefer_websocket_true_and_cursor_at_head` | orchestrator | Q-a |
| `hermetic_sync_from_chain_uses_http_backfill_then_ws_tip_follow` | orchestrator | Q-a |
| `hermetic_sync_from_chain_falls_back_to_http_on_ws_open_fail` | orchestrator | L10 |
| `sync_report_event_source_reports_websocket_on_ws_path` | L9 | telemetry |
| `sync_report_ws_drops_counter_increments_on_reconnect` | L12 | telemetry |
| `deployment_json_pins_match_rust_constants` (EXTEND) | L-ws-tls-downgrade | wss:// check |
| `next_reconnect_backoff_doubles` (existing) | regression | unchanged |
| `live_ws_subscribe_against_d017` (`#[ignore]`) | live residue | env-quirk #14 |

## CI / build-gate impacts
- env-quirk #15: builder runs `cargo audit` + `cargo deny check` post-flip; document new unmaintained advisories in `deny.toml`. NEW vulnerabilities (not unmaintained) are HARD BLOCKERS.
- env-quirk #11: WS workspace-level feature; every alloy-consumer gets WS transitives (intended per Q-e P).
- HIGH-1 (zero-serde): STRUCTURALLY preserved via dep direction.
- `ring` ban: NEW CI step `cargo tree -i ring` → 0. Builder verifies pre-merge.
- env-quirk #14: WS URL pinned in JSON; deployment-pin test extended for scheme; live residue catches transport regressions.
- env-quirk #16: if CI step adds multi-line pwsh, watch line length.
- Cargo.lock churn: ~30-60 lines.

## Threat-model touch points
- L-rpc-spoof-events (existing) — UPDATE for HTTP + WS.
- NEW rows: L-ws-silent-disconnect, L-ws-reconnect-storm, L-ws-event-replay, L-ws-out-of-order, L-ws-tls-downgrade, L-ws-feature-leak-pulls-ring.

## Estimated effort

**~10-14h wall-clock** (Option A + β + I+III + K + P + T + Σ + Ω):
- Workspace `Cargo.toml` flip + `cargo tree -i ring` + `cargo audit` + lockfile regen: ~30 min.
- `chain_sync/ws.rs` real `open_subscription` + `WsHandle` real receiver + WS-URL resolver: ~1.5h.
- WS recv loop + circuit breaker + keep-alive ping/pong: ~2h.
- Q-h reorg-check timer + Q-f per-event ingest in `sync_from_chain`: ~2h.
- Q-a backfill-then-tip-follow orchestrator branch: ~2h.
- Mock WS server (`ws_mock_server.rs`): ~1.5h.
- 15-20 hermetic tests: ~2-3h.
- Live residue test: ~30 min.
- Extend `deployment_json_pins_match_rust_constants` + `ws_default` JSON field: ~20 min.
- `check-no-ring.sh` + CI step: ~30 min.
- THREAT_MODEL.md + chain-sync.md rewrite + DECISIONS.md + DEVLOG.md: ~1h.
- Local `cargo test --workspace` + clippy + audit + deny check + adversarial audit re-read: ~1h.

**If `cargo tree -i ring` lights up** (alloy 2.0.4 `ws` feature transitively selects ring without `aws-lc-rs` opt-in), cycle is BLOCKED pending alloy bump — separate cycle. Verification: builder runs flip locally + checks tree BEFORE writing other code, so risk surfaces in first hour.
