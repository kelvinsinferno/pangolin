# Issue CLI-V1: CLI + FFI wiring batch — close deferred §3.x / §4.x / §5.x items

> **One-line scope:** the standing CLI-V1-wiring follow-up batch that closes the FFI gaps + CLI subcommand gaps accumulated across §3.2 (`wallet`), §3.5 (`balance` / `top-up`), §4.4 (`sync-mode`), §5.1 (`flush` / `queue-status` + FFI), §5.2 (`pull-status` + FFI for `pull_once`), §5.4 (`sync-loop` canonical host scheduler + FFI for `lock_with_drain`). The engine surface is 100% in tree from those cycles; CLI-V1 wires the orchestration shells. CLI-V1 is the FINAL batch before MVP-3 host work begins.
>
> **Status:** Plan-gate DRAFT 2026-05-17, awaiting Kelvin sign-off on Q-a..Q-i. Builder MUST NOT start until Kelvin lands resolutions in a "Resolved decisions" table mirroring 5.4 / 5.3. L1..L11 + the L-section below are non-negotiables independent of how Q-a..Q-i resolve.
>
> **Security-critical: NO.** CLI-V1 wires already-shipped engine primitives. ZERO new chain primitives, ZERO new on-disk schema, ZERO new crypto. Load-bearing security properties: L1 (CLI never bypasses session policy — reveal-class verbs go through 1.4's gates); L2 (CLI never imports `pangolin-chain` directly outside the existing adapter pattern from 5.1 R-h); L3 (every CLI exit path uses `Vault::lock_with_drain` per 5.4 R-e to close the 5.1 L1 deviation); L4 (FFI gap fills follow the `vault_*` UniFFI convention from 1.1).
>
> **Depends on:** 3.2 R-c `Vault::evm_wallet_address`; 3.5 R-d `BalanceMonitor` + `GasBalanceState`; 3.5 `pangolin-funder-client::initiate_top_up`; 4.4 R-b `SyncModePreference { Ask, AlwaysSlow, AlwaysFast }` + R-c `Vault::select_sync_mode`; 5.1 R-a `Vault::flush_publish_queue` + `publish_queue_state` + `coalesce_dirty_markers` + `enable_window_elapsed_flush`; 5.2 R-a `Vault::pull_once` + `PullReport` + `PULL_INTERVAL_SECS_DEFAULT` + `last_pull_at_unix_ms`; 5.3 R-d `Vault::list_conflicts_since` + `snapshot_conflicts`; 5.4 R-e `Vault::lock_with_drain` + R-h `vault_sync_status` FFI. Current `main` tip `18145f4` (post-5.4 merge).

## Resolved decisions (Kelvin sign-off 2026-05-17)

> Kelvin took all four surfaced plan-gate recommendations; Q-d (resolve interactive) + Q-e (--json) + Q-f (tests) + Q-h (drain retrofit) + Q-i (test posture) defaulted to plan-gate recommendations. Largest cycle since 5.1; closes 12 FFI gaps + ships 9 new subcommand modules + canonical host scheduler loop body. After CLI-V1, MVP-3 host work has zero engine-side dependencies.

| Decision | Resolution | Notes |
|---|---|---|
| **R-a Scope shape** | **Single CLI-V1 batch.** ~8-14h wall-clock; ~1200 LoC across CLI + FFI. Plan agent scope-assessment validated. | Tightly coupled around `cli.rs` clap tree + `commands/mod.rs`; splitting would just spawn coordination overhead. |
| **R-b Subcommand discipline** | **Mixed nested.** `pangolin sync flush|queue-status|pull-status|loop` (sync is verb-group) + `pangolin sync-mode show|set` (separate noun) + `pangolin wallet show` + `pangolin balance show` + `pangolin top-up` (flat). | Mirrors how `account` / `vault` / `authority` are nouns and `publish` / `pull` / `resolve` are verbs. |
| **R-c sync-loop long-running mode** | **Ship both sync-loop AND one-shot verbs.** One-shot verbs (`flush`, `pull`, `queue-status`, `pull-status`) for scripting + disaster recovery; `pangolin sync loop` long-running mode for "keep my vault synced." Uses `lock_with_drain` on SIGINT (L3). | Closes 5.4 R-a's canonical-host-scheduler-loop-body expectation. |
| **R-d resolve interactive mode** | **Combined.** No-flag invocation runs interactive TTY-detected flow (via `std::io::IsTerminal`); flags-only mode (existing `--account-id` / `--keep` / `--dry-run` / `--yes`) preserved as scripted form. Non-TTY without flags → helpful error. | Best UX + scripting both work. |
| **R-e Universal --json flag** | **Every new verb honors `--json`.** `queue-status` / `pull-status` / `wallet-show` / `balance-show` / `sync-mode show` emit JSON summaries; `sync loop` emits one JSON-Lines per tick. Per-event lines stay on stderr regardless. | Mirrors existing CLI posture; CI-scriptable. |
| **R-f Test surface** | **Per-verb smoke + integration + sync_loop file.** ~11 clap-parse smoke tests in `cli_arg_parsing.rs` + 7 integration tests in NEW `cli_v1_smoke.rs` + 3 integration tests in NEW `sync_loop.rs` + 3 in NEW `resolve_interactive.rs` + 13 FFI parity tests across new FFI modules. | Covers each new verb's clap shape + load-bearing end-to-end. |
| **R-g FFI gap fills** | **Ship all 12 gaps in CLI-V1.** `vault_pull_once` + `vault_last_pull_at_unix_ms` + `vault_flush_publish_queue` + `vault_publish_queue_state` + `vault_enable_window_elapsed_flush` + `vault_coalesce_dirty_markers` + `vault_select_sync_mode` + `vault_sync_mode_preference` + `vault_set_sync_mode_preference` + `vault_lock_with_drain` + `vault_evm_wallet_address` + `vault_initiate_top_up`. ~400 LoC + ~13 parity tests + UniFFI regen. | Closes every standing FFI defer; MVP-3 host work has zero engine-side dependencies left. |
| **R-h Pre-lock drain retrofit** | **Chain-touching commands only.** `publish` / `pull` / `resolve` / `flush` / `sync loop` / `top-up` swap `Vault::close` → `Vault::lock_with_drain`. Pure-local commands (`account *` / `vault *` / `import` / `authority` / `status` / `queue-status` / `pull-status` / `wallet show` / `balance show` / `sync-mode *`) keep `Vault::close`. | Drain only when chain access exists; mirrors the "5.1 L1 deviation only matters when there's a queue to drain" framing. |
| **R-i Test posture** | **Hermetic + 1 live `#[ignore]` test.** `live_sync_loop_converges_against_base_sepolia` in NEW `tests/sync_loop_live.rs` (deferred to fixture capture per §4.x/§5.x R-g precedent). No proptest. | Matches §5.x precedent verbatim. env-quirk #14 contract-side-semantics defense via the live test. |

---

---

## Open questions for Kelvin (LOAD-BEARING — surface at TOP per §16)

### Q-a · Scope shape — one batch or split?

**Option A: Single CLI-V1 batch (~8-14h).** All ~6 new subcommands + the `sync-loop` canonical host loop + ~9 FFI gap fills in one cycle. Pro: every bucket touches `cli.rs` clap tree + `commands/mod.rs`; coordinating them in one cycle reduces churn. Con: largest single cycle since 5.1.

**Option B: Three-way split (`cli-v1-sync` + `cli-v1-balance` + `cli-v1-resolve`).** Pro: smaller per-cycle. Con: artificial coordination overhead; the `sync-loop` body alone wires balance + sync-mode + flush + pull together.

**Option C: Two-way split (`cli-v1-verbs` + `cli-v1-loop`).** Pro: defers the load-bearing `sync-loop` work into its own cycle where it gets full plan-gate attention. Con: leaves the canonical host loop body — the BIGGEST CLI-V1 deliverable per the 5.4 plan — in a follow-up.

**Plan-gate recommends: Option A.** The actual code surface is small (~1200 LoC across CLI + FFI) and tightly coupled around `cli.rs` clap modifications.

**Kelvin's call.**

### Q-b · Subcommand discipline — flat or nested?

The existing CLI uses flat for orchestration verbs (`publish`, `pull`, `resolve`, `status`) and nested for noun-shaped verbs (`account add|list|...`, `vault create|...`, `authority list`).

**Option A: Flat.** `pangolin flush`, `pangolin queue-status`, `pangolin pull-status`, `pangolin sync-mode-show`, `pangolin sync-mode-set <ask|always-slow|always-fast>`, `pangolin wallet-show`, `pangolin balance-show`, `pangolin top-up`, `pangolin sync-loop`. Pro: matches existing posture. Con: 9 flat verbs blows out the top-level help.

**Option B: All nested under `sync`.** `pangolin sync flush`, `pangolin sync queue-status`, etc. Pro: groups sync verbs. Con: introduces a `sync` noun the CLI doesn't currently use.

**Option C: Mixed nested.** `pangolin sync flush|queue-status|pull-status|loop` + `pangolin sync-mode show|set` (separate noun) + `pangolin wallet show` + `pangolin balance show` + `pangolin top-up` flat. Pro: each verb aligns with its natural noun.

**Plan-gate recommends: Option C.** Mirrors how `account` / `vault` / `authority` are nouns and `publish` / `pull` / `resolve` are verbs.

**Kelvin's call.**

### Q-c · Canonical host scheduler loop — ship `sync-loop` long-running mode?

5.4's `docs/architecture/sync-orchestrator.md` lines 55-180 specify the canonical `tokio::select!` two-timer pattern as a Rust template. The CLI is documented as one of the canonical hosts (Tauri / mobile / CLI).

**Option A: Ship `pangolin sync loop` long-running subcommand.** Pasted from sync-orchestrator.md verbatim with CLI-specific wrapping (SIGINT handler, stderr status logging). Stays running until SIGINT/SIGTERM; uses `lock_with_drain` on shutdown (L3). Pro: closes the canonical-host-loop deliverable.

**Option B: Skip — one-shot only.** User wraps in shell loop themselves. Pro: minimal; sidesteps the session-policy friction. Con: deflects 5.4 R-a's explicit canonical-host-loop-body expectation.

**Option C: Both.** Ship `sync loop` AND keep individual `flush` / `pull` as one-shot subcommands. Pro: user picks. Con: same code-path twice in tests.

**Plan-gate recommends: Option C.** One-shot verbs are independently load-bearing for scripting / debugging / disaster recovery. The `sync loop` mode is the canonical-host-scheduler implementation 5.4 expects.

**Kelvin's call.**

### Q-d · `resolve` reshape — ADD interactive TTY mode?

`apps/cli/src/commands/resolve.rs` already ships with `--account-id <hex> --keep <hex> --dry-run --yes`. The 5.3 R-e `vault_list_conflicts` FFI lists every conflict; the CLI could surface this interactively.

**Option A: Add interactive TTY mode (no flags).** Calls `Vault::list_conflicts`; prints conflict table; prompts user. Pro: natural UX. Con: TTY prompts are flaky on Windows / non-pty environments.

**Option B: Keep flags-only.** Add `pangolin resolve list` subcommand that prints the conflict table only. Pro: clean separation. Con: two commands for one task.

**Option C: Combined.** No-flag invocation runs interactive flow; flags-only is the scripted form (already in tree). Pro: best UX. Con: same TTY-detection concern.

**Plan-gate recommends: Option C.** Detect TTY via `std::io::IsTerminal`; refuse interactive mode on non-TTY.

**Kelvin's call.**

### Q-e · Universal `--json` flag — every new verb?

`GlobalArgs::json` is already on every subcommand (`cli.rs:75`). Existing `status` / `publish` / `pull` honor it.

**Option A: Every new verb emits JSON summary on `--json`.** Including `sync loop` (one JSON-Lines per tick). Pro: every verb CI-scriptable.

**Option B: Read-only verbs JSON; mutating verbs human-only.** Pro: simpler. Con: scripts can't parse `top-up` outcomes.

**Plan-gate recommends: Option A.** Mirrors existing CLI posture.

**Kelvin's call.**

### Q-f · Test surface — extend `two_vault_roundtrip` or add new files?

**Option A: Extend `two_vault_roundtrip.rs`.** Pro: matches existing idiom. Con: file is ~600 lines; growing further is unwieldy.

**Option B: Add `tests/sync_loop.rs`.** Separate file; same `MockChainAdapter` + two-vault pattern. Pro: clean separation.

**Option C: Both — per-subcommand smoke tests in `cli_arg_parsing.rs` + a single `sync_loop.rs` integration test.** Pro: covers each new verb's clap shape + the load-bearing end-to-end.

**Plan-gate recommends: Option C.**

**Kelvin's call.**

### Q-g · FFI gap audit — ship the 9 gaps in CLI-V1?

The actual FFI gaps (verified by grepping `crates/pangolin-ffi/src`):

| Engine method | FFI exposed? | Cycle |
|---|---|---|
| `Vault::evm_wallet_address` | NO | 3.2 |
| `Vault::pull_once` | NO | 5.2 |
| `Vault::last_pull_at_unix_ms` | NO | 5.2 |
| `Vault::flush_publish_queue` | NO | 5.1 |
| `Vault::publish_queue_state` | NO | 5.1 |
| `Vault::enable_window_elapsed_flush` | NO | 5.1 |
| `Vault::coalesce_dirty_markers` | NO | 5.1 |
| `Vault::select_sync_mode` | NO | 4.4 |
| `Vault::sync_mode_preference` | NO | 4.4 |
| `Vault::set_sync_mode_preference` | NO | 4.4 |
| `Vault::lock_with_drain` | NO | 5.4 |
| `pangolin_funder_client::initiate_top_up` | NO | 3.5 |
| `Vault::resolve_fork` | YES (1.6 R-x) | - |
| `Vault::list_conflicts` | YES (5.3 R-e) | - |
| `Vault::sync_status_inputs` | YES (5.4 R-h consumes via `vault_sync_status`) | - |
| `BalanceMonitor` | YES (3.5 R-d) | - |

**Option A: Ship ALL 12 gaps in CLI-V1.** Each ~30-80 LoC. Total ~400 LoC. Pro: closes every standing FFI defer; MVP-3 host work has no FFI dependencies left. Con: large surface.

**Option B: Ship only what CLI uses.** CLI uses `pangolin-store::Vault` directly (no FFI dependency). CLI-V1 ships CLI-only; FFI to MVP-3. Pro: smallest cycle. Con: MVP-3 has to revisit every defer.

**Option C: Orchestration-critical only.** `vault_pull_once`, `vault_flush_publish_queue`, `vault_publish_queue_state`, `vault_lock_with_drain`. Defer the rest to MVP-3. Pro: medium scope. Con: half-measure.

**Plan-gate recommends: Option A.** The 12 FFI bindings are uniformly trivial; doing them all together is cheaper than re-opening the cycle later.

**Kelvin's call.**

### Q-h · Pre-lock drain retrofit — every CLI command or only `sync-loop`?

5.4 R-e ships `Vault::lock_with_drain`. Existing `vault_open.rs` / `commands/*.rs` use synchronous `Vault::close()` on exit.

**Option A: Retrofit every CLI command.** Pro: closes the 5.1 L1 deviation everywhere. Con: not every command has an `adapter` + `device_key` in scope.

**Option B: Only `sync-loop` graceful shutdown.** Pro: minimal. Con: 5.1 L1 deviation stays half-open.

**Option C: Retrofit only chain-touching commands.** `publish`, `pull`, `resolve`, `flush`, `sync-loop`, `top-up`. Pure-local commands keep `Vault::close`. Pro: matches the "drain only when chain access exists" intuition.

**Plan-gate recommends: Option C.** Commands that never publish have nothing to drain.

**Kelvin's call.**

### Q-i · Test posture — hermetic + 1 live `#[ignore]`?

**Option A: Hermetic + 1 live `#[ignore]` test.** Mirrors 5.1 / 5.2 / 5.3 / 5.4.

**Option B: Hermetic only.** Pro: faster CI. Con: live D-017 surface unexercised.

**Plan-gate recommends: Option A.**

**Kelvin's call.**

---

## Decisions locked (independent of Q-a..Q-i)

| # | Decision | Rationale |
|---|---|---|
| **L1** | **CLI subcommands NEVER bypass session policy.** Reveal-class operations require presence proofs (1.4). | 1.4 R-c lock. |
| **L2** | **CLI NEVER imports `pangolin-chain` directly outside the existing adapter pattern.** 5.1 R-h refactored `publish_all` to be a thin shell over `pangolin_store::publish::publish_all_for_vault`. | 5.1 R-h precedent. |
| **L3** | **`pangolin sync loop` graceful shutdown uses `Vault::lock_with_drain` (5.4 R-e).** Closes the 5.1 L1 deviation in the canonical host loop body. | 5.4 R-e + 5.1 L1. |
| **L4** | **New FFI bindings follow `vault_*` UniFFI convention.** Take `Arc<VaultHandle>` first parameter; return `Result<..., FfiError>`; wei values cross as hex strings. | 1.1 surface freeze + 5.4 R-h precedent. |
| **L5** | **NO new external crate dep.** Existing `clap` / `anyhow` / `tokio` / `serde_json` / `rpassword` / `zeroize` / `hex` cover everything. | Same dep discipline as 5.4 L6. |
| **L6** | **Dep direction preserved.** `pangolin-cli → pangolin-store → pangolin-chain`. | Anchor-types. |
| **L7** | **`forbid(unsafe_code)`** on every NEW `.rs` file; HIGH-1 + Q3 + 1.1 invariants preserved. | Mechanical. |
| **L8** | **AGPL-3.0-or-later SPDX header** on every NEW `.rs` file. | Standard. |
| **L9** | **ZERO on-chain broadcast outside `Vault::flush_publish_queue` / `Vault::publish_revision_v1`.** `top-up` invokes `pangolin_funder_client::initiate_top_up` (top-up request, not revision). | 5.1 L10 + 5.4 L10 inherited. |
| **L10** | **§8.1.5 vocabulary discipline in CLI help.** Every new subcommand's `--help` text avoids forbidden user-facing terms (`blockchain`, `gas`, `transaction`, etc.). Existing audit gate `cli.rs::account_help_avoids_forbidden_user_facing_terms` extends. | §8.1.5 + existing audit. |
| **L11** | **`forbid(unsafe_code)` in CLI-V1 FFI gap files.** | Inherited from 1.1 surface freeze. |

## Adversarial framing — L-section (load-bearing risks)

### L-cli-flag-injection-via-hex

**What goes wrong:** malicious `--account-id <hex>` value contains SQL-meta / shell-meta / overflow vectors. Mitigated by clap's `HexAccountId` value parser (`parse_32_byte_hex` rejects non-hex, length-checks) + `rusqlite` parameterized queries throughout. Dedicated test: `cli_v1_verbs_reject_non_hex_account_id`.

### L-resolve-prompt-misclick

**What goes wrong:** Q-d Option C interactive `resolve` misreads keystrokes; user kept the wrong branch. Mitigated by: (a) print full conflict table BEFORE prompt, (b) re-confirm chosen branch with `[y/N]` second prompt, (c) `--dry-run` flag in help text. Dedicated test: `interactive_resolve_re_confirms_chosen_branch`.

### L-status-leaks-balance-on-shared-screen

**What goes wrong:** `pangolin status --json` / `pangolin balance show --json` includes wei values in stdout. Acceptable per §5.4 L-status-leaks-balance-detail: same info already exposed via 5.1 + 5.4. L10 vocabulary discipline ensures no pricing copy leaks.

### L-sync-loop-leaks-creds-on-long-run

**What goes wrong:** `pangolin sync loop` holds the unlocked vault for hours; SIGTERM late in shutdown could leave cleartext in memory. Mitigated by: (a) `lock_with_drain` on SIGINT closes the session (L3), (b) 1.4 idle-expire / 4h-absolute session policy fires; orchestrator catches `PullError::NoActiveSession` and exits.

### L-graceful-shutdown-loses-pending-flush

**What goes wrong:** SIGINT during a `sync loop` iteration arrives between arms; pending flush lost. Mitigated by `lock_with_drain` (L3) running on shutdown.

### L-top-up-rebroadcast-on-retry

**What goes wrong:** `pangolin top-up` invoked twice in quick succession. Mitigated by `pangolin_funder_client::initiate_top_up`'s built-in idempotency (3.5 R-d) + CLI prompt confirming before broadcast.

### L-sync-mode-set-without-presence

**What goes wrong:** `pangolin sync-mode set always-fast` changes a meta row without presence proof. Acceptable per 4.4 R-b: `SyncModePreference` is a UI hint, not security-sensitive; engine still re-runs `select_sync_mode` per session.

---

## Affected crates

- **`apps/cli/src/cli.rs`** (~150 new LoC) — extend clap-derive tree with 7 new subcommand shapes (per Q-b resolution).
- **`apps/cli/src/commands/mod.rs`** — register 8 new modules.
- **NEW `apps/cli/src/commands/flush.rs`** (~80 LoC).
- **NEW `apps/cli/src/commands/queue_status.rs`** (~50 LoC).
- **NEW `apps/cli/src/commands/pull_status.rs`** (~40 LoC).
- **NEW `apps/cli/src/commands/sync_mode.rs`** (~100 LoC).
- **NEW `apps/cli/src/commands/wallet.rs`** (~40 LoC).
- **NEW `apps/cli/src/commands/balance.rs`** (~70 LoC).
- **NEW `apps/cli/src/commands/top_up.rs`** (~120 LoC).
- **NEW `apps/cli/src/commands/sync_loop.rs`** (~250 LoC) — implements canonical host scheduler loop body from `sync-orchestrator.md` lines 55-180.
- **`apps/cli/src/commands/resolve.rs`** (~60 LoC delta per Q-d Option C) — add interactive TTY mode.
- **`apps/cli/Cargo.toml`** — add `pangolin-funder-client` dep (in-tree; not external).
- **`crates/pangolin-ffi/src/sync_status.rs`** (~80 LoC delta) — NEW `vault_pull_once` + `FfiPullReport` record.
- **NEW `crates/pangolin-ffi/src/publish_queue.rs`** (~140 LoC) — `vault_flush_publish_queue` + `vault_publish_queue_state` + `vault_enable_window_elapsed_flush` + `vault_coalesce_dirty_markers`.
- **NEW `crates/pangolin-ffi/src/sync_mode.rs`** (~80 LoC) — `vault_select_sync_mode` + `vault_sync_mode_preference` + `vault_set_sync_mode_preference`.
- **`crates/pangolin-ffi/src/device.rs`** (~30 LoC delta) — `vault_evm_wallet_address`.
- **`crates/pangolin-ffi/src/session.rs`** (~50 LoC delta) — `vault_lock_with_drain`.
- **`crates/pangolin-ffi/src/balance.rs`** (~30 LoC delta) — `vault_initiate_top_up`.
- **`crates/pangolin-ffi/src/lib.rs`** — register all new bindings.
- **NEW `docs/architecture/cli.md`** (~300 LoC) — CLI user-facing command catalog.
- **`docs/architecture/sync-orchestrator.md`** — extend with CLI-specific subsection.
- **`docs/architecture/ffi-surface.md`** — add 9 new FFI bindings to catalog.
- **`docs/architecture/{funder-service,chain-sync,publish-queue,pull-loop,device,conflict-surface}.md`** — close CLI-V1 TODOs.
- **`DECISIONS.md`** + **`THREAT_MODEL.md`** + **`DEVLOG.md`** — append.

## Schema migration

**NONE.** CLI is a host; touches no schema rows.

## Test plan

### Per-verb clap-parse smoke tests in `apps/cli/tests/cli_arg_parsing.rs`

11 tests covering: `flush_parses_with_vault_path`, `queue_status_parses_with_vault_path`, `pull_status_parses_with_vault_path`, `sync_mode_show_parses`, `sync_mode_set_parses_with_value`, `sync_mode_set_rejects_unknown_value`, `wallet_show_parses_with_vault_path`, `balance_show_parses_with_vault_path`, `top_up_parses_with_vault_path`, `top_up_requires_confirmation_flag_or_tty`, `sync_loop_parses_with_vault_path`.

### Per-verb help-text vocabulary checks

`cli_v1_help_avoids_forbidden_user_facing_terms` extends existing audit.

### Per-verb integration tests in `apps/cli/tests/cli_v1_smoke.rs` (NEW)

7 tests: `flush_command_drains_dirty_queue`, `queue_status_emits_dirty_count`, `pull_status_emits_last_pulled_block`, `sync_mode_show_emits_preference`, `sync_mode_set_writes_preference`, `wallet_show_emits_address`, `balance_show_emits_state`.

### Canonical host loop body integration in `apps/cli/tests/sync_loop.rs` (NEW)

3 tests: `sync_loop_one_iteration_converges_two_vaults`, `sync_loop_sigint_during_loop_drains_pending_publishes`, `sync_loop_exits_on_session_expiry`.

### Interactive resolve in `apps/cli/tests/resolve_interactive.rs` (NEW, per Q-d Option C)

3 tests: `interactive_resolve_lists_conflicts_when_no_flags`, `interactive_resolve_re_confirms_chosen_branch`, `resolve_refuses_interactive_mode_on_non_tty`.

### FFI binding parity tests

13 tests across the new FFI modules — parity + session-discipline coverage.

### Live `#[ignore]` test (Q-i Option A)

`live_sync_loop_converges_against_base_sepolia` in `tests/sync_loop_live.rs`.

### Invariant tests

`cargo tree -p pangolin-chain --no-default-features --edges normal | grep -c pangolin-cli == 0`; `forbid(unsafe_code)`; `cli_v1_help_avoids_forbidden_user_facing_terms`.

## CI / build-gate impacts

- **No new external crate dep** (L5).
- **UniFFI bindings regen** required after FFI gap fills — swift + kotlin + cbindgen all need re-emit.
- **`pangolin-funder-client`** dep added to `apps/cli/Cargo.toml` (in-tree).
- **No `format_version` bump**.

## Threat-model touch points

`THREAT_MODEL.md` gains a NEW "CLI-V1 wiring (CLI-V1)" row covering L-cli-flag-injection-via-hex + L-resolve-prompt-misclick + L-sync-loop-leaks-creds-on-long-run + L-graceful-shutdown-loses-pending-flush + L-top-up-rebroadcast-on-retry + L-sync-mode-set-without-presence.

## Files expected to change

- 8 NEW `apps/cli/src/commands/*.rs`
- 3 NEW `apps/cli/tests/*.rs` (`cli_v1_smoke.rs`, `sync_loop.rs`, `resolve_interactive.rs`)
- 1 NEW `apps/cli/tests/sync_loop_live.rs` (`#[ignore]`)
- 1 modified `apps/cli/src/cli.rs` (clap subcommand shapes + tests)
- 1 modified `apps/cli/src/commands/mod.rs`
- 1 modified `apps/cli/src/commands/resolve.rs` (interactive mode)
- 1 modified `apps/cli/Cargo.toml`
- 3 NEW `crates/pangolin-ffi/src/*.rs` (`publish_queue.rs`, `sync_mode.rs`; sync_status / device / session / balance modified in place)
- 1 modified `crates/pangolin-ffi/src/lib.rs`
- 1 NEW `docs/architecture/cli.md`
- 8 modified architecture docs
- 3 appended (`DECISIONS.md`, `THREAT_MODEL.md`, `DEVLOG.md`)

Files NOT expected to change: `crates/pangolin-{store,chain,crypto,core,indexer,funder-client}/*` (engine 100% done from prior cycles); `contracts/*`; `services/funder/*`.

## Out of scope (explicit)

- **Tauri / mobile host UI** — MVP-3.
- **Browser-extension native messaging host** — MVP-4.
- **`pangolin authority register|clear`** — deferred to MVP-2 browser-extension work.
- **`pangolin device list|set-label`** — 1.5 deferred; different noun, different cycle.
- **`pangolin sync-mode set --probe`** that actually spawns the indexer — L1 inherited; indexer-spawn is host territory per D-007.
- **`pangolin top-up --auto`** auto-retry mode — manual API only per 3.5 R-e.
- **Telemetry / observability** — privacy-disallowed by D-006.
- **`pangolin balance show --watch`** long-running watch — would duplicate `sync loop`'s state machine.

## Estimated effort

**~8-14h wall-clock** if Kelvin defaults to plan-gate recommendations:

- 7 new CLI verbs × ~30-80 LoC + per-verb tests — ~3-4h
- `sync loop` canonical host body (~250 LoC + 3 integration tests) — ~2-3h
- Interactive `resolve` mode (Q-d Option C) — ~1h
- 9 FFI gap fills (~400 LoC + parity tests + UniFFI regen) — ~2-3h
- Docs — ~1.5h
- Live `#[ignore]` test — ~30min

If Kelvin splits scope (Q-a Option B/C), add ~2h coordination overhead per split. If Kelvin defers FFI (Q-g Option B), subtract ~2.5h. If Kelvin skips `sync loop` (Q-c Option B), subtract ~2.5h. If Kelvin keeps `resolve` flags-only (Q-d Option B), subtract ~1h.

CLI-V1 is the LAST scheduled cycle before MVP-3 host work begins; the master plan §6 table lists MVP-3 as Tauri shell + iOS shell + Android shell, all of which depend on CLI-V1's FFI gap fills landing.
