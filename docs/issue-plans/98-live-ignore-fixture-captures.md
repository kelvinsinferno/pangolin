# Issue 98: Live #[ignore] fixture captures across §4.x / §5.x / CLI-V1

> **One-line scope:** inventory every `#[ignore]`-gated test that depends on Base Sepolia (D-017 RevisionLogV1 + D-019 EntitlementRegistry); categorize each as (A) keep-`#[ignore]`-but-document-and-update-pinned-state, (B) hermeticize with a captured-from-live-chain fixture, or (C) move to a one-shot pre-release runner; capture the small set of real-chain fixtures needed for (B); update every pinned chain-state constant that has rotted relative to D-017/D-019 current state; ship one operator-facing runner that exercises the residue.
>
> **Status:** Plan-gate DRAFT 2026-05-18 awaiting Kelvin sign-off on Q-a..Q-f.
>
> **Security-critical: MEDIUM.** Does NOT close a known cryptographic gap. DOES alter the trust-edge between hermetic mocks and live verification — the discipline this cycle locks down is what catches the next env-quirk-#14-class bug (4.3 audit: calldata-vs-contract semantics mismatch invisible to hermetic tests, fatal on first live publish). One sub-decision (Q-d below) is AUDIT-CLASS severity because it surfaces a real rotted constant already in `main`.
>
> **Depends on:** current `main` tip `3dfdb80` (post-4.3-per-column-AEAD merge); D-017 + D-019 deployment records in `contracts/deployments/base-sepolia.json`; existing `#[ignore]`-gated tests in §4.x / §5.x / CLI-V1.
>
> **Out of scope:**
>
> - WS-enable cycle (#99). MVP-3-host-FFI-handles cycle (#100).
> - Any new chain-touching surface. This cycle ONLY changes test-discipline + fixture-storage around already-shipped code.
> - Re-deploying D-017 or D-019. If contract-semantics drift surfaces, that's its own cycle.
> - `search_10k_smoke` (non-chain `#[ignore]`).
> - Anvil-fork CI job (Q-a Option B — possible future cycle).
> - Migrating fixtures to a dedicated `pangolin-test-fixtures` crate (Q-b Option γ — refactor when duplication justifies).

## Resolved decisions (Kelvin sign-off PENDING)

| Decision | Resolution | Notes |
|---|---|---|
| **R-a Gating model** | TBD | Plan-gate recommends Option D (hybrid: hermetic-with-fixture for parsing surface; live `#[ignore]` residue for contract-execution surface). |
| **R-b Fixture storage** | TBD | Plan-gate recommends Option α (per-crate `tests/fixtures/`) + raw bytes. |
| **R-c Recapture cadence** | TBD | Plan-gate recommends Option ζ (recapture per-deploy). |
| **R-d Rotted deploy-block** | TBD | Plan-gate recommends Option III (re-query live chain to pin authoritative value; expects Option I outcome — JSON is right, Rust `23_640_113` is wrong). **AUDIT-CLASS severity.** |
| **R-e CI coverage** | TBD | Plan-gate recommends Option K (hermetic replay tests run on every PR) + Option M (no live-secrets CI job). |
| **R-f Runner shape** | TBD | Plan-gate recommends Option P (`scripts/run-live-tests.sh` + `.ps1`). |

---

## Inventory — grounds every decision below

**11 `#[ignore]`-gated tests** in 9 files. Categorized:

### A. Chain-touching (8 tests)

| # | File:fn | What | Pinned state | Rot? |
|---|---|---|---|---|
| 1 | `pangolin-chain/tests/integration.rs::live_balance_query_against_d017_wallet` | balance query | env-var address only | No |
| 2 | `pangolin-chain/src/secp256k1_signing.rs::cross_check_against_live_d017` | **EMPTY BODY** (runbook entry masquerading as test) | n/a | structural rot |
| 3 | `pangolin-chain/src/secp256k1_signing.rs::redemption_cross_check_against_live_d018` | **EMPTY BODY** + name says D-018 (superseded by D-019) | n/a | naming rot |
| 4 | `pangolin-chain/src/chain_submit.rs::publish_v1_live_d017_smoke` | live publish round-trip | wallet gas balance only | No |
| 5 | `pangolin-indexer/tests/parity.rs::live_indexer_vs_slow_mode_against_d017` | indexer-vs-slow-mode parity | `D017_DEPLOY_BLOCK = 23_640_113` | **YES** |
| 6 | `pangolin-indexer/tests/live_per_column_wrap.rs::live_per_column_aead_no_plaintext_on_disk` | 4.3 raw-disk sweep | same `23_640_113` | **YES** |
| 7 | `pangolin-store/tests/pull_live.rs::live_pull_once_against_d017_advances_checkpoint` | pull_once slow-mode | comment mentions `23640113` | **YES** |
| 8 | `pangolin-store/tests/sync_status_live.rs::live_orchestrator_observes_*` | sync-orchestrator transitions | no pinned block | No |
| 9 | `pangolin-store/tests/conflict_live.rs::live_two_device_*` | shape-only mock (body never reaches RPC) | none | No |

### B. Placeholders (2 tests)

| # | File:fn | Status |
|---|---|---|
| 10 | `apps/cli/tests/sync_loop_live.rs::live_sync_loop_placeholder_validates_env_var_contract` | env-var contract check; PLACEHOLDER body |
| 11 | `pangolin-funder-client/src/lib.rs::initiate_top_up_live_d019_placeholder` | empty body; "slot reserved" doc |

### C. Non-chain (1 test) — OUT OF SCOPE

| # | File:fn | Reason |
|---|---|---|
| 12 | `pangolin-store/tests/e2e.rs::search_10k_smoke` | release-mode perf; hermetic; unchanged |

### Critical rot finding (Q-d)

`d017_deploy_block(BaseSepolia)` returns **23_640_113** in `crates/pangolin-chain/src/chain_sync.rs:381`. Transitively pinned in 6 downstream files. `contracts/deployments/base-sepolia.json:"RevisionLogV1.deploy_block"` says **41639216**. These cannot both be right. The JSON value matches D-017's deploy timestamp `2026-05-14T18:07:28Z` (which is post-Base-Sepolia-genesis); `23_640_113` predates Sepolia by months. **Strong prior: JSON is right; Rust is rot.** This is exactly the env-quirk-#14 class.

### Other inventory findings

- **No `tests/fixtures/` directory exists** anywhere in `crates/**` or `apps/**`. Workspace has no fixture-storage convention.
- **No `include_bytes!` for chain data** in any test (only `handshake_ipc.rs` for stdio handshake bytes).
- **No anvil-fork workflow.** `--fork-url` appears 0× outside upstream forge-std.
- **`contracts/deployments/base-sepolia.json` is the de facto authoritative state ledger.** Rust constants are downstream and rot-prone.
- **`P5_4_DEPLOY_BLOCK = 41_133_000` in `chain/tests/integration.rs:33`** is the OLD `RevisionLogV0` deploy block (D-014), NOT D-017. Correct usage for V0 backwards-compat smoke — not rot.

---

## Plain-English glossary

- **`#[ignore]`** — Rust attribute that marks a test "skip by default; only run when explicitly asked via `cargo test -- --ignored`."
- **Hermetic test** — no I/O dependency on the outside world. No RPC, no network, no real chain. Deterministic on every machine.
- **Fixture** — chunk of real-world data, captured once and saved to a file, that a hermetic test replays. Example: real EVM log payload captured from D-017 on 2026-05-17, committed to repo.
- **Env-quirk #14** — audit lesson: hermetic tests can pass while live publish reverts every time. Discipline: pair every chain-broadcast cycle with EITHER manual pre-merge live test OR forge/anvil fork test in CI.
- **Anvil fork** — `anvil --fork-url <RPC>` boots local Ethereum node mirroring live chain. Deterministic + offline after initial pull.
- **Rotted fixture** — captured against older chain state that no longer matches reality. Either fails for wrong reason OR (worse) passes against stale data and hides regression.

---

## Q's for Kelvin (LOAD-BEARING)

### Q-a · Gating model

**Option A: Keep `#[ignore]`, document one-pass runner script.** Status quo + `scripts/run-live-tests.{sh,ps1}` reading gitignored `.env.live`. You run before each release.
- Pro: zero new infra. Con: discipline-dependent.

**Option B: Anvil-fork CI job.** `anvil --fork-url ... --fork-block-number <pinned>` boots local node; tests run against it on every PR.
- Pro: CI-side coverage. Con: new CI infra; flake surface; needs fork-block-bump on new deploy.

**Option C: Hermeticize all 8 with captured fixtures.** Capture real `eth_getLogs` responses + real `RevisionPublished` events to files; tests replay through same parser as production.
- Pro: every test runs on every PR. Con: tests requiring contract-execution result (#4 publish) genuinely can't be hermeticized.

**Option D (recommend): Hybrid.** Read-only / decode-only tests (#1, #2-runbook, #3-runbook, #5/#6/#7 decode side, #8) → hermetic+fixture. Round-trip / contract-execution tests (#4 publish, #5/#6/#7 contract-state assertions, #9 if ever made real) → keep `#[ignore]`, run pre-release via runner. Anvil-fork CI deferred to own cycle.

### Q-b · Fixture storage + format

**Option α (recommend): Per-crate `tests/fixtures/`.** `crates/<crate>/tests/fixtures/<test_name>/<purpose>.<ext>`. Locality wins; cross-crate refactor backward-compat.

**Option β: Workspace-level `tests/fixtures/`.** One folder at repo root. Single source of truth, but cross-crate `include_bytes!` is fragile.

**Option γ: Dedicated `pangolin-test-fixtures` dev-dep crate.** Typed accessors. Overkill until duplication forces it.

**Format: raw bytes** (exact JSON-RPC response / exact log hex) — replays through same parsers production uses. Decoded-JSON rejected (skips parsing surface that quirk #14 cares about).

### Q-c · Recapture cadence

**Option ε: Capture-once-and-lock.** Fixtures immutable except on contract deploy. Stable but blind to RPC-level drift.

**Option ζ (recommend): Recapture per-deploy.** Every new D-XXX triggers fixture-recapture in the deploy cycle's PR. `.meta.toml` diff is the audit signal.

**Option η: Idempotent script every release.** Noisy diff every time. Cognitive load > value.

### Q-d · Rotted `d017_deploy_block` — what's authoritative?

**THE LOAD-BEARING DECISION.** `23_640_113` (Rust) vs `41_639_216` (JSON). One of them is wrong.

**Option I: JSON is authoritative.** Update Rust to `41_639_216`; update 6 downstream pins; update the pinning test.

**Option II: Rust is authoritative.** Less likely.

**Option III (recommend): Re-query live chain.** `cast block-number` + `cast logs --address 0x179362... --from-block 0 ...` against the live D-017; pin whichever value matches. Expect Option I outcome.

**Why audit-class:** Sepolia is a testnet; getting the wrong block just means slower scans. But the same constant pattern on mainnet would mean missed events on fresh-vault first-sync. The discipline this cycle locks (`deployment_json_pins_match_rust_constants` hermetic test) prevents recurrence.

### Q-e · CI coverage

**Q-e Option K (recommend): Hermetic replay tests drop `#[ignore]` and run on every PR.** That IS the env-quirk-#14 defense.

**Q-e Option L: Keep replays `#[ignore]` too.** Defeats the purpose.

**Q-e' (sub-Q): Separate "live-chain-smoke" CI job with secrets?**

**Option M (recommend): No.** Keep CI secrets-free. Pre-release runner covers the residue.

**Option N: Yes, workflow_dispatch with repo-secret RPC + keystore.** Crosses the "secrets-in-CI" line. Not for this cycle.

### Q-f · Runner shape

**Option P (recommend): `scripts/run-live-tests.sh` + `scripts/run-live-tests.ps1`.** Two shell scripts; trivial.

**Option Q: `cargo xtask live-test`.** Workspace's first xtask. Idiomatic but overkill for one chore.

---

## Locked invariants (L1..L9)

| # | Invariant | Rationale |
|---|---|---|
| **L1** | `contracts/deployments/base-sepolia.json` is the SINGLE SOURCE OF TRUTH for every chain-state pin in Rust. | Q-d-class rot is otherwise inevitable. |
| **L2** | NO new chain-touching surface introduced. Only: (a) constants updated to match JSON, (b) fixtures captured for hermetic-rewrite of existing tests, (c) runner scripts. | Scope discipline. |
| **L3** | Every captured fixture ships with a sibling `.meta.toml` recording: source contract address, deploy reference (`D-017` etc.), capture UTC, `cast` command used, live block at capture. | Audit trail. Fixture without provenance is unverifiable. |
| **L4** | No fixture contains secret material. Public chain data only: logs, addresses, hashes, EIP-712 signatures over public typed data, domain separators. | Defense against accidental secret capture. |
| **L5** | Pre-release runner reads gitignored `.env.live` for RPC URL + keystore path. Script committed; `.env.live` in `.gitignore`. No env values in script. | Standard secrets-on-disk discipline. |
| **L6** | Every surviving `#[ignore]` test keeps a doc-block describing exactly what it tests + operator-visible failure mode. Empty-body tests get DEMOTED to runbook entries (NOT empty `#[test]` fns). | Empty `#[test]` bodies are a hazard — look like coverage but check nothing. |
| **L7** | All rotted constants identified by inventory MUST be fixed in this cycle. Specifically `d017_deploy_block` + 6 downstream pins (Q-d). | Fix-or-defer line: rot identified here does not survive to next cycle. |
| **L8** | `search_10k_smoke` (non-chain `#[ignore]`) NOT touched. Out of scope. | Mechanical. |
| **L9** | `forbid(unsafe_code)` preserved. AGPL-3.0-or-later SPDX header on every modified `.rs` file. | Same since 1.1. |

## Adversarial L-section

### L-fixture-rot
Captured fixture diverges from live chain over time (RPC adds field; contract gets renamed). Hermetic test passes against stale fixture; live moves on.
**Defense:** L1 + Q-c Option ζ + L3 provenance. Recapture's `.meta.toml` diff is the auditor's signal.
**Test:** every replay test asserts `.meta.toml` deploy-ID matches a live Rust constant.

### L-fake-fixture-from-wrong-test-build
Dev with buggy uncommitted change captures fixture from buggy output; commits; hermetic test perpetuates bug.
**Defense:** Q-c Option ζ protocol — fixtures captured via `cast` against live RPC, NOT via in-tree Rust adapter. `cast` command in `.meta.toml` (L3); reviewable in PR.
**Test:** `fixture_provenance` hermetic test parses `.meta.toml`; asserts `captured_via` starts with `cast `.

### L-secrets-in-fixtures
Developer captures `eth_signTransaction` response containing unsigned message bytes that include local entropy.
**Defense:** L4 + PR review. Capturable APIs (`cast logs`, `cast call`, `cast block`, `cast tx`) don't expose private material against public RPCs.
**Test:** `fixture_no_secrets` hermetic grep-sweep for entropy patterns matching private-key hex outside known-public-address list.

### L-rotted-constant-class
A constant in Rust drifts from JSON ground truth. Hermetic tests pass (share rotted constant); production fresh-sync starts at wrong block.
**Defense:** L1 + L7. NEW hermetic test `deployment_json_pins_match_rust_constants` — parses JSON; asserts each Rust constant matches corresponding JSON field. Future drift fails CI.
**Test:** asserts `d017_deploy_block == json["RevisionLogV1"]["deploy_block"]`; `EXPECTED_DEPLOYED_ADDRESS_BASE_SEPOLIA == json[...]["address"]`; `ENTITLEMENT_DOMAIN_SEPARATOR_BASE_SEPOLIA_V1 == json[...]["domain_separator"]["value"]`; `EXPECTED_ENTITLEMENT_REGISTRY_ADDRESS_BASE_SEPOLIA == json[...]["address"]`.

### L-empty-test-body
`cross_check_against_live_d017` + `redemption_cross_check_against_live_d018` are empty `{ }`-bodied `#[test]` fns. They "pass" doing nothing.
**Defense:** L6 — migrate to `crates/pangolin-chain/RUNBOOK.md`. `#[test]` fn disappears; operator runs documented cast call; no false-coverage signal.
**Test:** `no_empty_ignored_tests` hermetic grep-sweep asserts no test fn body is `{}` or `{ // ... }`.

## Affected files

**MODIFIED (~14 files):**
- `crates/pangolin-chain/src/chain_sync.rs:381` — `d017_deploy_block` constant per Q-d.
- `crates/pangolin-chain/src/chain_sync/tests.rs:647` — pinning test.
- `crates/pangolin-chain/src/chain_sync.rs:362-377` — docstring.
- `crates/pangolin-indexer/tests/parity.rs:55` — `D017_DEPLOY_BLOCK`.
- `crates/pangolin-indexer/tests/live_per_column_wrap.rs:43` — same.
- `crates/pangolin-indexer/tests/hermetic.rs:186, 305` — synthetic events; DECISION-MARKER low stakes.
- `crates/pangolin-indexer/tests/raw_disk_no_plaintext_per_column.rs:82, 214` — same as hermetic.rs.
- `crates/pangolin-store/tests/pull_live.rs:27` — comment block.
- `crates/pangolin-chain/src/secp256k1_signing.rs` — REMOVE empty-body `cross_check_against_live_d017` (lines 960-986) + `redemption_cross_check_against_live_d018` (lines 1427-1447); content migrates to RUNBOOK.md.
- `crates/pangolin-indexer/tests/parity.rs` — RENAME to `replay_d017_fixture_parity.rs` OR add hermetic sibling.
- `crates/pangolin-indexer/tests/live_per_column_wrap.rs` — same pattern.
- `crates/pangolin-store/tests/pull_live.rs` — same.
- `crates/pangolin-store/tests/sync_status_live.rs` — same.
- `crates/pangolin-store/tests/conflict_live.rs` — KEEP `#[ignore]`; add doc-block per L6.
- `crates/pangolin-chain/tests/integration.rs` — KEEP `#[ignore]` on balance query.
- `crates/pangolin-chain/src/chain_submit.rs:2410` — KEEP `#[ignore]` on publish smoke; add doc-block per L6.
- `crates/pangolin-funder-client/src/lib.rs:792` — doc-block per L6; note D-019 redemption-authority `0xaeE7E9bf859d938CB087D1e567221cffba9455AC`.
- `apps/cli/tests/sync_loop_live.rs` — UPDATE comment block describing the new state of the world.
- `.gitignore` — add `.env.live`.
- `THREAT_MODEL.md` — env-quirk #14 paragraph + new L-section rows.
- `DECISIONS.md` + `DEVLOG.md` — append.

**NEW (~8 files):**
- `crates/pangolin-chain/RUNBOOK.md` — operator-facing cast-call runbook (replaces empty-body tests).
- `crates/pangolin-chain/tests/deployment_json_pins_match_rust_constants.rs` — L-rotted-constant-class defense.
- `crates/pangolin-chain/tests/no_empty_ignored_tests.rs` — L-empty-test-body sweep.
- `crates/pangolin-indexer/tests/fixtures/parity/` — captured `eth_getLogs` + `.meta.toml`.
- `crates/pangolin-indexer/tests/fixtures/per_column_wrap/` — captured `RevisionPublished` payload + `.meta.toml`.
- `crates/pangolin-store/tests/fixtures/pull/` — captured `eth_getLogs` + `.meta.toml`.
- `crates/pangolin-store/tests/fixtures/sync_status/` — captured state + `.meta.toml`.
- `scripts/run-live-tests.sh` + `scripts/run-live-tests.ps1` — pre-release runner.
- `crates/<crate>/tests/fixture_provenance.rs` + `fixture_no_secrets.rs` — provenance + secrets sweeps.

## Test plan

| Test | Category | Criterion |
|---|---|---|
| `replay_d017_genesis_revisionpublished_decodes_correctly` (NEW) | parity hermetic | L-fixture-rot |
| `live_indexer_vs_slow_mode_against_d017` (residue `#[ignore]`) | live residue | quirk #14 |
| `replay_d017_revision_no_plaintext_per_column` (NEW) | per-column-wrap hermetic | L-fixture-rot |
| `raw_disk_scan_finds_plaintext_under_noop_cipher_negative_control` (existing) | regression | passes |
| `replay_d017_pull_batch_advances_checkpoint` (NEW) | pull-loop hermetic | L-fixture-rot |
| `replay_d017_sync_status_transitions` (NEW) | sync-status hermetic | L-fixture-rot |
| `live_two_device_concurrent_*` (KEEP `#[ignore]`) | shape-only mock | shape regression |
| `live_balance_query_against_d017_wallet` (KEEP `#[ignore]`) | live residue | quirk #14 |
| `publish_v1_live_d017_smoke` (KEEP `#[ignore]`) | live residue | quirk #14 |
| `initiate_top_up_live_d019_placeholder` (KEEP `#[ignore]`) | placeholder | none |
| `live_sync_loop_placeholder_validates_env_var_contract` (KEEP `#[ignore]`) | placeholder | none |
| `deployment_json_pins_match_rust_constants` (NEW hermetic) | constants-rot | L-rotted-constant-class |
| `no_empty_ignored_tests` (NEW hermetic) | empty-body sweep | L-empty-test-body |
| `fixture_provenance` (NEW hermetic) | provenance | L-fake-fixture |
| `fixture_no_secrets` (NEW hermetic) | secrets sweep | L-secrets-in-fixtures |
| `search_10k_smoke` (UNCHANGED `#[ignore]`) | perf | unchanged |

**Capture protocol** (Q-c Option ζ): each NEW fixture's PR description includes `cast` one-liner, block number + UTC timestamp, SHA-256 of fixture bytes. (1)+(2) → `.meta.toml`; (3) for PR-review traceability.

## CI / build-gate impacts

- All 5+ NEW hermetic tests run on every PR via standard `cargo test --workspace`.
- No new CI job. No new secret. No new artifact dep.
- env-quirk #14: bytes-parsing surface CLOSED via replays + `deployment_json_pins_match_rust_constants`. Contract-execution surface stays on manual pre-release runner.
- env-quirk #15 trivially clean (no new external crate dep).
- `chain_sync/tests.rs::d017_deploy_block_is_pinned_for_base_sepolia` FLIPS expected value per Q-d — that test becomes the load-bearing pin against the corrected value.

## Threat-model touch points

`THREAT_MODEL.md`:
- env-quirk #14 row — UPDATE: hermetic-with-fixture closes bytes-parsing side; pre-release runner closes contract-execution side.
- NEW rows: L-fixture-rot, L-rotted-constant-class, L-empty-test-body, L-secrets-in-fixtures, L-fake-fixture-from-wrong-test-build.

## Estimated effort

**~6-9h wall-clock** (Option D + α + ζ + III + K + M + P):

- Resolve Q-d (cast against block-explorer; pin truth): ~20 min.
- Update `d017_deploy_block` + 6 downstream + pinning test: ~30 min.
- Write `deployment_json_pins_match_rust_constants`: ~45 min (small serde_json dev-dep).
- Capture 4 fixtures via `cast` + `.meta.toml` boilerplate: ~1h.
- Write 4 hermetic replay tests: ~2-3h (hardest: `replay_d017_revision_no_plaintext_per_column` — may need `IndexerSession::test_inject_fixture` helper).
- Write `no_empty_ignored_tests`, `fixture_provenance`, `fixture_no_secrets` sweeps: ~45 min.
- Migrate 2 empty-body tests to RUNBOOK.md; remove from src: ~20 min.
- `scripts/run-live-tests.{sh,ps1}`; `.gitignore` update: ~30 min.
- Doc-blocks on residue `#[ignore]` tests (L6): ~30 min.
- THREAT_MODEL.md + DECISIONS.md + DEVLOG.md: ~30 min.
- Local `cargo test --workspace` + clippy clean + adversarial audit re-read: ~45 min.
