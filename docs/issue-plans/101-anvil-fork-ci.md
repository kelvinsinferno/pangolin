<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Issue #101 — anvil-fork CI harness (plan-gate DRAFT)

**Status: LOCKED — Kelvin sign-off 2026-05-20. Resolved decisions R-a..R-e in DECISIONS.md (Issue #101).**
**Base tip: `c4c51aa` (main; MVP-2 + pre-MVP-3 cleanup batch complete). MVP-3 foundation issue.**

## Why

MVP-3 (Social Recovery) adds a NEW on-chain contract (Recovery v1) — the project's highest-risk EPIC, audit-gated before mainnet. The Rust client builds calldata for its calls + decodes its events. That Rust↔contract seam is the env-quirk #14 class: the 3.3 `keccak256(encPayload)`-vs-preimage calldata bug passed the full hermetic suite (mocks fake receipts without running contract logic) and was caught only by adversarial audit. **#101 boots a local `anvil` node, deploys our real bytecode to it, and runs a curated subset of the `#[ignore]` live tests against it in CI** — so that bug class turns CI red automatically. Built before the Recovery contract, it de-risks every recovery-contract iteration.

## Headline finding — the Rust side is already anvil-ready

Every chain-touching guard is gated on `ChainEnv::BaseSepolia` and no-ops for `Dev` (verified): address-pin cross-check `matches!(env, ChainEnv::BaseSepolia)` (`chain_submit.rs:333,950`; `chain_sync.rs:453`); chain-id check reads `env.chain_id()` which is `None` for `Dev` (`deployments.rs:95`); `d017_deploy_block(Dev)==0` (scan fresh chain from genesis); `load_deployed_address(Dev,…)` reads `contracts/deployments/dev.json` and fails-closed if absent. So #101 is **CI plumbing + a generated `dev.json` + a thin test-parametrization seam**, not a chain-code rewrite. (`deploy-contracts.sh:406` explicitly skips dev-JSON writes — the harness needs its own ~30-line generator.)

## Scope

**Builds:** a gated `anvil-integration` CI job + a `scripts/anvil-ci.sh` wrapper that: starts anvil (poll-for-ready, never fixed sleep), deploys RevisionLogV1 + EntitlementRegistry via the existing forge scripts, parses the fresh addresses, generates `contracts/deployments/dev.json`, funds the deterministic test wallet via `cast rpc anvil_setBalance`, runs the in-scope tests at `ChainEnv::Dev` + the anvil RPC, and `trap`-teardowns anvil. Plus the test-parametrization seam + THREAT_MODEL/docs/DECISIONS/DEVLOG entries.

**In-scope tests (first cut — the calldata/event seam):** `publish_v1_live_d017_smoke` (`chain_submit.rs:2436` — the exact #14 surface), `live_pull_once_against_d017_advances_checkpoint` (`pull_live.rs:67`), `live_balance_query_against_d017_wallet` (`integration.rs:144`).

**NOT in scope (deferred):** the Recovery v1 contract itself (separate MVP-3 issue; #101 is its prerequisite harness); funder/top-up live tests (need the off-chain funder service in CI — own cycle); indexer parity / conflict / sync-status live tests (need self-generated seed events — fast-follow once harness is stable); forking Base Sepolia (we deploy fresh).

## Recommended architecture

Fresh-anvil + deploy-our-bytecode + generate `dev.json` + `anvil_setBalance`-fund the seed-derived test wallet + `ChainEnv::Dev`-target, as one gated Linux CI job using the pinned `foundry-toolchain@v1` (v1.0.0 — same anvil/forge/cast as the contracts jobs). Default `cargo test` + the existing CI jobs are untouched (the job is purely additive; `#[ignore]` tests still skip in the default path).

## L1..L9 invariants

- **L1** No production-code behavior change — test/CI-only + at most an additive test-parametrization env-read.
- **L2** BaseSepolia pins stay intact + enforced (`deployment_json_pins_match_rust_constants` green); anvil path uses the already-exempt `Dev`.
- **L3** Existing CI jobs untouched; the anvil job is additive.
- **L4** Foundry stays at the single pinned `v1.0.0` (env-quirk #4); bump in lockstep.
- **L5** Deterministic, no flake — poll for anvil readiness (never fixed sleep), `trap`-teardown always, fail-closed on deploy/parse failure.
- **L6** Fail-closed on Rust↔contract mismatch — in anvil mode the in-scope tests' skip-clean `return` branch becomes a HARD error (a missing `dev.json` / unset env turns CI red, not skip). The 3.3 bug "passed" precisely because the live test was skipped.
- **L7** No new `=`-pinned external Rust dep without `cargo deny check advisories` + `cargo audit` (env-quirk #15). Likely zero (anvil/cast are binaries).
- **L8** `forbid(unsafe_code)` + AGPL SPDX on new `.rs`/scripts.
- **L9** §16 ledger discipline; `git merge --no-ff`. The adversarial audit MUST verify the harness would actually have caught the 3.3 preimage bug (confirm the publish test runs the real contract hash path). Mind env-quirk #12 (`grep -c`/pipefail) + #16 (pwsh line-length) in new CI shell.

## Open decisions for Kelvin (Q-a..Q-e)

Recorded in the conversation / DECISIONS.md LOCKED entry. Summary (each with a recommendation):
- **Q-a** scope of lit-up tests: **A** (3 contract-execution tests only) vs B (+ indexer/conflict via self-seeded events).
- **Q-b** test targeting: **I** (minimally parametrize existing `#[ignore]` tests to read ChainEnv+RPC from env; skip→hard-error in dev mode per L6) vs II (fresh anvil-only tests).
- **Q-c** cadence: **every PR** vs label/schedule.
- **Q-d** chain: **fresh anvil deploy** vs fork Base Sepolia.
- **Q-e** dev.json: **generate at CI runtime** vs commit a fixture.

## Effort + delta

~6-9h. +0 new test fns under Q-b Option I (3 existing `#[ignore]` tests become CI-exercised); one new ~3-6 min Linux job, parallel to existing jobs.

## Open follow-ups #101 defers

Recovery v1's own anvil tests (land with the contract — slot into this harness); funder-service-in-CI for top-up tests; indexer/conflict/sync tests against anvil (Q-a Option B); time-warp testing (`evm_increaseTime`/`evm_mine`) for Recovery's finalize-after-delay (flag for the Recovery cycle); multi-OS anvil (Linux-only first cut).
