<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Issue #107 — fix V1 read-topic bug (`.topic1` → `.topic2` for vaultId) + filter-respecting hermetic test infra — plan-gate LOCKED

**Status: LOCKED — Kelvin sign-off 2026-05-22 (§0a).** A standalone bug fix dormant since the V1 chain-read path was written. Independent of the #106 multi-device epic.

## 0a. RESOLVED decisions (Kelvin sign-off 2026-05-22)

- **Q-a → SMARTER MOCK + HERMETIC TESTS** (the durable choice). Build a project-local filter-respecting Asserter-equivalent that parses an `eth_getLogs` request's `Filter.topics` array (topic0..3 wildcards/values) and applies it to the queued logs server-side. Similarly for `eth_subscribe("logs", filter)`: filter live-pushed logs against the subscription's filter before emitting. Then a hermetic regression test against the smarter mock catches THIS bug AND any future similar V1/V2/V0 filter mistake. Slot it next to / replacing the dumb `Asserter` usage in `crates/pangolin-chain/src/chain_sync/tests.rs`. (Alternative — anvil-only E2E — rejected as a narrower regression that wouldn't catch future similar bugs at compile/PR time.)
- **Q-b → BOTH HTTP + WS regression tests.** Same bug exists in `fetch_chunk` (HTTP `eth_getLogs`) and `open_subscription` (WS `eth_subscribe`). Cover both paths with hermetic tests against the smarter mock (the existing harness already exercises both; mirror the shape).
- **Q-c → Ship soon after #106e-2 merges.** V1 is the production default for legacy vaults; this is HIGH-impact, LOW-complexity.
- **Scope:** (1) the 2-line fix at `poll.rs:~196` + `ws.rs:~240` (`.topic1(vault_id)` → `.topic2(vault_id)`, rename local `topic1` → `vault_topic`); (2) the smarter filter-respecting mock (a `FilteringAsserter` or equivalent project-local helper) covering BOTH `eth_getLogs` and the `eth_subscribe("logs", filter)` push path; (3) hermetic regression tests against the smarter mock — both an HTTP `fetch_chunk` test and a WS `open_subscription` test that ASSERT a topic-mismatch returns zero logs (these are the bug's signature on a real RPC); (4) stale-comment cleanups (any "topic1 = vaultId" V1 references corrected).
- **L-invariants:** no semantic change beyond the topic correction; V0 untouched (V0's `.topic1(vault_id)` is correct — V0's event puts `vaultId` at topic1); V2 untouched (already correct); no new external crates; AGPL SPDX; the smarter mock lives ONLY behind `#[cfg(test)]` (no production surface change); the regression test must be DISCRIMINATING — proven by running it against the PRE-fix code and confirming it goes RED. Full gate: `cargo fmt --check` + `cargo clippy -D warnings` + `cargo test --workspace` (incl. the workspace `no_empty_ignored_tests` meta-test). The existing anvil harness E2Es continue to pass unchanged.

## 0. One-paragraph summary

The `RevisionLogV1.RevisionPublished` event puts `sequence` at **topic1** and `vaultId` at **topic2** (`contracts/src/RevisionLogV1.sol:72-81`). The V1 chain-read path filters by **`.topic1(vault_id)`** at two sites: `crates/pangolin-chain/src/chain_sync/poll.rs:196` (HTTP `eth_getLogs` for chunked reads) and `crates/pangolin-chain/src/chain_sync/ws.rs:240` (WS `eth_subscribe("logs")`). On a real RPC this filter resolves to `sequence == vault_id` — almost always false — so V1 reads return **zero logs**, breaking sync for any vault using V1. The bug is dormant because (a) the hermetic `chain_sync/tests.rs` uses an alloy `Asserter` mock that returns pre-queued logs WITHOUT inspecting filter topics, and (b) the only live V1 read test (`publish_v1_live_d017_smoke`, chain_submit.rs:2479) is `#[ignore]`-marked and only exercises *publishing*, not *reading*. The V2 path is already correct (`v2.rs:182` and `v2.rs:290` use `.topic2(vault_id)`) — the bug fix mirrors V2 verbatim. **Severity HIGH**: V1 is still the production default; vaults default to V1 until #106c2's V2-on-mainnet cut-over (gated behind D-011). Fix is a 2-line change + a non-ignored regression test.

## 1. Scope

**#107 builds:**
1. **The fix.** Change `.topic1(topic1)` → `.topic2(topic1)` at exactly two sites:
   - `crates/pangolin-chain/src/chain_sync/poll.rs:196` (inside `fetch_chunk`).
   - `crates/pangolin-chain/src/chain_sync/ws.rs:240` (inside `open_subscription`).
   Rename the local `topic1` variable to `vault_topic` to match V2's naming + remove the misleading name.
2. **The regression test.** A test that catches this bug AGAINST A REAL RPC (the mock Asserter can't — it ignores filters). See §5 Q-a for the recommendation.
3. **Inline comments correcting any stale references.** A few comments in `poll.rs` / `ws.rs` (and possibly a contract docstring) say "topic1 = vaultId" — correct them to "topic1 = sequence, topic2 = vaultId" to prevent future re-introduction.

**Explicitly NOT this slice:**
- Any change to V0 (`base_sepolia.rs:516`) — V0's event layout puts `vaultId` at topic1, so V0's `.topic1(vault_id)` is **correct**. Confirm by inspection during the build; do not touch.
- Any change to V2 — already correct.
- Any change to the alloy `Asserter` mock infrastructure (a separate test-helper improvement, see §5 Q-a).

## 2. Splittable? — no

Two surgical line changes + one regression test. ONE tight slice. **Recommend: one #107 PR, builder → focused audit (just the byte-identity of the topic change + that the regression test actually catches the bug) → merge.**

## 3. The fix + test (designed; decisions in §5)

### 3.1 The 2-line fix
**poll.rs (the V1 HTTP read):**
```rust
// BEFORE (line ~196)
let topic1: B256 = (*vault_id).into();
let filter = Filter::new()
    .address(contract_address)
    .event_signature(RevisionLogV1::RevisionPublished::SIGNATURE_HASH)
    .from_block(BlockNumberOrTag::Number(from_block))
    .to_block(BlockNumberOrTag::Number(to_block))
    .topic1(topic1);  // BUG: topic1 is `sequence`, not `vaultId`

// AFTER
let vault_topic: B256 = (*vault_id).into();
let filter = Filter::new()
    .address(contract_address)
    .event_signature(RevisionLogV1::RevisionPublished::SIGNATURE_HASH)
    .from_block(BlockNumberOrTag::Number(from_block))
    .to_block(BlockNumberOrTag::Number(to_block))
    .topic2(vault_topic);  // CORRECT: V1's vaultId is the 2nd indexed param
```

**ws.rs (the V1 WS subscription):** identical shape change — `.topic1(topic1)` → `.topic2(vault_topic)`.

Both fixes mirror `crates/pangolin-chain/src/chain_sync/v2.rs:182` / `v2.rs:290` (the V2 path, already correct).

### 3.2 The regression test (Q-a — the real decision)
The bug is dormant because the mock Asserter ignores filter topics. A test that catches the bug needs EITHER:
- **(a) An anvil-gated coupled E2E** — publish a V1 `RevisionPublished` event on local anvil, then call `fetch_chunk` (and `open_subscription`) against that anvil node, assert the events come back. Add to `scripts/anvil-ci.sh`'s `do_run`. Non-`#[ignore]`'d under the `integration-tests` feature; the anvil-ci CI job exercises it.
- **(b) A smarter mock Asserter** — write a project-local `FilteringAsserter` that intercepts `eth_getLogs` requests, applies the filter's `topics` array to the queued logs, returns only the matching ones. Add a hermetic test against the new mock that asserts ONLY the matching-vault_id logs come back. **Caveat:** non-trivial test-helper work + requires careful semantics matching for the topic-filter rules.
- **(c) Both** — (a) for the immediate regression gate; (b) as a follow-up so the existing hermetic test suite catches any future similar bug pre-merge.

Recommend (a) for #107 directly; (b) as a separate follow-up issue.

### 3.3 Comment cleanups
- `ws.rs` line ~234: "indexed vault_id topic1" → "indexed vaultId topic2".
- `poll.rs`: similar nearby comment, if present.
- Confirm `chain_submit.rs` / `chain_sync.rs` orchestrator doesn't carry the same stale comment.

## 4. L-invariants
- **L1 (correctness on a real RPC).** After the fix, a V1 vault syncing against the deployed `RevisionLogV1` contract on Base Sepolia (or anvil) returns its own revisions — not zero. The regression test pins this.
- **L2 (no semantic change beyond the topic).** The fix only changes which on-chain event-topic the filter binds against. The decoded event verification (`verify_alloy_log_v1`), the sequence/vault_id/account_id extraction, the cursor advancement, the dedup logic — all unchanged.
- **L3 (V0 untouched; V2 untouched).** V0's `.topic1(vault_id)` is correct (V0's event puts `vaultId` at topic1); V2 already uses `.topic2`. Audit confirms only the two V1 sites change.
- **L4 (no new deps; no `unsafe`; AGPL).** A pure line-fix. uniffi/store/crypto untouched.
- **L5 (full gate + the new anvil regression).** `cargo fmt --check` + `cargo clippy -D warnings` + `cargo test --workspace` (incl. the workspace `no_empty_ignored_tests` meta-test) + `scripts/anvil-ci.sh all` (running the new V1-read regression alongside the existing V1-publish + V2 + multi-device E2Es).
- **L6 (§16 ledger).** `git merge --no-ff`; DECISIONS / DEVLOG entry; Kelvin merge sign-off; focused #104a-style audit (small scope: byte-identity of the topic correction + that the new test actually goes RED under the old code).

## 5. Open decisions for Kelvin (Q-a, Q-b, Q-c)

- **Q-a — regression test approach.** **Recommend: anvil E2E only** (the (a) path from §3.2). One new test in the existing anvil harness: publish a V1 revision → `fetch_chunk` against anvil → assert the event comes back. Easy, immediate, catches the bug. The smarter-mock improvement (b) is a real coverage gain but a bigger change to test infrastructure — defer as a separate follow-up. *Plain English:* add a test that runs a real local blockchain, publishes a V1 event, and verifies the read path returns it. Don't rebuild the mock test framework right now. **Stakes: LOW-MEDIUM.**
- **Q-b — also test the WS subscription path?** **Recommend: yes if cheap, no if it doubles the test scope.** The bug exists in `ws.rs` identically; the anvil harness already supports WS (it sets `prefer_websocket: false` for HTTP, can flip to `true`). Add a `wsEnabled=true` variant of the same regression test, OR just fix WS and rely on V2's existing WS test pattern. *Plain English:* the bug is in two places; should we add two regression tests or just one and trust both fixes shipped together? **Stakes: LOW.**
- **Q-c — release urgency.** V1 is the production default for legacy vaults; any vault using V1 against a live chain RPC currently can't read its own revisions. **Recommend: ship this immediately after #106e-2 merges** — the fix is 2 lines + a test, low risk, high impact. *Plain English:* this bug breaks sync for real vaults; we should fix it soon. **Stakes: HIGH (impact); LOW (fix complexity).**

## 6. Places that need care
- **The local variable rename** (`topic1` → `vault_topic`) is purely cosmetic but prevents re-introduction.
- **The anvil regression must FAIL on the OLD code.** During the audit, run the new test against the pre-fix code (revert the topic change locally) and confirm it goes RED — this is the discrimination proof that the test actually catches the bug. Without this proof, the test is decorative.
- **V0 must remain untouched.** A naïve "fix all `.topic1(vault_id)` calls" sweep would break V0. The fix is V1-specific.
- **Stale comments** are the breeding ground for a future re-introduction. Correct them in the same commit.
