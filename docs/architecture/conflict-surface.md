<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Conflict surface (MVP-2 issue 5.3)

> **One-line scope:** the explicit conflict-detection + UI-surfacing
> plumbing that the existing 1.6 + P8 + P9 machinery has built up but
> never exposed at the host-facing layer. 5.3 ships the FFI binding
> for `list_conflicts`, a per-pull-tick conflict-diff signal in
> `PullReport`, and a thin `Vault::list_conflicts_since(prior)` diff
> accessor — all on top of unchanged ingest / freeze / canonical-head
> election code.

## What 5.3 ships

| Surface | Crate | Type |
|---|---|---|
| Enriched `ConflictReport` | `pangolin-store::conflict` | record (breaking change: `heads: Vec<RevisionId>` → `branches: Vec<ConflictBranchSummary>`) |
| `ConflictBranchSummary` | `pangolin-store::conflict` | NEW record |
| `ConflictSnapshot` | `pangolin-store::conflict` | NEW record |
| `ConflictDelta` | `pangolin-store::conflict` | NEW record |
| `Vault::snapshot_conflicts` | `pangolin-store::vault` | NEW accessor (`&self`) |
| `Vault::list_conflicts_since` | `pangolin-store::vault` | NEW accessor (`&self`) |
| `PullReport.newly_frozen_accounts` | `pangolin-store::pull` | extension field |
| `PullReport.newly_forked_accounts` | `pangolin-store::pull` | extension field |
| `PullReport.newly_resolved_accounts` | `pangolin-store::pull` | extension field |
| `vault_list_conflicts` | `pangolin-ffi::revision` | NEW UniFFI entry point |
| `FfiConflictReport` | `pangolin-ffi::revision` | NEW UniFFI record |
| `FfiConflictBranchSummary` | `pangolin-ffi::revision` | NEW UniFFI record |

## What 5.3 does NOT ship

- Schema changes (5.3 ships ZERO `format_version` bump; all needed
  columns already exist).
- Changes to `ingest_chain_revision` / `refuse_if_frozen` /
  `canonical_head` / `resolve_fork` / `clear_frozen`.
- Auto-resolve heuristics (Cardinal Principle 4 — "never silent
  merge"; deferred per R-f).
- New on-chain primitives or broadcasts (L11 — `vault_list_conflicts`
  is read-only).
- CLI subcommands (deferred to the CLI-V1 batch).

## Resolved decisions (Kelvin sign-off 2026-05-16)

R-a..R-g land verbatim from `docs/issue-plans/5.3.md`. The
load-bearing ones:

- **R-a** Auto-freeze trigger — UNCHANGED. The existing P8 CRIT-1
  freeze (any genuine-foreign-INSERT in `ingest_chain_revision`)
  is the spec. 5.3 surfaces it; 5.3 does NOT re-trigger.
- **R-b** Self-publish loopback — UNCHANGED. 5.1's
  `flush_publish_queue` stamps the anchor inline on the local
  revision row via `mark_published`; the next 5.2 pull-tick's
  `ingest_chain_revision` sees the round-trip event, matches it via
  idempotency arm #1 (exact-hash), returns
  `IngestOutcome::AlreadyPresent`, and does NOT fire the freeze.
  Defended by the mandatory regression test
  `pull_after_local_publish_does_not_self_freeze` in
  `crates/pangolin-store/src/pull.rs::tests`.
- **R-c** PullReport extension — directional set-difference. Pre-
  tick snapshot of `(frozen ∪ forked)`, post-tick snapshot, diff →
  `newly_*` fields. Already-frozen carry-overs do NOT re-surface;
  the set-difference is directional.
- **R-d** ConflictReport enrichment — breaking change to the
  `pangolin-store` public type. Replaces `heads: Vec<RevisionId>`
  with `branches: Vec<ConflictBranchSummary>` so host UIs get
  per-branch `device_id` / `observed_at_block` / `schema_version` /
  `is_tombstone` / `on_canonical_chain` in a single round-trip.
- **R-e** FFI binding — `vault_list_conflicts` ships in 5.3
  (master plan §5 row 5.3 verbatim).

## Per-cycle semantics

For every `Vault::pull_once(rpc_url, env, &vault_id)` invocation:

1. **L1 + R-e structural cancellation.** Inherited from 5.2.
2. **Pre-tick snapshot.** `snapshot_conflicts` computes the
   `(frozen, forked)` HashSet pair via the two existing accessors
   (`list_frozen_accounts` + `all_forked_accounts`). Two cheap
   O(N-conflicted) SQL reads.
3. **Picker + dispatch.** Inherited from 5.2 (R-c re-pick + L2 +
   L4 unchanged).
4. **Post-tick snapshot.** Same primitives as step 2.
5. **Set-difference diff.** `diff_conflict_snapshots(pre, post)`
   produces a `ConflictDelta`:
   - `added_frozen` = `frozen NOW − frozen BEFORE`
   - `removed_frozen` = `frozen BEFORE − frozen NOW` (= resolved)
   - `added_forked` = `forked NOW − forked BEFORE`
   - `removed_forked` = `forked BEFORE − forked NOW`
6. **Populate PullReport.** `newly_frozen_accounts = delta
   .added_frozen`, `newly_forked_accounts = delta.added_forked`,
   `newly_resolved_accounts = delta.removed_frozen`. The
   `removed_forked` channel is exposed via
   `Vault::list_conflicts_since` (the host's read-side accessor),
   not via `PullReport` directly — the 5.4 indicator state machine
   consumes both via the snapshot/diff API.
7. **Diagnostic stamp.** Inherited from 5.2.

## Relationship to P9 `resolve_fork`

P9 shipped `Vault::resolve_fork` (the merge-revision build) +
`Vault::clear_frozen` (the freeze-flag clear). 5.3 surfaces those
existing operations through the FFI binding but does NOT extend
them — there are no new `KeepLocal` / `KeepRemote` /
`KeepLatestTimestamp` resolve variants in 5.3 (deferred). The
host UI computes the user's choice, then calls the existing FFI
entry points (`account_resolve_fork` / `clear_frozen` — the
latter is reached via `account_resolve_fork` since 1.6 R-c
folded clear-on-resolve into the merge build).

## Canonical host scheduler reaction loop

```text
loop {
    let report = vault.pull_once(...).await?;
    if !report.newly_frozen_accounts.is_empty()
        || !report.newly_forked_accounts.is_empty()
    {
        host.notify_conflicts_appeared(
            report.newly_frozen_accounts,
            report.newly_forked_accounts,
        );
    }
    if !report.newly_resolved_accounts.is_empty() {
        host.notify_conflicts_resolved(
            report.newly_resolved_accounts,
        );
    }
    sleep(Vault::resolve_pull_interval_secs()).await;
}
```

The host's conflict-resolution screen calls `vault_list_conflicts`
once on screen entry (to render the current snapshot) and after
every notification (to refresh).

## Relationship to 5.4 indicator state machine

5.3 ships the data feed; 5.4 owns the state machine. The 5.4
"Synced / Syncing… / Offline / Conflicts pending" indicator
consumes:

- `Vault::last_pull_at_unix_ms()` — from 5.2 (the diagnostic
  stamp).
- `Vault::snapshot_conflicts()` — from 5.3 (R-c helper for the
  long-interval diff; complementary to the per-tick
  `PullReport.newly_*` fields).
- `Vault::list_conflicts_since(prior)` — from 5.3 (R-c helper for
  the long-interval diff).
- `vault_list_conflicts` FFI — from 5.3 (the rendering surface).

## L1..L11 invariants

| # | Invariant | How 5.3 preserves it |
|---|---|---|
| L1 | Resolution NEVER deletes a revision row | Inherited from 1.6 R-e + P9 §A4; 5.3 only reads. |
| L2 | `vault_list_conflicts` FFI binding bypasses NO freeze read guard | `list_conflicts` is `&self` + reads metadata only; does NOT call `get_account` / `reveal_password`; does NOT decrypt. |
| L3 | `refuse_if_frozen` UNCHANGED | 5.3 does not extend the refuse-set. |
| L4 | `canonical_head` election rule UNCHANGED | 5.3 reads the rule via `RevisionGraph::canonical_head`; it does not re-elect. |
| L5 | No schema change | All required columns (`frozen_pending_resolve`, `superseded_by`, `observed_at_block`, `chain_block_number`) already exist. |
| L6 | Accessors stay `&self` + locked-vault-safe | `list_conflicts` / `snapshot_conflicts` / `list_conflicts_since` are all `&self`; the FFI binding takes the existing read-side guard. |
| L7 | No new external crate dep | UniFFI already in `pangolin-ffi`'s `Cargo.toml`; no new direct deps in `pangolin-store`. |
| L8 | Dep direction `pangolin-store → pangolin-chain` preserved | 5.3 touches no chain code. |
| L9 | `forbid(unsafe_code)` on every new file | `conflict_live.rs` declares `#![forbid(unsafe_code)]`. |
| L10 | AGPL SPDX header on every NEW `.rs` file | `conflict_live.rs` carries the SPDX line. |
| L11 | ZERO on-chain broadcast in 5.3 | The FFI binding is read-only. Resolution merge revisions still flow through 5.1's publish queue on next flush; 5.3 itself never broadcasts. |

## Threat model touch-points

See `THREAT_MODEL.md` "Conflict surfacing (5.3)" row for the four
load-bearing L-section risks:

- **L-self-fork-on-publish** — defended by 5.1's inline
  `mark_published` + 5.2's idempotency arm #1; regression test
  `pull_after_local_publish_does_not_self_freeze`.
- **L-byte-flip-on-frozen-row-via-FFI** — no AEAD-open path is
  reached; per-row metadata is best-effort + advisory.
- **L-conflict-surface-leaks-frozen-payload** — every field on
  `ConflictBranchSummary` is metadata-class (already exposed via
  `FfiRevisionMeta`).
- **L-PullReport-delta-overcounts-on-existing-frozen** —
  set-difference is directional; pinned by
  `pull_tick_does_not_re_report_already_frozen_account`.

## File layout

- `crates/pangolin-store/src/conflict.rs` — `ConflictReport` (enriched),
  `ConflictBranchSummary`, `ConflictSnapshot`, `ConflictDelta`, hermetic
  tests.
- `crates/pangolin-store/src/vault.rs` —
  `list_conflicts` (enriched body), `snapshot_conflicts`,
  `list_conflicts_since`, `read_observed_at_block` helper,
  `diff_conflict_snapshots` free fn, `pull_once` extension.
- `crates/pangolin-store/src/pull.rs` — `PullReport` extension fields,
  hermetic tests for the per-tick diff signal.
- `crates/pangolin-store/src/lib.rs` — re-exports
  `ConflictBranchSummary` / `ConflictSnapshot` / `ConflictDelta`.
- `crates/pangolin-store/tests/conflict_live.rs` — live `#[ignore]`'d
  shape-only test (env-quirk #14 defense).
- `crates/pangolin-core/src/lib.rs` — re-exports the new conflict
  types so the FFI surface can name them under `pangolin_core::*`.
- `crates/pangolin-ffi/src/revision.rs` — `FfiConflictReport`,
  `FfiConflictBranchSummary`, `vault_list_conflicts` entry point.
- `crates/pangolin-ffi/src/lib.rs` — re-exports.

## Cross-references

- [`chain-sync.md`](chain-sync.md) — pull cycle + sync mode picker.
- [`pull-loop.md`](pull-loop.md) — host scheduler loop body +
  cancellation discipline.
- [`publish-queue.md`](publish-queue.md) — 5.1 `flush_publish_queue`
  + `mark_published` inline anchor stamp (R-b reliance).
- [`revision-lineage.md`](revision-lineage.md) — 1.6 canonical head
  election + `superseded_by` semantics.
