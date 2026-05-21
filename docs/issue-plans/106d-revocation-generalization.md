<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Issue #106d — REVOCATION GENERALIZATION + the v1→v2 honor-gate cut-over — plan-gate LOCKED

**Status: LOCKED — Kelvin sign-off 2026-05-21 (see §0a). Q-a..Q-f + GAP §6 resolved; ONE stage.** Fourth slice of the multi-device epic #106 (after #106a contract + #106b crypto/rotation + #106c client device-add flow, all merged). Folds in the PARKED #103-C revocation-on-read. Mirrors the §16 plan-gate format of `103c-revocation-on-read.md` / `106c-device-add-flow.md`.

## 0a. RESOLVED decisions (Kelvin sign-off 2026-05-21)

- **Q-a → V2 revocation rule = honor iff signer ∈ the LIVE on-chain `authorizedDevice` set; FAIL-CLOSED on a set-read error.** A genuine "no V2 set / V1 vault" → permissive V1 path (`Ok`); a real RPC/network/chain-id failure → `Err` that fails the whole sync (NEVER swallowed to honor-all — the #103-C CRITICAL `Ok-empty-vs-Err` lesson). Wire the #106c `is_signer_honored`/`ingest_v2_revision_if_honored` into BOTH arms of `sync_from_chain_with_ws_url` (they exist but aren't wired yet) + add retroactive re-eval.
- **Retroactive re-eval (salvaged from #103-C fix-pass):** re-check stored chain-anchored rows against the current set each sync; MARK-revoked (not delete) out-of-set rows; recompute both directions (re-add un-revokes); FILTER `revoked=1` from head/history/content reads. The `revisions.revoked` column + `migrate_revision_revoked_column` + the read-filters port VERBATIM; the predicate swaps `lineage.is_honoured`→`current_set.contains`.
- **Q-b → set source = event-fold (`decode_device_mgmt_events`) + the LIVE `authorizedDevice` read as authoritative tiebreaker** (matches #106c reads + the #103-C live-read anti-staleness posture).
- **Q-c → route by the vault's FIXED recorded revision-log contract binding** (V2 → set-gate; V1 → permissive, untouched), NOT a chain heuristic. **GAP §6 sub-decision:** the sync loop currently reads RevisionLog**V1** `RevisionPublished`; for a V2 vault the revision-event read MUST point at **RevisionLogV2** (different contract + v2 domain) — #106d wires the V2 event read alongside the V2 honor gate.
- **Q-d → CLOSE/abandon the parked branch `worktree-agent-a3f6272eca2f476be`; salvage ONLY its store plumbing** (revoked column/migration/read-filters/fail-closed taxonomy + tests + anvil-gate shape). DISCARD `revocation.rs` (`AuthorityLineage`/`read_authority_lineage_v1`/`RecoveryFinalized`-fold) — superseded by the live on-chain set. Record the branch closure in DECISIONS.md (don't merge-then-rip-out the lineage).
- **Q-e → STAY-PERMISSIVE for V1 (Kelvin).** A recovered V1 (single-device, RevisionLogV1) vault's old device stays trusted on its V1 log — accepted: a single-device V1 on-chain log is "pointless" per the multi-device pivot, new vaults are V2, push users to V2 rather than carry the discarded lineage machinery for a legacy edge (testnet-only). The #103-C lineage gate is NOT salvaged for V1.
- **Q-f → ONE #106d stage** (optionally 2 PRs on one branch).
- **No contract change** (RevisionLogV2 #106a already has the set + removeDevice + events; `currentManager` already cross-binds RecoveryV1.vaultAuthority). Read-side only. **Anvil gate:** bootstrap A → addDevice(B) → both honored → removeDevice(B) → B's new + retroactively-stored entries revoked-on-read, A honored → re-add B → honored. Negatives (honor-all predicate / fail-OPEN on read error / marks-but-reads-don't-filter) flip it RED. Full `cargo test --workspace` gate (the #106b-1 lesson).

This slice is **TESTNET-ONLY (Base Sepolia) until the D-011 external audit clears** — the revocation RULE is load-bearing and is inside the D-011 audit package (it gates which on-chain revisions every reader honors, the property the audit signs off on).

**Base: current main `b141668`** (#106c merged: `RevisionLogV2.sol` #106a `6e5bf74`; `pangolin-crypto::pairing` #106b-1; `pangolin-core::rotation` + `Vault::commit_vdk_rotation` #106b-2 `9f67221`; the #106c `multi_device.rs` minimal gate + `revisionlog_v2_client.rs` live SET reads + the `DeviceRemoved`→rotation trigger). RevisionLogV1 deployed/immutable (D-017); RevisionLogV2 deployed by `scripts/anvil-ci.sh`. **The PARKED #103-C production code lives on branch `worktree-agent-a3f6272eca2f476be` (NOT merged) — #106d salvages its store plumbing + supersedes its lineage inference; see §3.4 + Q-d.**

---

## 0a. The crux (locked in `106-multi-device.md` §0a) — read FIRST

The #106 architecture lock (Kelvin 2026-05-21) resolved device removal onto an **on-chain authorized SET** (`RevisionLogV2`'s `authorizedDevice` mapping + `addDevice`/`removeDevice`, both manager-gated). The load-bearing consequence, quoted verbatim from §0a:

> Honor rule becomes trivial: a revision is honored iff its signer is in the CURRENT on-chain set. This **largely dissolves #103-C's lineage-inference/retroactive-re-eval machinery** — the set itself is the live source of truth; #103-C's fold-in becomes "read the current set" instead of inferring from authority rotation.

**This is the entire shape of #106d.** #103-C had to *infer* "who is trusted now" from the authority-rotation lineage (`RecoveryFinalized` events folded into an ordered `[A_genesis … A_current]` lineage) because RevisionLogV1 had no on-chain set. RevisionLogV2 **publishes the trusted set directly**. So #106d keys revocation on the **LIVE on-chain authorized set** (read like #106c via `read_authorized_device_v2` / folding the device-management events), NOT on the #103-C `RecoveryFinalized`-lineage inference. The lineage machinery is **superseded**; the store plumbing (the `revoked` column + retroactive re-eval + read-filters + fail-closed discipline + anvil-gate shape) **carries over**, re-keyed from "former-authority lineage" to "current on-chain set membership."

---

## 0. One-paragraph summary

#106c shipped a **minimal** V2 honor gate as standalone helpers — `multi_device::is_signer_honored(signer, &current_set)` + `Vault::ingest_v2_revision_if_honored(...)` (honor iff signer ∈ a caller-supplied current on-chain set) — and deliberately LEFT the live `sync_from_chain_with_ws_url` loop on V1's permissive `auto_register_device_from_chain_sync` ("trust any signer seen", GAP FLAG D). The minimal gate is *available* but **not wired into the sync loop**; the cut-over was deferred here. #106d does the FULL revocation generalization, in three parts: **(1)** the comprehensive V2 honor rule — read the live on-chain authorized SET each sync; honor iff signer ∈ it; **FAIL-CLOSED on a set-read error** (never honor-all on a failed read — the #103-C CRITICAL `Ok-empty-vs-Err` lesson); **(2)** retroactive re-evaluation — re-check ALREADY-STORED rows against the current set each sync, MARK-revoked the ones whose signer left the set, and FILTER revoked rows out of the head / history / content reads (salvaging the #103-C `revoked` column + the additive migration + the read-query `revoked = 0` filters); **(3)** the v1→v2 cut-over routing — decide, per vault, which honor rule applies (V1 permissive-self-bootstrap path vs V2 set-membership gate), given new-vaults-only-on-V2 (V1 vaults stay deployed/immutable, single-device, permissive). It introduces **NO new contract** (RevisionLogV2 already provides the set + `removeDevice` + the events — confirmed) and **NO new external dep** (alloy + the merged #106c client provide everything).

---

## 1. Scope

**#106d builds (Rust read-side only):**

1. **The comprehensive V2 honor gate wired into the sync loop.** Replace the permissive `auto_register_device_from_chain_sync` (4.1 R-d) on the V2 path with "honor iff signer ∈ the LIVE on-chain authorized set", read once per sync via the #106c `revisionlog_v2_client` (`read_authorized_device_v2` per-signer, OR fold the device-management events into a SET snapshot via `decode_device_mgmt_events` — recommend the folded snapshot + a live cross-check, see §4). Sits ON TOP of 4.1's unchanged signature verification (an additive gate, byte-identical up to the membership check). Both arms of `sync_from_chain_with_ws_url` (HTTP backfill + WS tip-follow) gate identically.
2. **FAIL-CLOSED on a set-read error (the #103-C CRITICAL lesson).** A set-read that *genuinely* returns "no V2 set / this is a V1 vault" is distinct from a set-read that *failed* (RPC/network/chain-id error). The former routes to the V1 permissive path (correct); the latter is propagated as `Err` and **fails the whole sync** — it MUST NOT be swallowed to "honor all", which would re-honor a removed device on a rotated vault (under-revocation — the exact hole). This mirrors `read_authority_lineage_v1`'s resolved `Ok(empty())`-only-for-no-deployment-vs-`Err`-for-any-real-failure discipline.
3. **Retroactive re-evaluation + the `revoked` column.** Re-check stored V2 chain-anchored rows against the current set each sync; MARK (not delete, L6) `revoked = 1` for any row whose signer is no longer in the set; recompute both directions (un-revoke if a signer re-enters the set). FILTER `revoked = 1` rows out of the head set, the history walk, and the content/graph reads. Salvage the #103-C store plumbing (the `revoked` column + `migrate_revision_revoked_column` + the `revoked = 0` read-query filters) — they are V2-agnostic store plumbing (§3.4).
4. **The v1→v2 cut-over routing.** A per-vault decision of which honor rule applies: V1 (permissive self-bootstrap, single-device, RevisionLogV1) vs V2 (set-membership gate, RevisionLogV2). Recommend routing by which revision-log contract the vault is bound to (Q-c), surfaced through the same fail-closed read taxonomy in (2).
5. **`SyncReport.revisions_revoked`** — an additive counter (the new-event-gate rejections + the retroactive newly-revoked rows; disjoint, so the sum is an honest "what this sync cut").
6. **The anvil regression gate** (centerpiece): remove a device → its NEW publishes AND its retroactively-stored entries both revoked-on-read; re-add → honored again; a broken predicate ("honor all signers") OR a fail-OPEN-on-read-error turns the gate RED.

**Deferred / out of scope (this slice):**

- **Any contract change** — RevisionLogV2 already has the set + `removeDevice` + `DeviceAdded`/`DeviceRemoved`/`PromotionFinalized` events (#106a). #106d is Rust read-policy only (confirmed §6).
- **Migration of existing RevisionLogV1 vaults to V2** — `106-multi-device.md` Q-g: new-vaults-only on V2; V1 vaults stay single-device/immutable. A per-vault "opt into V2 re-home" is a flagged follow-up.
- **The VDK-rotation crypto on revoke** — that is #106b-2 (merged) + the #106c `DeviceRemoved`→rotation trigger (merged). #106d is purely about which on-chain entries the reader HONORS, not about re-keying the VDK.
- **6.x UX** — surfacing "N revisions revoked" / "a device was removed" to the host UI.
- **Mainnet** — testnet-only until D-011.

---

## 2. Splittable? — recommendation: ONE #106d stage

#106d is one cohesive read-policy change: the live-set honor gate, the retroactive re-eval, and the v1→v2 routing are mutually dependent and only meaningfully tested together by the anvil remove-then-read gate (which needs the new-event gate AND the retroactive pass AND the V1-untouched assertion present simultaneously). The store plumbing (the `revoked` column + read-filters) is a salvage, not a separable feature — it has no value without the gate that writes it. Splitting would leave a half-wired intermediate with no meaningful test boundary (the same reasoning that kept #106c one stage). **Recommend ONE #106d stage.** (Optionally two reviewable PRs on one branch: PR1 = salvage the #103-C store plumbing re-keyed to set-membership + the retroactive re-eval + read-filters with hermetic tests; PR2 = wire the live-set gate into both `sync_from_chain` arms + the v1→v2 routing + the coupled anvil remove-then-read E2E.) Surfaced as Q-f.

---

## 3. The design (decisions surfaced in §5)

### 3.1 The V2 revocation rule (the load-bearing rule)

> **Plain English:** "Only honor a chain revision if the device that signed it is in the set of devices your vault currently trusts on-chain. The chain itself publishes that set (RevisionLogV2's authorized-device set); read it live each sync. If you can't read the set, refuse to sync — never fall back to trusting everyone."

Rule: ingest a verified `RevisionPublished` event **iff** its recovered signer ∈ the vault's **current on-chain `authorizedDevice` set** (the #106a honor rule, generalized from #106c's minimal helper to the live sync loop). Concretely:

- **Read the live set once per sync.** Fold the device-management events (`VaultBootstrapped`/`DeviceAdded`/`DeviceRemoved`/`PromotionFinalized`) via the merged `revisionlog_v2_client::decode_device_mgmt_events` into a current SET snapshot, reconciled against the live per-signer `read_authorized_device_v2` reads (the live read is the authoritative tiebreaker — the #103-C L5 anti-stale anchor, re-keyed: the cheap event-fold supplies the SET, the live read is the final word on membership). (Q-b chooses fold-vs-per-signer-read; recommend fold + live cross-check.)
- A revision signed by an **in-set** signer is honored. A revision signed by a signer **not in the set** (removed device, never-added device, a former manager whose set membership was removed) is **revoked**.
- **The "no V2 set" case is NOT "honor all" — it routes to V1.** A vault genuinely on RevisionLogV1 has no V2 set; it takes the V1 permissive path (§3.3). A vault on RevisionLogV2 always has a set (`bootstrapVault` seeds it). The two are distinguished by the per-vault contract binding (Q-c), NOT by an empty set-read.

**Where the gate sits.** In `Vault::sync_from_chain_with_ws_url`, ON TOP of the unchanged 4.1 signature verification, in BOTH arms (HTTP backfill loop + WS tip-follow loop) — exactly where the parked #103-C added its `lineage.is_honoured(ev.signer)` check, but with `current_set.contains(&ev.signer)` as the predicate. The #106c `Vault::ingest_v2_revision_if_honored` helper already encapsulates the per-event check; #106d wires it into the loop + adds the retroactive pass + the routing.

### 3.2 Retroactive re-eval + the `revoked` column (the #103-C fix-pass mechanism, re-keyed)

The reader may already hold rows signed by a signer that has since left the set (ingested by 4.1 / #106c before the removal was observed, or in an earlier sync). The new-event gate only filters *incoming* events; the retroactive pass closes the historical hole — IDENTICAL in shape to #103-C GAP FLAG 3, with the predicate swapped:

- Each sync, after the live set is read, re-evaluate every chain-anchored row (`chain_tx_hash IS NOT NULL`): recover its signer from the row's `device_id` (the 32-byte left-padded EVM address, the same shape D-017 / the v2 publish emits), and set `revoked = i64::from(!current_set.contains(&signer))`. This is the parked branch's `reevaluate_revocation_against_lineage` with `lineage.is_honoured(signer)` replaced by `current_set.contains(&signer)` — **the function body is otherwise reused verbatim** (the loop, the device_id→address decode, the both-directions recompute, the idempotency, the malformed-length skip).
- MARK, do not hard-delete (L6) — the user can audit what was cut; a re-add un-revokes the row (recomputed both directions).
- FILTER `revoked = 1` out of the materialized honored state: the head-set query (outer `r.revoked = 0` + the child-existence subquery `r2.revoked = 0` so a revoked child doesn't mask an honored parent), the `revisions_for` history walk, and the `revision_graph` / content reads. **These read-query filters are salvaged verbatim from the #103-C branch** (they are pure store plumbing, V2-agnostic — they filter on the `revoked` column regardless of how it was set).

### 3.3 The v1→v2 cut-over routing (the cut-over)

The reader must decide, per vault, V1-permissive vs V2-set-gate. The clean separation:

- **V1 vaults stay permissive — and that is correct, not a gap.** A V1 vault is single-device by construction: RevisionLogV1 self-bootstraps exactly the first publisher (`registeredDeviceCount == 0` → register; else reject) and has NO `addDevice` and NO `removeDevice`. **A V1 vault can NEVER have a device removed** (no removal path, no second device). So there is nothing for a revocation rule to revoke — the permissive `auto_register_device_from_chain_sync` is the *right* behavior for V1 (it only ever sees the one bootstrapped signer). The V1 path is left UNTOUCHED (L-V1-untouched). (Note: a V1 vault that underwent a RecoveryV1 *authority rotation* is the original #103-C single-device case; under new-vaults-only-on-V2, such vaults are pre-existing and the project's stance is they stay V1/single-device — see Q-d/Q-e on whether the #103-C lineage gate is salvaged for THAT narrow case or dropped.)
- **V2 vaults take the set-membership gate** (§3.1).
- **Routing recommendation (Q-c): route by which revision-log contract the vault is bound to.** A vault created on V2 records (in `.pvf` local state, set at create/bootstrap time) that it is a V2 vault; its sync reads the V2 contract + applies the set gate. A V1 vault reads the V1 contract + the permissive path. This is the cleanest signal (it is a fixed property of the vault, not an inferred-from-chain heuristic) and it makes the fail-closed taxonomy crisp: a V2 vault that cannot read its set FAILS the sync (never silently downgrades to permissive); a V1 vault never attempts a set read. (Alternatives: a per-vault flag derived at first sync, or "presence of an on-chain set" — rejected because an absent set is ambiguous with a read failure, the exact #103-C `Ok-empty-vs-Err` trap.)

### 3.4 What carries from #103-C vs what is superseded (be specific)

**SUPERSEDED by the live on-chain set (DISCARD — the lineage inference):**
- `crates/pangolin-chain/src/revocation.rs` in its entirety: `AuthorityLineage`, `AuthorityRotation`, `from_events`/`from_genesis_and_rotations`, `with_live_current` (the stale-ahead truncation / unseen-append reconciliation), `is_honoured`, `is_former_authority`. The V2 set IS the live truth — there is no lineage to fold and no "former authority set" to infer.
- `recovery_client.rs::read_authority_lineage_v1` + `LINEAGE_LOG_BLOCK_CHUNK` + `recovery_v1_deploy_block` (the `RecoveryFinalized`/`GuardianSetInitialized` event scan + fold). #106d reads the V2 device-management events instead (already built in `revisionlog_v2_client::decode_device_mgmt_events`).

**CARRIES OVER (SALVAGE from the #103-C branch — the store plumbing + discipline):**
- The `revisions.revoked` column (additive `INTEGER NOT NULL DEFAULT 0`) + `migrate_revision_revoked_column` (the idempotent legacy-vault ALTER, no `format_version` bump) — V2-agnostic.
- The retroactive re-eval pass `reevaluate_revocation_against_lineage` — salvaged with the predicate swapped from `lineage.is_honoured(signer)` to `current_set.contains(&signer)` (rename to e.g. `reevaluate_revocation_against_set`); the device_id→address decode, both-directions recompute, idempotency, and malformed-skip are reused verbatim.
- The head/history/content read-query `revoked = 0` filters (the #103-C "FINDING 2" fix that made the column actually exclude rows from materialized state) — pure store plumbing, reused verbatim.
- The **FAIL-CLOSED-on-read-error discipline** (the #103-C "FINDING 1" CRITICAL fix): the `Ok(no-surface)`-vs-`Err(real-failure)` distinction. #106d re-keys it: `Ok` only for the genuine V1-vault / no-V2-set case (routes to permissive), `Err` for any real RPC/network/chain-id/`eth_getLogs`/view failure (fails the sync). The two regression tests that pin this (no-surface ⇒ `Ok`; RPC-failure ⇒ `Err`, never swallowed) are salvaged in shape.
- `SyncReport.revisions_revoked` (additive field) + the both-arms gate placement in `sync_from_chain_with_ws_url`.
- The anvil rotate/remove-then-read regression-gate SHAPE (the centerpiece + the negative arm).

**Recommendation on the parked branch (Q-d): formally CLOSE/abandon `worktree-agent-a3f6272eca2f476be`, salvaging only the store plumbing.** Do NOT merge it as-is and then generalize (that would land + then immediately rip out the lineage machinery — churn + a dead `revocation.rs` to delete). Instead, lift the store-plumbing diffs (schema + the read-filters + the retroactive pass + the fail-closed taxonomy + the anvil-gate shape) directly into #106d, re-keyed to the set. Record the closure in DECISIONS.md.

### 3.5 Multi-rotation / removed-then-re-added (the live-set rule handles these for free)

The #103-C scorched-earth framing (revoke ALL of a former authority's entries, including pre-rotation history; honor only `A_current`) was an *inference* artifact — it had to reason about lineage because there was no set. The live-set rule subsumes all of it for free, because **only current-set membership matters**:

- **Multiple removals/rotations:** honor iff in the *current* set; every signer ever removed and not re-added is revoked, regardless of order or how many times the set changed. (Equivalent to #103-C Q-d "honor only A_current".)
- **Removed-then-re-added:** if a signer is removed and later `addDevice`'d back, it is in the current set → honored again (its rows un-revoke on the next retroactive pass). The live set is the single source of truth; no special case. (#103-C Q-c "re-adds automatic via the signer-set rule" — now literally the on-chain set.)
- **Scorched-earth on a removed device's history:** under the set rule, a removed device's PAST rows are revoked too (its signer is no longer in the set, and the retroactive pass marks every chain-anchored row by current membership) — matching #103-C Q-b scorched-earth, but as a *consequence* of set-membership, not a separate decision. (Note: the user's vault DATA is unaffected — it is recovered byte-identical via the VDK; revocation only drops the removed device's on-chain revision/audit history. Same framing as #103-C Q-b.)

---

## 4. L1..Ln invariants (proposed — mirror 103c/106c style)

- **L1 (additive read-policy; v1/v2 contracts + #106b crypto untouched; new files / additive gate only).** #106d ADDS the live-set gate + the retroactive pass + the read-filters; it does NOT change signature verification (4.1 L5), the `sol!` bindings, the EIP-712/merkle paths, the ingest idempotency, or the #106c minimal-gate helpers (it WIRES them in + adds the retroactive + routing). New/salvaged: the `revoked` column + migration, the retroactive pass (re-keyed), the both-arms gate, the v1→v2 routing, the anvil gate. `RevisionLogV2.sol` / `RevisionLogV1.sol` / `pairing.rs` / `rotation.rs` REUSED, not modified.
- **L2 (honor = the CURRENT on-chain SET — LOAD-BEARING).** A verified V2 revision is ingested iff its recovered signer ∈ the live `authorizedDevice` set. Any out-of-set signer (removed / never-added / former-manager) is revoked. This is the property D-011 signs off; a regression must turn the anvil gate (L11) red.
- **L3 (FAIL-CLOSED on a set-read error — LOAD-BEARING, the #103-C CRITICAL lesson).** A genuine "no V2 set / V1 vault" resolves to the V1 permissive route (`Ok`); ANY real set-read failure (RPC/network/chain-id/`eth_getLogs`/view) is propagated as `Err` and FAILS the whole sync. A read failure is NEVER swallowed to "honor all" (which would re-honor a removed device — under-revocation). Two regression tests pin the `Ok-vs-Err` boundary (no-surface ⇒ `Ok` route to V1; RPC-failure ⇒ `Err`).
- **L4 (retroactive re-eval marks + the read-filters exclude — LOAD-BEARING).** Already-stored rows are re-evaluated against the current set each sync; out-of-set rows are MARKED `revoked = 1` (not deleted, L6); the head/history/content reads FILTER `revoked = 1`. Both directions recomputed (re-add un-revokes). A row marked revoked must NOT surface as a head, in history, or in the content graph (the #103-C FINDING 2 regression — pinned by a test that revokes a child and asserts the honored parent becomes the head).
- **L5 (the V1 path is UNTOUCHED / no regression).** V1 vaults keep the permissive `auto_register_device_from_chain_sync` (correct — V1 is single-device, no removal path, nothing to revoke). A test asserts a V1-routed sync behaves byte-identically to pre-#106d.
- **L6 (revocation is read-only + reversible).** A revoked row is filtered, never destructively mutated beyond the `revoked` flag; `--from-genesis` re-derive (or a re-add) recomputes it. No hard-delete in v1.
- **L7 (reuse RevisionLogV2 reads; NO contract change; NO new dep).** The set + `removeDevice` + the events already exist (#106a, confirmed §6). #106d reuses `read_authorized_device_v2` / `decode_device_mgmt_events` from the merged #106c client. `cargo tree` adds no `=`-pinned dep (alloy provides everything); the crypto crate's serde-count stays 0.
- **L8 (no reverse dep).** `pangolin-chain` gains no `pangolin-store` dep (the set-read + event-fold live in `pangolin-chain`; the gate orchestration + the retroactive pass + the read-filters live in `pangolin-store::Vault`). `check-chain-no-store.sh` stays green.
- **L9 (chain-id + pinned-address binding reused).** The V2 set reads reuse #101 `resolve_envelope_chain_id` + the pinned-address cross-check (the merged #106c client already does this); production never sources the binding chain-id from an untrusted RPC.
- **L10 (`forbid(unsafe_code)` except FFI; AGPL SPDX) on every new file.**
- **L11 (anvil remove-then-read regression gate = CI gate).** Deploy RevisionLogV2 + RecoveryV1 → bootstrap A → `addDevice(B)` → publish from A and B → assert both honored → `removeDevice(B)` → sync → assert B's NEW publish AND its retroactively-stored entries are BOTH revoked-on-read (filtered from head/history), A still honored → `addDevice(B)` again → assert B honored again (re-add un-revokes). Negatives that MUST turn it red: a broken predicate ("honor all signers" / "ignore the set"), a fail-OPEN on a set-read error (swallowed to honor-all), a retroactive pass that marks but the read-filters don't exclude (the FINDING 2 cosmetic-revocation regression). Env-quirk #14 class.
- **L12 (schema-version / additive migration).** The `revisions.revoked` column is additive (DEFAULT 0); legacy vaults pick it up via the idempotent migration; no `format_version` bump (the #103-C / `superseded_by` doctrine). The reader keeps the `schemaVersion ≤ MAX_KNOWN` reject.
- **L13 (testnet-only until D-011).** The V2 revocation rule stays Base-Sepolia-only until the external audit clears.
- **L14 (FULL `cargo test --workspace` gate — the #106b-1 lesson).** The merge gate is the WHOLE workspace test run + the anvil remove-then-read E2E via `anvil-ci.sh`.
- **L15 (§16 ledger).** `git merge --no-ff`; DECISIONS.md Q-resolution entries (incl. the parked-#103-C-branch closure, Q-d); DEVLOG at merge; explicit Kelvin approval at the merge boundary (§16.3); THREAT_MODEL revocation-generalization row (post-audit).

---

## 5. Open decisions for Kelvin (Q-a … Q-f) — recommendation + plain-English stakes

### Q-a · The V2 revocation rule + fail-closed (THE load-bearing rule)
**Recommend: honor iff signer ∈ the LIVE on-chain authorized set; FAIL-CLOSED on a set-read error (route a genuine "no V2 set" to the V1 permissive path; propagate any real read failure as `Err` and fail the sync).** See §3.1 + L2/L3.
**Plain-English stakes:** this decides which on-chain entries every device trusts after another device is removed. Get the rule wrong *lenient* (or fail OPEN on a read error — "couldn't read the set, so trust everyone") and a removed/compromised device's entries keep being honored forever — the whole point of removing it fails silently. Get it wrong *strict* and legitimate current devices get dropped (loud liveness failure). The live-set rule is precise; fail-closed is the foot-gun guard. This is the #103-C "Ok-empty-vs-Err" lesson, re-applied: an empty/failed read must never be read as "trust all."

### Q-b · Source the current set: fold the events, or per-signer live reads?
**Recommend: fold the device-management events into a SET snapshot (`decode_device_mgmt_events`, already merged) + cross-check the decisive signers against the live `read_authorized_device_v2`** (the live read is the authoritative tiebreaker — the #103-C L5 anti-stale anchor, re-keyed to membership). The fold is cheap (one event scan, reusing the sync's existing log pull); the live read is the final word.
**Plain-English stakes:** "how does the reader learn who's currently trusted?" Folding the chain's add/remove events rebuilds the set cheaply; a live membership check on the deciding signer is the safety anchor so a stale/tampered event-fold can only OVER-revoke (a recoverable liveness dent), never UNDER-revoke (the dangerous direction that re-honors a removed device).

### Q-c · The v1→v2 routing signal (the cut-over)
**Recommend: route by the vault's recorded revision-log contract binding** (a fixed per-vault property set at create/bootstrap — V2 vaults gate on the set, V1 vaults stay permissive). NOT by "presence of an on-chain set" (ambiguous with a read failure — the fail-closed trap). See §3.3.
**Plain-English stakes:** existing single-device V1 vaults must keep working exactly as today (no breakage, nothing to revoke — V1 has no removal path); new multi-device V2 vaults get the set gate. Routing by a fixed vault property (not a chain heuristic) keeps the two cleanly separated and makes "couldn't read the set" unambiguously a *failure* on a V2 vault (fail the sync), never a silent downgrade to permissive.

### Q-d · The parked #103-C branch: salvage-and-close, or merge-then-generalize?
**Recommend: formally CLOSE/abandon `worktree-agent-a3f6272eca2f476be`; salvage ONLY its store plumbing into #106d** (the `revoked` column + migration + the head/history/content read-filters + the retroactive pass re-keyed to set-membership + the fail-closed taxonomy + the anvil-gate shape). DISCARD its lineage inference (`revocation.rs` `AuthorityLineage` + `read_authority_lineage_v1`) — the on-chain set supersedes it. Record the closure in DECISIONS.md.
**Plain-English stakes:** #103-C was built before the architecture lock chose an on-chain set; its clever "infer who's trusted from the recovery-rotation history" machinery is now dead weight (the chain publishes the set directly). Merging it then immediately ripping the inference out is churn. Lift the genuinely reusable parts (the database column + filters + the fail-closed safety lesson — all hard-won) and abandon the rest. The branch's audit value (the FINDING 1 fail-closed + FINDING 2 read-filter lessons) is preserved by salvaging those exact mechanisms.

### Q-e · The narrow "V1 vault that rotated its RecoveryV1 authority" case
**Recommend: out of scope for #106d (it is the original #103-C single-device case, and under new-vaults-only-on-V2 such vaults stay V1/single-device); confirm whether it needs ANY revocation at all, or stays permissive as a pre-existing-vault tradeoff.**
**Plain-English stakes:** a vault created on V1 that later recovered (rotating its on-chain control authority) is exactly the case #103-C was originally written for. With multi-device living entirely on V2, do we (a) still want the #103-C lineage gate for these legacy V1-rotated vaults (salvage `revocation.rs` after all, for V1 only), or (b) accept they stay permissive (the pre-V2 status quo — a legitimate recovery forces re-enroll, the #103-C GAP FLAG 2 tradeoff Kelvin already accepted)? Recommend (b) for #106d simplicity, but flag it — it is the one place the lineage machinery might still earn its keep. **This is the only genuine open question about discarding #103-C wholesale.**

### Q-f · One PR or two on a single branch?
**Recommend: one #106d stage; optionally two reviewable PRs on one branch** (PR1 = salvaged store plumbing re-keyed to set-membership + retroactive re-eval + read-filters + hermetic tests; PR2 = the live-set gate wired into both sync arms + the v1→v2 routing + the coupled anvil remove-then-read E2E).
**Plain-English stakes:** purely review-ergonomics; either way the anvil remove-then-read gate is the merge gate. Low.

---

## 6. GAP FLAGS — do the merged #106a/#106c APIs cleanly support the full gate?

**Confirmed: NO contract change is needed, and the merged APIs cleanly support the full gate.** Specifically:

- **RevisionLogV2 (#106a) provides everything read-side.** `authorizedDevice(vaultId, signer) → bool`, `authorizedDeviceCount`, `currentManager`, `bootstrapped`, the `removeDevice` mutator, and the `VaultBootstrapped`/`DeviceAdded`/`DeviceRemoved`/`PromotionFinalized` events are all present in the deployed contract + the `sol!` binding (verified in `revisionlog_v2_client.rs`). The set is the live truth; revocation is purely read-side. **CONFIRM: no `RevisionLogV2.sol` change in #106d.**
- **The #106c client (`revisionlog_v2_client`) provides the reads + the event fold.** `read_authorized_device_v2`, `read_authorized_device_count_v2`, `read_current_manager_v2`, `read_bootstrapped_v2`, and `decode_device_mgmt_events` are merged and exactly what the gate needs. `currentManager` already returns `RecoveryV1.vaultAuthority` if set (else the V2-local `deviceManager`) — the cross-contract bind (#106 Q-h) means a recovery rotation automatically changes who can manage the set, with no extra work in #106d.
- **The #106c minimal gate (`multi_device::is_signer_honored` / `Vault::ingest_v2_revision_if_honored`) is built but NOT wired into the sync loop.** This is the deliberate #106c deferral. The live `sync_from_chain_with_ws_url` (both arms, vault.rs ~8304 + ~8500) still calls the permissive `auto_register_device_from_chain_sync`. **#106d's core wiring task is to route the V2 path through the gate + add the retroactive pass — the helpers exist; the loop integration + routing + retroactive + fail-closed taxonomy is the new work.**
- **`SyncReport` on main lacks `revisions_revoked`** (the parked #103-C branch added it; it is not on main). #106d adds it as an additive field (`Default` keeps it backward-source-compatible).
- **GAP (minor) — the V2 publish path.** The live sync loop reads RevisionLogV1's `RevisionPublished` via `fetch_and_verify_chunk`. A V2 vault publishes via `RevisionLogV2.publishRevision` (a DIFFERENT contract + a v2 EIP-712 domain). #106d's set gate presumes the sync loop is reading V2 revision events for a V2 vault. **Flag: does the merged sync loop already read V2 `RevisionPublished` for a V2 vault, or does the v1→v2 routing in #106d also need to point the revision-event read at the V2 contract?** If the latter, that is additional (still read-side, no contract change) wiring inside the routing of §3.3 — surfaced for the builder, and a sub-question of Q-c. This is the one place the routing may be wider than "just pick the predicate."

---

## 7. Test posture

- **Anvil remove-then-read regression gate (centerpiece, L11):** deploy RevisionLogV2 + RecoveryV1 → bootstrap A → `addDevice(B)` → publish from A and B → assert both honored → `removeDevice(B)` → sync → assert B's new publish AND its retroactively-stored entries BOTH revoked-on-read (filtered from head/history/content), A honored → `addDevice(B)` again → assert B honored again. Negative arms: broken predicate ("honor all"), fail-OPEN on a set-read error, retroactive-marks-but-read-filters-don't-exclude (FINDING 2) — each MUST flip the gate red.
- **Hermetic units (pangolin-store):** the retroactive pass over a fixture set (in-set honored / removed revoked / re-added un-revoked / both-directions idempotent); the head/history/content read-filter exclusion (revoke a child → honored parent becomes the head); additive-migration (legacy vault opens with `revoked` absent → DEFAULT 0 honored); the V1-untouched assertion (a V1-routed sync == pre-#106d behavior).
- **Hermetic units (pangolin-chain):** the set-fold from synthesized `DeviceAdded`/`DeviceRemoved`/`PromotionFinalized` logs (already partly covered by the merged `decode_device_mgmt_events` tests); the fail-closed taxonomy — no-V2-set ⇒ route-to-V1 (`Ok`); RPC failure ⇒ `Err` never swallowed (the salvaged #103-C FINDING 1 regression shape).
- **`#[ignore]`'d live tests** against the Base Sepolia V2 deployment once it exists (deferred, same posture as #103/#104b/#106c).

---

## 8. Effort + risk

**~1-2 weeks. Small-to-medium in code volume (a read-policy change + a salvage), but the revocation RULE + the fail-closed discipline are load-bearing.** The salvage (the `revoked` column + migration + read-filters + the retroactive pass) is mechanical re-keying of merged-quality #103-C plumbing; the net-new highest-care work is concentrated in: (1) **L2/L3 the live-set gate + fail-closed taxonomy** wired into both sync arms (a fail-OPEN here re-honors removed devices — the silent security failure #103-C exists to stop); (2) **the v1→v2 routing** (a wrong route either breaks V1 vaults or silently downgrades V2 to permissive); (3) the GAP §6 V2-revision-read question (does the routing also need to point the event read at the V2 contract). The anvil remove-then-read gate with its negatives is the structural defense for all three. Testnet-only until D-011; the in-house adversarial audit scrutinizes the gate placement + the fail-closed boundary + the read-filter completeness, not new primitives (there are none).

---

## 9. Where it lives (files expected to change — for the eventual build, NOT this draft)

- **`crates/pangolin-store/src/schema.rs`** — salvage the additive `revisions.revoked` column + `migrate_revision_revoked_column` (verbatim from the parked branch).
- **`crates/pangolin-store/src/vault.rs`** — the live-set gate wired into both arms of `sync_from_chain_with_ws_url` (replacing permissive auto-register on the V2 route); the retroactive re-eval pass (`reevaluate_revocation_against_set`, salvaged + re-keyed); the head/history/content `revoked = 0` read-filters (salvaged verbatim); the v1→v2 routing.
- **`crates/pangolin-chain/src/chain_sync.rs`** — `SyncReport.revisions_revoked` (additive field).
- **`crates/pangolin-chain/src/revisionlog_v2_client.rs`** — reused as-is for the set reads + event fold; possibly a small helper to fold a full SET snapshot (if Q-b picks the fold path) + the fail-closed taxonomy wrapper (the `Ok-no-set`-vs-`Err` resolver, mirroring `read_authority_lineage_v1`'s shape).
- **`scripts/anvil-ci.sh`** + the #106c lifecycle test module — the remove-then-read regression gate (extend the merged #106c add+remove+rotate E2E with the read-honor + retroactive-revoke + re-add assertions).
- **`DECISIONS.md` / `DEVLOG.md` / `THREAT_MODEL.md`** — append-only at merge; the Q-a..Q-f resolutions; the **parked-#103-C-branch closure** (Q-d); THREAT_MODEL revocation-generalization row (post-audit).

Files NOT expected to change: `contracts/src/RevisionLogV2.sol` + `RevisionLogV1.sol` + `RecoveryV1.sol` (deployed + immutable; #106d is Rust read-policy only); `pairing.rs` / `rotation.rs` / `multi_device.rs` minimal-gate helpers (REUSED); the EIP-712/merkle/signature-verification paths (4.1 + #106c unchanged).

---

## 10. Discard / supersession summary (the #103-C fold-in, at a glance)

| #103-C artifact | #106d disposition |
|---|---|
| `revocation.rs` `AuthorityLineage` / `AuthorityRotation` / `with_live_current` / `is_honoured` | **SUPERSEDED** — the on-chain set is the live truth; no lineage to infer |
| `recovery_client.rs::read_authority_lineage_v1` + `RecoveryFinalized`/`GuardianSetInitialized` fold | **SUPERSEDED** — read V2 device-management events instead (`decode_device_mgmt_events`, merged) |
| `revisions.revoked` column + `migrate_revision_revoked_column` | **SALVAGE verbatim** (V2-agnostic store plumbing) |
| `reevaluate_revocation_against_lineage` retroactive pass | **SALVAGE, predicate re-keyed** `lineage.is_honoured` → `current_set.contains` |
| head / history / content `revoked = 0` read-filters (FINDING 2) | **SALVAGE verbatim** |
| FAIL-CLOSED `Ok-no-surface`-vs-`Err` taxonomy (FINDING 1) | **SALVAGE, re-keyed** `Ok` = V1-route / no-V2-set; `Err` = real read failure |
| `SyncReport.revisions_revoked` + both-arms gate placement | **SALVAGE** (additive field; predicate swapped) |
| anvil rotate-then-read gate shape + negative arm | **SALVAGE, re-keyed** to remove-then-read on the V2 set |
| scorched-earth / multi-rotation / re-add decisions (Q-b/Q-c/Q-d) | **SUBSUMED for free** by current-set membership (§3.5) |
| the parked branch `worktree-agent-a3f6272eca2f476be` itself | **CLOSE/abandon** (Q-d) — salvage the plumbing, don't merge the inference |
