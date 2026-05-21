<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Issue #103-C — Revocation-on-read (honour the rotated `vaultAuthority`) — plan-gate LOCKED

**Status: LOCKED — Kelvin sign-off 2026-05-20. Q-a..Q-f + GAP FLAG 2/3 resolved (see §0a).** Mirrors the §16
plan-gate format of `103-recovery-client.md` / `104b-recovery-orchestration.md`. Recovery stays
**TESTNET-ONLY (Base Sepolia)** until the D-011 external audit clears; #103-C is part of that audit
package because the revocation RULE is load-bearing.

## 0a. RESOLVED decisions (Kelvin sign-off 2026-05-20)

- **Q-a revocation rule → signer-based (Option A).** Honour a verified revision iff its recovered signer
  is the current `vaultAuthority`; revoke anything signed by a former authority. (Block-cutoff rejected —
  it misses a compromised old key publishing *after* rotation, the exact attack.)
- **Q-b strictness → SCORCHED EARTH: revoke ALL entries signed by any former authority,** including its
  pre-rotation history. Rationale: recovery is invoked because the old device is lost/compromised; once
  superseded, even its historical entries are suspect. (User's actual vault data is unaffected — it's
  recovered byte-identical via the VDK; this only drops the old device's on-chain revision/audit history.)
  The "new authority re-attests specific old revisions" friendliness feature is a deferred follow-up.
- **Q-c re-adds → automatic via the signer-set rule** (no special case; current authority's signer is
  honoured, the old authority's is not).
- **Q-d multiple rotations → honour ONLY `A_current`;** every prior authority is dead.
- **Q-e lineage → live `read_vault_authority_v1` for "who is current" every sync + `.pvf`-cached
  `RecoveryFinalized` lineage for the cheap "former set"; `--from-genesis` re-derive escape hatch.**
- **Q-f tests → hermetic units + the anvil rotate-then-read regression gate (centerpiece, with a negative
  arm) + `#[ignore]` live.**
- **GAP FLAG 2 (multi-device) → SINGLE-DEVICE v1.** The current `vaultAuthority` is the SOLE honoured
  signer. Confirmed with Kelvin this is a normal-multi-device-UX tradeoff, NOT a collusion-security one
  (guardian-collusion exposure is identical either way, defended by the #102 72h-delay + owner-cancel +
  threshold size). A legitimate recovery while you still hold other devices forces those to re-enroll —
  accepted for v1. Multi-device-after-recovery (an authorised-signer-set) → RecoveryV2 / a new
  device-registry-with-authority-binding contract (deferred).
- **GAP FLAG 3 (pre-#103-C entries) → re-evaluate the local graph against the lineage every sync and
  MARK-revoked** (additive `revoked` status column, §18.7 bump; no hard-delete in v1, so the user can
  audit what was cut).

**Base tip: current main `ab8d33e`** (#104b orchestration merged; #102 RecoveryV1 `97cbe4c` /
D-? deployed; #103 client + #101 anvil harness + 4.1 reader + #99 WS branch all landed).

---

## 0. One-paragraph summary

When social recovery rotates a vault's on-chain control authority (RecoveryV1.`finalizeRecovery`
swaps `vaultAuthority[vaultId]` from the old secp256k1 address to the recovering device's address),
the **4.1 chain reader** must stop honouring vault state authored by the *old* authority — otherwise a
lost-or-compromised old device's revisions stay "valid on read" forever. Today the reader
(`pangolin-chain::chain_sync` + `pangolin-store::Vault::sync_from_chain`) has **ZERO authority
awareness**: it pulls `RevisionPublished` events from RevisionLogV1, recovers each event's secp256k1
signer, auto-registers that signer as a device, and ingests the revision — it never consults
RecoveryV1's `vaultAuthority` at all. #103-C adds an **additive filter** on top of the existing
verified-event path: before a verified revision is ingested, the reader checks the event's recovered
signer against the vault's **current** `vaultAuthority` lineage and **revokes** (ignores / does not
honour) any revision whose authorizing signer is not the current authority. This is the deferred
"enforcement-on-read" piece called out in `RevisionLogV1.sol` (no-revocation-in-v1, L9/L10),
`102-recovery-v1-contract.md` Q-d ("old-device-key revocation enforcement is client-side read-policy,
deferred"), and the recovery-model memory's dual-authority note. It introduces **no new contract** and
**no new crypto** — only read-side policy that keys off the secp256k1 `vaultAuthority` (the CONTROL
authority that rotates), reusing the already-shipped `read_vault_authority_v1` helper that was written
"by future #103-C revocation-on-read."

---

## 1. Scope

**#103-C builds (Rust read-side only):**

1. A reader-side lookup of the vault's **current** `vaultAuthority` from RecoveryV1 (reusing
   `pangolin_chain::recovery_client::read_vault_authority_v1`, which already exists and is pinned
   "for #103-C").
2. The **revocation rule** itself: a predicate that, given a verified `RevisionPublished` event
   (recovered signer + its block/sequence) and the vault's authority lineage, decides
   honour-vs-revoke. (Q-a chooses signer-based vs block-based — recommend **signer-based**.)
3. Wiring the predicate as an **additive gate** in the `sync_from_chain` ingest loop (and the WS
   tip-follow path): a revoked event is counted (`revisions_revoked`) but NOT fed into
   `ingest_pending_chain_revision`. Existing signature verification (4.1 L5) is **unchanged**.
4. The authority-lineage source + trust posture (Q-b): how the reader learns the current authority
   AND the rotation point(s) trustlessly, reusing #101 L4 chain-id binding + #103 L11 anti-replay
   posture.
5. The anvil regression gate (the centerpiece): seed RevisionLog entries under authority A → rotate
   to B via the full RecoveryV1 lifecycle → read → assert A's pre-rotation entries are revoked AND
   B's post-rotation entries are honoured.

**Deferred / out of scope:**

- **Mutable guardian sets / RecoveryV2** (the contract is immutable v1; not touched).
- **On-chain revocation** — impossible by design: RevisionLogV1 is append-only, no removal path
  (`RevisionLogV1.sol` L9/L10/R-c). Revocation is **strictly a client read-policy**.
- **Re-encrypt / re-key the vault payload** on rotation (that is the VDK re-wrap, already done in
  #104b; #103-C is purely about which chain entries the reader *honours*, not about decrypting them).
- **6.x UX** — surfacing "N revisions were revoked by your recovery" to the host UI.
- **EntitlementRegistry (D-018) revocation** — orthogonal contract; not consumed by the read path.
- **A new contract event carrying the rotation block** — see GAP FLAG 1; #103-C works around it
  rather than redeploying RecoveryV1.

---

## 2. What the reader does TODAY (and whether it has any authority awareness)

**It has NONE.** Traced end-to-end:

- `pangolin_chain::chain_sync::fetch_and_verify_chunk` → `poll::fetch_chunk` pulls
  `RevisionPublished` logs filtered by `(contract = RevisionLogV1, topic1 = vault_id,
  topic0 = RevisionPublished::SIGNATURE_HASH)`, decodes each via the reused `sol!` binding, checks
  chain-id (L3) + pinned address (L4) + vault-id (L-substitution) + schema-version
  (`≤ MAX_KNOWN_CLIENT_SCHEMA_VERSION`), then **recovers the secp256k1 signer**
  (`recover_signer_v1_raw`) and cross-checks it against the event's unindexed `signer` field (L5).
  The output is a `VerifiedRevisionEvent { event, signer, block_hash, schema_version }`.
- `pangolin_store::Vault::sync_from_chain_with_ws_url` consumes those: for each event it
  **auto-registers** the recovered signer into the local devices table
  (`auto_register_device_from_chain_sync`, 4.1 R-d "permissive auto-register"), then ingests via
  `ingest_pending_chain_revision`, runs reorg detection, promotes to Finalized at depth ≥ 12, and
  advances the checkpoint.
- **At no point does any of this consult RecoveryV1.** There is no read of `vaultAuthority`, no notion
  of "the authority rotated," no filter that drops pre-rotation entries. The only authority concept in
  the reader is RevisionLogV1's *own* self-bootstrapping device registry (`isRegisteredDevice`), which
  the reader mirrors permissively (4.1 R-d) and which has **no removal path** — exactly the gap.

**Consequence (the bug #103-C fixes):** after a recovery rotates `vaultAuthority` A→B, the old
device A is still a "registered device" both on-chain (RevisionLogV1 has no removal) and locally
(auto-registered, never removed). A revision A signed *before* the rotation — or a revision a
**compromised** A signs *after* the rotation (RevisionLogV1 will still accept it: it only checks
`isRegisteredDevice`, which never consults RecoveryV1) — is ingested and honoured by every reader.
The control-plane rotation is invisible to the read path.

**The two authorities (why this is subtle):** The recovery-model memory's dual-authority model means
"the authority" is two independent secp256k1/Ed25519 things. #103-C keys ONLY off the **on-chain
secp256k1 `vaultAuthority`** — the CONTROL authority RecoveryV1 rotates. Critically, in the #104b
flow the recovering device's secp256k1 signer becomes BOTH the new `vaultAuthority` (it is the
`proposedAuthority` that `finalizeRecovery` rotates to) AND the key it will use to sign future
RevisionLog revisions. So "honour only entries whose signer == current `vaultAuthority`" is coherent:
post-recovery, the new device's RevisionLog signer *equals* the new `vaultAuthority`. **GAP FLAG 2
(below) examines whether the multi-device case breaks this 1:1 assumption.**

---

## 3. The proposed revocation rule (the load-bearing decision)

Two candidate rules; recommend **signer-based** (Q-a Option A):

### Option A — signer-based (RECOMMENDED)
> **Plain English:** "Only honour a chain revision if the device that signed it is *the* device the
> vault currently trusts (the current `vaultAuthority`), or a device that current authority has
> legitimately authorised. Ignore everything signed by a former authority."

Rule: ingest a verified `RevisionPublished` event **iff** its recovered signer is in the vault's
**authorised-signer set as of the current authority lineage**. Concretely:

- Maintain the **authority lineage**: the ordered list of `vaultAuthority` values
  `[A_0 (genesis), A_1, A_2, …, A_current]` reconstructed from `RecoveryFinalized` /
  `GuardianSetInitialized` events (genesis authority = `GuardianSetInitialized.initialAuthority`;
  each rotation = `RecoveryFinalized.newAuthority`). Each lineage entry knows the block at which it
  *stopped* being current (the block of the next `RecoveryFinalized`), or "still current" for
  `A_current`.
- A revision signed by `A_current` is **always honoured** (regardless of block).
- A revision signed by a **former** authority `A_k (k < current)` is **revoked** — full stop,
  regardless of when it was signed. (This is stricter than "before its rotation block": if the old
  key is treated as compromised, even its *pre*-rotation entries are suspect once a recovery has
  declared it superseded. See Q-c for the softer variant.)
- **Why signer-based wins:** (1) It handles **re-adds** naturally (Q-c) — if the new authority B
  legitimately re-registers/keeps using a device, that device's signer is in the current set and is
  honoured; the *old* A entries stay dead because A is not in the current set. (2) It handles
  **multiple rotations** naturally (Q-d) — only `A_current` and its authorised signers are honoured;
  every prior authority is dead. (3) It does not depend on a precise rotation *block number* (which
  the contract event does not expose cleanly — GAP FLAG 1), only on the *identity* of the authority,
  which `vaultAuthority(vaultId)` returns directly and trustlessly.

### Option B — block-height-based (NOT recommended)
> **Plain English:** "Ignore any chain revision that landed in a block before the recovery finalized."

Rule: ingest iff `event.block_number ≥ rotation_block`. Simpler, but:
- **Cannot handle re-adds** — a device the new authority keeps using, whose revision happened to land
  before the rotation block, would be wrongly revoked.
- **Wrong granularity** — a *compromised* old key that publishes *after* the rotation block (which
  RevisionLogV1 still accepts, since it never consults RecoveryV1) would be wrongly **honoured**.
  This is the exact attack #103-C exists to stop, and block-cutoff misses it.
- **Needs the rotation block**, which the `RecoveryFinalized` event does not carry as a field (GAP
  FLAG 1) — you would derive it from the log's block number, which is fine, but you have done the
  harder work for a weaker rule.

**Recommendation: Option A (signer-based).** Block height is used only as **defence-in-depth
metadata** (recorded alongside each revoked decision for diagnostics), never as the primary gate.

---

## 4. How the reader learns the current `vaultAuthority` + the rotation lineage

- **Current authority:** reuse the already-shipped
  `pangolin_chain::recovery_client::read_vault_authority_v1(env, rpc_url, vault_id) -> Address`
  (a single `vaultAuthority(vaultId)` view call). This is the authoritative, trustless source — it
  reads contract storage, not an event the RPC could fabricate, and a malicious RPC returning a wrong
  authority is bounded by the same threat posture as a malicious RPC returning wrong revision logs
  (mitigated by L3 chain-id + L4 pinned-address cross-checks, identical to 4.1).
- **The lineage (for the "former authority" set):** read the RecoveryV1 `RecoveryFinalized`
  (+`GuardianSetInitialized`) events for the vault via the same chunked `eth_getLogs` machinery the
  4.1 reader already uses, filtered by `(contract = RecoveryV1, topic1 = vault_id)`. Each
  `RecoveryFinalized` carries `oldAuthority` + `newAuthority` (both unindexed) + the indexed
  `attemptNonce`; the log's own block number is the rotation point. Fold these into the ordered
  lineage. **GAP FLAG 1** (the event lacks an explicit rotation-block field) is a non-issue for
  Option A — we need the *set* of former authorities, which `oldAuthority`/`newAuthority` give
  directly; the block number is incidental.
- **Caching (Q-e):** the lineage is monotonic-append (rotations only add). Recommend caching the
  lineage in the `.pvf` keyed by `(chain_env, vault_id)` alongside the existing `last_synced_block`
  checkpoint, refreshed each sync by reading new `RecoveryFinalized` events since the checkpoint plus
  a live `read_vault_authority_v1` cross-check (the live read is the authoritative tiebreaker; the
  cached lineage just supplies the historical "former" set cheaply).
- **Trust / replay story:** reuse #101 L4 (BaseSepolia chain-id pinned + RPC cross-check; production
  never sources the binding chain-id from an untrusted RPC) and #103 L11 (read live state per
  operation; never act on a stale attempt). The current-authority live read is the anti-staleness
  anchor: even if the cached lineage is tampered, the live `vaultAuthority(vaultId)` is the final word
  on who is current, and a tampered cache that *adds* a fake former authority can only cause
  over-revocation (a liveness dent, recoverable by `--from-genesis`), never under-revocation (which
  would honour a compromised key — the dangerous direction). See L-cache-tamper.

---

## 5. Open decisions for Kelvin (Q-a … Q-f) — recommendation + plain-English stakes

### Q-a · Signer-based vs block-height-based revocation — THE load-bearing rule
**Recommend: Option A (signer-based).** See §3.
**Plain-English stakes:** Get this wrong in the *lenient* direction and a stolen/lost old device's
entries keep being trusted forever — the whole point of recovery (cutting off the old device) fails
silently. Get it wrong in the *strict* direction and legitimate entries get dropped — the user "loses"
real vault history after a recovery. Signer-based is the precise rule; block-cutoff is the foot-gun.

### Q-b · How strict is "former authority"? Revoke ALL of a former authority's entries, or only post-supersession?
**Recommend: revoke ALL entries signed by any former authority (the strict variant in §3).**
Rationale: recovery is invoked precisely because the old device is lost or compromised; once a
recovery has *superseded* a key, even its historical entries are suspect (a compromised key could have
back-published, and there is no way on-chain to distinguish "honest old history" from "attacker using
the old key"). The softer "honour the old authority's entries up to its rotation block, revoke after"
variant (Q-c-ish) preserves more history but trusts that the old key was honest right up to the
rotation — which the threat model cannot assume.
**Plain-English stakes:** strict = the user may lose pre-recovery history authored by the old device
(they must re-author it under the new device); lenient = a compromised old key's pre-rotation forgeries
survive. **This is genuinely a product call** — does Kelvin want recovery to be "scorched earth" (safest)
or "preserve honest history" (friendlier but trusts the old key's past)? Recommend scorched-earth for
v1 + a follow-up that lets the new authority *explicitly re-attest* specific old revisions it vouches for.

### Q-c · Re-adds: may the new authority re-honour a device the old authority used?
**Recommend: only via the signer-set rule — a device is honoured iff its signer is in the CURRENT
authority's authorised set.** Under Option A this is automatic and needs no special case: if the new
authority B continues using (or re-registers) device D, then D's signer is in the current set and is
honoured; D's *old* revisions authored while A was authority are still revoked under Q-b-strict (B must
re-author or explicitly re-attest them). The signer-based rule handles re-adds where a naive block
cutoff cannot.
**Plain-English stakes:** if mishandled, either a device the user still trusts gets wrongly silenced,
or an old device the user *thought* was cut off sneaks back in. The signer-set rule makes "who is
trusted now" the single source of truth.

### Q-d · Multiple rotations (recovery happened more than once)
**Recommend: honour ONLY `A_current` (+its authorised signers); every prior authority A_0..A_(current-1)
is dead.** Option A gives this for free — the lineage is just a "former set," and membership in the
current set is all that matters.
**Plain-English stakes:** a user who has recovered twice must not have *any* of the two prior devices'
entries trusted. A bug that honours `A_(current-1)` (the second-to-last) would mean the
second-most-recent — possibly the very device a *second* recovery was needed to escape — stays trusted.

### Q-e · Authority-lineage source + caching
**Recommend: live `read_vault_authority_v1` for "who is current" (authoritative every sync) +
`.pvf`-cached `RecoveryFinalized` lineage for the cheap "former set", refreshed incrementally.**
A `--from-genesis` re-derive escape hatch (mirroring 4.1 R-a Option C) rebuilds the lineage from chain
if the cache is suspect.
**Plain-English stakes:** caching wrong = either an extra view-call per sync (cheap, the safe failure)
or a stale "current authority" that wrongly honours a just-superseded key (dangerous — mitigated by
always doing the live current-authority read). The cache only ever supplies the *former* set, whose
worst-case tamper is over-revocation (safe direction).

### Q-f · Test surface depth
**Recommend: hermetic + the anvil rotate-then-read regression gate + `#[ignore]`'d live.** The anvil
gate is the centerpiece (mirrors 4.1 R-f / #103 L10): a deliberately-broken predicate (e.g. "honour
all signers") must turn the gate RED. See §6.
**Plain-English stakes:** the revocation rule is invisible in normal operation — it only fires after a
recovery. Without the anvil rotate-then-read gate, a regression that silently stops revoking
(re-trusting old keys) would never be caught by ordinary tests. Env-quirk #14 class: only a real
contract-semantics test exercises the rotation→read interaction.

---

## 6. L1..Ln invariants (proposed — mirror 103/104b style)

- **L1 (additive — new files / additive gate only).** #103-C ADDS a filter; it does NOT change
  signature verification (4.1 L5), the `sol!` bindings, the merkle/EIP-712 paths, or the existing
  ingest idempotency. New code: a `revocation` module (revocation predicate + lineage type) in
  `pangolin-chain` + the gate call-site + counters in `pangolin-store::sync_from_chain`. The verified-
  event path up to the gate is byte-identical to 4.1.
- **L2 (only the current authority's entries are honoured — LOAD-BEARING).** A verified revision is
  ingested iff its recovered signer is in the current `vaultAuthority` authorised-signer set
  (Option A). Any former-authority-signed revision is revoked. This is the single property the
  external audit (D-011) signs off on; a regression must turn the anvil gate red.
- **L3 (trustless authority source).** Current authority read via the live `vaultAuthority(vaultId)`
  view (storage, not an RPC-fabricable event); lineage folded from `RecoveryFinalized` events under
  the same L4 pinned-address + L3 chain-id cross-checks the 4.1 reader uses. Reuse
  `read_vault_authority_v1` verbatim; no parallel authority-sourcing path.
- **L4 (chain-id binding reused).** Reuse #101 `resolve_envelope_chain_id` / 4.1 L3 verbatim: pinned
  BaseSepolia id + RPC cross-check; production never sources the binding chain-id from an untrusted
  RPC.
- **L5 (anti-replay / anti-stale reused).** Reuse #103 L11 posture: the current-authority read is live
  per sync; a cached lineage never overrides the live "who is current" answer. Over-revocation (cache
  tamper that adds a fake former authority) is the only achievable tamper and is the safe direction.
- **L6 (revocation is read-only + reversible).** A revoked event is NOT ingested, but #103-C performs
  NO destructive mutation of already-stored rows in v1 (see GAP FLAG 3 — what to do about entries
  ingested *before* #103-C shipped / before a rotation was observed). Recommend: re-evaluate all
  locally-stored revisions against the lineage on each sync and surface a `revisions_revoked` count;
  whether to *delete* or *mark-revoked* already-stored rows is Q-b-adjacent and flagged.
- **L7 (no reverse dep).** `pangolin-chain` gains no `pangolin-store` dep
  (`cargo tree -p pangolin-chain | grep -c pangolin-store == 0` preserved); the predicate + lineage
  type live in `pangolin-chain`, the gate orchestration in `pangolin-store::Vault::sync_from_chain`.
- **L8 (`forbid(unsafe_code)` + AGPL SPDX) on every new file.**
- **L9 (no new external dep — likely ZERO).** alloy already provides everything (view call + event
  decode reuse the existing `recovery_v1_binding`). No new `=`-pinned dep without
  `cargo deny check advisories` + `cargo audit`.
- **L10 (anvil rotate-then-read regression gate = CI gate).** The full deploy → seed entries under A →
  setGuardianSet → initiate → approve×t → `evm_increaseTime(72h)` → finalize (rotate A→B) → seed
  entries under B → read → assert A's entries revoked AND B's honoured. A deliberately-broken predicate
  must turn it red (env-quirk #14 class).
- **L11 (schema-version ladder reused).** No new schema surface in the contract; the reader keeps the
  4.1 `schemaVersion ≤ MAX_KNOWN_CLIENT_SCHEMA_VERSION` reject. If a `.pvf` lineage-cache column is
  added, §18.7 ladder bump + additive migration (mirror 4.1 R-a).
- **L12 (§16 ledger).** `git merge --no-ff`; DECISIONS.md R-a..R-f entry; DEVLOG at merge; explicit
  Kelvin approval at the merge boundary (§16.3).

---

## 7. Adversarial framing — L-section (load-bearing risks)

### L-stale-authority-honours-compromised-key (the PRIMARY risk #103-C exists to close)
**What goes wrong:** the reader uses a stale/cached "current authority" (or no authority awareness at
all, = today). A compromised OLD device key — still `isRegisteredDevice` on RevisionLogV1 (no removal
path) — publishes a forged-but-validly-signed revision *after* a recovery. The reader honours it.
**Defence:** L2 + L3 — every sync reads the LIVE `vaultAuthority`; any signer not in the current set is
revoked, including a former authority publishing post-rotation. Signer-based (Option A) catches the
post-rotation-publish case that block-cutoff (Option B) misses.

### L-cache-tamper (lineage cache)
**What goes wrong:** a tampered `.pvf` lineage cache adds or removes former authorities.
**Defence:** the cache only supplies the *former* set; "who is current" is always the live read.
Adding a fake former authority → over-revocation (safe; recoverable via `--from-genesis`). Removing a
real former authority → that authority's entries would be re-honoured **only if** they are also not the
current authority — and since they are not current, Option A's "honour iff in current set" still
revokes them. So a cache tamper cannot cause under-revocation. (Document this asymmetry in the audit.)

### L-malicious-rpc-wrong-authority
**What goes wrong:** a hostile RPC returns a wrong `vaultAuthority` (e.g. the attacker's address, or
an old address) from the view call.
**Defence:** same posture as 4.1's malicious-RPC handling (L3 chain-id + L4 pinned-address); a wrong
*current* authority returned by the RPC is bounded by the same trust assumption as the RPC returning
wrong revision logs — and the worst case (RPC names the attacker's address as current) requires the
attacker to ALSO control the RecoveryV1 finalize, which the 72h-delay + guardian-quorum + cancel path
(#102) defends. A wrong *old* authority → over-revocation (safe). Recommend a sub-check: cross-read
`vaultAuthority` against the latest `RecoveryFinalized.newAuthority` the reader observed; a mismatch
flags an RPC inconsistency.

### L-over-revocation-liveness
**What goes wrong:** a too-strict rule (or a bug) revokes legitimate current-authority entries → the
user "loses" real history.
**Defence:** the anvil gate's second assertion (B's post-rotation entries ARE honoured) is the
structural guard; `--from-genesis` re-derive is the escape hatch.

---

## 8. Test posture

Centerpiece (L10): the anvil **rotate-then-read** regression gate, extending `scripts/anvil-ci.sh` /
the #103 lifecycle harness:
1. Deploy RevisionLogV1 + RecoveryV1 (both already in the harness).
2. Publish revisions signed by device A (genesis authority) → RevisionLogV1.
3. `setGuardianSet` (root over the real guardians) → `initiateRecovery`(proposedAuthority = device B)
   → `approveRecovery`×t (real EIP-712) → `evm_increaseTime(72h)` → `finalizeRecovery` (rotates
   `vaultAuthority` A→B).
4. Publish revisions signed by device B → RevisionLogV1.
5. Run `sync_from_chain` and assert: **A's revisions are revoked** (not in the local graph;
   `revisions_revoked == count(A)`) AND **B's revisions are honoured** (in the graph,
   `revisions_applied == count(B)`).
6. Negative gate: a deliberately-broken predicate ("honour all signers") MUST flip assertion (5) red.
7. Multi-rotation variant (Q-d): A→B→C; assert A AND B revoked, only C honoured.

Hermetic units: lineage-folding from synthesised `RecoveryFinalized` logs; the revocation predicate
over a fixture lineage (current honoured / former revoked / post-rotation-by-former revoked);
cache-tamper asymmetry (added fake former → over-revoke; removed real former → still revoked).
`#[ignore]`'d live test: against the testnet deployments once a testnet RecoveryV1 + RevisionLogV1
share a vault that has actually rotated (deferred like 4.1's live tests).

---

## 9. Effort + risk

**~1-2 weeks. Small + mechanical in code volume, but the revocation RULE is load-bearing.** The view
read + event fold + predicate are short; the risk concentration is entirely in the *rule's
correctness* (Q-a/Q-b) and the anvil gate that proves it. Get the rule wrong lenient → compromised
old keys survive (silent security failure); wrong strict → legitimate history dropped (loud liveness
failure). The anvil rotate-then-read gate with a negative arm is the structural defence; it is the
single most important deliverable. No new crypto, no new contract, no new external dep expected.

---

## 10. GAP FLAGS — where RecoveryV1 / RevisionLogV1 don't expose what the reader needs

- **GAP FLAG 1 — no explicit rotation-block field in `RecoveryFinalized`.** The event carries
  `oldAuthority`/`newAuthority`/`attemptNonce` but NOT a `rotationBlock` field. **Non-blocking for the
  recommended Option A** (signer-based needs the former-authority *set*, not block numbers; the log's
  own block number supplies the incidental block for diagnostics). It WOULD matter for Option B
  (block-cutoff), reinforcing the Option-A recommendation. No contract redeploy needed.
- **GAP FLAG 2 — no on-chain link between a RevisionLog signer and the RecoveryV1 `vaultAuthority`,
  and no enumeration of "which device-keys an authority added."** RevisionLogV1's `isRegisteredDevice`
  is a self-bootstrapping set with NO removal and NO reference to RecoveryV1; RecoveryV1's
  `vaultAuthority` is a single address with no list of subordinate signers. **Consequence:** the clean
  case is 1:1 (the recovering device's signer == the new `vaultAuthority` == its future RevisionLog
  signer, per the #104b flow). But the **multi-device** case is unspecified on-chain: if the user
  legitimately runs several devices, each device self-bootstraps its OWN RevisionLog signer, and only
  ONE of them is the `vaultAuthority`. A strict "honour iff signer == current `vaultAuthority`" rule
  would then revoke the user's *other legitimate current devices*. **This is the biggest open design
  question** and Kelvin must rule on it (Q-c-adjacent): does v1 assume single-device-per-vault (so
  signer == authority is exact), or does #103-C need a client-side "authorised signer set" that the
  current authority extends (off-chain, since the contract has no such list)? Recommend: **v1 assumes
  the current authority is the sole honoured signer** (matches the #104b single-recovering-device
  flow + the testnet-only posture), and a multi-device authorised-signer-set is a flagged follow-up
  (it likely needs a RecoveryV2 or a new on-chain device-registry-with-authority-binding contract).
  **This must be surfaced to Kelvin before build — it changes the rule's shape.**
- **GAP FLAG 3 — entries ingested before #103-C shipped (or before a rotation was observed).** The
  reader may already hold locally-stored revisions signed by what is now a former authority (ingested
  by 4.1 before #103-C, or before the recovery finalized). #103-C must decide whether to
  *retroactively* revoke already-stored rows (re-evaluate the local graph against the lineage every
  sync and delete / mark-revoked) or only filter *new* reads. Recommend: re-evaluate + mark-revoked
  (don't hard-delete in v1; a `revoked` status column mirrors the 4.1 `RevisionStatus::Pending` /
  `Finalized` pattern) so the user can audit what was cut. This is additive schema (L11 / §18.7 bump).

---

## 11. Where it lives (files expected to change — for the eventual build, NOT this draft)

- **`crates/pangolin-chain/src/revocation.rs`** (new) — the `AuthorityLineage` type + the revocation
  predicate (`is_honoured(signer, &lineage) -> bool`) + lineage folding from `RecoveryFinalized`
  events. `forbid(unsafe_code)` + AGPL SPDX.
- **`crates/pangolin-chain/src/recovery_client.rs`** — reuse `read_vault_authority_v1` (exists); add a
  `read_authority_lineage_v1` helper that pulls + folds `RecoveryFinalized`/`GuardianSetInitialized`
  events (reusing the existing `recovery_v1_binding`).
- **`crates/pangolin-chain/src/lib.rs`** — re-exports.
- **`crates/pangolin-store/src/vault.rs`** — additive gate in `sync_from_chain_with_ws_url` (both the
  HTTP backfill and WS tip-follow arms); new `SyncReport.revisions_revoked` counter; GAP FLAG 3
  retroactive re-evaluation pass; optional `revoked` status column.
- **`crates/pangolin-chain/src/chain_sync.rs`** — `SyncReport` gains `revisions_revoked` (additive
  field, `Default` derives keep it backward-source-compatible).
- **`crates/pangolin-store/src/schema.rs`** (GAP FLAG 3 only) — `revoked` status column + §18.7 bump
  + additive migration.
- **`scripts/anvil-ci.sh`** + the #103 lifecycle test module — the rotate-then-read regression gate.
- **`DECISIONS.md`** / **`DEVLOG.md`** / **`THREAT_MODEL.md`** — append-only entries at merge
  (THREAT_MODEL gets the "revocation-on-read" surface row post-audit).

Files NOT expected to change: `contracts/*` (RecoveryV1 + RevisionLogV1 are deployed + immutable;
#103-C is Rust read-policy only), the EIP-712 / merkle / signature-verification paths (4.1 + #103
unchanged).

---

## 12. Open follow-ups

Multi-device authorised-signer-set (GAP FLAG 2 — likely RecoveryV2 / a new device-registry contract);
host UI surface for "N revisions revoked by your recovery" (6.x); the live testnet rotate-then-read
test (needs a testnet vault that has actually rotated); the explicit "new authority re-attests
specific old revisions" friendliness feature (Q-b follow-up); THREAT_MODEL revocation-on-read entry
(post-D-011-audit).
