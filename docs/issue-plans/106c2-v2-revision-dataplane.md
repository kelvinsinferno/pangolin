<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Issue #106c2 — V2 REVISION DATA-PLANE (publish + read/verify under RevisionLogV2) — plan-gate LOCKED

**Status: LOCKED — Kelvin sign-off 2026-05-21 (see §0a). Q-a..Q-h resolved; ONE stage (2 PRs on one branch OK).** Mirrors the §16 plan-gate format of `103-recovery-client.md` / `106c-device-add-flow.md`. Splits the everyday revision data-plane out of #106d's revocation gate (Kelvin's decision), built FIRST.

## 0a. RESOLVED decisions (Kelvin sign-off 2026-05-21)

- **Binding:** additive `meta.revisionlog_version INTEGER` (1=V1, 2=V2; single-row meta, plaintext routing state); legacy absence → V1 via `migrate_revisionlog_version_column` (PRAGMA guard, no format_version bump); written at `Vault::create`; additive `.pvf` migration (legacy → V1, byte-identical).
- **Q-a → NEW vaults default V1 for now.** V2 isn't usable end-to-end yet (data-plane is this slice; gate=#106d; UX=#106e; no Base Sepolia V2 deploy; testnet-only until D-011). Flip the default to V2 once the stack is complete + V2 deployed + D-011 clears.
- **Publish:** the V2 `Revision` typehash is BYTE-IDENTICAL to V1's (contract reuses the V1 type string verbatim, `RevisionLogV2.sol:269-271`); the V1 struct_hash is domain-independent → `publish_revision_v2` reuses V1's struct_hash/`eip712_digest`/`is_canonical_s` UNCHANGED and only swaps the domain (`build_domain_revisionlog_v2`, version "2") at the final digest. Add a v2 digest helper + a v2 domain-separator byte-pin. Broadcast reuses the #106c `publishRevisionCall` binding + `chain_submit` envelope/retry/gas.
- **Read:** `fetch_and_verify_chunk_v2` (HTTP eth_getLogs of `RevisionLogV2.RevisionPublished` + `recover_signer_v2_raw` under the v2 domain) + V2 WS path, mirroring V1. Separate `chain_sync_v2_state` checkpoint (Q-e).
- **Q-c → HYBRID mirror:** domain selection is EXPLICIT + typed PER-VERSION (NEVER inferred — the silent-and-total class); share the domain-agnostic plumbing (struct_hash, envelope). A v1 vs v2 domain must not be able to leak/swap.
- **Q-d → LIBRARY-LAYER + anvil E2E ONLY.** `publish_revision_v2` + the read/verify path land at the library layer, proven by the anvil publish→read-back E2E. The store batch-publish-QUEUE cut-over (it still drives the OLD v0 Ed25519 ChainAdapter — affects V1 publishing too) is a SEPARATE downstream slice, NOT #106c2.
- **Routing:** branch `sync_from_chain_with_ws_url` on `revisionlog_version()`; V1 path UNTOUCHED (no regression).
- **#106d boundary CONFIRMED:** #106c2 produces+reads the V2 stream with V1-parity verification (contract + chain-id pins + the contract's publish-time ecrecover); the set-membership/honor GATE is strictly downstream (#106d).
- **Gaps to close in #106c2:** add the missing `RevisionPublished` event to the V2 `sol!` binding (for reads); add the v2 revision-publish digest. (Q-f: no Base Sepolia V2 deploy / pinned address — a follow-up, doesn't block the anvil/Dev E2E.)
- **L-invariants:** V2 revision EIP-712 digest byte-identical to `RevisionLogV2._hashRevision` (#103 L2/L3); canonical-low-s/v∈{27,28}/reject signer==0; binding routes correctly + V1 untouched; additive schema §18.7; NO contract change / NO new deps; anvil publish→read-back E2E; testnet-only/D-011; forbid(unsafe); AGPL; full `cargo test --workspace` gate.

This slice is **TESTNET-ONLY (Base Sepolia / Dev anvil) until the D-011 external audit clears** — it wires the deployed `RevisionLogV2` into the client publish/read path. No mainnet. No contract change. No new crypto. No new deps.

---

## 0. One-paragraph summary

The #106 epic built `RevisionLogV2.sol` (the contract, with `publishRevision` gated on the on-chain authorized SET — #106a), the device-management client (`revisionlog_v2_{signing,client}` — #106c), and the pairing/rotation crypto (#106b). But the everyday **"save a password → publish a revision to RevisionLogV2 → read + verify it on your other devices"** path was never built client-side. The only revision data-plane that exists (`chain_submit::publish_revision_v1` + `chain_sync::fetch_and_verify_chunk` + the WS path + `Vault::sync_from_chain_with_ws_url`) is hard-bound to `RevisionLogV1` + the v1 EIP-712 domain (`version "1"`). There is no V2 revision-publish digest, no V2 signer-recovery, no V2 `RevisionPublished` read/WS path, and nothing records whether a vault is V1 or V2 (the routing signal). **#106c2 builds exactly this data-plane:** (1) the per-vault **v1/v2 binding** (a `meta.revisionlog_version` column) that routes the sync loop + publish; (2) `publish_revision_v2` — mirroring `publish_revision_v1` but signing under the v2 domain (digest byte-identical to `RevisionLogV2._hashRevision`) and broadcasting to `RevisionLogV2.publishRevision` via the already-merged #106c `sol!` binding; (3) the V2 read/verify path (`fetch_and_verify_chunk_v2` over `RevisionLogV2.RevisionPublished` + the WS subscription); (4) the routing branch in `sync_from_chain_with_ws_url` + the publish call site; and (5) an anvil E2E that publishes a V2 revision and reads it back + verifies. It introduces **no new crypto and no new contract** — the digest, the broadcast envelope, and the read machinery are all reused, retargeted to the v2 domain + the v2 contract. #106d's revocation/honor gate then sits ON TOP of this read stream (plan-LOCKED, PARKED — downstream).

---

## 0a. KEY FINDINGS from the read-first survey (load-bearing for the design)

1. **The V2 binding has `publishRevision` calldata but NOT the read event.** `revisionlog_v2_client::revisionlog_v2_binding` (merged `b141668`) already declares `function publishRevision(...)` and the six device-mgmt EVENTS — but it does **NOT** declare the `event RevisionPublished(...)`. The V2 read path therefore needs that event added to the `sol!` binding (one event, byte-aligned to `RevisionLogV2.sol:107-116`, which is field-identical to V1's). This is the one binding gap.
2. **There is NO V2 revision-publish digest yet.** `revisionlog_v2_signing` has `build_domain_revisionlog_v2` (v2 domain, `version "2"`) + the `AddDevice`/`RemoveDevice`/`Promote` struct-hashes — but NOT a `Revision` struct-hash under the v2 domain. The V1 `struct_hash`/`REVISION_TYPEHASH_V1` in `secp256k1_signing.rs` is **domain-independent** (it's just the typehash + the six fields; the domain only enters at `eip712_digest`). The V2 `Revision` typehash is **byte-identical** to V1's (`RevisionLogV2.sol:269-271` reuses the V1 typehash string verbatim) — so the *struct-hash* is reusable as-is; only the domain separator differs.
3. **The V1 production read path does NOT recover the signer.** `poll::verify_alloy_log` trusts the event's unindexed `signer` field (the contract's own `ecrecover` output at publish time), gated by the L4 contract-address pin + L3 chain-id pin; `verify_signer_or_reject` (the client-side L5 recover) is reachable only via test fixtures (the v1 event carries no inline signature bytes). The V2 event has the identical shape (no inline signature), so the V2 read path mirrors this: trust the event `signer` in production, expose a client-side recover helper for tests/defense-in-depth.
4. **`publish_revision_v1` is a library fn not yet wired to a production CLI flow.** The store's `publish.rs` queue still drives the v0 `ChainAdapter`/`SignedRevision` (Ed25519) path; `publish_revision_v1` + `build_signed_revision_v1` exist with the anvil E2E + calldata-pin tests but are not called from `apps/cli`. **Implication:** wiring the *publish* side end-to-end through the store's batch queue is a larger orthogonal lift than this slice. #106c2 should provide `publish_revision_v2` at the SAME library layer as `publish_revision_v1` (parity), and prove it via the anvil E2E — NOT rewrite the store publish queue. (Surfaced as Q-d.)
5. **The sync read path IS wired** (`Vault::sync_from_chain_with_ws_url` → `fetch_and_verify_chunk` / WS), and its checkpoint state lives in `chain_sync_v1_state` (single-row `id=0` table). The routing branch + a V2 checkpoint analogue are the load-bearing store-side changes.
6. **RevisionLogV2 is deployed on anvil/Dev** (via `scripts/anvil-ci.sh`, recorded in `contracts/deployments/dev.json` as `"RevisionLogV2"`), bound to the dev RecoveryV1; there is **no Base Sepolia V2 deploy yet** (`resolve_contract_address` carries a TODO for the pinned-address cross-check). The anvil E2E can run today; the testnet path stays a follow-up until a V2 testnet deploy + pinned `EXPECTED_REVISIONLOG_V2_ADDRESS_*` constant land.

---

## 1. Scope

**#106c2 builds:**

1. **The v1/v2 vault BINDING** (`pangolin-store`): a fixed per-vault `meta.revisionlog_version` column (INTEGER; `1` = V1, `2` = V2), written at `Vault::create`, defaulted to V1 for any legacy vault via an additive `migrate_revisionlog_version_column` (the established §18.7 pattern). A typed read accessor (`Vault::revisionlog_version()`) that maps absence → V1. This is the routing signal for the sync loop + the publish call site + (downstream) #106d's gate.
2. **The V2 revision PUBLISH digest** (`pangolin-chain::secp256k1_signing` or a thin `revisionlog_v2_signing` addition): a `Revision` struct-hash + EIP-712 digest under the **v2 domain** (`build_domain_revisionlog_v2`), byte-identical to `RevisionLogV2._hashRevision`. Reuses the V1 `struct_hash` (the typehash + field layout are identical) + `eip712_digest` + `is_canonical_s` verbatim; only the domain separator is the v2 one.
3. **`publish_revision_v2`** (`pangolin-chain::chain_submit` or `revisionlog_v2_client`): mirrors `publish_revision_v1` — build the revision fields, sign the v2 digest, broadcast to `RevisionLogV2.publishRevision` reusing the #106c `sol!` binding + the `chain_submit` EIP-1559 envelope/retry/gas/`resolve_envelope_chain_id` + the `process_receipt` cross-check (event `signer == wallet`).
4. **The V2 READ/verify path** (`pangolin-chain::chain_sync`): `fetch_and_verify_chunk_v2` (HTTP `eth_getLogs` of `RevisionLogV2.RevisionPublished` + the same per-event verify chain: vault-id topic cross-check, schema-version bound, contract-address pin, recovered/claimed-signer parity available for tests) + the V2 WS subscription path. Mirrors the V1 `poll`/`ws` submodules; reuses `VerifiedRevisionEvent`. Adds the `RevisionPublished` event to the V2 `sol!` binding (finding 0a-1).
5. **Routing** (`pangolin-store`): the binding branches `Vault::sync_from_chain_with_ws_url` (V2-bound vault reads via the V2 path + its own checkpoint; V1-bound vault keeps the V1 path verbatim) + the publish call site. A V2 checkpoint analogue (`chain_sync_v2_state`, or a `revisionlog_version`-keyed reuse of the existing state — see Q-e).
6. **The coupled anvil E2E** (the regression gate): deploy RevisionLogV2 → `bootstrapVault` → `publish_revision_v2` (signer in set) → `fetch_and_verify_chunk_v2` reads it back + verifies the digest/signer round-trip. Negatives (wrong domain version, tampered payload, foreign contract address) turn it RED.

**Deferred / out of scope (this slice) — confirm the boundary:**

- **The revocation / honor gate = #106d** (plan-LOCKED, PARKED). #106d reads ALL V2 revisions off this stream and applies the set-membership / lineage honor rule (the #103-C generalization). #106c2 just PRODUCES + READS the stream; it does **not** decide which revisions are honored beyond the existing V1-parity verification (contract-address pin + chain-id pin + the contract's own publish-time `ecrecover`). **Boundary confirmed: the gate is downstream (#106d).**
- **The pairing / device-add UX = #106c (merged) + #106e.** #106c2 assumes the vault is already bootstrapped + the publishing device is in the set (a contract precondition; a non-member publish surfaces as an `ErrSignerNotAuthorized` revert — fine).
- **Rewiring the store batch publish queue** (the v0 `ChainAdapter` → v2). `publish_revision_v2` lands at the library layer (parity with `publish_revision_v1`); end-to-end batch-queue integration is a separate orthogonal lift (finding 0a-4; Q-d).
- **Mainnet + a testnet V2 deploy + pinned `EXPECTED_REVISIONLOG_V2_ADDRESS_*`** — follow-up (finding 0a-6; Q-f).

---

## 2. Splittable? — recommendation: ONE #106c2 stage, optionally two PRs on one branch

The binding + publish + read + routing are mutually dependent and the anvil E2E (the value) can only assert end-to-end with publish AND read present. Splitting "publish-only" from "read-only" creates a half-wired intermediate with no meaningful test gate (you can't round-trip). **Recommend ONE logical stage**, optionally two reviewable PRs on one branch:

- **PR1 = the read/verify path + the binding + routing** (`RevisionPublished` added to the V2 binding, `fetch_and_verify_chunk_v2` + V2 WS, the `meta.revisionlog_version` column + migration + accessor, the `sync_from_chain_with_ws_url` branch + V2 checkpoint). Testable hermetically (decode fixtures) + against anvil (a manually-published V2 revision read back).
- **PR2 = `publish_revision_v2` + the v2 publish digest + the coupled publish→read anvil E2E.** Depends on PR1's read path to assert the round-trip.

The publish digest + `publish_revision_v2` are the net-new highest-care work (the byte-identity class); the read + binding + routing are mechanical mirrors. Surfaced as Q-g.

---

## 3. The end-to-end design

### 3.1 The v1/v2 vault binding (§18.7 additive column)

- **Where it lives:** a new `meta.revisionlog_version INTEGER` column (single-row `meta`, `id = 0`). Plaintext UX/routing state, not secret material — same posture as the existing `session_idle_secs` / `sync_mode_preference` additive `meta` columns.
- **Legacy default:** absence → V1. A vault created before #106c2 has no column; `migrate_revisionlog_version_column` (PRAGMA `table_info(meta)` guard, `ALTER TABLE meta ADD COLUMN revisionlog_version INTEGER`, no `format_version` bump) adds it NULL on next open; `Vault::revisionlog_version()` maps NULL → `V1`. **Behaviour is byte-identical for a legacy vault opened post-#106c2** (it still routes to the V1 path).
- **Who writes it + when:** `Vault::create` seeds it. **Default for NEW vaults — Q-a (the load-bearing decision):** recommend NEW vaults are created **V1** until the testnet V2 deploy + pinned address land (finding 0a-6), so #106c2 lands with zero behavioural change on the production testnet path and the V2 path is exercised only on anvil/Dev + explicit opt-in. (The alternative — new vaults default V2 — is premature without a pinned testnet V2 address and a wired publish queue.) The column value is set in `meta::write`'s INSERT (or left NULL = V1 if Q-a picks "V1 default", since absence already means V1 — recommend writing the value explicitly for new vaults so the routing signal is unambiguous).
- **`.pvf` migration:** purely additive; a legacy vault gains a NULL column → reads as V1 → identical behaviour. No data rewrite, no re-encryption, no `format_version` bump (§18.7 ladder). Belt-and-suspenders migration helper mirrors `migrate_sync_mode_preference_column`.

### 3.2 The V2 revision publish path (`publish_revision_v2`, mirror of `publish_revision_v1`)

- **The digest (byte-identity — LOAD-BEARING).** `RevisionLogV2._hashRevision` (`RevisionLogV2.sol:958-978`) uses the SAME `REVISION_TYPEHASH` body as V1 (`:269-271`, verbatim) over the same six fields (`vaultId, accountId, parentRevision, deviceId, schemaVersion, encPayloadHash`), under the v2 DOMAIN_SEPARATOR (`name "Pangolin RevisionLog"`, `version "2"`). So the client reuses `secp256k1_signing::struct_hash` + `REVISION_TYPEHASH_V1` UNCHANGED (the struct-hash is domain-independent), and only swaps the domain at the final `eip712_digest` step — passing `build_domain_revisionlog_v2(contract, chain_id).separator()` instead of the v1 separator. A new pinned `REVISION_TYPEHASH_V2` constant is NOT needed (it equals V1's); a v2 *digest* helper (`revision_v2_digest`) IS, threading the v2 domain. Pin it with a `hashRevision` parity-oracle round-trip against the deployed V2 contract (the contract exposes `hashRevision` as a `view` — `RevisionLogV2.sol:863`).
- **The fields.** Reuse `RevisionFieldsV1` verbatim (Path B `device_id` = left-padded EVM address; `enc_payload_hash = keccak256(encPayload)`; the broadcast invariant `keccak256(enc_payload) == fields.enc_payload_hash` from `SignedRevisionV1`). The struct shape is identical across v1/v2; only the signing domain differs. Recommend a `SignedRevisionV2` newtype (or reuse `SignedRevisionV1` parameterised) — see §3.5.
- **The broadcast.** Reuse the #106c `sol!` `RevisionLogV2::publishRevisionCall` (already in the binding) + `chain_submit`'s EIP-1559 envelope, gas cap, R-c retry taxonomy, `resolve_envelope_chain_id` (#101), `process_receipt` (status==1, `RevisionPublished` log present, event `signer == wallet`). The contract gates on set-membership; a publish by a non-member device reverts `ErrSignerNotAuthorized` (a contract precondition, surfaced as a fatal revert — no retry). The pre-publish balance gate (`PublishConfig`) carries over.

### 3.3 The V2 read/verify path (`fetch_and_verify_chunk_v2` + V2 WS, mirror of V1)

- **Add `RevisionPublished` to the V2 binding** (finding 0a-1): one `event RevisionPublished(uint256 indexed sequence, bytes32 indexed vaultId, bytes32 indexed accountId, bytes32 parentRevision, bytes32 deviceId, uint16 schemaVersion, bytes encPayload, address signer)` — byte-aligned to `RevisionLogV2.sol:107-116`, field-identical to V1. (The DIFFERENT v2 domain gives it a different topic-0 from V1, which is correct: a v1 reader must never consume v2 events and vice-versa.)
- **HTTP poll** (`fetch_and_verify_chunk_v2`): mirror `poll::fetch_chunk` / `verify_alloy_log` — `eth_getLogs` filtered by the V2 contract address + `RevisionLogV2::RevisionPublished::SIGNATURE_HASH` + indexed `vaultId` topic1; per-log decode + (1) address pin, (2) vault-id topic cross-check, (3) schema-version bound, (4) anchor materialisation, producing `VerifiedRevisionEvent` (reused). Production trusts the event `signer` (the contract's publish-time `ecrecover`); the client-side L5 recover helper (`recover_signer_v2_raw`, under the v2 domain) is exposed for the test/defense-in-depth path exactly as V1's `verify_signer_or_reject` is.
- **WS** (`ws_v2`): mirror the V1 `ws` submodule — `eth_subscribe("logs")` with the V2 filter, calling the SAME `verify_alloy_log_v2` helper so HTTP + WS verification is byte-identical (the #99 L2 lesson).
- **Contract-address resolution.** Reuse `revisionlog_v2_client::resolve_contract_address` (its TODO for the BaseSepolia pinned-address cross-check carries forward — Q-f). For Dev/anvil it reads `dev.json`'s `RevisionLogV2`.

### 3.4 Routing the sync loop + the publish call site by the binding

- **Sync read.** `Vault::sync_from_chain_with_ws_url` branches at the top on `self.revisionlog_version()`: V1 → the existing path verbatim (no regression — the V1 path is untouched); V2 → the V2 backfill (`fetch_and_verify_chunk_v2`) + V2 WS, advancing the V2 checkpoint. The two branches share the ingest/reorg/finalize machinery (`ingest_pending_chain_revision`, `detect_reorg_via_rpc`, `promote_finalized_revisions`) — only the chunk-fetch + WS-subscribe + checkpoint-state differ. Recommend extracting the shared loop body so the V2 branch reuses it (the byte-identity-of-verification + reorg posture must not drift between paths).
- **Publish.** `publish_revision_v2` is selected at the call site by the binding. Since the store publish queue is not yet wired to either v1 OR v2 (finding 0a-4), the routing at the *publish* call site is realised in the anvil E2E + whatever thin call site uses `publish_revision_v2` directly; the full queue wiring is downstream (Q-d).
- **The V1 path is touched ZERO** beyond the routing branch entry — the L-no-regression invariant.

### 3.5 Mirror-verbatim vs refactor-to-generic — RECOMMENDATION

The V1 and V2 paths differ ONLY in (a) the EIP-712 domain version and (b) the contract address/binding; the field layout, typehash body, struct-hash, digest construction, recover, retry envelope, event shape, and verify chain are all identical. Two options:

- **(A) Verbatim V2 twin** — copy `publish_revision_v1` → `_v2`, `fetch_and_verify_chunk` → `_v2`, etc., swapping the domain + binding. Zero risk of v1↔v2 domain leak (each path hard-codes its own domain); higher line count + drift risk between twins.
- **(B) Thin generic parameterised by domain-version + contract** — one publish/read core taking the domain separator + the `sol!` binding (or a contract-version enum) as a parameter. Less code; but a shared generic risks the **v1 vs v2 domain leaking** (the silent-and-total #103 L2/L3 class — if the wrong domain is threaded, every signature recovers the wrong signer / every read consumes the wrong topic-0, and it fails silently).

**Recommendation: a hybrid leaning to (A) for the digest, (B) for the plumbing (Q-c).** Keep the digest/domain selection EXPLICIT and per-version (a `RevisionDomain::{V1,V2}` enum that owns its `build_domain` + separator, never inferred) so the byte-identity boundary is unmistakable and pinned per-version; but share the envelope/retry/event-decode plumbing (which is domain-agnostic) parameterised by the contract address + the binding. This minimises duplication of the mechanical parts while keeping the load-bearing domain selection loud, typed, and independently pinned per version. The L-invariant (L2 below) forbids the generic core from ever defaulting or inferring the domain.

---

## 4. L-invariants (L1..L13)

- **L1 (reuse, no rewrite).** Reuse `chain_submit` envelope/retry/gas/`process_receipt`, `secp256k1_signing::{struct_hash, eip712_digest, is_canonical_s, REVISION_TYPEHASH_V1}`, `revisionlog_v2_signing::build_domain_revisionlog_v2`, the #106c `RevisionLogV2` `sol!` binding, `chain_sync`'s `VerifiedRevisionEvent`/reorg/ingest. The V1 publish + read paths stay BYTE-IDENTICAL (no edits beyond the routing branch entry). New files/symbols only for the v2 twin + the binding column.
- **L2 (V2 revision EIP-712 digest byte-identity — LOAD-BEARING, the #103 L2/L3 silent-and-total class).** The client `revision_v2_digest` MUST equal `RevisionLogV2._hashRevision` (`:958-978`) byte-for-byte: V1 typehash body verbatim, v2 domain (`"Pangolin RevisionLog"`/`"2"`/chainId/verifyingContract), `\x19\x01` envelope. Pinned by (a) a `hashRevision` parity-oracle round-trip against the deployed V2 contract in the anvil E2E, and (b) a hermetic domain-separator pin for the v2 domain. A mismatch = every V2 publish recovers a wrong signer → `ErrSignerNotAuthorized` on every live publish (silent + total). The shared generic (§3.5) MUST NOT infer/default the domain.
- **L3 (canonical-low-s / v∈{27,28} / reject signer==0).** Reuse `is_canonical_s` + the `recover_address_from_prehash` posture verbatim on both sign + recover; reject high-s, `v∉{27,28}`, `signer == address(0)` — symmetric with the contract's `_recover` (`:1023-1047`).
- **L4 (chain-id binding).** Reuse #101 `resolve_envelope_chain_id` verbatim: BaseSepolia pinned + RPC cross-check; Dev reads the live anvil id; production never sources signing/envelope chain id from an untrusted RPC.
- **L5 (read-side verification).** The V2 read trusts the event `signer` (contract publish-time `ecrecover`) gated by the L4 chain-id pin + the V2 contract-address pin; the client-side recover (`recover_signer_v2_raw`) is the test/defense-in-depth arm (V2 events carry no inline signature — V1 parity, finding 0a-3). Vault-id topic cross-check + schema-version bound (`> MAX_KNOWN_CLIENT_SCHEMA_VERSION` rejected) on every event.
- **L6 (the binding routes correctly + V1 path untouched / no regression).** A V2-bound vault publishes/reads via the V2 path; a V1-bound vault keeps the V1 path verbatim. Legacy vault (NULL column) → V1. Asserted by a routing test + the V1 suite staying green unchanged.
- **L7 (additive schema / migration — §18.7).** `meta.revisionlog_version` is additive; `PRAGMA table_info` guard; no `format_version` bump; legacy → NULL → V1. Idempotent migration test (mirror `migrate_sync_mode_preference_column_*`).
- **L8 (reuse RevisionLogV2 — NO contract change, NO new deps).** Adds only the `RevisionPublished` event to the existing `sol!` binding; alloy provides keccak/sol!/EIP-712/secp256k1. `cargo deny` / `cargo audit` likely ZERO new advisories.
- **L9 (schema-version ladder).** Every V2 publish passes `schemaVersion = REVISIONLOG_V2_SCHEMA_VERSION` (= 1); reject `> MAX_KNOWN_SCHEMA_VERSION` symmetrically (the contract does too).
- **L10 (`pangolin-chain` has no `pangolin-store` dep).** cargo-tree guard green; signing/digest are sync-safe pure fns; the binding column + routing live store-side.
- **L11 (anvil E2E = regression gate).** deploy → `bootstrapVault` → `publish_revision_v2` (in set) → `fetch_and_verify_chunk_v2` reads it back + verifies the round-trip; negatives (wrong domain version, tampered `encPayload`, foreign contract address, non-member publisher) turn it RED. Wired into `anvil-ci.sh` beside the #106c lifecycle test.
- **L12 (testnet-only / D-011).** No mainnet; the testnet V2 path stays a follow-up until a Base Sepolia V2 deploy + pinned `EXPECTED_REVISIONLOG_V2_ADDRESS_*` land (Q-f).
- **L13 (`forbid(unsafe_code)` + AGPL SPDX on every new file; §16 ledger; `git merge --no-ff`; explicit Kelvin approval at merge; full `cargo test --workspace` gate — the #106b-1 lesson).**

---

## 5. Test posture

Centerpiece: the anvil publish→read E2E (real v2 EIP-712 sig accepted by the live `publishRevision` set-gate + real `RevisionPublished` read back + the digest/signer round-trip + negative gates). Hermetic byte-pins: the v2 domain separator, the v2 revision digest vs the contract `hashRevision` oracle, sign+recover round-trip under the v2 domain, the V2 `RevisionPublished` topic-0 distinct from V1's, the migration idempotency + legacy-NULL→V1 default, the routing branch. The v2 digest byte-identity is the load-bearing client property for the RevisionLogV2 external audit (D-011). Full `cargo test --workspace`.

## 6. Effort + risk

~1.5–2.5 weeks. The read/verify path + binding + routing are mechanical mirrors of merged code (lower risk). The v2 publish digest + `publish_revision_v2` are the net-new highest-care work — silent+total if the domain is wrong (the #103 L2/L3 class). The anvil round-trip is the structural defense. Main residual risk: the §3.5 generic-vs-twin choice (Q-c) — a shared core must never let the v1/v2 domain leak.

---

## 7. Open questions (each: recommendation + plain-English stakes)

- **Q-a — Default `revisionlog_version` for NEW vaults: V1 or V2?** *Recommend V1* until a Base Sepolia V2 deploy + pinned address land (the V2 path is exercised on anvil/Dev + explicit opt-in only). **Stakes:** if new vaults default V2 now, they'd try to publish to a contract that has no production testnet deployment + no wired publish queue — they'd be unable to sync on the real testnet. V1-default = zero behavioural change on landing; flip to V2 in a follow-up once the deploy + queue exist.
- **Q-b — Column shape: a plain `revisionlog_version INTEGER` (1/2), or an enum-backed TEXT?** *Recommend INTEGER (1/2), NULL→1.* **Stakes:** matches the contract's own version numbering + the simplest migration; an INTEGER is unambiguous and cheap. (TEXT would mirror `sync_mode_preference` but buys nothing here.)
- **Q-c — §3.5 mirror-verbatim vs generic.** *Recommend the hybrid: explicit per-version domain selection (a typed `RevisionDomain` enum, never inferred), shared domain-agnostic plumbing.* **Stakes:** a fully-shared generic risks silently threading the wrong domain (every signature/read breaks, invisibly — the worst failure class); a full verbatim twin is safe but doubles the surface to keep in sync. The hybrid keeps the dangerous part loud + pinned and shares only the safe mechanical parts.
- **Q-d — Does #106c2 wire `publish_revision_v2` into the store batch publish queue, or stop at the library layer + anvil E2E?** *Recommend stop at the library layer (parity with `publish_revision_v1`, which is itself not queue-wired) + prove via the E2E.* **Stakes:** the store queue still drives the v0 `ChainAdapter`/Ed25519 path (finding 0a-4); rewiring it to secp256k1-v2 is a large orthogonal lift that would balloon this slice. Defer the queue cut-over (likely with or after #106d).
- **Q-e — V2 sync checkpoint: a new `chain_sync_v2_state` table, or reuse `chain_sync_v1_state` keyed by version?** *Recommend a new `chain_sync_v2_state` single-row table* (additive, mirrors `chain_sync_v1_state`), so a vault that ever held both never cross-contaminates cursors + the V1 state is untouched. **Stakes:** sharing one checkpoint risks a V2 cursor being read by the V1 path (or vice-versa) and replaying/skipping events; a separate table is the clean, no-regression choice.
- **Q-f — Testnet V2 deploy + pinned `EXPECTED_REVISIONLOG_V2_ADDRESS_BASE_SEPOLIA` + v2 domain-separator constant: in #106c2 or a follow-up?** *Recommend follow-up* — #106c2 lands on anvil/Dev; the testnet pin + cross-check (mirroring the V1/RecoveryV1 posture, the existing `resolve_contract_address` TODO) lands once a real V2 testnet deploy exists. **Stakes:** pinning a non-existent address now would be dead/rotting config (the env-quirk #14 class); gate it on the actual deploy.
- **Q-g — Two PRs on one branch, or one PR?** *Recommend two PRs on one branch* (PR1 read+binding+routing; PR2 publish-digest + `publish_revision_v2` + coupled E2E) per §2. **Stakes:** smaller reviewable units; PR1 is mostly mechanical mirror (fast review), PR2 isolates the load-bearing digest work for careful audit. One branch keeps the coupled E2E intact.
- **Q-h — Confirm the #106d boundary.** *Recommend confirm: #106c2 produces+reads the V2 stream with V1-parity verification (contract+chain-id pins + the contract's publish-time ecrecover); #106d adds the set-membership/lineage HONOR gate on top.* **Stakes:** if #106c2 tried to fold the honor gate it would re-scope into the parked #106d work; keeping the gate strictly downstream is what made splitting this slice out worthwhile.

---

## 8. Confirmed gaps where the merged code doesn't cleanly support a V2 data-plane

1. **`RevisionPublished` event missing from the V2 `sol!` binding** (0a-1) — must be added for the read path. One event, byte-aligned to the contract; low risk.
2. **No v2 revision-publish digest** (0a-2) — must thread the v2 domain through the (reusable, domain-independent) V1 struct-hash. The typehash is identical to V1's, so no new typehash constant; a v2 digest helper + a v2 domain-separator pin are needed.
3. **`publish_revision_v1` (and therefore `_v2`) is not wired to the store publish queue** (0a-4) — `publish_revision_v2` lands at the library layer; full queue integration is downstream (Q-d). NOT a blocker for the data-plane + the E2E, but flag it: there is no production CLI flow that calls either publish fn today.
4. **No Base Sepolia V2 deploy / pinned address** (0a-6) — the testnet path is a follow-up (Q-f); anvil/Dev is fully supported today.

These are all additive + mechanical except (2), which is the load-bearing byte-identity work guarded by L2 + the anvil oracle round-trip.
