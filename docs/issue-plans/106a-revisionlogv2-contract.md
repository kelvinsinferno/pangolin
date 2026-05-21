<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Issue #106a — RevisionLogV2 contract (`RevisionLogV2.sol`) — plan-gate LOCKED

**Status: LOCKED — Kelvin sign-off 2026-05-21 (see §0a). Q-a..Q-k resolved.** First slice of the multi-device epic (#106). NEW
security-critical on-chain contract (same tier as RecoveryV1 / RevisionLogV1; D-011 external-audit
package). TESTNET-ONLY until D-011.
**Base tip: main `8b2878f`** (#106 architecture LOCKED 2026-05-21; #102 RecoveryV1 `97cbe4c` /
deployed-immutable; RevisionLogV1 D-017 deployed-immutable). Implements #106 §0a row "#106a RevisionLogV2
contract" (Whitepaper §F device enrollment/revocation; Key & Authority Model diagram).

## 0a. RESOLVED decisions (Kelvin sign-off 2026-05-21)

- **Q-a (CRUX) → Option B: RevisionLogV2 owns its own `deviceManager` pointer** (seeded from RecoveryV1 `vaultAuthority` at genesis, re-aligned after `RecoveryFinalized`). All device add/remove/promote lives in THIS one contract — survivor-promotion needs NO RecoveryV2. #106a stays self-contained. The honor rule stays on the device SET (not on either authority), so manager↔authority drift can never silently honor a wrong signer.
- **Q-c → promotion delay = 48h** (a fixed contract constant). Shorter than the 72h guardian-recovery delay because promotion ALSO requires the promoting device's own biometric. The cancel/veto window before `finalizePromotion` is valid.
- **Q-b → asymmetric: ONE `deviceManager`** (primary), other devices are authorized publishers; only the manager mutates the set.
- **Q-d → EIP-712 recovered-signer + per-vault `deviceNonce`** for addDevice/removeDevice/promotion (NOT `msg.sender` — relayer-friendly, matches the V1 R-a Path B model). Reject signer==address(0), canonical-low-s, v∈{27,28}.
- **Q-e → forbid removing the last / the manager device (no-brick).** The contract is immutable; a brick is unrecoverable.
- **Q-f → explicit `bootstrapVault` (once-only genesis):** seed `deviceManager` from RecoveryV1 `vaultAuthority` if set, else the first signer; prevents a publish racing the set.
- **Q-g → new-vaults-only; NO V1→V2 migration logic.** RevisionLogV1 stays deployed/immutable.
- **Q-h → cross-read RecoveryV1 `vaultAuthority` via staticcall** (pinned immutable RECOVERY_V1 address). One authority concept; closes #103-C GAP FLAG 2.
- **Q-i → `MAX_DEVICES` ≈ 32** (bounds off-chain set-fold DoS).
- **Q-j → new EIP-712 domain, version "2"** (V1 sigs can never replay against V2).
- **Q-k → manager re-aligns with recovery via LIVE-READ** (staticcall `vaultAuthority` at the manager-auth check) for zero drift, accepting a staticcall per set-mutation.

Cardinal rules HONORED (no admin/owner/upgrade/pause/selfdestruct/delegatecall/receive/fallback; EIP-712 + ecrecover canonical-s; custom errors; bug→redeploy). Build: §16 builder→adversarial audit→merge; forge unit + invariant tests (10k×N) + anvil device-add/remove/publish-gate/promotion lifecycle with negative arms.

## Scope — contract-only

#106a is `contracts/src/RevisionLogV2.sol` ONLY (+ its forge tests, ABI, deploy script). The client
device-add flow (#106c), the VDK-handoff crypto (#106b), and the read-side revocation generalisation
(#106d) are separate sub-issues that build calldata for / read events from this contract — so the
surface must lock first. Per #106 §2: #106a is the foundation everything binds to, self-contained and
testable on the existing #101 anvil harness, and forces the load-bearing authority decisions (Q-a/Q-d/
Q-h) to be made before the crypto + client are built against a frozen model.

**The contract is the on-chain device-registry + authorized-SET + revision-publish gate ONLY.** Per-device
keys, sealed-box VDK pairing, and the daily wrap model are CLIENT/crypto concerns (#106b/#106c) and never
appear on chain. The contract NEVER touches the VDK or any secret (inherits RecoveryV1 L12) — there is no
slot a key could live in.

**NET-NEW vs RevisionLogV1.** V1 self-bootstraps exactly the first publisher per vault
(`registeredDeviceCount == 0` → register, else `ErrSignerNotRegistered`) with NO add path, NO removal, NO
authority binding. V2 replaces that single-bootstrap gate with a **live authorized-device SET** governed
by the vault authority (`addDevice` / `removeDevice`) plus a survivor-promotion entrypoint, and binds
RecoveryV1's `vaultAuthority` cross-contract. Everything else — the EIP-712 `Revision` signing
(`_hashRevision`/`_recover`), the `publishRevision` shape, the global sequence counter, the
custom-error/`schemaVersion` discipline, all cardinal rules — is reused from V1 verbatim, retargeted to a
new EIP-712 domain (`version = "2"`).

## Authority model (the load-bearing reconciliation)

Per `pangolin_recovery_model.md` the on-chain control plane is a single secp256k1 `vaultAuthority`,
**owned by RecoveryV1** and rotated ONLY by (1) `setGuardianSet` self-bootstrap (`msg.sender` at genesis)
and (2) `finalizeRecovery` (guardian quorum + 72h delay). **There is NO "an authorized device promotes
itself" path in the deployed, immutable RecoveryV1.** This is the crux #106a must resolve (see THE CRUX
below): the locked architecture's survivor-promotion requires changing who the authority is *without*
guardians, which the deployed RecoveryV1 cannot express.

```
RevisionLogV1 (D-017, immutable)            RecoveryV1 (97cbe4c, immutable)
  isRegisteredDevice (single bootstrap)       vaultAuthority[vaultId]  (genesis=msg.sender;
  no add / no remove / no authority             rotated only by finalizeRecovery)
        │                                                   │
        └──────────────── superseded by ──────────┐        │ cross-read (staticcall)
                                                   ▼        ▼
                                       RevisionLogV2 (NEW, immutable)
                                         authorizedDevice[vaultId][signer] = bool   (the SET)
                                         publishRevision: honor iff signer ∈ SET
                                         addDevice / removeDevice: gated by vaultAuthority
                                         promoteSurvivor: see THE CRUX (Q-a)
```

## THE CRUX — survivor-promotion vs the immutable RecoveryV1 (resolve before build)

The locked architecture (#106 §0a "Trust model") requires: if the PRIMARY is lost, any SURVIVING device
can promote itself to primary — gated by biometric + a short delay + a heads-up — **WITHOUT full guardian
recovery**, then revoke the lost primary. "Becoming primary" means becoming the thing that may add/remove
devices. There are three ways to realise this:

- **Option A — device-management authority IS RecoveryV1's `vaultAuthority` (strict cross-bind).**
  `addDevice`/`removeDevice` are gated by `RecoveryV1.vaultAuthority(vaultId)`. Clean: one authority
  concept; recovery rotation automatically re-points who manages devices. BUT survivor-promotion
  (rotating the authority without guardians) is **NOT supported by the deployed RecoveryV1** — its only
  rotation path is the guardian flow. So promotion would need a **RecoveryV2** (or a separate
  authority-rotation contract) adding a self-promotion path (an authorized device rotates the authority
  to itself, gated by a delay + a cancel-by-current-authority window). **This pushes promotion OUT of
  #106a into a recovery-side change → #106a no longer self-contained, and promotion slips a sub-issue.**

- **Option B — V2 maintains its OWN device-management authority (RECOMMENDED).** V2 holds a per-vault
  `deviceManager[vaultId]` (the "primary" signer). add/remove/promote are governed entirely inside V2:
  a survivor self-promotes within V2's set (delay + cancelable by the current manager). The manager is
  *seeded* from RecoveryV1's `vaultAuthority` at genesis (one authority at birth) and *re-aligned* to
  RecoveryV1's authority whenever a guardian recovery finalizes (the reader/contract observes the new
  authority). Looser coupling than A; the risk is two authority notions drifting — mitigated by L-bind
  (genesis seed + recovery re-alignment) and by keeping the *honor* rule on the SET, not on either
  authority directly. **Keeps #106a fully self-contained; no RecoveryV2 needed for v1 of the epic.**

- **Option C — hybrid: A for the normal case, an in-V2 promotion escape hatch.** add/remove gated by
  RecoveryV1's `vaultAuthority`; promotion is an in-V2 path that, on success, sets an internal
  `localManagerOverride[vaultId]` that takes precedence until the next guardian finalize. Most faithful
  to "one authority" in steady state but introduces a second precedence rule (override vs cross-read) —
  the worst auditability of the three.

**Recommendation: Option B**, with the manager seeded at genesis from `vaultAuthority` and re-aligned on
each `RecoveryFinalized`. Rationale: it is the ONLY option that keeps survivor-promotion (a LOCKED
requirement) inside #106a without forcing a RecoveryV2 redeploy of an already-audited immutable contract;
it confines all device-set mutation to ONE contract (one audit surface); and the honor rule stays on the
SET so a manager-vs-authority disagreement can never silently honor a wrong signer. The cost (two
authority notions) is bounded by binding them at the only two moments either can change (genesis,
recovery-finalize) and is far cheaper than a RecoveryV2. **If Kelvin wants strict single-authority
(Option A), #106a's scope shrinks to add/remove only and a RecoveryV2 self-promotion design becomes a new
blocking sub-issue (#106a-bis) ahead of promotion.** This is the single scope-determining call.

## Proposed surface (final shape rides on the Q's)

Storage (slot layout documented per L7):
- `mapping(bytes32 vaultId => mapping(address signer => bool)) authorizedDevice` — the live SET (honor
  source of truth).
- `mapping(bytes32 vaultId => uint32) authorizedDeviceCount` — set size (drives genesis bootstrap +
  the no-brick floor; bounds DoS, Q-i).
- `mapping(bytes32 vaultId => address) deviceManager` — the "primary" (Option B). Seeded at genesis,
  re-aligned on recovery-finalize, rotated by `promoteSurvivor`.
- `mapping(bytes32 vaultId => uint64) deviceNonce` — monotonic per-vault nonce binding each
  add/remove/promote signature to one action (anti-replay, Q-d).
- `mapping(bytes32 vaultId => Promotion) pendingPromotion` — `{ address candidate; uint64 readyAt; }`
  for the survivor-promotion delay/veto window (Q-c).
- `uint256 _nextSequence` — global revision counter (verbatim from V1).
- `address immutable RECOVERY_V1` — pinned RecoveryV1 address (constructor arg; the one configurable
  field, justified by the cross-bind, Q-h).
- `bytes32 immutable DOMAIN_SEPARATOR` — `name="Pangolin RevisionLog", version="2"` (Q-j).

External functions:
- `publishRevision(vaultId, accountId, parentRevision, deviceId, schemaVersion, encPayload, signature)`
  → V1's body, EXCEPT the gate is "recovered signer ∈ `authorizedDevice[vaultId]`" (no self-bootstrap;
  the set is established by `bootstrapVault`/genesis, Q-f).
- `bootstrapVault(vaultId, firstSigner, schemaVersion, signature)` (Q-f) — establishes the genesis
  authorized device + seeds `deviceManager` from `RecoveryV1.vaultAuthority(vaultId)` if set, else from
  the recovered signer. Once-only per vault.
- `addDevice(vaultId, newSigner, nonce, schemaVersion, authoritySig)` — adds `newSigner` to the set iff
  `authoritySig` recovers to the current device manager over `AddDevice(vaultId,newSigner,nonce,...)`
  (Q-d recovered-signer model, matching V1; NOT `msg.sender`).
- `removeDevice(vaultId, signer, nonce, schemaVersion, authoritySig)` — removes iff manager-signed AND
  the no-brick guard holds (cannot remove the last device / the manager itself, Q-e).
- `proposePromotion(vaultId, candidate, nonce, schemaVersion, candidateSig)` + `finalizePromotion(
  vaultId, schemaVersion)` — survivor-promotion two-step: any current set member proposes itself,
  starts a `PROMOTION_DELAY` clock; the current manager may `cancelPromotion` during the window; after
  the delay anyone may finalize → `deviceManager` rotates to the candidate (Q-a Option B / Q-c).
- View digest oracles `hashAddDevice` / `hashRemoveDevice` / `hashPromote` + `domainSeparator()` +
  `_recover` copied VERBATIM from RevisionLogV1:405 (len-65, v∈{27,28}, canonical-low-s, reject
  signer==address(0)).

Events (each carries `uint16 schemaVersion`):
- `RevisionPublished(...)` — verbatim from V1 (new domain → different topic-0, correct).
- `DeviceAdded(bytes32 indexed vaultId, address signer, address manager, uint64 nonce, uint16 sv)`.
- `DeviceRemoved(bytes32 indexed vaultId, address signer, address manager, uint64 nonce, uint16 sv)`.
- `PromotionProposed(bytes32 indexed vaultId, address candidate, uint64 readyAt, uint16 sv)` — the
  event the client watches for the "notify your other devices" heads-up (locked-arch requirement).
- `PromotionFinalized(bytes32 indexed vaultId, address oldManager, address newManager, uint16 sv)`.
- `PromotionCanceled(bytes32 indexed vaultId, address candidate, uint16 sv)`.
- `VaultBootstrapped(bytes32 indexed vaultId, address firstSigner, address manager, uint16 sv)`.
  Readers fold the current set from `DeviceAdded`/`DeviceRemoved`/`VaultBootstrapped` (+ manager from
  the promotion/bootstrap events) — mirrors how #103-C folds the authority lineage.

Custom errors (revert-on-failure, no event on failure, state writes AFTER all checks):
`ErrInvalidSignature`, `ErrSignerNotAuthorized` (publish gate), `ErrNotDeviceManager` (add/remove auth),
`ErrAlreadyAuthorized` / `ErrNotAuthorized` (add/remove target state), `ErrVaultAlreadyBootstrapped`,
`ErrVaultNotBootstrapped`, `ErrWouldBrickVault` (no-brick guard, Q-e), `ErrNotSetMember` (promotion
candidate must be in the set), `ErrPromotionPending` / `ErrNoPromotionPending`, `ErrPromotionDelayNotElapsed`,
`ErrNotAuthorizedToCancel` (promotion cancel = current manager only), `ErrBadNonce` (anti-replay),
`ErrSetSizeExceeded` (Q-i bound), `ErrUnsupportedSchemaVersion`, `ErrZeroValue`.

## L1..Ln invariants

- **L1** New file/contract/deployment; RevisionLogV1 (D-017) + RecoveryV1 (97cbe4c) untouched + unmoved.
  New-vaults-only — NO V1→V2 migration logic in the contract (Q-g).
- **L2 (cardinal rules verbatim).** No admin / owner / role / multisig; no upgrade / proxy /
  `selfdestruct` / `delegatecall`; no pause/freeze; no `receive`/`fallback`; non-payable. The N-selector
  admin probe extends V1's with V2-specific forbidden selectors (`setManager`/`forceAddDevice`/
  `forceRemoveDevice`/`adminPromote`/`pause` — all MUST be absent). Bug → deploy V3, never patch (D-011).
  add/remove/promote are SELF-SOVEREIGN authority-gated mutations, NOT admin paths (the user's own
  authority signs them).
- **L3** solc 0.8.24 exact-pin, `evm_version=shanghai`, no Base-specific opcodes, `ecrecover` precompile
  only (L1-viable).
- **L4** Path B EIP-712 v4 + `_recover` discipline verbatim (len-65, v∈{27,28}, canonical-low-s, reject
  signer==address(0)); `DOMAIN_SEPARATOR` bakes chainId + `address(this)` + version `"2"`.
- **L5** `uint16 schemaVersion` on every event, starts 1, `MAX_KNOWN_SCHEMA_VERSION=1`, future-version
  reverts (§18.7 ladder). A V2 signature can never replay against V1 and vice-versa (distinct domain).
- **L6** Revert-on-failure; no event on failure; state writes AFTER all revertable checks; per-vault
  nonce bumps only on success.
- **L7** Documented storage-slot layout; field widths future-proofed (`uint64` nonces/timestamps,
  `uint32` count) so a V3 isn't forced just to add a field.
- **L8 (only the current authorized SET is honored — LOAD-BEARING).** `publishRevision` ingests iff the
  recovered signer ∈ `authorizedDevice[vaultId]`. A former manager, never-added device, or removed
  device is rejected. This is the property the D-011 audit signs off; a regression must turn the anvil
  gate (L13) red.
- **L9 (only the device manager mutates the SET — LOAD-BEARING).** `addDevice`/`removeDevice` succeed
  iff the recovered authority signature is the current `deviceManager`. No peer-add (Q-b), no admin key.
  A rogue non-manager device cannot add/remove another.
- **L10 (no-brick).** `removeDevice` reverts (`ErrWouldBrickVault`) if it would drop the set below 1
  device OR remove the current `deviceManager` (the manager must promote/replace before stepping down,
  Q-e). The set can never be emptied; the vault is never un-manageable.
- **L11 (survivor-promotion is delayed + vetoable).** `proposePromotion` only starts a clock; the
  current manager may `cancelPromotion` for the full `PROMOTION_DELAY`; rotation happens only via
  `finalizePromotion` after the delay. The candidate MUST already be in the authorized set
  (`ErrNotSetMember`) — a non-device cannot promote itself. (Biometric gating is CLIENT-side, #106c; the
  contract enforces the on-chain delay + set-membership + veto only.)
- **L12 (the contract NEVER touches the VDK or any secret).** Inherits RecoveryV1 L12 verbatim — no
  `bytes` key blob, no ciphertext, no share. The set is addresses + flags only.
- **L13 (anvil device-add + revoke + promote regression gate = CI gate).** Deploy V2 + RecoveryV1 →
  bootstrap A (manager) → `addDevice(B)` manager-signed → publish from A and B → assert both honored →
  `removeDevice(B)` → assert B revoked, A honored → simulate primary loss: `proposePromotion(B)` →
  `evm_increaseTime` past `PROMOTION_DELAY` → `finalizePromotion` → assert B is manager → `removeDevice(A)`
  → assert A revoked. Negative arms: a broken predicate ("honor all signers" / "ignore the set") MUST
  flip the gate red (env-quirk #14 class); finalize-before-delay reverts; non-manager add reverts.
- **L14 (EIP-712 byte-identity for the client).** The `AddDevice`/`RemoveDevice`/`Promote` typehash bodies
  match the off-chain signer (`pangolin-chain` device-signing) byte-for-byte; `hashAddDevice` etc. are
  parity oracles the client cross-checks (the env-quirk #14 anvil-domain-mismatch class is the canonical
  failure to guard).
- **L15 (cross-bind chain-id + pinned address).** The `RECOVERY_V1` immutable + the
  `staticcall RecoveryV1.vaultAuthority(vaultId)` reuse #101 L4 chain-id pinning + the 4.1 pinned-address
  cross-checks; production never sources the binding chain-id from an untrusted RPC. The cross-read is a
  `staticcall` (no state change, no reentrancy surface).
- **L16 (set-size bound).** `authorizedDeviceCount` is capped (`MAX_DEVICES`, Q-i — suggest 32) so the
  off-chain set-fold + any future on-chain enumeration cannot be griefed unboundedly.
- **L17 (testnet-only until D-011).** V2 stays Base-Sepolia-only until the external audit clears (mirrors
  the whole recovery/multi-device track). A D-0xx DECISIONS row records the V2 testnet address at deploy.
- **L18 (§16 ledger).** Ship contract + forge tests + `DeployRevisionLogV2.s.sol` + `abi/RevisionLogV2.json`
  + CI (forge build/test, ABI-drift, slither, no-admin selector probe); `git merge --no-ff`; DECISIONS.md
  Q-resolution entries; explicit Kelvin approval at the merge boundary (§16.3).

## Forge invariants (10k×N, mirror #102's 10k×32)

`onlyCurrentSetHonored`, `onlyManagerMutatesTheSet`, `cannotRemoveLastDeviceOrManager` (no-brick),
`promotionRequiresSetMembership`, `noFinalizePromotionBeforeDelay`, `managerOnlyCancelsPromotion`,
`nonceMonotonicPerVault`, `bootstrapOncePerVault`, `authorityOnlyMutatesViaSignedPaths`,
`noStorageMutationBesidesWhitelist`, `onlyKnownEventsEmitted`, `setSizeWithinBound`,
`noVDKLikeDataOnChain` (defense-in-depth). Plus slither `--fail-high`=0, ABI-drift, the V2 no-admin
selector probe, non-payable/no-fallback, EIP-712/ecrecover discipline, gas sanity.

## Test posture

Forge unit (~40-50 tests: full lifecycle + every revert path; `publishRevision` happy / wrong-signer-not-
in-set / tampered-field / cross-vault replay; `addDevice` happy / wrong-manager-rejected / duplicate /
bad-nonce; `removeDevice` happy / no-brick-revert / non-manager-rejected; bootstrap once-only;
promotion propose/cancel/finalize lifecycle + before-delay-revert + non-member-revert; cross-contract
`vaultAuthority` read happy/mismatch; no-admin selector probe; digest-oracle parity) + forge invariant
(10k×32) + the **#101 anvil slot with `evm_increaseTime`/`evm_mine`** for the promotion delay (no literal
wait) + the L13 add/remove/promote regression gate. The Rust client lifecycle tests land with #106c (this
issue ships the Solidity-level anvil deploy + time-warp tests). `#[ignore]`'d live tests against the
testnet deploy once a multi-device testnet vault exists (deferred, same posture as 4.1/#103-C).

## Effort + risk

~2-3 weeks focused contract work (new contract + add/remove/promote state machine + cross-contract read +
full test/invariant/anvil suite + testnet deploy). Risk concentration: (1) THE CRUX resolution — wrong
authority model lets a rogue device manage the set OR strands promotion in a RecoveryV2 redeploy; (2) the
no-brick guard (L10 — a wrong rule bricks a vault permanently, immutable); (3) the promotion delay/veto
race (L11 — too short = a thief promotes faster than the user notices; too long = real recovery is
painful). All three are in the D-011 audit package; the anvil add/remove/promote gate is the single most
important structural defence. Everything stays testnet-only until D-011.

## Open decisions for Kelvin (Q-a..Q-k) — see the report for full plain-English framing

- **Q-a** survivor-promotion authority model — **THE CRUX. Recommend Option B** (V2 owns the device
  manager; promotion stays in #106a). Option A pushes promotion into a RecoveryV2 (new blocking
  sub-issue). Scope-determining.
- **Q-b** primary + secondaries (asymmetric) vs flat equal set — **recommend asymmetric** (one
  `deviceManager`; matches #106 §0a Q-b LOCK + makes Q-a coherent).
- **Q-c** promotion delay duration + veto window — **recommend a fixed `PROMOTION_DELAY` constant**;
  needs Kelvin's number (suggest 24-72h; shorter than recovery's 72h since a surviving device is a
  stronger signal than a guardian quorum, but long enough for a heads-up).
- **Q-d** add/remove/promote authorization proof — **recommend EIP-712 recovered-signer** (match
  RevisionLogV1's Path B; gate on the recovered signer, NOT `msg.sender`) so a relayer can broadcast and
  the auth is portable. Per-vault `deviceNonce` anti-replay.
- **Q-e** `removeDevice` of the last/manager device — **recommend forbid** (`ErrWouldBrickVault`,
  L10): the manager must promote a replacement before being removable; the set can never empty.
- **Q-f** genesis/first-device bootstrap — **recommend an explicit `bootstrapVault`** (once-only) that
  seeds the manager from `RecoveryV1.vaultAuthority` if set, else the recovered first signer; cleaner
  than V1's implicit publish-time self-bootstrap and avoids a publish that races the set.
- **Q-g** confirm new-vaults-only — **recommend yes** (no V1→V2 migration in the contract; V1 stays
  immutable; per-vault opt-in re-home is a flagged later feature).
- **Q-h** cross-read RecoveryV1's `vaultAuthority` — **recommend yes** (`staticcall`, pinned immutable
  address) for the genesis seed + recovery re-alignment; closes #103-C GAP FLAG 2.
- **Q-i** set-size bound — **recommend a `MAX_DEVICES` cap (suggest 32)** to bound the off-chain fold.
- **Q-j** new EIP-712 domain + schema-version ladder — **recommend `version="2"`** + `MAX_KNOWN_SCHEMA_
  VERSION=1` (distinct domain so V1 sigs never replay against V2).
- **Q-k** recovery re-alignment trigger — **recommend the client re-points `deviceManager` via an
  on-chain manager re-seed observing `RecoveryFinalized`**, OR the contract reads `vaultAuthority` live
  on each manager check (zero drift, costs a `staticcall` per add/remove). Sub-decision of Q-a Option B;
  the live-read variant is the strongest anti-drift but couples gas to the cross-read.

## Open follow-ups (deferred to later sub-issues)

VDK device-to-device handoff crypto (#106b); client device-add/pairing flow + `deviceManager` re-align on
recovery (#106c); read-side revocation generalisation #103-C → set-membership (#106d); pairing UX +
presence gate (#106e); THREAT_MODEL multi-device + device-manager rows (post-audit); D-0xx DECISIONS row
for the V2 testnet address; the RecoveryV2 self-promotion design IF Kelvin picks Q-a Option A.
