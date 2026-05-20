<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Issue #102 — Recovery v1 contract (`RecoveryV1.sol`) — plan-gate DRAFT

**Status: LOCKED — Kelvin sign-off 2026-05-20. Resolved decisions R-a..R-h in DECISIONS.md (Issue #102). HIGHEST-RISK EPIC; external-audit-gated before mainnet; every change requires explicit Kelvin approval (§16.3).**
**Base tip: `b93c101` (main; MVP-3 started with #101 anvil harness). Implements master plan §6 row `2.2 Recovery contract v1` (Whitepaper §D2).**

## Scope — contract-only (recommended, confirmed)

#102 is the on-chain `contracts/src/RecoveryV1.sol` ONLY. The recovery **client logic** (Rust `pangolin-core::recovery` — today a 5-line stub) + guardian onboarding/initiation/approval/cancel UX (master plan `6.1`–`6.7`) are a separate parallel/follow-on issue. The master plan structurally separates them (§6: `2.2` contract vs `6.x` client; "2 in parallel: recovery contract · recovery client logic"). Matches the 2.1/2.2 pattern (each contract was its own issue, `Cargo impact = zero`). Contract-first is correct sequencing — the client builds calldata for the contract's surface, so the surface must lock first.

**NET-NEW + FIRST STATEFUL ON-CHAIN STATE MACHINE.** Unlike RevisionLogV1/EntitlementRegistry (stateless-per-call ledgers), RecoveryV1 has a lifecycle with a mandatory time gate — the source of most new threat surface (time manipulation, front-running cancel, initiation griefing) and why this is the highest-risk EPIC.

## Authority model (Whitepaper §5; master plan)

Layers: social recovery → vault ownership → session → operation (independent). **Recovery rotates *authority*; the VDK is re-wrapped client-side, never re-derived; the contract NEVER touches the VDK or any secret (L12). Guardians never see the VDK.** Recovery is observable (chain events) + cancelable during a mandatory delay (defeats hostile recovery).

## Lifecycle state machine

```
initiateRecovery → PENDING ──approveRecovery×N (dedup)──▶ (threshold)
                     │                                        │
   cancelRecovery ───┤ (any time before finalize)             │ finalizeRecovery
                     ▼                                         ▼  requires approvals>=threshold
                  CANCELED (terminal)                          AND now >= initiatedAt + MIN_DELAY
                                                            FINALIZED → vaultAuthority rotated
```
Every transition emits an event (contract-enforced observability): `RecoveryInitiated/Approved/Canceled/Finalized`. One active attempt per vault (Q-f).

## Proposed surface (final shape rides on the Q's)

- `setGuardianSet(vaultId, commitment, threshold, guardianCount, ...)` — establish guardian commitment, bounds-checked (Q-a/Q-e).
- `initiateRecovery(vaultId, proposedAuthority, sig)` — None→PENDING, stamp `initiatedAt`.
- `approveRecovery(vaultId, membership-proof + guardianSig)` — dedup + count (Q-c).
- `cancelRecovery(vaultId, authorizedSig)` — PENDING→CANCELED (Q-g).
- `finalizeRecovery(vaultId)` — threshold + delay → rotate `vaultAuthority` → FINALIZED.
- View digest oracles `hashInitiate/Approve/Cancel` + `domainSeparator()`.
- `_recover` copied VERBATIM from `RevisionLogV1.sol:405` (len-65, v∈{27,28}, canonical-s, reject signer==0).

Storage: `guardianSet[vaultId]` (commitment+threshold+count), `vaultAuthority[vaultId]`, `activeRecovery[vaultId]`, `hasApproved[vaultId][attemptNonce][guardian]`, immutable `_DOMAIN_SEPARATOR`. Custom errors per §2.3 of the research (revert-on-failure, no event on failure, state writes AFTER checks).

## L1..L16 invariants

- **L1** New file/contract/deployment; v0/v1/EntitlementRegistry untouched + unmoved.
- **L2** Cardinal rules verbatim + stricter: no admin/owner/upgrade/pause/selfdestruct/delegatecall/receive/fallback; non-payable; N-selector admin probe extended with recovery-specific selectors (`forceFinalize`/`adminCancel`/`setAuthority`/`setThreshold`/`pauseRecovery`/`removeGuardian` — all MUST be absent). **Bug → deploy RecoveryV2, never patch (D-011).** Highest-stakes application of no-admin in the project — an admin override here would be a hostile-recovery primitive by construction.
- **L3** solc 0.8.24 exact-pin, shanghai, no Base-specific opcodes, `ecrecover` precompile only (L1-viable).
- **L4** Path B `ecrecover`+EIP-712 v4; `_DOMAIN_SEPARATOR` bakes chainId+`address(this)` (cross-chain/contract replay defeated). (Conditional on Q-c choosing sig-auth.)
- **L5** `uint16 schemaVersion` on every event, starts 1, `MAX_KNOWN_SCHEMA_VERSION=1`, future-version reverts (§18.7).
- **L6** Revert-on-failure; no event on failure; state writes AFTER all revertable checks.
- **L7** Documented storage-slot layout; field widths future-proofed (uint64 initiatedAt, uint8 status) so a v2 isn't forced just to add a field.
- **L8** **Threshold bounds contract-enforced** (D-009): revert if threshold<2 / >9, count<3 / >15, threshold>count. Threshold cannot be reduced post-hoc by attacker action.
- **L9** **Mandatory delay contract-enforced + observable**: finalize reverts unless `now >= initiatedAt + MIN_DELAY`; not skippable by any party (no admin — L2).
- **L10** **Cancelability contract-enforced**: cancel callable throughout PENDING → CANCELED (defeats hostile recovery).
- **L11** Guardian approvals deduplicated + scoped to the specific attempt (`attemptNonce`); stale approvals can't carry into a fresh attempt.
- **L12** **The contract NEVER touches the VDK or any secret — rotates authority only.** No vault data/key/ciphertext on chain. THE most important invariant; makes "guardians never see VDK" structurally true. VDK re-wrap is client-side, out of #102.
- **L13** Guardian-set commitment does not leak guardian identities on-chain (Q-a). Observers learn a recovery is happening, not who guards whom.
- **L14** Ship contract + tests + `DeployRecoveryV1.s.sol` + `abi/RecoveryV1.json` + CI (forge build/test, ABI-drift, slither); testnet deploy is a follow-on; **mainnet gated on external audit (D-011, $30-80k) + Kelvin auth.**
- **L15** Cargo/Rust impact = ZERO in #102 (recovery stub untouched).
- **L16** AGPL SPDX; `git merge --no-ff` + §16 ledger; every change needs explicit Kelvin approval.

## Forge invariants (10k×32)

`noFinalizeBeforeDelay`, `noFinalizeBelowThreshold`, `canceledIsTerminal`, `oneActiveRecoveryPerVault`, `guardianApprovalDedup`, `thresholdAlwaysInBounds`, `authorityOnlyRotatesViaFinalize`, `noStorageMutationBesidesWhitelist`, `onlyKnownEventsEmitted`, `noVDKLikeDataOnChain` (defense-in-depth). Plus slither `--fail-high`=0, ABI-drift, the no-admin selector probe, non-payable/no-fallback, EIP-712/ecrecover discipline.

## Open decisions for Kelvin (Q-a..Q-h)

Full framing + security implications in the conversation / DECISIONS.md LOCK. Summary (each with a recommendation):
- **Q-a** guardian-set commitment: **merkle root** (privacy) vs hash vs explicit address registry (leaks guardian graph).
- **Q-b** delay window: **fixed constant, suggest 48-72h** vs per-vault-configurable-with-floor. *Duration is under-specified in the spec — needs Kelvin's number.*
- **Q-c** guardian-approval auth: **EIP-712 sigs** (no gas/tx for guardians) vs on-chain txs from guardian addresses.
- **Q-d** what "authority" rotates: **a secp256k1 `vaultAuthority` address RecoveryV1 owns** (RevisionLogV1 is immutable + can't be reached). *Honest gap: old-device-key revocation enforcement is client-side read-policy, deferred to `6.5`.*
- **Q-e** mutable guardian sets in v1: **immutable in v1** (defer mutation) + self-bootstrap establish by current authority.
- **Q-f** concurrent attempts: **one active recovery per vault**.
- **Q-g** who cancels: **current `vaultAuthority`** (still-holding-a-device user aborts hostile recovery); optional guardian-quorum cancel as defense-in-depth.
- **Q-h** replay/front-run/time hardening: confirm the discipline (EIP-712 domain binding; attempt-scoped approval sigs + expiresAt; block.timestamp delay; cancel-vs-finalize race posture).

## Test posture

Forge unit (~30-40 tests: full lifecycle + every revert path + replay rejection + no-admin probe + digest-oracle parity) + forge invariant (10k×32) + slither + ABI-drift + the **#101 anvil slot with `evm_increaseTime`/`evm_mine` time-warp** to test finalize-after-delay hermetically (no literal 48h wait). #102 ships at minimum a forge-level anvil deploy + Solidity time-warp finalize test; the Rust lifecycle tests land with the client issue. External-audit gate before mainnet.

## Effort + risk

~2-3 weeks focused contract work (first stateful state machine + merkle commitment + time-warp tests + heavy threat model). Within the master plan's 8-12wk MVP-3 estimate (most of which is the client + slow delay-window testing). Highest-risk EPIC; explicit Kelvin approval per change; bug = RecoveryV2 redeploy.

## Open follow-ups (deferred to client + 6.x issues)

VDK re-wrap (`6.5`, client-side); old-device-key revocation enforcement on read (the Q-d gap, `6.5` + chain-sync reader); guardian onboarding/notifications/countdown/copy (`6.1-6.3/6.7`); Rust `pangolin-core::recovery` impl; full E2E lose-all-devices test (`6.6`); the actual anvil Rust↔contract lifecycle tests (land with client; harness slot ready); mutable guardian sets (Q-e B); per-vault configurable delay (Q-b B); THREAT_MODEL RecoveryV1 entry (post-audit).
