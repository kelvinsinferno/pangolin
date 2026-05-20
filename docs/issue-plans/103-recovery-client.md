<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Issue #103 — Recovery v1 CLIENT (chain-client control plane) — plan-gate LOCKED

**Status: LOCKED — Kelvin sign-off 2026-05-20 ("lock + build #103"). Heightened-risk (Rust client for the highest-risk EPIC); chain-client decisions resolved on plan-gate recommendation. The security crux (VDK escrow) is split out to Workstream B.**
**Base tip: current main (RecoveryV1 `97cbe4c` merged; #100 FFI + #101 anvil harness landed). Implements the master plan §6 "recovery client logic" — chain-client half.**

## Recovery model context (LOCKED 2026-05-20)

Pangolin recovery = **Option 2 (true social recovery)**: guardians enable VDK unwrap WITHOUT the user's password, via threshold secret-sharing; no single guardian sees the VDK. See [[pangolin_recovery_model]]. The on-chain contract (#102) handles ONLY authority rotation + approval gating; the share-escrow is OFF-CHAIN. **#103 builds the on-chain control plane only.**

## Scope — chain-client control plane only (3-way split)

**#103 builds:** (1) guardian-set merkle construction (root for `setGuardianSet`, membership proofs for `approveRecovery`); (2) the 5 lifecycle calls' calldata + sign + broadcast (`setGuardianSet`/`initiateRecovery`/`approveRecovery`/`cancelRecovery`/`finalizeRecovery`); (3) the `Approve` EIP-712 guardian-signature builder + verifier (byte-identical to the contract); (4) a RecoveryV1 chain adapter (`sol!` binding + deployment-file entry + address pin + `RecoveryAnchorV1` receipt decode); (5) the anvil Rust↔contract lifecycle test (deploy → setGuardianSet → initiate → approve×threshold → `evm_increaseTime(72h)` → finalize), the centerpiece + the #101 harness's first real Rust-client use.

**Deferred (own audited cycles):**
- **Workstream B / #103-B — guardian-escrow / threshold-VDK-recovery crypto** (the Option-2 heart; net-new; highest-stakes; needs its own plan-gate + whitepaper-alignment).
- **#103-C — revocation-on-read** (honor `vaultAuthority`, ignore pre-rotation device entries; touches the 4.1 chain reader).
- 6.x UX (onboarding/notifications/countdown/copy); live testnet `#[ignore]` lifecycle tests; RecoveryV2 features.

## Resolved decisions (chain-client; on plan-gate recommendation)

- **R-scope** 3-way split as above; #103 = chain-client only.
- **R-where** new `pangolin-chain::recovery_signing` (EIP-712 machinery) + `recovery_client` (sol! binding + merkle builder + the 5 lifecycle broadcasts), mirroring the `secp256k1_signing.rs`/`chain_submit.rs` split; `pangolin-core::recovery` (the 5-line stub) gets pure no-secret no-chain domain types / a thin re-export (Q3 zero-uniffi). Rationale: merkle leaf = keccak-over-EVM-address (alloy/chain territory); reuses the audited byte-pin test harness.
- **R-merkle** hand-rolled sorted-pair-keccak builder (OZ-StandardMerkleTree-compatible): leaf = `keccak256(abi.encode(guardian))` (32-byte left-pad, matches `RecoveryV1.sol:609`); node = sorted-pair `keccak256(abi.encodePacked(min,max))` (matches `:845`). NO merkle crate dep (L9 — avoid dep + convention-mismatch). Byte-pinned via an anvil `approveRecovery` round-trip + a hermetic hand-computed-root test.
- **R-test** anvil Rust↔contract lifecycle test as the centerpiece + hermetic byte-pin units (APPROVE_TYPEHASH, recovery domain separator, merkle root, sign/recover round-trip); live testnet `#[ignore]` deferred (same posture as #101).
- **R-guardians** v1: the recovering device holds the guardian address list locally (or reconstructs from backup) + collects `Approve` sigs out-of-band; NO on-chain guardian directory (R-a privacy — addresses never on chain). UX for obtaining the list = later 6.x.
- **R-anvil** extend `scripts/anvil-ci.sh`: deploy RecoveryV1 (new forge script + `dev.json` entry) + fund `fixed_wallet()` + N guardian wallets via `anvil_setBalance` + run the lifecycle test with `evm_increaseTime`/`evm_mine` time-warp.

## L1..L12 invariants

- **L1** New files only (`recovery_signing.rs`, `recovery_client.rs`, `pangolin-core::recovery` body, `DeployRecoveryV1.s.sol`, `dev.json` RecoveryV1 entry); `chain_submit.rs`/`secp256k1_signing.rs`/`base_sepolia.rs` reused not rewritten; RevisionLogV1/EntitlementRegistry client paths byte-identical.
- **L2 (merkle byte-identity — LOAD-BEARING)** client root + proofs MUST be accepted by the contract's `_verifyMerkleProof` (`RecoveryV1.sol:837`). A mismatch = guardians can never approve = total liveness break. Pinned by an anvil `approveRecovery` round-trip + a hermetic hand-computed-root test.
- **L3 (EIP-712 byte-identity — LOAD-BEARING)** client `Approve` digest == contract `_hashApprove` (`:813`) byte-for-byte (typehash verbatim, domain `"Pangolin Recovery"`/`"1"`/chainId/verifyingContract, `\x19\x01`). Pinned constants + `typehash_matches_pinned_constant`/`domain_separator_matches_pinned_constant` tests. `v∈{27,28}`, canonical-low-s (`is_canonical_s`), reject `signer==address(0)`.
- **L4 (chain-id binding)** reuse #101 `resolve_envelope_chain_id` verbatim: BaseSepolia pinned + RPC cross-check; Dev reads live anvil id; production never sources signing/envelope chain id from an untrusted RPC.
- **L5 (no secret crosses where it shouldn't)** guardian secret keys never touch the recovering device (guardians sign off-chain, submit only 65-byte sig + proof); VDK NOT touched in #103; device secp256k1 signer read engine-side only (#100 L1 posture).
- **L6 (schema-version ladder)** every call passes `schemaVersion=1`; reject `> MAX_KNOWN_SCHEMA_VERSION` symmetrically.
- **L7** `pangolin-chain` no `pangolin-store` dep (cargo-tree guard green); merkle/signing are sync-safe pure fns.
- **L8** `forbid(unsafe_code)` + AGPL SPDX on every new file.
- **L9** no new `=`-pinned external dep without `cargo deny check advisories` + `cargo audit` (likely ZERO — alloy provides keccak/sol!/EIP-712/secp256k1; merkle hand-rolled).
- **L10 (anvil time-warp test = regression gate)** the full deploy→initiate→approve×threshold→`evm_increaseTime(72h)`→finalize lifecycle MUST be the CI gate (env-quirk #14 class). The audit must verify a deliberately-broken merkle leaf or digest turns it red.
- **L11 (anti-replay client-side)** read live `attemptNonce`+`proposedAuthority` for each `Approve` digest (`:617`); sane `expiresAt`; never construct a stale-attempt digest.
- **L12** §16 ledger; `git merge --no-ff`; every change needs explicit Kelvin approval (§16.3).

## Test posture

Centerpiece: the anvil lifecycle test (real merkle root + real guardian EIP-712 sigs + real proofs accepted by the live `_verifyMerkleProof` + 72h time-warp + negative gates: finalize-before-delay/below-threshold/non-authority-cancel/duplicate-approval revert). Hermetic byte-pins: typehash, domain separator, merkle root vs hand-computed fixture, sign+recover round-trip. The merkle + EIP-712 byte-identity are the load-bearing client-side properties for the RecoveryV1 external audit (D-011).

## Effort + risk

~2-3 weeks. Calldata/sign/broadcast = mechanical reuse; the merkle builder + byte-pin tests = the net-new highest-care work (silent+total if wrong — guardians can't approve / approvals revert; the env-quirk #14 class). The anvil time-warp lifecycle test is the structural defense.

## Open follow-ups

Workstream B (escrow crypto, the Option-2 heart); #103-C revocation-on-read; 6.x UX; live testnet lifecycle tests (need a testnet RecoveryV1 deploy + pinned `EXPECTED_RECOVERY_ADDRESS_*` + `RECOVERY_DOMAIN_SEPARATOR_*`); THREAT_MODEL recovery-client entry (post-audit).
