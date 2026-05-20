<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Workstream B (#104) — Guardian-escrow / threshold-VDK-recovery crypto — plan-gate DRAFT

**Status: DRAFT — foundational decisions OPEN (Q-a/Q-b/Q-c/Q-d/Q-l). DO NOT BUILD until signed off + (recommended) an external-auditor pre-opinion on the construction. The cryptographic heart of Option-2 social recovery + the single most external-audit-critical piece in the project (§16.3, D-011). Conservative posture; uncertainty flagged, not papered over.**
**Base: RecoveryV1 `97cbe4c` merged; #103 chain-client LOCKED. Couples to #102 (contract), #103 (chain-client), 6.1 (onboarding).**

## 1. Headline finding — the whitepaper does NOT specify the scheme

The whitepaper's only cryptographic statement (§5.1) is "**threshold-based recovery shares distributed among trusted individuals**" + the four invariants (guardians never see VDK; recovery rotates authority not VDK; VDK re-wrapped not re-created; observable+cancelable). The Hardware/Session Spec §9 **explicitly lists "cryptographic key derivation details" + "guardian governance mechanics" as NON-GOALS** — the whitepaper deliberately defers the construction to us. **We are designing *beyond* the whitepaper.** The external audit will scrutinize OUR construction, not a referenced standard — so the construction choice (Q-b/Q-c) carries the full weight, and an auditor pre-opinion before build is recommended.

## 2. Proposed scheme (Scheme A) — split a recovery-wrap key, double-wrap the VDK

The VDK is wrapped **twice**: once under the existing password-derived Ed25519 `AuthorityKey` (the daily path, unchanged) and once under a fresh **RecoveryWrapKey (RWK)** whose reconstruction capability is **threshold-shared across guardians** (t-of-M Shamir over the 32-byte RWK; each share then sealed to a guardian's X25519 public key). Recovery never needs the old password.

**Lifecycle:**
- **Onboarding:** unlocked device generates RWK → wraps the existing VDK a 2nd time under RWK (`WrappedVdk_recovery`) → Shamir-splits RWK (t = on-chain `guardianSet.threshold`, M = guardianCount) → seals each share to guardian i's X25519 pubkey → distributes; RWK + plaintext shares zeroized. No single guardian gets RWK or the VDK.
- **Recovery:** new device sets a fresh password (→ fresh Ed25519 wrap-authority) + a fresh secp256k1 device wallet (= on-chain `proposedAuthority`); `initiateRecovery` (#103); guardians both sign the `Approve` EIP-712 (gates on-chain rotation) AND release their plaintext share (decrypt their sealed share); recovering device collects ≥ t shares → reconstructs RWK → unwraps `WrappedVdk_recovery` → recovers the **byte-identical VDK** → after 72h delay, `finalizeRecovery` rotates on-chain authority → re-wraps the VDK under the new password authority + **re-splits a fresh RWK' for fresh shares** (forward security).

Satisfies all four whitepaper invariants. The on-chain control plane (#102) holds NO share/secret — escrow is entirely off-chain.

## 3. What exists vs net-new (verified)

Built: `VdkKey`/`WrappedVdk`(seal/unwrap/rewrap)/`AuthorityKey`(Ed25519-from-password) in `keys.rs`; `rewrap` needs the OLD authority (the gap Option-2 must route around — Scheme A's second wrap does). **Net-new: ALL share-splitting / threshold reconstruction / per-guardian sealing / the recovery VDK path / the new-authority derivation.** `pangolin-crypto` is zero-serde (HIGH-1), tiny hand-curated dep graph, NO Shamir/secp256k1/X25519/threshold lib today. `pangolin-core::recovery` is a 5-line stub. **Dual-authority reality:** on-chain `vaultAuthority` = secp256k1; VDK-wrap `AuthorityKey` = Ed25519-from-password — different curves; the contract's rotation does NOT rotate the wrap-authority (Q-d).

## 4. L1..L9 invariants (proposed)

- **L1** guardians never see the VDK/RWK/another guardian's share — only their own sealed share; < t learns NOTHING about RWK (Shamir info-theoretic).
- **L2** a single guardian's share is independent of RWK; < t compromise = zero VDK exposure.
- **L3** escrow threshold t == on-chain `guardianSet.threshold`, M == guardianCount, share-holders == the merkle-committed set (a mismatch is a silent catastrophe).
- **L4** no share/ciphertext/RWK/VDK on chain (structurally — #102 holds none; B adds nothing on-chain).
- **L5** VDK re-wrapped, never re-derived — recovered VDK byte-identical (`ct_eq`); `VdkKey::generate` never on the recovery path.
- **L6** HIGH-1 zero-serde preserved — new escrow types use fixed-layout byte encoding (not serde), `assert_not_impl_any!(Clone,Copy)`, zeroize, redacted Debug, `ct_eq`.
- **L7** forward security on recovery — released plaintext shares + old RWK are dead; recovery MUST re-split a fresh RWK' + re-distribute.
- **L8** domain separation / replay — sealed shares + RWK-wrap bind `vault_id` (+ epoch/attemptNonce) as AAD; versioned info strings.
- **L9** no new `=`-pinned dep without `cargo deny`+`cargo audit`+manual review (Kelvin gate); forbid(unsafe_code) + AGPL SPDX.

## 5. Open security decisions for Kelvin (Q-a..Q-n)

Headline forks (catastrophic-if-wrong; need explicit sign-off + likely auditor pre-opinion):
- **Q-a** Accept we design *beyond* the whitepaper (it under-specifies); ratify the scheme as a Pangolin spec addendum.
- **Q-b** Split a RecoveryWrapKey (Scheme A, recommended — VDK bytes stay out of the sharing math) vs Shamir the VDK directly (simpler, larger blast radius).
- **Q-c (THE BIG ONE)** Threshold-crypto provenance: a vetted Shamir/threshold **library** (if it clears the HIGH-1 supply-chain bar) vs a small KAT-tested constant-time GF(2^8) Shamir — and **NEVER hand-rolled curve/threshold-encryption crypto**. Recommend an **external-auditor pre-opinion on the construction BEFORE build.**
- **Q-d** The dual-authority mapping: on recovery, user sets a **fresh password** (→ fresh Ed25519 wrap-authority) independent of the secp256k1 device wallet (= on-chain authority)? I.e., "Option 2 = no password to *recover*, but set a new password to *re-secure*." Genuinely unresolved; the whitepaper's "rotate authority" prose papers over the two-curve reality. Alternative: password-less wrap-authority bound to the device key.
- **Q-l** Conscious acceptance: **t colluding guardians CAN reconstruct RWK → learn the VDK, even without finalizing on-chain.** The on-chain 72h delay protects *ownership rotation*, NOT *VDK confidentiality against a colluding quorum* — that asymmetry is inherent to social recovery; the user's defense is choosing trustworthy guardians + a high-enough t. Kelvin must consciously accept.

Supporting forks: Q-e (X25519 dep for share-sealing), Q-f (guardian key provenance/auth at onboarding), Q-g (share-release gated on on-chain PENDING state), Q-h (threshold-equality enforcement), Q-i (share transport channel — 6.1), Q-j (guardian directory — none on-chain, R-a privacy; how does a lost-everything user enumerate guardians?), Q-k (malicious onboarding device — propose out-of-scope v1, consistent with "no fully-compromised-OS defense"), Q-m (mandatory fresh re-distribution on recovery — L7), Q-n (guardian-set mutation / share refresh — deferred, sets immutable in v1).

## 6. Test posture + audit framing

Hermetic crypto tests (Shamir KAT; t-1 reveals nothing / t reconstructs exactly; sealed-share round-trip + wrong-key fail; RWK-wrapped VDK byte-identical; domain-separation negatives; proptest ≥1024 cases). Coupled anvil E2E (once #103 lands): onboard → setGuardianSet → lose-everything → initiate → approve+release → time-warp 72h → finalize → reconstruct → VDK byte-identical → re-wrap + re-distribute. **This is THE piece the external audit scrutinizes hardest — the only net-new primitive-level crypto in a project that otherwise "reuses vetted libraries, never invents." Recommend an auditor pre-opinion on Q-b/Q-c before build.**

## 7. Effort + risk

~5-8 weeks (vs #103's 2-3) — dominated by the construction decision + supply-chain clearance (Q-c, may need auditor consult first) + the dual-authority resolution (Q-d, may ripple into vault.rs unlock/create) + the coupled anvil E2E. **HIGHEST risk in the project: catastrophic-if-wrong (wrong party reconstructs the VDK; < t suffices; on-chain rotation leaks VDK). DO NOT build until Q-a/Q-b/Q-c/Q-d/Q-l are signed off.**

## 8. Where it lives

`pangolin-crypto/src/escrow.rs` (the threshold split/reconstruct + sealed-share + RWK primitives; zero-serde) + `pangolin-core::recovery` (orchestration) + `pangolin-store/src/vault.rs` (persist `WrappedVdk_recovery` + guardian pubkeys in meta).
