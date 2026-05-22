<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Issue #106e-0b — production guardian-escrow ONBOARDING (the missing recovery prerequisite) — plan-gate DRAFT

**Status: DRAFT — awaiting Kelvin sign-off (decisions in §5).** Split out of the #106e-1 plan-gate (Kelvin 2026-05-22: "build onboarding as #106e-0b first"). The production path to SET UP social recovery on a vault — the prerequisite that makes the #106e-1 recovery/rotation FFI a live surface instead of a dead one. Mirrors the §16 plan-gate format of `106e0-composition-layer.md`; its own #104a-style audit (the catastrophic-if-wrong recovery crypto path).

## 0. One-paragraph summary

`complete_rotation` reads the recovery escrow (`recovery_escrow_params`) and `recover_from_shares` re-splits it — but there is NO production way to CREATE the initial escrow on a vault. The only initial-escrow writer is the test-only `Vault::__test_onboard_recovery_escrow` (vault.rs:1820). #106e-0b promotes that to a production `Vault::onboard_guardians(threshold, guardian_x25519_pubs) -> OnboardingOutcome { epoch }`: read the active VDK store-side, mint a fresh `RecoveryWrapKey`, second-wrap the VDK under it, `split_rwk` into `M` shares, `seal_share` each to a guardian's X25519 SEALING pubkey, and `write_recovery_escrow_tx` the `wrapped_recovery` + sealed shares under the active VDK's column-AEAD — ALL in one transaction (the same single-tx discipline as `commit_recovery_rekey`). **Crucially this needs NO `pangolin-core` driver — it uses only `pangolin-crypto` escrow primitives (all upstream of store), so it is a pure `pangolin-store` `Vault` method (no dep-arrow problem, unlike #106e-0).** Zero new crypto, zero new deps. The one real question (§5 Q-a) is whether to promote the test helper's inline composition as-is (a 2nd copy of the onboard-split-seal logic that already lives in `pangolin_core::recovery::onboard_guardian_escrow`) or share one implementation so the initial-onboard and the rotation/recovery RE-split can never drift on this catastrophic path.

## 1. Scope

**#106e-0b builds (in `pangolin-store`):**
1. **`Vault::onboard_guardians(threshold: u8, guardian_x25519_pubs: &[[u8; 32]]) -> Result<OnboardingOutcome>`** — the production twin of `__test_onboard_recovery_escrow`. Reads `self.active.vdk` (store-internal, never exposed), runs the onboard composition (RWK → wrap VDK → split → seal per guardian), writes the escrow in ONE `unchecked_transaction()`. `OnboardingOutcome { epoch: u64 }` (the recovery-generation epoch the escrow was written at; non-secret). Session-gated (`require_active`). Idempotent semantics: a 2nd onboard REPLACES the prior generation (the escrow write already DELETEs prior guardian rows — confirm Q-b).
2. **The onboard composition source** — per Q-a: either (A) promote the test helper's inline `pangolin-crypto` composition verbatim, or (B) call a single shared onboarding primitive (lifted to `pangolin-crypto`, also used by the core re-split) so there is ONE implementation.

**Explicitly NOT this slice:**
- **The `vault_onboard_guardians` FFI binding** — lands in #106e-1 with the rest of the thin FFI (this slice is the production METHOD only, mirroring how #106e-0 was the composition layer and #106e-1 is the FFI).
- **The on-chain guardian SET (`RecoveryV1.setGuardianSet`, merkle root over guardian EVM addresses)** — that is the #103 recovery-client (`set_guardian_set_v1`, already built); the host calls it separately. #106e-0b is the OFF-CHAIN escrow (the X25519-sealed shares) only. The two halves use different guardian identities (EVM address on-chain vs X25519 sealing pubkey off-chain) — both come from the same guardian, bound by the host.
- Any recovery/rotation/FFI logic (already merged / #106e-1).

## 2. Splittable? — NO

One small method + its audit. Too small to split. **Recommend: one #106e-0b PR, builder → #104a-style audit → merge, BEFORE #106e-1.**

## 3. Design (decisions in §5)

The method body is the test helper at vault.rs:1820-1872 promoted to production: `require_active()` → `RecoveryWrapKey::generate()` → `wrap_vdk_under_rwk(&active.vdk, &rwk, &wrap_ctx)` → `split_rwk(&rwk, threshold, M)` → `drop(rwk)` → `seal_share(share_i, guardian_pub_i, &vault_id, &epoch_bytes)` per guardian → build `&[GuardianRecord]` → `write_recovery_escrow_tx(...)` in one tx → commit. **Secret hygiene:** the RWK and the shares are dropped immediately after use; the active VDK is borrowed store-internal and never leaves; the only OUT is the non-secret epoch. **Atomicity:** one `unchecked_transaction()`; a crash leaves NO partial escrow (the vault simply has no recovery set up — retryable).

**Epoch source:** the recovery-generation epoch. For a FIRST onboard this is GENESIS (0); a re-onboard would bump. Confirm Q-c: does `onboard_guardians` take the epoch as a param, read the current generation, or always write GENESIS for the initial set-up (and let rotation/recovery bump it thereafter)?

## 4. L-invariants (proposed)
- **L1 (atomic — one tx, no partial escrow).** Single `unchecked_transaction()`; rollback on any error (mirrors `commit_recovery_rekey` #105a L2).
- **L2 (secret hygiene).** RWK + shares dropped after use; active VDK borrowed store-internal, never returned/logged/exposed; only the non-secret epoch out. No new secret-lifetime surface.
- **L3 (pure store, no dep inversion).** Uses ONLY `pangolin-crypto` escrow primitives (upstream of store) + the existing `write_recovery_escrow_tx`. No `pangolin-core` dep, no `unsafe`, AGPL SPDX.
- **L4 (no new crypto / no new deps).** Reuses `RecoveryWrapKey`/`wrap_vdk_under_rwk`/`split_rwk`/`seal_share`/`write_recovery_escrow_tx` verbatim. (Q-a decides whether the COMPOSITION of them is shared or duplicated — not new crypto either way.)
- **L5 (the onboarded escrow is RECONSTRUCTABLE).** The catastrophic check: a vault onboarded via `onboard_guardians` must be recoverable via the merged `recover_from_shares` (the #106e-0 path) AND its params readable via `recovery_escrow_params` / `complete_rotation`. A hermetic round-trip test: `onboard_guardians` → `guardian_open_sealed_share` ×t → `recover_from_shares` → the recovered VDK opens the vault. (This is exactly the `composition_recovery.rs` shape but seeded by the PRODUCTION onboard instead of `__test_`.)
- **L6 (testnet-only until D-011; full `cargo test --workspace`).**
- **L7 (§16 ledger).** `git merge --no-ff`; DECISIONS/DEVLOG; Kelvin merge sign-off; its own #104a-style audit (the recovery crypto path).

## 5. Open decisions for Kelvin (Q-a … Q-c)

- **Q-a (THE MAIN ONE) — share the onboard composition, or duplicate the test helper?** The split-and-seal onboarding logic ALREADY exists as `pangolin_core::recovery::onboard_guardian_escrow` (used by the rotation/recovery RE-split). The test helper re-implements the same steps inline in store (because store can't call core). **Option A (small): promote the test helper's inline composition to production verbatim** — simplest, smallest slice, but leaves TWO implementations of the onboard crypto (the store initial-onboard + the core re-split). **Option B (no-drift): lift the pure onboard primitive DOWN into `pangolin-crypto`** (upstream of both store + core), have BOTH the store `onboard_guardians` and the core re-split call the one shared fn — no duplication, but it touches `pangolin-core`'s existing callers (a small refactor). *Plain English:* "set up my guardians" and "re-shuffle my guardians after a device is removed" do the same secret-splitting math. Right now that math is written twice (once for each). Option A leaves it written twice (risk: someone fixes a bug in one and not the other, and a vault set up by one path can't be recovered by the other). Option B writes it once and shares it. **Recommend B** — this is the catastrophic-if-wrong recovery path; one implementation is materially safer than two, and the L5 round-trip test only proves TODAY's compatibility, not that they stay in sync. The cost is a small refactor of core's callers. **Stakes: MEDIUM** (correctness/maintenance of the recovery crypto). If you'd rather keep the slice minimal, Option A + the L5 round-trip pin is acceptable.
- **Q-b — re-onboard semantics.** A 2nd `onboard_guardians` call (the user changes their guardian set). **Recommend: it REPLACES the prior generation** (the existing `write_recovery_escrow_tx` already DELETEs prior guardian rows) and bumps the generation epoch. *Plain English:* changing your guardians overwrites the old set rather than stacking. **Stakes: LOW** — confirm replace-not-append.
- **Q-c — the epoch the initial escrow is written at.** **Recommend: GENESIS (0) for the first onboard**, with rotation/recovery bumping it thereafter (the existing epoch model). *Plain English:* the first guardian set-up starts the counter at zero. **Stakes: LOW** — confirm vs reading a current generation.

## 6. Places that do NOT compose cleanly (flagged)
- **Two onboard implementations (Q-a)** — the only non-trivial decision; the rest is a faithful promotion of an already-tested helper.
- **Guardian identity has two faces** — the on-chain RecoveryV1 guardian set keys on EVM addresses (merkle), the off-chain escrow keys on X25519 sealing pubkeys. #106e-0b handles ONLY the X25519 escrow; the host binds the two guardian identities and calls `set_guardian_set_v1` (#103) separately. Pin that #106e-0b does not touch the on-chain set.
