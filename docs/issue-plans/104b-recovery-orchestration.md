<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Issue #104b — Recovery ORCHESTRATION (wire the #104a escrow primitive into the full Option-2 flow) — plan-gate LOCKED

**Status: LOCKED — Kelvin sign-off 2026-05-20. All open decisions (Q-a … Q-j) + GAP FLAG 1 resolved on plan-gate recommendation (see §5a). Mirrors the §16 plan-gate format of `103-recovery-client.md` / `104-recovery-escrow-crypto.md`. Build NOT yet dispatched (held until #103 + #104a merge-CI confirm green). Recovery stays TESTNET-ONLY until D-011.**

**Base: #104a primitive merged `1271766` (`pangolin-crypto::escrow`); #103 chain-client merged `17e2313` (`pangolin-chain::recovery_{client,signing}`); #102 RecoveryV1 contract merged `97cbe4c`. Recovery is TESTNET-ONLY until the D-011 external audit clears (unchanged; Workstream B carries the same gate).**

## 0. One-paragraph summary

#104a built the catastrophic-if-wrong *primitive* (split/seal/reconstruct an RWK; double-wrap the VDK). #103 built the on-chain *control plane* (merkle + the 5 lifecycle broadcasts + the `Approve` EIP-712). #104b is the **glue**: the pure orchestration that runs onboarding (generate RWK → split → seal-to-guardians → second-wrap the VDK → persist + push merkle root on-chain) and recovery (collect ≥t shares → on-chain initiate/approve/finalize → reconstruct RWK → unwrap byte-identical VDK → set a new password → re-wrap → re-split for forward security), plus the `pangolin-store` persistence for the new escrow state, the new-password-on-recovery branch in `vault.rs`, and the **coupled anvil E2E** that is the regression gate tying the off-chain reconstruction to the on-chain lifecycle. It introduces **no new crypto** — only composition and persistence.

## 1. Scope

**#104b builds:**
1. **`pangolin-core::recovery` orchestration types + flow logic** (extends the #103 pure-types module): an `OnboardingPlan` / `GuardianAssignment` / `RecoveryEpoch` vocabulary + the two pure state-machine drivers (`onboard_guardian_escrow`, `recover_vdk_from_shares`) that sequence the #104a primitive calls. PURE: no chain, no network, no `uniffi` (Q3 posture confirmed — `pangolin-core` depends on `pangolin-store`+`pangolin-crypto`, NOT `pangolin-chain`). The on-chain steps are passed in as already-resolved inputs / driven by the caller (CLI/host app), exactly as #103 keeps the broadcasts in `pangolin-chain`.
2. **`pangolin-store` persistence** for `WrappedVdkRecovery`, the guardian-set config (t, M), the per-guardian X25519 pubkey + sealed-share assignment, and the recovery `epoch` — new additive table(s) following the existing `meta`/`device_key` idiom.
3. **`vault.rs` new-password-on-recovery path** — the branch that, on TRUE recovery, derives a fresh password authority + re-wraps the daily `WrappedVdk` (Q-d). Normal device-add stays on the existing password.
4. **The coupled anvil E2E** (the centerpiece / regression gate) — lives in `pangolin-chain` integration-tests beside the #103 lifecycle test (pangolin-chain already has `pangolin-crypto` as a dep + `pangolin-store` as a dev-dep), tying the real `split_rwk` → real merkle root → on-chain lifecycle → real `reconstruct_rwk` → byte-identical VDK.

**Deferred (own cycles / later):**
- **6.x UX / FFI**: host-app entry points (guardian onboarding screen, share-transport channel, recovery wizard, countdown). The recovery flow eventually needs `uniffi` entry points — proposed **deferred to 6.x** (Q-i below); #104b keeps the orchestration pure and FFI-free.
- **#103-C revocation-on-read** (honor rotated `vaultAuthority`, ignore pre-rotation device entries) — separate, touches the 4.1 reader.
- **Guardian-set mutation / share refresh without a recovery** (R-e immutable in v1; #104 Q-n deferred).
- Live-testnet `#[ignore]` E2E (needs a Base Sepolia RecoveryV1 deploy + pinned address — same posture as #103/#101).

## 2. Splittable? — recommendation: keep #104b as ONE stage (do NOT split further)

Primitive-first worked because #104a was a self-contained, catastrophic-if-wrong crypto core that warranted its own focused audit. #104b is *composition*: the risk now is integration correctness, not new primitives. The three sub-pieces (core orchestration, store persistence, vault.rs branch) are mutually dependent — the coupled E2E can only assert end-to-end behaviour with all three present, and the E2E IS the value. Splitting would create a half-wired intermediate state with no meaningful test gate. **Recommend a single #104b stage**, with the *option* to land it as two reviewable PRs on one branch if it grows large (PR1 = core+store persistence with hermetic round-trip tests; PR2 = vault.rs branch + the coupled anvil E2E). Surfaced as **Q-j**.

## 3. The end-to-end flow (designed; decisions surfaced in §5)

### Onboarding (guardian-set setup, on an unlocked device)
1. `RecoveryWrapKey::generate()` → fresh RWK.
2. `wrap_vdk_under_rwk(vdk, &rwk, &ctx)` → `WrappedVdkRecovery` (the SECOND wrap, alongside the existing password `WrappedVdk`). `ctx` = the same `WrapContext{vault_id, schema_version}` the daily wrap uses.
3. `split_rwk(&rwk, t, M)` → `M` `Share`s, where `t` = on-chain `guardianSet.threshold`, `M` = `guardianCount` (L3 equality — escrow t/M MUST equal the contract's, both clamped to `2..=9` / `3..=15`).
4. For each guardian `i`: `seal_share(&share_i, &guardian_x25519_pub_i, &vault_id, &epoch)` → `SealedShare`.
5. Persist `WrappedVdkRecovery` + the guardian set (t, M) + per-guardian (X25519 pubkey, sealed-share) + `epoch` in `pangolin-store`. Zeroize the RWK + plaintext shares (they drop automatically — `!Clone` zeroizing types).
6. Push the guardian-set **merkle root** on-chain via #103 `set_guardian_set_v1` (root built from the guardians' **secp256k1 EVM addresses**, not their X25519 pubkeys — see Q-b).

### Recovery (lost password AND/OR all devices)
1. New device generates a fresh **secp256k1 EVM signer** (the on-chain `proposedAuthority`) — derived from a fresh `DeviceKey` via `derive_evm_wallet` (the established Ed25519→secp256k1 HKDF path in `pangolin-chain::evm`).
2. On-chain control plane (#103): `initiate_recovery_v1(proposedAuthority)` → guardians each sign the `Approve` EIP-712 off-chain → `approve_recovery_v1` × t → `evm_increaseTime`/72h → `finalize_recovery_v1` rotates the on-chain `vaultAuthority` to the new secp256k1 signer.
3. Off-chain escrow: each guardian opens THEIR OWN sealed share with their X25519 secret (`open_sealed_share`) and hands the recovering device the raw `Share` (Q-a). Recovering device collects ≥ t shares.
4. `reconstruct_rwk(&shares)` → RWK → `unwrap_vdk_under_rwk(&wrapped_recovery, &rwk)` → the byte-identical VDK (`ct_eq` the original).
5. User sets a NEW password → `AuthorityKey::from_seed(Argon2id(new_password, salt))` → re-wrap the daily `WrappedVdk` under the new authority (`vdk.wrap(&new_authority, &ctx)`), persist via the meta path.
6. **Forward security (Q-c, recommend yes):** generate a fresh `RWK'`, re-`split_rwk`, re-`seal_share` to the (same) guardians, bump `epoch`, persist, push a fresh guardian-set root on-chain if the set changed (it doesn't in v1 — R-e immutable). The old shares + old RWK are now dead.

### The two authorities (Q-d / Q-e — the key design tension, RESOLVED below)
- **On-chain secp256k1 `vaultAuthority`** = anti-hijack / control plane. Derived from the new device's `DeviceKey` (Ed25519) via the one-way `derive_evm_wallet` HKDF. Rotated by `finalizeRecovery`. This is the device's *identity to the chain*; it gates ownership rotation.
- **Off-chain Ed25519 password-`AuthorityKey`** = VDK decryption (the daily wrap key, via Argon2id over the password). Re-derived from the NEW password at recovery.
- They are **independent by construction** (different curves, different derivation, different purpose) and the contract's rotation does NOT touch the wrap-authority. The RWK escrow is the bridge that lets the new device recover the VDK *without* the old password; the new password then re-secures the daily path. **Both rotate at recovery; neither can rotate the other.** This is the single most important thing the audit + the whitepaper-addendum must state plainly.

## 4. L1..L12 invariants (proposed — mirror 103/104 style)

- **L1 (no-secret-crosses-the-pure-boundary)** `pangolin-core::recovery` stays zero-`uniffi`, zero-network, zero-chain, and zero-`serde` on any secret-bearing type; it never re-implements crypto — every secret operation delegates to a #104a `escrow` fn. The orchestration types carry only public context (epoch, t, M, vault_id, guardian pubkeys), never key material.
- **L2 (escrow ↔ on-chain threshold equality — LOAD-BEARING)** the Shamir `t`/`M` MUST equal the on-chain `guardianSet.threshold`/`guardianCount`, and the guardians the shares are sealed to MUST be the same set committed in the merkle root. A mismatch is a silent catastrophe (either reconstruction can't reach threshold, or the wrong quorum gates rotation). Enforced at onboarding + re-asserted in the coupled E2E. (Inherits #104 L3.)
- **L3 (byte-identical VDK — LOAD-BEARING)** the recovered VDK `ct_eq`s the original bit-for-bit; the VDK is re-wrapped, never re-derived; `VdkKey::generate` is NEVER on the recovery path. (Inherits #104 L5, #102 whitepaper invariant.)
- **L4 (the guardian secret never leaves the guardian)** each guardian opens their OWN sealed share locally and releases only the raw `Share`; the recovering device never sees a guardian's X25519 secret (matches #103 L5). The recovering device DOES end up holding ≥ t raw shares + the reconstructed RWK — accepted (that IS reconstruction); surfaced as Q-a.
- **L5 (dual-authority separation)** on-chain secp256k1 `vaultAuthority` rotation is independent of off-chain Ed25519 password-`AuthorityKey` re-derivation; neither rotates the other; both happen at recovery (§3). Documented + asserted in the E2E (the rotated `vaultAuthority` == the new device signer; the re-wrapped daily `WrappedVdk` opens under the new password).
- **L6 (forward security on recovery)** a successful recovery MUST rotate the RWK (fresh `RWK'` + re-split + re-seal) and bump the `epoch`; released/exposed shares cannot recover the post-recovery vault. (Inherits #104 L7; recommend mandatory, Q-c.)
- **L7 (epoch ⇒ AAD domain separation)** the `epoch` is bound into every `SealedShare` header + (optionally) the wrap context; a share from epoch `n` is rejected for epoch `n+1` (the #104a `open_sealed_share` header check). Epoch advances on every onboarding + every recovery re-split (Q-f).
- **L8 (new-password ONLY on true recovery — Q-d)** the normal "new phone" device-add path uses the EXISTING password (no guardian involvement, no RWK touch); only the lost-password recovery sets a new password + re-wraps + re-splits. The branch point lives in `vault.rs` (a new recovery entry distinct from the existing unlock/device-add).
- **L9 (store at-rest discipline)** new escrow state persists following the existing idiom: the `WrappedVdkRecovery` ciphertext/nonce/ctx + guardian pubkeys + sealed shares are **non-secret at rest** (the recovery wrapper is AEAD ciphertext keyed by the threshold-shared RWK; sealed shares are encrypted to guardians) → they live as plain BLOBs like `meta.wrapped_ct`, NOT under the VDK column-AEAD. (See Q-g — confirm whether the locally-retained sealed shares additionally get the per-row AEAD-under-VDK treatment for defence in depth.)
- **L10 (coupled anvil E2E = regression gate)** the deploy → setGuardianSet(real root from real split) → initiate → approve×t → time-warp 72h → finalize → reconstruct RWK from t opened shares → unwrap VDK → `ct_eq` original → set new password → re-wrap → re-split E2E MUST be a CI gate (env-quirk #14 class). The audit must verify that breaking any join (wrong guardian↔share mapping, t-1 shares, epoch mismatch) turns it RED. (Inherits #103 L10.)
- **L11 (no new on-chain data)** #104b adds NOTHING to the chain beyond what #103 already broadcasts; no share / ciphertext / RWK / VDK ever leaves the device for the chain (#104 L4 structural).
- **L12** `forbid(unsafe_code)` + AGPL SPDX on every new file; no new `=`-pinned dep without `cargo deny`/`cargo audit` (expect ZERO new deps — #104b is pure composition over the merged #104a/#103 surfaces); §16 ledger; `git merge --no-ff`; every change needs explicit Kelvin approval (§16.3).

## 5a. RESOLVED decisions (Kelvin sign-off 2026-05-20)

All recommendations in §5 ACCEPTED. Two were explicitly discussed; the rest confirmed by "lock in unless you object" with no objection.

- **Q-a custody** → guardian opens their OWN sealed share, hands the recovering device only the opened piece. Guardian secret never leaves them.
- **Q-b two-key guardian identity** → derive BOTH keys (secp256k1 Approve-signer + X25519 share-opener) from the guardian's single `DeviceKey`. The merkle root commits secp256k1 addresses; sealing uses X25519 pubkeys; they MUST be the same person (L2).
- **Q-c forward-security re-split** → **YES, mandatory, re-seal to ALL M guardians, AUTOMATIC/non-interactive.** Discussed explicitly: "only re-share the t used" is CRYPTOGRAPHICALLY IMPOSSIBLE — all M shares are points on one polynomial tied to one RWK, so you cannot retire the exposed shares without retiring the whole key, and retiring the key requires fresh shares for all M (re-sealing fewer than M would degrade the scheme to t-of-(those few) and strand the rest). The re-seal is NOT a guardian ceremony: the device re-seals M fresh `SealedShare`s to the guardians' X25519 pubkeys with no guardian present; delivery/sync to the guardians is passive (the transport channel itself is 6.x). **Build-time sub-detail to resolve (does NOT block LOCK):** in a lost-everything recovery the device must (re)obtain ALL M guardian X25519 pubkeys to re-seal — participating guardians can supply theirs alongside their share, but the M−t non-participants' pubkeys need a source (recovered guardian-set backup, or opportunistic re-seal as they come online, or a recovery-time guardian-roster re-confirm). Resolve during the build; lean toward "recovered guardian-set config carries the pubkeys + opportunistic completion."
- **Q-d new-password-only-on-true-recovery** → confirmed. Normal new-phone device-add reuses the existing password (no guardians); guardians + new password only on lost-password recovery. Branch in `vault.rs`.
- **Q-e new device's secp256k1 born locally = `proposedAuthority`** → confirmed.
- **Q-f epoch vs attemptNonce** → independent counters; record the finalizing attemptNonce alongside the new epoch for audit.
- **Q-g store schema** → additive non-secret `recovery_escrow` table; locally-retained sealed-share copies additionally double-wrapped under the VDK column-AEAD for defence in depth.
- **Q-h share storage/transport** → #104b does local persistence + the in-memory hand-off the E2E exercises; human-to-human transport is 6.x.
- **Q-i FFI/uniffi** → deferred to 6.x; `pangolin-core::recovery` stays pure.
- **Q-j packaging** → ONE logical #104b stage (optionally two PRs on one branch); the coupled anvil E2E is the merge gate.
- **GAP FLAG 1 (X25519 guardian-key derivation)** → add `derive_x25519_sealing_key(&DeviceKey)` in `pangolin-crypto` AS PART OF #104b (not a separate mini-issue), with the same KAT/determinism tests as `evm.rs`, explicitly called out for the in-house adversarial audit as audit-critical key-derivation. GAP FLAGS 2 (epoch allocator) + 3 (re-split regenerates a fresh `WrappedVdkRecovery`) are orchestration responsibilities folded into L6/L7 — no primitive change.

## 5. Open decisions for Kelvin (Q-a … Q-j) — recommendation + plain-English stakes

**Q-a — who opens the sealed shares? (custody at recovery)**
- *Term:* "sealed share" = a guardian's piece of the recovery key, locked so only that guardian can open it.
- *Recommendation:* **each guardian opens their OWN share** (with their own secret) and hands the recovering device the opened piece. The guardian's secret never leaves them (matches #103 L5). The recovering device assembles ≥ t opened pieces and reconstructs.
- *Plain-English stakes:* this is "no single person holds the master key." A guardian only ever gives you their one piece; you need t of them together. The trade-off (already accepted as #104 Q-l): once t guardians cooperate, the recovering device DOES hold the reconstructed key — that is reconstruction working as designed. The on-chain 72h delay protects *ownership rotation*, not *secrecy against a colluding quorum*. **Stakes: this is the heart of "be your own guardians" — confirm the custody model is "guardian opens their own, hands over the piece."**

**Q-b — guardian identity: two keys per guardian (X25519 for sealing + secp256k1 for on-chain Approve).**
- *Term:* a guardian needs an X25519 public key (to receive their sealed share) AND a secp256k1 EVM address (to sign the on-chain `Approve` + be committed in the merkle root). These are different keys.
- *Recommendation:* derive BOTH from the guardian's single Pangolin `DeviceKey` (the established pattern: Ed25519 device key → `derive_evm_wallet` gives secp256k1; an analogous one-way derivation gives the X25519 sealing key). Store both per-guardian at onboarding; the merkle root commits the secp256k1 addresses, the sealing uses the X25519 pubkeys.
- *Plain-English stakes:* a guardian is one person with one Pangolin identity, but the chain and the encryption use different math, so we derive two public keys from their one identity. **Stakes: getting the two-key mapping right is L2 — if the merkle-committed guardian and the share-sealed guardian aren't the same person, recovery silently can't complete.** GAP FLAG below.

**Q-c — forward security: re-split the RWK after every recovery?**
- *Recommendation:* **YES, mandatory** (L6). After recovery, generate a fresh recovery key, re-split, re-seal to guardians, bump the epoch.
- *Plain-English stakes:* during recovery, t guardians' pieces were exposed (handed to the new device). If we didn't rotate, those same exposed pieces could recover the vault again later (e.g., a guardian who kept a copy). Rotating means the old pieces are dead. **UX cost: guardians must RE-RECEIVE their new pieces after a recovery** (a re-distribution step) — surfaced because it's a real "you must re-onboard your guardians" prompt. Confirm we accept that UX cost for the security.

**Q-d — new password ONLY on true recovery (confirm the branch).**
- *Recommendation:* confirm #104's Q-d resolution: normal "I got a new phone" device-add reuses the EXISTING password (no guardians); guardians + a NEW password are used ONLY when the password is lost. The branch point is a new `vault.rs` recovery entry, distinct from unlock/device-add.
- *Plain-English stakes:* a user who just bought a new phone shouldn't have to bother their guardians — they still know their password. Guardians are the "I forgot everything" path. **Stakes: confirm the two paths are genuinely separate so we don't accidentally route normal device-add through the guardian flow (annoying) or route recovery through the password (impossible — they lost it).**

**Q-e — the two authorities: is the new device's secp256k1 signer generated locally + committed as `proposedAuthority`?**
- *Recommendation:* **YES.** The new device generates a fresh `DeviceKey`, derives its secp256k1 EVM wallet locally, and that address is the `proposedAuthority` passed to `initiate_recovery_v1`. After finalize, the chain's `vaultAuthority` IS that address. Separately, the new password derives the VDK wrap-authority. (Wiring spelled out in §3 + L5.)
- *Plain-English stakes:* "who controls the vault on-chain" (anti-theft) and "what decrypts your data" (the password) are two separate locks; recovery changes both, and they don't interfere. **Stakes: confirm the new on-chain identity is born on the new device (not handed over by a guardian) — that's what makes the rotation a genuine ownership transfer to the user, not to a guardian.**

**Q-f — epoch vs on-chain `attemptNonce`: same counter or independent?**
- *Term:* `epoch` = the off-chain freshness tag baked into sealed shares (#104a). `attemptNonce` = the on-chain per-recovery-attempt counter (#103/#102).
- *Recommendation:* **independent counters.** The `epoch` advances on onboarding + on each successful recovery re-split (it tags share generations). The `attemptNonce` advances on each on-chain `initiate` (it tags rotation attempts, including failed/cancelled ones). Coupling them would mean a cancelled on-chain attempt rotates the off-chain shares (wasteful + a re-distribution prompt for nothing).
- *Plain-English stakes:* the chain counts "rotation attempts"; the escrow counts "share generations." A failed/cancelled rotation shouldn't force everyone to re-receive shares. **Stakes: keeping them separate avoids spurious "re-onboard your guardians" prompts on every cancelled attempt.** (We can still RECORD the finalizing attemptNonce alongside the new epoch for audit.)

**Q-g — store schema: do the new escrow rows go under the per-column AEAD?**
- *Recommendation:* the `WrappedVdkRecovery` (ciphertext/nonce/ctx), guardian X25519 pubkeys, t/M, and epoch are **non-secret at rest** → store as plain BLOBs in a new additive `recovery_escrow` table, same idiom as `meta.wrapped_ct`. The locally-retained **sealed shares** are also non-secret (encrypted to guardians) but recommend wrapping them in the existing under-VDK column-AEAD for defence in depth (so a stolen-at-rest `.pvf` reveals nothing about even the guardian assignment without the VDK), matching the `device_key` table's discipline.
- *Plain-English stakes:* what an attacker who steals the vault file sees. The recovery wrapper and sealed shares are already encrypted, but layering the vault's own encryption on the local copies costs nothing and hides the guardian map. **Stakes: confirm "additive non-secret table, sealed-share copies double-wrapped under the VDK" — or simpler "all plain BLOBs" if you prefer minimal complexity.**

**Q-h — share storage / distribution: where do shares live between onboarding and recovery?**
- *Term:* at onboarding we produce M sealed shares; they must reach the guardians.
- *Recommendation:* #104b persists locally (a) the guardian set + pubkeys + epoch + `WrappedVdkRecovery` (always), and (b) optionally a local encrypted backup copy of the sealed shares (the "be-your-own-guardians" value-prop — you can spread them across your own devices). The actual TRANSPORT to other people's guardian devices (QR, app channel, file) is **6.x UX, out of scope for #104b** (an app-channel concern, like #103's R-guardians "obtain the list later").
- *Plain-English stakes:* who physically holds the pieces. For "be your own guardians" you keep your own encrypted copies; for human guardians, the app later ships their piece to them. **Stakes: confirm #104b only does the local persistence + the in-memory hand-off the E2E exercises, and the human-to-human transport channel is explicitly 6.x.**

**Q-i — FFI/uniffi exposure: in #104b or deferred to 6.x?**
- *Recommendation:* **defer to 6.x.** Keep `pangolin-core::recovery` pure (zero-`uniffi`, per the crate's confirmed discipline + #103 Q3). The host-app entry points (onboard wizard, recovery wizard) are 6.x UX and will wrap these pure drivers then.
- *Plain-English stakes:* "can the phone app call this yet?" — not in #104b; #104b proves the logic + the regression gate, the app wiring is the next cycle. **Stakes: confirm we don't gold-plate #104b with FFI before the UX cycle needs it.**

**Q-j — land #104b as one PR or two on a single branch?**
- *Recommendation:* one #104b stage (do NOT split into separately-merged issues — §2). Optionally two reviewable PRs on one branch (core+store, then vault.rs+E2E) if size warrants.
- *Plain-English stakes:* purely a review-ergonomics call; either way the coupled E2E is the merge gate. **Stakes: low; confirm "one logical stage."**

## 6. Test posture

- **Hermetic (pangolin-core / pangolin-crypto):** onboarding round-trip (split→seal→open→reconstruct→unwrap == original VDK, `ct_eq`); the orchestration drivers over fixtures; threshold-equality guard (t/M out of bounds or ≠ on-chain rejected); forward-security re-split produces a fresh RWK that the OLD shares cannot reconstruct; epoch-mismatch share rejected; proptest over random (t, M, vault_id, VDK) for the full onboard→recover round-trip (≥1024 cases, mirroring `keys.rs`).
- **Store:** persist → reload → reconstruct round-trip for `WrappedVdkRecovery` + guardian set + epoch; `no_plaintext_on_disk`-style assertion for any under-VDK-AEAD rows (Q-g); additive-migration test (legacy vault opens, recovery columns absent → clean default).
- **vault.rs:** new-password-on-recovery re-wrap opens under the new password + FAILS under the old (the `WrappedVdk` already proves this shape); normal device-add does NOT touch the RWK/guardians (L8 branch).
- **Coupled anvil E2E (CENTERPIECE / L10):** in `pangolin-chain` integration-tests beside the #103 lifecycle test. Asserts: deploy → `setGuardianSet`(root from the SAME `build_guardian_root` over the SAME guardians whose X25519 shares were sealed) → `initiateRecovery`(new device secp256k1) → `approveRecovery`×t (real EIP-712) → 72h time-warp → `finalizeRecovery` (vaultAuthority == new device) → off-chain `open_sealed_share`×t → `reconstruct_rwk` → `unwrap_vdk_under_rwk` → `ct_eq` original VDK → set new password → re-wrap → re-split. **Negatives (must turn RED):** < t shares fail to reconstruct; a wrong guardian's share (sealed to a different X25519 key) fails to open; finalize-before-delay reverts (already #103); guardian-set/root mismatch between the sealed set and the merkle-committed set is caught. The audit must confirm a deliberately-broken guardian↔share mapping fails here.

## 7. Effort + risk

~2-3 weeks (vs #104a's catastrophic-core weight). #104b adds NO new crypto and NO new deps — the hard primitives are merged + audited. Risk is **integration correctness**, concentrated in two places: (1) **L2 the guardian-identity two-key mapping** (X25519-sealed guardian == secp256k1-merkle-committed guardian — silent-and-total if wrong, the env-quirk #14 class) and (2) **L5/L8 the dual-authority + new-password branch** (must not corrupt the daily wrap or strand the on-chain identity). The coupled anvil E2E is the structural defence for both. Lower headline risk than #104a, but the in-house adversarial audit must scrutinise the joins, not the primitives.

## 8. Where it lives

- `crates/pangolin-core/src/recovery/mod.rs` — extended with orchestration types + the two pure drivers (no chain, no uniffi, no serde-on-secrets).
- `crates/pangolin-store/src/recovery_escrow.rs` (new) + a `recovery_escrow` additive table in `schema.rs` — persistence following the `meta`/`device_key` idiom.
- `crates/pangolin-store/src/vault.rs` — the new-password-on-recovery entry (distinct from `unlock` / device-add).
- `crates/pangolin-chain/tests` (or the existing integration-tests module) — the coupled anvil E2E, beside `recovery_client`'s lifecycle test; `scripts/anvil-ci.sh` already deploys RecoveryV1 + funds wallets (extend the guardian funding if the E2E needs gas-paying guardians — it does NOT, guardians sign off-chain).

## 9. Whitepaper-alignment note

The whitepaper (§5.1 / §F) states the four invariants (guardians never see the VDK; recovery rotates authority not VDK; VDK re-wrapped not re-created; observable + cancelable) and explicitly defers the *construction* (Hardware/Session Spec §9 lists key-derivation + guardian-governance as NON-GOALS). #104b satisfies all four. The ONE thing the whitepaper's prose under-specifies and #104b makes concrete (must go into the Pangolin spec addendum + the audit package): **"rotate authority" is TWO rotations — the on-chain secp256k1 control authority AND the off-chain password-derived VDK-wrap authority — that happen together at recovery but are cryptographically independent.** The whitepaper's single-word "authority" hides this two-curve reality (already flagged in #104 Q-d). No conflict; an addendum clarification.

## 10. GAP FLAGS — where the merged #104a/#103 API may not cleanly support the flow

1. **(Q-b) No X25519 guardian-key derivation exists yet.** #104a's `seal_share` takes a raw `&[u8; 32]` X25519 pubkey, and `pangolin-chain::evm::derive_evm_wallet` gives the secp256k1 side, but there is **no `derive_x25519_sealing_key(&DeviceKey)` in the merged code**. #104b needs a guardian's X25519 keypair derivation that is (a) one-way from the device seed and (b) gives the guardian both their secp256k1 Approve-signer and their X25519 share-opener from one identity. This is a SMALL net-new derivation (HKDF over the device seed → X25519 scalar, mirroring the secp256k1 `evm.rs` pattern). **It is arguably a primitive-level addition (lives in `pangolin-crypto`), so flag whether it belongs in #104b or a tiny #104a-follow-up** — it touches key derivation, which the discipline treats as audit-critical. RECOMMEND: add it to `pangolin-crypto` within #104b with the same KAT/determinism tests as `evm.rs`, and call it out for the in-house audit.
2. **(epoch type) `EPOCH_LEN = 16` is a raw `[u8; 16]`.** #104a defines the epoch as 16 opaque bytes bound into the seal header but provides NO epoch allocator / monotonic source. #104b must define how the epoch is generated + advanced (Q-f) — recommend a stored monotonic counter in the `recovery_escrow` table, encoded big-endian into the 16 bytes. No primitive change needed; an orchestration responsibility.
3. **(wrap ctx vs epoch) the `WrappedVdkRecovery` binds `vault_id`+`schema_version` (via `WrapContext`) but NOT the epoch.** Only the SEALED SHARES bind the epoch. This is fine (the RWK rotates on re-split so the recovery wrapper is regenerated anyway), but #104b must ensure on re-split it produces a FRESH `WrappedVdkRecovery` under the new RWK (not reuse the old wrapper). No primitive change; an orchestration invariant (folded into L6). No other gaps found — the #104a/#103 surfaces otherwise compose cleanly.
