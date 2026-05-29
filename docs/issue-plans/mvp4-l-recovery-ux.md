<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# MVP-4-L — Social-recovery UX (decomposition + gap analysis) — plan-gate DRAFT

**Status: DRAFT — awaiting Kelvin sign-off on Q-a (first slice / sequencing), Q-b (the opened-share cross-device
transport — the crux), and Q-c (is a solo backup-only recovery path intended).** Unlike MVP-4-I/J/K, recovery is
NOT "thin UX over finished FFI": the crypto + lifecycle are built (#102/#103/#104a/#104b/#105/#106e/#108/#109)
and recovery is end-to-end *in-process* on testnet, but the **cross-device, multi-party** UX exposes real
FFI/engine gaps (§0c) — the biggest being that a guardian's opened share has no transport off their device. This
plan-gate decomposes recovery into shippable slices, documents the gaps, and asks for the scoping decisions
needed before any UX is built. **The whole recovery system stays TESTNET-ONLY until the D-011 external audit
(recovery is the most audit-critical surface in the product).**

---

## 0. One-paragraph summary

Pangolin social recovery is **Option 2** (true "lost everything — devices AND password" recovery): t-of-M
guardians enable VDK reconstruction WITHOUT the user's password, no single guardian sees the VDK, and a
successful recovery rotates the on-chain authority + re-keys + re-splits fresh shares to all M. There are **two
planes** the UX must drive in lockstep: the **on-chain lifecycle** (RecoveryV1: guardian-set merkle root,
PENDING attempt, t approvals, 72h delay, authority rotation — `recovery_lifecycle.rs`) and the **off-chain
escrow** (the actual threshold VDK secret-sharing — `recovery_ffi.rs` + the backup envelope in
`recovery_backup.rs`). The crypto is built; the *desktop UX + a few FFI gaps* are what remain. Recovery is too
big + too multi-party for one slice, so this plan proposes a sequence (gap-fill → solo backup → guardian
onboarding → guardian-side help → the full recovery wizard).

---

## 0a. The recovery model (recap) + the two planes

- **Option 2, threshold-shared (Kelvin 2026-05-20; whitepaper §F/§G4).** Guardians never see the password or
  the VDK. A `RecoveryWrapKey` is Shamir-split (`vsss-rs`) into M shares, each sealed (`crypto_box`) to a
  guardian's X25519 pubkey. t shares reconstruct the unwrap capability. The user needs to remember nothing.
- **Dual-authority rotation at recovery:** (1) the on-chain secp256k1 `vaultAuthority` (anti-hijack control
  plane) rotates to the new device; (2) the off-chain Ed25519 password-`AuthorityKey` is re-derived from the
  NEW password. The RWK escrow bridges so the new device recovers the VDK WITHOUT the old password.
- **Forward security:** every successful recovery re-splits a FRESH RWK + re-seals to ALL M guardians
  automatically (re-sealing fewer is cryptographically impossible). 
- **The two planes are only loosely coupled in code** — nothing forces the on-chain approve before the
  off-chain share-open; the canonical "do both" order lives in the coupled anvil E2E
  (`recovery_client.rs::recovery_escrow_coupled_e2e_against_anvil`).

## 0b. The built FFI surface (what the UX wraps)

- **Owner / setup:** `vault_onboard_guardians(handle, threshold, guardian_x25519_pubs) -> FfiOnboardingResult`
  (off-chain: split + seal + persist); `vault_set_guardian_set(handle, pw, config, guardian_evm_addrs,
  threshold) -> FfiTxOutcome` (on-chain merkle root + self-bootstrap authority); `vault_create_backup(handle,
  pw) -> FfiBackup` (24-word phrase + envelope).
- **Recovering user:** `vault_initiate_recovery(handle, pw, config, target_vault_id, proposed_authority,
  expires_at)`; `vault_finalize_recovery(handle, config, target_vault_id)` (permissionless after 72h+threshold);
  `vault_decode_backup(bytes, phrase) -> FfiBackupContents` (pure); `vault_recover_from_shares(...)` /
  `vault_recover_from_backup(handle, bytes, phrase, opened_shares, new_password) -> FfiRecoveryResult`.
- **Guardian:** `vault_approve_recovery(handle, config, target_vault_id, attempt_nonce, proposed_authority,
  expires_at, guardian_set) -> FfiTxOutcome` (on-chain, signature-only); `vault_guardian_open_share(handle,
  sealed_share, vault_id, epoch) -> Arc<FfiOpenedShare>` (off-chain release).
- **Anti-theft / reads:** `vault_cancel_recovery(handle, pw, config, target_vault_id)` (authority-only escape
  hatch); `vault_read_vault_authority(...) -> FfiVaultAuthority`; `vault_read_recovery_status(...) ->
  FfiRecoveryStatus`.
- Records: `FfiGuardianRoster`, `FfiOnboardingResult`, `FfiRecoveryResult`, `FfiTxOutcome`,
  `FfiVaultAuthority`, `FfiRecoveryStatus`, `FfiBackup`, `FfiBackupContents`, `FfiOpenedShare` (opaque).

## 0c. THE GAPS (why this isn't thin UX) — all verified against current code

1. **G-1 (the crux): a guardian's opened share has NO transport off their device.** `FfiOpenedShare` is an
   opaque `Arc` with only `byte_length()` — no serializer. In EVERY test the guardian-open and the
   `recover_from_shares` happen **in the same process** holding the same `Arc`s. Real cross-device recovery
   (guardian on device X, recovering user on device Y) has **no path to move the opened share**. Fixing it is a
   security-sensitive design decision (a naive "serialize the opened share" re-introduces the
   readable-secret-crosses-FFI concern the L1 discipline deliberately avoids). This is the single hardest part
   of recovery + the most external-audit-critical. See Q-b.
2. **G-2: no FFI to publish a guardian's identity.** Onboarding needs each guardian's X25519 sealing pubkey
   (off-chain seal) + EVM address (on-chain root), both derived from the guardian's `DeviceKey` — but
   `derive_x25519_sealing_key` is never `#[uniffi::export]`ed, and there's no guardian-invite payload codec
   (the pairing analog). A person literally cannot produce "here's my guardian identity" today. Blocks
   onboarding (Slice A).
3. **G-3: `approval_count` + `initiated_at` are hardcoded `0`** in `FfiRecoveryStatus`
   (`recovery_lifecycle.rs`). The UX can't show "2 of 3 approved" or compute the 72h countdown — the recovery
   analog of MVP-4-K's `read_pending_promotion` gap. Needs a chain-read expansion (the contract's live-attempt
   view + the FFI plumbing).
4. **G-4: the backup phrase alone cannot recover.** `vault_recover_from_backup` STILL requires t opened guardian
   shares; the envelope carries the wrapped-recovery + roster, NOT the shares. So there is **no true solo /
   be-your-own-guardian single-secret recovery** today (it would be net-new crypto). The phrase is an aid to
   the guardian flow, not a replacement. See Q-c.

---

## 1. Proposed decomposition (sequence)

| Slice | What | Gaps it needs | Multi-party? |
|---|---|---|---|
| **L-0 (gap-fill, engine/FFI — NOT UX)** | guardian-identity export (G-2) + chain-read expansion for approval_count/initiated_at (G-3) + the G-1 opened-share transport DESIGN + impl | resolves G-1/G-2/G-3 | n/a (engine) |
| **L-D — backup-phrase create (SOLO, easiest)** | `vault_create_backup` → show 24 words once + save envelope; a read-only "recovery health" panel (`vault_read_vault_authority` + status) | NONE | no |
| **L-A — guardian onboarding (owner)** | collect each guardian's identity → `vault_onboard_guardians` + `vault_set_guardian_set` | G-2 | yes |
| **L-C — guardian-side help** | "someone asked you to help recover" → `vault_approve_recovery` + `vault_guardian_open_share` + release | G-1 (share release), G-3 | yes |
| **L-B — recovering-user wizard (hardest, last)** | `vault_initiate_recovery` → poll status → collect approvals + shares → 72h → `vault_finalize_recovery` → `vault_recover_from_backup` | G-1, G-3 (+ needs L-A & L-C to test) | yes |

**Recommended order:** L-0 (gap-fill) → L-D (solo, demonstrable now) → L-A → L-C → L-B. L-D is the ONLY slice
with zero gaps; everything multi-party is blocked on L-0 (esp. G-1). The full recovery wizard (L-B) integrates
everything + must be last.

---

## 2. Open decisions — need Kelvin

**Q-a — What does THIS slice ship first?**
- **Option 1 (Recommended): L-D backup-create + a read-only recovery-health panel.** Zero gaps, fully
  testable solo, demonstrable now, and it's the artifact a user should make BEFORE relying on guardians. The
  multi-party guardian flows (A/C/B) wait behind the L-0 gap-fill (which gets its own plan-gate, esp. for the
  G-1 transport design). Honest + unblocks something real immediately.
- **Option 2: do L-0 (gap-fill) first, as an engine slice, then come back for the UX.** Front-loads the hard
  crypto/FFI (esp. G-1) before any recovery UX. Slower to any user-visible result, but unblocks the whole
  guardian track.
- **Option 3: attempt the full guardian onboarding+recovery UX now**, designing the G-1 transport inline. NOT
  recommended — G-1 is external-audit-critical net-new crypto that shouldn't be rushed inside a UX slice.

**Q-b — The G-1 opened-share cross-device transport (the crux). How to resolve it?** Today an opened share can't
leave the guardian's device. Options (this likely needs its own dedicated crypto plan-gate + D-011 attention,
not a snap decision):
- **Option 1: re-seal the opened share to the recovering user's ephemeral pubkey** for transport (the guardian
  opens, then re-seals to the requester; the requester unseals locally). Keeps "no plaintext share crosses a
  channel," but adds a recipient-pubkey handshake (like pairing) + a new sealed-transport codec.
- **Option 2: the recovering user holds the sealed shares (from the backup) + each guardian releases only their
  X25519 unseal capability** against a transported sealed blob. Different trust/data-flow; may simplify the
  backup's role.
- **Option 3: defer — spike a dedicated "recovery share transport" design plan-gate** before committing. Given
  the audit-criticality, this is the safe default.

**Q-c — Is a true SOLO backup-only recovery intended (recover with just the phrase, no guardians)?** Today it's
impossible (shares always required). A real single-secret path would be net-new crypto (e.g., the phrase itself
is a guardian-equivalent escrow). Options: (1) NO — guardians are always required; the phrase only aids the
guardian flow (frame L-D's messaging accordingly); (2) YES — design a phrase-as-escrow path (net-new crypto, a
separate plan-gate). This affects how L-D is messaged ("this backup helps your guardians recover you" vs "this
backup alone can recover you").

---

## 3. Out of scope / follow-ups (until the above is decided)

- The L-0 gap-fill (G-1/G-2/G-3) gets its own engine plan-gate once Q-b is decided.
- L-A / L-C / L-B UX slices: each its own plan-gate after L-0.
- Mainnet recovery — hard-gated behind D-011.

---

## 4. Recommendation

Ship **L-D (backup-phrase create) + the read-only recovery-health panel** as the immediate, gap-free slice
(Q-a Option 1), and spin the **G-1 transport design** into its own focused plan-gate (Q-b Option 3) since it's
the audit-critical crux that gates the entire guardian track. That gets a real recovery affordance in front of
users now while we design the hard part deliberately rather than rushing it inside a UX slice.
