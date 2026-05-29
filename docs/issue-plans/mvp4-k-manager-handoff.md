<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# MVP-4-K — Manager handoff / promotion (desktop) — plan-gate DRAFT

**Status: LOCKED — Kelvin sign-off 2026-05-29.** Q-a resolved: **Option 1 (promotion-only)** — ship
propose/finalize/veto + the pending-promotion UX; "leave the vault" = this handoff + the successor removing the
departing device via the existing MVP-4-J flow (a guided wrapper + "delete my local vault" is a follow-up).
Everything else self-locked (§0a RESOLVED + §5 carve-outs). Like MVP-4-J this adds **net-new,
security-sensitive engine code** (it signs + broadcasts an on-chain authorization), so it gets a dedicated
adversarial audit gated on `test` green. Follows MVP-4-J (device removal). The contract + chain broadcasts
already exist + are Foundry-tested; the new work is one small chain READ, the FFI wrappers, the cross-device
UX, and Rust/FFI test coverage (none exists today).

---

## 0. One-paragraph summary

Let a vault **transfer the manager role** to another authorized device, so a manager can eventually leave (a
manager can't remove itself or the last device — `ErrWouldBrickVault` — so handing off is the prerequisite to
leaving). Promotion is a **two-step, two-party, 48h-delayed, candidate-initiated** on-chain flow: the
**candidate device self-signs** a `Promote` authorization and broadcasts `proposePromotion` (the current
manager CANNOT do this — only the candidate's key satisfies the contract's `recovered == candidate` check);
after a mandatory **48-hour delay** anyone broadcasts `finalizePromotion` (permissionless) and the on-chain
manager pointer rotates to the candidate; during the window the **current manager may veto** via
`cancelPromotion` (sent from the manager's own address). Promotion is a **pure on-chain authority-pointer
change — NO VDK rotation, no re-wrap, no escrow re-point** (unlike removal): the new manager already holds its
per-device vault key from when it was added. This slice adds 4 thin FFI entry points + 1 small chain read + the
two-perspective desktop UX (candidate: "Become manager" → propose → finalize; manager: "promotion pending"
banner → veto).

---

## 0a. Decisions

### RESOLVED — Kelvin sign-off 2026-05-29

**Q-a — Scope = Option 1 (promotion-only).** Ship propose / finalize / veto + the pending-promotion UX. "Leave
the vault" is the composition: promote a successor (this slice, cross-device + 48h) → the successor (now
manager) removes the departing device via the EXISTING MVP-4-J `removeDevice` flow (run on the successor's
device). A guided "leave" wrapper + "delete my local vault" affordance is a follow-up (§8), not this slice.

### RESOLVED — self-locked (from the research + contract semantics)

- **R-1 — Promotion is candidate-initiated + cross-device.** The contract's `proposePromotion` requires a
  signature that recovers to the **candidate** (`RevisionLogV2.sol`: `recovered != candidate` reverts;
  `DeviceAuthKind::Promote` is "candidate self-signed"). So the propose FFI runs on the **candidate's** device
  with the candidate's session signer; the manager CANNOT initiate it. The UX is framed accordingly: on a
  non-manager device, a **"Become this vault's manager"** action; on the manager's device, a **veto** of a
  pending promotion. Coordination is out-of-band agreement ("you take over") + the on-chain pending state both
  devices read — NOT a pairing-style signed-blob/QR/SAS handoff (nothing crosses a substitutable channel, so
  no MITM/SAS concern).
- **R-2 — The 48h delay + the manager veto are kept (the security point).** The delay exists so a legitimate
  manager can cancel a rogue/coerced promotion. We ship the veto (`cancelPromotion`) + the pending-promotion
  banner so the delay is usable, not cosmetic. Finalize is **manual** ("Finalize now", enabled after `readyAt`)
  — NOT auto-finalize on app open (a silent role transfer would surprise the user; this action is deliberate).
- **R-3 — NO VDK rotation / re-wrap / escrow re-point.** Promotion only rotates the on-chain `deviceManager`
  pointer; it touches no set membership and no key material (the candidate already holds its per-device VDK
  wrap). So — unlike `vault_remove_device` — the promotion FFI has **no store follow-up**
  (`process_device_removed_trigger` / `vault_complete_rotation` are NOT involved). This makes it strictly
  simpler than removal.
- **R-4 — Four net-new thin FFI entry points + one small chain read:**
  1. **`vault_propose_promotion(handle, config)`** — candidate self-proposes. Mirrors `vault_remove_device`'s
     spine but: `kind = DeviceAuthKind::Promote`, `subject = THIS device's own signer`
     (`vault.evm_wallet()?.address()`, not a peer arg), broadcast `propose_promotion_v2`, NO store follow-up.
     Takes no master password (the session signer suffices). Returns the `readyAt` (or `()` — §5).
  2. **`vault_finalize_promotion(handle, config)`** — permissionless; session-gate → broadcast
     `finalize_promotion_v2(vault_id)`. Any device may run it (typically the candidate after the delay).
  3. **`vault_cancel_promotion(handle, config)`** — the manager's veto; session-gate → broadcast
     `cancel_promotion_v2(vault_id)`. The contract gates `cancelPromotion` on `msg.sender == currentManager`,
     and the broadcast is signed by THIS device's session wallet — so it only succeeds on the manager's device.
     The UX gates the affordance behind `is_manager` (from `vault_list_authorized_devices`) to fail fast.
  4. **`vault_read_pending_promotion(handle, config)`** — NEW chain read → `Option<FfiPendingPromotion {
     candidate: Vec<u8>, ready_at: u64 }>`. **Requires a small `pangolin-chain` addition**: a
     `pendingPromotion(bytes32)` line in the `sol!` binding + a `read_pending_promotion_v2` wrapper returning
     `(Address, u64)` (the binding currently omits `pendingPromotion`). Fail-closed. Drives the banner,
     countdown, and veto gating.
  Reuses the EXISTING `propose_promotion_v2` / `finalize_promotion_v2` / `cancel_promotion_v2` /
  `read_current_manager_v2` (all public in `pangolin-chain`) + `DeviceAuthKind::Promote` (signing).
- **R-5 — Reuse the MVP-4-I/J infrastructure**: the `Devices` screen, chain-config sourcing (fail-closed),
  `spawn_blocking` for all chain-touching commands, the testnet banner, the DesktopError + invoke.ts pattern,
  and the `vault_list_authorized_devices` rows (for `is_current` / `is_manager` markers + listing the
  promotable peers). Derive manager-status from that list (no separate `vault_current_manager` — consistent
  with MVP-4-J).
- **R-6 — Testing**: NEW Rust/FFI tests (none exist for promotion — the Foundry suite covers only the
  contract): FFI placeholder/session/fail-closed tests mirroring `vault_remove_device`'s, plus an anvil-driven
  core/FFI E2E (propose-as-candidate → warp 48h → finalize → assert `currentManager` rotated; + a veto path).
  Desktop Vitest (the "Become manager" propose gate, the pending banner + countdown, the manager-only veto
  gating, the manual-finalize-after-delay gate, fail-closed fallback). + a documented manual two-device smoke
  (§9).
- **R-7 — Drive-by fix:** `vault_remove_device`'s doc-comment references a `vault_current_manager` FFI that was
  built-then-dropped in MVP-4-J (stale reference). Correct it while here.

---

## 0b. What NOT to ship in this slice

- **A pairing-style signed-blob/QR/SAS handoff.** Promotion needs no cross-channel blob (each device signs +
  broadcasts its own tx); coordination is out-of-band + the on-chain pending state.
- **Auto-finalize.** Finalize stays a manual, deliberate action after the delay (R-2).
- **Self-remove for a non-manager.** The contract has none; "leave" is handoff + the successor removing you
  (MVP-4-J). A guided wrapper for that is Q-a Option 2 / a follow-up.
- **Recovery-authority interplay UX.** When a `RecoveryV1.vaultAuthority` is set, it overrides `deviceManager`;
  a promotion's effect would be masked until recovery clears. Out of scope beyond a read-back sanity note (§6).
- **Mainnet** — testnet-only until D-011.

---

## 1. Scope

Let an authorized device become the vault's manager (with the current manager able to veto), on Base Sepolia.

**Built in MVP-4-K:**
1. `pangolin-chain`: a `pendingPromotion` `sol!` binding line + `read_pending_promotion_v2(env, rpc_url,
   vault_id) -> Result<Option<(Address, u64)>, ChainError>` (the only new chain-layer code; the three
   promotion broadcasts already exist).
2. `pangolin-ffi`: `vault_propose_promotion` / `vault_finalize_promotion` / `vault_cancel_promotion` /
   `vault_read_pending_promotion` (+ `FfiPendingPromotion` record) + re-exports + `#[cfg(test)]` tests + an
   anvil E2E. Fix the stale `vault_current_manager` doc reference (R-7).
3. Desktop: Tauri commands wrapping the 4 FFI fns (all chain-touching → `spawn_blocking`) + invoke.ts wrappers
   + DTOs.
4. Devices-screen UX (two perspectives):
   - **Candidate (non-manager authorized device):** a "Become this vault's manager" action → confirm → propose
     (progress) → a "pending — ready in ~48h" state → after `readyAt`, a "Finalize" action → becomes manager.
   - **Manager:** a "promotion pending: 0x… — ready <when>" banner with a **Veto** action (`cancelPromotion`).
   - Both: render the pending state + countdown from `vault_read_pending_promotion`.
5. Vitest + the §9 manual two-device smoke.

**Engine primitives reused (built + Foundry-tested):** `proposePromotion`/`finalizePromotion`/`cancelPromotion`
(contract) → `propose_promotion_v2`/`finalize_promotion_v2`/`cancel_promotion_v2` (pangolin-chain) +
`DeviceAuthKind::Promote` + `read_current_manager_v2`. Canonical order (Foundry `test_promotion_happyPath`):
candidate self-signs Promote(candidate, live-nonce) → `proposePromotion` (starts 48h clock) → warp →
`finalizePromotion` → `deviceManager == candidate`.

---

## 2. Splittable? — engine (chain read + FFI) first, then UX (ONE slice, two review surfaces)

The chain read + 4 FFI fns + UX ship together (the UX is untestable without them). The **adversarial audit's
primary surface is the new engine/chain code** — especially `vault_propose_promotion` (it self-signs +
broadcasts an authorization) and the `cancel`/manager-gating. If the FFI work is large, it may land first
(behind the UX); but there's no user value until the UX lands, so default to one slice.

---

## 3. Design

### 3.1 The cross-device, 48h choreography

```
Candidate device B (a non-manager authorized device):
  Devices → "Become this vault's manager" → confirm →
    vault_propose_promotion(config)      // B self-signs Promote(subject=B), broadcast proposePromotion
                                         //   → 48h clock starts  [spawn_blocking]
  … (≥48h later) … Devices shows "ready to finalize" →
    vault_finalize_promotion(config)     // permissionless broadcast → deviceManager := B
  B is now the manager.

Manager device A (during the 48h window):
  Devices shows "Promotion pending: 0x<B>… — ready <when>" (from vault_read_pending_promotion) →
    [Veto] → vault_cancel_promotion(config)   // msg.sender==A==manager → clears the pending promotion
```

No master password, no VDK rotation, no cross-channel blob. Each device signs + broadcasts its own tx; the
shared on-chain pending state (read fail-closed) is how both sides see the in-flight promotion.

### 3.2 New Tauri commands (all chain-touching → `spawn_blocking`)

| Tauri command | Wraps | Returns |
|---|---|---|
| `pairing_propose_promotion` | `vault_propose_promotion` | `PromotionPendingDto` (candidate hex + readyAt) or `()` |
| `pairing_finalize_promotion` | `vault_finalize_promotion` | `()` |
| `pairing_cancel_promotion` | `vault_cancel_promotion` | `()` |
| `pairing_pending_promotion` | `vault_read_pending_promotion` | `PromotionPendingDto \| null` |

### 3.3 Devices-screen UX

Extends the MVP-4-J manager-aware screen. From `vault_list_authorized_devices` we know `is_current` /
`is_manager`; from `vault_read_pending_promotion` we know any in-flight promotion. Branches:
- **This device is a non-manager authorized device + no pending promotion:** show a "Become this vault's
  manager" action (propose).
- **A promotion is pending:**
  - **on the candidate's device:** "Pending — ready <countdown>"; after `readyAt`, a "Finalize" button.
  - **on the manager's device:** a banner "0x<candidate>… wants to become manager — ready <when>" + "Veto".
  - **on a third device:** informational "promotion pending" (may also finalize after the delay —
    permissionless).
Confirmations name the candidate; the testnet banner persists.

---

## 4. L-invariants

- **L1 — no secret crosses.** Signer/candidate addresses, the pending state, `readyAt`, and the manager pointer
  are all non-secret. The candidate's session signer signs engine-side + never crosses FFI. NO master password
  is needed (promotion changes no key material). The VDK/RWK are never touched (R-3).
- **L2 — authorization is contract-enforced + UX-pre-checked.** Propose succeeds only with the candidate's own
  signature (`recovered == candidate`); veto succeeds only from the manager's address. The UX gates the veto
  behind `is_manager` and the propose behind "this is a non-manager authorized device", but the contract is the
  source of truth (fail-closed on a wrong-device attempt).
- **L3 — fail-closed.** `vault_read_pending_promotion` + the broadcasts surface chain errors as typed
  `DesktopError` (incl. `ErrPromotionPending`, `ErrPromotionDelayNotElapsed`, `ErrNotSetMember`,
  `ErrNotAuthorizedToCancel`); the UX never fabricates a pending state or a success.
- **L4 — session-gated.** All handle-bearing commands require Active (FFI). 
- **L7 — errors carry no secret** (addresses + revert names only).

---

## 5. Open decisions — pre-locked (builder carve-outs)

- **`vault_propose_promotion` return shape** — `PromotionPendingDto` (candidate + `readyAt`) is preferred so
  the UX can show the countdown immediately without a follow-up read; if cleanly reading `readyAt` back from
  the broadcast receipt is awkward, return `()` and have the UX call `vault_read_pending_promotion` right
  after. Builder's call.
- **The `pendingPromotion` `sol!` binding + `read_pending_promotion_v2`** — add the public-getter binding line
  + a thin read wrapper returning `Option<(Address, u64)>` (`readyAt == 0` ⇒ `None`). Builder mirrors the
  existing `read_current_manager_v2` shape.
- **FFI module placement** (extend `pairing.rs` vs a new `promotion.rs`) — builder's call.
- **Countdown rendering** (absolute time vs "ready in Nh") — builder's call.
- **Confirm friction** on propose/veto — builder picks within a clear destructive-confirm.

---

## 6. Places that need care

- **The candidate signs, not the manager (the inversion).** It is easy to wrongly model this as
  manager-driven. `vault_propose_promotion` MUST use THIS device's own signer as BOTH the signer and the
  `subject` (self-proposal). A manager-signed Promote reverts `ErrInvalidSignature` (Foundry-proven). Frame the
  UX as candidate-initiated.
- **The 48h delay is real + unskippable.** The UX must set expectations ("ready in ~2 days") and persist the
  pending state across app restarts (it's on-chain — re-read on each Devices open). Finalize is manual after
  `readyAt`.
- **`cancelPromotion` is `msg.sender`-gated, not signature-gated.** `vault_cancel_promotion` only works when
  THIS device's wallet IS the current manager. Gate the affordance behind `is_manager`; a non-manager attempt
  fails-closed (`ErrNotAuthorizedToCancel`).
- **`finalizePromotion` is permissionless + does NOT bump the device nonce** (only propose does) — don't
  re-read/assert the nonce around finalize.
- **RecoveryV1.vaultAuthority override.** If a guardian recovery has set `vaultAuthority`, it overrides
  `deviceManager`, so a finalized promotion's effect is masked until recovery clears. Read `currentManager`
  before/after to confirm the rotation actually changed the effective manager; surface a clear note if not.
- **No VDK rotation here** — do NOT call `process_device_removed_trigger` / `vault_complete_rotation` (that's
  removal). Promotion is set-membership-neutral.
- **`spawn_blocking` for all four commands** (nested-runtime trap, as MVP-4-I/J). Gas on the broadcasting
  device's signer (testnet funding caveat).

---

## 7. Success criteria

- `apps/desktop`: typecheck / lint / Vitest / build ✓ (propose gate on a non-manager device; manager-only
  veto; manual-finalize-after-delay; pending banner + countdown; fail-closed fallback).
- Rust: `cargo fmt --check` ✓ + `cargo clippy --workspace --all-targets -- -D warnings` ✓ +
  `cargo test --workspace` ✓ (NEW FFI unit tests + a NEW anvil promotion E2E — propose→warp→finalize +
  veto) + audit/deny ✓ + cardinal invariants 0/0/0/0. The new FFI carries doc + `#[cfg(test)]` tests mirroring
  `vault_remove_device`.
- The new commands appear in `lib.rs` `generate_handler!`.
- **Adversarial audit of the new engine/chain FFI = 0 HIGH** (esp. `vault_propose_promotion`'s self-sign + the
  veto gating + the new chain read).
- Existing desktop + extension + both E2E jobs still pass.
- **§9 manual two-device smoke** (promote a real device on Base Sepolia, observe the 48h gate, finalize, + a
  veto run) — NOT a CI gate; recorded before beta.
- CI green on `ubuntu-latest` + the matrix after merge.

---

## 8. Out of scope (filed for follow-up)

- **Guided "leave the vault" wrapper + "delete my local vault"** (Q-a Option 1 → follow-up): explanatory flow
  composing handoff + the successor's MVP-4-J removal.
- **Recovery-authority interplay UX** (beyond the read-back note).
- **Push/event-driven promotion notifications** (the desktop polls the pending state on Devices-screen open;
  no background chain-event subscription this slice).
- **Mainnet** — D-011-gated.

---

## 9. Manual two-device smoke test (run before beta)

On a manager device A + a peer device B, both on Base Sepolia (signers funded):
1. Pair B (MVP-4-I) so B is an authorized non-manager device.
2. On **B**: Devices → "Become this vault's manager" → confirm → watch `proposePromotion` confirm → B shows
   "pending — ready <~48h>". (To exercise the delay quickly, the anvil E2E warps time; the live smoke documents
   the real 48h.)
3. On **A**: confirm the "promotion pending" banner appears (via `vault_read_pending_promotion`). Optionally
   **Veto** → confirm `cancelPromotion` clears it (then re-propose to continue).
4. After `readyAt`: on **B** (or any device) → "Finalize" → watch `finalizePromotion` confirm → on-chain
   `currentManager` (Basescan / `read_current_manager_v2`) is now B.
5. Confirm role transfer: B can now add/remove devices; A's add/remove now reverts `ErrNotDeviceManager`.
6. "Leave" composition: B (new manager) removes A via the MVP-4-J flow; confirm A drops from the set + the VDK
   rotates (forward secrecy) — this is the MVP-4-J smoke, run on B.
Record the run (screencast + the propose/finalize tx hashes) before beta.
