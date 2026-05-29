<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# MVP-4-J — Device removal + VDK rotation (desktop) — plan-gate DRAFT

**Status: DRAFT — awaiting Kelvin sign-off on Q-a (rotation-completion flow) + Q-b (manager-only scope).**
Everything else self-locked (§0a RESOLVED + §5 carve-outs). Unlike MVP-4-I (pure UI), this slice adds
**net-new, security-sensitive engine code** — it must get a dedicated adversarial audit of the new FFI/chain
path, gated on `test` green (per the autonomy directive). Follows MVP-4-I (the add-device slice).

---

## 0. One-paragraph summary

Let the vault **manager** remove a paired device, on Base Sepolia testnet. Removing a device is two engine
operations the desktop must choreograph: (1) **`vault_remove_device`** signs an EIP-712 `RemoveDevice`
authorization engine-side, broadcasts the on-chain `removeDevice`, and queues a local rotation-pending row; then
(2) the mandatory **VDK rotation** (`vault_complete_rotation`) re-keys the vault to the surviving devices,
advances the epoch, re-points the guardian escrow, and prompts for the master password — so the removed device
(which still holds the OLD vault key) can no longer decrypt data written AFTER the removal (forward secrecy;
pre-removal history stays readable by it forever — unretractable, by design). The slice adds three thin FFI
entry points + the desktop "manage devices" + remove + rotate UX, reusing the already-built + audited rotation
crypto (#106b-2 / #106c / #106d).

---

## 0a. Decisions

### OPEN — need Kelvin (resolve at sign-off)

**Q-a — How forcefully does the UX drive the mandatory VDK rotation after a removal?**
`removeDevice` (on-chain) and the VDK rotation (local re-key, needs the master password) are two separate engine
ops. Between them there is a **forward-secrecy gap**: the removed device is out of the on-chain set immediately
(its future *publishes* are unhonored — #106d read-gate), but it still physically holds the old VDK, so it can
still *decrypt* new data until the rotation completes. The engine deliberately supports a **resumable,
crash-durable "rotation-pending" state** (#106c) so the user *can* defer. Options:

| Option | Flow | Forward-secrecy gap | Notes |
|---|---|---|---|
| **1. Single guided flow (Recommended)** | "Remove device" → confirm → enter master password → broadcast `removeDevice` → **immediately** complete rotation → done. A resumable "rotation pending" banner is the SAFETY NET if the app dies mid-flow. | Minimal (seconds) | Best forward secrecy; one uninterrupted action. Matches "revoke prompts for the master password" (LOCKED #106b-2). |
| **2. Two explicit steps** | "Remove device" broadcasts + queues → a persistent "Rotation pending — finish to fully lock out the removed device" surface the user completes later. | Wider (until the user returns) | More flexible; leans on the engine's resumable model; larger window where the removed device can still read new data. |

Recommendation: **Option 1** — drive remove→rotate as one flow to minimize the gap, with the resumable
pending-rotation banner as a crash safety net (built either way). Q-a is really "is deferral a first-class path
or just a recovery path?"

**Q-b — Manager-only scope: handle manager handoff now, or defer promotion to a later slice?**
The contract allows ONLY the current **manager** to remove a device, and it CANNOT remove itself or the last
device (`ErrWouldBrickVault`) — a manager who wants to leave must first **promote a successor**
(`proposePromotion`/`finalizePromotion`), which is a separate crypto-chain surface that is ALSO not exposed via
FFI. Options:

- **Option 1 (Recommended): manager-removes-peers only.** This slice = the manager removes other devices. A
  non-manager device shows a read-only device list + "Only the manager device can remove devices." Manager
  handoff / self-removal / promotion is a dedicated future slice (MVP-4-K). Keeps the audit surface to the
  remove+rotate path.
- **Option 2: also build promotion/handoff.** Add the promotion FFI + UX so a manager can transfer the role and
  leave. Much larger; two security-sensitive chain flows in one audit.

Recommendation: **Option 1** — promotion is its own unexposed surface; bundling it doubles the new-crypto audit.

### RESOLVED — self-locked (from the research + LOCKED #106b-2/#106c/#106d decisions)

- **R-1 — Removal MUST be followed by a VDK rotation; rotation is host-driven + master-password-prompted.**
  LOCKED in #106b-2 (Q "password-anchor on rotation" = prompt). `vault_complete_rotation` already takes the
  master password + chain config, reads the LIVE on-chain set fail-closed, re-keys to survivors, re-splits a
  fresh RWK' to all guardians (mandatory — skipping strands recovery), advances the shared per-vault epoch, and
  leaves the vault Locked. The UX re-unlocks after.
- **R-2 — Three net-new thin FFI entry points** (the research found `device_list` is the LOCAL trust list and
  cannot enumerate peer devices; the removal trigger + the set/manager reads are all unexposed):
  1. **`vault_remove_device(handle, master_password, config, signer_to_remove: Vec<u8>)`** — mirrors
     `vault_add_device`'s spine (L4 gate → engine signer → `block_on_local` → `ffi_chain_env_and_id` →
     `load_deployed_address` → `read_device_nonce_v2` → `build_signed_device_auth{kind: RemoveDevice, subject:
     signer_to_remove, nonce}` → `remove_device_v2`), then **queues the rotation-pending row** via
     `vault.process_device_removed_trigger(&new_on_chain_set, &[signer_to_remove], observed_epoch)` so
     `vault_pending_rotations` reports it. Drops the seal + directory-write steps. Returns `()` (or a small
     anchor record). **This queue step is the gap MVP-4-J closes** — nothing else writes the pending row.
  2. **`vault_list_authorized_devices(handle, config)`** — reads the live on-chain authorized set
     (`read_authorized_set_v2`), joined with the local `device_directory()` for any known `(signer, device_id,
     pairing_pub)`, so the UX can present removable peers by their 20-byte signer address (+ "this device" /
     "manager" markers). Fail-closed on a set-read error.
  3. **`vault_current_manager(handle, config)`** — exposes `read_current_manager_v2` so the UX can pre-check
     "is THIS device the manager?" and disable/explain removal otherwise.
  Reuses the EXISTING `vault_pending_rotations` + `vault_complete_rotation` (rotation_ffi.rs) verbatim.
- **R-3 — UX pre-checks mirror the contract guards (fail fast, save gas).** Before broadcasting, the UX
  verifies: this device == manager (`vault_current_manager`); the target is in the set; the target ≠ manager;
  authorized-device count > 1. The contract enforces all of these (`ErrNotDeviceManager`, `ErrNotAuthorized`,
  `ErrWouldBrickVault`), but pre-checking avoids a wasted gas tx + a cryptic revert.
- **R-4 — Removal is destructive + irreversible + on-chain → a strong confirm.** A type-to-confirm or explicit
  two-step confirm naming the device/address, plus the testnet banner (carried from MVP-4-I).
- **R-5 — Reuse the MVP-4-I infrastructure**: the `Devices` screen, the chain-config sourcing
  (`PANGOLIN_RPC_URL` / `PANGOLIN_DEPLOYMENT_PATH`, fail-closed), the `spawn_blocking` discipline for the
  chain-touching commands (`vault_remove_device`, `vault_complete_rotation`, `vault_list_authorized_devices`,
  `vault_current_manager` all do chain reads/writes via `block_on_local` → must run off the async runtime), and
  the testnet banner. The DesktopError envelope + invoke.ts pattern carry over.
- **R-6 — Testing = Rust FFI unit tests (mirror the `vault_add_device` arg/gate/error tests) + reuse the
  existing `anvil_device_e2e.rs` as the canonical engine proof + desktop Vitest (the remove confirm gate, the
  pre-check disabling, the rotation prompt, the resumable pending banner) + a documented MANUAL multi-device
  smoke test (§9).** The full automated multi-device-against-a-live-chain desktop E2E stays OUT (the FFI flow is
  already proven by `anvil_device_e2e.rs::complete_rotation_public_composition_e2e_against_anvil`).

---

## 0b. What NOT to ship in this slice

- **Manager handoff / promotion / self-removal** (Q-b Option 1 → MVP-4-K): `proposePromotion` /
  `finalizePromotion` FFI + UX. A manager cannot leave the vault this slice.
- **Recovery UX, sync-status UX** — separate back-half slices.
- **Auto-rotation / background rotation** — rotation stays explicitly host-driven + password-prompted (LOCKED).
- **Un-removing / re-adding** a device is just the MVP-4-I add flow (re-pair); not special-cased here (the
  #106d read-gate already un-revokes a re-added signer's stored revisions).
- **Mainnet** — testnet-only until D-011.

---

## 1. Scope

Wire the manager's desktop to remove a peer device + rotate the vault key, end to end on Base Sepolia.

**Built in MVP-4-J:**
1. Three net-new FFI entry points (R-2) in `crates/pangolin-ffi/src/` (extend `pairing.rs` or a new
   `device_lifecycle.rs`) + their `pub use` re-exports, with `#[cfg(test)]` unit tests mirroring the
   `vault_add_device` tests (length/gate/error-mapping; the live-chain behavior is covered by
   `anvil_device_e2e.rs`).
2. Desktop Tauri commands wrapping the three new FFI fns + the existing `vault_pending_rotations` /
   `vault_complete_rotation`, registered in `lib.rs` (all chain-touching → `spawn_blocking`).
3. `invoke.ts` wrappers + DTOs (authorized-device list, manager address, rotation-pending, rotation-result).
4. **Devices screen upgrade**: the read-only list (MVP-4-I) becomes a **manager-aware** list driven by
   `vault_list_authorized_devices` — each removable peer gets a "Remove" action (disabled w/ explanation when
   this device isn't the manager); a persistent "rotation pending" banner when `vault_pending_rotations` is
   non-empty.
5. **Remove + rotate flow**: confirm (R-4) → `vault_remove_device` (broadcast + queue) → master-password prompt
   → `vault_complete_rotation` → `vault_unlock` → done. (Exact single-vs-two-step per Q-a.)
6. Vitest + the §9 manual multi-device smoke test.

**Engine primitives reused (already built + audited):** `remove_device_v2`, `build_signed_device_auth` +
`DeviceAuthKind::RemoveDevice`, `read_device_nonce_v2`, `read_authorized_set_v2`, `read_current_manager_v2`
(pangolin-chain); `Vault::process_device_removed_trigger`, `device_directory()`, `pending_rotations()`
(pangolin-store); `composition::complete_rotation` (pangolin-core); `vault_pending_rotations` /
`vault_complete_rotation` (pangolin-ffi). The canonical call order is
`anvil_device_e2e.rs::complete_rotation_public_composition_e2e_against_anvil` (lines ~356–568): bootstrap →
addDevice ×2 → `remove_device_v2` → `process_device_removed_trigger` → `complete_rotation` → assert the removed
device is locked out of the new epoch + a survivor is not.

---

## 2. Splittable? — engine FFI first, then UX (ONE slice, two review surfaces)

The three FFI entry points + the UX ship together (the UX is untestable without the FFI), but the **adversarial
audit must treat the new engine/chain code (`vault_remove_device` + the queue step + the set/manager reads) as
the primary surface** — it signs + broadcasts an authorization and mutates the key hierarchy. If the builder
finds the FFI work alone is large, `vault_remove_device` + tests may land first (behind the UX) — but there is
no user value until the UX lands, so default to one slice.

---

## 3. Design

### 3.1 The remove + rotate choreography

```
Manager device (the only device allowed to remove):
  Devices screen → vault_list_authorized_devices(config)  // live on-chain set + local directory join
                 → vault_current_manager(config)           // is THIS device the manager?
  pick a peer → CONFIRM (destructive, names the device) →
  enter master password →
    vault_remove_device(pw, config, signer_to_remove)      // sign RemoveDevice, broadcast removeDevice,
                                                           //   queue rotation-pending  [spawn_blocking]
    → vault_complete_rotation(pw, config)                  // read live set (fail-closed), re-key survivors,
                                                           //   re-split RWK' to guardians, epoch++, Locked
    → vault_unlock(pw)                                     // re-activate the now-rotated vault
  done.  (Resumable: if interrupted after remove, vault_pending_rotations() != [] → "rotation pending" banner
         drives vault_complete_rotation on the next Devices-screen open.)
```

All signing + the VDK re-key happen engine-side; the removed signer (a 20-byte address) and the manager address
are non-secret; the master password crosses via the existing `SecretPassword::new(String)` path (no new secret
surface). The contract enforces manager-only + no-brick; the UX pre-checks the same to fail fast.

### 3.2 New Tauri commands (all chain-touching → `spawn_blocking`)

| Tauri command | Wraps | Returns |
|---|---|---|
| `pairing_list_authorized_devices` | `vault_list_authorized_devices` | `AuthorizedDeviceDto[]` (signer hex, isCurrent, isManager, label-if-known) |
| `pairing_current_manager` | `vault_current_manager` | manager signer hex |
| `pairing_remove_device` | `vault_remove_device` | `()` |
| `pairing_pending_rotations` | `vault_pending_rotations` (existing FFI) | `RotationPendingDto[]` |
| `pairing_complete_rotation` | `vault_complete_rotation` (existing FFI) | `RotationResultDto` (newEpoch, unknownSurvivors) |

### 3.3 Devices screen upgrade

The MVP-4-I read-only list becomes manager-aware: rows from `vault_list_authorized_devices` (on-chain set,
authoritative — vs the local-only `device_list`), each with a Remove button gated on `isManager`-of-this-device.
A non-manager sees the list + "Only the manager device can remove devices." A pending rotation surfaces a
prominent banner. The remove flow is a wizard (confirm → password → broadcast progress → rotation progress →
done), reusing the MVP-4-I wizard chrome + spinners + testnet banner.

---

## 4. L-invariants

- **L1 — no NEW secret crosses.** Signer addresses, the authorized set, the manager address, rotation epochs,
  and unknown-survivor lists are all non-secret. The master password crosses via the existing `vault_unlock`
  path (`SecretPassword::new`). The VDK/RWK never cross (re-key + re-split are engine-side).
- **L2 — forward-secrecy is the load-bearing security goal.** Removal alone is NOT sufficient — the UX MUST
  drive (or unmistakably surface) the VDK rotation, or the removed device keeps decrypting new data. The
  resumable pending-rotation banner is mandatory regardless of Q-a so an interrupted removal cannot silently
  leave the gap open.
- **L3 — fail-closed.** `vault_complete_rotation` + `vault_list_authorized_devices` read the live set
  fail-closed (chain error → `DesktopError::Chain`, never honor-all / never a stale set). The remove broadcast
  surfaces chain errors (incl. `ErrWouldBrickVault`, `ErrNotDeviceManager`, `ErrBadNonce`) as typed errors.
- **L4 — session + authorization gated.** All handle-bearing commands require Active (FFI). Removal is
  manager-only (contract-enforced via the recovered `authoritySig`; UX pre-checks).
- **L7 — errors carry no secret.** Chain/Display errors are non-secret (addresses + revert names only).

---

## 5. Open decisions — pre-locked (builder carve-outs)

- **Where `vault_remove_device` queues the pending rotation** — inside the FFI fn after a successful broadcast
  (preferred, per the research) by calling `process_device_removed_trigger` with the freshly-read post-removal
  set + the removed signer + the observed epoch. Builder confirms the exact `observed_epoch` source (the
  current vault epoch) + that the new set is read after the broadcast confirms.
- **FFI module placement** (`pairing.rs` vs a new `device_lifecycle.rs`) — builder's call.
- **Return shape** of `vault_remove_device` (`()` vs a small anchor record with the tx hash) — builder's call;
  the UX only needs success/failure + then drives the rotation.
- **`AuthorizedDeviceDto` content** — signer hex + isCurrent + isManager are required; the local
  `device_directory` join for a friendly label is best-effort (peer LABELS live in each peer's own `.pvf` and
  are NOT available cross-device — the UX shows the signer address + role markers; this is a known limitation,
  not a fork).
- **Confirm friction** (type-to-confirm vs two-tap) — builder picks within R-4.

---

## 6. Places that need care

- **The forward-secrecy gap (the #1 thing).** Order matters: broadcast `removeDevice` FIRST (so the read-gate
  stops honoring the removed device's publishes), THEN rotate (so it loses decrypt on new data). If rotation is
  skipped/deferred, the gap is real — make the pending-rotation banner impossible to miss.
- **The queue step is the gap that didn't exist before.** `process_device_removed_trigger` is the ONLY thing
  that writes the rotation-pending row, and it is not auto-wired into sync. If `vault_remove_device` doesn't
  call it, `vault_pending_rotations` returns empty + the rotation has nothing to drive. Verify the pending row
  is written + resolved (the resolve happens inside `complete_rotation`).
- **Manager pre-check + no-brick.** A manager removing itself or the last device reverts `ErrWouldBrickVault`;
  a non-manager device reverts `ErrNotDeviceManager`. Pre-check `vault_current_manager` == this device's
  `evm_address`, target ≠ manager, count > 1 — all before spending gas.
- **`device_list` is NOT the authorized set.** Use `vault_list_authorized_devices` (on-chain) for the removable
  list; the local `device_list` typically only shows the current device.
- **The vault is Locked after `vault_complete_rotation`** — the UX must re-`vault_unlock` (the password may be
  the same; the anchor was re-written under the new VDK). Mirror the engine sequence.
- **`spawn_blocking` for all four chain commands** (same nested-runtime trap as MVP-4-I).
- **Gas on the manager's signer** (same testnet funding caveat as MVP-4-I; surface a clear error + faucet hint).

---

## 7. Success criteria

- `apps/desktop`: typecheck / lint / Vitest / build ✓ (remove confirm gate; non-manager disables removal;
  rotation prompt + resumable pending banner; pre-check logic).
- Rust: `cargo fmt --check` ✓ + `cargo clippy --workspace --all-targets -- -D warnings` ✓ +
  `cargo test --workspace` ✓ (new FFI unit tests + the existing anvil device E2E still green) + audit/deny ✓ +
  cardinal invariants 0/0/0/0. **The new FFI entry points carry doc + `#[cfg(test)]` arg/gate/error tests
  mirroring `vault_add_device`.**
- The new commands appear in `lib.rs` `generate_handler!`.
- **Adversarial audit of the new engine/chain FFI = 0 HIGH** (the security-sensitive surface this slice adds).
- Existing desktop + extension + both E2E jobs still pass.
- **§9 manual multi-device smoke** (remove a real device on Base Sepolia + confirm the removed device can no
  longer decrypt new data) — NOT a CI gate; recorded before beta.
- CI green on `ubuntu-latest` + the matrix after merge.

---

## 8. Out of scope (filed for follow-up)

- **MVP-4-K — manager handoff / promotion** (`proposePromotion` / `finalizePromotion` FFI + UX; lets a manager
  transfer the role + leave; self-removal).
- **Automated multi-device desktop E2E against a live/anvil chain** (the FFI flow is proven by
  `anvil_device_e2e.rs`).
- **MVP-4-I camera-permission** (Linux WebKitGTK) + recovery/sync UX — unrelated back-half items.
- **Mainnet** — D-011-gated.

---

## 9. Manual multi-device smoke test (run before beta)

On the manager device + a peer device, both on Base Sepolia (manager signer funded):
1. Pair a peer (MVP-4-I add flow) so the vault has ≥ 2 authorized devices.
2. Manager → Devices → confirm the peer appears in `vault_list_authorized_devices` with its signer address.
3. Remove the peer → enter master password → watch the `removeDevice` tx confirm → watch the rotation complete →
   vault re-unlocks.
4. Verify on-chain (`read_authorized_set_v2` / Basescan) the peer's signer is OUT of the set, and the vault
   epoch advanced.
5. **Forward-secrecy check:** write a NEW account on the manager; confirm the removed peer (still holding its
   old vault key) CANNOT decrypt the new account, but CAN still read pre-removal entries (unretractable history).
6. Negative checks: a non-manager device shows no Remove affordance; attempting to remove the manager or the
   last device is blocked (pre-check + contract `ErrWouldBrickVault`).
Record the run (screencast + the removeDevice tx hash) before beta.
