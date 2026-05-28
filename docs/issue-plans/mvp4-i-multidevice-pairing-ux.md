<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# MVP-4-I — Multi-device pairing UX (desktop "Devices" flow) — plan-gate DRAFT

**Status: DRAFT — awaiting Kelvin sign-off on Q-a (transport channel) + Q-b (revocation scope).**
All other engineering choices self-locked (§0a RESOLVED + §5 builder carve-outs). The full pairing
crypto + on-chain handshake is already built + audited at the FFI layer (8 functions in
`crates/pangolin-ffi/src/pairing.rs`, proven end-to-end in `crates/pangolin-ffi/tests/anvil_pairing_e2e.rs`);
this slice builds ONLY the desktop UI + the thin Tauri-command layer that wires that surface to a human flow.

> Lettering note: `MVP-4-H` is reserved for the pre-mainnet **secure-input** slice (native-Rust input
> widget, lands alongside the D-011 audit — see `pangolin_secure_input` memory). This pairing-UX slice is
> the next thing to *build* but is lettered `I` so it does not steal H's reserved slot. Rename freely.

---

## 0. One-paragraph summary

Give the desktop app a **Devices** screen with two wizards: **"Add a device to this vault"** (this device
acts as the existing **manager / Device A**) and **"Join a vault from another device"** (this device acts as
the new **joiner / Device B**). The wizards drive the already-built pairing handshake: B generates a pairing
payload → A and B exchange payloads (over the channel chosen in Q-a) → both screens display the same **6-digit
SAS** which the human compares across the two devices (the anti-MITM gate) → after the human confirms, A
publishes `addDevice` on-chain (Base Sepolia, testnet-only) and produces a sealed VDK envelope → B opens the
envelope, sets its own new master password, and unlocks the now-shared vault. No new cryptography — this is UI
+ ~8 thin Tauri commands wrapping the existing FFI.

---

## 0a. Decisions

### OPEN — need Kelvin (resolve at sign-off)

**Q-a — Transport channel for the desktop MVP. (THE big one.)**
The pairing handshake moves ~3 small blobs between the two devices (B→A payload, A→B payload, A→B sealed
envelope). Each blob has two equivalent forms the engine already emits: a **QR image** (the bytes, ~137 bytes —
fits a QR trivially) and a **copy-paste text string** (base32 + checksum, ~142 chars). The Rust layer is
transport-agnostic; the UI owns how the bytes actually cross. The realistic "other device" in MVP-4 is
**another desktop** (mobile is MVP-5), and desktops mostly can't reliably scan a QR (needs a webcam + a
camera/scan library + camera permissions in the webview — fragile). Options:

| Option | What the user does | Build cost | Notes |
|---|---|---|---|
| **1. Text-string only** | Copy a ~142-char code from one app, paste into the other, 3× | Low | Reliable everywhere, no camera. Tedious but checksum-guarded; typos rejected. |
| **2. Text + QR *render* (Recommended)** | Same copy-paste fallback, PLUS each blob also shows a QR a camera-equipped device (future mobile) can scan | Low–med (add a QR-render component; **no** scanning) | Best foundation: desktop↔desktop uses paste; a future mobile joiner can scan. Render-only is cheap. |
| **3. Text + QR render + camera scan** | Point one app's webcam at the other's QR | High | Full QR UX but the webcam-scan-on-desktop path is fragile + a large dep; better deferred to when mobile (with a real camera) lands. |

Recommendation: **Option 2** — copy-paste text as the universal primary, QR *render* for the future mobile
joiner, camera scanning deferred to MVP-5 / a follow-up. This avoids the fragile desktop-webcam path while
keeping the protocol's QR affordance.

**Q-b — Does this slice include device *revocation* UX, or only *add* + a read-only list?**
The "remove a device" flow triggers an on-chain `DeviceRemoved` + a full **VDK rotation** (re-wrap the vault
key so the removed device can no longer open it) — all built (#106b-2 / #106d) but heavier UX (a destructive,
irreversible, gas-costing action with its own confirm + rotation-progress surface). Options:

- **Option 1 (Recommended): add-only this slice.** Ship the two pairing wizards + a **read-only** list of
  paired devices. Revocation UX is a dedicated follow-up slice. Keeps this slice focused + testable.
- **Option 2: add + revoke in one slice.** One bigger slice; more surface to audit at once.

Recommendation: **Option 1** — add-only + read-only list now; revocation as MVP-4-J follow-up.

### RESOLVED — self-locked

- **R-1 — Both roles ship in one slice.** A-side "add" and B-side "join" are useless apart (you can't pair
  anything with only one half), both run in the same app on the same `Devices` screen, and the E2E flow needs
  both. One slice. (See §2.)
- **R-2 — Full on-chain flow, testnet-only.** Pairing *is* the on-chain `addDevice`; there is no meaningful
  local-only variant. All chain mutations target **Base Sepolia** via the existing `ffi_chain_env_and_id`
  hardcoded `ChainEnv::BaseSepolia` (testnet-only until D-011). The `Devices` screen carries a persistent
  **testnet banner**.
- **R-3 — Rust command layer is STATELESS; the wizard holds non-secret blobs.** The in-flight pairing payloads
  are opaque Rust `Arc` objects that cannot serialize to JS, and they are **non-secret** (pubkeys + EVM
  address + random nonce — they are literally what a QR exposes). So the frontend wizard holds the serializable
  **bytes / text / SAS** as React state, and each Tauri command **re-decodes from bytes** per call (decode is
  pure + cheap). The only Rust-held state stays the existing unlocked `VaultState`. No new managed pairing-state
  struct. (See §3.3.)
- **R-4 — Master passwords cross via the existing direct-invoke path (MVP-4-B option 1).** `vault_add_device`
  (A re-unwraps its VDK to seal it for B) and `pairing_open_and_join` (B sets a new master password) both need a
  password. They reuse the *exact* same plaintext-password-over-`invoke` path that `vault_unlock` already uses —
  **no new secret-crossing surface** is introduced. The MVP-4-H secure-input widget will harden ALL of these
  password paths together, pre-mainnet. (See §4 L1.)
- **R-5 — Bootstrap is detected, not blindly attempted.** A vault must be `bootstrapVault`-ed on-chain exactly
  once before its first `addDevice`. The wizard detects bootstrap state and only bootstraps when needed
  (mechanism = §5 carve-out). The bootstrap tx is surfaced as its own progress step (it is a separate gas tx).
- **R-6 — QR render (if Q-a picks Option 2/3) lives in the component library** as a new `QRCode` component, not
  ad-hoc in the desktop app — the design system is load-bearing on every MVP-4 PR. (Dep choice = §5 carve-out.)
- **R-7 — Testing = Vitest (wizard state machine + invoke wrappers, mocked Tauri) + Rust command-handler unit
  tests + a documented MANUAL two-device smoke test (§9).** The full automated two-device-against-a-live-chain
  E2E is explicitly OUT of scope (§8) — the FFI flow is already proven by `anvil_pairing_e2e.rs`; a desktop
  two-instance + anvil harness is a separate, heavy gate. Mirrors the MVP-4-G "hermetic + manual smoke" pattern.

---

## 0b. What NOT to ship in this slice

- **Device revocation / removal UX** (unless Q-b = Option 2). Triggers VDK rotation; dedicated follow-up.
- **Camera / webcam QR *scanning*** (unless Q-a = Option 3). Deferred to MVP-5 (mobile) or a follow-up.
- **Recovery UX** (guardian setup, recover-from-shares, backup-phrase). Separate back-half slice (#108/#109 FFI
  is ready; its UX is its own plan-gate).
- **Sync-status UX** (publish/read revisions, pending-change indicators). Separate back-half slice.
- **Extension/popup involvement.** Pairing is a desktop vault-management operation; the extension is untouched.
- **In-app gas funding / faucet automation.** Testnet signer funding is manual; we surface a clear error +
  the signer address + a faucet link if the tx fails for insufficient gas (R-2 / §6).
- **Relay/server-mediated pairing** (online pairing without a shared physical moment). The engine is
  transport-agnostic and could grow this later; not now.
- **Multi-device conflict / "which device is manager" policy beyond what the contract enforces.** The contract's
  authorized-device-set is the source of truth.

---

## 1. Scope

Wire the desktop UI to the existing pairing FFI so a human can add a second device to a vault and have the new
device open it — end to end, on Base Sepolia testnet.

**Built in MVP-4-I:**
1. A new **`Devices`** screen reachable from the unlocked `AccountListScreen` (a "Devices" header button).
   Shows a read-only list of paired devices (Q-b Option 1) + two entry actions: *Add a device* / *Join a vault*.
2. **A-side "Add a device" wizard** (this device = manager): bootstrap-if-needed → ingest B's payload → show
   A's payload → show SAS + "do the codes match on both screens?" confirm → publish `addDevice` (progress) →
   show the sealed envelope for B to ingest → done.
3. **B-side "Join a vault" wizard** (this device = joiner): show B's payload → ingest A's payload → show SAS +
   confirm → ingest A's sealed envelope → set a new master password for this device → unlock → done.
4. **~8 thin `#[tauri::command]` handlers** in a new `apps/desktop/src/commands/pairing.rs` wrapping the FFI,
   registered in `lib.rs` `generate_handler!` + the `capabilities/default.json` allow-list.
5. **Typed `invoke.ts` wrappers** for each command + the DTOs.
6. A new **`QRCode`** component in `@pangolin/component-library` (if Q-a = Option 2/3) + a **code/text-input**
   affordance for pasting payloads (reuse `Input`; add a paste-and-validate pattern).
7. **Stage additions** to `useVault.ts` (`'devices'` stage + the wizard sub-state) + `App.tsx` routing.
8. Persistent **testnet banner** on the `Devices` screen.

**The pairing FFI surface this wraps (already built — `crates/pangolin-ffi/src/pairing.rs`):**

| FFI fn | Role | Signature (abridged) | Returns |
|---|---|---|---|
| `pairing_begin_new_device` | B step 1 | `(handle)` | `FfiPairingPayload` (fresh nonce) |
| `pairing_local_payload` | A step 2 | `(handle, their_freshness_nonce)` | `FfiPairingPayload` (mirror, B's nonce) |
| `pairing_decode_bytes` / `_string` | both | `(bytes)` / `(s)` | `FfiPairingPayload` (pure, no handle) |
| `pairing_derive_sas` | both | `(payload_a, payload_b)` | `String` (6-digit, canonical-symmetric) |
| `vault_bootstrap_chain` | A once | `(handle, master_password, config)` | `()` (genesis SET on-chain) |
| `vault_add_device` | A per-device | `(handle, master_password, config, new_device_payload)` | `FfiSealedVdkEnvelope` |
| `pairing_open_and_join` | B final | `(handle, sealed_vdk_bytes, vault_id, epoch, master_password)` | `()` |

`FfiPairingPayload` fields: `bytes`, `string_form`, `device_id`, `vault_id`, `x25519_pairing_pub`, `signer`,
`freshness_nonce`. `FfiSealedVdkEnvelope`: `bytes`, `string_form`. `FfiChainConfig`: `rpc_url`,
`deployment_path`, `prefer_websocket`.

---

## 2. Splittable? — ONE slice (both roles)

A-add and B-join cannot be tested or used independently (pairing is inherently two-sided), both live on the
same screen in the same binary, and the manual smoke test (§9) exercises both halves against each other. The
QR-render component (R-6) is small. Revocation is the natural *next* slice (Q-b) — that is where a split lives.

---

## 3. Design

### 3.1 Architecture

```
┌───────────────────────── Device A (manager) ──────────────────────────┐
│ DevicesScreen → "Add a device" wizard (useVault sub-state)             │
│   step 1  bootstrap-if-needed   → invoke pairing_chain_bootstrap(pw)   │
│   step 2  ingest B's payload    → invoke pairing_local_payload(bBytes) │
│            (paste text / scan)     → A's payload {bytes, stringForm}   │
│   step 3  show SAS + confirm    → invoke pairing_derive_sas(aB,bB)     │
│   step 4  publish (gas)         → invoke pairing_add_device(bBytes,pw) │
│            → FfiSealedVdkEnvelope {bytes, stringForm}                  │
│   step 5  show sealed envelope (QR/text) for B to ingest              │
└────────────────────────────────────────────────────────────────────────┘
                 ⇅  human moves blobs over the Q-a channel  ⇅
┌───────────────────────── Device B (joiner) ───────────────────────────┐
│ DevicesScreen → "Join a vault" wizard                                  │
│   step 1  show B's payload      → invoke pairing_begin_new_device()    │
│   step 2  ingest A's payload    → invoke pairing_decode(aInput)        │
│            (learn A's vault_id) → A's {bytes, vaultId}                 │
│   step 3  show SAS + confirm    → invoke pairing_derive_sas(aB,bB)     │
│   step 4  ingest sealed env +   → invoke pairing_open_and_join(        │
│           set NEW master pw         sealedBytes, vaultId, epoch, newPw)│
│   step 5  unlock                → invoke vault_unlock(newPw)           │
└────────────────────────────────────────────────────────────────────────┘
```

All crypto, signing, and the on-chain tx happen **inside the FFI** (engine-side `block_on_local`); the desktop
just choreographs steps + moves non-secret bytes. The SAS comparison is enforced by the **human + the UI gate**,
not the FFI (calling `pairing_add_device` *is* the confirmation — §4 L2).

### 3.2 The two wizards (state machine)

Model each wizard as an explicit step enum in the `useVault` `'devices'` sub-state — never advance A past the
SAS-confirm step without an explicit user "codes match" gesture (L2). A's `pairing_add_device` and the bootstrap
tx each get a dedicated **in-progress / waiting-for-chain** step (spinner + "Publishing to Base Sepolia…") since
they are async chain calls that can take seconds. Every step has a **Cancel** that returns to the `Devices`
landing and discards the in-memory blobs (they are non-secret, but stale payloads should not linger). B's
"set new master password" step reuses the password-strength affordance (`PasswordMeter`, available in the
component library).

### 3.3 New Tauri commands (stateless; re-decode from bytes — R-3)

New module `apps/desktop/src/commands/pairing.rs`. Bytes cross the wire as the engine's `string_form` where a
human-portable form is wanted, and as `Vec<u8>` (number arrays / hex — builder's call, §5) where only the
machine needs them. DTOs translated at the `invoke.ts` boundary like the existing `accounts_list` pattern.

| Tauri command | Wraps | Args | Returns |
|---|---|---|---|
| `pairing_begin_new_device` | `pairing_begin_new_device` | — | `PairingPayloadDto {bytes, stringForm, vaultId, freshnessNonce}` |
| `pairing_decode` | `pairing_decode_bytes`/`_string` | `{ input }` | `PairingPayloadDto` (validate a pasted/scanned blob; surfaces `vaultId`) |
| `pairing_local_payload` | decode theirs → extract nonce → `pairing_local_payload` | `{ theirBytes }` | `PairingPayloadDto` (A's mirror) |
| `pairing_derive_sas` | `pairing_derive_sas` | `{ aBytes, bBytes }` | `string` (6-digit) |
| `pairing_chain_bootstrap` | `vault_bootstrap_chain` | `{ password }` | `()` (or already-bootstrapped sentinel — §5) |
| `pairing_add_device` | `vault_add_device` | `{ theirBytes, password }` | `SealedEnvelopeDto {bytes, stringForm}` |
| `pairing_open_and_join` | `pairing_open_and_join` | `{ sealedBytes, vaultId, epoch, newPassword }` | `()` |

The pure-decode/SAS commands are session-tolerant; the handle-bearing ones are L4 session-gated by the FFI
(Active only). `FfiChainConfig` is constructed inside the command layer from app config (§6).

### 3.4 New / reused components

- **New: `QRCode`** in `@pangolin/component-library` (Q-a Option 2/3) — render-only, takes bytes/string, sizes
  via tokens. Dep choice = §5.
- **New: a "scan/paste payload" affordance** — for the MVP this is `Input` + a "Paste & validate" button that
  calls `pairing_decode` and shows a green/`Check` "valid payload for vault …" or a `Warning` on a bad checksum.
- **Reused:** `Card`, `Button`, `IconButton` (`Copy`, `Check`, `Warning`, `Chevron`), `Modal` (confirm-SAS,
  confirm-publish), `Toast` (errors), `PasswordMeter` (B's new password), `Badge`/`Tag` (device-list rows),
  `Spinner` (chain waits), `ListRow` (paired-device rows), `Code` (render the SAS + the text blobs in mono).

### 3.5 Chain config + bootstrap (R-2 / R-5)

The two chain-mutating commands need `FfiChainConfig { rpc_url, deployment_path, prefer_websocket }`. Source:
the bundled Base Sepolia deployment (`contracts/deployments/…`) + a configurable RPC URL defaulting to a public
Base Sepolia endpoint (builder confirms the exact path/default, §5/§6). Bootstrap detection (R-5): prefer a
read against the live device-set / `deviceNonce` if an FFI read makes "is this vault bootstrapped?" answerable;
otherwise attempt `vault_bootstrap_chain` and treat the contract's `VaultAlreadyBootstrapped` revert as
"already done, proceed" (§5).

### 3.6 Testing

- **Vitest** (`apps/desktop/src/**/*.test.tsx`): the wizard step machine (cannot skip SAS-confirm; Cancel
  discards blobs), the `invoke.ts` wrappers (mocked `@tauri-apps/api` `invoke`, snake/camel translation,
  `DesktopError` mapping), and the paste-and-validate affordance (good payload → advances; bad checksum →
  Warning, no advance).
- **Rust** (`commands/pairing.rs` `#[cfg(test)]`): each command's arg validation + error mapping
  (`DesktopError` kinds) with the handle in each session stage (the FFI flow itself is already covered by
  `anvil_pairing_e2e.rs`; do not re-test the crypto).
- **Manual** (§9): the real two-desktop smoke against Base Sepolia.

---

## 4. L-invariants

- **L1 — zero NEW secret crosses the boundary.** The pairing payloads, the sealed VDK envelope, and the SAS are
  all **non-secret** (the payload is literally what a QR exposes; the envelope is sealed to B's pubkey; the SAS
  is shown to the human). The only secrets are the master passwords, which cross via the **existing**
  `vault_unlock` direct-invoke path (R-4) — no new plaintext surface. The VDK NEVER crosses (sealing happens
  engine-side inside `vault_add_device`; opening happens engine-side inside `pairing_open_and_join`).
- **L2 — the SAS comparison is a hard human gate.** The UI MUST require an explicit "the 6-digit codes match on
  both screens" gesture before calling `pairing_add_device`. A swapped pubkey (MITM) yields different SAS on the
  two devices; the human catches it. The FFI does not enforce this — the UI is the gate. Never auto-advance.
- **L3 — fail-closed.** Any chain error (RPC down, insufficient gas, nonce race), bad checksum, version
  mismatch, or session-locked surfaces as a typed `DesktopError` + a clear UI message; the wizard never
  silently proceeds or fabricates success.
- **L4 — session-gated.** All handle-bearing commands require an Active (unlocked) vault — enforced FFI-side;
  the UI only reaches the wizards from the unlocked `AccountListScreen`.
- **L5 — new external deps are scoped + minimal.** Any QR-render dep (R-6) lives in the component library, not
  the desktop bundle directly, and renders only (no scanner, no network). No new Rust deps (the FFI is done).
- **L7 — errors carry no secret.** `DesktopError` envelopes carry kind + a non-secret message; never the
  password, the VDK, the seal, or signer key material.

---

## 5. Open decisions — pre-locked (builder carve-outs)

These are forced engineering details with one coherent answer; the builder resolves them against the live code
(no Kelvin gate):

- **Byte wire-form** (hex string vs number array) for the non-`string_form` blobs across `invoke` — builder
  picks the cleaner of the two against the existing `invoke.ts` DTO conventions.
- **QR-render dep** (if Q-a = Option 2/3) — a vetted, render-only, dependency-light lib (e.g. a `qrcode`-class
  encoder feeding a `<canvas>`/SVG) wrapped as the `QRCode` component. Builder picks; justify in the PR.
- **Bootstrap detection mechanism** (R-5) — read-status-if-available else attempt-and-catch
  `VaultAlreadyBootstrapped`. Builder verifies which the FFI/contract actually supports.
- **`epoch` for `pairing_open_and_join`** — `vault_add_device` seals at `epoch=0` for a first pairing (per
  `anvil_pairing_e2e.rs`); builder confirms whether the envelope carries the epoch or it is always 0 here.
- **Chain config sourcing** (rpc_url default + deployment_path) — §3.5; builder wires it to the bundled Base
  Sepolia deployment + a sensible default RPC.
- **Exact `Devices` entry point** (header button vs menu) on `AccountListScreen` — builder matches the existing
  header pattern.

---

## 6. Places that need care

- **The bidirectional round-trip is easy to get backwards.** B generates first (`pairing_begin_new_device`,
  which mints the fresh nonce); A *mirrors* (`pairing_local_payload(B's nonce)`) so both SAS derive over the
  SAME nonce. If A generates independently the SAS will not match. Follow the `anvil_pairing_e2e.rs` order
  exactly: B begin → A local_payload(B.nonce) → derive_sas → add_device → open_and_join.
- **SAS argument order is canonical-symmetric** (`derive_sas(a,b) == derive_sas(b,a)`), so each side may pass
  (mine, theirs) and still match — but be consistent and label which payload is which in the UI.
- **The on-chain tx can take seconds and can fail for insufficient gas.** The device's secp256k1 signer needs
  funded Base Sepolia ETH. On an insufficient-gas / chain error, surface the **signer address** + a faucet hint
  + a retry — do not wedge the wizard. (No in-app funding — §0b.)
- **`vault_add_device` and `vault_bootstrap_chain` re-prompt for the master password** (A must re-unwrap its VDK
  to seal it for B). Make this obvious in the UI ("confirm your master password to authorize this device") — it
  is not a bug.
- **B is left Locked after `pairing_open_and_join`** by design; the wizard must follow with `vault_unlock`
  (new password) to land B in the Active vault. Mirror the test's step 17→19.
- **`bytes` vs `string_form`:** show the human the `string_form` (with a Copy button) and/or the QR of `bytes`;
  feed `pairing_decode` whatever the user supplies (it accepts both forms).
- **Stale-QR / replay** is already defended (freshness nonce + on-chain `deviceNonce`); the UI should still
  expire an in-flight wizard on Cancel/timeout so a screenshotted payload is not reused blindly.

---

## 7. Success criteria

- `apps/desktop`: `pnpm typecheck` ✓ + `pnpm lint` ✓ + `pnpm test` (Vitest: wizard state machine + new invoke
  wrappers + paste-validate) ✓ + `pnpm build` ✓.
- `apps/component-library`: typecheck/lint/Vitest/Storybook/build ✓, incl. the new `QRCode` component + a story
  (if Q-a = Option 2/3).
- Rust: `cargo fmt --check` ✓ + `cargo clippy -p pangolin-desktop --all-targets -- -D warnings` ✓ +
  `cargo test -p pangolin-desktop` (new `commands/pairing.rs` unit tests) ✓ + full-workspace gate green.
- `cargo audit` / `cargo deny` ✓; cardinal invariants 0/0/0/0.
- The new commands appear in BOTH `lib.rs` `generate_handler!` AND `capabilities/default.json` (the security
  allow-list must mirror the handler list — a registered-but-not-allow-listed command is a silent 4xx).
- The existing desktop + extension + both E2E jobs still pass (regression-catch).
- **§9 manual two-device smoke test passes** (NOT a CI gate; recorded before closed beta).
- CI green on `ubuntu-latest` + the existing matrix after merge.

---

## 8. Out of scope (filed for follow-up)

- **Device revocation / removal UX** (Q-b Option 1 → MVP-4-J): on-chain `DeviceRemoved` + VDK rotation +
  rotation-progress surface + "this is irreversible" confirm.
- **Automated two-device desktop E2E against a live/anvil chain.** Heavy (two app instances + a chain); the FFI
  flow is already proven by `anvil_pairing_e2e.rs`. Revisit if pairing regressions recur.
- **Camera / webcam QR scanning** (Q-a Option 1/2 → follow-up / MVP-5 mobile).
- **Relay-mediated (remote) pairing** — online pairing without a shared physical moment.
- **In-app gas funding / faucet integration.**
- **Recovery UX, sync-status UX** — separate back-half slices.
- **Mainnet pairing** — hard-gated behind D-011 (testnet-only until then).

---

## 9. Manual two-device smoke test (run before closed beta)

On two machines (or two OS users) each running the desktop build, against Base Sepolia (both device signers
funded with testnet ETH):

1. **Device A:** create + unlock a vault; open **Devices**; "Add a device". (Bootstrap runs if first time.)
2. **Device B:** create + unlock a *fresh local* vault; open **Devices**; "Join a vault". B shows its payload.
3. Move B's payload to A (paste the text string / scan the QR per Q-a). A shows A's payload; move it to B.
4. **Confirm the 6-digit SAS is identical on both screens.** (Tamper check: if you garble one payload, the SAS
   differs and/or the checksum rejects — confirm the UI catches it.)
5. On A, confirm "codes match" → A publishes `addDevice` (watch the Base Sepolia tx confirm) → A shows the
   sealed envelope. Move it to B.
6. On B, ingest the envelope → set a NEW master password → B unlocks and shows the SAME accounts as A.
7. Verify B's signer now appears in the vault's on-chain authorized-device set (Basescan / `cast`), and that B
   can read/list accounts independently.

Record the run (screencast + the addDevice tx hash) before closed beta.
