<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Issue #106c — CLIENT device-add flow + the `DeviceRemoved`→rotation TRIGGER — plan-gate LOCKED

**Status: LOCKED — Kelvin sign-off 2026-05-21 (see §0a). Q-a..Q-i + GAP A-E resolved; ONE stage.** Third slice of the multi-device epic #106 (after #106a contract + #106b crypto/rotation, all merged). Mirrors the §16 plan-gate format of `103-recovery-client.md` / `104b-recovery-orchestration.md`.

## 0a. RESOLVED decisions (Kelvin sign-off 2026-05-21)

- **Scope / where it lives (ONE stage):** `pangolin-chain::revisionlog_v2_{signing,client}` (sol! binding + manager-EIP-712 calldata/sign/broadcast for bootstrapVault/addDevice/removeDevice/promotion, byte-identical to the contract — reuse #103 EIP-712 machinery; live SET/nonce/manager reads; device-mgmt event folding) + pure `pangolin-core::device_add` driver + `pangolin-store` persistence + the coupled anvil E2E. (Optionally 2 PRs on one branch; the E2E needs add + remove-and-rotate together.)
- **GAP A (load-bearing) → LOCAL survivor-pubkey directory.** The on-chain set stores secp256k1 ADDRESSES; rotation needs survivors' X25519 PAIRING pubkeys; no on-chain mapping (correct — no VDK-adjacent contract slots). Maintain a `pangolin-store` local persisted `signer → x25519_pairing_pub` directory (populated at device-add) + opportunistic completion — the SAME pattern as #104b's non-participant guardian-pubkey problem (already accepted).
- **Honor-gate sequencing (Q-g) → MINIMAL in #106c, FULL in #106d.** #106c replaces the permissive `auto_register_device_from_chain_sync` with a minimal set-membership honor gate (honor iff signer ∈ current on-chain authorized set — enough for the E2E + correctness). The FULL revocation generalization (folding parked #103-C: lineage/retroactive-re-eval) is #106d.
- **`DeviceRemoved`→rotation trigger:** engine-side detection (event decode in chain_sync + set-diff anti-staleness anchor) persists a crash-durable, resumable **"rotation-pending — enter master password"** state; HOST-driven completion (rotation needs the re-prompted master password — `pangolin-core` stays pure). CANNOT auto-rotate. If the user delays, the removed device is already out of the on-chain set (can't publish honored entries); rotation closes the local-VDK gap for future data.
- **Device-add handshake:** new device derives signer + X25519 pairing pubkey + device_id → existing UNLOCKED device reads live `deviceNonce`, signs `AddDevice`, broadcasts + `seal_vdk_to_device` → new device `open_vdk_from_pairing` (`ct_eq`) + `wrap_vdk_for_device` + persists.
- **Q-e promotion → fold the CALLDATA into the client; defer the full 48h promotion STATE MACHINE.**
- **Q-f FFI → DEFER** (keep pangolin-core pure; entry points fold with #105b recovery-FFI or #106e).
- **Q-d #106c/#106e line → crypto handshake (pubkey binding) in #106c; QR/short-code SCANNING UX in #106e.**
- **Q-h local re-encrypt → DEFER** (epoch chain is correct; local re-encrypt is a later nicety).
- **GAP B (DEVICE_ID_LEN=32 derivation), GAP C (remote-survivor seal-consumption path), GAP D (drop permissive auto-register), GAP E (#106d sequencing)** — all addressed in #106c per the above (D minimal-gate; E full-gen in #106d).
- **Anvil E2E (centerpiece):** deploy → bootstrapVault → addDevice(real manager EIP-712) → seal+open VDK (`ct_eq`) → new-device publish succeeds (in set) → removeDevice → new-device publish now unhonored + trigger fires → rotate_vdk_for_survivors+commit_vdk_rotation → assert forward secrecy (removed device can't open new epoch; survivor can). Negatives turn it RED.
- **Gate:** full `cargo test --workspace` (the #106b-1 lesson) + the anvil E2E + EIP-712 byte-identity client↔contract (the #103 L2/L3 class). Testnet-only until D-011.

This slice is **TESTNET-ONLY (Base Sepolia) until the D-011 external audit clears** (it wires the new `RevisionLogV2` + the net-new device-handoff crypto into client orchestration; both are inside the D-011 package). Per `106-multi-device.md` §0a the architecture is LOCKED: per-device keys; primary authorizes (Option B `deviceManager`) + survivor-promotion + preserve-survivors; on-chain authorized SET; **honor = signer in the current on-chain set**.

**Base: #106a `RevisionLogV2.sol` merged `6e5bf74`; #106b-1 `pangolin-crypto::pairing` merged; #106b-2 `pangolin-core::rotation` + `Vault::commit_vdk_rotation` merged `9f67221`. RevisionLogV2 is already deployed by `scripts/anvil-ci.sh` (the harness deploys it bound to the dev RecoveryV1).**

---

## 0. One-paragraph summary

#106a built the on-chain authorized-device SET + the manager-signed device lifecycle (`bootstrapVault`/`addDevice`/`removeDevice`/`proposePromotion`/`finalizePromotion`/`cancelPromotion`, all EIP-712 + per-vault `deviceNonce`) + the `publishRevision` set-membership gate + the events. #106b-1 built the device-to-device VDK pairing handoff (`seal_vdk_to_device`/`open_vdk_from_pairing` + the per-device `wrap_vdk_for_device`). #106b-2 built the pure `rotate_vdk_for_survivors` driver + the atomic `Vault::commit_vdk_rotation` (prompt-on-revoke). **#106c is the glue that wires all three into actual client orchestration**, exactly as #103 (chain-client) + #104b (pure-driver + store) wired the recovery pieces together. It builds: (1) a **`revisionlog_v2_client`** in `pangolin-chain` — a `sol!` binding + the manager-EIP-712 calldata/sign/broadcast for the six device-lifecycle calls + the authorized-SET read + the device-management event reads (the analogue of `recovery_client.rs`); (2) the **device-add (pairing) orchestration** — the pure driver in `pangolin-core` that sequences "new device generates pairing key → existing device `addDevice` on-chain + `seal_vdk_to_device` → new device `open_vdk_from_pairing` + `wrap_vdk_for_device` + persist"; (3) **the `DeviceRemoved`→rotation TRIGGER** — a watcher that observes the on-chain `DeviceRemoved` event and surfaces a persisted **"rotation-pending — enter master password"** state (it CANNOT auto-rotate, because `rotate_vdk_for_survivors`+`commit_vdk_rotation` need the re-prompted master password); (4) optionally the **survivor-promotion client**; and (5) the **coupled anvil E2E** that ties #106a+#106b-1+#106b-2 end-to-end with forward-secrecy negatives. It introduces **no new crypto and no new contract** — only composition, orchestration, persistence, and a chain-read watcher.

---

## 1. Scope

**#106c builds:**

1. **`pangolin-chain::revisionlog_v2_signing` + `revisionlog_v2_client`** (mirrors the `recovery_signing.rs` / `recovery_client.rs` split):
   - `revisionlog_v2_signing` — the EIP-712 v2 builders for the four manager-/candidate-signed digests the contract verifies (`AddDevice`, `RemoveDevice`, `Promote`, and the genesis `AddDevice`-at-nonce-0 that `bootstrapVault` reuses). REUSES `secp256k1_signing::{eip712_digest, is_canonical_s}` verbatim (one digest impl in the crate); only the struct-hashes + the v2 domain (`name = "Pangolin RevisionLog"`, `version = "2"`) are new. The `Revision` digest already exists for v1 publish — but v2 has a DIFFERENT domain separator (version "2"), so v2 publish needs its own digest path (L-byte-identity, see §4).
   - `revisionlog_v2_client` — a `sol!` binding for `RevisionLogV2` + calldata/sign/broadcast for `bootstrapVault`/`addDevice`/`removeDevice`/`proposePromotion`/`finalizePromotion`/`cancelPromotion`, REUSING `chain_submit.rs`'s EIP-1559 envelope + gas cap + retry taxonomy + `resolve_envelope_chain_id` (#101) verbatim, exactly as `recovery_client.rs` does. PLUS: the live reads `currentManager`/`deviceNonce`/`authorizedDevice`/`authorizedDeviceCount` + the parity-oracle `hashAddDevice`/`hashRemoveDevice`/`hashPromote` cross-checks (the contract exposes all of these as `view`s, the #103 posture). PLUS: folding the device-management events (`VaultBootstrapped`/`DeviceAdded`/`DeviceRemoved`/`PromotionProposed`/`PromotionFinalized`/`PromotionCanceled`) into a client-side authorized-SET snapshot.

2. **`pangolin-core::device_add` pure orchestration driver** (mirrors `recovery::orchestration`): the pure state-machine that sequences the device-add handshake from PUBLIC inputs — the new device's pairing pubkey + signer address in, the `SealedVdkForDevice` + the `AddDevice` digest-inputs out. PURE (zero chain, zero uniffi, zero serde-on-secrets); the on-chain `addDevice` broadcast is driven by the caller in `pangolin-chain`, and the new device's `open`+`wrap`+persist is driven store-side. The driver itself only composes #106b-1 `seal_vdk_to_device` (existing device side) and orchestrates the open/wrap (new device side).

3. **THE `DeviceRemoved`→rotation TRIGGER** (the subtle centerpiece, §3.3):
   - a **watcher** in `pangolin-chain` that detects a removal — either by decoding `DeviceRemoved` events in the existing `chain_sync` read path OR by diffing the live `authorizedDevice` set against local state (recommend BOTH: event-driven when synced live, set-diff as the catch-up/anti-staleness anchor, mirroring the #103/#101 chain-read posture);
   - a persisted **"rotation-pending"** state in `pangolin-store` (so a closed app resumes it — the removed device is already out of the on-chain set, so the cryptographic gap is closed at the next rotation, whenever the user supplies the password);
   - the **host-driven completion**: the watcher surfaces "rotation pending — enter master password"; the host prompts; the host then calls `rotate_vdk_for_survivors` (#106b-2) → `Vault::commit_vdk_rotation` (#106b-2). #106c does NOT auto-rotate (L-no-silent-rotate).

4. **`pangolin-store` persistence + the set-membership honor gate replacement**: the rotation-pending row + the device-add new-device persistence (the new device's `DeviceWrappedVdk` + its meta), and the replacement of the permissive `auto_register_device_from_chain_sync` (today it trusts ANY signer it sees, GAP FLAG D) with "register/honor iff in the current authorized SET" — folding the #103-C generalization that the locked arch dissolved into "read the current set." (NOTE: the master plan splits the full revocation generalization into **#106d**; #106c needs ENOUGH of it for the E2E's honor assertions — see Q-g.)

5. **The coupled anvil E2E** (the centerpiece / regression gate, §5): deploy → `bootstrapVault` → `addDevice`(real manager EIP-712) → seal+open the VDK to the new device (`ct_eq`) → new device `publishRevision` succeeds (in the set) → `removeDevice` → new device's publish now reverts → the rotation trigger fires → `rotate_vdk_for_survivors`+`commit_vdk_rotation` → assert forward secrecy (removed device can't open the new epoch; survivor can). Lives beside the #103/#104b lifecycle tests in `recovery_client.rs` (or a sibling integration module) and is wired into `anvil-ci.sh`.

**Deferred / out of scope (this slice):**

- **Pairing UX / trust bootstrap** (the QR / short-code scanning, the §5.3 presence-proof screens) — **#106e**. #106c builds the CRYPTO binding (the new device's pubkey reaches the existing unlocked device as already-resolved bytes; the driver consumes them); the out-of-band SCANNING + presence gate is #106e. THE LINE (Q-d): #106c's driver takes the new device's `(device_id, signer_addr, x25519_pairing_pub)` as a verified triple; #106e is how that triple physically + securely crosses to the primary.
- **FFI / uniffi** — recommend **defer/fold** (Q-f): keep `pangolin-core` pure; the host-app entry points (device-add wizard, the rotation-pending prompt) fold with the pending #105b recovery-FFI or land in #106e UX. #106c proves the logic + the regression gate.
- **The full revocation generalization (#106d)** — the systematic read-gate rewrite + the scorched-earth-on-recovery reset + the v1→v2 dual-read cut-over. #106c does the minimum honor gate the E2E needs (Q-g).
- **Local re-encrypt to the newest VDK** — explicitly #106c-optional per `106b2-…` Q-b, recommend STILL deferred (a perf nicety, not correctness; the epoch chain is always-correct). Surfaced as Q-h.
- **Mainnet** — testnet-only until D-011.

---

## 2. Splittable? — recommendation: ONE #106c stage, optionally two PRs on one branch

#106c is composition + a watcher, not new primitives — the same posture #104b took. The three load-bearing pieces are mutually dependent and the coupled anvil E2E (which is the value) can only assert end-to-end with all of them present:

- the `revisionlog_v2_client` (chain) — without it, no `addDevice`/`removeDevice` to drive;
- the device-add driver (core) + new-device persistence (store) — without them, no VDK reaches the new device;
- the `DeviceRemoved`→rotation trigger (chain watcher + store rotation-pending + host completion) — without it, the removal half of the E2E can't fire.

Splitting (e.g. "client + add-driver" vs "rotation-trigger watcher") would create a half-wired intermediate with no meaningful test gate — the E2E needs the add AND the remove arms. **Recommend ONE logical #106c stage**, with the option to land two reviewable PRs on one branch (PR1 = `revisionlog_v2_{signing,client}` + the device-add driver + new-device persistence with hermetic + anvil-add tests; PR2 = the `DeviceRemoved` watcher + rotation-pending state + the coupled remove-and-rotate E2E). Surfaced as Q-i. The survivor-promotion client (Q-e) is the one genuinely separable piece — recommend folding the propose/finalize/cancel CALLDATA into the `revisionlog_v2_client` (cheap, mirrors the other calls) but DEFERRING the full promotion CLIENT FLOW (the 48h-delay state machine + the "notify your other devices" surfacing) to its own follow-up, since it is orthogonal to the add+remove+rotate centerpiece.

---

## 3. The end-to-end design (decisions surfaced in §5)

### 3.1 The RevisionLogV2 chain-client (mirror `recovery_client.rs`)

The `sol!` binding mirrors the contract's external surface VERBATIM (drift caught by the calldata-pin tests + the anvil round-trip, exactly as the RecoveryV1 binding):

```
contract RevisionLogV2 {
    function bootstrapVault(bytes32 vaultId, address firstSigner, uint16 schemaVersion, bytes signature) external;
    function publishRevision(bytes32 vaultId, bytes32 accountId, bytes32 parentRevision, bytes32 deviceId, uint16 schemaVersion, bytes encPayload, bytes signature) external returns (uint256);
    function addDevice(bytes32 vaultId, address newSigner, uint64 nonce, uint16 schemaVersion, bytes authoritySig) external;
    function removeDevice(bytes32 vaultId, address signer, uint64 nonce, uint16 schemaVersion, bytes authoritySig) external;
    function proposePromotion(bytes32 vaultId, address candidate, uint64 nonce, uint16 schemaVersion, bytes candidateSig) external;
    function finalizePromotion(bytes32 vaultId, uint16 schemaVersion) external;
    function cancelPromotion(bytes32 vaultId, uint16 schemaVersion) external;
    // views (parity oracles + live reads)
    function currentManager(bytes32) view returns (address);
    function deviceNonce(bytes32) view returns (uint64);
    function authorizedDevice(bytes32, address) view returns (bool);
    function authorizedDeviceCount(bytes32) view returns (uint32);
    function hashAddDevice(...) view returns (bytes32);   // + hashRemoveDevice / hashPromote / hashRevision
    // events: VaultBootstrapped / DeviceAdded / DeviceRemoved / PromotionProposed / PromotionFinalized / PromotionCanceled / RevisionPublished
}
```

- **Where it lives:** `pangolin-chain` (alongside `recovery_client.rs`). The byte-pinned EIP-712 constants + the calldata-pin tests live here; `pangolin-chain` keeps NO `pangolin-store` dep (#103 L7 — cargo-tree guard).
- **The manager-EIP-712 signing (L-byte-identity, the #103 L2/L3 class).** The client's `AddDevice`/`RemoveDevice`/`Promote` digests MUST be byte-identical to the contract's `_hashAddDevice`/`_hashRemoveDevice`/`_hashPromote` (`RevisionLogV2.sol:981/992/1003`) — same typehash strings verbatim, same v2 domain (`"Pangolin RevisionLog"`/`"2"`/chainId/verifyingContract), `\x19\x01`, `v∈{27,28}`, canonical-low-s. A drift = the contract recovers a WRONG address → `ErrNotDeviceManager`/`ErrInvalidSignature` → device-add is unreachable (silent + total, the env-quirk #14 class). Pinned by hermetic typehash/domain-separator tests + the anvil `addDevice` round-trip (the live contract accepts the client's sig).
- **The `nonce` anti-replay (the L11-analogue).** Every `addDevice`/`removeDevice`/`proposePromotion` binds the vault's CURRENT `deviceNonce`. The client MUST read the live `deviceNonce(vaultId)` before building each digest (mirrors #103 reading the live `attemptNonce`) — a stale nonce reverts `ErrBadNonce`. The genesis `bootstrapVault` uses `nonce == 0`.
- **The genesis quirk (GAP-friendly).** `bootstrapVault` reuses the `AddDevice` typehash at `nonce == 0` and the recovered signer MUST equal `firstSigner` (`RevisionLogV2.sol:445-452`). The client's bootstrap path therefore signs the SAME `AddDevice` digest the first device signs for itself — clean, no separate typehash.

### 3.2 The device-add (pairing) orchestration — the full handshake

```
New device B (fresh install):
  1. generates its DeviceKey → derives:
       - its secp256k1 RevisionLog signer (pangolin-chain::evm::derive_evm_wallet)  → B_signer
       - its X25519 pairing pubkey (pangolin-crypto::pairing::derive_x25519_pairing_key) → B_x25519_pub
       - its stable 32-byte device_id (DEVICE_ID_LEN)                                → B_device_id
  2. presents (B_device_id, B_signer, B_x25519_pub) to an existing UNLOCKED device A
     out-of-band. THE CRYPTO BINDING is here; the QR/scanning + §5.3 presence proof is #106e (Q-d line).

Existing unlocked device A (holds the live VDK, is the deviceManager):
  a. reads live deviceNonce(vaultId) + currentManager(vaultId) from the chain;
  b. signs the AddDevice(vaultId, B_signer, nonce, sv) digest with its manager key (revisionlog_v2_signing);
  c. broadcasts addDevice(...) to RevisionLogV2 (revisionlog_v2_client) → B_signer is now in the on-chain SET;
  d. seal_vdk_to_device(vdk, B_x25519_pub, vault_id, B_device_id, epoch)  (#106b-1) → SealedVdkForDevice;
  e. delivers the SealedVdkForDevice to B over the (untrusted) pairing channel — it is sealed, so transport is untrusted.

New device B:
  f. open_vdk_from_pairing(sealed, B_x25519_secret, vault_id, B_device_id, epoch)  (#106b-1) → byte-identical VDK (ct_eq);
  g. wrap_vdk_for_device(vdk, B_DeviceKey, ctx)  (#106b-1) → its own DeviceWrappedVdk → persist (pangolin-store);
  h. B is now in the on-chain SET; it pulls the vault history + publishes its own revisions signed by B_signer.
```

- **Where each piece lives.** The **pure driver** (`device_add` in `pangolin-core`) sequences step (d) (the seal, from public inputs) on A's side and orchestrates (f)+(g) on B's side — it carries ONLY public context (device_id, pairing pubkey, vault_id, epoch) across its boundary, never key material, exactly like `recovery::orchestration` (L1). The **chain calls** (a)/(b)/(c) live in `pangolin-chain` (`revisionlog_v2_client`), driven by the host. The **new-device persistence** (g) lives in `pangolin-store` (the new device's `DeviceWrappedVdk` + meta).
- **Epoch.** The pairing seal binds the shared per-vault `epoch` (#106b-2 §4, the ONE monotonic clock). On a clean add (no rotation) the epoch is the vault's current epoch; A reads it from local state. (The on-chain set has no epoch — the epoch is purely off-chain client state, `106b2` Q-f/L.)
- **The clean case** has ONE primary (`deviceManager`, Option B). Only the manager's signature passes `_requireManagerSig`. The new device is a secondary that can publish (in the set) but cannot itself add devices unless promoted.

### 3.3 THE `DeviceRemoved`→rotation TRIGGER (the subtle one)

A watcher observes the on-chain `DeviceRemoved` event and must trigger the #106b-2 VDK rotation. **BUT rotation needs the master password** (prompt-on-revoke, `106b2` §0a + `commit_vdk_rotation` takes `new_password`) — so the trigger **CANNOT silently auto-rotate.** The design:

```
WATCHER (pangolin-chain + the chain_sync read path):
  detection (recommend BOTH, mirroring #103/#101 chain-read posture):
    (i)  event-driven: decode DeviceRemoved(vaultId, signer, manager, nonce, sv) in the chain_sync poll loop
         (the same loop that decodes RevisionPublished today) — a removal seen live;
    (ii) set-diff anti-staleness anchor: on each sync, compare the live authorizedDevice SET (folded from
         DeviceAdded/DeviceRemoved events, or read per-signer) against the local known-devices state.
         A signer that is locally-known-honored but NO LONGER in the on-chain set = a removal we may have
         missed (a closed app, a dropped event). The live-read is the source of truth (the #106a honor rule).

  on detecting "a device was removed from THIS vault's set":
    → persist a "rotation-pending" row in pangolin-store (vault_id, removed_signer, observed_epoch, observed_at).
      Idempotent: re-observing the same removal does not double-queue. A closed app re-reads this on next open
      and RESUMES the pending state (the removed device is already OUT of the on-chain set, so it can no
      longer publish honored entries — but the LOCAL VDK it still holds is the cryptographic gap rotation closes).

HOST (drives the password-gated completion — the engine NEVER auto-rotates):
    → surfaces a "rotation pending — enter master password" state to the user;
    → on password entry: rotate_vdk_for_survivors(survivors, vault_id, guardian_config, guardian_pubs, epoch)  (#106b-2)
        → Vault::commit_vdk_rotation(new_vdk, old_vdk, local_device, new_password, new_epoch, re_split…)  (#106b-2)
        → clears the rotation-pending row in the SAME atomic commit (or immediately after);
    → if the user DELAYS: the removed device stays out of the on-chain set (can't publish honored entries),
      so access-control is already closed; rotation closes the CRYPTO gap on the LOCAL VDK + all FUTURE data
      (forward secrecy). The pending state persists until completed (it is safe to defer — see §5 negatives).
```

- **Is the trigger client-side detection only, or does the host drive it?** RECOMMEND: **detection is client-side (engine: the watcher + the persisted pending state); completion is host-driven (the password prompt + the rotate call).** This is the exact #104b/#105 split — the engine is a toolbox that says "a rotation is needed and here is how to do it atomically"; the app decides WHEN to prompt + complete. The engine NEVER holds the master password (Argon2id lives in `pangolin-store::commit_vdk_rotation`, the password crosses there, not into `pangolin-core`).
- **Survivors + guardian pubkeys input.** `rotate_vdk_for_survivors` needs the surviving devices' `(device_id, x25519_pairing_pub)` (resolved from the surviving authorized set) + the guardian X25519 pubkeys (the SAME set; a device revoke does not touch the guardian set). The watcher/host resolves the survivors from the live on-chain SET minus the removed signer; the guardian pubkeys come from the persisted escrow config (`recovery_escrow`). GAP FLAG: resolving each surviving signer's `x25519_pairing_pub` from its on-chain `signer` address is NOT free — the on-chain set stores secp256k1 ADDRESSES, not X25519 pairing pubkeys. See GAP FLAG A (§6) + Q-c.

### 3.4 Survivor-promotion client (Q-e)

The propose/finalize/cancel calldata + the 48h-delay client flow. The contract (`RevisionLogV2.sol:720-840`) has `proposePromotion` (candidate self-signs `Promote`), `finalizePromotion` (permissionless after `PROMOTION_DELAY = 48h`), `cancelPromotion` (manager-only `msg.sender` veto). The `PromotionProposed` event is the "notify your other devices" trigger (the locked-arch requirement). RECOMMEND: fold the CALLDATA into `revisionlog_v2_client` (cheap, mirrors the other broadcasts); DEFER the full 48h-delay client STATE MACHINE + the notification surfacing to a follow-up — it is orthogonal to the add+remove+rotate centerpiece and the E2E does not need it. Surfaced as Q-e.

---

## 4. L-invariants (proposed — mirror 103/104b style)

- **L1 (new files only; v1/v2 contract + #106b crypto untouched; additive client surface).** New: `pangolin-chain::revisionlog_v2_{signing,client}`, `pangolin-core::device_add`, the `pangolin-store` rotation-pending + new-device persistence, the coupled E2E, the `anvil-ci.sh` wiring. `RevisionLogV2.sol`, `pairing.rs`, `rotation.rs`, `commit_vdk_rotation` are REUSED, not modified. `recovery_client.rs`/`secp256k1_signing.rs`/`chain_submit.rs`/`evm.rs` reused verbatim.
- **L2 (EIP-712 byte-identity client↔contract for the device-management calls — LOAD-BEARING, the #103 L2/L3 class).** The client's `AddDevice`/`RemoveDevice`/`Promote`/`Revision`(v2) digests are byte-identical to the contract's `_hashAddDevice`/`_hashRemoveDevice`/`_hashPromote`/`_hashRevision` under the v2 domain (`version = "2"`). A drift is SILENT + TOTAL (the contract recovers a wrong address → revert → device-add unreachable). Pinned by hermetic typehash + domain-separator constants AND the anvil `addDevice`/`removeDevice` round-trips (the live contract accepts the client's sig). The v2 domain MUST differ from v1 so a v1 signature can never replay against v2.
- **L3 (the rotation trigger NEVER auto-rotates without the master password — LOAD-BEARING).** The watcher only ever PERSISTS a rotation-pending state + SURFACES it; it never derives a password, never calls `rotate_vdk_for_survivors`+`commit_vdk_rotation` itself. Argon2id stays in `pangolin-store`; the master password crosses ONLY at host-driven completion. A test asserts the watcher path holds no password and the engine cannot complete a rotation autonomously.
- **L4 (the VDK never crosses where it shouldn't — CATASTROPHIC-IF-WRONG, inherits #106b-1 L4).** The VDK reaches a new device ONLY as a `SealedVdkForDevice` to that device's X25519 pairing pubkey, domain-bound to `vault_id‖device_id‖epoch`; it is opened by the recipient, re-wrapped under its own device key, never logged, never written un-sealed to any transport. The orchestration driver carries only public context. The rotation re-keys the new-epoch VDK ONLY to survivors (never the removed device, #106b-2 L1).
- **L5 (honor = the current on-chain SET; permissive auto-register REMOVED).** A revision is honored iff its signer ∈ the current on-chain `authorizedDevice` set (live-read, the #106a rule). `auto_register_device_from_chain_sync`'s permissive "trust any signer seen" (GAP FLAG D) is replaced by set-membership. A removed/never-added/former-manager signer is NOT honored. (#106c does the minimum the E2E needs; the systematic generalization is #106d, Q-g.)
- **L6 (rotation-pending state is crash-durable + idempotent).** The pending row survives an app close (a closed app resumes it); re-observing the same `DeviceRemoved` does not double-queue; completing the rotation clears it atomically with `commit_vdk_rotation` (or immediately after). A delayed rotation is safe (access-control already closed by the on-chain set; only the local-VDK crypto gap remains until completion).
- **L7 (chain-id + pinned-address binding reused).** `RevisionLogV2` reads + broadcasts reuse #101 `resolve_envelope_chain_id` verbatim (BaseSepolia pinned + RPC cross-check; Dev reads live anvil id) + the deployment-file address pin; production never sources the signing/envelope chain id from an untrusted RPC. The v2 deployment gets a `deployment_json_pins_match_rust_constants` cross-check + a pinned `EXPECTED_REVISIONLOG_V2_ADDRESS_*` + `REVISIONLOG_V2_DOMAIN_SEPARATOR_*` (mirroring the v1/RecoveryV1 posture; testnet capture is a TODO until the Base Sepolia v2 deploy lands).
- **L8 (`pangolin-chain` no `pangolin-store` dep; `pangolin-core` pure).** cargo-tree guard green (`check-chain-no-store.sh`). `pangolin-core::device_add` stays zero-uniffi, zero-chain, zero-serde-on-secrets (`check-no-uniffi-in-core.sh`). The crypto crate's serde-count stays 0.
- **L9 (schema-version ladder).** Every v2 call passes `schemaVersion = 1`; reject `> MAX_KNOWN_SCHEMA_VERSION` symmetrically (the contract reverts `ErrUnsupportedSchemaVersion`).
- **L10 (coupled anvil E2E = the regression gate).** The deploy → bootstrap → add → seal+open(`ct_eq`) → new-device publish-succeeds → remove → publish-now-reverts → rotation-trigger fires → rotate+commit → forward-secrecy assert E2E MUST be a CI gate (env-quirk #14 class). The audit must verify a deliberately-broken honor predicate ("honor all signers"), a broken EIP-712 digest, OR a silent auto-rotate turns it RED. Negatives are assertions inside the test (§5).
- **L11 (no new on-chain data; no VDK/secret to chain).** #106c broadcasts ONLY what #106a defined; no VDK / sealed envelope / device key / pairing secret ever leaves the device for the chain (the #106a contract has no slot for it). The pairing handoff travels over the pairing channel/relay, never the chain.
- **L12 (testnet-only until D-011).** `RevisionLogV2` + the pairing handoff + the rotation stay Base-Sepolia-only until the external audit clears.
- **L13 (`forbid(unsafe_code)` except FFI; AGPL SPDX on every new file).** No new `=`-pinned dep without `cargo deny`/`cargo audit` (expect ZERO — alloy provides keccak/sol!/EIP-712/secp256k1; the crypto is the merged #106b surface).
- **L14 (FULL `cargo test --workspace` gate — the #106b-1 lesson).** The merge gate is the WHOLE workspace test run (not just the touched crates), per the #106b-1 lesson that a crate-scoped run hid a cross-crate break. PLUS the anvil E2E via `anvil-ci.sh`.
- **L15 (§16 ledger).** `git merge --no-ff`; DECISIONS.md Q-resolution entries; DEVLOG at merge; explicit Kelvin approval at the merge boundary (§16.3). A new on-chain v2 testnet deploy → a D-0xx DECISIONS row for the RevisionLogV2 address.

---

## 5. The coupled anvil E2E (the centerpiece) — shape + negatives

Lives beside the #103/#104b lifecycle tests (a `#[cfg(integration-tests)]` `#[ignore]`d test driven by `scripts/anvil-ci.sh`, which ALREADY deploys RevisionLogV2 bound to the dev RecoveryV1). Shape:

```
1. deploy RevisionLogV2 (+ RecoveryV1, already in the harness);
2. bootstrapVault(vaultId, A_signer, sv, A_self_sig)            → A in the set, A is manager;
3. A reads live deviceNonce; A signs AddDevice(B_signer, nonce); addDevice(...)  → B in the set (real manager EIP-712);
4. A seal_vdk_to_device(vdk, B_x25519_pub, vault_id, B_device_id, epoch);
   B open_vdk_from_pairing(...) → assert ct_eq(B_vdk, A_vdk)    (the VDK handoff round-trips byte-identical);
5. B publishRevision(...) signed by B_signer → SUCCEEDS         (B is in the on-chain set, honored);
6. A reads live deviceNonce; A signs RemoveDevice(B_signer, nonce); removeDevice(...) → B out of the set;
7. B publishRevision(...) again → the client's honor gate (L5) treats B as UNhonored
   (and a fresh publish by B is no longer in the set → the read gate rejects it);
8. the DeviceRemoved watcher fires → a rotation-pending state is persisted (NOT an auto-rotate, L3);
9. host completes: rotate_vdk_for_survivors([A], …) + commit_vdk_rotation(new_vdk, …, master_password, …);
10. assert FORWARD SECRECY:
    - the survivor A opens the NEW epoch (its survivor seal opens under A's pairing secret; A re-wraps under A_DeviceKey);
    - the removed device B CANNOT open the new epoch (no survivor seal was minted to B — #106b-2 L1);
    - B still holds its pre-revoke VDK (immutable on-chain ciphertext stays readable to it — that is expected;
      forward secrecy is about POST-revoke data).
```

**Negatives that MUST turn the gate RED:**
- a deliberately-broken `AddDevice` EIP-712 digest (wrong typehash/domain/field-order) → the live contract reverts `ErrNotDeviceManager`/`ErrInvalidSignature` → step 3 fails (L2);
- a broken honor predicate ("honor all signers" / "ignore the set") → step 7 wrongly honors the removed B (L5);
- a silent auto-rotate (the watcher completing without a password) → L3 violated;
- the new-epoch VDK sealed to the REMOVED device (B in the survivor set) → step 10 forward-secrecy assert fails (#106b-2 L1);
- a skipped escrow re-point on rotation → a future guardian recovery strands on the dead VDK (#106b-2 L2/L8, asserted in the rotate+commit path);
- a stale `deviceNonce` → `addDevice`/`removeDevice` revert `ErrBadNonce` (the L11-analogue).

**Test posture (hermetic + coupled):**
- **Hermetic (pangolin-chain):** byte-pin tests for `ADD_DEVICE_TYPEHASH_V2`/`REMOVE_DEVICE_TYPEHASH_V2`/`PROMOTE_TYPEHASH_V2` + the v2 domain separator (re-keccak the literal, like `approve_typehash_matches_pinned_constant`); sign+recover round-trip; the v2-vs-v1 domain-separation test (a v1 sig must NOT verify under v2).
- **Hermetic (pangolin-core):** the device-add driver over fixtures (the seal is produced from public inputs; the open round-trips `ct_eq`); the rotation-trigger detection over synthesized `DeviceAdded`/`DeviceRemoved` logs (set-fold → "B removed" → pending state); the L3 "watcher holds no password / cannot auto-complete" assertion.
- **Hermetic (pangolin-store):** rotation-pending persist → reload → resume round-trip; the set-membership honor gate over a fixture set (in-set honored / removed rejected); additive-migration test (a legacy vault opens with the rotation-pending column absent → clean default).
- **Coupled anvil E2E (CENTERPIECE / L10):** the full sequence above.
- **`#[ignore]`'d live tests** against the Base Sepolia v2 deployment once it exists (deferred, same posture as #103/#104b/4.1).

---

## 6. GAP FLAGS — where the merged #106a/#106b APIs may not cleanly support the client flow

- **GAP FLAG A — the on-chain SET stores secp256k1 ADDRESSES; the pairing seal needs X25519 PAIRING PUBKEYS.** `rotate_vdk_for_survivors` takes each survivor's `(device_id, x25519_pairing_pub)`, but the on-chain `authorizedDevice` set keys on the secp256k1 `signer` address (the publish identity), not the X25519 pairing pubkey. There is NO on-chain mapping `signer → x25519_pairing_pub`, and the contract correctly never carries one (no VDK-adjacent slots, L12). So the client must maintain a LOCAL `signer → (device_id, x25519_pairing_pub)` directory, populated at device-add time (when A learns B's full triple) + persisted. A survivor whose pairing pubkey the local directory does not know cannot be re-keyed automatically (the same shape as #104b's "M−t non-participant guardian pubkeys" gap — recommend the device-add persists the full triple, with opportunistic completion as survivors come online). **Surfaced as Q-c. This is the single biggest "API doesn't cleanly compose" flag.**
- **GAP FLAG B — the `device_id` shape must be agreed end-to-end.** `pairing.rs` defines `DEVICE_ID_LEN = 32` ("a content/address-derived identifier matching the device_id shape the orchestration layer (#106c) carries") but does NOT define how it is derived. #106c must define the canonical `device_id` (recommend: derived one-way from the DeviceKey, like the signer + pairing pubkey, so it is stable + self-asserting) and bind it consistently into the seal header AND the publish `deviceId` field. No primitive change; an orchestration responsibility.
- **GAP FLAG C — `commit_vdk_rotation` produces ONLY the LOCAL device's per-device wrap; remote survivors get only the SEAL.** Per `rotation.rs` + `commit_vdk_rotation`, the store wraps the new VDK under the LOCAL device key + persists the survivor SEALS for the remote survivors. The REMOTE survivors must, on their next sync, open their seal + re-wrap under their own device key (the "survivors that synced the seal re-wrap under their own device keys" note in `commit_vdk_rotation`). #106c must build the remote-survivor SEAL-CONSUMPTION path (open the survivor seal from the synced rotation artifacts → `wrap_vdk_for_device` → persist) — this is NOT in the merged code; it is the symmetric peer of the device-add open/wrap. Recommend it lives in the same `device_add`/sync glue. **Surfaced as part of Q-c.**
- **GAP FLAG D — the reader permissively auto-registers every signer (inherited from 4.1 R-d).** `auto_register_device_from_chain_sync` trusts any signer in a verified event — correct for single-device, WRONG for the multi-device honor rule. #106c replaces it with set-membership (L5). The systematic version is #106d; #106c does the minimum the E2E needs (Q-g).
- **GAP FLAG E — #106d is not built.** The full revocation generalization (the read-gate rewrite + scorched-earth-on-recovery reset + v1→v2 dual-read) is #106d. #106c needs ENOUGH honor-gate for the E2E. Flag the sequencing (Q-g): do the minimum in #106c, or pull #106d forward.

---

## 7. Open decisions for Kelvin (Q-a … Q-i) — recommendation + plain-English stakes

See the companion report. Each Q below has a recommendation + plain-English stakes.

### Q-a · Scope: is the device-add CLIENT + the rotation TRIGGER one #106c, or split?
**Recommend: ONE #106c stage** (optionally two PRs on one branch), because the coupled anvil E2E — the value — needs the add arm AND the remove-and-rotate arm present together. **Stakes:** keeping them together means the regression gate actually proves the whole multi-device loop end-to-end; splitting leaves a half-wired intermediate with no meaningful test.

### Q-b · The `DeviceRemoved` trigger: client-side detection only, or host-driven completion?
**Recommend: detection client-side (the engine watcher + the persisted rotation-pending state); completion host-driven (the password prompt + the rotate call).** The engine NEVER auto-rotates (it cannot — it holds no master password; Argon2id is store-side). **Stakes:** this is the subtle safety property — a device removal can't silently re-key your vault behind your back; you must enter your master password to close the crypto gap. The app nags you ("rotation pending"); you decide when to complete. If the user delays, the removed device is already locked OUT of publishing honored entries (the on-chain set), so nothing is exposed — rotation just closes the gap on the LOCAL key for future data.

### Q-c · Resolving survivors' X25519 pairing pubkeys for rotation (GAP FLAG A/C)
**Recommend: maintain a LOCAL persisted `signer → (device_id, x25519_pairing_pub)` directory, populated at device-add time, with opportunistic completion** (a survivor whose pubkey we don't yet know is re-keyed when it next comes online + presents its triple). The on-chain set deliberately stores only addresses (no VDK-adjacent slots). **Stakes:** the chain knows WHO your devices are (addresses) but not the encryption key needed to hand them the new vault key — your own device remembers that locally. If a survivor's encryption key isn't on hand at rotation time, it gets re-keyed the next time it syncs (the same "opportunistic completion" #104b accepted for guardian pubkeys).

### Q-d · The line between #106c (crypto binding) and #106e (pairing UX)
**Recommend: #106c's driver takes the new device's verified `(device_id, signer_addr, x25519_pairing_pub)` triple as input + does the seal/add/open/wrap; #106e does the out-of-band SCANNING (QR/short-code) + the §5.3 presence-proof gate that delivers that triple to the primary.** **Stakes:** #106c proves the cryptography + the regression gate (the VDK reaches the new device safely, the removed device is cut off); #106e is the in-person "scan this QR / type this code" screen that stops a remote attacker from sneaking their device in. We build the lock now; the door + the doorbell are #106e.

### Q-e · Survivor-promotion client: in #106c or split out?
**Recommend: fold the propose/finalize/cancel CALLDATA into `revisionlog_v2_client` (cheap, mirrors the other calls); DEFER the full 48h-delay client STATE MACHINE + the "notify your other devices" surfacing to a follow-up.** **Stakes:** promotion is the "my primary phone is lost, promote my laptop to be the boss device" flow — important, but orthogonal to the add+remove+rotate centerpiece. We make the contract calls reachable now; the full delayed-promotion + heads-up UX is its own focused slice (it has its own 48h-window + veto + biometric concerns).

### Q-f · FFI/uniffi: in #106c or deferred?
**Recommend: defer/fold.** Keep `pangolin-core` pure (zero-uniffi, the crate's confirmed discipline + #103/#104b Q-i posture). The host-app entry points (device-add wizard, the rotation-pending prompt) fold with the pending #105b recovery-FFI or land in #106e UX. **Stakes:** "can the phone app call this yet?" — not in #106c; #106c proves the logic + the regression gate, the app wiring is the next cycle. Avoids gold-plating before the UX cycle needs it.

### Q-g · How much of the #106d revocation generalization does #106c need?
**Recommend: #106c does the MINIMUM honor gate the E2E needs — replace the permissive auto-register with set-membership (live-read the on-chain set, honor iff in it) — and DEFER the systematic generalization (scorched-earth-on-recovery reset, v1→v2 dual-read cut-over, the full read-gate rewrite) to #106d.** **Stakes:** the E2E must prove a removed device is no longer honored, so #106c can't skip the honor gate entirely — but the full systematic rewrite (folding #103-C, the dual-read during cut-over) is a separate, audit-critical slice. Confirm we do the minimum now and #106d does the rest. (Alternative: pull #106d forward into #106c — bigger, slower merge.)

### Q-h · Local re-encrypt to the newest VDK on rotation: now or deferred?
**Recommend: DEFER (keep the epoch chain as the always-correct source of truth; local re-encrypt is a perf nicety).** This matches `106b2` Q-b's resolution. **Stakes:** on-chain history is multi-epoch forever (immutable); locally we COULD rewrite our own rows to the newest key (fewer keys to juggle) but the epoch chain already decrypts everything correctly. For a password manager the key list is tiny. Confirm we ship the always-correct chain and defer the optimization.

### Q-i · Land #106c as one PR or two on a single branch?
**Recommend: one #106c stage; optionally two reviewable PRs on one branch (PR1 = chain-client + add-driver + new-device persistence; PR2 = the rotation-trigger watcher + the coupled E2E).** **Stakes:** purely review-ergonomics; either way the coupled anvil E2E is the merge gate. Low.

---

## 8. Effort + risk

**Medium-large — composition + a watcher, not new crypto/contract; lower headline risk than #106a/#106b but real integration risk.** Budget ~2-3 weeks. The mechanical reuse (calldata/sign/broadcast over the merged `chain_submit` envelope; the seal/open/wrap over the merged `pairing.rs`; the rotate+commit over the merged `rotation.rs`/`commit_vdk_rotation`) is fast. The net-new highest-care work is concentrated in three places: (1) **L2 the EIP-712 byte-identity** for the manager-signed device calls (silent + total if wrong, the env-quirk #14 class — the #103 lesson); (2) **L3 the no-silent-auto-rotate trigger** + the persisted resumable pending state (the subtle safety property); (3) **GAP FLAG A/C the survivor pairing-pubkey directory + remote-survivor seal consumption** (the API doesn't cleanly compose — the biggest design risk). The coupled anvil E2E is the structural defense for all three. All of it stays testnet-only until D-011; the in-house adversarial audit scrutinizes the joins (the digest byte-identity, the honor gate, the no-auto-rotate property), not the merged primitives.

---

## 9. Where it lives (files expected to change — for the eventual build, NOT this draft)

- **`crates/pangolin-chain/src/revisionlog_v2_signing.rs`** (new) — the v2 EIP-712 builders + pinned typehash/domain constants. `forbid(unsafe_code)` + AGPL.
- **`crates/pangolin-chain/src/revisionlog_v2_client.rs`** (new) — the `sol!` binding + the six lifecycle broadcasts + the live SET/nonce/manager reads + the device-management event folding + the watcher's event-decode hook into `chain_sync`.
- **`crates/pangolin-core/src/device_add.rs`** (new) — the pure device-add orchestration driver + the rotation-trigger detection types (set-fold → pending). PURE.
- **`crates/pangolin-store/src/vault.rs`** + a new additive table — the rotation-pending state (persist/resume), the new-device `DeviceWrappedVdk` persistence, the remote-survivor seal-consumption path, the set-membership honor gate replacing permissive `auto_register_device_from_chain_sync`, the local `signer → pairing-pubkey` directory (Q-c). Additive schema (§18.7 bump).
- **`crates/pangolin-chain/src/recovery_client.rs`** (or a sibling integration module) — the coupled anvil E2E beside the #103/#104b lifecycle tests.
- **`scripts/anvil-ci.sh`** — add the #106c device-add+remove+rotate E2E invocation (RevisionLogV2 is already deployed there).
- **`DECISIONS.md` / `DEVLOG.md` / `THREAT_MODEL.md`** — append-only at merge; a D-0xx row for the RevisionLogV2 testnet address; THREAT_MODEL device-add + rotation-trigger rows (post-audit).

Files NOT expected to change: `contracts/src/RevisionLogV2.sol` + `RecoveryV1.sol` (deployed + immutable); `pairing.rs` / `rotation.rs` / `escrow.rs` (the merged crypto, REUSED); `keys.rs`'s wrap model (unchanged — per-device wrap is additive).
