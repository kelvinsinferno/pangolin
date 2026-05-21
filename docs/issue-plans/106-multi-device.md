<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Issue #106 — MULTI-DEVICE (one vault, several devices) — plan-gate ARCHITECTURE LOCKED

**Status: ARCHITECTURE LOCKED — Kelvin sign-off 2026-05-21 (see §0a). Foundational model resolved; sub-issue-level details (#106b crypto, #106e UX) get their own plan-gates.** Mirrors the §16 plan-gate format of `103c-revocation-on-read.md` / `104b-recovery-orchestration.md` / `105-recovery-core-hardening.md`.
This epic is **TESTNET-ONLY (Base Sepolia)** in every shippable slice until the D-011 external audit
clears — it touches a new on-chain contract (`RevisionLogV2`) AND net-new device-to-device crypto,
both of which are inside the D-011 audit package.

**Base tip: current main `8b2878f`** (#105a atomic re-split persistence merged; #104b orchestration
`ab8d33e`; #102 RecoveryV1 `97cbe4c`; RevisionLogV1 deployed D-017 / immutable; #103-C revocation-on-read
production code built + audited on branch `worktree-agent-a3f6272eca2f476be` (NOT merged) — this epic
folds it in, see §3.4 + §0a).

## 0a. RESOLVED architecture decisions (Kelvin sign-off 2026-05-21)

The whitepaper confirms multi-device is intended (VDK fans out per device key; "devices revoked without recovery"; vault authority "authorizes device enrollment/revocation"). Decisions:

- **Per-device keys (LOCKED).** Each device auto-generates its own internal key (in the OS secure-enclave/keystore, unlocked by that device's biometric/PIN) — NOT a separate master password per device. ONE master password total (set on first device + recovery fallback). The VDK is wrapped per-device-key. Enables per-device biometric unlock AND device-level revocation. Rejected: shared-master-password (worse UX + no true device revocation). NOT offered as a user either/or (per-device dominates once the "extra passwords" misconception is cleared).
- **VDK handoff = sealed-box pairing (LOCKED approach; crypto detail → #106b).** Adding a device: the existing (unlocked) device seals the VDK to the new device's X25519 pubkey, reusing the #104a `crypto_box`/`guardian.rs` sealing primitive, domain-bound to vault_id‖device_id‖epoch; the new device opens it + wraps under its own device key. No master-password re-entry on the new device beyond pairing presence.
- **Trust model (LOCKED): primary authorizes + survivor-promotion + preserve-survivors-on-loss.** Normal add: only the current `vaultAuthority` (your primary device) authorizes a new device. If the PRIMARY is lost: any SURVIVING device can promote itself to primary — gated by its own biometric (a thief can't), a short delay, and a heads-up to your other devices/guardians — then revoke the lost primary + pair a replacement, WITHOUT full guardian recovery. **Losing one device never touches your other devices** (no whole-set wipe). Full guardian social-recovery is only for the lost-EVERYTHING case (no surviving device).
- **Device removal = ON-CHAIN authorized set (LOCKED; REVISES the earlier read-side lean).** `RevisionLogV2` holds a live authorized-device SET with `addDevice` AND `removeDevice`, BOTH gated by the vault authority (self-sovereign vault management — NOT the "admin/upgrade/pause" the cardinal no-admin rule forbids). Honor rule becomes trivial: a revision is honored iff its signer is in the CURRENT on-chain set. This **largely dissolves #103-C's lineage-inference/retroactive-re-eval machinery** — the set itself is the live source of truth; #103-C's fold-in becomes "read the current set" instead of inferring from authority rotation. (True cryptographic kill of a removed device's already-held VDK ALSO requires VDK rotation + re-seal to survivors — the access-control set-membership is one layer, the key rotation is the crypto layer; detail for #106b/#106d.)
- **V2 binds RecoveryV1 `vaultAuthority` cross-contract (LOCKED)** — one authority concept; closes the #103-C GAP FLAG 2 "no on-chain link" gap.
- **Recovery × device set (REVISED from #103-C scorched-earth):** recovery rotation PRESERVES surviving authorized devices; the set resets to only the recovering device in the lost-EVERYTHING case (where there are no survivors anyway). This supersedes the #103-C single-device-v1 / scorched-earth assumption now that multi-device exists.
- **Migration (recommend-lock): new-vaults-only on V2;** RevisionLogV1 stays deployed/immutable. (Confirm at #106a.)
- **Split (LOCKED): 5 sub-issues** — **#106a** RevisionLogV2 contract (authorized set + add/remove/promote, authority-gated, reads RecoveryV1) = FIRST slice; **#106b** device-pairing VDK-handoff crypto + VDK-rotation-on-revoke (highest-stakes, own adversarial audit like #104a); **#106c** client device-add flow; **#106d** revocation generalization (folds #103-C → "honor in current on-chain set"); **#106e** pairing UX. Each gets §16 builder→audit→merge; #106b gets its own plan-gate.

**Remaining sub-issue-level opens (NOT blocking the architecture lock):** exact survivor-promotion on-chain mechanism + delay/notification (#106a/#106c); VDK-rotation-on-revoke specifics (#106b); pairing trust-bootstrap UX — QR/short-code + presence proof (#106e); §18-style schema/domain versioning for V2 (#106a).

---

## 0. One-paragraph summary

Today a Pangolin vault is permanently bound to **one** device. `RevisionLogV1.sol` self-bootstraps
exactly the first publisher per vault (`registeredDeviceCount == 0` → register that signer; otherwise
`ErrSignerNotRegistered`) and has **no** function to add a second device; and the Vault Data Key (VDK,
which decrypts everything) is wrapped only under the **password-derived** `AuthorityKey`
(`Argon2id(password)` → `AuthorityKey::from_seed`), so a brand-new device has no way to obtain the VDK
except by re-deriving it from the same password — which is not a real multi-device handshake. The
whitepaper's Key & Authority Model diagram explicitly shows the VDK wrapped **per device key (Phone /
Laptop / Tablet)** and lists "Devices can be revoked without recovery" and the on-chain Vault Authority
as the thing that "Authorizes device enrollment/revocation." **Pangolin therefore already promised
multi-device; the current code does not implement it.** This epic builds it: a new immutable
**`RevisionLogV2`** with an authority-bound `addDevice` path (RevisionLogV1 is deployed + immutable —
the project's "bug → redeploy v2" rule), a **device-to-device VDK handoff** that reuses the #104a
`crypto_box` sealed-box primitive (an existing device seals the VDK to a new device's X25519 public
key — analogous to the guardian-share seal but device-to-device), a client device-add / pairing flow,
and the **generalisation of #103-C's revocation rule** from "honour only the single current authority's
signer" to "honour the current **authorised device set**." The owner's framing: "there is no point to
saving on chain unless it's a multi-device system" — this epic is what gives the on-chain revision log
its actual purpose (cross-device sync).

---

## 1. Scope

**#106 builds (across sub-issues — see §2):**

1. **`RevisionLogV2`** (new immutable contract) — RevisionLogV1's append-only revision log + EIP-712/
   `ecrecover` signature gate, PLUS an **authority-bound device-registry** with an explicit `addDevice`
   path (Q-a) and a per-vault **authorised-signer set** (not the v1 single-bootstrap). Reads/binds
   RecoveryV1's `vaultAuthority` (Q-h) so the "who may add a device" authority is the same secp256k1
   control authority recovery rotates. Optional on-chain `removeDevice` (Q-e).
2. **Device-pairing / VDK-handoff crypto** (net-new, in `pangolin-crypto`) — an existing paired device
   seals the VDK to the new device's X25519 public key (reusing `escrow.rs`'s `crypto_box` sealed-box +
   domain-bound header machinery), so the VDK is usable on the new device **without** crossing in the
   clear and **without** the new device needing the password (Q-c). Net-new but composition-over-vetted-
   library, same posture as #104a.
3. **Client device-add flow** (`pangolin-core` + `pangolin-store` + `pangolin-chain`) — the pairing
   handshake (Q-d trust bootstrap), the existing device signing the `addDevice` authority message +
   broadcasting it, the new device persisting its handed-over VDK, and both devices syncing the same
   vault.
4. **Revocation generalisation** — fold in #103-C: the read-side rule goes from "honour iff signer ==
   current `vaultAuthority`" to "honour iff signer ∈ current **authorised device set**" (§3.4).
5. **UX / pairing trust bootstrap** (6.x — the trust model belongs here even though the screens are 6.x):
   QR / short-code pairing, the presence-proof gate the spec already requires for "Adding or approving
   new devices" (`pangolin_main_text.txt` §5.3 — high-risk action), device-list management.

**Deferred / out of scope (this epic):**

- **Migration of existing RevisionLogV1 vaults to V2** — Q-g: recommend **new-vaults-only on V2**;
  RevisionLogV1 stays deployed + immutable, V1 vaults stay single-device until the user opts a vault into
  a V2 re-home (a flagged follow-up, not v1 of this epic).
- **Browser-extension-as-a-limited-device** (the `DeviceCapabilities` read-only seat — already a hook in
  the 1.5 schema; MVP-4 territory).
- **Mainnet** — every slice is Base-Sepolia-only until D-011.
- **Conflict resolution across devices** — already specified (whitepaper §7) and partly built (P9
  pending-merges / fork detection); multi-device makes it *reachable* but does not redesign it.

---

## 2. Splittable? — recommendation: SPLIT into 5 sub-issues; first shippable slice is the contract

This is large (new contract + net-new crypto + client + revocation generalisation + UX). Recommend the
following ordered split, each its own plan-gate + merge boundary (mirrors the #102→#103→#104a→#104b→#105
decomposition that worked for recovery):

| Sub-issue | Title | Depends on | Audit-critical? |
|---|---|---|---|
| **#106a** | **`RevisionLogV2` contract** — authority-bound `addDevice` + authorised-signer set + (opt) `removeDevice` | RecoveryV1 (deployed) | YES (D-011) |
| **#106b** | **Device-pairing VDK-handoff crypto** (`pangolin-crypto`) — seal VDK to peer device's X25519 key | #104a primitive (merged) | **YES — catastrophic-if-wrong** (D-011) |
| **#106c** | **Client device-add flow** (`pangolin-core`/`-store`/`-chain`) — pairing handshake + `addDevice` broadcast + VDK persist | #106a, #106b | partial |
| **#106d** | **Revocation generalisation** — #103-C's rule → authorised-device-set; the read gate honours the set | #103-C (build it here or just before), #106a | YES (D-011) |
| **#106e** | **Pairing UX + presence gate** (6.x) — QR/short-code, device-list management | #106c | no |

**First shippable slice: #106a (the `RevisionLogV2` contract).** Reasons: (i) it is the foundation
everything else binds to; (ii) it is self-contained + testable in isolation with the same anvil harness
RevisionLogV1 already uses; (iii) deploying it to Base Sepolia (testnet-only) unblocks #106c without
touching client crypto; (iv) it forces the load-bearing Q-a/Q-b/Q-e/Q-h decisions to be made first, so
the crypto + client are built against a frozen authority model. **#106b is the highest-stakes piece**
(wrong device-handoff design = the VDK leaks or a rogue device gets it) and should get the same in-house
adversarial-audit rigor as #104a.

---

## 3. The end-to-end design (decisions surfaced in §5)

### 3.0 What the whitepaper specifies the design SHOULD be (the intent we build to)

The four canonical specs (`docs/specs/README.md`) are normative. The multi-device design is spelled out
in the **whitepaper** + the **Key & Authority Model** diagram + the technical key-hierarchy section:

- **Whitepaper §7 "Multi-Device Synchronization & Conflicts":** *"Multiple devices may independently
  update the same account identity… Each update references a previous state. If two updates occur
  concurrently, a conflict is detected. The system never silently merges secrets… The user selects the
  authoritative version."* — multi-device is a first-class promised capability, with conflict surfacing
  (already partly built: P9 fork detection).
- **Key & Authority Model diagram** (`whitepaper_text.txt` L549-588): the VDK fans out to **`Device Key
  A (Phone)`, `Device Key B (Laptop)`, `Device Key C (Tablet)`**, with the stated properties:
  *"Devices can be revoked without recovery"* and *"VDK is re-wrapped, not re-created."*
- **Technical key-hierarchy** (`pangolin_main_text.txt` §F L3177-3200): *"Vault Authority … Authorizes:
  device enrollment/revocation, revision publication, recovery cancellation… Device Keys: Generated per
  device. Authorized under vault authority. Can be revoked at any time."*
- **Daily-sync flow** (whitepaper Flow 4): *"Edit account on Device A → … → Device B pulls + applies
  update. User sees: 'Synced'."* — this is the cross-device sync the on-chain log exists to serve.
- **Session spec** (`pangolin_main_text.txt` §5.3): *"Adding or approving new devices"* is a **high-risk
  action that requires an explicit presence proof** even within an active session — the UX trust gate
  (Q-d / #106e) is already spec'd.

> **WHITEPAPER-vs-CURRENT-ARCHITECTURE DIVERGENCE (load-bearing).** The diagram shows the VDK wrapped
> **per device key**. The **current code does NOT do this** — `keys.rs` wraps the VDK only under the
> single password-derived `AuthorityKey` (`WrappedVdk::seal_under` keyed by `AuthorityKey::derive_wrap_
> key`; the only persistent VDK form). A second device cannot obtain the VDK from this wrapper without
> the password. #104a added a *second* wrap under the guardian RWK (recovery path), but there is **no
> per-device VDK wrap**. So the whitepaper's "VDK fans out to each device key" is **aspirational, not
> built.** Q-c decides how to close this: a per-device VDK wrap (faithful to the diagram) vs a one-shot
> device-to-device handoff at pairing time (lighter — the new device then re-wraps under its own copy of
> the password authority). **Recommend the handoff (Q-c), which keeps the daily wrap password-derived
> (one authority, matching the current single-`WrappedVdk` storage) and only adds a transient pairing
> seal — minimal new at-rest surface.**

### 3.1 The device-add flow (designed)

```
Device A (already paired, unlocked, holds VDK + is in the authorised set)
   │  1. New device B installs app, generates its DeviceKey (Ed25519) → derives
   │     its secp256k1 RevisionLog signer (evm.rs) + its X25519 sealing pubkey (guardian.rs path)
   │  2. PAIRING HANDSHAKE (Q-d): B shows A its (device_id || secp256k1 addr || X25519 pubkey)
   │     out-of-band — QR code on B's screen scanned by A, or a short code typed into A.
   │  3. A verifies presence proof (spec §5.3 high-risk gate), confirms "add this device?"
   ▼
Device A:
   a. signs an authority-bound `addDevice(vaultId, B_signer, B_x25519_pub)` message
      with the vault's CONTROL authority (the secp256k1 `vaultAuthority` — A holds it
      in the clean single-primary case) → broadcasts the addDevice tx to RevisionLogV2
   b. seals the VDK to B's X25519 pubkey: `seal_share`-analogue
      `seal_vdk_to_device(vdk, B_x25519_pub, vault_id, epoch)` → a `SealedVdk` envelope
      (crypto_box sealed box, domain-bound header `vault_id || device_id_B || epoch`)
   c. delivers `SealedVdk` to B (over the same pairing channel or a relay drop — it is
      sealed, so the transport is untrusted)
   ▼
Device B:
   d. opens `SealedVdk` with its X25519 secret → recovers the byte-identical VDK
   e. re-wraps the VDK under ITS OWN copy of the password authority (Q-c: the password is the
      same vault password, entered on B during pairing) → its own local `WrappedVdk`
   f. now in the authorised set on-chain (RevisionLogV2 recorded the addDevice); pulls + applies
      the full vault history; publishes its own revisions signed by B_signer
```

The clean case has **one primary** device holding the `vaultAuthority`; secondaries are added by it
(Q-b). The contract records the authorised-signer set so the read gate (§3.4) honours all of them.

### 3.2 The VDK handoff crypto (#106b — the net-new, catastrophic-if-wrong piece)

Reuse the **exact** `escrow.rs` machinery, retargeted device-to-device:

- `crypto_box` anonymous **sealed box** (ephemeral-X25519 → XSalsa20-Poly1305) — already a vetted dep
  (`crypto_box` 0.9, Cure53-audited; `default-features = false`, no serde). The new device's X25519
  recipient key is derived from its `DeviceKey` exactly as a guardian's is
  (`guardian::derive_x25519_sealing_key`, `pangolin-guardian-x25519-v0`) — OR under a **distinct,
  device-pairing-specific HKDF info string** (`pangolin-device-pair-x25519-v0`) so a pairing key is never
  the same primitive as a guardian-share key (Q-c sub-decision; recommend distinct info — domain
  separation discipline the codebase already follows for every HKDF use).
- Domain-bound header inside the sealed plaintext: `SEAL_DOMAIN || vault_id || recipient_device_id ||
  epoch` (mirrors `sealed_share_header`), so a `SealedVdk` minted for device B / vault X / epoch n
  cannot be replayed against device C / vault Y / epoch m.
- The recovered VDK `ct_eq`s the original byte-for-byte (the VDK is **handed over, never re-derived** —
  faithful to "VDK is re-wrapped, not re-created"). **The VDK never crosses in the clear** (L-invariant).

This is genuinely net-new (the existing escrow seals a *Shamir share of an RWK*, not the VDK directly),
but it is composition over the same audited sealed-box, so the design risk is "did we bind the right
context + use the right recipient key," not "did we invent a cipher." **In-house adversarial audit is
the only review before testnet (per the recovery-track constraint); D-011 is the hard pre-mainnet gate.**

### 3.3 The contract — `RevisionLogV2` (#106a)

`RevisionLogV2` = RevisionLogV1's `publishRevision` (EIP-712/`ecrecover`, `schemaVersion` ladder,
append-only, no admin / no upgrade / no pause — all v1 cardinal rules inherited verbatim) PLUS:

- `mapping(bytes32 vaultId => mapping(address signer => bool)) authorisedDevice` — the **authorised-
  signer set** (generalises v1's single-bootstrap `isRegisteredDevice`).
- `function addDevice(bytes32 vaultId, address newSigner, bytes authoritySig)` — adds `newSigner` to the
  set **iff** `authoritySig` is a valid signature by the vault's **current control authority** over a
  domain-bound `AddDevice(vaultId, newSigner, nonce)` digest (Q-a). The authority identity is **read
  from RecoveryV1's `vaultAuthority(vaultId)`** (Q-h cross-contract bind) — so "who may add a device" ==
  "the secp256k1 authority recovery rotates," and a recovery that rotates the authority automatically
  changes who can add devices.
- Bootstrap: the **first** publish (or an explicit `bootstrapVault`) registers the creating device's
  signer as both the genesis authorised device AND aligns with RecoveryV1's `setGuardianSet` initial
  authority (the creating device is `msg.sender` there). (Q-a sub-decision on bootstrap shape.)
- `removeDevice(...)` (Q-e) — OPTIONAL on-chain removal, authority-signed. The alternative is keeping
  removal **read-side** (#103-C generalised, §3.4). Big call — see Q-e.
- Emits `DeviceAdded(vaultId, newSigner)` (+ `DeviceRemoved` if Q-e on-chain) so readers fold the
  authorised set from events (mirrors how #103-C folds the authority lineage).

### 3.4 How #103-C folds in (the revocation generalisation — #106d)

#103-C (plan LOCKED, not yet built) decided **GAP FLAG 2 → SINGLE-DEVICE v1**: the current
`vaultAuthority` is the SOLE honoured signer, and multi-device-after-recovery was explicitly punted to
"RecoveryV2 / a new device-registry-with-authority-binding contract (deferred)." **This epic IS that
contract.** The fold-in:

- **#103-C's predicate generalises, its infra is reused.** The read gate goes from
  `is_honoured(signer) := signer == A_current` to
  `is_honoured(signer) := signer ∈ authorisedSet(A_current)` — where `authorisedSet` is the set the
  current authority has built via `addDevice` (folded from `RevisionLogV2.DeviceAdded` events, minus any
  `DeviceRemoved` / minus the scorched-earth-on-rotation reset, Q-f). The authority-lineage machinery
  (`read_vault_authority_v1`, `RecoveryFinalized` folding, the `.pvf` lineage cache, the live-read anti-
  staleness anchor) is **reused verbatim**; #106d just swaps the single-signer check for a set-membership
  check.
- **The scorched-earth + signer-based decisions carry over.** #103-C Q-a (signer-based) and Q-b
  (scorched-earth: revoke ALL of a former authority's entries) still hold; the only change is the
  *current* honoured thing is now a set, not a singleton.
- **Build ordering:** #103-C can be built standalone first (single-device, as its plan says) and #106d
  generalises it; OR #103-C is built directly in its generalised form inside #106d. Recommend: **build
  #103-C standalone first** (it is small, ~1-2 weeks, closes a real security gap today, and is already
  plan-LOCKED), then #106d widens the predicate. This keeps each merge boundary small.

### 3.5 The dual-authority interaction (reconcile with the recovery model)

Per `pangolin_recovery_model.md` the "authority" is **two independent things**: (1) on-chain secp256k1
`vaultAuthority` (control plane, rotated by RecoveryV1) and (2) off-chain Ed25519 password-`AuthorityKey`
(the VDK daily-wrap key). Multi-device interacts with both:

- **Control plane:** the **authorised device set** is a property of the *current* secp256k1
  `vaultAuthority`. Adding a device = the control authority signs `addDevice`. This is why #106a binds
  RecoveryV1's `vaultAuthority` (Q-h).
- **VDK wrap:** in the recommended handoff (Q-c), each device keeps its **own** password-derived
  `WrappedVdk` (same password, so same `AuthorityKey`, so the same wrap key — the VDK is shared, the wrap
  is per-device-local). The handoff is only the *bootstrap* that gets the VDK onto the new device; daily
  operation is unchanged per-device. **No change to `keys.rs`'s wrap model is required** under Q-c.
- **Recovery rotation interaction (Q-f):** when recovery rotates the `vaultAuthority` (lost everything),
  does the device set reset to just the new device, or carry over? #103-C chose scorched-earth (old
  devices revoked). Recommend the device set **resets to the single recovering device** on rotation
  (matches #103-C scorched-earth + the whitepaper Flow 3 "Old Devices Revoked"); the user re-pairs their
  surviving devices afterward. Carry-over would re-honour devices the recovery was invoked to escape.

---

## 4. L1..Ln invariants (proposed — mirror 103c/104b/105 style)

- **L1 (new contract; v1 untouched; additive client gate).** `RevisionLogV2` is a brand-new immutable
  file at a fresh address. RevisionLogV1 (and its deployed instances) are NOT modified. The client read
  gate is an **additive** generalisation of #103-C's filter — signature verification (4.1 L5) and the
  ingest idempotency are byte-identical up to the set-membership check.
- **L2 (only the current authorised device SET is honoured — LOAD-BEARING).** A verified revision is
  ingested iff its recovered signer ∈ the current `vaultAuthority`'s authorised-device set. Any signer
  not in the set (former authority, never-added device, removed device) is revoked. This is the property
  the D-011 audit signs off; a regression must turn the anvil gate (L11) red.
- **L3 (only the control authority may add a device — LOAD-BEARING).** `addDevice` succeeds iff the
  authority signature verifies against the **current** `vaultAuthority` (read from RecoveryV1, Q-h). No
  admin key, no peer-add (Q-b recommends authority-gated). A rogue device cannot add another device.
- **L4 (the VDK NEVER crosses in the clear — CATASTROPHIC-IF-WRONG).** The device-to-device handoff
  (#106b) only ever transports the VDK as a `crypto_box` sealed envelope to the recipient device's
  X25519 pubkey, domain-bound to `vault_id || recipient_device_id || epoch`. The recovered VDK `ct_eq`s
  the original; the VDK is handed over, never re-derived, never logged, never written un-sealed to any
  transport. In-house adversarial audit is the only review before testnet.
- **L5 (testnet-only until D-011).** `RevisionLogV2` + the pairing crypto stay Base-Sepolia-only until
  the external audit clears. Mirrors the whole recovery track.
- **L6 (no upgrade / no admin / no pause on V2).** Inherits RevisionLogV1's cardinal rules verbatim:
  exact-pinned pragma, no proxy, no `selfdestruct`, no owner, no role. Append-only revision log; the only
  mutating slots are the sequence counter + the authorised-set mapping (+ removal mapping if Q-e),
  written exclusively from `addDevice`/`removeDevice`/`publishRevision` success paths.
- **L7 (`forbid(unsafe_code)` except FFI; AGPL SPDX) on every new Rust file.** The crypto crate keeps
  `forbid(unsafe_code)`; the only `unsafe` in the workspace is the documented uniffi FFI surface.
- **L8 (zero-serde / secret discipline on the handoff).** The `SealedVdk` envelope + any new key types
  follow the #104a discipline: no serde anywhere on the secret path, `!Clone`/`!Copy`, zeroizing,
  redacted `Debug`, `ct_eq`, fixed-layout byte encodings. `cargo tree -p pangolin-crypto | grep -ci
  serde == 0` preserved.
- **L9 (domain separation / replay).** The pairing seal binds `vault_id` + `recipient_device_id` +
  `epoch`; the `AddDevice` digest binds `vault_id` + `newSigner` + a nonce. Distinct HKDF info string for
  the pairing X25519 key (`pangolin-device-pair-x25519-v0`), distinct from every existing info string.
- **L10 (chain-id + pinned-address binding reused).** `RevisionLogV2` reads + the RecoveryV1
  `vaultAuthority` cross-read reuse #101 L4 chain-id pinning + 4.1 L3/L4 pinned-address cross-checks;
  production never sources the binding chain-id from an untrusted RPC.
- **L11 (anvil regression gate for device-add + revoke = CI gate).** Deploy RevisionLogV2 + RecoveryV1 →
  bootstrap device A → `addDevice(B)` signed by A's authority → publish revisions from A and B → read →
  assert BOTH A and B honoured. Then add the revoke arm: rotate authority A→C via recovery → read →
  assert A and B revoked, only C (+ C's added devices) honoured. A deliberately-broken predicate
  ("honour all signers" or "ignore the authorised set") MUST turn the gate red (env-quirk #14 class).
- **L12 (schema-version / domain separation for V2).** `RevisionLogV2` gets its own EIP-712 domain
  (`name = "Pangolin RevisionLog", version = "2"`) so a v1 signature can never be replayed against v2 and
  vice-versa; event `schemaVersion` keeps the §18.7 ladder; the `AddDevice` typehash + the pairing seal
  domain are versioned.
- **L13 (§16 ledger).** `git merge --no-ff` per sub-issue; DECISIONS.md Q-resolution entries; DEVLOG at
  each merge; explicit Kelvin approval at each merge boundary (§16.3). New on-chain deployment → a D-0xx
  DECISIONS row for the RevisionLogV2 testnet address.

---

## 5. Open decisions for Kelvin (Q-a … Q-i) — recommendation + plain-English stakes

### Q-a · Device-add authorization model (THE core question)
Who can authorize a new device? **(a) authority-gated** — only the current `vaultAuthority` (the
primary / recovering device) signs an `addDevice`; **(b) peer/web-of-trust** — any already-authorised
device can add another (write-additive grow); **(c)** a device-add is just a special signed revision.
**Recommend (a) authority-gated.** It binds cleanly to RecoveryV1 (recovery rotates the authority →
automatically changes who can add devices; the device set resets on rotation, Q-f), it is the smallest
trusted surface, and it matches the whitepaper's "Vault Authority authorizes device enrollment." (b) is
friendlier (add a laptop from your phone without the "primary" present) but means a *single compromised
device* can silently add an attacker's device — a much worse blast radius. (c) collapses into the v1
self-bootstrap threat profile (anyone who gets a device key claims the vault).
**Plain-English stakes:** this decides "who can let a new gadget into your vault." Authority-gated =
only your designated primary (or your recovered device) can; safest, but you must have the primary on
hand to add a device. Peer = any of your devices can add another; convenient, but if one device is
stolen-and-unlocked, the thief can quietly enroll their own device and read everything.

### Q-b · One "primary" device (+ secondaries) vs a flat set of equal devices
**Recommend: one primary holds the `vaultAuthority`; secondaries are authorised by it (asymmetric).**
This shapes everything — it makes Q-a (a) natural, makes recovery's "rotate the authority" coherent (the
primary's key IS the authority), and matches the #104b single-recovering-device flow. A flat set (every
device is an equal authority) would need on-chain multi-authority (each device able to add/remove others
= each device's compromise is total), which is a much larger contract + a worse blast radius.
**Plain-English stakes:** "primary + secondaries" means your phone (say) is the boss device that admits
others and is what recovery restores; lose it and you recover to a new primary. "All equal" means any
device can do anything — simpler mental model for the user, but any one stolen device compromises the
whole vault's membership.

### Q-c · How a newly-paired device gets the VDK (the crypto handoff)
**Recommend: a one-shot device-to-device SEAL at pairing** — the existing device seals the VDK to the
new device's X25519 pubkey (reuse `escrow.rs` `crypto_box`), the new device opens it and re-wraps under
its own copy of the **same password** authority. This keeps the daily wrap model in `keys.rs` UNCHANGED
(one password authority, one `WrappedVdk` per device, no per-device-key VDK wrap), adds only a transient
pairing envelope, and never re-derives the VDK (byte-identical, faithful to the whitepaper). The
alternative — a true **per-device-key VDK wrap** (the diagram's literal model: store N `WrappedVdk`s,
one per device's key) — is more faithful to the diagram but is a bigger change to `keys.rs` + the at-rest
schema + the recovery re-wrap, for a benefit (device joins without re-entering the password) that the
spec's high-risk-action presence gate (§5.3) arguably wants the password for anyway.
**Plain-English stakes:** the new device needs the key that decrypts your vault. The recommended way
hands it over **encrypted just for that device** during pairing (nobody in between can read it), and the
new device still asks for your vault password to set itself up. The per-device-key alternative would let
a device join with *no* password, just the pairing handshake — more convenient, but a paired-but-not-
password-protected device is a weaker at-rest story. **This is net-new security-critical crypto either
way (#106b) — it must get the in-house adversarial-audit rigor #104a got.**

### Q-d · Pairing UX / trust bootstrap (what stops an attacker pairing their device)
**Recommend: out-of-band channel — the new device shows a QR (its device_id + secp256k1 addr + X25519
pubkey); the primary scans it, shows a confirmation + a presence proof (spec §5.3 high-risk gate), then
signs `addDevice` + seals the VDK.** Short-code typed entry is the fallback for no-camera. The
out-of-band channel + presence proof is what stops a remote attacker: they cannot present a QR to your
physically-held primary, and they cannot forge the authority signature.
**Plain-English stakes:** pairing is the moment an attacker would try to sneak their device in. Requiring
the new device's identity to be shown *to your trusted primary in person* (QR/short code) + a presence
proof means an attacker has to be physically at your primary device with it unlocked — the same bar as
"add a device" everywhere good. Get this wrong (e.g. a "pair by entering a code the server emails you")
and remote phishing can enroll a rogue device.

### Q-e · Device REMOVAL: on-chain (`removeDevice`) or read-side (#103-C generalised)?
**Recommend: read-side first (no on-chain `removeDevice` in #106a); add on-chain removal only if a
concrete need appears.** Removal-on-read (the #103-C mechanism, generalised) means "stop honouring a
device's signer in the client" — the contract stays append-only (no removal path, matching the v1
cardinal rule), and the authorised set the reader folds simply excludes the removed signer (via an
authority-signed "revoke" the reader honours, OR via the scorched-earth-on-recovery reset). On-chain
`removeDevice` would make removal globally visible + enforced at write time, but it adds a mutating
authority-keyed path to an otherwise append-only contract (closer to an admin surface) and a second
attack-surface to audit.
**Plain-English stakes:** "remove my old laptop." Read-side removal = your *own* devices stop trusting
that laptop's future entries (and, scorched-earth, its past ones) the next time they sync — the chain
still physically holds the old entries but nobody honours them; this is how recovery already works.
On-chain removal = the contract itself refuses the removed laptop's future writes — stronger, visible to
everyone, but adds a privileged "delete" path to a contract whose whole design is "no privileged paths."
Read-side matches the existing posture; on-chain is a deliberate exception Kelvin would have to want.

### Q-f · Authorised-device-set × recovery rotation: reset to the new device, or carry over?
**Recommend: RESET to the single recovering device on rotation (scorched-earth, matches #103-C + the
whitepaper Flow 3 "Old Devices Revoked").** When recovery rotates the authority (you lost everything),
the new device is the only honoured one; you re-pair surviving devices afterward.
**Plain-English stakes:** recovery is invoked because devices are lost/compromised. Resetting the set
means "after recovery, only your new device is trusted; re-add the others if you still have them" —
safest. Carrying the old set over would re-trust devices the recovery existed to escape (e.g. a stolen
laptop), defeating recovery. The cost of reset is a small re-pair chore for any surviving devices.

### Q-g · Migration from RevisionLogV1 — new-vaults-only on V2, or a migration path?
**Recommend: new-vaults-only on V2; RevisionLogV1 vaults stay single-device + immutable; a per-vault
"opt into V2" re-home is a flagged follow-up.** RevisionLogV1 stays deployed (the "versioned deployments
allowed" rule). Forcing migration would mean re-publishing or re-anchoring v1 history under v2's domain,
which is a substantial separate design.
**Plain-English stakes:** existing single-device vaults keep working exactly as today (no breakage);
multi-device is available to vaults created after V2 ships. An existing vault gets multi-device only if
the user explicitly re-homes it (a later feature). Alternative (auto-migrate everyone) is more
seamless but a much bigger, riskier change touching deployed-vault data.

### Q-h · Does `RevisionLogV2` read RecoveryV1's `vaultAuthority` on-chain (cross-contract), or keep its own authority?
**Recommend: read RecoveryV1's `vaultAuthority` (cross-contract bind).** This closes #103-C's GAP FLAG 2
("no on-chain link between a RevisionLog signer and the RecoveryV1 `vaultAuthority`"). It means there is
ONE authority concept: recovery rotates it, and device-add is gated by the same address — no second,
divergent authority to keep in sync. The cost is a cross-contract `staticcall` to RecoveryV1 in
`addDevice` (cheap) + a hard dependency on RecoveryV1's address (pinned at V2 deploy, the same way the
client pins it).
**Plain-English stakes:** this is "is there one notion of 'who controls this vault,' or two?" Binding to
RecoveryV1 = one authority; recovering your vault automatically updates who can add devices — clean,
no drift. Keeping a separate authority in V2 = simpler contract (no cross-call) but now a recovery
rotation and a device-add authority can disagree, which is exactly the gap that lets a stale key linger.
Recommend the bind.

### Q-i · Does the existing chain reader / #104b recovery flow need changes?
**Recommend: the reader gains the set-membership gate (#106d) + a `RevisionLogV2` event path (dual-read
v1 + v2 during cut-over, mirroring the 4.1 v0→v1 dual-read pattern); #104b recovery is unchanged except
the post-recovery device set resets to the recovering device (Q-f).** The `pangolin-chain`
`chain_sync`/`poll` event decode gains the V2 ABI + `DeviceAdded` folding; `Vault::sync_from_chain`'s
`auto_register_device_from_chain_sync` (currently permissive R-d) is replaced by "register iff in the
authorised set."
**Plain-English stakes:** the sync engine that pulls revisions has to learn about V2's events and stop
auto-trusting any signer it sees (today it permissively registers every signer — fine for single-device,
wrong for multi-device where trust must come from the authorised set). Recovery itself barely changes —
it already rotates the authority; the only addition is "reset the device set on rotate."

---

## 6. Where the existing contracts / crypto do NOT cleanly support multi-device (GAP FLAGS)

- **GAP FLAG A — no per-device VDK access (the VDK-sharing gap).** The VDK is wrapped ONLY under the
  password authority (`keys.rs` `WrappedVdk::seal_under`); there is no per-device wrap and no device-to-
  device handoff primitive. A new device literally cannot get the VDK from the current at-rest data
  without the password re-deriving the same authority. #106b builds the missing handoff. **This is the
  biggest crypto gap and the whitepaper-vs-code divergence (§3.0).**
- **GAP FLAG B — no on-chain authorised-signer SET (only v1's single-bootstrap).** RevisionLogV1 has a
  one-shot self-bootstrap (`registeredDeviceCount == 0` registers, else reject) with NO add path and NO
  authority binding. There is no way on-chain to express "vault X trusts signers {A, B, C}." #106a's
  RevisionLogV2 builds it. (Same gap #103-C flagged as GAP FLAG 2 and deferred to "RecoveryV2 / a new
  device-registry contract" — this epic.)
- **GAP FLAG C — no cross-contract authority link.** RevisionLogV1's registry and RecoveryV1's
  `vaultAuthority` are unrelated on-chain; nothing makes "the device that may publish" track "the
  authority recovery rotates." Q-h closes this by having V2 read RecoveryV1's `vaultAuthority`.
- **GAP FLAG D — the reader permissively auto-registers every signer it sees.**
  `auto_register_device_from_chain_sync` (4.1 R-d) trusts any signer in a verified event — correct for
  single-device, but it means multi-device "trust" currently comes from "whoever published," not from an
  authorised set. #106d replaces it with set-membership.
- **GAP FLAG E — #103-C is plan-LOCKED but NOT BUILT.** This epic depends on either building #103-C
  first (recommended) or building its generalised form inside #106d. Flag the sequencing to Kelvin.

---

## 7. Test posture

- **Anvil device-add + revoke regression gate (centerpiece, L11):** deploy RevisionLogV2 + RecoveryV1 →
  bootstrap A → `addDevice(B)` authority-signed → publish from A and B → assert both honoured → rotate
  A→C via the full RecoveryV1 lifecycle → assert A and B revoked, only C honoured. Negative arm: a broken
  predicate ("honour all signers") MUST flip the gate red.
- **Contract unit + invariant tests (#106a):** mirror RevisionLogV1's suite (happy path, invalid sig,
  unregistered signer, tampered fields, cross-vault replay, no-admin-selector probe, gas sanity) PLUS
  `addDevice` happy/rejected-by-wrong-authority/cross-contract-authority-read tests + an invariant that
  only `publishRevision`/`addDevice`/(`removeDevice`) mutate state and the authorised set only ever holds
  authority-signed entries.
- **Crypto adversarial tests (#106b):** VDK handoff round-trips byte-identical; a `SealedVdk` for device
  B / vault X / epoch n is rejected for device C / vault Y / epoch m (domain binding); the VDK never
  appears un-sealed in any transport buffer; `cargo tree` serde-count == 0; redacted-Debug snapshots.
- **Hermetic units (#106d):** authorised-set folding from synthesised `DeviceAdded`/`RecoveryFinalized`
  logs; the set-membership predicate over a fixture set (current set honoured / removed revoked / former-
  authority's set revoked); the scorched-earth-on-rotation reset.
- **`#[ignore]`'d live tests** against the testnet deployments once a multi-device testnet vault exists
  (deferred like 4.1/#103-C live tests).

---

## 8. Effort + risk

**Large — the biggest single epic since recovery; budget per sub-issue.** #106a (contract) ~2-3 weeks
(new contract + full test/invariant/anvil suite + testnet deploy). #106b (handoff crypto) ~2-3 weeks
**and the highest-stakes** — wrong design leaks the VDK; in-house adversarial audit is the only review
pre-testnet, D-011 is the hard pre-mainnet gate. #106c (client flow) ~2-3 weeks. #106d (revocation
generalisation) ~1-2 weeks on top of #103-C. #106e (UX) ~2-4 weeks (6.x). Risk concentration: (1) the
VDK-handoff crypto (#106b, catastrophic-if-wrong); (2) the device-add authorization rule (#106a Q-a/Q-h
— a wrong rule lets a rogue device in); (3) the revocation generalisation (#106d — a wrong rule keeps a
removed device trusted). All three are in the D-011 audit package; the anvil device-add+revoke gate is
the single most important structural defence. **Everything stays testnet-only until D-011.**

---

## 9. Where it lives (files expected to change — for the eventual build, NOT this draft)

- **`contracts/src/RevisionLogV2.sol`** (new) + `contracts/test/RevisionLogV2*.t.sol` +
  `contracts/abi/RevisionLogV2.json` + `contracts/script/DeployRevisionLogV2.s.sol`.
- **`crates/pangolin-crypto/src/pairing.rs`** (new) — the `SealedVdk` envelope + `seal_vdk_to_device` /
  `open_sealed_vdk` (reuse `crypto_box` from `escrow.rs`) + the device-pairing X25519 derivation (distinct
  HKDF info). `forbid(unsafe_code)` + AGPL SPDX + the #104a secret discipline.
- **`crates/pangolin-chain/`** — `RevisionLogV2` `sol!` binding; `addDevice` build/sign/broadcast; the
  `DeviceAdded` event folding into an authorised-set type; the set-membership revocation predicate
  (generalising #103-C's `revocation.rs`).
- **`crates/pangolin-store/src/vault.rs`** — the device-add orchestration (pairing handshake glue, VDK
  persist), the set-membership gate replacing permissive `auto_register_device_from_chain_sync`, the
  scorched-earth-on-rotation reset; additive schema for any pairing/authorised-set cache (§18.7 bump).
- **`crates/pangolin-core/`** + **`crates/pangolin-ffi/`** — the host-callable device-add / pairing
  entry points (uniffi) for #106e.
- **`scripts/anvil-ci.sh`** + the #103/#101 lifecycle harness — the device-add + revoke regression gate.
- **`DECISIONS.md`** / **`DEVLOG.md`** / **`THREAT_MODEL.md`** — append-only at each merge; a D-0xx row
  for the RevisionLogV2 testnet address; THREAT_MODEL multi-device + device-handoff rows (post-audit).

Files NOT expected to change: `contracts/src/RevisionLogV1.sol` + `contracts/src/RecoveryV1.sol`
(deployed + immutable); the EIP-712/merkle/signature-verification paths (reused); `keys.rs`'s wrap model
(unchanged under the recommended Q-c handoff).

---

## 10. Whitepaper / model alignment note

This epic implements the **promised-but-unbuilt** multi-device design: the Key & Authority Model
diagram's VDK-fans-out-to-Device-Keys, whitepaper §7's multi-device sync, and §F's "Vault Authority
authorizes device enrollment/revocation." The **one divergence to record in the spec addendum + the
D-011 audit package** (§3.0, GAP FLAG A): the diagram's literal "VDK wrapped per device key" is realised
under the recommended Q-c as a **device-to-device VDK handoff at pairing** (the VDK is shared via a
sealed envelope, then each device wraps it under its own copy of the password authority) rather than N
distinct on-chain/at-rest per-device VDK wrappers — a faithful realisation of "VDK is re-wrapped, not
re-created; never crosses in the clear," chosen to keep the daily wrap model (`keys.rs`) unchanged. If
Kelvin prefers the diagram's literal per-device-key wrap (password-less device join), that is Q-c's
alternative and changes `keys.rs` + the at-rest schema.
