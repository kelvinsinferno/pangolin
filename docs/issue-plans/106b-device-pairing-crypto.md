<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Issue #106b — Device-pairing VDK-handoff crypto + cryptographic device-kill (VDK rotation on revoke) — plan-gate ARCHITECTURE LOCKED

**Status: ARCHITECTURE LOCKED — Kelvin sign-off 2026-05-21 (see §0a). SPLIT primitive-first: #106b-1 (pairing-seal + per-device-wrap primitive) FIRST, then #106b-2 (VDK-rotation-on-revoke flow, own plan-gate).** Highest-stakes slice of the multi-device epic (#106). NET-NEW
security-critical off-chain crypto in `pangolin-crypto` (same tier as #104a / RecoveryV1). Gets its own
in-house adversarial audit (the ONLY review before testnet; D-011 external audit is the hard pre-mainnet
gate). Mirrors the §16 plan-gate structure of `104-recovery-escrow-crypto.md` / `104b-recovery-orchestration.md`.

## 0a. RESOLVED decisions (Kelvin sign-off 2026-05-21)

- **Q-b (CRUX) → R1: device-revoke ROTATES (re-creates) the VDK.** A removed device keeps ONLY data it had already synced at revoke time and is permanently locked out of all FUTURE data (re-encrypted under a fresh VDK it never receives). Rejected R2 (on-chain-set-removal only = the revoked device reads the whole vault forever = revocation in name only).
- **Q-c → whitepaper reconciliation RATIFIED (spec-addendum + D-011 package):** "VDK is re-wrapped, not re-created" is the RECOVERY invariant (regain the SAME VDK via guardians — #104a/#104b); "devices revoked without recovery" is a SEPARATE operation that re-CREATES the VDK. No contradiction.
- **Q-g → SPLIT primitive-first (like #104):** **#106b-1** = pairing-seal + per-device-wrap PRIMITIVE (own #104a-style adversarial audit) FIRST → **#106b-2** = VDK-rotation-on-revoke FLOW (its own plan-gate; composes #106b-1 + the #104b guardian escrow).
- **Q-a → per-device wrap LAYERED on the password anchor** (Option 1): the password `WrappedVdk` stays the primary/recovery anchor; per-device wraps are layered on for biometric unlock. NO `keys.rs`/recovery change.
- **Q-e → bind recipient `device_id` into the seal header** (hardening).
- **Q-f → ONE shared monotonic per-vault epoch** for both recovery re-split and device rotation.
- **Pairing crypto:** reuse the audited #104a `crypto_box` sealed-box VERBATIM (seal the 32-byte VDK to the new device's X25519 pubkey, domain-bound vault_id‖device_id‖epoch); new device's X25519 recipient key from its `DeviceKey` under distinct info `pangolin-device-pair-x25519-v0`; per-device wrap reuses `keys.rs` `seal_under_key`/`open_with_key` under distinct info `pangolin-device-wrap-v0`. ZERO new deps. MITM stopped by out-of-band QR/short-code (UX #106e) + the `deviceManager`-signed on-chain `addDevice` (#106a) + epoch/device_id header.

**Deferred to #106b-2's own plan-gate (NOT settled here):** Q-d — device-revoke MUST re-point the guardian recovery escrow at the rotated VDK (else a future recovery silently restores the dead old VDK). The EXACT mechanism — whether it re-splits the RWK (re-involving guardians, per #104b L6) or re-wraps the new VDK under the existing RWK without bothering guardians (needs the RWK available, an RWK-custody tradeoff) — is a #106b-2 design decision with a real guardian-UX cost. Flagged.

**Base tip: main `8b2878f`** (#106 architecture LOCKED 2026-05-21; #106a `RevisionLogV2` LOCKED 2026-05-21,
Q-a Option B `deviceManager`; #104a escrow primitive merged `1271766`; #104b orchestration merged `ab8d33e`;
#102 RecoveryV1 `97cbe4c` deployed-immutable; RevisionLogV1 D-017 deployed-immutable). Implements #106 §0a
row "#106b device-pairing VDK-handoff crypto + VDK-rotation-on-revoke" and #106a's open follow-up "VDK
device-to-device handoff crypto (#106b)". **TESTNET-ONLY (Base Sepolia) until D-011 clears.**

---

## 0. One-paragraph summary

#106a built the on-chain authorized-device SET (`addDevice`/`removeDevice`/`promoteSurvivor`, gated by an
in-V2 `deviceManager`) — the **access-control** layer: a revision is honored iff its signer is in the
current set. #106b builds the **crypto** layer that backs that set: (1) the **device-pairing VDK handoff** —
when a device is added on-chain, an existing unlocked device seals the VDK to the new device's X25519 pubkey
(reusing the #104a `crypto_box` sealed-box, domain-bound to `vault_id‖device_id‖epoch`), so the new device
obtains the byte-identical VDK without it ever crossing in the clear and without the password crossing the
wire; and (2) the **cryptographic device-kill** — when a device is removed/compromised, mint a FRESH VDK,
re-encrypt the vault payload under it, and re-seal/re-wrap it ONLY to the surviving devices, so the removed
device — which still physically holds the OLD VDK — can decrypt nothing published after the kill. This is
the operation that makes "revoke a device" mean something cryptographically rather than in-name-only.
**It introduces no novel primitive** — every byte is composition over the #104a sealed-box + the `keys.rs`
AEAD wrap machinery — but the *composition* (sealing the VDK itself, and rotating it on revoke) is net-new
and catastrophic-if-wrong, so it gets #104a-grade adversarial-audit rigor.

---

## 1. Scope

**#106b builds (in `pangolin-crypto`; orchestration glue is #106c):**

1. **Per-device VDK wrap** (`WrappedVdkDevice` — the at-rest form on each device). A VDK wrapped under a key
   derived from that device's own `DeviceKey` (enclave/keystore-resident, biometric-gated at the platform
   layer — #106e), via a DISTINCT versioned HKDF info (`pangolin-device-wrap-v0`) so it can never collide
   with the password-wrap (`pangolin-vdk-wrap-v0`), the recovery-wrap (`pangolin-recovery-wrap-v0`), or the
   guardian-seal (`pangolin-guardian-x25519-v0`) derivations. **Whether this is the daily at-rest form or
   only a transient is Q-a** (see THE FORK below); the primitive is built either way.
2. **Device-pairing handoff** (`SealedVdk` + `seal_vdk_to_device` / `open_sealed_vdk`). The existing device
   seals the VDK to the new device's X25519 recipient key (derived from the new device's `DeviceKey` via a
   pairing-specific HKDF info `pangolin-device-pair-x25519-v0`, mirroring `guardian::derive_x25519_sealing_key`),
   domain-bound to `vault_id‖recipient_device_id‖epoch`. The new device opens it and re-wraps under its own
   device key (and/or the password — Q-a). Structurally identical to #104a's `seal_share`, sealing the
   32-byte VDK instead of a 33-byte Shamir share.
3. **VDK rotation on revoke** (`rotate_vdk_for_survivors`) — the cryptographic device-kill. Generate a fresh
   `VdkKey`, bump the vault `epoch`, re-encrypt the vault payload under the new VDK (the bulk re-encrypt is a
   `pangolin-store` concern; the crypto crate provides the new VDK + the re-wrap/re-seal to survivors), and
   re-seal/re-wrap the new VDK to every SURVIVING device — never to the removed one. (THE CRUX, §3.)

**Deferred / out of scope (this sub-issue):**
- **The bulk vault-payload re-encrypt** on rotation (the loop over revisions/records) — a `pangolin-store`
  orchestration concern (#106c); #106b provides the rotated `VdkKey` + the survivor re-wrap/re-seal and the
  property that the old VDK is dead for new data.
- **Pairing UX / trust bootstrap** (QR / short-code / presence proof) — #106e; #106b defines only the crypto
  binding (what is authenticated, what crosses the wire) the UX must carry.
- **The on-chain set + `deviceManager` + promotion** — #106a (LOCKED). #106b reacts to set mutations.
- **The read-side set-membership honor rule** — #106d.
- **Mainnet** — every slice is Base-Sepolia-only until D-011.

---

## 2. Splittable? — recommendation: SPLIT #106b into two stages (primitive-first, like #104)

#106b bundles two catastrophic-if-wrong operations with different shapes. Recommend the same primitive-first
decomposition that worked for #104 (a → primitive, b → orchestration):

| Stage | Title | Contains | Audit |
|---|---|---|---|
| **#106b-1** | **Pairing-seal + per-device-wrap PRIMITIVE** | `WrappedVdkDevice` (per-device wrap), `SealedVdk` + `seal_vdk_to_device`/`open_sealed_vdk`, the pairing X25519 derivation. Pure crypto, hermetic tests (round-trip, domain-binding negatives, KAT, proptest). | YES — #104a-grade in-house adversarial audit |
| **#106b-2** | **VDK-rotation-on-revoke flow** | `rotate_vdk_for_survivors` (fresh VDK + survivor re-seal/re-wrap + epoch bump), the "removed device can't open the rotated VDK" property, the recovery/#104b re-split interaction (§4). | YES — its own audit pass; the forward-secrecy property is the load-bearing one |

**Recommend #106b-1 first** (the catastrophic-if-wrong core, self-contained + testable in isolation, forces
Q-a/Q-c first), then #106b-2 (composition: it *uses* #106b-1's seal/wrap + the #104a re-split discipline).
Surfaced as **Q-g**. (If Kelvin prefers one stage, the doc supports it — but two merge boundaries keeps each
audit focused, exactly as #104a/#104b did.)

---

## 3. THE CRUX — VDK-rotation-on-revoke vs the whitepaper's "VDK is re-wrapped, not re-created"

### 3.1 What the whitepaper actually says (quoted, normative)

The Key & Authority Model diagram (`whitepaper_text.txt` L536-588) is:

```
Vault Authority Key (Root of control)
        │  unwraps / rewraps
        ▼
   Vault Data Key (VDK) — Encrypts all secrets
        │  (fans out)
   ┌────┴─────┬──────────┐
 Device Key A  Device Key B  Device Key C
  (Phone)       (Laptop)      (Tablet)

Important properties
 • Guardians never see VDK
 • Devices can be revoked without recovery
 • Recovery rotates authority, not daily access
 • VDK is re-wrapped, not re-created
```

And Recovery Flow 3 ("Lost All Devices", L590-677) has the edge: `Authority Rotated / New Device Becomes
Owner` → **`rewrap VDK`** → `Encrypted Vault Pulled / decrypt locally`.

### 3.2 The reconciliation (RESOLVE — recommended reading)

**"VDK is re-wrapped, not re-created" is normatively about RECOVERY / authority-rotation, NOT about device
revocation.** The evidence is structural and unambiguous:
- The diagram's "re-wrapped not re-created" sits directly under the **Vault Authority → (unwraps/rewraps) →
  VDK** edge, and the ONLY flow in the whitepaper that exercises that edge is Recovery Flow 3, whose VDK edge
  is literally labeled "rewrap VDK." So "re-wrapped not re-created" is the recovery invariant: when guardians
  rotate the on-chain authority, the user regains access to the **SAME** VDK (the byte-identical VDK #104a/
  #104b already guarantee via `ct_eq`) — it is not regenerated, so the user's existing encrypted vault stays
  decryptable. That is correct and already built.
- **"Devices can be revoked without recovery" is listed as a SEPARATE property** and says NOTHING about
  whether the VDK is rotated on revoke. It only asserts that you don't need the guardian/social-recovery
  ceremony to drop a device (the #106a on-chain `removeDevice`, manager-gated). The whitepaper is silent on
  the crypto consequence of revocation — exactly as #104's plan found the whitepaper "deliberately defers the
  construction to us" (Hardware/Session Spec §9 lists key-derivation + governance mechanics as NON-GOALS).

**Therefore there is NO conflict.** Recovery re-wraps (same VDK, new authority). Device-revocation is a
DIFFERENT operation, and for it to be a *cryptographic* kill rather than access-control-only it SHOULD rotate
(re-create) the VDK for forward secrecy. "Re-wrapped not re-created" does not forbid this — it scopes a
different operation. **This must be recorded prominently in the spec addendum + the D-011 audit package** as
the one place the literal diagram wording could be mis-read against the device-kill design.

### 3.3 The two options for "revoke a device"

**Option R1 — rotate the VDK on revoke (RECOMMENDED).** On `removeDevice`: mint a fresh `VdkKey`, bump the
vault `epoch`, re-encrypt the vault payload under the new VDK, and re-wrap/re-seal the new VDK ONLY to the
surviving devices. The removed device keeps whatever it already synced (you cannot un-give plaintext it
already decrypted) but is **locked out of every future write** — it can never open data encrypted under the
new VDK, because it never receives the new VDK. This is the standard "rotate the shared group key when a
member leaves" model (the same shape as #104b's mandatory forward-security re-split on recovery).
- Cost: re-encrypt the whole vault payload once per revocation + re-wrap to N−1 survivors + push the new
  epoch. For a password manager (small payloads, infrequent revocations) this is cheap.
- Limit (accepted, unavoidable): data the removed device ALREADY synced before revocation is already in its
  hands — no scheme can retract it. R1 protects all FUTURE data. This is the honest, standard guarantee.

**Option R2 — no VDK rotation; rely only on on-chain set removal + read-side not-honored.** The removed
device's signer drops out of the #106a set (#106d stops honoring its revisions). But it STILL holds the VDK,
so it can decrypt everything already synced AND anything it can still pull from the chain/indexer (the
encrypted payload is public-durability data; honor is a *write*-side / *trust*-side rule, not a *read*-side
confidentiality barrier). This is "revocation in name only" cryptographically — the removed device retains
full read access to the vault forever.

**Recommendation: R1.** R2 makes "revoke" a lie at the crypto layer for a confidential password vault — a
stolen/compromised laptop you "revoked" could still read every password you ever sync until end of time. R1
is the only option that delivers forward secrecy, it reuses the #104b re-split discipline the project already
audited and accepted, and it aligns with the whitepaper's intent (the diagram shows the VDK as the thing all
devices fan out from; removing a fan-out edge is meaningless unless the key behind it changes). **What "revoke
a device" then MEANS cryptographically (the sentence for the spec/audit/UX):** *the removed device retains
access to data it had already synced at the moment of revocation, and is permanently locked out of all data
created after revocation; new data is re-encrypted under a fresh VDK that is never delivered to the removed
device.* (Surfaced as **Q-b**; R1 recommended.)

---

## 4. How rotation composes with recovery (#104b) + the on-chain set (#106a)

Two operations touch the VDK/authority; they MUST NOT conflict:

- **Recovery (#104b)** RE-WRAPS the SAME VDK to a new password authority (and rotates the on-chain secp256k1
  `vaultAuthority`, and re-splits a fresh RWK to guardians). The VDK is preserved bit-for-bit. Epoch advances
  for the RWK re-split.
- **Device-revoke (#106b, R1)** RE-CREATES the VDK (fresh `VdkKey`) and re-wraps/re-seals it to survivors.
  The epoch advances. **This is the ONE place a Pangolin operation legitimately re-creates the VDK** — and it
  is NOT the recovery operation, so the whitepaper invariant (§3.2) holds.

**Reconciliation rules (proposed L-invariants L4/L9 below):**
- **Single epoch counter, single VDK-generation, monotonic.** Both onboarding/recovery re-split AND device
  rotation advance the SAME per-vault `epoch` (reuse the #104a/#104b `EPOCH_LEN`-byte epoch). Every
  `SealedVdk`, `WrappedVdkDevice`, and `WrappedVdkRecovery` binds the current epoch in its domain header /
  AAD, so a sealed/wrapped VDK from epoch `n` is rejected at epoch `n+1` (the #104a `open_sealed_share`
  header-check pattern, extended to the VDK seal). A stale pairing envelope or a removed device's old wrap
  cannot be replayed forward.
- **VDK rotation MUST trigger a guardian re-split (forward security carries over).** When R1 mints a fresh
  VDK, the recovery escrow that wraps the VDK (`WrappedVdkRecovery`) is now stale — it wraps the OLD VDK.
  Following #104b L6 (mandatory re-split on any VDK change) and the recovery-model memory's "all M shares are
  points on ONE polynomial tied to ONE key — you cannot retire a subset," **a device-revoke must re-wrap the
  NEW VDK under a fresh `RWK'` and re-split/re-seal to ALL M guardians** (re-using #104a `wrap_vdk_under_rwk`
  + `split_rwk` + `seal_share`, with the bumped epoch). Otherwise a future recovery would reconstruct the RWK
  and recover the OLD (dead) VDK — a silent catastrophe. **So a device-revoke touches BOTH the per-device
  wraps AND the guardian escrow.** (Surfaced as **Q-d** — confirm device-revoke re-splits the guardian
  escrow; recommended YES, mandatory, matching #104b L6.)
- **The on-chain set is the trigger, not the carrier.** #106a's `removeDevice` (on-chain, manager-signed) is
  the *signal*; the VDK rotation is the *off-chain crypto reaction* the surviving devices perform when they
  observe the `DeviceRemoved` event (#106c orchestration). The contract never holds the VDK (RevisionLogV2
  L12). Recovery's authority-reset (#106 Q-f: set resets to the recovering device on lost-everything) and the
  device-revoke rotation are distinct: recovery resets the SET + re-wraps the same VDK; device-revoke keeps
  the surviving set + re-creates the VDK.
- **WrapContext schema.** The per-device wrap reuses `keys.rs::WrapContext{vault_id, schema_version}` AAD
  (and adds the epoch binding via the seal header for the pairing path). Bump `schema_version` for the new
  per-device wrap layout (§18.7 ladder) so a password-`WrappedVdk` can never be mis-read as a
  device-`WrappedVdkDevice`.

---

## 5. The pairing handoff design (detail)

```
Device B (new): generates DeviceKey_B → derives (i) secp256k1 signer (evm.rs), (ii) X25519 pairing
                recipient key (NEW: derive_device_pair_x25519_key, info "pangolin-device-pair-x25519-v0")
   │  out-of-band: B shows A {device_id_B || secp256k1 addr_B || X25519 pairing pub_B} via QR/short-code (#106e)
   ▼
Device A (existing, unlocked, holds VDK, is the on-chain deviceManager or an authorized device):
   a. presence-proof + confirm (spec §5.3 high-risk gate, #106e)
   b. deviceManager signs addDevice(vaultId, addr_B, nonce) → broadcast to RevisionLogV2 (#106a/#106c)
   c. seal_vdk_to_device(&vdk, &x25519_pub_B, &vault_id, &device_id_B, &epoch) → SealedVdk
      (crypto_box sealed box over plaintext  SEAL_DOMAIN || vault_id || device_id_B || epoch || vdk_bytes)
   d. deliver SealedVdk to B over the (untrusted) pairing channel / relay
   ▼
Device B:
   e. open_sealed_vdk(&sealed, &x25519_secret_B, &vault_id, &device_id_B, &epoch) → byte-identical VDK
   f. re-wrap under its OWN device key → WrappedVdkDevice  (+ password wrap if Q-a = "password is anchor")
   g. now in the on-chain set; pulls + applies the full vault history; publishes signed by addr_B
```

**What is authenticated / what stops an attacker:**
- The VDK is ONLY ever transported as a `crypto_box` sealed box to B's X25519 pubkey — **never in the clear**
  (L4, catastrophic-if-wrong). The transport (QR-adjacent channel or relay) is untrusted.
- **MITM / rogue-pubkey injection** is stopped by the OUT-OF-BAND binding (#106e): A obtains B's
  `{device_id, secp256k1 addr, X25519 pub}` triple by scanning B's QR / typing B's short code, in person, on
  A's unlocked trusted device. An attacker cannot present their pubkey to A's physically-held device, and the
  short-code/QR commits to the X25519 pubkey the VDK is sealed to — so A seals to the device B is actually
  holding, not an injected key. The **on-chain `addDevice` is `deviceManager`-signed** (#106a L9), so even if
  an attacker got a `SealedVdk`, their signer is not in the set and #106d won't honor their revisions; and the
  domain header binds `device_id_B`, so a `SealedVdk` for B cannot be opened-and-accepted as if for device C.
- **Replay** is stopped by the `vault_id‖device_id‖epoch` header (the #104a `seal_share` pattern): a
  `SealedVdk` for vault X / device B / epoch n is rejected for vault Y / device C / epoch m, and is rejected
  after the next epoch bump (post-revoke rotation invalidates in-flight pairing envelopes — a paired-but-not-
  yet-opened envelope for a device that gets revoked before opening is dead).

---

## 6. Per-device VDK wrapping (detail) — and how it relates to the password wrap

The literal whitepaper diagram shows the VDK fanning out to per-device keys. #106b realizes this as a
per-device AEAD wrap: `WrappedVdkDevice` = the VDK sealed under `HKDF-SHA512(DeviceKey.seed, "pangolin-device-
wrap-v0")`, reusing `keys.rs`'s crate-private `WrappedVdk::seal_under_key`/`open_with_key` (the same generic-
AEAD-key path #104a's recovery wrap already reuses — so NO change to the existing password-wrap code, and the
device path is symmetric to the recovery path). HKDF info distinct from all four existing infos (§1.1).

**Q-a — does the password wrap remain the daily/primary anchor, with per-device wraps layered on, or does the
per-device wrap REPLACE the password wrap as the daily at-rest form?**

- **Q-a Option 1 (RECOMMENDED — password-anchored, device-wrap layered).** Each device keeps a password-
  derived `WrappedVdk` (the existing `keys.rs` daily form, unchanged) AND a `WrappedVdkDevice` for biometric
  fast-unlock. Pairing hands over the VDK via `SealedVdk`; the new device then creates BOTH wraps (it asks
  for the vault password once at pairing — matching the spec §5.3 high-risk presence gate). Daily unlock can
  use the device wrap (biometric); the password wrap remains the recovery-independent anchor and keeps the
  `keys.rs` model + #104b recovery re-wrap UNCHANGED. **Smallest blast-radius + faithful to "one master
  password" (#106 §0a LOCK) + the spec's add-a-device-is-high-risk presence gate.**
- **Q-a Option 2 (per-device-only, password-less device join).** The new device stores ONLY the
  `WrappedVdkDevice`; no password is entered on the new device (pairing presence is the only proof). More
  faithful to the diagram's literal "fans out per device key" and friendlier UX, BUT a paired device with no
  password wrap is a weaker at-rest story (compromise of the device's enclave = VDK, with no second factor),
  it changes the #104b recovery re-wrap (which device's wrap is the recovery anchor?), and it contradicts the
  spec's high-risk-presence-gate-for-device-add. **Not recommended for v1.**

**Plain-English:** Option 1 = a new gadget gets the key handed to it encrypted-just-for-it during pairing, AND
you confirm the vault password on it once, so it has both a biometric fast-path and the password as a backstop.
Option 2 = a new gadget joins with just the in-person pairing handshake and no password — slicker, but a
stolen-and-unlocked device is then the whole story, with nothing behind it.

---

## 7. L1..Ln invariants (proposed — mirror 104a/104b/106a style)

- **L1 (the VDK NEVER crosses in the clear — CATASTROPHIC-IF-WRONG).** The handoff transports the VDK ONLY as
  a `crypto_box` sealed box to the recipient device's X25519 pubkey, domain-bound to
  `vault_id‖recipient_device_id‖epoch`. The recovered VDK `ct_eq`s the original. Never logged, never written
  un-sealed to any transport buffer. The in-house adversarial audit signs this off; a regression must turn a
  hermetic gate red.
- **L2 (byte-identical handoff; VDK handed over, never re-derived on pairing).** A paired device opens a
  byte-identical VDK (`ct_eq` the original) — pairing does NOT regenerate the VDK (faithful to "re-wrapped not
  re-created" for the *normal add* path; only REVOKE re-creates, L3).
- **L3 (revoke forward secrecy — LOAD-BEARING).** After `rotate_vdk_for_survivors`, a removed device CANNOT
  open any post-rotation `SealedVdk`/`WrappedVdkDevice`/payload: the new VDK is never sealed/wrapped to it,
  and the epoch bump rejects its stale envelopes. Tested: "a removed device can't open the rotated VDK / can't
  decrypt a post-rotation payload." The removed device retaining pre-rotation synced data is the documented,
  accepted limit (§3.3).
- **L4 (single monotonic epoch; domain separation across ALL HKDF infos & seal headers).** One per-vault epoch
  advances on onboarding, recovery re-split, AND device-revoke rotation; bound into every VDK seal header +
  wrap context. Distinct versioned HKDF infos: `pangolin-device-wrap-v0` (per-device wrap),
  `pangolin-device-pair-x25519-v0` (pairing recipient key), distinct from the four existing infos
  (`pangolin-vdk-wrap-v0`, `pangolin-recovery-wrap-v0`, `pangolin-guardian-x25519-v0`,
  `pangolin-chain-evm-wallet-v0`). A grep-able audit assertion (the #104a `domain_strings_are_versioned_and_
  distinct` test pattern) confirms no collision.
- **L5 (reuse audited #104a primitives; NO novel primitive).** The pairing seal is the #104a `crypto_box`
  sealed box (Cure53-audited, `default-features=false`, no serde) over the VDK; the per-device wrap is the
  existing `keys.rs` XChaCha20-Poly1305 AEAD via `seal_under_key`/`open_with_key`; the pairing X25519
  derivation mirrors `guardian::derive_x25519_sealing_key`. ZERO new dependencies expected (`cargo tree -p
  pangolin-crypto | grep -ci serde == 0` preserved).
- **L6 (zero-serde / secret-type discipline).** `SealedVdk`, `WrappedVdkDevice`, and any new key type follow
  the #104a discipline: no serde on the secret path, `!Clone`/`!Copy` on secrets, zeroizing, redacted `Debug`,
  `ct_eq`, fixed-layout byte encodings (NOT serde derives).
- **L7 (`forbid(unsafe_code)` except FFI; AGPL SPDX).** Every new file. The only `unsafe` in the workspace is
  the documented uniffi surface.
- **L8 (device-revoke re-splits the guardian escrow — LOAD-BEARING; §4).** A VDK rotation re-wraps the NEW VDK
  under a fresh `RWK'` and re-splits/re-seals to ALL M guardians (bumped epoch). The recovery escrow can never
  point at a dead VDK (else a future recovery silently restores the old key). Inherits #104b L6.
- **L9 (recovery vs revoke do not conflict).** Recovery re-wraps the SAME VDK to a new authority (no
  re-create); device-revoke re-creates the VDK for survivors. The whitepaper "re-wrapped not re-created"
  invariant is the RECOVERY invariant (§3.2); the spec addendum records that device-revoke is the distinct
  operation that legitimately re-creates the VDK.
- **L10 (testnet-only until D-011).** The pairing crypto + rotation stay Base-Sepolia-only until the external
  audit clears (mirrors the whole recovery/multi-device track).
- **L11 (hermetic adversarial test posture = CI gate; §8).** The "removed device can't open the rotated VDK"
  + "paired device opens byte-identical VDK" + domain-binding negatives + KAT + proptest suite is a CI gate; a
  deliberately-broken binding (seal to wrong epoch / re-seal to the removed device / skip the re-split) MUST
  turn it red (env-quirk #14 class).
- **L12 (§16 ledger).** `git merge --no-ff` per stage; DECISIONS.md Q-resolution entries; DEVLOG + THREAT_MODEL
  rows (device-handoff + device-kill, post-audit); explicit Kelvin approval at each merge boundary (§16.3).

---

## 8. Test posture (#104a-grade hermetic adversarial)

- **Pairing round-trip (L1/L2):** `seal_vdk_to_device` → `open_sealed_vdk` with the recipient's derived X25519
  key recovers the byte-identical VDK (`ct_eq`); a wrong recipient key fails; a `SealedVdk` for device B / vault
  X / epoch n is rejected for device C / vault Y / epoch m (domain-binding negatives, the #104a
  `open_sealed_share` reject pattern).
- **Per-device wrap round-trip:** `WrappedVdkDevice` seals under DeviceKey_A's derived wrap key, opens to the
  byte-identical VDK; a different device key fails (`AeadError::Tampered`); cross-vault / cross-schema replay
  fails (reuse the `keys.rs` cross-vault/schema-mismatch tests).
- **Revoke forward secrecy (L3, the centerpiece):** mint VDK_n → seal to devices {A, B, C} → revoke C →
  `rotate_vdk_for_survivors` mints VDK_{n+1} re-sealed to {A, B} only → assert A and B open VDK_{n+1}; assert C
  (with its OLD device key + OLD wrap) CANNOT open the new `SealedVdk`/`WrappedVdkDevice`; assert a payload
  encrypted under VDK_{n+1} does not decrypt under VDK_n. A broken rotation that re-seals to C MUST fail this.
- **Recovery × revoke composition (L8/L9):** after a rotation, a simulated guardian recovery reconstructs the
  fresh `RWK'` and unwraps the NEW VDK (`ct_eq` VDK_{n+1}), NOT the dead VDK_n; skipping the re-split makes
  recovery restore VDK_n (the catastrophe the test guards).
- **KAT:** a pinned device seed derives a fixed X25519 pairing pubkey (the #104a `kat_pinned_public_key_for_
  fixed_seed` pattern, distinct info string) so a future drift in the domain message / HKDF info / curve flips
  it.
- **Proptest (≥1024 cases):** random vault_id / device_id / epoch / VDK bytes round-trip the seal + the
  per-device wrap byte-equal; random epoch advance rejects stale envelopes.
- **Domain-separation grep assertion:** the two new info strings are versioned `-v0` and distinct from all four
  existing infos (the #104a `domain_strings_are_versioned_and_distinct` test).
- **Debug-redaction snapshots; `cargo tree` serde-count == 0; `forbid(unsafe_code)` compile check.**
- **`#[ignore]`'d live tests** against the testnet `RevisionLogV2` once a multi-device testnet vault exists
  (deferred, same posture as 4.1/#103-C/#104b).

---

## 9. Effort + risk

**~2-3 weeks, HIGHEST-stakes of the epic** (#106 §8). #106b-1 (primitive) ~1-1.5 weeks; #106b-2 (rotation
flow) ~1-1.5 weeks. Risk concentration: (1) the VDK never crossing in clear during pairing (L1 —
catastrophic-if-wrong, the VDK leaks if the seal/recipient binding is wrong); (2) the revoke forward-secrecy
property (L3 — a removed device retaining FUTURE access = "revoke" is a lie); (3) the revoke × recovery
re-split composition (L8 — a missed re-split silently strands the recovery escrow on a dead VDK). The mitigant
is that all three are COMPOSITION over the already-audited #104a sealed-box + `keys.rs` AEAD — the design risk
is "did we bind the right context + rotate the right key + re-seal to the right set," not "did we invent a
cipher." In-house adversarial audit is the ONLY review before testnet; D-011 is the hard pre-mainnet gate.
**Everything stays testnet-only until D-011.**

---

## 10. Where it lives (for the eventual build, NOT this draft)

- **`crates/pangolin-crypto/src/pairing.rs`** (new) — `SealedVdk` + `seal_vdk_to_device`/`open_sealed_vdk`
  (reuse `crypto_box` from `escrow.rs`); `derive_device_pair_x25519_key` (distinct HKDF info). #104a discipline.
- **`crates/pangolin-crypto/src/keys.rs`** — add `WrappedVdkDevice` + `wrap_under_device`/`open_under_device`
  reusing the crate-private `seal_under_key`/`open_with_key` (NO change to the existing password-wrap surface);
  add `pangolin-device-wrap-v0` info.
- **`crates/pangolin-crypto/src/escrow.rs`** — `rotate_vdk_for_survivors` orchestration entry (composes a fresh
  `VdkKey::generate` + the survivor re-seal/re-wrap + the mandatory `RWK'` re-split, L8), or a thin
  `pangolin-core` driver if the bulk re-encrypt stays in store (#106c).
- **`crates/pangolin-store/`, `crates/pangolin-core/`** — the device-add orchestration + bulk payload
  re-encrypt on rotation + the per-device-wrap persistence (#106c; #106b provides the crypto primitives only).
- **`DECISIONS.md` / `DEVLOG.md` / `THREAT_MODEL.md`** — Q-resolution + device-handoff + device-kill rows
  (post-audit); spec-addendum row recording the §3.2 "re-wrapped not re-created is the RECOVERY invariant;
  device-revoke re-creates" reconciliation.

Files NOT expected to change: `RevisionLogV1.sol` / `RecoveryV1.sol` (deployed-immutable); the existing
password-`WrappedVdk` wrap model under Q-a Option 1 (unchanged); the #104a `seal_share`/`open_sealed_share` /
the guardian X25519 derivation (REUSED, not modified).

---

## 11. Open decisions for Kelvin (Q-a … Q-g) — recommendation + plain-English stakes

### Q-a · Per-device wrap relationship to the password wrap
**Recommend Option 1 (password-anchored; device-wrap layered for biometric fast-unlock).** The password
`WrappedVdk` stays the daily/recovery anchor (no `keys.rs` change, no #104b recovery-re-wrap change); the
per-device wrap is an added biometric convenience; the new device confirms the vault password once at pairing
(spec §5.3 high-risk gate). Option 2 (per-device-only, password-less join) is more faithful to the literal
diagram and slicker, but weaker at-rest and contradicts the high-risk-presence gate.
**Plain-English stakes:** "does a new gadget need your vault password once when you add it?" Recommended =
yes, once, and it then has both a fingerprint fast-path and the password behind it. Alternative = no password
ever on the new gadget, just the in-person pairing — slicker but a stolen-unlocked gadget is then the whole story.

### Q-b · THE CRUX — rotate the VDK on revoke (R1) vs set-removal-only (R2)
**Recommend R1 (rotate the VDK on revoke).** R2 leaves a "revoked" device able to read the entire vault
forever — revocation in name only. R1 gives forward secrecy: the removed device keeps only what it already
synced and is locked out of all future data. **What "revoke a device" then means cryptographically:** the
removed device retains data it had already synced at revocation time, and is permanently shut out of
everything created afterward (re-encrypted under a fresh VDK it never receives).
**Plain-English stakes:** "I revoked my stolen laptop — can it still read my passwords?" R1 = it can read
only what it had already downloaded before you revoked it; everything you add or change afterward is invisible
to it. R2 = it can read everything you ever sync, forever — "revoke" wouldn't really mean anything.

### Q-c · Reconcile the whitepaper "VDK is re-wrapped, not re-created" wording (FLAG)
**Recommend: ratify §3.2 as a spec addendum** — "re-wrapped not re-created" is the RECOVERY invariant (same
VDK regained on authority rotation, already built/audited via #104a/#104b); "devices can be revoked without
recovery" is a SEPARATE property the whitepaper leaves crypto-silent, and device-revoke is the distinct
operation that legitimately RE-CREATES the VDK for forward secrecy. No conflict; record it prominently for the
D-011 audit so the literal diagram wording is not mis-read against the device-kill.
**Plain-English stakes:** the whitepaper says "the VDK is re-wrapped, not re-created." That promise is about
RECOVERY (you get your same vault back). Revoking a device is a different action where re-creating the key is
exactly the point. We should write that distinction into the spec so an auditor doesn't flag a false conflict.

### Q-d · Does a device-revoke re-split the guardian escrow?
**Recommend YES, mandatory.** A VDK rotation makes the existing recovery escrow point at the dead VDK; per
#104b L6 (and the recovery-model "you can't retire a subset of one polynomial's shares"), the rotation must
re-wrap the new VDK under a fresh `RWK'` and re-split/re-seal to all M guardians (bumped epoch). Otherwise a
future recovery silently restores the OLD vault key.
**Plain-English stakes:** when you revoke a device and the vault key changes, your guardians' recovery shares
must be refreshed to point at the NEW key — otherwise "recover my vault" later would hand you back the dead
old key. This happens automatically (no guardian ceremony), exactly like the existing recovery re-split.

### Q-e · Device-id binding in the seal header
**Recommend YES — bind `device_id` (the recipient's stable id) in the `SealedVdk` header alongside
`vault_id‖epoch`**, mirroring #104a's `vault_id‖epoch` header but adding the recipient device so a `SealedVdk`
minted for device B cannot be opened-and-accepted as if for device C even if both keys were somehow available.
**Plain-English stakes:** each "key handoff envelope" is stamped with which device it's for, so it can't be
re-aimed at a different device. Pure hardening; near-zero cost.

### Q-f · Epoch granularity — one per-vault counter for both recovery re-split AND device rotation?
**Recommend ONE shared monotonic per-vault epoch** (reuse #104a/#104b `EPOCH_LEN`). Both operations advance
it; every seal/wrap binds it; stale envelopes from a prior epoch are rejected. A single counter is simpler to
audit than parallel counters and guarantees a global ordering of key-state changes.
**Plain-English stakes:** there's one "version number" for your vault's key state; every time the key changes
(recovery or a revoke), it ticks up, and anything stamped with an old number stops working. One clean clock,
not several.

### Q-g · Split #106b into two stages (primitive #106b-1, rotation flow #106b-2)?
**Recommend YES (primitive-first, like #104a→#104b).** #106b-1 = the pairing-seal + per-device-wrap primitive
(self-contained, own audit); #106b-2 = the VDK-rotation-on-revoke flow (composes #106b-1 + the #104b re-split).
Two focused merge/audit boundaries beat one large one for catastrophic-if-wrong crypto.
**Plain-English stakes:** build and audit the "hand the key to a new device" core first in isolation, then
build the "kill a device's key" flow on top — two smaller, separately-scrutinized pieces instead of one big one.

---

## 12. Where the existing crypto does / does NOT cleanly support this

- **Cleanly supports — the pairing seal.** `escrow.rs`'s `seal_share`/`open_sealed_share` already seal
  arbitrary bytes to an X25519 recipient bound to `vault_id‖epoch`; sealing the 32-byte VDK (instead of a
  33-byte Shamir share) and adding `device_id` to the header is a direct, low-risk reuse of an audited path.
  `derive_x25519_sealing_key` is the exact template for the pairing recipient-key derivation (new info string).
- **Cleanly supports — the per-device wrap.** `keys.rs`'s crate-private `seal_under_key`/`open_with_key`
  (already reused by the recovery wrap) is a generic-AEAD-key wrap; a device-key-derived wrap is symmetric to
  the recovery wrap. The cross-vault/schema-replay tests transfer directly.
- **Does NOT exist today — the per-device wrap itself + the pairing seal of the VDK.** GAP FLAG A (#106 §6):
  the VDK is wrapped ONLY under the password authority; there is no per-device wrap and no device-to-device
  VDK handoff. #106b builds both. This is the whitepaper-vs-code divergence (#106 §3.0 / §10): the diagram's
  "VDK fans out per device key" becomes a per-device wrap (Q-a Option 1) PLUS a pairing handoff, not N
  literal on-chain per-device wrappers.
- **Does NOT exist today — VDK rotation.** `keys.rs` has `rewrap` (re-wrap the SAME VDK to a new authority —
  the recovery path) but NO "mint a fresh VDK + re-encrypt payload + re-seal to a set" operation. `VdkKey::
  generate` exists but is currently NEVER on a re-key path (the recovery invariant). #106b-2 introduces the
  ONE legitimate re-create-the-VDK operation, gated to device-revoke and explicitly distinct from recovery.
- **Whitepaper-vs-design divergence to record (§3.2 / Q-c):** the literal "VDK is re-wrapped, not re-created"
  is the recovery invariant; device-revoke re-creates the VDK. No conflict, but it MUST be written into the
  spec addendum + D-011 package so the diagram wording isn't read as forbidding the device-kill.
