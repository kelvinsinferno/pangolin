<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Issue #106e-2 — device-pairing TRANSPORT (QR / short-code payload) + SAS + device-add FFI — plan-gate DRAFT

**Status: DRAFT — awaiting Kelvin sign-off (decisions in §5). BLOCKED on #106e-1 (FFI layer).** The final #106e slice + the last of the multi-device epic: the "add a new device" handshake transport. The pairing CRYPTO (#106b-1) and the on-chain `addDevice` (#106c) already exist; #106e-2 is the net-new TRANSPORT payload codec + the SAS (short authentication string, anti-MITM) + the device-add FFI bindings. Its own #106b-style adversarial audit (the SAS is the net-new security property).

## 0. One-paragraph summary

To add a new phone B to a vault, B must hand A (an existing unlocked manager device) a non-secret triple `(device_id, x25519_pairing_pub, signer)`; A authorizes B on-chain (`addDevice` v2, #106c) and seals the VDK to B's pairing pubkey (`seal_vdk_to_new_device`, #106c); B opens it (`open_vdk_for_new_device`) and stores its own per-device wrap. ALL of that crypto is merged. **What is missing is the CHANNEL: how the triple gets from B to A and the sealed VDK from A to B, and — critically — how a human is protected against a MITM that swaps B's pairing pubkey for the attacker's.** #106e-2 builds (1) a fixed-layout, zero-serde PAIRING PAYLOAD codec (`DOMAIN ‖ schema_version ‖ vault_id ‖ device_id ‖ x25519_pairing_pub ‖ freshness_nonce`) the host renders as a QR / scans, (2) a domain-separated SAS derivation over BOTH devices' pairing pubkeys + the nonce, surfaced as a short human-comparable code, and (3) the thin device-add FFI bindings (mirroring the #100 / #106e-1 session-gated, secret-never-crosses model). **The Rust layer produces/consumes BYTES + derives the SAS; it does NOT implement a network relay — the host moves the bytes (camera/QR, app-to-app, or a relay).** The one substantive design question (§5 Q-a) is the channel structure the SAS forces: a human SAS comparison requires BOTH pubkeys on BOTH devices, i.e. a bidirectional pubkey exchange BEFORE the VDK seal flows.

## 1. Scope

**#106e-2 builds:**
1. **Pairing transport codec** (`pangolin-core::pairing_transport`, pure / no-chain / zero-serde): encode + decode the non-secret pairing payload `DOMAIN ‖ schema_version(2) ‖ vault_id(32) ‖ device_id(32) ‖ x25519_pairing_pub(32) ‖ freshness_nonce(N)`, fixed-layout, length-checked, version-gated. Both directions use the SAME payload shape (B→A carries B's triple; A→B carries A's pubkey for the SAS — see Q-a). NO QR-image rendering (the host draws the QR from the bytes); this is the byte payload only.
2. **SAS derivation** (`pangolin-crypto` — a domain-separated hash, the net-new security primitive): `derive_sas(pub_a, pub_b, freshness_nonce) -> Sas` — a transcript hash over BOTH pairing pubkeys (sorted/canonical-ordered so both devices compute the same value regardless of role) + the nonce, truncated to a short human-comparable code (Q-b format). Domain-separated info (`pangolin-pairing-sas-v0`), distinct from the existing pairing/seal HKDF infos.
3. **Device-add FFI bindings** (`pangolin-ffi::pairing`, thin, session-gated, secret-never-crosses — mirrors #106e-1 / #100): the new-device-role + existing-device-role entry points (§3.1) wrapping the merged `seal_vdk_to_new_device` / `open_vdk_for_new_device` + the on-chain `add_device_v2` + the new codec/SAS. The X25519 pairing SECRET + the VDK stay engine-side; only payload bytes + the SAS string + the sealed (non-secret) envelope cross.
4. **Tests**: hermetic codec round-trip + version/length negatives; SAS determinism + the **MITM negative (a swapped pairing pubkey ⇒ SAS mismatch — the L2 gate)**; the FFI binding discipline (no secret crosses); and a coupled add-device anvil E2E extension if warranted (the on-chain addDevice + seal/open is already E2E-tested by #106c — confirm #106e-2 adds the codec/SAS round-trip on top).

**Explicitly NOT this slice:**
- Any NETWORK TRANSPORT / relay server / app-to-app channel — the host moves the bytes; #106e-2 is the payload codec + SAS only.
- QR IMAGE rendering / camera scanning — the host renders/scans; Rust handles bytes.
- The recovery/rotation FFI (#106e-1, the prerequisite slice).
- Guardian onboarding (#106e-0b) / the recovery composition (#106e-0) — merged / separate.

## 2. Splittable? — recommend ONE slice (Q-e)

Codec + SAS + FFI are cohesive (the FFI is a thin wrapper over the codec/SAS/merged-crypto). **Recommend: ONE #106e-2 slice**, with the SAS getting focused adversarial-audit attention (the net-new security property). Could split (core codec+SAS first, FFI second) if preferred — low stakes.

## 3. The handshake design (decisions in §5)

### 3.1 The channel + SAS structure (the crux — Q-a)
The merged seal is ONE-WAY (A→B). But a human SAS comparison needs the SAME code on BOTH screens, and the SAS is a function of BOTH pairing pubkeys — so B must learn A's pubkey and A must learn B's. The ZRTP-class flow:

1. **B → A (QR #1):** B displays a pairing payload `(B.device_id, B.x25519_pairing_pub, B.signer, freshness_nonce)`. A scans it.
2. **A → B (QR #2 / short code):** A displays its own pairing payload `(A.x25519_pairing_pub, …, same freshness_nonce)`. B scans / enters it.
3. **Both compute** `SAS = derive_sas(A.pub, B.pub, nonce)` (canonical pubkey ordering ⇒ identical on both) and DISPLAY it.
4. **Humans compare** the two SAS codes. Match ⇒ both confirm; mismatch ⇒ ABORT (a MITM that swapped a pubkey yields different codes — the L2 anti-MITM property).
5. **Only after confirmation:** A broadcasts `addDevice` (manager-signed, #106c) + `seal_vdk_to_new_device` → the `SealedVdkForDevice` travels A→B (over the now-SAS-authenticated channel).
6. **B** `open_vdk_for_new_device` (the seal is cryptographically bound to B's `device_id`+pubkey — belt-and-suspenders: even a skipped SAS can't let anyone but the real B open it) → `wrap_vdk_for_device` + persist + `record_device_directory_entry`.

So #106e-2's transport is a **two-message pubkey exchange (B→A, A→B) gating a one-way seal (A→B)**. The SAS comparison must precede the on-chain `addDevice` + the seal (so A never authorizes/seals to an attacker). Q-a confirms this structure + whether the SAS check is a MANDATORY gate (block addDevice/seal until confirmed) vs advisory (seal-binding alone protects the VDK).

### 3.2 The FFI entry points (mirror #106e-1 / #100 — thin, session-gated)
- **New-device role:** `pairing_begin_new_device(handle) -> FfiPairingPayload{bytes, device_id, schema_version}` (derive B's keys engine-side, return the non-secret payload to render as QR #1); `pairing_open_and_join(handle, sealed_vdk_bytes, vault_id, device_id, epoch) -> ()` (open the seal engine-side, wrap+persist; VDK never crosses out).
- **Existing-device (manager) role:** `pairing_ingest_new_device(payload_bytes) -> FfiDecodedPairing{device_id, signer, x25519_pairing_pub}` (decode QR #1, pure); `pairing_local_payload(handle) -> FfiPairingPayload` (A's own payload for QR #2); `pairing_derive_sas(payload_a, payload_b) -> String` (pure SAS, no handle); `vault_add_device(handle, rpc_url, deployment_path, decoded_pairing) -> FfiSealedVdk{bytes}` (engine reads live deviceNonce + signs AddDevice + broadcasts + seals VDK → returns the sealed envelope bytes for transport to B; async via block_on_local).
- All session-gated (`lock_vault().as_mut()?`); the X25519 pairing secret + VDK never cross; payload/SAS/sealed-envelope are non-secret.

## 4. L-invariants (proposed)
- **L1 (zero secret crosses).** The X25519 pairing SECRET, the VDK, the password never cross the FFI as readable bytes. The QR payload (pubkeys/ids/signer/nonce), the SAS string, and the `SealedVdkForDevice` bytes are all NON-secret. `grep -ci uniffi` on core/crypto stays 0.
- **L2 (SAS defeats MITM — the net-new security property; LOAD-BEARING).** A MITM that swaps a pairing pubkey produces a DIFFERENT SAS on the two devices; the human comparison surfaces it. A transport test asserts: tamper a pubkey ⇒ `derive_sas` output differs (turns the gate RED if the SAS stops binding both pubkeys). Belt-and-suspenders: the VDK seal is bound to the real recipient `device_id`+pubkey, so a swapped pubkey cannot open the seal regardless of the SAS.
- **L3 (SAS canonical-symmetric).** `derive_sas` orders the two pubkeys canonically (e.g. lexicographic) so both devices compute the IDENTICAL code regardless of which is A/B; tested.
- **L4 (zero-serde fixed-layout, version-gated).** The payload codec is fixed-offset, length-checked, rejects unknown `schema_version` / wrong length — no serde, no parser ambiguity (the #103/byte-identity discipline).
- **L5 (replay/freshness).** The freshness nonce + the on-chain per-vault `deviceNonce` (already enforced by the contract, #106a/#106c) prevent replay of a stale pairing/addDevice. Confirm the nonce's origin + lifetime (Q-c).
- **L6 (thin / no new deps; forbid(unsafe); AGPL; testnet-only/D-011).** SAS = a hash over existing primitives (no new crate). FFI mirrors #106e-1. The whole surface stays Base-Sepolia-only until D-011.
- **L7 (§16 ledger + its own #106b-style adversarial audit).**

## 5. Open decisions for Kelvin (Q-a … Q-f)

- **Q-a (THE MAIN ONE) — the channel structure + SAS gate.** **Recommend: a two-message pubkey exchange (B→A via QR, A→B via a 2nd QR / short code) → both compute + display the SAS → humans compare → ONLY THEN A does `addDevice` + seals the VDK** (so A never authorizes/seals to an attacker). The SAS check is a MANDATORY gate; the seal-binding is belt-and-suspenders. *Plain English:* to add your new phone you'll scan a code on each device (one each way), both screens then show a short matching number, you eyeball that they match, and only after you confirm does the old phone hand over the keys. Confirm: (i) the two-way scan (vs a one-way QR with no real human MITM check), (ii) the SAS as a hard gate before the on-chain authorize+seal. **Stakes: HIGH (security)** — this is the anti-MITM design of the whole add-device flow.
- **Q-b — SAS format.** **Recommend: a 6–7 digit decimal code** (language-neutral, ZRTP-class, trivial to compare). Alternative: a 4–5 word list (friendlier but needs a wordlist + i18n). *Plain English:* the matching code humans compare — a 6-digit number vs a few words. **Stakes: LOW (UX).**
- **Q-c — the freshness nonce + transport scope.** **Recommend: B generates a random freshness nonce in QR #1; the Rust layer produces/consumes payload BYTES + derives the SAS only — the HOST moves the bytes (QR render/scan, app-to-app, or a relay); #106e-2 does NOT build a network relay.** *Plain English:* we make the data and the safety-check; the app draws/scans the QR and ferries the bytes — we don't run a server. **Stakes: LOW-MEDIUM (scope boundary).**
- **Q-d — sign the pairing payload with B's device key (Ed25519)?** B's `device_id` IS its Ed25519 verifying key, so B COULD sign its payload, letting A verify the `(device_id, pairing_pub, signer)` triple is self-consistent before authorizing. **Recommend: DEFER (do not add).** It does NOT replace the SAS (an attacker self-signs its OWN consistent triple and presents it as B; only the human SAS comparison anchors "A is talking to the real B"), and the seal-binding already prevents anyone but the holder of the matching pairing secret from opening the VDK. The signature would add surface for marginal gain. *Plain English:* we could have the new phone cryptographically sign its own intro, but it doesn't stop the attack that matters (an attacker signing their own fake intro), and the human code-compare already covers it — so skip it. **Stakes: LOW (hardening; recommend out).**
- **Q-e — split #106e-2?** **Recommend: ONE slice** (codec + SAS + FFI), SAS gets focused audit. **Stakes: LOW (process).**
- **Q-f — where the code lives.** **Recommend: codec in `pangolin-core::pairing_transport` (pure, no chain), SAS in `pangolin-crypto` (a domain-separated hash), FFI in `pangolin-ffi::pairing`.** **Stakes: LOW.**

## 6. Places that need care (flagged)
- **The SAS symmetry (Q-a/L3)** — both devices MUST compute the identical code; canonical pubkey ordering + a shared nonce is the mechanism. A role-dependent ordering bug = no human check.
- **Ordering of addDevice+seal vs SAS (Q-a)** — the on-chain authorize + the VDK seal MUST come after SAS confirmation, or A authorizes/seals to a possible attacker before the human check.
- **Freshness/replay (L5)** — the nonce's lifetime + binding to the on-chain deviceNonce; a stale pairing payload must not re-authorize.
- **This is the END of the #106 multi-device epic** — after #106e-2, multi-device (contract + crypto + rotation + device-add + V2 data-plane + revocation + recovery + onboarding + FFI + pairing transport) is complete end-to-end. Remaining project item: the standalone #107 V1-read-topic bug.
