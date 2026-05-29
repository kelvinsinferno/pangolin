<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# L-0 — recovery engine gap-fill (G-1 transport impl + G-2 + G-3) — build plan-gate DRAFT

**Status: LOCKED — Kelvin sign-off 2026-05-29.** Decision S = **3 slices, primitive-first** (L-0b → L-0a-1 →
L-0a-2); Decision D = **deploy RecoveryV2 to Base Sepolia as part of L-0a-1**. This is the engine build cycle
that implements the three gaps the MVP-4-L decomposition (§0c) found between the built recovery crypto and a real
cross-device guardian recovery — the prerequisite for the guardian UX slices (L-C / L-A / L-B). The G-1 transport
scheme is already designed + LOCKED (`docs/issue-plans/mvp4-l-share-transport-design.md`); this gate plans its
*implementation* plus the two lighter gaps. **Net-new crypto + a contract change on the most
external-audit-critical surface; testnet-only until D-011.**

> **What L-0 builds:** (G-1) the re-seal transport — RecoveryV2 contract (`recipientCommitment` + new Approve
> typehash) + chain-client + the `pangolin-crypto` re-seal primitive + the FFI transport surface; (G-2) a
> guardian-identity export codec + FFI; (G-3) plumb the already-on-chain `approvals`/`initiatedAt` into the FFI
> status. **No UX** (that's L-A/L-C/L-B). Each gap's exact current-state is verified against code in §1.

---

## 0. One-paragraph summary

Recovery's crypto + lifecycle are built and work end-to-end *in one process* on anvil, but three engine gaps
block the real cross-device, multi-party flow: **G-1** — a guardian's opened share has no transport off their
device (the LOCKED design fixes this by re-sealing each share to the recovering user's ephemeral pubkey, with
that pubkey committed on-chain so guardians can't be tricked into sealing to an attacker — Decision B =
RecoveryV2); **G-2** — there's no way to export a guardian's identity (X25519 sealing pubkey + EVM address) as a
shareable invite, so onboarding can't collect guardians; **G-3** — the FFI recovery-status hardcodes
`approval_count`/`initiated_at` to `0`, so the UX can't show "2 of 3 approved" or the 72h countdown. L-0 fills all
three at the engine/FFI/contract layer (no UX), gated by an exceptionally-rigorous in-house adversarial audit
(the only review before testnet — no external pre-opinion affordable).

---

## 1. Current-state facts (verified against code — drives the scope)

### G-1 — transport (the heavy, audit-critical gap)
- Design + both decisions LOCKED in the share-transport plan-gate: **re-seal scheme**; **Decision A = ephemeral
  per-attempt recipient key**; **Decision B = on-chain `recipientCommitment` (RecoveryV2)**.
- The re-seal primitive is **net-new** in `pangolin-crypto` (mirrors `pairing::seal_vdk_to_device`; new distinct
  domain string `b"pangolin-recovery-share-transport-v0"`).
- **RecoveryV1 contract is hard-immutable by design** (`contracts/src/RecoveryV1.sol:29-31` — "No upgrades… a
  bug is fixed by deploying RecoveryV2, NEVER by patching v1"). No proxy/`initialize`; plain `constructor()`.
- **RecoveryV1 has NEVER been deployed to Base Sepolia** — `contracts/deployments/base-sepolia.json` has no
  `RecoveryV1` entry; only `contracts/deployments/dev.json` (anvil) lists it. So **"RecoveryV2" is the FIRST
  recovery deploy to testnet — there are no live vaults to re-bootstrap; no migration.**
- The Approve EIP-712 typehash is duplicated in **THREE** synced places that all gain `recipientCommitment`:
  `RecoveryV1.sol:331-332` (literal), `recovery_signing.rs:68-69` (pinned hex `APPROVE_TYPEHASH_V1` + the manual
  `approve_struct_hash` byte buffer `:185-207`, grow `6*32→7*32`), `contracts/test/RecoveryV1.t.sol:71-72`
  (test literal). CI fails loudly on drift (`approve_typehash_matches_pinned_constant`, `recovery_signing.rs:351`).
- Live-attempt struct on-chain: `struct Recovery { address proposedAuthority; uint64 initiatedAt; uint64
  attemptNonce; uint8 approvals; Status status; }` (`RecoveryV1.sol:131-137`). `recipientCommitment` is a NEW
  field on this struct (written in `initiateRecovery`, read into `_hashApprove`).
- Client surface to extend (`crates/pangolin-chain`): `initiate_recovery_v1` (`recovery_client.rs:425`) gains the
  commitment param; the `sol!` binding (`:91-187`) mirrors the V2 ABI; `ApproveFieldsV1`/`approve_struct_hash`
  (`recovery_signing.rs`) gains the field; the anvil E2Es update.

### G-2 — guardian-identity export (small, independent, NO contract)
- `pangolin_crypto::guardian::derive_x25519_sealing_key(device: &DeviceKey) -> X25519SealingKey`
  (`guardian.rs:170`) is **NOT `#[uniffi::export]`ed** (only used in `#[cfg(test)]`). The on-chain identity is
  `pangolin_chain::evm::derive_evm_wallet(device) -> Result<EvmWallet, _>` (`evm.rs:335`).
- **Template to mirror:** `pairing_transport.rs` `PairingPayload` (`:138-169`) + `encode_string`/`decode_string`
  (base32 + 4-byte checksum, `:312`/`:338`). A new `GuardianInvite` payload carries the guardian's X25519 sealing
  pub + 20-byte EVM addr, new distinct DOMAIN. **Net-new confirmed** (no `guardian_invite`/`GuardianIdentity`
  anywhere outside tests).

### G-3 — status reads (tiny, ~5 lines, NO contract)
- `FfiRecoveryStatus` (`recovery_lifecycle.rs:158-179`) has `initiated_at`/`approval_count` fields, hardcoded to
  `0` at `recovery_lifecycle.rs:724-725` (in `vault_read_recovery_status`).
- The chain `recovery()` RPC **already returns** `initiatedAt` + `approvals`; the client's `LiveAttemptV1`
  (`recovery_client.rs:363-371`) + its mapping (`:479-483`) simply **drop them**. Fix: add two fields to
  `LiveAttemptV1` + two mapping lines + two FFI lines. No new RPC, no contract change.
- **Note the overlap:** the RecoveryV2 work (G-1) already edits `LiveAttemptV1` + the `recovery()` binding (to
  surface `recipientCommitment`). So G-3's two fields land in the SAME edit — G-3 bundles naturally with G-1.

---

## 2. Proposed slicing (the §5 decision sets the final shape)

Recommended **primitive-first** structure (mirrors the #104a/#104b discipline: isolate the catastrophic-if-wrong
crypto core in its own focused build + audit):

| Slice | Scope | Contract? | Depends on | Audit weight |
|---|---|---|---|---|
| **L-0b — guardian-identity export (G-2)** | `GuardianInvite` codec (mirror `PairingPayload`) + `#[uniffi::export]` to produce this device's guardian identity | no | nothing | light |
| **L-0a-1 — RecoveryV2 control plane (G-1 on-chain + G-3)** | RecoveryV2.sol (`recipientCommitment` + V2 Approve typehash, synced ×3) + deploy script + (Decision, §5) the first Base Sepolia deploy + domain-sep pins + `sol!` binding + client (`initiate` gains commitment; V2 Approve digest) + `LiveAttemptV2` (commitment **+ G-3 initiated_at/approvals**) + Solidity tests | **yes (fresh V2 deploy)** | nothing | heavy (contract + typehash + on-chain binding) |
| **L-0a-2 — re-seal transport primitive + FFI (G-1 off-chain)** | `pangolin-crypto` re-seal primitive (`seal_share_to_recoverer`/`open`) + FFI: ephemeral-key gen + persist-sealed-at-rest for the attempt + commitment-on-initiate + `vault_guardian_release_share` (open-and-reseal, verifies commitment) + `vault_recovery_ingest_share` + anvil E2E | no (consumes L-0a-1's commitment) | L-0a-1 | **heaviest** (the §6 transport audit bar — the catastrophic core) |

Each slice = its own §16 cycle (build → in-house audit → `git merge --no-ff` → CI). The §5 fork decides whether
to keep this 3-way split, collapse to 2 (L-0b + a combined L-0a), or 1.

---

## 3. Per-slice build detail

### L-0b — guardian-identity export (G-2)
- **`pangolin-core`** (new, mirror `pairing_transport.rs`): `GuardianInvite { schema_version, x25519_sealing_pub:
  [u8;32], signer: [u8;20] }` + `encode_string`/`decode_string` (new DOMAIN, base32 + 4-byte checksum,
  fail-closed decode). Unit tests: round-trip, wrong-domain, bad-checksum, length.
- **`pangolin-ffi`**: `#[uniffi::export] vault_export_guardian_identity(handle) -> FfiGuardianInvite` (or a
  `String`) — derives `derive_x25519_sealing_key(&active.device_key).public_bytes()` +
  `derive_evm_wallet(&active.device_key).address()` from the active session, encodes. Session-gated; no secret
  crosses (the sealing *public* key + EVM address are both non-secret — same posture as the pairing pubkey).
- **Tests:** FFI test (export → decode → fields match the device's derived keys); the meta no-empty-test gate.

### L-0a-1 — RecoveryV2 control plane (G-1 on-chain + G-3)
- **`contracts/src/RecoveryV2.sol`** (copy of V1; do NOT edit V1 — immutability discipline): add
  `bytes32 recipientCommitment` to `struct Recovery`; `initiateRecovery` gains a `recipientCommitment` param +
  stores it; `APPROVE_TYPEHASH` literal gains `bytes32 recipientCommitment`; `_hashApprove` reads the stored
  commitment into the digest. New `contracts/script/DeployRecoveryV2.s.sol` (near-verbatim copy).
- **`contracts/test/RecoveryV2.t.sol`** (+ invariant): port V1's suite; new cases — commitment stored on
  initiate, Approve digest covers the commitment, a V1-style approval (no commitment) is rejected.
- **`crates/pangolin-chain`**: new `recovery_v2_binding` `sol!` block (mirror V2 ABI); `recovery_signing.rs` —
  `ApproveFieldsV2` (+ `recipient_commitment: [u8;32]`), grow `approve_struct_hash` buffer + re-derive the pinned
  `APPROVE_TYPEHASH_V2` hex (assert-equals test catches drift); `initiate_recovery_v2`(+commitment) calldata;
  `LiveAttemptV2 { proposed_authority, attempt_nonce, status, initiated_at, approvals, recipient_commitment }`
  (this is the G-3 fix + the commitment in one struct) + `read_live_attempt_v2`.
- **`crates/pangolin-ffi`**: `vault_read_recovery_status` → return `live.initiated_at` / `live.approvals`
  (delete the `0` hardcodes); thread the V2 client through the recovery-lifecycle exports.
- **Deploy (Decision §5):** if yes — `forge script DeployRecoveryV2` to Base Sepolia, add the `RecoveryV2` entry
  to `base-sepolia.json` + `dev.json`, add `RECOVERY_DOMAIN_SEPARATOR_BASE_SEPOLIA_V2` +
  `EXPECTED_RECOVERY_ADDRESS_BASE_SEPOLIA` pins + the `deployment_json_pins_match_rust_constants` cross-check
  (resolves the pre-existing `recovery_signing.rs:77-88` TODO).
- **Tests:** the ported Solidity suite; the typehash-pin test; an anvil E2E for initiate-with-commitment +
  approve-over-commitment.

### L-0a-2 — re-seal transport primitive + FFI (G-1 off-chain)
- **`pangolin-crypto`** (new module): `seal_share_to_recoverer` / `open_share_from_recoverer` per the design §2
  (crypto_box sealed box; header binds DOMAIN ‖ vault_id ‖ attempt_nonce ‖ recoverer_x25519_pub ‖
  share_identifier ‖ piece). `SealedShareForRecoverer { from_bytes/as_bytes }`. New distinct domain (pins test).
- **`pangolin-core`/`pangolin-store`**: ephemeral recipient keypair lifecycle — generate at `initiate`, persist
  the secret sealed-at-rest under the recovering device's vault for the attempt duration (spans the 72h delay),
  zeroize on finalize/cancel. Wire `recipientCommitment` = the ephemeral pubkey (or hash) into the L-0a-1
  initiate calldata.
- **`pangolin-ffi`**: `vault_recovery_recipient_identity` (surface the ephemeral pubkey + SAS/QR for the L2 human
  check); `vault_guardian_release_share` (open-and-reseal in ONE engine call — never materialize a host-held
  opened share; verify the recipient key == the on-chain commitment before sealing); `vault_recovery_ingest_share`
  (unseal in-engine toward the quorum; report k-of-t). Keep the in-process `FfiOpenedShare` path for same-device.
- **Tests + anvil E2E:** full cross-"device" recovery against anvil (guardian release → transport blob →
  recoverer ingest → reconstruct → re-split), plus the negative cases the §6 audit pins.

---

## 4. Invariants (must hold across L-0)

- **L1** — no NEW readable secret crosses the FFI: the re-seal happens in-engine (guardian side opens + reseals
  in one call; recoverer unseals in-engine); only sealed blobs + non-secret reads (status, identity, commitment)
  cross. The cleartext `Share` keeps having no host-reachable serializer.
- **L2** — the recipient identity is backed by the on-chain commitment (Decision B) + a SAS/QR human check.
- **L3** — fail-closed on every chain/crypto error; undifferentiated errors (no oracle on which guardian/blob).
- **Forward security** — unchanged: reconstruction still re-splits a fresh RWK to all M.
- **Typehash sync** — the V2 Approve typehash stays byte-identical across Solidity + Rust pinned hex + Solidity
  test (CI-enforced).

---

## 5. DECISIONS — RESOLVED (Kelvin sign-off 2026-05-29)

- **Decision S = 3 slices, primitive-first** (L-0b → L-0a-1 → L-0a-2). The catastrophic-if-wrong crypto core
  (L-0a-2) gets its own isolated, focused in-house audit — the same discipline as the #104a/#104b recovery-crypto
  build. Order: L-0b first (light, independent, good momentum + unblocks onboarding-prep) → L-0a-1 (RecoveryV2
  control plane + G-3) → L-0a-2 (re-seal primitive + FFI transport, depends on L-0a-1's commitment).
- **Decision D = deploy RecoveryV2 to Base Sepolia as part of L-0a-1.** Cheap on testnet; locks the contract
  address + domain-separator pins (resolving the standing `recovery_signing.rs:77-88` TODO — there is currently
  NO Base Sepolia recovery deploy at all); makes L-D's recovery-health panel read a real testnet contract. The
  deploy is an external public-testnet action — when L-0a-1 reaches it, confirm the deploy step before
  broadcasting. Recovery stays testnet-only until D-011 regardless.

---

## 6. In-house adversarial-audit bar

Per the share-transport design §6 (the full transport checklist) PLUS, for L-0a-1: the RecoveryV2 contract
(commitment stored + covered by Approve; V1 approvals can't be replayed against V2; the immutable-no-proxy
posture preserved) and the typehash 3-way sync. For L-0b: the guardian-invite carries only non-secret material
(no DeviceKey/secret leaks via the export). The crypto core (L-0a-2) is the catastrophic-if-wrong piece and gets
the most scrutiny: the < t-reveals-nothing property survives the new envelope; no cleartext share ever leaves the
engine; the commitment binding cannot be bypassed; anti-replay across attempts; domain separation.

---

## 7. Scope / out-of-scope

- **In:** the three engine/FFI/contract gaps (G-1 impl, G-2, G-3). RecoveryV2 contract + (Decision D) its first
  Base Sepolia deploy.
- **Out:** all recovery UX (L-A onboarding, L-C guardian-help, L-B recovery wizard — each its own plan-gate after
  L-0); the share *delivery channel* beyond the existing text/QR codec (no relay/cloud inbox); mainnet (hard-gated
  behind D-011).

---

## 8. Recommendation

Build L-0 **primitive-first in 3 slices** (Decision S): L-0b (guardian identity, light + independent — good first
landing) → L-0a-1 (RecoveryV2 control plane + G-3) → L-0a-2 (re-seal primitive + FFI transport — the catastrophic
core, its own focused in-house audit). **Deploy RecoveryV2 to Base Sepolia as part of L-0a-1** (Decision D) — it's
cheap on testnet, locks the address + domain-separator pins (resolving the standing TODO), and lets L-D's health
panel read a real contract. This keeps the audit-critical crypto isolated for a rigorous review while the lighter
identity/read gaps land independently, and it leaves the recovery system fully testnet-only until D-011.
