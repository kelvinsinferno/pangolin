<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Recovery opened-share cross-device transport (G-1) — crypto design plan-gate

**Status: LOCKED — Kelvin sign-off 2026-05-29.** Decision A = **ephemeral per-attempt recipient key**;
Decision B = **on-chain commitment (the strongest anti-redirect control → a RecoveryV2 contract change).** This
is the dedicated crypto-design cycle promised by MVP-4-L Q-b: the opened-share cross-device transport (G-1) is
the single audit-critical crux that gates the entire guardian recovery UX (slices L-A / L-C / L-B). This gate
**LOCKS the design + both decisions**; the *build* (a RecoveryV2 contract change + a new `pangolin-crypto`
primitive + the FFI delta + the L-0 engine slice) follows as a separate §16 build cycle. **Net-new crypto on the
most external-audit-critical surface in the product. Testnet-only; the whole recovery system stays on Base
Sepolia until D-011 clears — so a pre-D-011 contract change is correctly-timed (no mainnet state to migrate).**

> **What this gate decides:** *how a guardian's opened share physically travels from the guardian's device to
> the recovering user's device, without a readable share ever crossing a channel an attacker could intercept, and
> without weakening the t-of-M threshold.* It does NOT build UX (that's L-A/L-C/L-B). It DOES change the recovery
> lifecycle contract (RecoveryV1 → RecoveryV2) to commit the recipient key on-chain (Decision B).

---

## 0. The problem (G-1 recap), in plain English

Recovery works like this: at onboarding, a single secret "recovery wrap key" (**RWK** — the key that ultimately
unlocks the vault data key without the password) is mathematically split into M pieces ("shares") using Shamir
secret-sharing. Any **t** of the M pieces, combined, rebuild the RWK; fewer than t reveal *literally nothing*
(this is the information-theoretic property the whole design rests on). Each piece is sealed (encrypted) to one
guardian and stored on their device.

To recover, the user needs t guardians to each (a) approve on-chain and (b) hand over their piece. Today step (b)
**only works if everyone is in the same process** — the opened (decrypted) piece is an opaque in-memory object
(`FfiOpenedShare`) with no serializer, deliberately, so a readable share never crosses the FFI boundary. In every
test, the guardian-open and the reconstruct happen on one machine. **Real recovery has the guardian on device X
and the recovering user on device Y, and there is no path to move the piece between them.**

The naive fix — "add a `to_bytes()` to the opened share and send it" — is exactly what we must NOT do: the
opened piece *is* a secret, and t of them rebuild the RWK. Putting t cleartext pieces on any channel (QR, file,
chat, relay) means an eavesdropper who collects t of them reconstructs the vault. So the transport has to move
the piece in **sealed** (encrypted-to-the-recipient) form, never cleartext.

**Good news:** the codebase already solved a structurally identical problem. Device pairing re-seals the vault
data key to a *new device's* public key (`pairing::seal_vdk_to_device` → `SealedVdkForDevice`, a non-secret blob
that ships over the existing text/QR codec). The share transport is the same shape: **re-seal the opened piece to
the recovering user's public key.** We reuse that proven, Cure53-audited `crypto_box` sealed-box pattern.

---

## 1. The chosen scheme — re-seal to the recoverer (and why the alternative is rejected)

**SCHEME (locked design foundation, not a fork):** *open-and-re-seal.* On the guardian's device, in ONE engine
call that never exposes the cleartext piece to the host:

1. open the guardian's stored sealed share with the guardian's own derived X25519 secret → cleartext piece (in
   the engine, never crossing the FFI);
2. immediately **re-seal** that piece to the **recovering user's** X25519 public key, producing a new sealed
   blob (`SealedShareForRecoverer`) — non-secret at rest, like `SealedVdkForDevice`;
3. emit only that sealed blob over the FFI. The cleartext piece is zeroized; the host never holds it.

On the recovering user's device: ingest t such blobs, unseal each locally with the recovering user's X25519
secret → t cleartext pieces (in the engine), reconstruct the RWK, unwrap the VDK, re-secure under the new
password, and (forward security) re-split a fresh RWK to all M guardians. Reconstruction needs **only the 33
share bytes** per piece (the share's x-coordinate is embedded in byte 0) — no guardian identity has to travel.

**Why not the alternative ("recoverer holds the sealed shares; guardians release an unseal capability"):**
the shares stored at onboarding are sealed to each *guardian's* key, so the recoverer cannot open them. For the
recoverer to use them, a guardian would have to either (i) hand over their long-term X25519 secret — catastrophic:
it's reusable, opens *every* share for *every* epoch, and t such secrets let a collector reconstruct unilaterally
forever (far worse than the t-collusion bound); or (ii) run an interactive proxy/oblivious-decryption protocol —
heavy net-new crypto with no vetted library in our stack. The re-seal scheme avoids both, reuses an existing
primitive, and keeps every secret ephemeral. **Rejected.**

### Data flow

```text
GUARDIAN device X                          RECOVERING USER device Y
─────────────────                          ────────────────────────
stored SealedShare (sealed to guardian)
        │  open (engine, guardian X25519 secret)
        ▼
   cleartext piece  ──re-seal to recoverer pubkey (engine)──►  SealedShareForRecoverer (blob, non-secret)
   [zeroized]                                                          │
                                                            ship over text/QR codec (existing)
                                                                       │
                                                                       ▼
                                                     ingest t blobs ─unseal (engine, recoverer secret)─► t pieces
                                                                       │ reconstruct RWK → unwrap VDK
                                                                       │ set new password → re-split fresh RWK to all M
                                                                       ▼
                                                                  recovered vault
```

---

## 2. The new crypto primitive (`pangolin-crypto`)

A new module mirroring `pairing.rs` (which itself mirrors `escrow::seal_share`). Sketch signatures:

```rust
/// Re-seals an already-opened Shamir piece to the recovering user's X25519 public key.
/// Distinct DOMAIN from escrow/pairing seals (the codebase pins all domain strings distinct).
pub fn seal_share_to_recoverer(
    piece: &Share,                                   // 33-byte cleartext piece (engine-only)
    recoverer_x25519_pub: &[u8; X25519_KEY_LEN],
    vault_id: &[u8; VAULT_ID_LEN],
    attempt_nonce: u64,                              // freshness — see §3/Decision E
    share_identifier: u8,                            // share x-coord, for dedup/ordering (non-secret)
) -> Result<SealedShareForRecoverer, EscrowError>;

pub fn open_share_from_recoverer(
    sealed: &SealedShareForRecoverer,
    recoverer_x25519_secret: &[u8; X25519_KEY_LEN],
    vault_id: &[u8; VAULT_ID_LEN],
    attempt_nonce: u64,
) -> Result<Share, EscrowError>;
```

- **Primitive:** `crypto_box` anonymous sealed box (X25519 → XSalsa20-Poly1305) — identical to `seal_share` /
  `seal_vdk_to_device`. Sealed boxes have no associated-data channel, so the context is authenticated *inside*
  the plaintext header: `DOMAIN(b"pangolin-recovery-share-transport-v0") || vault_id || attempt_nonce ||
  recoverer_x25519_pub || share_identifier || piece_bytes`. Binding `recoverer_x25519_pub` into the header means
  a blob sealed to one recipient cannot be silently re-pointed; binding `attempt_nonce` prevents cross-attempt
  replay (see §3).
- **New domain string required** (a hard test pins all domains distinct: `pairing_transport.rs:687`).
- `SealedShareForRecoverer` is shaped exactly like `SealedShare` / `SealedVdkForDevice` — `from_bytes`/`as_bytes`,
  `#[derive(Clone)]`, non-secret at rest (the piece inside is sealed). It ships over the **existing**
  `encode_text_with_checksum` / `decode_text_with_checksum` codec (`pairing_transport.rs:457`) — same text/QR
  affordance the pairing UX already uses; no new transport infra.

---

## 3. Threat model + invariants the design must hold

The attacker may: eavesdrop the transport channel (capture any number of sealed blobs); collude with up to
**t − 1** guardians; attempt a man-in-the-middle on the *recipient identity* (trick guardians into sealing to the
attacker's key); and replay a captured blob into a later attempt.

| # | Property | How the design holds it |
|---|---|---|
| **L1** | No cleartext piece ever crosses the FFI / a channel | Guardian side: open-and-re-seal in ONE engine call; the host receives only the sealed blob (mirrors `FfiOpenedShare` exposing only `byte_length()`). Recoverer side: unseal happens in-engine; pieces never surface to the host. Only sealed blobs cross — exactly the codebase's sealed-vs-opened discipline. |
| **< t reveals nothing, *under transport*** | Capturing < t blobs, even with the recoverer's secret, rebuilds nothing | Shamir's information-theoretic floor is preserved because the blobs decrypt to the *same* pieces as today; transport changes only the envelope, not the sharing. **Audit must re-verify the floor survives the new envelope.** |
| **Recipient key = quorum SPOF** | t blobs + the recoverer's X25519 secret = full reconstruction | This is inherent (the recoverer must be able to assemble the quorum). Decision A (recipient-key lifetime) bounds the blast radius: an *ephemeral per-attempt* key means captured blobs are useless once the attempt's key is zeroized. |
| **Anti-redirect** | Guardians must seal to the *legitimate* recoverer, not an attacker's key | **Decision B = on-chain:** the recoverer's (ephemeral) X25519 pubkey is committed in the on-chain recovery attempt, and each guardian's on-chain Approve signs over that commitment (RecoveryV2). The guardian's client refuses to release a share unless the recipient key it's sealing to matches the on-chain commitment — so an attacker cannot redirect shares without controlling the on-chain attempt itself. Strongest available binding. |
| **L2 (human gate)** | A short out-of-band check backs the recipient identity | The recoverer's pubkey/attestation surfaces as a short-authentication-string (SAS) / QR the guardian confirms — same posture as pairing. Defense-in-depth atop the on-chain commitment. |
| **Anti-replay** | A blob from a cancelled attempt can't be reused in a new one | Header binds `attempt_nonce` (Decision E). Note the escrow `epoch` is *independent* of `attempt_nonce`, so binding the nonce (not just the epoch) is what closes cross-attempt replay. |
| **L3 (fail-closed)** | Any open/verify/binding failure aborts, leaks nothing | All failures collapse to an undifferentiated error (existing `EscrowError::OpenFailed` posture); no oracle on which guardian/blob failed. |
| **Forward security unchanged** | A used quorum is fully retired | Untouched: `recover_from_shares` still re-splits a FRESH RWK to all M after reconstruction. Transport doesn't alter this. |

---

## 4. FFI surface delta (built in the follow-up L-0 cycle)

- **Recoverer — ephemeral recipient identity (Decision A) committed on-chain (Decision B):**
  `vault_initiate_recovery` is extended to generate the per-attempt ephemeral X25519 keypair, persist its secret
  sealed-at-rest for the attempt, and **commit its pubkey (or hash) in the on-chain recovery attempt**. A read
  `vault_recovery_recipient_identity(handle) -> FfiRecipientIdentity` surfaces the pubkey + SAS/QR for the L2
  human check. The ephemeral secret is zeroized on `finalize`/`cancel`.
- **Guardian — open-and-re-seal (replaces the host-held opened share for cross-device):**
  `vault_guardian_release_share(handle, sealed_share, vault_id, attempt_nonce, recoverer_identity) ->
  Vec<u8>` (the `SealedShareForRecoverer` blob, text/QR-encodable). **Verifies the recipient key equals the
  on-chain `recipientCommitment` the guardians approved (Decision B) before sealing.** The existing in-process
  `vault_guardian_open_share` → `FfiOpenedShare` path stays for same-device/test flows; the cross-device path
  never materializes a host-held opened share.
- **Recoverer — ingest:** `vault_recovery_ingest_share(handle, blob) -> FfiIngestOutcome` (unseal in-engine,
  hold toward the quorum; report progress "k of t"). Then `vault_recover_from_shares` / `_from_backup` consume
  the in-engine pieces as today.
- All new opaque/secret state stays engine-side; only sealed blobs + non-secret progress cross the FFI.

---

## 5. DECISIONS — RESOLVED (Kelvin sign-off 2026-05-29)

- **Decision A = ephemeral per-attempt recipient key.** The recovering device generates a fresh X25519 keypair
  *for this recovery attempt only*. Rationale: transport forward-secrecy — once the attempt closes
  (finalize/cancel), the secret is zeroized and any blobs an eavesdropper captured become permanently
  undecryptable; it never concentrates the whole quorum on a reusable, long-lived key. Matches the product's
  rotate-everything posture (VDK on every removal; fresh RWK on every recovery).
  - **Lifetime nuance (build note):** a recovery attempt spans the 72h delay (initiate → approvals + shares →
    72h → finalize), so the ephemeral secret must *persist at rest for the attempt's duration* on the recovering
    device — sealed under that device's own vault/password (the recovering device is Active under its new
    password during the attempt) — and be zeroized on finalize/cancel. It is "ephemeral per-attempt," not
    "in-memory only."

- **Decision B = on-chain commitment (RecoveryV2 contract change) — the strongest anti-redirect control.**
  The recovering device's ephemeral X25519 pubkey (or its hash) is committed in the on-chain recovery attempt at
  `initiate` time, and the guardian's on-chain Approve EIP-712 signs over that commitment (extend
  `ApproveFieldsV1` → V2). A guardian's client releases a share only after verifying the recipient key it is
  sealing to equals the on-chain commitment the guardians approved — so shares cannot be redirected to an
  attacker's key without the attacker controlling the on-chain attempt itself. Kelvin chose this over the
  cheaper off-chain signed-attestation option: for the single most audit-critical surface, the cryptographic
  on-chain binding is worth a contract change. **Correctly timed:** recovery is testnet-only until D-011, so
  there is no mainnet state to migrate, and the RecoveryV2 surface simply becomes part of the (not-yet-started)
  D-011 contract audit scope rather than re-opening a cleared one.
  - **Build implications:** RecoveryV2 contract (add a `recipientCommitment` field to the live attempt; Approve
    typehash gains the commitment field); the #103 recovery chain-client `initiate`/`approve` calldata + signing
    extended; the in-house contract tests + anvil E2E updated. The §2 in-header `recoverer_x25519_pub` binding
    stays as defense-in-depth atop the authoritative on-chain commitment.

### Self-resolved engineering choices (one coherent answer; folded into the design, not gated)

### Self-resolved engineering choices (one coherent answer; folded into the design, not gated)

- **C — scheme = re-seal** (§1); the alternative is cryptographically worse. Locked.
- **D — channel = the existing text/QR codec** (`encode_text_with_checksum`); the blob is non-secret and the
  codec already serves the pairing/SealedVdk envelope. A relay/cloud inbox is out of scope for testnet.
- **E — freshness = bind `attempt_nonce` in the seal header** (not just the escrow epoch), closing cross-attempt
  replay; new distinct domain string.
- **F — FFI shape = open-and-re-seal in one engine call**; never expose a host-held opened share on the
  cross-device path (the safest option the research surfaced); keep the in-process `FfiOpenedShare` path for
  same-device/tests.

---

## 6. In-house adversarial-audit bar (the ONLY review before testnet)

This piece gets a dedicated, exceptionally-rigorous in-house audit (per the recovery-model constraint — no
external pre-opinion affordable). The audit must verify, at minimum:

1. **< t still reveals nothing under the new envelope** — capturing t−1 blobs (+ the recoverer secret) rebuilds
   nothing; the Shamir floor is unaffected by re-sealing.
2. **No cleartext piece escapes** — neither FFI surface (guardian release, recoverer ingest) exposes a readable
   piece; the host-held `FfiOpenedShare` is *not* reachable on the cross-device path; pieces are zeroized.
3. **The binding can't be bypassed** — a blob sealed to recipient X cannot be opened by, or silently re-pointed
   to, recipient Y (recipient pubkey in the authenticated header); the guardian client provably refuses to seal
   to any key that does not match the on-chain `recipientCommitment` (Decision B); the RecoveryV2 Approve
   typehash actually covers the commitment and old V1 approvals cannot be replayed against a V2 attempt.
4. **Anti-replay** — a blob from attempt N fails to open under attempt N+1 (nonce in header).
5. **Fail-closed + no oracle** — every failure is undifferentiated; nothing reveals which guardian/blob failed.
6. **Domain separation** — the new domain string is distinct from escrow/pairing; no cross-protocol confusion.
7. **Forward security intact** — reconstruction still triggers the all-M re-split; transport changes nothing here.
8. **Zero-serde on the secret path** — the cleartext `Share` still has no serializer reachable from the host.

---

## 7. Scope / sequencing

- **This gate:** LOCK the design + Decisions A (ephemeral key) and B (on-chain commitment). No code lands here.
- **Follow-up build cycle (the L-0 engine slice, its own §16 plan-gate):** in build order —
  (1) **RecoveryV2 contract** (add `recipientCommitment` to the live attempt; Approve typehash → V2) + redeploy
  to Base Sepolia; (2) the **#103 chain-client** `initiate`/`approve` calldata + EIP-712 signing extended;
  (3) the new **`pangolin-crypto`** re-seal primitive (§2); (4) the **FFI delta** (§4) incl. ephemeral-key
  generation + on-chain commitment + the guardian commitment-check; (5) anvil/in-house tests. Then the in-house
  adversarial audit (§6).
- **Then** the guardian UX slices unblock in order: L-C (guardian-side release) → L-A (onboarding, needs G-2) →
  L-B (recovery wizard, needs G-3 reads + everything above).
- **Hard gate:** mainnet recovery stays blocked behind the D-011 external audit; the entire recovery system —
  now including RecoveryV2 — is testnet-only (Base Sepolia) until then. The RecoveryV2 surface joins the D-011
  contract audit scope (it is not yet started, so this re-opens nothing).

---

## 8. Outcome

Locked: the **re-seal scheme** (§1), **Decision A = ephemeral per-attempt key**, **Decision B = on-chain
commitment (RecoveryV2)**. Together they give transport forward-secrecy *and* the strongest available
anti-redirect binding (a guardian provably seals only to the key the chain says was approved). The cost is a
RecoveryV2 contract change — accepted deliberately for the most audit-critical surface, and correctly timed
since recovery is pre-D-011 testnet-only (no mainnet state to migrate; RecoveryV2 just joins the not-yet-started
D-011 contract scope). The follow-up build (RecoveryV2 → chain-client → re-seal primitive → FFI → in-house
audit) proceeds as its own §16 cycle; it reuses the already-vetted `crypto_box` sealed-box pattern and the
existing text/QR codec for everything off-chain.
