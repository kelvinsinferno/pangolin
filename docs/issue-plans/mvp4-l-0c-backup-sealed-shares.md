<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# MVP-4-L (L-0c) — Backup envelope carries sealed_shares — plan-gate DRAFT

**Status: LOCKED — Kelvin sign-off 2026-05-31.** Q-a = **Option 1** (hard reject v1 with typed `UnsupportedVersion`). Q-b = **Option 1** (per-guardian opaque `Vec<u8>` mirroring the existing `wrapped_recovery` carry). Parent plan-gates: [mvp4-l-recovery-ux.md](mvp4-l-recovery-ux.md) (L-0 gap-fill row — this is the third engine prereq slice alongside L-0b and L-0a-1/2) + [mvp4-l-share-transport-design.md](mvp4-l-share-transport-design.md) (the locked Decision-B anti-redirect design). L-0c is the missing piece that closes the cross-device recovery loop: the recoverer needs the M sealed shares to send each guardian their share alongside the request blob — but the existing `BackupContents` (#109) deliberately deferred that field (composition.rs:286 — "The backup FORMAT itself stays deferred (#106e Q-g)").

> **This slice builds ONLY:** `BackupContents` (the CBOR plaintext inside the AEAD-sealed backup envelope) gains `sealed_shares: Vec<Vec<u8>>` (one per guardian, ordered by index 0..M-1). Schema version bumps 1 → 2. `Vault::create_recovery_backup` populates from the existing `read_recovery_escrow` read (which already has the sealed_share bytes engine-side). `vault_decode_backup` surfaces them through `FfiBackupContents.sealed_shares`. Tests pin the new field round-trips + v1 envelopes are rejected with a clear "recreate the backup under the current Pangolin version" message. NO UX, NO new crypto, NO contract change.

---

## 0. One-paragraph summary

`BackupContents` (`crates/pangolin-store/src/recovery_backup.rs:285`) currently carries `wrapped_recovery + vault_id + epoch + threshold + guardian_count + guardian_x25519_pubs + metadata` — but NOT the M sealed-share ciphertexts that were sealed at L-A onboarding to each guardian's pubkey. The sealed shares live only in the OWNER's local `recovery_escrow` table (`crates/pangolin-store/src/recovery_escrow.rs`, accessed via `read_recovery_escrow`). When the owner loses every device, those shares are gone. The L-C wizard I just built takes `sealed_share` as a per-request input — the recoverer is supposed to send each guardian their share alongside the request blob — but the recoverer has no way to get them. L-0c fills the gap by including the sealed_shares in the backup envelope: `Vault::create_recovery_backup` reads them from the live escrow (the bytes are already there at backup time) and the backup wire format carries them through the AEAD-sealed CBOR body. The recoverer decodes the envelope (under the 24-word phrase) and now has all M shares to distribute. L-C wizard works unchanged.

---

## 1. Scope (build + test)

### What ships
- `BackupContents.sealed_shares: Vec<Vec<u8>>` — one per guardian, ordered by index (parity with `guardian_x25519_pubs[i]` ↔ `sealed_shares[i]`). Each entry is the canonical wire form of `pangolin_crypto::escrow::SealedShare` (already opaque + length-strict at the crypto layer).
- `recovery_backup` wire format **schema_version = 2**. The CBOR plaintext body grows by one map entry. The OUTER envelope shape (DOMAIN + KDF + AEAD + integrity-hash) is unchanged.
- `Vault::create_recovery_backup` populates `sealed_shares` from `escrow.guardians[i].sealed_share.as_bytes().to_vec()`. The escrow read is already there (currently only `guardian_x25519_pub` is consumed; this slice extends the same loop).
- Decoder rejects schema_version 1 with a typed `BackupError::UnsupportedVersion` carrying a clear "recreate the backup under the current Pangolin version" message. (Recovery is testnet-only — no production v1 backups exist; clean break is safer than dual-path.)
- `FfiBackupContents.sealed_shares: Vec<Vec<u8>>` field surfaces the bytes to the host. L-B's recoverer wizard will read this; nothing else consumes it.
- Tests: golden round-trip with M=3 + M=15; v1 envelope rejected with the typed error; AAD tamper still fails-closed at AEAD open; new field present in the CBOR plaintext at the expected map key.

### What does NOT ship
- Any UX (that is L-B).
- Any change to `vault_recover_from_backup` (it already consumes opened_shares not sealed_shares; the new field flows through `FfiBackupContents` → L-B wizard → per-guardian request blobs → L-C wizard's existing input).
- Backward-compat v1 decoder (clean break; no production state to migrate).
- Schema-3 forward-compat scaffolding (one bump at a time; v3 would be its own plan).
- Any change to `SealedShare` shape itself (the bytes are passed through opaque from the engine's POV).

---

## 2. Decisions to resolve (each: pick ONE)

### Q-a — v1 backwards compatibility
1. **Hard reject v1** with `BackupError::UnsupportedVersion` (recommended). Clean break; no production v1 backups exist (recovery is testnet-only, gated behind D-011 for mainnet). One code path; one test surface.
2. **Dual-decode**: v1 envelopes decode to a `BackupContents` with `sealed_shares = vec![]`. The recoverer wizard then refuses (no shares → can't proceed). Two code paths; more test surface; no real user value since v1 backups can't recover cross-device anyway.

**Recommend Option 1 (hard reject).** No real cost to the user (they just re-run the backup-create flow, which they should do periodically anyway); much smaller test surface; explicit failure better than implicit "you have a backup but can't recover with it."

### Q-b — sealed_share wire shape inside the CBOR body
1. **Per-guardian opaque `Vec<u8>`** (recommended). The CBOR body has `sealed_shares: [bytes, bytes, ...]` with M opaque byte strings. Mirrors how `wrapped_recovery` is carried (opaque to recovery_backup.rs per its own comment). Forward-compat: if `SealedShare` internal shape ever changes, the backup envelope stays at schema 2 — only the cipher-level format moves.
2. **Tagged-and-typed** — explicit `{schema_version, length, ciphertext}` per share. More verbose, no real validation benefit (the engine already validates length-strict + AEAD-authenticates on open).

**Recommend Option 1 (opaque Vec<u8>).** Matches the existing `wrapped_recovery` pattern. Simpler. The downstream open path already rejects mis-shaped blobs via `SealedShare::from_bytes` length checks.

---

## 3. Files

### Edited
- `crates/pangolin-store/src/recovery_backup.rs` — `BackupContents` gains `sealed_shares`; `SCHEMA_VERSION = 2`; CBOR encoder + decoder paths add the new map entry; the v1-reject path returns the typed `UnsupportedVersion`. Update the wire-format docblock (§3.2). Round-trip tests + the v1 rejection test.
- `crates/pangolin-store/src/vault.rs` — `create_recovery_backup` populates `sealed_shares` from `escrow.guardians[i].sealed_share.as_bytes().to_vec()`. Already iterates `escrow.guardians`; just add a parallel collect.
- `crates/pangolin-ffi/src/recovery_backup.rs` — `FfiBackupContents` gains `sealed_shares: Vec<Vec<u8>>`; `into_ffi_contents` projects.

### New
- (None — no new files needed.)

### Untouched (verify, then leave alone)
- All UX layers (L-B will consume this in the next slice).
- L-C wizard surface (its request blob already accepts `sealed_share`; this slice supplies the missing data path TO the recoverer).
- All chain bindings + contracts.

---

## 4. L-invariants

- **L1 (no NEW secret crosses).** `sealed_share` bytes are **non-secret** — they are AEAD-sealed ciphertexts that only the matching guardian's X25519 secret can open. They cross the FFI as plain `Vec<u8>` just like `wrapped_recovery` already does. The 24-word seed phrase remains the wrap authority for the OUTER envelope.
- **L2 (no new atomic surface).** `create_recovery_backup` already reads + builds the envelope in one pass; we just add one field to the build.
- **L3 (fail-closed).** v1 envelope → typed `UnsupportedVersion`. Tampered ciphertext → AEAD open fails the same way it does today. Length-mismatch on any sealed_share → caller's `SealedShare::from_bytes` rejects.
- **L4 (Active-gated where applicable).** `create_recovery_backup` stays Active-gated; `vault_decode_backup` stays pure (no handle).
- **L5 (round-trip).** A backup created at schema 2 must round-trip through decode unchanged (golden vector test). The HEAVIEST load-bearing check.
- **L6.** `forbid(unsafe)`; AGPL+SPDX; no new external crates (CBOR encoder + AEAD primitives are already in workspace).

---

## 5. Adversarial-audit focus

- **Ordering invariant** — `sealed_shares[i]` must correspond to `guardian_x25519_pubs[i]`. If the order drifts between L-A's recovery_escrow write order and the L-0c backup-build read order, the recoverer would send each guardian the wrong share + every release would fail authentication (correctly fail-closed, but a UX disaster). Verify: `read_recovery_escrow` returns guardians in a stable order, and `create_recovery_backup` consumes that exact order for BOTH x25519_pubs (existing) and sealed_shares (new). A golden test with M=3 distinct guardians + asserting `sealed_shares[i]` opens under `guardian_x25519_pubs[i]`'s matching secret would pin this.
- **Wire-format growth** — the envelope adds M × ~80B (a SealedShare ciphertext is ~80 bytes). At M=15 (the cap) the envelope grows by ~1.2 KB. Still well inside reasonable copy-paste / QR limits. Verify the bound is reasonable + documented.
- **v1 rejection clarity** — the error message must tell the user what to do ("This backup was created under an older Pangolin format; create a fresh backup with the current version"). Not opaque "UnsupportedVersion".
- **CBOR field ordering** — CBOR maps are unordered but the encoder must produce DETERMINISTIC output for a given input (so the AEAD-AAD over the outer header is stable). Verify the encoder uses a canonical key order.
- **Test isolation** — the existing `recovery_backup.rs` tests probably include golden byte vectors that pin the v1 wire shape. Those tests must EITHER be regenerated for v2 OR explicitly mark themselves as "v1 negative tests" (now they test the rejection path).
- **L-C downstream consistency** — verify the bytes a recoverer would extract via `FfiBackupContents.sealed_shares[i]` match exactly what the L-C wizard expects in `recovery_help_release`'s `sealed_share` parameter (= what was originally stored in `escrow.guardians[i].sealed_share`).
- **Empty / edge cases** — M=3 (min) + M=15 (max). What if M=0 (impossible per the contract bounds, but the decoder shouldn't panic)? An empty `sealed_shares` vec from a malformed-but-AEAD-passing envelope should fail closed at recovery time (the contract bounds catch it earlier, but defense-in-depth).

---

## 6. Gate (pre-merge, all green required)

1. `cargo +nightly fmt --all -- --check`
2. `cargo clippy --workspace --all-targets -- -D warnings`
3. `cargo test --workspace` (the recovery_backup tests run here; also workspace meta-tests)
4. `forge fmt --check` (defense — no contract change)
5. `forge test` (defense)
6. `pnpm --filter @pangolin/desktop typecheck` (FfiBackupContents shape may flow to TS via uniffi-generated bindings)
7. `pnpm --filter @pangolin/desktop lint`
8. `pnpm --filter @pangolin/desktop test` (vitest)

---

## 7. Branch + merge

- Branch: `mvp4-l-0c-backup-sealed-shares` off `main` (currently `7b639b0`).
- Per-commit granularity: single logical commit (one engine slice; the change is concentrated in 3 files). Audit-fix may add a second.
- Merge via `git merge --no-ff` per `pangolin_merge_workflow.md` §16 + push immediately.
- Watch CI proactively per `feedback_ci_proactive_recovery.md`.

---

## 8. Recommendation

Lock the two decisions per the recommendations above (Q-a = Option 1 hard-reject v1, Q-b = Option 1 opaque Vec<u8>), put L-0c on `mvp4-l-0c-backup-sealed-shares`, ship it as a small focused engine PR. Should be ~30 minutes of editing + tests + audit. L-B unblocks immediately after L-0c merges + is then a thin UX slice over the now-complete FFI surface (decode → has all M shares → assemble M request blobs → run the L-C handshake from the recoverer side).
