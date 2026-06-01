<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# MVP-4-L (L-0d) — Escrow persists guardian EVM signers + backup carries them — plan-gate DRAFT

**Status: LOCKED — Kelvin sign-off 2026-06-01.** Q-a = **Option 1** (hard reject all-zero signer rows with typed `CorruptedRecovery`). Q-b = **Option 1** (paired parallel arrays). Q-c = **Option 1** (hard reject v2 backups with typed `UnknownSchemaVersion(2, 3)`). Parent plan-gates: [mvp4-l-recovery-ux.md](mvp4-l-recovery-ux.md) (L-0 gap-fill row — fourth engine prereq alongside L-0b / L-0a-1/2 / L-0c) + [mvp4-l-0c-backup-sealed-shares.md](mvp4-l-0c-backup-sealed-shares.md) (the immediately-prior structurally-identical slice). L-0d surfaced during L-B drafting on the **same** branch L-0c surfaced from: the recoverer's request blob (consumed by L-C's `recovery_help_approve`) requires the FULL M-address EVM guardian roster to compute the merkle proof, but neither the backup envelope NOR the `recovery_guardians` table currently persists those addresses. The owner DID know them at L-A onboarding time (each `guardian_invite` carries `(x25519_sealing_pub, signer)`); the engine drops the signer at onboarding-write time.

> **This slice builds:** `StoredGuardian` gains `signer: [u8; 20]`; the
> `recovery_guardians` SQLite table gains a `guardian_signer BLOB NOT NULL`
> column (additive migration mirroring `migrate_recovery_recipient_table`);
> `Vault::onboard_guardians` takes paired `(x25519_pubs, signers)` arrays
> with an internal length-equality check; `BackupContents.guardian_evm_addrs:
> Vec<[u8;20]>` joins the existing `guardian_x25519_pubs` + `sealed_shares`
> as the third parallel-by-index field; backup schema bumps 2 → 3 (hard
> reject v2, no production v2 backups exist); `FfiBackupContents.guardian_evm_addrs`
> surfaces. The desktop L-A command + invoke wrapper + `SetupGuardiansWizard`
> get the new `evm_addrs` parameter — the wizard already collects them from
> guardian invites, just hadn't been threading them through. After L-0d merges
> the L-B wizard's `buildRequestBlob` populates `guardian_set` from
> `backup.guardianEvmAddrs` and produces valid L-C-decodable request blobs.

---

## 0. One-paragraph summary

The L-C wizard's `recovery_help_approve` FFI takes `guardian_set: Vec<Vec<u8>>` (the M 20-byte EVM addresses); the engine builds the merkle proof for THIS guardian's signer against that root + signs the V2 Approve digest. The recoverer's request blob (L-C's `RecoveryRequest`) carries this M-roster. But the backup envelope (after L-0c) carries only `guardian_x25519_pubs` + `sealed_shares`. Under the hood `recovery_guardians` (the SQLite escrow table) was set up at L-A onboarding time WITHOUT the signer column — the L-A wizard collected both halves of each invite but only the X25519 half made it to disk. L-0d closes the gap symmetrically to L-0c: add `signer` to `StoredGuardian` + the SQL table + the L-A FFI call + the backup envelope. Schema 2 → 3.

---

## 1. Scope (build + test)

### What ships
- **`StoredGuardian.signer: [u8; 20]`** new field (mirror of `guardian_x25519_pub`).
- **`recovery_guardians` SQLite migration**: a new `guardian_signer BLOB NOT NULL DEFAULT (zeroblob(20))` column. Additive migration via a new `migrate_recovery_guardians_table` fn (mirrors `migrate_recovery_recipient_table` at `schema.rs:722`). Existing vaults pick it up on next open. **NOTE:** the default zero-fill is a SENTINEL — any guardian row whose `guardian_signer` reads as all-zero on load is from a pre-L-0d onboard and CANNOT participate in a recovery (the recoverer's request blob would need an address; the merkle root would fail). Handled by a clear `StoreError::CorruptedRecovery` error on the read path with a "re-onboard your guardians under the current Pangolin version" message — testnet-only, no real users impacted.
- **`Vault::onboard_guardians(threshold, &[x25519_pub], &[signer])`** — paired parallel arrays. Internal length-equality check returns `StoreError::InvalidInput` on mismatch; SQL write joins by index.
- **`BackupContents.guardian_evm_addrs: Vec<[u8; 20]>`** new field. CBOR body grows 10 → 11 elements. Cross-field check that `guardian_evm_addrs.len() == guardian_count`.
- **Backup `SCHEMA_VERSION = 2 → 3`** with hard-reject of v2 envelopes (mirror L-0c's hard-reject of v1).
- **`Vault::create_recovery_backup`** populates `guardian_evm_addrs` from the now-persisted escrow signers.
- **`FfiBackupContents.guardian_evm_addrs: Vec<Vec<u8>>`** surface.
- **`vault_onboard_guardians` FFI signature change**: gains `guardian_evm_addrs: Vec<Vec<u8>>` parameter alongside the existing `guardian_x25519_pubs`. Both must be M-length (engine validates).
- **`recovery_onboard_guardians` desktop command** + **`recoveryOnboardGuardians` invoke.ts wrapper**: gain `evm_addrs: Vec<String>` parameter.
- **`SetupGuardiansWizard.tsx` (L-A)** updated to pass `evm_addrs` (already collected from guardian invites' `signer` field; the data path is wired, just hadn't been used at onboard-time).

### What does NOT ship
- L-B wizard completion (separate slice, resumed after L-0d merges).
- Mainnet (D-011 gated).
- A migration to back-fill signers for existing pre-L-0d testnet onboardings (clean break — re-onboard).
- Any change to RecoveryV2 contract (on-chain merkle root carries the addresses already; no surface change).
- Any change to `recovery_recipient` (separate table, L-0a-2.2's domain).

---

## 2. Decisions to resolve (each: pick ONE)

### Q-a — Migration policy for pre-L-0d escrow rows
1. **Hard reject any row whose `guardian_signer` reads as all-zero** (Recommended). Returns typed `StoreError::CorruptedRecovery` from `read_recovery_escrow` with a "re-onboard guardians under the current version" message. Mirrors L-0c's v1-rejection posture. Testnet-only; no production state.
2. Soft-tolerate: load with zero signers but every chain operation downstream will fail at the merkle proof step. Buries the failure deep; worse UX.

**Recommend Option 1.** Surface fail-loud at the read; same shape as L-0c.

### Q-b — `Vault::onboard_guardians` parameter shape
1. **Paired parallel arrays** `(&[x25519_pub], &[signer])` (Recommended). Equivalent at the engine; matches the FFI's `Vec<Vec<u8>>, Vec<Vec<u8>>` shape; easy to validate (just length equality).
2. Single array of tuples `&[(x25519_pub, signer)]`. Cleaner ownership but requires a custom struct in the FFI (uniffi-flat shape is more JS-friendly with two parallel arrays).

**Recommend Option 1 (parallel arrays).** Matches the FFI ergonomics and the existing `vault_set_guardian_set` which already uses `Vec<Vec<u8>>` for EVM addresses.

### Q-c — Backup v2 rejection
1. **Hard reject v2 with typed `UnknownSchemaVersion(2, 3)`** (Recommended). Mirror of L-0c. No production v2 backups exist (L-0c shipped <24h ago, testnet-only).
2. Dual-decode v2 envelopes into a `BackupContents` with `guardian_evm_addrs = vec![]`, then refuse downstream. More code paths; no real win.

**Recommend Option 1.** Mirror of L-0c.

---

## 3. Files

### Edited
- `crates/pangolin-store/src/recovery_escrow.rs` — `StoredGuardian.signer` field; `GuardianRecord.signer`; `write_recovery_escrow_tx` writes the new column; `read_recovery_escrow` reads it + applies the all-zero rejection.
- `crates/pangolin-store/src/schema.rs` — `recovery_guardians` CREATE TABLE gains `guardian_signer`; new `migrate_recovery_guardians_table` fn (additive ALTER TABLE).
- `crates/pangolin-store/src/vault.rs` — `Vault::onboard_guardians` gains `guardian_signers: &[[u8;20]]` parameter; persists per-guardian alongside the pubkey; `create_recovery_backup` populates `BackupContents.guardian_evm_addrs`.
- `crates/pangolin-store/src/recovery_backup.rs` — `BackupContents.guardian_evm_addrs`; SCHEMA_VERSION 2→3; encode/decode body gains the new field; cross-field length check; v2 rejection. New tests (round-trip ordering pin + v2 rejection + manually-mismatched length).
- `crates/pangolin-ffi/src/recovery_ffi.rs` — `vault_onboard_guardians(handle, threshold, guardian_x25519_pubs, guardian_evm_addrs)` signature change.
- `crates/pangolin-ffi/src/recovery_backup.rs` — `FfiBackupContents.guardian_evm_addrs` field + projection.
- `apps/desktop/src/commands/recovery.rs` — `recovery_onboard_guardians` desktop command gains `evm_addrs: Vec<String>` parameter; hex parse + pass through.
- `apps/desktop/src/ui/lib/invoke.ts` — `recoveryOnboardGuardians(threshold, x25519Pubs, evmAddrs)` wrapper update; `BackupContents` interface gains `guardianEvmAddrs`.
- `apps/desktop/src/ui/screens/SetupGuardiansWizard.tsx` — pass `guardians.map(g => g.signer)` alongside the existing `x25519SealingPub` list at the onboarding-call site.

### Untouched (verify, then leave alone)
- `vault_set_guardian_set` — already takes EVM addresses (used for the on-chain root); no change.
- L-C wizard surface (its request shape was already correct; L-0d unblocks the recoverer building valid blobs).
- RecoveryV2 contract — on-chain merkle root semantics unchanged.

---

## 4. L-invariants

- **L1.** `signer` is non-secret (a public EVM address). Same posture as `guardian_x25519_pub`. No new secret-handling surface.
- **L2.** The atomicity discipline of `write_recovery_escrow_tx` is preserved — the new column writes inside the same transaction as the existing columns; a crash mid-write rolls all back.
- **L3.** Read-path validation: all-zero signer → typed `CorruptedRecovery`; cross-field length mismatch → typed `Validation`; v2 backup → typed `UnknownSchemaVersion(2, 3)`.
- **L5 (round-trip).** A backup created at schema 3 round-trips through decode unchanged; the `guardian_evm_addrs[i]` corresponds to the same guardian's identity as `guardian_x25519_pubs[i]` (pinned by the real-crypto E2E ordering test, NOT just byte round-trip).
- **L6.** `forbid(unsafe)`; AGPL; no new external crates.

---

## 5. Adversarial-audit focus

- **Ordering invariant (THE critical check)**: `signer[i]` must correspond to `x25519_pub[i]` AND `sealed_share[i]`. Verify the L-A wizard passes them in the SAME order; verify the store writes them at the SAME index; verify the read returns them in `ORDER BY guardian_index ASC`; verify the backup builder reads them in the SAME order; verify the decoder reads them in the SAME order.
- **All-zero signer rejection**: a row whose `guardian_signer` reads as all-zero (sentinel for a pre-L-0d legacy onboard OR a malformed schema migration) MUST surface as `CorruptedRecovery`, not silently load.
- **Length-mismatch defenses**: `signers.len() != x25519_pubs.len()` at `onboard_guardians`; `guardian_evm_addrs.len() != guardian_count` at `decode_body`. Each must fire with a typed error BEFORE any allocation or downstream work.
- **v2 envelope rejection**: hand-build a schema=2 envelope; assert `UnknownSchemaVersion(2, 3)` fires.
- **L-A wizard integration**: confirm the wizard collects `signer` from each `GuardianInvite` (already exposed as `invite.signer`) and passes it to `recoveryOnboardGuardians` — no new collection UX needed.
- **Tests pinning the L-B unblock**: at minimum a real-crypto round-trip where `decoded.guardian_evm_addrs` matches what was input + opens-under-matching-secret on `sealed_shares[i]` AND the EVM address matches what L-A's invite had.

---

## 6. Gate

1. `cargo +nightly fmt --all -- --check`
2. `cargo clippy --workspace --all-targets -- -D warnings`
3. `cargo test --workspace`
4. `forge fmt --check` (defense — no contract change)
5. `forge test` (defense)
6. `pnpm --filter @pangolin/desktop typecheck`
7. `pnpm --filter @pangolin/desktop lint`
8. `pnpm --filter @pangolin/desktop test` (vitest — L-A wizard tests may need update for the new arg)

---

## 7. Branch + merge

- Branch: `mvp4-l-0d-escrow-guardian-signers` off `main` (currently `ea6b62e`).
- Per-commit granularity: 3 logical commits — (1) store-side: SQL migration + StoredGuardian.signer + Vault::onboard_guardians signature; (2) backup envelope: BackupContents.guardian_evm_addrs + schema 2→3 + tests; (3) FFI + desktop surface update (vault_onboard_guardians, recovery_onboard_guardians, SetupGuardiansWizard).
- Merge `--no-ff` per §16 + push immediately.

---

## 8. Recommendation

Lock Q-a..c per the recommendations above (all = Option 1), put L-0d on `mvp4-l-0d-escrow-guardian-signers`. Expected size: similar to L-0c (~1-1.5h build + audit + merge). After L-0d merges, return to `mvp4-l-b-recoverer-wizard`, rebase onto main, plug `backup.guardianEvmAddrs` into `buildRequestBlob`'s `guardian_set` parameter, finish the wizard + vitest + audit + merge. L-B is then the FINAL slice of the MVP-4-L recovery track.
