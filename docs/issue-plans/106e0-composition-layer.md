<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Issue #106e-0 — store/core COMPOSITION LAYER (the public `Vault` methods #106e-1 FFI needs) — plan-gate LOCKED

**Status: LOCKED — Kelvin sign-off 2026-05-22 (see §0a). ONE small slice; own #104a-style audit before #106e-1.** Mirrors the §16 plan-gate format of `105-recovery-core-hardening.md` / `106e-pairing-ux-ffi.md`. The **missing middle slice** between the merged-and-audited drivers/commits and the (LOCKED-but-unbuilt) #106e-1 FFI: public production `Vault` methods that pull the **active session's secrets** + read the recovery escrow + compose the audited primitives, so the thin #106e-1 FFI never juggles a secret. Security-critical (the catastrophic-if-wrong recovery/rotation atomic-commit path).

## 0a. RESOLVED decisions (Kelvin sign-off 2026-05-22)

### 0a-CORRECTION (2026-05-22, builder dep-arrow finding — supersedes Q-a's location)

The builder correctly found that **Q-a's "all three as `Vault` methods in `vault.rs`" is impossible for two of them.** The workspace dependency arrow is one-way **`pangolin-core` → `pangolin-store`** (`pangolin-core/Cargo.toml` deps on store; store has NO core dep). `complete_rotation`/`recover_from_shares` MUST call `pangolin-core` drivers (`resolve_survivors`, `rotate_vdk_for_survivors`, `recover_vdk_from_shares`), so a `Vault` method physically in `pangolin-store` cannot reach them (Cargo-prohibited cycle). The corrected, verified-clean placement:

- **`complete_rotation` + `recover_from_shares` → free fns in `pangolin-core`** taking `&mut Vault` (core CAN call both the core drivers AND store's pub commits). NOT `Vault` methods.
- **`guardian_open_sealed_share` → STAYS a `Vault` method in `pangolin-store`** (it only needs `pangolin-crypto` — `derive_x25519_sealing_key`/`open_sealed_share` — which is upstream of store; no core dep). Buildable as Q-a specified.
- **Secret hygiene holds (verified against vault.rs:1497/1618 + the anvil E2E):** `rotate_vdk_for_survivors` takes ONLY non-secret inputs (survivor/guardian pubkeys, epoch) and MINTS `new_vdk` internally — the core fn never reads `old_vdk`/`device_key`. To keep those store-internal, **PROMOTE `__test_commit_vdk_rotation_reusing_active` (vault.rs:1618) to a production pub `Vault::commit_vdk_rotation_from_active(new_vdk, new_password, new_epoch, re_split…)`** (a thin delegate that does `self.active.take()` then calls the already-audited `commit_vdk_rotation` — NO new atomic surface). The core `complete_rotation` calls THAT, supplying only the driver's `new_vdk` + password + re_split. `recover_from_shares` calls the EXISTING pub `commit_recovery_rekey(recovered_vdk, …)` directly (the recovered VDK is reconstructed by the core driver, not from `self.active`). The `re_split → &[GuardianRecord]` decomposition moves into the core fns (core can construct store's pub `GuardianRecord`). Only secret OUT remains the guardian `Share`.

All other §0a decisions (behavior, GAP-A surfacing, lost-everything scope, Q-b/Q-d/Q-e, the test gate) are UNCHANGED — only the *file/crate location* of two methods moves from store to core.

---

The three methods PROMOTE the existing `#[cfg(any(test, feature="test-utilities"))]` helpers to production — wrapping the already-audited single-tx commits; NO new atomic surface.
- **`Vault::complete_rotation(master_password, current_onchain_set) -> RotationOutcome { new_epoch, unknown_survivors }`** — pulls `old_vdk` + local `DeviceKey` from `self.active`; `read_directory` → `resolve_survivors` → `rotate_vdk_for_survivors` → `commit_vdk_rotation` → `resolve_rotation_pending`; `(t,M)`/epoch/guardian-pubs read store-side via `read_recovery_escrow(active.vdk.aead_key())` + `read_current_epoch`. **GAP-A:** the `unknown`-pubkey survivors flow into `RotationOutcome.unknown_survivors` (never silently stranded).
- **Q-b (MAIN) → `Vault::recover_from_shares(wrapped_recovery, opened_shares, roster, new_password) -> RecoveryOutcome { new_epoch }` — LOST-EVERYTHING ONLY.** A fresh device has no VDK → can't read its own escrow (chicken-and-egg), so `wrapped_recovery` + roster `(t,M)`+M-X25519-pubs + recovered epoch + `vault_id` are ALL HOST-SUPPLIED parameters from the backup (backup FORMAT stays deferred — the recurring roster-restore gap). Pulls NOTHING from `self.active`. The has-vault-refresh variant is DROPPED (just a password change, no distinct use). → `recover_vdk_from_shares` → `commit_recovery_rekey`.
- **`Vault::guardian_open_sealed_share(sealed_share, vault_id, epoch) -> Share`** — derives the guardian X25519 sealing secret from `self.active.device_key` via **`derive_x25519_sealing_key`** (confirmed — the share-to-guardian derivation, NOT pairing) + `open_sealed_share`. The returned `Share` is the only secret out (the #106e-1 FFI wraps it opaque).
- **Q-a → SUPERSEDED by 0a-CORRECTION:** `complete_rotation`/`recover_from_shares` are `pangolin-core` free fns over `&mut Vault` (the dep arrow forbids store reaching the core drivers); `guardian_open_sealed_share` stays a store `Vault` method. Plus a new thin pub store wrapper `commit_vdk_rotation_from_active` (promoted from the `__test_` helper) so `old_vdk`/`device_key` never cross into core.
- **Q-e → `resolve_rotation_pending` loops over the WHOLE survivor set** (a rotation retires the whole set, not one `removed_signer`).
- **Q-d (secret hygiene — the audit's central check):** the extracted VDK/device-key/guardian-secret are BORROWED from `self.active` (already in memory), not copied/leaked; methods return NON-secret outcomes except the guardian `Share`. ZERO new secret-lifetime surface.
- **Promote the inline `re_split → &[GuardianRecord]` decomposition** (currently test code at vault.rs:10754) to a production helper.
- **L-invariants:** atomic via the already-audited commits (no new atomic surface); zero new secret-lifetime exposure; these methods are the ONLY new public surface; reuse audited drivers (NO new crypto/deps); testnet-only/D-011; forbid(unsafe); AGPL; tests promote the existing test-helper coverage + the rotation/recovery anvil E2Es exercise the PUBLIC methods; full `cargo test --workspace` gate.

**Base (all merged + audited):** #104a escrow primitive (`open_sealed_share`, `wrap/unwrap_vdk_under_rwk`); #104b recovery orchestration (`recover_vdk_from_shares`); #105a atomic re-split persistence (`commit_recovery_rekey`, vault.rs:1387); #106b device-pairing crypto (`derive_x25519_pairing_key` / `derive_x25519_sealing_key`); #106b-2 atomic VDK-rotation-on-revoke commit (`commit_vdk_rotation`, vault.rs:1497) + `rotate_vdk_for_survivors` (rotation.rs:242); #106c GAP-A survivor directory + rotation-pending (`resolve_survivors` device_add.rs:260, `pending_rotations`/`resolve_rotation_pending` vault.rs:7990/8000, `read_directory` multi_device.rs:127). The active-secret composition ALREADY EXISTS as `#[cfg(any(test, feature = "test-utilities"))]` helpers (`__test_commit_vdk_rotation_reusing_active` vault.rs:1618; `__test_commit_recovery_rekey_reusing_active_vdk` vault.rs:1698) — this issue PROMOTES that logic to production.

## 0. One-paragraph summary

Every merged driver/commit in the multi-device + recovery epic takes its secrets as **explicit borrowed parameters** (`commit_vdk_rotation(new_vdk, old_vdk: &VdkKey, local_device: &DeviceKey, …)`; `commit_recovery_rekey(recovered_vdk: VdkKey, …)`; `open_sealed_share(sealed, guardian_x25519_secret: &[u8;32], …)`). That parameter shape was deliberate: it kept the audited commits free of session-state coupling and let the #105/#106c builders test them hermetically by pulling the active VDK out of `self.active` inside a `#[cfg(test)]` helper. But the LOCKED #106e-1 FFI surface (`106e-pairing-ux-ffi.md` §0a / §3.1) — `vault_complete_rotation(master_password)`, `vault_recover_from_shares(opened_shares, roster, new_password)`, `vault_guardian_open_share(sealed_share)` — must NOT juggle secrets across the FFI boundary (L1 of #100/#105/#106e). Today the only code that pulls the active session's VDK / DeviceKey / guardian X25519 secret out of the private `self.active` and feeds it to the audited commit is `#[cfg(test)]`-gated; the merged docstring on `commit_vdk_rotation` literally says *"the FFI surface is a later issue"* (vault.rs:1477). #106e-0 closes that gap with **three public production methods on `Vault`** that promote the test-helper composition, returning NON-secret outcomes (plus the one opaque `Share` the guardian-open accessor yields). It introduces **NO new crypto, NO new deps, NO new atomic surface** — each method WRAPS an already-audited single-transaction commit. It is the prerequisite that unblocks #106e-1.

## 1. Scope

**#106e-0 builds (three public methods; in `pangolin-store::vault`, one possible pure-core helper):**

1. **`Vault::complete_rotation(master_password)`** — the production twin of `__test_commit_vdk_rotation_reusing_active`. Pulls `self.active`'s current VDK (`old_vdk`) + local `DeviceKey`, resolves survivors from a host-supplied on-chain authorized set + the local directory (`resolve_survivors`), runs `rotate_vdk_for_survivors` engine-side, calls the audited `commit_vdk_rotation(master_password, …)`, then `resolve_rotation_pending`. Returns a NON-secret `RotationOutcome { new_epoch, unknown_survivors }` (GAP-A surfacing).
2. **`Vault::recover_from_shares(opened_shares, roster, new_password, …)`** — runs `recover_vdk_from_shares` engine-side → the audited atomic `commit_recovery_rekey(new_password, …)`. The DESIGN NUANCE (Q-b): a lost-everything device has NO current VDK, so it CANNOT call `read_recovery_escrow` (which needs `vdk.aead_key()`); the `wrapped_recovery` + `(t,M)` + epoch must come from a host-supplied backup. Recommendation §3.2.
3. **`Vault::guardian_open_sealed_share(sealed_share, vault_id, epoch)`** — derives the engine-side guardian X25519 **sealing** secret from the active session's `DeviceKey` via `derive_x25519_sealing_key` (NOT the pairing key — confirmed §3.3), calls `open_sealed_share`, returns the opened `Share` (the ONLY secret out; the FFI wraps it opaque per #106e L1).

**Deferred (NOT this slice):**
- The FFI bindings themselves (#106e-1 — LOCKED, builds on top of these).
- The pairing transport / QR / SAS (#106e-2).
- The guardian-roster BACKUP FORMAT for a lost-everything recovery (recurring #104b Q-c / #105 GAP 2 / #106e Q-g gap — the roster is a HOST-SUPPLIED input here; persisting/restoring it stays 6.x).
- Any new atomic primitive — these methods WRAP `commit_vdk_rotation` / `commit_recovery_rekey` verbatim.

## 2. Splittable? — recommendation: **ONE small slice (the 3 methods)**

These three methods share one shape (extract-active-secret → run-pure-driver → call-audited-commit → return-non-secret), one audit surface (the active-secret extraction discipline + the lost-everything signature decision), and one test gate (promote the existing test-helper coverage to drive the public methods + the rotation/recovery anvil E2Es exercise them). They are too small and too coupled to split usefully. **Recommend: one #106e-0 PR, builder→#104a-style audit→merge, BEFORE #106e-1.** (Surfaced as Q-f — Kelvin may prefer to fold #106e-0 INTO #106e-1 as its first commits, the #105a-into-#105 precedent; see Q-f.)

## 3. The composition layer (designed; decisions surfaced in §5)

All three methods inherit the existing session discipline: `let active = self.active.take()` / `self.active.as_ref().ok_or(StoreError::NotUnlocked)?` is the gate; the extracted secrets are **borrowed from `self.active` (already in memory)** and never copied into a non-zeroizing buffer; the methods return non-secret outcomes (except the guardian `Share`). No new secret-lifetime surface (Q-d).

### 3.1 `Vault::complete_rotation` (the rotation method)

**Proposed signature (per 0a-CORRECTION: `pangolin-core` free fn over `&mut Vault`, NOT a store method):**
```text
// in pangolin-core (can call both the core drivers AND store's pub commits)
pub fn complete_rotation(
    vault: &mut Vault,
    master_password: &SecretBytes,
    current_onchain_set: &[[u8; 20]],   // host-supplied: the live RevisionLogV2 authorized set
) -> Result<RotationOutcome>

pub struct RotationOutcome {
    pub new_epoch: u64,
    /// GAP A: in-set survivors whose pairing pubkey the LOCAL directory does
    /// not know — re-keyed opportunistically when they next present a triple.
    pub unknown_survivors: Vec<[u8; 20]>,   // 20-byte secp256k1 signers
}
```
**Where each input comes from / the composition (mirrors `__test_commit_vdk_rotation_reusing_active`):**
- **`old_vdk` + `local_device`** — per 0a-CORRECTION these stay STORE-INTERNAL: the core fn does NOT read them (it can't see private `self.active`). Instead it calls the new pub `vault.commit_vdk_rotation_from_active(new_vdk, master_password, new_epoch, re_split…)` (promoted from `__test_commit_vdk_rotation_reusing_active`, vault.rs:1618), which does `self.active.take()` to pull `old_vdk`/`device_key` and delegates to the audited `commit_vdk_rotation`. So the core fn supplies only the driver's `new_vdk` + password + re_split — the old VDK/device key never cross the crate boundary.
- **survivor directory + `(survivors, unknown)`** — `resolve_survivors(current_onchain_set, &directory)` where `directory` is built from `multi_device::read_directory(&self.conn)` mapped into `SurvivorDirectoryEntry`. `unknown` flows straight into `RotationOutcome.unknown_survivors` (GAP-A, Q-c).
- **guardian set `(t, M)` + the M X25519 pubkeys + `current_epoch`** — read store-side: `(t,M)`/epoch from `read_recovery_escrow(&self.conn, vault_id, self.active.vdk.aead_key())` (the CURRENT VDK opens it — a rotation always has a current VDK); the M guardian X25519 pubkeys are the `guardian_x25519_pub` of each `StoredRecoveryEscrow.guardians` entry; `current_epoch` from `vdk_chain::read_current_epoch(&self.conn)`.
- **`rotate_vdk_for_survivors(survivors, vault_id, GuardianSetConfig{t,M}, &guardian_pubs, current_epoch)`** → `RotationArtifacts { new_vdk, re_split: OnboardingArtifacts, new_epoch, .. }`.
- **the audited commit** — decompose `re_split` into `&[GuardianRecord]` exactly as the existing tests do (`re_split.assignments[i] → GuardianRecord { index, guardian_x25519_pub, sealed_share: &… }`; the core fn constructs store's pub `GuardianRecord`), then `vault.commit_vdk_rotation_from_active(new_vdk, master_password, new_epoch, &re_split.wrapped_recovery, t, M, re_split.epoch.into(), &records)` — which internally pulls `old_vdk`/`device_key` and delegates to the audited `commit_vdk_rotation`. ATOMIC via the existing single `unchecked_transaction()` (#106b-2 L4) — no new atomic surface.
- **`resolve_rotation_pending(removed_signer)`** — after the commit, mark the pending row(s) resolved. (Open detail Q-e: which removed signer to clear — see §5.)

### 3.2 `Vault::recover_from_shares` (the recovery method) — THE MAIN NUANCE (Q-b)

**The two scenarios:**
- **Lost-everything (a NEW device, NO current VDK).** This is the REAL recovery use: the user lost every device, installs fresh, and recovers. There is NO active session and NO local escrow to read (`read_recovery_escrow` needs `vdk.aead_key()` — a chicken-and-egg: you can't read the escrow without the VDK you're trying to recover). The `wrapped_recovery` + `(t,M)` + epoch MUST be HOST-SUPPLIED (from a backup — #106e Q-g defers the backup FORMAT; the inputs are taken as parameters here).
- **Has-vault refresh (an EXISTING unlocked vault re-keys under a new password).** A current VDK exists, so `read_recovery_escrow(conn, vault_id, active.vdk.aead_key())` yields the local `wrapped_recovery`/`(t,M)`/epoch. This is the path the `__test_commit_recovery_rekey_reusing_active_vdk` helper exercises (it reuses the active VDK as the stand-in for the reconstructed one).

**Recommendation (Q-b): support LOST-EVERYTHING as the PRIMARY (and, for #106e-0, the ONLY) scenario** — it is the genuine recovery use, and it is the one #106e-1's `vault_recover_from_shares(opened_shares, roster, new_password)` (LOCKED §3.1) is shaped for. The has-vault refresh has no real user need distinct from a normal password change and would force a `read_recovery_escrow` branch keyed on session state. Take the recovery inputs as host-supplied parameters; do NOT read the local escrow.

**Proposed signature (lost-everything; per 0a-CORRECTION: `pangolin-core` free fn over `&mut Vault`):**
```text
// in pangolin-core
pub fn recover_from_shares(
    vault: &mut Vault,
    wrapped_recovery: &WrappedVdkRecovery,   // host-supplied (from backup)
    opened_shares: Vec<Share>,               // collected from >= t guardians (opaque carriers)
    roster: &GuardianRoster,                 // M X25519 pubkeys + (t,M) — host-supplied
    new_password: &SecretBytes,
) -> Result<RecoveryOutcome>

pub struct RecoveryOutcome { pub new_epoch: u64 }
```
**Composition:** `recover_vdk_from_shares(wrapped_recovery, opened_shares, vault_id, GuardianSetConfig{t,M}, &roster.x25519_pubs, current_epoch)` → `RecoveryArtifacts { vdk, re_split }`; then the audited atomic `commit_recovery_rekey(vdk, new_password, &re_split.wrapped_recovery, t, M, re_split.epoch.into(), &records)` (vault.rs:1387 — single transaction spanning the meta re-wrap + the re-split escrow, #105a L2). The recovered `vdk` is consumed + dropped (zeroized) inside the commit. NON-secret out: `{ new_epoch }`.
**`current_epoch` source (lost-everything):** also host-supplied (alongside `wrapped_recovery`/roster from the backup) — `recover_vdk_from_shares` tags the re-split `current_epoch.next()`, so it must be the epoch the recovered shares belong to. FLAG (§5 Q-b): on a fresh device `vdk_chain::read_current_epoch` would return the default, NOT the recovered epoch — confirm the epoch is carried in the backup envelope. **Defining `GuardianRoster` (the host-supplied input type) + where `vault_id` comes from on a fresh device are the two build sub-details** (vault_id likely from the same backup / from `self.meta` if the .pvf was provisioned with it).

### 3.3 `Vault::guardian_open_sealed_share` (the guardian-open accessor)

**Proposed signature:**
```text
pub fn guardian_open_sealed_share(
    &self,
    sealed_share: &SealedShare,
    vault_id: &[u8; VAULT_ID_LEN],   // the vault being recovered (NOT necessarily self's)
    epoch: &[u8; EPOCH_LEN],
) -> Result<Share>
```
**The X25519 derivation (Q-c resolved by reading the code):** a guardian opening a share sealed to it uses **`derive_x25519_sealing_key`** (guardian.rs:171), NOT `derive_x25519_pairing_key`. CONFIRMED two ways: (1) `escrow.rs` seals shares to a guardian's SEALING pubkey and `recovery::orchestration`'s own tests open them with `derive_x25519_sealing_key(&dev).secret_bytes()` (orchestration.rs:382-393); (2) the two derivations use DISTINCT domain-separators (`pangolin-guardian-x25519-derive-v0` vs `pangolin-device-pair-x25519-…`) — pairing seals the VDK to a DEVICE, sealing seals a SHARE to a GUARDIAN. **Composition:** `let sealing = derive_x25519_sealing_key(&self.active.device_key); open_sealed_share(sealed_share, &sealing.secret_bytes(), vault_id, epoch)`. The `secret_bytes()` returns a `Zeroizing<[u8;32]>` passed straight in (no copy). The returned `Share` is the one secret out — the #106e-1 FFI wraps it as an opaque `Arc` Object (the `SecretPassword` pattern, #106e L1). Session-gated (`require_active`).

### 3.4 What the methods extract / return (the secret-hygiene table — Q-d)

| Method | Extracted from `self.active` (borrowed, never copied) | Returns (non-secret unless noted) |
|---|---|---|
| `complete_rotation` | current VDK (`old_vdk`), local `DeviceKey` | `RotationOutcome { new_epoch, unknown_survivors }` |
| `recover_from_shares` | (nothing — lost-everything has no active VDK; inputs host-supplied) | `RecoveryOutcome { new_epoch }` |
| `guardian_open_sealed_share` | local `DeviceKey` → derived X25519 sealing secret | the opened **`Share`** (SECRET — FFI wraps opaque) |

## 4. L-invariants (proposed — mirror 105/106c/106e style)

- **L1 (atomic via the AUDITED commits — no new atomic surface; LOAD-BEARING).** `complete_rotation` calls `commit_vdk_rotation` (the #106b-2 single-transaction commit, L4); `recover_from_shares` calls `commit_recovery_rekey` (the #105a single-transaction commit, L2). Neither method opens its own transaction or re-orchestrates two writes — the atomicity (and its crash-injection gate) is INHERITED, not re-implemented. A crash mid-method leaves the vault on the OLD epoch / OLD escrow (retryable, L8).
- **L2 (zero NEW secret-lifetime exposure — inherits #100/#105 L1).** The extracted VDK / DeviceKey / guardian X25519 secret are borrowed from `self.active` (already resident) and live only across the commit; they are never copied into a non-zeroizing buffer, never logged, never returned. The methods return non-secret outcomes; the ONE secret crossing out is the opened `Share` from `guardian_open_sealed_share`, which the FFI immediately wraps opaque (this method is the ONLY new path that returns a secret-bearing type, by design).
- **L3 (these three methods are the ONLY new public surface).** No new public types beyond the two small non-secret outcome structs (`RotationOutcome`, `RecoveryOutcome`) + the host-supplied `GuardianRoster` input. The `#[cfg(test)]` helpers stay (they keep their hermetic coverage); the production methods are added alongside, not by un-gating the helpers (the helpers reuse the ACTIVE VDK as a stand-in — a test-only affordance that must NOT leak to production).
- **L4 (reuse the audited drivers — NO new crypto, NO new deps).** Every crypto/persistence op delegates to a merged-and-audited fn (`resolve_survivors`, `rotate_vdk_for_survivors`, `recover_vdk_from_shares`, `derive_x25519_sealing_key`, `open_sealed_share`, `commit_vdk_rotation`, `commit_recovery_rekey`, `read_recovery_escrow`, `read_directory`, `read_current_epoch`). Zero new pinned deps expected.
- **L5 (session-gated).** Every method gates on `self.active` before touching a secret (`take()` / `as_ref().ok_or(StoreError::NotUnlocked)`). EXCEPTION nuance: `recover_from_shares` lost-everything runs WITHOUT a prior active session (there is no VDK to unlock with) — confirm the gate posture (it does NOT require `active`; it CREATES the unlockable state via the commit). FLAG §5 Q-b.
- **L6 (`forbid(unsafe_code)`; AGPL SPDX).** `pangolin-store` / `pangolin-core` stay `forbid(unsafe_code)`; no new module needs `unsafe`. Every touched/new file carries the AGPL SPDX header.
- **L7 (testnet-only until D-011).** The whole recovery/rotation surface stays Base-Sepolia-only until the external audit clears (inherits #105 L9 / #106e L9 / D-011).
- **L8 (tests = promote the existing test-helper coverage + the anvil E2Es exercise the PUBLIC methods).** The hermetic rotation/recovery store tests are re-pointed (or duplicated) to drive `complete_rotation` / `recover_from_shares` / `guardian_open_sealed_share` instead of (or alongside) the `__test_*` helpers; the existing rotation/recovery anvil E2Es are extended to call the public methods. FULL `cargo test --workspace` is the merge gate (the #106b-1 lesson — not just the touched crates).
- **L9 (§16 ledger).** `git merge --no-ff`; DECISIONS.md Q-resolution entries; DEVLOG at merge; explicit Kelvin approval at the merge boundary. Its own #104a-style adversarial audit AFTER build (the catastrophic-if-wrong path).

## 5. Open decisions for Kelvin (Q-a … Q-f) — recommendation + plain-English stakes

- **Q-a — Where do the methods live? → RESOLVED by 0a-CORRECTION (NOT all-in-store; the dep arrow forbids it).** `complete_rotation`/`recover_from_shares` are `pangolin-core` free fns over `&mut Vault` (store cannot call the core drivers); `guardian_open_sealed_share` stays a store `Vault` method; a new thin pub `Vault::commit_vdk_rotation_from_active` keeps `old_vdk`/`device_key` store-internal. See 0a-CORRECTION for the full rationale + secret-flow verification.
- **Q-b (THE MAIN ONE) — `recover_from_shares` scenario scope: lost-everything only, or BOTH?** **Recommend: lost-everything ONLY for #106e-0.** Take `wrapped_recovery` + roster + `(t,M)` + the recovered epoch + `vault_id` as HOST-SUPPLIED parameters (from a backup); do NOT read the local escrow (a fresh device has no VDK to read it with). *Plain English:* "recovery" means the user lost all their devices and is starting over — there's nothing local to read, so the recovery material has to come from a backup the host hands us. The "refresh an existing vault" variant has no real distinct use (it's just a password change) and would complicate the method with a session-state branch. **Stakes if wrong: HIGH** — if we accidentally shape the method to read the local escrow, lost-everything recovery (the whole point of social recovery) is impossible on a fresh device. **Sub-flag (must resolve in build, not blocking the gate): the recovered EPOCH and `vault_id` must travel in the backup envelope** — on a fresh device `read_current_epoch` returns the default, not the recovered epoch, so the re-split would be tagged at the wrong epoch. The backup-format itself stays deferred (#106e Q-g), but #106e-0 must pin that these two values are method PARAMETERS, not store reads.
- **Q-c — Guardian-open X25519 derivation + GAP-A surfacing.** **Resolved by reading the code (confirm):** a guardian uses **`derive_x25519_sealing_key`** (not pairing) to open a share sealed to it (orchestration.rs's own tests do exactly this). And `complete_rotation` surfaces `resolve_survivors`'s `unknown` list in `RotationOutcome.unknown_survivors` so the host never silently strands an in-set survivor whose pubkey the local directory doesn't yet know (#106e GAP A). *Plain English:* a guardian's "open my share" key is a different derived key from a device's "receive the vault key" key — we use the guardian one. And if a surviving device's public key isn't in our local address book yet, we tell the caller rather than dropping it.
- **Q-d — Secret hygiene / new secret-lifetime surface?** **Recommend: confirm NONE.** The extracted secrets are borrowed from `self.active` and live only across the audited commit; the only secret OUT is the opened `Share` (FFI-wrapped opaque). *Plain English:* we're not creating any new place a secret could leak — we borrow what's already in memory, use it, and the only thing that leaves is the guardian's opened share, which the FFI immediately seals behind an opaque handle. Stakes: this is the audit's central claim — pin it precisely.
- **Q-e — `complete_rotation`'s `resolve_rotation_pending` argument.** A revoke can leave MULTIPLE pending rows. **Recommend: resolve ALL currently-pending rows whose removed signer is absent from the supplied `current_onchain_set`** (one rotation re-keys against the whole survivor set, retiring every outstanding removal at once), rather than threading a single `removed_signer`. *Plain English:* if two devices were revoked, one master-password rotation cleans up both — don't make the user re-enter the password per revocation. **Stakes: medium** — get it wrong and a stale "rotation pending" prompt nags forever, or (worse) a removal is marked resolved without being rotated against. Confirm with Kelvin.
- **Q-f — Split: standalone #106e-0, or fold into #106e-1 as its first commits?** **Recommend: standalone #106e-0**, builder→#104a-style audit→merge, BEFORE #106e-1 — it is the security-critical composition that deserves its own adversarial review separate from the FFI plumbing (the #105a-as-its-own-PR precedent). *Plain English:* this is the dangerous part (the atomic recovery/rotation path); review it on its own so the audit isn't diluted by FFI boilerplate. Stakes: low/process — Kelvin may prefer one ledger entry (#105a-into-#105 style); either way the composition lands as its own audited commit-set first.

## 6. Places the merged drivers do NOT compose cleanly into a public method (flagged)

- **`recover_from_shares` cannot read its own escrow on a fresh device** (the chicken-and-egg in Q-b): `read_recovery_escrow` requires `vdk.aead_key()`, which lost-everything recovery does not have. RESOLUTION: take the recovery material as host-supplied parameters; do NOT call `read_recovery_escrow` on this path. This is the single non-clean composition and the reason Q-b is the main decision.
- **The recovered EPOCH + `vault_id` have no store source on a fresh device** (Q-b sub-flag): `read_current_epoch` returns the default on a fresh .pvf, so the re-split would be mis-tagged. Both must be method parameters carried in the backup envelope. Pin in build.
- **`resolve_rotation_pending` takes ONE `removed_signer`** but a rotation retires the whole survivor set (Q-e): the public method must loop over all pending rows absent from `current_onchain_set`, a small glue not present in the drivers.
- **The `re_split: OnboardingArtifacts` → `&[GuardianRecord]` decomposition** is currently inline test code (vault.rs:10754) — the production methods must do the same mapping (`assignment.index` / `.guardian_x25519_pub` / `&.sealed_share`). Clean but must be promoted, not left test-only.
