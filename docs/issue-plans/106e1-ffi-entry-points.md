<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Issue #106e-1 — recovery + rotation FFI entry points (the thin uniffi layer over #106e-0) — plan-gate LOCKED (BLOCKED on #106e-0b)

**Status: LOCKED — Kelvin sign-off 2026-05-22 (§0a). BLOCKED on #106e-0b (onboarding) — build that first.** Mirrors the §16 plan-gate format of `106e0-composition-layer.md`. The thin uniffi surface that exposes the merged #106e-0 composition methods to host apps so the multi-device recovery/rotation flows are reachable from the UI. **Subsumes the long-pending #105b recovery-FFI** (per the LOCKED `106e-pairing-ux-ffi.md` §0a Q-a). Pairing transport / QR / SAS / device-add FFI stays #106e-2.

## 0a. RESOLVED decisions (Kelvin sign-off 2026-05-22)

- **Q-a → SPLIT: onboarding is its own slice #106e-0b, built FIRST.** The production guardian-escrow onboarding path (the missing prerequisite) is NOT folded into #106e-1; it gets its own plan-gate + builder + audit + merge (`106e0b-guardian-onboarding.md`), then #106e-1's recovery FFI builds on top. #106e-1 is BLOCKED until #106e-0b merges.
- **Q-b → the FFI READS the live authorized set itself** (engine is the single source of truth). `vault_complete_rotation` becomes async (`block_on_local` + the fail-closed `read_authorized_set_v2`), taking `rpc_url`/`deployment_path` like `vault_lock_with_drain`; the host does NOT pass the set in. A buggy/malicious host cannot inject a wrong set that strands a survivor or skips a revocation.
- **Q-c → opened `Share` as a `SecretPassword`-style opaque `Arc<FfiOpenedShare>` Object** (zeroizing buffer, exposes only `byte_length()`); `vault_recover_from_shares` consumes `Vec<Arc<FfiOpenedShare>>` and extracts the `Share`s engine-side. The Object NEVER exposes the raw scalar (the audit's central FFI check).
- **Q-d → recovery material (`wrapped_recovery`/`current_epoch`/`vault_id`) crosses as raw length-validated `Vec<u8>`/`u64` params** (host-supplied from a backup; backup FORMAT stays deferred to 6.x).
- **Q-e → ONE slice** for the 4 recovery/rotation bindings (onboarding is the separate #106e-0b per Q-a).
- **Q-f → pairing/device-add FFI is OUT** → #106e-2 (QR/short-code/SAS + `vault_add_device`).
- **L-invariants:** L1 zero-secret-crosses-FFI (only opaque Objects + epochs/survivor-lists out; `grep -ci uniffi` on core/store stays 0); no new atomic surface (wraps the merged commits); rotation never auto-completes (master password crosses IN); session-gated except lost-everything recover; thin (uniffi 0.31.1, no new deps); errors carry no secret; testnet-only/D-011; AGPL; full `cargo test --workspace` + uniffi binding tests; its own #104a-style audit focused on L1.

> NOTE: §5 below is the original DRAFT decision discussion; §0a is authoritative.

## 0. One-paragraph summary

#106e-0 merged three production composition entry points — `pangolin_core::composition::complete_rotation` / `recover_from_shares` (free fns over `&mut Vault`) and `Vault::guardian_open_sealed_share` — plus the non-secret `Vault::recovery_escrow_params` accessor and the thin `commit_vdk_rotation_from_active` commit. They are pure Rust; no host can call them yet. #106e-1 wraps them as `#[uniffi::export]` bindings on `pangolin-ffi`, following the established #100 model verbatim: `VaultHandle = Mutex<Option<Vault>>` with the `lock_vault().as_mut()?` session gate (uniffi 0.31.1, proc-macro), `block_on_local` for any async chain read, the `SecretPassword`/`SecretBuf` opaque-`Arc`-Object pattern for the ONE secret that crosses out (the opened guardian `Share`), the `#[uniffi(flat_error)] FfiError` enum (which already has a `Recovery` variant), and byte arrays crossing as length-validated `Vec<u8>` / `Vec<Vec<u8>>` inside `uniffi::Record`s. **L1 (the cardinal rule, inherited from #100): NO secret crosses the FFI as readable bytes** — `cargo tree -p pangolin-core | grep -ci uniffi` stays `0`, and only epochs / merkle-context / unknown-survivor lists / opaque Objects leave the engine. **The build is thin: zero new crypto, zero new atomic surface — each binding is `lock → as_mut()? → call the merged method → map the result`.** The one substantive question is a missing PREREQUISITE (§5 Q-a): there is no production guardian-escrow ONBOARDING path, so the recovery surface has nothing to recover against until one exists.

## 1. Scope

**#106e-1 builds (uniffi bindings in `pangolin-ffi`, one new module e.g. `src/recovery.rs` + `src/rotation.rs`):**

1. **`vault_pending_rotations(handle) -> Result<Vec<FfiRotationPending>, FfiError>`** — read the crash-durable rotation-pending rows (`Vault::pending_rotations`) so the host can render "rotation pending — enter master password". `FfiRotationPending { removed_signer: Vec<u8> /*20*/, observed_epoch: u64, observed_at: u64 }`. Non-secret; session-gated.
2. **`vault_complete_rotation(handle, master_password: Arc<SecretPassword>, …live-set source…) -> Result<FfiRotationResult, FfiError>`** — drives `composition::complete_rotation`. The master password crosses IN as an opaque Object; out comes only `FfiRotationResult { new_epoch: u64, unknown_survivors: Vec<Vec<u8>>, schema_version: u16 }` (GAP-A surfaced). The live authorized-set source is Q-b.
3. **`vault_guardian_open_share(handle, sealed_share: Vec<u8>, vault_id: Vec<u8>, epoch: Vec<u8>) -> Result<Arc<FfiOpenedShare>, FfiError>`** — drives `Vault::guardian_open_sealed_share`; returns the opened `Share` wrapped as an opaque `Arc` Object (the `SecretPassword` template — Q-c), never readable bytes.
4. **`vault_recover_from_shares(handle, wrapped_recovery: Vec<u8>, opened_shares: Vec<Arc<FfiOpenedShare>>, roster: FfiGuardianRoster, new_password: Arc<SecretPassword>, current_epoch: u64, vault_id: Vec<u8>) -> Result<FfiRecoveryResult, FfiError>`** — drives `composition::recover_from_shares` (LOST-EVERYTHING). All recovery material host-supplied (Q-d). Out: `FfiRecoveryResult { new_epoch: u64, schema_version: u16 }`.
5. **The FFI result/record types + error mapping**: `FfiRotationResult`, `FfiRecoveryResult`, `FfiRotationPending`, `FfiGuardianRoster { threshold: u8, guardian_count: u8, x25519_pubs: Vec<Vec<u8>> }`, the `FfiOpenedShare` opaque Object, and `From<CompositionError>`/`From<StoreError>` → `FfiError` (Rotation/Recovery/Store/`Validation{kind:"authentication"}` collapse). Exhaustive-match error test (mirrors `tests/error_taxonomy.rs`).

**Deferred (NOT this slice):**
- Pairing transport / QR / short-code / SAS + the device-add FFI (`vault_add_device`) — **#106e-2** (its own plan-gate + audit).
- The guardian-roster BACKUP FORMAT for lost-everything recovery (recurring #104b Q-c / #105 GAP 2 / #106e Q-g gap — the recovery material is HOST-SUPPLIED raw bytes here; persisting/parsing the backup envelope stays 6.x).
- **Possibly the guardian-escrow ONBOARDING path — see Q-a (the MAIN decision).**

## 2. Splittable? — depends on Q-a

If Q-a folds onboarding in, #106e-1 has two coherent halves: (1) the onboarding production method + its FFI, (2) the recovery/rotation/guardian-open FFI. They could split (onboarding = #106e-1a, the rest = #106e-1b). If Q-a splits onboarding out entirely, #106e-1 is one tight slice (the four bindings above) — recommended. **Recommend: ONE slice for the four bindings; onboarding handled per Q-a.**

## 3. The FFI surface (designed; decisions in §5)

Every binding is the #100 idiom: `let mut guard = handle.lock_vault(); let vault = guard.as_mut()?;` (the L5 session gate → `FfiError::Session "vault is not unlocked"` on a locked/placeholder handle) → call the merged method → map `Result`. No binding opens a transaction or re-orchestrates writes; the atomicity is wholly inherited from the #106e-0 commits (L4).

### 3.1 `vault_complete_rotation`
`composition::complete_rotation(vault, &master_password, &current_onchain_set)` is SYNC, but obtaining `current_onchain_set` (the live RevisionLogV2 authorized set) is a chain READ → see Q-b for whether the FFI reads it (async `block_on_local` + `read_authorized_set_v2`, fail-closed) or the host passes it in. `master_password.bytes_for_bridge()` → `SecretBytes` engine-side (never logged, dropped after). The returned `unknown_survivors: Vec<[u8;20]>` → `Vec<Vec<u8>>` (GAP-A). After it returns the vault is `Locked`; the host re-unlocks with the new password.

### 3.2 `vault_guardian_open_share` + `FfiOpenedShare`
`derive_x25519_sealing_key(&self.active.device_key)` + `open_sealed_share` engine-side → the opened `Share`. The `Share` is wrapped in `#[derive(uniffi::Object)] FfiOpenedShare { inner: Share }` (or a zeroizing buffer holding the share bytes — Q-c), exposing ONLY a `byte_length()` like `SecretPassword`. Session-gated. Fails closed (`FfiError::Validation{kind:"authentication"}`) on a wrong vault_id/epoch.

### 3.3 `vault_recover_from_shares`
The host collects `>= t` `FfiOpenedShare` Objects (from `vault_guardian_open_share` on the guardians' devices), plus the host-supplied backup material. The FFI unwraps the `Arc<FfiOpenedShare>`s back into `Vec<Share>` (Q-c: how — `Arc::try_unwrap` vs an internal clone-out), builds `GuardianRoster`, and calls `composition::recover_from_shares`. LOST-EVERYTHING: no active session required (it CREATES the unlockable state). Out: `{ new_epoch }`.

### 3.4 The secret-hygiene table (L1 — the audit's central check)
| Binding | Secret IN (opaque) | Secret OUT | Non-secret OUT |
|---|---|---|---|
| `vault_complete_rotation` | `master_password` (Object) | none | `new_epoch`, `unknown_survivors` |
| `vault_guardian_open_share` | none | the opened `Share` (opaque `FfiOpenedShare` Object) | none |
| `vault_recover_from_shares` | `new_password` (Object) + the `Share` Objects | none | `new_epoch` |
| `vault_pending_rotations` | none | none | the pending rows |

## 4. L-invariants (proposed)
- **L1 (ZERO secret crosses FFI as readable bytes — the #100 cardinal rule).** Passwords + the opened `Share` cross ONLY as opaque `Arc` Objects exposing at most a length; epochs/survivor-lists/merkle-context are the only plain values out. `grep -ci uniffi` on `pangolin-core`/`-store` stays 0 (FFI isolation).
- **L2 (no new atomic surface).** Every binding wraps a merged #106e-0 method; none opens a transaction. Atomicity inherited from `commit_vdk_rotation`/`commit_recovery_rekey` (#106b-2/#105a).
- **L3 (rotation NEVER auto-completes).** `vault_complete_rotation` requires the master password to cross IN; the engine never auto-rotates (prompt-on-revoke, #106b-2 §0a).
- **L4 (session-gated).** Every binding gates on `lock_vault().as_mut()?` before touching a secret — EXCEPT `vault_recover_from_shares` (lost-everything has no prior session; it creates the state). Confirm the gate posture per binding.
- **L5 (thin — zero new crypto/deps/atomic surface).** No new crate deps; uniffi stays pinned 0.31.1; `forbid(unsafe)` everywhere except the existing FFI scaffolding discipline; AGPL SPDX on new files.
- **L6 (errors carry no secret).** `From<CompositionError>` maps to `FfiError::{Recovery,Store}`; authentication-class collapses to `Validation{kind:"authentication"}`; exhaustive-match test.
- **L7 (testnet-only until D-011).** The whole surface stays Base-Sepolia-only until the external audit clears.
- **L8 (tests).** uniffi binding tests (handle-locked round-trips against an in-memory `VaultHandle::from_vault`) for each binding: rotation completes + surfaces unknowns; guardian-open returns an opaque Object whose bytes are NOT reachable via the exported API; recover round-trips; pending rows read; the secret-Object exposes only length; error mapping exhaustive. The end-to-end recovery/rotation are already anvil-E2E-proven at the core layer (#106e-0); the FFI tests are the binding-discipline gate. Full `cargo test --workspace`.
- **L9 (§16 ledger).** `git merge --no-ff`; DECISIONS/DEVLOG; Kelvin merge sign-off; its own #104a-style audit (focused on L1 — does any secret leak through a binding, a Debug, an error, or a readable Object accessor?).

## 5. Open decisions for Kelvin (Q-a … Q-f) — recommendation + plain-English stakes

- **Q-a (THE MAIN ONE) — the missing guardian-escrow ONBOARDING path.** There is NO production way to set up social recovery on a vault: `onboard_guardian_escrow` is called only by tests + the rotation/recovery *re-split*; the only initial-escrow writer is the test-only `__test_onboard_recovery_escrow`. So `complete_rotation` (reads the escrow) and `recover_from_shares` (re-splits the escrow) both presuppose an escrow a real vault can never create. **Recommend: FOLD a thin production onboarding method into #106e-1** — promote `__test_onboard_recovery_escrow` to a production `Vault::onboard_guardians(threshold, guardian_x25519_pubs, guardian_evm_addrs) -> FfiOnboardingResult{merkle_root, epoch}` (the same "promote the test helper" move #106e-0 did for the rotation commit; it wraps `onboard_guardian_escrow` + a single-tx escrow write), plus its `vault_onboard_guardians` FFI binding. *Plain English:* right now there's working code to RECOVER a vault but no code to first HAND your keys to guardians — so recovery can never actually be used. We should add the "set up my guardians" step or the whole recovery FFI is a button that does nothing. **Stakes: HIGH (end-to-end usability) but LOW build-risk** (a small promotion + one binding). Alternative: split it as its own slice (#106e-0b) built first — cleaner audit isolation but one more round-trip. **Needs your call: fold in, or split first?**
- **Q-b — does `vault_complete_rotation` READ the live on-chain set itself, or take it as a host param?** **Recommend: the FFI reads it engine-side** (async `block_on_local` + the fail-closed `read_authorized_set_v2`, taking `rpc_url`/`deployment_path` like the existing `vault_lock_with_drain`). *Plain English:* the list of "which devices are still authorized" is the thing a rotation rekeys against — if we let the host hand us that list, a buggy or malicious host could pass a wrong list and either lock out a real device or fail to revoke a removed one. Reading it ourselves from the chain keeps the engine the single source of truth. **Stakes: MEDIUM-HIGH (security)** — the host-passes variant is thinner but trusts the host with a security-critical input. The cost of reading-it-ourselves is the binding becomes async (block_on_local) + needs chain config.
- **Q-c — wrapping the opened `Share` + consuming it back.** **Recommend: a `SecretPassword`-style `FfiOpenedShare` opaque `Arc` Object** (zeroizing buffer, exposes only `byte_length()`); `vault_recover_from_shares` consumes `Vec<Arc<FfiOpenedShare>>` and pulls the `Share`s out engine-side. *Plain English:* a guardian's "opened share" is a secret; it must cross between devices as a sealed handle the app can hold and pass back but never read. **Stakes: LOW** (mechanical) — confirm the Object never exposes the raw scalar (the audit's central FFI check).
- **Q-d — recovery material (`wrapped_recovery`, `current_epoch`, `vault_id`) as raw byte params.** **Recommend: yes, raw length-validated `Vec<u8>`/`u64` params** — the host supplies them from a backup; the backup FORMAT stays deferred (6.x). *Plain English:* on a brand-new phone there's nothing local to read, so the recovery blob has to come from wherever the user stashed their backup; we just take the bytes and the format question waits. **Stakes: LOW-MEDIUM** — pin that these are params, not store reads.
- **Q-e — split #106e-1?** Tied to Q-a. **Recommend: ONE slice for the 4 recovery/rotation bindings; onboarding per Q-a (fold = a small 2nd half, or split = #106e-0b first).** *Plain English:* keep the FFI bindings together; the only thing that might be its own piece is the guardian-setup step. **Stakes: LOW (process).**
- **Q-f — confirm pairing/device-add FFI is OUT (→ #106e-2).** **Recommend: yes** — #106e-1 is recovery + rotation + guardian-open only; QR/short-code/SAS pairing + `vault_add_device` are #106e-2. *Plain English:* "add a new phone by scanning a code" is a separate chunk of UI plumbing; this slice is the recovery/rotation buttons. **Stakes: LOW (scope).**

## 6. Places that do NOT compose cleanly into a thin binding (flagged)
- **The onboarding prerequisite (Q-a)** — the single non-thin gap; the recovery FFI is a dead surface without a production onboarding path.
- **`complete_rotation` needs the live set** (Q-b) — the one binding that isn't a pure pass-through; either it goes async to read the chain, or it trusts a host-supplied set.
- **`recover_from_shares` is the one un-gated binding** (L4) — lost-everything runs without a prior session; confirm it does not require `as_mut()` to already hold a `Some(Vault)` the way the others do (it creates the unlockable state).
- **`Arc<FfiOpenedShare>` → `Vec<Share>`** (Q-c) — pulling an owned `Share` out of an `Arc` shared Object needs `Arc::try_unwrap` (fails if the host kept a ref) or an internal clone; pick the discipline that keeps zeroization intact.
