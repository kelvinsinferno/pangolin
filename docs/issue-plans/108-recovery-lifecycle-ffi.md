<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Issue #108 — on-chain recovery lifecycle FFI entry points — plan-gate LOCKED

**Status: LOCKED — decisions are minor (mirror #106e-1's recovery/rotation FFI patterns; self-locked 2026-05-23 with no genuine forks).** Closes the remaining FFI gap so the host app can drive the full RecoveryV1 lifecycle (setGuardianSet → initiate → approve×t → finalize / cancel) end-to-end. Independent of #109 (recovery backup format).

## 0. One-paragraph summary

`#106e-1` exposed the OFF-chain recovery primitives via FFI (`vault_onboard_guardians`, `vault_guardian_open_share`, `vault_recover_from_shares`). The ON-chain RecoveryV1 lifecycle stayed unwrapped — the pure Rust primitives in `pangolin_chain::recovery_client` (`set_guardian_set_v1`, `initiate_recovery_v1`, `approve_recovery_v1`, `cancel_recovery_v1`, `finalize_recovery_v1`) + the readers (`read_vault_authority_v1`, `read_live_attempt_v1`) all exist + are E2E-tested by the `recovery_lifecycle_against_anvil` test, but no host can call them. #108 adds **thin uniffi bindings** in `pangolin-ffi::recovery_lifecycle` following #106e-1's pattern verbatim: `VaultHandle::lock_vault().as_mut()?` session gate, `block_on_local` for async chain calls, `FfiChainConfig` for the RPC + deployment, `SecretPassword` opaque master-password ingress, `FfiError::Chain` for fail-closed chain-read errors, length-validated `Vec<u8>` for byte-array params, no new crypto/deps/atomic surface. **The engine computes the merkle proof internally** for `approve_recovery` (the host supplies the guardian SET; the FFI builds the proof against the active session's signer). This keeps the engine the single source of truth + matches #106e-1's "host doesn't pass derived data" posture.

## 1. Scope — 5 lifecycle bindings + 2 read bindings

In a new `crates/pangolin-ffi/src/recovery_lifecycle.rs` (register in `lib.rs`):

1. **`vault_set_guardian_set(handle, master_password, config, guardian_evm_addrs: Vec<Vec<u8>>, threshold: u8) -> Result<FfiTxOutcome, FfiError>`** — manager-only. Engine validates each address is 20 bytes, computes the merkle root over them, signs+broadcasts `setGuardianSet`. Session-gated (Active). `FfiTxOutcome { tx_hash: Vec<u8>, block_number: u64, schema_version: u16 }`.
2. **`vault_initiate_recovery(handle, master_password, config, target_vault_id: Vec<u8>, proposed_authority: Vec<u8>, expires_at_unix: u64) -> Result<FfiTxOutcome, FfiError>`** — driven by the NEW (post-loss) device. Engine validates lengths (`vault_id`=32, `proposed_authority`=20), signs+broadcasts `initiateRecovery`. Session-gated (Active — the new device has a fresh vault unlocked under its own master password before initiating recovery on a target vault).
3. **`vault_approve_recovery(handle, config, target_vault_id: Vec<u8>, attempt_nonce: u64, proposed_authority: Vec<u8>, expires_at_unix: u64, guardian_set: Vec<Vec<u8>>) -> Result<FfiTxOutcome, FfiError>`** — guardian role. Engine validates each guardian address (20 bytes); computes the merkle proof for the active session's signer against the guardian_set; builds + signs the `Approve` EIP-712 digest bound to the live `(attempt_nonce, proposed_authority, expires_at)`; broadcasts `approveRecovery`. Session-gated (Active — the guardian must be in their own unlocked vault, which is the source of the signing key). NO master password param — the approval is a guardian-DEVICE operation that doesn't re-wrap any local state.
4. **`vault_cancel_recovery(handle, master_password, config, target_vault_id: Vec<u8>) -> Result<FfiTxOutcome, FfiError>`** — vault-authority-only (the current `vaultAuthority` of the target vault, enforced by the contract via `msg.sender`). Session-gated.
5. **`vault_finalize_recovery(handle, config, target_vault_id: Vec<u8>) -> Result<FfiTxOutcome, FfiError>`** — anyone may call after the 72h delay. The session-gating relaxes here: the handle just needs to be loaded (any vault, even Locked — anyone with a configured RPC + the target vault_id can finalize). Use `as_mut()?` only.

Read bindings:
6. **`vault_read_vault_authority(config, target_vault_id: Vec<u8>) -> Result<FfiVaultAuthority, FfiError>`** — no handle needed; reads the current on-chain authority. `FfiVaultAuthority { address: Vec<u8> /* 20 */, schema_version: u16 }`. Fail-closed on chain read error.
7. **`vault_read_recovery_status(config, target_vault_id: Vec<u8>) -> Result<FfiRecoveryStatus, FfiError>`** — reads the current attempt state. `FfiRecoveryStatus { status: u8 /* mirrors RecoveryStatus enum 0..=3 */, proposed_authority: Vec<u8>, attempt_nonce: u64, initiated_at: u64, approval_count: u8, schema_version: u16 }`.

Plus: the FFI result records, error mapping (`ChainError` → `FfiError::Chain`/`Validation`), exhaustive-match test, length-validation tests, fail-closed-on-bad-rpc tests, session-gate tests.

**Deferred (NOT this slice):**
- Any change to RecoveryV1.sol or the chain primitives themselves.
- A coupled FFI anvil E2E driving the full lifecycle through the new bindings (file as a follow-up if warranted; the chain primitives' lifecycle E2E `recovery_lifecycle_against_anvil` already covers the underlying flow, and #109's backup format work is more impactful).
- The recovery UX state machine (host responsibility).

## 2. Splittable? — no

5+2 thin bindings + the result records share one shape (lock → gate → validate → block_on_local → call merged primitive → map result). Too small + too coupled to split. ONE PR, builder → focused audit (L1 secret hygiene + the merkle-proof engine-internal property + fail-closed reads) → merge.

## 3. Design (mirrors #106e-1)

Every binding is the #100 idiom: `let mut guard = handle.lock_vault(); let vault = guard.as_mut()?;` (the L5 session gate) → length-validate inputs → bridge master_password to `SecretBytes` if relevant → `block_on_local(async { primitive(...).await })?` for any chain call → map `Result`. The merkle proof for `approve_recovery` is computed INSIDE the FFI binding (the engine builds the leaf for the active signer + walks the supplied guardian_set; the host never holds the proof).

### Key wiring details
- Guardian merkle leaves use the existing `pangolin_chain::recovery_client::guardian_leaf` (= `keccak256(abi.encode(addr))`, OZ-StandardMerkleTree-compatible, sorted-pair-keccak).
- `Approve` EIP-712 digest uses the existing `pangolin_chain::recovery_signing::build_signed_approval_v1`.
- `setGuardianSet`'s merkle root via `pangolin_chain::recovery_client::build_guardian_root`.
- The active vault's signer comes from `Vault::evm_wallet()` (the established #100 pattern — no key ever crosses the FFI).
- `ChainEnv` is hardcoded `BaseSepolia` (testnet-only/D-011; never crossed FFI), same as `vault_complete_rotation`.

## 4. L-invariants (mirror #106e-1)
- **L1 zero-secret-crosses-FFI.** Master passwords cross only as `Arc<SecretPassword>`. Signing keys stay inside `Vault::evm_wallet()`. Merkle proofs/leaves are computed engine-side. Outputs are tx hashes / block numbers / non-secret status (`status enum`, `attempt_nonce`, `proposed_authority`, `approval_count`).
- **L2 no new atomic surface.** Each binding wraps ONE existing `pangolin_chain::recovery_client` primitive. No multi-step state machine.
- **L3 fail-closed on chain-read errors.** A bad RPC / missing contract / read error returns `FfiError::Chain` and the binding NEVER proceeds with partial/guessed state (mirrors `vault_complete_rotation`'s fail-closed live-set-read).
- **L4 session-gating per binding.** `set_guardian_set` / `initiate` / `approve` / `cancel` require Active. `finalize` requires only loaded (any vault — `finalize` is contract-anyone-may-call after delay). Reads require only loaded handle (or possibly no handle — see Q-a).
- **L5 no new external crates; uniffi pinned `=0.31.1`; `forbid(unsafe)`; AGPL SPDX.**
- **L6 testnet-only/D-011.** Whole surface stays Base-Sepolia-only until the external audit clears.
- **L7 errors carry no secret.** `From<ChainError> for FfiError` maps every variant; nothing embeds key material.
- **L8 (tests).** Hermetic FFI binding tests: length-validation negatives, session-gate negatives, fail-closed on bad RPC. The chain primitives' lifecycle is already anvil-tested by `recovery_lifecycle_against_anvil` (#103); the FFI plumbing is the new surface. FULL `cargo test --workspace` is the gate (#106b-1 lesson). `cargo fmt --check` + `cargo clippy -p pangolin-ffi --all-targets -- -D warnings`.
- **L9 (§16 ledger).** `git merge --no-ff`; DECISIONS/DEVLOG; Kelvin merge sign-off; focused audit (L1 secret hygiene + merkle-proof-computed-internally + fail-closed reads — small scope).

## 5. Open decisions — pre-locked

- **Q-a (merkle proof computation): engine internal.** The FFI takes `guardian_set: Vec<Vec<u8>>` (the M guardian EVM addresses) + computes both the leaf for the active signer and the proof against the set engine-side. Host never holds the proof. (Alternative: host pre-computes — rejected for #106e-1-style "engine is the source of truth.")
- **Q-b (reads need a handle?): yes for `vault_read_*`.** Pass `handle` to gate against placeholder handles + future flexibility (might want to record the read in vault telemetry). Pure "no handle" reads would be cleaner but less consistent with the rest of the FFI. Open to override.
- **Q-c (finalize gating): loaded-only, not Active.** Any device can complete the on-chain finalize after the 72h delay (the contract enforces the timing); a Locked vault is acceptable so a recovery can finalize even if the local session expired.
- **Q-d (anvil FFI E2E): defer.** The chain primitives' lifecycle is already anvil-tested by `recovery_lifecycle_against_anvil`; the FFI plumbing is thin enough that hermetic tests cover the discipline.

If any of these are wrong, raise it; otherwise build proceeds with these decisions.

## 6. Places that need care
- **Length validation must come BEFORE `block_on_local`.** A bad `vault_id` / `proposed_authority` / guardian address should fail-fast with `FfiError::Validation` (no wasted RPC), mirroring `vault_complete_rotation`'s active-session-pre-check pattern.
- **`approve_recovery`'s active session IS the guardian's vault.** The guardian uses THEIR OWN vault's signer to approve — the binding doesn't know "is this device a guardian?" The contract enforces (`isRegisteredGuardian` via the merkle proof). The FFI passes the active signer through; if they aren't actually in the merkle root, the contract reverts (turn the test RED).
- **`finalize` is permissionless on-chain.** The FFI passes through; anyone with a configured RPC + the target vault_id + (optionally) the will to pay gas can call. This matches the contract's design (the security is the quorum + delay, not msg.sender gating).
