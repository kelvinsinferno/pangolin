<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# MVP-4-L (L-B) — Recoverer wizard (closes the loop) — plan-gate DRAFT

**Status: DRAFT — awaiting Kelvin sign-off.** Parent plan-gates: [mvp4-l-recovery-ux.md](mvp4-l-recovery-ux.md) (decomposition §1, L-B row — *the hardest, last*) + [mvp4-l-a-guardian-onboarding.md](mvp4-l-a-guardian-onboarding.md) + [mvp4-l-c-guardian-help.md](mvp4-l-c-guardian-help.md) + [mvp4-l-0c-backup-sealed-shares.md](mvp4-l-0c-backup-sealed-shares.md) (the engine prereq just merged). L-0c unblocked the last data path: the recoverer's decode now yields the M sealed shares to distribute. L-B is now a thin UX slice over the complete FFI surface — but it is the **largest L-slice by step-count**: a 7-step multi-day resumable wizard with its own Rust-side state for the in-flight opened-share accumulator.

> **This slice builds:** a `RecoverVaultWizard.tsx` that drives the recovering-user flow end-to-end: decode the backup envelope (paste text + 24-word phrase) → preview the target vault + roster → initiate on-chain (broadcasts `initiateRecovery`, engine generates the ephemeral X25519 keypair + persists) → emit M per-guardian request blobs (one for each guardian; the blob shape is exactly what L-C's `recoveryDecodeRequest` consumes) → collect re-sealed share blobs (one per cooperating guardian, paste-in, each ingested via `vault_recovery_ingest_share` whose `Arc<FfiOpenedShare>` handles accumulate Rust-side) → poll on-chain status until `approval_count >= threshold` AND `now >= initiated_at + 72h` → finalize on-chain (`vault_finalize_recovery`) → enter a NEW master password → drive `vault_recover_from_backup` to rebuild THIS local vault as the recovered vault. NO new crypto, NO new on-chain primitives, NO contract change. Testnet-only.

---

## 0. One-paragraph summary

L-B closes the recovery loop. The user starts on a **fresh device** — they've installed Pangolin, created a new local vault file with a new master password (the standard create-vault flow, not L-B), unlocked it, and that vault is now Active. Inside RecoveryScreen they click "Recover a vault" and drive L-B against the fresh vault as the *host* — at the end, `vault_recover_from_backup` **REBUILDS that vault** in-place: its `vault_id` rotates to the lost vault's, its VDK becomes the recovered one, it's re-keyed under whatever new master password the user entered at the final step (which can be the same or different from their fresh-vault password — both work, the fresh password is now gone after the rekey). This is **destructive** to the fresh local vault's prior contents (a brand-new vault has no contents, so in practice this is fine — the wizard's first step shows a clear "this rebuilds THIS vault from the backup" warning). The whole flow spans days (72h delay on-chain), so the wizard must be **resumable** — closing the app mid-recovery and re-opening it has to land back in the right step. The persisted ephemeral X25519 keypair (already engine-side, L-0a-2.2) survives close; the in-flight opened shares (opaque `Arc<FfiOpenedShare>`) do **not** — those live only in Rust memory and the user re-collects them on re-open.

---

## 1. Scope (build + test)

### What ships
- One new desktop screen — `RecoverVaultWizard.tsx` — driven from a new "Recover a vault" card on `RecoveryScreen.tsx` (always visible when no other wizard is up, gating per L-C's mutual-exclusion fix).
- **Six** new Tauri commands wrapping the existing FFI:
  1. `recovery_decode_backup(text, phrase)` — pure decode (wraps `vault_decode_backup`); accepts EITHER byte-form OR text-form envelope; returns the parsed `BackupContents` shape (incl. `sealedShares` from L-0c).
  2. `recovery_initiate(password, target_vault_id, proposed_authority, expires_at)` — wraps `vault_initiate_recovery`; `spawn_blocking` (chain broadcast).
  3. `recovery_recipient_identity(target_vault_id)` — wraps `vault_recovery_recipient_identity`; inline (local store read).
  4. `recovery_target_status(target_vault_id)` — wraps `vault_read_recovery_status` *with the target vault id*, distinct from L-D's `recovery_health` (which reads the CURRENT vault's id); `spawn_blocking` (chain read).
  5. `recovery_ingest_share(sealed_blob, target_vault_id, attempt_nonce)` — wraps `vault_recovery_ingest_share`; pushes the resulting `Arc<FfiOpenedShare>` into the new `VaultState.recovery_opened_shares` slot (see below); returns the new accumulator length so the UI can render "X of t collected".
  6. `recovery_complete(target_vault_id, backup_text, phrase, new_password)` — drives finalize + recover-from-backup in sequence inside a single `spawn_blocking`: `vault_finalize_recovery` then takes the accumulated opened shares out of `VaultState` + drives `vault_recover_from_backup`. Returns the new epoch.
- **New `VaultState` slot:** `recovery_opened_shares: Mutex<Vec<Arc<FfiOpenedShare>>>` — Rust-side accumulator. Cleared on `vault_close` and on any error path that re-routes to "start over". JS NEVER holds these handles (Q-a).
- TS wrappers + DTOs in `apps/desktop/src/ui/lib/invoke.ts`.
- Rust closed-vault tests for the five session-gated commands + a pure-decode smoke for `recovery_decode_backup`.
- Frontend vitest covering: decode + preview happy path, decode error (wrong phrase), initiate happy path, request-blob shape pinned to what L-C's `recoveryDecodeRequest` expects, ingest accumulates count, status polling shows approval_count + 72h-elapsed gating, finalize gated until both pass, complete (recover-from-backup) happy path, resume-on-reopen probes chain + persisted recipient, destructive-replace warning surfaced before initiate.

### What does NOT ship
- Mainnet (D-011 gated).
- Camera-scan ingestion (parks behind MVP-4-I camera-permission work; Q-a covers transport choice).
- Multi-vault recovery in one wizard pass (one target vault per L-B run).
- Programmatic recovery REQUEST blob persistence (if the user closes the app mid-collect, they re-paste shares — but the chain knows the attempt is alive + the persisted ephemeral key still opens incoming blobs).
- Recoverer-side **cancel** during an in-flight attempt (the contract's `cancelRecovery` is `msg.sender == vaultAuthority`-only; the recoverer is by definition NOT the current authority, so cancel-on-recoverer-side is unsupported per the L-0a-2.2 plan-LOCK).
- "Recover into an EXISTING (non-fresh) vault" — L-B always rebuilds the host vault. Recovering into a vault that already has contents is out of scope.

---

## 2. Decisions to resolve (each: pick ONE)

### Q-a — Opened-share accumulator location (THE main design decision)
The recoverer collects t opened shares before finalizing + recovering. Each `vault_recovery_ingest_share` call returns an `Arc<FfiOpenedShare>` which is a uniffi opaque Object — secret bytes inside, NOT serializable to JS. Where do these accumulate during the multi-step flow?

1. **Rust-side `Mutex<Vec<Arc<FfiOpenedShare>>>` in `VaultState`** (Recommended). The JS side gets back only a count after each ingest. The accumulator is cleared on vault-close and on any "start over" path. `recovery_complete` takes the Vec out + passes to `vault_recover_from_backup` in one `spawn_blocking`. Clean L1 posture (opaque handles never cross the FFI in either direction post-ingest); matches the existing VaultState pattern.
2. **Opaque JS handles** — each ingest returns an integer index into a Rust-side `Vec`, JS holds the indices, passes them all back to `recovery_complete`. More state surface on the JS side; doesn't materially improve security.

**Recommend Option 1 (Rust-side accumulator).** Cleanest L1 boundary; smaller JS state; matches the existing `VaultState` ownership model.

### Q-b — Resume strategy on wizard re-open
The flow can span days (72h on-chain delay). If the user closes the app at any point and reopens it, the wizard must land back in the correct step.

1. **Chain-driven probe** (Recommended). On wizard open, prompt for the backup + phrase (always required — neither persists). After decode, call `recovery_target_status(vault_id)` AND `recovery_recipient_identity(vault_id)`. If both report a live PENDING attempt with a matching nonce, jump to the share-collection step (user re-pastes shares; the accumulator is empty). If the chain reports None / Finalized / Canceled or the persisted identity is absent, treat as a fresh start.
2. **Local-only persistence** — additionally persist a local recovery-state JSON. Doesn't help (the in-memory share Arcs still can't be reconstructed); adds attack surface; no real UX win since the user has to re-paste shares anyway.

**Recommend Option 1 (chain-driven probe).** Engine is source of truth (L11 discipline); zero new on-disk state; user pays the "re-paste shares" cost in exchange for never holding secret material across the close boundary.

### Q-c — Destructive-replace warning presentation
The final step rebuilds the host vault. A user could miss this if it's just a sentence at the bottom of step 1.

1. **Big, explicit warning card before the wizard even starts** (Recommended). When the user clicks "Recover a vault" on RecoveryScreen, they first land on a confirmation card (`Card variant=warning`) that says: "This will REBUILD this vault from your backup. All current data in THIS vault will be replaced. Continue?" with explicit "Cancel" + "I understand, continue" buttons.
2. **Inline warning at step 1** — text next to the decode form. Easier to skip; smaller cost to mis-click.

**Recommend Option 1 (pre-wizard warning card).** Forcing one explicit confirm before the destructive flow starts is the cheap insurance against the user picking the wrong button in the RecoveryScreen card. Almost zero engineering cost; significant UX safety.

### Q-d — Polling cadence while waiting for approvals + delay
On the share-collection / waiting step, the wizard displays "X of t shares received locally · Y of t approvals on-chain · finalize available in N hours". The status polls `recovery_target_status`.

1. **Every 30s** (Recommended). Aggressive enough that the user sees progress within a screen-glance; slow enough to not hammer the public RPC.
2. **Every 5 minutes** — much lighter on the RPC; long enough that the user might think the UI is dead.
3. **Manual refresh button only** — pure pull model. Lowest RPC load; worst UX (the user manages the cadence).

**Recommend Option 1 (30s).** Matches the existing health-panel cadence convention; the wizard is open relatively briefly per session (the user comes back to it across days; each session is minutes, not hours).

---

## 3. Files

### New
- `apps/desktop/src/ui/screens/RecoverVaultWizard.tsx` — the wizard (steps: pre-warn → decode → preview → initiate-password → distribute-requests → collect-shares + polling → finalize → recover-new-password → done).
- `apps/desktop/src/ui/screens/RecoverVaultWizard.test.tsx` — vitest (~10 cases per the §1 list).

### Edited
- `apps/desktop/src/state.rs` — `VaultState` gains `recovery_opened_shares: Mutex<Vec<Arc<FfiOpenedShare>>>`; `vault_close` clears it; new accessor methods `push_opened_share` / `take_opened_shares` / `clear_opened_shares` / `opened_share_count`.
- `apps/desktop/src/commands/recovery.rs` — six new `#[tauri::command]` handlers + new closed-vault tests for the five session-gated commands + a pure-decode smoke + the accumulator unit tests (push, take, clear, count).
- `apps/desktop/src/lib.rs` — register the six new commands.
- `apps/desktop/src/ui/lib/invoke.ts` — six TS wrappers + DTOs (`BackupContents` mirroring the FFI shape; `RecipientIdentity`; reuse `RecoveryHealth` → `RecoveryStatus`; `RecoveryResult`).
- `apps/desktop/src/ui/screens/RecoveryScreen.tsx` — add the "Recover a vault" card (gated by `!anyWizardOpen`; opens the wizard).
- `apps/desktop/src/ui/screens/RecoveryScreen.test.tsx` — add a card-visibility case for L-B.
- `apps/desktop/src/commands/vault.rs` — `vault_close` calls `state.clear_opened_shares()` before clearing the slot (defense-in-depth: a close while shares are in-flight wipes them).

### Untouched (verify, then leave alone)
- All Rust crates other than `apps/desktop/`. The FFI surface is complete after L-0c.
- L-A and L-C wizards (their state machines are independent).
- `contracts/*` — no contract change.

---

## 4. L-invariants

- **L1.** Secrets crossing the boundary: the master password (for `vault_initiate_recovery`'s parity slot AND the new master password at `recovery_complete`); the 24-word phrase (for `recovery_decode_backup`). NO opened-share bytes ever cross the FFI to JS — they live as opaque `Arc<FfiOpenedShare>` in the Rust accumulator. Cleartext from `vault_recover_from_backup` is the recovered VDK, which never crosses out (engine consumes it inside `commit_recovery_rekey`).
- **L3 (fail-closed).** Decode failures → typed `Validation`. RPC failures → typed `Chain`. The 72h-elapsed + approval-count gates are CONTRACT-enforced; the wizard's display of "Finalize" is UI-side defense-in-depth but the FFI revalidates.
- **L4 (session-gated).** The five handle-bearing commands first-line `state.require_open()`. `recovery_decode_backup` is pure (no handle).
- **L6.** Error messages carry no secrets.
- **L11 (engine is source of truth).** The chain probe is the authoritative resume signal; the wizard NEVER infers state from JS-side variables.
- **L13.** All chain calls run via `spawn_blocking` per the pairing/L-A/L-C precedent.

---

## 5. Adversarial-audit focus (predictable LOW classes the auditor should hunt)

- **Accumulator lifecycle** — verify `recovery_opened_shares` is cleared on `vault_close`, on `vault_lock` (if applicable), AND on the final `recovery_complete` path (after the shares are moved out + consumed). A leftover share in a closed/locked state is an L1 violation.
- **Resume invariants** — the wizard MUST require both the backup AND the chain state to agree before jumping to the share-collection step. If the chain says PENDING but the persisted recipient_identity differs from what the wizard expects (e.g., a DIFFERENT recovering device initiated a competing attempt), the wizard must surface a clear error, not silently use stale state.
- **Threshold gating** — the wizard gates the "Continue to finalize" button on `accumulator_count >= threshold`. Verify the count comparison is sound (off-by-one); verify the gating accepts EXACTLY threshold shares (more is fine; fewer must fail).
- **72h-elapsed gating** — `initiated_at` is unix-seconds on-chain. Compare `Date.now() / 1000 >= initiated_at + 72*3600`. Verify no overflow / signed-vs-unsigned trap.
- **Per-guardian request-blob shape match** — the blob JS generates MUST be byte-identical to what L-C's `recoveryDecodeRequest` expects. Trace one through. A typo'd field name would make the entire L-B → L-C wire incompatible.
- **L-0c sealed-shares index correctness** — verify the wizard sends `sealedShares[i]` to the guardian whose pubkey is `guardianX25519Pubs[i]` (and signer is `guardianSet[i]`). A misordering would make every release fail authentication.
- **`recovery_complete` atomicity** — the finalize + recover-from-backup pair runs in one `spawn_blocking`. Verify that if finalize succeeds and recover-from-backup fails, the user lands in a clear "chain authority rotated but local rebuild failed — your data is intact on-chain, retry the rebuild" state (NOT a confused half-state).
- **Master-password parity slot** — `vault_initiate_recovery` takes `master_password` for forward-compat parity; verify the L-B wizard collects + passes it correctly (mirror L-A's `recovery_set_guardian_set` pattern).
- **errMessage parity** — same nested-Validation unwrap pattern as L-A/L-C.
- **broadcastGuard** — every chain-broadcasting step must have a re-entry guard (mirrors L-A's broadcastGuard).
- **Destructive-replace warning** — verify the warning card is the SOLE entry path to the wizard (no backdoor route bypasses the confirm).

---

## 6. Gate (pre-merge, all green required)

1. `cargo +nightly fmt --all -- --check`
2. `cargo clippy --workspace --all-targets -- -D warnings`
3. `cargo test --workspace`
4. `forge fmt --check` (defense)
5. `forge test` (defense)
6. `pnpm --filter @pangolin/desktop typecheck`
7. `pnpm --filter @pangolin/desktop lint`
8. `pnpm --filter @pangolin/desktop test` (vitest)

---

## 7. Branch + merge

- Branch: `mvp4-l-b-recoverer-wizard` off `main` (currently `8bff44d`).
- Per-commit granularity: 5 logical commits — (1) `VaultState` accumulator + `vault_close` clears; (2) six FFI wrapper commands + Rust tests; (3) TS wrappers + DTOs; (4) wizard + RecoveryScreen integration + vitest; (5) audit-fix commit(s).
- Merge via `git merge --no-ff` per `pangolin_merge_workflow.md` §16 + push immediately.
- Watch CI proactively per `feedback_ci_proactive_recovery.md`.

---

## 8. Recommendation

Lock the four decisions per the recommendations above (Q-a..d all = Option 1), put L-B on `mvp4-l-b-recoverer-wizard`, ship as a single branch with the 5-commit granularity. Likely the **largest L-slice by code volume** (~2× L-C: 6 commands vs 3, 7-step wizard vs 5-step, new VaultState accumulator + lifecycle plumbing). Expect 1 dense session for the build + a more thorough audit pass than usual given the multi-step + multi-day surface. After L-B + a CI-green merge, the recovery loop is **end-to-end shipped** on testnet — owner sets up guardians, owner creates backup, owner loses everything, recoverer rebuilds. The remaining MVP-4-L follow-ups (Etherscan verification of RecoveryV2 deploy, the `vault_create_backup` MUST-be-Active fix if any, etc.) are housekeeping.
