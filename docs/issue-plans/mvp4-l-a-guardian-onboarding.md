<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# MVP-4-L (L-A) — Guardian onboarding UX (owner) — plan-gate DRAFT

**Status: LOCKED — Kelvin sign-off 2026-05-30.** Q-a = **Option 1** (paste-only). Q-b = **Option 1** (extend RecoveryScreen). Q-c = **Option 1** (resume + idempotent retry). Q-d = **Option 1** (hard refuse self-as-guardian). Q-e = **Option 1** (auto-refresh health panel after success). Parent plan-gates: [mvp4-l-recovery-ux.md](mvp4-l-recovery-ux.md) (decomposition §1, L-A row) + [mvp4-l-0-engine-gapfill.md](mvp4-l-0-engine-gapfill.md) (gap G-2 closed by L-0b). L-0a-1 (RecoveryV2 + on-chain G-1/G-3) + L-0a-2 (off-chain G-1 transport) are already merged, so L-A is now an unblocked thin-UX slice over the existing FFI surface.

> **This slice builds ONLY:** the owner-side wizard that collects M guardian invites + a threshold `t`, then drives `vault_onboard_guardians` (off-chain Shamir split + seal) followed by `vault_set_guardian_set` (on-chain merkle root + self-bootstrap as `vaultAuthority`). NO guardian-side flow (that's L-C), NO recovery wizard (that's L-B), NO net-new crypto, NO net-new FFI. Testnet-only.

---

## 0. One-paragraph summary

L-A is the first of three multi-party recovery UX slices. The owner gathers M guardian "invites" — the non-secret `(x25519_sealing_pub, signer)` blobs each guardian produced via `vault_export_guardian_identity` (L-0b) — picks a threshold `t`, confirms their master password, and a two-step engine transaction wires up social recovery: first off-chain (Shamir-split a fresh `RecoveryWrapKey` into M sealed shares, persist the roster) then on-chain (commit the merkle root of the `M` guardian EVM addresses + self-bootstrap the vault authority to this device's EVM wallet, via `setGuardianSet` on RecoveryV2 at `0xf0E08fd0…06CA`). Nothing here changes any contract or new FFI — it's UX glue + thin Tauri commands over an FFI surface that already has 100% test coverage for the closed-vault failure-mode (per the L-D LOW-2 precedent).

---

## 1. Scope (build + test)

### What ships
- One new desktop screen — `SetupGuardiansWizard.tsx` — driven from a new "Set up guardians" card on `RecoveryScreen.tsx` (visible only when the on-chain status read says NOT initialized).
- Three new Tauri commands wrapping the existing FFI:
  1. `guardian_invite_decode(text)` — pure decode of a guardian-supplied invite (text OR base32). Wraps `guardian_invite_decode_string` / `guardian_invite_decode_bytes`. NO handle, no session.
  2. `recovery_onboard_guardians(threshold, pubs)` — wraps `vault_onboard_guardians`. Session-gated FFI-side.
  3. `recovery_set_guardian_set(password, evm_addrs, threshold)` — wraps `vault_set_guardian_set`. Session-gated + chain-broadcasting; runs via `spawn_blocking` like the pairing chain commands.
- TS wrappers + DTOs in `apps/desktop/src/ui/lib/invoke.ts`.
- Rust closed-vault tests in `apps/desktop/src/commands/recovery.rs` for the two session-gated commands (mirroring the L-D LOW-2 `require_open` pattern).
- Frontend vitest for `SetupGuardiansWizard.tsx` covering: invite-paste happy path, t/M bounds validation, self-as-guardian guard (Q-d), partial-failure resume banner (Q-c).

### What does NOT ship
- Mainnet (D-011 gated).
- Recovery wizard (L-B) and guardian-side approve+release wizard (L-C).
- Camera-scan ingestion of guardian invites (parks behind MVP-4-I camera-permission work; Q-a covers).
- Editing / rotating the guardian set after on-chain commit (the contract is set-once; out of scope for L-A).
- Gas pre-funding for the manager device's `EvmWallet` (assumes Base Sepolia ETH already present; matches MVP-4-J/K convention).
- A "Become a guardian for someone else" surface — L-0b's `vault_export_guardian_identity` is the engine, but the user-facing "share your invite" affordance is part of the L-C plan-gate (the guardian's flow as a whole).

---

## 2. Decisions to resolve (each: pick ONE)

### Q-a — Transport for collecting guardian invites
The owner needs to ingest the M guardian invites the guardians produced via L-0b. Options:
1. **Paste-only.** Owner gets the invite text from the guardian (any out-of-band channel: Signal, email, paper) and pastes M of them. Simplest. ZERO new platform dependencies.
2. **Paste + QR-display.** Owner can ALSO paste the byte-form QR if the guardian rendered it (the L-0b FFI exposes both `bytes` and `string_form`). Still no camera, no platform-specific permissions. Adds a `<QRCode>` import + a tiny "decode pasted base64" branch.
3. **Paste + QR-display + camera-scan.** Mirror MVP-4-I's three modes. Camera-scan is "likely dead on Linux/WebKitGTK" per [`pangolin_environment_quirks.md`](../../.claude/projects/.../memory/pangolin_environment_quirks.md) (memory note); the L-A wizard would degrade gracefully to paste. Adds `jsqr` dep + `<video>` capture path.

**Recommend Option 1 (paste-only)** for L-A. Rationale: an invite is a one-time, low-frequency, identity-establishing artifact — the user can be expected to copy-paste it deliberately, the guardian can render it however they choose, and we avoid the Linux camera-permission rabbit hole. Camera-scan can be a follow-up alongside the broader MVP-4-I camera fix.

### Q-b — Where the wizard lives
1. **Extend `RecoveryScreen.tsx`.** Add a "Set up guardians" card (visible when health-panel says NOT initialized); clicking it opens the wizard as a modal-like child of the same screen. Owner always lands on Recovery → either creates a backup (L-D) OR sets up guardians (L-A).
2. **New top-level `GuardiansScreen.tsx`** at parity with `DevicesScreen.tsx`. Reached from a nav entry. Symmetry with the device-management surface; better discoverability long-term.

**Recommend Option 1 (extend RecoveryScreen).** Recovery is the conceptual home of guardians + backup; splitting them across two top-level screens early would fragment the mental model BEFORE L-B / L-C land. Option 2 is the right answer at L-C time, when guardian help, guardian invite display, and active recoveries all want their own room.

### Q-c — Partial-failure semantics
The engine work is two FFI calls. Step 1 (`vault_onboard_guardians`) writes the off-chain escrow row + bumps the recovery epoch. Step 2 (`vault_set_guardian_set`) broadcasts on-chain — and if it reverts / RPC-times-out / runs out of gas, the user is in a half-state (off-chain seeded, no on-chain commitment).

1. **Resume + idempotent retry.** Show a clear "Guardians seeded but the on-chain step failed; retry the chain step" banner on the RecoveryScreen. Re-attempt is safe: `setGuardianSet` reverts `ErrGuardianSetAlreadyInitialized` if it landed on-chain, or proceeds cleanly if not. Off-chain re-onboard is NOT triggered — the existing escrow row is reused.
2. **Destructive rollback.** On step-2 failure, delete the off-chain escrow row + force the owner to re-collect all M invites. Discards the work the owner already did, re-leaks randomness on the next attempt, and forces the same guardians to re-paste their invites — pure penalty for the user.

**Recommend Option 1 (resume + idempotent retry).** Lower friction, matches the chain-mutation pattern from MVP-4-J/K. The resume banner queries `vault_read_vault_authority` to detect "off-chain epoch >0 but no chain authority" and surfaces accordingly.

### Q-d — Self-as-guardian guard
Should the wizard refuse if the owner pastes THIS device's OWN guardian invite (i.e., `x25519_sealing_pub == vault_export_guardian_identity().x25519_sealing_pub`)? An owner-as-guardian defeats the recovery threat model: if the owner loses all devices, the share sealed to the owner's device is unrecoverable, so the effective threshold becomes `t` of `M-1`.

1. **Hard refuse** with an inline error: "This is your own device's identity — guardians must be other people's devices."
2. **Warn only** — show the warning but let the user proceed.

**Recommend Option 1 (hard refuse).** This is a defense-in-depth gate against a user error that breaks the security model; not a paternalistic UI choice. Cheap; no real legitimate use case for self-as-guardian.

### Q-e — Refresh the health panel after success
After both engine steps succeed, should the wizard automatically refresh the RecoveryScreen's health panel (so the owner immediately sees `Authority: 0x… · Status: No recovery in progress`) before closing?

1. **Yes** — single chain-read call to `recovery_health`, free pageload-feel.
2. **No** — close + let the user manually refresh on next screen open.

**Recommend Option 1 (yes).** Confirms to the owner that the chain step landed; reuses the L-D health panel.

---

## 3. Files

### New
- `apps/desktop/src/ui/screens/SetupGuardiansWizard.tsx` — the wizard (steps: collect invites → pick threshold → confirm password → onboarding-progress → done|retry).
- `apps/desktop/src/ui/screens/SetupGuardiansWizard.test.tsx` — vitest (~8 cases per the §1 list).

### Edited
- `apps/desktop/src/ui/screens/RecoveryScreen.tsx` — add the "Set up guardians" card (gated on health-panel says NOT initialized) + the partial-failure resume banner (Q-c) + post-success health refresh (Q-e).
- `apps/desktop/src/commands/recovery.rs` — three new `#[tauri::command]` handlers (Q-d guard belongs in the WIZARD, not here, so backend stays stateless) + two new closed-vault tests.
- `apps/desktop/src/lib.rs` — register the three new commands in `tauri::generate_handler!`.
- `apps/desktop/src/ui/lib/invoke.ts` — three TS wrappers + DTOs (`GuardianInvite`, `OnboardingResult`, reuse `TxOutcome` if it already exists for L-0a-1/2).
- `apps/desktop/src/ui/screens/RecoveryScreen.test.tsx` — add cases for the new card visibility + resume banner.

### Untouched (verify, then leave alone)
- All Rust crates other than `apps/desktop/`. The FFI surface is complete; if anything turns out to need a new FFI we abort this slice + circle back with a follow-up plan-gate (forced-decision gate per the no-fake-decision-gates rule).
- `contracts/*` — no contract change.

---

## 4. L-invariants

- **L1.** The only secret crossing the new desktop ↔ FFI surface is the master password (for `vault_set_guardian_set`'s forward-compat parity slot). Crosses via `SecretPassword::new(password.into_bytes())` exactly as `recovery_create_backup` already does; zeroize on consume. Guardian invites + EVM addresses + sealing pubkeys are all explicitly non-secret per L-0b.
- **L3 (fail-closed).** Chain failures surface as `DesktopError::Chain` → the wizard shows the resume banner (Q-c). No fabricated success.
- **L4 (session-gated).** Both `recovery_onboard_guardians` + `recovery_set_guardian_set` first-line `state.require_open()`; closed-vault tests prove the guard. `guardian_invite_decode` is PURE (no handle).
- **L6.** No error message carries any secret (passwords, sealing pubkeys treated as non-secret per L-0b, no share material is in scope).
- **L13.** Chain reads use `spawn_blocking` per the pairing-chain-commands trap (the FFI drives a nested runtime that would panic inline).

---

## 5. Adversarial-audit focus (predictable LOW classes the auditor should hunt)

- Self-as-guardian guard — verify it's enforced in the wizard AND that the wizard can't be bypassed by direct invoke from the devtools (the FFI `vault_onboard_guardians` does NOT check this; the gate is UX-side only by design, since the engine has no concept of "this device's identity vs another's" — but that means the wizard MUST be the source of truth and the FFI MUST be marked accordingly).
- Partial-failure resume — verify the resume banner actually shows when off-chain step succeeded + on-chain step failed (mock the chain to revert; the banner should appear next open).
- t/M bounds — the contract enforces `t ∈ 2..=9`, `M ∈ 3..=15`, `t ≤ M`. The wizard validates locally; the FFI revalidates; the contract reverts. Triple-gated; verify each layer rejects the same bad inputs.
- Idempotence — re-running the wizard after a full success should refuse to onboard a second time (the contract reverts `ErrGuardianSetAlreadyInitialized`); the wizard should detect this proactively and route to "guardians already set up" rather than producing a confusing chain error.
- Capabilities — none of the new commands need a Tauri v2 capabilities entry (recall L-D LOW-3 — `capabilities/*.json` gates only plugin commands + `core:` APIs, not the app's own `#[tauri::command]` handlers).

---

## 6. Gate (pre-merge, all green required)

1. `cargo +nightly fmt --all -- --check`
2. `cargo clippy --workspace --all-targets -- -D warnings`
3. `cargo test --workspace` (must pass the workspace meta-tests per `feedback_full_workspace_test_gate.md`)
4. `forge fmt --check` (no contract change expected; runs as defense)
5. `forge test` (sanity — no contract change should not affect results; runs as defense)
6. `pnpm --filter @pangolin/desktop typecheck`
7. `pnpm --filter @pangolin/desktop lint`
8. `pnpm --filter @pangolin/desktop test` (vitest)

---

## 7. Branch + merge

- Branch: `mvp4-l-a-guardian-onboarding` off `main` (currently `74ecc40`).
- Per-commit granularity: one commit per logical layer (FFI wrappers, TS wrappers, wizard, RecoveryScreen integration, tests).
- Merge via `git merge --no-ff` per `pangolin_merge_workflow.md` §16 + push immediately.
- Watch CI proactively per `feedback_ci_proactive_recovery.md`.

---

## 8. Recommendation

Lock the four decisions per the recommendations above (Q-a/b/c/d/e all = Option 1), put L-A on `mvp4-l-a-guardian-onboarding`, ship it as a single PR-shaped branch. Should be ~1 working session — the FFI surface is complete and tested, and the UX is one wizard with the well-trodden ingest → confirm → progress pattern (mirrors `AddDeviceWizard.tsx` from MVP-4-I).
