<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# MVP-4-L (L-C) — Guardian-side help UX — plan-gate DRAFT

**Status: DRAFT — awaiting Kelvin sign-off.** Parent plan-gates: [mvp4-l-recovery-ux.md](mvp4-l-recovery-ux.md) (decomposition §1, L-C row) + [mvp4-l-a-guardian-onboarding.md](mvp4-l-a-guardian-onboarding.md) (the symmetric owner-side slice that immediately precedes this one). L-0a-1 (RecoveryV2 + on-chain G-1/G-3 + V2 Approve typehash binding `recipientCommitment`) + L-0a-2 (`vault_guardian_release_share` off-chain re-seal with Decision-B anti-redirect verification) are already merged, so L-C is now an unblocked thin-UX slice over the existing FFI surface.

> **This slice builds ONLY:** the guardian-side wizard that ingests a recovery REQUEST (sent by a recovering user — vault id, attempt nonce, proposed authority, recipient commitment, sealed share, epoch, guardian set, approval expiry), confirms the guardian's intent, then drives `vault_approve_recovery` (on-chain V2 Approve signature) followed by `vault_guardian_release_share` (off-chain open-and-reseal of the guardian's stored share, returning the `SealedShareForRecoverer` ciphertext for the guardian to send back to the recovering user). NO recovering-user wizard (that's L-B). NO net-new crypto, NO net-new FFI, NO contract change. Testnet-only.

---

## 0. One-paragraph summary

The recovery flow has THREE human roles: the **owner** (onboards guardians — L-A, done), the **recovering user** (lost everything, runs the recovery wizard — L-B, next), and the **guardian** (gets pinged out-of-band by the recovering user, opens this wizard, helps — L-C, this slice). L-C is the symmetric counterpart of L-A: the owner sets up guardians, the guardian sets up nothing — but when called on, the guardian sees a clear "Someone is trying to recover their vault; here's what they're asking; do you want to help?" screen, confirms their master password, and the desktop drives one on-chain transaction (the EIP-712 Approve, binding the recoverer's commitment per Decision B) + one local re-seal (open the share that was sealed to this guardian's pubkey at onboarding time + re-seal it to the recoverer's ephemeral pubkey via `seal_share_to_recoverer`). The re-sealed blob is shown as copy-pasteable text + the guardian sends it back to the recovering user via any out-of-band channel.

---

## 1. Scope (build + test)

### What ships
- One new desktop screen — `HelpRecoverWizard.tsx` — driven from a new "Help someone recover" card on `RecoveryScreen.tsx` (always visible when the vault is Active, since any guardian can be asked at any time).
- Two new Tauri commands wrapping the existing FFI:
  1. `recovery_decode_request(text)` — pure decode of a recovery-request blob the recovering user pasted to the guardian. Format = base64-of-JSON of an 8-field record (`vaultId`, `attemptNonce`, `proposedAuthority`, `recipientCommitment`, `sealedShare`, `epoch`, `guardianSet`, `expiresAt`); strict shape validation (all hex fields length-checked, `attemptNonce`/`expiresAt` numeric, `guardianSet` non-empty array). NO handle, no session.
  2. `recovery_help` (single coordinator command) — wraps `vault_approve_recovery` + `vault_guardian_release_share` in sequence in a single `spawn_blocking` boundary. Active-gated FFI-side. Returns the re-sealed-share bytes (hex-encoded) + the on-chain receipt anchor.
- TS wrappers + DTOs in `apps/desktop/src/ui/lib/invoke.ts`.
- Rust closed-vault tests for the session-gated coordinator (mirroring the L-D / L-A patterns).
- Frontend vitest for `HelpRecoverWizard.tsx` covering: paste happy path, paste-rejects-bad-format, t/M consistency check (Decision-B fail-loud if the on-chain commitment doesn't match), expired-approval refusal, partial-failure (approve succeeded, release failed) → retry-release-only.

### What does NOT ship
- Mainnet (D-011 gated).
- Recovering-user wizard (L-B — the side that *initiates* the recovery + collects t re-sealed shares).
- A persistent "in-flight recovery requests" inbox (the guardian gets the request out-of-band per the threat model — no Pangolin-mediated mailbox).
- Camera-scan ingestion (parks behind MVP-4-I camera-permission work; Q-a covers).
- A re-attempt flow if the request is malformed (the user pastes it again).
- A way to view what requests this guardian has previously approved (chain history; out of scope at L-C).

---

## 2. Decisions to resolve (each: pick ONE)

### Q-a — Transport for the recovery REQUEST (recovering user → guardian)
Options:
1. **Paste-only** (mirrors L-A Q-a). The recovering user copies their request text from the L-B wizard, sends it to the guardian over any out-of-band channel (Signal, email, in-person), and the guardian pastes it into the L-C wizard. Zero new deps.
2. **Paste + QR-display** — recovering user can also render the QR locally; guardian-side ingest stays paste-only. Modest +deps.
3. **Paste + QR-display + camera-scan** — full three-mode parity with MVP-4-I. Camera-scan likely broken on Linux/WebKitGTK; would degrade to paste.

**Recommend Option 1 (paste-only)** for L-C — matches L-A's resolution. The request is a one-time artifact; the user can copy/paste deliberately, and we avoid the camera-permission rabbit hole until MVP-4-I's camera fix lands.

### Q-b — Transport for the re-sealed-share RESPONSE (guardian → recovering user)
Options:
1. **Text-display + copy-to-clipboard** (mirrors L-D's backup-envelope show + copy). Guardian sees the hex blob with a "Copy" button; sends it to the recovering user over any out-of-band channel.
2. **Text-display + QR-render** — adds a `<QRCode>` of the bytes for visual scanning, recovering user pastes the corresponding base64.
3. **File-export** — saves the response to a `.json` or `.txt` file the guardian attaches to email.

**Recommend Option 1 (text + copy)** — matches the L-D backup-envelope pattern + the L-A invite-ingest pattern, keeps the L-C wizard one-dependency-set with the existing recovery UX. QR-render adds value if camera-scan is in the picture (it isn't — Q-a) so it's deferred to a follow-up alongside camera.

### Q-c — Where the wizard lives
1. **Extend `RecoveryScreen.tsx`** with a "Help someone recover" card, always visible when the vault is Active (matching the L-A Q-b posture). The wizard opens as a sibling card of the L-A setup wizard + the L-D backup card.
2. **New top-level `GuardiansScreen.tsx`** at parity with `DevicesScreen.tsx`. Fragments the recovery surface before L-B lands.

**Recommend Option 1 (extend RecoveryScreen)** — same rationale as L-A Q-b: keep the recovery mental model unified at L-C time.

### Q-d — Partial-failure semantics (approve succeeded, release failed)
The coordinator runs `vault_approve_recovery` (on-chain — slow, costs gas) then `vault_guardian_release_share` (off-chain — fast, local). If the approve lands but the release fails (wrong sealed-share bytes pasted, expired chain RPC, etc.):
1. **Resume + retry release-only.** Show a "Approval recorded on-chain; share release failed — retry release" banner. Re-attempt is safe: the approval is already on-chain (`ErrDuplicateApproval` would block a re-approve anyway). The retry path re-invokes only `vault_guardian_release_share`.
2. **Treat as a full failure** — guardian must re-do BOTH steps. But the contract reverts the second approve, so they'd hit `ErrDuplicateApproval` and be stuck.

**Recommend Option 1 (retry release-only).** Lower friction, matches the L-A Q-c shape, and is forced by the contract's idempotence-on-approve.

---

## 3. Files

### New
- `apps/desktop/src/ui/screens/HelpRecoverWizard.tsx` — the wizard (steps: ingest request → preview + password → progress → done|retry-release).
- `apps/desktop/src/ui/screens/HelpRecoverWizard.test.tsx` — vitest (~7 cases per the §1 list).

### Edited
- `apps/desktop/src/ui/screens/RecoveryScreen.tsx` — add the "Help someone recover" card + open `HelpRecoverWizard` from the card.
- `apps/desktop/src/commands/recovery.rs` — add two new `#[tauri::command]` handlers (`recovery_decode_request`, `recovery_help`) + two new closed-vault tests for the session-gated coordinator + the closed-vault path on the pure decoder smoke.
- `apps/desktop/src/lib.rs` — register the two new commands in `tauri::generate_handler!`.
- `apps/desktop/src/ui/lib/invoke.ts` — two TS wrappers + DTOs (`RecoveryRequest`, `HelpRecoverResult`). Re-uses `TxOutcome` from L-A.
- `apps/desktop/src/ui/screens/RecoveryScreen.test.tsx` — add a case for the new card visibility (it's always visible when the vault is Active, so the assertion is simpler than L-A's zero-authority gate).

### Untouched (verify, then leave alone)
- All Rust crates other than `apps/desktop/`. The FFI surface is complete (`vault_approve_recovery` + `vault_guardian_release_share` are merged via L-0a-1 + L-0a-2).
- `contracts/*` — no contract change.

---

## 4. L-invariants

- **L1 (no NEW secret crosses).** The master password crosses in via `SecretPassword::new(password.into_bytes())` exactly as L-A's `recovery_set_guardian_set` already does. The opened guardian share NEVER crosses the FFI in cleartext (`vault_guardian_release_share` opens it + re-seals it engine-side; only the non-secret `SealedShareForRecoverer` bytes cross out). The recipient commitment + sealed-share input bytes are explicitly non-secret. The recoverer's `proposed_authority` is a 20-byte EVM address; the `attempt_nonce` is a u64; `expiresAt` is a u64.
- **L3 (fail-closed).** Decision-B anti-redirect check inside `vault_guardian_release_share` (Phase 1) refuses to open the share if the on-chain `recipientCommitment` doesn't match the host's input. Decode-failure surfaces as `DesktopError::Validation`. RPC failure surfaces as `DesktopError::Chain`.
- **L4 (session-gated).** `recovery_help` first-line `state.require_open()`; closed-vault tests prove the guard. `recovery_decode_request` is PURE.
- **L6.** No error message carries any secret.
- **L11 (engine is source of truth).** `vault_approve_recovery` reads the LIVE PENDING attempt's `(attempt_nonce, proposed_authority)` via `build_live_approve_fields_v2` and asserts the host params match (fail-closed Chain if not). The L-C wizard does NOT re-implement that check — it surfaces the engine's typed error.
- **L13.** Chain calls run via `spawn_blocking` per the pairing/L-A precedent.

---

## 5. Adversarial-audit focus (predictable LOW classes the auditor should hunt)

- **Decision-B anti-redirect end-to-end** — verify that the guardian's wizard cannot release a share to a recipient commitment that does NOT match the chain's `RecoveryV2.recipientCommitment` field. The FFI's Phase 1 check is the load-bearing gate; the wizard should not re-implement (would invite drift) but should DISPLAY the on-chain commitment so the guardian can visually verify (defense-in-depth, not a gate).
- **Expired-approval handling** — `vault_approve_recovery` takes `expires_at_unix`. If the recoverer's request has a stale `expiresAt` (clock skew or just an old request), the contract reverts `ErrApprovalExpired`. The wizard should refuse to even attempt the approve if the request's `expiresAt` is in the past.
- **Partial-failure retry** — verify the L-A Q-c shape applies cleanly (the coordinator gates the retry path on "approve has landed on-chain" — probe via `recovery_health` like L-A's `chainShowsAuthoritySet`).
- **L1 — re-confirm the opened share never crosses the FFI.** The auditor should grep for any direct exposure of the cleartext `Share` bytes; the only out-path should be `SealedShareForRecoverer.as_bytes()`.
- **Idempotence of approve** — verify the wizard does NOT call `recovery_help` twice on a double-click (broadcastGuard pattern from L-A's `SetupGuardiansWizard`).
- **Capabilities** — none of the new commands need a Tauri v2 capabilities entry (per L-D LOW-3).
- **errMessage parity** — verify the wizard's `errMessage` uses the L-A audit-fixed shape (unwraps the nested `{kind, message}` Validation envelope).
- **selfLoaded equivalent** — L-C has NO self-check (a guardian isn't checking against their own identity; they ARE the guardian). So no `selfPubkey` / `selfLoaded` is needed. The wizard's Add button is simply disabled on empty paste + during the in-flight transaction.

---

## 6. Gate (pre-merge, all green required)

1. `cargo +nightly fmt --all -- --check`
2. `cargo clippy --workspace --all-targets -- -D warnings`
3. `cargo test --workspace`
4. `forge fmt --check` (defense — no contract change expected)
5. `forge test` (defense)
6. `pnpm --filter @pangolin/desktop typecheck`
7. `pnpm --filter @pangolin/desktop lint`
8. `pnpm --filter @pangolin/desktop test` (vitest)

---

## 7. Branch + merge

- Branch: `mvp4-l-c-guardian-help` off `main` (currently `d034756`).
- Per-commit granularity: one commit per logical layer (FFI wrappers + decoder, TS wrappers, wizard + RecoveryScreen integration, tests, audit fixes).
- Merge via `git merge --no-ff` per `pangolin_merge_workflow.md` §16 + push immediately.
- Watch CI proactively per `feedback_ci_proactive_recovery.md`.

---

## 8. Recommendation

Lock the four decisions per the recommendations above (Q-a..d all = Option 1; "match L-A"), put L-C on `mvp4-l-c-guardian-help`, ship it as a single PR-shaped branch. Should be ~1 working session — the FFI surface is complete + tested, the wire-format work is desktop-only (no engine codec), and the wizard is one screen with the ingest → confirm → progress pattern (mirrors `SetupGuardiansWizard.tsx` from L-A).
