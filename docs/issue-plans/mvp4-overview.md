<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# MVP-4 overview — Desktop App + Browser Extension — plan-gate LOCKED

**Status: LOCKED — Kelvin sign-off 2026-05-24.** MVP-3 closed (PoC + MVP-1 + MVP-2 + MVP-3 all shipped + CI-green on `main`). Recovery + multi-device stay TESTNET-ONLY on Base Sepolia until **D-011 external audit** clears.

This is the umbrella plan for MVP-4 — the Desktop App (Tauri v2 + React) plus the Chromium-first Browser Extension. Each sub-issue (MVP-4-A through MVP-4-E + the E2E gates) gets its own focused plan-LOCK doc as it's dispatched.

## 0a. RESOLVED decisions (Kelvin sign-off 2026-05-24)

- **Desktop shell = Tauri v2.x.** Current stable. Rust integration via direct `pangolin-ffi` link inside `tauri::command` handlers — no separate IPC server, no Electron, no native shell per platform. The Tauri WebView hosts the React UI.
- **Browser-extension scope = Chromium-first (Manifest V3).** Ships Chromium first; Firefox + Safari follow as parallel work in MVP-4's back half if time + audit cycles allow, otherwise slip to MVP-4.5.
- **Native-messaging host = auto-install on first desktop run.** Rust binary built alongside the desktop app; the desktop app's first-run wizard registers the native-messaging manifest on every supported OS (Windows / macOS / Linux). Clear manual-install fallback path documented.
- **Closed-beta participant count = deferred to MVP-4 close.** Beta-funnel UX (allowlist / invite codes / open signup) is Kelvin's call after the first end-to-end UX gate (Day 10 in the §13 plan).

## 0b. Cross-cutting policies (every MVP-4 sub-issue honors)

- **L1 zero-secret-crosses-FFI-as-readable-bytes** still applies at the desktop + extension layer. Master passwords behind `Arc<SecretPassword>`; opened guardian shares behind `Arc<FfiOpenedShare>`; the seed-phrase carve-out (#109) is the only documented exception.
- **AGPL-3.0-or-later** SPDX header on every new file (D-016 supersedes D-002).
- **`forbid(unsafe_code)`** on every new Rust crate.
- **Spec ref** in every issue plan — Design Spec §1–§8, Browser-Ext spec §1–§5, Session spec §5.4 (autofill flow), UI/UX Design System.
- **No new external crates** unless justified inline (workspace pin via `[workspace.dependencies]`); uniffi stays pinned `=0.31.1`.
- **D-011 external audit is a hard pre-mainnet gate** for recovery + multi-device. MVP-4 builds the UX for those flows; mainnet wiring stays gated.
- **Per-issue protocol §16** applies as it did through MVP-1/2/3: plan-gate → builder agent in worktree → adversarial audit → fix-in-place to 100% clean → `git merge --no-ff` → push → CI watch.

## 1. Issue list — dependency-ordered

### MVP-4-A — Design tokens (foundation; lands first)

- **Path**: `apps/design-tokens/` (new) — single canonical JSON source generating:
  - `apps/design-tokens/dist/tokens.css` — CSS variables for the Tauri WebView + the extension popup
  - `apps/design-tokens/dist/tokens.rs` — Rust constants for any Rust-side rendering (notifications, system-tray badges)
- **Spec ref**: Design Spec §4 (color) + §5 (type scale) + §6 (spacing).
- **Why first**: Every later issue depends on the tokens. Locking them down before any UI work prevents downstream churn.
- **Plan-LOCK doc**: `docs/issue-plans/mvp4-a-design-tokens.md` (drafted when dispatched).
- **Scope**: token authoring + the generator script (Rust binary in a new tools crate or a `build.rs`); NO actual UI consumes the tokens yet.

### MVP-4-B — Tauri v2 desktop shell scaffold

- **Path**: `apps/desktop/` (new) — Tauri v2 + React/Vite.
- **Spec ref**: Design Spec §3 (information architecture); §16 hosting model.
- **Scope**: minimum runnable: open a window → choose a `.pvf` file → enter master password → unlock → show "vault unlocked" (no account list yet).
- **Plan-LOCK doc**: `docs/issue-plans/mvp4-b-desktop-shell.md`.
- **Kelvin-gate**: yes (architectural — uniffi binding shape, Tauri command policy, IPC posture).
- **Depends on**: MVP-4-A.

### MVP-4-C — Browser-extension scaffold (Chromium MV3)

- **Path**: `apps/extension/` (new).
- **Spec ref**: Browser-Ext + Autofill spec §1–§3.
- **Scope**: manifest V3 + service worker + content-script stub + popup shell (no autofill yet; no native messaging yet — just a popup that loads a hardcoded "no vault connected" view).
- **Plan-LOCK doc**: `docs/issue-plans/mvp4-c-extension-scaffold.md`.
- **Depends on**: MVP-4-A. Can run in parallel with MVP-4-B once tokens land.

### MVP-4-D — Component library

- **Path**: `apps/component-library/` (new).
- **Spec ref**: Design Spec §6 (atomic) + §7 (composite).
- **Scope**: input, button, list-row, modal, toast, password-meter, seed-phrase-grid (for #109 backup display). React + Storybook-style docs page. Importable by both the Tauri shell + the extension popup.
- **Plan-LOCK doc**: `docs/issue-plans/mvp4-d-component-library.md`.
- **Depends on**: MVP-4-A.

### MVP-4-E — Native-messaging host

- **Path**: `apps/native-messaging-host/` (new Rust binary).
- **Spec ref**: Browser-Ext + Autofill spec §4 (transport).
- **Scope**: stdio-framed JSON-RPC over Chrome's native-messaging protocol; first-run installer registers the manifest at the right OS path; runs alongside the Tauri desktop process; speaks to `pangolin-ffi` directly (same in-process FFI as the Tauri shell).
- **Plan-LOCK doc**: `docs/issue-plans/mvp4-e-native-messaging.md`.
- **Kelvin-gate**: yes (architectural — transport security, IPC posture, manifest install policy).
- **Depends on**: MVP-4-B.

### MVP-4-F — Desktop E2E UX gate (Day 7–10)

- **Scope**: open vault → unlock → list accounts → reveal password → copy. All through the Tauri shell + FFI. No chain hits, no recovery, no multi-device — minimum viable desktop UX.
- **Plan-LOCK doc**: `docs/issue-plans/mvp4-f-desktop-e2e.md`.
- **Depends on**: MVP-4-B + MVP-4-D.

### MVP-4-G — Extension E2E UX gate (Day 10–12)

- **Scope**: install the extension → open popup → popup speaks to the running desktop via the native-messaging host → show the same account list → copy a password.
- **Plan-LOCK doc**: `docs/issue-plans/mvp4-g-extension-e2e.md`.
- **Depends on**: MVP-4-C + MVP-4-D + MVP-4-E + MVP-4-F.

### MVP-4 back-half (after the Day-14 demo gate)

These ship in MVP-4's second 2–3 weeks; sub-plan-LOCKs drafted as they're dispatched.

- **Recovery UX flows** — "set up recovery" + "use recovery (lost-everything)" + "rotate after revoke". Ties together every MVP-3 primitive with the 4-spec design system. **Largest lift** in MVP-4 because it's the most-coupled-to-spec surface.
- **Multi-device UX flows** — "add device" pairing UX (QR + 6-digit SAS) + "remove device" + "see authorized devices".
- **Sync status surface** — pull queue health, push queue health, chain confirmations, balance monitor.
- **Settings + KDBX import UI** — wraps the existing pangolin-kdbx + reveal/export flows.
- **First closed-beta-feedback iteration** — Kelvin-driven; beta-list mechanics settled here.
- **Firefox + Safari extension targets** — slip to MVP-4.5 if time tight.

## 2. Splittable? — yes, ALWAYS split by sub-issue

Unlike MVP-3 issues where one builder PR was the right grain, MVP-4 sub-issues are LARGE (each is hundreds of LoC of UI code + design integration + native plumbing). **One sub-issue = one builder = one PR = one CI cycle**. The dependency arrows above are the merge order.

## 3. L-invariants (mirror MVP-1/2/3)

- **L1 zero-secret-crosses-FFI** still applies; the desktop + extension are downstream consumers of `pangolin-ffi`, which is the chokepoint.
- **L2 no new atomic surface** — desktop + extension wrap existing FFI bindings, never invent state-machine work that the engine doesn't already own.
- **L3 fail-closed** — UI surfaces typed `FfiError` classes (Validation / Session / Chain / Recovery) directly to the user with no inferred state.
- **L5 no new external crates unless justified** — Tauri v2 + the React stack are the obvious additions; everything else stays within the existing pin set.
- **L6 testnet-only / D-011** — recovery + multi-device UX shows testnet-only banners until D-011 clears.
- **L7 AGPL SPDX + `forbid(unsafe_code)`**.
- **L8 tests** — every new Rust crate has hermetic unit tests; UI has Playwright/Vitest where appropriate; the E2E gates (MVP-4-F + MVP-4-G) are the load-bearing integration tests.
- **L9 §16 ledger** — DECISIONS / DEVLOG / merge sign-off per sub-issue.

## 4. Parallel external workstreams

These run in parallel with the build-out and are Kelvin-driven (cannot be agent-executed):

- **D-011 audit firm selection + commissioning** — 4–8 week lead time. **Start ASAP.** Findings must land before recovery + multi-device flows can target mainnet.
- **Design Figma file** — mirror Design Spec §4–§8; pays back when MVP-4-D component library is built out.
- **Closed-beta strategy** — Kelvin's call at MVP-4 close (deferred per §0a).
- **Marketing** — landing-page positioning that reflects what's shipped (PoC + MVP-1/2/3 done; testnet-only recovery + multi-device until D-011).

## 5. What's NOT this slice (deferred to MVP-5 or beyond)

- Mobile (iOS + Android) — §8 / MVP-5.
- Enhanced Privacy Mode (CoinJoin pre-mixing, per-revision wallet rotation) — post-launch.
- Public mainnet recovery + multi-device — gated on D-011.
- Multi-vault / shared-vault — post-launch.
- Enterprise / team features — post-launch.
- Web app — not in scope for the foreseeable future (the design is local-first + extension + native; web is anti-pattern for the threat model).

## 6. Dispatch order (autonomy directive: intermediate steps autonomous, Kelvin approves at sub-issue merges)

1. **MVP-4-A design tokens** — dispatch next, no Kelvin gate (pure data + generator).
2. **MVP-4-B Tauri shell** — Kelvin plan-gate (architectural).
3. **MVP-4-C extension scaffold** — parallel with -B; no Kelvin gate.
4. **MVP-4-D component library** — after -A; no Kelvin gate.
5. **MVP-4-E native-messaging host** — Kelvin plan-gate (architectural).
6. **MVP-4-F + MVP-4-G E2E gates** — Kelvin demo-gate at Day 14.

Parallel: D-011 audit firm engagement (Kelvin-driven).
