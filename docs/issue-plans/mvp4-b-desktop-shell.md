<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# MVP-4-B — Tauri v2 desktop shell scaffold — plan-gate LOCKED

**Status: LOCKED — Kelvin call 2026-05-24 + 2026-05-25.** Three architectural decisions resolved via the staged-secure-input call + the "minimal first surface + red toasts" approvals; remaining defaults self-locked. Decisions captured in §0a.

## 0. One-paragraph summary

Stand up the canonical Tauri v2 desktop app (`apps/desktop/`) that the closed-beta UX runs on. React 19 frontend (Vite) hosted in the Tauri WebView; `tauri::command` handlers in Rust bridge to the merged `pangolin-ffi` surface. This slice ships the SCAFFOLD + a **minimum runnable surface** — open vault → unlock → list accounts → show selected account's password → copy to clipboard — and nothing else. Recovery, multi-device, sync, settings, KDBX import all defer to MVP-4-F's back-half UX work. The discipline being installed here is the Tauri-command policy (which `pangolin-ffi` bindings get wrapped + how secrets cross the bridge), the design-token integration (consuming `@pangolin/component-library` + `pangolin-design-tokens`), the error-surface posture (typed `FfiError` → red toast at the bottom), and the CI gate.

## 0a. RESOLVED decisions

**Kelvin-approved (carry forward from session decisions on 2026-05-24/25):**

- **Tauri v2.x** as the desktop shell. Direct `pangolin-ffi` link via `tauri::command` handlers in Rust; NO separate IPC server, NO Electron, NO per-OS native shell.
- **Minimum first surface = open + unlock + list + reveal + copy.** No sync, no recovery, no multi-device, no settings, no add-account, no KDBX import. Matches the existing CLI's surface for side-by-side comparison.
- **Error surface = red toast at the bottom-right** (the [`Toast`] component from `@pangolin/component-library` with `variant="danger"`). EXCEPTION: the unlock screen surfaces "wrong master password" as an inline error directly under the password field (per UX best-practice — a toast for a critical-action failure is too easy to miss). All other typed `FfiError` classes (`Chain`, `Validation`, `Session`, `Store`, `Recovery`) get toasts.
- **IPC posture = option 1 (`tauri::command` direct invoke).** Password JS string lingers in V8 heap until GC; Rust receives + zeroizes via `Arc<SecretPassword>`. Acceptable during closed beta (testnet-only). The MVP-4-H sub-issue ships option 2 (native Rust input widget) BEFORE mainnet alongside D-011 audit fixes. See the [`pangolin_secure_input.md`](../../.claude/projects/C--Users-kelvi/memory/pangolin_secure_input.md) memory + the MVP-4 overview §0a.

**Self-locked (no Kelvin gate needed):**

- **Frontend = React 19 + TypeScript strict + Vite 6.** Same versions as `@pangolin/component-library` (MVP-4-D); shared dependency tree.
- **pnpm 10 (corepack-managed)**, mirrors the MVP-4-C extension settle after the pnpm 11 ↔ Node 20.18 incompatibility. `.nvmrc` pins Node 20.18.0; `engines.node` matches.
- **Component library consumption via `file:../component-library` path** in `package.json`. Until a root-level pnpm workspace lands as a deferred follow-up, the desktop's CI build pre-builds the component-library (`pnpm --dir ../component-library install --frozen-lockfile && pnpm --dir ../component-library build`) BEFORE installing the desktop. This is brittle but trivial; the cleanup is a follow-up.
- **Design tokens via the existing `pangolin-design-tokens` crate** (Rust constants for the Rust side; CSS vars via `apps/component-library/dist/component-library.css` for the frontend). The component-library re-exports the design-tokens CSS so the desktop only imports the component-library bundle.
- **State management = Tauri's built-in `tauri::State`.** The vault handle is managed via `app.manage(Mutex<Option<Arc<VaultHandle>>>::new(None))`; each command acquires the lock + reads/writes the slot. NO Zustand, NO Redux, NO TanStack Query.
- **AGPL-3.0-or-later SPDX header** on every TS/TSX/CSS/Rust file in the new crate. `Cargo.toml`'s `license = "AGPL-3.0-or-later"`. `private: true` in `package.json`.

## 0b. What NOT to ship in this slice

- Recovery onboarding / use / rotation UX (MVP-4 back-half).
- Multi-device add / remove / list UX (MVP-4 back-half).
- Sync status surface (MVP-4 back-half).
- Settings panel (MVP-4 back-half).
- KDBX import UI (MVP-4 back-half).
- Add-account / edit-account / delete-account flows (MVP-4 back-half).
- TOTP generation UX (MVP-4 back-half).
- Search (MVP-4 back-half).
- Session-state surface, presence-escalation flows, autofill-related UX, browser-extension-integration UX (MVP-4-G).
- Auto-update mechanism (post-MVP-4).
- App-signing / code-signing for releases (post-MVP-4).
- MVP-4-H secure-input plugin (separate sub-issue, pre-mainnet hardening).

## 1. Scope

**Built in MVP-4-B:**

- `apps/desktop/` (NEW directory at the repo root). Mixed Rust + JS workspace member.
- `apps/desktop/Cargo.toml` — new crate `pangolin-desktop`; `[lib]` + `[[bin]]`; deps: `tauri = "=2.x"`, `tauri-plugin-clipboard-manager`, `pangolin-ffi = { path = "../../crates/pangolin-ffi" }`, `pangolin-design-tokens = { path = "../design-tokens" }`, `serde`, `tokio`, `zeroize`.
- `apps/desktop/src/main.rs` — bin entry; `tauri::Builder::default().plugin(tauri_plugin_clipboard_manager::init()).manage(VaultState::default()).invoke_handler(...).run(...)`.
- `apps/desktop/src/lib.rs` — re-exports the `tauri::command` handlers from `commands/`.
- `apps/desktop/src/commands/mod.rs` + `commands/vault.rs` + `commands/account.rs` — the Rust command surface (see §3.2).
- `apps/desktop/src/state.rs` — `VaultState` wrapper around `Arc<VaultHandle>` + helper guards.
- `apps/desktop/src/error.rs` — `DesktopError` enum mapping every `pangolin_ffi::FfiError` variant to a typed Tauri error response (`{"kind": "...", "message": "..."}`). Serializable; never embeds secret material.
- `apps/desktop/tauri.conf.json` — Tauri v2 config; bundle identifier `studio.kelvinsinferno.pangolin`; allowed `invoke_targets` only for the explicitly-exported commands; CSP set to default-deny + the popup HTML's local-file origin.
- `apps/desktop/package.json` — `"name": "@pangolin/desktop"`, `private: true`, `license: "AGPL-3.0-or-later"`, deps: `react@19`, `react-dom@19`, `@pangolin/component-library: file:../component-library`, `@tauri-apps/api@2`, scripts (`dev`, `build`, `typecheck`, `lint`, `test`).
- `apps/desktop/pnpm-lock.yaml` (committed).
- `apps/desktop/.nvmrc` + `tsconfig.json` (strict mirror of MVP-4-D) + `vite.config.ts` (React + Tauri integration).
- `apps/desktop/index.html` + `apps/desktop/src/ui/main.tsx` + `apps/desktop/src/ui/App.tsx` — the React entry + the root component.
- `apps/desktop/src/ui/screens/` — `UnlockScreen.tsx`, `AccountListScreen.tsx`, `AccountDetailScreen.tsx`. Each a thin functional component composed from `@pangolin/component-library` primitives.
- `apps/desktop/src/ui/hooks/` — `useVault.ts` (the single source of truth for the open/unlock state machine + Tauri invoke wrappers), `useToast.ts` (toast-queue management).
- `apps/desktop/src/ui/lib/invoke.ts` — typed wrapper around `@tauri-apps/api`'s `invoke()`; one TS function per Tauri command; full type coverage end-to-end.
- New CI job `desktop` in `.github/workflows/ci.yml`: pre-builds `apps/component-library` then runs `pnpm install --frozen-lockfile && pnpm typecheck && pnpm lint && pnpm test && pnpm build` for `apps/desktop`. Caches pnpm-store + Cargo target. Runs on `ubuntu-latest` (matches MVP-4-C+D pattern; macOS/Windows production builds added at release time).
- Hermetic tests:
  - **Rust-side:** unit tests on the command handlers using a mocked `VaultHandle` (every command's error path returns a typed `DesktopError`; success path round-trips). Plus `Cargo.toml`'s `[[bin]]` builds cleanly (`cargo build -p pangolin-desktop`).
  - **TS-side:** Vitest tests on the typed `invoke()` wrappers (mocks `@tauri-apps/api`'s `invoke`; asserts the right command name + args); component tests on `UnlockScreen` + `AccountListScreen` + `AccountDetailScreen` (RTL; mocked `useVault` hook).

**Deferred (NOT this slice):** per §0b.

## 2. Splittable? — recommend ONE slice

The Rust command surface + the React frontend + the Tauri bridge config + the CI gate all need to land together for the desktop to be buildable. Splitting forces a half-runnable shell between PRs. ONE slice → focused audit (Tauri-command policy + secret-bridge discipline + error-surface taxonomy + design-token integration) → merge.

## 3. Design

### 3.1 Directory layout

```text
apps/desktop/
├─ Cargo.toml
├─ tauri.conf.json
├─ package.json
├─ pnpm-lock.yaml
├─ tsconfig.json
├─ vite.config.ts
├─ .nvmrc
├─ .gitignore
├─ index.html
├─ README.md
└─ src/
   ├─ main.rs                       ← bin entry
   ├─ lib.rs                        ← re-exports commands
   ├─ state.rs                      ← VaultState wrapper
   ├─ error.rs                      ← DesktopError
   ├─ commands/
   │  ├─ mod.rs
   │  ├─ vault.rs                   ← create / open / unlock / lock / close
   │  └─ account.rs                 ← list / show / reveal_password / copy_to_clipboard
   └─ ui/
      ├─ main.tsx                   ← React entry
      ├─ App.tsx                    ← root router (state-machine over vault state)
      ├─ App.css
      ├─ lib/
      │  └─ invoke.ts               ← typed wrappers around @tauri-apps/api
      ├─ hooks/
      │  ├─ useVault.ts             ← state machine + invoke wrappers
      │  └─ useToast.ts             ← toast queue
      └─ screens/
         ├─ UnlockScreen.tsx        ← `Input` (password, masked) + Unlock button + inline error
         ├─ AccountListScreen.tsx   ← `ListRow` × N
         └─ AccountDetailScreen.tsx ← detail view + reveal + copy button
```

### 3.2 The Tauri command surface (MINIMAL first cut)

Each command is a `#[tauri::command]` wrapper over a `pangolin-ffi` binding. The vault handle is stored in `tauri::State<VaultState>`; commands acquire the mutex inside the handler. **Master password crosses behind an opaque `String` argument** (option 1; the JS lifetime ≈ ms; Rust immediately bridges into `SecretPassword`).

| Tauri command | Wraps | Notes |
|---|---|---|
| `vault_open` | `pangolin_ffi::vault_open(path)` | Stores the resulting `Arc<VaultHandle>` in the managed state. |
| `vault_unlock` | `pangolin_ffi::vault_unlock(handle, password, presence)` | `password: String` consumed + immediately wrapped into `Arc<SecretPassword>`. Presence proof = `PressYPresenceProof::confirmed()` (no real presence gate this slice). |
| `vault_lock` | `pangolin_ffi::vault_lock(handle)` | |
| `vault_close` | drops the handle from managed state | No `pangolin-ffi` call; just clears the state slot. |
| `accounts_list` | `pangolin_ffi::accounts_list(handle)` | Returns `Vec<FfiAccountSummary>`. |
| `account_show` | `pangolin_ffi::account_show(handle, account_id)` | Returns the full account record (NOT the password — that requires `reveal_password`). |
| `reveal_password` | `pangolin_ffi::reveal_password(handle, account_id)` | Returns the password as `String` JUST FOR THIS CALL. Caller (the React side) MUST clear it within 10s (per Browser-Ext spec §4.7 memory-hygiene rule). |
| `copy_to_clipboard` | `tauri_plugin_clipboard_manager::write_text(text)` | The reveal flow: invoke `reveal_password` → invoke `copy_to_clipboard(result)` → discard the local `result`. |

**NOT wrapped this slice:** `vault_create`, `vault_publish_queue_flush`, `vault_pull_once`, `vault_lock_with_drain`, `vault_complete_rotation`, the recovery FFI surface (#108), the recovery-backup FFI surface (#109), `vault_add_device` / `vault_bootstrap_chain` / pairing surface (#106e-2). Those land in MVP-4 back-half sub-issues.

### 3.3 Error surface

Every `pangolin_ffi::FfiError` variant maps to a typed `DesktopError`:

```rust
// apps/desktop/src/error.rs (sketch)
#[derive(serde::Serialize, Debug)]
#[serde(tag = "kind", content = "message")]
pub enum DesktopError {
    Session(String),
    Validation { kind: String, message: String },
    Chain(String),
    Store(String),
    Recovery(String),
    Internal(String),
    /// Wrong master password — surfaced inline on the unlock screen,
    /// NOT as a toast (UX-required).
    AuthenticationFailed,
}

impl From<FfiError> for DesktopError {
    fn from(e: FfiError) -> Self { ... }
}
```

The React side discriminates on `kind`:
- `AuthenticationFailed` → inline red text under the password field (unlock screen).
- All others → red toast at the bottom-right via `useToast.danger(message)`.

### 3.4 State machine (React side)

```text
              vault_open(path)
[ Welcome ] ────────────────────▶ [ Locked (handle) ]
                                          │
                                          │ vault_unlock(password)
                                          ▼
                                  [ Active (handle, accounts) ]
                                          │   │
                                          │   │ click on account row
                                          │   ▼
                                          │ [ AccountDetail ]
                                          │   │
                                          │   │ click Reveal → reveal_password
                                          │   ▼
                                          │ [ AccountDetail w/ password ]
                                          │
                                          │ vault_lock OR vault_close
                                          ▼
                                  [ Locked OR Welcome ]
```

Encoded as a single `useVault()` hook returning the current state + the available transitions.

### 3.5 Tauri v2 config (CSP + invoke targets)

```jsonc
// tauri.conf.json (sketch)
{
  "$schema": "https://schema.tauri.app/config/2",
  "productName": "Pangolin",
  "version": "0.0.0",
  "identifier": "studio.kelvinsinferno.pangolin",
  "build": {
    "frontendDist": "./dist",
    "devUrl": "http://localhost:5173",
    "beforeDevCommand": "pnpm dev:vite",
    "beforeBuildCommand": "pnpm build:vite"
  },
  "app": {
    "windows": [{ "title": "Pangolin", "width": 1024, "height": 720 }],
    "security": {
      "csp": "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'",
      "capabilities": ["default"]
    }
  }
}
```

A `capabilities/default.json` allows ONLY the explicitly-exported commands (vault_open / vault_unlock / vault_lock / vault_close / accounts_list / account_show / reveal_password / copy_to_clipboard) — closes the principle-of-least-authority gate at the Tauri layer.

## 4. L-invariants

- **L1 — zero secret crosses FFI as readable bytes (except master password under staged option 1 + the reveal-password result for ≤10s).**
  - Master password: `String` arg to `vault_unlock` → bridged immediately into `SecretBytes` → `Arc<SecretPassword>`. JS-side string lifetime ≈ ms (V8 GC; not actively zeroized — the MVP-4-H deferred upgrade fixes this).
  - `reveal_password` return: the password `String` crosses out for the explicit reveal flow. Browser-Ext spec §4.7 imposes a 10s memory-hygiene rule on the host; the React side clears the local `useState` slot within 10s.
  - Vault handle: opaque `Arc<VaultHandle>` lives in Rust-side `tauri::State`. NEVER serialized to JS.
- **L2** — no new atomic surface; commands wrap existing FFI bindings.
- **L3** — typed `DesktopError` taxonomy is fail-closed (every FfiError variant has a mapping; an unknown variant becomes `Internal`).
- **L4** — Tauri's capability system + the `capabilities/default.json` allow-list close the IPC surface to ONLY the declared commands.
- **L5** — no new external crates beyond Tauri's required deps; React + Vite + TS already in the workspace via MVP-4-D.
- **L6** — `forbid(unsafe_code)` on every new Rust file; AGPL SPDX everywhere.
- **L7** — testnet-only flag for any chain-touching command (none in this slice — all chain commands deferred to MVP-4 back-half).
- **L8** — Rust unit tests on each command's error path + the typed-invoke TS tests + the screen-level RTL tests. `cargo test -p pangolin-desktop` + `pnpm test` both gate.
- **L9** — `§16` ledger: DECISIONS / DEVLOG entries on merge; Kelvin merge sign-off implicit (per the autonomy directive — Kelvin already pre-resolved this sub-issue's architectural questions).

## 5. Open decisions — pre-locked (one carve-out for the builder)

- **Q-a (clipboard-clear timer policy): builder's call.** `copy_to_clipboard` should ideally clear the OS clipboard after some duration (Bitwarden's pattern: ~30s). Options:
  - (i) NO timer this slice — the user manually pastes + we trust them. Simplest.
  - (ii) Fire a 30s `setTimeout` in JS after `copy_to_clipboard` resolves; on fire, invoke `clear_clipboard` (a new Tauri command). Slightly more code.
  Pick whichever needs less ceremony. Real timer-with-cancellation + user-configurable duration is MVP-4 back-half territory.
- **Q-b (Tauri v2 patch version pin): builder's call.** Tauri 2.x cycles patch releases roughly monthly. Pin `=2.X.Y` to whatever's current at build time; if `cargo deny` flags any advisory in the resulting Cargo.lock, bump.

## 6. Places that need care

- **The `pangolin-ffi` crate ALREADY has the unlock+list+reveal surface.** This slice's job is wrapping it in `tauri::command`s + driving the React UI — NOT inventing new FFI. If the builder finds itself adding to `pangolin-ffi`, STOP + flag.
- **`reveal_password` returns a `String` across Tauri's serialization boundary.** This is the LOAD-BEARING L1 carve-out for this slice. Document explicitly in the binding's doc-comment; React side has a `useEffect` that clears the local state after 10s (per spec).
- **Tauri's `tauri::command` async invocation under `tokio::main` works fine — but holding a `MutexGuard` over an `.await` is `!Send` and panics.** Standard Tauri pattern: lock → extract handle ref → drop the guard → call FFI. Watch for accidental long-held guards.
- **`tauri.conf.json`'s CSP is restrictive.** `script-src 'self'` blocks any inline `<script>`. Vite's dev mode HMR may need `'unsafe-inline'` in dev only (`devUrl` config). Verify HMR works in dev without weakening the prod CSP.
- **The component-library `file:` dep means desktop CI MUST pre-build component-library.** Don't skip that step.

## 7. Success criteria

- `cargo build -p pangolin-desktop` clean on the Rust side.
- `cd apps/desktop && pnpm install --frozen-lockfile && pnpm typecheck && pnpm lint && pnpm test && pnpm build` all green.
- `cd apps/desktop && pnpm tauri dev` opens a window showing the Welcome screen → user picks a `.pvf` file → enters master password → sees account list → clicks one → sees detail → clicks Reveal → password shows → clicks Copy → clipboard has the password.
- The new CI job `desktop` is green on `ubuntu-latest`.
- Cardinal invariants still 0.

## 8. Out of scope (filed for follow-up)

- All §0b items.
- Root-level pnpm workspace migration (clean dep arrow between desktop / component-library / extension).
- Per-OS native installer (Windows MSI, macOS DMG, Linux AppImage) — release-time work.
- Auto-update mechanism — post-MVP-4.
- App + code signing — post-MVP-4.
- Per-OS production CI matrix (macOS + Windows builds at every PR) — release-time; ubuntu-latest is enough for closed beta.
