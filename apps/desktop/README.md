<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# @pangolin/desktop

The Pangolin Tauri v2 desktop shell — closed-beta UX host.

## Architecture

- **Rust side** (`src/`, `Cargo.toml`): a Tauri v2 binary crate
  (`pangolin-desktop`) that wires the React frontend to the merged
  `pangolin-ffi` surface via `tauri::command` handlers. The managed
  state is a single `VaultState` slot that holds the open
  `Arc<VaultHandle>`.
- **Frontend** (`src/ui/`): a React 19 + TypeScript app built with
  Vite 6. Consumes the `@pangolin/component-library` primitives
  (Button, Input, Toast, Card, ListRow). The state machine lives in
  a single `useVault()` hook; toasts render through `useToast()`.

The plan-LOCK lives at `docs/issue-plans/mvp4-b-desktop-shell.md`.

## First-surface scope

The minimum runnable surface ships ONLY these flows:

1. **Welcome** — pick a `.pvf` vault file.
2. **Locked** — enter the master password (wrong password renders an
   inline error under the field; other failure classes flow through
   the red toast at the bottom-right).
3. **Active** — list every account in the vault.
4. **Detail** — show the selected account's metadata + a
   reveal-password button + a copy-to-clipboard button. The revealed
   plaintext auto-clears from React state after 10 s per the
   Browser-Ext spec §4.7 memory-hygiene rule.

Deferred to MVP-4 back-half: recovery, multi-device, sync, settings,
KDBX import, add-account, search, TOTP UX, secure-input plugin
(MVP-4-H).

## Build + run

The `apps/component-library` dependency uses a `file:` path that
requires the library's `dist/` to exist before this app's
`pnpm install`. The CI job pre-builds it; for local development:

```bash
# 1. Pre-build the component-library (once)
cd apps/component-library
pnpm install --frozen-lockfile
pnpm build

# 2. Frontend gates (typecheck + lint + test + build)
cd ../desktop
pnpm install --frozen-lockfile
pnpm typecheck
pnpm lint
pnpm test
pnpm build

# 3. Rust gates (from repo root)
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo build -p pangolin-desktop
```

To launch the shell against the Vite dev server:

```bash
cd apps/desktop
pnpm dev   # starts Vite on http://localhost:5173
# In a second terminal:
cargo run -p pangolin-desktop
```

## Q-a + Q-b (builder-deferred decisions)

The plan-LOCK §5 left two carve-outs to the builder:

- **Q-a — clipboard-clear timer policy.** Decided: **option (i)** — no
  host-side clear timer this slice. The React side already clears the
  revealed plaintext from local state within 10 s; clearing the OS
  clipboard requires a separate timer + cancel-on-rewrite policy that
  is MVP-4 back-half scope. The capability allow-list permits only
  `clipboard-manager:allow-write-text` so the policy can be tightened
  later without API drift.
- **Q-b — Tauri 2.x patch version pin.** Decided: `tauri = "=2.11.2"`
  + `tauri-plugin-clipboard-manager = "=2.3.2"` + `tauri-build =
  "=2.6.2"` — the current 2.x latest at the time of the MVP-4-B build
  (May 2026). Bump in lockstep with `cargo deny` advisories.
