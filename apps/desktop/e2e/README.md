<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Pangolin desktop E2E gate (MVP-4-F)

End-to-end UX gate for the `pangolin-desktop` Tauri v2 shell. Five
WebDriverIO + `tauri-driver` scenarios drive the real binary through
the minimum viable user journey: open vault → unlock → list accounts
→ reveal → copy.

Plan-LOCK: [`docs/issue-plans/mvp4-f-desktop-e2e.md`](../../../docs/issue-plans/mvp4-f-desktop-e2e.md).

## Scenarios

| Scenario | File |
|---|---|
| `boot_to_choose_vault` | `specs/boot_to_choose_vault.test.ts` |
| `unlock_with_correct_password` | `specs/unlock_with_correct_password.test.ts` |
| `unlock_rejects_wrong_password` | `specs/unlock_rejects_wrong_password.test.ts` |
| `reveal_password_for_account` | `specs/reveal_password_for_account.test.ts` |
| `copy_password_via_rust_command` | `specs/copy_password_via_rust_command.test.ts` |

## Selector contract (`data-testid` stable IDs)

The suite selects on `data-testid` attributes added to the React
components for E2E stability. **Renaming any of these is a
coordinated change with the spec files.**

| ID | Component | Purpose |
|---|---|---|
| `vault-file-picker` | `WelcomeScreen` | Cold-boot CTA wrapper |
| `master-password-input` | `UnlockScreen` | Password field wrapper |
| `unlock-error-banner` | `UnlockScreen` | Wrong-password banner wrapper |
| `accounts-list` | `AccountListScreen` | Unlocked-state list container |
| `account-row-<N>` | `AccountListScreen` | Per-row stable index |
| `reveal-password-button` | `AccountDetailScreen` | Reveal CTA wrapper |
| `revealed-password-text` | `AccountDetailScreen` | Plaintext output wrapper |
| `copy-password-button` | `AccountDetailScreen` | Copy CTA wrapper |

## Local dev loop

Linux only — the WebKitGTK WebView E2E runs against `xvfb` (or the
host's native X server). On macOS / Windows the renderer is a
different WebView; cross-OS coverage is deferred per plan §0a.

Prerequisites:

- The Tauri Linux system deps (`libwebkit2gtk-4.1-dev`, `libgtk-3-dev`,
  `libsoup-3.0-dev`, `libxdo-dev`, `libssl-dev`,
  `libayatana-appindicator3-dev`, `librsvg2-dev`, `libdbus-1-dev`,
  `pkg-config`).
- `xvfb` (`sudo apt-get install -y xvfb`).
- `tauri-driver` 2.0.6 (`cargo install --locked --version =2.0.6 tauri-driver`).
  The `0.1.x` line is the LEGACY Tauri v1 driver and will NOT work
  against the Pangolin Tauri v2 binary — installing it fails at
  WebDriver session init. Always pin a `2.0.x` release.
- pnpm 10 + Node 20.18 (per `.nvmrc` and the `extension` / `desktop`
  CI jobs).

Run:

```bash
cd apps/desktop/e2e
pnpm install --frozen-lockfile
xvfb-run --auto-servernum pnpm e2e
```

`pnpm e2e` orchestrates the full pipeline:

1. `tsx setup/build-fixture-vault.ts` — builds the deterministic fixture
   vault under a fresh tempdir via `pangolin-cli`; writes the absolute
   path to `.fixture-path`.
2. `cargo build -p pangolin-desktop --features test-hooks` — produces
   the debug binary the WebDriverIO suite spawns (the `test-hooks`
   feature flag enables the `__test__commands_invoked` Tauri command
   the scenario-5 spec reads).
3. `wdio run wdio.conf.ts` — executes the five spec files in series.

The `wdio.conf.ts` `onPrepare` hook spawns `tauri-driver` on port
4444; `onComplete` reaps it.

## CI parity

CI runs the same orchestration via the `desktop-e2e` job in
`.github/workflows/ci.yml`. The job installs the same apt deps + the
same pinned `tauri-driver` 2.0.6, then runs `xvfb-run --auto-servernum
pnpm e2e` under `apps/desktop/e2e/`. Failed runs upload
`wdio-logs/` as an artifact for debug.

## Out of scope

See plan §0b. Notably: chain-touching flows, cross-OS matrix, visual
regression tests, perf benchmarking, axe-core a11y (covered by the
component-library Vitest suite), i18n / l10n.
