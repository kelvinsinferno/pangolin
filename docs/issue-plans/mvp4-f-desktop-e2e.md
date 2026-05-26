<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# MVP-4-F — Desktop E2E UX gate — plan-gate LOCKED

**Status: LOCKED — self-locked 2026-05-26.** Per MVP-4 overview §6 this slice is a **demo-gate**, not a Kelvin-architectural-gate; all engineering decisions self-locked per the no-fake-decision-gates discipline. Decisions in §0a; Kelvin reviews at the merge boundary.

## 0. One-paragraph summary

Stand up the first end-to-end UX gate for the Tauri desktop shell (MVP-4-B). A new WebDriverIO + `tauri-driver` test suite under `apps/desktop/e2e/` drives the real `pangolin-desktop` binary through the minimum viable user journey: open vault → enter master password → unlock → list accounts → reveal a password → copy via the Rust-side clipboard command. The suite runs headlessly under `xvfb-run` on `ubuntu-latest` as a new `desktop-e2e` CI job. Test data comes from a fixture vault generated at test setup time by the existing `pangolin-cli` (no committed `.pvf` blob); the fixture lives under a `tempfile::TempDir` HOME so the test never touches a real keychain / real chain / real clipboard. **No chain hits, no recovery, no multi-device** — that surface arrives in MVP-4's back half. This slice is the load-bearing integration test that gates every future desktop change.

## 0a. RESOLVED decisions (self-locked 2026-05-26)

- **E2E framework = WebDriverIO + `tauri-driver`.** The official Tauri v2 E2E path (`https://v2.tauri.app/develop/tests/webdriver/`). `tauri-driver` is a Cargo-installable proxy that bridges WebDriverIO to the Tauri WebView (WebKitGTK on Linux, WebView2 on Windows, WKWebView on macOS). Higher-fidelity than a pure mocked-`invoke()` Vitest path; correctly exercises the React renderer + the real Rust commands + the real `pangolin-ffi` chain. Industry-standard wire (W3C WebDriver) — debuggable with any WebDriver inspector.
- **Test scope = the minimum viable user journey** (5 scenarios; each a single `.test.ts` spec under `apps/desktop/e2e/specs/`):
  1. `boot_to_choose_vault` — app launches; lock-icon visible; "Choose vault file" CTA present + focused.
  2. `unlock_with_correct_password` — pick fixture vault; type correct master password; "Vault unlocked" screen renders with the 3 fixture accounts listed.
  3. `unlock_rejects_wrong_password` — pick fixture vault; type wrong password; error banner shows; no accounts list rendered; password input cleared.
  4. `reveal_password_for_account` — unlock + click an account row + "Reveal password" → asserts the plaintext is rendered to the DOM (the documented H-1 carve-out from MVP-4-B for ≤10s reveals).
  5. `copy_password_via_rust_command` — unlock + click "Copy" on an account row → asserts the Rust-side `copy_password_to_clipboard` command was invoked (via a Tauri test-hook that records command-fire events; see §3.4). Does NOT assert the OS clipboard contents — xvfb-run's clipboard sandboxing is unreliable across distros + the H-1 invariant is "the Rust path was taken", not "the system clipboard ended up with the bytes".
- **CI matrix = `ubuntu-latest` only this slice.** Matches the existing `desktop` Tauri-build job. Win + macOS E2E coverage deferred to follow-up — adds matrix-time without changing the load-bearing correctness signal (the FFI + IPC layers under test are platform-agnostic; the renderer is WebKitGTK on Linux, which is the production target for closed beta anyway). Cross-OS visual / native-clipboard coverage is a release-time concern.
- **Fixture vault = generated at test setup**, not committed. A `apps/desktop/e2e/setup/build-fixture-vault.ts` script invokes the existing `cargo run -p pangolin-cli -- vault create` + `vault add-account` flow under a `tempfile::TempDir` HOME to produce a deterministic fixture with 3 known accounts (GitHub / Gmail / Twitter; password `test-password-123!`; weak deliberately so Argon2 finishes in <1s for the test). Rebuilt at every test run from the canonical CLI, so when the PVF format evolves the fixture follows. No committed binary blob.
- **Headless display on Linux = `xvfb-run`.** Standard headless-X harness; works on `ubuntu-latest` with `sudo apt-get install -y xvfb` (cheap; the runner image ships it on every recent Ubuntu LTS, but the job declares the install to stay reproducible). The Tauri WebKitGTK WebView renders into the xvfb display; WebDriverIO talks to `tauri-driver` via localhost.
- **Test runner = pnpm script in `apps/desktop/package.json`.** New script `pnpm test:e2e` orchestrates: (a) build the fixture vault via the CLI, (b) build `pangolin-desktop` in debug mode (debug is fast + a real bug there fails differently than the production build only on optimizer-induced behavior, which is rare), (c) start `tauri-driver`, (d) run WebDriverIO against it, (e) teardown. Single pnpm command for the local dev loop + CI.
- **`tauri-driver` install = `cargo install --locked --version =2.0.6 tauri-driver`.** `tauri-driver` ships TWO release lines: `0.1.x` for Tauri v1 (legacy) and `2.0.x` for Tauri v2 (current). Pangolin is on Tauri v2 (see `apps/desktop/Cargo.toml`) so the `2.0.x` line is the correct match — installing `0.1.4` against a v2 binary fails at session start because the WebDriver shim expects the Tauri v1 lifecycle hooks. 2.0.6 is the current stable; matches the `cargo install tauri-driver --locked` floating-stable command the official Tauri v2 docs recommend (<https://v2.tauri.app/develop/tests/webdriver/>). Verified clean against `cargo audit` (no RUSTSEC advisories on `tauri-driver` itself). Installed in the CI job via the existing Swatinem cache layer (lands in `~/.cargo/bin`).
- **WebDriverIO version pin = `=9.27.2`**. The latest coordinated 9.x release across the whole `webdriverio` + `@wdio/*` monorepo as of build time. The `@wdio/types` sub-package skipped intermediate 9.x versions (jumped 9.0 → 9.27), so an earlier 9.4-era plan draft that pinned `=9.4.5` for everything was unbuildable. Pinned in `apps/desktop/e2e/package.json` (split from the main desktop package.json — see §1) to keep the heavy dev deps out of the production build's pnpm-lock + audit surface.
- **`@wdio/mocha-framework` for the spec runner.** Mocha syntax (`describe` / `it`) is the WebDriverIO default + matches the test-shape already familiar from the desktop's Vitest suite. No Jest. No Cucumber / Gherkin.
- **No visual regression tests this slice.** Chromatic / Percy / Playwright-screenshots are deferred (budget + flake-rate concerns); the WebDriverIO assertions are DOM-content + ARIA-role-based, not pixel-based.
- **No flakiness retries.** WebDriverIO defaults to zero retries; we keep that. A retry policy hides genuine timing bugs that the renderer + FFI surface are the most likely to introduce; better to fail loudly + fix the underlying race.
- **`forbid(unsafe_code)`** stays on every Rust file. The E2E suite is TypeScript-only; no new Rust crate.
- **AGPL SPDX header** on every new `.ts` / `.json` / `.sh` / `.ps1` file. Tests carry the same licence as the code under test.

## 0b. What NOT to ship in this slice

- Chain-touching tests (recovery, multi-device pairing, RevisionLog publish). Those land in their own MVP-4 back-half slice when the UX exists.
- Cross-OS coverage (Win + macOS WebDriverIO matrix). Release-time concern.
- Visual regression tests (Chromatic / Percy / Playwright screenshots).
- Performance benchmarking (page-load time / FCP / interaction latency). E2E gates assert correctness, not perf.
- Accessibility (axe-core) coverage from the WebDriverIO side — the component-library already runs axe-core under Vitest (MVP-4-D), which is the load-bearing a11y gate; rerunning axe through WebDriverIO would be duplicative.
- Internationalization / localization tests. English-only for closed beta.
- The extension's UI (MVP-4-G covers that).
- Hot-reload / watch mode for the E2E suite. The dev loop is `pnpm test:e2e` once; no watcher.
- Test report HTML upload / dashboard (Allure / wdio-html-reporter UI). CI prints the raw WebDriverIO output, which is enough at this stage.
- Reverse-direction tests (UI → `pangolin-cli` script invocation to assert vault on-disk state). The fixture-build path goes one way only.

## 1. Scope

**Built in MVP-4-F:**

- `apps/desktop/e2e/` (NEW directory at the desktop crate root, sibling to `src/`).
- `apps/desktop/e2e/package.json` — pnpm-managed, `private: true`. Deps: `webdriverio = "=9.27.2"`, `@wdio/cli = "=9.27.2"`, `@wdio/local-runner = "=9.27.2"`, `@wdio/mocha-framework = "=9.27.2"`, `@wdio/spec-reporter = "=9.27.2"`, `@wdio/types = "=9.27.2"`, `@wdio/globals = "=9.27.2"`, `mocha`, `chai`, `@types/mocha`, `@types/chai`, `typescript`, `tsx` (for the fixture-build script). Pinned via `pnpm-lock.yaml`.
- `apps/desktop/e2e/pnpm-lock.yaml` (committed).
- `apps/desktop/e2e/tsconfig.json` (strict TS, `module: "esnext"`).
- `apps/desktop/e2e/wdio.conf.ts` — WebDriverIO config: `tauri-driver` capabilities, spec glob `specs/**/*.test.ts`, mocha framework, before-suite hook that ensures the fixture vault + Tauri binary are present, after-suite hook that kills `tauri-driver`.
- `apps/desktop/e2e/specs/boot_to_choose_vault.test.ts` — scenario 1.
- `apps/desktop/e2e/specs/unlock_with_correct_password.test.ts` — scenario 2.
- `apps/desktop/e2e/specs/unlock_rejects_wrong_password.test.ts` — scenario 3.
- `apps/desktop/e2e/specs/reveal_password_for_account.test.ts` — scenario 4.
- `apps/desktop/e2e/specs/copy_password_via_rust_command.test.ts` — scenario 5.
- `apps/desktop/e2e/setup/build-fixture-vault.ts` — invokes the workspace `pangolin-cli` to create a deterministic fixture vault under a `TempDir`; writes its path to `apps/desktop/e2e/.fixture-path` for the WebDriverIO specs to read at setup time.
- `apps/desktop/e2e/setup/start-tauri-driver.ts` — spawns `tauri-driver` as a child process, waits for the WebDriver endpoint to be reachable on `localhost:4444` (default `tauri-driver` port), exits non-zero if not reachable within 30s.
- `apps/desktop/e2e/README.md` — local dev loop ("install xvfb if not present + pnpm install + pnpm test:e2e"), CI parity notes.
- `apps/desktop/e2e/.gitignore` — `.fixture-path`, `node_modules/`, `wdio-logs/`.
- `apps/desktop/package.json` (TOUCHED) — new `"test:e2e"` script that delegates to `apps/desktop/e2e/`. Also a `"build:debug"` script (`cargo build -p pangolin-desktop`) the e2e suite invokes.
- `apps/desktop/src/test_hooks.rs` (NEW Rust module, `#[cfg(any(test, feature = "test-hooks"))]`) — exposes a `record_command_invocation(name: &str)` hook that pushes the invoked command name onto a `Mutex<Vec<String>>` accessible from a new `__test__commands_invoked` Tauri command. The Tauri commands `copy_password_to_clipboard` and `reveal_password` push their name when this feature is active. Compiled out of release builds.
- `apps/desktop/Cargo.toml` (TOUCHED) — new `[features] test-hooks = []` block. CI's `desktop-e2e` job compiles with `--features test-hooks`.
- `.github/workflows/ci.yml` (TOUCHED) — new `desktop-e2e` job: `runs-on: ubuntu-latest`, depends on the same apt installs as the existing `desktop` job (`libwebkit2gtk-4.1-dev`, `libgtk-3-dev`, `xvfb`, etc.), additionally installs `tauri-driver` via `cargo install --locked --version =2.0.6 tauri-driver`, runs `pnpm install --frozen-lockfile` under `apps/desktop/e2e/`, runs `xvfb-run --auto-servernum pnpm test:e2e`. Uploads `wdio-logs/` as an artifact on failure for debug.
- Hermetic verification: the suite drives the real binary; no FFI mock, no Tauri `MockRuntime`, no fake commands. Real React, real WebView, real Rust commands, real `pangolin-ffi`.

**Deferred (NOT this slice):** per §0b.

## 2. Splittable? — ONE slice

The fixture-build harness + the WebDriverIO config + the test-hook Rust module + the CI job all need to land together for any of the 5 scenarios to execute. Splitting per-scenario would land a multi-PR sequence where each PR's "test passes" claim is moot until the harness lands. ONE PR → focused audit (test-fixture discipline, no-secret-leak from the test-hooks module, xvfb hygiene, CI-job correctness) → merge.

## 3. Design

### 3.1 Architecture

```text
┌────────────────────────────────────────────────────────────────┐
│ ubuntu-latest CI runner (also a dev's local machine)            │
│                                                                 │
│   xvfb-run --auto-servernum                                     │
│     ┌─────────────────────────────────────────────────────┐    │
│     │ Headless X display (:99)                             │    │
│     │                                                       │    │
│     │   tauri-driver (port 4444)  ◀── W3C WebDriver ──┐   │    │
│     │     │                                            │   │    │
│     │     │ spawns + drives                            │   │    │
│     │     ▼                                            │   │    │
│     │   pangolin-desktop (debug build, --features      │   │    │
│     │     test-hooks)                                  │   │    │
│     │     ├── React renderer (WebKitGTK WebView)       │   │    │
│     │     └── Rust commands + pangolin-ffi             │   │    │
│     └─────────────────────────────────────────────────────┘    │
│                                                       │         │
│                                                       │ test:e2e│
│                                                       ▼         │
│                                              ┌──────────────┐   │
│                                              │ WebDriverIO  │   │
│                                              │  + Mocha     │   │
│                                              │  (specs)     │   │
│                                              └──────────────┘   │
│                                                                 │
│   Fixture: TempDir HOME with pre-built .pvf (3 accounts)        │
│   built once at test-setup via `cargo run -p pangolin-cli`       │
└────────────────────────────────────────────────────────────────┘
```

Lifecycle:

1. CI job `desktop-e2e` checks out the repo, installs apt deps (matches the existing `desktop` job plus xvfb), installs Rust + pnpm + Node, runs `cargo install --locked --version =2.0.6 tauri-driver` (Tauri v2 line; `0.1.x` is Tauri v1 legacy).
2. `pnpm install --frozen-lockfile` under `apps/desktop/e2e/` pulls WebDriverIO + the test deps.
3. The `pnpm test:e2e` script:
   - Runs `tsx setup/build-fixture-vault.ts` → invokes `cargo run -p pangolin-cli -- vault create` + `vault add-account` 3× under a fresh `TempDir`, writes the path to `.fixture-path`.
   - Runs `cargo build -p pangolin-desktop --features test-hooks` → produces the debug binary that records command invocations.
   - Runs `tsx setup/start-tauri-driver.ts` → spawns `tauri-driver` as a background process under xvfb-run, waits for port 4444 to bind.
   - Runs `wdio run wdio.conf.ts` → executes the 5 spec files in series under Mocha.
   - On exit (success or failure): sends SIGTERM to `tauri-driver`, removes the TempDir HOME.
4. Each spec:
   - WebDriverIO connects to `tauri-driver` at `localhost:4444`.
   - `tauri-driver` spawns the `pangolin-desktop` binary as a child, scoped to the xvfb display.
   - The spec drives the renderer via WebDriverIO selectors (DOM + ARIA roles per the component-library's accessibility discipline).
   - For the "command was invoked" assertion in scenario 5, the spec calls a `__test__commands_invoked` Tauri command via `tauri::Invoke` over WebDriverIO's `executeAsync` hook to read the in-memory log.
   - WebDriverIO + tauri-driver kill the desktop binary on spec end.

### 3.2 Test-hooks Rust module (the only Rust-side change)

`apps/desktop/src/test_hooks.rs`:

```rust
//! Test-only command-invocation log for the E2E gate.
//!
//! Compiled in under the `test-hooks` feature (CI's `desktop-e2e` job
//! enables it; production release builds DO NOT). Records the name of
//! every privileged Tauri command that fires so the WebDriverIO suite
//! can assert that scenario 5 (`copy_password_via_rust_command`) took
//! the Rust-side clipboard path instead of routing plaintext through
//! V8 (the H-1 invariant from MVP-4-B).

#![cfg(feature = "test-hooks")]
#![forbid(unsafe_code)]

use std::sync::Mutex;

static INVOCATIONS: Mutex<Vec<String>> = Mutex::new(Vec::new());

pub fn record(command_name: &'static str) {
    if let Ok(mut g) = INVOCATIONS.lock() {
        g.push(command_name.to_string());
    }
}

#[tauri::command]
pub fn __test__commands_invoked() -> Vec<String> {
    INVOCATIONS.lock()
        .map(|g| g.clone())
        .unwrap_or_default()
}

#[tauri::command]
pub fn __test__clear_invocations() {
    if let Ok(mut g) = INVOCATIONS.lock() {
        g.clear();
    }
}
```

`apps/desktop/src/commands/account.rs::copy_password_to_clipboard` and `reveal_password` add a single line `#[cfg(feature = "test-hooks")] crate::test_hooks::record("copy_password_to_clipboard");` at the top of the function body. The hook is a NO-OP in production builds (the feature gate compiles the call out entirely).

The two `__test__*` commands are registered conditionally in `lib.rs::build_app`:

```rust
#[cfg(feature = "test-hooks")]
.invoke_handler(tauri::generate_handler![..existing.., __test__commands_invoked, __test__clear_invocations])
```

### 3.3 Fixture-vault build

`setup/build-fixture-vault.ts` invokes the workspace CLI via `child_process.spawnSync`:

```text
$TMPDIR/pangolin-e2e-fixture/
  ├── HOME/                    (set as HOME for every CLI call)
  │   └── .pangolin/           (vault data + config)
  └── vault.pvf                (the fixture file the UI opens)
```

CLI commands (in order; using the existing P11B `vault create` + P11A `account add` shape):

```bash
# 1. Create a fresh vault. `--password-stdin` reads the master from
#    the first line of stdin; this is the only non-prompt password
#    entry path the CLI exposes (per `cli.rs::VaultCreateArgs` —
#    flag-form `--password <value>` is deliberately refused because
#    it leaks via `ps aux`).
echo "test-password-123!" | cargo run -p pangolin-cli -- \
    vault create --vault-path "$FIXTURE_DIR/vault.pvf" --password-stdin

# 2-4. Add three accounts. `account add` accepts a CI-leaky
#    `--vault-password <value>` flag explicitly for scripted use
#    (the cli.rs docstring calls this out as "echoes in `ps`; CI use
#    only" — fixture builds are exactly that). Account password
#    routes through `--password-stdin`. `--no-totp` skips the TOTP
#    prompt that would otherwise block on stdin.
echo "github-fixture-pw-1" | cargo run -p pangolin-cli -- account add \
    --vault-path "$FIXTURE_DIR/vault.pvf" --vault-password "test-password-123!" \
    --name "GitHub" --username "alice@example.com" --password-stdin --no-totp

echo "gmail-fixture-pw-2" | cargo run -p pangolin-cli -- account add \
    --vault-path "$FIXTURE_DIR/vault.pvf" --vault-password "test-password-123!" \
    --name "Gmail" --username "alice@gmail.com" --password-stdin --no-totp

echo "twitter-fixture-pw-3" | cargo run -p pangolin-cli -- account add \
    --vault-path "$FIXTURE_DIR/vault.pvf" --vault-password "test-password-123!" \
    --name "Twitter" --username "alice_handle" --password-stdin --no-totp
```

The Argon2 KDF runs once per CLI invocation; with `test-password-123!` (deliberately weak) the KDF finishes in <500ms on the CI runner. Total fixture-build time: ~3-4s. The fixture passwords are deliberately unique + greppable so a spec assertion like `await expect(passwordField).toHaveText("github-fixture-pw-1")` is unambiguous.

Builder note on the `--vault-password` flag: this is the documented CI-only path for scripted vault access. The fixture-build script lives entirely within the E2E suite + uses fixture passwords; no real-user secret ever touches this flag. The same flag is what powers existing CI smoke tests for `account show` / `account update` / `account delete`.

### 3.4 WebDriverIO selector discipline

Selectors prefer (in order):
1. `data-testid="<stable-id>"` attributes — added to the React components in `apps/desktop/src/ui/` ONLY for E2E selector stability (does NOT cross into the component-library; the desktop owns its own E2E surface).
2. ARIA roles + accessible names (`getByRole('button', { name: /unlock/i })` etc.) — matches the component-library's accessibility-first stance.
3. Text content — last resort, only when the ARIA name is volatile.

`data-testid` attributes added this slice:
- `vault-file-picker` — the "Choose vault file" CTA on the boot screen.
- `master-password-input` — the password field on the unlock screen.
- `unlock-error-banner` — the error banner shown on wrong-password.
- `accounts-list` — the unlocked-state list container.
- `account-row-<index>` — each account row (e.g. `account-row-0`, `account-row-1`, …).
- `reveal-password-button` — the reveal CTA on the account detail screen.
- `revealed-password-text` — the rendered plaintext element.
- `copy-password-button` — the copy CTA.

`data-testid` is a non-render attribute; no styling reaches it; production users never see it; the React component-library tests (Vitest) do NOT rely on it.

### 3.5 CI integration

New job in `.github/workflows/ci.yml`:

```yaml
desktop-e2e:
  name: desktop-e2e
  runs-on: ubuntu-latest
  needs: [desktop, component-library]  # ensure their gates passed first
  steps:
    - uses: actions/checkout@v4
    - name: "Install Tauri + xvfb Linux system deps (apt)"
      run: |
        sudo apt-get update
        sudo apt-get install -y \
          libwebkit2gtk-4.1-dev libgtk-3-dev libsoup-3.0-dev libxdo-dev \
          libssl-dev libayatana-appindicator3-dev librsvg2-dev libdbus-1-dev \
          pkg-config xvfb
    - uses: dtolnay/rust-toolchain@stable
    - uses: Swatinem/rust-cache@v2
      with:
        prefix-key: "v1"
        cache-bin: "false"
    - name: "Install tauri-driver"
      run: cargo install --locked --version =0.1.4 tauri-driver
    - uses: pnpm/action-setup@v4
      with:
        version: 10
    - uses: actions/setup-node@v4
      with:
        node-version-file: 'apps/desktop/.nvmrc'
        cache: 'pnpm'
        cache-dependency-path: 'apps/desktop/e2e/pnpm-lock.yaml'
    - name: "Install E2E pnpm deps"
      working-directory: apps/desktop/e2e
      run: pnpm install --frozen-lockfile
    - name: "Run E2E suite under xvfb"
      working-directory: apps/desktop
      run: xvfb-run --auto-servernum pnpm test:e2e
    - name: "Upload wdio logs on failure"
      if: failure()
      uses: actions/upload-artifact@v4
      with:
        name: wdio-logs
        path: apps/desktop/e2e/wdio-logs/
        retention-days: 7
```

Reused libdbus-1-dev install (from the MVP-4-E hotfix); reuses pnpm 10 + Node `.nvmrc` pattern from the `desktop` + `component-library` jobs.

## 4. L-invariants

- **L1 zero-secret-crosses-FFI** still holds. The fixture passwords (`github-fixture-pw-1` etc.) are NOT real secrets; they're test fixtures generated fresh per run. The H-1 invariant from MVP-4-B (`copy_password_to_clipboard` is Rust-side; plaintext never crosses V8 except in the deliberate `reveal_password` carve-out) is the load-bearing assertion of scenario 5 — that's exactly what the test-hooks log proves.
- **L2 no new atomic surface.** The E2E suite drives existing Tauri commands; no new state machines.
- **L3 fail-closed.** Test-hook commands are gated behind a feature flag; production builds cannot see them. The `__test__*` commands return empty / clear-only outputs that carry no privileged data even if accidentally exposed.
- **L5 new external deps:** `webdriverio = "=9.27.2"` + the full `@wdio/{cli,types,globals,local-runner,mocha-framework,spec-reporter} = "=9.27.2"` set (latest coordinated 9.x release), `mocha`, `chai`, `tsx`, `tauri-driver` (Cargo, pinned `=2.0.6` — Tauri v2 line). All scoped to `apps/desktop/e2e/`; do NOT enter the production lockfile or the workspace audit / deny surface. Verified separately by the new job; advisories run inside the E2E job too.
- **L6 testnet-only / D-011.** This slice does not touch chain code.
- **L7 errors carry no secret.** Test-hook log records command NAMES only; no params, no return values. Even with the feature flag accidentally on in a release build, no secret material leaks.
- **L8 tests:** the slice IS the test layer.
- **L9 §16 ledger** — DECISIONS / DEVLOG on merge.

## 5. Open decisions — pre-locked (one carve-out for the builder)

- **Q-a (tauri-driver port management): builder's call.** Default port 4444 is fine for single-suite serial runs; if a flake surfaces in CI from "port already in use" (rare — the job is in a fresh runner each time), the builder may move to a randomized port via `$PORT` env-var + WebDriverIO config interpolation. Either approach is acceptable.

All other decisions are locked per §0a.

## 6. Places that need care

- **`tauri-driver` ↔ WebKitGTK timing.** The Tauri binary needs ~1-3s to boot the WebView. WebDriverIO's default implicit-wait is 0; rely on explicit `await element.waitForExist({ timeout: 15_000 })` at the start of every spec. Don't use `sleep()` calls — they hide genuine timing bugs that the renderer + FFI surface are the most likely to introduce.
- **xvfb display lifecycle.** `xvfb-run --auto-servernum` allocates a new display per invocation; the wrapper handles teardown when the wrapped command exits. Do NOT background the wrapped command — when xvfb-run exits, it kills the X server + everything bound to it. If a future builder splits the orchestration across multiple commands, switch to explicit `Xvfb :99 -screen 0 1280x1024x24 &` + `DISPLAY=:99` env-var + manual cleanup, OR keep the wrapper as a single command (preferred).
- **`tauri-driver` is single-WebView.** It cannot drive multiple Tauri windows simultaneously. The desktop opens only one window in this slice, so this is fine; future multi-window UI (e.g., a separate settings dialog) needs a different approach.
- **The test-hooks feature flag must NEVER be on in release builds.** The release pipeline (out of MVP-4-F scope) gates `cargo build -p pangolin-desktop --release` WITHOUT `--features test-hooks`; CI's `desktop` (non-E2E) job continues to build without the flag as a regression-catch. The `__test__*` commands are not in the Tauri capability allowlist either (their `tauri::generate_handler!` registration is feature-gated) — defense in depth.
- **Fixture vault Argon2 cost.** The CLI uses the default Argon2 params for production; with the chosen weak fixture password `test-password-123!` the KDF still completes in <500ms because Argon2's cost is parameter-driven, not password-driven. If a future iteration tunes the production KDF cost UP, the fixture-build time goes up linearly. If E2E build time becomes painful (>10s per scenario), add a CLI flag `--kdf-fast` that the fixture-builder uses (NOT this slice).
- **WebDriverIO + ESM imports.** `wdio.conf.ts` uses ESM (`type: "module"` in package.json). Recent WebDriverIO 9.x supports it natively but some plugins (e.g. older `@wdio/cli` versions) still emit CJS interop warnings. The pinned `=9.4.x` is verified clean; bumping requires re-verifying.
- **Spec ordering matters.** Scenario 2 (`unlock_with_correct_password`) leaves the desktop in an unlocked state at exit. Scenario 3 (`unlock_rejects_wrong_password`) needs to start from a clean boot. WebDriverIO's `tauri-driver` capability spawns a fresh binary per spec by default, so this is handled — but a future "speed up by sharing a session across specs" refactor MUST add explicit lock-state reset between specs.
- **Selector stability.** The 8 `data-testid` attributes introduced this slice are the load-bearing E2E contract. Renaming any of them is a coordinated change with `apps/desktop/e2e/specs/`. Document them in the README of `apps/desktop/e2e/` + grep gate in the audit.
- **AGPL SPDX header** on every new `.ts` / `.json` / `.rs` file. The `package.json` declares `"license": "AGPL-3.0-or-later"`.

## 7. Success criteria

- `cargo build -p pangolin-desktop --features test-hooks` clean on Linux.
- `cargo build -p pangolin-desktop` (no `--features test-hooks`) still clean — confirms the feature gate is correctly applied.
- `cargo clippy -p pangolin-desktop --features test-hooks --all-targets -- -D warnings` ✓.
- `pnpm typecheck` ✓ under `apps/desktop/e2e/`.
- `pnpm lint` ✓ under `apps/desktop/e2e/` (ESLint + `@typescript-eslint`).
- `xvfb-run --auto-servernum pnpm test:e2e` ✓ locally on Linux (in the CI image's environment) — all 5 scenarios pass.
- New CI job `desktop-e2e` green on `ubuntu-latest`.
- The existing `desktop` job still passes WITHOUT the `test-hooks` feature (regression-catch on the feature-gate hygiene).
- `cargo audit --deny warnings <existing --ignore set>` ✓ (no new advisories from `tauri-driver` 0.1.4).
- `cargo deny check advisories bans licenses sources` ✓.
- Cardinal invariants still 0/0/0.

## 8. Out of scope (filed for follow-up)

- All §0b items.
- Performance budgets (e.g. "unlock screen renders in <500ms"). E2E gates are correctness gates; perf budgets live in a perf-dashboard slice.
- Mutation testing of the test suite itself. Defer until the gate has stabilized.
- Sharded parallel test execution (per-OS / per-spec parallelism). Single-runner serial is fine at 5 scenarios.
- Generated-test scaffolding (a CLI that emits a new `.test.ts` from a template). Premature.
- Localized assertion strings — English-only.
- Recording videos of failed test runs (a `@wdio/visual-service` or screencast plugin). The on-failure WebDriverIO logs are enough at this stage.
- Test-hooks for the extension popup (MVP-4-G ships its own equivalent via `puppeteer` + the native-messaging host).
