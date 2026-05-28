<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# MVP-4-G — Extension E2E UX gate (popup ⇄ native-messaging host ⇄ desktop) — plan-gate LOCKED

**Status: LOCKED — Kelvin sign-off 2026-05-27; AMENDED 2026-05-28 (Q-c: E2E transport boundary).** Q-a resolved: Option 1 (manual paste at first connection). Q-c resolved: the automated E2E gate uses an **injected stdio host-bridge** against the real `pangolin-native-messaging-host` binary + real desktop, NOT Chrome's `chrome.runtime.connectNative`, because Chrome for Testing 138+ refuses to spawn native-messaging hosts for `--load-extension` dev-loaded extensions (diagnosed via strace 2026-05-28; see §0a Q-c). The real-Chrome transport path is covered by a documented MANUAL smoke test (§9) run before closed beta. All other engineering choices self-locked. Decisions in §0a.

## 0. One-paragraph summary

Wire the Chromium MV3 extension popup (MVP-4-C scaffold) to actually talk to the running Tauri desktop via the native-messaging host (MVP-4-E), and stand up the second end-to-end UX gate to prove the full popup-client→host→desktop chain works. In production the popup connects via `chrome.runtime.connectNative('studio.kelvinsinferno.pangolin.host')`, performs the auth handshake with the desktop-generated token, calls `session.status` + `vault.list_accounts` + `vault.copy_password`, and renders the account list with copy buttons. The H-1 invariant: the extension's "Copy" routes through Rust-side `copy_password_to_clipboard`, NOT through V8 plaintext crossing.

**Test-coverage split (Q-c, amended 2026-05-28):**
- **Popup UI + state machine** (provisioning → connecting → connected → error, token paste, copy click): covered by **Vitest** (`apps/extension/src/popup/*.test.tsx`) with a mocked connector — fast, hermetic, already green.
- **Cross-process data path** (the real `NativeHostClient` → real `pangolin-native-messaging-host` binary → real `pangolin-desktop` IPC → `pangolin-ffi`), including the H-1 `copy_password_to_clipboard` assertion: covered by a **Node integration gate** (`apps/extension/e2e/`) that injects a stdio host-bridge connector into the real `NativeHostClient`, spawns the actual host binary, and frames stdin/stdout with byte-identical native-messaging framing (4-byte LE length + UTF-8 JSON — the EXACT protocol the host expects). This exercises every line of OUR code end-to-end against the real binaries; only Chrome's `connectNative` transport (Google's code) is replaced.
- **Real-Chrome transport** (`chrome.runtime.connectNative` + Chrome's `allowed_origins` enforcement): covered by a **manual smoke test** (§9), run by a human before closed beta. Automated real-Chrome testing is blocked by a Chrome-for-Testing platform restriction (§0a Q-c).

Reuses MVP-4-F's fixture-vault builder + test-hooks Rust feature.

## 0a. RESOLVED decisions

**Kelvin-approved (2026-05-27):**

- **Q-a (token provisioning) = Option 1 (manual paste at first connection).** Desktop's `install-native-host` command prints the generated 32-byte handshake token to stdout (in addition to writing the OS keychain + sibling file). The extension popup's provisioning view shows on first open with no stored token; user pastes; extension stores in `chrome.storage.local` (encrypted at rest by Chrome's profile key). Future popup opens skip provisioning. Token rotation via `uninstall-native-host` causes the next popup open's `chrome.runtime.connectNative` to fail with `auth_failed`; popup clears the stored token + reverts to provisioning. Trade-off accepted: one-time manual step on install, justified by zero-new-IPC-surface + the user gesture (typing the install command) being its own trust anchor. Option 2 (deep-link) deferred to MVP-4 back-half polish if closed-beta feedback wants it.

**Kelvin-approved AMENDMENT (2026-05-28):**

- **Q-c (E2E transport boundary) = injected stdio host-bridge + manual real-Chrome smoke test.** The original plan (below) called for Puppeteer driving a real Chrome with the unpacked extension. During the build cycle this proved impossible: **Chrome for Testing 138 (and Chrome stable 137+) refuse to spawn native-messaging hosts for `--load-extension` dev-loaded extensions.** Diagnosed empirically on 2026-05-28 — the manifest was byte-correct + in all four browser config dirs (`google-chrome`, `google-chrome-for-testing`, `chromium`, brave) with the right `name`, `allowed_origins`, and an absolute `path` to an existing binary; `strace -f -e openat` showed Chrome made **zero** `NativeMessagingHosts` filesystem accesses before returning `Unchecked runtime.lastError: Specified native messaging host not found`. Chrome short-circuits the lookup for dev-loaded extensions — a platform restriction, not a Pangolin bug.

  **Resolution (decided after weighing security + product-foundation):**
  - The automated CI gate (`apps/extension/e2e/`) becomes a **Node integration test** (not Puppeteer/Chrome). It injects a connector into the real `NativeHostClient` that spawns the actual `pangolin-native-messaging-host` binary and pipes its stdin/stdout with **byte-identical native-messaging framing** (4-byte LE length + UTF-8 JSON, the same protocol `frame.rs` implements). The real desktop runs in the background. This verifies 100% of OUR security-relevant code end-to-end: the handshake-token gate (INNER lock), the JSON-RPC relay, the `copy_password_to_clipboard` Rust-side path (H-1), the host's framing + error mapping.
  - What this does NOT verify: Chrome's `allowed_origins` enforcement (the OUTER lock) + Chrome's actual `connectNative` transport. Those are Google's code — we configure the manifest correctly (and DO test the manifest GENERATION: name, allowed_origins, absolute path), but cannot meaningfully unit-test Google's honoring of it.
  - **Why this is the most secure ACHIEVABLE option**: it tests every security property that is Pangolin's responsibility against the real binaries. The real-Chrome path is the OUTER lock, covered by the §9 manual smoke test before closed beta (mirrors the MVP-3 pattern of hermetic tests + a human-run live check; env-quirk #14).
  - **Why this is the best product foundation**: it gives a stable, fast, CI-friendly harness that every future popup↔desktop feature (recovery UX, multi-device UX, autofill) inherits, without being hostage to Chrome's ever-tightening dev-mode native-messaging restrictions. Pinning an old Chrome-for-Testing (the alternative) is a ticking time bomb — Google prunes old CfT builds + it validates against a browser real users don't run.
  - **Framing fidelity is mandatory**: the injected connector MUST replicate Chrome's native-messaging stdio framing exactly (4-byte little-endian length prefix + UTF-8 JSON body, ≤1 MB/frame). A divergent framing would make the test pass on a protocol production rejects. The connector spawns the REAL host binary, so the host does its own framing on its side; the connector must match it on the popup side.

**Self-locked (original — Puppeteer approach SUPERSEDED by Q-c above; retained for context):**

- ~~**E2E framework = Puppeteer.**~~ Superseded by Q-c. Puppeteer's `--load-extension` MV3 support is real, but Chrome-for-Testing's native-messaging restriction makes the popup→host hop untestable through Chrome. The `apps/extension/e2e/` directory still exists but holds the Node integration gate, not a Puppeteer suite.
- **The popup actually wires up to native-messaging this slice.** MVP-4-C left it as a placeholder hard-coded "Desktop not connected" view; MVP-4-G replaces that with the real `chrome.runtime.connectNative` flow, the JSON-RPC client, and the account-list UI. NO autofill, NO content-script wiring beyond a token-state ping — just the popup.
- **Reuse MVP-4-F's fixture-vault build script** (`apps/desktop/e2e/setup/build-fixture-vault.ts`). The same `test-password-123!` master + 3 GitHub/Gmail/Twitter accounts. MVP-4-G's e2e setup imports the script + builds the same fixture (different TempDir HOME).
- **Reuse MVP-4-F's `test-hooks` Cargo feature on `pangolin-desktop`.** The `__test__commands_invoked` log is the same H-1 oracle — scenario 4 reads it via the desktop's IPC server (the extension can't reach it directly; the test harness's own desktop-side WDIO connection does).
- **Stable extension ID = manifest `key` field** committed to `apps/extension/manifest.json`. Chrome derives the extension ID from the public key in `key` (if present); otherwise it picks one at load time. Without a stable ID we can't put it in the native-messaging manifest's `allowed_origins` list — that's the OUTER trust lock per MVP-4-E §0a. We generate a dev key + commit it; production builds use Chrome Web Store's key (out of scope, MVP-4 back-half).
- **Test harness uses xvfb + headless-new Chrome (`--headless=new`)**. Headless-new is required for MV3 service workers (legacy headless doesn't support them). The xvfb wrapper handles the display teardown the same way MVP-4-F uses it.
- **CI matrix = `ubuntu-latest` only this slice.** Same Linux-only justification as MVP-4-F.
- **`forbid(unsafe_code)` + AGPL SPDX header** on every new file.

## 0b. What NOT to ship in this slice

- Autofill on web pages (the content-script reads form fields + injects credentials). Per the plan-LOCK overview that's a separate slice (MVP-4 back-half, "autofill" gets its own plan-LOCK).
- Reveal password from the popup. Per MVP-4-E §0a: "`vault.reveal_password` is NOT exposed" through the native-messaging surface — the extension never holds plaintext. Copy is allowed because the plaintext stays Rust-side (H-1 carve-out).
- Recovery / multi-device UX in the popup. MVP-4 back-half.
- Cross-OS extension E2E (Win, macOS, Brave, Edge). Release-time concern.
- Firefox WebExtensions port. MVP-4.5.
- Production extension `key` (Chrome Web Store signing). Dev `key` only.
- Settings / preferences UI in the popup. MVP-4 back-half.
- Service-worker autoconnect-on-idle. Popup-driven for this slice (user clicks the toolbar icon, popup opens, popup initiates `connectNative`).
- Audit-grade UX polish (transitions, error animations, i18n). English-only, functional UI.
- Token rotation UX. Out of scope; ties into MVP-4-H pre-mainnet hardening.

## 1. Scope

**Built in MVP-4-G:**

- `apps/extension/src/popup/native-host.ts` (NEW) — JSON-RPC client wrapping `chrome.runtime.connectNative`. Handles the 4-byte LE length-prefix framing, request/response ID correlation, the `auth.handshake` opening exchange, typed error mapping. ~150-200 LoC TypeScript.
- `apps/extension/src/popup/Popup.tsx` (REWRITTEN) — replaces the placeholder with the real flow: state machine (provisioning → connecting → connected → error), token-provisioning view (Option 1 per Q-a), account-list view, per-row Copy button. Wires to `native-host.ts`.
- `apps/extension/src/popup/account-list.ts` (NEW) — the `FfiAccountSummary` rendering helpers + Copy handlers.
- `apps/extension/src/popup/use-native-host.ts` (NEW) — React hook around the JSON-RPC client; manages lifecycle + retry on transient disconnect.
- `apps/extension/src/popup/token-store.ts` (NEW) — `chrome.storage.local` get/set/clear helpers, typed.
- `apps/extension/manifest.json` (TOUCHED) — add the `key` field (committed dev public key) for stable extension ID.
- `apps/extension/e2e/` (NEW DIRECTORY) — Puppeteer test harness:
  - `package.json`, `pnpm-lock.yaml` (committed), `tsconfig.json`, `eslint.config.js`, `README.md`, `.gitignore`.
  - `setup/start-desktop.ts` — spawns `pangolin-desktop --features test-hooks,custom-protocol` in background, captures pid, ensures clean teardown.
  - `setup/install-native-host.ts` — runs the desktop's `install-native-host` CLI subcommand with a TempDir HOME; captures the printed token + the per-OS manifest paths.
  - `setup/launch-chrome.ts` — launches Puppeteer with `--load-extension`, `--disable-extensions-except`, `--headless=new`; navigates to `chrome://extensions` to extract the actual loaded extension ID (verify it matches the `key`-derived ID).
  - `specs/popup_loads_disconnected.test.ts` — scenario 1.
  - `specs/popup_provisions_and_connects.test.ts` — scenario 2 (Option-1 flow).
  - `specs/popup_lists_accounts.test.ts` — scenario 3.
  - `specs/popup_copies_password.test.ts` — scenario 4 (H-1 invariant).
  - `specs/popup_handles_desktop_disconnect.test.ts` — scenario 5.
- `apps/desktop/src/commands/install_native_host.rs` (TOUCHED) — print the generated handshake token to stdout (in addition to the keychain + sibling-file writes). Per Q-a Option 1.
- `.github/workflows/ci.yml` (TOUCHED) — new `extension-e2e` job: ubuntu-latest, needs [extension, desktop, native-messaging-host, desktop-e2e]. Apt deps: `libwebkit2gtk-4.1-dev webkit2gtk-driver libgtk-3-dev libsoup-3.0-dev libxdo-dev libssl-dev libayatana-appindicator3-dev librsvg2-dev libdbus-1-dev pkg-config xvfb google-chrome-stable`. Builds desktop with test-hooks + builds extension dist + runs `xvfb-run --auto-servernum pnpm e2e` under `apps/extension/e2e/`.
- Hermetic tests: the extension's existing Vitest suite gets new tests for `native-host.ts` (mocked `chrome.runtime.connectNative`), `use-native-host.ts` (mocked Chrome storage), and `Popup.tsx` state machine.

**Deferred (NOT this slice):** per §0b.

## 2. Splittable? — ONE slice

The popup wiring + the Puppeteer harness + the install-native-host token-print + the CI job all need to land together for any of the 5 scenarios to execute. ONE PR → focused audit (token-provisioning trust model, JSON-RPC client framing safety, popup state-machine correctness, Puppeteer harness hygiene) → merge.

## 3. Design

### 3.1 Architecture

```text
┌─────────────────────────────────────────────────────────────────┐
│ ubuntu-latest CI runner (or dev WSL)                             │
│                                                                  │
│   xvfb-run                                                       │
│     ┌────────────────────────────────────────────────────────┐  │
│     │ Headless X display (:99)                                │  │
│     │                                                         │  │
│     │   pangolin-desktop (debug, --features test-hooks,       │  │
│     │     custom-protocol) — running in background            │  │
│     │     ├─ IPC server bound at per-user pipe/socket         │  │
│     │     ├─ vault unlocked with fixture password             │  │
│     │     └─ test-hooks command-invocation log live           │  │
│     │                                                         │  │
│     │   google-chrome-stable --headless=new                   │  │
│     │     --load-extension=apps/extension/dist                │  │
│     │     ↓                                                   │  │
│     │   Extension popup ⇄ chrome.runtime.connectNative ⇄      │  │
│     │     pangolin-native-messaging-host (spawned by Chrome)  │  │
│     │     ⇄ IPC ⇄ pangolin-desktop                            │  │
│     │                                                         │  │
│     └────────────────────────────────────────────────────────┘  │
│                                                       ▲          │
│                                                       │ Puppeteer│
│                                                       │ + Mocha  │
│                                                       │          │
│   Puppeteer drives the popup via the extension's      │          │
│   service-worker context + the popup window.          │          │
└─────────────────────────────────────────────────────────────────┘
```

Lifecycle (per spec):

1. CI installs apt deps + tauri-driver dependencies + google-chrome-stable.
2. `pnpm e2e` orchestrates: (a) build the fixture vault, (b) build the desktop debug binary with test-hooks+custom-protocol, (c) build the extension dist via `pnpm build`, (d) install native-messaging-host manifests under TempDir HOME via `pangolin-desktop install-native-host` (capturing the printed token), (e) spawn `pangolin-desktop` in background, wait for IPC server to bind, (f) launch Puppeteer/Chrome with the extension loaded, (g) run the 5 specs serially.
3. Each spec uses Puppeteer to interact with the popup window (`chrome-extension://<id>/src/popup/popup.html`), assert DOM state, optionally read the desktop's test-hooks log via a side-channel WDIO-style call to a host-local diagnostic endpoint.
4. Teardown: SIGTERM Chrome → SIGTERM the desktop binary → scrub the TempDir HOME's vault sidecars (carries the LOW-1 workaround from MVP-4-F until the underlying production bug is fixed per issue #3).

### 3.2 Token provisioning (per Q-a — Kelvin chooses; default Option 1)

**Option 1 flow** (the recommendation):

1. User runs `pangolin-desktop install-native-host` from a terminal.
2. Desktop generates a fresh 32-byte token, stores in keychain + sibling file + writes the per-OS native-messaging manifests + **prints the token to stdout** as `EXTENSION_TOKEN=<base64url-32-bytes>`.
3. User copies the token. Opens browser. Opens Pangolin extension popup.
4. Popup, on first open with no `chrome.storage.local["extensionToken"]`, shows a provisioning view: "Paste the extension token from your terminal:" + textarea + Save button.
5. On Save, popup stores the token + transitions to the connect view. Subsequent opens skip provisioning and go straight to connect.
6. The popup calls `chrome.runtime.connectNative('studio.kelvinsinferno.pangolin.host')`. Chrome spawns the host. Popup sends `{"method":"auth.handshake","params":{"token":"..."}}` as the first JSON-RPC frame. Host constant-time-compares against the keychain token. Match → connection upgraded. Mismatch → host emits `auth_failed` + exits 1; popup clears the stored token + returns to provisioning.

**Token rotation**: if the desktop's `uninstall-native-host` rotates the token, the next popup-open's `chrome.runtime.connectNative` fails with `auth_failed`, the popup clears + re-prompts.

### 3.3 JSON-RPC client (popup-side)

`native-host.ts` exposes:

```ts
class NativeHostClient {
  connect(token: string): Promise<void>;            // chrome.runtime.connectNative + auth.handshake
  sessionStatus(): Promise<SessionStatus>;
  listAccounts(): Promise<AccountSummary[]>;
  copyPassword(id: string): Promise<void>;          // Rust-side clipboard; no plaintext returned
  disconnect(): void;
}
```

Wire shape on `chrome.runtime.connectNative`'s `port`: Chrome handles the 4-byte LE length-prefix framing internally; the popup just `port.postMessage(jsonObj)` and listens on `port.onMessage`. Request/response correlation by integer `id`. Errors map per MVP-4-E §3.2 `{code, message, data}`.

L1 discipline: NO method that returns plaintext. `reveal_password` is deliberately absent from the client surface. `copyPassword(id)` returns `void` — the clipboard write happens entirely Rust-side, mirroring MVP-4-B's H-1 invariant.

### 3.4 The 5 scenarios

1. `popup_loads_disconnected` — extension installs cleanly; popup opens with no token in storage; provisioning view renders; "Paste token" textarea + Save button visible + focused.
2. `popup_provisions_and_connects` — paste the captured token → Save → state transitions to "Connected"; session.status returns `{vault_open: true, vault_unlocked: true}` (because the fixture vault was pre-unlocked by the setup script via a `__test__force_unlock` Tauri command, NEW this slice — see §6).
3. `popup_lists_accounts` — connected state shows the 3 fixture accounts (GitHub, Gmail, Twitter) with their usernames.
4. `popup_copies_password` — click Copy on GitHub row → popup's `vault.copy_password('<id>')` IPC call → assert via a side-channel that `pangolin-desktop`'s test-hooks log recorded `copy_password_to_clipboard` + did NOT record `reveal_password` (H-1 mirror of MVP-4-F scenario-5).
5. `popup_handles_desktop_disconnect` — SIGTERM `pangolin-desktop` from the spec harness; re-open popup; assert provisioning view does NOT re-show (token still valid) but a "Desktop not running" error renders with a Retry button.

### 3.5 CI integration

```yaml
extension-e2e:
  name: extension-e2e
  runs-on: ubuntu-latest
  needs: [extension, desktop, native-messaging-host, desktop-e2e]
  steps:
    - uses: actions/checkout@v4
    - name: "Install Tauri + Chrome + xvfb Linux deps (apt)"
      run: |
        sudo apt-get update
        # Tauri Linux deps (matches desktop-e2e job exactly)
        sudo apt-get install -y \
          libwebkit2gtk-4.1-dev webkit2gtk-driver libgtk-3-dev libsoup-3.0-dev libxdo-dev \
          libssl-dev libayatana-appindicator3-dev librsvg2-dev libdbus-1-dev \
          pkg-config xvfb
        # google-chrome-stable from the Google Chrome apt repo. We pin
        # the install but float the version — Chrome auto-updates fast
        # and pinning major versions is impractical at the apt layer.
        wget -q -O - https://dl.google.com/linux/linux_signing_key.pub | sudo apt-key add -
        sudo sh -c 'echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google-chrome.list'
        sudo apt-get update
        sudo apt-get install -y google-chrome-stable
    - uses: dtolnay/rust-toolchain@stable
    - uses: Swatinem/rust-cache@v2
      with:
        prefix-key: "v1"
        cache-bin: "false"
    - uses: pnpm/action-setup@v4
      with:
        version: 10
    - uses: actions/setup-node@v4
      with:
        node-version-file: 'apps/extension/.nvmrc'
        cache: 'pnpm'
        cache-dependency-path: 'apps/extension/e2e/pnpm-lock.yaml'
    - name: "Build extension dist"
      working-directory: apps/extension
      run: |
        pnpm install --frozen-lockfile
        pnpm build
    - name: "Install E2E pnpm deps"
      working-directory: apps/extension/e2e
      run: pnpm install --frozen-lockfile
    - name: "TypeScript typecheck (E2E)"
      working-directory: apps/extension/e2e
      run: pnpm typecheck
    - name: "ESLint (E2E)"
      working-directory: apps/extension/e2e
      run: pnpm lint
    - name: "Run E2E suite under xvfb"
      working-directory: apps/extension/e2e
      run: xvfb-run --auto-servernum pnpm e2e
    - name: "Upload Puppeteer + desktop logs on failure"
      if: failure()
      uses: actions/upload-artifact@v4
      with:
        name: extension-e2e-logs
        path: apps/extension/e2e/logs/
        retention-days: 7
```

## 4. L-invariants

- **L1 zero-secret-crosses-FFI**: the popup NEVER receives plaintext. `copyPassword(id)` returns `void`; the clipboard write is Rust-side. The handshake token is NOT a vault secret (it's a per-install auth credential, comparable in sensitivity to a session cookie). The fixture-vault passwords are test material.
- **L2 no new atomic surface**: the popup wraps existing JSON-RPC methods (`session.status`, `vault.list_accounts`, `vault.account_show`, `vault.copy_password`); no new state-machine work in the engine.
- **L3 fail-closed**: bad token → host emits `auth_failed` + exits 1; popup clears stored token + reverts to provisioning. Connect failures show a typed error + a Retry button. Disconnects don't silently leak partial state.
- **L5 new external deps**: `puppeteer` for the test harness (scoped to `apps/extension/e2e/`; does NOT enter the production extension bundle). The popup itself adds NO new runtime deps beyond what MVP-4-C already shipped.
- **L6 testnet-only / D-011**: this slice does not touch chain code.
- **L7 errors carry no secret**: the JSON-RPC error mapping returns `{code, message, data}` per MVP-4-E §3.2; `data` never embeds the token, fixture passwords, or vault state beyond `vault_open` / `vault_unlocked` booleans.
- **L8 tests**: the slice IS the test layer (plus Vitest for the popup's units).
- **L9 §16 ledger**: DECISIONS / DEVLOG on merge.

## 5. Open decisions — pre-locked (one builder carve-out)

- **Q-b (extension `key` field generation): builder's call.** The committed dev `key` field must derive a deterministic extension ID. Either (a) generate a fresh keypair, derive ID, commit both, or (b) reuse the dev ID convention from a sister project (avoid). Both produce the same trust model — the dev ID is NOT the production ID. Document the chosen path in the builder's commit + add a one-line README breadcrumb so future contributors don't accidentally regenerate the key.

All other decisions are locked per §0a.

## 6. Places that need care

Per the Q-c amendment, the automated gate is a Node integration test (no Puppeteer/Chrome). The care-points below are updated accordingly; the original Chrome-harness notes are struck where superseded.

- **Framing fidelity is the load-bearing correctness property (Q-c).** The injected stdio connector MUST frame messages to/from the spawned `pangolin-native-messaging-host` exactly as Chrome's native-messaging protocol does: a 4-byte little-endian `u32` length prefix followed by the UTF-8 JSON body, ≤1 MB per frame. The host binary does its side via `frame.rs`; the connector must match byte-for-byte. A divergent connector framing makes the test pass on a protocol production rejects. Prefer reusing/porting the exact `frame.rs` constants; add a round-trip test asserting a known JSON object frames + reframes identically across the connector ↔ host boundary.
- **Test-hooks side channel for the H-1 assertion.** The integration test drives the `NativeHostClient` (popup-side) directly, but to assert `copy_password_to_clipboard` fired Rust-side it reads the desktop's `__test__commands_invoked` log. Use the file-based side channel the MVP-4-F harness already established (`PANGOLIN_TEST_HOOKS_LOG_PATH` env var → the desktop appends each invocation; the test reads the file). Do NOT route the read through the native-messaging chain (contaminates the production wire with test-only commands).
- **`__test__force_unlock` Tauri command (NEW).** The desktop starts locked. The integration test needs an unlocked vault (the popup has no master-password input). Adds a `#[cfg(feature = "test-hooks")] #[tauri::command] __test__force_unlock(password: String)` that bypasses the normal `vault_unlock` flow, OR reuse MVP-4-F's auto-unlock-at-startup env-var path (`PANGOLIN_TEST_AUTO_UNLOCK_PATH` / `_PASSWORD`) if that already exists. Production builds compile it out. L7-safe (fixture password).
- **Extension `key` field stability (still required).** Even though the automated gate no longer loads the extension in Chrome, the manifest GENERATION test (Rust side: `install-native-host` writes `allowed_origins` with the dev extension ID) + the §9 manual smoke test BOTH depend on a deterministic dev extension ID. Keep the committed `key` field + a README breadcrumb.
- **Sidecar `.lock` scrubbing.** Carries the MVP-4-F LOW-1 workaround until issue #3 is fixed. The harness's teardown deletes `.lock`/`-shm`/`-wal` so the next run starts clean.
- **Don't auto-connect on extension install.** The extension's service worker MUST NOT call `chrome.runtime.connectNative` until the popup is opened. (Still a production-correctness property; verified by the Vitest service-worker test + the §9 manual smoke, not the Node gate.)
- ~~`--headless=new` / Puppeteer MV3 service-worker access / Chrome native-messaging stderr swallowing / manifest path under TempDir HOME~~ — SUPERSEDED by Q-c (no Chrome in the automated gate). These move to the §9 manual smoke-test concerns.
- **`forbid(unsafe_code)`** on every new Rust file.
- **AGPL SPDX header** on every new `.ts` / `.tsx` / `.json` (via `"license"`) / `.md` / `.sh` file.

## 7. Success criteria

- `cargo build -p pangolin-desktop --features test-hooks,custom-protocol` clean.
- `cargo test -p pangolin-desktop --features test-hooks` ✓ (new `__test__force_unlock` test + the install-native-host manifest-generation test asserting `name` / `allowed_origins` / absolute `path`).
- `cargo clippy --workspace --exclude pangolin-desktop --all-targets -- -D warnings` ✓.
- `cargo audit --deny warnings <17 RUSTSEC ignores>` ✓.
- `cargo deny check advisories bans licenses sources` ✓.
- Cardinal invariants 0/0/0/0.
- `apps/extension`: `pnpm typecheck` ✓ + `pnpm lint` ✓ + `pnpm test` ✓ (Vitest: popup state-machine + `native-host` client + `token-store` + `account-list` units, with the e2e dir excluded from Vitest discovery).
- `apps/extension/e2e`: `pnpm typecheck` ✓ + `pnpm lint` ✓ + the **Node integration gate** passes — the real `NativeHostClient` (via the injected stdio connector) → real `pangolin-native-messaging-host` → real `pangolin-desktop` chain: handshake succeeds, `session.status` returns unlocked, `list_accounts` returns the 3 fixture accounts, `copy_password` fires `copy_password_to_clipboard` Rust-side (asserted via the test-hooks log) and does NOT fire `reveal_password`, and a desktop-kill surfaces a typed disconnect error.
- A **framing round-trip test** asserts the connector's native-messaging framing is byte-identical to the host's.
- The new `extension-e2e` CI job green on `ubuntu-latest` (no Chrome / no xvfb needed — pure Node + the Rust binaries).
- The existing `extension` (Vitest) + `desktop-e2e` jobs still pass — regression-catch.
- §9 manual real-Chrome smoke test: NOT a CI gate; run + recorded before closed beta.

## 8. Out of scope (filed for follow-up)

- All §0b items.
- Performance budgets (popup-open latency, copy-to-clipboard latency). E2E gates assert correctness, not perf.
- Cross-browser matrix (Firefox WebExtensions / Safari / Brave / Edge). Release-time.
- Token rotation UX (rotate-without-reinstall). MVP-4-H pre-mainnet hardening.
- Settings UI in the popup (per-account favorite, sort order, theme). MVP-4 back-half.
- Autofill content-script flow. Separate plan-LOCK in the back-half.
- The 3 MVP-4-F follow-up issues (#1 IPC race, #2 withGlobalTauri feature-gate, #3 vault .lock SIGTERM). Tracked separately.
- Visual regression / screenshot tests of the popup. Defer.
- Multiple-vault UX (the popup shows accounts from a single open vault). Post-launch.

## 9. Manual real-Chrome smoke test (run before closed beta)

The automated gate (§0a Q-c) covers the popup-client → host → desktop data path against the real binaries but stubs Chrome's `connectNative` transport. The real-Chrome path + Chrome's `allowed_origins` OUTER lock are verified by this manual checklist, run by a human on a real desktop OS (NOT Chrome-for-Testing) before the closed-beta cut. Mirrors the MVP-3 discipline of hermetic tests + a documented human-run live check (env-quirk #14).

**Pre-req**: real Google Chrome (or Chromium/Brave/Edge) installed; `pangolin-desktop` + `pangolin-native-messaging-host` release binaries built.

1. Run `pangolin-desktop install-native-host <abs-path-to-host> --allowed-extension-id <real-extension-id>`. Confirm it prints `EXTENSION_TOKEN=...` and reports "wrote token … and N manifests".
2. Load the unpacked extension in Chrome (`chrome://extensions` → Developer mode → Load unpacked → `apps/extension/dist`). Confirm the loaded extension ID matches the `key`-derived ID baked into `manifest.json`.
3. Start `pangolin-desktop`, unlock the vault.
4. Open the extension popup. Paste the `EXTENSION_TOKEN` into the provisioning view. Save.
5. **PASS criteria**: popup transitions to "Connected", lists the vault's accounts. Click Copy on an account → confirm the OS clipboard holds the password (paste into a scratch buffer) AND `reveal_password` did NOT fire (the plaintext never rendered in the popup DOM).
6. **OUTER-lock check**: edit the native-messaging manifest's `allowed_origins` to a DIFFERENT extension ID, reload, retry the popup connect. Confirm Chrome refuses with "Specified native messaging host not found" / access denied — proving Chrome enforces `allowed_origins`.
7. Record the Chrome version + OS + result in the PR / DEVLOG. Re-run whenever the native-messaging manifest format or the host's handshake protocol changes.

This checklist is NOT automated in CI (Chrome-for-Testing can't run it; real Chrome on a CI runner is a separate, heavier infra investment deferred to release-time). The §0a Q-c automated gate is the per-PR safety net; this manual test is the pre-beta + on-protocol-change gate.
