<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# MVP-4-M — packaged release (closed-beta downloadable installer) — plan-gate LOCKED

**Status: LOCKED — Kelvin call 2026-06-02.** Q-a..e all resolved; build can start.

## 0. One-paragraph summary

Replace the current "clone the repo and `pnpm tauri dev`" install story
with a `Download` button on GitHub Releases. Today (`apps/desktop/tauri.conf.json`)
has `bundle.active: false` and `version: "0.0.0"` — Tauri's bundler is
turned off, no installer artifacts are built, and `gh release list`
returns empty. MVP-4-M flips the bundler on, adds a tag-triggered
release workflow that builds AppImage + `.deb` (Linux), `.exe` NSIS
installer (Windows), and `.dmg` (macOS, gated on manual unlock smoke
per [[pangolin_macos_release_smoke]]), uploads them as Release assets,
and wires the browser extension's `dist/` zip alongside. No paid code-
signing certs — accepted Gatekeeper / SmartScreen friction documented
in README. Pre-D-011 + pre-mainnet posture preserved via "closed-beta,
testnet only" framing.

Reference posture memories:
- [`pangolin_state.md`](../../.claude/projects/C--Users-kelvi/memory/pangolin_state.md) — MVP-4-H closed, D-011 next
- [`pangolin_macos_release_smoke.md`](../../.claude/projects/C--Users-kelvi/memory/pangolin_macos_release_smoke.md) — manual smoke required pre-release
- [`pangolin_secure_input.md`](../../.claude/projects/C--Users-kelvi/memory/pangolin_secure_input.md) — staged posture

## 0a. LOCKED decisions (proposed — Kelvin to confirm)

### Kelvin-locked decisions (2026-06-02)

- **Q-a — macOS Gatekeeper UX = README docs only.** Explain right-click
  → Open the first time + the `xattr -d com.apple.quarantine
  /Applications/Pangolin.app` fallback in the Download section.
  Standard unsigned-app dance; smallest moving-part surface. No helper
  scripts, no extra trust asks.

- **Q-b — Beta framing = README + first-launch in-app dialog.** One-shot
  modal on fresh install ("Pangolin is in closed beta on Base Sepolia
  testnet. Not audited. Do not store production secrets. Continue?")
  with an "I understand" button; persistent "BETA / TESTNET" chip in
  the title bar afterwards. Dismissal-persistence stored in
  `app_data_dir()` (NOT localStorage — see §4 audit prompt: clearing
  the data dir = fresh install = warning re-fires, which is desired).

- **Q-c — Extension distribution = zip `dist/` into the same Release.**
  Built extension artifact attached as `pangolin-extension-<version>.zip`.
  Single tag covers desktop + extension; versions stay
  synchronized. Users `chrome://extensions` → Developer Mode → Load
  Unpacked.

- **Q-d — Native-messaging install = first-launch in-app wizard.**
  Desktop detects the missing native-messaging manifest on app start;
  surfaces a "Connect browser extension?" wizard that takes the user's
  extension ID (paste from `chrome://extensions`) and invokes the
  existing `install-native-host` command under the hood. No baked-in
  IDs; reversible via `uninstall-native-host`. Surfaces the file paths
  being written so users know what's happening on disk.

- **Q-e — macOS release gating = two-phase release.** Tag triggers
  Linux + Windows publish immediately; release notes start with
  "macOS: PENDING SMOKE." The `.dmg` is built in CI and uploaded as a
  workflow artifact (NOT attached to the release yet); a manual
  follow-on (Kelvin or the homie with the Mac) downloads the
  artifact, runs the [[pangolin_macos_release_smoke]] checklist, and
  on pass attaches the `.dmg` to the existing Release + updates the
  notes to "macOS: available." Honest about the gap; honors the
  smoke memory; matches the L6 layer gate.

### Self-locked (no gate needed)

- **Version scheme**: semver pre-release — first release tag
  `v0.1.0-beta.1`. Subsequent releases bump the pre-release identifier
  (`v0.1.0-beta.2`, etc.); when D-011 lands, the first stable release
  becomes `v0.1.0`. Standard, machine-readable, sorts correctly.
- **Windows installer = NSIS only** (`.exe`). Tauri's default;
  smaller artifact; fewer permission prompts than MSI; supports
  per-user install (no UAC required). MSI can be added later if an
  enterprise tester asks.
- **Linux bundles = AppImage + `.deb`.** Both are cheap to produce
  (Tauri builds them in the same step); AppImage covers
  distro-agnostic portable use, `.deb` covers Debian/Ubuntu native
  install. RPM skipped (Tauri can produce one, but RPM-first distros
  are a smaller closed-beta demographic and we can add it later).
- **Release trigger**: git tag push (`v*.*.*-*` glob). The tag is the
  canonical release marker, captures the source commit, integrates
  cleanly with `gh release create` from the workflow. Manual
  `workflow_dispatch` available as a fallback in case a re-run is
  needed.
- **Tag naming**: `v<semver>` (e.g. `v0.1.0-beta.1`). Standard prefix;
  matches the version inside `tauri.conf.json` 1:1.
- **Icon source**: existing `apps/desktop/icons/icon.png` +
  `icon.ico` are reused. Tauri's `tauri icon` regenerates the per-OS
  family (.icns, multi-size .ico, etc.) from a single source —
  Layer 1 runs this once and commits the regenerated set.
- **No code-signing this slice.** Apple Developer ID ($99/yr) and
  Authenticode cert (~$200-400/yr) are intentionally skipped. The
  Gatekeeper / SmartScreen friction is documented per Q-a/Q-b. Code-
  signing is a separate post-mainnet sub-issue tied to the D-011
  outcome.
- **`bundle.active: true` only on release-tag builds.** The flag in
  `tauri.conf.json` is flipped (the CI gate already builds without
  `--bundles`; the release workflow passes `--bundles all`). Existing
  `desktop / scaffold` CI job continues to `cargo build -p
  pangolin-desktop` without bundling — no new CI cost.
- **AGPL-3.0-or-later SPDX header** on every new file.

## 0b. What NOT to ship in this slice

- **Auto-updater.** Tauri 2 ships `tauri-plugin-updater` but it requires
  signed releases (cryptographic signing of the bundle, separate from
  Authenticode/Gatekeeper). The pre-D-011 closed-beta releases will
  be manual download + re-install. Updater is a follow-on tied to
  signing-cert acquisition.
- **App-store listings.** Explicitly out of scope per Kelvin's call.
- **Code-signing certs.** Both paid and free routes (e.g. SignPath
  community sponsorship) deferred until post-D-011 / mainnet.
- **Hardened runtime / notarization.** macOS-specific; required only
  for paid-signed distribution. N/A for unsigned beta.
- **Windows ARM64 / macOS x86_64.** First release targets the
  dominant arch per OS: Linux `x86_64`, Windows `x86_64`, macOS
  `aarch64` (Apple Silicon). Intel-Mac and ARM-Windows are follow-on
  if testers ask.
- **RPM / Snap / Flatpak.** AppImage + `.deb` cover the closed-beta
  audience. Extra Linux formats are follow-on.
- **In-app self-update prompt.** Without the updater plugin there's
  nothing useful to prompt about. README documents the manual
  "download new release" upgrade path.
- **Telemetry / crash reporting.** Sentry-style hookups are
  intentionally absent — the password-manager threat model
  precludes shipping a process that calls out on crash. Closed-beta
  testers report manually.

## 1. Surface that needs to change

| Layer | File / path | Change |
|---|---|---|
| L1 | `apps/desktop/tauri.conf.json` | `bundle.active: false → true`; `version: "0.0.0" → "0.1.0-beta.1"`; populate `bundle.icon: []` with the regenerated icon set; add `bundle.resources` for `install-native-host` documentation if Q-d picks Option 3 |
| L1 | `apps/desktop/icons/` | Regenerate via `pnpm tauri icon apps/desktop/icons/icon.png` (produces `.icns`, multi-size `.ico`, per-size PNGs) |
| L2 | `.github/workflows/release.yml` (new) | Tag-triggered (`v*.*.*-*` + `v*.*.*`) + `workflow_dispatch` fallback; matrix over ubuntu-latest / windows-latest / macos-14 (Apple Silicon); steps: install deps → `pnpm install` → `pnpm tauri build --bundles <os-targets>` → upload artifacts → `gh release create` (or upload to existing release if Q-e picks Option 1's two-phase flow) |
| L2 | `.github/workflows/release.yml` | Extension job: `pnpm --filter @pangolin/extension build` → zip `apps/extension/dist/` → attach to release (gated on Q-c = Option 1) |
| L3 | `apps/desktop/src/ui/` (TBD per Q-d) | If Q-d = Option 1: new `BrowserConnectScreen` wizard or first-launch detection in `useVault.ts` + an `installNativeHost` invoke wrapper |
| L4 | `apps/desktop/src/ui/` (TBD per Q-b) | If Q-b = Option 1: new first-launch dialog modal + a persistent "BETA / TESTNET" title-bar annotation |
| L5 | `README.md` | New "## Download" section near the top with badges pointing at the latest Release + per-OS install instructions; per-OS Gatekeeper/SmartScreen notes (Q-a-dependent); separate "## Build from source" section for the existing flow |
| L5 | `README.md` | "## Browser extension" section: link to the `.zip` asset + Load-Unpacked instructions (Q-c-dependent) |
| L6 | Tag `v0.1.0-beta.1` | First release. Smoke-test the pipeline end-to-end. If Q-e = Option 1: macOS leg waits for manual smoke before adding the `.dmg` to the same release |

## 2. Layers + gates

Each layer is a separate commit; gate is what proves it works.

| Layer | What it does | Gate |
|---|---|---|
| L1 | Tauri bundle config + regenerated icons | `cargo tauri build --bundles app` (Linux) produces `.AppImage` + `.deb` locally; file sizes sane (~30-60 MB each); icons visible in built bundle |
| L2 | Release workflow file | `act` (local actions runner) or `workflow_dispatch` on a throwaway tag like `v0.0.1-dryrun.1` produces the three-OS artifacts in CI; sanity-check `gh release view v0.0.1-dryrun.1` lists the expected assets; delete the dryrun release after |
| L3 | Native-host install UX (Q-d-dependent) | Vitest + Tauri command unit tests: `install_native_host` round-trip writes the expected manifest path; UX: actually load the extension in Chrome, paste the ID, confirm the desktop sees the connect |
| L4 | First-launch beta dialog (Q-b-dependent) | Vitest: dialog renders on first launch, dismisses on accept, doesn't re-show on second launch; e2e: full unlock flow still works post-dismissal |
| L5 | README updates | `markdownlint` clean; manual read-through; the macOS Gatekeeper / Windows SmartScreen notes match the actual first-launch behavior on each OS |
| L6 | First production release `v0.1.0-beta.1` | The whole point — download the artifact on each OS, run, confirm the unlock flow against Base Sepolia testnet works. The macOS `.dmg` only ships after the manual unlock smoke per Q-e |

## 3. Threat model + posture notes

- **Unsigned binaries**: trust model is "the user verified the GitHub
  Releases SHA-256 matches the workflow log." We document this in
  README. Closed-beta audience accepted by virtue of seeking out the
  testnet-only password manager.
- **No auto-update means CVE-fix lag**: if a HIGH lands in main, users
  on older betas don't get the patch automatically. Mitigation:
  README + release notes name a fresh-install upgrade path; in-app
  "BETA" indicator already implies "you should be re-downloading often."
- **Native-messaging manifest writes outside `~/.local/share/`**: the
  install-native-host subcommand writes to
  `~/.config/google-chrome/NativeMessagingHosts/` (Linux),
  `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/`
  (macOS), or the Chrome registry hive (Windows). Documented in
  `apps/native-messaging-host/src/manifest.rs:7-9`. The
  `uninstall-native-host` subcommand reverses it cleanly. Q-d Option
  1's first-launch wizard surfaces this so users know what's being
  written.
- **`.deb` post-install scripts**: the Tauri-generated `.deb` does not
  ship custom post-install scripts in this slice (Q-d Option 1 keeps
  the native-host install inside the app). If a future slice adds
  post-install scripts they need explicit posture sign-off.

## 4. Adversarial-audit prompts

When the builder finishes, audit specifically for:

- **Workflow secret leakage**: does `release.yml` echo any env var or
  GitHub token to logs? Even unsigned releases — no `gh auth status`
  output, no `cat ~/.config/...` debugging.
- **Bundle reproducibility**: does the same source commit produce the
  same artifact bytes? (Probably not perfectly — Tauri bundles include
  timestamps — but document the gap so users CAN reproduce-from-source
  if they want.)
- **Extension ID hardcoding**: if Q-d = Option 2, what's the baked-in
  extension ID and what happens if the user sideloads with a different
  one?
- **First-launch dialog persistence (Q-b Option 1)**: where does the
  "user dismissed the beta warning" bit get stored? A file in
  `app_data_dir()` is fine; a localStorage entry is not (clears on
  reinstall, the warning fires again, which is actually desirable —
  flag that). Confirm dismissal does NOT persist across vault wipes.
- **README Gatekeeper / SmartScreen text**: empirically verify the
  exact strings users will see on each OS match what we tell them.
  Apple's wording changes between major macOS versions.
- **macOS smoke gating (Q-e)**: does the release workflow actually
  prevent the `.dmg` from publishing without the smoke sign-off? Or
  is it documentation-only? If the latter, mistake-prone — add a
  manual-approval environment to the macOS job.
- **`pnpm tauri build` on the runner**: does the build pull any non-
  reproducible dependency at release time (e.g. `latest` tags)? Lock
  versions where possible.
- **Release notes auto-generation**: if `gh release create
  --generate-notes` is used, does it leak any private commit-message
  content? Pangolin is fully public so this is low-risk, but worth
  spot-checking.

## 5. CI cost notes

- New `release.yml` ONLY triggers on tags + `workflow_dispatch`. No
  per-PR cost. Matrix is 3 OSes × ~10 min build = ~30 min per release.
- Existing `ci.yml` is unchanged. `desktop / scaffold` still does
  `cargo build -p pangolin-desktop` without `--bundles`, so PR CI cost
  is unaffected by Layer 1's config flip.
- Tauri build is the slow leg — primarily a `tauri-runtime-wry`
  recompile that's already cached in the normal CI runs. The release
  workflow uses its own runner so it's a cold-cache build (~10 min
  Linux, ~12 min Windows, ~8 min macOS).

## 6. Out-of-band coordination

- **Q-e Option 1** (recommended): requires a human (Kelvin or the
  homie with the Mac) to run the unlock smoke checklist within ~24h
  of each release tag and update the release notes. Coordinate via
  the [[pangolin_macos_release_smoke]] memory's checklist.
- **First release tag** (`v0.1.0-beta.1`): pick a moment when no
  in-flight work is on `main` (post-merge CI green); the tag will
  trigger the release workflow against that exact commit.

## 7. Merge-boundary policy

Per the standing autonomy directive ([[feedback_pangolin_autonomy]])
this slice's merge boundary is the **first successful release tag**
landing artifacts on GitHub Releases. Intermediate layer commits (L1
config flip, L2 workflow add, L3-4 UX, L5 README) merge to main
autonomously after each layer's gate clears. The release tag itself
is the merge-boundary confirmation moment: Kelvin pulls down the
artifact on his platform of choice, confirms the install + unlock
work, and the slice is closed. If Q-e = Option 1 the macOS leg may
land as a follow-on commit + amended release after the manual smoke.

## 8. Risks (known up front)

- **Tauri bundle fails on the runner**: the GitHub-hosted runners
  sometimes lack libraries the local dev box has (libwebkit2gtk-4.1 on
  Linux, specific MSVC toolchain on Windows). Mitigation: the workflow
  installs the Tauri-recommended dep set explicitly; CI's existing
  `secure-input-e2e` job already proves the deps work on all 3 OSes.
- **Apple Silicon-only macOS .dmg**: users on Intel Macs (pre-2020) get
  nothing in this release. Acceptable for closed-beta; add Intel as a
  follow-on if a tester asks.
- **`gh release create` race condition** if two tags push close
  together: workflow uses `--target $GITHUB_SHA` to pin the source
  commit, and the assets uploader is idempotent.
- **macOS notarization not done**: even with Q-a Option 1's "right-
  click → Open" workaround, some macOS versions add an extra prompt
  ("Pangolin will damage your computer"). The workaround is
  `xattr -d com.apple.quarantine ...` documented in README. Real fix
  is the paid signing route post-mainnet.
