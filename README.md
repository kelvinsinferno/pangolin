# Pangolin

> A local-first, hardware-assisted password manager with blockchain-backed durability and social recovery.

[![License: AGPL v3.0-or-later](https://img.shields.io/badge/License-AGPL_v3.0--or--later-blue.svg)](LICENSE)
[![Latest release](https://img.shields.io/github/v/release/kelvinsinferno/pangolin?include_prereleases&sort=semver)](https://github.com/kelvinsinferno/pangolin/releases/latest)
[![CI](https://github.com/kelvinsinferno/pangolin/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/kelvinsinferno/pangolin/actions/workflows/ci.yml)

**Status: closed beta on Base Sepolia testnet. Unaudited — independent community audits welcomed. Do not store production secrets.**

Pangolin is a password manager built on a hard threat model:

- **Local-first** — vault data is encrypted at rest with a key derived from a master password the OS dialog handles end-to-end. Plaintext never crosses the WebView's V8 heap.
- **Multi-device** — devices pair via QR / short-code over an off-line channel; an on-chain authorized-device set (RevisionLogV2) is the source of truth for who can publish updates.
- **Threshold social recovery** — Shamir secret-sharing across user-chosen guardians. Backup envelope carries sealed shares so any guardian quorum can help a new device come online without the original being present.
- **No telemetry, no calls home, no auto-updater** — the binary you download runs without ever talking to a Pangolin-controlled server.

The implementation completes Pangolin per the canonical specifications:

- Whitepaper (local-first, layered authority, append-only revisions, blockchain as durability log only)
- Unified Session Authority, Hardware & Interaction Specification
- Browser Extension & Mobile Autofill Integration Specification
- Unified UI/UX Design System Specification

---

## Download

Closed-beta installers are published to the [GitHub Releases page](https://github.com/kelvinsinferno/pangolin/releases). Each release ships:

| Platform | File | How to install |
|---|---|---|
| Linux (Debian/Ubuntu) | `Pangolin_<version>_amd64.deb` | `sudo dpkg -i Pangolin_<version>_amd64.deb` |
| Linux (portable AppImage) | `Pangolin_<version>_amd64.AppImage` | `chmod +x Pangolin_<version>_amd64.AppImage` then run |
| Windows (NSIS installer) | `Pangolin_<version>_x64-setup.exe` | Double-click, then click "More info" → "Run anyway" if SmartScreen warns (see below) |
| macOS (Apple Silicon) | `Pangolin_<version>_aarch64.dmg` | Right-click the .dmg → Open. Drag to Applications. Right-click Pangolin.app → Open (first launch). See below if Gatekeeper still blocks. |
| Browser extension | `pangolin-extension-<version>.zip` | `chrome://extensions` → enable Developer Mode → Load Unpacked → point at the unzipped folder |

> **Heads-up:** these are unsigned beta binaries. The OS will warn you on first launch because no Apple/Microsoft code-signing cert is in the chain of trust. Code-signing is a separate post-mainnet workstream.

### Windows — getting past SmartScreen

When you double-click the installer, SmartScreen says **"Windows protected your PC"**. This is expected for any unsigned executable. To proceed:

1. Click **More info**
2. Click **Run anyway**

This warning will appear once per install. Subsequent updates on the same machine usually skip it (SmartScreen learns the file hash after first execution).

### macOS — getting past Gatekeeper

When you open the `.dmg` and try to launch Pangolin.app, macOS says **"Pangolin can't be opened because it is from an unidentified developer"**. Two ways to proceed:

**Recommended (one click):**

1. Right-click (or Control-click) `Pangolin.app` → **Open**
2. Click **Open** in the dialog that appears
3. After this once, macOS remembers your choice for this binary

**If that doesn't work** (some macOS versions add an extra "Pangolin will damage your computer" prompt for unquarantined apps), run this from Terminal:

```sh
xattr -d com.apple.quarantine /Applications/Pangolin.app
```

This removes the quarantine attribute that triggers Gatekeeper. The macOS `.dmg` ships only after a manual unlock smoke (see [release notes](https://github.com/kelvinsinferno/pangolin/releases/latest) — it may be marked "PENDING SMOKE" briefly).

### Linux

```sh
# Debian / Ubuntu (.deb)
sudo dpkg -i Pangolin_<version>_amd64.deb

# Portable / any distro (.AppImage)
chmod +x Pangolin_<version>_amd64.AppImage
./Pangolin_<version>_amd64.AppImage
```

The `.deb` registers Pangolin in your application launcher; the `.AppImage` is self-contained and leaves no installer trace.

### Browser extension

The browser extension is **optional** — Pangolin desktop is fully usable without it. The extension adds browser autofill convenience.

To install:

1. Download `pangolin-extension-<version>.zip` from the latest release
2. Unzip somewhere persistent (the folder needs to stay where it is)
3. Open `chrome://extensions` (or `edge://extensions`) in your browser
4. Enable **Developer mode** (toggle, top-right)
5. Click **Load unpacked** → select the unzipped folder
6. Copy the extension ID Chrome assigns (under the extension name, ~32 lowercase letters)
7. Open Pangolin desktop → **Settings → Browser connection** → paste the extension ID → **Connect**

The desktop registers a native-messaging manifest in your browser's profile directory so the extension can talk to the local Pangolin process. You can disconnect later via the same Settings panel.

---

## Build from source

If you want to inspect, modify, or run the latest unreleased main, build from source:

### Prerequisites

- **Rust** ≥ 1.94 (stable)
- **Node.js** ≥ 20.18.0, < 23
- **pnpm** ≥ 10
- **Tauri build deps** per OS (Linux needs `libwebkit2gtk-4.1-dev`, `libgtk-3-dev`, `libsoup-3.0-dev`, `libayatana-appindicator3-dev`, `librsvg2-dev`, `libdbus-1-dev`, `patchelf`; macOS needs Xcode CLT; Windows needs MSVC Build Tools)
- **Foundry** (for the on-chain contract suite; not required for desktop-only)

### Run from source

```sh
git clone https://github.com/kelvinsinferno/pangolin
cd pangolin

# Build the design-token consumers
(cd apps/component-library && pnpm install --frozen-lockfile && pnpm build)

# Run the desktop in dev mode
(cd apps/desktop && pnpm install --frozen-lockfile && cargo tauri dev)
```

### Build production installers locally

```sh
# Linux (.deb + .AppImage)
(cd apps/desktop && cargo tauri build --bundles deb,appimage)

# Windows (NSIS .exe) — run on Windows
cd apps\desktop
cargo tauri build --bundles nsis

# macOS (.dmg) — run on macOS
(cd apps/desktop && cargo tauri build --bundles dmg)
```

Output lands in `target/release/bundle/<format>/`. The same `cargo tauri build` invocation is what CI runs (see `.github/workflows/release.yml`).

### Repository layout

```
crates/        Rust workspace — pangolin-core, pangolin-crypto, pangolin-store,
               pangolin-chain, pangolin-indexer, pangolin-funder-client, pangolin-cli
contracts/     Solidity (Foundry) — RevisionLogV2, RecoveryV2, EntitlementRegistry
apps/          Client shells — desktop (Tauri), extension (Chromium MV3),
               native-messaging-host, component-library
services/      Off-chain — funder (one-way ETH dispenser; never signs or submits)
tools/         chaincli debug oracle
docs/          issue-plans, architecture, specs
```

---

## How development works

Every issue follows the §16 Per-Issue Development Protocol from the master plan:

1. **PLAN** — write `docs/issue-plans/<issue-id>.md` before any code
2. **APPROVE** — peer or Kelvin reviews the plan (Kelvin required for security-critical)
3. **BUILD** — code on the issue branch, with spec references in comments
4. **TEST** — every success criterion has a test; CI green; never weaken tests to make them pass
5. **SIGNOFF** — DEVLOG entry; close issue; move to next

See `CONTRIBUTING.md` for the full protocol and `SECURITY.md` for the responsible-disclosure path.

## What's in the closed beta

Closed beta covers the full MVP-4 desktop + extension surface on Base Sepolia testnet:

- Vault create / open / lock / unlock with OS-native master-password dialog (no JS-heap residue)
- Account add / edit / delete / reveal / copy with audit-hardened clipboard handoff
- Multi-device pairing (QR + short-code) with on-chain authorized-device set
- Device removal + VDK rotation after revoke
- Manager handoff / promotion
- Threshold social recovery — guardian onboarding (owner side), guardian help (guardian side), lost-everything wizard (recoverer side)
- Recovery backup with sealed-share envelope for cross-device recovery
- Browser extension for autofill (optional)

**Not in beta yet (mainnet-gated):**

- Code-signing for installers (Apple Developer ID + Authenticode)
- Mainnet contracts + production funder
- Auto-updater
- iOS / Android shells (later MVP)

## Security review

The full Pangolin source is AGPL-3.0 — anyone is welcome to read, fork, and audit it. We don't have a paid external audit lined up; independent community audits are welcomed and findings filed as GitHub issues or via the responsible-disclosure path in `SECURITY.md` will be triaged on the same HIGH/MED/LOW/INFO ladder used internally. The threat model is documented in `THREAT_MODEL.md`.

## License

GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later) for the core code shipped in this repository — vault engine, sync logic, recovery logic, credential management, local storage, session policy, and TOTP handling. See `LICENSE` for the full text and `LICENSE-RATIONALE.md` for the per-layer license map (AGPL core, Apache-2.0 future SDKs and integrations, CC BY-SA documentation, trademark-protected branding) per the Pangolin Licensing & Intellectual Property Specification.
