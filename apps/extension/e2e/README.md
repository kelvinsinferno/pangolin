<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Pangolin extension E2E gate

Node integration gate for the MVP-4-G popup → native-messaging host →
desktop chain. Plan-LOCK: `docs/issue-plans/mvp4-g-extension-e2e.md`
(§0a Q-c).

## What this is (and is NOT)

This gate does **NOT** drive a real Chrome. Chrome for Testing 138+
refuses to spawn native-messaging hosts for `--load-extension`
dev-loaded extensions (verified via strace; see plan §0a Q-c). Instead
it injects a stdio bridge (`setup/stdio-connector.ts`) into the real
popup-side `NativeHostClient`, spawns the **real**
`pangolin-native-messaging-host` binary, frames stdin/stdout with
byte-identical native-messaging framing (4-byte LE length + UTF-8
JSON), and runs against the **real** `pangolin-desktop`. Every line of
Pangolin's code runs end-to-end; only Chrome's `connectNative`
transport is replaced.

- **Popup UI + state machine** → covered by Vitest in
  `../src/popup/*.test.tsx` (run from `apps/extension`).
- **Cross-process data path + H-1** → covered here.
- **Real-Chrome transport + Chrome's `allowed_origins` outer lock** →
  covered by the MANUAL smoke test in plan §9, run by a human before
  closed beta. NOT automated.

## Run it

```bash
# from apps/extension/e2e (its own pnpm workspace — see pnpm-workspace.yaml)
pnpm install --frozen-lockfile
pnpm build:desktop   # cargo build desktop + host with test-hooks
pnpm test:e2e        # mocha: framing.test.ts + integration.test.ts
```

`pnpm test:e2e` runs the framing-fidelity round-trip + 5 integration
scenarios (handshake/session, list-accounts, copy-password H-1,
desktop-disconnect, wrong-token). No Chrome, no xvfb — pure Node + the
Rust binaries.

## The extension `key` / stable ID — DO NOT regenerate

`../manifest.json` ships a committed dev `key` field. Chrome derives a
deterministic extension ID from it; that ID is hard-coded as
`ALLOWED_EXTENSION_ID` in `setup/install-native-host.ts` and lands in
the native-messaging manifest's `allowed_origins` (the OUTER trust
lock). The current dev ID is:

```
ffdfbifkfdoookbcechjlkgpmcdojdjl
```

**Do NOT regenerate the `key`** without also updating
`ALLOWED_EXTENSION_ID` + re-running the §9 manual smoke test — a
mismatch silently breaks `connectNative` ("Specified native messaging
host not found"). The production Chrome Web Store key is a separate,
out-of-scope concern (MVP-4 back-half).

## Known follow-ups (filed separately)

- Tighten the wrong-token integration assertion to check
  `.label === "auth_failed"` (currently only `instanceOf
  NativeHostError`), paired with a connect-probe `waitForIpcReady` so
  the restart-race can't surface a transport error in its place.
