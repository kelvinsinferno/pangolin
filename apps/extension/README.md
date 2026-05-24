<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# @pangolin/extension

Pangolin browser extension scaffold (Chromium Manifest V3).

This slice (MVP-4-C) ships only the loadable shell:

- a popup that renders a hard-coded "Desktop not connected" view,
- a service worker that registers MV3 lifecycle handlers,
- a content-script stub.

Autofill, native-messaging wire protocol, form detection, and the real
component-library imports all land in later sub-issues
(MVP-4-E / MVP-4-F / MVP-4-G).

## Requirements

- Node `>=20.18.0 <23` (see `.nvmrc`)
- pnpm 9.x (`corepack enable pnpm` if you don't already have it)

## Install + build

```bash
cd apps/extension
pnpm install --frozen-lockfile
pnpm build
```

The build emits to `apps/extension/dist/`:

- `manifest.json`
- `src/popup/popup.html` (+ hashed asset bundles under `assets/`)
- `service-worker.js`
- `content-script.js`
- `src/icons/icon-{16,32,48,128}.png`

## Load the extension in Chrome (manual verification)

1. Run `pnpm build`.
2. Open `chrome://extensions`.
3. Enable **Developer mode** (top-right toggle).
4. Click **Load unpacked** and choose `apps/extension/dist`.
5. The Pangolin icon should appear in the toolbar; click it.
6. The popup should open and read **"Desktop not connected"**.
7. To inspect the service worker, find the extension card, click
   **Service worker** under "Inspect views", and confirm the lifecycle
   log lines (`"Pangolin extension installed"` / `"Pangolin extension
   startup"`).

## Development

- `pnpm dev` — Vite dev server (popup only; the service-worker + content
  script are MV3-only and not exercised in dev-server mode).
- `pnpm typecheck` — `tsc --noEmit` in strict mode.
- `pnpm lint` — ESLint over `src/**/*.{ts,tsx}`.
- `pnpm test` — Vitest (jsdom env) over the test suite.

## Permissions

The manifest grants only:

- `storage` — non-secret user preferences only (no secrets ever live in
  extension storage).
- `activeTab` — scoped per-tab access on user interaction.
- `scripting` — programmatic `chrome.scripting.executeScript` injection
  for the future autofill flow.
- `nativeMessaging` — talk to the Pangolin desktop's native-messaging host
  (host process ships in MVP-4-E).

The extension declares `<all_urls>` host_permissions so the future
autofill flow (MVP-4-G) can detect login forms anywhere. The extension
only **actively** reads tab content when a registered login form is
present; the per-site allowlist / blocklist is enforced inside the
content-script logic, not at the manifest layer.

## Architecture notes

- Token CSS is consumed from the sibling `apps/design-tokens/dist/tokens.css`
  via a relative import — see `src/tokens.css`.
- The popup uses inline placeholder components in `src/popup/Placeholder.tsx`
  (Button, Card, Text). MVP-4-D's `@pangolin/component-library` is in
  parallel development and will replace these placeholders at MVP-4-F /
  MVP-4-G; this scaffold deliberately ships zero coupling to it.
- MV3 service workers are **not** persistent — they idle out and restart.
  Any state added to the service worker in later sub-issues must be
  re-derivable on cold start.
