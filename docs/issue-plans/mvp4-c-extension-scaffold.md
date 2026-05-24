<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# MVP-4-C — Browser extension scaffold (Chromium MV3) — plan-gate LOCKED

**Status: LOCKED — self-locked 2026-05-24.** No Kelvin gate per MVP-4 overview §6. Decisions pre-resolved in §0a below. Runs in parallel with MVP-4-D (component library) per Kelvin call 2026-05-24.

## 0. One-paragraph summary

Stand up the canonical Chromium Manifest V3 extension scaffold that hosts the Pangolin popup + the content-script + the service-worker plumbing. **This slice ships ONLY the scaffold** — popup shows a hardcoded "no vault connected" view; no autofill, no native-messaging-host integration (deferred to MVP-4-E + MVP-4-G), no form detection (deferred to MVP-4-G). The discipline being installed here is the workspace + manifest + service-worker + content-script + popup shell + CI gate; later sub-issues fill in the actual capabilities.

## 0a. RESOLVED decisions (self-locked 2026-05-24)

- **Manifest V3 only** (Chromium-first per MVP-4 overview §0a). Service worker (not background page); declarative content-scripts only where unavoidable, programmatic injection (`chrome.scripting.executeScript`) elsewhere per Browser-Ext spec §4.2.
- **TypeScript strict** (matches MVP-4-D's posture). React 19 for the popup. Vanilla TS for the service worker (no React needed; lighter bundle).
- **Vite 6.x** as the build tool. Multi-entry config:
  - `popup` → `dist/popup.html` + `dist/popup.[hash].js`
  - `service-worker` → `dist/service-worker.js`
  - `content-script` → `dist/content-script.js`
  - `manifest.json` → `dist/manifest.json` (copied + content-hash-patched at build)
- **pnpm-managed**, mirrors MVP-4-D. `private: true`; engines `>=20.18.0 <23`; `.nvmrc`.
- **Component library**: the popup will eventually `import { Button, Input } from '@pangolin/component-library'` (MVP-4-D). For THIS slice, MVP-4-D is in parallel + may not have merged when the builder reaches the dependency. Builder uses **inline placeholder components** in the popup (a single `Placeholder.tsx` file with the absolute-minimum 3 components: Button, Card, Text) so the scaffold compiles + Storybook-style smoke-tests pass; MVP-4-F or MVP-4-G later swaps the placeholders for `@pangolin/component-library` imports.
- **CSS tokens**: import `apps/design-tokens/dist/tokens.css` via relative path (the dist file is at a known location). Placeholder components reach token vars via `var(--space-4)` etc. just like the component library does.
- **MV3 permissions declared in `manifest.json`** (minimal for this scaffold; expanded by MVP-4-G):
  - `"permissions": ["storage", "activeTab", "scripting", "nativeMessaging"]`
  - `"host_permissions": ["<all_urls>"]` (autofill needs to detect login forms anywhere; user-level allowlist/blocklist enforced engine-side, NOT via manifest)
  - **NO** `"tabs"` permission (would expose URL history — Browser-Ext spec §4.7 hygiene rule).
  - **NO** `"webRequest"` (not needed for autofill; only adds attack surface).
  - **NO** `"unlimitedStorage"` (per spec §4.7: no secrets in extension storage; the storage permission is for non-secret user prefs only).
- **The popup view this slice ships**: a single screen that reads "Pangolin desktop not connected. Open the Pangolin desktop app." plus a small status indicator (filled circle: connected; empty circle: disconnected) — hardcoded "disconnected" for now. NO active functionality.
- **Service worker** in this slice: registers + logs lifecycle events; sets up the structure for the future native-messaging-host bridge (MVP-4-E) but does NOT actually connect to anything. Includes a `chrome.runtime.onInstalled` handler that does nothing more than `console.log('Pangolin extension installed')`.
- **Content script** in this slice: empty stub. Registered in manifest but its body is a single `console.log('Pangolin content script loaded')` so we can verify the manifest's content-script declaration works in MVP-4-G.
- **No icon work this slice** — uses a placeholder 16/32/48/128 px icon set (a tiny solid-color SVG converted to PNG via the build pipeline OR commit pre-generated placeholder PNGs). Real icon work happens at MVP-4 closeout when the design system stabilizes.
- **AGPL-3.0-or-later SPDX header** on every TS/TSX/CSS file. `manifest.json` doesn't carry SPDX (consistent with the other JSON files in the repo — Cargo.lock, ABI JSONs, etc.).
- **`"private": true` package.json** — never published.
- **No new Rust dependencies.** This is pure JS/TS work.

## 0b. What NOT to ship in this slice

- Form detection / autofill — MVP-4-G.
- Native-messaging-host wire protocol — MVP-4-E.
- Domain matching + alias flow — MVP-4-G.
- Per-site rules UI — MVP-4-G.
- Origin binding + iframe rules — MVP-4-G.
- Memory hygiene enforcement — MVP-4-G.
- Real component-library imports (placeholder components only; swap later).
- Real icons (placeholder set only).
- Firefox + Safari (slip per MVP-4 overview).

## 1. Scope

**Built in MVP-4-C:**
- `apps/extension/` (NEW directory at the repo root).
- `apps/extension/package.json` — pnpm-managed; `private: true`; React + Vite + TS deps.
- `apps/extension/pnpm-lock.yaml` (committed).
- `apps/extension/.nvmrc`.
- `apps/extension/tsconfig.json` — strict mode (mirrors MVP-4-D).
- `apps/extension/vite.config.ts` — multi-entry MV3 build per §0a.
- `apps/extension/manifest.json` — MV3 manifest with the permission set above + content-script declaration + popup + service-worker + icons.
- `apps/extension/src/popup/` — popup React app:
  - `popup.html` (entry)
  - `index.tsx` (mounts the React tree)
  - `Popup.tsx` (the "not connected" view)
  - `Popup.css` (token-var-only styling)
  - `Placeholder.tsx` (the 3 inline placeholder components: Button, Card, Text; swapped for `@pangolin/component-library` later)
- `apps/extension/src/service-worker/index.ts` — vanilla TS; lifecycle handlers; structure-only.
- `apps/extension/src/content-script/index.ts` — empty stub with a `console.log`.
- `apps/extension/src/icons/` — placeholder PNG icons (16/32/48/128) — committed.
- `apps/extension/src/tokens.css` — `@import url('../../design-tokens/dist/tokens.css');` (relative path; mirrors MVP-4-D's discipline).
- `apps/extension/.gitignore` — `node_modules/`, `dist/`.
- `apps/extension/README.md` — how to build + load unpacked in Chrome for local testing.
- `.github/workflows/ci.yml` — new `extension` job that runs `pnpm install --frozen-lockfile`, `pnpm typecheck`, `pnpm lint`, `pnpm test`, `pnpm build`. Caches `~/.pnpm-store` via `actions/cache@v4`. Matrix on `node-version-file: 'apps/extension/.nvmrc'`.
- Hermetic tests: the popup renders without throwing (Vitest + React Testing Library); the service-worker module imports without error; the build produces a valid manifest (parse + check required fields).
- **Manual verification step documented in README**: build the extension; open `chrome://extensions`; enable Developer Mode; "Load unpacked" → `apps/extension/dist`; verify the popup opens + shows "Pangolin desktop not connected"; verify the service worker logs in `chrome://extensions/?id=<id>` → "Inspect views: service worker".

**Deferred (NOT this slice):**
- All capabilities listed in §0b.
- Firefox + Safari builds.
- Storybook for the extension popup (MVP-4-G can add one if useful; for this slice the popup is too small to warrant it).
- Hosted screenshots / chrome-web-store metadata.

## 2. Splittable? — no

The scaffold + manifest + service-worker + popup + content-script + CI all need to land together for the extension to load + the CI gate to be meaningful. Splitting forces a half-loadable extension between PRs. ONE slice → audit → merge.

## 3. Design

### 3.1 Directory layout

```text
apps/extension/
├─ package.json
├─ pnpm-lock.yaml
├─ tsconfig.json
├─ vite.config.ts
├─ .nvmrc
├─ .gitignore
├─ README.md
├─ manifest.json
└─ src/
   ├─ popup/
   │  ├─ popup.html
   │  ├─ index.tsx
   │  ├─ Popup.tsx
   │  ├─ Popup.css
   │  └─ Placeholder.tsx
   ├─ service-worker/
   │  └─ index.ts
   ├─ content-script/
   │  └─ index.ts
   ├─ tokens.css
   └─ icons/
      ├─ icon-16.png
      ├─ icon-32.png
      ├─ icon-48.png
      └─ icon-128.png
```

### 3.2 Vite multi-entry config

```ts
// vite.config.ts (sketch)
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { resolve } from 'node:path';
import { copyFileSync } from 'node:fs';

export default defineConfig({
  plugins: [
    react(),
    {
      name: 'copy-manifest-and-icons',
      writeBundle() {
        copyFileSync('manifest.json', 'dist/manifest.json');
        // copy icons
      },
    },
  ],
  build: {
    outDir: 'dist',
    rollupOptions: {
      input: {
        popup: resolve(__dirname, 'src/popup/popup.html'),
        'service-worker': resolve(__dirname, 'src/service-worker/index.ts'),
        'content-script': resolve(__dirname, 'src/content-script/index.ts'),
      },
      output: {
        entryFileNames: (chunk) =>
          chunk.name === 'service-worker' || chunk.name === 'content-script'
            ? '[name].js'
            : 'assets/[name].[hash].js',
      },
    },
  },
});
```

### 3.3 manifest.json (sketch)

```json
{
  "manifest_version": 3,
  "name": "Pangolin",
  "version": "0.0.0",
  "description": "Pangolin password vault — desktop-connected browser extension.",
  "action": { "default_popup": "src/popup/popup.html", "default_icon": { "16": "src/icons/icon-16.png", "32": "src/icons/icon-32.png" } },
  "background": { "service_worker": "service-worker.js", "type": "module" },
  "content_scripts": [{ "matches": ["<all_urls>"], "js": ["content-script.js"], "run_at": "document_idle" }],
  "permissions": ["storage", "activeTab", "scripting", "nativeMessaging"],
  "host_permissions": ["<all_urls>"],
  "icons": { "16": "src/icons/icon-16.png", "32": "src/icons/icon-32.png", "48": "src/icons/icon-48.png", "128": "src/icons/icon-128.png" }
}
```

(Final exact JSON gets vite-transformed — paths rewrite to the built `dist/` layout.)

### 3.4 Popup view

The Popup.tsx ships a single composition:

```text
┌──────────────────────────────────┐
│  Pangolin                        │
│                                  │
│  ○ Desktop not connected         │
│                                  │
│  Open the Pangolin desktop app   │
│  to start using your vault.      │
│                                  │
│  [ Open Pangolin (placeholder) ] │
└──────────────────────────────────┘
```

Width ~340px (standard MV3 popup). All styling via design-token CSS vars. The button is a placeholder (no click handler beyond `console.log`).

## 4. L-invariants

- **L1 zero-secret-crosses-the-extension.** This scaffold ships zero secret handling; the discipline is baked in (the popup has nothing to do with secrets yet). When MVP-4-G adds autofill, the L1 rule is: secrets cross the native-messaging boundary ONCE per fill + are zeroized in the content-script's clipboard write within 10 seconds per Browser-Ext spec §4.7.
- **L2 no new atomic surface** — the scaffold is structural; no state-machine work.
- **L3 fail-closed** — TS strict mode catches missing props at compile time; manifest validates at build time; the popup handles its single "disconnected" state explicitly.
- **L5** — React + Vite + TS + Vitest + `@types/chrome` are the only new external deps. NO Tailwind, NO Material UI, NO autofill libs (rolled in MVP-4-G).
- **L6** — `forbid` doesn't apply to JS/TS, but the equivalent posture: no `eval`, no `new Function`, no dynamic `import()` from runtime-computed paths (CSP would block them anyway in MV3). AGPL SPDX on every source file.
- **L7 — no user-facing forbidden terms.** Popup text + manifest description + README must pass the existing forbidden-terms CI grep (`\bgas\b|\bblockchain\b|\bdecentralized storage\b|\bhashes\b|\brevisions\b` -i).
- **L8 tests** — the popup renders; the service-worker imports; the manifest parses + has the required MV3 fields.
- **L9 §16 ledger** — DECISIONS + DEVLOG entries on merge.

## 5. Open decisions — pre-locked (one carve-out for the builder)

- **Q-a (placeholder icon source): builder's call.** Three options:
  - (i) Generate a tiny solid-orange-square PNG with the letter "P" via a build script.
  - (ii) Commit pre-rendered 4 placeholder PNGs (16/32/48/128) from an inline SVG via any tool the builder has.
  - (iii) Use the existing `pangolin.png` from the project root if it's at an acceptable resolution.
  Pick whichever needs the least incidental tooling. Real icons land at MVP-4 closeout.
- **Q-b (popup mount root vs `dialog` element): builder's call.** MV3 popups render in their own frame; using `<dialog>` is unnecessary. Default to a plain `<div id="popup-root">`. Mention if the builder picked something else.

All other decisions are locked per §0a.

## 6. Places that need care

- **MV3 service workers are NOT persistent.** They idle out + restart. Any state in the service worker MUST be re-derivable on cold start; this is structural for now (the service worker is empty) but will matter at MVP-4-G when native-messaging connects.
- **Content-script CSP**: MV3 content scripts run in an isolated world with their own CSP. The empty stub passes; future autofill code in MVP-4-G needs to be CSP-clean.
- **Manifest validation**: Chrome silently disables malformed manifests at "Load unpacked" time. The CI gate must `node`-parse the built `dist/manifest.json` + assert required fields. Don't trust the build output without that check.
- **Forbidden-terms grep**: every visible text string (popup HTML, manifest `description`, README) must pass. The existing CI step covers `apps/extension/` automatically once the workspace member is added.
- **`<all_urls>` host_permissions is a powerful grant**: documented in the README that the extension only ACTIVELY reads tab content when a registered login form is present (enforced by content-script logic in MVP-4-G). For closed beta, this is fine; for chrome-web-store submission (post-MVP-4) the explanation goes into the listing description.
- **Source-map handling**: ship source maps in dev builds; strip them in production builds. Chrome warns on missing source maps if any third-party tool re-bundles. Use Vite's `build.sourcemap = 'hidden'` for the production build.

## 7. Success criteria

- `pnpm install --frozen-lockfile` clean.
- `pnpm typecheck` clean.
- `pnpm test` green (popup renders + service-worker imports + manifest parses).
- `pnpm build` produces `dist/manifest.json` + `dist/popup.html` + `dist/service-worker.js` + `dist/content-script.js` + the icon files.
- New CI job `extension` green.
- Manual verification (documented in README): load unpacked in Chrome → popup opens + shows the "not connected" view → no console errors.
- Forbidden-terms CI step passes.
- Cardinal invariants still 0: `cargo tree -p pangolin-crypto | grep -ci serde`, `cargo tree -p pangolin-core | grep -ci uniffi`, `cargo tree -p pangolin-store | grep -ci uniffi`.

## 8. Out of scope (filed for follow-up)

- All MVP-4-G items per §0b (autofill, form detection, domain matching, per-site rules, origin binding, memory hygiene).
- Firefox + Safari builds.
- Storybook for the extension popup.
- Chrome Web Store listing / screenshots / category metadata.
- Real icons (placeholder set ships now).
- Real `@pangolin/component-library` imports (placeholder inline components ship now; swap at MVP-4-F or MVP-4-G).
