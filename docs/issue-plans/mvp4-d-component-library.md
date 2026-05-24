<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# MVP-4-D — Component library — plan-gate LOCKED

**Status: LOCKED — self-locked 2026-05-24.** No Kelvin gate per MVP-4 overview §6 (pure UI implementation against the locked design-tokens layer; no architectural surface that wasn't already settled in the overview). Decisions pre-resolved in §0a below.

## 0. One-paragraph summary

Stand up the canonical React component library that the Tauri desktop shell (MVP-4-B/-F) and the Chromium MV3 extension popup (MVP-4-C/-G) both consume. Atomic primitives (Button, Input, Card, Avatar, …) + composite components (ListRow, Modal, Toast, PasswordMeter, SeedPhraseGrid) per Design Spec §6 + §7. Styled exclusively via the CSS custom properties emitted by `pangolin-design-tokens` (MVP-4-A); no Tailwind, no CSS-in-JS runtime. React 19 + TypeScript + Vite library mode + Vitest + Storybook. Importable as `@pangolin/component-library` from both the desktop shell and the extension popup.

## 0a. RESOLVED decisions (self-locked 2026-05-24)

- **React 19.x** (current stable; Tauri v2 + Vite both support it). Concurrent rendering primitives + `use()` hook + native form actions land — useful for the recovery / multi-device UX flows in MVP-4's back half.
- **TypeScript** in strict mode (`"strict": true`, `"noUncheckedIndexedAccess": true`, `"exactOptionalPropertyTypes": true`). All exports typed; no `any`.
- **Vite 6.x** in library mode (`build.lib`). Emits both ESM + CJS bundles + `.d.ts` declarations via `vite-plugin-dts`. Source-maps shipped.
- **Vitest** for unit + behavior tests (Vite-native; zero config surprise). React Testing Library for the DOM-test posture (`@testing-library/react` + `@testing-library/jest-dom`). No Jest, no separate test runner.
- **Storybook 8.x** for the component-catalog docs page. Runs against the same Vite build so what you see in Storybook is what the shell renders. **CI runs `storybook build` as part of the lint job** to catch broken stories before they reach a reviewer's screen.
- **CSS approach: vanilla CSS files per component**, styled exclusively via the CSS custom properties from `pangolin-design-tokens/dist/tokens.css`. NO Tailwind (defeats the tokens layer + ships ~100KB of CSS the user never uses). NO `styled-components` / `emotion` / `vanilla-extract` (runtime cost + theme-switching friction). The token CSS file is imported once at the library entrypoint; every component reaches the vars via `var(--space-4)` / `var(--color-surface)` etc.
- **Package manager = pnpm** (fast install, strict lockfile, monorepo-friendly for the future MVP-4 sub-issues that may want to share deps). Lockfile committed; `pnpm-lock.yaml` becomes a load-bearing reproducibility artifact.
- **Node version pinned** via `.nvmrc` + `package.json#engines.node` to `>=20.18.0 <23` (the current LTS line that Vite 6 + Storybook 8 both support). CI uses `actions/setup-node@v4` with `node-version-file: '.nvmrc'`.
- **Package name on npm-style imports = `@pangolin/component-library`** (npm-scoped; never actually published to npm — `private: true` in package.json — but the scope makes the import paths readable).
- **No standalone Storybook deployment in this slice**. Storybook builds locally + in CI to catch breakage; a hosted Storybook is deferred to a follow-up (host on GitHub Pages from CI when the design system stabilizes).
- **Component primitives shipping THIS slice** (Design Spec §6 + §7; named per the spec; each gets a Storybook story + unit tests + an accessibility-axe story):
  - **Atomic**: Button (primary / secondary / ghost / danger × md / sm sizes), Input (text, password-masked, with leading-icon slot, with right-rail action), Label, IconButton, Avatar (initials fallback), Spinner, Badge, Divider, Tag, Code (mono inline + block).
  - **Composite**: ListRow (icon + title + subtitle + right-rail action), Modal (overlay + focus-trap + esc/click-outside), Toast (success/warning/danger × auto-dismiss), PasswordMeter (entropy-bar + the four-band rating from the password-generator UX), SeedPhraseGrid (the 24-word display for #109 backup; numbered + copy-each-row), Card (surface + elevation tiers).
- **Accessibility**: every interactive component is keyboard-operable + screen-reader-labelled by default; `axe-core` runs as a Storybook addon in CI. Color contrast verified against the dark + light variants of the semantic tokens (the auto-checker catches regressions when MVP-4-D's first-pass colors get refined at closed beta).
- **Dark/light theming** = read from `[data-theme]` attribute on the root the shell sets; component-library code never knows what mode it's in (it just reads token vars). Tested in Storybook via a theme switcher addon.
- **No icon library dep**. Inline SVGs in a `src/icons/` folder, each a tiny named React component. Easier to track diffs + zero runtime cost; matches the Design Spec's "no Material / no Phosphor" preference.
- **AGPL-3.0-or-later SPDX header** on every `.ts` / `.tsx` / `.css` file. The package.json declares `"license": "AGPL-3.0-or-later"`.

## 1. Scope

**Built in MVP-4-D:**
- `apps/component-library/` (NEW directory at the repo root).
- `apps/component-library/package.json` — pnpm-managed; `private: true`; deps + devDeps below.
- `apps/component-library/pnpm-lock.yaml` (committed).
- `apps/component-library/tsconfig.json` (strict TS).
- `apps/component-library/vite.config.ts` (library mode + dts).
- `apps/component-library/.storybook/` (Storybook config; uses Vite).
- `apps/component-library/src/index.ts` — barrel export of every component + every type.
- `apps/component-library/src/tokens.css` — imports `pangolin-design-tokens/dist/tokens.css` via a relative path (the dist file is at a known location in the repo). Imported by `src/index.ts` so consumers get the tokens automatically.
- `apps/component-library/src/{atomic,composite,icons}/` — the components, each in its own folder (`Button/Button.tsx` + `Button.css` + `Button.stories.tsx` + `Button.test.tsx` + `Button.module.css` if needed for collision avoidance).
- `apps/component-library/dist/` — build artifacts (NOT committed; CI builds; `.gitignore` covers it).
- Root `.gitignore` updates: add `apps/*/node_modules/` and `apps/*/dist/` (the latter is global; design-tokens' narrow exception from MVP-4-A still wins for the `apps/design-tokens/dist/` subpath via `.gitignore` rule precedence).
- `.github/workflows/ci.yml` — new `component-library` job that runs `pnpm install --frozen-lockfile`, then `pnpm typecheck`, `pnpm lint`, `pnpm test`, and `pnpm storybook:build`. Caches `~/.pnpm-store` via `actions/cache@v4`. Matrix on `node-version-file: '.nvmrc'`.
- Hermetic tests: every component has a render-test (it mounts without throwing); every interactive component has a behavior test (Button-click fires callback, Input-onChange fires with the typed value, Modal-esc closes, Toast-auto-dismiss fires); the `axe-core` Storybook addon runs in CI to catch a11y regressions.

**Deferred (NOT this slice):**
- Hosted Storybook (GitHub Pages from CI) — follow-up when design system stabilizes.
- Visual regression tests (Chromatic / Percy / Playwright screenshots) — defer until the team has a budget.
- The actual Design-Spec-fidelity token values — MVP-4-A's first-pass values ship; refinement in a future cycle once Kelvin sees them rendered.
- iOS/Android-specific component variants — MVP-5.
- Internationalization — deferred (English-only for closed beta; the components accept any string children so they're i18n-ready in shape).
- Form validation library wiring — deferred (the recovery + multi-device flows will need it; pick at MVP-4-F).

## 2. Splittable? — recommend ONE slice

The component library is small enough (~20 components × ~80 LoC TSX + ~60 LoC CSS + ~50 LoC tests + a story ≈ 4-5k LoC total) that splitting per-component would add cycle-time overhead without buying anything. ONE PR → audit (focus: a11y, type strictness, token-vars discipline, SPDX coverage, Storybook smoke) → merge.

## 3. Design

### 3.1 Directory layout

```text
apps/component-library/
├─ package.json
├─ pnpm-lock.yaml
├─ tsconfig.json
├─ vite.config.ts
├─ .nvmrc
├─ .storybook/
│  ├─ main.ts
│  ├─ preview.ts
│  └─ themes.ts
└─ src/
   ├─ index.ts                 ← barrel
   ├─ tokens.css               ← imports pangolin-design-tokens/dist/tokens.css
   ├─ atomic/
   │  ├─ Button/
   │  │  ├─ Button.tsx
   │  │  ├─ Button.css
   │  │  ├─ Button.stories.tsx
   │  │  └─ Button.test.tsx
   │  ├─ Input/...
   │  ├─ Label/...
   │  ├─ IconButton/...
   │  ├─ Avatar/...
   │  ├─ Spinner/...
   │  ├─ Badge/...
   │  ├─ Divider/...
   │  ├─ Tag/...
   │  └─ Code/...
   ├─ composite/
   │  ├─ ListRow/...
   │  ├─ Modal/...
   │  ├─ Toast/...
   │  ├─ PasswordMeter/...
   │  ├─ SeedPhraseGrid/...
   │  └─ Card/...
   └─ icons/
      ├─ index.ts
      ├─ Eye.tsx
      ├─ EyeOff.tsx
      ├─ Copy.tsx
      ├─ Check.tsx
      ├─ Warning.tsx
      ├─ Lock.tsx
      ├─ Unlock.tsx
      ├─ Plus.tsx
      ├─ X.tsx
      └─ Chevron.tsx
```

### 3.2 Vite library build

```ts
// vite.config.ts
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import dts from 'vite-plugin-dts';
import { resolve } from 'node:path';

export default defineConfig({
  plugins: [react(), dts({ rollupTypes: true })],
  build: {
    lib: {
      entry: resolve(__dirname, 'src/index.ts'),
      name: 'PangolinComponentLibrary',
      formats: ['es', 'cjs'],
      fileName: (fmt) => `index.${fmt === 'es' ? 'mjs' : 'cjs'}`,
    },
    rollupOptions: {
      external: ['react', 'react-dom', 'react/jsx-runtime'],
      output: { globals: { react: 'React', 'react-dom': 'ReactDOM' } },
    },
    sourcemap: true,
  },
});
```

### 3.3 The token-vars discipline

Components NEVER hard-code values:

```css
/* GOOD — Button.css */
.button {
  padding: var(--space-2) var(--space-4);
  border-radius: var(--radius-md);
  background: var(--color-accent-primary);
  color: var(--color-surface);
  font-family: var(--font-family-sans);
  font-weight: var(--font-weight-semibold);
  transition: transform var(--motion-duration-fast) var(--motion-easing-standard);
}

/* BAD — never ship this */
.button {
  padding: 8px 16px;          /* should be var(--space-2) var(--space-4) */
  border-radius: 8px;         /* should be var(--radius-md) */
  background: #F2843E;        /* should be var(--color-accent-primary) */
}
```

The audit catches this with a grep (or a custom ESLint rule) — `audit.config.js` enumerates the forbidden patterns (raw hex codes outside `tokens.css`, raw `px` units outside the icon SVGs, raw font-family names outside `tokens.css`).

### 3.4 Storybook

`.storybook/main.ts` — Vite framework; stories under `src/**/*.stories.tsx`. Addons: `@storybook/addon-essentials`, `@storybook/addon-a11y` (axe-core).

`.storybook/preview.ts` — global decorator that wraps stories in `<div data-theme="dark">` by default; toolbar toggle switches to `light`. Imports `src/tokens.css` so token vars are in scope.

`pnpm storybook` for local dev. `pnpm storybook:build` for the static build (CI-checked).

### 3.5 Accessibility floor (a11y)

- Every interactive component has a focus-visible state styled via `:focus-visible` + the `--color-accent-primary` ring.
- Every component that has a label OR a leading icon has an `aria-label` slot.
- Modal traps focus + restores it on close; Toast has `role="status"`; PasswordMeter has `role="meter"` + `aria-valuemin/max/now`.
- Storybook `addon-a11y` runs in CI; any new VIOLATION ranks fail-CI.

## 4. L-invariants

- **L1 — UI never holds secrets that aren't already in the host's hands.** PasswordMeter takes the password by reference and operates entropy/length math; it does not retain the password across renders. SeedPhraseGrid takes `words: string[]` from the host (already in the host's hands per the #109 L1 carve-out) and renders them; never logs, never copies to a global state.
- **L2 no new atomic surface** — components are stateless wrappers over their prop types (where possible); composite components own only ephemeral UI state (modal-open, toast-visible).
- **L3 fail-closed** — every component handles `null`/`undefined` props gracefully (typed via TS strict mode); a missing required prop is a compile-time error.
- **L5 limited new external deps** — react + react-dom + vite (build) + vitest (test) + storybook (docs) + @testing-library/react + @testing-library/jest-dom + axe-core + vite-plugin-dts + @vitejs/plugin-react + typescript. NO Tailwind, NO Material UI, NO Radix, NO Chakra, NO Mantine — pure React + tokens. The deps lock in `pnpm-lock.yaml` (committed).
- **L6 — AGPL SPDX + `private: true` + no publish to npm.**
- **L8 tests** — every component has at least one render + one behavior test; CI runs `pnpm test` + `pnpm typecheck` + `pnpm storybook:build` + `pnpm lint`.
- **L9 §16 ledger** — DECISIONS + DEVLOG entries on merge.

## 5. Open decisions — pre-locked (one carve-out for the builder)

- **Q-a (CSS modules vs global classnames): builder's call.** With ONE component library + clear naming convention (`pcl-button`, `pcl-input` etc.), CSS modules are arguably overkill. But CSS modules give per-component scope + prevent collisions if downstream code accidentally uses the same class name. Pick the simpler option that doesn't sacrifice the token-vars discipline — likely global classnames with a `pcl-` prefix is simplest + works fine since the components are consumed by trusted internal code.
- **Q-b (which Storybook addons): builder's call.** `essentials` + `a11y` are mandatory. Add `interactions` if play-functions are useful; skip `viewport` (the desktop + extension are fixed-form-factor); skip `docs` autogen (the stories ARE the docs at this size). Whatever the builder picks, report.

All other decisions are locked per §0a.

## 6. Places that need care

- **Strict TS** is non-negotiable. `noUncheckedIndexedAccess` catches a class of bugs that ship to production — keep it on.
- **Storybook a11y addon** must run in CI, not just locally. The `axe-core` violations are easy to ignore in the local dev loop but accumulate.
- **The `react` + `react-dom` external** in the Vite config is critical — the consumer (Tauri shell / extension popup) provides its own React; the library bundle must NOT include a second copy.
- **Forbidden-terms CI step** (existing) must still pass — verify component names + Storybook story titles don't trip it.
- **The `pangolin-design-tokens` import path** — the components consume `apps/design-tokens/dist/tokens.css` via a relative path. This is a known fragility (relative paths break if either side moves). The MVP-4-D component library should NOT add a workspace-level alias for this; just document the dependency in the README + let the future MVP-4-B / -C builds verify the import resolves.
- **`pnpm install --frozen-lockfile` in CI** — never `pnpm install` (which would silently update the lockfile).

## 7. Success criteria

- `pnpm install --frozen-lockfile` clean.
- `pnpm typecheck` clean (strict TS, zero errors).
- `pnpm test` runs every component's tests + axe-core checks; all green.
- `pnpm storybook:build` produces `storybook-static/` that opens to a navigable catalog.
- `pnpm build` produces `dist/index.mjs` + `dist/index.cjs` + `dist/index.d.ts`.
- New CI job `component-library` green.
- A downstream consumer can `import { Button, Input, Modal } from '@pangolin/component-library'` (verified via a tiny smoke-test script in CI).
- Cardinal invariants still 0: `cargo tree -p pangolin-crypto | grep -ci serde`, `cargo tree -p pangolin-core | grep -ci uniffi`, `cargo tree -p pangolin-store | grep -ci uniffi`.

## 8. Out of scope (filed for follow-up)

- Visual-regression tests (Chromatic / Playwright screenshots) — when the team has budget.
- Hosted Storybook on GH Pages — when the design system stabilizes.
- Per-OS tokens (Windows / macOS / Linux system colors) — out of scope.
- Form-validation library wiring — MVP-4-F's call.
- Internationalization — components are i18n-ready in shape; runtime + dictionaries are deferred.
- iOS/Android variants — MVP-5.
