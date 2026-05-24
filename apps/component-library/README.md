<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# `@pangolin/component-library`

The canonical React component library that the Tauri desktop shell
(MVP-4-B/-F) and the Chromium MV3 extension popup (MVP-4-C/-G) both
consume. See `docs/issue-plans/mvp4-d-component-library.md` for the
locked plan and design rationale.

`private: true` — never published to npm. The `@pangolin` scope is for
import-path readability only.

## Quickstart

```sh
cd apps/component-library
pnpm install
pnpm storybook       # local catalog at http://localhost:6006
pnpm build           # emits dist/index.{mjs,cjs,d.ts}
pnpm test            # vitest + RTL
pnpm typecheck       # tsc --noEmit (strict)
pnpm lint            # eslint
pnpm storybook:build # static build (CI gate)
```

Node `>=20.18.0 <23` (matches `.nvmrc`). pnpm is the only supported
package manager; the lockfile (`pnpm-lock.yaml`) is committed and CI
runs `pnpm install --frozen-lockfile`.

## Design tokens dependency

Components style themselves exclusively via the CSS custom properties
emitted by [`@pangolin/design-tokens`](../design-tokens/). At build
time `src/tokens.css` re-exports them with:

```css
@import url('../../design-tokens/dist/tokens.css');
```

This is a **relative-path** dependency on
`apps/design-tokens/dist/tokens.css` (a committed, generated artifact).
If either app moves, that import must be updated. The library
intentionally does not introduce a workspace-level alias — keeping the
relationship explicit and local makes the dependency obvious at audit
time.

`src/index.ts` imports `./tokens.css` as its very first statement so
downstream consumers get tokens automatically when they import any
component.

## Usage

```tsx
import { Button, Input, Modal } from '@pangolin/component-library';

export function App() {
  return (
    <div data-theme="dark">
      <Button variant="primary" onClick={() => console.log('clicked')}>
        Continue
      </Button>
    </div>
  );
}
```

Set `data-theme="dark"` or `data-theme="light"` on a root element
(typically `<html>` or `<body>`); the components read the appropriate
token override block automatically. No theme context, no provider — the
design-tokens layer owns theme switching at the CSS variable layer.

## Component inventory

**Atomic** (`src/atomic/`):
Button, Input, Label, IconButton, Avatar, Spinner, Badge, Divider,
Tag, Code.

**Composite** (`src/composite/`):
ListRow, Modal, Toast, PasswordMeter, SeedPhraseGrid, Card.

**Icons** (`src/icons/`):
Eye, EyeOff, Copy, Check, Warning, Lock, Unlock, Plus, X, Chevron.

Every component has a `.tsx` source, a `.css` stylesheet (tokens only;
no hard-coded values), a `.stories.tsx` Storybook entry, and a
`.test.tsx` test.

## CSS naming convention

Global classnames with a `pcl-` (Pangolin Component Library) prefix
— see plan §5 Q-a. No CSS modules: simpler build, no hash-suffix
mangling in the consumer bundle. Collision-safety relies on the
`pcl-` prefix + the fact that consumers are trusted internal code.

## Accessibility

- All interactive components are keyboard-operable and have visible
  `:focus-visible` styles.
- The Storybook `addon-a11y` (axe-core) runs against every story in
  CI; any new violation fails the build.
- Modal traps focus and restores it on close. Toast uses `role="status"`
  for the non-danger variants and `role="alert"` for danger.
  PasswordMeter exposes `role="meter"` with valid `aria-valuemin/max/now`.
