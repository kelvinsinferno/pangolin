// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * **Audit HIGH H1 regression gate (axe-core actually runs in CI).**
 *
 * The plan + README promised "axe-core runs against every story; any
 * new violation fails the build." But `@storybook/addon-a11y` ONLY
 * runs axe interactively in the Storybook UI — `storybook:build`
 * produces static HTML+JS and never executes axe. Every later MVP-4
 * sub-issue would have inherited a non-existent a11y gate.
 *
 * This file fills that gate at the Vitest layer: it renders every
 * component in the library with sensible default props + runs axe
 * against the resulting DOM. Any new violation fails the
 * `pnpm test` job (which CI runs).
 *
 * The check is **synchronous-per-component** and uses jsdom (already
 * the Vitest test env). Coverage:
 * - color-contrast is DISABLED because jsdom doesn't compute styles
 *   (every contrast test would falsely pass; we'd rather have
 *   visible-CSS-contrast checks in Storybook + the closed-beta visual
 *   pass than fake-pass them here).
 * - all other axe rules (label, aria, role, region, etc.) run with
 *   their defaults — these are the rules that catch the real-world
 *   issues (missing labels, mis-paired aria, etc.) without needing
 *   computed styles.
 */
import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render } from '@testing-library/react';
import axe from 'axe-core';

import { Avatar } from './atomic/Avatar/Avatar';
import { Badge } from './atomic/Badge/Badge';
import { Button } from './atomic/Button/Button';
import { Code } from './atomic/Code/Code';
import { Divider } from './atomic/Divider/Divider';
import { IconButton } from './atomic/IconButton/IconButton';
import { Input } from './atomic/Input/Input';
import { Label } from './atomic/Label/Label';
import { Spinner } from './atomic/Spinner/Spinner';
import { Tag } from './atomic/Tag/Tag';
import { Card } from './composite/Card/Card';
import { ListRow } from './composite/ListRow/ListRow';
import { Modal } from './composite/Modal/Modal';
import { PasswordMeter } from './composite/PasswordMeter/PasswordMeter';
import { SeedPhraseGrid } from './composite/SeedPhraseGrid/SeedPhraseGrid';
import { Toast } from './composite/Toast/Toast';
import { X } from './icons/X';

/**
 * Run axe against the currently-rendered DOM + assert zero violations.
 * Disables `color-contrast` because jsdom can't compute styles
 * accurately enough to evaluate it; visible contrast is gated in
 * Storybook + visual review.
 */
async function expectNoAxeViolations(container: HTMLElement): Promise<void> {
  const results = await axe.run(container, {
    rules: {
      'color-contrast': { enabled: false },
    },
  });
  if (results.violations.length > 0) {
    const details = results.violations
      .map(
        (v) =>
          `  - ${v.id} (${v.impact ?? 'unknown'}): ${v.help} -- nodes: ${v.nodes
            .map((n) => n.target.join(' '))
            .join(', ')}`,
      )
      .join('\n');
    throw new Error(`axe-core found ${results.violations.length} violation(s):\n${details}`);
  }
}

describe('axe-core a11y gate (every component renders without axe violations)', () => {
  afterEach(cleanup);

  it('Avatar', async () => {
    const { container } = render(<Avatar name="Kelvin Pangolin" />);
    await expectNoAxeViolations(container);
  });

  it('Badge', async () => {
    const { container } = render(<Badge>3</Badge>);
    await expectNoAxeViolations(container);
  });

  it('Button (each variant)', async () => {
    for (const variant of ['primary', 'secondary', 'ghost', 'danger'] as const) {
      const { container, unmount } = render(<Button variant={variant}>Action</Button>);
      await expectNoAxeViolations(container);
      unmount();
    }
  });

  it('Code (inline + block)', async () => {
    const { container, unmount } = render(<Code>let x = 1;</Code>);
    await expectNoAxeViolations(container);
    unmount();
    const { container: c2 } = render(<Code variant="block">{'multi\nline'}</Code>);
    await expectNoAxeViolations(c2);
  });

  it('Divider', async () => {
    const { container } = render(<Divider />);
    await expectNoAxeViolations(container);
  });

  it('IconButton (requires aria-label)', async () => {
    const { container } = render(
      <IconButton aria-label="Close" icon={<X />} onClick={() => undefined} />,
    );
    await expectNoAxeViolations(container);
  });

  it('Input (label association via htmlFor/id)', async () => {
    const { container } = render(
      <div>
        <Label htmlFor="email">Email</Label>
        <Input id="email" type="email" placeholder="you@example.com" />
      </div>,
    );
    await expectNoAxeViolations(container);
  });

  it('Spinner', async () => {
    const { container } = render(<Spinner aria-label="Loading" />);
    await expectNoAxeViolations(container);
  });

  it('Tag', async () => {
    const { container } = render(<Tag>Recovery</Tag>);
    await expectNoAxeViolations(container);
  });

  it('Card', async () => {
    const { container } = render(<Card>Card body content</Card>);
    await expectNoAxeViolations(container);
  });

  it('ListRow', async () => {
    const { container } = render(<ListRow title="GitHub" subtitle="github.com" />);
    await expectNoAxeViolations(container);
  });

  it('Modal (open)', async () => {
    const { container } = render(
      <Modal open onClose={() => undefined} title="Confirm">
        <p>body</p>
      </Modal>,
    );
    await expectNoAxeViolations(container);
  });

  it('PasswordMeter', async () => {
    const { container } = render(<PasswordMeter password="correct-horse-battery-staple" />);
    await expectNoAxeViolations(container);
  });

  it('SeedPhraseGrid (24 words)', async () => {
    const words = Array.from({ length: 24 }, (_, i) => `word${i + 1}`);
    const { container } = render(<SeedPhraseGrid words={words} />);
    await expectNoAxeViolations(container);
  });

  it('Toast (each variant; container has the live-region role)', async () => {
    for (const variant of ['success', 'warning', 'danger'] as const) {
      const { container, unmount } = render(
        <Toast variant={variant} onDismiss={() => undefined}>
          A {variant} message.
        </Toast>,
      );
      await expectNoAxeViolations(container);
      unmount();
    }
  });
});
