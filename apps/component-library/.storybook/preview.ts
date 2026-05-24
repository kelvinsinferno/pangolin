// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Preview } from '@storybook/react';
import React from 'react';
import '../src/tokens.css';

// Global decorator wraps every story in <div data-theme="..."> so
// the [data-theme="dark"] override block in tokens.css is exercised.
// Toolbar `theme` toggle switches between dark (default) and light.
const preview: Preview = {
  parameters: {
    controls: {
      matchers: { color: /(background|color)$/i, date: /Date$/i },
    },
    a11y: {
      // axe-core runs against every story automatically. New violation
      // = CI fails per plan §3.5.
      element: '#storybook-root',
      config: {},
      options: {},
    },
  },
  globalTypes: {
    theme: {
      description: 'Color theme',
      defaultValue: 'dark',
      toolbar: {
        title: 'Theme',
        icon: 'circlehollow',
        items: [
          { value: 'dark', title: 'Dark' },
          { value: 'light', title: 'Light' },
        ],
        dynamicTitle: true,
      },
    },
  },
  decorators: [
    (Story, ctx) => {
      const theme = (ctx.globals['theme'] as string | undefined) ?? 'dark';
      return React.createElement(
        'div',
        {
          'data-theme': theme,
          style: {
            background: 'var(--color-surface)',
            color: 'var(--color-text)',
            minHeight: '100vh',
            padding: 'var(--space-4)',
            fontFamily: 'var(--font-family-sans)',
          },
        },
        React.createElement(Story),
      );
    },
  ],
};

export default preview;
