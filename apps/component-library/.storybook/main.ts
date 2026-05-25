// SPDX-License-Identifier: AGPL-3.0-or-later
import type { StorybookConfig } from '@storybook/react-vite';

// Storybook 8 with Vite framework. Addons per plan §3.4 + §5 Q-b:
// `addon-essentials` (controls, actions, backgrounds, toolbars,
// measure, outline, viewport) plus `addon-a11y` (axe-core). Q-b
// decision: SKIP `interactions` (play-functions not used at this size),
// `docs` autogen (stories ARE the docs), and any other addons —
// keep the surface minimal so CI is fast.
const config: StorybookConfig = {
  stories: ['../src/**/*.stories.@(ts|tsx)'],
  addons: [
    '@storybook/addon-essentials',
    '@storybook/addon-a11y',
  ],
  framework: {
    name: '@storybook/react-vite',
    options: {},
  },
  core: {
    disableTelemetry: true,
  },
  typescript: {
    check: false,
  },
  // Strip vite-plugin-dts when running inside Storybook. The dts plugin
  // is only useful for the library `pnpm build` — it tries to roll up
  // declaration files from `dist/` which Storybook never populates, so
  // leaving it active here fails the build with a missing-file error.
  viteFinal: async (cfg) => {
    const isDtsPlugin = (p: unknown): boolean => {
      if (p === null || p === undefined || p === false) return false;
      if (typeof p === 'object' && p !== null && 'name' in p) {
        const name = (p as { name: unknown }).name;
        if (typeof name === 'string') {
          return name === 'vite:dts' || name.includes('vite-plugin-dts');
        }
      }
      return false;
    };
    if (Array.isArray(cfg.plugins)) {
      // Plugins can be nested arrays; flatten one level which is what
      // Vite supports + drop any dts entries.
      const flat: unknown[] = [];
      for (const p of cfg.plugins) {
        if (Array.isArray(p)) {
          flat.push(...p);
        } else {
          flat.push(p);
        }
      }
      cfg.plugins = flat.filter((p) => !isDtsPlugin(p)) as typeof cfg.plugins;
    }
    // Also strip the build.lib config — Storybook builds an app, not a library.
    if (cfg.build !== undefined) {
      delete cfg.build.lib;
      if (cfg.build.rollupOptions !== undefined) {
        delete cfg.build.rollupOptions.external;
        delete cfg.build.rollupOptions.output;
      }
    }
    return cfg;
  },
};

export default config;
