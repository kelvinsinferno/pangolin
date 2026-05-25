// SPDX-License-Identifier: AGPL-3.0-or-later
/// <reference types="vitest" />
import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import dts from 'vite-plugin-dts';
import { resolve } from 'node:path';

// Vite 6 library-mode build per docs/issue-plans/mvp4-d-component-library.md §3.2.
// Emits both ESM + CJS bundles + `.d.ts` declarations via vite-plugin-dts
// (rollupTypes: true bundles every public type into a single index.d.ts).
// react + react-dom + react/jsx-runtime are marked external so the
// downstream consumer (Tauri desktop shell / Chromium MV3 popup) provides
// its own React copy — bundling a second copy would break hooks.
//
// Storybook reuses this config and strips vite-plugin-dts via its
// `viteFinal` hook in `.storybook/main.ts` — leaving dts active there
// fails the build because it expects the library's dist/ entry which
// Storybook never produces.
//
// `vitest/config` re-exports defineConfig so the same file legitimately
// owns both build + test config without TS complaining about the `test`
// key on the Vite UserConfig type.
export default defineConfig({
  plugins: [react(), dts({ rollupTypes: true, include: ['src/**/*'] })],
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
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test-setup.ts'],
    include: ['src/**/*.test.{ts,tsx}'],
    css: true,
  },
});
