// SPDX-License-Identifier: AGPL-3.0-or-later
/// <reference types="vitest" />
import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

/**
 * Vite 6 config for the Pangolin Tauri v2 desktop shell.
 *
 * - The React 19 plugin hosts the frontend (apps/desktop/src/ui/).
 * - Tauri integration: `server.port: 5173` matches tauri.conf.json's
 *   `build.devUrl`; `clearScreen: false` keeps Vite's startup banner
 *   visible alongside Tauri's so `pnpm tauri dev` debug output is
 *   readable. `strictPort: true` ensures the dev server fails loudly
 *   if port 5173 is occupied (Tauri's WebView would silently 404).
 * - `build.outDir: 'dist'` matches tauri.conf.json's `frontendDist`.
 * - `build.target: 'esnext'` because the WebView is the only consumer
 *   (Chromium on Linux/Windows, WebKit on macOS — both ship modern ES).
 *
 * Vitest borrows the same module graph; jsdom + the same RTL setup
 * file the other apps use.
 */
export default defineConfig({
  plugins: [react()],
  // Relative base so the popup HTML's emitted asset URLs resolve as
  // Tauri-relative paths when the WebView loads `index.html` from the
  // bundle root. Mirrors the extension app's pattern.
  base: './',
  server: {
    port: 5173,
    strictPort: true,
  },
  clearScreen: false,
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    target: 'esnext',
    sourcemap: 'hidden',
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/ui/test-setup.ts'],
    include: ['src/**/*.test.{ts,tsx}'],
    css: true,
  },
});
