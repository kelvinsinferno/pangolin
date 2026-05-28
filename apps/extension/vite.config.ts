// SPDX-License-Identifier: AGPL-3.0-or-later
import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

/**
 * MV3 multi-entry build:
 *  - popup       → HTML entry; assets hashed (Vite default for HTML pipeline)
 *  - service-worker → emits dist/service-worker.js (fixed name; manifest refers
 *    to it by exact filename — hashing would break the manifest reference)
 *  - content-script → emits dist/content-script.js (same reason)
 *
 * The custom plugin copies manifest.json + icons into dist/, and rewrites
 * `action.default_popup` to point at the built popup HTML (which Vite outputs
 * at dist/src/popup/popup.html because we use it as a multi-page HTML entry).
 */
export default defineConfig({
  plugins: [
    react(),
    {
      name: 'pangolin-extension-manifest-and-assets',
      apply: 'build',
      writeBundle(): void {
        const manifestSrc = resolve(__dirname, 'manifest.json');
        const manifestDst = resolve(__dirname, 'dist/manifest.json');
        const manifest = JSON.parse(readFileSync(manifestSrc, 'utf8'));

        // Rewrite popup HTML path: source = src/popup/popup.html,
        // Vite's multi-entry HTML output preserves the relative directory
        // structure under dist/, so the built popup lives at
        // dist/src/popup/popup.html.
        manifest.action.default_popup = 'src/popup/popup.html';

        // Icon paths: copy src/icons/* into dist/src/icons/* and leave the
        // manifest's icon paths untouched (already point at src/icons/*).
        const iconsDst = resolve(__dirname, 'dist/src/icons');
        mkdirSync(iconsDst, { recursive: true });
        for (const size of ['16', '32', '48', '128']) {
          const name = `icon-${size}.png`;
          copyFileSync(
            resolve(__dirname, 'src/icons', name),
            resolve(iconsDst, name),
          );
        }

        writeFileSync(manifestDst, `${JSON.stringify(manifest, null, 2)}\n`);
      },
    },
  ],
  // Relative base so the popup HTML's emitted <script src="..."> + <link
  // href="..."> resolve as extension-relative paths once Chrome loads
  // popup.html from a nested directory inside the unpacked extension.
  base: './',
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: 'hidden',
    rollupOptions: {
      input: {
        popup: resolve(__dirname, 'src/popup/popup.html'),
        'service-worker': resolve(__dirname, 'src/service-worker/index.ts'),
        'content-script': resolve(__dirname, 'src/content-script/index.ts'),
      },
      output: {
        entryFileNames: (chunk) => {
          if (
            chunk.name === 'service-worker' ||
            chunk.name === 'content-script'
          ) {
            return '[name].js';
          }
          return 'assets/[name]-[hash].js';
        },
        chunkFileNames: 'assets/[name]-[hash].js',
        assetFileNames: 'assets/[name]-[hash][extname]',
      },
    },
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test-setup.ts'],
    // Exclude the Puppeteer e2e specs from Vitest discovery — they
    // use Mocha syntax (this.timeout(...)) and are driven separately
    // by apps/extension/e2e/ via its own pnpm e2e script. Without
    // this exclusion Vitest tries to load them + crashes with
    // Cannot read properties of undefined (reading timeout)
    // (Mochas this is undefined under Vitest).
    exclude: ['node_modules/**', 'dist/**', 'e2e/**'],
  },
});
