// SPDX-License-Identifier: AGPL-3.0-or-later
//
// WebDriverIO config for the Pangolin desktop E2E gate.
//
// Plan-LOCK: docs/issue-plans/mvp4-f-desktop-e2e.md §3.1 + §3.5.
//
// The config drives `tauri-driver` (a Cargo-installed proxy that
// bridges W3C WebDriver to the Tauri WebView) against a debug build
// of `pangolin-desktop --features test-hooks`. The `onPrepare` hook
// spawns `tauri-driver` on port 4444; `onComplete` reaps it. Each
// spec connects to `localhost:4444`, drives the renderer, and reads
// the in-process invocation log (the `__test__commands_invoked`
// Tauri command) for the H-1 assertion in scenario 5.
//
// Linux only this slice; xvfb-run is the wrapper the dev loop + CI
// both invoke. See README.md.

import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { startTauriDriver, stopTauriDriver } from './setup/start-tauri-driver.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Path to the debug-built Tauri binary. The `build:desktop` script
// (`cargo build -p pangolin-desktop --features test-hooks`) produces
// it; on Linux + macOS the path is `target/debug/pangolin-desktop`.
// On Windows the binary would be `target\debug\pangolin-desktop.exe`
// but this slice is Linux-only.
const WORKSPACE_ROOT = path.resolve(__dirname, '..', '..', '..');
const PANGOLIN_DESKTOP_BINARY = path.join(
  WORKSPACE_ROOT,
  'target',
  'debug',
  'pangolin-desktop',
);

// `tauri-driver` keeps a reference to the child it spawns; we hold the
// `tauri-driver` process handle here so the after-hook can reap it.
let tauriDriverHandle: { kill: () => void } | null = null;

// `WebdriverIO.Config` (introduced in 9.x) is the canonical type for
// wdio.conf.ts in 9.27.x — it extends `Options.Testrunner` with the
// capabilities-requesting fields the runner reads. Earlier 9.4-era
// drafts used `Options.Testrunner` directly; that type alone lacks the
// `capabilities` field and triggers TS2353.
export const config: WebdriverIO.Config = {
  runner: 'local',
  framework: 'mocha',
  specs: [path.join(__dirname, 'specs', '**', '*.test.ts')],
  // `tauri-driver` is a single-session driver: one Tauri window at a
  // time. Per plan §6 (Places that need care): "tauri-driver is
  // single-WebView". Forces `maxInstances: 1` so the 5 spec files
  // execute serially.
  maxInstances: 1,
  capabilities: [
    {
      // `tauri-driver` keys its session on the `tauri:options.application`
      // capability — the absolute path to the Tauri binary it should
      // spawn. Anything else in `tauri:options` is documented at
      // https://v2.tauri.app/develop/tests/webdriver/.
      'tauri:options': {
        application: PANGOLIN_DESKTOP_BINARY,
      },
      browserName: 'wry',
    } as WebdriverIO.Capabilities,
  ],
  logLevel: 'info',
  outputDir: path.join(__dirname, 'wdio-logs'),
  bail: 0,
  // `tauri-driver` defaults to port 4444; the start-tauri-driver
  // helper waits for the port to bind before resolving.
  hostname: 'localhost',
  port: 4444,
  waitforTimeout: 15_000,
  connectionRetryTimeout: 30_000,
  connectionRetryCount: 3,
  reporters: ['spec'],
  mochaOpts: {
    ui: 'bdd',
    timeout: 60_000,
  },

  /**
   * Spawn `tauri-driver` before any sessions start. Runs once per
   * suite. The helper waits for port 4444 to bind before resolving;
   * failure to bind within 30s exits non-zero.
   */
  onPrepare: async function (_config, _capabilities) {
    tauriDriverHandle = await startTauriDriver();
  },

  /**
   * Reap `tauri-driver` after the last session ends. Runs once per
   * suite, even on failure.
   */
  onComplete: function (_exitCode, _config, _capabilities) {
    stopTauriDriver(tauriDriverHandle);
    tauriDriverHandle = null;
  },
};
