// SPDX-License-Identifier: AGPL-3.0-or-later
//
// MVP-4-H Layer 5 — OS-automation integration suite wdio config.
//
// Plan-LOCK: docs/issue-plans/mvp4-h-secure-input.md sec 3 Layer 5.
//
// Sibling of `wdio.conf.ts`. Drives the same Tauri binary, but the
// binary is built WITHOUT the `secure-input-stub` feature so the
// REAL per-OS native password widget runs. The specs in
// `specs-secure-input/` use platform-specific OS automation tools
// (xdotool on Linux, osascript on macOS, AutoIt on Windows) to drive
// the dialog the user would see, then observe the React DOM via wdio
// to assert the FFI succeeded (accounts-list appears).
//
// The Layer-1 secure_input::stub is INTENTIONALLY not built into this
// binary — that's the whole point. The `test-hooks` feature is still
// enabled (we keep the invocation log for future cross-checks and
// `__test__force_unlock` so the integration suite can also drive
// flows that don't depend on the unlock UI), but the stub Tauri
// commands (`__test__secure_input_inject`/`_clear`) are absent.

import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { startTauriDriver, stopTauriDriver } from './setup/start-tauri-driver.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const WORKSPACE_ROOT = path.resolve(__dirname, '..', '..', '..');
// Same binary path as wdio.conf.ts (cargo target/debug). Pre-built
// step in the secure-input-e2e CI job runs:
//   cargo build -p pangolin-desktop --features test-hooks,custom-protocol
// (NO secure-input-stub — the real per-OS widget is what we want to
// exercise here). On Windows the binary is `pangolin-desktop.exe`.
const BINARY_NAME =
  process.platform === 'win32' ? 'pangolin-desktop.exe' : 'pangolin-desktop';
const PANGOLIN_DESKTOP_BINARY = path.join(
  WORKSPACE_ROOT,
  'target',
  'debug',
  BINARY_NAME,
);

let tauriDriverHandle: { kill: () => void } | null = null;

export const config: WebdriverIO.Config = {
  runner: 'local',
  framework: 'mocha',
  // Pick exactly the per-OS spec for the current platform. The CI
  // matrix job sets `runs-on` for each OS leg; we only want to run
  // the matching spec. The other-OS specs use OS-specific tools
  // (xdotool / osascript / AutoIt) that would error out anyway.
  specs: (() => {
    const platform = process.platform;
    if (platform === 'linux') return [path.join(__dirname, 'specs-secure-input', 'linux.spec.ts')];
    if (platform === 'darwin') return [path.join(__dirname, 'specs-secure-input', 'macos.spec.ts')];
    if (platform === 'win32') return [path.join(__dirname, 'specs-secure-input', 'windows.spec.ts')];
    throw new Error(`secure-input-e2e: unsupported platform ${platform}`);
  })(),
  maxInstances: 1,
  capabilities: [
    {
      'tauri:options': {
        application: PANGOLIN_DESKTOP_BINARY,
      },
    } as WebdriverIO.Capabilities,
  ],
  logLevel: 'info',
  outputDir: path.join(__dirname, 'wdio-logs-secure-input'),
  bail: 0,
  hostname: 'localhost',
  port: 4444,
  waitforTimeout: 30_000,
  connectionRetryTimeout: 120_000,
  connectionRetryCount: 3,
  reporters: ['spec'],
  mochaOpts: {
    ui: 'bdd',
    // L5 specs include a dialog-wait + OS automation step that adds
    // latency on top of the regular unlock flow; bump the per-spec
    // budget to 240s (vs 180s in wdio.conf.ts) so CI runners have
    // headroom for the apt/brew tool install + the xvfb-driven
    // dialog event loop.
    timeout: 240_000,
  },
  onPrepare: async function (_config, _capabilities) {
    tauriDriverHandle = await startTauriDriver();
  },
  onComplete: function (_exitCode, _config, _capabilities) {
    stopTauriDriver(tauriDriverHandle);
    tauriDriverHandle = null;
  },
};
