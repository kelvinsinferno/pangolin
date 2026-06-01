// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Shared helpers for the MVP-4-H Layer 5 OS-automation integration
// suite. Plan-LOCK: docs/issue-plans/mvp4-h-secure-input.md sec 3 L5.
//
// Distinct from `../specs/helpers.ts` — that helper uses
// `__test__secure_input_inject` (only exists when the
// `secure-input-stub` feature is enabled). The Layer-5 build has the
// stub DISABLED, so the integration spec drives the real OS dialog
// via platform-specific automation tools.

import { execSync } from 'node:child_process';

import { openFixtureVault, MASTER_PASSWORD } from '../specs/helpers.js';

export { openFixtureVault, MASTER_PASSWORD };

/**
 * Click the SecurePasswordButton on the Unlock screen, which triggers
 * the real OS native password dialog via `vault_unlock_via_secure_prompt`.
 *
 * Returns AFTER the button click but BEFORE the OS dialog necessarily
 * has focus — the caller drives the OS-automation tool next.
 */
export async function clickUnlockButton(): Promise<void> {
  const wrapper = await $('[data-testid="master-password-input"]');
  await wrapper.waitForExist({ timeout: 30_000 });
  const button = await $('[data-testid="unlock-button"]');
  await button.click();
}

/**
 * Wait for the accounts-list testid to appear, which means the unlock
 * completed successfully and the React state machine transitioned to
 * the active stage. This is the L5 success assertion.
 */
export async function waitForAccountsList(): Promise<void> {
  const list = await $('[data-testid="accounts-list"]');
  await list.waitForExist({ timeout: 30_000 });
}

/**
 * Run a shell command synchronously and return its stdout. Throws on
 * non-zero exit with the stderr included so CI logs surface the OS
 * automation tool's complaint. Used by the platform-specific specs to
 * drive xdotool / osascript / AutoIt.
 */
export function shell(cmd: string): string {
  try {
    return execSync(cmd, { stdio: ['ignore', 'pipe', 'pipe'] }).toString('utf8');
  } catch (e) {
    const err = e as { stderr?: Buffer; stdout?: Buffer; message: string };
    const stderr = err.stderr?.toString('utf8') ?? '';
    const stdout = err.stdout?.toString('utf8') ?? '';
    throw new Error(`shell failed: ${cmd}\nstderr: ${stderr}\nstdout: ${stdout}\n${err.message}`);
  }
}

/**
 * Sleep for `ms` milliseconds. The OS dialog spawn is async (driven
 * by the Tauri command's `app.run_on_main_thread` + the OS toolkit's
 * event loop), so the spec waits a short beat before driving the
 * automation tool.
 */
export async function sleep(ms: number): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, ms));
}
