// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Shared helpers for the WebDriverIO specs.
//
// Plan-LOCK: docs/issue-plans/mvp4-f-desktop-e2e.md §3.4.

import { existsSync, readFileSync, rmSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/** Path the build-fixture-vault.ts script writes the absolute vault path to. */
const FIXTURE_PATH_FILE = path.resolve(__dirname, '..', '.fixture-path');

/**
 * Remove SQLite WAL + lock sidecars that a prior spec may have left
 * behind. tauri-driver SIGTERMs the Tauri instance between specs and
 * Rust does NOT run `Drop` on statics, so `pangolin-store::Vault`'s
 * `.lock` sidecar file persists. The next spec's `vault_open` then
 * fails with `StoreError::AlreadyOpen` (a `Store` DesktopError that
 * shows up as a toast but never transitions the React state machine
 * out of the welcome stage — hence the `master-password-input`
 * selector wait times out). Scrubbing the sidecars before each Open
 * makes the specs hermetic across the maxInstances=1 spec serialisation.
 * Plan-LOCK §3.4.
 */
function scrubVaultSidecars(vaultPath: string): void {
  for (const suffix of ['.lock', '-shm', '-wal']) {
    const sidecar = `${vaultPath}${suffix}`;
    if (existsSync(sidecar)) {
      try {
        rmSync(sidecar, { force: true });
      } catch {
        // best-effort; the vault_open path surfaces a `Store` error
        // upstream if the lock can't be cleared
      }
    }
  }
}

/** The deterministic master password used by `setup/build-fixture-vault.ts`. */
export const MASTER_PASSWORD = 'test-password-123!';

/** The deterministic per-account fixture data. */
export const FIXTURE_ACCOUNTS = [
  { name: 'GitHub', username: 'alice@example.com', password: 'github-fixture-pw-1' },
  { name: 'Gmail', username: 'alice@gmail.com', password: 'gmail-fixture-pw-2' },
  { name: 'Twitter', username: 'alice_handle', password: 'twitter-fixture-pw-3' },
] as const;

/**
 * Read the absolute path to the fixture vault recorded by the
 * build-fixture-vault.ts setup script.
 */
export function readFixturePath(): string {
  const raw = readFileSync(FIXTURE_PATH_FILE, 'utf8');
  return raw.trim();
}

/**
 * Open the fixture vault on the welcome screen + submit.
 *
 * Selector strategy: `data-testid` first, ARIA-role + accessible
 * name second, text content last. See plan §3.4. The `vault-path-input`
 * testid lives on the welcome-screen text input; the existing
 * `vault-file-picker` wrapper carries the E2E stable ID.
 */
export async function openFixtureVault(): Promise<void> {
  const vaultPath = readFixturePath();
  // Scrub sidecars left by a prior spec's Tauri SIGTERM (see helper
  // comment above scrubVaultSidecars).
  scrubVaultSidecars(vaultPath);
  const picker = await $('[data-testid="vault-file-picker"]');
  await picker.waitForExist({ timeout: 15_000 });
  const input = await picker.$('[data-testid="vault-path-input"]');
  await input.setValue(vaultPath);
  const openButton = await $('button=Open');
  await openButton.click();
}

/**
 * Type a password into the unlock screen + click Unlock.
 *
 * Uses the plan's `master-password-input` wrapper testid as the
 * locator + reaches into the inner element for the actual text input.
 */
export async function typeUnlockPassword(password: string): Promise<void> {
  const wrapper = await $('[data-testid="master-password-input"]');
  await wrapper.waitForExist({ timeout: 15_000 });
  // The Input component renders the underlying <input> with the
  // existing `password-input` testid; that's the actual text field.
  const input = await wrapper.$('input');
  await input.setValue(password);
  const unlockButton = await $('button*=Unlock');
  await unlockButton.click();
}
