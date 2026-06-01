// SPDX-License-Identifier: AGPL-3.0-or-later
//
// MVP-4-H Layer 5 — macOS OS-automation integration spec.
//
// Plan-LOCK: docs/issue-plans/mvp4-h-secure-input.md sec 3 L5.
//
// Validates that the REAL NSAlert + NSSecureTextField produced by
// `apps/desktop/src/secure_input/macos.rs` opens, accepts a typed
// password via osascript (System Events), and the FFI chain succeeds
// (the React DOM transitions to the accounts-list). Driven from the
// same wdio harness that drives Linux/Windows; the only per-OS thing
// is the keystroke pipeline.

import {
  clickUnlockButton,
  MASTER_PASSWORD,
  openFixtureVault,
  shell,
  sleep,
  waitForAccountsList,
} from './integration-helpers.js';

describe('secure-input-integration (macos/osascript)', () => {
  it('unlocks via the real NSAlert driven by osascript', async () => {
    await openFixtureVault();
    await clickUnlockButton();

    // NSAlert.runModal is synchronous on the main thread; wait a
    // beat so the alert is up before the System Events keystroke
    // pipeline targets it. The alert message text is "Unlock vault"
    // (set in `secure_prompt.rs::vault_unlock_via_secure_prompt`).
    await sleep(1500);

    // Type into the focused NSSecureTextField via System Events.
    // `keystroke return` submits the alert's default ("OK") button.
    // The escaping below is intentional: osascript's outer shell
    // and inner AppleScript both interpret quotes, so we escape both
    // levels.
    const escaped = MASTER_PASSWORD.replace(/"/g, '\\"');
    shell(
      `osascript -e 'tell application "System Events" to keystroke "${escaped}"' -e 'delay 0.2' -e 'tell application "System Events" to keystroke return'`,
    );

    // L5 success assertion (same as Linux): React transitions to
    // active and accounts-list appears.
    await waitForAccountsList();
  });
});
