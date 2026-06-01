// SPDX-License-Identifier: AGPL-3.0-or-later
//
// MVP-4-H Layer 5 — Windows OS-automation integration spec.
//
// Plan-LOCK: docs/issue-plans/mvp4-h-secure-input.md sec 3 L5.
//
// Validates that the REAL CredUIPromptForCredentialsW dialog produced
// by `apps/desktop/src/secure_input/windows.rs` opens, accepts a
// typed password via PowerShell SendKeys, and the FFI chain succeeds
// (the React DOM transitions to the accounts-list).
//
// **Tooling note:** the plan-LOCK §3 L5 named "AutoIt v3" but
// PowerShell's `[System.Windows.Forms.SendKeys]::SendWait` provides
// the same focused-window keystroke pipeline without any
// non-default-MSI install (AutoIt requires a separate download +
// install step on the GitHub Windows runner). Both target the same
// Win32 message pump; the choice is operational only.

import {
  clickUnlockButton,
  MASTER_PASSWORD,
  openFixtureVault,
  shell,
  sleep,
  waitForAccountsList,
} from './integration-helpers.js';

describe('secure-input-integration (windows/powershell-sendkeys)', () => {
  it('unlocks via the real CredUI dialog driven by SendKeys', async () => {
    await openFixtureVault();
    await clickUnlockButton();

    // CredUIPromptForCredentialsW spawns a modal credential dialog;
    // wait a beat for it to be the focused window before sending
    // keystrokes. The dialog window title is "Unlock vault"
    // (set in `secure_prompt.rs::vault_unlock_via_secure_prompt`).
    await sleep(1500);

    // Escape characters with special meaning in SendKeys:
    // `+ ^ % ~ ( ) { } [ ]` — wrap each in braces. The fixture
    // password "test-password-123!" contains a `!` which (in
    // SendKeys grammar) is shift-prefix for the NEXT key; wrapping
    // in braces makes it literal.
    const escaped = MASTER_PASSWORD.replace(/[+^%~(){}\[\]!]/g, '{$&}');
    const ps = [
      'Add-Type -AssemblyName System.Windows.Forms',
      `[System.Windows.Forms.SendKeys]::SendWait('${escaped}')`,
      // Small pause so the dialog's accept handler sees the input.
      'Start-Sleep -Milliseconds 200',
      "[System.Windows.Forms.SendKeys]::SendWait('{ENTER}')",
    ].join('; ');
    shell(`powershell -NoProfile -NonInteractive -Command "${ps}"`);

    // L5 success assertion (same as Linux/macOS): React transitions
    // to active and accounts-list appears.
    await waitForAccountsList();
  });
});
