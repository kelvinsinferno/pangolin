// SPDX-License-Identifier: AGPL-3.0-or-later
//
// MVP-4-H Layer 5 — Linux OS-automation integration spec.
//
// Plan-LOCK: docs/issue-plans/mvp4-h-secure-input.md sec 3 L5.
//
// Validates that the REAL GtkDialog produced by
// `apps/desktop/src/secure_input/linux.rs` opens, accepts a typed
// password via xdotool, and the FFI chain succeeds (the React DOM
// transitions to the accounts-list, proving vault_unlock_via_secure_prompt
// → vault_unlock returned Ok). The Tauri binary under test was built
// WITHOUT the `secure-input-stub` feature so this is the same code
// path the end user runs.

import {
  clickUnlockButton,
  MASTER_PASSWORD,
  openFixtureVault,
  shell,
  sleep,
  waitForAccountsList,
} from './integration-helpers.js';

describe('secure-input-integration (linux/xdotool)', () => {
  it('unlocks via the real GtkDialog driven by xdotool', async () => {
    await openFixtureVault();
    await clickUnlockButton();

    // The Tauri command spawns the GtkDialog on the main thread via
    // `app.run_on_main_thread`. Give the event loop a beat to render
    // it before we send keypresses. The dialog title is "Unlock vault"
    // (set in `secure_prompt.rs::vault_unlock_via_secure_prompt`).
    await sleep(2000);

    // Diagnostic: dump every window xdotool can see, so a future
    // failure surfaces the actual window titles in the CI log instead
    // of a bare "no match" error.
    try {
      const allWindows = shell(
        'xdotool search --name "." 2>/dev/null | head -20 | xargs -I {} sh -c \'echo "wid={} title=$(xdotool getwindowname {} 2>/dev/null)"\'',
      );
      console.log('[xdotool diagnostic] visible windows:\n' + allWindows);
    } catch {
      // Diagnostic-only; don't fail on diag-shell errors.
    }

    // Find the dialog window by title. `search --sync` blocks until at
    // least one window matches (no inherent timeout, but mocha's 240s
    // budget is the outer bound).
    //
    // VERIFIED LOCALLY (xvfb + xdotool 3.20160805) against a Python
    // GTK3 dialog clone of `linux.rs::run_gtk_dialog`. Two earlier
    // approaches failed under xvfb:
    //   (a) `xdotool search ... windowactivate --sync`
    //       → "windowmanager claims not to support _NET_ACTIVE_WINDOW"
    //         (xvfb has no WM, so the activate-and-wait times out)
    //   (b) `xdotool type --window <id>` WITHOUT first setting focus
    //       → events reach the window but the GtkEntry doesn't
    //         consume them (no input focus = widget ignores the key)
    //
    // Working sequence:
    //   1. `windowfocus --sync <id>` — uses `XSetInputFocus`, does
    //      NOT need a WM (passes the xvfb test).
    //   2. `type --window <id>` — delivers keys via XSendEvent
    //      targeted at the focused window's input chain.
    //   3. `key --window <id> Return` — same, triggers the default
    //      OK button.
    //
    // Reproduced the failure + the working fix locally; the working
    // path produces `GTK_RESPONSE=-5` (OK) + the typed text in the
    // GtkEntry buffer.
    const windowId = shell('xdotool search --sync --name "Unlock vault"').trim().split(/\s+/)[0];
    if (!windowId) {
      throw new Error('xdotool search did not return a window id for "Unlock vault"');
    }
    shell(`xdotool windowfocus --sync ${windowId}`);
    shell(`xdotool type --window ${windowId} --delay 30 "${MASTER_PASSWORD}"`);
    shell(`xdotool key --window ${windowId} Return`);

    // L5 success assertion: the React app transitions to active and
    // renders the accounts list. If the GtkDialog didn't actually
    // talk to the FFI (or the FFI rejected the bytes), the wizard
    // would stay on the unlock screen + render the auth-failed
    // inline banner, and waitForAccountsList times out.
    await waitForAccountsList();
  });
});
