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
    await sleep(1500);

    // Focus the dialog by its title, then type the password + Enter.
    // `xdotool search --name` returns the window id; `--sync` blocks
    // until at least one match exists (5s max). The `--delay 30`
    // keypress spacing is generous enough that GTK's IME pipeline
    // doesn't drop keys on slow CI runners.
    shell('xdotool search --sync --name "Unlock vault" windowactivate --sync');
    shell(`xdotool type --delay 30 "${MASTER_PASSWORD}"`);
    shell('xdotool key Return');

    // L5 success assertion: the React app transitions to active and
    // renders the accounts list. If the GtkDialog didn't actually
    // talk to the FFI (or the FFI rejected the bytes), the wizard
    // would stay on the unlock screen + render the auth-failed
    // inline banner, and waitForAccountsList times out.
    await waitForAccountsList();
  });
});
