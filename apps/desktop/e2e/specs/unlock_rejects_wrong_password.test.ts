// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Scenario 3: unlock_rejects_wrong_password.
//
// Plan-LOCK: docs/issue-plans/mvp4-f-desktop-e2e.md §0a.
//
// Open the fixture vault, type a WRONG master password, assert
// the error banner renders + no accounts list appears + the
// password input is cleared.

import { expect } from 'chai';

import { openFixtureVault, typeUnlockPassword } from './helpers.js';

describe('unlock_rejects_wrong_password', () => {
  it('renders the error banner + does not render accounts list', async () => {
    await openFixtureVault();
    await typeUnlockPassword('definitely-not-the-correct-password');

    // The error banner renders. Timeout bumped to 30s because the
    // Argon2 KDF on the wrong-password path runs to completion (it
    // doesn't short-circuit until the derived key fails to decrypt
    // the vault header) and CI runners can be 2-3× slower than the
    // WSL reference. Flake observed on CI run 26521343396 (commit
    // c84e747) timed out at exactly 10s; the parallel run 26521342425
    // on the same SHA passed in ~6s. 30s gives 3× headroom over the
    // slowest reproducible local run.
    const banner = await $('[data-testid="unlock-error-banner"]');
    await banner.waitForExist({ timeout: 30_000 });
    expect(await banner.isDisplayed()).to.equal(true);

    // The accounts list does NOT render.
    const list = await $('[data-testid="accounts-list"]');
    expect(await list.isExisting()).to.equal(false);

    // The password input is cleared (the UnlockScreen resets the
    // local state on auth failure per plan §3.3 of MVP-4-B).
    const wrapper = await $('[data-testid="master-password-input"]');
    const input = await wrapper.$('input');
    expect(await input.getValue()).to.equal('');
  });
});
