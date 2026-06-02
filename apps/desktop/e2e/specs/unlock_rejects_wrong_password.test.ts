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

    // MVP-4-H L3: there is no longer a password `<input>` to clear —
    // the password is collected by the OS native widget (stubbed in
    // E2E builds) and never enters the React state. The inline
    // error banner above is the only auth-failure UX; the
    // SecurePasswordButton stays interactive so the user can retry.
    // Assert the button is still present (i.e. the wizard didn't
    // route to a different surface on failure).
    const retryButton = await $('[data-testid="unlock-button"]');
    expect(await retryButton.isExisting()).to.equal(true);
  });
});
