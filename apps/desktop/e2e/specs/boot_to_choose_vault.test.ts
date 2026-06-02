// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Scenario 1: boot_to_choose_vault.
//
// Plan-LOCK: docs/issue-plans/mvp4-f-desktop-e2e.md §0a.
// MVP-4-N rewrite (2026-06-02): the welcome screen now has two
// native-dialog-backed action buttons instead of a typed-path text
// input. This scenario verifies the cold-boot welcome surface
// renders + both action buttons are present + enabled.

import { expect } from 'chai';

describe('boot_to_choose_vault', () => {
  it('renders the welcome screen with Create + Open actions on cold boot', async () => {
    const actions = await $('[data-testid="welcome-actions"]');
    await actions.waitForExist({ timeout: 15_000 });
    expect(await actions.isDisplayed()).to.equal(true);

    const createButton = await $('[data-testid="welcome-create-button"]');
    expect(await createButton.isDisplayed()).to.equal(true);
    expect(await createButton.isEnabled()).to.equal(true);

    const openButton = await $('[data-testid="welcome-open-button"]');
    expect(await openButton.isDisplayed()).to.equal(true);
    expect(await openButton.isEnabled()).to.equal(true);
  });
});
