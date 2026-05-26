// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Scenario 1: boot_to_choose_vault.
//
// Plan-LOCK: docs/issue-plans/mvp4-f-desktop-e2e.md §0a.
//
// App launches; the welcome screen renders the "Choose vault file"
// affordance (`vault-file-picker` wrapper). No vault interaction in
// this scenario — purely the cold-boot smoke test.

import { expect } from 'chai';

describe('boot_to_choose_vault', () => {
  it('renders the choose-vault picker on cold boot', async () => {
    const picker = await $('[data-testid="vault-file-picker"]');
    await picker.waitForExist({ timeout: 15_000 });
    expect(await picker.isDisplayed()).to.equal(true);
  });
});
