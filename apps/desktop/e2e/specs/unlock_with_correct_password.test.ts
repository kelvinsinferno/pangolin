// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Scenario 2: unlock_with_correct_password.
//
// Plan-LOCK: docs/issue-plans/mvp4-f-desktop-e2e.md §0a.
//
// Open the fixture vault, type the correct master password, assert
// the accounts list renders with the 3 fixture accounts.

import { expect } from 'chai';

import {
  FIXTURE_ACCOUNTS,
  MASTER_PASSWORD,
  openFixtureVault,
  typeUnlockPassword,
} from './helpers.js';

describe('unlock_with_correct_password', () => {
  it('renders the accounts list with the 3 fixture accounts', async () => {
    await openFixtureVault();
    await typeUnlockPassword(MASTER_PASSWORD);

    const list = await $('[data-testid="accounts-list"]');
    await list.waitForExist({ timeout: 15_000 });
    expect(await list.isDisplayed()).to.equal(true);

    // Each fixture account is greppable by display name in the
    // accounts list. The plan's invariant is that the list contains
    // the 3 known accounts (in some order — the CLI add order
    // determines the persisted order but the list query may
    // reorder).
    for (const account of FIXTURE_ACCOUNTS) {
      const row = await $(`*=${account.name}`);
      await row.waitForExist({ timeout: 5_000 });
      expect(await row.isDisplayed()).to.equal(true);
    }

    // Belt-and-braces: the indexed row testids exist for at least
    // the first three account rows (the plan's stable IDs).
    for (let i = 0; i < FIXTURE_ACCOUNTS.length; i += 1) {
      const row = await $(`[data-testid="account-row-${i}"]`);
      expect(await row.isExisting()).to.equal(true);
    }
  });
});
