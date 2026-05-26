// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Scenario 4: reveal_password_for_account.
//
// Plan-LOCK: docs/issue-plans/mvp4-f-desktop-e2e.md §0a.
//
// Unlock the fixture vault, click into the first account, click
// Reveal, assert the plaintext renders. This is the documented L1
// carve-out from MVP-4-B (the ≤10s reveal window).

import { expect } from 'chai';

import {
  FIXTURE_ACCOUNTS,
  MASTER_PASSWORD,
  openFixtureVault,
  typeUnlockPassword,
} from './helpers.js';

describe('reveal_password_for_account', () => {
  it('renders the plaintext for the first account after Reveal', async () => {
    await openFixtureVault();
    await typeUnlockPassword(MASTER_PASSWORD);

    // Click into the first account row.
    const firstRow = await $('[data-testid="account-row-0"]');
    await firstRow.waitForExist({ timeout: 15_000 });
    await firstRow.click();

    // Click the Reveal button (plan's `reveal-password-button`
    // wrapper carries the stable E2E ID).
    const revealWrapper = await $('[data-testid="reveal-password-button"]');
    await revealWrapper.waitForExist({ timeout: 10_000 });
    const revealButton = await revealWrapper.$('button');
    await revealButton.click();

    // The plaintext appears in the `revealed-password-text` wrapper.
    const revealed = await $('[data-testid="revealed-password-text"]');
    await revealed.waitForExist({ timeout: 10_000 });
    const text = (await revealed.getText()).trim();

    // The plaintext must match ONE of the three fixture passwords
    // (order of account creation determines which row is "first" —
    // CLI add order is GitHub, Gmail, Twitter so row-0 should be
    // GitHub, but the list query may reorder, so we accept any).
    const fixturePasswords = FIXTURE_ACCOUNTS.map((a) => a.password);
    expect(fixturePasswords).to.include(text);
  });
});
