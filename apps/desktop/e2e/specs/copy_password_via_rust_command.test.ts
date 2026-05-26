// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Scenario 5: copy_password_via_rust_command.
//
// Plan-LOCK: docs/issue-plans/mvp4-f-desktop-e2e.md §0a + §3.2.
//
// Unlock the fixture vault, click into the first account, click
// the Copy button, assert the Rust-side `copy_password_to_clipboard`
// command was invoked via the test-hooks invocation log
// (`__test__commands_invoked`).
//
// This is the H-1 invariant assertion: scenario 5 PROVES that the
// copy flow took the Rust-side path (plaintext stayed in Rust the
// whole time) instead of the previous JS-round-trip path. The OS
// clipboard contents are NOT asserted because xvfb-run's clipboard
// sandboxing is unreliable across distros (per plan §0a).

import { expect } from 'chai';

import { MASTER_PASSWORD, openFixtureVault, typeUnlockPassword } from './helpers.js';

describe('copy_password_via_rust_command', () => {
  it('the Rust copy_password_to_clipboard command fires when Copy is clicked', async () => {
    await openFixtureVault();
    await typeUnlockPassword(MASTER_PASSWORD);

    // Click into the first account row.
    const firstRow = await $('[data-testid="account-row-0"]');
    await firstRow.waitForExist({ timeout: 15_000 });
    await firstRow.click();

    // Wait for the account-detail screen to render before clearing
    // the invocation log; the navigation itself may fire other
    // commands (e.g. account_show) that we don't care about here.
    const copyWrapper = await $('[data-testid="copy-password-button"]');
    await copyWrapper.waitForExist({ timeout: 10_000 });

    // Clear the invocation log so we have a fresh window of activity
    // to assert on. `executeAsync` invokes the Tauri command from
    // the renderer; the second arg is the `done` callback (WDIO's
    // shape).
    await browser.executeAsync((done: () => void) => {
      // The Tauri global is injected by `@tauri-apps/api/core`. The
      // renderer's invoke() routes to the Rust `__test__*` command.
      type WindowWithTauri = Window & {
        __TAURI__?: { core?: { invoke: (cmd: string) => Promise<unknown> } };
      };
      const win = window as WindowWithTauri;
      const invoke = win.__TAURI__?.core?.invoke;
      if (!invoke) {
        done();
        return;
      }
      void invoke('__test__clear_invocations').then(() => done());
    });

    // Click the Copy button.
    const copyButton = await copyWrapper.$('button');
    await copyButton.click();

    // Read the invocation log — `copy_password_to_clipboard` MUST
    // appear; `reveal_password` MUST NOT (the H-1 invariant: the
    // copy path does not first reveal-then-copy).
    const log = await browser.executeAsync<string[], []>(
      (done: (value: string[]) => void) => {
        type WindowWithTauri = Window & {
          __TAURI__?: {
            core?: { invoke: (cmd: string) => Promise<unknown> };
          };
        };
        const win = window as WindowWithTauri;
        const invoke = win.__TAURI__?.core?.invoke;
        if (!invoke) {
          done([]);
          return;
        }
        void invoke('__test__commands_invoked').then((result) => {
          done(Array.isArray(result) ? (result as string[]) : []);
        });
      },
    );

    expect(log).to.include('copy_password_to_clipboard');
    expect(log).to.not.include('reveal_password');
  });
});
