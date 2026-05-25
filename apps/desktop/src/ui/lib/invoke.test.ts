// SPDX-License-Identifier: AGPL-3.0-or-later
import { beforeEach, describe, expect, test, vi } from 'vitest';

const invokeMock = vi.fn();
vi.mock('@tauri-apps/api/core', () => ({
  invoke: (cmd: string, args?: unknown) => invokeMock(cmd, args),
}));

import {
  accountShow,
  accountsList,
  copyPasswordToClipboard,
  copyToClipboard,
  isDesktopError,
  revealPassword,
  vaultClose,
  vaultLock,
  vaultOpen,
  vaultUnlock,
} from './invoke';

beforeEach(() => {
  invokeMock.mockReset();
});

describe('typed invoke wrappers', () => {
  test('vaultOpen dispatches the right command name + args', async () => {
    invokeMock.mockResolvedValue(undefined);
    await vaultOpen('/path/to/vault.pvf');
    expect(invokeMock).toHaveBeenCalledTimes(1);
    expect(invokeMock).toHaveBeenCalledWith('vault_open', { path: '/path/to/vault.pvf' });
  });

  test('vaultUnlock passes the password argument', async () => {
    invokeMock.mockResolvedValue(undefined);
    await vaultUnlock('hunter2');
    expect(invokeMock).toHaveBeenCalledWith('vault_unlock', { password: 'hunter2' });
  });

  test('vaultLock dispatches with the right command name', async () => {
    invokeMock.mockResolvedValue(undefined);
    await vaultLock();
    expect(invokeMock).toHaveBeenCalledTimes(1);
    expect(invokeMock.mock.calls[0]![0]).toBe('vault_lock');
  });

  test('vaultClose dispatches with the right command name', async () => {
    invokeMock.mockResolvedValue(undefined);
    await vaultClose();
    expect(invokeMock).toHaveBeenCalledTimes(1);
    expect(invokeMock.mock.calls[0]![0]).toBe('vault_close');
  });

  test('accountsList maps snake_case wire shape to camelCase DTO', async () => {
    invokeMock.mockResolvedValue([
      {
        id: 'aa'.repeat(32),
        display_name: 'Acme',
        tags: ['work'],
        usernames: ['alice@acme'],
        urls: ['https://acme.example'],
        password_history_count: 3,
        has_totp: true,
        current_password_changed_at: 1_700_000_000,
      },
    ]);
    const list = await accountsList();
    expect(list).toEqual([
      {
        id: 'aa'.repeat(32),
        displayName: 'Acme',
        tags: ['work'],
        usernames: ['alice@acme'],
        urls: ['https://acme.example'],
        passwordHistoryCount: 3,
        hasTotp: true,
        currentPasswordChangedAt: 1_700_000_000,
      },
    ]);
  });

  test('accountShow maps single-record wire shape', async () => {
    invokeMock.mockResolvedValue({
      id: 'bb'.repeat(32),
      display_name: 'Bank',
      tags: [],
      usernames: [],
      urls: [],
      password_history_count: 1,
      has_totp: false,
      current_password_changed_at: 0,
    });
    const snap = await accountShow('bb'.repeat(32));
    expect(snap.displayName).toBe('Bank');
    expect(snap.hasTotp).toBe(false);
  });

  test('revealPassword passes id + returns the plaintext string', async () => {
    invokeMock.mockResolvedValue('correct horse battery staple');
    const pw = await revealPassword('cc'.repeat(32));
    expect(invokeMock).toHaveBeenCalledWith('reveal_password', { id: 'cc'.repeat(32) });
    expect(pw).toBe('correct horse battery staple');
  });

  test('copyToClipboard passes the text', async () => {
    invokeMock.mockResolvedValue(undefined);
    await copyToClipboard('hello');
    expect(invokeMock).toHaveBeenCalledWith('copy_to_clipboard', { text: 'hello' });
  });

  test('copyPasswordToClipboard passes only the account id (audit H-1 — no plaintext crosses V8)', async () => {
    invokeMock.mockResolvedValue(undefined);
    await copyPasswordToClipboard('dd'.repeat(32));
    expect(invokeMock).toHaveBeenCalledWith('copy_password_to_clipboard', { id: 'dd'.repeat(32) });
    // Critical: the args carry only the id, NEVER the plaintext.
    const args = invokeMock.mock.calls[0]?.[1] as Record<string, unknown>;
    expect(args).toEqual({ id: 'dd'.repeat(32) });
    expect(Object.keys(args)).not.toContain('text');
    expect(Object.keys(args)).not.toContain('password');
  });

  test('invoke rejection surfaces the DesktopError envelope as a thrown value', async () => {
    invokeMock.mockRejectedValue({ kind: 'AuthenticationFailed' });
    await expect(vaultUnlock('wrong')).rejects.toEqual({ kind: 'AuthenticationFailed' });
  });
});

describe('isDesktopError type guard', () => {
  test('recognises every typed kind', () => {
    const kinds = [
      'Session',
      'Validation',
      'Chain',
      'Store',
      'Recovery',
      'Sync',
      'Crypto',
      'Internal',
      'AuthenticationFailed',
    ];
    for (const kind of kinds) {
      expect(isDesktopError({ kind, message: 'x' })).toBe(true);
    }
  });

  test('rejects non-objects', () => {
    expect(isDesktopError(null)).toBe(false);
    expect(isDesktopError('Session')).toBe(false);
    expect(isDesktopError(42)).toBe(false);
  });

  test('rejects unknown kinds', () => {
    expect(isDesktopError({ kind: 'NopeNotAVariant', message: 'x' })).toBe(false);
  });

  test('rejects shape without kind', () => {
    expect(isDesktopError({ message: 'no kind here' })).toBe(false);
  });
});
