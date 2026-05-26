// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, test, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';

import { AccountListScreen } from './AccountListScreen';
import type { AccountSummary } from '../lib/invoke';

const sample: AccountSummary[] = [
  {
    id: 'aa'.repeat(32),
    displayName: 'Acme',
    tags: ['work'],
    usernames: ['alice@acme.example'],
    urls: ['https://acme.example'],
    passwordHistoryCount: 3,
    hasTotp: false,
    currentPasswordChangedAt: 1_700_000_000,
  },
  {
    id: 'bb'.repeat(32),
    displayName: 'Bank',
    tags: [],
    usernames: ['alice@bank.example'],
    urls: ['https://bank.example'],
    passwordHistoryCount: 1,
    hasTotp: true,
    currentPasswordChangedAt: 1_700_000_010,
  },
];

describe('AccountListScreen', () => {
  test('renders one row per account', () => {
    render(
      <AccountListScreen
        accounts={sample}
        onSelect={async () => {}}
        onLock={async () => {}}
      />,
    );
    expect(screen.getByText('Acme')).toBeInTheDocument();
    expect(screen.getByText('Bank')).toBeInTheDocument();
    expect(screen.getByTestId(`account-row-${sample[0]!.id}`)).toBeInTheDocument();
    expect(screen.getByTestId(`account-row-${sample[1]!.id}`)).toBeInTheDocument();
  });

  test('clicking a row fires onSelect with the id', async () => {
    const onSelect = vi.fn(async () => {});
    render(
      <AccountListScreen
        accounts={sample}
        onSelect={onSelect}
        onLock={async () => {}}
      />,
    );
    fireEvent.click(screen.getByTestId(`account-row-${sample[0]!.id}`));
    await waitFor(() => {
      expect(onSelect).toHaveBeenCalledWith(sample[0]!.id);
    });
  });

  test('Lock button fires onLock', async () => {
    const onLock = vi.fn(async () => {});
    render(
      <AccountListScreen
        accounts={sample}
        onSelect={async () => {}}
        onLock={onLock}
      />,
    );
    fireEvent.click(screen.getByTestId('lock-button'));
    await waitFor(() => {
      expect(onLock).toHaveBeenCalledTimes(1);
    });
  });

  test('empty account list shows the empty-state copy', () => {
    render(
      <AccountListScreen
        accounts={[]}
        onSelect={async () => {}}
        onLock={async () => {}}
      />,
    );
    expect(screen.getByText('No accounts in this vault.')).toBeInTheDocument();
  });
});
