// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, describe, expect, test, vi } from 'vitest';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';

import { AccountDetailScreen } from './AccountDetailScreen';
import type { AccountSummary } from '../lib/invoke';

const sample: AccountSummary = {
  id: 'aa'.repeat(32),
  displayName: 'Acme',
  tags: ['work'],
  usernames: ['alice@acme.example'],
  urls: ['https://acme.example'],
  passwordHistoryCount: 3,
  hasTotp: false,
  currentPasswordChangedAt: 1_700_000_000,
};

describe('AccountDetailScreen', () => {
  afterEach(() => {
    // Restore real timers if a test enabled fake ones.
    vi.useRealTimers();
  });

  test('shows masked password by default', () => {
    render(
      <AccountDetailScreen
        account={sample}
        onBack={() => {}}
        onReveal={async () => ({ ok: true, password: 'pw' })}
        onCopy={async () => ({ ok: true })}
      />,
    );
    expect(screen.getByText('••••••••')).toBeInTheDocument();
    expect(screen.queryByTestId('revealed-password')).not.toBeInTheDocument();
  });

  test('clicking Reveal renders the plaintext password', async () => {
    render(
      <AccountDetailScreen
        account={sample}
        onBack={() => {}}
        onReveal={async () => ({ ok: true, password: 'correct horse' })}
        onCopy={async () => ({ ok: true })}
      />,
    );
    fireEvent.click(screen.getByTestId('reveal-button'));
    const revealed = await screen.findByTestId('revealed-password');
    expect(revealed).toHaveTextContent('correct horse');
  });

  test('revealed password auto-clears after the 10s memory-hygiene timer', async () => {
    // Approach: real timers throughout; await the reveal, then race a real
    // 10.5s wait against the cleanup. To keep the test fast we drive the
    // setTimeout via vi.useFakeTimers from BEFORE render so the
    // `useEffect`-scheduled timer is also fake.
    vi.useFakeTimers({ shouldAdvanceTime: true });
    render(
      <AccountDetailScreen
        account={sample}
        onBack={() => {}}
        onReveal={async () => ({ ok: true, password: 'correct horse' })}
        onCopy={async () => ({ ok: true })}
      />,
    );
    await act(async () => {
      fireEvent.click(screen.getByTestId('reveal-button'));
    });
    // Drain any pending microtasks so the post-await setState runs.
    await act(async () => {
      await Promise.resolve();
    });
    expect(screen.getByTestId('revealed-password')).toBeInTheDocument();
    // Advance the 10s memory-hygiene timer; useEffect cleanup clears state.
    await act(async () => {
      vi.advanceTimersByTime(10_000);
    });
    expect(screen.queryByTestId('revealed-password')).not.toBeInTheDocument();
    expect(screen.getByText('••••••••')).toBeInTheDocument();
  });

  test('Back fires onBack', () => {
    const onBack = vi.fn();
    render(
      <AccountDetailScreen
        account={sample}
        onBack={onBack}
        onReveal={async () => ({ ok: true, password: 'pw' })}
        onCopy={async () => ({ ok: true })}
      />,
    );
    fireEvent.click(screen.getByTestId('back-button'));
    expect(onBack).toHaveBeenCalledTimes(1);
  });

  test('Copy invokes onCopy with the revealed text', async () => {
    const onCopy = vi.fn(async () => ({ ok: true as const }));
    render(
      <AccountDetailScreen
        account={sample}
        onBack={() => {}}
        onReveal={async () => ({ ok: true, password: 'sekret' })}
        onCopy={onCopy}
      />,
    );
    // First reveal, then copy uses the cached plaintext.
    fireEvent.click(screen.getByTestId('reveal-button'));
    await screen.findByTestId('revealed-password');
    fireEvent.click(screen.getByTestId('copy-button'));
    await waitFor(() => {
      expect(onCopy).toHaveBeenCalledWith('sekret');
    });
  });

  test('Copy without prior reveal re-issues the reveal and copies', async () => {
    const onReveal = vi.fn(async () => ({ ok: true as const, password: 'fresh' }));
    const onCopy = vi.fn(async () => ({ ok: true as const }));
    render(
      <AccountDetailScreen
        account={sample}
        onBack={() => {}}
        onReveal={onReveal}
        onCopy={onCopy}
      />,
    );
    fireEvent.click(screen.getByTestId('copy-button'));
    await waitFor(() => {
      expect(onReveal).toHaveBeenCalledTimes(1);
      expect(onCopy).toHaveBeenCalledWith('fresh');
    });
  });
});
