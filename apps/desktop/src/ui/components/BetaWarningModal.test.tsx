// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';

import { BetaWarningModal } from './BetaWarningModal';
import { betaWarningDismiss, betaWarningState } from '../lib/invoke';

vi.mock('../lib/invoke', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../lib/invoke')>();
  return {
    ...actual,
    betaWarningState: vi.fn(async () => ({
      shouldShow: true,
      currentVersion: '0.1.0-beta.1',
    })),
    betaWarningDismiss: vi.fn(async () => {}),
  };
});

describe('BetaWarningModal (MVP-4-M L4)', () => {
  beforeEach(() => {
    // `vi.clearAllMocks()` clears call history but does NOT reset
    // mock implementations set via mockResolvedValue / mockRejectedValue
    // in prior tests. Re-pin the defaults here so tests are
    // order-independent (same pattern as RecoveryScreen.test.tsx).
    vi.clearAllMocks();
    vi.mocked(betaWarningState).mockResolvedValue({
      shouldShow: true,
      currentVersion: '0.1.0-beta.1',
    });
    vi.mocked(betaWarningDismiss).mockResolvedValue(undefined);
  });

  it('renders the modal when state.shouldShow is true', async () => {
    render(<BetaWarningModal />);
    expect(await screen.findByTestId('beta-warning-modal')).toBeInTheDocument();
    expect(screen.getByText(/closed beta on the Base Sepolia testnet/i)).toBeInTheDocument();
  });

  it('shows the current binary version in the body', async () => {
    render(<BetaWarningModal />);
    const version = await screen.findByTestId('beta-modal-version');
    expect(version).toHaveTextContent('0.1.0-beta.1');
  });

  it('does NOT render the modal when state.shouldShow is false', async () => {
    vi.mocked(betaWarningState).mockResolvedValue({
      shouldShow: false,
      currentVersion: '0.1.0-beta.1',
    });
    render(<BetaWarningModal />);
    // Wait one tick for the effect to settle, then assert absence.
    await waitFor(() => {
      expect(betaWarningState).toHaveBeenCalledTimes(1);
    });
    expect(screen.queryByTestId('beta-warning-modal')).not.toBeInTheDocument();
  });

  it('stays hidden if the state read errors (safer than phantom modal)', async () => {
    vi.mocked(betaWarningState).mockRejectedValue(new Error('command not registered'));
    render(<BetaWarningModal />);
    await waitFor(() => {
      expect(betaWarningState).toHaveBeenCalled();
    });
    expect(screen.queryByTestId('beta-warning-modal')).not.toBeInTheDocument();
  });

  it('calls betaWarningDismiss + closes when the user clicks I understand', async () => {
    render(<BetaWarningModal />);
    const btn = await screen.findByTestId('beta-modal-acknowledge');
    fireEvent.click(btn);
    await waitFor(() => {
      expect(betaWarningDismiss).toHaveBeenCalledTimes(1);
    });
    expect(screen.queryByTestId('beta-warning-modal')).not.toBeInTheDocument();
  });

  it('surfaces dismiss errors via onError + still closes the modal', async () => {
    vi.mocked(betaWarningDismiss).mockRejectedValue(new Error('disk full'));
    const onError = vi.fn();
    render(<BetaWarningModal onError={onError} />);
    const btn = await screen.findByTestId('beta-modal-acknowledge');
    fireEvent.click(btn);
    await waitFor(() => {
      expect(onError).toHaveBeenCalledWith('disk full');
    });
    expect(screen.queryByTestId('beta-warning-modal')).not.toBeInTheDocument();
  });
});
