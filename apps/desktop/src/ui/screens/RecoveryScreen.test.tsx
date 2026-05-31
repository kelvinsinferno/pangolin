// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';

import { RecoveryScreen } from './RecoveryScreen';
import { recoveryCreateBackup, recoveryHealth } from '../lib/invoke';

vi.mock('../lib/invoke', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../lib/invoke')>();
  return {
    ...actual,
    recoveryHealth: vi.fn(async () => ({
      authority: 'aa'.repeat(20),
      recoveryStatus: 0,
      proposedAuthority: '',
      attemptNonce: 0,
    })),
    recoveryCreateBackup: vi.fn(async () => ({
      seedPhraseWords: Array.from({ length: 24 }, (_, i) => `word${i + 1}`),
      bytes: [1, 2, 3],
      text: 'envelope-text',
    })),
    copyToClipboard: vi.fn(async () => {}),
  };
});

const noop = { onClose: () => {}, onError: () => {} };

describe('RecoveryScreen (L-D)', () => {
  beforeEach(() => vi.clearAllMocks());

  it('shows the recovery-health panel when the read succeeds', async () => {
    render(<RecoveryScreen {...noop} />);
    expect(await screen.findByTestId('recovery-health')).toBeInTheDocument();
  });

  it('shows the not-set-up note when the health read fails', async () => {
    vi.mocked(recoveryHealth).mockRejectedValue({ kind: 'Chain', message: 'not set up' });
    render(<RecoveryScreen {...noop} />);
    expect(await screen.findByTestId('recovery-health-unavailable')).toBeInTheDocument();
  });

  it('does NOT create a backup until password + create are supplied', async () => {
    render(<RecoveryScreen {...noop} />);
    fireEvent.click(await screen.findByTestId('backup-start'));
    expect(recoveryCreateBackup).not.toHaveBeenCalled();
    fireEvent.change(screen.getByTestId('backup-password-input'), {
      target: { value: 'master-pw' },
    });
    fireEvent.click(screen.getByTestId('backup-create'));
    await waitFor(() => {
      expect(recoveryCreateBackup).toHaveBeenCalledWith('master-pw');
    });
  });

  it('shows the 24-word phrase after creating a backup', async () => {
    render(<RecoveryScreen {...noop} />);
    fireEvent.click(await screen.findByTestId('backup-start'));
    fireEvent.change(screen.getByTestId('backup-password-input'), {
      target: { value: 'pw' },
    });
    fireEvent.click(screen.getByTestId('backup-create'));
    expect(await screen.findByTestId('backup-show')).toBeInTheDocument();
    expect(screen.getByText('word1')).toBeInTheDocument();
    expect(screen.getByText('word24')).toBeInTheDocument();
  });

  it('Back fires onClose', async () => {
    const onClose = vi.fn();
    render(<RecoveryScreen onClose={onClose} onError={() => {}} />);
    fireEvent.click(await screen.findByTestId('recovery-back'));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  // ---- L-A: Set up guardians card (visible only when authority is unset) ----

  it('L-A: shows the Set up guardians card when on-chain authority is zero', async () => {
    vi.mocked(recoveryHealth).mockResolvedValue({
      authority: '0'.repeat(40),
      recoveryStatus: 0,
      proposedAuthority: '',
      attemptNonce: 0,
    });
    render(<RecoveryScreen {...noop} />);
    expect(await screen.findByTestId('setup-guardians-open')).toBeInTheDocument();
  });

  it('L-C: shows the Help someone recover card unconditionally', async () => {
    // Card visibility is independent of authority state — any guardian
    // can be asked to help at any time.
    render(<RecoveryScreen {...noop} />);
    expect(await screen.findByTestId('help-recover-open')).toBeInTheDocument();
  });

  it('L-A: hides the Set up guardians card once authority is set', async () => {
    // vi.clearAllMocks() clears call history but NOT mock implementations
    // set via mockResolvedValue in prior tests — re-pin the default here
    // so this test is order-independent.
    vi.mocked(recoveryHealth).mockResolvedValue({
      authority: 'aa'.repeat(20),
      recoveryStatus: 0,
      proposedAuthority: '',
      attemptNonce: 0,
    });
    render(<RecoveryScreen {...noop} />);
    await screen.findByTestId('recovery-health');
    expect(screen.queryByTestId('setup-guardians-open')).not.toBeInTheDocument();
  });
});
