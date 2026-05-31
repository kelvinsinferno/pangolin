// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';

import { HelpRecoverWizard } from './HelpRecoverWizard';
import {
  recoveryDecodeRequest,
  recoveryHelpApprove,
  recoveryHelpRelease,
  type RecoveryRequest,
} from '../lib/invoke';

// Build a fake parsed RecoveryRequest with a future expiresAt so the
// wizard's local pre-check passes. Tests override expiresAt where needed.
function fakeRequest(overrides: Partial<RecoveryRequest> = {}): RecoveryRequest {
  return {
    vaultId: 'aa'.repeat(32),
    attemptNonce: 7,
    proposedAuthority: 'bb'.repeat(20),
    recipientCommitment: 'cc'.repeat(32),
    sealedShare: 'dd'.repeat(40),
    epoch: 'ee'.repeat(16),
    guardianSet: ['aa'.repeat(20), 'bb'.repeat(20), 'cc'.repeat(20)],
    expiresAt: Math.floor(Date.now() / 1000) + 3_600, // 1h from now
    ...overrides,
  };
}

vi.mock('../lib/invoke', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../lib/invoke')>();
  return {
    ...actual,
    recoveryDecodeRequest: vi.fn(async (_text: string) => fakeRequest()),
    recoveryHelpApprove: vi.fn(async () => ({
      txHash: 'aa'.repeat(32),
      blockNumber: 42,
    })),
    recoveryHelpRelease: vi.fn(async () => ({
      sealedShareForRecoverer: 'beef'.repeat(20),
    })),
    recoveryHealth: vi.fn(async () => ({
      authority: '0'.repeat(40),
      recoveryStatus: 0,
      proposedAuthority: '',
      attemptNonce: 0,
    })),
    copyToClipboard: vi.fn(async () => {}),
  };
});

async function advanceToPreview() {
  fireEvent.change(screen.getByTestId('help-recover-paste'), {
    target: { value: 'PASTED-REQUEST-BLOB' },
  });
  fireEvent.click(screen.getByTestId('help-recover-ingest'));
  await screen.findByTestId('step-preview');
}

describe('HelpRecoverWizard (MVP-4-L L-C)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('happy path: ingest → preview → approve → release → done', async () => {
    render(<HelpRecoverWizard onError={() => {}} onClose={() => {}} />);

    await advanceToPreview();
    expect(recoveryDecodeRequest).toHaveBeenCalledWith('PASTED-REQUEST-BLOB');

    fireEvent.click(screen.getByTestId('help-recover-confirm'));

    // Approve fires first with the parsed request fields.
    await waitFor(() => {
      expect(recoveryHelpApprove).toHaveBeenCalledTimes(1);
    });
    expect(recoveryHelpApprove).toHaveBeenCalledWith(
      'aa'.repeat(32), // vaultId
      7, // attemptNonce
      'bb'.repeat(20), // proposedAuthority
      expect.any(Number), // expiresAt
      ['aa'.repeat(20), 'bb'.repeat(20), 'cc'.repeat(20)], // guardianSet
    );

    // Release fires second with the release-specific subset.
    await waitFor(() => {
      expect(recoveryHelpRelease).toHaveBeenCalledTimes(1);
    });
    expect(recoveryHelpRelease).toHaveBeenCalledWith(
      'aa'.repeat(32), // vaultId
      7, // attemptNonce
      'cc'.repeat(32), // recipientCommitment
      'dd'.repeat(40), // sealedShare
      'ee'.repeat(16), // epoch
    );

    // Done step renders the re-sealed share for the guardian to copy.
    await screen.findByTestId('step-done');
    expect(screen.getByTestId('help-recover-output')).toHaveTextContent('beef');
  });

  it('rejects expired requests at the ingest pre-check (no FFI burn)', async () => {
    const onError = vi.fn();
    const decode = recoveryDecodeRequest as unknown as ReturnType<typeof vi.fn>;
    decode.mockResolvedValueOnce(fakeRequest({ expiresAt: 1 })); // 1970 — long expired

    render(<HelpRecoverWizard onError={onError} onClose={() => {}} />);
    fireEvent.change(screen.getByTestId('help-recover-paste'), {
      target: { value: 'EXPIRED' },
    });
    fireEvent.click(screen.getByTestId('help-recover-ingest'));

    await waitFor(() => {
      expect(onError).toHaveBeenCalled();
    });
    expect(onError.mock.calls[0]?.[0]).toMatch(/expired/i);
    // Must not have advanced past ingest; must not have burned approve.
    expect(screen.queryByTestId('step-preview')).not.toBeInTheDocument();
    expect(recoveryHelpApprove).not.toHaveBeenCalled();
  });

  it('decoder validation error surfaces via errMessage unwrap', async () => {
    const onError = vi.fn();
    const decode = recoveryDecodeRequest as unknown as ReturnType<typeof vi.fn>;
    decode.mockRejectedValueOnce({
      kind: 'Validation',
      message: { kind: 'argument', message: 'recovery request: base64 decode failed' },
    });

    render(<HelpRecoverWizard onError={onError} onClose={() => {}} />);
    fireEvent.change(screen.getByTestId('help-recover-paste'), {
      target: { value: 'GARBAGE' },
    });
    fireEvent.click(screen.getByTestId('help-recover-ingest'));

    await waitFor(() => {
      expect(onError).toHaveBeenCalled();
    });
    expect(onError.mock.calls[0]?.[0]).toMatch(/base64 decode failed/);
    expect(onError.mock.calls[0]?.[0]).not.toBe('Validation');
  });

  it('approve failure leaves the user on preview, never fires release', async () => {
    const onError = vi.fn();
    const approve = recoveryHelpApprove as unknown as ReturnType<typeof vi.fn>;
    approve.mockRejectedValueOnce({ kind: 'Chain', message: 'RPC down' });

    render(<HelpRecoverWizard onError={onError} onClose={() => {}} />);
    await advanceToPreview();
    fireEvent.click(screen.getByTestId('help-recover-confirm'));

    await waitFor(() => {
      expect(approve).toHaveBeenCalledTimes(1);
    });
    // Release MUST NOT have been called.
    expect(recoveryHelpRelease).not.toHaveBeenCalled();
    // User is back on preview with the error toasted.
    await screen.findByTestId('step-preview');
    expect(onError).toHaveBeenCalled();
  });

  it('Q-d: release failure routes to retry step + retry re-fires release only', async () => {
    const onError = vi.fn();
    const release = recoveryHelpRelease as unknown as ReturnType<typeof vi.fn>;
    release.mockRejectedValueOnce({ kind: 'Chain', message: 'release failed' });

    render(<HelpRecoverWizard onError={onError} onClose={() => {}} />);
    await advanceToPreview();
    fireEvent.click(screen.getByTestId('help-recover-confirm'));

    // Initial path: approve succeeded, release failed → 'retry' step.
    await screen.findByTestId('step-retry');
    expect(recoveryHelpApprove).toHaveBeenCalledTimes(1);
    expect(release).toHaveBeenCalledTimes(1);

    // Retry: ONLY the release fires; approve is NOT re-called.
    fireEvent.click(screen.getByTestId('help-recover-retry'));

    await screen.findByTestId('step-done');
    expect(recoveryHelpApprove).toHaveBeenCalledTimes(1); // unchanged
    expect(release).toHaveBeenCalledTimes(2);
  });

  it('Cancel from any step closes the wizard', async () => {
    const onClose = vi.fn();
    render(<HelpRecoverWizard onError={() => {}} onClose={onClose} />);
    fireEvent.click(await screen.findByTestId('help-recover-cancel'));
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});
