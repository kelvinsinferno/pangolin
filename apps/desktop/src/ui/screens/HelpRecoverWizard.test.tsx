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

  it('audit LOW-1: rejects requests with expiresAt within the 60s safety margin', async () => {
    // A request that expires in 30s would race the broadcast time on the
    // contract's block.timestamp check. Reject loud at ingest so the
    // guardian doesn't burn gas only to hit ErrApprovalExpired.
    const onError = vi.fn();
    const decode = recoveryDecodeRequest as unknown as ReturnType<typeof vi.fn>;
    decode.mockResolvedValueOnce(
      fakeRequest({ expiresAt: Math.floor(Date.now() / 1000) + 30 }),
    );

    render(<HelpRecoverWizard onError={onError} onClose={() => {}} />);
    fireEvent.change(screen.getByTestId('help-recover-paste'), {
      target: { value: 'NEAR-EXPIRY' },
    });
    fireEvent.click(screen.getByTestId('help-recover-ingest'));

    await waitFor(() => {
      expect(onError).toHaveBeenCalled();
    });
    expect(onError.mock.calls[0]?.[0]).toMatch(/too soon|expires in/i);
    expect(screen.queryByTestId('step-preview')).not.toBeInTheDocument();
    expect(recoveryHelpApprove).not.toHaveBeenCalled();
  });

  it('audit LOW-3: preview truncates hex with first AND last segments', async () => {
    // A prefix-only truncation lets an attacker craft a fake target with
    // a colliding prefix; showing both ends raises the bar.
    render(<HelpRecoverWizard onError={() => {}} onClose={() => {}} />);
    await advanceToPreview();

    const vaultPreview = screen.getByTestId('preview-vault-id');
    // Truncated form should match 0x{6 hex}…{6 hex}.
    expect(vaultPreview.textContent).toMatch(/^0x[a-f0-9]{6}…[a-f0-9]{6}$/);
    // The commitment field also.
    const commitPreview = screen.getByTestId('preview-recipient-commitment');
    expect(commitPreview.textContent).toMatch(/^0x[a-f0-9]{6}…[a-f0-9]{6}$/);
  });

  // Audit LOW-4 defense (in-function broadcastGuard re-check in
  // runReleaseOnly) — not directly testable: after the first retry
  // click, React flushes the setStep('releasing') re-render before the
  // second click can find the button, so testing-library can't simulate
  // a true double-click during the in-flight call. The defense remains
  // load-bearing for the case where (in production) two events race
  // through React's event system before the re-render commits. The
  // guard mirrors AddDeviceWizard.publishGuard + SetupGuardiansWizard's
  // broadcastGuard, both of which are well-trodden patterns.
});
