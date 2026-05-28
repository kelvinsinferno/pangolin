// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';

import { JoinVaultWizard } from './JoinVaultWizard';
import { bytesToBase64 } from '../lib/base64';
import { pairingOpenAndJoin } from '../lib/invoke';

vi.mock('../lib/invoke', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../lib/invoke')>();
  const payload = (bytes: number[]) => ({
    bytes,
    stringForm: 'str',
    vaultId: 'aa'.repeat(32),
    deviceId: 'bb'.repeat(32),
    signer: 'cc'.repeat(20),
  });
  return {
    ...actual,
    pairingBeginNewDevice: vi.fn(async () => payload([5, 5, 5])),
    pairingDecodeBytes: vi.fn(async (b: number[]) => payload(b)),
    pairingDeriveSas: vi.fn(async () => '472913'),
    pairingOpenAndJoin: vi.fn(async () => {}),
    copyToClipboard: vi.fn(async () => {}),
  };
});

async function advanceToSas() {
  // show (generated on mount) → next
  fireEvent.click(await screen.findByTestId('wizard-show-next'));
  // ingest manager payload
  const ingest = await screen.findByTestId('code-ingest-input');
  fireEvent.change(ingest, { target: { value: bytesToBase64([9, 9, 9]) } });
  fireEvent.click(screen.getByTestId('code-ingest-submit'));
}

describe('JoinVaultWizard (B-side SAS gate)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    Object.defineProperty(globalThis.navigator, 'mediaDevices', {
      value: undefined,
      configurable: true,
    });
  });

  it('generates this device payload on mount and shows it', async () => {
    render(
      <JoinVaultWizard onError={() => {}} onClose={() => {}} onJoined={async () => {}} />,
    );
    expect(await screen.findByTestId('step-show')).toBeInTheDocument();
    expect(await screen.findByTestId('code-display-text')).toBeInTheDocument();
  });

  it('does NOT open-and-join until the SAS is confirmed + envelope + password', async () => {
    const onJoined = vi.fn(async () => {});
    render(
      <JoinVaultWizard onError={() => {}} onClose={() => {}} onJoined={onJoined} />,
    );
    await advanceToSas();
    // SAS shown; open-and-join not yet called.
    expect(await screen.findByTestId('wizard-sas')).toHaveTextContent('472913');
    expect(pairingOpenAndJoin).not.toHaveBeenCalled();

    // Confirm SAS → envelope ingest.
    fireEvent.click(screen.getByTestId('wizard-sas-confirm'));
    const envIngest = await screen.findByTestId('code-ingest-input');
    fireEvent.change(envIngest, { target: { value: bytesToBase64([1, 2, 3, 4]) } });
    fireEvent.click(screen.getByTestId('code-ingest-submit'));
    // Still not called — the password step gates it.
    await screen.findByTestId('step-password');
    expect(pairingOpenAndJoin).not.toHaveBeenCalled();

    // Set password → finish.
    fireEvent.change(screen.getByTestId('wizard-new-password'), {
      target: { value: 'fresh-pw' },
    });
    fireEvent.click(screen.getByTestId('wizard-join-finish'));
    await waitFor(() => {
      expect(pairingOpenAndJoin).toHaveBeenCalledTimes(1);
    });
    expect(pairingOpenAndJoin).toHaveBeenCalledWith(
      expect.objectContaining({ vaultId: 'aa'.repeat(32), epoch: 0, newPassword: 'fresh-pw' }),
    );
    await waitFor(() => {
      expect(onJoined).toHaveBeenCalledWith('fresh-pw');
    });
  });

  it('rejecting the SAS cancels without joining', async () => {
    const onClose = vi.fn();
    render(
      <JoinVaultWizard onError={() => {}} onClose={onClose} onJoined={async () => {}} />,
    );
    await advanceToSas();
    fireEvent.click(await screen.findByTestId('wizard-sas-reject'));
    expect(onClose).toHaveBeenCalledTimes(1);
    expect(pairingOpenAndJoin).not.toHaveBeenCalled();
  });
});
