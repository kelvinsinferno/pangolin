// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';

import { AddDeviceWizard } from './AddDeviceWizard';
import { bytesToBase64 } from '../lib/base64';
import {
  pairingAddDevice,
  pairingChainBootstrap,
  pairingDeriveSas,
  pairingLocalPayload,
} from '../lib/invoke';

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
    pairingChainBootstrap: vi.fn(async () => {}),
    pairingDecodeBytes: vi.fn(async (b: number[]) => payload(b)),
    pairingLocalPayload: vi.fn(async () => payload([1, 2, 3])),
    pairingDeriveSas: vi.fn(async () => '472913'),
    pairingAddDevice: vi.fn(async () => ({ bytes: [7, 7, 7], stringForm: 'env' })),
    copyToClipboard: vi.fn(async () => {}),
  };
});

async function advanceToSas() {
  // password
  fireEvent.change(screen.getByTestId('wizard-password'), {
    target: { value: 'master-pw' },
  });
  fireEvent.click(screen.getByTestId('wizard-password-next'));
  // bootstrap → skip
  fireEvent.click(await screen.findByTestId('wizard-bootstrap-skip'));
  // ingest B's payload
  const ingest = await screen.findByTestId('code-ingest-input');
  fireEvent.change(ingest, { target: { value: bytesToBase64([9, 9, 9]) } });
  fireEvent.click(screen.getByTestId('code-ingest-submit'));
  // share → next
  fireEvent.click(await screen.findByTestId('wizard-share-next'));
}

describe('AddDeviceWizard (L2 SAS gate)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('does NOT publish addDevice until the human confirms the SAS matches', async () => {
    render(<AddDeviceWizard onError={() => {}} onClose={() => {}} />);
    await advanceToSas();

    // We are on the SAS step; the code is shown, but addDevice MUST NOT
    // have fired yet (the human gate, plan §4 L2).
    expect(await screen.findByTestId('wizard-sas')).toHaveTextContent('472913');
    expect(pairingDeriveSas).toHaveBeenCalled();
    expect(pairingLocalPayload).toHaveBeenCalled();
    expect(pairingAddDevice).not.toHaveBeenCalled();

    // Confirm → addDevice fires, envelope shows.
    fireEvent.click(screen.getByTestId('wizard-sas-confirm'));
    await waitFor(() => {
      expect(pairingAddDevice).toHaveBeenCalledTimes(1);
    });
    expect(await screen.findByTestId('step-envelope')).toBeInTheDocument();
  });

  it('rejecting the SAS cancels without publishing', async () => {
    const onClose = vi.fn();
    render(<AddDeviceWizard onError={() => {}} onClose={onClose} />);
    await advanceToSas();
    fireEvent.click(await screen.findByTestId('wizard-sas-reject'));
    expect(onClose).toHaveBeenCalledTimes(1);
    expect(pairingAddDevice).not.toHaveBeenCalled();
  });

  it('skipping bootstrap does not call the bootstrap command', async () => {
    render(<AddDeviceWizard onError={() => {}} onClose={() => {}} />);
    fireEvent.change(screen.getByTestId('wizard-password'), {
      target: { value: 'master-pw' },
    });
    fireEvent.click(screen.getByTestId('wizard-password-next'));
    fireEvent.click(await screen.findByTestId('wizard-bootstrap-skip'));
    await screen.findByTestId('step-ingest');
    expect(pairingChainBootstrap).not.toHaveBeenCalled();
  });
});
