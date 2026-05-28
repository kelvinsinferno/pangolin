// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';

import { DevicesScreen } from './DevicesScreen';

vi.mock('../lib/invoke', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../lib/invoke')>();
  return {
    ...actual,
    pairingDeviceList: vi.fn(async () => [
      {
        id: 'aa'.repeat(32),
        label: 'Laptop',
        isCurrent: true,
        registeredAt: 1_700_000_000,
        evmAddress: '11'.repeat(20),
      },
    ]),
    pairingBeginNewDevice: vi.fn(async () => ({
      bytes: [1, 2, 3],
      stringForm: 's',
      vaultId: 'aa'.repeat(32),
      deviceId: 'bb'.repeat(32),
      signer: 'cc'.repeat(20),
    })),
  };
});

describe('DevicesScreen', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('shows the testnet banner + the paired device list', async () => {
    render(<DevicesScreen onClose={() => {}} onError={() => {}} onJoined={async () => {}} />);
    expect(screen.getByTestId('devices-testnet-banner')).toBeInTheDocument();
    expect(await screen.findByText('Laptop')).toBeInTheDocument();
    expect(screen.getByText('This device')).toBeInTheDocument();
  });

  it('Back fires onClose', () => {
    const onClose = vi.fn();
    render(<DevicesScreen onClose={onClose} onError={() => {}} onJoined={async () => {}} />);
    fireEvent.click(screen.getByTestId('devices-back'));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('launches the Add-a-device wizard', async () => {
    render(<DevicesScreen onClose={() => {}} onError={() => {}} onJoined={async () => {}} />);
    fireEvent.click(await screen.findByTestId('devices-add'));
    expect(await screen.findByTestId('step-password')).toBeInTheDocument();
  });

  it('launches the Join-a-vault wizard', async () => {
    render(<DevicesScreen onClose={() => {}} onError={() => {}} onJoined={async () => {}} />);
    fireEvent.click(await screen.findByTestId('devices-join'));
    // The join wizard generates this device's payload on mount, then shows it.
    expect(await screen.findByTestId('step-show')).toBeInTheDocument();
  });
});
