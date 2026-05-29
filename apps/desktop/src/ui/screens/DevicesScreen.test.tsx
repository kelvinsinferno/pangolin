// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';

import { DevicesScreen } from './DevicesScreen';
import {
  pairingCancelPromotion,
  pairingFinalizePromotion,
  pairingListAuthorizedDevices,
  pairingPendingPromotion,
  pairingPendingRotations,
  pairingProposePromotion,
  type AuthorizedDevice,
} from '../lib/invoke';

const THIS_MANAGER = 'aa'.repeat(20);
const PEER = 'bb'.repeat(20);

vi.mock('../lib/invoke', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../lib/invoke')>();
  return {
    ...actual,
    pairingPendingRotations: vi.fn(async () => []),
    pairingListAuthorizedDevices: vi.fn(async () => []),
    pairingDeviceList: vi.fn(async () => []),
    pairingPendingPromotion: vi.fn(async () => null),
    pairingProposePromotion: vi.fn(async () => ({ candidate: PEER, readyAt: 9_999_999_999 })),
    pairingFinalizePromotion: vi.fn(async () => {}),
    pairingCancelPromotion: vi.fn(async () => {}),
    pairingBeginNewDevice: vi.fn(async () => ({
      bytes: [1],
      stringForm: 's',
      vaultId: 'cc'.repeat(32),
      deviceId: 'dd'.repeat(32),
      signer: 'ee'.repeat(20),
    })),
  };
});

const noop = {
  onClose: () => {},
  onError: () => {},
  onJoined: async () => {},
  onRekeyed: async () => {},
};

function setAuthorized(list: AuthorizedDevice[]) {
  vi.mocked(pairingListAuthorizedDevices).mockResolvedValue(list);
}

describe('DevicesScreen (MVP-4-J)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(pairingPendingRotations).mockResolvedValue([]);
    vi.mocked(pairingPendingPromotion).mockResolvedValue(null);
    setAuthorized([]);
  });

  it('shows a Remove action on peers when THIS device is the manager', async () => {
    setAuthorized([
      { signer: THIS_MANAGER, isCurrent: true, isManager: true, deviceId: '' },
      { signer: PEER, isCurrent: false, isManager: false, deviceId: '' },
    ]);
    render(<DevicesScreen {...noop} />);
    expect(await screen.findByTestId(`remove-${PEER}`)).toBeInTheDocument();
  });

  it('hides Remove when THIS device is NOT the manager', async () => {
    setAuthorized([
      { signer: THIS_MANAGER, isCurrent: false, isManager: true, deviceId: '' },
      { signer: PEER, isCurrent: true, isManager: false, deviceId: '' },
    ]);
    render(<DevicesScreen {...noop} />);
    await screen.findByTestId('authorized-list');
    expect(screen.queryByTestId(`remove-${THIS_MANAGER}`)).not.toBeInTheDocument();
  });

  it('clicking Remove opens the remove wizard at the confirm step', async () => {
    setAuthorized([
      { signer: THIS_MANAGER, isCurrent: true, isManager: true, deviceId: '' },
      { signer: PEER, isCurrent: false, isManager: false, deviceId: '' },
    ]);
    render(<DevicesScreen {...noop} />);
    fireEvent.click(await screen.findByTestId(`remove-${PEER}`));
    expect(await screen.findByTestId('step-confirm')).toBeInTheDocument();
    expect(screen.getByTestId('remove-target')).toHaveTextContent(PEER);
  });

  it('surfaces a pending-rotation banner + opens the re-key form', async () => {
    vi.mocked(pairingPendingRotations).mockResolvedValue([
      { removedSigner: PEER, observedEpoch: 1 },
    ]);
    render(<DevicesScreen {...noop} />);
    expect(await screen.findByTestId('rotation-pending-banner')).toBeInTheDocument();
    fireEvent.click(screen.getByTestId('rotation-complete'));
    expect(await screen.findByTestId('rekey-form')).toBeInTheDocument();
  });

  it('falls back to the local device list when the on-chain read fails', async () => {
    vi.mocked(pairingListAuthorizedDevices).mockRejectedValue({
      kind: 'Chain',
      message: 'not bootstrapped',
    });
    render(<DevicesScreen {...noop} />);
    expect(await screen.findByTestId('auth-fallback-note')).toBeInTheDocument();
    // The fallback has no authoritative set → it must offer NO removal.
    expect(screen.queryByTestId(`remove-${PEER}`)).not.toBeInTheDocument();
  });

  it('Back fires onClose', async () => {
    const onClose = vi.fn();
    render(<DevicesScreen {...noop} onClose={onClose} />);
    fireEvent.click(await screen.findByTestId('devices-back'));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('launches the Add + Join wizards', async () => {
    render(<DevicesScreen {...noop} />);
    fireEvent.click(await screen.findByTestId('devices-add'));
    expect(await screen.findByTestId('step-password')).toBeInTheDocument();
  });

  // ---- MVP-4-K: promotion ----

  const CAND = 'cc'.repeat(20);

  it('offers "Become manager" on a non-manager device + proposes', async () => {
    setAuthorized([
      { signer: CAND, isCurrent: true, isManager: false, deviceId: '' },
      { signer: THIS_MANAGER, isCurrent: false, isManager: true, deviceId: '' },
    ]);
    render(<DevicesScreen {...noop} />);
    fireEvent.click(await screen.findByTestId('promotion-propose'));
    await waitFor(() => {
      expect(pairingProposePromotion).toHaveBeenCalled();
    });
  });

  it('does NOT offer "Become manager" when this device is already the manager', async () => {
    setAuthorized([
      { signer: THIS_MANAGER, isCurrent: true, isManager: true, deviceId: '' },
      { signer: CAND, isCurrent: false, isManager: false, deviceId: '' },
    ]);
    render(<DevicesScreen {...noop} />);
    await screen.findByTestId('authorized-list');
    expect(screen.queryByTestId('promotion-propose')).not.toBeInTheDocument();
  });

  it('shows the manager a veto for a pending promotion', async () => {
    setAuthorized([
      { signer: THIS_MANAGER, isCurrent: true, isManager: true, deviceId: '' },
      { signer: PEER, isCurrent: false, isManager: false, deviceId: '' },
    ]);
    vi.mocked(pairingPendingPromotion).mockResolvedValue({ candidate: PEER, readyAt: 9_999_999_999 });
    render(<DevicesScreen {...noop} />);
    fireEvent.click(await screen.findByTestId('promotion-veto'));
    await waitFor(() => {
      expect(pairingCancelPromotion).toHaveBeenCalled();
    });
  });

  it('lets the candidate finalize once the delay has elapsed', async () => {
    setAuthorized([
      { signer: CAND, isCurrent: true, isManager: false, deviceId: '' },
      { signer: THIS_MANAGER, isCurrent: false, isManager: true, deviceId: '' },
    ]);
    vi.mocked(pairingPendingPromotion).mockResolvedValue({ candidate: CAND, readyAt: 1000 });
    render(<DevicesScreen {...noop} />);
    const finalize = await screen.findByTestId('promotion-finalize');
    expect(finalize).not.toBeDisabled();
    fireEvent.click(finalize);
    await waitFor(() => {
      expect(pairingFinalizePromotion).toHaveBeenCalled();
    });
  });

  it('disables finalize before the delay has elapsed', async () => {
    setAuthorized([
      { signer: CAND, isCurrent: true, isManager: false, deviceId: '' },
      { signer: THIS_MANAGER, isCurrent: false, isManager: true, deviceId: '' },
    ]);
    vi.mocked(pairingPendingPromotion).mockResolvedValue({ candidate: CAND, readyAt: 9_999_999_999 });
    render(<DevicesScreen {...noop} />);
    expect(await screen.findByTestId('promotion-finalize')).toBeDisabled();
    expect(pairingFinalizePromotion).not.toHaveBeenCalled();
  });
});
