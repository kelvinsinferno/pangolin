// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';

import { RemoveDeviceWizard } from './RemoveDeviceWizard';
import { pairingCompleteRotation, pairingRemoveDevice } from '../lib/invoke';

const TARGET = 'bb'.repeat(20);

vi.mock('../lib/invoke', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../lib/invoke')>();
  return {
    ...actual,
    pairingRemoveDevice: vi.fn(async () => {}),
    pairingCompleteRotation: vi.fn(async () => ({ newEpoch: 1, unknownSurvivors: [] })),
  };
});

describe('RemoveDeviceWizard', () => {
  beforeEach(() => vi.clearAllMocks());

  it('does NOT remove until confirm → password → run', async () => {
    const onRekeyed = vi.fn(async () => {});
    render(
      <RemoveDeviceWizard
        signer={TARGET}
        onError={() => {}}
        onClose={() => {}}
        onRekeyed={onRekeyed}
      />,
    );
    // Confirm step shows the target; nothing fired yet.
    expect(screen.getByTestId('remove-target')).toHaveTextContent(TARGET);
    expect(pairingRemoveDevice).not.toHaveBeenCalled();

    fireEvent.click(screen.getByTestId('remove-confirm'));
    fireEvent.change(await screen.findByTestId('remove-password'), {
      target: { value: 'master-pw' },
    });
    // Still nothing until run.
    expect(pairingRemoveDevice).not.toHaveBeenCalled();

    fireEvent.click(screen.getByTestId('remove-run'));
    await waitFor(() => {
      expect(pairingRemoveDevice).toHaveBeenCalledWith(TARGET);
    });
    // Removal is immediately followed by the re-key, then the unlock.
    await waitFor(() => {
      expect(pairingCompleteRotation).toHaveBeenCalledWith('master-pw');
    });
    await waitFor(() => {
      expect(onRekeyed).toHaveBeenCalledWith('master-pw');
    });
  });

  it('after removal succeeds but the re-key fails, the retry does NOT re-broadcast removal', async () => {
    vi.mocked(pairingRemoveDevice).mockResolvedValue(undefined);
    vi.mocked(pairingCompleteRotation)
      .mockRejectedValueOnce({ kind: 'Chain', message: 'rpc blip' })
      .mockResolvedValueOnce({ newEpoch: 2, unknownSurvivors: [] });
    const onRekeyed = vi.fn(async () => {});
    render(
      <RemoveDeviceWizard
        signer={TARGET}
        onError={() => {}}
        onClose={() => {}}
        onRekeyed={onRekeyed}
      />,
    );
    fireEvent.click(screen.getByTestId('remove-confirm'));
    fireEvent.change(await screen.findByTestId('remove-password'), {
      target: { value: 'pw' },
    });
    fireEvent.click(screen.getByTestId('remove-run'));

    // Removal landed once; the re-key failed → rotation-only retry step.
    expect(await screen.findByTestId('step-rekey-retry')).toBeInTheDocument();
    expect(pairingRemoveDevice).toHaveBeenCalledTimes(1);

    // Retry: this must re-run ONLY the rotation, never re-broadcast removal
    // (which would revert ErrNotAuthorized + leave the gap open).
    fireEvent.click(screen.getByTestId('rekey-retry-run'));
    await waitFor(() => {
      expect(onRekeyed).toHaveBeenCalled();
    });
    expect(pairingRemoveDevice).toHaveBeenCalledTimes(1);
    expect(pairingCompleteRotation).toHaveBeenCalledTimes(2);
  });

  it('cancel fires onClose without removing', () => {
    const onClose = vi.fn();
    render(
      <RemoveDeviceWizard
        signer={TARGET}
        onError={() => {}}
        onClose={onClose}
        onRekeyed={async () => {}}
      />,
    );
    fireEvent.click(screen.getByTestId('remove-cancel'));
    expect(onClose).toHaveBeenCalledTimes(1);
    expect(pairingRemoveDevice).not.toHaveBeenCalled();
  });
});
