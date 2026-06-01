// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';

import { RemoveDeviceWizard } from './RemoveDeviceWizard';
import {
  pairingCompleteRotationViaSecurePrompt,
  pairingRemoveDevice,
} from '../lib/invoke';

const TARGET = 'bb'.repeat(20);

vi.mock('../lib/invoke', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../lib/invoke')>();
  return {
    ...actual,
    // MVP-4-H L3: the wizard now calls
    // `pairingCompleteRotationViaSecurePrompt` instead of
    // `pairingCompleteRotation`. The legacy variant is intentionally
    // omitted from the mock so any regression that re-introduces it
    // would trip a hard mock-miss.
    pairingRemoveDevice: vi.fn(async () => {}),
    pairingCompleteRotationViaSecurePrompt: vi.fn(async () => ({
      newEpoch: 1,
      unknownSurvivors: [],
    })),
  };
});

describe('RemoveDeviceWizard (MVP-4-H L3 secure-prompt)', () => {
  beforeEach(() => vi.clearAllMocks());

  it('does NOT remove until confirm → secure-prompt click', async () => {
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
    // Now on the 'run' step — still nothing fired (the secure-prompt
    // is the only trigger). NB: no password input exists anymore.
    expect(await screen.findByTestId('step-run')).toBeInTheDocument();
    expect(screen.queryByTestId('remove-password')).not.toBeInTheDocument();
    expect(pairingRemoveDevice).not.toHaveBeenCalled();

    fireEvent.click(screen.getByTestId('remove-run'));
    await waitFor(() => {
      expect(pairingRemoveDevice).toHaveBeenCalledWith(TARGET);
    });
    await waitFor(() => {
      expect(pairingCompleteRotationViaSecurePrompt).toHaveBeenCalledTimes(1);
    });
    await waitFor(() => {
      expect(onRekeyed).toHaveBeenCalledTimes(1);
    });
    // onRekeyed no longer takes a password arg.
    expect(onRekeyed).toHaveBeenCalledWith();
  });

  it('after removal succeeds but the re-key fails, the retry does NOT re-broadcast removal', async () => {
    vi.mocked(pairingRemoveDevice).mockResolvedValue(undefined);
    vi.mocked(pairingCompleteRotationViaSecurePrompt)
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
    fireEvent.click(await screen.findByTestId('remove-run'));

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
    expect(pairingCompleteRotationViaSecurePrompt).toHaveBeenCalledTimes(2);
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
