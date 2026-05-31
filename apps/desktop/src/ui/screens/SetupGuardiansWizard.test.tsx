// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';

import { SetupGuardiansWizard } from './SetupGuardiansWizard';
import {
  guardianIdentityExport,
  guardianInviteDecodeText,
  recoveryOnboardGuardians,
  recoverySetGuardianSet,
} from '../lib/invoke';

// Helper: build a fake GuardianInvite. We make the pubkey deterministic
// from `seed` so the wizard's duplicate-detection logic has stable inputs.
function fakeInvite(seed: string) {
  const pub = seed.padEnd(64, '0').slice(0, 64);
  const sig = seed.padEnd(40, '1').slice(0, 40);
  return {
    x25519SealingPub: pub,
    signer: sig,
    stringForm: `INV-${seed}`,
  };
}

// ME = THIS device's identity (for the self-as-guardian guard). Distinct
// from every fakeInvite seed below so the happy path is unaffected.
const ME = fakeInvite('SELF');

vi.mock('../lib/invoke', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../lib/invoke')>();
  return {
    ...actual,
    guardianIdentityExport: vi.fn(async () => ME),
    guardianInviteDecodeText: vi.fn(async (text: string) => {
      // Echo "INV-XYZ" → fakeInvite('XYZ'); reject everything else as
      // Validation so the wizard's error-toast path is exercised on bad input.
      const m = /^INV-([A-Za-z0-9]+)$/.exec(text);
      if (m === null) {
        const err = { kind: 'Validation', message: 'malformed invite' };
        throw err;
      }
      return fakeInvite(m[1]);
    }),
    recoveryOnboardGuardians: vi.fn(async () => ({ epoch: 0 })),
    recoverySetGuardianSet: vi.fn(async () => ({
      txHash: 'aa'.repeat(32),
      blockNumber: 42,
    })),
  };
});

async function addGuardian(seed: string) {
  fireEvent.change(screen.getByTestId('setup-guardians-paste'), {
    target: { value: `INV-${seed}` },
  });
  fireEvent.click(screen.getByTestId('setup-guardians-add'));
  await waitFor(() => {
    expect(guardianInviteDecodeText).toHaveBeenCalled();
  });
}

async function addThreeAndAdvance() {
  await addGuardian('AAA');
  await addGuardian('BBB');
  await addGuardian('CCC');
  fireEvent.click(screen.getByTestId('setup-guardians-next'));
  await screen.findByTestId('step-threshold');
}

describe('SetupGuardiansWizard (MVP-4-L L-A)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('drives the happy path: collect → threshold → password → onboard + commit', async () => {
    const onSuccess = vi.fn();
    render(
      <SetupGuardiansWizard
        onError={() => {}}
        onClose={() => {}}
        onSuccess={onSuccess}
      />,
    );

    await addThreeAndAdvance();
    fireEvent.click(screen.getByTestId('setup-guardians-threshold-next'));
    await screen.findByTestId('step-password');

    fireEvent.change(screen.getByTestId('setup-guardians-password'), {
      target: { value: 'master-pw' },
    });
    fireEvent.click(screen.getByTestId('setup-guardians-onboard'));

    // Step 1: off-chain onboard fires with the collected pubkeys + threshold.
    await waitFor(() => {
      expect(recoveryOnboardGuardians).toHaveBeenCalledTimes(1);
    });
    expect(recoveryOnboardGuardians).toHaveBeenCalledWith(2, [
      fakeInvite('AAA').x25519SealingPub,
      fakeInvite('BBB').x25519SealingPub,
      fakeInvite('CCC').x25519SealingPub,
    ]);

    // Step 2: on-chain set fires with the matching EVM addresses + threshold.
    await waitFor(() => {
      expect(recoverySetGuardianSet).toHaveBeenCalledTimes(1);
    });
    expect(recoverySetGuardianSet).toHaveBeenCalledWith(
      'master-pw',
      [
        fakeInvite('AAA').signer,
        fakeInvite('BBB').signer,
        fakeInvite('CCC').signer,
      ],
      2,
    );

    // Done step + onSuccess fired for Q-e auto-refresh.
    await screen.findByTestId('step-done');
    expect(onSuccess).toHaveBeenCalledTimes(1);
  });

  it('Q-d: hard-refuses self-as-guardian (the local device identity)', async () => {
    const onError = vi.fn();
    render(
      <SetupGuardiansWizard onError={onError} onClose={() => {}} onSuccess={() => {}} />,
    );

    // Wait for the self-identity export to settle so the guard is armed.
    await waitFor(() => {
      expect(guardianIdentityExport).toHaveBeenCalled();
    });

    // Try to add ME — should be refused without bumping the list.
    fireEvent.change(screen.getByTestId('setup-guardians-paste'), {
      target: { value: 'INV-SELF' },
    });
    fireEvent.click(screen.getByTestId('setup-guardians-add'));
    await waitFor(() => {
      expect(onError).toHaveBeenCalled();
    });
    expect(onError.mock.calls[0][0]).toMatch(/own device/);
    expect(screen.queryByTestId('guardian-0')).not.toBeInTheDocument();
  });

  it('refuses duplicate invites (same sealing pubkey)', async () => {
    const onError = vi.fn();
    render(
      <SetupGuardiansWizard onError={onError} onClose={() => {}} onSuccess={() => {}} />,
    );
    await waitFor(() => {
      expect(guardianIdentityExport).toHaveBeenCalled();
    });
    await addGuardian('AAA');
    expect(screen.getByTestId('guardian-0')).toBeInTheDocument();
    // Second add of the same invite must be refused.
    await addGuardian('AAA');
    expect(onError).toHaveBeenCalled();
    expect(onError.mock.calls.at(-1)?.[0]).toMatch(/already been added/);
    expect(screen.queryByTestId('guardian-1')).not.toBeInTheDocument();
  });

  it('does NOT advance past collect with fewer than MIN_GUARDIANS', async () => {
    render(
      <SetupGuardiansWizard
        onError={() => {}}
        onClose={() => {}}
        onSuccess={() => {}}
      />,
    );
    await waitFor(() => {
      expect(guardianIdentityExport).toHaveBeenCalled();
    });
    await addGuardian('AAA');
    await addGuardian('BBB');
    const next = screen.getByTestId('setup-guardians-next');
    expect(next).toBeDisabled();
  });

  it('Q-c: routes to retry on chain failure + idempotent re-attempt', async () => {
    const onError = vi.fn();
    const onSuccess = vi.fn();
    const setGuardianSet = recoverySetGuardianSet as unknown as ReturnType<typeof vi.fn>;

    // First call FAILS (the on-chain step never lands).
    setGuardianSet.mockRejectedValueOnce({ kind: 'Chain', message: 'RPC down' });

    render(
      <SetupGuardiansWizard onError={onError} onClose={() => {}} onSuccess={onSuccess} />,
    );
    await addThreeAndAdvance();
    fireEvent.click(screen.getByTestId('setup-guardians-threshold-next'));
    await screen.findByTestId('step-password');
    fireEvent.change(screen.getByTestId('setup-guardians-password'), {
      target: { value: 'master-pw' },
    });
    fireEvent.click(screen.getByTestId('setup-guardians-onboard'));

    // Off-chain step fired; on-chain step fired + failed → retry step.
    await screen.findByTestId('step-retry');
    expect(recoveryOnboardGuardians).toHaveBeenCalledTimes(1);
    expect(setGuardianSet).toHaveBeenCalledTimes(1);
    expect(onSuccess).not.toHaveBeenCalled();

    // Second attempt SUCCEEDS — the off-chain step is NOT re-fired.
    fireEvent.change(screen.getByTestId('setup-guardians-retry-password'), {
      target: { value: 'master-pw' },
    });
    fireEvent.click(screen.getByTestId('setup-guardians-retry'));

    await screen.findByTestId('step-done');
    expect(recoveryOnboardGuardians).toHaveBeenCalledTimes(1); // unchanged
    expect(setGuardianSet).toHaveBeenCalledTimes(2);
    expect(onSuccess).toHaveBeenCalledTimes(1);
  });

  it('retry treats "already initialized" chain revert as success', async () => {
    const onSuccess = vi.fn();
    const setGuardianSet = recoverySetGuardianSet as unknown as ReturnType<typeof vi.fn>;
    // Both first attempt + retry fail — but retry hits the
    // ErrGuardianSetAlreadyInitialized revert which the wizard treats as
    // "the on-chain step DID land; we just lost the receipt".
    setGuardianSet.mockRejectedValueOnce({ kind: 'Chain', message: 'RPC down' });
    setGuardianSet.mockRejectedValueOnce({
      kind: 'Chain',
      message: 'ErrGuardianSetAlreadyInitialized',
    });

    render(
      <SetupGuardiansWizard onError={() => {}} onClose={() => {}} onSuccess={onSuccess} />,
    );
    await addThreeAndAdvance();
    fireEvent.click(screen.getByTestId('setup-guardians-threshold-next'));
    await screen.findByTestId('step-password');
    fireEvent.change(screen.getByTestId('setup-guardians-password'), {
      target: { value: 'master-pw' },
    });
    fireEvent.click(screen.getByTestId('setup-guardians-onboard'));
    await screen.findByTestId('step-retry');

    fireEvent.change(screen.getByTestId('setup-guardians-retry-password'), {
      target: { value: 'master-pw' },
    });
    fireEvent.click(screen.getByTestId('setup-guardians-retry'));

    await screen.findByTestId('step-done');
    expect(onSuccess).toHaveBeenCalledTimes(1);
  });
});
