// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';

import { RecoverVaultWizard } from './RecoverVaultWizard';
import {
  recoveryDecodeBackup,
  recoveryInitiateViaSecurePrompt,
  recoveryIngestShare,
  recoveryCompleteViaSecurePrompt,
  recoveryRecipientIdentity,
  recoveryTargetStatus,
  type BackupContents,
  type RecoveryTargetStatus,
} from '../lib/invoke';

function fakeBackup(overrides: Partial<BackupContents> = {}): BackupContents {
  return {
    vaultId: 'aa'.repeat(32),
    epoch: 5,
    threshold: 2,
    guardianCount: 3,
    guardianX25519Pubs: ['11'.repeat(32), '22'.repeat(32), '33'.repeat(32)],
    sealedShares: ['aaaa'.repeat(40), 'bbbb'.repeat(40), 'cccc'.repeat(40)],
    guardianEvmAddrs: ['11'.repeat(20), '22'.repeat(20), '33'.repeat(20)],
    vaultDisplayName: 'my vault',
    createdAtUnix: 1_700_000_000,
    ...overrides,
  };
}

function fakeStatus(overrides: Partial<RecoveryTargetStatus> = {}): RecoveryTargetStatus {
  return {
    status: 0,
    proposedAuthority: '',
    attemptNonce: 0,
    initiatedAt: 0,
    approvalCount: 0,
    ...overrides,
  };
}

const VALID_PHRASE_24 = Array.from({ length: 24 }, (_, i) => `word${i + 1}`).join(' ');

vi.mock('../lib/invoke', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../lib/invoke')>();
  return {
    ...actual,
    guardianIdentityExport: vi.fn(async () => ({
      x25519SealingPub: '99'.repeat(32),
      signer: 'ab'.repeat(20),
      stringForm: 'pangolin-guardian-invite-v1-...',
    })),
    recoveryDecodeBackup: vi.fn(async () => fakeBackup()),
    recoveryRecipientIdentity: vi.fn(async () => {
      throw new Error('no persisted identity (fresh recovery)');
    }),
    recoveryTargetStatus: vi.fn(async () => fakeStatus()),
    // MVP-4-H L3: the wizard now calls the *_via_secure_prompt
    // variants. The legacy `recoveryInitiate` + `recoveryComplete`
    // are intentionally omitted from the mock so any regression that
    // re-introduces them would trip a hard mock-miss.
    recoveryInitiateViaSecurePrompt: vi.fn(async () => ({
      txHash: 'aa'.repeat(32),
      blockNumber: 100,
    })),
    recoveryIngestShare: vi.fn(async () => ({ collectedCount: 1 })),
    recoveryCompleteViaSecurePrompt: vi.fn(async () => ({ newEpoch: 6 })),
    copyToClipboard: vi.fn(async () => {}),
  };
});

async function advancePastWarn() {
  fireEvent.click(screen.getByTestId('warn-continue'));
  await screen.findByTestId('step-decode');
}

async function decodeBackup() {
  fireEvent.change(screen.getByTestId('recover-vault-backup-text'), {
    target: { value: 'PASTED-BACKUP-TEXT' },
  });
  fireEvent.change(screen.getByTestId('recover-vault-phrase'), {
    target: { value: VALID_PHRASE_24 },
  });
  fireEvent.click(screen.getByTestId('recover-vault-decode'));
  await screen.findByTestId('step-preview');
}

describe('RecoverVaultWizard (MVP-4-L L-B + MVP-4-H L3 secure-prompt)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('warn step gates entry — cancel returns to caller', () => {
    const onClose = vi.fn();
    render(<RecoverVaultWizard onError={() => {}} onClose={onClose} />);
    expect(screen.getByTestId('step-warn')).toBeTruthy();
    fireEvent.click(screen.getByTestId('warn-cancel'));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('decode → preview surfaces backup metadata', async () => {
    render(<RecoverVaultWizard onError={() => {}} onClose={() => {}} />);
    await advancePastWarn();
    await decodeBackup();
    expect(recoveryDecodeBackup).toHaveBeenCalledWith(
      'PASTED-BACKUP-TEXT',
      VALID_PHRASE_24.split(/\s+/),
    );
    expect(screen.getByTestId('preview-vault-name').textContent).toContain('my vault');
    expect(screen.getByTestId('preview-threshold').textContent).toContain('2 of 3');
  });

  it('phrase < 24 words is rejected before the FFI is called', async () => {
    const onError = vi.fn();
    render(<RecoverVaultWizard onError={onError} onClose={() => {}} />);
    await advancePastWarn();
    fireEvent.change(screen.getByTestId('recover-vault-backup-text'), {
      target: { value: 'X' },
    });
    fireEvent.change(screen.getByTestId('recover-vault-phrase'), {
      target: { value: 'only three words here' },
    });
    fireEvent.click(screen.getByTestId('recover-vault-decode'));
    await waitFor(() => {
      expect(onError).toHaveBeenCalled();
    });
    expect(recoveryDecodeBackup).not.toHaveBeenCalled();
  });

  it('distribute step builds M request blobs that include guardian_evm_addrs as guardian_set (L-0d)', async () => {
    render(<RecoverVaultWizard onError={() => {}} onClose={() => {}} />);
    await advancePastWarn();
    await decodeBackup();
    // preview → init-confirm
    fireEvent.click(screen.getByTestId('preview-continue'));
    await screen.findByTestId('step-init-confirm');

    // No password input anymore — the native dialog collects it.
    expect(screen.queryByTestId('init-password-input')).not.toBeInTheDocument();

    // mock recipient identity for the post-initiate read
    const { recoveryRecipientIdentity: mockId } =
      await import('../lib/invoke');
    (mockId as unknown as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      recipientPubkey: 'ee'.repeat(32),
      attemptNonce: 11,
    });
    fireEvent.click(screen.getByTestId('init-password-broadcast'));

    await screen.findByTestId('step-distribute');
    expect(recoveryInitiateViaSecurePrompt).toHaveBeenCalledWith(
      'aa'.repeat(32),
      'ab'.repeat(20),
      expect.any(Number),
    );

    // M=3 request-blob entries.
    const list = screen.getByTestId('step-distribute').querySelectorAll('li');
    expect(list.length).toBe(3);

    // The first request-blob decoded should contain guardian_set
    // populated from the backup's guardianEvmAddrs (L-0d invariant).
    const code = screen.getByTestId('step-distribute').querySelector('code');
    expect(code).not.toBeNull();
    const decoded = JSON.parse(atob(code!.textContent ?? ''));
    expect(decoded.guardian_set).toEqual(['11'.repeat(20), '22'.repeat(20), '33'.repeat(20)]);
    expect(decoded.vault_id).toBe('aa'.repeat(32));
    expect(decoded.attempt_nonce).toBe(11);
    expect(decoded.recipient_commitment).toBe('ee'.repeat(32));
    // sealed_share is one of the M sealed_shares; the first blob in list
    // order should map to sealed_shares[0].
    expect(decoded.sealed_share).toBe('aaaa'.repeat(40));
    // epoch is 16-byte hex of the u64 (8 leading zero bytes + BE u64).
    expect(decoded.epoch).toMatch(/^0{16}[0-9a-f]{16}$/);
  });

  it('collect step ingests a pasted share and bumps the collected counter', async () => {
    render(<RecoverVaultWizard onError={() => {}} onClose={() => {}} />);
    await advancePastWarn();
    await decodeBackup();
    fireEvent.click(screen.getByTestId('preview-continue'));
    await screen.findByTestId('step-init-confirm');

    const { recoveryRecipientIdentity: mockId } =
      await import('../lib/invoke');
    (mockId as unknown as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      recipientPubkey: 'ee'.repeat(32),
      attemptNonce: 11,
    });
    fireEvent.click(screen.getByTestId('init-password-broadcast'));

    await screen.findByTestId('step-distribute');
    fireEvent.click(screen.getByTestId('distribute-continue'));
    await screen.findByTestId('step-collect');

    fireEvent.change(screen.getByTestId('share-paste'), {
      target: { value: 'PASTED-RESEALED-SHARE-FROM-GUARDIAN' },
    });
    fireEvent.click(screen.getByTestId('share-ingest'));

    await waitFor(() => {
      expect(recoveryIngestShare).toHaveBeenCalledWith(
        'PASTED-RESEALED-SHARE-FROM-GUARDIAN',
        'aa'.repeat(32),
        11,
      );
    });
    await waitFor(() => {
      expect(screen.getByTestId('collect-progress').textContent).toContain(
        '1 of 2 shares ingested',
      );
    });
  });

  it('resume probe jumps straight to distribute when chain Pending matches local nonce', async () => {
    const initiated = Math.floor(Date.now() / 1000) - 2 * 3600;
    // Two consecutive recoveryTargetStatus calls happen on the resume
    // path: one from doDecode + one from the polling effect. Both return
    // the matching-Pending status so the wizard jumps to distribute.
    (recoveryTargetStatus as unknown as ReturnType<typeof vi.fn>).mockResolvedValue(
      fakeStatus({
        status: 1,
        attemptNonce: 7,
        initiatedAt: initiated,
        proposedAuthority: 'ab'.repeat(20),
      }),
    );
    // recoveryRecipientIdentity now returns a persisted identity instead
    // of throwing.
    (recoveryRecipientIdentity as unknown as ReturnType<typeof vi.fn>).mockResolvedValue({
      recipientPubkey: 'ff'.repeat(32),
      attemptNonce: 7,
    });

    render(<RecoverVaultWizard onError={() => {}} onClose={() => {}} />);
    await advancePastWarn();
    await act(async () => {
      fireEvent.change(screen.getByTestId('recover-vault-backup-text'), {
        target: { value: 'X' },
      });
      fireEvent.change(screen.getByTestId('recover-vault-phrase'), {
        target: { value: VALID_PHRASE_24 },
      });
      fireEvent.click(screen.getByTestId('recover-vault-decode'));
    });

    await screen.findByTestId('step-distribute');
    expect(recoveryInitiateViaSecurePrompt).not.toHaveBeenCalled();
  });

  it('finalize is gated until status=Pending + approvals>=threshold + 24h delay met', async () => {
    // Resume into collect with status=Pending but approvals = 0 and
    // initiated just now (no delay met).
    const initiated = Math.floor(Date.now() / 1000) - 10;
    (recoveryTargetStatus as unknown as ReturnType<typeof vi.fn>).mockResolvedValue(
      fakeStatus({
        status: 1,
        attemptNonce: 7,
        initiatedAt: initiated,
        approvalCount: 0,
        proposedAuthority: 'ab'.repeat(20),
      }),
    );
    (recoveryRecipientIdentity as unknown as ReturnType<typeof vi.fn>).mockResolvedValue({
      recipientPubkey: 'ff'.repeat(32),
      attemptNonce: 7,
    });
    render(<RecoverVaultWizard onError={() => {}} onClose={() => {}} />);
    await advancePastWarn();
    await act(async () => {
      fireEvent.change(screen.getByTestId('recover-vault-backup-text'), {
        target: { value: 'X' },
      });
      fireEvent.change(screen.getByTestId('recover-vault-phrase'), {
        target: { value: VALID_PHRASE_24 },
      });
      fireEvent.click(screen.getByTestId('recover-vault-decode'));
    });
    await screen.findByTestId('step-distribute');
    fireEvent.click(screen.getByTestId('distribute-continue'));
    await screen.findByTestId('step-collect');

    const finalizeBtn = screen.getByTestId('collect-finalize') as HTMLButtonElement;
    expect(finalizeBtn.disabled).toBe(true);
    expect(recoveryCompleteViaSecurePrompt).not.toHaveBeenCalled();
  });

  it('full happy-path: collect → finalize-confirm → done', async () => {
    // Finalize delay is 72h; pick > 72h ago so the time gate is met.
    const initiated = Math.floor(Date.now() / 1000) - 73 * 3600;
    (recoveryTargetStatus as unknown as ReturnType<typeof vi.fn>).mockResolvedValue(
      fakeStatus({
        status: 1,
        attemptNonce: 7,
        initiatedAt: initiated,
        approvalCount: 2,
        proposedAuthority: 'ab'.repeat(20),
      }),
    );
    (recoveryRecipientIdentity as unknown as ReturnType<typeof vi.fn>).mockResolvedValue({
      recipientPubkey: 'ff'.repeat(32),
      attemptNonce: 7,
    });
    // Two ingests so collectedCount hits the threshold (2).
    const ingestCalls = [{ collectedCount: 1 }, { collectedCount: 2 }];
    (recoveryIngestShare as unknown as ReturnType<typeof vi.fn>).mockImplementation(
      async () => ingestCalls.shift() ?? { collectedCount: 2 },
    );

    render(<RecoverVaultWizard onError={() => {}} onClose={() => {}} />);
    await advancePastWarn();
    await act(async () => {
      fireEvent.change(screen.getByTestId('recover-vault-backup-text'), {
        target: { value: 'X' },
      });
      fireEvent.change(screen.getByTestId('recover-vault-phrase'), {
        target: { value: VALID_PHRASE_24 },
      });
      fireEvent.click(screen.getByTestId('recover-vault-decode'));
    });
    await screen.findByTestId('step-distribute');
    fireEvent.click(screen.getByTestId('distribute-continue'));
    await screen.findByTestId('step-collect');

    // Ingest twice to reach threshold.
    for (let i = 0; i < 2; i += 1) {
      fireEvent.change(screen.getByTestId('share-paste'), {
        target: { value: `SHARE-${i}` },
      });
      fireEvent.click(screen.getByTestId('share-ingest'));
      await waitFor(() => {
        expect(recoveryIngestShare).toHaveBeenCalledTimes(i + 1);
      });
    }

    await waitFor(() => {
      const btn = screen.getByTestId('collect-finalize') as HTMLButtonElement;
      expect(btn.disabled).toBe(false);
    });
    fireEvent.click(screen.getByTestId('collect-finalize'));
    await screen.findByTestId('step-finalize-confirm');

    // No password input anymore — the native dialog collects it.
    expect(screen.queryByTestId('finalize-password-input')).not.toBeInTheDocument();

    fireEvent.click(screen.getByTestId('finalize-complete'));
    await screen.findByTestId('step-done');
    expect(recoveryCompleteViaSecurePrompt).toHaveBeenCalledWith(
      'aa'.repeat(32),
      'X',
      VALID_PHRASE_24.split(/\s+/),
    );
  });
});
