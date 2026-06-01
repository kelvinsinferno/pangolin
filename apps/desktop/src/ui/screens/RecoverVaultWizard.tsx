// SPDX-License-Identifier: AGPL-3.0-or-later
import { useEffect, useRef, useState } from 'react';
import {
  Button,
  Card,
  Code,
  Input,
  SecurePasswordButton,
  Spinner,
  type SecureSubmitOutcome,
} from '@pangolin/component-library';

import {
  copyToClipboard,
  guardianIdentityExport,
  isDesktopError,
  recoveryCompleteViaSecurePrompt,
  recoveryDecodeBackup,
  recoveryIngestShare,
  recoveryInitiateViaSecurePrompt,
  recoveryRecipientIdentity,
  recoveryTargetStatus,
  type BackupContents,
  type RecoveryTargetStatus,
} from '../lib/invoke';

export interface RecoverVaultWizardProps {
  /** Surface a non-fatal error (decode / chain) as a toast. */
  onError: (message: string) => void;
  /** Return to the Recovery landing — invoked on success + on cancel. */
  onClose: () => void;
}

type Step =
  | 'warn'
  | 'decode'
  | 'preview'
  | 'init-confirm'
  | 'initiating'
  | 'distribute'
  | 'collect'
  | 'finalize-confirm'
  | 'finalizing'
  | 'done';

/** 72h delay enforced by the contract. Used by the local countdown gate
 *  on top of the contract's authoritative check. */
const FINALIZE_DELAY_SEC = 72 * 60 * 60;

/** Polling cadence on the collect step (Q-d). */
const STATUS_POLL_MS = 30_000;

function errMessage(e: unknown): string {
  if (isDesktopError(e)) {
    const m = e.message;
    if (typeof m === 'string') return m;
    if (m !== null && typeof m === 'object') {
      const inner = (m as { message?: unknown }).message;
      if (typeof inner === 'string') return inner;
    }
    return e.kind;
  }
  return e instanceof Error ? e.message : 'unexpected error';
}

/** Encode `epoch: u64` as the 16-byte form the engine's escrow header
 *  expects (8 zero bytes + 8 big-endian u64 bytes). Returns 32-char hex
 *  parallel to what L-C's `recoveryDecodeRequest` consumes. Mirrors
 *  vault.rs's `epoch_bytes[8..].copy_from_slice(&epoch.to_be_bytes())`. */
function epochToHex16(epoch: number): string {
  return '0'.repeat(16) + BigInt(epoch).toString(16).padStart(16, '0');
}

/** Build the per-guardian request blob shape L-C's wizard ingests.
 *  Format: base64-of-JSON of the snake_case 8-field record. */
function buildRequestBlob(args: {
  vaultId: string;
  attemptNonce: number;
  proposedAuthority: string;
  recipientCommitment: string;
  sealedShare: string;
  epoch: string;
  guardianSet: string[];
  expiresAt: number;
}): string {
  const json = JSON.stringify({
    vault_id: args.vaultId,
    attempt_nonce: args.attemptNonce,
    proposed_authority: args.proposedAuthority,
    recipient_commitment: args.recipientCommitment,
    sealed_share: args.sealedShare,
    epoch: args.epoch,
    guardian_set: args.guardianSet,
    expires_at: args.expiresAt,
  });
  return btoa(json);
}

/** Truncate hex with first AND last segments (anti prefix-collision UX,
 *  same shape as L-C's preview). */
function truncateHex(hex: string, segLen: number = 6): string {
  if (hex.length <= segLen * 2 + 1) return hex;
  return `${hex.slice(0, segLen)}…${hex.slice(-segLen)}`;
}

/**
 * Recoverer wizard (MVP-4-L slice L-B). Per
 * `docs/issue-plans/mvp4-l-b-recoverer-wizard.md` — Q-a Rust-side
 * accumulator, Q-b chain-driven resume, Q-c destructive-replace warning,
 * Q-d 30s poll. Multi-day, resumable, the LARGEST recovery UX slice.
 *
 * Steps: warn → decode → preview → init-password → initiating →
 * distribute → collect (paste shares + 30s poll) → finalize-password →
 * finalizing → done.
 */
export function RecoverVaultWizard({ onError, onClose }: RecoverVaultWizardProps) {
  const [step, setStep] = useState<Step>('warn');
  const [backupText, setBackupText] = useState('');
  const [phraseInput, setPhraseInput] = useState('');
  const [backup, setBackup] = useState<BackupContents | null>(null);
  const [proposedAuthority, setProposedAuthority] = useState<string | null>(null);
  const [recipientCommitment, setRecipientCommitment] = useState<string | null>(null);
  const [attemptNonce, setAttemptNonce] = useState<number | null>(null);
  const [expiresAt, setExpiresAt] = useState<number | null>(null);
  const [sharePaste, setSharePaste] = useState('');
  const [collectedCount, setCollectedCount] = useState(0);
  const [chainStatus, setChainStatus] = useState<RecoveryTargetStatus | null>(null);
  // Re-entry guards for the chain steps.
  const initiateGuard = useRef(false);
  const ingestGuard = useRef(false);
  const completeGuard = useRef(false);

  // Load this device's signer (proposed_authority) once. Quiet failure
  // → wizard surfaces an error on the init-password step where the
  // address is actually needed.
  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const me = await guardianIdentityExport();
        if (!cancelled) setProposedAuthority(me.signer);
      } catch {
        // Stay null; init-password step refuses to advance without it.
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  // 30s status poll during the collect step.
  useEffect(() => {
    if (step !== 'collect' || backup === null) return undefined;
    let cancelled = false;
    const fetchOnce = async () => {
      try {
        const s = await recoveryTargetStatus(backup.vaultId);
        if (!cancelled) setChainStatus(s);
      } catch {
        // Quiet — RPC may flake; next tick retries.
      }
    };
    void fetchOnce();
    const tid = setInterval(() => {
      void fetchOnce();
    }, STATUS_POLL_MS);
    return () => {
      cancelled = true;
      clearInterval(tid);
    };
  }, [step, backup]);

  const cancel = () => {
    setSharePaste('');
    onClose();
  };

  const doDecode = async () => {
    const text = backupText.trim();
    const phraseWords = phraseInput.trim().split(/\s+/).filter((w) => w.length > 0);
    if (text === '') {
      onError('Paste the backup envelope text.');
      return;
    }
    if (phraseWords.length !== 24) {
      onError(`Enter all 24 recovery words (got ${phraseWords.length}).`);
      return;
    }
    try {
      const c = await recoveryDecodeBackup(text, phraseWords);
      setBackup(c);
      // Resume probe (Q-b): if there's already a persisted identity for
      // this vault AND the chain says Pending with a matching nonce,
      // jump straight to distribute/collect.
      try {
        const id = await recoveryRecipientIdentity(c.vaultId);
        const status = await recoveryTargetStatus(c.vaultId);
        if (status.status === 1 && status.attemptNonce === id.attemptNonce) {
          setRecipientCommitment(id.recipientPubkey);
          setAttemptNonce(id.attemptNonce);
          // expiresAt isn't persisted; let the user re-enter it
          // implicitly via a default (24h from initiated_at).
          setExpiresAt(status.initiatedAt + 24 * 3600);
          setChainStatus(status);
          setStep('distribute');
          return;
        }
      } catch {
        // No persisted identity → fresh start; proceed to preview.
      }
      setStep('preview');
    } catch (e) {
      onError(errMessage(e));
    }
  };

  const doInitiate = async (): Promise<SecureSubmitOutcome> => {
    if (backup === null || proposedAuthority === null) {
      return { ok: false, message: 'wizard not ready' };
    }
    if (initiateGuard.current) {
      return { ok: false, message: 'already broadcasting' };
    }
    initiateGuard.current = true;
    setStep('initiating');
    try {
      // Expiry: 24h from now. Defensive margin against L-C's 60s
      // minimum + a generous window for the recoverer to send out
      // requests + receive guardian approvals.
      const exp = Math.floor(Date.now() / 1000) + 24 * 3600;
      await recoveryInitiateViaSecurePrompt(backup.vaultId, proposedAuthority, exp);
      setExpiresAt(exp);
      // After broadcast: read the persisted recipient identity to
      // learn the engine-assigned attempt_nonce + ephemeral pubkey.
      const id = await recoveryRecipientIdentity(backup.vaultId);
      setRecipientCommitment(id.recipientPubkey);
      setAttemptNonce(id.attemptNonce);
      setStep('distribute');
      return { ok: true };
    } catch (e) {
      initiateGuard.current = false;
      setStep('init-confirm');
      return { ok: false, message: errMessage(e) };
    }
  };

  const doIngestShare = async () => {
    if (
      backup === null ||
      attemptNonce === null ||
      ingestGuard.current ||
      sharePaste.trim() === ''
    )
      return;
    ingestGuard.current = true;
    try {
      const result = await recoveryIngestShare(sharePaste.trim(), backup.vaultId, attemptNonce);
      setCollectedCount(result.collectedCount);
      setSharePaste('');
    } catch (e) {
      onError(errMessage(e));
    } finally {
      ingestGuard.current = false;
    }
  };

  const doComplete = async (): Promise<SecureSubmitOutcome> => {
    if (backup === null) {
      return { ok: false, message: 'wizard not ready' };
    }
    if (completeGuard.current) {
      return { ok: false, message: 'already finalizing' };
    }
    completeGuard.current = true;
    setStep('finalizing');
    try {
      const phraseWords = phraseInput.trim().split(/\s+/).filter((w) => w.length > 0);
      await recoveryCompleteViaSecurePrompt(backup.vaultId, backupText.trim(), phraseWords);
      setStep('done');
      return { ok: true };
    } catch (e) {
      completeGuard.current = false;
      setStep('collect');
      return { ok: false, message: errMessage(e) };
    }
  };

  // Build the M per-guardian request blobs once the in-flight state is
  // ready. Each maps `sealed_shares[i]` to `guardian_x25519_pubs[i]` ↔
  // `guardian_set[i]` by index — pinned by L-0c ordering invariants.
  const requestBlobs: string[] =
    backup !== null &&
    recipientCommitment !== null &&
    attemptNonce !== null &&
    expiresAt !== null
      ? backup.sealedShares.map((sealedShare) =>
          buildRequestBlob({
            vaultId: backup.vaultId,
            attemptNonce,
            // proposed_authority is read from the in-flight chain state
            // — `proposedAuthority` is THIS device's signer (set on the
            // initiate step) but if we resumed we may not have it set;
            // fall back to chainStatus's proposed_authority for parity.
            proposedAuthority: proposedAuthority ?? chainStatus?.proposedAuthority ?? '',
            recipientCommitment,
            sealedShare,
            epoch: epochToHex16(backup.epoch),
            // L-0d: pass the FULL M-address EVM signer roster from the
            // backup envelope. Each guardian's L-C `recovery_help_approve`
            // rebuilds the merkle root over this list and produces the
            // proof for THEIR address against the on-chain commitment.
            guardianSet: backup.guardianEvmAddrs,
            expiresAt,
          }),
        )
      : [];

  // Compute the finalize-readiness gate (defense-in-depth on top of the
  // contract's authoritative check).
  const nowSec = Math.floor(Date.now() / 1000);
  const finalizeAvailable =
    chainStatus !== null &&
    chainStatus.status === 1 &&
    chainStatus.approvalCount >= (backup?.threshold ?? 0xff) &&
    collectedCount >= (backup?.threshold ?? 0xff) &&
    nowSec >= chainStatus.initiatedAt + FINALIZE_DELAY_SEC;

  return (
    <Card elevation="md">
      <header className="recovery-wizard__header">
        <h2>Recover a vault</h2>
        <Button variant="ghost" onClick={cancel} data-testid="recover-vault-cancel">
          Cancel
        </Button>
      </header>

      {step === 'warn' && (
        <div className="recovery-wizard__step" data-testid="step-warn">
          <Card elevation="sm">
            <p className="recovery-wizard__warning" role="alert">
              <strong>This will REBUILD this vault from your backup.</strong> All
              current data in THIS vault will be replaced by the data you are
              recovering. If you intended to keep the contents of this vault,
              cancel now.
            </p>
          </Card>
          <div className="recovery-wizard__actions">
            <Button variant="ghost" onClick={cancel} data-testid="warn-cancel">
              Cancel
            </Button>
            <Button onClick={() => setStep('decode')} data-testid="warn-continue">
              I understand — continue
            </Button>
          </div>
        </div>
      )}

      {step === 'decode' && (
        <div className="recovery-wizard__step" data-testid="step-decode">
          <p>Paste your backup envelope text + the 24 recovery words.</p>
          <Input
            type="text"
            value={backupText}
            onChange={(e) => setBackupText(e.target.value)}
            placeholder="Backup envelope text"
            data-testid="recover-vault-backup-text"
          />
          <Input
            type="text"
            value={phraseInput}
            onChange={(e) => setPhraseInput(e.target.value)}
            placeholder="24 recovery words, separated by spaces"
            data-testid="recover-vault-phrase"
          />
          <Button onClick={() => void doDecode()} data-testid="recover-vault-decode">
            Decode backup
          </Button>
        </div>
      )}

      {step === 'preview' && backup !== null && (
        <div className="recovery-wizard__step" data-testid="step-preview">
          <p>Backup decoded. Verify these details before continuing.</p>
          <dl className="recovery-wizard__preview">
            <dt>Vault id</dt>
            <dd data-testid="preview-vault-id">0x{truncateHex(backup.vaultId)}</dd>
            <dt>Vault name</dt>
            <dd data-testid="preview-vault-name">
              {backup.vaultDisplayName === '' ? '(none)' : backup.vaultDisplayName}
            </dd>
            <dt>Threshold</dt>
            <dd data-testid="preview-threshold">
              {backup.threshold} of {backup.guardianCount} guardians
            </dd>
            <dt>Backup created</dt>
            <dd data-testid="preview-created-at">
              {new Date(backup.createdAtUnix * 1000).toISOString()}
            </dd>
          </dl>
          <div className="recovery-wizard__actions">
            <Button
              variant="ghost"
              onClick={() => setStep('decode')}
              data-testid="preview-back"
            >
              Back
            </Button>
            <Button
              onClick={() => setStep('init-confirm')}
              data-testid="preview-continue"
            >
              Continue
            </Button>
          </div>
        </div>
      )}

      {step === 'init-confirm' && (
        <div className="recovery-wizard__step" data-testid="step-init-confirm">
          <p>
            Click below to broadcast the recovery attempt to Base Sepolia. A
            native dialog will collect this device&apos;s master password — it
            never enters this app&apos;s memory. (Your new vault password is
            set later, at the final step.)
          </p>
          <SecurePasswordButton
            label="Broadcast recovery attempt"
            onSubmit={doInitiate}
            onError={onError}
            disabled={proposedAuthority === null}
            data-testid="init-password-broadcast"
          />
        </div>
      )}

      {step === 'initiating' && (
        <div className="recovery-wizard__step" data-testid="step-initiating">
          <Spinner />
          <p>Broadcasting initiate to Base Sepolia… this can take a few seconds.</p>
        </div>
      )}

      {step === 'distribute' && backup !== null && requestBlobs.length > 0 && (
        <div className="recovery-wizard__step" data-testid="step-distribute">
          <p>
            Send each request to its matching guardian via any out-of-band
            channel (Signal, email, in-person). They paste it into their
            Pangolin desktop&apos;s &quot;Help someone recover&quot; wizard.
          </p>
          <ul className="recovery-wizard__list">
            {requestBlobs.map((blob) => (
              <li key={blob} data-testid={`request-blob-${blob.slice(0, 6)}`}>
                <Code variant="block">{blob}</Code>
                <Button
                  variant="ghost"
                  onClick={() => void copyToClipboard(blob)}
                  data-testid={`request-blob-copy-${blob.slice(0, 6)}`}
                >
                  Copy
                </Button>
              </li>
            ))}
          </ul>
          <Button onClick={() => setStep('collect')} data-testid="distribute-continue">
            I&apos;ve sent the requests — continue
          </Button>
        </div>
      )}

      {step === 'collect' && backup !== null && (
        <div className="recovery-wizard__step" data-testid="step-collect">
          <p>
            As each guardian sends back their re-sealed share, paste it here.
            You need {backup.threshold} of {backup.guardianCount} to recover.
          </p>
          <Input
            type="text"
            value={sharePaste}
            onChange={(e) => setSharePaste(e.target.value)}
            placeholder="Paste a re-sealed share from a guardian"
            data-testid="share-paste"
          />
          <Button
            onClick={() => void doIngestShare()}
            disabled={sharePaste.trim() === ''}
            data-testid="share-ingest"
          >
            Ingest share
          </Button>
          <p className="recovery-wizard__muted" data-testid="collect-progress">
            {collectedCount} of {backup.threshold} shares ingested locally ·{' '}
            {chainStatus?.approvalCount ?? 0} of {backup.threshold} approvals on-chain
            {chainStatus !== null && chainStatus.initiatedAt > 0
              ? (() => {
                  const remaining =
                    chainStatus.initiatedAt + FINALIZE_DELAY_SEC - nowSec;
                  if (remaining <= 0) return ' · Finalize available now';
                  const hrs = Math.ceil(remaining / 3600);
                  return ` · Finalize available in ~${hrs}h`;
                })()
              : ''}
          </p>
          <Button
            onClick={() => setStep('finalize-confirm')}
            disabled={!finalizeAvailable}
            data-testid="collect-finalize"
          >
            Finalize and recover
          </Button>
        </div>
      )}

      {step === 'finalize-confirm' && backup !== null && (
        <div className="recovery-wizard__step" data-testid="step-finalize-confirm">
          <p>
            Click below to finalize. A native dialog will collect a NEW master
            password for the recovered vault — this password will replace this
            device&apos;s current master password and unlock your recovered
            data.
          </p>
          <SecurePasswordButton
            label="Finalize and rebuild"
            onSubmit={doComplete}
            onError={onError}
            data-testid="finalize-complete"
          />
        </div>
      )}

      {step === 'finalizing' && (
        <div className="recovery-wizard__step" data-testid="step-finalizing">
          <Spinner />
          <p>Finalizing on-chain + rebuilding this vault… this can take a moment.</p>
        </div>
      )}

      {step === 'done' && (
        <div className="recovery-wizard__step" data-testid="step-done">
          <p>
            Recovery complete. Lock and unlock this vault with your new master
            password to use your recovered data.
          </p>
          <Button onClick={cancel} data-testid="done-close">
            Done
          </Button>
        </div>
      )}
    </Card>
  );
}
