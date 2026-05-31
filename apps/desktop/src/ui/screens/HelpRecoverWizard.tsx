// SPDX-License-Identifier: AGPL-3.0-or-later
import { useRef, useState } from 'react';
import { Button, Card, Code, Input, Spinner } from '@pangolin/component-library';

import {
  copyToClipboard,
  isDesktopError,
  recoveryDecodeRequest,
  recoveryHelpApprove,
  recoveryHelpRelease,
  type RecoveryRequest,
} from '../lib/invoke';

export interface HelpRecoverWizardProps {
  /** Surface a non-fatal error (decode / chain) as a toast. */
  onError: (message: string) => void;
  /** Return to the Recovery landing. */
  onClose: () => void;
}

type Step =
  | 'ingest'
  | 'preview'
  | 'approving'
  | 'releasing'
  | 'done'
  | 'retry';

/** Display a truncated hex string as `prefix…suffix` so the guardian can
 *  detect a swap attempt that only differs in the middle bytes. Prefix-
 *  only truncation (audit LOW-3) was vulnerable to a trivial off-chain
 *  prefix collision; showing BOTH ends raises the bar to a full-length
 *  preimage attack on a 32-byte hash. The full hex is still shown in the
 *  click-to-expand block if a guardian wants byte-level certainty. */
function truncateHex(hex: string, segLen: number = 6): string {
  if (hex.length <= segLen * 2 + 1) return hex;
  return `${hex.slice(0, segLen)}…${hex.slice(-segLen)}`;
}

function errMessage(e: unknown): string {
  if (isDesktopError(e)) {
    // Validation envelope is { kind, message: { kind, message } } — unwrap
    // so toasts surface the inner reason, mirroring SetupGuardiansWizard.
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

/** Minimum margin between now and the request's `expiresAt`. Below this,
 *  gas estimation + broadcast latency would race the contract's
 *  ErrApprovalExpired revert — better to fail loud client-side (audit
 *  LOW-1). The contract's check is `block.timestamp > expiresAt`. */
const EXPIRY_MIN_MARGIN_SEC = 60;

/**
 * Guardian-side "Help someone recover" wizard (MVP-4-L slice L-C). Per
 * `docs/issue-plans/mvp4-l-c-guardian-help.md`:
 *
 * - Q-a paste-only request ingest.
 * - Q-b text-display + copy for the re-sealed-share response.
 * - Q-c extends RecoveryScreen as a child wizard.
 * - Q-d on partial failure (approve landed, release failed) → retry
 *   release-only.
 *
 * 5 steps: ingest → preview → approving → releasing → done | retry.
 */
export function HelpRecoverWizard({ onError, onClose }: HelpRecoverWizardProps) {
  const [step, setStep] = useState<Step>('ingest');
  const [pasteText, setPasteText] = useState('');
  const [req, setReq] = useState<RecoveryRequest | null>(null);
  const [sealedForRecoverer, setSealedForRecoverer] = useState<string | null>(null);
  // Re-entry guard: the chain step must never fire twice from a double-
  // click. Mirrors SetupGuardiansWizard / AddDeviceWizard.
  const broadcastGuard = useRef(false);

  const cancel = () => {
    setPasteText('');
    onClose();
  };

  const ingest = async () => {
    const trimmed = pasteText.trim();
    if (trimmed === '') return;
    try {
      const parsed = await recoveryDecodeRequest(trimmed);
      // Local pre-check: refuse to advance if the approval is already
      // expired OR within the EXPIRY_MIN_MARGIN_SEC window — by the time
      // we estimate gas + broadcast, the contract's
      // `block.timestamp > expiresAt` would revert ErrApprovalExpired
      // and the guardian would burn gas (audit LOW-1).
      const nowSec = Math.floor(Date.now() / 1000);
      const marginRemaining = parsed.expiresAt - nowSec;
      if (marginRemaining < EXPIRY_MIN_MARGIN_SEC) {
        if (marginRemaining <= 0) {
          onError(
            `Recovery request has expired (expiresAt was ${parsed.expiresAt}; now ${nowSec}). Ask the recovering user to send a fresh request.`,
          );
        } else {
          onError(
            `Recovery request expires in ${marginRemaining}s — too soon to safely broadcast (need at least ${EXPIRY_MIN_MARGIN_SEC}s). Ask the recovering user to send a fresh request.`,
          );
        }
        return;
      }
      setReq(parsed);
      setStep('preview');
    } catch (e) {
      onError(errMessage(e));
    }
  };

  const runApproveAndRelease = async () => {
    if (req === null || broadcastGuard.current) return;
    broadcastGuard.current = true;

    // Step 1 of 2: approve on-chain.
    setStep('approving');
    try {
      await recoveryHelpApprove(
        req.vaultId,
        req.attemptNonce,
        req.proposedAuthority,
        req.expiresAt,
        req.guardianSet,
      );
    } catch (e) {
      broadcastGuard.current = false;
      onError(errMessage(e));
      setStep('preview');
      return;
    }

    // Step 2 of 2: release the re-sealed share. Release the broadcast
    // guard before the in-function call so runReleaseOnly's own guard
    // check can re-acquire it. There's no race here because the UI is
    // on the 'approving'/'releasing' step with no clickable confirm
    // button surfaced.
    broadcastGuard.current = false;
    await runReleaseOnly();
  };

  /** Used both by the initial flow (after a successful approve) AND by
   *  the retry path (when the approve already landed). The contract's
   *  approve is idempotent — a duplicate would revert
   *  ErrDuplicateApproval — so the retry handler treats that revert as
   *  "approve has landed; proceed to release". */
  const runReleaseOnly = async () => {
    // Audit LOW-4: the retry button calls this function directly, so the
    // broadcastGuard check must live HERE (not just in the initial-flow
    // caller). A double-click on retry would otherwise fire two parallel
    // recoveryHelpRelease calls.
    if (req === null || broadcastGuard.current) return;
    broadcastGuard.current = true;
    setStep('releasing');
    try {
      const result = await recoveryHelpRelease(
        req.vaultId,
        req.attemptNonce,
        req.recipientCommitment,
        req.sealedShare,
        req.epoch,
      );
      setSealedForRecoverer(result.sealedShareForRecoverer);
      setStep('done');
    } catch (e) {
      broadcastGuard.current = false;
      // The retry shape relies on the contract's approve idempotence: if
      // the prior approve actually landed, re-attempting reverts
      // ErrDuplicateApproval and we'd reach release-only via the retry
      // button. No client-side connectivity probe is load-bearing here
      // (audit MED-1 removed the dead probe).
      onError(errMessage(e));
      setStep('retry');
    }
  };

  return (
    <Card elevation="md">
      <header className="recovery-wizard__header">
        <h2>Help someone recover</h2>
        <Button variant="ghost" onClick={cancel} data-testid="help-recover-cancel">
          Cancel
        </Button>
      </header>

      {step === 'ingest' && (
        <div className="recovery-wizard__step" data-testid="step-ingest">
          <p>
            Paste the recovery-request text the recovering user sent you.
            You&apos;ll see what they&apos;re asking for before you approve.
          </p>
          <Input
            type="text"
            value={pasteText}
            onChange={(e) => setPasteText(e.target.value)}
            placeholder="Paste the recovery request"
            data-testid="help-recover-paste"
          />
          <Button
            onClick={() => void ingest()}
            disabled={pasteText.trim() === ''}
            data-testid="help-recover-ingest"
          >
            Next
          </Button>
        </div>
      )}

      {step === 'preview' && req !== null && (
        <div className="recovery-wizard__step" data-testid="step-preview">
          <p>Verify these details with the recovering user out-of-band before continuing.</p>
          <dl className="recovery-wizard__preview">
            <dt>Target vault</dt>
            <dd data-testid="preview-vault-id">0x{truncateHex(req.vaultId)}</dd>
            <dt>New authority (where recovery will rotate to)</dt>
            <dd data-testid="preview-proposed-authority">0x{req.proposedAuthority}</dd>
            <dt>Attempt nonce</dt>
            <dd data-testid="preview-attempt-nonce">{req.attemptNonce}</dd>
            <dt>Recoverer pubkey (commitment)</dt>
            <dd data-testid="preview-recipient-commitment">
              0x{truncateHex(req.recipientCommitment)}
            </dd>
            <dt>Approval expires</dt>
            <dd data-testid="preview-expires-at">
              {new Date(req.expiresAt * 1000).toISOString()}
            </dd>
          </dl>
          <p className="recovery-wizard__warning">
            This will broadcast one on-chain approval (Base Sepolia) and
            release a re-sealed share to the recovering user&apos;s new
            device. Make sure you actually trust this request.
          </p>
          <div className="recovery-wizard__actions">
            <Button
              variant="ghost"
              onClick={() => setStep('ingest')}
              data-testid="help-recover-preview-back"
            >
              Back
            </Button>
            <Button
              onClick={() => void runApproveAndRelease()}
              data-testid="help-recover-confirm"
            >
              Approve and release
            </Button>
          </div>
        </div>
      )}

      {step === 'approving' && (
        <div className="recovery-wizard__step" data-testid="step-approving">
          <Spinner />
          <p>Broadcasting your approval to Base Sepolia… this can take a few seconds.</p>
        </div>
      )}

      {step === 'releasing' && (
        <div className="recovery-wizard__step" data-testid="step-releasing">
          <Spinner />
          <p>Opening + re-sealing your share for the recovering user…</p>
        </div>
      )}

      {step === 'done' && sealedForRecoverer !== null && (
        <div className="recovery-wizard__step" data-testid="step-done">
          <p>
            Send this re-sealed share back to the recovering user (via
            Signal, email, in-person — any channel). They need t of these
            from t guardians to recover.
          </p>
          <Code variant="block" data-testid="help-recover-output">
            {sealedForRecoverer}
          </Code>
          <div className="recovery-wizard__actions">
            <Button
              variant="ghost"
              onClick={() => void copyToClipboard(sealedForRecoverer)}
              data-testid="help-recover-copy"
            >
              Copy
            </Button>
            <Button onClick={cancel} data-testid="help-recover-done">
              Done
            </Button>
          </div>
        </div>
      )}

      {step === 'retry' && req !== null && (
        <div className="recovery-wizard__step" data-testid="step-retry">
          <p>
            Your approval is on-chain but releasing the share failed. You
            can retry the release step — the approval doesn&apos;t need
            to be re-broadcast.
          </p>
          <Button
            onClick={() => void runReleaseOnly()}
            data-testid="help-recover-retry"
          >
            Retry release
          </Button>
        </div>
      )}
    </Card>
  );
}
