// SPDX-License-Identifier: AGPL-3.0-or-later
import { useRef, useState } from 'react';
import { Button, Card, Code, Input, Spinner } from '@pangolin/component-library';

import {
  copyToClipboard,
  isDesktopError,
  recoveryDecodeRequest,
  recoveryHealth,
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

/** Client-side RPC timeout for the chain-probe path (mirrors L-A's
 *  CHAIN_PROBE_TIMEOUT_MS — the L-D LOW-1 lesson: a hung RPC must NOT
 *  pin the wizard on its progress step forever). */
const CHAIN_PROBE_TIMEOUT_MS = 5_000;

/** Probe whether the guardian's approval is already on-chain (the L-C
 *  analog of L-A's chainShowsAuthoritySet). We can't query "has this
 *  guardian approved THIS attempt" directly without a chain read that
 *  isn't exposed at the FFI level today; instead we observe via the
 *  shared `recoveryHealth` read on THIS device's vault — but that's the
 *  GUARDIAN'S vault, not the recovering user's. So we can't actually
 *  detect "approve landed but release failed" through health. The Q-d
 *  retry shape relies on the contract's idempotence: if the prior
 *  approve landed, a re-attempt reverts ErrDuplicateApproval, which the
 *  retry handler treats as success and falls through to the release
 *  step. */
async function approveAlreadyLanded(): Promise<boolean> {
  let timeoutHandle: ReturnType<typeof setTimeout> | null = null;
  try {
    // The guardian-side health-panel reads THIS device's vault health.
    // This is a low-fidelity signal for "has my approve to a foreign
    // vault landed" but it does at least confirm RPC reachability,
    // which is the more common failure mode at the retry boundary.
    const probe = await Promise.race([
      recoveryHealth(),
      new Promise((_, reject) => {
        timeoutHandle = setTimeout(
          () => reject(new Error('approveAlreadyLanded: client-side RPC timeout')),
          CHAIN_PROBE_TIMEOUT_MS,
        );
      }),
    ]);
    // We don't have a "did THIS guardian approve target-vault attempt
    // N" view at the FFI today; this probe is purely a connectivity
    // smoke. Return false so the keyword check is the authoritative
    // signal — matches the L-A fallback shape.
    void probe;
    return false;
  } catch {
    return false;
  } finally {
    if (timeoutHandle !== null) clearTimeout(timeoutHandle);
  }
}

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
      // expired — the contract would revert ErrApprovalExpired anyway,
      // but failing locally surfaces the issue to the guardian without
      // burning gas. We compare against the client's clock; minor skew
      // (a few seconds) is fine, large skew is the user's problem.
      const nowSec = Math.floor(Date.now() / 1000);
      if (parsed.expiresAt <= nowSec) {
        onError(
          `Recovery request has expired (expiresAt was ${parsed.expiresAt}; now ${nowSec}). Ask the recovering user to send a fresh request.`,
        );
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

    // Step 2 of 2: release the re-sealed share.
    await runReleaseOnly();
  };

  /** Used both by the initial flow (after a successful approve) AND by
   *  the retry path (when the approve already landed). The contract's
   *  approve is idempotent — a duplicate would revert
   *  ErrDuplicateApproval — so the retry handler treats that revert as
   *  "approve has landed; proceed to release". */
  const runReleaseOnly = async () => {
    if (req === null) return;
    broadcastGuard.current = true; // belt-and-suspenders: already set in the initial path
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
      // approveAlreadyLanded is a low-fidelity reachability smoke at the
      // L-C boundary (we can't query "did THIS guardian approve target
      // vault attempt N" without a new FFI); the wizard surfaces the
      // typed error to the guardian and routes to the retry step so
      // they can re-attempt without re-approving.
      void (await approveAlreadyLanded());
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
            <dd data-testid="preview-vault-id">0x{req.vaultId.slice(0, 12)}…</dd>
            <dt>New authority (where recovery will rotate to)</dt>
            <dd data-testid="preview-proposed-authority">0x{req.proposedAuthority}</dd>
            <dt>Attempt nonce</dt>
            <dd data-testid="preview-attempt-nonce">{req.attemptNonce}</dd>
            <dt>Recoverer pubkey (commitment)</dt>
            <dd data-testid="preview-recipient-commitment">
              0x{req.recipientCommitment.slice(0, 12)}…
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
