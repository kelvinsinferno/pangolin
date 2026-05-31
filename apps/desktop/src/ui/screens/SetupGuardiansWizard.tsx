// SPDX-License-Identifier: AGPL-3.0-or-later
import { useEffect, useRef, useState } from 'react';
import { Button, Card, Input, Spinner } from '@pangolin/component-library';

import {
  guardianIdentityExport,
  guardianInviteDecodeText,
  isDesktopError,
  recoveryHealth,
  recoveryOnboardGuardians,
  recoverySetGuardianSet,
  type GuardianInvite,
} from '../lib/invoke';

export interface SetupGuardiansWizardProps {
  /** Surface a non-fatal error (decode / chain) as a toast. */
  onError: (message: string) => void;
  /** Return to the Recovery landing — invoked on success + on user cancel. */
  onClose: () => void;
  /** Called after a successful on-chain commit so the parent can refresh
   *  the health panel (Q-e). */
  onSuccess: () => void;
  /** When non-null, the wizard opens directly in 'retry' mode for a
   *  half-state where the off-chain escrow was seeded on a prior attempt
   *  but the on-chain step never landed (Q-c). The host detects this via
   *  the RecoveryScreen's resume-banner check. */
  resume?: ResumeContext;
}

/** Context the parent passes when re-entering after a partial-onboarding
 *  failure (off-chain step succeeded, on-chain step failed). The pubkey
 *  list is the SAME ordering the original onboard used so the merkle root
 *  computes identically. */
export interface ResumeContext {
  guardians: GuardianInvite[];
  threshold: number;
}

type Step =
  | 'collect'
  | 'threshold'
  | 'password'
  | 'onboarding'
  | 'broadcasting'
  | 'done'
  | 'retry';

// Contract bounds (RecoveryV2 MIN_*/MAX_*): keep in lockstep with
// crates/pangolin-chain. The FFI revalidates; the contract reverts as the
// final gate. Triple-defense.
const MIN_GUARDIANS = 3;
const MAX_GUARDIANS = 15;
const MIN_THRESHOLD = 2;
const MAX_THRESHOLD = 9;

function errMessage(e: unknown): string {
  if (isDesktopError(e)) {
    // Validation errors carry a nested { kind, message } record (see the
    // invoke.ts DesktopError comment). Unwrap it so the toast surfaces
    // the actual bound-violation reason, not the bare label "Validation".
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

/** ZERO_AUTHORITY in hex (40 chars) — matches `hex_encode` of a 20-byte
 *  all-zero EVM address. Used by the chain-read fallback in the retry path
 *  to detect "the broadcast actually landed" without depending on the
 *  revert message shape (audit LOW-3). */
const ZERO_AUTHORITY_HEX = '0'.repeat(40);

/** Client-side RPC timeout for the chain-probe path (audit re-audit
 *  NEW-LOW-1). Same shape as the L-D LOW-1 RecoveryScreen timeout: if a
 *  hung Base Sepolia RPC doesn't respond promptly, we degrade to the
 *  keyword-check + retry path instead of pinning the wizard on its
 *  "broadcasting" spinner forever. */
const CHAIN_PROBE_TIMEOUT_MS = 5_000;

/** Probe the on-chain authority. Returns true iff a non-zero authority is
 *  set, indicating the prior `setGuardianSet` broadcast landed. Quiet on
 *  ANY failure (RPC down, vault not initialized, RPC timeout, anything)
 *  — the caller falls back to the error-message keyword check. */
async function chainShowsAuthoritySet(): Promise<boolean> {
  let timeoutHandle: ReturnType<typeof setTimeout> | null = null;
  try {
    const h = await Promise.race<{ authority: string }>([
      recoveryHealth(),
      new Promise<{ authority: string }>((_, reject) => {
        timeoutHandle = setTimeout(
          () => reject(new Error('chainShowsAuthoritySet: client-side RPC timeout')),
          CHAIN_PROBE_TIMEOUT_MS,
        );
      }),
    ]);
    return h.authority !== '' && h.authority !== ZERO_AUTHORITY_HEX;
  } catch {
    return false;
  } finally {
    if (timeoutHandle !== null) clearTimeout(timeoutHandle);
  }
}

/**
 * Owner-side "Set up guardians" wizard (MVP-4-L slice L-A). Per
 * `docs/issue-plans/mvp4-l-a-guardian-onboarding.md`:
 *
 * Q-a paste-only invite ingest. Q-b extends the RecoveryScreen as a child.
 * Q-c partial-failure → resume + idempotent retry (the 'retry' step). Q-d
 * hard refuse self-as-guardian. Q-e success auto-refreshes the parent's
 * health panel via the `onSuccess` callback.
 *
 * Five steps: collect → threshold → password → onboarding (two FFI calls
 * in sequence) → done|retry.
 */
export function SetupGuardiansWizard({
  onError,
  onClose,
  onSuccess,
  resume,
}: SetupGuardiansWizardProps) {
  const [step, setStep] = useState<Step>(resume ? 'password' : 'collect');
  const [guardians, setGuardians] = useState<GuardianInvite[]>(
    resume?.guardians ?? [],
  );
  const [threshold, setThreshold] = useState<number>(
    resume?.threshold ?? MIN_THRESHOLD,
  );
  const [pasteText, setPasteText] = useState('');
  const [password, setPassword] = useState('');
  const [selfPubkey, setSelfPubkey] = useState<string | null>(null);
  // `selfLoaded` is set once the identity-export resolves OR fails, so the
  // UI can close the Q-d race window where a fast paste-and-click could
  // sneak past the guard while the pubkey is still loading (audit LOW-1).
  // The guard's degraded mode (selfPubkey === null after a failed load)
  // is preserved — selfLoaded is true even on failure, so the user can
  // still proceed.
  const [selfLoaded, setSelfLoaded] = useState(false);
  // Re-entry guard: the chain step must never fire twice from a double-
  // click. Mirrors AddDeviceWizard.publishGuard.
  const broadcastGuard = useRef(false);

  // Load this device's guardian pubkey once so the self-as-guardian guard
  // (Q-d) can compare against ingested invites. Quiet failure → the guard
  // degrades to "no self-check available" (the FFI's t/M bounds + the
  // chain still gate the catastrophic states).
  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const me = await guardianIdentityExport();
        if (!cancelled) setSelfPubkey(me.x25519SealingPub);
      } catch {
        if (!cancelled) setSelfPubkey(null);
      } finally {
        if (!cancelled) setSelfLoaded(true);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const cancel = () => {
    setPassword('');
    setPasteText('');
    onClose();
  };

  const addInvite = async () => {
    const trimmed = pasteText.trim();
    if (trimmed === '') return;
    // Defense beyond the disabled-button UI gate (audit re-audit LOW-1):
    // the Q-d self-as-guardian check is meaningless until the identity
    // export has settled. Refuse to advance until then so a synthesized
    // event (devtools, accessibility tooling, future programmatic UX)
    // cannot bypass the guard via the disabled-attribute path.
    if (!selfLoaded) {
      onError(
        'Still loading this device’s identity — please wait a moment and try again.',
      );
      return;
    }
    try {
      const invite = await guardianInviteDecodeText(trimmed);

      // Q-d: hard refuse self-as-guardian.
      if (selfPubkey !== null && invite.x25519SealingPub === selfPubkey) {
        onError(
          "This is your own device's identity — guardians must be other people's devices.",
        );
        return;
      }
      // Duplicate detection by sealing pubkey (the catastrophic primary
      // identity; address is non-distinguishing per the L-0b invite shape).
      if (guardians.some((g) => g.x25519SealingPub === invite.x25519SealingPub)) {
        onError('This guardian invite has already been added.');
        return;
      }
      if (guardians.length >= MAX_GUARDIANS) {
        onError(`The maximum guardian count is ${MAX_GUARDIANS}.`);
        return;
      }

      setGuardians([...guardians, invite]);
      setPasteText('');
    } catch (e) {
      onError(errMessage(e));
    }
  };

  const removeInvite = (idx: number) => {
    setGuardians(guardians.filter((_, i) => i !== idx));
  };

  const advanceToThreshold = () => {
    if (guardians.length < MIN_GUARDIANS) return;
    // Clamp threshold to the valid range for the current guardian count.
    const maxT = Math.min(MAX_THRESHOLD, guardians.length);
    if (threshold < MIN_THRESHOLD) setThreshold(MIN_THRESHOLD);
    if (threshold > maxT) setThreshold(maxT);
    setStep('threshold');
  };

  const advanceToPassword = () => {
    setStep('password');
  };

  const runOnboarding = async () => {
    if (broadcastGuard.current) return;
    broadcastGuard.current = true;

    const x25519Pubs = guardians.map((g) => g.x25519SealingPub);
    const evmAddrs = guardians.map((g) => g.signer);

    // Step 1 of 2: off-chain escrow. Skipped on RESUME (the parent only
    // shows the retry path when step 1 has already succeeded).
    if (!resume) {
      setStep('onboarding');
      try {
        await recoveryOnboardGuardians(threshold, x25519Pubs);
      } catch (e) {
        broadcastGuard.current = false;
        onError(errMessage(e));
        setStep('password');
        return;
      }
    }

    // Step 2 of 2: on-chain merkle root + self-bootstrap.
    setStep('broadcasting');
    try {
      await recoverySetGuardianSet(password, evmAddrs, threshold);
      setPassword('');
      setStep('done');
      onSuccess();
    } catch (e) {
      broadcastGuard.current = false;
      // Audit LOW-3: a post-broadcast on-chain revert surfaces as
      // "unknown revert (status=0)" — the reason is not decoded — so
      // the keyword check alone could miss a successful broadcast that
      // technically reverted on a re-attempt. Probe the chain DIRECTLY:
      // if the authority is set, the prior broadcast actually landed.
      if (await chainShowsAuthoritySet()) {
        setPassword('');
        setStep('done');
        onSuccess();
        return;
      }
      // Q-c: a chain failure leaves the off-chain escrow seeded. Route to
      // the retry step so the user can re-attempt JUST the chain step
      // (idempotent: the contract reverts ErrGuardianSetAlreadyInitialized
      // if it actually landed, which the retry handler treats as success).
      onError(errMessage(e));
      setStep('retry');
    }
  };

  const retryChainOnly = async () => {
    if (broadcastGuard.current) return;
    broadcastGuard.current = true;
    setStep('broadcasting');
    const evmAddrs = guardians.map((g) => g.signer);
    try {
      await recoverySetGuardianSet(password, evmAddrs, threshold);
      setPassword('');
      setStep('done');
      onSuccess();
    } catch (e) {
      broadcastGuard.current = false;
      // Audit LOW-3: the chain-read fallback is the most robust signal
      // that the prior broadcast landed — independent of however the
      // revert reason is (or isn't) decoded.
      if (await chainShowsAuthoritySet()) {
        setPassword('');
        setStep('done');
        onSuccess();
        return;
      }
      // Estimate-gas revert messages DO include the reason; keyword
      // check is the fallback for that path (or any error class where
      // the chain isn't yet observably in the post-broadcast state).
      const msg = errMessage(e).toLowerCase();
      if (msg.includes('alreadyinitialized') || msg.includes('already initialized')) {
        setPassword('');
        setStep('done');
        onSuccess();
        return;
      }
      onError(errMessage(e));
      setStep('retry');
    }
  };

  const maxT = Math.min(MAX_THRESHOLD, Math.max(guardians.length, MIN_THRESHOLD));

  return (
    <Card elevation="md">
      <header className="recovery-wizard__header">
        <h2>Set up guardians</h2>
        <Button variant="ghost" onClick={cancel} data-testid="setup-guardians-cancel">
          Cancel
        </Button>
      </header>

      {step === 'collect' && (
        <div className="recovery-wizard__step" data-testid="step-collect">
          <p>
            Add at least {MIN_GUARDIANS} guardian invites. Each guardian sends
            you the invite text from their own device. Your guardians help you
            recover if you lose your devices and password.
          </p>

          <Input
            type="text"
            value={pasteText}
            onChange={(e) => setPasteText(e.target.value)}
            placeholder="Paste a guardian invite"
            data-testid="setup-guardians-paste"
          />
          <Button
            onClick={() => void addInvite()}
            disabled={pasteText.trim() === '' || !selfLoaded}
            data-testid="setup-guardians-add"
          >
            Add guardian
          </Button>

          <ul className="recovery-wizard__list" data-testid="setup-guardians-list">
            {guardians.map((g, i) => (
              <li key={g.x25519SealingPub} data-testid={`guardian-${i}`}>
                <span>
                  Guardian {i + 1} · {g.signer.slice(0, 10)}…
                </span>
                <Button
                  variant="ghost"
                  onClick={() => removeInvite(i)}
                  data-testid={`guardian-remove-${i}`}
                >
                  Remove
                </Button>
              </li>
            ))}
          </ul>

          <p className="recovery-wizard__muted">
            {guardians.length} of {MIN_GUARDIANS}–{MAX_GUARDIANS} guardians added.
          </p>

          <Button
            onClick={advanceToThreshold}
            disabled={guardians.length < MIN_GUARDIANS}
            data-testid="setup-guardians-next"
          >
            Next — pick threshold
          </Button>
        </div>
      )}

      {step === 'threshold' && (
        <div className="recovery-wizard__step" data-testid="step-threshold">
          <p>
            How many of your {guardians.length} guardians must agree to recover
            your vault? A higher number is safer; a lower number is easier to
            recover.
          </p>
          <Input
            type="number"
            min={MIN_THRESHOLD}
            max={maxT}
            value={threshold}
            onChange={(e) => setThreshold(Number(e.target.value))}
            data-testid="setup-guardians-threshold"
          />
          <p className="recovery-wizard__muted">
            {threshold} of {guardians.length} guardians required (between{' '}
            {MIN_THRESHOLD} and {maxT}).
          </p>
          <div className="recovery-wizard__actions">
            <Button
              variant="ghost"
              onClick={() => setStep('collect')}
              data-testid="setup-guardians-threshold-back"
            >
              Back
            </Button>
            <Button
              onClick={advanceToPassword}
              disabled={threshold < MIN_THRESHOLD || threshold > maxT}
              data-testid="setup-guardians-threshold-next"
            >
              Next
            </Button>
          </div>
        </div>
      )}

      {step === 'password' && (
        <div className="recovery-wizard__step" data-testid="step-password">
          <p>
            Confirm your master password to finish setting up your{' '}
            {guardians.length} guardians (threshold {threshold}).
          </p>
          <Input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Master password"
            data-testid="setup-guardians-password"
          />
          <Button
            onClick={() => void runOnboarding()}
            disabled={password === ''}
            data-testid="setup-guardians-onboard"
          >
            Set up guardians
          </Button>
        </div>
      )}

      {step === 'onboarding' && (
        <div className="recovery-wizard__step" data-testid="step-onboarding">
          <Spinner />
          <p>Seeding the off-chain recovery escrow…</p>
        </div>
      )}

      {step === 'broadcasting' && (
        <div className="recovery-wizard__step" data-testid="step-broadcasting">
          <Spinner />
          <p>Committing to Base Sepolia… this can take a few seconds.</p>
        </div>
      )}

      {step === 'done' && (
        <div className="recovery-wizard__step" data-testid="step-done">
          <p>
            Guardians set up. Your {guardians.length}-guardian recovery is now
            anchored on-chain, with a threshold of {threshold}.
          </p>
          <Button onClick={cancel} data-testid="setup-guardians-done">
            Done
          </Button>
        </div>
      )}

      {step === 'retry' && (
        <div className="recovery-wizard__step" data-testid="step-retry">
          <p>
            The off-chain part of setting up your guardians succeeded, but the
            on-chain step failed. You can retry just the on-chain step — your
            guardians don&apos;t need to re-send their invites.
          </p>
          <Input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Master password"
            data-testid="setup-guardians-retry-password"
          />
          <Button
            onClick={() => void retryChainOnly()}
            disabled={password === ''}
            data-testid="setup-guardians-retry"
          >
            Retry on-chain step
          </Button>
        </div>
      )}
    </Card>
  );
}
