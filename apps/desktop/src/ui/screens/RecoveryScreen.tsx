// SPDX-License-Identifier: AGPL-3.0-or-later
import { useEffect, useRef, useState } from 'react';
import { Badge, Button, Card, Input, SeedPhraseGrid } from '@pangolin/component-library';

import {
  copyToClipboard,
  isDesktopError,
  recoveryCreateBackup,
  recoveryHealth,
  type Backup,
  type RecoveryHealth,
} from '../lib/invoke';
import { SetupGuardiansWizard } from './SetupGuardiansWizard';

export interface RecoveryScreenProps {
  onClose: () => void;
  onError: (message: string) => void;
}

type Step = 'overview' | 'password' | 'show-backup';

function errMessage(e: unknown): string {
  if (isDesktopError(e)) {
    return typeof e.message === 'string' ? e.message : e.kind;
  }
  return e instanceof Error ? e.message : 'unexpected error';
}

const STATUS_LABEL: Record<number, string> = {
  0: 'No recovery in progress',
  1: 'Recovery PENDING',
  2: 'Recovery finalized',
  3: 'Recovery canceled',
};

/**
 * Recovery screen (MVP-4-L, slice L-D): create a recovery backup + a
 * read-only recovery-health panel. A backup ALWAYS requires guardians to
 * actually recover (the phrase is an aid to the guardian flow, not a
 * standalone key — Q-c); guardian onboarding + the recovery wizard are
 * later slices. Testnet-only.
 */
export function RecoveryScreen({ onClose, onError }: RecoveryScreenProps) {
  const [step, setStep] = useState<Step>('overview');
  const [health, setHealth] = useState<RecoveryHealth | null>(null);
  const [healthLoaded, setHealthLoaded] = useState(false);
  const [healthAvailable, setHealthAvailable] = useState(true);
  const [password, setPassword] = useState('');
  const [backup, setBackup] = useState<Backup | null>(null);
  const [showGuardiansWizard, setShowGuardiansWizard] = useState(false);
  // Health refresh trigger — bumped after the wizard reports success so
  // the panel re-fetches without a full screen remount (Q-e).
  const [healthRefreshTick, setHealthRefreshTick] = useState(0);
  const guard = useRef(false);

  // ALL-ZERO authority address (40 hex zeros) — the contract returns this
  // when `vaultAuthority` has never been set, i.e. setGuardianSet has not
  // landed on-chain. Used by the "set up guardians" gating + the resume
  // banner detection (Q-c).
  const ZERO_AUTHORITY = '0'.repeat(40);
  const authorityIsZero =
    health !== null && (health.authority === '' || health.authority === ZERO_AUTHORITY);
  const showSetupGuardiansCard = healthLoaded && healthAvailable && authorityIsZero;

  useEffect(() => {
    let cancelled = false;
    // L-D LOW-1 follow-up: race the chain read against a 5s client-side
    // timeout so a slow / unreachable Base Sepolia RPC doesn't keep the
    // "Loading…" panel pinned indefinitely. On timeout (or any other
    // failure) we fall through to the "not set up on-chain" path (L3
    // fail-closed) — which is the correct UX for the common L-D state
    // anyway (guardian onboarding doesn't ship until L-A).
    const HEALTH_RPC_TIMEOUT_MS = 5_000;
    let timeoutHandle: ReturnType<typeof setTimeout> | null = null;
    void (async () => {
      try {
        const h = await Promise.race<RecoveryHealth>([
          recoveryHealth(),
          new Promise<RecoveryHealth>((_, reject) => {
            timeoutHandle = setTimeout(
              () => reject(new Error('recovery_health: client-side RPC timeout')),
              HEALTH_RPC_TIMEOUT_MS,
            );
          }),
        ]);
        if (!cancelled) {
          setHealth(h);
          setHealthAvailable(true);
        }
      } catch {
        // Not set up on-chain for recovery yet / read unavailable (L3) /
        // RPC timeout. Any of these → degrade to the "not set up" note.
        if (!cancelled) setHealthAvailable(false);
      } finally {
        if (timeoutHandle !== null) clearTimeout(timeoutHandle);
        if (!cancelled) setHealthLoaded(true);
      }
    })();
    return () => {
      cancelled = true;
      if (timeoutHandle !== null) clearTimeout(timeoutHandle);
    };
  }, [healthRefreshTick]);

  const cancel = () => {
    setPassword('');
    onClose();
  };

  const createBackup = async () => {
    if (guard.current) return;
    guard.current = true;
    try {
      const b = await recoveryCreateBackup(password);
      setPassword('');
      setBackup(b);
      setStep('show-backup');
    } catch (e) {
      onError(errMessage(e));
    } finally {
      guard.current = false;
    }
  };

  return (
    <main className="recovery-screen" aria-labelledby="recovery-title">
      <header className="recovery-screen__header">
        <h1 id="recovery-title">Recovery</h1>
        <Button variant="ghost" onClick={cancel} data-testid="recovery-back">
          Back
        </Button>
      </header>

      <p className="recovery-screen__testnet" role="note" data-testid="recovery-testnet-banner">
        Testnet only — recovery stays on Base Sepolia until the external audit
        (D-011) clears.
      </p>

      {showGuardiansWizard ? (
        <SetupGuardiansWizard
          onError={onError}
          onClose={() => setShowGuardiansWizard(false)}
          onSuccess={() => {
            // Q-e: trigger a health-panel refresh; the wizard's own
            // 'done' step lets the user dismiss when they're ready.
            setHealthRefreshTick((t) => t + 1);
          }}
        />
      ) : null}

      {/* Read-only recovery-health panel */}
      <Card elevation="sm">
        <h2>Recovery status</h2>
        {!healthLoaded ? (
          <p>Loading…</p>
        ) : healthAvailable && health !== null ? (
          <div className="recovery-screen__health" data-testid="recovery-health">
            <p>
              <Badge tone={health.recoveryStatus === 1 ? 'warning' : 'neutral'}>
                {STATUS_LABEL[health.recoveryStatus] ?? 'Unknown'}
              </Badge>
            </p>
            <p className="recovery-screen__muted">
              Current authority: 0x{health.authority.slice(0, 12)}…
            </p>
          </div>
        ) : (
          <p className="recovery-screen__muted" data-testid="recovery-health-unavailable">
            Recovery isn&apos;t set up on-chain for this vault yet. Set up
            guardians below to enable recovery.
          </p>
        )}
      </Card>

      {/* L-A: set up guardians card — visible when the health panel
          confirms no on-chain authority is set yet, and the wizard
          modal isn't already up. */}
      {showSetupGuardiansCard && !showGuardiansWizard && (
        <Card elevation="sm">
          <h2>Set up guardians</h2>
          <p>
            Choose people you trust to help you recover this vault if you lose
            your devices and password. You&apos;ll need at least 3 guardians;
            you can set the threshold (how many must agree) afterwards.
          </p>
          <Button
            onClick={() => setShowGuardiansWizard(true)}
            data-testid="setup-guardians-open"
          >
            Set up guardians
          </Button>
        </Card>
      )}

      {/* Create-backup section */}
      <Card elevation="sm">
        <h2>Recovery backup</h2>
        {step === 'overview' && (
          <div className="recovery-screen__section" data-testid="backup-overview">
            <p>
              Create a recovery backup — a 24-word phrase + an encrypted file.
              This backup <strong>helps your guardians recover you</strong> if
              you lose your devices and password; it is NOT a standalone key,
              and you must set up guardians (coming soon) for it to work.
            </p>
            <Button onClick={() => setStep('password')} data-testid="backup-start">
              Create recovery backup
            </Button>
          </div>
        )}

        {step === 'password' && (
          <div className="recovery-screen__section" data-testid="backup-password">
            <p>Confirm your master password to create the backup.</p>
            <Input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Master password"
              data-testid="backup-password-input"
            />
            <div className="recovery-screen__actions">
              <Button
                onClick={() => void createBackup()}
                disabled={password === ''}
                data-testid="backup-create"
              >
                Create backup
              </Button>
              <Button variant="ghost" onClick={() => { setPassword(''); setStep('overview'); }}>
                Cancel
              </Button>
            </div>
          </div>
        )}

        {step === 'show-backup' && backup !== null && (
          <div className="recovery-screen__section" data-testid="backup-show">
            <p className="recovery-screen__warning" role="alert">
              Write these 24 words down and store them safely. They are shown
              ONCE and never again — anyone with them + your guardians can
              recover your vault.
            </p>
            <SeedPhraseGrid words={backup.seedPhraseWords} />
            <div className="recovery-screen__actions">
              <Button
                variant="ghost"
                onClick={() => void copyToClipboard(backup.text)}
                data-testid="backup-copy-envelope"
              >
                Copy encrypted backup file
              </Button>
              <Button onClick={() => setStep('overview')} data-testid="backup-done">
                I&apos;ve saved it
              </Button>
            </div>
          </div>
        )}
      </Card>
    </main>
  );
}
