// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * MVP-4-M L4: one-shot closed-beta warning modal.
 *
 * On mount calls the Rust-side `beta_warning_state` to learn whether
 * the user has dismissed the warning for the current binary version.
 * If not, renders a blocking modal explaining the closed-beta /
 * testnet-only / unaudited posture and offering an "I understand"
 * button that calls `beta_warning_dismiss` (persisting the current
 * version) and hides the modal for this session.
 *
 * Per plan-LOCK Q-L4 LOCKED Option 1: the modal RE-FIRES on every
 * version bump. Persistence lives in Rust-side `app_data_dir()`, NOT
 * localStorage — see commands/beta_warning.rs for the rationale.
 *
 * Failure modes: if the state read errors (e.g. command not yet
 * registered in a dev build), the modal stays hidden — production
 * users won't see a phantom modal on initial-load races. Errors on
 * dismiss are surfaced via the `onError` callback so the parent can
 * toast them; the modal still closes optimistically.
 */
import { useEffect, useState } from 'react';

import { Button } from '@pangolin/component-library';

import { betaWarningDismiss, betaWarningState } from '../lib/invoke';

export interface BetaWarningModalProps {
  /** Called if the Rust-side `beta_warning_dismiss` call errors after
   *  the user clicks "I understand". The modal still closes
   *  optimistically — re-firing the modal next launch is the natural
   *  fallback. */
  onError?: (message: string) => void;
}

export function BetaWarningModal({ onError }: BetaWarningModalProps): React.JSX.Element | null {
  const [shouldShow, setShouldShow] = useState(false);
  const [currentVersion, setCurrentVersion] = useState('');

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const state = await betaWarningState();
        if (cancelled) return;
        setCurrentVersion(state.currentVersion);
        setShouldShow(state.shouldShow);
      } catch {
        // Stay hidden on a read error — better to under-warn once than
        // to flash a modal that the user can't close because Rust isn't
        // registered. The next-launch re-read will surface a real
        // warning if needed.
        if (!cancelled) setShouldShow(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const dismiss = async () => {
    setShouldShow(false);
    try {
      await betaWarningDismiss();
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'Failed to record beta acknowledgement';
      onError?.(msg);
    }
  };

  if (!shouldShow) return null;

  return (
    <div className="beta-modal__overlay" data-testid="beta-warning-overlay">
      <div
        className="beta-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="beta-modal-heading"
        data-testid="beta-warning-modal"
      >
        <h2 id="beta-modal-heading" className="beta-modal__heading">
          <span className="beta-chip" aria-hidden="true">
            Beta · Testnet
          </span>
          You're about to use a pre-audit build
        </h2>
        <p className="beta-modal__body">
          Pangolin is in closed beta on the Base Sepolia testnet. This build
          has <strong>not</strong> been independently audited — the AGPL source is public
          for community review. Please:
        </p>
        <ul className="beta-modal__list">
          <li>Do not store production secrets in this vault.</li>
          <li>Use a throwaway recovery seed phrase for testing.</li>
          <li>Expect breaking changes between beta versions; back up + re-create vaults if upgrades fail.</li>
        </ul>
        <p className="beta-modal__version" data-testid="beta-modal-version">
          Current build: {currentVersion || 'unknown'}
        </p>
        <div className="beta-modal__actions">
          <Button
            variant="primary"
            onClick={dismiss}
            data-testid="beta-modal-acknowledge"
          >
            I understand
          </Button>
        </div>
      </div>
    </div>
  );
}
