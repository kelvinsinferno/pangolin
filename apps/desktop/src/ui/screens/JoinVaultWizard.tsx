// SPDX-License-Identifier: AGPL-3.0-or-later
import { useEffect, useRef, useState } from 'react';
import {
  Button,
  Card,
  Code,
  Spinner,
  SecurePasswordButton,
  type SecureSubmitOutcome,
} from '@pangolin/component-library';

import { CodeDisplay } from '../components/CodeDisplay';
import { CodeIngest } from '../components/CodeIngest';
import {
  isDesktopError,
  pairingBeginNewDevice,
  pairingDeriveSas,
  pairingDecodeBytes,
  pairingOpenAndJoinViaSecurePrompt,
  type PairingPayload,
} from '../lib/invoke';

export interface JoinVaultWizardProps {
  /** Surface a non-fatal error as a toast. */
  onError: (message: string) => void;
  /** Return to the Devices landing. */
  onClose: () => void;
  /** Called after the seal opens + the VDK installs under the new
   *  device-local master password (collected by the OS native widget).
   *  The app re-unlocks the now-shared vault via a second native prompt
   *  and lands on the account list. */
  onJoined: () => Promise<void>;
}

type Step = 'show' | 'ingest' | 'sas' | 'envelope' | 'finish';

function errMessage(e: unknown): string {
  if (isDesktopError(e)) {
    return typeof e.message === 'string' ? e.message : e.kind;
  }
  return e instanceof Error ? e.message : 'unexpected error';
}

/**
 * New-device "Join a vault" wizard (MVP-4-I, **MVP-4-H L3 migrated**).
 *
 * Drives the join handshake: show this device's payload → ingest the
 * manager's payload → SAS confirm (L2) → ingest the sealed envelope →
 * click "Join vault" → the OS native widget collects a NEW master
 * password for this device, opens the seal + adopts the shared vault.
 *
 * **MVP-4-H L3 migration:** the new master password is collected by
 * the OS native widget at the final step (no React state ever holds
 * a password). The parent's `onJoined` then drives a SECOND native
 * prompt to unlock the now-Locked vault; the user types the same
 * password twice — accepted UX for first ship.
 */
export function JoinVaultWizard({ onError, onClose, onJoined }: JoinVaultWizardProps) {
  const [step, setStep] = useState<Step>('show');
  const [myPayload, setMyPayload] = useState<PairingPayload | null>(null);
  const [theirPayload, setTheirPayload] = useState<PairingPayload | null>(null);
  const [sas, setSas] = useState<string | null>(null);
  const [sealedBytes, setSealedBytes] = useState<number[] | null>(null);

  // Keep the latest callbacks in refs so the mount effect can run EXACTLY
  // once (a parent re-render must not regenerate this device's payload —
  // that would mint a fresh freshness nonce mid-handshake).
  const onErrorRef = useRef(onError);
  onErrorRef.current = onError;
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;
  // Re-entry guard so a double-click can't drive two open-and-join attempts.
  const joinGuard = useRef(false);

  const cancel = () => onClose();

  // Generate this device's payload once on mount.
  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const mine = await pairingBeginNewDevice();
        if (!cancelled) setMyPayload(mine);
      } catch (e) {
        if (!cancelled) {
          onErrorRef.current(errMessage(e));
          onCloseRef.current();
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  // Ingest the manager's payload → derive the SAS.
  const ingestManager = async (bytes: number[]) => {
    if (myPayload === null) throw new Error('this device is not ready yet');
    const theirs = await pairingDecodeBytes(bytes);
    const code = await pairingDeriveSas(theirs.bytes, myPayload.bytes);
    setTheirPayload(theirs);
    setSas(code);
    setStep('sas');
  };

  // Ingest the sealed envelope → advance to the final "set password" step.
  const ingestEnvelope = async (bytes: number[]) => {
    setSealedBytes(bytes);
    setStep('finish');
  };

  // Driven directly from the SecurePasswordButton click — the native
  // widget collects the new master password and routes it into
  // pairing_open_and_join WITHOUT crossing V8.
  const finishViaSecurePrompt = async (): Promise<SecureSubmitOutcome> => {
    if (theirPayload === null || sealedBytes === null) {
      return { ok: false, message: 'wizard not ready' };
    }
    if (joinGuard.current) {
      return { ok: false, message: 'already joining' };
    }
    joinGuard.current = true;
    try {
      await pairingOpenAndJoinViaSecurePrompt(sealedBytes, theirPayload.vaultId, 0);
      await onJoined();
      return { ok: true };
    } catch (e) {
      joinGuard.current = false;
      return { ok: false, message: errMessage(e) };
    }
  };

  return (
    <Card elevation="md">
      <header className="devices-wizard__header">
        <h2>Join a vault</h2>
        <Button variant="ghost" onClick={cancel} data-testid="wizard-cancel">
          Cancel
        </Button>
      </header>

      {step === 'show' && (
        <div className="devices-wizard__step" data-testid="step-show">
          {myPayload === null ? (
            <Spinner />
          ) : (
            <>
              <p>Show this code to the device that already has the vault.</p>
              <CodeDisplay bytes={myPayload.bytes} label="This device's pairing code" />
              <Button onClick={() => setStep('ingest')} data-testid="wizard-show-next">
                Next
              </Button>
            </>
          )}
        </div>
      )}

      {step === 'ingest' && (
        <div className="devices-wizard__step" data-testid="step-ingest">
          <p>Scan or paste the code shown on the other device.</p>
          <CodeIngest
            prompt="The other device's pairing code"
            onSubmit={ingestManager}
            testId="join-ingest"
          />
        </div>
      )}

      {step === 'sas' && sas !== null && (
        <div className="devices-wizard__step" data-testid="step-sas">
          <p>Check that this 6-digit code is identical on both devices.</p>
          <Code variant="block" data-testid="wizard-sas">
            {sas}
          </Code>
          <div className="devices-wizard__actions">
            <Button onClick={() => setStep('envelope')} data-testid="wizard-sas-confirm">
              The codes match — continue
            </Button>
            <Button variant="ghost" onClick={cancel} data-testid="wizard-sas-reject">
              They don&apos;t match — cancel
            </Button>
          </div>
        </div>
      )}

      {step === 'envelope' && (
        <div className="devices-wizard__step" data-testid="step-envelope">
          <p>Scan or paste the final code from the other device.</p>
          <CodeIngest
            prompt="Sealed vault-key envelope"
            onSubmit={ingestEnvelope}
            testId="join-envelope-ingest"
          />
        </div>
      )}

      {step === 'finish' && (
        <div className="devices-wizard__step" data-testid="step-finish">
          <p>
            Set a master password for this device. Clicking below opens a
            native dialog — the password never enters this app's memory.
          </p>
          <SecurePasswordButton
            label="Join vault"
            onSubmit={finishViaSecurePrompt}
            onError={onError}
            data-testid="wizard-join-finish"
          />
        </div>
      )}
    </Card>
  );
}
