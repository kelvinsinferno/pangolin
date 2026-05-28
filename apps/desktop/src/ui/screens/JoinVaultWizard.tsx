// SPDX-License-Identifier: AGPL-3.0-or-later
import { useEffect, useRef, useState } from 'react';
import { Button, Card, Code, Input, Spinner } from '@pangolin/component-library';

import { CodeDisplay } from '../components/CodeDisplay';
import { CodeIngest } from '../components/CodeIngest';
import {
  isDesktopError,
  pairingBeginNewDevice,
  pairingDeriveSas,
  pairingDecodeBytes,
  pairingOpenAndJoin,
  type PairingPayload,
} from '../lib/invoke';

export interface JoinVaultWizardProps {
  /** Surface a non-fatal error as a toast. */
  onError: (message: string) => void;
  /** Return to the Devices landing. */
  onClose: () => void;
  /** Called after the seal opens + the VDK installs under `newPassword`.
   *  The app unlocks the now-shared vault with this password and lands on
   *  the account list. */
  onJoined: (newPassword: string) => Promise<void>;
}

type Step = 'show' | 'ingest' | 'sas' | 'envelope' | 'password';

function errMessage(e: unknown): string {
  if (isDesktopError(e)) {
    return typeof e.message === 'string' ? e.message : e.kind;
  }
  return e instanceof Error ? e.message : 'unexpected error';
}

/**
 * New-device "Join a vault" wizard (MVP-4-I). Shows this device's pairing
 * payload → ingests the manager's payload → SAS confirm (L2) → ingests the
 * sealed envelope → sets a NEW master password for this device → opens the
 * seal + adopts the shared vault, then unlocks.
 */
export function JoinVaultWizard({ onError, onClose, onJoined }: JoinVaultWizardProps) {
  const [step, setStep] = useState<Step>('show');
  const [myPayload, setMyPayload] = useState<PairingPayload | null>(null);
  const [theirPayload, setTheirPayload] = useState<PairingPayload | null>(null);
  const [sas, setSas] = useState<string | null>(null);
  const [sealedBytes, setSealedBytes] = useState<number[] | null>(null);
  const [newPassword, setNewPassword] = useState('');
  const [busy, setBusy] = useState(false);

  // Keep the latest callbacks in refs so the mount effect can run EXACTLY
  // once (a parent re-render must not regenerate this device's payload —
  // that would mint a fresh freshness nonce mid-handshake).
  const onErrorRef = useRef(onError);
  onErrorRef.current = onError;
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;

  const cancel = () => {
    setNewPassword('');
    onClose();
  };

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

  // Ingest the sealed envelope → advance to set a new password.
  const ingestEnvelope = async (bytes: number[]) => {
    setSealedBytes(bytes);
    setStep('password');
  };

  const finish = async () => {
    if (theirPayload === null || sealedBytes === null) return;
    setBusy(true);
    try {
      await pairingOpenAndJoin({
        sealedBytes,
        vaultId: theirPayload.vaultId,
        epoch: 0,
        newPassword,
      });
      const pw = newPassword;
      setNewPassword('');
      await onJoined(pw);
    } catch (e) {
      onError(errMessage(e));
      setBusy(false);
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

      {step === 'password' && (
        <div className="devices-wizard__step" data-testid="step-password">
          <p>Set a master password for this device.</p>
          <Input
            type="password"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
            placeholder="New master password"
            data-testid="wizard-new-password"
          />
          {busy ? (
            <Spinner />
          ) : (
            <Button
              onClick={() => void finish()}
              disabled={newPassword === ''}
              data-testid="wizard-join-finish"
            >
              Join vault
            </Button>
          )}
        </div>
      )}
    </Card>
  );
}
