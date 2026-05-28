// SPDX-License-Identifier: AGPL-3.0-or-later
import { useState } from 'react';
import { Button, Card, Code, Input, Spinner } from '@pangolin/component-library';

import { CodeDisplay } from '../components/CodeDisplay';
import { CodeIngest } from '../components/CodeIngest';
import {
  isDesktopError,
  pairingAddDevice,
  pairingChainBootstrap,
  pairingDeriveSas,
  pairingDecodeBytes,
  pairingLocalPayload,
  type PairingPayload,
  type SealedEnvelope,
} from '../lib/invoke';

export interface AddDeviceWizardProps {
  /** Surface a non-fatal error (chain / RPC) as a toast. */
  onError: (message: string) => void;
  /** Return to the Devices landing. */
  onClose: () => void;
}

type Step =
  | 'password'
  | 'bootstrap'
  | 'ingest'
  | 'share'
  | 'sas'
  | 'publishing'
  | 'envelope';

function errMessage(e: unknown): string {
  if (isDesktopError(e)) {
    return typeof e.message === 'string' ? e.message : e.kind;
  }
  return e instanceof Error ? e.message : 'unexpected error';
}

/**
 * Manager-side "Add a device" wizard (MVP-4-I). Drives the device-add
 * handshake: collect the master password → optionally bootstrap on-chain
 * → ingest device B's payload → show this device's mirror payload + the
 * SAS → (human confirms the codes match — L2) → publish `addDevice` →
 * show the sealed envelope for B to finish.
 */
export function AddDeviceWizard({ onError, onClose }: AddDeviceWizardProps) {
  const [step, setStep] = useState<Step>('password');
  const [password, setPassword] = useState('');
  const [theirBytes, setTheirBytes] = useState<number[] | null>(null);
  const [myPayload, setMyPayload] = useState<PairingPayload | null>(null);
  const [sas, setSas] = useState<string | null>(null);
  const [envelope, setEnvelope] = useState<SealedEnvelope | null>(null);
  const [busy, setBusy] = useState(false);

  const cancel = () => {
    setPassword('');
    onClose();
  };

  const runBootstrap = async () => {
    setBusy(true);
    try {
      await pairingChainBootstrap(password);
      setStep('ingest');
    } catch (e) {
      // A second bootstrap reverts VaultAlreadyBootstrapped — treat any
      // "already" chain error as "already set up, proceed".
      const msg = errMessage(e).toLowerCase();
      if (msg.includes('alreadybootstrapped') || msg.includes('already bootstrapped')) {
        setStep('ingest');
      } else {
        onError(errMessage(e));
      }
    } finally {
      setBusy(false);
    }
  };

  // Ingest B's payload → build this device's mirror → derive the SAS.
  const ingestPeer = async (bytes: number[]) => {
    // Validate the scanned/pasted payload (throws → CodeIngest shows it).
    await pairingDecodeBytes(bytes);
    const mine = await pairingLocalPayload(bytes);
    const code = await pairingDeriveSas(mine.bytes, bytes);
    setTheirBytes(bytes);
    setMyPayload(mine);
    setSas(code);
    setStep('share');
  };

  // Publish addDevice once the human has confirmed the SAS matches.
  // Driven directly from the confirm click (NOT an effect) so a parent
  // re-render can never re-fire the on-chain transaction.
  const confirmAndPublish = async () => {
    if (theirBytes === null) return;
    setStep('publishing');
    try {
      const env = await pairingAddDevice(theirBytes, password);
      setEnvelope(env);
      setStep('envelope');
    } catch (e) {
      onError(errMessage(e));
      setStep('sas');
    }
  };

  return (
    <Card elevation="md">
      <header className="devices-wizard__header">
        <h2>Add a device</h2>
        <Button variant="ghost" onClick={cancel} data-testid="wizard-cancel">
          Cancel
        </Button>
      </header>

      {step === 'password' && (
        <div className="devices-wizard__step" data-testid="step-password">
          <p>Confirm your master password to authorize a new device.</p>
          <Input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Master password"
            data-testid="wizard-password"
          />
          <Button
            onClick={() => setStep('bootstrap')}
            disabled={password === ''}
            data-testid="wizard-password-next"
          >
            Next
          </Button>
        </div>
      )}

      {step === 'bootstrap' && (
        <div className="devices-wizard__step" data-testid="step-bootstrap">
          <p>
            If this is the first device you are adding, initialize this vault
            on-chain first (a one-time Base Sepolia transaction). If you have
            already done this, skip.
          </p>
          {busy ? (
            <Spinner />
          ) : (
            <div className="devices-wizard__actions">
              <Button onClick={() => void runBootstrap()} data-testid="wizard-bootstrap">
                Initialize on-chain
              </Button>
              <Button
                variant="ghost"
                onClick={() => setStep('ingest')}
                data-testid="wizard-bootstrap-skip"
              >
                Skip — already initialized
              </Button>
            </div>
          )}
        </div>
      )}

      {step === 'ingest' && (
        <div className="devices-wizard__step" data-testid="step-ingest">
          <p>Scan or paste the code shown on the device you are adding.</p>
          <CodeIngest
            prompt="Device B's pairing code"
            onSubmit={ingestPeer}
            testId="add-ingest"
          />
        </div>
      )}

      {step === 'share' && myPayload !== null && (
        <div className="devices-wizard__step" data-testid="step-share">
          <p>Now show this code to the device you are adding.</p>
          <CodeDisplay bytes={myPayload.bytes} label="This device's pairing code" />
          <Button onClick={() => setStep('sas')} data-testid="wizard-share-next">
            Next
          </Button>
        </div>
      )}

      {step === 'sas' && sas !== null && (
        <div className="devices-wizard__step" data-testid="step-sas">
          <p>
            Check that this 6-digit code is identical on both devices before
            continuing.
          </p>
          <Code variant="block" data-testid="wizard-sas">
            {sas}
          </Code>
          <div className="devices-wizard__actions">
            <Button
              onClick={() => void confirmAndPublish()}
              data-testid="wizard-sas-confirm"
            >
              The codes match — authorize
            </Button>
            <Button variant="ghost" onClick={cancel} data-testid="wizard-sas-reject">
              They don&apos;t match — cancel
            </Button>
          </div>
        </div>
      )}

      {step === 'publishing' && (
        <div className="devices-wizard__step" data-testid="step-publishing">
          <Spinner />
          <p>Publishing to Base Sepolia… this can take a few seconds.</p>
        </div>
      )}

      {step === 'envelope' && envelope !== null && (
        <div className="devices-wizard__step" data-testid="step-envelope">
          <p>
            Almost done. Show this final code to the new device to complete
            pairing.
          </p>
          <CodeDisplay bytes={envelope.bytes} label="Sealed vault-key envelope" />
          <Button onClick={cancel} data-testid="wizard-done">
            Done
          </Button>
        </div>
      )}
    </Card>
  );
}
