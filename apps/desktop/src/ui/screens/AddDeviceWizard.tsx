// SPDX-License-Identifier: AGPL-3.0-or-later
import { useRef, useState } from 'react';
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
  pairingAddDeviceViaSecurePrompt,
  pairingChainBootstrapViaSecurePrompt,
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

type Step = 'bootstrap' | 'ingest' | 'share' | 'sas' | 'publishing' | 'envelope';

function errMessage(e: unknown): string {
  if (isDesktopError(e)) {
    return typeof e.message === 'string' ? e.message : e.kind;
  }
  return e instanceof Error ? e.message : 'unexpected error';
}

/**
 * Manager-side "Add a device" wizard (MVP-4-I, **MVP-4-H L3 migrated**).
 *
 * Drives the device-add handshake: optionally bootstrap on-chain →
 * ingest device B's payload → show this device's mirror payload + the
 * SAS → (human confirms the codes match — L2) → publish `addDevice` →
 * show the sealed envelope for B to finish.
 *
 * **MVP-4-H L3 migration:** the master password is collected by the OS
 * native widget at both the bootstrap step AND the SAS-confirm step.
 * The user re-types twice — accepted trade-off (the alternative would
 * be a combined `bootstrap_and_add` Tauri command which adds engine
 * complexity for a minor UX win).
 */
export function AddDeviceWizard({ onError, onClose }: AddDeviceWizardProps) {
  // Step now starts at 'bootstrap'; the legacy 'password' step is gone
  // because no React state needs to hold the password.
  const [step, setStep] = useState<Step>('bootstrap');
  const [theirBytes, setTheirBytes] = useState<number[] | null>(null);
  const [myPayload, setMyPayload] = useState<PairingPayload | null>(null);
  const [sas, setSas] = useState<string | null>(null);
  const [envelope, setEnvelope] = useState<SealedEnvelope | null>(null);
  // Re-entry guard: a second click before the 'publishing' re-render
  // must never fire a second on-chain addDevice (defense-in-depth on
  // top of the contract's deviceNonce, which would already revert a
  // duplicate).
  const publishGuard = useRef(false);

  const cancel = () => onClose();

  const runBootstrap = async (): Promise<SecureSubmitOutcome> => {
    try {
      await pairingChainBootstrapViaSecurePrompt();
      setStep('ingest');
      return { ok: true };
    } catch (e) {
      // A second bootstrap reverts VaultAlreadyBootstrapped — treat
      // any "already" chain error as "already set up, proceed".
      const msg = errMessage(e).toLowerCase();
      if (msg.includes('alreadybootstrapped') || msg.includes('already bootstrapped')) {
        setStep('ingest');
        return { ok: true };
      }
      return { ok: false, message: errMessage(e) };
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
  const confirmAndPublish = async (): Promise<SecureSubmitOutcome> => {
    if (theirBytes === null || publishGuard.current) {
      return { ok: false, message: 'already publishing' };
    }
    publishGuard.current = true;
    setStep('publishing');
    try {
      const env = await pairingAddDeviceViaSecurePrompt(theirBytes);
      setEnvelope(env);
      setStep('envelope');
      return { ok: true };
    } catch (e) {
      publishGuard.current = false;
      setStep('sas');
      return { ok: false, message: errMessage(e) };
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

      {step === 'bootstrap' && (
        <div className="devices-wizard__step" data-testid="step-bootstrap">
          <p>
            If this is the first device you are adding, initialize this vault
            on-chain first (a one-time Base Sepolia transaction). If you have
            already done this, skip.
          </p>
          <div className="devices-wizard__actions">
            <SecurePasswordButton
              label="Initialize on-chain"
              onSubmit={runBootstrap}
              onError={onError}
              data-testid="wizard-bootstrap"
            />
            <Button
              variant="ghost"
              onClick={() => setStep('ingest')}
              data-testid="wizard-bootstrap-skip"
            >
              Skip — already initialized
            </Button>
          </div>
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
            <SecurePasswordButton
              label="The codes match — authorize"
              onSubmit={confirmAndPublish}
              onError={onError}
              data-testid="wizard-sas-confirm"
            />
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
