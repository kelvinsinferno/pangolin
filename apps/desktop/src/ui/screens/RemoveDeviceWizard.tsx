// SPDX-License-Identifier: AGPL-3.0-or-later
import { useRef, useState } from 'react';
import { Button, Card, Code, Input, Spinner } from '@pangolin/component-library';

import {
  isDesktopError,
  pairingCompleteRotation,
  pairingRemoveDevice,
} from '../lib/invoke';

export interface RemoveDeviceWizardProps {
  /** 40-char hex signer of the device to remove. */
  signer: string;
  onError: (message: string) => void;
  onClose: () => void;
  /** After the removal + re-key, unlock the now-rotated (Locked) vault with
   *  this password and land on the account list. */
  onRekeyed: (password: string) => Promise<void>;
}

type Step = 'confirm' | 'password' | 'working';

function errMessage(e: unknown): string {
  if (isDesktopError(e)) {
    return typeof e.message === 'string' ? e.message : e.kind;
  }
  return e instanceof Error ? e.message : 'unexpected error';
}

/**
 * Manager-side "Remove a device" wizard (MVP-4-J, Q-a single guided flow).
 * Confirm (destructive, names the signer) → master password → broadcast
 * `removeDevice` AND immediately complete the VDK rotation in one
 * uninterrupted action → unlock the re-keyed vault. A re-entry guard
 * prevents a double broadcast; if the app dies mid-flow the resumable
 * pending-rotation banner on the Devices screen finishes the re-key.
 */
export function RemoveDeviceWizard({
  signer,
  onError,
  onClose,
  onRekeyed,
}: RemoveDeviceWizardProps) {
  const [step, setStep] = useState<Step>('confirm');
  const [password, setPassword] = useState('');
  const guard = useRef(false);

  const cancel = () => {
    setPassword('');
    onClose();
  };

  const run = async () => {
    if (guard.current) return;
    guard.current = true;
    setStep('working');
    try {
      await pairingRemoveDevice(signer);
      await pairingCompleteRotation(password);
      const pw = password;
      setPassword('');
      await onRekeyed(pw);
    } catch (e) {
      onError(errMessage(e));
      guard.current = false;
      setStep('password');
    }
  };

  return (
    <Card elevation="md">
      <header className="devices-wizard__header">
        <h2>Remove device</h2>
        <Button variant="ghost" onClick={cancel} data-testid="wizard-cancel">
          Cancel
        </Button>
      </header>

      {step === 'confirm' && (
        <div className="devices-wizard__step" data-testid="step-confirm">
          <p>
            Permanently remove this device from the vault? It keeps access to
            data created before now, but loses access to anything added
            afterward. This publishes an on-chain removal on Base Sepolia and
            re-keys the vault — it cannot be undone.
          </p>
          <Code variant="block" data-testid="remove-target">
            0x{signer}
          </Code>
          <div className="devices-wizard__actions">
            <Button onClick={() => setStep('password')} data-testid="remove-confirm">
              Remove this device
            </Button>
            <Button variant="ghost" onClick={cancel} data-testid="remove-cancel">
              Cancel
            </Button>
          </div>
        </div>
      )}

      {step === 'password' && (
        <div className="devices-wizard__step" data-testid="step-password">
          <p>Enter your master password to remove the device and re-key the vault.</p>
          <Input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Master password"
            data-testid="remove-password"
          />
          <Button
            onClick={() => void run()}
            disabled={password === ''}
            data-testid="remove-run"
          >
            Remove + re-key
          </Button>
        </div>
      )}

      {step === 'working' && (
        <div className="devices-wizard__step" data-testid="step-working">
          <Spinner />
          <p>Removing the device and re-keying the vault on Base Sepolia…</p>
        </div>
      )}
    </Card>
  );
}
