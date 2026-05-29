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

type Step = 'confirm' | 'password' | 'working' | 'rekey-retry';

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
  // Once the on-chain removal succeeds, the device is OUT of the set —
  // re-broadcasting it would revert (ErrNotAuthorized). So a later failure
  // (the re-key) must retry ONLY the rotation, never the removal.
  const removed = useRef(false);

  const cancel = () => {
    setPassword('');
    onClose();
  };

  const run = async () => {
    if (guard.current) return;
    guard.current = true;
    setStep('working');
    try {
      if (!removed.current) {
        await pairingRemoveDevice(signer);
        removed.current = true;
      }
      await pairingCompleteRotation(password);
      const pw = password;
      setPassword('');
      await onRekeyed(pw);
    } catch (e) {
      onError(errMessage(e));
      guard.current = false;
      // If the removal already landed on-chain, only the re-key remains —
      // route to the rotation-only retry (re-broadcasting would revert and
      // would leave the forward-secrecy gap open). Otherwise it is safe to
      // retry the whole flow from the password step.
      setStep(removed.current ? 'rekey-retry' : 'password');
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

      {step === 'rekey-retry' && (
        <div className="devices-wizard__step" data-testid="step-rekey-retry">
          <p>
            The device was removed on-chain, but re-keying the vault did not
            finish. Until you complete it, the removed device can still read
            newly-added data. Re-enter your master password and retry — this
            only finishes the re-key (the device is already removed).
          </p>
          <Input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Master password"
            data-testid="rekey-retry-password"
          />
          <Button
            onClick={() => void run()}
            disabled={password === ''}
            data-testid="rekey-retry-run"
          >
            Retry re-key
          </Button>
        </div>
      )}
    </Card>
  );
}
