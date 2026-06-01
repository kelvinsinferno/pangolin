// SPDX-License-Identifier: AGPL-3.0-or-later
import { useRef, useState } from 'react';
import {
  Button,
  Card,
  Code,
  SecurePasswordButton,
  type SecureSubmitOutcome,
} from '@pangolin/component-library';

import {
  isDesktopError,
  pairingCompleteRotationViaSecurePrompt,
  pairingRemoveDevice,
} from '../lib/invoke';

export interface RemoveDeviceWizardProps {
  /** 40-char hex signer of the device to remove. */
  signer: string;
  onError: (message: string) => void;
  onClose: () => void;
  /** After the removal + re-key, re-unlock the now-rotated (Locked)
   *  vault and land on the account list. The parent drives the unlock
   *  via its own native prompt (the wizard no longer hands a password
   *  back). */
  onRekeyed: () => Promise<void>;
}

type Step = 'confirm' | 'run' | 'rekey-retry';

function errMessage(e: unknown): string {
  if (isDesktopError(e)) {
    return typeof e.message === 'string' ? e.message : e.kind;
  }
  return e instanceof Error ? e.message : 'unexpected error';
}

/**
 * Manager-side "Remove a device" wizard (MVP-4-J, **MVP-4-H L3 migrated**).
 *
 * Confirm (destructive, names the signer) → click "Remove + re-key"
 * → broadcast `removeDevice` (no password) → OS native dialog
 * collects the master password → complete the VDK rotation → unlock
 * the re-keyed vault.
 *
 * **MVP-4-H L3 migration:** the rotation password is collected by
 * the OS native widget at click time (no React state ever holds a
 * password). Both the initial 'run' step AND the 'rekey-retry'
 * fall-through step use SecurePasswordButton.
 *
 * A re-entry guard prevents a double broadcast. If the app dies
 * mid-flow the resumable pending-rotation banner on the Devices
 * screen finishes the re-key (which itself uses
 * `pairingCompleteRotationViaSecurePrompt`).
 */
export function RemoveDeviceWizard({
  signer,
  onError,
  onClose,
  onRekeyed,
}: RemoveDeviceWizardProps) {
  const [step, setStep] = useState<Step>('confirm');
  const guard = useRef(false);
  // Once the on-chain removal succeeds, the device is OUT of the set —
  // re-broadcasting it would revert (ErrNotAuthorized). So a later failure
  // (the re-key) must retry ONLY the rotation, never the removal.
  const removed = useRef(false);

  const cancel = () => onClose();

  // Removal + re-key in one click. The OS native dialog opens INSIDE
  // pairingCompleteRotationViaSecurePrompt (i.e. AFTER the on-chain
  // removal lands). If the user dismisses the dialog after the
  // removal already landed, we route to the rotation-only retry step.
  const removeAndRekey = async (): Promise<SecureSubmitOutcome> => {
    if (guard.current) {
      return { ok: false, message: 'already running' };
    }
    guard.current = true;
    try {
      if (!removed.current) {
        await pairingRemoveDevice(signer);
        removed.current = true;
      }
      await pairingCompleteRotationViaSecurePrompt();
      await onRekeyed();
      return { ok: true };
    } catch (e) {
      guard.current = false;
      // If the removal already landed on-chain, only the re-key remains —
      // route to the rotation-only retry (re-broadcasting would revert and
      // would leave the forward-secrecy gap open). Otherwise it is safe to
      // retry the whole flow from the run step.
      setStep(removed.current ? 'rekey-retry' : 'run');
      return { ok: false, message: errMessage(e) };
    }
  };

  // Rotation-only retry — the removal already landed, so this only
  // re-runs the VDK rotation under a fresh password prompt.
  const rekeyOnly = async (): Promise<SecureSubmitOutcome> => {
    if (guard.current) {
      return { ok: false, message: 'already running' };
    }
    guard.current = true;
    try {
      await pairingCompleteRotationViaSecurePrompt();
      await onRekeyed();
      return { ok: true };
    } catch (e) {
      guard.current = false;
      return { ok: false, message: errMessage(e) };
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
            <Button onClick={() => setStep('run')} data-testid="remove-confirm">
              Remove this device
            </Button>
            <Button variant="ghost" onClick={cancel} data-testid="remove-cancel">
              Cancel
            </Button>
          </div>
        </div>
      )}

      {step === 'run' && (
        <div className="devices-wizard__step" data-testid="step-run">
          <p>
            Click below to remove the device and re-key the vault. A native
            dialog will prompt for your master password to complete the
            re-key — the password never enters this app&apos;s memory.
          </p>
          <SecurePasswordButton
            label="Remove + re-key"
            onSubmit={removeAndRekey}
            onError={onError}
            data-testid="remove-run"
          />
        </div>
      )}

      {step === 'rekey-retry' && (
        <div className="devices-wizard__step" data-testid="step-rekey-retry">
          <p>
            The device was removed on-chain, but re-keying the vault did not
            finish. Until you complete it, the removed device can still read
            newly-added data. Click below to retry — the native dialog will
            collect your master password and finish the re-key only (the
            device is already removed).
          </p>
          <SecurePasswordButton
            label="Retry re-key"
            onSubmit={rekeyOnly}
            onError={onError}
            data-testid="rekey-retry-run"
          />
        </div>
      )}
    </Card>
  );
}
