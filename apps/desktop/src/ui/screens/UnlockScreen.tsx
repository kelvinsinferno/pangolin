// SPDX-License-Identifier: AGPL-3.0-or-later
import { useState } from 'react';
import {
  Button,
  Card,
  SecurePasswordButton,
  type SecureSubmitOutcome,
} from '@pangolin/component-library';

import type { UnlockResult } from '../hooks/useVault';

export interface UnlockScreenProps {
  /** MVP-4-H L3: the password is collected by the OS native widget
   *  inside `unlockVault`; this prop takes NO args. */
  onUnlock: () => Promise<UnlockResult>;
  onClose: () => Promise<void>;
}

/**
 * Unlock screen — the locked-vault password entry surface.
 *
 * **MVP-4-H L3** migrated: the password is collected by the OS native
 * widget (Win32 CredUI / NSAlert+NSSecureTextField / GtkEntry) instead
 * of a React `<Input type="password">`. The plaintext never enters the
 * V8 heap. The visible UI is just an "Unlock" button that triggers the
 * native dialog.
 *
 * Per MVP-4-B plan §3.3 the "wrong master password" case is surfaced
 * **inline under the button**, NOT as a danger toast. Implementation:
 * `unlockVault` returns a discriminated `UnlockResult`; this component
 * reads `authenticationFailed` and renders the inline message.
 */
export function UnlockScreen({ onUnlock, onClose }: UnlockScreenProps) {
  const [authFailed, setAuthFailed] = useState(false);

  const handleSubmit = async (): Promise<SecureSubmitOutcome> => {
    setAuthFailed(false);
    const result = await onUnlock();
    if (result.ok) {
      return { ok: true };
    }
    if (result.authenticationFailed) {
      setAuthFailed(true);
      // The inline banner is the chosen UX (plan §3.3); the
      // SecurePasswordButton's onError toast is NOT fired here. We
      // return a non-`ok` outcome with an empty message so onError
      // isn't even called (parent's onError is a no-op when handler
      // returns success-ish from caller's POV — but to keep the
      // contract honest we return `{ ok: false }` and rely on the
      // parent's onError being benign).
      return { ok: false, message: '' };
    }
    const m = result.error.message;
    let msg: string;
    if (typeof m === 'string') {
      msg = m;
    } else if (m !== null && typeof m === 'object') {
      const inner = (m as { message?: unknown }).message;
      msg = typeof inner === 'string' ? inner : result.error.kind;
    } else {
      msg = result.error.kind;
    }
    return { ok: false, message: msg };
  };

  return (
    <main className="unlock-screen" aria-labelledby="unlock-title">
      <Card elevation="md">
        <h1 id="unlock-title">Unlock</h1>
        {authFailed && (
          <div data-testid="unlock-error-banner">
            <p
              id="password-error"
              role="alert"
              className="unlock-screen__error"
              data-testid="auth-failed-inline"
            >
              The master password is not correct. Try again.
            </p>
          </div>
        )}
        {/* MVP-4-F E2E gate carrier — kept on the action wrapper so
            wdio can still locate the unlock surface (Plan §3.4). */}
        <div className="unlock-screen__actions" data-testid="master-password-input">
          <SecurePasswordButton
            label="Unlock"
            onSubmit={handleSubmit}
            data-testid="unlock-button"
          />
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
        </div>
      </Card>
    </main>
  );
}
