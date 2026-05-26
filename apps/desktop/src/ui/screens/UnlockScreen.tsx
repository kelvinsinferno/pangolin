// SPDX-License-Identifier: AGPL-3.0-or-later
import { useState } from 'react';
import { Button, Card, Input } from '@pangolin/component-library';

import type { UnlockResult } from '../hooks/useVault';

export interface UnlockScreenProps {
  onUnlock: (password: string) => Promise<UnlockResult>;
  onClose: () => Promise<void>;
}

/**
 * Unlock screen — the locked-vault password entry surface.
 *
 * Per MVP-4-B plan §3.3 the "wrong master password" case is surfaced
 * **inline under the password field**, NOT as a danger toast — every
 * other error class flows through `useToast.danger()` at the App
 * level. Implementation: the `useVault.unlockVault` hook returns a
 * discriminated `UnlockResult`; this component reads `authenticationFailed`
 * and renders the inline message.
 */
export function UnlockScreen({ onUnlock, onClose }: UnlockScreenProps) {
  const [password, setPassword] = useState('');
  const [pending, setPending] = useState(false);
  const [authFailed, setAuthFailed] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (password.length === 0 || pending) return;
    setPending(true);
    setAuthFailed(false);
    const result = await onUnlock(password);
    setPending(false);
    if (!result.ok && result.authenticationFailed) {
      setAuthFailed(true);
      setPassword('');
    }
    // Other failure modes propagate to the App-level danger toast via
    // the hook's caller path; success is handled by the state machine
    // (the App re-renders into the AccountList screen).
  };

  return (
    <main className="unlock-screen" aria-labelledby="unlock-title">
      <Card elevation="md">
        <h1 id="unlock-title">Unlock</h1>
        <form onSubmit={handleSubmit}>
          {/* MVP-4-F E2E gate: the wrapper carries `master-password-input`
              so WebDriverIO can locate the unlock surface independent of
              the component-library's internal DOM shape (the `<Input>`
              element's `data-testid="password-input"` is the Vitest
              contract; the wrapper is the E2E contract). Plan §3.4. */}
          <div data-testid="master-password-input">
            <Input
              label="Master Password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoFocus
              data-testid="password-input"
              aria-invalid={authFailed}
              aria-describedby={authFailed ? 'password-error' : undefined}
            />
          </div>
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
          <div className="unlock-screen__actions">
            <Button
              type="submit"
              disabled={pending || password.length === 0}
              data-testid="unlock-button"
            >
              {pending ? 'Unlocking...' : 'Unlock'}
            </Button>
            <Button variant="ghost" onClick={onClose} disabled={pending}>
              Cancel
            </Button>
          </div>
        </form>
      </Card>
    </main>
  );
}
