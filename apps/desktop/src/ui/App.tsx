// SPDX-License-Identifier: AGPL-3.0-or-later
import { Toast } from '@pangolin/component-library';

import { useToast } from './hooks/useToast';
import { useVault, type UnlockResult } from './hooks/useVault';
import { AccountDetailScreen } from './screens/AccountDetailScreen';
import { AccountListScreen } from './screens/AccountListScreen';
import { DevicesScreen } from './screens/DevicesScreen';
import { UnlockScreen } from './screens/UnlockScreen';
import { WelcomeScreen } from './screens/WelcomeScreen';
import type { DesktopError } from './lib/invoke';
import './App.css';

/**
 * Root component for the Pangolin desktop shell.
 *
 * Dispatches on `useVault().state.stage` to render the active screen.
 * Toast queue is shared across screens; the `AuthenticationFailed`
 * variant of `DesktopError` is handled inline by the `UnlockScreen`
 * (per plan §3.3) and NEVER reaches the toast queue here.
 */
export function App() {
  const { state, actions } = useVault();
  const { toasts, actions: toastActions } = useToast();

  // Helper to surface non-AuthenticationFailed errors as a red toast.
  const showError = (err: DesktopError) => {
    if (err.kind === 'AuthenticationFailed') return; // Inline-only.
    const msg = typeof err.message === 'string' ? err.message : err.kind;
    toastActions.danger(msg);
  };

  const onOpen = async (path: string) => {
    const r = await actions.openVault(path);
    if (!r.ok) showError(r.error);
  };
  const onUnlock = async (password: string): Promise<UnlockResult> => {
    const r = await actions.unlockVault(password);
    if (!r.ok && !r.authenticationFailed) {
      showError(r.error);
    }
    return r;
  };
  const onSelect = async (id: string) => {
    const r = await actions.showAccount(id);
    if (!r.ok) showError(r.error);
  };
  const onReveal = async () => {
    const r = await actions.revealPasswordForSelected();
    if (!r.ok) {
      showError(r.error);
      return { ok: false as const };
    }
    return { ok: true as const, password: r.password };
  };
  const onCopyPassword = async () => {
    // Routes through the new copy_password_to_clipboard Tauri command
    // (audit H-1 hardening) — plaintext never crosses V8.
    const r = await actions.copySelectedPassword();
    if (r.ok) {
      toastActions.success('Password copied to clipboard');
    } else {
      showError(r.error);
    }
    return r.ok ? ({ ok: true as const }) : ({ ok: false as const });
  };

  return (
    <div className="app">
      {state.stage === 'welcome' && <WelcomeScreen onOpen={onOpen} />}
      {state.stage === 'locked' && (
        <UnlockScreen onUnlock={onUnlock} onClose={actions.closeVault} />
      )}
      {state.stage === 'active' && (
        <AccountListScreen
          accounts={state.accounts}
          onSelect={onSelect}
          onLock={async () => {
            const r = await actions.lockVault();
            if (!r.ok) showError(r.error);
          }}
          onDevices={actions.goToDevices}
        />
      )}
      {state.stage === 'devices' && (
        <DevicesScreen
          onClose={actions.backToList}
          onError={(msg) => toastActions.danger(msg)}
          onJoined={async (newPassword) => {
            const r = await actions.unlockVault(newPassword);
            if (!r.ok && !r.authenticationFailed) {
              showError(r.error);
            }
          }}
        />
      )}
      {state.stage === 'detail' && state.selected !== null && (
        <AccountDetailScreen
          account={state.selected}
          onBack={actions.backToList}
          onReveal={onReveal}
          onCopyPassword={onCopyPassword}
        />
      )}
      <div className="toast-region" aria-live="polite">
        {toasts.map((t) => (
          <Toast
            key={t.id}
            variant={t.variant}
            durationMs={t.durationMs}
            onDismiss={() => toastActions.dismiss(t.id)}
          >
            {t.message}
          </Toast>
        ))}
      </div>
    </div>
  );
}
