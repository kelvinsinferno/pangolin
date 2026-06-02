// SPDX-License-Identifier: AGPL-3.0-or-later
import { useEffect } from 'react';
import { Toast } from '@pangolin/component-library';

import { BetaChip } from './components/BetaChip';
import { BetaWarningModal } from './components/BetaWarningModal';
import { ExtensionBanner } from './components/ExtensionBanner';
import { useToast } from './hooks/useToast';
import { useVault, type UnlockResult } from './hooks/useVault';
import { AccountDetailScreen } from './screens/AccountDetailScreen';
import { AccountListScreen } from './screens/AccountListScreen';
import { DevicesScreen } from './screens/DevicesScreen';
import { RecoveryScreen } from './screens/RecoveryScreen';
import { SettingsScreen } from './screens/SettingsScreen';
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
  const onCreate = async (path: string) => {
    const r = await actions.createVault(path);
    if (!r.ok) showError(r.error);
  };

  // MVP-4-N: expose the React openVault / createVault actions on
  // `window.__pangolinE2e` so the desktop-e2e suite can drive the
  // welcome screen without needing to control the native file dialog
  // (wdio can't interact with native widgets — same limitation that
  // motivated the MVP-4-H secure-input stub for unlocks). The hook
  // is purely a JS-side reference to the existing actions; no new
  // Tauri command, no new IPC surface. Production CSP (`script-src
  // 'self'`) blocks third-party scripts from calling it; the hook
  // can't do anything `window.__TAURI__.core.invoke('vault_open')`
  // couldn't already do.
  useEffect(() => {
    (window as unknown as {
      __pangolinE2e?: {
        openVault: (path: string) => Promise<void>;
        createVault: (path: string) => Promise<void>;
      };
    }).__pangolinE2e = { openVault: onOpen, createVault: onCreate };
    // onOpen / onCreate are recreated each render but capture the
    // same `actions.*` refs (which are stable from useVault). Re-
    // assigning the hook on every render is cheap and avoids a
    // stale-closure bug.
  });
  const onUnlock = async (): Promise<UnlockResult> => {
    const r = await actions.unlockVault();
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
      {/* MVP-4-M L4: persistent "BETA · TESTNET" chip + one-shot
          first-launch / version-bump warning modal. Chip shows on every
          launch regardless of dismissal state; modal fires once per
          fresh version and persists dismissal in app_data_dir(). */}
      <BetaChip fixed />
      <BetaWarningModal onError={(msg) => toastActions.danger(msg)} />
      {/* MVP-4-M L3: soft "connect browser extension?" banner shown
          ONCE per session when no native-host manifest is installed.
          Non-blocking; user can dismiss to "Maybe later". */}
      {state.stage === 'active' && <ExtensionBanner onConfigure={actions.goToSettings} />}
      {state.stage === 'welcome' && (
        <WelcomeScreen
          onOpen={onOpen}
          onCreate={onCreate}
          onError={(msg) => toastActions.danger(msg)}
        />
      )}
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
          onRecovery={actions.goToRecovery}
          onSettings={actions.goToSettings}
        />
      )}
      {state.stage === 'recovery' && (
        <RecoveryScreen
          onClose={actions.backToList}
          onError={(msg) => toastActions.danger(msg)}
        />
      )}
      {state.stage === 'settings' && (
        <SettingsScreen
          onClose={actions.backToList}
          onError={(msg) => toastActions.danger(msg)}
        />
      )}
      {state.stage === 'devices' && (
        <DevicesScreen
          onClose={actions.backToList}
          onError={(msg) => toastActions.danger(msg)}
          onJoined={async () => {
            // MVP-4-H L3: the wizard collected the new master password
            // via the OS native widget; nothing flows back to JS. The
            // vault is left Locked; the user lands on UnlockScreen
            // which prompts via SecurePasswordButton to activate.
            const r = await actions.unlockVault();
            if (!r.ok && !r.authenticationFailed) {
              showError(r.error);
            }
          }}
          onRekeyed={async () => {
            // The vault is Locked after a rotation; re-unlock via
            // the OS native widget + land on the account list.
            const r = await actions.unlockVault();
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
