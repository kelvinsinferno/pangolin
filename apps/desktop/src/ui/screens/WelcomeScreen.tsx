// SPDX-License-Identifier: AGPL-3.0-or-later
import { useState } from 'react';
import { open as openDialog, save as saveDialog } from '@tauri-apps/plugin-dialog';
import { Button, Card } from '@pangolin/component-library';

export interface WelcomeScreenProps {
  /** Open an existing vault file. Called with the absolute path the
   *  native open-dialog returned. */
  onOpen: (path: string) => Promise<void>;
  /** MVP-4-N: create a fresh vault file at the path the native save-
   *  dialog returned. The OS native password dialog fires next
   *  (`vault_create_via_secure_prompt` Tauri command); after success
   *  the vault is on disk + the state machine lands on Locked. */
  onCreate: (path: string) => Promise<void>;
  /** Toast-worthy errors that should bubble up to the App-level
   *  toast region (e.g. dialog plugin failures, file-system errors).
   *  Cancelled dialogs are NOT errors and don't fire this. */
  onError?: (message: string) => void;
}

/**
 * Welcome screen — the entry surface when no vault is open.
 *
 * **MVP-4-N rewrite (2026-06-02)**. The original screen asked the user
 * to paste an absolute path to a `.pvf` vault file. This was a dead-end
 * for fresh installs (no vault file exists yet — the FFI's
 * `vault_create` was never wired to the UI). The first-beta-tester
 * report on v0.1.0-beta.1 surfaced the dead-end.
 *
 * Now: two primary actions backed by `tauri-plugin-dialog`'s native
 * open/save dialogs:
 *   - **Create new vault** — native save dialog suggests `vault.pvf`,
 *     user picks a folder, then the OS password prompt fires
 *     (MVP-4-H secure-input — no V8 residue), the file lands on disk,
 *     state machine moves to Locked, user unlocks via the existing
 *     SecurePasswordButton flow.
 *   - **Open existing vault** — native open dialog with `.pvf` filter;
 *     after selection, state machine moves to Locked.
 *
 * Dialog cancellation is a no-op (returns null from the plugin); we
 * stay on the welcome screen. Plugin-level errors surface via
 * `onError` as a toast.
 */
export function WelcomeScreen({ onOpen, onCreate, onError }: WelcomeScreenProps) {
  const [pending, setPending] = useState<'create' | 'open' | null>(null);

  const handleCreate = async () => {
    setPending('create');
    try {
      // Native save dialog. Returns null if the user cancels.
      const path = await saveDialog({
        title: 'Create new Pangolin vault',
        defaultPath: 'vault.pvf',
        filters: [{ name: 'Pangolin vault', extensions: ['pvf'] }],
      });
      if (path === null || path === undefined) {
        return; // cancelled — back to the welcome screen
      }
      await onCreate(path);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      onError?.(`Create vault failed: ${msg}`);
    } finally {
      setPending(null);
    }
  };

  const handleOpen = async () => {
    setPending('open');
    try {
      // Native open dialog. Returns string | null (single-selection).
      const path = await openDialog({
        title: 'Open Pangolin vault',
        multiple: false,
        directory: false,
        filters: [{ name: 'Pangolin vault', extensions: ['pvf'] }],
      });
      if (path === null || path === undefined) {
        return; // cancelled
      }
      if (typeof path !== 'string') {
        // Sanity guard: with `multiple: false` the plugin returns a
        // string | null. If it ever returns an array we don't want
        // to silently pick the first element.
        onError?.('Open vault: dialog returned unexpected shape');
        return;
      }
      await onOpen(path);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      onError?.(`Open vault failed: ${msg}`);
    } finally {
      setPending(null);
    }
  };

  return (
    <main className="welcome-screen" aria-labelledby="welcome-title">
      <Card elevation="md">
        <h1 id="welcome-title">Pangolin</h1>
        <p>Closed-beta password manager. Get started:</p>
        <div className="welcome-screen__actions" data-testid="welcome-actions">
          <Button
            variant="primary"
            onClick={() => void handleCreate()}
            disabled={pending !== null}
            data-testid="welcome-create-button"
          >
            {pending === 'create' ? 'Creating…' : 'Create new vault'}
          </Button>
          <Button
            variant="secondary"
            onClick={() => void handleOpen()}
            disabled={pending !== null}
            data-testid="welcome-open-button"
          >
            {pending === 'open' ? 'Opening…' : 'Open existing vault'}
          </Button>
        </div>
        <p className="welcome-screen__hint">
          Pangolin vaults are <code>.pvf</code> files on your local disk. New users:
          start with <strong>Create new vault</strong>; pick a folder, choose a master
          password, and the file lands on disk ready to unlock.
        </p>
      </Card>
    </main>
  );
}
