// SPDX-License-Identifier: AGPL-3.0-or-later
import { useState } from 'react';
import { Button, Card } from '@pangolin/component-library';

export interface WelcomeScreenProps {
  onOpen: (path: string) => Promise<void>;
}

/**
 * Welcome screen — the entry surface when no vault is open.
 *
 * **No native file picker this slice.** The HTML `<input type="file">`
 * picker was dropped because the WebView's `File` interface does NOT
 * expose absolute paths in modern browsers (audit MEDIUM M-3 fix,
 * 2026-05-25); the resulting `file.name` is just the basename and the
 * Tauri `vault_open(path)` command requires an absolute path. The
 * proper fix is `tauri-plugin-dialog`'s native picker, which lands at
 * MVP-4-F as part of the back-half UX work.
 *
 * Until then: the user pastes the absolute path into the text input.
 * Closed-beta users typed paths in CLI flags anyway; this is a
 * temporary affordance that the MVP-4-F dialog plugin replaces with
 * the proper native picker.
 */
export function WelcomeScreen({ onOpen }: WelcomeScreenProps) {
  const [pending, setPending] = useState(false);
  const [pathDraft, setPathDraft] = useState('');

  const handleTextOpen = async () => {
    if (pathDraft.length === 0) return;
    setPending(true);
    try {
      await onOpen(pathDraft);
    } finally {
      setPending(false);
    }
  };

  return (
    <main className="welcome-screen" aria-labelledby="welcome-title">
      <Card elevation="md">
        <h1 id="welcome-title">Pangolin</h1>
        <p>Open a vault file to begin.</p>
        <div className="welcome-screen__text-input" data-testid="vault-file-picker">
          <label htmlFor="path-input">Vault file path:</label>
          <input
            id="path-input"
            type="text"
            value={pathDraft}
            onChange={(e) => setPathDraft(e.target.value)}
            placeholder="/absolute/path/to/vault.pvf"
            data-testid="vault-path-input"
          />
          <Button onClick={handleTextOpen} disabled={pending || pathDraft.length === 0}>
            Open
          </Button>
          <p className="welcome-screen__hint">
            A native file picker lands in a later update. For now, paste
            the absolute path to your <code>.pvf</code> vault file.
          </p>
        </div>
      </Card>
    </main>
  );
}
