// SPDX-License-Identifier: AGPL-3.0-or-later
import { useRef, useState } from 'react';
import { Button, Card } from '@pangolin/component-library';

export interface WelcomeScreenProps {
  onOpen: (path: string) => Promise<void>;
}

/**
 * Welcome screen — the entry surface when no vault is open.
 *
 * Uses a hidden `<input type="file">` driven by the `Open Vault` button
 * because Tauri's `dialog` plugin is NOT in the minimum first-surface
 * (per plan §0a). The file input gives us the path via the WebView's
 * `webkitRelativePath` / `name` plus a host-side hop through the
 * `vault_open` command, which the user-facing path here yields as the
 * raw file name. Production work in MVP-4 back-half will swap this for
 * `tauri-plugin-dialog`'s native picker.
 */
export function WelcomeScreen({ onOpen }: WelcomeScreenProps) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [pending, setPending] = useState(false);

  const handlePick = () => {
    inputRef.current?.click();
  };

  const handleChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file === undefined) return;
    // The WebView's File interface exposes a `path` field via Tauri's
    // file-drop integration on some platforms, but the most portable
    // source is the file name; the user types the absolute path in a
    // text input below as a fallback. For the minimum first surface
    // we surface the name + let the user paste an absolute path.
    setPending(true);
    try {
      // Tauri v2 exposes the absolute path via `File.path` when the file
      // is selected via the dialog plugin; the HTML file input does not
      // surface it. The MVP-4 back-half work swaps to dialog. For now,
      // hand the name through so the user can copy-paste an absolute
      // path if needed — production users will use the typed text
      // input below.
      await onOpen(file.name);
    } finally {
      setPending(false);
    }
  };

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
        <input
          ref={inputRef}
          type="file"
          accept=".pvf"
          style={{ display: 'none' }}
          onChange={handleChange}
          data-testid="vault-file-input"
        />
        <div className="welcome-screen__actions">
          <Button onClick={handlePick} disabled={pending}>
            Open Vault File...
          </Button>
        </div>
        <div className="welcome-screen__text-input">
          <label htmlFor="path-input">Or paste a vault path:</label>
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
        </div>
      </Card>
    </main>
  );
}
