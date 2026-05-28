// SPDX-License-Identifier: AGPL-3.0-or-later
import { useState } from 'react';
import { Button } from '@pangolin/component-library';

import { base64ToBytes } from '../lib/base64';
import { CameraScan } from './CameraScan';

export interface CodeIngestProps {
  /** Prompt shown above the input (e.g. "Paste or scan device B's code"). */
  prompt: string;
  /** Receives the decoded bytes. May throw / reject to signal an invalid
   *  code — the thrown message is rendered inline so the wizard step does
   *  not advance. */
  onSubmit: (bytes: number[]) => Promise<void>;
  testId?: string;
}

/**
 * Pairing-blob ingest with three inputs that all funnel into `onSubmit`:
 * paste (base64 text), camera scan (decodes a QR to the same base64 text),
 * and — implicitly — inline validation feedback. Camera degrades to paste
 * when unavailable (L3). The bytes are non-secret transport blobs.
 */
export function CodeIngest({ prompt, onSubmit, testId }: CodeIngestProps) {
  const [text, setText] = useState('');
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (b64: string) => {
    setBusy(true);
    setError(null);
    try {
      const bytes = base64ToBytes(b64);
      await onSubmit(bytes);
    } catch (e) {
      const msg =
        e instanceof Error
          ? e.message
          : typeof (e as { message?: unknown })?.message === 'string'
            ? String((e as { message: unknown }).message)
            : 'that code is not valid';
      setError(msg);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="code-ingest" data-testid={testId}>
      <label className="code-ingest__label">
        {prompt}
        <textarea
          className="code-ingest__input"
          value={text}
          onChange={(e) => setText(e.target.value)}
          rows={3}
          spellCheck={false}
          autoComplete="off"
          data-testid="code-ingest-input"
        />
      </label>
      <div className="code-ingest__actions">
        <Button
          onClick={() => void submit(text)}
          disabled={busy || text.trim() === ''}
          data-testid="code-ingest-submit"
        >
          Use code
        </Button>
        <Button
          variant="ghost"
          onClick={() => setScanning((s) => !s)}
          data-testid="code-ingest-scan-toggle"
        >
          {scanning ? 'Stop camera' : 'Scan with camera'}
        </Button>
      </div>
      {scanning && (
        <CameraScan
          onResult={(t) => {
            setScanning(false);
            void submit(t);
          }}
          onUnavailable={(m) => setError(m)}
        />
      )}
      {error !== null && (
        <p className="code-ingest__error" role="alert" data-testid="code-ingest-error">
          {error}
        </p>
      )}
    </div>
  );
}
