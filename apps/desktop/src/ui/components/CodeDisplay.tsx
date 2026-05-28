// SPDX-License-Identifier: AGPL-3.0-or-later
import { Button, Code, QRCode } from '@pangolin/component-library';

import { bytesToBase64 } from '../lib/base64';
import { copyToClipboard } from '../lib/invoke';

export interface CodeDisplayProps {
  /** The non-secret transport blob to display (QR + copy-paste base64). */
  bytes: number[];
  /** Accessible label for the QR symbol. */
  label: string;
}

/**
 * Show a pairing blob for the peer device to scan or copy. Renders a QR
 * of the base64 form + the base64 text + a Copy button. All non-secret
 * (a pairing payload / sealed envelope is exactly what a QR exposes).
 */
export function CodeDisplay({ bytes, label }: CodeDisplayProps) {
  const b64 = bytesToBase64(bytes);
  return (
    <div className="code-display">
      <QRCode value={b64} label={label} size={200} />
      <Code variant="block" data-testid="code-display-text">
        {b64}
      </Code>
      <Button
        variant="ghost"
        onClick={() => void copyToClipboard(b64)}
        data-testid="code-display-copy"
      >
        Copy code
      </Button>
    </div>
  );
}
