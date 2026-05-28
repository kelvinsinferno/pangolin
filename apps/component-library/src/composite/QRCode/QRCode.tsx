// SPDX-License-Identifier: AGPL-3.0-or-later
import { type HTMLAttributes } from 'react';
import qrcode from 'qrcode-generator';
import './QRCode.css';

export interface QRCodeProps extends Omit<HTMLAttributes<HTMLDivElement>, 'children'> {
  /** The string to encode. Pangolin pairing renders the base32
   *  `string_form` of a payload / sealed envelope so a scanner round-trips
   *  it back through `pairing_decode_string`. */
  value: string;
  /** Rendered edge length in px (the SVG is square). Default 200. */
  size?: number;
  /** Quiet-zone modules around the symbol (QR spec recommends ≥ 4).
   *  Default 4. */
  margin?: number;
  /** Accessible label for the symbol. Default "QR code". */
  label?: string;
}

/**
 * Render-only QR code. Encodes `value` with the dependency-light
 * `qrcode-generator` (error-correction level M, auto type-number) and
 * draws the module matrix as a single SVG `<path>` — no canvas, no
 * network, no innerHTML — so it renders identically under jsdom (tests),
 * Storybook, the Tauri webview, and the extension popup. Colors come from
 * the design tokens (`--color-text` on `--color-surface`).
 *
 * Camera SCANNING is NOT part of this component — that needs a webcam +
 * the host's camera capability and lives in the consuming app (MVP-4-I
 * desktop). This component is the display half only.
 */
export function QRCode({
  value,
  size = 200,
  margin = 4,
  label = 'QR code',
  className,
  ...rest
}: QRCodeProps) {
  const qr = qrcode(0, 'M');
  qr.addData(value, 'Byte');
  qr.make();
  const count = qr.getModuleCount();
  const total = count + margin * 2;

  // Build one path string for every dark module (1 unit = 1 module; the
  // SVG viewBox is `total` units wide so the rendered px size is set on
  // the element, keeping the path resolution-independent).
  let d = '';
  for (let row = 0; row < count; row += 1) {
    for (let col = 0; col < count; col += 1) {
      if (qr.isDark(row, col)) {
        const x = col + margin;
        const y = row + margin;
        d += `M${x} ${y}h1v1h-1z`;
      }
    }
  }

  const classes = ['pcl-qrcode', className].filter(Boolean).join(' ');

  return (
    <div className={classes} {...rest}>
      <svg
        className="pcl-qrcode__svg"
        role="img"
        aria-label={label}
        width={size}
        height={size}
        viewBox={`0 0 ${total} ${total}`}
        shapeRendering="crispEdges"
      >
        <rect width={total} height={total} className="pcl-qrcode__bg" />
        <path d={d} className="pcl-qrcode__fg" />
      </svg>
    </div>
  );
}
