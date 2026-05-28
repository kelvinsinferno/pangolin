// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Base64 round-trip for the pairing transport blobs.
 *
 * The pairing payloads + the sealed VDK envelope cross between devices as
 * raw bytes. The frontend moves them as base64 text — what the QR encodes,
 * what the Copy button copies, and what the paste/camera ingest decodes —
 * so a single uniform string form covers both the copy-paste and the
 * QR/scan channels without needing an engine-side string decoder for the
 * envelope. These blobs are NON-secret (the payload is what a QR exposes;
 * the envelope is sealed to the recipient's pubkey).
 *
 * `btoa`/`atob` are available in the Tauri webview, jsdom (tests), and
 * Node 20 — no polyfill needed.
 */

/** Encode a byte array as standard base64. */
export function bytesToBase64(bytes: number[]): string {
  let binary = '';
  for (const b of bytes) {
    binary += String.fromCharCode(b & 0xff);
  }
  return btoa(binary);
}

/**
 * Decode base64 (tolerating surrounding whitespace) back to a byte array.
 * Throws `Error` on non-base64 input so the ingest UI can surface an
 * inline "that doesn't look like a valid code" message.
 */
export function base64ToBytes(text: string): number[] {
  const cleaned = text.replace(/\s+/g, '');
  let binary: string;
  try {
    binary = atob(cleaned);
  } catch {
    throw new Error('not valid base64');
  }
  const out: number[] = new Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}
