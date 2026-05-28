// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect } from 'vitest';
import { base64ToBytes, bytesToBase64 } from './base64';

describe('base64 transport round-trip', () => {
  it('round-trips an arbitrary byte array', () => {
    const bytes = [0, 1, 2, 127, 128, 255, 42, 0xab];
    expect(base64ToBytes(bytesToBase64(bytes))).toEqual(bytes);
  });

  it('round-trips an empty array', () => {
    expect(base64ToBytes(bytesToBase64([]))).toEqual([]);
  });

  it('tolerates surrounding whitespace / newlines on decode', () => {
    const b64 = bytesToBase64([1, 2, 3, 4]);
    const wrapped = `  ${b64.slice(0, 2)}\n${b64.slice(2)}  `;
    expect(base64ToBytes(wrapped)).toEqual([1, 2, 3, 4]);
  });

  it('throws on non-base64 input', () => {
    expect(() => base64ToBytes('not valid !!!! base64 @@@')).toThrow();
  });
});
