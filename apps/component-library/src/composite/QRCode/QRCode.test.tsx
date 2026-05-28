// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { QRCode } from './QRCode';

describe('QRCode', () => {
  it('renders an accessible SVG image with the default label', () => {
    render(<QRCode value="hello" />);
    const svg = screen.getByRole('img', { name: 'QR code' });
    expect(svg.tagName.toLowerCase()).toBe('svg');
  });

  it('honors a custom label + size', () => {
    render(<QRCode value="hello" size={120} label="Pairing QR" />);
    const svg = screen.getByRole('img', { name: 'Pairing QR' });
    expect(svg.getAttribute('width')).toBe('120');
    expect(svg.getAttribute('height')).toBe('120');
  });

  it('encodes data into a non-empty module path', () => {
    const { container } = render(<QRCode value="pangolin-pairing-payload" />);
    const path = container.querySelector('path.pcl-qrcode__fg');
    expect(path).not.toBeNull();
    // A non-trivial payload always produces at least one dark module.
    expect((path?.getAttribute('d') ?? '').length).toBeGreaterThan(0);
  });

  it('produces a larger module matrix for a longer payload', () => {
    const short = render(<QRCode value="a" />);
    const shortBox = short.container
      .querySelector('svg')
      ?.getAttribute('viewBox');
    short.unmount();
    const long = render(<QRCode value={'a'.repeat(300)} />);
    const longBox = long.container.querySelector('svg')?.getAttribute('viewBox');
    // viewBox is `0 0 N N` where N grows with the QR type-number.
    const shortN = Number((shortBox ?? '0 0 0 0').split(' ')[2]);
    const longN = Number((longBox ?? '0 0 0 0').split(' ')[2]);
    expect(longN).toBeGreaterThan(shortN);
  });
});
