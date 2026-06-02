// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';

import { BetaChip } from './BetaChip';

describe('BetaChip (MVP-4-M L4)', () => {
  it('renders inline by default with the BETA · TESTNET text', () => {
    const { container } = render(<BetaChip />);
    const chip = screen.getByTestId('beta-chip');
    expect(chip).toHaveTextContent(/beta/i);
    expect(chip).toHaveTextContent(/testnet/i);
    // Inline mode: chip is the root node, not wrapped in a positioning div.
    expect(container.querySelector('.beta-chip__bar')).toBeNull();
  });

  it('wraps in a fixed-positioned bar when fixed=true', () => {
    const { container } = render(<BetaChip fixed />);
    expect(container.querySelector('.beta-chip__bar')).not.toBeNull();
    expect(screen.getByTestId('beta-chip')).toBeInTheDocument();
  });

  it('exposes a screen-reader label naming the testnet posture', () => {
    render(<BetaChip />);
    expect(screen.getByTestId('beta-chip')).toHaveAttribute(
      'aria-label',
      'Closed beta on Base Sepolia testnet',
    );
  });
});
