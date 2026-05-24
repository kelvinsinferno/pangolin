// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { SeedPhraseGrid } from './SeedPhraseGrid';

const TWELVE = [
  'witch', 'collapse', 'practice', 'feed',
  'shame', 'open', 'despair', 'creek',
  'road', 'again', 'ice', 'least',
];

describe('SeedPhraseGrid', () => {
  it('renders all words for a 12-word phrase', () => {
    render(<SeedPhraseGrid words={TWELVE} />);
    for (const word of TWELVE) {
      expect(screen.getByText(word)).toBeInTheDocument();
    }
  });

  it('throws on unsupported lengths', () => {
    // Suppress React error-boundary console noise for this test.
    const spy = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    expect(() => render(<SeedPhraseGrid words={['a', 'b']} />)).toThrow();
    spy.mockRestore();
  });

  it('fires onCopy with the row text when the row copy button is clicked', async () => {
    const onCopy = vi.fn();
    render(<SeedPhraseGrid words={TWELVE} onCopy={onCopy} />);
    await userEvent.click(screen.getByRole('button', { name: 'Copy row 1' }));
    expect(onCopy).toHaveBeenCalledWith('witch collapse practice feed');
  });
});
