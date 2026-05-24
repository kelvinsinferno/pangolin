// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { Divider } from './Divider';

describe('Divider', () => {
  it('renders with separator role (implicit on <hr>) and horizontal orientation by default', () => {
    render(<Divider data-testid="d" />);
    const sep = screen.getByTestId('d');
    expect(sep.tagName).toBe('HR');
    expect(sep).toHaveAttribute('aria-orientation', 'horizontal');
    // <hr> exposes role="separator" implicitly; testing-library's getByRole
    // confirms the accessibility-tree mapping.
    expect(screen.getByRole('separator')).toBe(sep);
  });

  it('renders vertical orientation when requested', () => {
    render(<Divider orientation="vertical" data-testid="d" />);
    expect(screen.getByTestId('d')).toHaveAttribute('aria-orientation', 'vertical');
  });
});
