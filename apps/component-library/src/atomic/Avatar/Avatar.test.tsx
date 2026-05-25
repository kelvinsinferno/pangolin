// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { Avatar } from './Avatar';

describe('Avatar', () => {
  it('renders initials from a two-word name', () => {
    render(<Avatar name="Satoshi Nakamoto" />);
    expect(screen.getByRole('img', { name: 'Satoshi Nakamoto' })).toBeInTheDocument();
    expect(screen.getByText('SN')).toBeInTheDocument();
  });

  it('renders a fallback img when src is supplied', () => {
    render(<Avatar name="Alice" src="https://example.com/a.png" />);
    const img = screen.getByRole('img', { name: 'Alice' });
    expect(img).toHaveAttribute('src', 'https://example.com/a.png');
  });

  it('handles whitespace-only names without crashing', () => {
    render(<Avatar name="   " />);
    expect(screen.getByText('?')).toBeInTheDocument();
  });
});
