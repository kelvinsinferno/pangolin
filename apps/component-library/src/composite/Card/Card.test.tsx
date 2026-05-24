// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { Card } from './Card';

describe('Card', () => {
  it('renders its children', () => {
    render(<Card><p>hello</p></Card>);
    expect(screen.getByText('hello')).toBeInTheDocument();
  });

  it('applies the elevation modifier class', () => {
    const { container } = render(<Card elevation="lg">x</Card>);
    expect(container.firstChild).toHaveClass('pcl-card--elev-lg');
  });
});
