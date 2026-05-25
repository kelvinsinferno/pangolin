// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { Label } from './Label';

describe('Label', () => {
  it('renders its text content', () => {
    render(<Label htmlFor="x">Hello</Label>);
    expect(screen.getByText('Hello')).toBeInTheDocument();
  });

  it('applies the muted modifier class when muted', () => {
    render(
      <Label htmlFor="x" muted>
        muted text
      </Label>,
    );
    expect(screen.getByText('muted text')).toHaveClass('pcl-label--muted');
  });
});
