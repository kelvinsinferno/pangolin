// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { Badge } from './Badge';

describe('Badge', () => {
  it('renders its children', () => {
    render(<Badge>Beta</Badge>);
    expect(screen.getByText('Beta')).toBeInTheDocument();
  });

  it('applies the tone modifier class', () => {
    render(<Badge tone="danger">Locked</Badge>);
    expect(screen.getByText('Locked')).toHaveClass('pcl-badge--danger');
  });
});
