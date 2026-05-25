// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { PasswordMeter } from './PasswordMeter';

describe('PasswordMeter', () => {
  it('renders with role="meter" and exposes valuemin/max/now', () => {
    render(<PasswordMeter password="abc" />);
    const meter = screen.getByRole('meter', { name: 'Password strength' });
    expect(meter).toHaveAttribute('aria-valuemin', '0');
    expect(meter).toHaveAttribute('aria-valuemax', '4');
    expect(meter).toHaveAttribute('aria-valuenow', '0');
  });

  it('reports a stronger value for a longer mixed-charset password', () => {
    render(<PasswordMeter password="correct-horse-battery-staple-9!Q" />);
    const meter = screen.getByRole('meter');
    expect(Number(meter.getAttribute('aria-valuenow'))).toBeGreaterThanOrEqual(3);
  });

  it('handles empty password without crashing', () => {
    render(<PasswordMeter password="" />);
    expect(screen.getByRole('meter')).toHaveAttribute('aria-valuenow', '0');
  });
});
