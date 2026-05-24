// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { ListRow } from './ListRow';

describe('ListRow', () => {
  it('renders title + subtitle', () => {
    render(<ListRow title="Wallet" subtitle="0xabc" />);
    expect(screen.getByText('Wallet')).toBeInTheDocument();
    expect(screen.getByText('0xabc')).toBeInTheDocument();
  });

  it('fires onClick when interactive', async () => {
    const onClick = vi.fn();
    render(<ListRow interactive title="Tap me" onClick={onClick} data-testid="row" />);
    await userEvent.click(screen.getByTestId('row'));
    expect(onClick).toHaveBeenCalledTimes(1);
  });
});
