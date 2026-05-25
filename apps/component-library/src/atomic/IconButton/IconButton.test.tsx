// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { IconButton } from './IconButton';
import { Copy } from '../../icons/Copy';

describe('IconButton', () => {
  it('renders with the supplied aria-label', () => {
    render(<IconButton aria-label="Copy address" icon={<Copy />} />);
    expect(screen.getByRole('button', { name: 'Copy address' })).toBeInTheDocument();
  });

  it('fires onClick when activated', async () => {
    const onClick = vi.fn();
    render(<IconButton aria-label="Tap" icon={<Copy />} onClick={onClick} />);
    await userEvent.click(screen.getByRole('button', { name: 'Tap' }));
    expect(onClick).toHaveBeenCalledTimes(1);
  });
});
