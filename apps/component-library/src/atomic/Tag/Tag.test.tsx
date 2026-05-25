// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Tag } from './Tag';

describe('Tag', () => {
  it('renders its label', () => {
    render(<Tag>base-sepolia</Tag>);
    expect(screen.getByText('base-sepolia')).toBeInTheDocument();
  });

  it('fires onRemove when the remove button is clicked', async () => {
    const onRemove = vi.fn();
    render(<Tag onRemove={onRemove}>delete-me</Tag>);
    await userEvent.click(screen.getByRole('button', { name: 'Remove' }));
    expect(onRemove).toHaveBeenCalledTimes(1);
  });
});
