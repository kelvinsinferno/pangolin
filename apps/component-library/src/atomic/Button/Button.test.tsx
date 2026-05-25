// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Button } from './Button';

describe('Button', () => {
  it('renders its children', () => {
    render(<Button>Continue</Button>);
    expect(screen.getByRole('button', { name: 'Continue' })).toBeInTheDocument();
  });

  it('fires onClick when activated', async () => {
    const onClick = vi.fn();
    render(<Button onClick={onClick}>Tap me</Button>);
    await userEvent.click(screen.getByRole('button', { name: 'Tap me' }));
    expect(onClick).toHaveBeenCalledTimes(1);
  });

  it('does not fire onClick when disabled', async () => {
    const onClick = vi.fn();
    render(
      <Button onClick={onClick} disabled>
        Disabled
      </Button>,
    );
    await userEvent.click(screen.getByRole('button', { name: 'Disabled' }));
    expect(onClick).not.toHaveBeenCalled();
  });

  it('defaults to type="button" to avoid accidental form submission', () => {
    render(<Button>Default</Button>);
    expect(screen.getByRole('button', { name: 'Default' })).toHaveAttribute('type', 'button');
  });
});
