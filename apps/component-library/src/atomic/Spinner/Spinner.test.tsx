// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { Spinner } from './Spinner';

describe('Spinner', () => {
  it('renders with the default "Loading" accessible name', () => {
    render(<Spinner />);
    expect(screen.getByRole('status', { name: 'Loading' })).toBeInTheDocument();
  });

  it('honours a custom label', () => {
    render(<Spinner label="Syncing chain state" />);
    expect(screen.getByRole('status', { name: 'Syncing chain state' })).toBeInTheDocument();
  });
});
