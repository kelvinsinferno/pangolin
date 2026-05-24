// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, screen, cleanup } from '@testing-library/react';
import { Popup } from './Popup';

describe('Popup', () => {
  let errorSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    cleanup();
    errorSpy.mockRestore();
  });

  it('renders the "Desktop not connected" status', () => {
    render(<Popup />);
    expect(screen.getByText('Desktop not connected')).toBeInTheDocument();
  });

  it('renders the placeholder action button', () => {
    render(<Popup />);
    const button = screen.getByRole('button', { name: /open pangolin/i });
    expect(button).toBeInTheDocument();
    expect(button).not.toBeDisabled();
  });

  it('renders without console.error', () => {
    render(<Popup />);
    expect(errorSpy).not.toHaveBeenCalled();
  });
});
