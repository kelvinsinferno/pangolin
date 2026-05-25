// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { Toast } from './Toast';

describe('Toast', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it('renders success variant with role="status"', () => {
    render(<Toast variant="success">Saved.</Toast>);
    expect(screen.getByRole('status')).toHaveTextContent('Saved.');
  });

  it('renders danger variant with role="alert"', () => {
    render(<Toast variant="danger">Failed.</Toast>);
    expect(screen.getByRole('alert')).toHaveTextContent('Failed.');
  });

  it('fires onDismiss after durationMs', () => {
    const onDismiss = vi.fn();
    render(<Toast durationMs={1000} onDismiss={onDismiss}>x</Toast>);
    expect(onDismiss).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1000);
    expect(onDismiss).toHaveBeenCalledTimes(1);
  });

  it('does NOT auto-dismiss when durationMs is 0', () => {
    const onDismiss = vi.fn();
    render(<Toast durationMs={0} onDismiss={onDismiss}>x</Toast>);
    vi.advanceTimersByTime(10000);
    expect(onDismiss).not.toHaveBeenCalled();
  });
});
