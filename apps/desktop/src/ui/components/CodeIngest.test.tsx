// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';

import { CodeIngest } from './CodeIngest';
import { bytesToBase64 } from '../lib/base64';

describe('CodeIngest', () => {
  beforeEach(() => {
    // Default: no camera in jsdom — the scan path must degrade to paste.
    Object.defineProperty(globalThis.navigator, 'mediaDevices', {
      value: undefined,
      configurable: true,
    });
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('decodes a pasted base64 code and calls onSubmit with the bytes', async () => {
    const onSubmit = vi.fn(async () => {});
    render(<CodeIngest prompt="Paste it" onSubmit={onSubmit} />);
    const input = screen.getByTestId('code-ingest-input');
    fireEvent.change(input, { target: { value: bytesToBase64([10, 20, 30]) } });
    fireEvent.click(screen.getByTestId('code-ingest-submit'));
    await waitFor(() => {
      expect(onSubmit).toHaveBeenCalledWith([10, 20, 30]);
    });
  });

  it('shows an inline error when onSubmit rejects (invalid payload)', async () => {
    const onSubmit = vi.fn(async () => {
      throw new Error('that code is not a valid payload');
    });
    render(<CodeIngest prompt="Paste it" onSubmit={onSubmit} />);
    fireEvent.change(screen.getByTestId('code-ingest-input'), {
      target: { value: bytesToBase64([1, 2, 3]) },
    });
    fireEvent.click(screen.getByTestId('code-ingest-submit'));
    await waitFor(() => {
      expect(screen.getByTestId('code-ingest-error')).toHaveTextContent(
        'that code is not a valid payload',
      );
    });
  });

  it('shows an inline error on non-base64 paste (does not call onSubmit)', async () => {
    const onSubmit = vi.fn(async () => {});
    render(<CodeIngest prompt="Paste it" onSubmit={onSubmit} />);
    fireEvent.change(screen.getByTestId('code-ingest-input'), {
      target: { value: '!!! definitely not base64 @@@' },
    });
    fireEvent.click(screen.getByTestId('code-ingest-submit'));
    await waitFor(() => {
      expect(screen.getByTestId('code-ingest-error')).toBeInTheDocument();
    });
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it('falls back to paste when the camera is unavailable', async () => {
    render(<CodeIngest prompt="Paste it" onSubmit={async () => {}} />);
    fireEvent.click(screen.getByTestId('code-ingest-scan-toggle'));
    await waitFor(() => {
      expect(screen.getByText(/Camera unavailable/i)).toBeInTheDocument();
    });
  });
});
