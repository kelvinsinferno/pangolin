// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';

import { BrowserConnectionPanel } from './BrowserConnectionPanel';
import {
  installNativeHost,
  nativeHostStatus,
  uninstallNativeHost,
} from '../lib/invoke';

vi.mock('../lib/invoke', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../lib/invoke')>();
  return {
    ...actual,
    nativeHostStatus: vi.fn(async () => ({
      connected: false,
      browsers: [
        { browser: 'chrome', manifestPath: '/chrome.json', present: false },
        { browser: 'brave', manifestPath: '/brave.json', present: false },
      ],
    })),
    installNativeHost: vi.fn(async () => {}),
    uninstallNativeHost: vi.fn(async () => {}),
  };
});

describe('BrowserConnectionPanel (MVP-4-M L3)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(nativeHostStatus).mockResolvedValue({
      connected: false,
      browsers: [
        { browser: 'chrome', manifestPath: '/chrome.json', present: false },
        { browser: 'brave', manifestPath: '/brave.json', present: false },
      ],
    });
    vi.mocked(installNativeHost).mockResolvedValue(undefined);
    vi.mocked(uninstallNativeHost).mockResolvedValue(undefined);
  });

  it('shows the connect form when no manifest is installed', async () => {
    render(<BrowserConnectionPanel onClose={() => {}} onError={() => {}} />);
    expect(await screen.findByTestId('browser-connection-form')).toBeInTheDocument();
    expect(screen.getByTestId('extension-id-input')).toBeInTheDocument();
    expect(screen.getByTestId('binary-path-input')).toBeInTheDocument();
  });

  it('shows the connected status + disconnect button when manifest exists', async () => {
    vi.mocked(nativeHostStatus).mockResolvedValue({
      connected: true,
      browsers: [
        { browser: 'chrome', manifestPath: '/chrome.json', present: true },
        { browser: 'brave', manifestPath: '/brave.json', present: false },
      ],
    });
    render(<BrowserConnectionPanel onClose={() => {}} onError={() => {}} />);
    expect(await screen.findByTestId('browser-connection-status-connected')).toBeInTheDocument();
    expect(screen.getByTestId('browser-connection-disconnect')).toBeInTheDocument();
    // Only present browsers should be listed.
    expect(screen.getByText('chrome')).toBeInTheDocument();
    expect(screen.queryByText('brave')).not.toBeInTheDocument();
  });

  it('Connect button disabled until both fields are non-empty', async () => {
    render(<BrowserConnectionPanel onClose={() => {}} onError={() => {}} />);
    const connect = await screen.findByTestId('browser-connection-connect');
    // binaryPath is pre-filled from defaultBinaryPath() so initial state
    // is "ext ID empty, binary path filled" -> button disabled.
    expect(connect).toBeDisabled();
    fireEvent.change(screen.getByTestId('extension-id-input'), {
      target: { value: 'abcdefghijklmnopabcdefghijklmnop' },
    });
    expect(connect).not.toBeDisabled();
  });

  it('Connect calls installNativeHost with both fields trimmed', async () => {
    render(<BrowserConnectionPanel onClose={() => {}} onError={() => {}} />);
    fireEvent.change(await screen.findByTestId('extension-id-input'), {
      target: { value: '  abcdefghijklmnopabcdefghijklmnop  ' },
    });
    fireEvent.change(screen.getByTestId('binary-path-input'), {
      target: { value: '  /my/path  ' },
    });
    fireEvent.click(screen.getByTestId('browser-connection-connect'));
    await waitFor(() => {
      expect(installNativeHost).toHaveBeenCalledWith(
        '/my/path',
        'abcdefghijklmnopabcdefghijklmnop',
      );
    });
  });

  it('surfaces Validation errors inline (not via toast)', async () => {
    vi.mocked(installNativeHost).mockRejectedValue({
      kind: 'Validation',
      message: 'extension ID must be exactly 32 characters (got 3)',
    });
    const onError = vi.fn();
    render(<BrowserConnectionPanel onClose={() => {}} onError={onError} />);
    fireEvent.change(await screen.findByTestId('extension-id-input'), {
      target: { value: 'abc' },
    });
    fireEvent.click(screen.getByTestId('browser-connection-connect'));
    await waitFor(() => {
      expect(screen.getByTestId('browser-connection-error')).toHaveTextContent(
        /must be exactly 32 characters/,
      );
    });
    expect(onError).not.toHaveBeenCalled();
  });

  it('surfaces non-Validation errors via the onError callback', async () => {
    vi.mocked(installNativeHost).mockRejectedValue({
      kind: 'Internal',
      message: 'file not found',
    });
    const onError = vi.fn();
    render(<BrowserConnectionPanel onClose={() => {}} onError={onError} />);
    fireEvent.change(await screen.findByTestId('extension-id-input'), {
      target: { value: 'abcdefghijklmnopabcdefghijklmnop' },
    });
    fireEvent.click(screen.getByTestId('browser-connection-connect'));
    await waitFor(() => {
      expect(onError).toHaveBeenCalledWith(expect.stringContaining('file not found'));
    });
  });

  it('Disconnect calls uninstallNativeHost', async () => {
    vi.mocked(nativeHostStatus).mockResolvedValue({
      connected: true,
      browsers: [{ browser: 'chrome', manifestPath: '/chrome.json', present: true }],
    });
    render(<BrowserConnectionPanel onClose={() => {}} onError={() => {}} />);
    fireEvent.click(await screen.findByTestId('browser-connection-disconnect'));
    await waitFor(() => {
      expect(uninstallNativeHost).toHaveBeenCalledTimes(1);
    });
  });

  it('Back button fires onClose', async () => {
    const onClose = vi.fn();
    render(<BrowserConnectionPanel onClose={onClose} onError={() => {}} />);
    fireEvent.click(await screen.findByTestId('browser-connection-back'));
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});
