// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';

import { CameraScan } from './CameraScan';

afterEach(() => {
  vi.restoreAllMocks();
});

describe('CameraScan', () => {
  it('reports unavailable + renders the paste fallback when there is no camera', async () => {
    Object.defineProperty(globalThis.navigator, 'mediaDevices', {
      value: undefined,
      configurable: true,
    });
    const onUnavailable = vi.fn();
    render(<CameraScan onResult={() => {}} onUnavailable={onUnavailable} />);
    await waitFor(() => {
      expect(onUnavailable).toHaveBeenCalled();
    });
    expect(screen.getByText(/Camera unavailable/i)).toBeInTheDocument();
  });

  it('stops the camera stream on unmount (no hot webcam left running)', async () => {
    const stop = vi.fn();
    const getUserMedia = vi.fn(async () => ({ getTracks: () => [{ stop }] }) as unknown as MediaStream);
    Object.defineProperty(globalThis.navigator, 'mediaDevices', {
      value: { getUserMedia },
      configurable: true,
    });
    const { unmount } = render(<CameraScan onResult={() => {}} />);
    await waitFor(() => {
      expect(getUserMedia).toHaveBeenCalled();
    });
    // Let the getUserMedia promise resolve + assign the stream.
    await Promise.resolve();
    await Promise.resolve();
    unmount();
    await waitFor(() => {
      expect(stop).toHaveBeenCalled();
    });
  });
});
