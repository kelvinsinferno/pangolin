// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';

import { ExtensionBanner } from './ExtensionBanner';
import { nativeHostStatus } from '../lib/invoke';

vi.mock('../lib/invoke', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../lib/invoke')>();
  return {
    ...actual,
    nativeHostStatus: vi.fn(async () => ({
      connected: false,
      browsers: [],
    })),
  };
});

describe('ExtensionBanner (MVP-4-M L3)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(nativeHostStatus).mockResolvedValue({
      connected: false,
      browsers: [],
    });
  });

  it('shows the banner when no native-host manifest is installed', async () => {
    render(<ExtensionBanner onConfigure={() => {}} />);
    expect(await screen.findByTestId('extension-banner')).toBeInTheDocument();
  });

  it('hides the banner when native-host manifest is already installed', async () => {
    vi.mocked(nativeHostStatus).mockResolvedValue({
      connected: true,
      browsers: [
        {
          browser: 'chrome',
          manifestPath: '/home/u/.config/google-chrome/NativeMessagingHosts/studio.json',
          present: true,
        },
      ],
    });
    render(<ExtensionBanner onConfigure={() => {}} />);
    await waitFor(() => {
      expect(nativeHostStatus).toHaveBeenCalled();
    });
    expect(screen.queryByTestId('extension-banner')).not.toBeInTheDocument();
  });

  it('Configure button fires onConfigure', async () => {
    const onConfigure = vi.fn();
    render(<ExtensionBanner onConfigure={onConfigure} />);
    fireEvent.click(await screen.findByTestId('extension-banner-configure'));
    expect(onConfigure).toHaveBeenCalledTimes(1);
  });

  it('Maybe-later dismisses the banner for the rest of the session', async () => {
    render(<ExtensionBanner onConfigure={() => {}} />);
    fireEvent.click(await screen.findByTestId('extension-banner-dismiss'));
    expect(screen.queryByTestId('extension-banner')).not.toBeInTheDocument();
  });

  it('stays hidden if nativeHostStatus errors (safer than phantom banner)', async () => {
    vi.mocked(nativeHostStatus).mockRejectedValue(new Error('command not registered'));
    render(<ExtensionBanner onConfigure={() => {}} />);
    await waitFor(() => {
      expect(nativeHostStatus).toHaveBeenCalled();
    });
    expect(screen.queryByTestId('extension-banner')).not.toBeInTheDocument();
  });
});
