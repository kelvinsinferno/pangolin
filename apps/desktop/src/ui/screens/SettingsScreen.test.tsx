// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';

import { SettingsScreen } from './SettingsScreen';

// The BrowserConnectionPanel makes a `nativeHostStatus()` call on mount;
// stub it so the panel renders without errors when the test navigates
// into it.
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

describe('SettingsScreen (MVP-4-M L3)', () => {
  it('renders the index section list', () => {
    render(<SettingsScreen onClose={() => {}} onError={() => {}} />);
    expect(screen.getByText('Settings')).toBeInTheDocument();
    expect(screen.getByTestId('settings-open-browser-connection')).toBeInTheDocument();
  });

  it('navigates into the Browser connection panel when Configure is clicked', async () => {
    render(<SettingsScreen onClose={() => {}} onError={() => {}} />);
    fireEvent.click(screen.getByTestId('settings-open-browser-connection'));
    // The panel renders either form or status; both pull on the
    // nativeHostStatus mock which resolves async, so we await one of
    // the two stable test-ids.
    expect(await screen.findByTestId('browser-connection-form')).toBeInTheDocument();
  });

  it('Back fires onClose from the index view', () => {
    const onClose = vi.fn();
    render(<SettingsScreen onClose={onClose} onError={() => {}} />);
    fireEvent.click(screen.getByTestId('settings-back'));
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});
