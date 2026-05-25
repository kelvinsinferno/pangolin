// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, test, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';

import { UnlockScreen } from './UnlockScreen';

describe('UnlockScreen', () => {
  test('renders the password field + an unlock button', () => {
    render(
      <UnlockScreen
        onUnlock={async () => ({ ok: true })}
        onClose={async () => {}}
      />,
    );
    expect(screen.getByTestId('password-input')).toBeInTheDocument();
    expect(screen.getByTestId('unlock-button')).toBeInTheDocument();
  });

  test('typed password fires onUnlock with the value', async () => {
    const onUnlock = vi.fn(async () => ({ ok: true as const }));
    render(
      <UnlockScreen
        onUnlock={onUnlock}
        onClose={async () => {}}
      />,
    );
    const input = screen.getByTestId('password-input') as HTMLInputElement;
    fireEvent.change(input, { target: { value: 'hunter2' } });
    fireEvent.click(screen.getByTestId('unlock-button'));
    await waitFor(() => {
      expect(onUnlock).toHaveBeenCalledWith('hunter2');
    });
  });

  test('AuthenticationFailed renders inline error under the password field', async () => {
    render(
      <UnlockScreen
        onUnlock={async () => ({ ok: false, authenticationFailed: true })}
        onClose={async () => {}}
      />,
    );
    const input = screen.getByTestId('password-input') as HTMLInputElement;
    fireEvent.change(input, { target: { value: 'wrong' } });
    fireEvent.click(screen.getByTestId('unlock-button'));
    const inline = await screen.findByTestId('auth-failed-inline');
    expect(inline).toBeInTheDocument();
    expect(inline).toHaveAttribute('role', 'alert');
    // The password field gets aria-invalid + aria-describedby.
    expect(input).toHaveAttribute('aria-invalid', 'true');
  });

  test('disables the Unlock button while pending', async () => {
    let resolveUnlock: (r: { ok: true }) => void = () => {};
    const onUnlock = vi.fn(
      () =>
        new Promise<{ ok: true }>((resolve) => {
          resolveUnlock = resolve;
        }),
    );
    render(
      <UnlockScreen
        onUnlock={onUnlock}
        onClose={async () => {}}
      />,
    );
    fireEvent.change(screen.getByTestId('password-input'), { target: { value: 'x' } });
    fireEvent.click(screen.getByTestId('unlock-button'));
    await waitFor(() => {
      expect(screen.getByTestId('unlock-button')).toBeDisabled();
    });
    resolveUnlock({ ok: true });
  });

  test('Unlock button stays disabled on empty password', () => {
    render(
      <UnlockScreen
        onUnlock={async () => ({ ok: true })}
        onClose={async () => {}}
      />,
    );
    expect(screen.getByTestId('unlock-button')).toBeDisabled();
  });
});
