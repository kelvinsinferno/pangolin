// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, test, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';

import { UnlockScreen } from './UnlockScreen';

/** MVP-4-H L3: the password input lives in the OS native widget, NOT
 *  in React. These tests verify the React-side state machine + the
 *  `onUnlock` contract (which has no arg post-migration). The native
 *  widget is invoked inside `onUnlock` — the unit tests stub `onUnlock`
 *  directly so we never actually open a dialog. */
describe('UnlockScreen', () => {
  test('renders the unlock button (no password field — native widget owns it)', () => {
    render(
      <UnlockScreen
        onUnlock={async () => ({ ok: true })}
        onClose={async () => {}}
      />,
    );
    expect(screen.getByTestId('unlock-button')).toBeInTheDocument();
    // The legacy `password-input` testid is GONE — React no longer
    // collects the password.
    expect(screen.queryByTestId('password-input')).not.toBeInTheDocument();
  });

  test('clicking Unlock fires onUnlock (no args — native widget collects the password)', async () => {
    const onUnlock = vi.fn(async () => ({ ok: true as const }));
    render(
      <UnlockScreen
        onUnlock={onUnlock}
        onClose={async () => {}}
      />,
    );
    fireEvent.click(screen.getByTestId('unlock-button'));
    await waitFor(() => {
      expect(onUnlock).toHaveBeenCalledWith();
    });
  });

  test('AuthenticationFailed renders inline error', async () => {
    render(
      <UnlockScreen
        onUnlock={async () => ({ ok: false, authenticationFailed: true })}
        onClose={async () => {}}
      />,
    );
    fireEvent.click(screen.getByTestId('unlock-button'));
    const inline = await screen.findByTestId('auth-failed-inline');
    expect(inline).toBeInTheDocument();
    expect(inline).toHaveAttribute('role', 'alert');
  });

  test('Successful unlock clears the auth-failed banner on retry', async () => {
    let attempt = 0;
    const onUnlock = vi.fn(async () => {
      attempt += 1;
      return attempt === 1
        ? ({ ok: false, authenticationFailed: true } as const)
        : ({ ok: true } as const);
    });
    render(
      <UnlockScreen
        onUnlock={onUnlock}
        onClose={async () => {}}
      />,
    );
    fireEvent.click(screen.getByTestId('unlock-button'));
    await screen.findByTestId('auth-failed-inline');
    fireEvent.click(screen.getByTestId('unlock-button'));
    await waitFor(() => {
      expect(screen.queryByTestId('auth-failed-inline')).not.toBeInTheDocument();
    });
  });

  test('button disables while onUnlock is in flight (Spinner shown)', async () => {
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
    fireEvent.click(screen.getByTestId('unlock-button'));
    await waitFor(() => {
      expect(screen.getByTestId('unlock-button')).toBeDisabled();
    });
    resolveUnlock({ ok: true });
  });
});
