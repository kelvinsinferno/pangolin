// SPDX-License-Identifier: AGPL-3.0-or-later
import { useState } from 'react';
import { describe, it, expect, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Modal } from './Modal';

describe('Modal', () => {
  it('does not render when closed', () => {
    render(
      <Modal open={false} onClose={() => undefined} title="Hidden">
        <p>body</p>
      </Modal>,
    );
    expect(screen.queryByRole('dialog')).toBeNull();
  });

  it('renders with role="dialog" + aria-modal + labelled by title', () => {
    render(
      <Modal open onClose={() => undefined} title="Confirm">
        <p>body</p>
      </Modal>,
    );
    const dialog = screen.getByRole('dialog');
    expect(dialog).toHaveAttribute('aria-modal', 'true');
    const titleId = dialog.getAttribute('aria-labelledby');
    expect(titleId).not.toBeNull();
    expect(screen.getByText('Confirm').id).toBe(titleId);
  });

  it('calls onClose when Escape is pressed', async () => {
    const onClose = vi.fn();
    render(
      <Modal open onClose={onClose} title="Confirm">
        <p>body</p>
      </Modal>,
    );
    await userEvent.keyboard('{Escape}');
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('calls onClose when the backdrop is clicked', async () => {
    const onClose = vi.fn();
    render(
      <Modal open onClose={onClose} title="Confirm">
        <p>body</p>
      </Modal>,
    );
    await userEvent.click(screen.getByTestId('pcl-modal-backdrop'));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  /**
   * Audit MEDIUM M3 regression gate. The Modal MUST restore focus to
   * the trigger element when it closes — without this, keyboard +
   * screen-reader users lose their place every time a dialog dismisses.
   *
   * Drives a realistic open/close cycle through a stateful parent (the
   * common consumer shape) so the inline `onClose={() => setOpen(false)}`
   * identity churns each render. The Modal effect's `onCloseRef` +
   * `[open]`-only deps must absorb that churn without re-snapshotting
   * the focus target (audit M2 — the previous `[open, onClose]` deps
   * regression).
   */
  it('restores focus to the trigger when closed', async () => {
    const user = userEvent.setup();

    function TriggerHarness() {
      const [open, setOpen] = useState(false);
      return (
        <>
          <button type="button" data-testid="trigger" onClick={() => setOpen(true)}>
            Open dialog
          </button>
          <Modal open={open} onClose={() => setOpen(false)} title="Confirm">
            <p>body</p>
          </Modal>
        </>
      );
    }

    render(<TriggerHarness />);
    const trigger = screen.getByTestId('trigger');
    trigger.focus();
    expect(document.activeElement).toBe(trigger);

    await user.click(trigger);
    expect(await screen.findByRole('dialog')).toBeInTheDocument();

    await user.keyboard('{Escape}');
    await waitFor(() => {
      expect(screen.queryByRole('dialog')).toBeNull();
    });
    await waitFor(() => {
      expect(document.activeElement).toBe(trigger);
    });
  });

  /**
   * Audit MEDIUM M3 regression gate. The Modal MUST trap Tab + Shift+Tab
   * focus inside the dialog while open — keyboard users cannot escape
   * the dialog by Tab-ing past the last focusable; Shift+Tab from the
   * first wraps back to the last.
   *
   * The Modal renders the Close (X) IconButton as the first focusable,
   * then the body's button as the next. Tab from Close lands on the
   * body button; Tab from the body button wraps back to Close.
   * Shift+Tab from Close wraps to the body button.
   */
  it('traps Tab + Shift+Tab focus inside the dialog', async () => {
    const user = userEvent.setup();
    render(
      <Modal open onClose={() => undefined} title="Confirm">
        <button type="button" data-testid="body-button">
          Body action
        </button>
      </Modal>,
    );

    // Wait for the dialog to land focus on the first focusable
    // (the Close IconButton — the queueMicrotask deferred-focus call).
    const close = screen.getByRole('button', { name: 'Close' });
    const body = screen.getByTestId('body-button');
    await waitFor(() => {
      expect(document.activeElement).toBe(close);
    });

    // Tab forward → body button.
    await user.tab();
    expect(document.activeElement).toBe(body);

    // Tab forward from last → wraps back to Close.
    await user.tab();
    expect(document.activeElement).toBe(close);

    // Shift+Tab from first → wraps to last (body button).
    await user.tab({ shift: true });
    expect(document.activeElement).toBe(body);
  });
});
