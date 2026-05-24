// SPDX-License-Identifier: AGPL-3.0-or-later
import { useEffect, useId, useRef, type ReactNode } from 'react';
import { createPortal } from 'react-dom';
import { IconButton } from '../../atomic/IconButton/IconButton';
import { X } from '../../icons/X';
import './Modal.css';

export interface ModalProps {
  open: boolean;
  onClose: () => void;
  /** Accessible title — rendered in the header and used as aria-labelledby. */
  title: ReactNode;
  children: ReactNode;
  /** When false, clicking the backdrop will NOT close the modal. Defaults true. */
  closeOnBackdropClick?: boolean;
}

const FOCUSABLE_SELECTOR =
  'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

export function Modal({
  open,
  onClose,
  title,
  children,
  closeOnBackdropClick = true,
}: ModalProps) {
  const titleId = useId();
  const dialogRef = useRef<HTMLDivElement | null>(null);
  const lastActiveElementRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (!open) {
      return;
    }
    // Remember the element to restore focus to.
    lastActiveElementRef.current = document.activeElement as HTMLElement | null;

    const handleKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.stopPropagation();
        onClose();
        return;
      }
      if (e.key === 'Tab' && dialogRef.current !== null) {
        const focusables = Array.from(
          dialogRef.current.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR),
        ).filter((el) => !el.hasAttribute('aria-hidden'));
        if (focusables.length === 0) {
          e.preventDefault();
          return;
        }
        const first = focusables[0];
        const last = focusables[focusables.length - 1];
        if (first === undefined || last === undefined) {
          return;
        }
        const active = document.activeElement as HTMLElement | null;
        if (e.shiftKey && active === first) {
          e.preventDefault();
          last.focus();
        } else if (!e.shiftKey && active === last) {
          e.preventDefault();
          first.focus();
        }
      }
    };

    window.addEventListener('keydown', handleKey);

    // Move focus into the dialog (close button as default landing).
    queueMicrotask(() => {
      if (dialogRef.current === null) {
        return;
      }
      const focusables = dialogRef.current.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR);
      const first = focusables[0];
      if (first !== undefined) {
        first.focus();
      } else {
        dialogRef.current.focus();
      }
    });

    return () => {
      window.removeEventListener('keydown', handleKey);
      // Restore focus.
      const prev = lastActiveElementRef.current;
      if (prev !== null && typeof prev.focus === 'function') {
        prev.focus();
      }
    };
  }, [open, onClose]);

  if (!open) {
    return null;
  }

  // The backdrop is a presentational overlay. We attach a click handler
  // so clicking outside the dialog dismisses it (when allowed), but the
  // keyboard-equivalent path is already covered by the global Escape
  // listener installed above — so the lint rule's "must have a keyboard
  // listener" requirement is satisfied at the application layer.
  return createPortal(
    <div
      className="pcl-modal__backdrop"
      role="presentation"
      onClick={() => {
        if (closeOnBackdropClick) {
          onClose();
        }
      }}
      data-testid="pcl-modal-backdrop"
    >
      {/* eslint-disable-next-line jsx-a11y/no-noninteractive-element-interactions, jsx-a11y/click-events-have-key-events --
          The dialog is keyboard-operable via the focus-trap + Escape handler
          installed in the effect above; the onClick here is solely to stop
          backdrop-click propagation when the user clicks inside the dialog. */}
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        className="pcl-modal"
        tabIndex={-1}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="pcl-modal__header">
          <h2 id={titleId} className="pcl-modal__title">
            {title}
          </h2>
          <IconButton aria-label="Close" icon={<X />} onClick={onClose} size="sm" />
        </div>
        <div className="pcl-modal__body">{children}</div>
      </div>
    </div>,
    document.body,
  );
}
