// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Toast queue management hook.
 *
 * Wraps the @pangolin/component-library `Toast` (variant="danger" |
 * "warning" | "success"). Per MVP-4-B plan §0a, every typed FfiError
 * class except `AuthenticationFailed` becomes a danger toast at the
 * bottom-right; `AuthenticationFailed` is surfaced inline on the
 * unlock screen.
 *
 * The hook returns a small action set + the current toast list; the
 * `App` component is responsible for rendering the active toasts via
 * the component-library's `Toast`.
 */
import { useCallback, useState } from 'react';
import type { ToastVariant } from '@pangolin/component-library';

export interface ToastItem {
  id: number;
  variant: ToastVariant;
  message: string;
  /** Auto-dismiss duration in ms. 0 disables. */
  durationMs: number;
}

export interface ToastActions {
  push(item: Omit<ToastItem, 'id'>): void;
  danger(message: string): void;
  warning(message: string): void;
  success(message: string): void;
  dismiss(id: number): void;
}

let nextId = 1;

export function useToast(): { toasts: ToastItem[]; actions: ToastActions } {
  const [toasts, setToasts] = useState<ToastItem[]>([]);

  const push = useCallback((item: Omit<ToastItem, 'id'>) => {
    const id = nextId++;
    setToasts((prev) => [...prev, { ...item, id }]);
  }, []);

  const dismiss = useCallback((id: number) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const danger = useCallback(
    (message: string) => push({ variant: 'danger', message, durationMs: 4000 }),
    [push],
  );
  const warning = useCallback(
    (message: string) => push({ variant: 'warning', message, durationMs: 4000 }),
    [push],
  );
  const success = useCallback(
    (message: string) => push({ variant: 'success', message, durationMs: 4000 }),
    [push],
  );

  return {
    toasts,
    actions: { push, danger, warning, success, dismiss },
  };
}
