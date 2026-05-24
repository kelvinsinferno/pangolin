// SPDX-License-Identifier: AGPL-3.0-or-later
import { useEffect, type ReactNode } from 'react';
import { Check } from '../../icons/Check';
import { Warning } from '../../icons/Warning';
import './Toast.css';

export type ToastVariant = 'success' | 'warning' | 'danger';

export interface ToastProps {
  variant?: ToastVariant;
  children: ReactNode;
  /** Milliseconds before auto-dismiss. Defaults to 4000. Set to 0 to disable. */
  durationMs?: number;
  onDismiss?: () => void;
}

const VARIANT_ICON: Record<ToastVariant, ReactNode> = {
  success: <Check />,
  warning: <Warning />,
  danger: <Warning />,
};

export function Toast({
  variant = 'success',
  children,
  durationMs = 4000,
  onDismiss,
}: ToastProps) {
  useEffect(() => {
    if (durationMs <= 0 || onDismiss === undefined) {
      return;
    }
    const handle = setTimeout(onDismiss, durationMs);
    return () => clearTimeout(handle);
  }, [durationMs, onDismiss]);

  const role = variant === 'danger' ? 'alert' : 'status';
  return (
    <div className={`pcl-toast pcl-toast--${variant}`} role={role}>
      <span className="pcl-toast__icon" aria-hidden="true">
        {VARIANT_ICON[variant]}
      </span>
      <span className="pcl-toast__body">{children}</span>
    </div>
  );
}
