// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Inline placeholder components for the MVP-4-C scaffold popup. These are
// deliberately minimal — they exist so the popup compiles + renders before
// MVP-4-D's @pangolin/component-library is wired in (MVP-4-F / MVP-4-G).
// Token-vars only; no hard-coded values.

import type { ReactNode, MouseEvent } from 'react';

export interface ButtonProps {
  children: ReactNode;
  onClick?: (event: MouseEvent<HTMLButtonElement>) => void;
  disabled?: boolean;
}

export function Button({ children, onClick, disabled }: ButtonProps) {
  return (
    <button
      type="button"
      className="pcl-placeholder-button"
      onClick={onClick}
      disabled={disabled === true}
    >
      {children}
    </button>
  );
}

export interface CardProps {
  children: ReactNode;
}

export function Card({ children }: CardProps) {
  return <div className="pcl-placeholder-card">{children}</div>;
}

export type TextVariant = 'heading' | 'body' | 'muted';

export interface TextProps {
  children: ReactNode;
  variant?: TextVariant;
}

export function Text({ children, variant = 'body' }: TextProps) {
  return (
    <p className={`pcl-placeholder-text pcl-placeholder-text-${variant}`}>
      {children}
    </p>
  );
}
