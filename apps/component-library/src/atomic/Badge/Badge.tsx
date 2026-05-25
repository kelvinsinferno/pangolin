// SPDX-License-Identifier: AGPL-3.0-or-later
import { type HTMLAttributes, type ReactNode } from 'react';
import './Badge.css';

export type BadgeTone = 'neutral' | 'success' | 'warning' | 'danger' | 'accent';

export interface BadgeProps extends HTMLAttributes<HTMLSpanElement> {
  tone?: BadgeTone;
  children: ReactNode;
}

export function Badge({ tone = 'neutral', className, children, ...rest }: BadgeProps) {
  const classes = [
    'pcl-badge',
    `pcl-badge--${tone}`,
    className,
  ]
    .filter(Boolean)
    .join(' ');
  return (
    <span className={classes} {...rest}>
      {children}
    </span>
  );
}
