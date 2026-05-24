// SPDX-License-Identifier: AGPL-3.0-or-later
import { type HTMLAttributes, type ReactNode } from 'react';
import './Card.css';

export type CardElevation = 'none' | 'sm' | 'md' | 'lg';

export interface CardProps extends HTMLAttributes<HTMLDivElement> {
  elevation?: CardElevation;
  children: ReactNode;
}

export function Card({
  elevation = 'sm',
  className,
  children,
  ...rest
}: CardProps) {
  const classes = [
    'pcl-card',
    `pcl-card--elev-${elevation}`,
    className,
  ]
    .filter(Boolean)
    .join(' ');
  return (
    <div className={classes} {...rest}>
      {children}
    </div>
  );
}
