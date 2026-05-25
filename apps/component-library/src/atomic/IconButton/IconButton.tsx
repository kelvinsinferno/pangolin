// SPDX-License-Identifier: AGPL-3.0-or-later
import { forwardRef, type ButtonHTMLAttributes, type ReactNode } from 'react';
import './IconButton.css';

export type IconButtonSize = 'sm' | 'md';

export interface IconButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  /** REQUIRED — accessible name for the icon-only button. */
  'aria-label': string;
  icon: ReactNode;
  size?: IconButtonSize;
}

export const IconButton = forwardRef<HTMLButtonElement, IconButtonProps>(function IconButton(
  { icon, size = 'md', className, type, ...rest },
  ref,
) {
  const classes = [
    'pcl-icon-button',
    `pcl-icon-button--${size}`,
    className,
  ]
    .filter(Boolean)
    .join(' ');
  return (
    <button ref={ref} type={type ?? 'button'} className={classes} {...rest}>
      <span aria-hidden="true">{icon}</span>
    </button>
  );
});
