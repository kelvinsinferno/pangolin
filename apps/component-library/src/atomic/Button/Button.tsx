// SPDX-License-Identifier: AGPL-3.0-or-later
import { forwardRef, type ButtonHTMLAttributes, type ReactNode } from 'react';
import './Button.css';

export type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger';
export type ButtonSize = 'sm' | 'md';

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  /** Optional element rendered to the left of the children (typically an icon). */
  leadingIcon?: ReactNode;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { variant = 'primary', size = 'md', leadingIcon, className, children, type, ...rest },
  ref,
) {
  const classes = [
    'pcl-button',
    `pcl-button--${variant}`,
    `pcl-button--${size}`,
    className,
  ]
    .filter(Boolean)
    .join(' ');
  return (
    <button
      ref={ref}
      type={type ?? 'button'}
      className={classes}
      {...rest}
    >
      {leadingIcon !== undefined && (
        <span className="pcl-button__icon" aria-hidden="true">
          {leadingIcon}
        </span>
      )}
      <span className="pcl-button__label">{children}</span>
    </button>
  );
});
