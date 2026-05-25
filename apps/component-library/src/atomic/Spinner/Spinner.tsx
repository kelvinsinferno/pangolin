// SPDX-License-Identifier: AGPL-3.0-or-later
import { type HTMLAttributes } from 'react';
import './Spinner.css';

export type SpinnerSize = 'sm' | 'md' | 'lg';

export interface SpinnerProps extends HTMLAttributes<HTMLSpanElement> {
  size?: SpinnerSize;
  /** Accessible name. Defaults to "Loading". */
  label?: string;
}

export function Spinner({
  size = 'md',
  label = 'Loading',
  className,
  ...rest
}: SpinnerProps) {
  const classes = [
    'pcl-spinner',
    `pcl-spinner--${size}`,
    className,
  ]
    .filter(Boolean)
    .join(' ');
  return (
    <span
      className={classes}
      role="status"
      aria-live="polite"
      aria-label={label}
      {...rest}
    >
      <span className="pcl-spinner__ring" aria-hidden="true" />
    </span>
  );
}
