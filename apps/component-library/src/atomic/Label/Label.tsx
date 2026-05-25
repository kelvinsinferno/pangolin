// SPDX-License-Identifier: AGPL-3.0-or-later
import { type LabelHTMLAttributes } from 'react';
import './Label.css';

export interface LabelProps extends LabelHTMLAttributes<HTMLLabelElement> {
  /** When true, renders the muted-help variant (e.g. for hint text under a field). */
  muted?: boolean;
}

export function Label({ muted = false, className, children, ...rest }: LabelProps) {
  const classes = [
    'pcl-label',
    muted ? 'pcl-label--muted' : '',
    className,
  ]
    .filter(Boolean)
    .join(' ');
  return (
    <label className={classes} {...rest}>
      {children}
    </label>
  );
}
