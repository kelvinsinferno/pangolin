// SPDX-License-Identifier: AGPL-3.0-or-later
import { type HTMLAttributes } from 'react';
import './Divider.css';

export type DividerOrientation = 'horizontal' | 'vertical';

export interface DividerProps extends HTMLAttributes<HTMLHRElement> {
  orientation?: DividerOrientation;
}

export function Divider({ orientation = 'horizontal', className, ...rest }: DividerProps) {
  const classes = [
    'pcl-divider',
    `pcl-divider--${orientation}`,
    className,
  ]
    .filter(Boolean)
    .join(' ');
  // <hr> has an implicit role of "separator" so we omit role= explicitly.
  return (
    <hr
      className={classes}
      aria-orientation={orientation}
      {...rest}
    />
  );
}
