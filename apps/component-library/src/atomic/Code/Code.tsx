// SPDX-License-Identifier: AGPL-3.0-or-later
import { type HTMLAttributes, type ReactNode } from 'react';
import './Code.css';

export type CodeVariant = 'inline' | 'block';

export interface CodeProps extends HTMLAttributes<HTMLElement> {
  variant?: CodeVariant;
  children: ReactNode;
}

export function Code({ variant = 'inline', className, children, ...rest }: CodeProps) {
  const classes = [
    'pcl-code',
    `pcl-code--${variant}`,
    className,
  ]
    .filter(Boolean)
    .join(' ');
  if (variant === 'block') {
    return (
      <pre className={`${classes} pcl-code__pre`}>
        <code {...rest}>{children}</code>
      </pre>
    );
  }
  return (
    <code className={classes} {...rest}>
      {children}
    </code>
  );
}
