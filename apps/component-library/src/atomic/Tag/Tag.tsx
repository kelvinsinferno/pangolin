// SPDX-License-Identifier: AGPL-3.0-or-later
import { type HTMLAttributes, type ReactNode } from 'react';
import { X } from '../../icons/X';
import './Tag.css';

export interface TagProps extends HTMLAttributes<HTMLSpanElement> {
  children: ReactNode;
  /** When provided, renders a remove button on the right. */
  onRemove?: () => void;
  /** Accessible label for the remove button (defaults to "Remove"). */
  removeLabel?: string;
}

export function Tag({
  children,
  className,
  onRemove,
  removeLabel = 'Remove',
  ...rest
}: TagProps) {
  const classes = ['pcl-tag', className].filter(Boolean).join(' ');
  return (
    <span className={classes} {...rest}>
      <span className="pcl-tag__text">{children}</span>
      {onRemove !== undefined && (
        <button
          type="button"
          className="pcl-tag__remove"
          aria-label={removeLabel}
          onClick={onRemove}
        >
          <X />
        </button>
      )}
    </span>
  );
}
