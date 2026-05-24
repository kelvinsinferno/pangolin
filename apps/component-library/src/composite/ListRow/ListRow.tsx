// SPDX-License-Identifier: AGPL-3.0-or-later
import { type HTMLAttributes, type ReactNode } from 'react';
import './ListRow.css';

export interface ListRowProps extends Omit<HTMLAttributes<HTMLDivElement>, 'title'> {
  icon?: ReactNode;
  title: ReactNode;
  subtitle?: ReactNode;
  /** Right-rail action slot (button, badge, icon, etc.). */
  rightAction?: ReactNode;
  /** When true, the row gets a hover affordance and pointer cursor. */
  interactive?: boolean;
}

export function ListRow({
  icon,
  title,
  subtitle,
  rightAction,
  interactive = false,
  className,
  ...rest
}: ListRowProps) {
  const classes = [
    'pcl-list-row',
    interactive ? 'pcl-list-row--interactive' : '',
    className,
  ]
    .filter(Boolean)
    .join(' ');
  return (
    <div className={classes} {...rest}>
      {icon !== undefined && (
        <span className="pcl-list-row__icon" aria-hidden="true">
          {icon}
        </span>
      )}
      <div className="pcl-list-row__text">
        <div className="pcl-list-row__title">{title}</div>
        {subtitle !== undefined && (
          <div className="pcl-list-row__subtitle">{subtitle}</div>
        )}
      </div>
      {rightAction !== undefined && (
        <div className="pcl-list-row__right">{rightAction}</div>
      )}
    </div>
  );
}
