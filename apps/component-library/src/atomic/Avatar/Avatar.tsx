// SPDX-License-Identifier: AGPL-3.0-or-later
import { type HTMLAttributes } from 'react';
import './Avatar.css';

export type AvatarSize = 'sm' | 'md' | 'lg';

export interface AvatarProps extends HTMLAttributes<HTMLSpanElement> {
  /** Display name; used to derive initials when no image is supplied. */
  name: string;
  /** Optional image URL. When set, replaces the initials fallback. */
  src?: string;
  size?: AvatarSize;
}

function initialsFor(name: string): string {
  const tokens = name
    .trim()
    .split(/\s+/)
    .filter((t) => t.length > 0);
  if (tokens.length === 0) {
    return '?';
  }
  if (tokens.length === 1) {
    const first = tokens[0];
    if (first === undefined) {
      return '?';
    }
    return first.slice(0, 2).toUpperCase();
  }
  const first = tokens[0];
  const last = tokens[tokens.length - 1];
  if (first === undefined || last === undefined) {
    return '?';
  }
  return (first.charAt(0) + last.charAt(0)).toUpperCase();
}

export function Avatar({ name, src, size = 'md', className, ...rest }: AvatarProps) {
  const classes = [
    'pcl-avatar',
    `pcl-avatar--${size}`,
    className,
  ]
    .filter(Boolean)
    .join(' ');
  if (src !== undefined && src.length > 0) {
    return (
      <span className={classes} {...rest}>
        <img src={src} alt={name} className="pcl-avatar__img" />
      </span>
    );
  }
  return (
    <span className={classes} role="img" aria-label={name} {...rest}>
      <span className="pcl-avatar__initials" aria-hidden="true">
        {initialsFor(name)}
      </span>
    </span>
  );
}
