// SPDX-License-Identifier: AGPL-3.0-or-later
import type { SVGProps } from 'react';

export type ChevronDirection = 'up' | 'down' | 'left' | 'right';

export interface ChevronProps extends SVGProps<SVGSVGElement> {
  direction?: ChevronDirection;
}

const ROTATION: Record<ChevronDirection, number> = {
  down: 0,
  left: 90,
  up: 180,
  right: 270,
};

export function Chevron({ direction = 'down', style, ...rest }: ChevronProps) {
  const rotation = ROTATION[direction];
  return (
    <svg
      width="16"
      height="16"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
      style={{ transform: `rotate(${rotation}deg)`, ...style }}
      {...rest}
    >
      <polyline points="6 9 12 15 18 9" />
    </svg>
  );
}
