// SPDX-License-Identifier: AGPL-3.0-or-later
import type { SVGProps } from 'react';

export function EyeOff(props: SVGProps<SVGSVGElement>) {
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
      {...props}
    >
      <path d="M9.88 5.09A10.6 10.6 0 0 1 12 5c6.5 0 10 7 10 7a17.6 17.6 0 0 1-3.16 4.19" />
      <path d="M6.61 6.61A17.6 17.6 0 0 0 2 12s3.5 7 10 7a10.6 10.6 0 0 0 5.39-1.61" />
      <path d="M9.9 9.9a3 3 0 0 0 4.2 4.2" />
      <path d="M2 2l20 20" />
    </svg>
  );
}
