// SPDX-License-Identifier: AGPL-3.0-or-later
import type { SVGProps } from 'react';

export function Check(props: SVGProps<SVGSVGElement>) {
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
      <path d="M20 6L9 17l-5-5" />
    </svg>
  );
}
