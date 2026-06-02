// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * MVP-4-M L4: persistent "BETA · TESTNET" chip rendered unconditionally
 * over every screen. Independent of the one-shot warning modal — even
 * after dismissal the chip stays so the user is reminded on every
 * launch that they're not on a stable / mainnet build.
 *
 * Two render modes:
 *   - inline   (default): inserted into another component's layout
 *   - fixed    : positioned at the top-right of the viewport (used by
 *                the App root so the chip floats above all screens)
 */

export interface BetaChipProps {
  /** When true, the chip is fixed-positioned at top-right; otherwise it
   *  renders inline. Default false. */
  fixed?: boolean;
}

export function BetaChip({ fixed = false }: BetaChipProps): React.JSX.Element {
  const chip = (
    <span
      className="beta-chip"
      role="status"
      aria-label="Closed beta on Base Sepolia testnet"
      data-testid="beta-chip"
    >
      Beta · Testnet
    </span>
  );
  if (!fixed) return chip;
  return <div className="beta-chip__bar">{chip}</div>;
}
