// SPDX-License-Identifier: AGPL-3.0-or-later
import { useCallback } from 'react';
import { IconButton } from '../../atomic/IconButton/IconButton';
import { Copy } from '../../icons/Copy';
import './SeedPhraseGrid.css';

export interface SeedPhraseGridProps {
  /** The seed phrase words. Length must be 12 or 24. */
  words: string[];
  /** When true (default), each row exposes a Copy button. */
  showRowCopy?: boolean;
  /** Hook for the consumer's clipboard adapter — defaults to navigator.clipboard. */
  onCopy?: (text: string) => void;
}

export function SeedPhraseGrid({
  words,
  showRowCopy = true,
  onCopy,
}: SeedPhraseGridProps) {
  if (words.length !== 12 && words.length !== 24) {
    throw new Error(
      `SeedPhraseGrid: words.length must be 12 or 24, got ${words.length}`,
    );
  }

  const copyText = useCallback(
    (text: string) => {
      if (onCopy !== undefined) {
        onCopy(text);
        return;
      }
      if (typeof navigator !== 'undefined' && navigator.clipboard !== undefined) {
        void navigator.clipboard.writeText(text);
      }
    },
    [onCopy],
  );

  // Render 4 columns: 3 rows of 4 (12-word) or 6 rows of 4 (24-word).
  const rowCount = words.length / 4;
  const rows: string[][] = [];
  for (let r = 0; r < rowCount; r += 1) {
    const start = r * 4;
    const slice = words.slice(start, start + 4);
    rows.push(slice);
  }

  return (
    <div className="pcl-seed-grid" role="list">
      {rows.map((row, rowIdx) => (
        <div key={rowIdx} className="pcl-seed-grid__row" role="listitem">
          {row.map((word, colIdx) => {
            const index = rowIdx * 4 + colIdx + 1;
            return (
              <div key={colIdx} className="pcl-seed-grid__cell">
                <span className="pcl-seed-grid__num">{index}.</span>
                <span className="pcl-seed-grid__word">{word}</span>
              </div>
            );
          })}
          {showRowCopy && (
            <IconButton
              aria-label={`Copy row ${rowIdx + 1}`}
              icon={<Copy />}
              size="sm"
              onClick={() => copyText(row.join(' '))}
            />
          )}
        </div>
      ))}
    </div>
  );
}
