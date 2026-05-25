// SPDX-License-Identifier: AGPL-3.0-or-later
import { useMemo } from 'react';
import './PasswordMeter.css';

export interface PasswordMeterProps {
  /** The candidate password. NOT retained across renders. */
  password: string;
  /** Optional accessible label override. */
  label?: string;
}

export type PasswordStrength = 0 | 1 | 2 | 3 | 4;

/** Rough Shannon-style entropy estimator: bits ≈ log2(charsetSize) * length.
 *  No external dep. Good enough for a visual hint; not a security gate. */
function estimateEntropyBits(password: string): number {
  if (password.length === 0) {
    return 0;
  }
  let charset = 0;
  if (/[a-z]/.test(password)) charset += 26;
  if (/[A-Z]/.test(password)) charset += 26;
  if (/[0-9]/.test(password)) charset += 10;
  if (/[^a-zA-Z0-9]/.test(password)) charset += 32;
  if (charset === 0) {
    charset = 26;
  }
  return Math.log2(charset) * password.length;
}

function bitsToStrength(bits: number): PasswordStrength {
  if (bits < 28) return 0;
  if (bits < 50) return 1;
  if (bits < 70) return 2;
  if (bits < 90) return 3;
  return 4;
}

const STRENGTH_LABEL: Record<PasswordStrength, string> = {
  0: 'Very weak',
  1: 'Weak',
  2: 'Fair',
  3: 'Strong',
  4: 'Very strong',
};

export function PasswordMeter({ password, label }: PasswordMeterProps) {
  const { strength, bits } = useMemo(() => {
    const b = estimateEntropyBits(password);
    return { strength: bitsToStrength(b), bits: b };
  }, [password]);

  const accessibleLabel = label ?? 'Password strength';

  return (
    <div className="pcl-password-meter">
      <div
        className="pcl-password-meter__bars"
        role="meter"
        aria-label={accessibleLabel}
        aria-valuemin={0}
        aria-valuemax={4}
        aria-valuenow={strength}
        aria-valuetext={STRENGTH_LABEL[strength]}
      >
        {[0, 1, 2, 3].map((i) => (
          <span
            key={i}
            className={`pcl-password-meter__bar ${
              i < strength ? `pcl-password-meter__bar--filled-${strength}` : ''
            }`}
            aria-hidden="true"
          />
        ))}
      </div>
      <div className="pcl-password-meter__label">
        <span>{STRENGTH_LABEL[strength]}</span>
        <span className="pcl-password-meter__bits">{Math.round(bits)} bits</span>
      </div>
    </div>
  );
}
