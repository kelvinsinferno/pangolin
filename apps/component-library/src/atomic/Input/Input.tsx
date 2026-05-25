// SPDX-License-Identifier: AGPL-3.0-or-later
import {
  forwardRef,
  useId,
  useState,
  type InputHTMLAttributes,
  type ReactNode,
} from 'react';
import { Eye } from '../../icons/Eye';
import { EyeOff } from '../../icons/EyeOff';
import './Input.css';

export type InputType = 'text' | 'password' | 'email' | 'tel' | 'url' | 'search' | 'number';

export interface InputProps extends Omit<InputHTMLAttributes<HTMLInputElement>, 'type'> {
  /** Optional label rendered above the input and wired via `htmlFor`. */
  label?: ReactNode;
  /** Optional leading-icon slot rendered inside the input's left rail. */
  leadingIcon?: ReactNode;
  /** Optional right-rail action (button, icon, etc.). Ignored when `type === "password"`
   * because the password-mask toggle takes that slot. */
  rightAction?: ReactNode;
  /** Input type. `password` enables the built-in mask-toggle button. */
  type?: InputType;
}

export const Input = forwardRef<HTMLInputElement, InputProps>(function Input(
  { label, leadingIcon, rightAction, type = 'text', id, className, ...rest },
  ref,
) {
  const reactId = useId();
  const inputId = id ?? `pcl-input-${reactId}`;
  const [reveal, setReveal] = useState(false);
  const isPassword = type === 'password';
  const effectiveType: InputType = isPassword && reveal ? 'text' : type;

  const wrapperClasses = ['pcl-input', className].filter(Boolean).join(' ');

  return (
    <div className={wrapperClasses}>
      {label !== undefined && (
        <label htmlFor={inputId} className="pcl-input__label">
          {label}
        </label>
      )}
      <div className="pcl-input__field">
        {leadingIcon !== undefined && (
          <span className="pcl-input__leading" aria-hidden="true">
            {leadingIcon}
          </span>
        )}
        <input
          ref={ref}
          id={inputId}
          type={effectiveType}
          className="pcl-input__control"
          {...rest}
        />
        {isPassword ? (
          <button
            type="button"
            className="pcl-input__toggle"
            aria-label={reveal ? 'Hide password' : 'Show password'}
            aria-pressed={reveal}
            onClick={() => setReveal((v) => !v)}
          >
            {reveal ? <EyeOff /> : <Eye />}
          </button>
        ) : (
          rightAction !== undefined && (
            <span className="pcl-input__right">{rightAction}</span>
          )
        )}
      </div>
    </div>
  );
});
