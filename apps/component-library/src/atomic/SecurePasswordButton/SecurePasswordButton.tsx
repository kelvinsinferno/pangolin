// SPDX-License-Identifier: AGPL-3.0-or-later
import { useRef, useState, type ReactNode } from 'react';
import { Button, type ButtonProps, type ButtonVariant } from '../Button/Button';
import { Spinner } from '../Spinner/Spinner';

/** Result returned by {@link SecurePasswordButtonProps.onSubmit}. The
 *  button uses the variant to decide whether to invoke the success or
 *  error path. */
export type SecureSubmitOutcome =
  | { ok: true }
  | { ok: false; message: string };

export interface SecurePasswordButtonProps
  // `onError` is omitted from the inherited Button props because the
  // React DOM `onError` is a `ReactEventHandler<HTMLButtonElement>`
  // (image-loading style errors) and our local `onError` carries a
  // string message — the two signatures are incompatible. We never
  // need to forward the DOM event, so the omit is safe.
  extends Omit<ButtonProps, 'children' | 'onClick' | 'onError' | 'type'> {
  /** Button label. The native widget collects the password — the
   *  button is just the trigger. */
  label: ReactNode;
  /** Async handler invoked on click. Should:
   *  1. Open the native password dialog (typically via a
   *     `*_via_secure_prompt` Tauri command).
   *  2. Drive whatever FFI op the password unlocks.
   *  3. Return `{ ok: true }` on success or `{ ok: false, message }`
   *     on a typed failure. THROWN exceptions are treated as
   *     `{ ok: false, message: e.message }` (catch-all defense).
   *
   *  The button re-entrancy guards via an internal ref so a double-
   *  click cannot fire two parallel prompts.
   */
  onSubmit: () => Promise<SecureSubmitOutcome>;
  /** Called when `onSubmit` returns `{ ok: false }` or throws. The
   *  parent typically routes the message to a toast. */
  onError?: (message: string) => void;
  /** Called when `onSubmit` returns `{ ok: true }`. The parent
   *  typically advances the wizard state. */
  onSuccess?: () => void;
  /** Optional button variant; defaults to `primary`. */
  variant?: ButtonVariant;
}

/**
 * **SecurePasswordButton** — MVP-4-H Layer 3 component.
 *
 * Replaces every `<Input type="password">` + accompanying
 * `<Button>` pair in the desktop UI with a single trigger that
 * opens the OS native password dialog. The password bytes never
 * enter the V8 heap — they flow directly from the native widget
 * into Rust via the `*_via_secure_prompt` Tauri commands.
 *
 * Plan-LOCK: docs/issue-plans/mvp4-h-secure-input.md §3.
 *
 * ## Behavior
 *
 * - Click → invoke `onSubmit` (which opens the native dialog).
 * - During invocation: button disabled + Spinner replaces label.
 * - On `{ ok: true }`: `onSuccess` called (parent advances state).
 * - On `{ ok: false, message }` or thrown error: `onError(message)`
 *   called (parent typically toasts the message).
 * - Re-entrancy guard via `useRef<boolean>`: double-clicks become
 *   no-ops while a prompt is already in flight.
 *
 * ## Why no `<Input>`
 *
 * The password is collected by the OS native dialog (Win32
 * TaskDialog / NSAlert / GtkEntry). React never sees the bytes —
 * the whole point of MVP-4-H is to close the V8 heap residue. The
 * button is the ONLY React-side trigger.
 */
export function SecurePasswordButton({
  label,
  onSubmit,
  onError,
  onSuccess,
  disabled,
  variant = 'primary',
  ...rest
}: SecurePasswordButtonProps) {
  const [busy, setBusy] = useState(false);
  // Re-entrancy guard. The button's `disabled` attribute also
  // prevents double-clicks, but a synthesized event (devtools,
  // accessibility tooling) could bypass the disabled state — the
  // ref makes that a no-op too.
  const inFlight = useRef(false);

  const handleClick = () => {
    if (inFlight.current) return;
    inFlight.current = true;
    setBusy(true);
    void (async () => {
      try {
        const outcome = await onSubmit();
        if (outcome.ok) {
          onSuccess?.();
        } else {
          onError?.(outcome.message);
        }
      } catch (e) {
        const message = e instanceof Error ? e.message : 'unexpected error';
        onError?.(message);
      } finally {
        inFlight.current = false;
        setBusy(false);
      }
    })();
  };

  return (
    <Button
      {...rest}
      variant={variant}
      type="button"
      onClick={handleClick}
      disabled={disabled || busy}
    >
      {busy ? <Spinner size="sm" /> : label}
    </Button>
  );
}
