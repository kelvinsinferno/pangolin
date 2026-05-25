// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Typed wrappers around Tauri v2's `invoke()` bridge.
 *
 * Mirrors the Rust-side `tauri::command` surface in `apps/desktop/src/
 * commands/` 1:1. Every wrapper:
 *
 * - takes a typed argument record (no positional args; Tauri's bridge
 *   passes by-name);
 * - returns a typed `Promise<T>`;
 * - throws `DesktopError` (the typed envelope from `error.rs`) for the
 *   error arm so the React side can discriminate on `kind`.
 *
 * The wrappers re-throw raw error envelopes; the calling hook
 * (`useVault`) is the layer that branches on `kind`.
 */
import { invoke as tauriInvoke } from '@tauri-apps/api/core';

// ---- Error envelope (mirror of Rust `DesktopError`) -------------------

export type DesktopErrorKind =
  | 'Session'
  | 'Validation'
  | 'Chain'
  | 'Store'
  | 'Recovery'
  | 'Sync'
  | 'Crypto'
  | 'Internal'
  | 'AuthenticationFailed';

export interface DesktopError {
  kind: DesktopErrorKind;
  /** Present on every variant except `AuthenticationFailed`. The
   *  `Validation` variant carries a nested `{ kind, message }` record
   *  but the Rust side flattens it through `#[serde(tag, content)]`
   *  so the wire shape is uniform: `{ kind: "Validation", message: { kind: "...", message: "..." } }`.
   *  We model the `message` field as `unknown` so callers narrow
   *  explicitly. */
  message?: unknown;
}

/** Type guard for `DesktopError`. Tauri's invoke() throws the JSON
 *  envelope as-is; this guard recovers the typed shape. */
export function isDesktopError(e: unknown): e is DesktopError {
  if (typeof e !== 'object' || e === null) return false;
  const k = (e as { kind?: unknown }).kind;
  return (
    k === 'Session' ||
    k === 'Validation' ||
    k === 'Chain' ||
    k === 'Store' ||
    k === 'Recovery' ||
    k === 'Sync' ||
    k === 'Crypto' ||
    k === 'Internal' ||
    k === 'AuthenticationFailed'
  );
}

// ---- Account DTO (mirror of Rust `AccountSummaryDto`) -----------------

export interface AccountSummary {
  /** 64-character lowercase hex of the 32-byte account id. */
  id: string;
  /** User-visible display name. */
  displayName: string;
  tags: string[];
  usernames: string[];
  urls: string[];
  passwordHistoryCount: number;
  hasTotp: boolean;
  /** Wall-clock unix-second timestamp of the most recent password
   *  rotation; `0` if the history is somehow empty. */
  currentPasswordChangedAt: number;
}

/** Internal wire shape — Rust's serde renames are camelCase-free
 *  (it's a Rust struct, so `display_name` etc. cross the wire as
 *  snake_case). We translate at the boundary so the React side only
 *  ever sees camelCase. */
interface AccountSummaryWire {
  id: string;
  display_name: string;
  tags: string[];
  usernames: string[];
  urls: string[];
  password_history_count: number;
  has_totp: boolean;
  current_password_changed_at: number;
}

function fromWire(w: AccountSummaryWire): AccountSummary {
  return {
    id: w.id,
    displayName: w.display_name,
    tags: w.tags,
    usernames: w.usernames,
    urls: w.urls,
    passwordHistoryCount: w.password_history_count,
    hasTotp: w.has_totp,
    currentPasswordChangedAt: w.current_password_changed_at,
  };
}

// ---- Command wrappers --------------------------------------------------

/** Open a vault file. */
export async function vaultOpen(path: string): Promise<void> {
  await tauriInvoke<void>('vault_open', { path });
}

/** Unlock the currently-open vault with the supplied master password. */
export async function vaultUnlock(password: string): Promise<void> {
  await tauriInvoke<void>('vault_unlock', { password });
}

/** Lock the currently-open vault (the handle stays open; subsequent
 *  `vault_unlock` re-activates the session). */
export async function vaultLock(): Promise<void> {
  await tauriInvoke<void>('vault_lock');
}

/** Close the currently-open vault. Returns to the Welcome screen. */
export async function vaultClose(): Promise<void> {
  await tauriInvoke<void>('vault_close');
}

/** List every account in the unlocked vault. */
export async function accountsList(): Promise<AccountSummary[]> {
  const list = await tauriInvoke<AccountSummaryWire[]>('accounts_list');
  return list.map(fromWire);
}

/** Fetch a single account's metadata. */
export async function accountShow(id: string): Promise<AccountSummary> {
  const wire = await tauriInvoke<AccountSummaryWire>('account_show', { id });
  return fromWire(wire);
}

/** Reveal the current head-of-history plaintext password for an
 *  account. The caller MUST clear the local state slot within 10 s per
 *  Browser-Ext spec §4.7 (the AccountDetailScreen's useEffect enforces
 *  this). */
export async function revealPassword(id: string): Promise<string> {
  return tauriInvoke<string>('reveal_password', { id });
}

/** Write `text` to the OS clipboard. For PASSWORD copies prefer
 *  {@link copyPasswordToClipboard} — it keeps the plaintext entirely
 *  Rust-side, never crossing it through V8. This wrapper stays for
 *  non-secret strings (e.g. an account username). */
export async function copyToClipboard(text: string): Promise<void> {
  await tauriInvoke<void>('copy_to_clipboard', { text });
}

/** **Copy the head-of-history plaintext password directly to the OS
 *  clipboard** — the plaintext NEVER crosses the FFI boundary back
 *  into V8 (audit HIGH H-1 hardening, 2026-05-25). The Rust side
 *  reads the password via FFI + writes to the clipboard plugin in
 *  the same `tauri::command` body that holds the zeroizing buffer.
 *
 *  Use this for the AccountDetailScreen's "Copy" button. For the
 *  reveal-to-view flow (the user wants to SEE the password before
 *  deciding to copy) use {@link revealPassword}. */
export async function copyPasswordToClipboard(id: string): Promise<void> {
  await tauriInvoke<void>('copy_password_to_clipboard', { id });
}
