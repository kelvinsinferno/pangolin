// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * `useVault()` — the single source of truth for the desktop's open /
 * unlock / list state machine.
 *
 * Encodes plan §3.4:
 *
 * ```text
 *   Welcome ─open(path)─▶ Locked ─unlock(pw)─▶ Active ──▶ Detail
 *      ▲                                          │
 *      └───── close ──────────────────────────────┘
 * ```
 *
 * Surfaces the typed `DesktopError` envelope to the caller — except
 * `AuthenticationFailed`, which the hook returns as a structured flag
 * on `unlockVault` (the UnlockScreen renders it inline; the rest of
 * the app never sees it as a toast).
 */
import { useCallback, useState } from 'react';

import {
  accountShow,
  accountsList,
  copyPasswordToClipboard,
  isDesktopError,
  revealPassword,
  vaultClose,
  vaultLock,
  vaultOpen,
  vaultUnlock,
  type AccountSummary,
  type DesktopError,
} from '../lib/invoke';

export type VaultStage = 'welcome' | 'locked' | 'active' | 'detail' | 'devices' | 'recovery';

export interface VaultState {
  stage: VaultStage;
  /** The currently-selected account (when stage === 'detail'). */
  selected: AccountSummary | null;
  /** The current account list (when stage === 'active' | 'detail'). */
  accounts: AccountSummary[];
}

const initialState: VaultState = {
  stage: 'welcome',
  selected: null,
  accounts: [],
};

/** Discriminated unlock result. The unlock screen reads this directly
 *  rather than throwing, because the bad-password case has a unique
 *  inline-error UX treatment. */
export type UnlockResult =
  | { ok: true }
  | { ok: false; authenticationFailed: true }
  | { ok: false; authenticationFailed: false; error: DesktopError };

export interface VaultActions {
  openVault(path: string): Promise<{ ok: true } | { ok: false; error: DesktopError }>;
  unlockVault(password: string): Promise<UnlockResult>;
  lockVault(): Promise<{ ok: true } | { ok: false; error: DesktopError }>;
  closeVault(): Promise<void>;
  listAccounts(): Promise<{ ok: true } | { ok: false; error: DesktopError }>;
  showAccount(id: string): Promise<{ ok: true } | { ok: false; error: DesktopError }>;
  /** Closes the detail screen and returns to the account list. */
  backToList(): void;
  /** Opens the Devices (multi-device pairing) screen. */
  goToDevices(): void;
  /** Opens the Recovery (backup + health) screen. */
  goToRecovery(): void;
  /** Reveals the head-of-history password for the currently-selected
   *  account. Caller-managed lifetime: the AccountDetailScreen sets it
   *  via local state + clears within 10 s. */
  revealPasswordForSelected(): Promise<{ ok: true; password: string } | { ok: false; error: DesktopError }>;
  /** Copies the currently-selected account's password to the OS
   *  clipboard via the Rust-side `copy_password_to_clipboard` command.
   *  Plaintext NEVER crosses V8 — audit H-1 hardening. */
  copySelectedPassword(): Promise<{ ok: true } | { ok: false; error: DesktopError }>;
}

function toDesktopError(e: unknown): DesktopError {
  if (isDesktopError(e)) return e;
  return { kind: 'Internal', message: String(e) };
}

export function useVault(): { state: VaultState; actions: VaultActions } {
  const [state, setState] = useState<VaultState>(initialState);

  const openVault = useCallback(async (path: string) => {
    try {
      await vaultOpen(path);
      setState((prev) => ({ ...prev, stage: 'locked' }));
      return { ok: true as const };
    } catch (e) {
      return { ok: false as const, error: toDesktopError(e) };
    }
  }, []);

  const unlockVault = useCallback(async (password: string): Promise<UnlockResult> => {
    try {
      await vaultUnlock(password);
      const list = await accountsList();
      setState((prev) => ({ ...prev, stage: 'active', accounts: list }));
      return { ok: true };
    } catch (e) {
      const err = toDesktopError(e);
      if (err.kind === 'AuthenticationFailed') {
        return { ok: false, authenticationFailed: true };
      }
      return { ok: false, authenticationFailed: false, error: err };
    }
  }, []);

  const lockVault = useCallback(async () => {
    try {
      await vaultLock();
      setState((prev) => ({ ...prev, stage: 'locked', selected: null, accounts: [] }));
      return { ok: true as const };
    } catch (e) {
      return { ok: false as const, error: toDesktopError(e) };
    }
  }, []);

  const closeVault = useCallback(async () => {
    try {
      await vaultClose();
    } catch {
      // Idempotent at the FFI level; even if the close errored we
      // reset the UI so the user is not stuck.
    }
    setState(initialState);
  }, []);

  const listAccounts = useCallback(async () => {
    try {
      const list = await accountsList();
      setState((prev) => ({ ...prev, accounts: list }));
      return { ok: true as const };
    } catch (e) {
      return { ok: false as const, error: toDesktopError(e) };
    }
  }, []);

  const showAccount = useCallback(async (id: string) => {
    try {
      const snap = await accountShow(id);
      setState((prev) => ({ ...prev, stage: 'detail', selected: snap }));
      return { ok: true as const };
    } catch (e) {
      return { ok: false as const, error: toDesktopError(e) };
    }
  }, []);

  const backToList = useCallback(() => {
    setState((prev) => ({ ...prev, stage: 'active', selected: null }));
  }, []);

  const goToDevices = useCallback(() => {
    setState((prev) => ({ ...prev, stage: 'devices', selected: null }));
  }, []);

  const goToRecovery = useCallback(() => {
    setState((prev) => ({ ...prev, stage: 'recovery', selected: null }));
  }, []);

  const revealPasswordForSelected = useCallback(async () => {
    // Capture the id at call time so a concurrent backToList does not
    // race past us.
    const selectedId = state.selected?.id;
    if (selectedId === undefined) {
      return {
        ok: false as const,
        error: { kind: 'Internal' as const, message: 'no account selected' },
      };
    }
    try {
      const password = await revealPassword(selectedId);
      return { ok: true as const, password };
    } catch (e) {
      return { ok: false as const, error: toDesktopError(e) };
    }
  }, [state.selected]);

  const copySelectedPassword = useCallback(async () => {
    // Same id-capture discipline as revealPasswordForSelected — a
    // racing backToList must not corrupt the FFI call.
    const selectedId = state.selected?.id;
    if (selectedId === undefined) {
      return {
        ok: false as const,
        error: { kind: 'Internal' as const, message: 'no account selected' },
      };
    }
    try {
      await copyPasswordToClipboard(selectedId);
      return { ok: true as const };
    } catch (e) {
      return { ok: false as const, error: toDesktopError(e) };
    }
  }, [state.selected]);

  return {
    state,
    actions: {
      openVault,
      unlockVault,
      lockVault,
      closeVault,
      listAccounts,
      showAccount,
      backToList,
      goToDevices,
      goToRecovery,
      revealPasswordForSelected,
      copySelectedPassword,
    },
  };
}
