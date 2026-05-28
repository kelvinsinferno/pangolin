// SPDX-License-Identifier: AGPL-3.0-or-later
//
// React hook wrapping the NativeHostClient lifecycle. Owns the
// state machine: provisioning -> connecting -> connected -> error.
//
// Plan-LOCK: docs/issue-plans/mvp4-g-extension-e2e.md section 1
// (apps/extension/src/popup/use-native-host.ts).

import { useCallback, useEffect, useRef, useState } from "react";

import {
  type FfiAccountSummary,
  type SessionStatus,
  NativeHostClient,
  NativeHostError,
} from "./native-host";
import { clearToken, loadToken, saveToken } from "./token-store";

export type PopupState =
  | { kind: "loading" }
  | { kind: "provisioning" }
  | { kind: "connecting" }
  | {
      kind: "connected";
      session: SessionStatus;
      accounts: FfiAccountSummary[];
    }
  | { kind: "error"; label: string; message: string };

export interface UseNativeHostOptions {
  /** Optional client factory; tests inject a mock. */
  createClient?: () => NativeHostClient;
}

export interface UseNativeHost {
  state: PopupState;
  /** Provisioning view -> Save. Persists token + transitions to
   * connecting. */
  submitToken: (token: string) => Promise<void>;
  /** Connected view -> per-row Copy. */
  copyPassword: (id: string) => Promise<void>;
  /** Manual retry from the error view. */
  retry: () => Promise<void>;
}

/** React hook owning the popup state machine. */
export function useNativeHost(opts: UseNativeHostOptions = {}): UseNativeHost {
  const [state, setState] = useState<PopupState>({ kind: "loading" });
  const clientRef = useRef<NativeHostClient | null>(null);
  // Latest mount marker so async callbacks that finish after a
  // setState-to-different-state ignore their resolved value.
  const mountedRef = useRef<boolean>(true);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      const c = clientRef.current;
      if (c !== null) {
        c.disconnect();
        clientRef.current = null;
      }
    };
  }, []);

  const create = useCallback((): NativeHostClient => {
    const f = opts.createClient;
    return f === undefined ? new NativeHostClient() : f();
  }, [opts]);

  /** Connect + populate accounts. Updates state at each step. */
  const connectWith = useCallback(
    async (token: string): Promise<void> => {
      setState({ kind: "connecting" });
      // Tear down any prior client (e.g. retry from error view).
      const prior = clientRef.current;
      if (prior !== null) {
        prior.disconnect();
        clientRef.current = null;
      }
      const client = create();
      clientRef.current = client;
      try {
        await client.connect(token);
        const session = await client.sessionStatus();
        let accounts: FfiAccountSummary[] = [];
        if (session.vault_unlocked) {
          accounts = await client.listAccounts();
        }
        if (!mountedRef.current) return;
        setState({ kind: "connected", session, accounts });
      } catch (e) {
        clientRef.current = null;
        try {
          client.disconnect();
        } catch {
          // ignore
        }
        if (!mountedRef.current) return;
        const label =
          e instanceof NativeHostError ? e.label : "unknown_error";
        const message =
          e instanceof Error ? e.message : String(e ?? "unknown");
        // Per Q-a Option 1: auth_failed clears the stored token and
        // reverts to provisioning.
        if (label === "auth_failed") {
          await clearToken();
          if (!mountedRef.current) return;
          setState({ kind: "provisioning" });
          return;
        }
        setState({ kind: "error", label, message });
      }
    },
    [create],
  );

  // Bootstrap: read storage, route to provisioning or connecting.
  useEffect(() => {
    let cancelled = false;
    void (async () => {
      const stored = await loadToken();
      if (cancelled || !mountedRef.current) return;
      if (stored === null) {
        setState({ kind: "provisioning" });
        return;
      }
      await connectWith(stored);
    })();
    return () => {
      cancelled = true;
    };
  }, [connectWith]);

  const submitToken = useCallback(
    async (token: string): Promise<void> => {
      const trimmed = token.trim();
      if (trimmed.length === 0) {
        setState({
          kind: "error",
          label: "validation_failed",
          message: "Token cannot be empty.",
        });
        return;
      }
      const saved = await saveToken(trimmed);
      if (!saved) {
        setState({
          kind: "error",
          label: "storage_error",
          message: "Could not save token to extension storage.",
        });
        return;
      }
      await connectWith(trimmed);
    },
    [connectWith],
  );

  const copyPassword = useCallback(async (id: string): Promise<void> => {
    const c = clientRef.current;
    if (c === null) {
      setState({
        kind: "error",
        label: "transport",
        message: "Not connected to desktop.",
      });
      return;
    }
    try {
      await c.copyPassword(id);
    } catch (e) {
      if (!mountedRef.current) return;
      const label = e instanceof NativeHostError ? e.label : "unknown_error";
      const message = e instanceof Error ? e.message : String(e ?? "unknown");
      setState({ kind: "error", label, message });
    }
  }, []);

  const retry = useCallback(async (): Promise<void> => {
    const stored = await loadToken();
    if (stored === null) {
      setState({ kind: "provisioning" });
      return;
    }
    await connectWith(stored);
  }, [connectWith]);

  return { state, submitToken, copyPassword, retry };
}
