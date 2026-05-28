// SPDX-License-Identifier: AGPL-3.0-or-later
//
// JSON-RPC client for the native-messaging host.
//
// Plan-LOCK: docs/issue-plans/mvp4-g-extension-e2e.md section 3.3.
//
// The client wraps chrome.runtime.connectNative(HOST_NAME). Chrome
// handles the 4-byte LE length-prefix framing internally on its
// port API; the client just does port.postMessage(obj) plus
// port.onMessage(listener). Each method correlates a request to a
// response by an integer id.
//
// L1 (zero-secret-crosses-FFI) discipline: the class deliberately
// does NOT expose a revealPassword(id) method. copyPassword(id)
// returns void -- the clipboard write happens entirely Rust-side.
// The plaintext NEVER crosses the extension boundary. Any future
// method that returns plaintext MUST pass plan-LOCK review (this
// comment is the load-bearing guard).
//
// Error mapping: JSON-RPC error responses are surfaced as a typed
// NativeHostError with the server-provided code + message. The
// data field is ignored (the desktop and host both pin it to null,
// per L7).

/** Native-messaging host name advertised by the desktop install code
 * (mirrors pangolin_native_messaging_host::paths::HOST_NAME). */
export const NATIVE_HOST_NAME = "studio.kelvinsinferno.pangolin.host";

/** Account summary shape returned by vault.list_accounts and
 * vault.account_show. Mirrors the desktop crate AccountSummaryDto. */
export interface FfiAccountSummary {
  /** 64-character lowercase-hex account id. */
  id: string;
  display_name: string;
  tags: string[];
  usernames: string[];
  urls: string[];
  password_history_count: number;
  has_totp: boolean;
  current_password_changed_at: number;
}

/** Result of session.status. */
export interface SessionStatus {
  vault_open: boolean;
  vault_unlocked: boolean;
}

/** Class of failure surfaced by the JSON-RPC client. */
export class NativeHostError extends Error {
  /** Numeric JSON-RPC code or 0 for client-side transport failures. */
  readonly code: number;
  /** Stable label (e.g. "auth_failed", "session_locked"). */
  readonly label: string;
  constructor(code: number, label: string, message?: string) {
    super(message ?? label);
    this.code = code;
    this.label = label;
    this.name = "NativeHostError";
  }
}

/** Minimal subset of chrome.runtime.Port the client depends on. */
interface PortLike {
  postMessage: (msg: unknown) => void;
  disconnect: () => void;
  onMessage: { addListener: (cb: (msg: unknown) => void) => void };
  onDisconnect: { addListener: (cb: () => void) => void };
}

interface PendingCall {
  resolve: (value: unknown) => void;
  reject: (err: NativeHostError) => void;
}

/** Optional connector factory. Defaults to chrome.runtime.connectNative. */
export type NativeConnector = (hostName: string) => PortLike;

const defaultConnector: NativeConnector = (hostName) =>
  chrome.runtime.connectNative(hostName) as unknown as PortLike;

/**
 * JSON-RPC client wrapping a single chrome.runtime.connectNative
 * port. One client per popup-open; disconnect() tears the port down
 * (Chrome reaps the host subprocess).
 */
export class NativeHostClient {
  private port: PortLike | null = null;
  private nextId = 1;
  private readonly pending = new Map<number, PendingCall>();
  private disconnected = false;
  private readonly connector: NativeConnector;
  private readonly hostName: string;

  constructor(
    connector: NativeConnector = defaultConnector,
    hostName: string = NATIVE_HOST_NAME,
  ) {
    this.connector = connector;
    this.hostName = hostName;
  }

  async connect(token: string): Promise<void> {
    if (this.port !== null) {
      throw new NativeHostError(0, "transport", "already connected");
    }
    let p: PortLike;
    try {
      p = this.connector(this.hostName);
    } catch (e) {
      throw new NativeHostError(
        0,
        "transport",
        "connectNative failed: " + (e instanceof Error ? e.message : String(e)),
      );
    }
    this.port = p;
    this.disconnected = false;
    p.onMessage.addListener((msg) => this.handleMessage(msg));
    p.onDisconnect.addListener(() => this.handleDisconnect());

    await this.callRaw("auth.handshake", { token });
  }

  async sessionStatus(): Promise<SessionStatus> {
    const v = await this.callRaw("session.status", {});
    const r = v as Partial<SessionStatus> | null;
    return {
      vault_open: r?.vault_open === true,
      vault_unlocked: r?.vault_unlocked === true,
    };
  }

  async listAccounts(): Promise<FfiAccountSummary[]> {
    const v = await this.callRaw("vault.list_accounts", {});
    if (!Array.isArray(v)) {
      return [];
    }
    return v as FfiAccountSummary[];
  }

  /**
   * Trigger the Rust-side clipboard write for an account password.
   * Resolves void on success -- the plaintext NEVER crosses the IPC
   * boundary, per L1.
   */
  async copyPassword(id: string): Promise<void> {
    await this.callRaw("vault.copy_password", { id });
  }

  disconnect(): void {
    if (this.port === null) return;
    try {
      this.port.disconnect();
    } catch {
      // Best-effort; the popup is closing anyway.
    }
    this.handleDisconnect();
  }

  isDisconnected(): boolean {
    return this.disconnected;
  }

  private callRaw(method: string, params: unknown): Promise<unknown> {
    return new Promise<unknown>((resolve, reject) => {
      if (this.port === null || this.disconnected) {
        reject(new NativeHostError(0, "transport", "not connected"));
        return;
      }
      const id = this.nextId;
      this.nextId += 1;
      this.pending.set(id, { resolve, reject });
      const req = { jsonrpc: "2.0", id, method, params };
      try {
        this.port.postMessage(req);
      } catch (e) {
        this.pending.delete(id);
        reject(
          new NativeHostError(
            0,
            "transport",
            "postMessage failed: " +
              (e instanceof Error ? e.message : String(e)),
          ),
        );
      }
    });
  }

  private handleMessage(msg: unknown): void {
    if (typeof msg !== "object" || msg === null) {
      return;
    }
    const m = msg as { id?: unknown; result?: unknown; error?: unknown };
    if (typeof m.id !== "number") {
      return;
    }
    const pending = this.pending.get(m.id);
    if (pending === undefined) {
      return;
    }
    this.pending.delete(m.id);
    if (m.error !== undefined && m.error !== null) {
      const e = m.error as { code?: unknown; message?: unknown };
      const code = typeof e.code === "number" ? e.code : 0;
      const label = typeof e.message === "string" ? e.message : "error";
      pending.reject(new NativeHostError(code, label));
      return;
    }
    pending.resolve(m.result ?? null);
  }

  private handleDisconnect(): void {
    if (this.disconnected) return;
    this.disconnected = true;
    this.port = null;
    for (const [, pending] of this.pending) {
      pending.reject(new NativeHostError(0, "transport", "port disconnected"));
    }
    this.pending.clear();
  }
}
