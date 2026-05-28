// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Injected native-messaging connector for the MVP-4-G Node
// integration gate (plan-LOCK §0a Q-c).
//
// The production popup connects via chrome.runtime.connectNative,
// which Chrome frames as the native-messaging stdio protocol:
// a 4-byte little-endian u32 length prefix followed by a UTF-8 JSON
// body. Chrome-for-Testing 138+ refuses to spawn native-messaging
// hosts for --load-extension dev-loaded extensions, so the automated
// gate can't use real Chrome (§0a Q-c). This connector replaces ONLY
// Chrome's transport: it spawns the REAL pangolin-native-messaging-host
// binary and frames its stdin/stdout with byte-identical framing, so
// the real NativeHostClient, real host binary, and real desktop are
// all exercised end-to-end.
//
// FRAMING FIDELITY (plan §6): the 4-byte LE length + UTF-8 JSON below
// MUST match the host's frame.rs exactly. A round-trip test
// (framing.test.ts) asserts this.

import { type ChildProcessWithoutNullStreams, spawn } from "node:child_process";

/** Minimal subset of chrome.runtime.Port the NativeHostClient depends on.
 * Mirrors the PortLike interface in src/popup/native-host.ts. */
export interface PortLike {
  postMessage: (msg: unknown) => void;
  disconnect: () => void;
  onMessage: { addListener: (cb: (msg: unknown) => void) => void };
  onDisconnect: { addListener: (cb: () => void) => void };
}

export type NativeConnector = (hostName: string) => PortLike;

const MAX_FRAME = 1024 * 1024;

export interface StdioConnectorOptions {
  /** Absolute path to the pangolin-native-messaging-host binary. */
  hostBinary: string;
  /** TempDir HOME — the host reads its token sibling-file + resolves
   * the desktop IPC socket path from here. MUST match the HOME the
   * desktop was started with. */
  home: string;
  /** XDG_RUNTIME_DIR — where the desktop bound its IPC socket. MUST
   * match the desktop's. */
  xdgRuntimeDir: string;
  /** Optional sink for the host's stderr (debug). */
  onStderr?: (line: string) => void;
}

/**
 * Build a NativeConnector that spawns the real host binary and frames
 * stdio per Chrome's native-messaging protocol.
 *
 * Each invocation (one per NativeHostClient.connect) spawns a fresh
 * host process — matching Chrome's "spawn host per connectNative"
 * lifecycle. disconnect() SIGKILLs it (Chrome SIGTERMs; either reaps
 * the relay).
 */
export function makeStdioConnector(opts: StdioConnectorOptions): NativeConnector {
  return (_hostName: string): PortLike => {
    const child: ChildProcessWithoutNullStreams = spawn(opts.hostBinary, [], {
      env: {
        ...process.env,
        HOME: opts.home,
        XDG_RUNTIME_DIR: opts.xdgRuntimeDir,
        XDG_DATA_HOME: `${opts.home}/.local/share`,
      },
      stdio: ["pipe", "pipe", "pipe"],
    });

    const messageListeners: Array<(msg: unknown) => void> = [];
    const disconnectListeners: Array<() => void> = [];
    let disconnected = false;

    // ---- stdout de-framer: 4-byte LE length prefix + UTF-8 JSON ----
    let buf = Buffer.alloc(0);
    child.stdout.on("data", (chunk: Buffer) => {
      buf = Buffer.concat([buf, chunk]);
      // Drain as many complete frames as are buffered.
      for (;;) {
        if (buf.length < 4) return;
        const len = buf.readUInt32LE(0);
        if (len > MAX_FRAME) {
          // Protocol violation — tear down.
          fireDisconnect();
          return;
        }
        if (buf.length < 4 + len) return;
        const body = buf.subarray(4, 4 + len);
        buf = buf.subarray(4 + len);
        let parsed: unknown;
        try {
          parsed = JSON.parse(body.toString("utf8"));
        } catch {
          // Malformed frame — ignore this frame (matches the client's
          // tolerant handleMessage which drops non-object messages).
          continue;
        }
        for (const cb of messageListeners) cb(parsed);
      }
    });

    if (opts.onStderr !== undefined) {
      const onStderr = opts.onStderr;
      child.stderr.on("data", (chunk: Buffer) => {
        onStderr(chunk.toString("utf8"));
      });
    }

    const fireDisconnect = (): void => {
      if (disconnected) return;
      disconnected = true;
      try {
        child.kill("SIGKILL");
      } catch {
        // already dead
      }
      for (const cb of disconnectListeners) cb();
    };

    child.on("exit", () => fireDisconnect());
    child.on("error", () => fireDisconnect());
    // When the host exits (e.g. its desktop-IPC relay dropped), a
    // pending write to its stdin surfaces an async EPIPE on the
    // stdin stream. Swallow it + convert to a disconnect so the
    // NativeHostClient's pending calls reject as a typed transport
    // error rather than crashing the process with an uncaught EPIPE.
    child.stdin.on("error", () => fireDisconnect());

    return {
      postMessage: (msg: unknown): void => {
        if (disconnected) return;
        const json = Buffer.from(JSON.stringify(msg), "utf8");
        if (json.length > MAX_FRAME) {
          throw new Error("frame too long");
        }
        const header = Buffer.alloc(4);
        header.writeUInt32LE(json.length, 0);
        // The write can fail synchronously (dead pipe) or asynchronously
        // (EPIPE event, handled above). On a synchronous throw, mark
        // disconnected so the client rejects the pending call.
        try {
          child.stdin.write(header);
          child.stdin.write(json);
        } catch {
          fireDisconnect();
        }
      },
      disconnect: (): void => fireDisconnect(),
      onMessage: {
        addListener: (cb: (msg: unknown) => void): void => {
          messageListeners.push(cb);
        },
      },
      onDisconnect: {
        addListener: (cb: () => void): void => {
          disconnectListeners.push(cb);
        },
      },
    };
  };
}

/** Frame a JS value the way the connector frames postMessage — exported
 * so the framing round-trip test can assert byte-identity with the
 * host's frame.rs. */
export function frameMessage(msg: unknown): Buffer {
  const json = Buffer.from(JSON.stringify(msg), "utf8");
  const header = Buffer.alloc(4);
  header.writeUInt32LE(json.length, 0);
  return Buffer.concat([header, json]);
}

/** Inverse of frameMessage — parse a single framed buffer. Returns the
 * decoded value + the number of bytes consumed. */
export function deframeMessage(b: Buffer): { value: unknown; consumed: number } | null {
  if (b.length < 4) return null;
  const len = b.readUInt32LE(0);
  if (b.length < 4 + len) return null;
  const body = b.subarray(4, 4 + len);
  return { value: JSON.parse(body.toString("utf8")), consumed: 4 + len };
}
