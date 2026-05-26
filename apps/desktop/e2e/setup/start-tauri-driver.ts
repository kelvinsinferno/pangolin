// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Spawn + reap the `tauri-driver` child process for the E2E gate.
//
// Plan-LOCK: docs/issue-plans/mvp4-f-desktop-e2e.md §1 + §3.1.
//
// `tauri-driver` is installed via `cargo install --version =0.1.4
// tauri-driver` (lands in `~/.cargo/bin/`). The binary takes no args;
// it binds to port 4444 by default and proxies W3C WebDriver requests
// to the Tauri WebView the spec drives. The helper:
//
//   1. Spawns `tauri-driver` as a child process (stdio captured for
//      the wdio-logs/ artifact).
//   2. Polls `localhost:4444` until the driver responds (or 30s).
//   3. Returns a handle the wdio.conf.ts `onComplete` hook uses to
//      SIGTERM the child.
//
// The 30s poll budget covers the cold-start case where cargo's
// `~/.cargo/bin` has just been added to PATH + the binary is being
// linked for the first time. On a warm CI runner the bind happens in
// <100ms.

import { spawn, type ChildProcess } from 'node:child_process';
import { createConnection } from 'node:net';

const TAURI_DRIVER_PORT = 4444;
const POLL_INTERVAL_MS = 200;
const POLL_TIMEOUT_MS = 30_000;

/**
 * Probe a TCP port; resolves true if the port accepts a TCP connection.
 *
 * Closes the socket as soon as it's open (we only care that a server
 * is listening). 100ms timeout per probe; the outer loop retries.
 */
function probePort(port: number, host: string): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = createConnection({ port, host });
    let done = false;
    const finish = (result: boolean): void => {
      if (done) return;
      done = true;
      socket.destroy();
      resolve(result);
    };
    socket.setTimeout(100);
    socket.once('connect', () => finish(true));
    socket.once('error', () => finish(false));
    socket.once('timeout', () => finish(false));
  });
}

/**
 * Spawn `tauri-driver` and wait for its port to bind.
 *
 * The spawned process inherits the parent's PATH so `~/.cargo/bin`
 * must already be on it (CI's `cargo install` step appends it via the
 * `dtolnay/rust-toolchain@stable` action; local devs use their own
 * `cargo install`).
 */
export async function startTauriDriver(): Promise<{ kill: () => void }> {
  const child: ChildProcess = spawn('tauri-driver', [], {
    stdio: ['ignore', 'inherit', 'inherit'],
  });

  child.on('error', (err) => {
    // `child.on('error')` fires when the binary itself cannot be
    // spawned (e.g. not on PATH). The outer port-poll loop will
    // notice the lack of a listener + fail with a clearer message;
    // we surface the underlying spawn error here for the wdio logs.
    process.stderr.write(`tauri-driver spawn error: ${err.message}\n`);
  });

  const deadline = Date.now() + POLL_TIMEOUT_MS;
  while (Date.now() < deadline) {
    if (await probePort(TAURI_DRIVER_PORT, 'localhost')) {
      return {
        kill: () => {
          if (!child.killed) {
            child.kill('SIGTERM');
          }
        },
      };
    }
    await new Promise<void>((r) => setTimeout(r, POLL_INTERVAL_MS));
  }

  // Failed to bind within the budget. Kill the child (best-effort)
  // + raise so wdio.conf.ts's onPrepare propagates the failure.
  if (!child.killed) {
    child.kill('SIGTERM');
  }
  throw new Error(
    `tauri-driver did not bind localhost:${TAURI_DRIVER_PORT} within ${POLL_TIMEOUT_MS} ms`,
  );
}

/**
 * SIGTERM the spawned `tauri-driver` process. Safe to call with `null`
 * if `startTauriDriver` was never called (e.g. an earlier setup step
 * failed).
 */
export function stopTauriDriver(handle: { kill: () => void } | null): void {
  if (handle) {
    handle.kill();
  }
}
