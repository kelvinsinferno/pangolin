// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Spawn pangolin-desktop in background under a TempDir HOME so it
// binds its IPC server on a path the native-messaging host (also
// spawned under that HOME) can reach. The spawned process exposes
// the test-hooks side-channel via the env var
// PANGOLIN_TEST_HOOKS_LOG_PATH which we set to a per-run file.
// Specs read that file to assert on the H-1 invariant in scenario 4.

import { spawn, type ChildProcess } from "node:child_process";
import { existsSync, mkdirSync, openSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const WORKSPACE_ROOT = path.resolve(__dirname, "..", "..", "..", "..");
const HOOKS_LOG_FILE_NAME = "test-hooks-invocations.log";

const DESKTOP_BINARY = path.join(
  WORKSPACE_ROOT,
  "target",
  "debug",
  "pangolin-desktop",
);

export interface DesktopHandle {
  child: ChildProcess;
  pid: number;
  home: string;
  hooksLogPath: string;
  stop: () => Promise<void>;
}

export interface SpawnOptions {
  /** Absolute path to the TempDir HOME (also where Chrome reads its
   * native-messaging manifest from). */
  home: string;
  /** Path the desktop will append each test-hooks invocation to. */
  hooksLogPath?: string;
  /** XDG_RUNTIME_DIR; when omitted defaults to home + /xdg. */
  xdgRuntimeDir?: string;
}

/**
 * Spawn pangolin-desktop in background. Captures stdout + stderr to
 * logs/desktop.log. Returns a handle with a stop() method.
 *
 * The caller is expected to wait for the IPC server bind via a
 * separate readiness probe (the IPC socket path appears under
 * /run/user/1000//pangolin/native-host.sock once bind completes).
 */
export function startDesktop(opts: SpawnOptions): DesktopHandle {
  const hooksLogPath =
    opts.hooksLogPath ?? path.join(opts.home, HOOKS_LOG_FILE_NAME);
  // Pre-create the file so OpenOptions::append always finds it.
  writeFileSync(hooksLogPath, "", "utf8");
  const logsDir = path.resolve(__dirname, "..", "logs");
  mkdirSync(logsDir, { recursive: true });
  const stderrLog = path.join(logsDir, "desktop.log");
  const xdgRuntimeDir =
    opts.xdgRuntimeDir ?? path.join(opts.home, "xdg-runtime");
  mkdirSync(xdgRuntimeDir, { recursive: true, mode: 0o700 });
  const env = {
    ...process.env,
    HOME: opts.home,
    XDG_DATA_HOME: path.join(opts.home, ".local", "share"),
    XDG_RUNTIME_DIR: xdgRuntimeDir,
    PANGOLIN_TEST_HOOKS_LOG_PATH: hooksLogPath,
    // GTK / WebKit need a DISPLAY; xvfb-run --auto-servernum sets
    // it for us, but if it slips through unset, the Tauri window
    // will refuse to open.
    DISPLAY: process.env["DISPLAY"] ?? ":99",
  };
  // Persist for cross-spec discovery.
  writeFileSync(path.join(opts.home, ".hooks-log-path"), hooksLogPath, "utf8");
  const out = openSync(stderrLog, "a");
  const child = spawn(DESKTOP_BINARY, [], {
    env,
    stdio: ["ignore", out, out],
    detached: false,
  });
  if (child.pid === undefined) {
    throw new Error("pangolin-desktop spawn returned no pid");
  }
  const pid = child.pid;
  const stop = async (): Promise<void> => {
    try {
      child.kill("SIGTERM");
    } catch {
      /* already dead */
    }
    // Wait up to 5s for exit.
    await new Promise<void>((resolve) => {
      let done = false;
      const finish = (): void => {
        if (done) return;
        done = true;
        resolve();
      };
      child.once("exit", finish);
      setTimeout(() => {
        try {
          child.kill("SIGKILL");
        } catch {
          /* already dead */
        }
        finish();
      }, 5_000);
    });
  };
  return { child, pid, home: opts.home, hooksLogPath, stop };
}

/**
 * Poll for the IPC server bind by checking the per-user socket
 * exists. Resolves true once present; false on timeout.
 */
export async function waitForIpcReady(
  _home: string,
  xdgRuntimeDir: string,
  timeoutMs: number = 30_000,
): Promise<boolean> {
  const sock = path.join(xdgRuntimeDir, "pangolin", "native-host.sock");
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (existsSync(sock)) return true;
    await new Promise((r) => setTimeout(r, 200));
  }
  return false;
}

/** Read the hooks log file as a newline-separated list. */
export function readHooksLog(hooksLogPath: string): string[] {
  if (!existsSync(hooksLogPath)) return [];
  const body = readFileSync(hooksLogPath, "utf8");
  return body.split(/\r?\n/).filter((s) => s.length > 0);
}
