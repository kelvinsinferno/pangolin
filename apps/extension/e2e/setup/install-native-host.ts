// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Run pangolin-desktop install-native-host under a TempDir HOME.
// Captures the EXTENSION_TOKEN= line from stdout and the per-OS
// manifest install paths.
//
// Plan-LOCK: docs/issue-plans/mvp4-g-extension-e2e.md sec 1.

import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const WORKSPACE_ROOT = path.resolve(__dirname, "..", "..", "..", "..");
const HOST_HOME_FILE = path.resolve(__dirname, "..", ".host-home-path");
const TOKEN_FILE = path.resolve(__dirname, "..", ".token-path");

const ALLOWED_EXTENSION_ID = "ffdfbifkfdoookbcechjlkgpmcdojdjl";

const DESKTOP_BINARY = path.join(
  WORKSPACE_ROOT,
  "target",
  "debug",
  "pangolin-desktop",
);
const HOST_BINARY = path.join(
  WORKSPACE_ROOT,
  "target",
  "debug",
  "pangolin-native-messaging-host",
);

/**
 * Run pangolin-desktop install-native-host. Returns the captured
 * token (base64url no-pad, 32 bytes decoded) and the absolute path
 * of the TempDir HOME the install used. The HOME root will be set
 * on the Chrome subprocess too so chrome reads the same manifest
 * directory the install just wrote.
 */
export async function installNativeHost(): Promise<{ token: string; home: string }> {
  const home = mkdtempSync(path.join(tmpdir(), "pangolin-ext-e2e-home-"));
  const env = { ...process.env, HOME: home };
  const result = spawnSync(
    DESKTOP_BINARY,
    [
      "install-native-host",
      HOST_BINARY,
      "--allowed-extension-id",
      ALLOWED_EXTENSION_ID,
    ],
    { env, encoding: "utf8" },
  );
  if (result.status !== 0) {
    throw new Error(
      "install-native-host exited " + (result.status ?? "null") + ": " + (result.stderr ?? ""),
    );
  }
  const out = result.stdout ?? "";
  const match = /^EXTENSION_TOKEN=(\S+)$/m.exec(out);
  if (match === null || match[1] === undefined) {
    throw new Error(
      "install-native-host did not print EXTENSION_TOKEN. stdout=" + out,
    );
  }
  const token = match[1];
  // Persist for the spec layer.
  // Chrome for Testing (Q4-2025 replacement for chrome-stable as
  // the only Chromium that still honors --load-extension) reads
  // its native-messaging manifests from
  // .config/google-chrome-for-testing/NativeMessagingHosts/ --
  // NOT .config/google-chrome/ which is what the desktop install
  // code writes (mirroring the production google-chrome install
  // path). Copy the chrome manifest across so CfT finds it.
  // Done in the harness, NOT the desktop install code, so
  // production installs remain pinned to Chrome Stable path.
  const fs = await import("node:fs");
  const srcManifest = path.join(
    home,
    ".config",
    "google-chrome",
    "NativeMessagingHosts",
    "studio.kelvinsinferno.pangolin.host.json",
  );
  if (fs.existsSync(srcManifest)) {
    const dstDir = path.join(
      home,
      ".config",
      "google-chrome-for-testing",
      "NativeMessagingHosts",
    );
    fs.mkdirSync(dstDir, { recursive: true });
    fs.copyFileSync(srcManifest, path.join(dstDir, "studio.kelvinsinferno.pangolin.host.json"));
  }
  writeFileSync(HOST_HOME_FILE, home, "utf8");
  writeFileSync(TOKEN_FILE, token, "utf8");
  return { token, home };
}

/** Read the previously-captured HOME from .host-home-path. */
export function readHostHome(): string {
  return readFileSync(HOST_HOME_FILE, "utf8").trim();
}

/** Read the previously-captured token from .token-path. */
export function readToken(): string {
  return readFileSync(TOKEN_FILE, "utf8").trim();
}
