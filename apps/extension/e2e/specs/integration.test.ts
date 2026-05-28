// SPDX-License-Identifier: AGPL-3.0-or-later
//
// MVP-4-G Node integration gate (plan-LOCK §0a Q-c).
//
// Exercises the REAL popup-side NativeHostClient → REAL
// pangolin-native-messaging-host binary → REAL pangolin-desktop IPC
// → pangolin-ffi, end-to-end. Only Chrome's connectNative transport
// is replaced (by the stdio bridge in setup/stdio-connector.ts);
// every line of OUR code runs against the real binaries.
//
// Covers the data-path halves of the plan's 5 scenarios:
//   2. provisions-and-connects  -> connect() + session.status
//   3. lists-accounts           -> list_accounts returns the 3 fixtures
//   4. copies-password (H-1)    -> copy_password fires Rust-side; reveal does NOT
//   5. handles-desktop-disconnect -> kill desktop, next call rejects transport
// (scenario 1 "loads-disconnected" is a pure popup-UI concern; Vitest
// covers it in src/popup/Popup.test.tsx.)

import { expect } from "chai";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import {
  type FfiAccountSummary,
  NativeHostClient,
  NativeHostError,
} from "../../src/popup/native-host.js";
import { makeStdioConnector } from "../setup/stdio-connector.js";
import { installNativeHost } from "../setup/install-native-host.js";
import {
  type DesktopHandle,
  readHooksLog,
  startDesktop,
  waitForIpcReady,
} from "../setup/start-desktop.js";
import { buildFixtureVault } from "../setup/build-fixture-vault.js";

const MASTER_PASSWORD = "test-password-123!";
const HOST_BINARY = path.resolve(
  import.meta.dirname,
  "..",
  "..",
  "..",
  "..",
  "target",
  "debug",
  "pangolin-native-messaging-host",
);

interface Ctx {
  home: string;
  token: string;
  xdgRuntimeDir: string;
  desktop: DesktopHandle;
  hooksLogPath: string;
}

async function setup(): Promise<Ctx> {
  // 1. Build a fixture vault + capture its path.
  const fixtureVaultPath = buildFixtureVault();

  // 2. install-native-host under a TempDir HOME → token + manifests.
  const { token, home } = await installNativeHost();

  // 3. Copy the fixture vault into the test HOME so auto-unlock finds it.
  const specVaultPath = path.join(home, "vault.pvf");
  const { copyFileSync } = await import("node:fs");
  copyFileSync(fixtureVaultPath, specVaultPath);

  // 4. XDG_RUNTIME_DIR for the IPC socket rendezvous.
  const xdgRuntimeDir = mkdtempSync(path.join(tmpdir(), "pangolin-xdg-"));

  // 5. Start the desktop with auto-unlock + the test-hooks side channel.
  const hooksLogPath = path.join(home, "hooks.log");
  const saved = {
    p: process.env["PANGOLIN_TEST_AUTO_UNLOCK_PATH"],
    w: process.env["PANGOLIN_TEST_AUTO_UNLOCK_PASSWORD"],
  };
  process.env["PANGOLIN_TEST_AUTO_UNLOCK_PATH"] = specVaultPath;
  process.env["PANGOLIN_TEST_AUTO_UNLOCK_PASSWORD"] = MASTER_PASSWORD;
  let desktop: DesktopHandle;
  try {
    desktop = startDesktop({ home, xdgRuntimeDir, hooksLogPath });
  } finally {
    if (saved.p === undefined) delete process.env["PANGOLIN_TEST_AUTO_UNLOCK_PATH"];
    else process.env["PANGOLIN_TEST_AUTO_UNLOCK_PATH"] = saved.p;
    if (saved.w === undefined) delete process.env["PANGOLIN_TEST_AUTO_UNLOCK_PASSWORD"];
    else process.env["PANGOLIN_TEST_AUTO_UNLOCK_PASSWORD"] = saved.w;
  }

  const ready = await waitForIpcReady(home, xdgRuntimeDir, 60_000);
  if (!ready) {
    await desktop.stop();
    throw new Error("pangolin-desktop IPC server did not bind within 60s");
  }

  return { home, token, xdgRuntimeDir, desktop, hooksLogPath };
}

function makeClient(ctx: Ctx): NativeHostClient {
  const connector = makeStdioConnector({
    hostBinary: HOST_BINARY,
    home: ctx.home,
    xdgRuntimeDir: ctx.xdgRuntimeDir,
  });
  return new NativeHostClient(connector);
}

describe("MVP-4-G integration: popup-client → host → desktop", function () {
  this.timeout(180_000);
  let ctx: Ctx | null = null;

  before(async () => {
    if (!existsSync(HOST_BINARY)) {
      throw new Error(
        `host binary missing at ${HOST_BINARY} — run \`cargo build -p pangolin-native-messaging-host --features test-hooks\` first`,
      );
    }
    ctx = await setup();
  });

  after(async () => {
    if (ctx !== null) {
      await ctx.desktop.stop();
      // Scrub vault sidecars (MVP-4-F LOW-1 workaround; issue #3).
      for (const suffix of [".lock", "-shm", "-wal"]) {
        const sidecar = path.join(ctx.home, `vault.pvf${suffix}`);
        if (existsSync(sidecar)) rmSync(sidecar, { force: true });
      }
    }
  });

  it("scenario 2 — handshake + session.status reports unlocked", async () => {
    if (ctx === null) throw new Error("no ctx");
    const client = makeClient(ctx);
    await client.connect(ctx.token);
    const status = await client.sessionStatus();
    expect(status.vault_open).to.equal(true);
    expect(status.vault_unlocked).to.equal(true);
    client.disconnect();
  });

  it("scenario 3 — list_accounts returns the 3 fixture accounts", async () => {
    if (ctx === null) throw new Error("no ctx");
    const client = makeClient(ctx);
    await client.connect(ctx.token);
    const accounts: FfiAccountSummary[] = await client.listAccounts();
    const names = accounts.map((a) => a.display_name).sort();
    expect(names).to.deep.equal(["GitHub", "Gmail", "Twitter"]);
    client.disconnect();
  });

  it("scenario 4 (H-1) — copy_password fires Rust-side; reveal does NOT", async () => {
    if (ctx === null) throw new Error("no ctx");
    const client = makeClient(ctx);
    await client.connect(ctx.token);
    const accounts = await client.listAccounts();
    const github = accounts.find((a) => a.display_name === "GitHub");
    expect(github, "GitHub fixture present").to.not.equal(undefined);
    await client.copyPassword(github!.id);
    // Allow the desktop to flush its hooks-log append.
    await new Promise((r) => setTimeout(r, 500));
    const log = readHooksLog(ctx.hooksLogPath);
    expect(log, "copy_password_to_clipboard fired Rust-side").to.include(
      "copy_password_to_clipboard",
    );
    expect(log, "reveal_password must NOT fire on the copy path").to.not.include(
      "reveal_password",
    );
    client.disconnect();
  });

  it("scenario 5 — desktop disconnect surfaces a typed transport error", async () => {
    if (ctx === null) throw new Error("no ctx");
    const client = makeClient(ctx);
    await client.connect(ctx.token);
    // Kill the desktop; the host's relay drops, the port disconnects.
    await ctx.desktop.stop();
    let threw: unknown = null;
    try {
      await client.listAccounts();
    } catch (e) {
      threw = e;
    }
    expect(threw, "a call after desktop death must reject").to.be.instanceOf(
      NativeHostError,
    );
    client.disconnect();
  });

  it("rejects a wrong handshake token (auth_failed)", async () => {
    if (ctx === null) throw new Error("no ctx");
    // Restart the desktop killed by scenario 5 so this runs against a
    // live IPC server.
    process.env["PANGOLIN_TEST_AUTO_UNLOCK_PATH"] = path.join(ctx.home, "vault.pvf");
    process.env["PANGOLIN_TEST_AUTO_UNLOCK_PASSWORD"] = MASTER_PASSWORD;
    ctx.desktop = startDesktop({
      home: ctx.home,
      xdgRuntimeDir: ctx.xdgRuntimeDir,
      hooksLogPath: ctx.hooksLogPath,
    });
    delete process.env["PANGOLIN_TEST_AUTO_UNLOCK_PATH"];
    delete process.env["PANGOLIN_TEST_AUTO_UNLOCK_PASSWORD"];
    const ready = await waitForIpcReady(ctx.home, ctx.xdgRuntimeDir, 60_000);
    expect(ready, "desktop re-bound").to.equal(true);

    const client = makeClient(ctx);
    let threw: NativeHostError | null = null;
    try {
      await client.connect("wrong-token-not-the-real-one");
    } catch (e) {
      threw = e as NativeHostError;
    }
    expect(threw, "wrong token rejected").to.be.instanceOf(NativeHostError);
    client.disconnect();
  });
});
