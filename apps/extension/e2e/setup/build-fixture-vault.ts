// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Build a deterministic fixture vault for the extension E2E gate.
//
// Plan-LOCK: docs/issue-plans/mvp4-g-extension-e2e.md §1 + §0a.
//
// Exposes buildFixtureVault(): returns the absolute path to a freshly
// built vault.pvf under apps/extension/e2e/.fixture/. Built via the
// workspace pangolin-cli (the canonical PVF producer) so the fixture
// follows the on-disk format for free; no committed binary blob.
//
// Three known accounts with deliberately greppable passwords:
//   - GitHub  / alice@example.com / github-fixture-pw-1
//   - Gmail   / alice@gmail.com   / gmail-fixture-pw-2
//   - Twitter / alice_handle      / twitter-fixture-pw-3
//
// Master password: test-password-123! (deliberately weak; fixture
// passwords are fake test secrets, never real-user material).

import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";

const WORKSPACE_ROOT = path.resolve(import.meta.dirname, "..", "..", "..", "..");
const FIXTURE_PATH_FILE = path.resolve(import.meta.dirname, "..", ".fixture-path");

export const MASTER_PASSWORD = "test-password-123!";

interface AccountFixture {
  name: string;
  username: string;
  password: string;
}

const ACCOUNTS: readonly AccountFixture[] = [
  { name: "GitHub", username: "alice@example.com", password: "github-fixture-pw-1" },
  { name: "Gmail", username: "alice@gmail.com", password: "gmail-fixture-pw-2" },
  { name: "Twitter", username: "alice_handle", password: "twitter-fixture-pw-3" },
];

/**
 * Redact the value following a `--vault-password` flag in an argv
 * array — used when formatting the argv into an error string. The
 * fixture passwords are test material, but the same code path could
 * be reused against a real vault, so we scrub the flag value before
 * it can reach a log. (Carried from the MVP-4-F audit H-1 hardening.)
 */
function redactArgs(args: readonly string[]): string {
  const out: string[] = [];
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i]!;
    out.push(a);
    if (a === "--vault-password" && i + 1 < args.length) {
      out.push("<REDACTED>");
      i += 1;
    }
  }
  return out.join(" ");
}

function runCli(args: readonly string[], stdin: string): void {
  const result = spawnSync(
    "cargo",
    ["run", "--quiet", "-p", "pangolin-cli", "--", ...args],
    { cwd: WORKSPACE_ROOT, input: stdin, stdio: ["pipe", "inherit", "inherit"] },
  );
  if (result.status !== 0) {
    throw new Error(
      `pangolin-cli ${redactArgs(args)} exited with status ${result.status ?? "null"}`,
    );
  }
}

/**
 * Build a fresh fixture vault. Returns the absolute path to vault.pvf.
 * Idempotent: removes any prior .fixture dir before rebuilding.
 */
export function buildFixtureVault(): string {
  const fixtureDir = path.resolve(import.meta.dirname, "..", ".fixture");
  if (existsSync(fixtureDir)) {
    rmSync(fixtureDir, { recursive: true, force: true });
  }
  mkdirSync(fixtureDir, { recursive: true });

  try {
    const vaultPath = path.join(fixtureDir, "vault.pvf");
    runCli(
      ["vault", "create", "--path", vaultPath, "--password-stdin"],
      `${MASTER_PASSWORD}\n`,
    );
    for (const account of ACCOUNTS) {
      runCli(
        [
          "account", "add",
          "--vault-path", vaultPath,
          "--vault-password", MASTER_PASSWORD,
          "--name", account.name,
          "--username", account.username,
          "--password-stdin", "--no-totp",
        ],
        `${account.password}\n`,
      );
    }
    writeFileSync(FIXTURE_PATH_FILE, `${vaultPath}\n`, "utf8");
    return vaultPath;
  } catch (err) {
    rmSync(fixtureDir, { recursive: true, force: true });
    throw err;
  }
}

// Allow `tsx build-fixture-vault.ts` as a standalone script too.
if (import.meta.url === `file://${process.argv[1]}`) {
  const p = buildFixtureVault();
  process.stdout.write(`[build-fixture-vault] wrote ${p}\n`);
}
