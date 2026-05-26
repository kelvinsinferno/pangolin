// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Build a deterministic fixture vault for the E2E gate.
//
// Plan-LOCK: docs/issue-plans/mvp4-f-desktop-e2e.md §3.3.
//
// Generates `vault.pvf` at a fresh tempdir + writes the resulting
// absolute path to `apps/desktop/e2e/.fixture-path` so the spec files
// can read it back. The vault is built via the workspace
// `pangolin-cli` (the canonical PVF producer); when the on-disk
// format evolves the fixture follows for free. No committed binary
// blob.
//
// Three known accounts with deliberately greppable passwords:
//
//   - GitHub  / alice@example.com / github-fixture-pw-1
//   - Gmail   / alice@gmail.com   / gmail-fixture-pw-2
//   - Twitter / alice_handle      / twitter-fixture-pw-3
//
// Master password: test-password-123! (deliberately weak so Argon2
// completes in <500ms; the fixture passwords are fake test secrets,
// never real-user material).
//
// Re-run-safe: the script removes any previous fixture dir at the
// canonical path before re-building.

import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const WORKSPACE_ROOT = path.resolve(__dirname, '..', '..', '..', '..');
const FIXTURE_PATH_FILE = path.resolve(__dirname, '..', '.fixture-path');

const MASTER_PASSWORD = 'test-password-123!';

interface AccountFixture {
  name: string;
  username: string;
  password: string;
}

const ACCOUNTS: readonly AccountFixture[] = [
  { name: 'GitHub', username: 'alice@example.com', password: 'github-fixture-pw-1' },
  { name: 'Gmail', username: 'alice@gmail.com', password: 'gmail-fixture-pw-2' },
  { name: 'Twitter', username: 'alice_handle', password: 'twitter-fixture-pw-3' },
];

/**
 * Redact the value following a `--vault-password` flag in an argv
 * array — used when formatting the argv into a user-facing error
 * string. Audit HIGH H-1 hardening (2026-05-26): the prior error
 * formatter passed `args.join(' ')` straight through, leaking the
 * fixture master password into CI logs on any `account add` failure.
 * Fixture passwords are test material, but the same code path could
 * be reused (or extended) against a real vault in the future, so we
 * scrub the flag value before it ever reaches an error string. Other
 * fixture-only secrets (per-account passwords) flow via stdin and
 * never enter the argv at all.
 */
function redactArgs(args: readonly string[]): string {
  const out: string[] = [];
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i]!;
    out.push(a);
    if (a === '--vault-password' && i + 1 < args.length) {
      out.push('<REDACTED>');
      i += 1;
    }
  }
  return out.join(' ');
}

/**
 * Run `cargo run -p pangolin-cli -- <args>` from the workspace root
 * with the given stdin. Throws on non-zero exit (with the
 * `--vault-password` value redacted from the error string — see
 * `redactArgs`). Stdout + stderr pass through for debug visibility.
 */
function runCli(args: readonly string[], stdin: string): void {
  const result = spawnSync(
    'cargo',
    ['run', '--quiet', '-p', 'pangolin-cli', '--', ...args],
    {
      cwd: WORKSPACE_ROOT,
      input: stdin,
      stdio: ['pipe', 'inherit', 'inherit'],
    },
  );
  if (result.status !== 0) {
    throw new Error(
      `pangolin-cli ${redactArgs(args)} exited with status ${result.status ?? 'null'}`,
    );
  }
}

function main(): void {
  // Tear down any previous fixture dir at the recorded path. The
  // mkdtempSync below creates a fresh one for this run; old runs
  // leave temp dirs around but the OS reaps them on reboot.
  if (existsSync(FIXTURE_PATH_FILE)) {
    try {
      const previousPath = readFileSync(FIXTURE_PATH_FILE, 'utf8').trim();
      if (previousPath.length > 0 && existsSync(previousPath)) {
        const previousDir = path.dirname(previousPath);
        rmSync(previousDir, { recursive: true, force: true });
      }
    } catch {
      // Best-effort cleanup; ignore any stat/read error.
    }
  }

  const fixtureDir = mkdtempSync(path.join(tmpdir(), 'pangolin-e2e-fixture-'));

  // Audit M-5 hardening (2026-05-26): if the CLI invocation chain
  // fails partway through (e.g., on the third `account add` after the
  // vault file is already half-populated), we must remove `fixtureDir`
  // before re-throwing — otherwise the script leaks the tempdir +
  // leaves `.fixture-path` pointing at the prior run's stale path.
  // The try/finally pattern keeps the cleanup unconditional regardless
  // of throw site.
  try {
    const vaultPath = path.join(fixtureDir, 'vault.pvf');

    process.stdout.write(`[build-fixture-vault] creating ${vaultPath}\n`);

    // 1. Create a fresh vault with the master password via stdin.
    runCli(
      ['vault', 'create', '--path', vaultPath, '--password-stdin'],
      `${MASTER_PASSWORD}\n`,
    );

    // 2-4. Add the three known accounts. `--vault-password` is the
    //      documented CI-leaky path the CLI exposes for scripted use
    //      (see cli.rs::AccountAddArgs::vault_password); fixture
    //      passwords are test material only. The `--vault-password`
    //      flag value is redacted from any error message via
    //      `redactArgs` (audit HIGH H-1 hardening).
    for (const account of ACCOUNTS) {
      runCli(
        [
          'account',
          'add',
          '--vault-path',
          vaultPath,
          '--vault-password',
          MASTER_PASSWORD,
          '--name',
          account.name,
          '--username',
          account.username,
          '--password-stdin',
          '--no-totp',
        ],
        `${account.password}\n`,
      );
    }

    // Write the absolute fixture path for the spec files to read.
    writeFileSync(FIXTURE_PATH_FILE, `${vaultPath}\n`, 'utf8');
    process.stdout.write(`[build-fixture-vault] wrote ${FIXTURE_PATH_FILE}\n`);
  } catch (err) {
    rmSync(fixtureDir, { recursive: true, force: true });
    throw err;
  }
}

main();
