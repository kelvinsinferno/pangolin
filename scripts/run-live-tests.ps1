# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Issue #98 R-f Option P: pre-release live-test runner (PowerShell 7+).
#
# Runs the surviving #[ignore]'d live tests (the Option D
# residue — bytes-parsing surfaces are covered by the hermetic
# replay siblings on every PR) against a real Base Sepolia RPC.
#
# Pairs with `run-live-tests.sh` (the Bash sibling).
#
# Sources gitignored `.env.live` from the repo root; that file
# should NOT be committed (already in `.gitignore`). Suggested
# template (PowerShell syntax):
#
#   # .env.live (gitignored)
#   $env:BASE_SEPOLIA_RPC_URL = 'https://sepolia.base.org'
#   $env:BASE_SEPOLIA_DEV_WALLET = '0x89e720238A3913688CB0E025ef03a64539575c54'
#   $env:PANGOLIN_INDEXER_VAULT_ID = '...'    # 64-char hex, no 0x
#   $env:PANGOLIN_PULL_LIVE_VAULT_ID = '...'  # 64-char hex, no 0x
#   $env:PANGOLIN_SYNC_LIVE_VAULT_ID = '...'  # 64-char hex, no 0x
#   $env:PANGOLIN_LIVE_KEYSTORE_PATH = '...'
#   $env:PANGOLIN_LIVE_KEYSTORE_PASSWORD = '...'

$ErrorActionPreference = 'Stop'

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
Set-Location $RepoRoot

$EnvFile = Join-Path $RepoRoot '.env.live'
if (-not (Test-Path $EnvFile)) {
    Write-Error "ERROR: .env.live not found at $EnvFile. Create it from the template in scripts/run-live-tests.ps1 comment."
}

# PowerShell-native sourcing: the file is expected to contain
# `$env:KEY = 'value'` statements (NOT Bash-style `export`). Dot-source
# it so the assignments land in the current scope.
. $EnvFile

Write-Host "==> Issue #98 R-f: live-test runner (PowerShell)"
Write-Host "    repo root: $RepoRoot"
Write-Host "    BASE_SEPOLIA_RPC_URL=$($env:BASE_SEPOLIA_RPC_URL)"
Write-Host ""

# Issue #98 env-quirk #16: workspace-wide `cargo test --workspace ... --
# --ignored --nocapture` is short enough to clear PowerShell's
# ~8191-char limit without per-crate enumeration.
Write-Host "==> cargo test --workspace -- --ignored"
& cargo test --workspace --all-targets -- --ignored --nocapture
if ($LASTEXITCODE -ne 0) {
    Write-Error "live tests reported failures (exit $LASTEXITCODE)"
}
