# HIGH-1 invariant guard — `pangolin-crypto` MUST NOT pull `serde` into
# its dependency tree.
#
# PowerShell mirror of `scripts/check-no-serde-in-crypto.sh`. CI runs
# the .sh script on Linux/macOS; this script runs on Windows runners.
#
# Run locally (PowerShell 7+):
#   pwsh ./scripts/check-no-serde-in-crypto.ps1
#
# Per docs/issue-plans/P1.md success criterion #11 + deny.toml: see
# the .sh script's comment block for the full rationale.

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$repoRoot = Resolve-Path (Join-Path $scriptDir "..")
Set-Location $repoRoot

# `cargo tree` writes to stdout; we count occurrences of "serde"
# case-insensitively. `Select-String -CaseSensitive:$false` returns
# match objects; `.Count` gives the line count.
$treeOutput = cargo tree -p pangolin-crypto 2>$null
$matches = $treeOutput | Select-String -Pattern 'serde' -CaseSensitive:$false
$matchCount = if ($null -eq $matches) { 0 } else { $matches.Count }

if ($matchCount -ne 0) {
    Write-Host "::error::HIGH-1 invariant violated: pangolin-crypto's tree contains $matchCount reference(s) to serde."
    Write-Host "::error::Re-run 'cargo tree -p pangolin-crypto' and inspect the path; either drop the offending dep"
    Write-Host "::error::or escalate to a Kelvin-gated plan-amendment per docs/issue-plans/P1.md."
    exit 1
}

Write-Host "OK: pangolin-crypto tree contains 0 references to serde (HIGH-1 invariant preserved)."
