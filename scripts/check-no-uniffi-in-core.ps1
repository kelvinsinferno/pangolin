# MVP-1 issue 1.1 (Q3) invariant guard — `pangolin-core` MUST NOT pull
# `uniffi` into its dependency tree.
#
# PowerShell mirror of `scripts/check-no-uniffi-in-core.sh`.
#
# Run locally (PowerShell 7+):
#   pwsh ./scripts/check-no-uniffi-in-core.ps1

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$repoRoot = Resolve-Path (Join-Path $scriptDir "..")
Set-Location $repoRoot

$treeOutput = cargo tree -p pangolin-core 2>$null
$matches = $treeOutput | Select-String -Pattern 'uniffi' -CaseSensitive:$false
$matchCount = if ($null -eq $matches) { 0 } else { $matches.Count }

if ($matchCount -ne 0) {
    Write-Host "::error::MVP-1 issue 1.1 Q3 invariant violated: pangolin-core's tree contains $matchCount reference(s) to uniffi."
    Write-Host "::error::Re-run 'cargo tree -p pangolin-core' and inspect the path; the FFI surface must stay isolated"
    Write-Host "::error::in pangolin-ffi. See docs/issue-plans/1.1.md success criterion 4."
    exit 1
}

Write-Host "OK: pangolin-core tree contains 0 references to uniffi (issue 1.1 Q3 invariant preserved)."
