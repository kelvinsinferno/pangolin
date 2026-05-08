<#
.SYNOPSIS
    Pangolin PoC release pipeline for Windows-x64.

.DESCRIPTION
    Produces a distributable artefact set under dist/windows-x64/:
        pangolin-cli.exe        (the user-facing PoC CLI)
        chaincli.exe            (the debug oracle CLI)
        LICENSE                 (Apache-2.0 — required redistribution)
        POC_README.md           (snapshot of the entry-point doc)
        docs/E2E_REPRODUCER.md  (snapshot of the scenario walkthrough)
        SHA256SUMS              (Linux-style "<hash>  <filename>" manifest)
        SHA256SUMS.asc          (detached GPG signature over the manifest;
                                 produced unless -SkipSign is set)

    Bundles the directory into pangolin-poc-v0.0.0-windows-x64.zip at the
    repository root for upload to the GitHub Releases page.

    Per docs/issue-plans/P12.md §A1, the binaries themselves are NOT
    Authenticode-signed for the PoC; trust is anchored on the GPG-signed
    SHA256SUMS manifest plus per-binary hash verification. Authenticode
    acquisition is deferred to MVP-1.

.PARAMETER SkipSign
    Skip the gpg --detach-sign step. Use this in CI, on hosts without the
    signing key, or for pre-flight smoke runs. The resulting release zip
    is INCOMPLETE — it ships SHA256SUMS but no SHA256SUMS.asc, so users
    cannot verify the manifest's authenticity. Suitable for testing the
    pipeline; not suitable for the actual user-facing release.

.PARAMETER SkipPreflight
    Skip the cargo fmt / clippy / test pre-flight gate (§A15 of P12.md).
    Provided for repeated re-runs while debugging the release script
    itself; the actual user-facing release MUST run the pre-flight.

.PARAMETER Version
    Version tag to embed in the zip filename. Defaults to "0.0.0-poc"
    per DECISIONS D-014/D-015 era + P12 §A3 versioning.

.EXAMPLE
    .\scripts\release-windows.ps1
    # Full release with pre-flight + GPG sign. Produces the user-facing zip.

.EXAMPLE
    .\scripts\release-windows.ps1 -SkipSign
    # Pipeline smoke test; no GPG required. CI / non-keyholder path.

.EXAMPLE
    .\scripts\release-windows.ps1 -SkipPreflight -SkipSign
    # Fastest re-run while debugging the script itself.

.NOTES
    Spec: docs/issue-plans/P12.md §2 (P12-1).
    Runbook: docs/RELEASE.md (prerequisites, GPG key fingerprint,
    GitHub Release upload steps).
#>

[CmdletBinding()]
param(
    [switch]$SkipSign,
    [switch]$SkipPreflight,
    [string]$Version = "0.0.0-poc"
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# Resolve repository root (parent of the script directory).
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$repoRoot = Resolve-Path (Join-Path $scriptDir "..")
Set-Location $repoRoot

Write-Host "==> Pangolin PoC release pipeline (Windows-x64)" -ForegroundColor Cyan
Write-Host "    Repo:    $repoRoot"
Write-Host "    Version: $Version"
Write-Host "    Sign:    $(if ($SkipSign) { 'NO (--SkipSign)' } else { 'YES (gpg --detach-sign)' })"
Write-Host ""

# -----------------------------------------------------------------------------
# Step 0 — pre-flight gate (cargo fmt / clippy / test).
# Per P12.md §A15: releases should not ship from a red tree.
# -----------------------------------------------------------------------------
if (-not $SkipPreflight) {
    Write-Host "==> Pre-flight: cargo fmt --all -- --check" -ForegroundColor Cyan
    cargo fmt --all -- --check
    if ($LASTEXITCODE -ne 0) { throw "cargo fmt --check failed; aborting release." }

    Write-Host "==> Pre-flight: cargo clippy --workspace --all-targets -- -D warnings" -ForegroundColor Cyan
    cargo clippy --workspace --all-targets -- -D warnings
    if ($LASTEXITCODE -ne 0) { throw "cargo clippy failed; aborting release." }

    Write-Host "==> Pre-flight: cargo test --workspace --lib" -ForegroundColor Cyan
    cargo test --workspace --lib
    if ($LASTEXITCODE -ne 0) { throw "cargo test --lib failed; aborting release." }
} else {
    Write-Host "==> Pre-flight SKIPPED (--SkipPreflight)" -ForegroundColor Yellow
}

# -----------------------------------------------------------------------------
# Step 1 — release build.
# -----------------------------------------------------------------------------
Write-Host ""
Write-Host "==> Building release artefacts (cargo build --workspace --release)" -ForegroundColor Cyan
cargo build --workspace --release
if ($LASTEXITCODE -ne 0) { throw "cargo build --release failed; aborting." }

# -----------------------------------------------------------------------------
# Step 2 — verify the expected binaries built.
# -----------------------------------------------------------------------------
$expectedBinaries = @(
    @{ name = "pangolin-cli.exe"; src = "target\release\pangolin-cli.exe" },
    @{ name = "chaincli.exe";     src = "target\release\chaincli.exe" }
)

foreach ($bin in $expectedBinaries) {
    if (-not (Test-Path $bin.src)) {
        throw "Expected binary not found: $($bin.src)"
    }
    $size = (Get-Item $bin.src).Length
    if ($size -le 0) {
        throw "Binary is zero-length: $($bin.src)"
    }
    Write-Host ("    {0,-22} {1,12:N0} bytes" -f $bin.name, $size)
}

# -----------------------------------------------------------------------------
# Step 3 — clobber + recreate dist/windows-x64/ for idempotency.
# -----------------------------------------------------------------------------
$distRoot = Join-Path $repoRoot "dist"
$distDir  = Join-Path $distRoot "windows-x64"

if (Test-Path $distDir) {
    Write-Host ""
    Write-Host "==> Clearing existing $distDir" -ForegroundColor Cyan
    Remove-Item -Recurse -Force $distDir
}
New-Item -ItemType Directory -Path $distDir -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $distDir "docs") -Force | Out-Null

# -----------------------------------------------------------------------------
# Step 4 — copy binaries + redistributable docs into dist.
# -----------------------------------------------------------------------------
Write-Host ""
Write-Host "==> Copying artefacts into $distDir" -ForegroundColor Cyan

foreach ($bin in $expectedBinaries) {
    Copy-Item -Path $bin.src -Destination (Join-Path $distDir $bin.name) -Force
}

$docsToShip = @(
    @{ src = "LICENSE";                     dst = "LICENSE" },
    @{ src = "POC_README.md";               dst = "POC_README.md" },
    @{ src = "docs\E2E_REPRODUCER.md";      dst = "docs\E2E_REPRODUCER.md" }
)

foreach ($doc in $docsToShip) {
    if (-not (Test-Path $doc.src)) {
        throw "Expected redistributable doc not found: $($doc.src)"
    }
    Copy-Item -Path $doc.src -Destination (Join-Path $distDir $doc.dst) -Force
}

# -----------------------------------------------------------------------------
# Step 5 — compute SHA-256 manifest.
# Format: "<lowercase-hex-hash>  <relative-path>" per Linux sha256sum.
# Sorted by relative path for determinism across re-runs.
# -----------------------------------------------------------------------------
Write-Host ""
Write-Host "==> Computing SHA-256 manifest" -ForegroundColor Cyan

$manifestEntries = New-Object System.Collections.Generic.List[string]
$relPaths = Get-ChildItem -Path $distDir -Recurse -File |
    Where-Object { $_.Name -ne "SHA256SUMS" -and $_.Name -ne "SHA256SUMS.asc" } |
    ForEach-Object { (Resolve-Path -LiteralPath $_.FullName -Relative -RelativeBasePath $distDir) -replace '^\.[\\/]','' -replace '\\','/' } |
    Sort-Object

foreach ($rel in $relPaths) {
    # Convert the unix-style relative path back to a real filesystem path.
    $abs = Join-Path $distDir ($rel -replace '/','\')
    $hash = (Get-FileHash -Algorithm SHA256 -Path $abs).Hash.ToLowerInvariant()
    $line = "{0}  {1}" -f $hash, $rel
    $manifestEntries.Add($line)
    Write-Host "    $line"
}

$manifestPath = Join-Path $distDir "SHA256SUMS"
# Write as UTF-8 WITHOUT BOM (sha256sum -c on Linux/WSL is tolerant of BOM
# but we keep the file portable; LF line endings for the same reason).
$manifestText = ($manifestEntries -join "`n") + "`n"
[System.IO.File]::WriteAllText($manifestPath, $manifestText, [System.Text.UTF8Encoding]::new($false))

# -----------------------------------------------------------------------------
# Step 6 — GPG-sign the manifest (unless --SkipSign).
# -----------------------------------------------------------------------------
$sigPath = Join-Path $distDir "SHA256SUMS.asc"

if (-not $SkipSign) {
    Write-Host ""
    Write-Host "==> Signing manifest with GPG (gpg --detach-sign --armor)" -ForegroundColor Cyan

    $gpgCmd = Get-Command gpg -ErrorAction SilentlyContinue
    if ($null -eq $gpgCmd) {
        throw "gpg.exe not found on PATH. Install GnuPG (https://www.gnupg.org/download/) or re-run with -SkipSign."
    }

    if (Test-Path $sigPath) { Remove-Item -Force $sigPath }
    & gpg --batch --yes --detach-sign --armor --output $sigPath $manifestPath
    if ($LASTEXITCODE -ne 0) { throw "gpg --detach-sign failed; aborting." }

    if (-not (Test-Path $sigPath)) { throw "GPG signature file was not produced at $sigPath" }
    Write-Host "    Wrote $sigPath"
} else {
    Write-Host ""
    Write-Host "==> GPG signing SKIPPED (--SkipSign)" -ForegroundColor Yellow
    Write-Host "    The release zip will ship SHA256SUMS but NO SHA256SUMS.asc."
    Write-Host "    This is suitable for pipeline testing; NOT for the user-facing release."
}

# -----------------------------------------------------------------------------
# Step 7 — bundle into the upload zip.
# -----------------------------------------------------------------------------
$zipName = "pangolin-poc-v$Version-windows-x64.zip"
$zipPath = Join-Path $repoRoot $zipName

Write-Host ""
Write-Host "==> Bundling $zipName" -ForegroundColor Cyan

if (Test-Path $zipPath) { Remove-Item -Force $zipPath }
# -DestinationPath wants a literal file name; -Path takes the directory contents.
Compress-Archive -Path (Join-Path $distDir "*") -DestinationPath $zipPath -CompressionLevel Optimal

$zipSize = (Get-Item $zipPath).Length

# -----------------------------------------------------------------------------
# Step 8 — summary.
# -----------------------------------------------------------------------------
Write-Host ""
Write-Host "==> Release pipeline complete." -ForegroundColor Green
Write-Host ""
Write-Host "    Dist directory: $distDir"
Write-Host "    Upload zip:     $zipPath ({0:N0} bytes)" -f $zipSize
Write-Host "    Manifest:       $manifestPath"
if (-not $SkipSign) {
    Write-Host "    Signature:      $sigPath"
} else {
    Write-Host "    Signature:      (skipped)"
}
Write-Host ""
Write-Host "    Verify locally:"
Write-Host "        Get-FileHash -Algorithm SHA256 (Join-Path '$distDir' 'pangolin-cli.exe')"
if (-not $SkipSign) {
    Write-Host "        gpg --verify '$sigPath' '$manifestPath'"
}
Write-Host ""
Write-Host "    Next: upload $zipName plus SHA256SUMS and SHA256SUMS.asc"
Write-Host "    to a GitHub Release tagged v$Version. See docs/RELEASE.md."
