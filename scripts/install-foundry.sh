#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Direct-tarball Foundry installer for CI. Replaces the
# `foundry-rs/foundry-toolchain@v1` Action with a fixed install path
# that is reproducible across runners.
#
# # Why this exists (CI regression — first failure run #196, 2026-06-01)
#
# The `foundry-toolchain@v1` Action wraps `foundryup --install
# <version>`. `foundryup` downloads its own latest source on every
# invocation (from `raw.githubusercontent.com/foundry-rs/foundry/HEAD/foundryup/foundryup`),
# so a foundryup-side change can break our CI even though we pin the
# Foundry release to v1.0.0.
#
# Around 2026-04 the upstream foundryup added a sigstore attestation
# verification path (commit `906020fe "feat: immutable releases"`).
# That path probes `foundry_<VERSION>_<PLATFORM>.attestation.txt` on
# the GitHub release. The v1.0.0 release (2025-02) predates the
# attestation feature and has NO `.attestation.txt` asset — only the
# `.tar.gz`. Both WSL and CI runners get HTTP 404 with body "Not
# Found" for that URL.
#
# On WSL, foundryup's `grep -q 'Not Found'` on the downloaded body
# matches, sets `attestation_missing=true`, and skips verification
# (the binaries install cleanly). On GitHub-hosted Linux runners
# (verified by reading run 26757764183 — first failure on
# mvp4-h-secure-input), the same `grep` does NOT match — foundryup
# proceeds to "found attestation, downloading attestation artifact"
# and then errors with `Command failed: bash foundryup --install
# 1.0.0` after the download. The most likely explanation is the
# GitHub Actions egress path serving a different 404 body (HTML or
# a 200 from an edge cache) — confirmed by the discrepancy between
# the WSL reproduction (works) and CI (fails) using IDENTICAL
# foundryup HEADs (the script's own "is up to date" check passes).
#
# Bumping Foundry to a release with attestation assets (v1.7.x) would
# fix the symptom, but per [[pangolin_environment_quirks.md]] the CI
# forge MUST match Kelvin's local forge — bumping requires a
# coordinated local update + verifying our scripts under the v1.7.x
# breaking changes (`--no-commit` removed, new `unsafe-typecast`
# linter). Out of scope for THIS fix.
#
# This script keeps Foundry on v1.0.0 (matching local) while
# bypassing the broken foundryup path. We download the official
# release tarball over TLS and pin its SHA256 — same security
# posture as the foundryup happy path on WSL (where it skips
# attestation anyway).
#
# # Behavior
#
# 1. Downloads `foundry_v1.0.0_linux_amd64.tar.gz` from the GitHub
#    release (with retry/backoff for transient flakes).
# 2. Verifies the tarball SHA256 against a hardcoded pin (recomputed
#    on every Foundry bump — see "Bumping" below).
# 3. Extracts `forge`, `cast`, `anvil`, `chisel` to `$HOME/.foundry/bin/`.
# 4. Smoke-checks `forge --version`.
# 5. If running under GitHub Actions, appends `$HOME/.foundry/bin`
#    to `$GITHUB_PATH` so subsequent steps see the binaries.
#
# # Bumping
#
# To bump Foundry version:
# 1. Update `FOUNDRY_VERSION` default below.
# 2. Recompute SHA256:
#      curl -sSfL -o /tmp/foundry.tar.gz \
#        "https://github.com/foundry-rs/foundry/releases/download/<VERSION>/foundry_<VERSION>_linux_amd64.tar.gz"
#      sha256sum /tmp/foundry.tar.gz
# 3. Update `FOUNDRY_SHA256_*` below.
# 4. Bump Kelvin's local foundry in lockstep (memory: `pangolin_environment_quirks.md` #4).
#
# # Linux only this slice
#
# All five `foundry-toolchain@v1` callsites in `.github/workflows/ci.yml`
# run on `ubuntu-latest`. If a future macOS/Windows job needs Foundry,
# extend the `case` switch below + add the matching SHA256 pin.

set -euo pipefail

FOUNDRY_VERSION="${FOUNDRY_VERSION:-v1.0.0}"
FOUNDRY_PLATFORM="${FOUNDRY_PLATFORM:-linux_amd64}"

# SHA256 pins — recomputed at bump time (see "Bumping" above).
case "${FOUNDRY_VERSION}_${FOUNDRY_PLATFORM}" in
  v1.0.0_linux_amd64)
    expected_sha256="8c078eaced6bfce76af902def65e36db677842ffbf53f76730647082a5b1e45a"
    ;;
  *)
    echo "install-foundry.sh: no SHA256 pin for ${FOUNDRY_VERSION}_${FOUNDRY_PLATFORM}" >&2
    echo "  add one to the case switch in this file before bumping" >&2
    exit 1
    ;;
esac

FOUNDRY_DIR="$HOME/.foundry"
FOUNDRY_BIN="$FOUNDRY_DIR/bin"
mkdir -p "$FOUNDRY_BIN"

# If the binary is already installed at the right version, skip
# (idempotent re-runs in the same job + cache-friendly).
if [ -x "$FOUNDRY_BIN/forge" ]; then
  installed="$("$FOUNDRY_BIN/forge" --version 2>/dev/null | head -1 || true)"
  case "$installed" in
    *"$FOUNDRY_VERSION"*)
      echo "install-foundry.sh: already installed: $installed"
      if [ -n "${GITHUB_PATH:-}" ]; then
        echo "$FOUNDRY_BIN" >> "$GITHUB_PATH"
      fi
      exit 0
      ;;
  esac
fi

tarball="$(mktemp --suffix=.tar.gz)"
trap 'rm -f "$tarball"' EXIT

url="https://github.com/foundry-rs/foundry/releases/download/${FOUNDRY_VERSION}/foundry_${FOUNDRY_VERSION}_${FOUNDRY_PLATFORM}.tar.gz"
echo "install-foundry.sh: downloading ${url}"
# Same retry posture as foundryup's `fetch` (5 attempts over up to
# 120s) so a transient 5xx from the release-assets CDN doesn't fail
# the whole CI run.
curl -sSfL --retry 5 --retry-delay 2 --retry-max-time 120 -o "$tarball" "$url"

actual_sha256="$(sha256sum "$tarball" | awk '{print $1}')"
if [ "$actual_sha256" != "$expected_sha256" ]; then
  echo "install-foundry.sh: SHA256 mismatch for ${FOUNDRY_VERSION}_${FOUNDRY_PLATFORM}" >&2
  echo "  expected: $expected_sha256" >&2
  echo "  actual:   $actual_sha256" >&2
  exit 1
fi

echo "install-foundry.sh: SHA256 OK ($actual_sha256); extracting to $FOUNDRY_BIN"
tar -xzf "$tarball" -C "$FOUNDRY_BIN"

# Smoke: forge --version must run and print the matching version.
installed="$("$FOUNDRY_BIN/forge" --version | head -1)"
case "$installed" in
  *"$FOUNDRY_VERSION"*)
    echo "install-foundry.sh: $installed"
    ;;
  *)
    echo "install-foundry.sh: forge --version did not mention ${FOUNDRY_VERSION}: $installed" >&2
    exit 1
    ;;
esac

# When running under GitHub Actions, append the bin dir to GITHUB_PATH
# so subsequent steps pick up the binary. The `working-directory:`
# defaults of various jobs (e.g. `contracts`) do not affect PATH
# inheritance, so this is the canonical way to add to PATH for
# subsequent steps in the same job.
if [ -n "${GITHUB_PATH:-}" ]; then
  echo "$FOUNDRY_BIN" >> "$GITHUB_PATH"
  echo "install-foundry.sh: added $FOUNDRY_BIN to GITHUB_PATH"
fi
