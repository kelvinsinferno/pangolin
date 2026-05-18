#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Issue #98 R-f Option P: pre-release live-test runner.
#
# Runs the surviving #[ignore]'d live tests (the Option D
# residue — bytes-parsing surfaces are covered by the hermetic
# replay siblings on every PR) against a real Base Sepolia RPC.
#
# Pairs with `run-live-tests.ps1` (the PowerShell sibling).
#
# Sources gitignored `.env.live` from the repo root; that file
# should NOT be committed (already in `.gitignore`). Suggested
# template:
#
#   # .env.live (gitignored)
#   export BASE_SEPOLIA_RPC_URL=https://sepolia.base.org
#   export BASE_SEPOLIA_DEV_WALLET=0x89e720238A3913688CB0E025ef03a64539575c54
#   export PANGOLIN_INDEXER_VAULT_ID=...    # 64-char hex, no 0x
#   export PANGOLIN_PULL_LIVE_VAULT_ID=...  # 64-char hex, no 0x
#   export PANGOLIN_SYNC_LIVE_VAULT_ID=...  # 64-char hex, no 0x
#   export PANGOLIN_LIVE_KEYSTORE_PATH=...
#   export PANGOLIN_LIVE_KEYSTORE_PASSWORD=...

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if [ ! -f .env.live ]; then
  echo "ERROR: .env.live not found at $REPO_ROOT/.env.live" >&2
  echo "       create it from the template in scripts/run-live-tests.sh comment" >&2
  exit 2
fi

# shellcheck disable=SC1091
source .env.live

echo "==> Issue #98 R-f: live-test runner"
echo "    repo root: $REPO_ROOT"
echo "    BASE_SEPOLIA_RPC_URL=${BASE_SEPOLIA_RPC_URL:-<unset>}"
echo ""

# Run the workspace-wide --ignored set, filtered by `live_` and the
# placeholder names. Workspace-wide invocation avoids the
# PowerShell-#16 long-command-line issue if anyone uses the .ps1 path.
echo "==> cargo test --workspace -- --ignored"
cargo test --workspace --all-targets -- --ignored --nocapture
