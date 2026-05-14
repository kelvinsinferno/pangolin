#!/usr/bin/env bash
# MVP-2 issue 3.2 (L7) invariant guard — `pangolin-chain` MUST NOT
# gain a non-dev dependency on `pangolin-store`.
#
# Per `crates/pangolin-chain/Cargo.toml:55-58` + P7 success criterion 6:
# the locked workspace dep direction is `pangolin-store → pangolin-chain`
# (one-way). `pangolin-chain` lists `pangolin-store` only as a
# dev-dependency (for its base_sepolia integration tests via the
# `test-utilities` feature). The PRODUCTION tree must remain clean.
#
# `--edges normal` filters dev-dependencies out of the tree so the
# existing dev-dep does not false-positive on this check. The raw form
# (`cargo tree -p pangolin-chain --no-default-features | grep -i
# pangolin-store`) would match the dev-dep and falsely fail.
#
# Run locally:
#   bash scripts/check-chain-no-store.sh

set -euo pipefail

cd "$(dirname "$0")/.."

count=$(cargo tree -p pangolin-chain --no-default-features --edges normal 2>/dev/null | grep -c pangolin-store || true)

if [ "$count" -ne 0 ]; then
    echo "::error::MVP-2 issue 3.2 L7 invariant violated: pangolin-chain's production tree contains $count reference(s) to pangolin-store."
    echo "::error::Run 'cargo tree -p pangolin-chain --no-default-features --edges normal' to inspect the path."
    echo "::error::The locked workspace dep direction is pangolin-store → pangolin-chain (one-way). See"
    echo "::error::crates/pangolin-chain/Cargo.toml:55-58 + docs/issue-plans/3.2.md L7."
    exit 1
fi

echo "OK: pangolin-chain production tree contains 0 references to pangolin-store (L7 invariant preserved)."
