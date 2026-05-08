#!/usr/bin/env bash
# HIGH-1 invariant guard — `pangolin-crypto` MUST NOT pull `serde` into
# its dependency tree.
#
# Per `docs/issue-plans/P1.md` success criterion #11 + the deny.toml
# rationale block, the secret-bearing crypto types MUST NOT be reachable
# from any `serde::Serialize` impl. P6 lifted the workspace-wide serde
# ban (because `tools/chaincli/` and `pangolin-chain` legitimately need
# alloy's RPC types), and the protection moved to a stricter narrowly-
# scoped rule: `pangolin-crypto`'s dep tree must contain ZERO references
# to `serde`. This script enforces that rule in CI.
#
# Run locally:
#   bash scripts/check-no-serde-in-crypto.sh

set -euo pipefail

cd "$(dirname "$0")/.."

count=$(cargo tree -p pangolin-crypto 2>/dev/null | grep -ci serde || true)

if [ "$count" -ne 0 ]; then
    echo "::error::HIGH-1 invariant violated: pangolin-crypto's tree contains $count reference(s) to serde."
    echo "::error::Re-run cargo tree -p pangolin-crypto and inspect the path; either drop the offending dep"
    echo "::error::or escalate to a Kelvin-gated plan-amendment per docs/issue-plans/P1.md."
    exit 1
fi

echo "OK: pangolin-crypto tree contains 0 references to serde (HIGH-1 invariant preserved)."
