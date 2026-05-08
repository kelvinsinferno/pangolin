#!/usr/bin/env bash
# MVP-1 issue 1.1 (Q3) invariant guard — `pangolin-core` MUST NOT pull
# `uniffi` into its dependency tree.
#
# Q3 of issue 1.1 placed the FFI surface in a separate `pangolin-ffi`
# crate so UniFFI's transitive deps (which include serde in some
# configs) never reach `pangolin-core`. The dependency arrow goes
# ffi → core, never the reverse.
#
# Run locally:
#   bash scripts/check-no-uniffi-in-core.sh

set -euo pipefail

cd "$(dirname "$0")/.."

count=$(cargo tree -p pangolin-core 2>/dev/null | grep -ci uniffi || true)

if [ "$count" -ne 0 ]; then
    echo "::error::MVP-1 issue 1.1 Q3 invariant violated: pangolin-core's tree contains $count reference(s) to uniffi."
    echo "::error::Re-run 'cargo tree -p pangolin-core' and inspect the path; the FFI surface must stay isolated"
    echo "::error::in pangolin-ffi. See docs/issue-plans/1.1.md success criterion 4."
    exit 1
fi

echo "OK: pangolin-core tree contains 0 references to uniffi (issue 1.1 Q3 invariant preserved)."
