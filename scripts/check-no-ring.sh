#!/usr/bin/env bash
# L5 + L-ws-feature-leak-pulls-ring invariant guard — the workspace
# tree MUST NOT contain `ring`.
#
# `ring` is BANNED via `deny.toml` (per `docs/issue-plans/P1.md`:
# Pangolin uses RustCrypto / dalek-cryptography crates exclusively;
# `ring` is FFI-laden and outside the audit surface). Issue #99
# flipped alloy's `provider-ws` + `pubsub` features which COULD have
# transitively selected `ring` via `rustls`'s default crypto provider
# — alloy 2.0.4's `transport-ws` feature uses `aws-lc-rs` instead,
# preserving the L5 invariant. This script enforces the invariant in
# CI so a future alloy / rustls / reqwest bump that re-routes the
# TLS backend back to `ring` fails at PR time.
#
# Run locally:
#   bash scripts/check-no-ring.sh

set -euo pipefail

cd "$(dirname "$0")/.."

# `cargo tree -i ring` prints the tree of crates that depend on `ring`.
# When `ring` is not in the tree, cargo prints `warning: nothing to
# print.` to STDERR + exits 0. We capture both streams + count `ring`
# tokens in the COMBINED output — zero rows is the pass condition.
count=$(cargo tree -i ring 2>&1 | grep -c '^ring v' || true)

if [ "$count" -ne 0 ]; then
    echo "::error::L5 + L-ws-feature-leak-pulls-ring violated: workspace tree contains $count reference(s) to ring."
    echo "::error::Re-run \`cargo tree -i ring\` to see the chain; either drop the offending feature/dep"
    echo "::error::or escalate via a deny.toml plan-amendment (the ring ban is gated by docs/issue-plans/P1.md)."
    exit 1
fi

echo "OK: workspace tree contains 0 references to ring (L5 + L-ws-feature-leak-pulls-ring preserved)."
