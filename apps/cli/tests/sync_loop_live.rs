// SPDX-License-Identifier: AGPL-3.0-or-later
//! Live `sync loop` placeholder (CLI-V1 R-i, Option D residue per
//! issue #98).
//!
//! **STATUS: PLACEHOLDER (Option D residue).** This test file exists
//! per the §5.x R-g/R-i precedent (4.1 / 4.2 / 4.3 / 5.1 / 5.2 / 5.3
//! / 5.4 all ship a `#[ignore]`'d live test file as a structural
//! anchor) — but the body is intentionally a skeleton: it verifies
//! env-var presence + emits operator guidance, NO real chain
//! exercise.
//!
//! ## Issue #98 update (2026-05-18)
//!
//! Issue #98 hermeticized the bytes-parsing side of the §4.x / §5.x
//! tests by:
//!
//! - Capturing real D-014 V0 `RevisionPublished` bytes +
//!   raw `eth_getLogs` JSON-RPC responses + D-017 contract state
//!   snapshots under `crates/pangolin-indexer/tests/fixtures/` and
//!   `crates/pangolin-store/tests/fixtures/`.
//! - Writing four hermetic replay siblings (`replay_d017_*.rs`) that
//!   drive the captured fixtures through the same parsers production
//!   uses, all running on every PR (no `#[ignore]`).
//! - Adding hermetic invariant sweeps:
//!   `deployment_json_pins_match_rust_constants` (catches
//!   L-rotted-constant-class), `no_empty_ignored_tests` (catches
//!   L-empty-test-body), `fixture_provenance` (catches
//!   L-fake-fixture-from-wrong-test-build), `fixture_no_secrets`
//!   (catches L-secrets-in-fixtures).
//! - Removing two empty-body `#[test]` fns in
//!   `pangolin-chain/src/secp256k1_signing.rs` and migrating their
//!   content to `crates/pangolin-chain/RUNBOOK.md`.
//!
//! **What stayed `#[ignore]`'d (Option D residue):** the
//! contract-execution surface — `publish_v1_live_d017_smoke`,
//! `live_balance_query_against_d017_wallet`, the live `live_*` tests
//! in §4.x / §5.x, and this CLI-V1 sync-loop placeholder. They run
//! via `scripts/run-live-tests.{sh,ps1}` (which sources gitignored
//! `.env.live`) before each release.
//!
//! **This placeholder specifically.** The full live wire-up of the
//! sync-loop body still requires a funded D-017 vault + a published
//! revision to ingest. That work is operationally deferred to the
//! cycle that lands a real D-017 publish round-trip (the smoke test
//! at `chain_submit.rs::publish_v1_live_d017_smoke` is the upstream
//! gating exercise; once it runs green pre-release, this placeholder
//! can be populated). Until then, the test serves as a structural
//! anchor — pinning the env-var contract and ensuring the file
//! compiles + the `#[ignore]` discipline holds.

#![forbid(unsafe_code)]

/// **CLI-V1 R-i — PLACEHOLDER.** Skeleton test that validates the
/// env-var contract for the future live invocation. Body to be
/// replaced with a real `BaseSepoliaAdapter` + `run_loop_body`
/// exercise during the fixture-capture follow-up cycle.
///
/// Manual invocation contract (for the eventual real body):
/// ```bash
/// export BASE_SEPOLIA_RPC_URL=https://...
/// export PANGOLIN_LIVE_KEYSTORE_PATH=/path/to/keystore
/// export PANGOLIN_LIVE_KEYSTORE_PASSWORD=...
/// cargo test -p pangolin-cli --test sync_loop_live -- --ignored
/// ```
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "PLACEHOLDER — fixture-capture follow-up will replace body with real D-017 exercise; meanwhile validates env-var contract only"]
async fn live_sync_loop_placeholder_validates_env_var_contract() {
    let rpc_url = std::env::var("BASE_SEPOLIA_RPC_URL").ok();
    let keystore_path = std::env::var("PANGOLIN_LIVE_KEYSTORE_PATH").ok();
    let keystore_pwd = std::env::var("PANGOLIN_LIVE_KEYSTORE_PASSWORD").ok();
    if rpc_url.is_none() || keystore_path.is_none() || keystore_pwd.is_none() {
        eprintln!(
            "live_sync_loop_placeholder: skipping — set BASE_SEPOLIA_RPC_URL, \
             PANGOLIN_LIVE_KEYSTORE_PATH, PANGOLIN_LIVE_KEYSTORE_PASSWORD"
        );
        return;
    }
    // PLACEHOLDER honesty: when all 3 env vars ARE present, the
    // test still doesn't exercise the chain side. The real body
    // belongs to the fixture-capture follow-up. We emit clear
    // operator-facing guidance so anyone running this with env vars
    // set understands the gap.
    eprintln!(
        "live_sync_loop_placeholder: env vars present BUT this test body is a \
         skeleton. The full BaseSepoliaAdapter + run_loop_body exercise is \
         deferred to the fixture-capture follow-up cycle that bundles all \
         §4.x / §5.x / CLI-V1 live tests."
    );
}
