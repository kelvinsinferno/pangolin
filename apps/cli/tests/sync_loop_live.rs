// SPDX-License-Identifier: AGPL-3.0-or-later
//! Live `sync loop` placeholder (CLI-V1 R-i).
//!
//! **STATUS: PLACEHOLDER.** This test file exists per the §5.x
//! R-g/R-i precedent (4.1 / 4.2 / 4.3 / 5.1 / 5.2 / 5.3 / 5.4 all
//! ship a `#[ignore]`'d live test file as a structural anchor) —
//! but the body is intentionally a skeleton: it verifies env-var
//! presence + emits operator guidance, NO real chain exercise.
//!
//! **Why placeholder?** The full live wire-up requires constructing
//! a `BaseSepoliaAdapter` against the deployed D-017 contract +
//! driving `run_loop_body` end-to-end with a funded keystore. That
//! work is operationally deferred to the standing fixture-capture
//! follow-up that bundles 4.1 / 4.2 / 4.3 / 5.1 / 5.2 / 5.3 / 5.4
//! / CLI-V1 live tests into one operational commit when a real
//! D-017 publish round-trip is available.
//!
//! Follow-up: when the fixture-capture cycle runs, this placeholder's
//! body gets replaced with the actual `BaseSepoliaAdapter` + vault
//! creation + `run_loop_body` exercise. Until then, the test serves
//! as a structural anchor — pinning the env-var contract and
//! ensuring the file compiles + the `#[ignore]` discipline holds.

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
