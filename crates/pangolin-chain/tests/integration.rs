//! Integration tests against the deployed `RevisionLogV0` contract
//! on Base Sepolia (`0x8566D3de653ee55775783bD7918Fe91b66373896`).
//!
//! Gated behind `--features integration-tests` so the default
//! `cargo test --workspace --lib` and `cargo test --workspace
//! --all-targets` do NOT attempt to reach
//! `https://sepolia.base.org`.  CI runs without the feature; humans
//! enable it for manual smoke verification:
//!
//! ```text
//! cargo test -p pangolin-chain --features integration-tests --test integration
//! ```
//!
//! The RPC URL resolves with the same priority chaincli uses:
//! `BASE_SEPOLIA_RPC_URL` env var if set, else the `chain.rpc_default`
//! field from `contracts/deployments/base-sepolia.json`.
//!
//! Tests in this file: `current_block_returns_a_value` (sanity:
//! `eth_blockNumber` returns a value strictly above `deploy_block`)
//! and `pull_since_returns_smoke_revision` (the P5-4 smoke revision
//! is reachable through `pull_since` against the real chain).

#![cfg(feature = "integration-tests")]

use std::path::PathBuf;

use pangolin_chain::{BaseSepoliaAdapter, ChainAdapter};

/// Deploy block for the canonical `RevisionLogV0` deployment on
/// Base Sepolia. Hard-coded here rather than re-loaded from the
/// deployment file so this test fails loudly if a future deployment
/// overwrites the canonical record (we want to know).
const P5_4_DEPLOY_BLOCK: u64 = 41_133_000;

/// The smoke-test revision published as part of P5-4 deployment
/// verification (per `contracts/deployments/base-sepolia.json`
/// `smoke_tests.test_2_write_revision`). Used to assert
/// `pull_since(...)` returns a non-empty result on the real chain.
const P5_4_SMOKE_VAULT_ID: [u8; 32] = {
    let mut v = [0u8; 32];
    v[0] = 0xAA;
    v[1] = 0xAA;
    v
};

fn deployment_path() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(std::path::Path::parent)
        .expect("CARGO_MANIFEST_DIR has at least two ancestors")
        .join("contracts")
        .join("deployments")
        .join("base-sepolia.json")
}

fn rpc_url() -> String {
    if let Ok(v) = std::env::var("BASE_SEPOLIA_RPC_URL") {
        if !v.is_empty() {
            return v;
        }
    }
    // Mirror chaincli's default: `chain.rpc_default` from the
    // deployment file.  We hard-code the well-known public endpoint
    // here rather than re-parse the JSON so this file's dep set stays
    // small.
    "https://sepolia.base.org".to_owned()
}

#[tokio::test]
async fn current_block_returns_a_value() {
    let adapter = BaseSepoliaAdapter::new_read_only(&rpc_url(), &deployment_path())
        .await
        .expect("adapter construction succeeds against the real chain");
    let block = adapter
        .current_block()
        .await
        .expect("current_block returns");
    assert!(
        block > P5_4_DEPLOY_BLOCK,
        "current_block ({block}) should be strictly after deploy_block ({P5_4_DEPLOY_BLOCK})"
    );
}

/// P7 audit MED-2: the constructor's `eth_getCode` keccak cross-check
/// must succeed against the live chain — i.e., the canonical
/// deployment file's `deployed_runtime_keccak256` matches what the
/// real RPC returns. If `BaseSepoliaAdapter::new_read_only` returns
/// `Ok`, the cross-check fired and matched. If a future contract is
/// re-deployed without the deployment file being updated, this test
/// fails with `ChainError::DeploymentMismatch` and the operator knows
/// to refresh the recorded keccak.
#[tokio::test]
async fn runtime_keccak_cross_check_passes_on_live_chain() {
    let result = BaseSepoliaAdapter::new_read_only(&rpc_url(), &deployment_path()).await;
    let adapter =
        result.expect("constructor's runtime-keccak cross-check must pass against live chain");
    // Using the adapter to do another read confirms the provider is
    // in working order and not just a stub.
    let _ = adapter
        .current_block()
        .await
        .expect("post-cross-check provider call works");
}

/// **MVP-2 issue 3.5 (env-quirk #14 live test).** Query the EVM
/// balance of a known-funded testnet wallet against Base Sepolia.
///
/// `BASE_SEPOLIA_DEV_WALLET` env var carries the 20-byte hex address
/// of a funded `pangolin-dev` wallet (the same one chaincli's `--keystore`
/// path uses for live publish smoke tests). Asserts the U256 is
/// non-zero and prints the wei value at info-level so a human running
/// the test can sanity-check.
///
/// Marked `#[ignore]` so default CI doesn't reach the network.
/// Manually run with:
///
/// ```text
/// BASE_SEPOLIA_DEV_WALLET=0x... \
///   cargo test -p pangolin-chain --features integration-tests \
///   live_balance_query_against_d017_wallet -- --ignored --nocapture
/// ```
#[tokio::test]
#[ignore = "live-RPC test; requires BASE_SEPOLIA_DEV_WALLET + network"]
async fn live_balance_query_against_d017_wallet() {
    use pangolin_chain::{query_evm_balance, ChainEnv};
    let Ok(addr_hex) = std::env::var("BASE_SEPOLIA_DEV_WALLET") else {
        eprintln!("skipping live balance test: BASE_SEPOLIA_DEV_WALLET not set");
        return;
    };
    let address: alloy::primitives::Address = addr_hex.parse().expect("addr hex");
    let balance = query_evm_balance(&rpc_url(), address, ChainEnv::BaseSepolia)
        .await
        .expect("live balance query");
    println!(
        "live balance for {address:?}: {balance} wei (~{:.6} ETH)",
        f64::from(
            u32::try_from(balance / alloy::primitives::U256::from(10u64.pow(12))).unwrap_or(0)
        ) / 1_000_000.0
    );
    assert!(
        balance > alloy::primitives::U256::ZERO,
        "dev wallet must have a non-zero balance for the live test to be meaningful"
    );
}

#[tokio::test]
async fn pull_since_returns_smoke_revision() {
    let adapter = BaseSepoliaAdapter::new_read_only(&rpc_url(), &deployment_path())
        .await
        .expect("adapter construction succeeds");
    // Pull from one block before the deploy so the smoke-test
    // revision (test_2_write_revision in the deployment file) lands
    // in the result. Use a small `until_block` cap above the smoke
    // tx's block (41_133_109) so we don't trigger a 9000-block loop
    // for nothing.
    let events = adapter
        .pull_since(
            &P5_4_SMOKE_VAULT_ID,
            P5_4_DEPLOY_BLOCK.saturating_sub(1),
            Some(P5_4_DEPLOY_BLOCK + 200),
        )
        .await
        .expect("pull_since succeeds");
    assert!(
        !events.is_empty(),
        "pull_since must return at least the P5-4 smoke revision; got 0 events"
    );
    // The smoke revision is the very first event in the contract's
    // log.  Its sequence number was 0 per the deployment record's
    // smoke_tests.test_3_state_mutated.
    let first = events
        .iter()
        .find(|e| e.sequence == 0)
        .expect("the sequence-0 smoke revision must be present");
    assert_eq!(first.vault_id, P5_4_SMOKE_VAULT_ID);
    // The smoke revision's encPayload was 0xdeadbeefdeadbeefdeadbeefdeadbeef
    // per the deployment record.
    assert_eq!(
        first.enc_payload,
        vec![
            0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad,
            0xbe, 0xef
        ],
        "smoke revision payload must match the deployment record"
    );
}
