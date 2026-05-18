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

/// **MVP-2 issue 3.5 (env-quirk #14 live test, Option D residue per
/// issue #98).** Query the EVM balance of a known-funded testnet
/// wallet against Base Sepolia.
///
/// `BASE_SEPOLIA_DEV_WALLET` env var carries the 20-byte hex address
/// of a funded `pangolin-dev` wallet (the same one chaincli's `--keystore`
/// path uses for live publish smoke tests). Asserts the U256 is
/// non-zero and prints the wei value at info-level so a human running
/// the test can sanity-check.
///
/// **What this test covers (live residue).** The actual
/// `eth_getBalance` RPC roundtrip + alloy U256 decoding +
/// non-zero balance assertion. This is intrinsically NOT
/// hermetic-able: the assertion is "the live wallet has funds,"
/// and that's a property of the live chain at test time. The
/// existing hermetic mock tests (`query_evm_balance` with
/// `MockChainAdapter`) cover the decoding path; this one closes
/// the env-quirk-#14 contract-execution surface for the
/// pre-publish balance gate.
///
/// **Operator-visible failure mode.** If this test fails when run
/// via `scripts/run-live-tests.{sh,ps1}`, either the configured
/// `BASE_SEPOLIA_DEV_WALLET` ran out of testnet ETH (recovery:
/// top up via the Base Sepolia faucet) or the RPC URL is wrong /
/// unreachable.
///
/// Marked `#[ignore]` so default CI doesn't reach the network.
/// Manually run with:
///
/// ```text
/// BASE_SEPOLIA_DEV_WALLET=0x... \
///   cargo test -p pangolin-chain --features integration-tests \
///   live_balance_query_against_d017_wallet -- --ignored --nocapture
/// ```
///
/// Or, easier: `bash scripts/run-live-tests.sh` (sources `.env.live`).
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

/// **MVP-2 issue #99 (Q-d Option K — live residue against the
/// production WS endpoint).** Opens a real WebSocket subscription
/// against `wss://sepolia.base.org`, filtered to D-017 +
/// `RevisionPublished` topic0 + an arbitrary indexed vault id.
/// Asserts that `open_subscription` returns a handle within a sane
/// time budget — the subscription does NOT need to receive an event
/// (D-017 has no production events at MVP-2 time per the #98
/// fixture-capture inventory). The test confirms:
///
/// 1. The TLS handshake against `wss://sepolia.base.org` completes.
/// 2. The `eth_subscribe("logs", filter)` JSON-RPC request succeeds.
/// 3. The chain-side filter is honored (server accepts the
///    contract-address + topic0 + topic1 shape pangolin-chain emits).
///
/// Closes the env-quirk-#14 audit-class for the WS path: a future
/// regression in alloy's WS provider, a TLS-stack drift, or a public
/// RPC behaviour change surfaces here on demand (run via
/// `scripts/run-live-tests.{sh,ps1}`).
///
/// Marked `#[ignore]` so default CI does not reach the network;
/// manually invoke with:
///
/// ```text
/// cargo test -p pangolin-chain --features integration-tests \
///   live_ws_subscribe_against_d017 -- --ignored --nocapture
/// ```
#[tokio::test]
#[ignore = "live-RPC test; opens real WS against wss://sepolia.base.org"]
async fn live_ws_subscribe_against_d017() {
    use pangolin_chain::chain_sync::ws::open_subscription;
    use pangolin_chain::ChainEnv;

    let ws_url = std::env::var("BASE_SEPOLIA_WS_URL")
        .unwrap_or_else(|_| "wss://sepolia.base.org".to_owned());
    // D-017 contract address from the deployment file
    // (`0x179362Ad7fb7dA664312aEFDdaa53431eb748E42`). Hard-coded
    // here to keep the dep set minimal (no JSON parse in this test).
    let contract_addr: alloy::primitives::Address = "0x179362Ad7fb7dA664312aEFDdaa53431eb748E42"
        .parse()
        .expect("D-017 address parses");
    // Arbitrary vault id; we don't expect any events (the assertion
    // is that the subscription HANDLE is established).
    let vault_id: [u8; 32] = [0x42u8; 32];

    let handle = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        open_subscription(&ws_url, ChainEnv::BaseSepolia, &vault_id, contract_addr),
    )
    .await
    .expect("WS open within 30s budget")
    .expect("open_subscription succeeds against live WS endpoint");

    // The handle's Debug impl confirms the subscription is live.
    eprintln!("live WS handle established: {handle:?}");
    drop(handle);
}
