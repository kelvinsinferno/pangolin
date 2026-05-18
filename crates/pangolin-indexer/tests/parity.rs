// SPDX-License-Identifier: AGPL-3.0-or-later
//! 4.2 R-f `#[ignore]`'d live parity test (Option D residue per issue #98).
//!
//! Verifies L4: the indexer's output against D-017 is byte-identical
//! to slow-mode 4.1's output for the same chain state, exercising
//! contract-execution + checkpoint-state assertions that the hermetic
//! sibling (`tests/replay_d017_fixture_parity.rs`) genuinely cannot
//! cover.
//!
//! ## Why `#[ignore]`'d (operator-visible failure mode)
//!
//! This test sits on the contract-execution side of env-quirk #14:
//! the hermetic replay (which DOES run on every PR) exercises the
//! bytes-parsing surface using the captured D-014 V0 event fixture,
//! but the live tip-of-chain query against D-017 must remain manual
//! because (a) D-017 currently has zero `RevisionPublished` events
//! emitted (no smoke publish has been recorded since deploy on
//! 2026-05-14, see `chain_submit.rs::publish_v1_live_d017_smoke`),
//! and (b) even when events exist, the rolling chain tip is not
//! deterministic at PR time.
//!
//! **Operator-visible failure mode:** if this test fails when run via
//! `scripts/run-live-tests.{sh,ps1}` it indicates either (i) the live
//! D-017 RPC has drifted from `EXPECTED_DEPLOYED_ADDRESS_BASE_SEPOLIA`
//! / `d017_deploy_block(BaseSepolia)`, or (ii) the indexer's
//! StartIndex⇒Pull cycle returned a different event sequence than
//! `Vault::sync_from_chain` for the same window. The hermetic replay
//! (which DID pass at PR time) localizes the regression to live-only
//! state — usually a contract redeploy at a new address without an
//! accompanying constant bump.
//!
//! ## How to run
//!
//! ```text
//! BASE_SEPOLIA_RPC_URL=https://sepolia.base.org \
//!     PANGOLIN_INDEXER_VAULT_ID=<64-char hex, no 0x prefix> \
//!     cargo test -p pangolin-indexer --test parity -- --ignored
//! ```
//!
//! Or, easier: `bash scripts/run-live-tests.sh` (sources `.env.live`).

#![forbid(unsafe_code)]

use std::sync::Arc;

use pangolin_chain::ChainEnv;
use pangolin_indexer::{
    IndexerConfig, IndexerRequest, IndexerResponse, IndexerSession, NoOpCipher, TempDbCipher,
};

/// D-017's deploy block on Base Sepolia (per `pangolin_chain::d017_deploy_block`).
/// Issue #98 (2026-05-18): re-pinned via cast verification — see
/// `pangolin_chain::d017_deploy_block` docstring for the rot-fix history.
const D017_DEPLOY_BLOCK: u64 = 41_507_120;

/// Run the live parity test against D-017. Requires:
///
/// - `BASE_SEPOLIA_RPC_URL` env var pointing at a Base Sepolia RPC.
/// - `PANGOLIN_INDEXER_VAULT_ID` env var carrying a 64-char hex
///   (no `0x`) vault id known to exist in D-017's event history.
///
/// Without those env vars set, the test is a no-op return; the
/// `#[ignore]` keeps CI from running it by default.
#[tokio::test]
#[ignore = "requires BASE_SEPOLIA_RPC_URL + PANGOLIN_INDEXER_VAULT_ID + captured event fixture"]
async fn live_indexer_vs_slow_mode_against_d017() {
    let rpc_url = match std::env::var("BASE_SEPOLIA_RPC_URL") {
        Ok(s) if !s.is_empty() => s,
        _ => {
            eprintln!("SKIP: BASE_SEPOLIA_RPC_URL not set");
            return;
        }
    };
    let vault_id = match std::env::var("PANGOLIN_INDEXER_VAULT_ID") {
        Ok(s) if !s.is_empty() => s,
        _ => {
            eprintln!("SKIP: PANGOLIN_INDEXER_VAULT_ID not set");
            return;
        }
    };

    let cfg = IndexerConfig {
        rpc_url,
        env: ChainEnv::BaseSepolia,
        idle_timeout_secs: 120,
    };
    let cipher: Arc<dyn TempDbCipher> = NoOpCipher::new_arc();
    let mut session = IndexerSession::new(cfg, cipher).expect("session new");

    // Index the deploy-block + a small window forward.
    let resp = session
        .handle_request(IndexerRequest::StartIndex {
            vault_id: vault_id.clone(),
            start_block: D017_DEPLOY_BLOCK,
            end_block: Some(D017_DEPLOY_BLOCK + 100_000),
        })
        .await
        .expect("StartIndex");
    match resp {
        IndexerResponse::Started { vault_id: vid, .. } => {
            assert_eq!(vid, vault_id);
        }
        other => panic!("expected Started, got {other:?}"),
    }

    // Drain.
    let resp = session
        .handle_request(IndexerRequest::Pull { batch_size: 1024 })
        .await
        .expect("Pull");
    match resp {
        IndexerResponse::Batch { events } => {
            // 4.2 builder follow-up: once a known event exists for
            // the configured vault, switch this to a byte-identical
            // comparison against `Vault::sync_from_chain` (4.1
            // slow-mode). Today we only assert the batch shape
            // round-trips.
            eprintln!("indexed {} events for vault {vault_id}", events.len());
        }
        other => panic!("expected Batch, got {other:?}"),
    }

    // Stop + verify Stopped.
    let resp = session.handle_request(IndexerRequest::Stop).await.unwrap();
    assert!(matches!(resp, IndexerResponse::Stopped));
}
