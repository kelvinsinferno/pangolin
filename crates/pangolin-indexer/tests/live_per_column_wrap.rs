// SPDX-License-Identifier: AGPL-3.0-or-later
//! §4.3 per-column AEAD: live `#[ignore]`-gated parity test against
//! D-017.
//!
//! Same posture as `parity.rs` (the §4.3-baseline live parity test):
//! requires `BASE_SEPOLIA_RPC_URL` + `PANGOLIN_INDEXER_VAULT_ID` env
//! vars + a captured `RevisionPublished` event fixture from D-017.
//! Without those env vars set, the test is a no-op return; the
//! `#[ignore]` keeps CI from running it by default.
//!
//! ## What this test adds beyond `parity.rs`
//!
//! `parity.rs` exercises the high-level Start ⇒ Pull cycle but
//! pre-§4.3-per-column-AEAD it did NOT verify the on-disk file
//! contains zero plaintext. This test:
//!
//! 1. Starts a real session against D-017 with real bytes.
//! 2. Pulls events.
//! 3. Reads the temp DB file via `std::fs::read` BEFORE the session
//!    is dropped.
//! 4. Asserts no event's `vault_id`, `enc_payload`, `signer`,
//!    `tx_hash`, or `block_hash` BLOB content appears in the raw
//!    file (= cipher wrap landed for the real chain payload).
//!
//! Per the §4.3 per-column-AEAD plan-gate Builder note: hermetic
//! tests catch the cipher-wiring property; the live test exercises
//! the REAL byte patterns of D-017 events so a contract-side
//! semantics regression (e.g., the verifier silently widening the
//! schema_version ladder) doesn't sneak past us.

#![forbid(unsafe_code)]
#![allow(clippy::doc_markdown)]

use std::sync::Arc;

use pangolin_chain::ChainEnv;
use pangolin_crypto::rng::fill_random;
use pangolin_crypto::secret::SecretBytes;
use pangolin_indexer::{
    AeadCipher, IndexerConfig, IndexerRequest, IndexerResponse, IndexerSession, TempDbCipher,
};

const D017_DEPLOY_BLOCK: u64 = 23_640_113;

#[tokio::test]
#[ignore = "requires BASE_SEPOLIA_RPC_URL + PANGOLIN_INDEXER_VAULT_ID + captured event fixture"]
async fn live_per_column_aead_no_plaintext_on_disk() {
    let rpc_url = match std::env::var("BASE_SEPOLIA_RPC_URL") {
        Ok(s) if !s.is_empty() => s,
        _ => {
            eprintln!("SKIP: BASE_SEPOLIA_RPC_URL not set");
            return;
        }
    };
    let vault_hex = match std::env::var("PANGOLIN_INDEXER_VAULT_ID") {
        Ok(s) if !s.is_empty() => s,
        _ => {
            eprintln!("SKIP: PANGOLIN_INDEXER_VAULT_ID not set");
            return;
        }
    };
    let vault_bytes = hex::decode(&vault_hex).expect("vault_id hex");
    assert_eq!(vault_bytes.len(), 32);

    let cfg = IndexerConfig {
        rpc_url,
        env: ChainEnv::BaseSepolia,
        idle_timeout_secs: 120,
    };
    let mut key = [0u8; 32];
    fill_random(&mut key);
    let cipher: Arc<dyn TempDbCipher> = AeadCipher::new_arc(SecretBytes::new(key.to_vec()));
    let mut session = IndexerSession::new(cfg, cipher).expect("session new");

    // Drive a Start over a small window — keeps the live RPC
    // surface bounded.
    let resp = session
        .handle_request(IndexerRequest::StartIndex {
            vault_id: vault_hex.clone(),
            start_block: D017_DEPLOY_BLOCK,
            end_block: Some(D017_DEPLOY_BLOCK + 100_000),
        })
        .await
        .expect("StartIndex");
    let _ = resp;

    // Read the on-disk file BEFORE we drain (the rows are in the
    // temp DB now; the pull would unwrap them in memory but we
    // want to see what's on disk).
    let path = session.temp_db_path().to_path_buf();
    let raw = std::fs::read(&path).expect("read temp DB on disk");

    // Drain so we get the plaintext content back for assertion.
    let pull = session
        .handle_request(IndexerRequest::Pull { batch_size: 1024 })
        .await
        .expect("Pull");
    let events = match pull {
        IndexerResponse::Batch { events } => events,
        other => panic!("expected Batch, got {other:?}"),
    };

    // For each event, assert the plaintext BLOB content does NOT
    // appear in the raw file. If any event's vault_id /
    // enc_payload / signer / block_hash / tx_hash appears as a
    // contiguous run on disk, the per-column AEAD wrap regressed.
    for e in &events {
        let pts: &[(&'static str, Vec<u8>)] = &[
            ("vault_id", hex::decode(&e.vault_id).unwrap()),
            ("account_id", hex::decode(&e.account_id).unwrap()),
            ("parent_revision", hex::decode(&e.parent_revision).unwrap()),
            ("device_id", hex::decode(&e.device_id).unwrap()),
            ("enc_payload", hex::decode(&e.enc_payload).unwrap()),
            ("signer", hex::decode(&e.signer).unwrap()),
            ("block_hash", hex::decode(&e.block_hash).unwrap()),
            ("tx_hash", hex::decode(&e.tx_hash).unwrap()),
        ];
        for (name, bytes) in pts {
            if bytes.is_empty() || bytes.len() < 8 {
                // Skip tiny / empty plaintexts (e.g., a degenerate
                // payload) — the search would false-positive on a
                // common byte sequence.
                continue;
            }
            let mut leaked = false;
            for window in raw.windows(bytes.len()) {
                if window == bytes.as_slice() {
                    leaked = true;
                    break;
                }
            }
            assert!(
                !leaked,
                "LIVE REGRESSION: column {name} plaintext appears in temp DB on disk \
                 (vault {vault_hex}); per-column AEAD wrap regressed for real D-017 payload",
            );
        }
    }

    // Stop + verify Stopped.
    let resp = session.handle_request(IndexerRequest::Stop).await.unwrap();
    assert!(matches!(resp, IndexerResponse::Stopped));
}
