// SPDX-License-Identifier: AGPL-3.0-or-later
//! §4.3 per-column AEAD: live `#[ignore]`-gated parity test against
//! D-017 (Option D residue per issue #98).
//!
//! Sibling of the hermetic
//! `tests/replay_d017_revision_no_plaintext_per_column.rs` (which
//! drives the same disk-sweep against the captured D-014 V0 event
//! fixture on every PR). This live residue covers the rolling-tip
//! contract-execution side of env-quirk #14: real D-017 byte
//! patterns drive the indexer through its persistence path, then the
//! raw temp DB is scanned for plaintext leakage.
//!
//! ## What this test adds beyond the hermetic replay
//!
//! The hermetic replay catches the AEAD-wiring property by exercising
//! `IndexerSession::test_inject_chunk` against the captured fixture's
//! decoded events — covering the indexer's persist path verbatim. The
//! live test additionally exercises (i) the end-to-end RPC ⇒ decoder ⇒
//! persist chain against arbitrary current D-017 chain state, and (ii)
//! contract-side semantics-drift catches (e.g., the verifier silently
//! widening the schema_version ladder mid-flight).
//!
//! **Operator-visible failure mode:** if the test fails when run via
//! `scripts/run-live-tests.{sh,ps1}`, the raw temp DB file leaked a
//! plaintext field from a real D-017 event payload. That means the
//! `AeadCipher` wrap silently bypassed at least one column. The
//! per-column failure assertion names which column leaked.

#![forbid(unsafe_code)]
#![allow(clippy::doc_markdown)]

use std::sync::Arc;

use pangolin_chain::ChainEnv;
use pangolin_crypto::rng::fill_random;
use pangolin_crypto::secret::SecretBytes;
use pangolin_indexer::{
    AeadCipher, IndexerConfig, IndexerRequest, IndexerResponse, IndexerSession, TempDbCipher,
};

/// Issue #98 (2026-05-18): re-pinned via cast verification — see
/// `pangolin_chain::d017_deploy_block` docstring.
const D017_DEPLOY_BLOCK: u64 = 41_507_120;

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
            if bytes.is_empty() || bytes.len() < 4 {
                // Skip tiny / empty plaintexts (≤ 3 bytes) where the
                // search would false-positive on any common byte
                // sequence (16M possible 3-byte windows in a few-MB
                // file ⇒ ~0% confidence). Threshold rationale:
                // 4 bytes = 32-bit window; in a 100 KiB temp DB the
                // chance any specific 4-byte pattern appears by
                // coincidence is ~2^-15 (still false-positive-prone
                // for the all-zero or all-0xFF case but acceptable
                // for cryptographic AEAD payloads which have
                // ~uniform byte distribution). The tightened
                // threshold makes the live sweep proportionately
                // sharper than the previous 8-byte cutoff.
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

/// **Negative-control sentinel** for the live raw-disk sweep.
///
/// The above `live_per_column_aead_no_plaintext_on_disk` test asserts
/// no event's plaintext appears in the raw temp DB file — but a test
/// that ONLY ever asserts absence can silently pass on degenerate
/// inputs (e.g., if every captured payload is shorter than the skip
/// threshold). To prove the test machinery would actually FAIL if
/// per-column wrapping leaked a payload, this negative-control test:
///
/// 1. Spins up a session backed by a **`NoOpCipher`** (the test-only
///    passthrough — every "wrap" is identity, so the BLOB plaintext
///    is written to disk verbatim).
/// 2. Injects a synthetic event with a distinctive 4-byte sentinel
///    in `enc_payload`.
/// 3. Reads the raw temp DB file and asserts the sentinel IS visible.
///
/// If this control test ever PASSES under `NoOpCipher` (i.e., the
/// sentinel is NOT found) something is wrong with the file-reading
/// machinery itself — the real positive test's "no plaintext" claim
/// would be unfalsifiable. Hermetic + does not need live RPC env
/// vars, so it runs on every PR.
#[test]
fn raw_disk_scan_finds_plaintext_under_noop_cipher_negative_control() {
    use alloy::primitives::{Address, B256};
    use pangolin_chain::{ChainAnchor, ChainEnv, RevisionEvent, VerifiedRevisionEvent};
    use pangolin_indexer::{IndexerConfig, IndexerSession, NoOpCipher};

    // A 4-byte sentinel — the same threshold we use in the positive
    // live sweep above. Distinctive enough not to false-positive in
    // typical SQLite header / page bytes.
    const SHORT_SENTINEL: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];

    let cfg = IndexerConfig {
        rpc_url: "http://localhost:1".into(),
        env: ChainEnv::BaseSepolia,
        idle_timeout_secs: 60,
    };
    // NoOpCipher: encrypt_page = identity, decrypt_page = identity.
    // The wrapped columns end up as plaintext on disk.
    let cipher: Arc<dyn pangolin_indexer::TempDbCipher> = NoOpCipher::new_arc();
    let mut session = IndexerSession::new(cfg, cipher).expect("session new");

    // Inject a synthetic event whose enc_payload begins with the
    // sentinel — the rest of the plaintext is padded so the payload
    // length is >= the live sweep's 4-byte threshold.
    let vault_id = [0xAAu8; 32];
    let mut payload = Vec::with_capacity(64);
    payload.extend_from_slice(&SHORT_SENTINEL);
    payload.extend_from_slice(&[0u8; 60]);
    let ev = VerifiedRevisionEvent {
        event: RevisionEvent {
            vault_id,
            account_id: [0xBBu8; 32],
            parent_revision: [0xCCu8; 32],
            device_id: [0xDDu8; 32],
            schema_version: 1,
            sequence: 1,
            enc_payload: payload.clone(),
            anchor: ChainAnchor {
                tx_hash: [0x33u8; 32],
                block_number: 1,
                log_index: 0,
                sequence: 1,
            },
        },
        signer: Address::from([0x11u8; 20]),
        block_hash: B256::from([0x22u8; 32]),
        schema_version: 1,
    };
    session.test_inject_chunk(vault_id, &[ev]).expect("inject");

    // Read the temp DB raw bytes; the sentinel MUST appear (NoOp
    // cipher writes plaintext blobs straight to disk).
    let path = session.temp_db_path().to_path_buf();
    let raw = std::fs::read(&path).expect("read temp DB");
    let mut found = false;
    for window in raw.windows(SHORT_SENTINEL.len()) {
        if window == SHORT_SENTINEL {
            found = true;
            break;
        }
    }
    assert!(
        found,
        "negative-control FAILED: the 4-byte sentinel was NOT found in the raw temp DB \
         under NoOpCipher (which is passthrough plaintext). This means the live sweep's \
         file-reading machinery is broken and its 'no plaintext' assertions are \
         unfalsifiable — the positive live test would silently pass even on a regression."
    );
}
