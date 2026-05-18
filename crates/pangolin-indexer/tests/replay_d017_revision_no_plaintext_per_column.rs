// SPDX-License-Identifier: AGPL-3.0-or-later
//! Issue #98 R-a Option D — hermetic replay sibling for
//! `tests/live_per_column_wrap.rs::live_per_column_aead_no_plaintext_on_disk`.
//!
//! Loads the captured `eth_getLogs` JSON-RPC response from
//! `tests/fixtures/per_column_wrap/d017_real_revisionpublished_payload.json`,
//! parses it through alloy's serde (the SAME path production uses),
//! derives a `VerifiedRevisionEvent` from the captured topics + data,
//! injects via `IndexerSession::test_inject_chunk`, and asserts the
//! raw temp DB file contains zero of the captured plaintext bytes.
//!
//! Defends env-quirk-#14's bytes-parsing surface AND the §4.3
//! per-column-AEAD wrap discipline simultaneously: a future
//! regression that bypasses the AEAD wrap for ANY captured-payload
//! column fails this test at PR time.

#![forbid(unsafe_code)]
#![allow(clippy::doc_markdown)]

use std::sync::Arc;

use alloy::primitives::{Address, B256};
use alloy::rpc::types::Log as RpcLog;

use pangolin_chain::{ChainAnchor, ChainEnv, RevisionEvent, VerifiedRevisionEvent};
use pangolin_crypto::rng::fill_random;
use pangolin_crypto::secret::SecretBytes;
use pangolin_indexer::{AeadCipher, IndexerConfig, IndexerSession, TempDbCipher};

fn load_fixture() -> Vec<RpcLog> {
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let path = manifest
        .join("tests")
        .join("fixtures")
        .join("per_column_wrap")
        .join("d017_real_revisionpublished_payload.json");
    let bytes =
        std::fs::read(&path).unwrap_or_else(|e| panic!("read fixture at {}: {e}", path.display()));
    serde_json::from_slice::<Vec<RpcLog>>(&bytes)
        .unwrap_or_else(|e| panic!("parse fixture as Vec<RpcLog>: {e}"))
}

/// Derive a `VerifiedRevisionEvent` from the captured log's topics +
/// data bytes. The shape mirrors what
/// `BaseSepoliaAdapter::pull_since` produces in production for a V0
/// `RevisionPublished` log (see `base_sepolia.rs::pull_since`).
///
/// Per the fixture's `.meta.toml` `live_event_gap`: D-017 has no
/// events yet, so this builds the equivalent V0-derived event from
/// the captured D-014 bytes. The disk-leak property holds for ANY
/// VerifiedRevisionEvent (it's about the AEAD wrap, not the V0/V1
/// distinction), so the test surface is real.
fn fixture_event() -> VerifiedRevisionEvent {
    let logs = load_fixture();
    assert_eq!(logs.len(), 1, "fixture should hold one log");
    let log = &logs[0];
    let topics = log.topics();
    // V0 RevisionPublished indexed fields: (vaultId, accountId, parentRevision)
    let vault_id: [u8; 32] = topics[1].into();
    let account_id: [u8; 32] = topics[2].into();
    let parent_revision: [u8; 32] = topics[3].into();
    // V0 RevisionPublished non-indexed data layout (6 × 32-byte slots,
    // 192 bytes total — pinned by `replay_d017_fixture_parity::
    // replay_d017_genesis_revisionpublished_decodes_correctly`):
    //   slot 0:  deviceId (bytes32)
    //   slot 1:  schemaVersion (uint8, left-padded to 32)
    //   slot 2:  sequence (uint256)
    //   slot 3:  offset to encPayload (= 0x80)
    //   slot 4:  encPayload length
    //   slot 5+: encPayload bytes (padded to 32-byte boundary)
    let data = log.inner.data.data.as_ref();
    assert_eq!(data.len(), 192, "V0 RevisionPublished is 192 bytes");
    let mut device_id = [0u8; 32];
    device_id.copy_from_slice(&data[0..32]);
    let schema_version_u8 = data[63];
    let schema_version = u16::from(schema_version_u8);
    let mut sequence_be = [0u8; 8];
    sequence_be.copy_from_slice(&data[88..96]); // tail of 32-byte sequence slot
    let sequence = u64::from_be_bytes(sequence_be);
    let payload_len = u64::from_be_bytes(data[152..160].try_into().expect("8 bytes"));
    assert!(
        payload_len > 0 && payload_len <= 32,
        "fixture payload should be 16 bytes (deadbeef sentinel) per .meta.toml"
    );
    let payload_len_usize = usize::try_from(payload_len).expect("payload_len fits in usize");
    let enc_payload = data[160..(160 + payload_len_usize)].to_vec();
    let tx_hash: [u8; 32] = log.transaction_hash.expect("tx_hash present").0;
    let block_number = log.block_number.expect("block_number present");
    let log_index = log.log_index.expect("log_index present");
    let block_hash: B256 = log.block_hash.expect("block_hash present");

    VerifiedRevisionEvent {
        event: RevisionEvent {
            vault_id,
            account_id,
            parent_revision,
            device_id,
            schema_version: schema_version_u8,
            sequence,
            enc_payload,
            anchor: ChainAnchor {
                tx_hash,
                block_number,
                log_index,
                sequence,
            },
        },
        // Synthetic signer (V0 doesn't carry a signer on-chain). The
        // disk-leak property scans the BLOB columns by content; the
        // signer's actual identity doesn't matter for the assertion.
        signer: Address::from([0x55u8; 20]),
        block_hash,
        schema_version,
    }
}

#[tokio::test]
async fn replay_d017_revision_no_plaintext_per_column() {
    let ev = fixture_event();
    let captured_plaintexts: Vec<(&'static str, Vec<u8>)> = vec![
        ("vault_id", ev.event.vault_id.to_vec()),
        ("account_id", ev.event.account_id.to_vec()),
        ("parent_revision", ev.event.parent_revision.to_vec()),
        ("device_id", ev.event.device_id.to_vec()),
        ("enc_payload", ev.event.enc_payload.clone()),
        ("signer", ev.signer.0.to_vec()),
        ("block_hash", ev.block_hash.0.to_vec()),
        ("tx_hash", ev.event.anchor.tx_hash.to_vec()),
    ];

    let cfg = IndexerConfig {
        rpc_url: "http://localhost:1".into(),
        env: ChainEnv::BaseSepolia,
        idle_timeout_secs: 60,
    };
    let mut key = [0u8; 32];
    fill_random(&mut key);
    let cipher: Arc<dyn TempDbCipher> = AeadCipher::new_arc(SecretBytes::new(key.to_vec()));
    let mut session = IndexerSession::new(cfg, cipher).expect("session new");

    session
        .test_inject_chunk(ev.event.vault_id, std::slice::from_ref(&ev))
        .expect("inject");

    let path = session.temp_db_path().to_path_buf();
    let raw = std::fs::read(&path).expect("read temp DB");

    for (name, bytes) in &captured_plaintexts {
        if bytes.len() < 4 {
            // Same skip rationale as the live sibling
            // (`live_per_column_wrap.rs::live_per_column_aead_no_plaintext_on_disk`):
            // tiny / empty plaintexts false-positive on common byte
            // sequences. 4-byte threshold is the sharpest viable one.
            continue;
        }
        // Skip degenerate plaintext values (all-zero, all-0xFF) that
        // would false-positive against SQLite's structural padding
        // bytes. The D-014 V0 smoke event has `parent_revision =
        // 0x0000...` (genesis revision); the AEAD wrap is still
        // exercised on those bytes (the cipher output is non-zero),
        // but a contains-match against an all-zero plaintext would
        // trip on any SQLite page header. Same exclusion applied in
        // the §4.3 hermetic per-column-wrap tests.
        if bytes.iter().all(|&b| b == 0) || bytes.iter().all(|&b| b == 0xFF) {
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
            "REPLAY REGRESSION: column {name} plaintext appears in temp DB on disk \
             (captured from fixture per_column_wrap/d017_real_revisionpublished_payload.json); \
             per-column AEAD wrap regressed for captured chain payload"
        );
    }
}
