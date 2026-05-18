// SPDX-License-Identifier: AGPL-3.0-or-later
//! Issue #98 R-a Option D — hermetic replay sibling for
//! `tests/parity.rs::live_indexer_vs_slow_mode_against_d017`.
//!
//! Loads the captured `eth_getLogs` JSON-RPC response from
//! `tests/fixtures/parity/d017_revisionpublished_batch.json` and
//! replays it through alloy's `RpcLog` deserializer + the workspace's
//! `IndexedEvent` shape. Defends env-quirk-#14's bytes-parsing
//! surface: a future alloy version that silently changes the JSON
//! decoding rules (or a future contract whose log shape drifts) is
//! caught at PR time, not on a live publish.
//!
//! ## Why this is a parity sibling (not a replacement)
//!
//! The live `parity.rs` test exercises the full StartIndex ⇒ Pull
//! cycle against a real RPC. This sibling can't do that without
//! network access; instead it asserts that the captured JSON-RPC
//! bytes round-trip through alloy's Log deserializer + pin the
//! load-bearing fields (address, topic_0, block_number, data
//! length) so a parser-side regression surfaces here on every PR.
//!
//! Per the fixture's `.meta.toml`: the captured bytes are from
//! D-014 (RevisionLogV0)'s only on-chain event (`block 41133109`,
//! tx `0x5cb4a7...f7ba6`). D-017 has no events yet — recapture
//! against D-017 is triggered automatically by the next deploy
//! cycle (R-c Option ζ).

#![forbid(unsafe_code)]
#![allow(clippy::doc_markdown)]

use alloy::rpc::types::Log as RpcLog;

/// Loads the captured fixture + deserializes as `Vec<RpcLog>`.
/// The whole point of issue #98 R-b Option α: replays through the
/// SAME parser production uses (alloy serde) so a parser regression
/// fails here.
fn load_fixture() -> Vec<RpcLog> {
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let path = manifest
        .join("tests")
        .join("fixtures")
        .join("parity")
        .join("d017_revisionpublished_batch.json");
    let bytes =
        std::fs::read(&path).unwrap_or_else(|e| panic!("read fixture at {}: {e}", path.display()));
    serde_json::from_slice::<Vec<RpcLog>>(&bytes)
        .unwrap_or_else(|e| panic!("parse fixture as Vec<RpcLog>: {e}"))
}

#[test]
fn replay_d017_genesis_revisionpublished_decodes_correctly() {
    let logs = load_fixture();
    // Pin the load-bearing fields. The fixture is the D-014 V0 first
    // event (block 41133109) — see `.meta.toml` for provenance + the
    // live-event-gap explanation for why this is D-014 not D-017.
    assert_eq!(logs.len(), 1, "fixture should hold exactly one log");
    let log = &logs[0];
    // Address — D-014 RevisionLogV0 deployment.
    assert_eq!(
        format!("{:?}", log.address()).to_lowercase(),
        "0x8566d3de653ee55775783bd7918fe91b66373896"
    );
    // Topic_0 — V0 RevisionPublished signature hash (audit-class:
    // any drift in the event signature ABI would shift this).
    let topics = log.topics();
    assert!(!topics.is_empty(), "log must have at least topic_0");
    assert_eq!(
        format!("{:?}", topics[0]).to_lowercase(),
        "0x6562412104cd03f86bf4f5184aa68e9d47cdb237b31b1de9d2fe1904eddcae8f"
    );
    // V0 RevisionPublished is `indexed vaultId, indexed accountId,
    // indexed parentRevision` — 4 topics including topic_0.
    assert_eq!(topics.len(), 4);
    // topic_1 (vaultId) = 0xaaaa...
    assert!(format!("{:?}", topics[1])
        .to_lowercase()
        .starts_with("0xaaaa"));
    // topic_2 (accountId) = 0xbbbb...
    assert!(format!("{:?}", topics[2])
        .to_lowercase()
        .starts_with("0xbbbb"));
    // topic_3 (parentRevision) = 0x0000... (genesis revision)
    assert_eq!(
        format!("{:?}", topics[3]).to_lowercase(),
        "0x0000000000000000000000000000000000000000000000000000000000000000"
    );
    // Block number = 41133109 (= 0x273a435).
    assert_eq!(log.block_number, Some(41_133_109));
    // tx_hash matches the recorded smoke-test tx.
    assert_eq!(
        format!("{:?}", log.transaction_hash.expect("tx_hash present")).to_lowercase(),
        "0x5cb4a7f4242838303964a7196b5326380b72d803d5d2e8f73d2c9d46664f7ba6"
    );
    // log_index = 0x9b = 155.
    assert_eq!(log.log_index, Some(155));
    // data length pins the encoded payload shape (deviceId 32 + schemaVersion-padded
    // 32 + sequence 32 + offset 32 + length 32 + 16-byte payload padded to 32 = 192 bytes).
    let data_bytes = log.inner.data.data.as_ref();
    assert_eq!(
        data_bytes.len(),
        192,
        "V0 RevisionPublished data is exactly 192 bytes (6 × 32-byte slots)"
    );
}

#[test]
fn replay_fixture_round_trips_through_alloy_serde() {
    // Defense against a future alloy version silently re-shaping the
    // Log JSON: round-trip the fixture and assert the re-encoded
    // bytes deserialize back to the same logical content.
    let original = load_fixture();
    let re_encoded = serde_json::to_string(&original).expect("re-encode");
    let round_tripped: Vec<RpcLog> = serde_json::from_str(&re_encoded).expect("round-trip parse");
    assert_eq!(round_tripped.len(), original.len());
    let a = &original[0];
    let b = &round_tripped[0];
    assert_eq!(a.address(), b.address());
    assert_eq!(a.topics(), b.topics());
    assert_eq!(a.block_number, b.block_number);
    assert_eq!(a.transaction_hash, b.transaction_hash);
    assert_eq!(a.log_index, b.log_index);
    assert_eq!(a.inner.data.data, b.inner.data.data);
}
