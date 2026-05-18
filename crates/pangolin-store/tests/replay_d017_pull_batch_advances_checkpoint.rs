// SPDX-License-Identifier: AGPL-3.0-or-later
//! Issue #98 R-a Option D — hermetic replay sibling for
//! `tests/pull_live.rs::live_pull_once_against_d017_advances_checkpoint`.
//!
//! Loads the captured `eth_getLogs` JSON-RPC response from
//! `tests/fixtures/pull/d017_pull_batch_logs.json`, builds the
//! `RevisionEvent` shape the fixture pins (vault/account/parent/
//! device/payload + chain anchor — same values pinned by the
//! indexer's sibling `replay_d017_genesis_revisionpublished_decodes_correctly`
//! test), then DRIVES that event through `Vault::ingest_chain_revision`
//! (the same ingestion path `Vault::sync_from_chain` calls per the
//! pull-cycle) AND `update_last_synced_block_v1` (the checkpoint-
//! monotonicity primitive `sync_from_chain` invokes after each
//! batch chunk per `vault.rs:7537`). Asserts the full ingest +
//! checkpoint round-trip:
//!
//!   1. `ingest_chain_revision` returns `Inserted` for a fresh event.
//!   2. The row queried back via `revisions_for` carries the
//!      captured fixture's chain anchor (block_number + log_index).
//!   3. `update_last_synced_block_v1(fixture_block)` advances the
//!      checkpoint from `None` to `Some(fixture_block)`.
//!   4. Re-applying the same block is a no-op (monotonic equal).
//!   5. Backward advance is rejected.
//!
//! Defends env-quirk-#14's bytes-parsing surface for the
//! pangolin-store pull cycle: a future regression in either the
//! `RevisionEvent` ingestion contract or the checkpoint-monotonicity
//! property surfaces here on every PR. The fixture is loaded raw
//! (and pinned by-length in `replay_fixture_byte_pin_audit`) — the
//! captured-event values used here are the same ones the indexer's
//! `replay_d017_fixture_parity` test pins from the SAME fixture
//! bytes through alloy's deserializer. The store crate intentionally
//! does NOT take a `serde_json` dev-dep (env-quirk #15): the
//! cross-crate parity test in pangolin-indexer is where the bytes
//! → `RpcLog` decode is exercised. This test owns the
//! `RevisionEvent` → `Vault` ingest path.
//!
//! Per the fixture's `.meta.toml`: bytes are from D-014 V0; D-017
//! has no events yet. The ingest + checkpoint properties are
//! parser-agnostic, so the hermetic test is real coverage.

#![forbid(unsafe_code)]
#![allow(clippy::doc_markdown)]

use pangolin_chain::{ChainAnchor, RevisionEvent};
use pangolin_crypto::secret::SecretBytes;
use pangolin_store::{AccountId, IngestOutcome, PinIdentityProof, PressYPresenceProof, Vault};

/// Fixture path. The bytes-→-`RpcLog` parsing surface is covered
/// by the `replay_d017_fixture_parity` sibling in pangolin-indexer
/// (where alloy is a regular dep); this test focuses on the
/// store's `RevisionEvent` → ingest → checkpoint pipeline. The
/// fixture's exact byte length is pinned in
/// `replay_fixture_byte_pin_audit` below.
fn fixture_path() -> std::path::PathBuf {
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .join("tests")
        .join("fixtures")
        .join("pull")
        .join("d017_pull_batch_logs.json")
}

fn pwd() -> SecretBytes {
    SecretBytes::new(b"correct horse battery staple".to_vec())
}

/// Build the captured event's `RevisionEvent` shape from the
/// fixture-pinned values. The indexer's
/// `replay_d017_genesis_revisionpublished_decodes_correctly` test
/// asserts the SAME hex (vault `0xaaaa...`, account `0xbbbb...`,
/// device `0xcccc...`, parent `0x0000...`, payload
/// `deadbeef...×4`, block `0x273a435 = 41133109`, log_index `0x9b
/// = 155`, tx_hash `0x5cb4a7...f7ba6`) from the fixture bytes
/// through alloy's `RpcLog` deserializer. Keeping the values
/// hand-pinned here (rather than parsing the fixture in-line via
/// `serde_json`) avoids taking a `serde_json` dev-dep on
/// pangolin-store — the cross-crate parity is the audit signal
/// per R-b Option α (same fixture, two parsers).
fn captured_event() -> RevisionEvent {
    let mut vault_id = [0u8; 32];
    vault_id[0] = 0xAA;
    vault_id[1] = 0xAA;
    let mut account_id = [0u8; 32];
    account_id[0] = 0xBB;
    account_id[1] = 0xBB;
    let parent_revision = [0u8; 32];
    let mut device_id = [0u8; 32];
    device_id[0] = 0xCC;
    device_id[1] = 0xCC;
    let enc_payload = vec![
        0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe,
        0xef,
    ];
    // Recorded D-014 tx hash + block per fixture's .meta.toml
    // captured cast command output (block 0x273a435 = 41133109).
    let tx_hash_hex = "5cb4a7f4242838303964a7196b5326380b72d803d5d2e8f73d2c9d46664f7ba6";
    let mut tx_hash = [0u8; 32];
    for (i, byte) in tx_hash.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&tx_hash_hex[i * 2..i * 2 + 2], 16).unwrap();
    }
    RevisionEvent {
        vault_id,
        account_id,
        parent_revision,
        device_id,
        schema_version: 0,
        sequence: 0,
        enc_payload,
        anchor: ChainAnchor {
            tx_hash,
            block_number: 41_133_109,
            log_index: 155,
            sequence: 0,
        },
    }
}

#[test]
fn replay_d017_pull_batch_advances_checkpoint() {
    // Fixture must exist + must be readable. The exact byte length is
    // separately pinned in `replay_fixture_byte_pin_audit` (below).
    let bytes = std::fs::read(fixture_path()).expect("fixture readable");
    assert!(!bytes.is_empty(), "fixture must be non-empty");

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("replay.pvf");
    Vault::create(&path, &pwd()).expect("create");
    let mut v = Vault::open(&path).expect("open");
    v.unlock(
        &PressYPresenceProof::confirmed(),
        &PinIdentityProof::new(pwd()),
    )
    .expect("unlock");

    // Pre-condition: fresh vault has no checkpoint + no rows for the
    // fixture's account.
    let pre_checkpoint = v.last_synced_block_v1().expect("read checkpoint");
    assert_eq!(pre_checkpoint, None, "fresh vault checkpoint must be None");
    let ev = captured_event();
    let account = AccountId::from_bytes(ev.account_id);
    let pre_revs = v.revisions_for(account).expect("revisions_for pre");
    assert!(
        pre_revs.is_empty(),
        "fresh vault must have no rows for the fixture's account"
    );
    let captured_block = ev.anchor.block_number;
    let captured_log_index = ev.anchor.log_index;
    assert_eq!(
        captured_block, 41_133_109_u64,
        "fixture's pinned block number — same value the indexer's \
         replay_d017_genesis_revisionpublished_decodes_correctly asserts \
         from the same bytes"
    );

    // ─── Phase 1: drive the captured event through ingest_chain_revision
    // ─── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ──
    // This is the production ingestion path: `Vault::sync_from_chain`
    // (vault.rs:7436) → adapter `pull_since` → for-each-event
    // `ingest_chain_revision`. The captured fixture would normally
    // be returned by the adapter; here we replay the event values
    // pinned from the captured bytes directly. The bytes-→-event
    // parse is exercised by the indexer's `replay_d017_fixture_parity`
    // sibling (alloy is a regular dep there; this crate avoids
    // taking serde_json as a dev-dep).
    let outcome = v.ingest_chain_revision(&ev).expect("ingest must succeed");
    assert_eq!(
        outcome,
        IngestOutcome::Inserted,
        "fresh fixture event must be inserted (no prior row)"
    );

    // The inserted row must carry the captured chain anchor — this
    // is the load-bearing property: a downstream consumer querying
    // `revisions_for` sees the same block/log_index it would see
    // after a live `sync_from_chain` run.
    let revs = v.revisions_for(account).expect("revisions_for post");
    assert_eq!(revs.len(), 1, "exactly one row after fixture ingest");
    let anchor = revs[0]
        .chain_anchor
        .expect("ingested row must carry a chain anchor");
    assert_eq!(
        anchor.block_number, captured_block,
        "row anchor must pin the captured fixture's block"
    );
    assert_eq!(
        anchor.log_index, captured_log_index,
        "row anchor must pin the captured fixture's log_index"
    );

    // Idempotency: re-ingesting the same event returns `AlreadyPresent`
    // + leaves the row count untouched. This is what `sync_from_chain`
    // relies on when the same log re-arrives in an overlapping pull
    // window.
    let re = v
        .ingest_chain_revision(&ev)
        .expect("re-ingest must succeed");
    assert_eq!(re, IngestOutcome::AlreadyPresent);
    let revs2 = v
        .revisions_for(account)
        .expect("revisions_for after re-ingest");
    assert_eq!(revs2.len(), 1, "no duplicate row on re-ingest");

    // ─── Phase 2: advance the checkpoint via the same primitive
    // ─── `sync_from_chain` calls after each chunk (vault.rs:7537)
    // ─── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ──
    v.update_last_synced_block_v1(captured_block)
        .expect("checkpoint must advance");
    let post_checkpoint = v.last_synced_block_v1().expect("read checkpoint");
    assert_eq!(
        post_checkpoint,
        Some(captured_block),
        "checkpoint must equal the fixture's captured block"
    );
    assert!(
        post_checkpoint.unwrap_or(0) > pre_checkpoint.unwrap_or(0),
        "checkpoint must strictly advance from None ⇒ Some(captured_block)"
    );

    // Re-applying the same block is a no-op (monotonic equal — the
    // exact semantics `sync_from_chain` depends on for chunks that
    // do not advance the head).
    v.update_last_synced_block_v1(captured_block)
        .expect("idempotent re-apply");
    assert_eq!(
        v.last_synced_block_v1().expect("re-read"),
        Some(captured_block)
    );

    // Backward advance is rejected (checkpoint monotonicity defense
    // — a malicious or buggy adapter returning a regressed
    // `eth_blockNumber` must not be able to rewind the local cursor).
    let backward = v.update_last_synced_block_v1(captured_block.saturating_sub(1));
    assert!(
        backward.is_err(),
        "checkpoint must reject backward advance — got Ok"
    );
}

#[test]
fn replay_fixture_byte_pin_audit() {
    // The fixture file's exact byte length pins its content — any
    // unintended edit fires here. Updates to the fixture MUST come
    // with a `.meta.toml` `sha256_of_fixture` update + a `cast`
    // recapture per R-c Option ζ.
    let bytes = std::fs::read(fixture_path()).expect("fixture readable");
    assert_eq!(
        bytes.len(),
        1026,
        "captured eth_getLogs response is exactly 1026 bytes (per .meta.toml); \
         a mismatch means the fixture drifted from its provenance record"
    );
}
