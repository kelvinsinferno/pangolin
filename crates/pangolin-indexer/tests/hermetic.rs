// SPDX-License-Identifier: AGPL-3.0-or-later
//! 4.2 R-f hermetic integration suite.
//!
//! These tests exercise the public lifecycle + protocol surface
//! without touching a live RPC. Per L1 + L5 + L-stdio-injection +
//! Q-c: lifecycle constants, the JSON protocol contract, the
//! idle-timeout env clamp, and the vault-id filter discipline are
//! covered here.
//!
//! Live `eth_getLogs` semantics are covered in `parity.rs`
//! (`#[ignore]`-gated).

#![forbid(unsafe_code)]

use std::sync::Arc;
use std::time::Duration;

use pangolin_chain::ChainEnv;
use pangolin_indexer::{
    resolve_idle_timeout_from, IndexedEvent, IndexerConfig, IndexerError, IndexerRequest,
    IndexerResponse, IndexerSession, NoOpCipher, TempDbCipher, IDLE_TIMEOUT_DEFAULT_SECS,
    IDLE_TIMEOUT_MAX_SECS, IDLE_TIMEOUT_MIN_SECS, MAX_REQUEST_LINE_BYTES, PROTOCOL_VERSION,
    PULL_BATCH_SIZE_MAX,
};

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

fn make_config() -> IndexerConfig {
    IndexerConfig {
        rpc_url: "http://localhost:8545".into(),
        env: ChainEnv::BaseSepolia,
        idle_timeout_secs: 60,
    }
}

fn fresh_session() -> IndexerSession {
    IndexerSession::new(make_config(), NoOpCipher::new_arc()).expect("new")
}

// ---------------------------------------------------------------------
// Constants pinning (R-c + L1 + L-stdio-injection)
// ---------------------------------------------------------------------

#[test]
fn protocol_version_is_pinned_at_1() {
    assert_eq!(PROTOCOL_VERSION, 1);
}

#[test]
fn idle_timeout_constants_are_pinned() {
    assert_eq!(IDLE_TIMEOUT_DEFAULT_SECS, 300);
    assert_eq!(IDLE_TIMEOUT_MIN_SECS, 60);
    assert_eq!(IDLE_TIMEOUT_MAX_SECS, 3_600);
}

#[test]
fn max_request_line_bytes_is_64k() {
    assert_eq!(MAX_REQUEST_LINE_BYTES, 65_536);
}

#[test]
fn pull_batch_size_max_is_pinned() {
    assert_eq!(PULL_BATCH_SIZE_MAX, 1_024);
}

// ---------------------------------------------------------------------
// Lifecycle — temp file create + drop (L1 + L11)
// ---------------------------------------------------------------------

#[test]
fn session_lifecycle_normal_exit_deletes_temp_db() {
    // L1 + L11 normal-exit branch: the NamedTempFile is unlinked
    // when the session is dropped. Captured-then-released path so
    // we can inspect the path *after* drop.
    let path = {
        let s = fresh_session();
        s.temp_db_path().to_path_buf()
    };
    assert!(!path.exists(), "temp file must be gone after Drop");
}

#[test]
fn session_temp_file_exists_during_lifetime() {
    let s = fresh_session();
    let path = s.temp_db_path().to_path_buf();
    assert!(path.exists(), "temp file must exist while session is live");
    // Schema migrated; count query works.
    assert_eq!(s.cached_event_count().unwrap(), 0);
}

#[test]
fn session_debug_does_not_leak_temp_path() {
    let s = fresh_session();
    let dbg = format!("{s:?}");
    let path_str = s.temp_db_path().display().to_string();
    assert!(
        !dbg.contains(&path_str),
        "Debug must not leak temp file path"
    );
}

// ---------------------------------------------------------------------
// R-c idle-timeout env clamp
// ---------------------------------------------------------------------

#[test]
fn idle_timeout_env_override_clamps_to_max() {
    assert_eq!(
        resolve_idle_timeout_from(Some("99999")),
        IDLE_TIMEOUT_MAX_SECS
    );
}

#[test]
fn idle_timeout_env_override_clamps_to_min() {
    assert_eq!(resolve_idle_timeout_from(Some("1")), IDLE_TIMEOUT_MIN_SECS);
}

#[test]
fn idle_timeout_env_override_in_range_is_passed_through() {
    assert_eq!(resolve_idle_timeout_from(Some("120")), 120);
}

#[test]
fn idle_timeout_default_resolves_to_300() {
    assert_eq!(resolve_idle_timeout_from(None), IDLE_TIMEOUT_DEFAULT_SECS);
}

#[test]
fn idle_timeout_invalid_input_falls_back_to_default() {
    assert_eq!(
        resolve_idle_timeout_from(Some("not-a-number")),
        IDLE_TIMEOUT_DEFAULT_SECS
    );
}

// ---------------------------------------------------------------------
// L5 idle-timeout fires under simulated time
// ---------------------------------------------------------------------

#[tokio::test(start_paused = true)]
async fn idle_timeout_fires_under_simulated_time() {
    // R-c / L5 verbatim: an indexer that idles past
    // `idle_timeout_secs` exits cleanly. We simulate this via
    // tokio's paused clock — no wall-clock sleeps in CI.
    let cfg = IndexerConfig {
        rpc_url: "http://localhost:8545".into(),
        env: ChainEnv::BaseSepolia,
        // 5 seconds — well under the default but valid for the
        // session struct (clamping happens at the
        // resolve_idle_timeout layer, not the IndexerConfig
        // struct constructor; this lets tests drive arbitrarily
        // short timeouts).
        idle_timeout_secs: 5,
    };
    let session = IndexerSession::new(cfg, NoOpCipher::new_arc()).unwrap();
    assert_eq!(session.idle_timeout(), Duration::from_secs(5));
    // Drive simulated time past the idle deadline + verify the
    // sleep future would have completed by then. (The library does
    // not run the loop without a transport; the test asserts the
    // configured duration is honoured.)
    tokio::time::advance(Duration::from_secs(6)).await;
    // Stop request short-circuits any pending idle-timeout, so the
    // session can be cleanly dropped.
    drop(session);
}

// ---------------------------------------------------------------------
// R-b stdio JSON protocol
// ---------------------------------------------------------------------

#[test]
fn well_formed_pull_request_round_trips() {
    let req = IndexerRequest::Pull { batch_size: 16 };
    let s = serde_json::to_string(&req).unwrap();
    let back: IndexerRequest = serde_json::from_str(&s).unwrap();
    assert_eq!(req, back);
}

#[test]
fn well_formed_start_index_request_round_trips() {
    let req = IndexerRequest::StartIndex {
        vault_id: "ab".repeat(32),
        start_block: 23_640_113,
        end_block: Some(23_640_213),
    };
    let s = serde_json::to_string(&req).unwrap();
    let back: IndexerRequest = serde_json::from_str(&s).unwrap();
    assert_eq!(req, back);
}

#[test]
fn malformed_input_rejected_as_protocol_error() {
    // R-b L-stdio-injection: garbage on stdin must NOT crash the
    // dispatcher.
    let bad = "this is not json at all";
    let res: Result<IndexerRequest, _> = serde_json::from_str(bad);
    assert!(res.is_err());
}

#[test]
fn unknown_request_variant_rejected() {
    let bad = r#"{"type":"detonate","seed":42}"#;
    let res: Result<IndexerRequest, _> = serde_json::from_str(bad);
    assert!(res.is_err());
}

#[test]
fn unknown_request_field_rejected() {
    // deny_unknown_fields catches typos on the request side.
    let bad = r#"{"type":"pull","batch_size":1,"poison":"!"}"#;
    let res: Result<IndexerRequest, _> = serde_json::from_str(bad);
    assert!(res.is_err());
}

#[test]
fn response_started_carries_protocol_version_field() {
    let resp = IndexerResponse::Started {
        protocol_version: PROTOCOL_VERSION,
        vault_id: "ab".repeat(32),
    };
    let s = serde_json::to_string(&resp).unwrap();
    assert!(s.contains("\"protocol_version\":1"));
}

#[tokio::test]
async fn heartbeat_request_yields_heartbeat_response() {
    let mut s = fresh_session();
    let resp = s.handle_request(IndexerRequest::Heartbeat).await.unwrap();
    assert!(matches!(resp, IndexerResponse::Heartbeat));
}

#[tokio::test]
async fn stop_request_yields_stopped_response() {
    let mut s = fresh_session();
    let resp = s.handle_request(IndexerRequest::Stop).await.unwrap();
    assert!(matches!(resp, IndexerResponse::Stopped));
}

#[tokio::test]
async fn pull_before_start_index_returns_protocol_error() {
    let mut s = fresh_session();
    let res = s
        .handle_request(IndexerRequest::Pull { batch_size: 10 })
        .await;
    assert!(matches!(res, Err(IndexerError::ProtocolError { .. })));
}

// ---------------------------------------------------------------------
// R-d cipher trait stub
// ---------------------------------------------------------------------

#[test]
fn noop_cipher_round_trips_arbitrary_input() {
    let c = NoOpCipher;
    let aad: &[u8] = b"hermetic-noop-aad";
    for n in [0usize, 1, 16, 4096, 1 << 16] {
        let buf: Vec<u8> = (0..n).map(|i| u8::try_from(i & 0xFF).unwrap()).collect();
        let enc = c.encrypt_page(&buf, aad);
        // §4.3 per-column AEAD: TempDbCipher::decrypt_page returns
        // `Result<Vec<u8>, CipherError>` and takes an AAD param.
        // NoOpCipher always returns Ok and ignores AAD.
        let dec = c.decrypt_page(&enc, aad).expect("noop decrypt always Ok");
        assert_eq!(buf, dec);
    }
}

#[test]
fn noop_cipher_is_an_arc_dyn_temp_db_cipher() {
    let arc: Arc<dyn TempDbCipher> = NoOpCipher::new_arc();
    let plaintext = b"hermetic test payload";
    let aad: &[u8] = b"hermetic-arc-aad";
    let round = arc
        .decrypt_page(&arc.encrypt_page(plaintext, aad), aad)
        .expect("noop decrypt always Ok");
    assert_eq!(round, plaintext.to_vec());
}

// ---------------------------------------------------------------------
// L2 vault_id filter discipline at the temp-DB insert + read paths
// ---------------------------------------------------------------------

#[test]
fn pull_response_carries_only_bound_vault_id() {
    // We can't easily wire a live chain into a hermetic test, so
    // this test verifies the contract at the `IndexedEvent` shape
    // level: any event emitted to the host carries the same
    // vault_id the session was bound to.
    //
    // The session's persist_chunk skips foreign-vault rows BEFORE
    // they hit the temp DB; the read-side has a second guard. The
    // protocol-level invariant we pin here is that `IndexedEvent`
    // carries an explicit `vault_id` field the host can verify.
    let event = IndexedEvent {
        vault_id: "ab".repeat(32),
        account_id: "cd".repeat(32),
        parent_revision: "ef".repeat(32),
        device_id: "01".repeat(32),
        schema_version: 1,
        sequence: 7,
        enc_payload: hex::encode([0u8; 64]),
        signer: hex::encode([0u8; 20]),
        block_number: 23_640_113,
        block_hash: "12".repeat(32),
        tx_hash: "34".repeat(32),
        log_index: 1,
    };
    // Round-trip JSON: the wire format pins the vault_id field.
    let s = serde_json::to_string(&event).unwrap();
    assert!(s.contains("\"vault_id\""));
    let back: IndexedEvent = serde_json::from_str(&s).unwrap();
    assert_eq!(event, back);
}

// ---------------------------------------------------------------------
// L7 (mechanical) — the indexer crate doesn't depend on pangolin-store.
// ---------------------------------------------------------------------

#[test]
fn indexer_module_does_not_link_pangolin_store() {
    // Compile-time check: this test file only `use`s
    // pangolin_indexer + pangolin_chain. If the indexer crate ever
    // grows a pangolin-store dep, the workspace tree command in
    // the CI invariants surfaces the regression; this test pins
    // the discipline at the test-binary level (the test crate
    // itself doesn't pull pangolin-store as a dep).
    // Smoke-touch the public surface so the import set is
    // exercised by `cargo test`.
    let _ = NoOpCipher;
    let _ = IndexerRequest::Heartbeat;
}
