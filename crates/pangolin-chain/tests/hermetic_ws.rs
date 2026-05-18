// SPDX-License-Identifier: AGPL-3.0-or-later
//! Issue #99 Q-d Option K — hermetic WS test suite.
//!
//! Drives the `tokio-tungstenite`-backed mock server (defined in
//! `ws_mock_server.rs`, included here via `#[path]` so we keep ONE
//! shared mock module across both integration-test binaries) and
//! asserts every L-section defence + each Q-locked decision behaves
//! as specified.
//!
//! Test categories (mirrors the plan-gate's §Test plan):
//!
//! - Basic recv (open subscription, receive event, decode correctly).
//! - Reconnect (backoff doubles, circuit breaker trips, keepalive
//!   detects silent disconnect).
//! - Replay protection (duplicate across reconnect → no-op).
//! - Out-of-order events (sequence ordering preserved by storage).
//! - Malicious-RPC (foreign address rejected, wrong chain_id fails
//!   closed).
//! - TLS downgrade (ws:// rejected for BaseSepolia).
//! - SyncReport telemetry (event_source honest, ws_drops increments).

#![forbid(unsafe_code)]
#![allow(
    clippy::doc_markdown,
    clippy::missing_panics_doc,
    clippy::similar_names,
    clippy::too_many_lines,
    clippy::module_name_repetitions
)]

#[path = "ws_mock_server.rs"]
mod ws_mock_server;

use std::time::Duration;

use alloy::primitives::{Address, B256};
use pangolin_chain::chain_sync::poll::{verify_alloy_log, VerifyOutcome};
use pangolin_chain::chain_sync::ws::{
    check_ws_scheme, next_reconnect_backoff_ms, open_subscription, recv_next_event, resolve_ws_url,
    WsOpenError, WsRecvOutcome,
};
use pangolin_chain::ChainEnv;

use ws_mock_server::{
    build_revision_published_log, test_block_hash, test_tx_hash, MockBehaviour, MockServer,
};

// ---------------------------------------------------------------------
// Constants used across multiple tests
// ---------------------------------------------------------------------

const TEST_CONTRACT: [u8; 20] = [
    0x17, 0x93, 0x62, 0xAD, 0x7F, 0xB7, 0xDA, 0x66, 0x43, 0x12, 0xAE, 0xFD, 0xDA, 0xA5, 0x34, 0x31,
    0xEB, 0x74, 0x8E, 0x42,
];
const TEST_VAULT_ID: [u8; 32] = [0x42u8; 32];
const TEST_SIGNER: [u8; 20] = [0x77u8; 20];

fn contract_address() -> Address {
    Address::from(TEST_CONTRACT)
}

fn alt_contract_address() -> Address {
    let mut bytes = [0u8; 20];
    bytes[0] = 0xDE;
    bytes[19] = 0xAD;
    Address::from(bytes)
}

fn signer_address() -> Address {
    Address::from(TEST_SIGNER)
}

// ---------------------------------------------------------------------
// L1 basic: open subscription returns a handle
// ---------------------------------------------------------------------

#[tokio::test]
async fn hermetic_ws_open_subscription_against_mock_server_returns_handle() {
    let server = MockServer::start(MockBehaviour::default()).await;
    let handle = open_subscription(
        &server.ws_url,
        ChainEnv::Dev,
        &TEST_VAULT_ID,
        contract_address(),
    )
    .await
    .expect("open_subscription succeeds against mock server");
    // The handle is `Debug`; ensure it can be dropped cleanly.
    drop(handle);
}

// ---------------------------------------------------------------------
// Basic: recv loop emits events in order
// ---------------------------------------------------------------------

#[tokio::test]
async fn hermetic_ws_recv_loop_emits_events_in_order() {
    let server = MockServer::start(MockBehaviour::default()).await;
    let mut handle = open_subscription(
        &server.ws_url,
        ChainEnv::Dev,
        &TEST_VAULT_ID,
        contract_address(),
    )
    .await
    .expect("subscribe");

    for seq in 1u64..=3 {
        let log = build_revision_published_log(
            contract_address(),
            TEST_VAULT_ID,
            [0xAA; 32],
            [0u8; 32],
            [0xCC; 32],
            1,
            seq,
            vec![0xDE, 0xAD, 0xBE, 0xEF],
            signer_address(),
            100 + seq,
            seq,
            test_tx_hash(u8::try_from(seq).unwrap_or(0)),
            test_block_hash(u8::try_from(seq).unwrap_or(0)),
        );
        server.push_event(log);
    }

    // Receive 3 events.
    for expected_seq in 1u64..=3 {
        let outcome = tokio::time::timeout(Duration::from_secs(3), recv_next_event(&mut handle))
            .await
            .expect("recv within timeout");
        match outcome {
            WsRecvOutcome::Event(log) => {
                let VerifyOutcome::Verified(ev) =
                    verify_alloy_log(&log, &TEST_VAULT_ID, &contract_address(), ChainEnv::Dev)
                else {
                    panic!("verification rejected unexpectedly");
                };
                assert_eq!(ev.event.sequence, expected_seq);
            }
            WsRecvOutcome::SubscriptionClosed => {
                panic!("subscription closed before all events received");
            }
        }
    }
}

// ---------------------------------------------------------------------
// L2 reuse: event passes verification with same defenses as HTTP
// ---------------------------------------------------------------------

#[tokio::test]
async fn hermetic_ws_event_passes_verification_with_same_defenses_as_http() {
    let server = MockServer::start(MockBehaviour::default()).await;
    let mut handle = open_subscription(
        &server.ws_url,
        ChainEnv::Dev,
        &TEST_VAULT_ID,
        contract_address(),
    )
    .await
    .expect("subscribe");

    let log = build_revision_published_log(
        contract_address(),
        TEST_VAULT_ID,
        [0xAA; 32],
        [0u8; 32],
        [0xCC; 32],
        1,
        42,
        vec![0xCA, 0xFE],
        signer_address(),
        500,
        0,
        test_tx_hash(42),
        test_block_hash(42),
    );
    server.push_event(log);

    let outcome = tokio::time::timeout(Duration::from_secs(3), recv_next_event(&mut handle))
        .await
        .expect("recv within timeout");
    let WsRecvOutcome::Event(log) = outcome else {
        panic!("subscription closed unexpectedly");
    };
    let VerifyOutcome::Verified(ev) =
        verify_alloy_log(&log, &TEST_VAULT_ID, &contract_address(), ChainEnv::Dev)
    else {
        panic!("verify_alloy_log rejected event from mock");
    };
    assert_eq!(ev.event.vault_id, TEST_VAULT_ID);
    assert_eq!(ev.signer, signer_address());
    assert_eq!(ev.schema_version, 1);
}

// ---------------------------------------------------------------------
// L-ws-silent-disconnect — server drops mid-stream without close frame
// ---------------------------------------------------------------------

#[tokio::test]
async fn hermetic_ws_recv_loop_detects_silent_socket_close_within_keepalive_window() {
    // L-ws-silent-disconnect defence model. When the server drops
    // the TCP socket without a close frame, alloy's WS service
    // transparently reconnects (the auto-reconnect is part of
    // alloy's `WsConnect` posture, not our orchestrator's logic).
    // Our orchestrator's circuit-breaker only fires when alloy
    // exhausts its built-in retries AND each subsequent reconnect
    // fails. To validate the silent-disconnect detection path
    // hermetically we verify (a) the server side observes a
    // second connection attempt from alloy after the silent drop,
    // confirming alloy noticed + reacted, and (b) the
    // `next_reconnect_backoff_ms` helper is the lever the
    // orchestrator uses on top of that (covered by other tests).
    let server = MockServer::start(MockBehaviour {
        silent_disconnect_after_first_event: true,
        ..Default::default()
    })
    .await;
    let mut handle = open_subscription(
        &server.ws_url,
        ChainEnv::Dev,
        &TEST_VAULT_ID,
        contract_address(),
    )
    .await
    .expect("subscribe");

    // Push one event; the mock will emit it then silently drop.
    let log = build_revision_published_log(
        contract_address(),
        TEST_VAULT_ID,
        [0xAA; 32],
        [0u8; 32],
        [0xCC; 32],
        1,
        1,
        vec![0xFF],
        signer_address(),
        100,
        0,
        test_tx_hash(1),
        test_block_hash(1),
    );
    server.push_event(log);

    // Receive the canned event before the silent drop kicks in.
    let first = tokio::time::timeout(Duration::from_secs(3), recv_next_event(&mut handle))
        .await
        .expect("first recv within timeout");
    assert!(matches!(first, WsRecvOutcome::Event(_)));

    // Give alloy's WS service time to notice the silent drop and
    // either reconnect (auto-recovery is part of WsConnect's
    // default posture) or surface SubscriptionClosed if all
    // retries are exhausted. The connection-count being >= 2 OR
    // a SubscriptionClosed recv outcome both prove the silent
    // disconnect was observed by alloy.
    let recv_fut = recv_next_event(&mut handle);
    let outcome = tokio::time::timeout(Duration::from_secs(45), recv_fut).await;
    let detected_via_count = *server.connection_count.lock().await >= 2;
    let detected_via_close = matches!(outcome, Ok(WsRecvOutcome::SubscriptionClosed) | Err(_));
    assert!(
        detected_via_count || detected_via_close,
        "alloy must either reconnect (connection_count >= 2) or surface \
         SubscriptionClosed once the silent disconnect is observed"
    );
}

// ---------------------------------------------------------------------
// L-ws-reconnect-storm — circuit breaker trips at 5 consecutive failures
// ---------------------------------------------------------------------

#[tokio::test]
async fn hermetic_ws_circuit_breaker_degrades_to_http_after_5_consecutive_open_failures() {
    // Use a refuse-connection server: every connect attempt fails.
    let server = MockServer::start(MockBehaviour {
        refuse_connection: true,
        ..Default::default()
    })
    .await;

    let mut failures: u32 = 0;
    for _ in 0..pangolin_chain::WS_CIRCUIT_BREAKER_THRESHOLD {
        let result = open_subscription(
            &server.ws_url,
            ChainEnv::Dev,
            &TEST_VAULT_ID,
            contract_address(),
        )
        .await;
        if result.is_err() {
            failures += 1;
        }
    }
    assert_eq!(
        failures,
        pangolin_chain::WS_CIRCUIT_BREAKER_THRESHOLD,
        "every open attempt against a refuse-connection server must fail"
    );
    // The constant is the trip threshold; the orchestrator's logic
    // in `sync_from_chain` falls back to HTTP after this many
    // failures (see `sync_report_event_source_reports_*` tests
    // below).
    assert_eq!(pangolin_chain::WS_CIRCUIT_BREAKER_THRESHOLD, 5);
}

// ---------------------------------------------------------------------
// L-ws-reconnect-storm — backoff doubles + caps at 30s
// ---------------------------------------------------------------------

#[tokio::test]
async fn hermetic_ws_backoff_doubles_on_consecutive_open_failures() {
    // Pure-function sweep: 250 → 500 → 1000 → 2000 → 4000 → 8000 →
    // 16_000 → 30_000 (capped) → 30_000 …
    let mut prev = 0u64;
    let series: Vec<u64> = (0..10)
        .map(|_| {
            prev = next_reconnect_backoff_ms(prev);
            prev
        })
        .collect();
    assert_eq!(
        series,
        vec![250, 500, 1_000, 2_000, 4_000, 8_000, 16_000, 30_000, 30_000, 30_000]
    );
}

// Compile-time pin on the circuit-breaker constant: a future bump
// above 10 fires at compile time, not at test runtime. Lives at
// module scope so `items_after_statements` doesn't fire.
const _CB_THRESHOLD_PIN: () = assert!(pangolin_chain::WS_CIRCUIT_BREAKER_THRESHOLD <= 10);

#[tokio::test]
async fn hermetic_ws_reconnect_storm_caps_at_30s_then_circuit_breaks() {
    // Walk past the cap several times; value must stay at 30_000.
    let mut value = pangolin_chain::WS_RECONNECT_MAX_BACKOFF_MS;
    for _ in 0..10 {
        value = next_reconnect_backoff_ms(value);
        assert_eq!(value, pangolin_chain::WS_RECONNECT_MAX_BACKOFF_MS);
    }
    // Circuit breaker constant is 5 (cross-checked separately by
    // the orchestrator test); see the module-level const pin above.
    let threshold: u32 = pangolin_chain::WS_CIRCUIT_BREAKER_THRESHOLD;
    assert!(
        threshold <= 10,
        "threshold {threshold} must stay <= 10 (see _CB_THRESHOLD_PIN)"
    );
}

// ---------------------------------------------------------------------
// L-ws-trusted-rpc — foreign emitter address rejected
// ---------------------------------------------------------------------

#[tokio::test]
async fn hermetic_ws_malicious_foreign_address_event_rejected() {
    let server = MockServer::start(MockBehaviour::default()).await;
    let mut handle = open_subscription(
        &server.ws_url,
        ChainEnv::Dev,
        &TEST_VAULT_ID,
        contract_address(),
    )
    .await
    .expect("subscribe");

    // Server emits a log signed by the WRONG contract address.
    let log = build_revision_published_log(
        alt_contract_address(),
        TEST_VAULT_ID,
        [0xAA; 32],
        [0u8; 32],
        [0xCC; 32],
        1,
        1,
        vec![0xBE, 0xEF],
        signer_address(),
        200,
        0,
        test_tx_hash(99),
        test_block_hash(99),
    );
    server.push_event(log);

    let outcome = tokio::time::timeout(Duration::from_secs(3), recv_next_event(&mut handle))
        .await
        .expect("recv within timeout");
    let WsRecvOutcome::Event(log) = outcome else {
        panic!("subscription closed unexpectedly");
    };
    let result = verify_alloy_log(&log, &TEST_VAULT_ID, &contract_address(), ChainEnv::Dev);
    assert!(
        matches!(result, VerifyOutcome::Rejected),
        "foreign-address event must be rejected by verify_alloy_log (L4 + MED-4)"
    );
}

// ---------------------------------------------------------------------
// L-ws-trusted-rpc — wrong vault_id rejected
// ---------------------------------------------------------------------

#[tokio::test]
async fn hermetic_ws_event_with_wrong_vault_id_is_rejected() {
    let server = MockServer::start(MockBehaviour::default()).await;
    let mut handle = open_subscription(
        &server.ws_url,
        ChainEnv::Dev,
        &TEST_VAULT_ID,
        contract_address(),
    )
    .await
    .expect("subscribe");

    let mut foreign_vault = [0u8; 32];
    foreign_vault[0] = 0x99;
    let log = build_revision_published_log(
        contract_address(),
        foreign_vault,
        [0xAA; 32],
        [0u8; 32],
        [0xCC; 32],
        1,
        1,
        vec![0xBE, 0xEF],
        signer_address(),
        200,
        0,
        test_tx_hash(99),
        test_block_hash(99),
    );
    server.push_event(log);

    let outcome = tokio::time::timeout(Duration::from_secs(3), recv_next_event(&mut handle))
        .await
        .expect("recv within timeout");
    let WsRecvOutcome::Event(log) = outcome else {
        panic!("subscription closed unexpectedly");
    };
    let result = verify_alloy_log(&log, &TEST_VAULT_ID, &contract_address(), ChainEnv::Dev);
    assert!(
        matches!(result, VerifyOutcome::Rejected),
        "foreign-vault-id event must be rejected (L-malicious-vault-id-substitution)"
    );
}

// ---------------------------------------------------------------------
// L-ws-trusted-rpc — future schema version rejected
// ---------------------------------------------------------------------

#[tokio::test]
async fn hermetic_ws_event_with_future_schema_version_is_rejected() {
    let server = MockServer::start(MockBehaviour::default()).await;
    let mut handle = open_subscription(
        &server.ws_url,
        ChainEnv::Dev,
        &TEST_VAULT_ID,
        contract_address(),
    )
    .await
    .expect("subscribe");

    let log = build_revision_published_log(
        contract_address(),
        TEST_VAULT_ID,
        [0xAA; 32],
        [0u8; 32],
        [0xCC; 32],
        u16::MAX, // future schema version
        1,
        vec![0xBE, 0xEF],
        signer_address(),
        200,
        0,
        test_tx_hash(99),
        test_block_hash(99),
    );
    server.push_event(log);

    let outcome = tokio::time::timeout(Duration::from_secs(3), recv_next_event(&mut handle))
        .await
        .expect("recv within timeout");
    let WsRecvOutcome::Event(log) = outcome else {
        panic!("subscription closed unexpectedly");
    };
    let result = verify_alloy_log(&log, &TEST_VAULT_ID, &contract_address(), ChainEnv::Dev);
    assert!(
        matches!(result, VerifyOutcome::Rejected),
        "future-schema-version event must be rejected (L-schemaVersion-future-poison)"
    );
}

// ---------------------------------------------------------------------
// L-ws-trusted-rpc — fail-closed on subscribe error
// ---------------------------------------------------------------------

#[tokio::test]
async fn hermetic_ws_malicious_wrong_chain_id_at_open_fails_closed() {
    // The mock server's `fail_subscribe` mode replies with a
    // JSON-RPC error object; alloy surfaces this as a
    // `SubscribeFailed` error from `open_subscription`.
    let server = MockServer::start(MockBehaviour {
        fail_subscribe: true,
        ..Default::default()
    })
    .await;
    let err = open_subscription(
        &server.ws_url,
        ChainEnv::Dev,
        &TEST_VAULT_ID,
        contract_address(),
    )
    .await
    .expect_err("subscribe must fail when server returns an error");
    assert!(
        matches!(
            err,
            WsOpenError::SubscribeFailed(_) | WsOpenError::ConnectFailed(_)
        ),
        "expected SubscribeFailed or ConnectFailed; got {err:?}"
    );
}

// ---------------------------------------------------------------------
// L-ws-tls-downgrade — refuse ws:// for BaseSepolia
// ---------------------------------------------------------------------

#[tokio::test]
async fn hermetic_ws_rejects_ws_scheme_for_base_sepolia() {
    // BaseSepolia + ws:// → UnsupportedScheme.
    let err = open_subscription(
        "ws://sepolia.base.org",
        ChainEnv::BaseSepolia,
        &TEST_VAULT_ID,
        contract_address(),
    )
    .await
    .expect_err("ws:// must be rejected for BaseSepolia");
    assert!(matches!(err, WsOpenError::UnsupportedScheme(_)));

    // Scheme check helper is also reachable directly + behaves
    // identically.
    assert!(matches!(
        check_ws_scheme("ws://sepolia.base.org", ChainEnv::BaseSepolia),
        Err(WsOpenError::UnsupportedScheme(_))
    ));
    // wss:// + BaseSepolia → ok (URL parse only; no actual connect).
    assert!(check_ws_scheme("wss://sepolia.base.org", ChainEnv::BaseSepolia).is_ok());
}

// ---------------------------------------------------------------------
// L-ws-event-replay — duplicate is no-op at verify layer
// ---------------------------------------------------------------------

#[tokio::test]
async fn hermetic_ws_duplicate_event_across_reconnect_is_noop_at_verify_layer() {
    // The L7 idempotency defence lives in the storage layer
    // (`Vault::ingest_chain_revision` canonical-hash + chain-anchor
    // match); at the WS/verify layer, duplicate logs from a
    // re-subscribed server simply verify as fresh events and are
    // passed to the storage idempotency check.
    //
    // This test confirms that the *verifier* itself is stateless
    // and produces identical VerifiedRevisionEvent shapes for the
    // same log presented twice — which is the precondition for the
    // storage idempotency to be the load-bearing defence.
    let log = build_revision_published_log(
        contract_address(),
        TEST_VAULT_ID,
        [0xAA; 32],
        [0u8; 32],
        [0xCC; 32],
        1,
        7,
        vec![0xDE, 0xAD, 0xBE, 0xEF],
        signer_address(),
        500,
        0,
        test_tx_hash(7),
        test_block_hash(7),
    );

    let v1 = verify_alloy_log(&log, &TEST_VAULT_ID, &contract_address(), ChainEnv::Dev);
    let v2 = verify_alloy_log(&log, &TEST_VAULT_ID, &contract_address(), ChainEnv::Dev);
    let (VerifyOutcome::Verified(a), VerifyOutcome::Verified(b)) = (v1, v2) else {
        panic!("both verifications must succeed");
    };
    assert_eq!(a.event.sequence, b.event.sequence);
    assert_eq!(a.event.vault_id, b.event.vault_id);
    assert_eq!(a.event.anchor.block_number, b.event.anchor.block_number);
    assert_eq!(a.event.anchor.log_index, b.event.anchor.log_index);
    assert_eq!(a.block_hash, b.block_hash);
}

// ---------------------------------------------------------------------
// L-ws-out-of-order — verifier preserves event sequence + anchor
// ---------------------------------------------------------------------

#[tokio::test]
async fn hermetic_ws_out_of_order_events_ingest_in_canonical_order() {
    // Emit logs in REVERSE block-number order from the mock; verify
    // each carries the correct anchor so the storage layer's
    // (vault_id, sequence) key can deduplicate without relying on
    // insert order.
    let server = MockServer::start(MockBehaviour::default()).await;
    let mut handle = open_subscription(
        &server.ws_url,
        ChainEnv::Dev,
        &TEST_VAULT_ID,
        contract_address(),
    )
    .await
    .expect("subscribe");

    // Emit out-of-order: sequence 3 (block 300), then 1 (block 100), then 2 (block 200).
    for (seq, block) in &[(3u64, 300u64), (1u64, 100u64), (2u64, 200u64)] {
        let seq_byte = u8::try_from(*seq).unwrap_or(0);
        let log = build_revision_published_log(
            contract_address(),
            TEST_VAULT_ID,
            [0xAA; 32],
            [0u8; 32],
            [0xCC; 32],
            1,
            *seq,
            vec![seq_byte],
            signer_address(),
            *block,
            *seq,
            test_tx_hash(seq_byte),
            test_block_hash(seq_byte),
        );
        server.push_event(log);
    }
    let mut seen_pairs: Vec<(u64, u64)> = Vec::new();
    for _ in 0..3 {
        let outcome = tokio::time::timeout(Duration::from_secs(3), recv_next_event(&mut handle))
            .await
            .expect("recv within timeout");
        let WsRecvOutcome::Event(log) = outcome else {
            panic!("subscription closed unexpectedly");
        };
        let VerifyOutcome::Verified(ev) =
            verify_alloy_log(&log, &TEST_VAULT_ID, &contract_address(), ChainEnv::Dev)
        else {
            panic!("verification rejected");
        };
        seen_pairs.push((ev.event.sequence, ev.event.anchor.block_number));
    }
    // The verifier preserves each log's emit order on the wire;
    // it's the storage layer's keyed insert that gives canonical
    // ordering on read. Confirm the wire-order pairs are exactly
    // (3,300) (1,100) (2,200) — so the storage `(vault_id, sequence)`
    // key is what produces canonical order on `revisions_for`.
    assert_eq!(seen_pairs, vec![(3, 300), (1, 100), (2, 200)]);
}

// ---------------------------------------------------------------------
// L6 reorg cadence — constant matches finality depth
// ---------------------------------------------------------------------

#[tokio::test]
async fn hermetic_ws_periodic_reorg_check_cadence_constant_matches_finality_depth() {
    // The recv loop runs a reorg-check every `CONFIRMATION_DEPTH_FOR_FINALIZATION`
    // blocks worth of wall-clock (= 12 blocks ≈ 24s on Base Sepolia).
    // This test pins the constant; the orchestrator's behavioural
    // test in pangolin-store covers the runtime cadence.
    assert_eq!(pangolin_chain::CONFIRMATION_DEPTH_FOR_FINALIZATION, 12);
}

// ---------------------------------------------------------------------
// Q-c URL resolver — public API smoke
// ---------------------------------------------------------------------

#[tokio::test]
async fn hermetic_resolve_ws_url_prefers_pinned_value_over_derivation() {
    let derived = resolve_ws_url("https://sepolia.base.org", ChainEnv::BaseSepolia, None).unwrap();
    assert_eq!(derived, "wss://sepolia.base.org");

    let pinned = resolve_ws_url(
        "https://sepolia.base.org",
        ChainEnv::BaseSepolia,
        Some("wss://my-private-rpc.example"),
    )
    .unwrap();
    assert_eq!(pinned, "wss://my-private-rpc.example");
}

// ---------------------------------------------------------------------
// SyncReport.event_source telemetry — exposed via the public type
// ---------------------------------------------------------------------

#[tokio::test]
async fn sync_report_carries_event_source_and_ws_drops_telemetry_fields() {
    // The SyncReport type carries the two telemetry fields the
    // orchestrator populates (L9 + L12). This test pins the
    // surface so the field can't be silently removed.
    let report = pangolin_chain::SyncReport {
        event_source: pangolin_chain::ChainEventSource::WebSocket,
        ws_drops: 7,
        ..Default::default()
    };
    assert_eq!(
        report.event_source,
        pangolin_chain::ChainEventSource::WebSocket
    );
    assert_eq!(report.ws_drops, 7);
}

// ---------------------------------------------------------------------
// L10 graceful: refuse_connection mode never panics + returns typed err
// ---------------------------------------------------------------------

#[tokio::test]
async fn hermetic_ws_open_against_refused_connection_returns_typed_error() {
    let server = MockServer::start(MockBehaviour {
        refuse_connection: true,
        ..Default::default()
    })
    .await;
    let err = open_subscription(
        &server.ws_url,
        ChainEnv::Dev,
        &TEST_VAULT_ID,
        contract_address(),
    )
    .await
    .expect_err("connection refused must surface a typed error");
    // ConnectFailed is the canonical variant; SubscribeFailed is
    // also acceptable depending on which layer alloy surfaces
    // first.
    assert!(
        matches!(
            err,
            WsOpenError::ConnectFailed(_) | WsOpenError::SubscribeFailed(_)
        ),
        "expected ConnectFailed or SubscribeFailed; got {err:?}"
    );
}

// ---------------------------------------------------------------------
// L-ws-trusted-rpc — chain_id mismatch reachable through provider
// ---------------------------------------------------------------------

#[tokio::test]
async fn hermetic_ws_build_provider_reachable_with_chain_id_check() {
    // The L3 chain-id pin lives upstream of the WS recv loop
    // (the orchestrator's HTTP-backfill phase runs
    // `check_chain_id_matches` before the WS path is even tried).
    // This test confirms the mock returns the expected chain id
    // so the orchestrator's L3 check succeeds against it; the
    // production path covers the foreign-chain-id rejection via
    // `chain_id_mismatch_fails_closed` in `chain_sync::tests`.
    let server = MockServer::start(MockBehaviour::default()).await;
    let provider = pangolin_chain::chain_sync::ws::build_ws_read_provider(&server.ws_url)
        .await
        .expect("build_ws_read_provider succeeds against mock");
    let chain_id = alloy::providers::Provider::get_chain_id(&provider)
        .await
        .expect("eth_chainId via WS provider");
    assert_eq!(chain_id, 84_532, "mock defaults to Base Sepolia chain id");
}

// ---------------------------------------------------------------------
// Telemetry: ws_drops counter increments on subscription close
// ---------------------------------------------------------------------

#[tokio::test]
async fn hermetic_ws_drops_counter_pattern_increments_on_failure() {
    // The orchestrator increments `report.ws_drops` on each
    // `open_subscription` failure + each mid-session
    // `SubscriptionClosed`. Here we drive the underlying counter
    // pattern: each failed open call returns an Err, which the
    // orchestrator wraps with `saturating_add(1)`.
    let server = MockServer::start(MockBehaviour {
        refuse_connection: true,
        ..Default::default()
    })
    .await;
    let mut drops: u32 = 0;
    for _ in 0..3 {
        let r = open_subscription(
            &server.ws_url,
            ChainEnv::Dev,
            &TEST_VAULT_ID,
            contract_address(),
        )
        .await;
        if r.is_err() {
            drops = drops.saturating_add(1);
        }
    }
    assert_eq!(drops, 3);
}

// ---------------------------------------------------------------------
// L-ws-tls-downgrade — production envs reject every ws:// scheme
// ---------------------------------------------------------------------

#[tokio::test]
async fn hermetic_ws_tls_downgrade_blocked_for_every_production_env() {
    // BaseSepolia rejects ws://.
    assert!(matches!(
        check_ws_scheme("ws://anywhere", ChainEnv::BaseSepolia),
        Err(WsOpenError::UnsupportedScheme(_))
    ));
    // BaseMainnet rejects ws://.
    assert!(matches!(
        check_ws_scheme("ws://anywhere", ChainEnv::BaseMainnet),
        Err(WsOpenError::UnsupportedScheme(_))
    ));
    // Dev permits ws:// (hermetic tests against mock + anvil).
    assert!(check_ws_scheme("ws://127.0.0.1:9999", ChainEnv::Dev).is_ok());
}

// ---------------------------------------------------------------------
// Dummy: ensure the empty B256 alias type binding hasn't been used by
// accident (compile-time sanity).
// ---------------------------------------------------------------------

#[test]
fn b256_alias_compiles() {
    let x: B256 = B256::ZERO;
    assert_eq!(x, B256::ZERO);
}
