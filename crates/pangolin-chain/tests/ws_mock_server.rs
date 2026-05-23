// SPDX-License-Identifier: AGPL-3.0-or-later
//! Issue #99 Q-d Option K — hermetic WS mock server harness.
//!
//! Local `tokio-tungstenite` WebSocket server that speaks the
//! `eth_subscribe("logs", filter)` JSON-RPC dialect well enough for
//! alloy's WS provider to open a subscription against it. Used by
//! `tests/hermetic_ws.rs` to drive the WS recv-loop, circuit breaker,
//! and L-section adversarial tests without touching the live RPC.
//!
//! ## What the mock does
//!
//! - Accepts a single WS connection per session.
//! - Replies to `eth_subscribe` with a stable subscription id.
//! - Emits `eth_subscription` notifications carrying canned `Log`
//!   payloads on demand (driven by the test's `tx` channel).
//! - Supports adversarial modes: silent disconnect (drop TCP without
//!   close frame), refuse connection (close immediately during
//!   handshake), force a server-side error reply.
//!
//! ## What the mock does NOT do
//!
//! - Subscription filter matching by DEFAULT. The mock pushes the
//!   exact log payload the test queues, regardless of the
//!   subscribe filter; matching is the production path's
//!   responsibility via `verify_alloy_log`. **Issue #107 added an
//!   opt-in `MockBehaviour::respect_filter` flag** that captures
//!   the `eth_subscribe("logs", filter)` filter argument at
//!   subscribe time + applies `Filter::matches` + `matches_log_block`
//!   to each outgoing log; only matching logs reach the
//!   subscriber. The flag defaults `false` so existing tests keep
//!   their current behaviour.
//! - Full Ethereum RPC surface. Only `eth_subscribe`, `eth_chainId`,
//!   `eth_blockNumber`, and `eth_getBlockByNumber` are answered with
//!   canned values so the orchestrator's L3 chain-id pin + reorg
//!   check pass.
//! - Multi-connection state. Each test spawns a fresh server.

#![forbid(unsafe_code)]
#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions,
    dead_code
)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use alloy::primitives::{Address, Bloom, Bytes, B256, U256};
use alloy::rpc::types::Log as RpcLog;
use alloy::sol_types::SolEvent;
use pangolin_chain::chain_submit::revision_log_v1_binding::RevisionLogV1;
use serde_json::{json, Value};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{accept_async, WebSocketStream};

use futures_util::{SinkExt, StreamExt};

/// Configurable behaviours of the mock server. Default = "behave like
/// a real RPC".
///
/// `clippy::struct_excessive_bools` is allowed here because each
/// boolean encodes an INDEPENDENT adversarial mode the tests opt
/// into; a state machine / two-variant enum split would couple modes
/// that are intentionally orthogonal.
#[derive(Debug, Clone, Default)]
#[allow(clippy::struct_excessive_bools)]
pub struct MockBehaviour {
    /// If `true`, refuse the WS upgrade by closing the TCP socket
    /// immediately. Drives `WsOpenError::ConnectFailed` on the
    /// client side.
    pub refuse_connection: bool,
    /// If `true`, the server replies to `eth_subscribe` with a
    /// JSON-RPC error object instead of a subscription id. Drives
    /// `WsOpenError::SubscribeFailed`.
    pub fail_subscribe: bool,
    /// If `true`, the server silently drops the TCP socket
    /// (RST-without-close-frame style) after the first event is
    /// emitted. Drives L-ws-silent-disconnect.
    pub silent_disconnect_after_first_event: bool,
    /// Chain id to return for `eth_chainId`. Defaults to Base Sepolia
    /// (84_532). Tests that exercise the L3 mismatch path set this
    /// to a foreign value.
    pub chain_id: u64,
    /// If `true`, the server replies to `eth_subscribe` with a valid
    /// subscription id (open succeeds) and then immediately closes
    /// the WS connection without emitting any event.
    ///
    /// **Scope honesty (F-4 + F-5 re-audit empirical finding).** This
    /// mode was originally introduced for an orchestrator-level
    /// breaker-bookkeeping regression test, but the F-4 re-audit
    /// established empirically that alloy 2.0.4's `alloy-pubsub`
    /// layer transparently reconnects on accept-then-drop and does
    /// NOT surface `WsRecvOutcome::SubscriptionClosed` to the
    /// orchestrator's `recv_next_event`. The mode therefore pins
    /// the close-without-emitting-events SHAPE of the mock + alloy
    /// pipeline, NOT orchestrator-level breaker accumulation. See
    /// `L-ws-alloy-pubsub-masks-fast-drops` in `THREAT_MODEL.md`
    /// for the full limitation enumeration + the deferred
    /// direct-WS-transport architectural follow-up. Used by
    /// `hermetic_ws_accept_then_drop_subscribe_mock_mode_shape_pin`
    /// in `tests/hermetic_ws.rs` (renamed from the prior
    /// orchestrator-claiming name during the F-4 fix-pass).
    pub accept_then_drop_subscribe: bool,
    /// Issue #107 — when `true`, the server parses the
    /// `eth_subscribe("logs", filter)` filter argument (via
    /// `serde_json` into an `alloy::rpc::types::Filter`) and
    /// applies `Filter::matches` to each outgoing log; only logs
    /// matching the captured filter are emitted to the subscriber.
    /// When `false` (the default), the server emits every pushed
    /// log unfiltered — preserving the original mock semantics for
    /// existing tests that hand-craft per-event payloads.
    ///
    /// Used by `hermetic_ws_subscription_filters_by_topic2_not_topic1`
    /// to catch the V1 `.topic1(vault_id)` → `.topic2(vault_id)`
    /// bug at unit-test time. Mirrors the HTTP-path
    /// `FilteringAsserter` in
    /// `crates/pangolin-chain/src/chain_sync/filtering_asserter.rs`.
    pub respect_filter: bool,
}

/// Handle to a running mock server. Drop closes the server.
#[derive(Debug)]
pub struct MockServer {
    pub addr: SocketAddr,
    pub ws_url: String,
    /// Channel for pushing events to be sent to the connected client.
    pub event_tx: mpsc::UnboundedSender<RpcLog>,
    /// Counter incremented every time the server accepts a new WS
    /// connection. Useful for asserting reconnect attempts.
    pub connection_count: Arc<Mutex<u32>>,
    /// One-shot to abort the listener loop on drop.
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl Drop for MockServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

impl MockServer {
    /// Start a mock WS server on an ephemeral port. Returns
    /// immediately after binding.
    pub async fn start(behaviour: MockBehaviour) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral port");
        let addr = listener.local_addr().expect("local_addr");
        let ws_url = format!("ws://{addr}");
        let (event_tx, event_rx) = mpsc::unbounded_channel::<RpcLog>();
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let connection_count = Arc::new(Mutex::new(0u32));
        let cc_clone = Arc::clone(&connection_count);
        let event_rx = Arc::new(Mutex::new(event_rx));
        let behaviour_clone = behaviour.clone();
        tokio::spawn(async move {
            run_listener(listener, shutdown_rx, behaviour_clone, event_rx, cc_clone).await;
        });
        Self {
            addr,
            ws_url,
            event_tx,
            connection_count,
            shutdown_tx: Some(shutdown_tx),
        }
    }

    /// Convenience: push a canned `RevisionPublished` log.
    pub fn push_event(&self, log: RpcLog) {
        let _ = self.event_tx.send(log);
    }
}

async fn run_listener(
    listener: TcpListener,
    mut shutdown_rx: oneshot::Receiver<()>,
    behaviour: MockBehaviour,
    event_rx: Arc<Mutex<mpsc::UnboundedReceiver<RpcLog>>>,
    connection_count: Arc<Mutex<u32>>,
) {
    loop {
        tokio::select! {
            _ = &mut shutdown_rx => break,
            accept = listener.accept() => {
                let Ok((stream, _peer)) = accept else { continue };
                let behaviour = behaviour.clone();
                let event_rx = Arc::clone(&event_rx);
                let connection_count = Arc::clone(&connection_count);
                tokio::spawn(async move {
                    if behaviour.refuse_connection {
                        // Drop the TCP socket without WS handshake.
                        drop(stream);
                        return;
                    }
                    let mut count_guard = connection_count.lock().await;
                    *count_guard = count_guard.saturating_add(1);
                    drop(count_guard);
                    if let Ok(ws) = accept_async(stream).await {
                        handle_connection(ws, behaviour, event_rx).await;
                    }
                });
            }
        }
    }
}

#[allow(clippy::too_many_lines)]
async fn handle_connection(
    mut ws: WebSocketStream<TcpStream>,
    behaviour: MockBehaviour,
    event_rx: Arc<Mutex<mpsc::UnboundedReceiver<RpcLog>>>,
) {
    // Subscription id we'll reply with on eth_subscribe (and stamp
    // into outgoing eth_subscription notifications). Short hex
    // string (deserializes as `SubId::Number(U256)`) so alloy's
    // pubsub matcher accepts the notification.
    let sub_id_str = "0x1".to_string();
    let mut subscribed = false;
    // Issue #107: when `respect_filter` is set, capture the
    // `eth_subscribe("logs", filter)` filter at subscribe time +
    // apply it to outgoing logs via `Filter::matches` +
    // `matches_log_block`. `None` = unfiltered (legacy mock
    // behaviour).
    let mut active_filter: Option<alloy::rpc::types::Filter> = None;
    // Buffer for events that arrived BEFORE the client subscribed.
    // The mock supports the test ordering "push events first, then
    // subscribe" by holding the events here until subscribe lands.
    let mut pending: Vec<RpcLog> = Vec::new();

    let chain_id = if behaviour.chain_id == 0 {
        84_532
    } else {
        behaviour.chain_id
    };

    loop {
        // If subscribed and we have pending events buffered from
        // pre-subscribe pushes, flush them now (in order).
        if subscribed && !pending.is_empty() {
            let log = pending.remove(0);
            // #107 filter gate: if respect_filter is on, only emit
            // logs that match the captured subscribe filter.
            let emit = active_filter
                .as_ref()
                .is_none_or(|f| f.matches(&log.inner) && f.matches_log_block(&log));
            if emit {
                let log_value = serialize_log(&log, &sub_id_str);
                let _ = ws.send(Message::Text(log_value.to_string().into())).await;
                if behaviour.silent_disconnect_after_first_event {
                    break;
                }
            }
            continue;
        }

        tokio::select! {
            msg = ws.next() => {
                let Some(Ok(msg)) = msg else { break };
                let Message::Text(text) = msg else { continue };
                let Ok(req) = serde_json::from_str::<Value>(&text) else { continue };
                let method = req["method"].as_str().unwrap_or("");
                let id = req["id"].clone();
                match method {
                    "eth_subscribe" => {
                        if behaviour.fail_subscribe {
                            let err = json!({
                                "jsonrpc": "2.0",
                                "id": id,
                                "error": {
                                    "code": -32000,
                                    "message": "mock: fail_subscribe",
                                },
                            });
                            let _ = ws.send(Message::Text(err.to_string().into())).await;
                            let _ = ws.flush().await;
                            continue;
                        }
                        // Issue #107: capture the subscribe filter when
                        // `respect_filter` is on. Params shape from
                        // alloy is `[<SubscriptionKind>, <Params>]`
                        // where SubscriptionKind == "logs" and Params
                        // is the `Filter` JSON object. Index [1] is
                        // the Filter; deserialize via serde.
                        if behaviour.respect_filter {
                            if let Some(params) = req.get("params").and_then(Value::as_array) {
                                if params.len() >= 2 {
                                    if let Ok(f) = serde_json::from_value::<
                                        alloy::rpc::types::Filter,
                                    >(params[1].clone())
                                    {
                                        active_filter = Some(f);
                                    }
                                }
                            }
                        }
                        let resp = json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": sub_id_str,
                        });
                        let resp_str = resp.to_string();
                        let _ = ws.send(Message::Text(resp_str.into())).await;
                        let _ = ws.flush().await;
                        // Issue #99 F-2 fix-pass. The
                        // `accept_then_drop_subscribe` mode
                        // returns a valid subscription id then
                        // immediately closes the WS connection
                        // WITHOUT emitting any event. Drives
                        // the accept-then-drop storm that the
                        // circuit-breaker recv-loop-exit gate is
                        // designed to catch.
                        if behaviour.accept_then_drop_subscribe {
                            let _ = ws.close(None).await;
                            return;
                        }
                        // Set subscribed AFTER the response is
                        // flushed so any pending events that
                        // arrived pre-subscribe land on the wire
                        // strictly after the subscribe response.
                        subscribed = true;
                    }
                    "eth_chainId" => {
                        let resp = json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": format!("0x{chain_id:x}"),
                        });
                        let _ = ws.send(Message::Text(resp.to_string().into())).await;
                    }
                    "eth_blockNumber" => {
                        let resp = json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": "0x2796f30",
                        });
                        let _ = ws.send(Message::Text(resp.to_string().into())).await;
                    }
                    _ => {
                        // Ignore unknown methods; alloy may probe
                        // a few we don't care about.
                    }
                }
            }
            log = pull_next_log(&event_rx) => {
                let Some(log) = log else { break };
                if !subscribed {
                    pending.push(log);
                    continue;
                }
                // #107 filter gate: if respect_filter is on, only emit
                // logs that match the captured subscribe filter.
                let emit = active_filter
                    .as_ref()
                    .is_none_or(|f| f.matches(&log.inner) && f.matches_log_block(&log));
                if !emit {
                    continue;
                }
                let log_value = serialize_log(&log, &sub_id_str);
                let _ = ws.send(Message::Text(log_value.to_string().into())).await;
                if behaviour.silent_disconnect_after_first_event {
                    // Drop the connection mid-stream without sending
                    // a close frame (RST-style).
                    break;
                }
            }
        }
    }
}

async fn pull_next_log(rx: &Arc<Mutex<mpsc::UnboundedReceiver<RpcLog>>>) -> Option<RpcLog> {
    let mut guard = rx.lock().await;
    guard.recv().await
}

/// Serialize an `RpcLog` as an `eth_subscription` notification.
fn serialize_log(log: &RpcLog, sub_id_str: &str) -> Value {
    // alloy's `RpcLog` deserialises from the standard `eth_getLogs` /
    // `eth_subscription` payload shape; round-trip via serde_json.
    let log_json = serde_json::to_value(log).expect("serialize log");
    json!({
        "jsonrpc": "2.0",
        "method": "eth_subscription",
        "params": {
            "subscription": sub_id_str,
            "result": log_json,
        },
    })
}

// ---------------------------------------------------------------------
// Canned-log builder for tests
// ---------------------------------------------------------------------

/// Build a synthetic `RevisionPublished` `RpcLog`. The bytes here are
/// the exact wire shape alloy expects to see; the test's verification
/// pipeline (`verify_alloy_log`) decodes them.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn build_revision_published_log(
    contract_address: Address,
    vault_id: [u8; 32],
    account_id: [u8; 32],
    parent_revision: [u8; 32],
    device_id: [u8; 32],
    schema_version: u16,
    sequence: u64,
    enc_payload: Vec<u8>,
    signer: Address,
    block_number: u64,
    log_index: u64,
    tx_hash: B256,
    block_hash: B256,
) -> RpcLog {
    // Build the event via alloy's typed binding so the encoded form
    // matches what the verifier expects bit-for-bit.
    let event = RevisionLogV1::RevisionPublished {
        sequence: U256::from(sequence),
        vaultId: vault_id.into(),
        accountId: account_id.into(),
        parentRevision: parent_revision.into(),
        deviceId: device_id.into(),
        schemaVersion: schema_version,
        encPayload: Bytes::from(enc_payload),
        signer,
    };
    let encoded = event.encode_log_data();
    let inner = alloy::primitives::Log::<alloy::primitives::LogData> {
        address: contract_address,
        data: encoded,
    };
    RpcLog {
        inner,
        block_hash: Some(block_hash),
        block_number: Some(block_number),
        block_timestamp: Some(1_700_000_000),
        transaction_hash: Some(tx_hash),
        transaction_index: Some(0),
        log_index: Some(log_index),
        removed: false,
    }
}

/// Sentinel test_block_hash and tx_hash generators so tests can
/// produce different anchors without colliding on hash space.
#[must_use]
pub fn test_block_hash(seed: u8) -> B256 {
    let mut bytes = [0u8; 32];
    bytes[0] = 0xBB;
    bytes[31] = seed;
    B256::from(bytes)
}

#[must_use]
pub fn test_tx_hash(seed: u8) -> B256 {
    let mut bytes = [0u8; 32];
    bytes[0] = 0xCC;
    bytes[31] = seed;
    B256::from(bytes)
}

#[must_use]
pub fn test_bloom() -> Bloom {
    Bloom::default()
}

// ---------------------------------------------------------------------
// Self-test: spin up the mock + run a no-op handshake so this file
// works as a standalone integration-test binary (Cargo runs it via
// `cargo test --test ws_mock_server`).
// ---------------------------------------------------------------------

#[tokio::test]
async fn mock_server_starts_and_shuts_down_cleanly() {
    let server = MockServer::start(MockBehaviour::default()).await;
    assert!(server.ws_url.starts_with("ws://127.0.0.1:"));
    // Wait briefly so the listener task actually runs.
    tokio::time::sleep(Duration::from_millis(50)).await;
    // Drop closes via shutdown_tx.
}

#[tokio::test]
async fn build_revision_published_log_is_decodable() {
    let contract = Address::from([0x01u8; 20]);
    let vault: [u8; 32] = [0x42; 32];
    let signer = Address::from([0x77u8; 20]);
    let log = build_revision_published_log(
        contract,
        vault,
        [0xAAu8; 32],
        [0u8; 32],
        [0xCCu8; 32],
        1,
        7,
        vec![0xDE, 0xAD, 0xBE, 0xEF],
        signer,
        100,
        0,
        test_tx_hash(1),
        test_block_hash(1),
    );
    // Round-trip via the typed binding.
    let decoded =
        RevisionLogV1::RevisionPublished::decode_log(&log.inner).expect("decode synthetic log");
    let decoded_vault: [u8; 32] = decoded.vaultId.into();
    assert_eq!(decoded_vault, vault);
    assert_eq!(decoded.sequence, U256::from(7u64));
    assert_eq!(decoded.signer, signer);
    assert_eq!(decoded.encPayload.to_vec(), vec![0xDE, 0xAD, 0xBE, 0xEF]);
}
