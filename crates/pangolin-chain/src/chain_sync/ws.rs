// SPDX-License-Identifier: AGPL-3.0-or-later
//! WebSocket-preferred branch of the R-b WS+HTTP-fallback state machine.
//!
//! **Issue #99 (2026-05-18):** the L8 deferral note that earlier shipped
//! here is closed. The workspace `Cargo.toml` now selects alloy's
//! `provider-ws` + `pubsub` features (which transitively bring
//! `tokio-tungstenite` + `tungstenite` + `alloy-pubsub` + `rustls` with
//! `aws-lc-rs` per L5 — `ring` remains BANNED via `deny.toml`), so
//! [`open_subscription`] now opens a real `eth_subscribe("logs", filter)`
//! WS subscription and the orchestrator (`Vault::sync_from_chain`)
//! enters a recv loop at tip per Q-a Option A.
//!
//! ## Topology (Q-a Option A — locked 2026-05-18)
//!
//! 1. HTTP chunk loop backfills `cursor → head` via the existing
//!    `fetch_and_verify_chunk` path. WS subscriptions cannot replay
//!    history; backfill via WS would force a polling layer on top of
//!    WS anyway. This branch is unchanged from MVP-2 4.1.
//! 2. After backfill, if `SyncOptions.prefer_websocket == true`, the
//!    orchestrator calls [`open_subscription`] and enters a WS recv
//!    loop. Every event is verified via the SAME
//!    [`crate::chain_sync::poll::verify_alloy_log`] helper (L2: WS
//!    verification is byte-identical to HTTP) and ingested via the
//!    existing `Vault::ingest_pending_chain_revision` path. The L7
//!    canonical-hash + chain-anchor idempotency defends against WS
//!    event replay across reconnect.
//! 3. On WS drop, the orchestrator backs off via
//!    [`next_reconnect_backoff_ms`] up to
//!    [`super::WS_CIRCUIT_BREAKER_THRESHOLD`] consecutive failures,
//!    then falls through to HTTP polling at
//!    [`super::HTTP_POLL_INTERVAL_SECS`] cadence for the rest of the
//!    session (Q-b Option β).
//! 4. WS open-fail or mid-session-drop NEVER fails the sync (L10).
//!    `SyncReport.event_source` is written honestly per the path
//!    actually taken at exit (L9). `SyncReport.ws_drops` counts
//!    reconnect attempts for UX telemetry.
//!
//! ## TLS-downgrade defense (L-ws-tls-downgrade)
//!
//! [`open_subscription`] rejects `ws://` URLs in production envs
//! (`BaseSepolia`, future `BaseMainnet`) with
//! [`WsOpenError::UnsupportedScheme`]. The dev env may use `ws://`
//! against anvil. The deployment-pin test
//! `deployment_json_pins_match_rust_constants` enforces that the JSON
//! `chain.ws_default` field starts with `wss://` so the source-of-truth
//! pin is also TLS.
//!
//! ## Ring-ban defense (L5 + L-ws-feature-leak-pulls-ring)
//!
//! alloy 2.0.4's `provider-ws` feature transitively selects
//! `rustls + aws-lc-rs` (not `ring`). Verified post-flip via
//! `cargo tree -i ring` returning zero rows. The
//! `scripts/check-no-ring.sh` CI gate (issue #99 §2j) catches any
//! future drift.

use std::time::Duration;

use alloy::network::Ethereum;
use alloy::primitives::{Address, B256};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::pubsub::Subscription;
use alloy::rpc::client::WsConnect;
use alloy::rpc::types::{Filter, Log as RpcLog};
use alloy::sol_types::SolEvent;

use crate::chain_submit::revision_log_v1_binding::RevisionLogV1;
use crate::deployments::ChainEnv;
use crate::error::ChainError;
use crate::types::VaultId;

/// Reasons a WS subscription open call may fail. The orchestrator's
/// fallback branch treats every variant as "fall back to HTTP polling"
/// per L10 — none of these surface to the caller as a hard error.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum WsOpenError {
    /// The RPC URL did not parse as `ws://` or `wss://`. The caller
    /// should fall back to HTTP polling rather than try to coerce.
    UnsupportedScheme(String),
    /// alloy / the RPC server reported a connection-time error.
    /// Carries the upstream description (non-secret).
    ConnectFailed(String),
    /// `eth_subscribe("logs", filter)` request failed at the RPC layer
    /// (e.g. the server rejected the subscription with an error).
    SubscribeFailed(String),
    /// L3 defence: the WS provider's `eth_chainId` did not match the
    /// build's expected chain id for `env`. The HTTP-backfill phase
    /// upstream of the WS path performs the same check on the HTTP
    /// provider; this variant catches the asymmetric-host topology
    /// where `chain.ws_default` and `chain.rpc_default` resolve to
    /// different RPC hosts (post Q-c Option III JSON-pin loader).
    /// The orchestrator's fallback branch treats this the same as
    /// any other open-fail — counts toward the circuit breaker, then
    /// degrades to HTTP polling per L10.
    ChainIdMismatch(String),
}

impl From<WsOpenError> for ChainError {
    fn from(err: WsOpenError) -> Self {
        match err {
            WsOpenError::UnsupportedScheme(s) => {
                Self::Rpc(format!("WebSocket scheme unsupported: {s}"))
            }
            WsOpenError::ConnectFailed(s) => Self::Rpc(format!("WebSocket connect failed: {s}")),
            WsOpenError::SubscribeFailed(s) => {
                Self::Rpc(format!("WebSocket subscribe failed: {s}"))
            }
            WsOpenError::ChainIdMismatch(s) => {
                Self::Rpc(format!("WebSocket chain-id mismatch: {s}"))
            }
        }
    }
}

/// Open WS handle for a `RevisionPublished` log subscription. Carries
/// the alloy `Subscription<RpcLog>` receiver (post-flip surface);
/// dropping it closes the subscription.
///
/// The orchestrator consumes events via [`recv_next_event`]; the
/// public `subscription` field is left visible so tests can drive
/// it directly.
///
/// **Provider lifetime.** The alloy `DynProvider` owns the WS
/// service task spawned by `connect_ws`; if it's dropped the
/// service shuts down + the subscription's broadcast channel
/// closes. We keep it inside the handle so the subscription stays
/// live for the recv loop's lifetime.
///
/// **L3 chain-id pin.** [`open_subscription`] runs
/// [`crate::chain_sync::check_chain_id_matches`] against the
/// freshly-built WS provider BEFORE issuing `eth_subscribe`. The
/// HTTP-backfill phase upstream of the WS branch already verified
/// chain-id on the HTTP provider, but a future Q-c Option III
/// JSON-pin loader can point `chain.ws_default` at a different host
/// than `chain.rpc_default`; the WS-provider chain-id check makes
/// that scenario fail-closed instead of silently bypassing L3.
#[derive(Debug)]
pub struct WsHandle {
    /// Keeps the alloy WS service task alive for the duration of
    /// the subscription. Holding this here is what prevents alloy
    /// from shutting down the WS backend when `open_subscription`
    /// returns. The field is not directly read at the call site —
    /// it's the Drop semantics that matter — so clippy's
    /// `#[allow(dead_code)]` is applied via the outer
    /// `#[allow]` on the struct.
    #[allow(dead_code)]
    provider: DynProvider,
    /// Live alloy `Subscription<RpcLog>`. Recv via
    /// [`recv_next_event`] which wraps the underlying broadcast
    /// receiver.
    pub subscription: Subscription<RpcLog>,
}

/// Outcome of one WS recv step. The orchestrator consumes events
/// until the recv loop signals [`WsRecvOutcome::SubscriptionClosed`]
/// (RPC server closed the channel) at which point it backs off +
/// reconnects per [`super::WS_CIRCUIT_BREAKER_THRESHOLD`] policy.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum WsRecvOutcome {
    /// One log payload received from the WS channel.
    Event(RpcLog),
    /// The RPC server closed the subscription cleanly OR the receiver
    /// detected a lagged broadcast channel. The orchestrator should
    /// reconnect per the Q-b Option β policy.
    SubscriptionClosed,
}

/// Try to open a WS log-subscription filtered by `contract_address` +
/// `RevisionPublished` topic0 + `vault_id` topic1. Issue #99 §2a.
///
/// Per L-ws-tls-downgrade: production envs (`BaseSepolia`,
/// `BaseMainnet`) refuse `ws://` URLs; only `wss://` is accepted.
/// Dev env permits `ws://` (used by hermetic tests against the local
/// mock server).
///
/// **L3 chain-id pin (issue #99 F-3 fix-pass).** After the WS provider
/// is built but BEFORE `eth_subscribe` is issued, this helper runs
/// [`crate::chain_sync::check_chain_id_matches`] on the WS provider.
/// The HTTP-backfill phase upstream already verifies chain-id on the
/// HTTP provider for the same RPC endpoint; this WS-side check
/// defends the asymmetric-host topology where `chain.ws_default`
/// resolves to a different RPC host than `chain.rpc_default` (post
/// Q-c Option III JSON-pin loader). On mismatch this returns
/// [`WsOpenError::ChainIdMismatch`]; the orchestrator's fallback
/// branch counts this toward the circuit breaker and degrades to
/// HTTP polling per L10 — the WS path is silently disabled, the
/// sync continues against the HTTP provider that already passed L3.
///
/// # Errors
///
/// - [`WsOpenError::UnsupportedScheme`] when the URL scheme is
///   neither `ws://` nor `wss://`, OR when `ws://` is used against a
///   production env.
/// - [`WsOpenError::ConnectFailed`] when alloy fails to establish the
///   TCP / TLS / WS-handshake layer.
/// - [`WsOpenError::ChainIdMismatch`] when the WS provider's
///   `eth_chainId` does not match `env.chain_id()`.
/// - [`WsOpenError::SubscribeFailed`] when the RPC server rejects the
///   `eth_subscribe("logs", filter)` request.
pub async fn open_subscription(
    ws_url: &str,
    env: ChainEnv,
    vault_id: &VaultId,
    contract_address: Address,
) -> Result<WsHandle, WsOpenError> {
    // L-ws-tls-downgrade: refuse `ws://` for production envs. The
    // URL scheme is checked BEFORE any network I/O so a downgrade
    // attempt surfaces immediately.
    check_ws_scheme(ws_url, env)?;

    // Q-a Option A: open a pubsub provider over the WS transport.
    // `WsConnect::new(url)` sets the alloy-default 10s keepalive
    // ping interval; we override it to
    // `super::WS_KEEPALIVE_INTERVAL_SECS = 30` per Q-h cadence.
    let connect = WsConnect::new(ws_url)
        .with_keepalive_interval(Duration::from_secs(super::WS_KEEPALIVE_INTERVAL_SECS));
    let provider = ProviderBuilder::new()
        .network::<Ethereum>()
        .connect_ws(connect)
        .await
        .map_err(|e| WsOpenError::ConnectFailed(format!("connect_ws {ws_url}: {e}")))?;

    // L3 chain-id pin (issue #99 F-3 fix-pass). Verify the WS
    // provider's reported chain id matches the expected env id
    // BEFORE issuing `eth_subscribe`. This closes the gap where a
    // future Q-c Option III JSON-pin loader can point
    // `chain.ws_default` at a different host than `chain.rpc_default`.
    super::check_chain_id_matches(&provider, env)
        .await
        .map_err(|e| WsOpenError::ChainIdMismatch(format!("ws-provider eth_chainId: {e}")))?;

    // L2 + L4: filter ALL events at the RPC layer by
    // `RevisionPublished` topic0 + contract address + indexed
    // vault_id topic1, so verification has less to reject.
    let topic1: B256 = (*vault_id).into();
    let filter = Filter::new()
        .address(contract_address)
        .event_signature(RevisionLogV1::RevisionPublished::SIGNATURE_HASH)
        .topic1(topic1);

    let sub = provider
        .subscribe_logs(&filter)
        .await
        .map_err(|e| WsOpenError::SubscribeFailed(format!("eth_subscribe: {e}")))?;
    Ok(WsHandle {
        provider: provider.erased(),
        subscription: sub,
    })
}

/// Q-c URL resolver. Returns the WS URL to use for this sync, in
/// priority order:
///
/// 1. `deployment_json_ws_default` — the source-of-truth pin from
///    `contracts/deployments/<env>.json` (Option III).
/// 2. Derived from `http_url` by replacing `https://` → `wss://` and
///    `http://` → `ws://` (Option I).
///
/// L-ws-tls-downgrade: the production-env scheme check fires at
/// [`open_subscription`] time so a misconfigured deployment JSON or
/// runtime HTTP URL doesn't silently land cleartext WS.
///
/// # Errors
///
/// [`WsOpenError::UnsupportedScheme`] when `http_url` has neither
/// `https://` nor `http://` prefix.
#[allow(clippy::option_if_let_else)]
pub fn resolve_ws_url(
    http_url: &str,
    _env: ChainEnv,
    deployment_json_ws_default: Option<&str>,
) -> Result<String, WsOpenError> {
    if let Some(ws_pinned) = deployment_json_ws_default {
        return Ok(ws_pinned.to_owned());
    }
    if let Some(rest) = http_url.strip_prefix("https://") {
        Ok(format!("wss://{rest}"))
    } else if let Some(rest) = http_url.strip_prefix("http://") {
        Ok(format!("ws://{rest}"))
    } else {
        Err(WsOpenError::UnsupportedScheme(format!(
            "cannot derive WS URL from {http_url}"
        )))
    }
}

/// L-ws-tls-downgrade defense. Production envs (`BaseSepolia`,
/// `BaseMainnet`) refuse `ws://`; only `wss://` accepted. The dev env
/// permits `ws://` so hermetic tests can drive a local mock server.
pub fn check_ws_scheme(ws_url: &str, env: ChainEnv) -> Result<(), WsOpenError> {
    let is_wss = ws_url.starts_with("wss://");
    let is_ws = ws_url.starts_with("ws://");
    if !is_wss && !is_ws {
        return Err(WsOpenError::UnsupportedScheme(format!(
            "URL scheme must be ws:// or wss://, got {ws_url}"
        )));
    }
    // For production envs, reject cleartext ws://.
    if matches!(env, ChainEnv::BaseSepolia | ChainEnv::BaseMainnet) && is_ws {
        return Err(WsOpenError::UnsupportedScheme(format!(
            "production env {env:?} requires wss://; got {ws_url}"
        )));
    }
    Ok(())
}

/// Receive the next event from a WS subscription, or signal that the
/// subscription is closed (server hung up, or broadcast channel
/// lagged).
///
/// The recv loop in `Vault::sync_from_chain` calls this in a tokio
/// `select!` against a periodic reorg-check timer + circuit-breaker
/// counter.
pub async fn recv_next_event(handle: &mut WsHandle) -> WsRecvOutcome {
    handle
        .subscription
        .recv()
        .await
        .map_or(WsRecvOutcome::SubscriptionClosed, WsRecvOutcome::Event)
}

/// Build a read-only alloy provider over a WS transport. Sibling to
/// `super::build_read_provider` for HTTP. Used by tests that need a
/// `DynProvider` over WS for shared helpers (e.g. reorg detection
/// runs at finality cadence on the same WS-backed provider; the
/// orchestrator calls `detect_reorg_via_rpc` which builds its own
/// HTTP provider, so this helper is currently test-facing).
///
/// # Errors
///
/// [`ChainError::Rpc`] if alloy fails to connect.
pub async fn build_ws_read_provider(
    ws_url: &str,
) -> Result<alloy::providers::DynProvider, ChainError> {
    let connect = WsConnect::new(ws_url)
        .with_keepalive_interval(Duration::from_secs(super::WS_KEEPALIVE_INTERVAL_SECS));
    let provider = ProviderBuilder::new()
        .network::<Ethereum>()
        .connect_ws(connect)
        .await
        .map_err(|e| ChainError::Rpc(format!("connect_ws {ws_url}: {e}")))?;
    Ok(provider.erased())
}

/// Compute the next backoff duration for a reconnect attempt.
///
/// Exponential from [`super::WS_RECONNECT_INITIAL_BACKOFF_MS`] up to
/// [`super::WS_RECONNECT_MAX_BACKOFF_MS`]. Doubles each attempt; caps
/// at the max.
#[must_use]
pub fn next_reconnect_backoff_ms(prev_ms: u64) -> u64 {
    let candidate = prev_ms.saturating_mul(2);
    candidate.clamp(
        super::WS_RECONNECT_INITIAL_BACKOFF_MS,
        super::WS_RECONNECT_MAX_BACKOFF_MS,
    )
}

#[cfg(test)]
mod tests {
    use super::{check_ws_scheme, next_reconnect_backoff_ms, resolve_ws_url, WsOpenError};
    use crate::deployments::ChainEnv;

    #[test]
    fn next_reconnect_backoff_doubles() {
        assert_eq!(next_reconnect_backoff_ms(0), 250);
        assert_eq!(next_reconnect_backoff_ms(250), 500);
        assert_eq!(next_reconnect_backoff_ms(500), 1_000);
        assert_eq!(next_reconnect_backoff_ms(15_000), 30_000);
        // Caps at the max ceiling.
        assert_eq!(next_reconnect_backoff_ms(40_000), 30_000);
    }

    #[test]
    fn resolve_ws_url_prefers_pinned_value() {
        let out = resolve_ws_url(
            "https://sepolia.base.org",
            ChainEnv::BaseSepolia,
            Some("wss://example-pinned.invalid"),
        )
        .unwrap();
        assert_eq!(out, "wss://example-pinned.invalid");
    }

    #[test]
    fn resolve_ws_url_derives_wss_from_https() {
        let out = resolve_ws_url("https://sepolia.base.org", ChainEnv::BaseSepolia, None).unwrap();
        assert_eq!(out, "wss://sepolia.base.org");
    }

    #[test]
    fn resolve_ws_url_derives_ws_from_http() {
        let out = resolve_ws_url("http://127.0.0.1:8545", ChainEnv::Dev, None).unwrap();
        assert_eq!(out, "ws://127.0.0.1:8545");
    }

    #[test]
    fn resolve_ws_url_rejects_unknown_scheme() {
        let err = resolve_ws_url("ftp://example.invalid", ChainEnv::BaseSepolia, None).unwrap_err();
        assert!(matches!(err, WsOpenError::UnsupportedScheme(_)));
    }

    #[test]
    fn check_ws_scheme_rejects_cleartext_for_base_sepolia() {
        let err = check_ws_scheme("ws://sepolia.base.org", ChainEnv::BaseSepolia).unwrap_err();
        assert!(matches!(err, WsOpenError::UnsupportedScheme(_)));
    }

    #[test]
    fn check_ws_scheme_accepts_wss_for_base_sepolia() {
        check_ws_scheme("wss://sepolia.base.org", ChainEnv::BaseSepolia).unwrap();
    }

    #[test]
    fn check_ws_scheme_accepts_ws_for_dev() {
        check_ws_scheme("ws://127.0.0.1:9999", ChainEnv::Dev).unwrap();
    }

    #[test]
    fn check_ws_scheme_rejects_non_ws_scheme() {
        let err = check_ws_scheme("http://anywhere", ChainEnv::Dev).unwrap_err();
        assert!(matches!(err, WsOpenError::UnsupportedScheme(_)));
    }
}
