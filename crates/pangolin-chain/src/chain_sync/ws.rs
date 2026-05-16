// SPDX-License-Identifier: AGPL-3.0-or-later
//! WebSocket-preferred branch of the R-b WS+HTTP-fallback state machine.
//!
//! **NOTE on L8 deferral.** alloy's WS provider lives behind the
//! `ws` feature on the `alloy` umbrella crate; enabling it pulls
//! `alloy-pubsub`, `tokio-tungstenite`, `tungstenite`, and an OS-level
//! tls stack. The MVP-2 workspace `Cargo.toml` does NOT enable that
//! feature (per L8 — no new external crate dep in 4.1). The structural
//! state-machine for R-b is fully present (the
//! [`super::ChainEventSource`] enum, the `open_subscription` entry,
//! the reconnect-with-backoff helper, the adapter that converts WS
//! payloads into the same shape HTTP polling produces); the actual
//! WS-open returns [`WsOpenError::Unavailable`] immediately so the
//! orchestrator falls back to HTTP polling.
//!
//! The MVP-3 issue 4.1.x feature-flag flip is: (a) add
//! `features = ["ws", ...]` to the `alloy` dep; (b) replace the
//! `Unavailable` branch in [`open_subscription`] with a real
//! `ProviderBuilder::new().on_ws(...)` call. Every other consumer (the
//! orchestrator, the reorg detector, the verifier) is shape-stable
//! across both branches.

use crate::error::ChainError;

/// Reasons a WS subscription open call may fail. The orchestrator's
/// fallback branch treats every variant as "fall back to HTTP polling".
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum WsOpenError {
    /// alloy WS support is not built into this binary (L8 — no new
    /// external crate dep in 4.1; see module docstring).
    Unavailable,
    /// The RPC URL did not parse as `ws://` or `wss://`. The caller
    /// should fall back to HTTP polling rather than try to coerce.
    UnsupportedScheme(String),
    /// alloy / the RPC server reported a connection-time error.
    /// Carries the upstream description (non-secret).
    ConnectFailed(String),
}

impl From<WsOpenError> for ChainError {
    fn from(err: WsOpenError) -> Self {
        match err {
            WsOpenError::Unavailable => {
                Self::Rpc("WebSocket support not enabled in this build".to_string())
            }
            WsOpenError::UnsupportedScheme(s) => {
                Self::Rpc(format!("WebSocket scheme unsupported: {s}"))
            }
            WsOpenError::ConnectFailed(s) => Self::Rpc(format!("WebSocket connect failed: {s}")),
        }
    }
}

/// Opaque handle for an open WS subscription. The orchestrator passes
/// it to a recv loop; on drop the subscription is closed. Today the
/// variant is unit-shaped (placeholder) since the WS path is deferred;
/// once alloy WS is enabled the struct grows the alloy subscription
/// receiver.
#[derive(Debug, Default)]
pub struct WsHandle {
    // Placeholder unit field; future feature-flag flip replaces this
    // with the alloy subscription receiver.
    _placeholder: (),
}

/// Try to open a WS log-subscription filtered by `contract_address` +
/// `RevisionPublished` topic0 + `vault_id` topic1. Returns
/// [`WsOpenError::Unavailable`] in MVP-2 (L8 deferral).
///
/// # Errors
///
/// Always [`WsOpenError::Unavailable`] in MVP-2. Future feature-flag
/// flip replaces with alloy connect errors.
#[allow(clippy::missing_const_for_fn)] // future impl will be async non-const
pub fn open_subscription(_rpc_url: &str) -> Result<WsHandle, WsOpenError> {
    Err(WsOpenError::Unavailable)
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
    use super::{next_reconnect_backoff_ms, open_subscription, WsOpenError};

    #[test]
    fn ws_open_returns_unavailable_in_mvp2() {
        let err = open_subscription("wss://example.invalid").unwrap_err();
        assert!(matches!(err, WsOpenError::Unavailable));
    }

    #[test]
    fn next_reconnect_backoff_doubles() {
        assert_eq!(next_reconnect_backoff_ms(0), 250);
        assert_eq!(next_reconnect_backoff_ms(250), 500);
        assert_eq!(next_reconnect_backoff_ms(500), 1_000);
        assert_eq!(next_reconnect_backoff_ms(15_000), 30_000);
        // Caps at the max ceiling.
        assert_eq!(next_reconnect_backoff_ms(40_000), 30_000);
    }
}
