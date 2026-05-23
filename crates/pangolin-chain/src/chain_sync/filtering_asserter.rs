// SPDX-License-Identifier: AGPL-3.0-or-later
//! Filter-respecting hermetic mock transport for the chain-sync read path.
//!
//! **Issue #107 §0a Q-a — the durable mock.** The base
//! [`alloy::transports::mock::Asserter`] returns the next queued response
//! REGARDLESS of the request's params, including any topic filter on
//! `eth_getLogs`. That made the V1 `.topic1(vault_id)` bug dormant: the
//! buggy server-side filter never got exercised because the mock didn't
//! inspect it.
//!
//! [`FilteringAsserter`] is a `tower::Service<RequestPacket>` that
//! intercepts JSON-RPC requests by method name:
//!
//! - `eth_getLogs(filter)`: parses the request's `Filter` param via
//!   `serde_json`, applies [`alloy::rpc::types::Filter::matches`] (which
//!   does the standard `(address, topic0..3)` matching with `None` as
//!   wildcard per slot) to each queued log, returns ONLY the matching
//!   subset.
//! - `eth_chainId`: returns the configured chain id.
//! - `eth_blockNumber`: returns the configured tip height.
//! - Any other method: falls through to a fallback queue (FIFO, same
//!   shape as the upstream `Asserter::push_success` — so existing tests
//!   that don't care about filter semantics can use the legacy queue
//!   without rewriting them).
//!
//! ## Why a custom transport, not a wrapper around Asserter
//!
//! Upstream `Asserter` is a FIFO queue of canned responses; it never
//! sees the request. To inspect the request we need to sit in the
//! `tower::Service<RequestPacket>` position (the transport layer
//! itself). This module implements that service from scratch using
//! only types already public in alloy 2.0.4 (`RequestPacket`,
//! `ResponsePacket`, `Response`, `ResponsePayload`, `TransportError`,
//! `TransportFut`); no new external crates.
//!
//! ## Usage
//!
//! ```ignore
//! use crate::chain_sync::filtering_asserter::FilteringAsserter;
//! use alloy::providers::ProviderBuilder;
//! use alloy::rpc::client::RpcClient;
//!
//! let mock = FilteringAsserter::new();
//! mock.push_log(log_a);
//! mock.push_log(log_b);
//! let provider = ProviderBuilder::new()
//!     .connect_client(RpcClient::new(mock.clone(), true));
//! let logs = provider.get_logs(&filter).await?; // returns only matches
//! ```

#![allow(
    dead_code,
    clippy::similar_names,
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    clippy::needless_pass_by_value,
    clippy::unused_async
)]

use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use alloy::primitives::B256;
use alloy::rpc::types::{Filter, Log as RpcLog};
use alloy_json_rpc::{
    Id, RequestPacket, Response, ResponsePacket, ResponsePayload, SerializedRequest,
};
use alloy_transport::{TransportError, TransportErrorKind, TransportFut};
use serde_json::value::RawValue;

/// Filter-respecting mock transport. Cloneable (cheap — all state is
/// behind `Arc<Mutex<_>>`); fan out via `Clone` so the provider holds
/// one handle and the test holds another.
#[derive(Clone, Debug, Default)]
pub struct FilteringAsserter {
    state: Arc<Mutex<State>>,
}

#[derive(Debug, Default)]
struct State {
    /// Logs the test has staged. Each `eth_getLogs(filter)` returns
    /// the subset matching `filter` (address + topics + block range,
    /// per `Filter::matches` + `matches_log_block`).
    logs: Vec<RpcLog>,
    /// Canned `eth_chainId` value, in hex form. `None` means "respond
    /// with the default 84_532 (Base Sepolia)".
    chain_id: Option<u64>,
    /// Canned `eth_blockNumber` value, in u64 form. `None` means "0".
    block_number: Option<u64>,
    /// Fallback FIFO queue, used for methods we don't natively handle
    /// (e.g. tests that drive `eth_getBlockByNumber` with a canned
    /// payload). Same `push_success(json)` shape as the upstream
    /// `Asserter`.
    fallback: Vec<Box<RawValue>>,
}

impl FilteringAsserter {
    /// Build a new asserter with empty queues + default chain_id 84_532.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Stage a log that subsequent `eth_getLogs(filter)` calls will
    /// see + filter-match against.
    pub fn push_log(&self, log: RpcLog) {
        self.state
            .lock()
            .expect("filtering_asserter mutex")
            .logs
            .push(log);
    }

    /// Stage multiple logs in one call.
    pub fn push_logs(&self, logs: impl IntoIterator<Item = RpcLog>) {
        let mut st = self.state.lock().expect("filtering_asserter mutex");
        st.logs.extend(logs);
    }

    /// Set the chain id returned by `eth_chainId`. Defaults to
    /// 84_532 (Base Sepolia).
    pub fn set_chain_id(&self, chain_id: u64) {
        self.state
            .lock()
            .expect("filtering_asserter mutex")
            .chain_id = Some(chain_id);
    }

    /// Set the tip block number returned by `eth_blockNumber`.
    pub fn set_block_number(&self, block_number: u64) {
        self.state
            .lock()
            .expect("filtering_asserter mutex")
            .block_number = Some(block_number);
    }

    /// Drain the `eth_getLogs` filter-applied subset for a given
    /// filter. Used internally by `call`, also exposed for direct
    /// unit-testing the filter semantics without a Provider in the
    /// loop.
    fn apply_filter(&self, filter: &Filter) -> Vec<RpcLog> {
        let st = self.state.lock().expect("filtering_asserter mutex");
        st.logs
            .iter()
            .filter(|log| {
                // `Filter::matches` checks address + topics.
                // `matches_log_block` covers the from/to block range.
                filter.matches(&log.inner) && filter.matches_log_block(log)
            })
            .cloned()
            .collect()
    }

    fn handle_request(&self, req: &SerializedRequest) -> Result<Box<RawValue>, TransportError> {
        let method = req.method();
        match method {
            "eth_getLogs" => {
                // Params shape: a single-element array containing the
                // Filter object — `(Filter,)` tuple-serialized.
                let params = req
                    .params()
                    .ok_or_else(|| TransportErrorKind::custom_str("eth_getLogs without params"))?;
                // The outer wrapper is `[<filter>]`; deserialize a
                // 1-tuple of Filter.
                let (filter,): (Filter,) = serde_json::from_str(params.get())
                    .map_err(|e| TransportError::deser_err(e, params.get()))?;
                let matched = self.apply_filter(&filter);
                let json = serde_json::to_string(&matched).map_err(TransportError::ser_err)?;
                RawValue::from_string(json).map_err(|e| {
                    TransportErrorKind::custom_str(&format!("RawValue::from_string: {e}"))
                })
            }
            "eth_chainId" => {
                let id = self
                    .state
                    .lock()
                    .expect("filtering_asserter mutex")
                    .chain_id
                    .unwrap_or(84_532);
                let s =
                    serde_json::to_string(&format!("0x{id:x}")).map_err(TransportError::ser_err)?;
                RawValue::from_string(s).map_err(|e| {
                    TransportErrorKind::custom_str(&format!("RawValue::from_string: {e}"))
                })
            }
            "eth_blockNumber" => {
                let n = self
                    .state
                    .lock()
                    .expect("filtering_asserter mutex")
                    .block_number
                    .unwrap_or(0);
                let s =
                    serde_json::to_string(&format!("0x{n:x}")).map_err(TransportError::ser_err)?;
                RawValue::from_string(s).map_err(|e| {
                    TransportErrorKind::custom_str(&format!("RawValue::from_string: {e}"))
                })
            }
            _ => {
                // Fall back to the FIFO queue for unhandled methods.
                let mut st = self.state.lock().expect("filtering_asserter mutex");
                if st.fallback.is_empty() {
                    return Err(TransportErrorKind::custom_str(&format!(
                        "FilteringAsserter: no handler + empty fallback queue for method '{method}'"
                    )));
                }
                Ok(st.fallback.remove(0))
            }
        }
    }

    fn map_request(&self, req: SerializedRequest) -> Result<Response, TransportError> {
        let id = req.id().clone();
        match self.handle_request(&req) {
            Ok(rv) => Ok(Response {
                id,
                payload: ResponsePayload::Success(rv),
            }),
            Err(e) => Err(e),
        }
    }

    async fn handle(self, req: RequestPacket) -> Result<ResponsePacket, TransportError> {
        match req {
            RequestPacket::Single(req) => Ok(ResponsePacket::Single(self.map_request(req)?)),
            RequestPacket::Batch(reqs) => {
                let mut out = Vec::with_capacity(reqs.len());
                for r in reqs {
                    out.push(self.map_request(r)?);
                }
                Ok(ResponsePacket::Batch(out))
            }
        }
    }
}

impl tower::Service<RequestPacket> for FilteringAsserter {
    type Response = ResponsePacket;
    type Error = TransportError;
    type Future = TransportFut<'static>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: RequestPacket) -> Self::Future {
        let this = self.clone();
        Box::pin(this.handle(req))
    }
}

// Convenience: silence the unused `B256` / `Id` import warnings if a
// future trim removes their usages. These are imported here so the
// module compiles regardless of small future tweaks to the response
// shape.
#[allow(dead_code)]
const _B256_PIN: B256 = B256::ZERO;
#[allow(dead_code)]
fn _id_pin() -> Id {
    Id::Number(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{Address, Bytes, U256};
    use alloy::providers::{Provider, ProviderBuilder};
    use alloy::rpc::client::RpcClient;
    use alloy::rpc::types::Log as RpcLog;
    use alloy::sol_types::SolEvent;

    use crate::chain_submit::revision_log_v1_binding::RevisionLogV1;

    fn build_v1_log(contract: Address, vault_id: [u8; 32], sequence: u64) -> RpcLog {
        use alloy::primitives::{Log as PrimLog, LogData};
        let seq_topic = B256::from(U256::from(sequence).to_be_bytes::<32>());
        let vault_topic = B256::from(vault_id);
        let account_topic = B256::from([0x33; 32]);
        let topic0 = RevisionLogV1::RevisionPublished::SIGNATURE_HASH;
        let event = RevisionLogV1::RevisionPublished {
            sequence: U256::from(sequence),
            vaultId: vault_id.into(),
            accountId: [0x33; 32].into(),
            parentRevision: [0u8; 32].into(),
            deviceId: [0xCC; 32].into(),
            schemaVersion: 1,
            encPayload: Bytes::from(vec![0xDE, 0xAD]),
            signer: Address::from([0x77; 20]),
        };
        let body_data = event.encode_data();
        let log_data = LogData::new(
            vec![topic0, seq_topic, vault_topic, account_topic],
            Bytes::from(body_data),
        )
        .expect("topics ok");
        RpcLog {
            inner: PrimLog {
                address: contract,
                data: log_data,
            },
            block_hash: Some(B256::repeat_byte(0xBB)),
            block_number: Some(100),
            block_timestamp: Some(1_700_000_000),
            transaction_hash: Some(B256::repeat_byte(0xCC)),
            transaction_index: Some(0),
            log_index: Some(0),
            removed: false,
        }
    }

    /// Direct semantic test: `apply_filter` returns only logs that
    /// match the filter's topic constraints.
    #[test]
    fn apply_filter_matches_topic2_for_vault_id() {
        let asserter = FilteringAsserter::new();
        let contract = Address::from([0xAB; 20]);
        let vault_a: [u8; 32] = [0xAA; 32];
        let vault_b: [u8; 32] = [0xBB; 32];
        asserter.push_log(build_v1_log(contract, vault_a, 1));
        asserter.push_log(build_v1_log(contract, vault_b, 2));

        // Filter on topic2 (vault_id) = vault_a.
        let f = Filter::new()
            .address(contract)
            .event_signature(RevisionLogV1::RevisionPublished::SIGNATURE_HASH)
            .topic2(B256::from(vault_a));
        let matched = asserter.apply_filter(&f);
        assert_eq!(matched.len(), 1, "expected exactly one match for vault_a");
        // The matched log's topic2 must be vault_a.
        assert_eq!(matched[0].topics()[2], B256::from(vault_a));
    }

    /// Buggy filter (`topic1 == vault_id`) returns NOTHING because the
    /// topic1 slot is `sequence`, not `vaultId`. This is the
    /// signature behaviour of the dormant V1 bug.
    #[test]
    fn apply_filter_with_topic1_vault_id_returns_no_logs() {
        let asserter = FilteringAsserter::new();
        let contract = Address::from([0xAB; 20]);
        let vault_a: [u8; 32] = [0xAA; 32];
        asserter.push_log(build_v1_log(contract, vault_a, 1));

        // The buggy filter — topic1 expects sequence, not vault_id.
        let f = Filter::new()
            .address(contract)
            .event_signature(RevisionLogV1::RevisionPublished::SIGNATURE_HASH)
            .topic1(B256::from(vault_a));
        let matched = asserter.apply_filter(&f);
        assert!(
            matched.is_empty(),
            "buggy topic1=vault_id filter must return zero matches"
        );
    }

    /// Smoke: chain_id flows through as expected.
    #[tokio::test]
    async fn get_chain_id_via_provider_returns_configured_value() {
        let asserter = FilteringAsserter::new();
        asserter.set_chain_id(31_337);
        let provider =
            ProviderBuilder::new().connect_client(RpcClient::new(asserter.clone(), true));
        let id = provider.get_chain_id().await.expect("chain id");
        assert_eq!(id, 31_337);
    }
}
