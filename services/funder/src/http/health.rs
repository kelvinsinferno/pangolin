// SPDX-License-Identifier: AGPL-3.0-or-later
//! `GET /funder/v1/health` — operator probe.

use axum::extract::State;
use axum::Json;

use pangolin_funder_client::FUNDER_DEVICE_BINDING_DOMAIN_V1;

use crate::http::AppState;

/// Health response body. Includes the registry address + chain id so
/// operators can sanity-check the funder is bound to the right
/// contract; includes the device-binding domain literal so clients
/// can sanity-check protocol-version compatibility (R-g (5)).
#[derive(Debug, serde::Serialize)]
pub struct HealthResponse {
    /// Always `true` (the funder is reachable enough to answer).
    pub ok: bool,
    /// Build commit hash, baked in at compile time via the `GIT_SHA`
    /// env var (operator wires this through their build pipeline).
    /// Defaults to `"unknown"` when the env var is unset.
    pub commit: &'static str,
    /// `EntitlementRegistry` contract address (0x-prefixed hex).
    pub registry: String,
    /// Chain id (`84_532` for Base Sepolia).
    pub chain_id: Option<u64>,
    /// Funder signer address (0x-prefixed hex). Non-secret per
    /// D-006 + L12 (the address is the public counterparty).
    pub signer_address: String,
    /// `PAYMENT_AUTHORITY` address read on-chain at startup (cached).
    pub payment_authority: String,
    /// Device-binding domain literal (R-g (5)). Clients verify this
    /// matches the constant they were built against; mismatch =
    /// protocol-version skew.
    pub device_binding_domain: &'static str,
}

/// Compile-time-baked commit hash. Build pipelines set `GIT_SHA`;
/// when unset (e.g., local `cargo run`), we report `"unknown"`.
const COMMIT: &str = match option_env!("GIT_SHA") {
    Some(v) => v,
    None => "unknown",
};

/// `GET /funder/v1/health` handler.
pub async fn handle(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        ok: true,
        commit: COMMIT,
        registry: format!("{:?}", state.registry_address),
        chain_id: state.chain_env.chain_id(),
        signer_address: format!("{:?}", state.signer.address()),
        payment_authority: format!("{:?}", state.payment_authority),
        device_binding_domain: FUNDER_DEVICE_BINDING_DOMAIN_V1,
    })
}
