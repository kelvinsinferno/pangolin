// SPDX-License-Identifier: AGPL-3.0-or-later
//! HTTP surface (R-a + L6).
//!
//! Two endpoints only:
//! - `POST /funder/v1/top-up` — the redemption + ETH-transfer flow.
//! - `GET /funder/v1/health` — operator probe.
//!
//! No admin, no debug, no metrics. Metrics live on a SEPARATE port
//! per L6 (deferred to 18.10).

pub mod health;
pub mod routes;
pub mod top_up;

use std::sync::Arc;

use alloy::primitives::Address;
use pangolin_chain::ChainEnv;

use crate::ledger::PaymentLedger;
use crate::rate_limit::RateLimiter;
use crate::signer::FunderSigner;

/// Shared application state passed into every axum handler via
/// `State`.
///
/// All fields are `Clone`-able / `Arc`-wrapped so axum's
/// `with_state` machinery can clone the struct cheaply across
/// handler invocations.
#[derive(Clone)]
pub struct AppState {
    /// Funder signer (R-f).
    pub signer: Arc<dyn FunderSigner>,
    /// Payment ledger (R-b).
    pub ledger: PaymentLedger,
    /// Layered rate limiter (R-e).
    pub rate_limiter: RateLimiter,
    /// `EntitlementRegistry` contract address (read from the
    /// deployment file at startup; pinned for the process lifetime).
    pub registry_address: Address,
    /// `PAYMENT_AUTHORITY` address cached at startup. R-c verbatim:
    /// the funder reads `PAYMENT_AUTHORITY()` from the contract
    /// once + caches the result for the process lifetime; the
    /// `payment_authority_cache_used` test asserts no per-request
    /// chain query.
    pub payment_authority: Address,
    /// Chain env in use (Base Sepolia / Mainnet / Dev).
    pub chain_env: ChainEnv,
    /// RPC URL the chain submit path uses.
    pub rpc_url: String,
}

impl core::fmt::Debug for AppState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AppState")
            .field("signer_address", &self.signer.address())
            .field("registry_address", &self.registry_address)
            .field("payment_authority", &self.payment_authority)
            .field("chain_env", &self.chain_env)
            // rpc_url is not secret per the deployment-file pattern;
            // it's still terse for log readability.
            .field("rpc_url", &self.rpc_url)
            .finish()
    }
}
