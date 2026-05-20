// SPDX-License-Identifier: AGPL-3.0-or-later
//! Test-only environment seam for the issue #101 anvil-fork CI harness.
//!
//! The curated `#[ignore]`'d live tests (`publish_v1_live_d017_smoke`,
//! `live_pull_once_against_d017_advances_checkpoint`,
//! `live_balance_query_against_d017_wallet`) historically targeted Base
//! Sepolia only. Issue #101 (R-b) parametrizes them so the SAME test
//! can run against either:
//!
//! - the real **Base Sepolia** chain (the existing manual / live-residue
//!   posture), or
//! - a **local anvil** node deployed fresh by `scripts/anvil-ci.sh` and
//!   run on every PR.
//!
//! This module is the thin seam those tests read. It is gated to test /
//! test-utilities / integration-tests builds and is never compiled into
//! a production binary — L1 (no production-code behavior change) holds.
//!
//! ## Mode selection (`PANGOLIN_CHAIN_ENV`)
//!
//! - unset / `base-sepolia` → [`ChainEnv::BaseSepolia`] (default; the
//!   pre-#101 behavior is unchanged for humans running the live tests).
//! - `dev` → [`ChainEnv::Dev`] (local anvil; the CI harness sets this).
//!
//! ## L6 — skip-clean becomes a HARD error in dev mode
//!
//! The pre-#101 live tests `return` early ("SKIP") when their required
//! env vars are unset, so default CI never reaches the network. That
//! skip-clean posture is RETAINED for `base-sepolia` mode (a human
//! without `.env.live` set just gets a no-op). But in **`dev` mode** a
//! missing `dev.json` / RPC / env var is a HARD failure: the whole
//! point of #101 is that a Rust↔contract mismatch turns CI RED, and the
//! 3.3 preimage bug "passed" precisely because its live test skipped.
//! Tests call [`require_or_fail`] at each would-be-skip point: it
//! `return`s `false` (skip) in base-sepolia mode and `panic!`s in dev
//! mode.

use alloy::providers::{Provider, ProviderBuilder};

use crate::deployments::ChainEnv;
use crate::error::ChainError;

/// Env var selecting which chain the parametrized live tests target.
pub const CHAIN_ENV_VAR: &str = "PANGOLIN_CHAIN_ENV";

/// Env var carrying the RPC URL.
///
/// In dev mode `scripts/anvil-ci.sh` repoints this at the local anvil
/// node (`http://127.0.0.1:8545`); in base-sepolia mode it carries the
/// real Base Sepolia RPC (or defaults to the public endpoint).
pub const RPC_URL_VAR: &str = "BASE_SEPOLIA_RPC_URL";

/// Resolve the [`ChainEnv`] the live tests should target.
///
/// `PANGOLIN_CHAIN_ENV=dev` → [`ChainEnv::Dev`]; anything else (incl.
/// unset) → [`ChainEnv::BaseSepolia`] (the default keeps the pre-#101
/// human-run posture intact).
#[must_use]
pub fn target_chain_env() -> ChainEnv {
    match std::env::var(CHAIN_ENV_VAR).ok().as_deref() {
        Some("dev") => ChainEnv::Dev,
        _ => ChainEnv::BaseSepolia,
    }
}

/// `true` when the harness selected dev / local-anvil mode.
#[must_use]
pub fn is_dev_mode() -> bool {
    matches!(target_chain_env(), ChainEnv::Dev)
}

/// Resolve the RPC URL the live tests should dial.
///
/// Reads [`RPC_URL_VAR`]; falls back to the public Base Sepolia endpoint
/// only in base-sepolia mode. In dev mode an unset / empty value is a
/// caller error surfaced via [`require_or_fail`] (the harness always
/// sets it), so the fallback there is the loud `http://127.0.0.1:8545`
/// anvil default which will then fail-closed if anvil isn't actually up.
#[must_use]
pub fn rpc_url() -> String {
    match std::env::var(RPC_URL_VAR) {
        Ok(s) if !s.is_empty() => s,
        _ => {
            if is_dev_mode() {
                "http://127.0.0.1:8545".to_owned()
            } else {
                "https://sepolia.base.org".to_owned()
            }
        }
    }
}

/// L6 gate: convert a would-be skip into either a clean skip
/// (base-sepolia mode) or a HARD failure (dev mode).
///
/// Returns `true` if the test should PROCEED, `false` if it should
/// cleanly skip. In dev mode it never returns `false` — it `panic!`s
/// with `reason`, turning the CI job RED. Call this at each point the
/// pre-#101 test used to `return` early.
///
/// # Panics
///
/// Panics in dev mode (`PANGOLIN_CHAIN_ENV=dev`) — that is the L6
/// fail-closed contract.
#[must_use]
pub fn require_or_fail(reason: &str) -> bool {
    assert!(
        !is_dev_mode(),
        "L6 (issue #101 dev mode): {reason}. In PANGOLIN_CHAIN_ENV=dev this is a HARD \
         error, never a skip — a missing dev.json / RPC / env var means the anvil harness \
         is misconfigured and the Rust↔contract gate would be silently bypassed."
    );
    eprintln!("SKIP (base-sepolia mode): {reason}");
    false
}

/// Resolve the signing chain id for `env` (issue #101 amendment).
///
/// Returns the chain id to bind into the EIP-712 signing domain + the
/// EIP-1559 tx envelope, reading `rpc_url` only on the Dev path.
/// Mirrors the production resolution contract (see
/// [`crate::secp256k1_signing::build_domain`]):
///
/// - **`env.chain_id()` is `Some`** (e.g. `BaseSepolia` → `84_532`):
///   return the pinned id WITHOUT reading the RPC. Production never
///   sources its signing chain id from an untrusted RPC.
/// - **`env.chain_id()` is `None`** (`Dev` / local anvil): read the live
///   `eth_chainId` from the connected (trusted, local) node and return
///   it (e.g. `31337`).
///
/// # Errors
///
/// [`ChainError::Rpc`] if the dev-mode `eth_chainId` read fails (anvil
/// not reachable). For fixed envs this never touches the network so it
/// is infallible in practice.
pub async fn resolve_signing_chain_id(env: ChainEnv, rpc_url: &str) -> Result<u64, ChainError> {
    if let Some(pinned) = env.chain_id() {
        return Ok(pinned);
    }
    // Dev / local anvil only: read the live id from the trusted node.
    let provider = ProviderBuilder::new()
        .connect(rpc_url)
        .await
        .map_err(|e| ChainError::Rpc(format!("connect {rpc_url}: {e}")))?;
    provider
        .get_chain_id()
        .await
        .map_err(|e| ChainError::Rpc(format!("eth_chainId: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `target_chain_env` defaults to `BaseSepolia` and reads `dev` only
    /// on the exact string. Uses a process-global env var so we serialize
    /// via a single test (set + assert + unset) to avoid cross-test
    /// races.
    #[test]
    fn target_chain_env_default_and_dev() {
        // Default (unset) → BaseSepolia.
        std::env::remove_var(CHAIN_ENV_VAR);
        assert_eq!(target_chain_env(), ChainEnv::BaseSepolia);
        assert!(!is_dev_mode());

        // `dev` → Dev.
        std::env::set_var(CHAIN_ENV_VAR, "dev");
        assert_eq!(target_chain_env(), ChainEnv::Dev);
        assert!(is_dev_mode());

        // Any other value → BaseSepolia (fail-safe to production posture).
        std::env::set_var(CHAIN_ENV_VAR, "base-sepolia");
        assert_eq!(target_chain_env(), ChainEnv::BaseSepolia);
        std::env::remove_var(CHAIN_ENV_VAR);
    }

    /// For a fixed env, `resolve_signing_chain_id` returns the pinned id
    /// WITHOUT touching the network (the `rpc_url` is intentionally
    /// bogus; if it were dialed the test would error).
    #[tokio::test]
    async fn resolve_signing_chain_id_fixed_env_is_offline() {
        let id = resolve_signing_chain_id(ChainEnv::BaseSepolia, "http://127.0.0.1:1")
            .await
            .expect("fixed env never dials the RPC");
        assert_eq!(id, 84_532);
    }
}
