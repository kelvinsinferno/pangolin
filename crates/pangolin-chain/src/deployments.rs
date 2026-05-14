// SPDX-License-Identifier: AGPL-3.0-or-later
//! Deployment-address loader for the EIP-712 v1 signing path.
//!
//! Per MVP-2 issue 3.1 R-c (Kelvin sign-off 2026-05-14): the
//! `verifyingContract` field that binds every v1 signature MUST be
//! sourced from the workspace's `contracts/deployments/<env>.json`
//! file, written by the 2.3 deploy pipeline and held under
//! version-control as the single source of truth for D-017 / D-018 /
//! future redeploys.
//!
//! ## Why a separate module
//!
//! The existing `base_sepolia.rs::Deployment::load` is a fuller-fat
//! loader that ALSO bears the runtime-keccak + chain-id cross-checks
//! (P7 MED-1 / MED-2). 3.1's signing primitive only needs **the
//! address**; threading the full deployment-aware adapter through the
//! signer would have forced the adapter shape onto the signing API.
//! This module exposes a narrow `load_deployed_address(env, name)`
//! helper that reads only what the signing primitive needs. The richer
//! validation continues to live in `base_sepolia.rs` for the runtime
//! adapter path; 3.1's signer is a one-way (no-RPC) write primitive
//! and inherits the cross-checks indirectly via the pinned
//! `EXPECTED_DEPLOYED_ADDRESS_BASE_SEPOLIA` constant — see
//! `secp256k1_signing::build_signed_revision_v1` for the
//! cross-check.
//!
//! ## Path resolution (R-c verbatim)
//!
//! Path roots at `CARGO_MANIFEST_DIR + "/../../contracts/deployments/"`
//! — baked at **compile time** so it works from any runtime CWD
//! (test harness, `pangolin-cli` from the user's home dir, an
//! installed binary). Per-env file:
//!
//! - `ChainEnv::BaseSepolia` -> `base-sepolia.json`
//! - `ChainEnv::BaseMainnet` -> `base-mainnet.json`
//! - `ChainEnv::Dev`         -> `dev.json`
//!
//! ## Error surface
//!
//! Every failure path produces a typed
//! [`ChainError::DeploymentNotFound`] /
//! [`ChainError::DeploymentParseError`]; the helper never panics on
//! malformed input. Callers (the signing primitive in
//! `secp256k1_signing.rs`) treat any of these as a hard fail-closed
//! and surface to the operator.

use std::fs;
use std::path::PathBuf;

use alloy::primitives::Address;

use crate::error::ChainError;

/// Which deployed environment a caller is binding to.
///
/// Per master plan §0 cardinal principle 4 + §5 MVP-2 architecture:
/// one chain per build at the production-binding level, but the enum
/// surface here is the audit-friendly way to talk about the deployed
/// addresses (e.g., dev nets, future mainnet) without resorting to a
/// string parameter. Both R-c (single source of truth in the JSON) and
/// L6 (deterministic + auditor-traceable sourcing) are honored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ChainEnv {
    /// Base Sepolia testnet — `chainId = 84_532`. D-017 lives here.
    BaseSepolia,
    /// Base mainnet — `chainId = 8_453`. No production deploy as of
    /// 3.1 plan-gate (2026-05-14); enum slot reserved for the eventual
    /// production cut.
    BaseMainnet,
    /// Local dev chain (anvil / hardhat) for ad-hoc testing. Optional
    /// deployment file at `contracts/deployments/dev.json`.
    Dev,
}

impl ChainEnv {
    /// File-name slug used to locate this env's deployment file.
    #[must_use]
    pub const fn file_name(self) -> &'static str {
        match self {
            Self::BaseSepolia => "base-sepolia.json",
            Self::BaseMainnet => "base-mainnet.json",
            Self::Dev => "dev.json",
        }
    }

    /// `eth_chainId`-style numeric chain id, when fixed. Returns
    /// `None` for the `Dev` env (which may carry any chain id; the
    /// caller cross-checks against the JSON file at load time).
    #[must_use]
    pub const fn chain_id(self) -> Option<u64> {
        match self {
            Self::BaseSepolia => Some(84_532),
            Self::BaseMainnet => Some(8_453),
            Self::Dev => None,
        }
    }
}

/// Workspace-root-relative path to the `contracts/deployments`
/// directory, baked at compile time via [`CARGO_MANIFEST_DIR`].
///
/// `pangolin-chain` lives at `crates/pangolin-chain`, so `../..`
/// reaches the workspace root. This trick works for both `cargo test`
/// (which sets CWD = the crate dir) and `pangolin-cli` (whose runtime
/// CWD is the user's home dir, irrelevant once the path is baked
/// here).
const DEPLOYMENTS_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../contracts/deployments");

/// Load the deployed contract address for `contract_name` under
/// `env`'s deployment file.
///
/// Path: `{DEPLOYMENTS_DIR}/{env.file_name()}` (baked at compile
/// time). Walks `.contracts.<contract_name>.address` via `serde_json`;
/// parses the resulting string as an EIP-55-or-lowercase hex
/// `Address`.
///
/// # Errors
///
/// - [`ChainError::DeploymentNotFound`] — file missing on disk, or the
///   JSON tree does not contain the requested contract entry.
/// - [`ChainError::DeploymentParseError`] — the file is present but
///   malformed JSON, OR the recorded address is not a valid hex
///   address.
pub fn load_deployed_address(env: ChainEnv, contract_name: &str) -> Result<Address, ChainError> {
    let mut path: PathBuf = PathBuf::from(DEPLOYMENTS_DIR);
    path.push(env.file_name());

    let raw = match fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(ChainError::DeploymentNotFound {
                env,
                contract_name: contract_name.to_string(),
            });
        }
        Err(e) => {
            return Err(ChainError::DeploymentParseError {
                env,
                detail: format!("read {}: {e}", path.display()),
            });
        }
    };

    let json: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| ChainError::DeploymentParseError {
            env,
            detail: format!("parse {}: {e}", path.display()),
        })?;

    let addr_str = json
        .get("contracts")
        .and_then(|c| c.get(contract_name))
        .and_then(|c| c.get("address"))
        .and_then(|a| a.as_str())
        .ok_or_else(|| ChainError::DeploymentNotFound {
            env,
            contract_name: contract_name.to_string(),
        })?;

    addr_str
        .parse::<Address>()
        .map_err(|e| ChainError::DeploymentParseError {
            env,
            detail: format!("address {addr_str:?}: {e}"),
        })
}

#[cfg(test)]
mod tests {
    use super::{load_deployed_address, ChainEnv};
    use crate::error::ChainError;

    /// Hermetic test (R-e): the workspace's checked-in
    /// `contracts/deployments/base-sepolia.json` yields D-017's
    /// address verbatim. Fails closed if anyone re-deploys to a
    /// new address without updating the JSON OR if the path
    /// resolution drifts.
    #[test]
    fn load_deployed_address_base_sepolia_v1() {
        let got = load_deployed_address(ChainEnv::BaseSepolia, "RevisionLogV1")
            .expect("base-sepolia.json must list RevisionLogV1 (D-017)");
        let expected: alloy::primitives::Address = "0x179362Ad7fb7dA664312aEFDdaa53431eb748E42"
            .parse()
            .unwrap();
        assert_eq!(got, expected, "deployment-file address must match D-017");
    }

    /// Asking for a contract that the JSON doesn't list surfaces a
    /// typed `DeploymentNotFound` — distinct from a generic parse
    /// error so the caller can distinguish "file is fine; you asked
    /// for the wrong name" from "the file itself is malformed".
    #[test]
    fn load_deployed_address_missing_contract_errors() {
        let err = load_deployed_address(ChainEnv::BaseSepolia, "NotARealContract")
            .expect_err("missing contract entry must error");
        match err {
            ChainError::DeploymentNotFound { env, contract_name } => {
                assert_eq!(env, ChainEnv::BaseSepolia);
                assert_eq!(contract_name, "NotARealContract");
            }
            other => panic!("expected DeploymentNotFound, got {other:?}"),
        }
    }

    /// Sanity: the per-env file slugs are stable across builds — a
    /// silent rename would silently redirect signing. Pin them.
    #[test]
    fn chain_env_file_name_slugs_are_pinned() {
        assert_eq!(ChainEnv::BaseSepolia.file_name(), "base-sepolia.json");
        assert_eq!(ChainEnv::BaseMainnet.file_name(), "base-mainnet.json");
        assert_eq!(ChainEnv::Dev.file_name(), "dev.json");
    }

    /// Numeric chain-id mappings (L2 of 3.1: chainId must be the
    /// production Base Sepolia value; mainnet reserved).
    #[test]
    fn chain_env_chain_ids_are_pinned() {
        assert_eq!(ChainEnv::BaseSepolia.chain_id(), Some(84_532));
        assert_eq!(ChainEnv::BaseMainnet.chain_id(), Some(8_453));
        assert_eq!(ChainEnv::Dev.chain_id(), None);
    }
}
