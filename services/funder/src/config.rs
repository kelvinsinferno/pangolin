// SPDX-License-Identifier: AGPL-3.0-or-later
//! Configuration parsing for the funder service.
//!
//! Per R-e the rate-limit constants can be overridden via env vars
//! (`FUNDER_RATE_LIMIT_*`); all other settings are also env-driven so
//! the binary can be deployed with zero extra files beyond the
//! keystore.

use core::net::SocketAddr;
use std::env;
use std::path::PathBuf;

use pangolin_chain::ChainEnv;

use crate::error::FunderError;
use crate::rate_limit::{
    RateLimitConfig, GLOBAL_CAP_PER_HOUR, PER_ADDRESS_BUCKET_SIZE,
    PER_ADDRESS_REPLENISH_INTERVAL_SECS,
};
use crate::ETH_TRANSFER_PER_TX_CAP_WEI;

/// Default bind address. `127.0.0.1` (NOT `0.0.0.0`) per L-funder-service-MITM:
/// the funder is expected to sit behind a TLS-terminating reverse proxy.
pub const DEFAULT_BIND_ADDR: &str = "127.0.0.1:8080";

/// Default RPC URL for Base Sepolia.
pub const DEFAULT_BASE_SEPOLIA_RPC: &str = "https://sepolia.base.org";

/// Default ledger path. Relative to the funder's working directory.
pub const DEFAULT_LEDGER_PATH: &str = "./funder-ledger.sqlite";

/// Default HTTP body size limit. 16 KB is well above the ~1 KB a
/// well-formed `TopUpRequest` needs; small enough to defeat memory-
/// exhaustion `DoS`.
pub const DEFAULT_BODY_SIZE_LIMIT_BYTES: usize = 16 * 1024;

/// Runtime configuration for the funder service. Constructed once at
/// startup via [`FunderConfig::from_env`].
#[derive(Debug, Clone)]
pub struct FunderConfig {
    /// Chain env (Base Sepolia / Base Mainnet / Dev). Determines the
    /// deployment-file slug, expected chain id, and the alloy
    /// domain-separator binding.
    pub chain_env: ChainEnv,
    /// HTTP bind address (e.g., `127.0.0.1:8080`).
    pub bind_addr: SocketAddr,
    /// RPC URL.
    pub rpc_url: String,
    /// Ledger file path.
    pub ledger_path: PathBuf,
    /// Keystore file path (Foundry Web3 Secret Storage format).
    /// `None` when running with `FUNDER_PRIVATE_KEY_HEX` (dev mode).
    pub keystore_path: Option<PathBuf>,
    /// Keystore passphrase file path. `None` reads from stdin TTY at
    /// startup.
    pub keystore_passphrase_file: Option<PathBuf>,
    /// Dev-mode private key hex. Production paths use the keystore.
    pub dev_private_key_hex: Option<String>,
    /// Layered rate-limit config (R-e).
    pub rate_limit: RateLimitConfig,
    /// HTTP body size limit (bytes).
    pub body_size_limit_bytes: usize,
    /// Per-tx ETH-transfer hard cap (wei). Override via
    /// `FUNDER_ETH_TRANSFER_PER_TX_CAP_WEI` (decimal or 0x-hex).
    pub eth_transfer_per_tx_cap_wei: u128,
}

impl FunderConfig {
    /// Build a config from process environment variables. Returns a
    /// [`FunderError::Configuration`] on missing required vars or
    /// parse failures.
    pub fn from_env() -> Result<Self, FunderError> {
        let chain_env = parse_chain_env(&env_var_or("FUNDER_CHAIN_ENV", "base-sepolia"))?;
        let bind_addr_raw = env_var_or("FUNDER_BIND_ADDR", DEFAULT_BIND_ADDR);
        let bind_addr: SocketAddr = bind_addr_raw.parse().map_err(|e| {
            FunderError::Configuration(format!(
                "FUNDER_BIND_ADDR={bind_addr_raw:?} not a SocketAddr: {e}"
            ))
        })?;
        let rpc_url = env_var_or(
            "FUNDER_RPC_URL",
            match chain_env {
                ChainEnv::BaseSepolia => DEFAULT_BASE_SEPOLIA_RPC,
                _ => "http://127.0.0.1:8545",
            },
        );
        let ledger_path = PathBuf::from(env_var_or("FUNDER_LEDGER_PATH", DEFAULT_LEDGER_PATH));
        let keystore_path = env::var("FUNDER_KEYSTORE_PATH").ok().map(PathBuf::from);
        let keystore_passphrase_file = env::var("FUNDER_KEYSTORE_PASSPHRASE_FILE")
            .ok()
            .map(PathBuf::from);
        let dev_private_key_hex = env::var("FUNDER_PRIVATE_KEY_HEX").ok();

        let rate_limit = RateLimitConfig {
            per_address_bucket_size: env_var_u32("FUNDER_RATE_LIMIT_BUCKET_SIZE")?
                .unwrap_or(PER_ADDRESS_BUCKET_SIZE),
            per_address_replenish_interval_secs: env_var_u64("FUNDER_RATE_LIMIT_REPLENISH_SECS")?
                .unwrap_or(PER_ADDRESS_REPLENISH_INTERVAL_SECS),
            global_cap_per_hour: env_var_u32("FUNDER_RATE_LIMIT_GLOBAL_CAP")?
                .unwrap_or(GLOBAL_CAP_PER_HOUR),
        };
        let body_size_limit_bytes =
            env_var_usize("FUNDER_BODY_SIZE_LIMIT_BYTES")?.unwrap_or(DEFAULT_BODY_SIZE_LIMIT_BYTES);
        let eth_transfer_per_tx_cap_wei =
            env_var_u128_hex_or_dec("FUNDER_ETH_TRANSFER_PER_TX_CAP_WEI")?
                .unwrap_or(ETH_TRANSFER_PER_TX_CAP_WEI);

        Ok(Self {
            chain_env,
            bind_addr,
            rpc_url,
            ledger_path,
            keystore_path,
            keystore_passphrase_file,
            dev_private_key_hex,
            rate_limit,
            body_size_limit_bytes,
            eth_transfer_per_tx_cap_wei,
        })
    }
}

fn env_var_u128_hex_or_dec(key: &str) -> Result<Option<u128>, FunderError> {
    match env::var(key) {
        Ok(v) => {
            let trimmed = v.trim();
            let parsed = if let Some(hex) = trimmed.strip_prefix("0x") {
                u128::from_str_radix(hex, 16)
            } else {
                trimmed.parse::<u128>()
            };
            parsed
                .map(Some)
                .map_err(|e| FunderError::Configuration(format!("{key}={trimmed:?} not u128: {e}")))
        }
        Err(_) => Ok(None),
    }
}

fn parse_chain_env(s: &str) -> Result<ChainEnv, FunderError> {
    match s.to_ascii_lowercase().as_str() {
        "base-sepolia" | "basesepolia" | "sepolia" => Ok(ChainEnv::BaseSepolia),
        "base-mainnet" | "basemainnet" | "mainnet" => Ok(ChainEnv::BaseMainnet),
        "dev" | "local" => Ok(ChainEnv::Dev),
        other => Err(FunderError::Configuration(format!(
            "unknown FUNDER_CHAIN_ENV {other:?}; supported: base-sepolia, base-mainnet, dev"
        ))),
    }
}

fn env_var_or(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_owned())
}

fn env_var_u32(key: &str) -> Result<Option<u32>, FunderError> {
    match env::var(key) {
        Ok(v) => v
            .parse::<u32>()
            .map(Some)
            .map_err(|e| FunderError::Configuration(format!("{key}={v:?} not u32: {e}"))),
        Err(_) => Ok(None),
    }
}

fn env_var_u64(key: &str) -> Result<Option<u64>, FunderError> {
    match env::var(key) {
        Ok(v) => v
            .parse::<u64>()
            .map(Some)
            .map_err(|e| FunderError::Configuration(format!("{key}={v:?} not u64: {e}"))),
        Err(_) => Ok(None),
    }
}

fn env_var_usize(key: &str) -> Result<Option<usize>, FunderError> {
    match env::var(key) {
        Ok(v) => v
            .parse::<usize>()
            .map(Some)
            .map_err(|e| FunderError::Configuration(format!("{key}={v:?} not usize: {e}"))),
        Err(_) => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_chain_env_accepts_canonical_strings() {
        assert!(matches!(
            parse_chain_env("base-sepolia"),
            Ok(ChainEnv::BaseSepolia)
        ));
        assert!(matches!(
            parse_chain_env("sepolia"),
            Ok(ChainEnv::BaseSepolia)
        ));
        assert!(matches!(parse_chain_env("dev"), Ok(ChainEnv::Dev)));
        assert!(matches!(
            parse_chain_env("base-mainnet"),
            Ok(ChainEnv::BaseMainnet)
        ));
        assert!(parse_chain_env("garbage").is_err());
    }
}
