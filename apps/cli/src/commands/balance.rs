// SPDX-License-Identifier: AGPL-3.0-or-later
//! `pangolin-cli balance show` — read the cached entitlement
//! balance state.
//!
//! Spins up a short-lived `BalanceMonitor` (one poll, then stop),
//! reads the cached `GasBalanceState`, prints the §8.1.5-compliant
//! variant label + wei values as hex strings, then closes the
//! vault via `Vault::close` (pure-local — no on-chain writes).

#![forbid(unsafe_code)]

use core::time::Duration;

use alloy::primitives::Address;
use anyhow::{Context, Result};
use pangolin_chain::{BalanceMonitor, ChainEnv, GasBalanceState};

use crate::cli::{BalanceShowArgs, GlobalArgs};
use crate::config::ResolvedConfig;
use crate::vault_open::open_and_unlock;

/// Run `balance show`.
pub async fn run_show(global: &GlobalArgs, args: BalanceShowArgs) -> Result<()> {
    let cfg = ResolvedConfig::from_args(global)?;
    let deployment_path = cfg.require_deployment_file()?.clone();
    let vault = open_and_unlock(&args.vault_path, args.vault_password.as_deref())
        .context("vault open + unlock failed")?;

    let address_bytes = vault
        .evm_wallet_address()
        .context("evm_wallet_address failed")?;
    let address = Address::from(address_bytes);

    let rpc_url_default = read_deployment_default_rpc(&deployment_path)?;
    let rpc_url = cfg.rpc_url_or_default(&rpc_url_default);
    cfg.enforce_rpc_scheme(&rpc_url)?;

    // Spin up a one-shot monitor: 30 s poll interval, but we stop
    // it immediately after observing the first state. The current
    // value may be `Unknown` if the first poll hasn't landed yet
    // (network in-flight); we wait briefly to give it a chance.
    let monitor = std::sync::Arc::new(BalanceMonitor::start(
        rpc_url.clone(),
        address,
        ChainEnv::BaseSepolia,
        Duration::from_secs(30),
    ));
    // Give the first poll a small window to land. The monitor's
    // first poll fires immediately on start, so 1 s is generous for
    // a healthy RPC and bounded for an unreachable one.
    tokio::time::sleep(Duration::from_secs(1)).await;
    // `current` uses `blocking_read` internally — call it on a
    // dedicated blocking worker so we don't deadlock the runtime.
    let m_clone = std::sync::Arc::clone(&monitor);
    let state = tokio::task::spawn_blocking(move || m_clone.current())
        .await
        .context("spawn_blocking for BalanceMonitor::current")?;
    monitor.stop().await;
    vault.close().context("vault close failed")?;

    let value = render_state(state, cfg.json);
    if cfg.json {
        println!("{value}");
    }
    Ok(())
}

/// Render the state to stdout (human) and/or as a JSON value (for
/// the caller to `println!`).
fn render_state(state: GasBalanceState, json: bool) -> serde_json::Value {
    let (label, value) = match state {
        GasBalanceState::Sufficient {
            balance_wei,
            estimate_wei,
        } => {
            if !json {
                println!("state             sufficient");
                println!("balance_wei_hex   0x{balance_wei:x}");
                println!("estimate_wei_hex  0x{estimate_wei:x}");
            }
            (
                "sufficient",
                serde_json::json!({
                    "state": "sufficient",
                    "balance_wei_hex": format!("0x{balance_wei:x}"),
                    "estimate_wei_hex": format!("0x{estimate_wei:x}"),
                }),
            )
        }
        GasBalanceState::RequiresActiveAccount {
            balance_wei,
            estimate_wei,
        } => {
            if !json {
                println!("state             requires_active_account");
                println!("balance_wei_hex   0x{balance_wei:x}");
                println!("estimate_wei_hex  0x{estimate_wei:x}");
            }
            (
                "requires_active_account",
                serde_json::json!({
                    "state": "requires_active_account",
                    "balance_wei_hex": format!("0x{balance_wei:x}"),
                    "estimate_wei_hex": format!("0x{estimate_wei:x}"),
                }),
            )
        }
        GasBalanceState::TopUpInFlight { initiated_at_unix } => {
            if !json {
                println!("state              top_up_in_flight");
                println!("initiated_at_unix  {initiated_at_unix}");
            }
            (
                "top_up_in_flight",
                serde_json::json!({
                    "state": "top_up_in_flight",
                    "initiated_at_unix": initiated_at_unix,
                }),
            )
        }
        GasBalanceState::Unknown { reason } => {
            if !json {
                println!("state   unknown");
                println!("reason  {reason}");
            }
            (
                "unknown",
                serde_json::json!({
                    "state": "unknown",
                    "reason": reason,
                }),
            )
        }
    };
    let _ = label;
    value
}

/// Pluck `chain.rpc_default` from the deployment file. Duplicated
/// across commands.
fn read_deployment_default_rpc(path: &std::path::Path) -> Result<String> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read deployment file at {}", path.display()))?;
    let value: serde_json::Value = serde_json::from_str(&raw)
        .with_context(|| format!("deployment file {} is not valid JSON", path.display()))?;
    let s = value
        .pointer("/chain/rpc_default")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("deployment file missing /chain/rpc_default (string)"))?;
    Ok(s.to_owned())
}
