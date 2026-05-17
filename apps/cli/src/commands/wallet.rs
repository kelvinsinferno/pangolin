// SPDX-License-Identifier: AGPL-3.0-or-later
//! `pangolin-cli wallet show` — print the per-device EVM wallet
//! address (20-byte hex, `0x...` prefix).
//!
//! Pure-local — no chain calls; closes via `Vault::close` per R-h
//! (chain-touching commands are the only ones that use
//! `lock_with_drain`).

#![forbid(unsafe_code)]

use anyhow::{Context, Result};

use crate::cli::{GlobalArgs, WalletShowArgs};
use crate::config::ResolvedConfig;
use crate::vault_open::open_and_unlock;

/// Run `wallet show`.
#[allow(clippy::unused_async)]
pub async fn run_show(global: &GlobalArgs, args: WalletShowArgs) -> Result<()> {
    let cfg = ResolvedConfig::from_args(global)?;
    let vault = open_and_unlock(&args.vault_path, args.vault_password.as_deref())
        .context("vault open + unlock failed")?;
    let address = vault
        .evm_wallet_address()
        .context("evm_wallet_address failed")?;
    let hex = format!("0x{}", hex::encode(address));
    if cfg.json {
        let value = serde_json::json!({ "address": hex });
        println!("{value}");
    } else {
        println!("{hex}");
    }
    vault.close().context("vault close failed")?;
    Ok(())
}
