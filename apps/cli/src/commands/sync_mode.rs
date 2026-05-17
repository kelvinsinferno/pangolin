// SPDX-License-Identifier: AGPL-3.0-or-later
//! `pangolin-cli sync-mode show|set` — manage the per-vault
//! sync-mode preference. Pure-local — no chain calls; closes
//! `Vault::close` (NOT `lock_with_drain`) on exit per R-h.

#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use pangolin_store::SyncModePreference;

use crate::cli::{GlobalArgs, SyncModePref, SyncModeSetArgs, SyncModeShowArgs};
use crate::config::ResolvedConfig;
use crate::vault_open::open_and_unlock;

/// Map the CLI surface enum to the `pangolin-store` enum. The CLI
/// surface uses kebab-case (`ask` / `always-slow` / `always-fast`)
/// per CLI-V1 R-b; the store uses `Auto` / `AlwaysSlow` / `AlwaysFast`.
fn pref_to_store(p: SyncModePref) -> SyncModePreference {
    match p {
        SyncModePref::Ask => SyncModePreference::Auto,
        SyncModePref::AlwaysSlow => SyncModePreference::AlwaysSlow,
        SyncModePref::AlwaysFast => SyncModePreference::AlwaysFast,
    }
}

/// Inverse map: store → CLI surface (display string).
fn pref_to_str(p: SyncModePreference) -> &'static str {
    match p {
        SyncModePreference::Auto => "ask",
        SyncModePreference::AlwaysSlow => "always-slow",
        SyncModePreference::AlwaysFast => "always-fast",
    }
}

/// Run `sync-mode show`.
#[allow(clippy::unused_async)]
pub async fn run_show(global: &GlobalArgs, args: SyncModeShowArgs) -> Result<()> {
    let cfg = ResolvedConfig::from_args(global)?;
    let vault = open_and_unlock(&args.vault_path, args.vault_password.as_deref())
        .context("vault open + unlock failed")?;
    let pref = vault
        .sync_mode_preference()
        .context("sync_mode_preference failed")?;
    let label = pref_to_str(pref);
    if cfg.json {
        let value = serde_json::json!({ "preference": label });
        println!("{value}");
    } else {
        println!("preference  {label}");
    }
    // Pure-local — Vault::close, not lock_with_drain.
    vault.close().context("vault close failed")?;
    Ok(())
}

/// Run `sync-mode set`.
#[allow(clippy::unused_async)]
pub async fn run_set(global: &GlobalArgs, args: SyncModeSetArgs) -> Result<()> {
    let cfg = ResolvedConfig::from_args(global)?;
    let mut vault = open_and_unlock(&args.vault_path, args.vault_password.as_deref())
        .context("vault open + unlock failed")?;
    let store_pref = pref_to_store(args.value);
    vault
        .set_sync_mode_preference(store_pref)
        .context("set_sync_mode_preference failed")?;
    let label = pref_to_str(store_pref);
    if cfg.json {
        let value = serde_json::json!({
            "outcome": "set",
            "preference": label,
        });
        println!("{value}");
    } else {
        eprintln!("set sync-mode preference: {label}");
    }
    vault.close().context("vault close failed")?;
    Ok(())
}
