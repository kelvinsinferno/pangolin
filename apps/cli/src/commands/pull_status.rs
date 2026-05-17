// SPDX-License-Identifier: AGPL-3.0-or-later
//! `pangolin-cli sync pull-status` — surface pull-loop telemetry.
//!
//! Read-only. Reports:
//! - `last_pulled_block` — on-disk checkpoint (works on a Locked
//!   vault).
//! - `last_pull_at_unix_ms` — in-session timestamp of the most
//!   recent successful `pull_once` cycle (requires an Active
//!   session; reported as `None` on Locked).

#![forbid(unsafe_code)]

use anyhow::{Context, Result};

use crate::cli::{GlobalArgs, SyncPullStatusArgs};
use crate::config::ResolvedConfig;
use crate::vault_open::{open_and_unlock, open_locked};

/// Run `sync pull-status`.
#[allow(clippy::unused_async)]
pub async fn run(global: &GlobalArgs, args: SyncPullStatusArgs) -> Result<()> {
    let cfg = ResolvedConfig::from_args(global)?;
    let vault = if args.vault_password.is_some() {
        open_and_unlock(&args.vault_path, args.vault_password.as_deref())
            .context("vault open + unlock failed")?
    } else {
        open_locked(&args.vault_path).context("vault open failed")?
    };

    let last_pulled_block = vault
        .last_pulled_block()
        .context("last_pulled_block failed")?;
    let last_pull_at_unix_ms = vault.last_pull_at_unix_ms();

    if cfg.json {
        let value = serde_json::json!({
            "last_pulled_block": last_pulled_block,
            "last_pull_at_unix_ms": last_pull_at_unix_ms,
        });
        println!("{value}");
    } else {
        println!("last_pulled_block       {last_pulled_block}");
        match last_pull_at_unix_ms {
            Some(t) => println!("last_pull_at_unix_ms    {t}"),
            None => println!("last_pull_at_unix_ms    (none)"),
        }
    }
    Ok(())
}
