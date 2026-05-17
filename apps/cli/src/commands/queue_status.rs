// SPDX-License-Identifier: AGPL-3.0-or-later
//! `pangolin-cli sync queue-status` — snapshot the publish queue
//! state.
//!
//! Read-only — works on a Locked vault for the metadata-only
//! counters (dirty count, byte size). The in-session
//! `window_started_at_unix_ms` field is only populated when the
//! vault is Active; we surface `None` in that field on a Locked
//! vault.

#![forbid(unsafe_code)]

use anyhow::{Context, Result};

use crate::cli::{GlobalArgs, SyncQueueStatusArgs};
use crate::config::ResolvedConfig;
use crate::vault_open::{open_and_unlock, open_locked};

/// Run `sync queue-status`.
#[allow(clippy::unused_async)]
pub async fn run(global: &GlobalArgs, args: SyncQueueStatusArgs) -> Result<()> {
    let cfg = ResolvedConfig::from_args(global)?;
    // Open Locked unless a password was provided (the window
    // timestamp lives in the Active session state).
    let vault = if args.vault_password.is_some() {
        open_and_unlock(&args.vault_path, args.vault_password.as_deref())
            .context("vault open + unlock failed")?
    } else {
        open_locked(&args.vault_path).context("vault open failed")?
    };

    let state = vault
        .publish_queue_state()
        .context("publish_queue_state failed")?;

    if cfg.json {
        let value = serde_json::json!({
            "dirty_count": state.dirty_count,
            "dirty_byte_size": state.dirty_byte_size,
            "window_started_at_unix_ms": state.window_started_at_unix_ms,
            "blocked_on_balance": state.blocked_on_balance,
        });
        println!("{value}");
    } else {
        println!("dirty_count               {}", state.dirty_count);
        println!("dirty_byte_size           {}", state.dirty_byte_size);
        match state.window_started_at_unix_ms {
            Some(t) => println!("window_started_at_unix_ms {t}"),
            None => println!("window_started_at_unix_ms (none)"),
        }
        println!(
            "blocked_on_balance        {}",
            if state.blocked_on_balance {
                "yes"
            } else {
                "no"
            }
        );
    }
    Ok(())
}
