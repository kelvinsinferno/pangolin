//! `pangolin-cli status` — read-only diagnostics.
//!
//! This is the P8-1 stub. It loads the resolved config and prints a
//! placeholder line; the real summary lands in P8-5 once the
//! `dirty_accounts` API (P8-2) is in place.

use anyhow::Result;

use crate::cli::{GlobalArgs, StatusArgs};
use crate::config::ResolvedConfig;

/// Run the `status` subcommand.
// P8-1 stub — `async` is required for the dispatch shape in
// `main.rs` (every subcommand is awaited uniformly), even though
// this stub doesn't yet `.await` anything. The real handler lands
// in P8-5.
#[allow(clippy::unused_async)]
pub async fn run(global: &GlobalArgs, _args: StatusArgs) -> Result<()> {
    let _cfg = ResolvedConfig::from_args(global)?;
    // P8-1: stub. Real implementation lands in P8-5.
    eprintln!("pangolin-cli status: subcommand not yet implemented (P8-5)");
    Ok(())
}
