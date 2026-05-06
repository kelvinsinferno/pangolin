//! `pangolin-cli pull` — ingest chain events into the local vault.
//!
//! P8-1 stub. Real orchestration lands in P8-4.

use anyhow::{bail, Result};

use crate::cli::{GlobalArgs, PullArgs};
use crate::config::ResolvedConfig;

/// Run the `pull` subcommand.
// P8-1 stub — see `status::run` for `async` rationale.
#[allow(clippy::unused_async)]
pub async fn run(global: &GlobalArgs, _args: PullArgs) -> Result<()> {
    let _cfg = ResolvedConfig::from_args(global)?;
    // P8-1: stub. Real implementation lands in P8-4.
    bail!("pangolin-cli pull: subcommand not yet implemented (P8-4)")
}
