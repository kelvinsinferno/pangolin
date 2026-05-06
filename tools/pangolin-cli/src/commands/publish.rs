//! `pangolin-cli publish` — push dirty revisions to chain.
//!
//! P8-1 stub. Real orchestration lands in P8-3.

use anyhow::{bail, Result};

use crate::cli::{GlobalArgs, PublishArgs};
use crate::config::ResolvedConfig;

/// Run the `publish` subcommand.
// P8-1 stub — see `status::run` for `async` rationale.
#[allow(clippy::unused_async)]
pub async fn run(global: &GlobalArgs, _args: PublishArgs) -> Result<()> {
    let _cfg = ResolvedConfig::from_args(global)?;
    // P8-1: stub. Real implementation lands in P8-3.
    bail!("pangolin-cli publish: subcommand not yet implemented (P8-3)")
}
