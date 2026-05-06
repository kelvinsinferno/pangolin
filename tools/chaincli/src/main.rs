//! chaincli — debug oracle CLI for the deployed `RevisionLogV0` contract.
//!
//! See `docs/issue-plans/P6.md` for the full design. P6-2 wires up
//! the deployment-file loader and the alloy-provider construction;
//! subsequent commits add the `status`, `list`, `dump`, and `publish`
//! sub-commands.

mod client;

use anyhow::Result;
use clap::Parser;

/// Environment variable consulted second in the RPC-URL resolution
/// chain (after `--rpc-url` and before the deployment file's
/// `chain.rpc_default`).
pub const RPC_URL_ENV_VAR: &str = "BASE_SEPOLIA_RPC_URL";

#[derive(Debug, Parser)]
#[command(
    name = "chaincli",
    version,
    about = "Debug oracle CLI for the deployed RevisionLogV0 contract.",
    long_about = "Reads the canonical deployment record at \
                  contracts/deployments/base-sepolia.json so chaincli \
                  always talks to the contract recorded by P5-4. The \
                  RPC URL resolves with priority: --rpc-url flag, then \
                  $BASE_SEPOLIA_RPC_URL, then the deployment file's \
                  chain.rpc_default."
)]
struct Cli {
    /// Override the deployment-file location. Defaults to walking up
    /// from the current directory until `contracts/deployments/base-sepolia.json` is found.
    #[arg(long, global = true)]
    deployment_file: Option<std::path::PathBuf>,

    /// Override the RPC URL. Otherwise uses `$BASE_SEPOLIA_RPC_URL` or
    /// the deployment file's `chain.rpc_default`.
    #[arg(long, global = true)]
    rpc_url: Option<String>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, clap::Subcommand)]
enum Command {
    /// Print resolved configuration without contacting the chain.
    /// Subsequent commits replace this with a real
    /// `status`/`list`/`dump`/`publish` dispatch.
    Echo,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command.unwrap_or(Command::Echo) {
        Command::Echo => {
            let dep_path = if let Some(p) = cli.deployment_file {
                p
            } else {
                let cwd = std::env::current_dir()?;
                client::Deployment::find_default(&cwd)?
            };
            let dep = client::Deployment::load(&dep_path)?;
            let rpc = client::resolve_rpc_url(cli.rpc_url.as_deref(), RPC_URL_ENV_VAR, &dep);
            println!("deployment_file    : {}", dep.source_path.display());
            println!("chain_id           : {}", dep.chain_id);
            println!("contract_address   : {:?}", dep.contract_address);
            println!("rpc                : {rpc}");
        }
    }
    Ok(())
}
