//! chaincli — debug oracle CLI for the deployed `RevisionLogV0` contract.
//!
//! See `docs/issue-plans/P6.md` for the full design. P6-3 wires `status`,
//! P6-4 adds `list` + `dump`, P6-5 adds `publish`.

mod client;
mod commands;
mod contract;
mod format;

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
    command: Command,
}

#[derive(Debug, clap::Subcommand)]
enum Command {
    /// Sanity-check command: confirms RPC reachable, contract address
    /// matches deployment metadata, and `nextSequence()` returns a
    /// current value. Zero-config — uses public Base Sepolia RPC by
    /// default.
    Status,

    /// List `RevisionPublished` events filtered by `vaultId`.
    List(commands::list::ListArgs),

    /// Pretty-print a single `RevisionPublished` event by tx-hash or
    /// (block, log-index).
    Dump(commands::dump::DumpArgs),

    /// Publish a new revision (write path). Signs with a Foundry
    /// keystore via `--account <name>`; password is read from the
    /// terminal without echo.
    Publish(commands::publish::PublishArgs),
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let dep_path = if let Some(p) = cli.deployment_file {
        p
    } else {
        let cwd = std::env::current_dir()?;
        client::Deployment::find_default(&cwd)?
    };
    let deployment = client::Deployment::load(&dep_path)?;
    let rpc_url = client::resolve_rpc_url(cli.rpc_url.as_deref(), RPC_URL_ENV_VAR, &deployment);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        match cli.command {
            Command::Status => commands::status::run(&deployment, &rpc_url).await,
            Command::List(args) => commands::list::run(&deployment, &rpc_url, args).await,
            Command::Dump(args) => commands::dump::run(&deployment, &rpc_url, args).await,
            Command::Publish(args) => commands::publish::run(&deployment, &rpc_url, args).await,
        }
    })
}
