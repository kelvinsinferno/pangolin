//! clap-derive types for `pangolin-cli`.
//!
//! Global flags (apply to every subcommand): vault path, deployment
//! file, RPC URL, JSON-output toggle. Per-subcommand args live next to
//! their handler in `commands/`.
//!
//! ## RPC URL resolution
//!
//! The same precedence chain as `chaincli`:
//!
//!   `--rpc-url <url>`  >  `$BASE_SEPOLIA_RPC_URL`  >  deployment-file's
//!   `chain.rpc_default`.
//!
//! The clap `env` feature is what pulls `BASE_SEPOLIA_RPC_URL` into the
//! parser. The deployment-file fallback is resolved inside
//! [`crate::config::ResolvedConfig::resolve`] once we've loaded the
//! deployment metadata.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

/// Environment variable consulted second in the RPC-URL resolution
/// chain (after `--rpc-url` and before the deployment file's
/// `chain.rpc_default`). Same name `chaincli` uses.
pub const RPC_URL_ENV_VAR: &str = "BASE_SEPOLIA_RPC_URL";

#[derive(Debug, Parser)]
#[command(
    name = "pangolin-cli",
    version,
    about = "Pangolin sync orchestrator — publish, pull, and inspect a Pangolin vault.",
    long_about = "Drives a local vault end-to-end through the deployed \
                  RevisionLogV0 contract on Base Sepolia. Use `status` \
                  for read-only diagnostics, `publish` to push dirty \
                  revisions to chain, and `pull` to ingest chain \
                  events into the local vault. See \
                  docs/issue-plans/P8.md for design details."
)]
pub struct Cli {
    #[command(flatten)]
    pub global: GlobalArgs,

    #[command(subcommand)]
    pub command: Command,
}

/// Global args shared by every subcommand.
#[derive(Debug, Args)]
pub struct GlobalArgs {
    /// Override the deployment-file location. Defaults to walking up
    /// from the current directory until
    /// `contracts/deployments/base-sepolia.json` is found.
    #[arg(long, global = true)]
    pub deployment_file: Option<PathBuf>,

    /// Override the RPC URL. Otherwise uses `$BASE_SEPOLIA_RPC_URL` or
    /// the deployment file's `chain.rpc_default`.
    #[arg(long, global = true, env = RPC_URL_ENV_VAR)]
    pub rpc_url: Option<String>,

    /// Emit JSON-Lines summary output where supported (`status` and
    /// the per-run summaries of `publish` / `pull`). Errors and
    /// per-event lines stay human-readable on stderr.
    #[arg(long, global = true)]
    pub json: bool,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Read-only diagnostics: dirty count, account count,
    /// last-pulled-block, last-published-block, head count per account.
    /// Does NOT make any chain calls.
    Status(StatusArgs),

    /// Walk the dirty list, sign each revision with the vault's
    /// device key, submit to chain, and clear the dirty marker on
    /// success. Per-account error isolation; A3 pre-publish check
    /// guards against duplicate publish on re-run.
    Publish(PublishArgs),

    /// Incremental chunked pull from `last_pulled_block`. Every event
    /// is signature-verified before being persisted (Q6 defense in
    /// depth). Forks are reported; auto-resolution is P9's job.
    Pull(PullArgs),
}

/// `status` subcommand args.
#[derive(Debug, Args)]
pub struct StatusArgs {
    /// Path to the `.pvf` vault file.
    #[arg(long)]
    pub vault_path: PathBuf,

    /// Vault password (echoes in `ps`; prefer the prompt for non-CI
    /// use). If omitted, no unlock is attempted — `status` reports
    /// the metadata-only counters that survive a `Locked` vault.
    #[arg(long)]
    pub vault_password: Option<String>,
}

/// `publish` subcommand args.
#[derive(Debug, Args)]
pub struct PublishArgs {
    /// Path to the `.pvf` vault file.
    #[arg(long)]
    pub vault_path: PathBuf,

    /// Vault password. If omitted, prompted at the terminal without
    /// echo.
    #[arg(long)]
    pub vault_password: Option<String>,

    /// Foundry keystore name. Resolved against
    /// `$FOUNDRY_DIR/keystores/<name>` (default
    /// `~/.foundry/keystores/<name>` on Linux/macOS,
    /// `%USERPROFILE%\.foundry\keystores\<name>` on Windows). Mutually
    /// exclusive with `--keystore-path`.
    #[arg(long, conflicts_with = "keystore_path")]
    pub account: Option<String>,

    /// Override the keystore directory. Useful for tests against a
    /// fixture keystore. Mutually exclusive with `--account`.
    #[arg(long)]
    pub keystore_dir: Option<PathBuf>,

    /// Direct path to a Foundry keystore file. Mutually exclusive with
    /// `--account`.
    #[arg(long, conflicts_with = "account")]
    pub keystore_path: Option<PathBuf>,

    /// Keystore password. Echoes in `ps`; prefer the prompt for
    /// non-CI use. If omitted, prompted at the terminal without echo.
    #[arg(long)]
    pub keystore_password: Option<String>,
}

/// `pull` subcommand args.
#[derive(Debug, Args)]
pub struct PullArgs {
    /// Path to the `.pvf` vault file.
    #[arg(long)]
    pub vault_path: PathBuf,

    /// Vault password. If omitted, prompted at the terminal without
    /// echo. Required because `pull` needs an unlocked vault to
    /// authenticate ingested AEAD payloads (the AAD is bound to
    /// `(vault_id, account_id, parent_revision, schema_version)` —
    /// the AEAD open path needs the VDK).
    #[arg(long)]
    pub vault_password: Option<String>,

    /// Override `last_pulled_block` for this run only. Useful for
    /// disaster recovery. Default: read from vault's `sync_state` row.
    #[arg(long)]
    pub from_block: Option<u64>,

    /// Override the upper-bound block. Default: chain head at the time
    /// of the call.
    #[arg(long)]
    pub until_block: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::{Cli, Command};
    use clap::Parser;

    /// Top-level help renders. Smoke test — clap's derive correctness.
    #[test]
    fn help_renders() {
        let err = Cli::try_parse_from(["pangolin-cli", "--help"]).unwrap_err();
        // `--help` exits with `DisplayHelp` kind, not a parse failure.
        assert!(matches!(err.kind(), clap::error::ErrorKind::DisplayHelp));
    }

    /// `--vault-path` is required for every subcommand.
    #[test]
    fn vault_path_is_required_for_status() {
        let err = Cli::try_parse_from(["pangolin-cli", "status"]).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("--vault-path"),
            "expected missing --vault-path, got: {msg}"
        );
    }

    /// `--vault-path` is required for `publish`.
    #[test]
    fn vault_path_is_required_for_publish() {
        let err = Cli::try_parse_from(["pangolin-cli", "publish"]).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("--vault-path"),
            "expected missing --vault-path, got: {msg}"
        );
    }

    /// `--vault-path` is required for `pull`.
    #[test]
    fn vault_path_is_required_for_pull() {
        let err = Cli::try_parse_from(["pangolin-cli", "pull"]).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("--vault-path"),
            "expected missing --vault-path, got: {msg}"
        );
    }

    /// `--account` and `--keystore-path` are mutually exclusive.
    #[test]
    fn account_and_keystore_path_conflict() {
        let err = Cli::try_parse_from([
            "pangolin-cli",
            "publish",
            "--vault-path",
            "/tmp/v.pvf",
            "--account",
            "dev",
            "--keystore-path",
            "/tmp/keystore",
        ])
        .unwrap_err();
        // clap surfaces the conflict via ArgumentConflict.
        assert!(matches!(
            err.kind(),
            clap::error::ErrorKind::ArgumentConflict
        ));
    }

    /// `status` parses cleanly with `--vault-path`.
    #[test]
    fn status_parses_with_vault_path() {
        let cli = Cli::try_parse_from(["pangolin-cli", "status", "--vault-path", "/tmp/v.pvf"])
            .expect("status with --vault-path parses");
        assert!(matches!(cli.command, Command::Status(_)));
    }

    /// `publish` parses cleanly with `--vault-path` + `--account`.
    #[test]
    fn publish_parses_with_account() {
        let cli = Cli::try_parse_from([
            "pangolin-cli",
            "publish",
            "--vault-path",
            "/tmp/v.pvf",
            "--account",
            "dev",
        ])
        .expect("publish with --account parses");
        match cli.command {
            Command::Publish(p) => {
                assert_eq!(p.account.as_deref(), Some("dev"));
                assert!(p.keystore_path.is_none());
            }
            _ => panic!("expected Publish command"),
        }
    }

    /// `--rpc-url` flag overrides the env-var resolution.
    #[test]
    fn rpc_url_flag_parses() {
        let cli = Cli::try_parse_from([
            "pangolin-cli",
            "--rpc-url",
            "https://example.test/rpc",
            "status",
            "--vault-path",
            "/tmp/v.pvf",
        ])
        .expect("rpc-url flag parses");
        assert_eq!(
            cli.global.rpc_url.as_deref(),
            Some("https://example.test/rpc")
        );
    }

    /// `--json` global flag is recognized at the top level.
    #[test]
    fn json_flag_parses() {
        let cli = Cli::try_parse_from([
            "pangolin-cli",
            "--json",
            "status",
            "--vault-path",
            "/tmp/v.pvf",
        ])
        .expect("--json parses");
        assert!(cli.global.json);
    }
}
