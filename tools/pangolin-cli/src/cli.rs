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
    /// the deployment file's `chain.rpc_default`. Must use `https://`
    /// unless `--allow-insecure-rpc` is set (the latter is for local
    /// anvil testing only).
    #[arg(long, global = true, env = RPC_URL_ENV_VAR)]
    pub rpc_url: Option<String>,

    /// **P8 fix MED-2.** Allow `http://` (or other non-`https`)
    /// scheme RPC URLs. Default refuses non-HTTPS URLs to defeat
    /// passive eavesdroppers and active MITM attackers on the
    /// transport layer. Toggle this on only for local development
    /// against a local anvil node — never in production.
    #[arg(long, global = true)]
    pub allow_insecure_rpc: bool,

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

    /// Resolve a fork or freeze on one account. Picks the user's
    /// chosen revision as the head, re-seals its payload under a
    /// fresh nonce, publishes a merge revision pointing at the
    /// chosen head, and clears the freeze flag.
    Resolve(ResolveArgs),
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

/// `resolve` subcommand args.
///
/// Args mirror `publish` for the keystore + vault password resolution
/// (the resolve flow publishes a merge revision through the same
/// adapter), plus two resolve-specific flags:
///
/// - `--account-id <hex>` — 64-char hex (= 32 bytes) of the account
///   the user is resolving. Required.
/// - `--keep <hex>` — 64-char hex of the revision to ratify as the
///   chosen head. Required.
/// - `--yes` — skip the interactive confirmation prompt. Defaults to
///   `false`; default behavior prints the planned action and reads
///   a single character from stdin to gate the on-chain side-effect.
/// - `--dry-run` — print the planned action without publishing or
///   clearing the freeze flag. Defaults to `false`.
#[derive(Debug, Args)]
pub struct ResolveArgs {
    /// Path to the `.pvf` vault file.
    #[arg(long)]
    pub vault_path: PathBuf,

    /// Vault password. If omitted, prompted at the terminal without
    /// echo. Required because resolve needs an unlocked vault to
    /// re-seal the chosen revision's payload under the local VDK.
    #[arg(long)]
    pub vault_password: Option<String>,

    /// 32-byte account identifier as 64-char lowercase hex.
    #[arg(long, value_parser = clap::value_parser!(HexAccountId))]
    pub account_id: HexAccountId,

    /// 32-byte revision identifier as 64-char lowercase hex. The user
    /// is committing to this revision as the new canonical head; the
    /// merge revision the resolve flow publishes will have this
    /// `revision_id` as its `parent_revision`.
    #[arg(long, value_parser = clap::value_parser!(HexRevisionId))]
    pub keep: HexRevisionId,

    /// Foundry keystore name (same resolution as `publish` —
    /// `$FOUNDRY_DIR/keystores/<name>`). Mutually exclusive with
    /// `--keystore-path`.
    #[arg(long, conflicts_with = "keystore_path")]
    pub account: Option<String>,

    /// Override the keystore directory. Useful for tests against a
    /// fixture keystore. Mutually exclusive with `--account`.
    #[arg(long)]
    pub keystore_dir: Option<PathBuf>,

    /// Direct path to a Foundry keystore file. Mutually exclusive
    /// with `--account`.
    #[arg(long, conflicts_with = "account")]
    pub keystore_path: Option<PathBuf>,

    /// Keystore password. Echoes in `ps`; prefer the prompt for
    /// non-CI use. If omitted, prompted at the terminal without echo.
    #[arg(long)]
    pub keystore_password: Option<String>,

    /// Skip the interactive confirmation prompt. Required for
    /// scripted use (CI, MVP-1 host-app integration).
    #[arg(long)]
    pub yes: bool,

    /// Print the planned action without publishing or clearing the
    /// freeze flag. Validates the args and prints the canonical hash
    /// of the merge revision that WOULD be published. Read-only.
    #[arg(long)]
    pub dry_run: bool,
}

/// 32-byte account identifier parsed from a 64-character lowercase
/// hex string. Parsed at clap-arg-validation time so a malformed
/// `--account-id` surfaces before any vault open or chain call.
#[derive(Debug, Clone, Copy)]
pub struct HexAccountId(pub [u8; 32]);

impl core::str::FromStr for HexAccountId {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_32_byte_hex(s, "--account-id").map(Self)
    }
}

/// 32-byte revision identifier parsed from a 64-character lowercase hex string.
///
/// Same shape as `HexAccountId`; kept as a distinct newtype so the
/// call site of `--keep` cannot accidentally swap argument order
/// with `--account-id`.
#[derive(Debug, Clone, Copy)]
pub struct HexRevisionId(pub [u8; 32]);

impl core::str::FromStr for HexRevisionId {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_32_byte_hex(s, "--keep").map(Self)
    }
}

/// Shared parser body. Returns a friendly error message including
/// the flag name so the user knows which argument to fix.
///
/// Per P9 plan §"Open questions for Kelvin" Q3, P9 ships full-hex
/// (no prefix support). The parser refuses any input that does not
/// decode to exactly 32 bytes.
fn parse_32_byte_hex(s: &str, flag: &str) -> Result<[u8; 32], String> {
    if s.len() != 64 {
        return Err(format!(
            "{flag}: expected 64-character hex (32 bytes), got {} characters",
            s.len()
        ));
    }
    if !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("{flag}: contains non-hex characters"));
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        let pair = &s[i * 2..i * 2 + 2];
        out[i] = u8::from_str_radix(pair, 16)
            .map_err(|e| format!("{flag}: hex decode failed at byte {i}: {e}"))?;
    }
    Ok(out)
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

    // -----------------------------------------------------------
    // P9-3: resolve subcommand clap shape
    // -----------------------------------------------------------

    /// **P9-3.** `resolve` parses with the minimum required args
    /// (`--vault-path`, `--account-id`, `--keep`).
    #[test]
    fn resolve_parses_with_minimum_args() {
        // Every byte = 0xAB ⇒ 64 chars of 'a'+'b'+'a'+'b'+...
        let hex = "ab".repeat(32);
        let cli = Cli::try_parse_from([
            "pangolin-cli",
            "resolve",
            "--vault-path",
            "/tmp/v.pvf",
            "--account-id",
            &hex,
            "--keep",
            &hex,
        ])
        .expect("resolve with minimum args parses");
        match cli.command {
            Command::Resolve(args) => {
                assert_eq!(args.account_id.0, [0xAB; 32]);
                assert_eq!(args.keep.0, [0xAB; 32]);
                assert!(!args.yes);
                assert!(!args.dry_run);
            }
            other => panic!("expected Resolve command, got {other:?}"),
        }
    }

    /// **P9-3.** `--account-id` is required.
    #[test]
    fn resolve_requires_account_id() {
        let hex = "00".repeat(32);
        let err = Cli::try_parse_from([
            "pangolin-cli",
            "resolve",
            "--vault-path",
            "/tmp/v.pvf",
            "--keep",
            &hex,
        ])
        .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("--account-id"),
            "expected missing --account-id, got: {msg}"
        );
    }

    /// **P9-3.** `--keep` is required.
    #[test]
    fn resolve_requires_keep() {
        let hex = "00".repeat(32);
        let err = Cli::try_parse_from([
            "pangolin-cli",
            "resolve",
            "--vault-path",
            "/tmp/v.pvf",
            "--account-id",
            &hex,
        ])
        .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("--keep"),
            "expected missing --keep, got: {msg}"
        );
    }

    /// **P9-3.** `--account-id` must be exactly 64 hex chars.
    #[test]
    fn resolve_account_id_must_be_64_hex_chars() {
        // Too short.
        let err = Cli::try_parse_from([
            "pangolin-cli",
            "resolve",
            "--vault-path",
            "/tmp/v.pvf",
            "--account-id",
            "deadbeef",
            "--keep",
            &"aa".repeat(32),
        ])
        .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("64-character hex") || msg.contains("--account-id"),
            "expected length-rejection message, got: {msg}"
        );
    }

    /// **P9-3.** `--keep` must be exactly 64 hex chars.
    #[test]
    fn resolve_keep_must_be_64_hex_chars() {
        let err = Cli::try_parse_from([
            "pangolin-cli",
            "resolve",
            "--vault-path",
            "/tmp/v.pvf",
            "--account-id",
            &"aa".repeat(32),
            "--keep",
            "deadbeef",
        ])
        .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("64-character hex") || msg.contains("--keep"),
            "expected length-rejection message, got: {msg}"
        );
    }

    /// **P9-3.** `--account-id` rejects non-hex input.
    #[test]
    fn resolve_account_id_rejects_non_hex() {
        let mut bad = "z".repeat(64);
        bad.truncate(64);
        let err = Cli::try_parse_from([
            "pangolin-cli",
            "resolve",
            "--vault-path",
            "/tmp/v.pvf",
            "--account-id",
            &bad,
            "--keep",
            &"aa".repeat(32),
        ])
        .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("non-hex") || msg.contains("--account-id"),
            "expected non-hex rejection, got: {msg}"
        );
    }

    /// **P9-3.** `--dry-run` flag is recognised and defaults to false.
    #[test]
    fn resolve_dry_run_flag_parses() {
        let hex = "ab".repeat(32);
        let cli = Cli::try_parse_from([
            "pangolin-cli",
            "resolve",
            "--vault-path",
            "/tmp/v.pvf",
            "--account-id",
            &hex,
            "--keep",
            &hex,
            "--dry-run",
        ])
        .expect("dry-run parses");
        match cli.command {
            Command::Resolve(args) => {
                assert!(args.dry_run);
            }
            _ => panic!("expected Resolve"),
        }
    }

    /// **P9-3.** `--yes` flag is recognised and defaults to false.
    #[test]
    fn resolve_yes_flag_parses() {
        let hex = "ab".repeat(32);
        let cli = Cli::try_parse_from([
            "pangolin-cli",
            "resolve",
            "--vault-path",
            "/tmp/v.pvf",
            "--account-id",
            &hex,
            "--keep",
            &hex,
            "--yes",
        ])
        .expect("--yes parses");
        match cli.command {
            Command::Resolve(args) => {
                assert!(args.yes);
            }
            _ => panic!("expected Resolve"),
        }
    }

    /// **P9-3.** `--account` and `--keystore-path` are mutually
    /// exclusive (same as `publish`).
    #[test]
    fn resolve_account_and_keystore_path_conflict() {
        let hex = "ab".repeat(32);
        let err = Cli::try_parse_from([
            "pangolin-cli",
            "resolve",
            "--vault-path",
            "/tmp/v.pvf",
            "--account-id",
            &hex,
            "--keep",
            &hex,
            "--account",
            "dev",
            "--keystore-path",
            "/tmp/keystore",
        ])
        .unwrap_err();
        assert!(matches!(
            err.kind(),
            clap::error::ErrorKind::ArgumentConflict
        ));
    }

    /// **P8 fix MED-2.** `--allow-insecure-rpc` is recognized as a
    /// global flag and defaults to false.
    #[test]
    fn allow_insecure_rpc_flag_parses() {
        let cli = Cli::try_parse_from([
            "pangolin-cli",
            "--allow-insecure-rpc",
            "status",
            "--vault-path",
            "/tmp/v.pvf",
        ])
        .expect("--allow-insecure-rpc parses");
        assert!(cli.global.allow_insecure_rpc);

        let cli_default =
            Cli::try_parse_from(["pangolin-cli", "status", "--vault-path", "/tmp/v.pvf"])
                .expect("default parses");
        assert!(
            !cli_default.global.allow_insecure_rpc,
            "default is secure (HTTPS-only)"
        );
    }
}
