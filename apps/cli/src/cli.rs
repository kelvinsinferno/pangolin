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

    /// Manage credential entries inside a vault: add, list, show,
    /// update, delete. All operations are local to the vault file;
    /// no chain calls. Use `pangolin-cli publish` to push the
    /// resulting changes on chain.
    Account(AccountArgs),

    /// Manage vault files at the filesystem level: create. The
    /// nested `create` verb provisions a brand-new `.pvf` file at
    /// a user-specified path under a fresh master password. No
    /// chain calls.
    Vault(VaultArgs),

    /// Import credentials from a `KeePass` 2.x `.kdbx` file into an
    /// unlocked vault (MVP-1 issue 1.9). Prompts for the KDBX file's
    /// own password on stderr; an optional `--keyfile` adds a keyfile
    /// to the composite key. Prints the import counts (imported /
    /// skipped / per-category failures) on stdout. No chain calls.
    Import(ImportArgs),
}

/// `import` subcommand args.
#[derive(Debug, Args)]
pub struct ImportArgs {
    /// Path to the destination `.pvf` vault file (must already exist;
    /// the import unlocks it and adds the entries).
    #[arg(long)]
    pub vault_path: PathBuf,

    /// Vault password (echoes in `ps`; CI use only). If omitted,
    /// prompted at the terminal without echo.
    #[arg(long)]
    pub vault_password: Option<String>,

    /// Path to the `.kdbx` file to import.
    #[arg(value_name = "FILE")]
    pub kdbx_path: PathBuf,

    /// Optional keyfile for the `.kdbx` (`KeePass` `.keyx` XML / 32-raw /
    /// 64-hex / arbitrary file — hashed into the composite key).
    #[arg(long)]
    pub keyfile: Option<PathBuf>,

    /// KDBX file password (echoes in `ps`; CI use only). If omitted,
    /// prompted at the terminal without echo.
    #[arg(long)]
    pub kdbx_password: Option<String>,
}

/// `vault` subcommand — wraps the per-verb sub-subcommands.
///
/// Per P11B plan §A1 the verbs live under a nested
/// `pangolin-cli vault <verb>` namespace, mirroring P11A's
/// `account <verb>` shape. `create` is the only verb shipped by
/// P11B; MVP-1 may add `open` / `info` / `destroy` /
/// `rotate-password` / `export` / `import` under the same noun.
#[derive(Debug, Args)]
pub struct VaultArgs {
    #[command(subcommand)]
    pub command: VaultCommand,
}

/// The `vault` sub-subcommands.
#[derive(Debug, Subcommand)]
pub enum VaultCommand {
    /// Create a brand-new vault file at the given path. Prompts
    /// for a fresh master password (with confirmation) or reads
    /// it from stdin when `--password-stdin` is set. Refuses to
    /// overwrite an existing file. Pangolin has no
    /// password-recovery mechanism; loss of this password is
    /// permanent data loss.
    Create(VaultCreateArgs),

    /// Export the vault as a self-contained, portable encrypted
    /// archive (`.pvea`) — the move-to-a-new-device / off-site backup
    /// artifact (MVP-1 issue 1.10). Prompts on stderr for a fresh
    /// export passphrase (independent of the vault master password) and
    /// writes the AEAD-sealed archive to the given output path; warns
    /// (does not block) if zxcvbn rates the passphrase weak. With
    /// `--accounts` only the listed accounts are included (same archive
    /// format). With `--plaintext` the spec-guarded cleartext branch is
    /// selected instead — a double-confirmed, 30-second-delayed,
    /// loudly-warned `.pvtxt` dump that writes every secret in
    /// cleartext.
    Export(VaultExportArgs),

    /// Restore a **brand-new** vault file from an encrypted archive
    /// (`.pvea`) produced by `vault export` (MVP-1 issue 1.10). Prompts
    /// on stderr for the archive passphrase and a fresh master password
    /// for the new vault, decodes the archive, and writes the new `.pvf`
    /// at `--out` (never clobbers an existing file). Does NOT merge into
    /// an existing vault.
    Restore(VaultRestoreArgs),
}

/// `vault export` — write a portable archive of the vault.
#[derive(Debug, Args)]
pub struct VaultExportArgs {
    /// Path to the `.pvf` vault file to export.
    #[arg(long)]
    pub vault_path: PathBuf,

    /// Output path for the archive. `.pvea` is suggested for the
    /// encrypted form, `.pvtxt` for `--plaintext`. The path must not
    /// already exist.
    #[arg(value_name = "OUT_PATH")]
    pub out_path: PathBuf,

    /// Vault password (echoes in `ps`; CI use only). If omitted,
    /// prompted at the terminal without echo.
    #[arg(long)]
    pub vault_password: Option<String>,

    /// Comma-separated list of account ids (64-hex each) to include.
    /// Omit to export the whole vault.
    #[arg(long, value_delimiter = ',')]
    pub accounts: Vec<String>,

    /// Read the export passphrase from the first line of stdin (CI use).
    /// Mutually exclusive with the interactive prompt.
    #[arg(long)]
    pub export_passphrase_stdin: bool,

    /// Select the **dangerous** cleartext-export branch instead of the
    /// default encrypted archive. Guarded behind a typed confirmation +
    /// a 30-second delay + a second y/N prompt + an in-file warning
    /// banner.
    #[arg(long)]
    pub plaintext: bool,

    /// **Test/CI only.** Skip the 30-second `--plaintext` cooling-off
    /// delay. Hidden — never document this in user-facing material.
    #[arg(long, hide = true)]
    pub no_delay: bool,
}

/// `vault restore` — create a fresh `.pvf` from an encrypted archive.
#[derive(Debug, Args)]
pub struct VaultRestoreArgs {
    /// Path to the `.pvea` archive to restore from.
    #[arg(value_name = "ARCHIVE")]
    pub archive_path: PathBuf,

    /// Path where the brand-new vault file will be created. Must not
    /// already exist.
    #[arg(long)]
    pub out: PathBuf,

    /// Read the archive passphrase from the first line of stdin (CI
    /// use). The new vault's master password is then read from the
    /// second stdin line.
    #[arg(long)]
    pub archive_passphrase_stdin: bool,
}

/// `vault create` — provision a fresh `.pvf` at `--path`.
///
/// Password input has two exclusive paths:
///
/// 1. `--password-stdin` — read the first line of stdin as the
///    master password (CI / scripted use). Trailing newline is
///    trimmed. Empty input is rejected.
/// 2. (default) Interactive prompt at the terminal without echo,
///    plus a confirmation re-prompt; aborts on mismatch after a
///    bounded retry budget.
///
/// There is **NO** `--password <flag>` form. The flag form leaks
/// via process listing (`ps aux`) and Pangolin refuses to ship
/// that footgun. The vault password is the master credential for
/// every account stored inside; its leak compromises the entire
/// vault.
///
/// **No password recovery.** Pangolin has no
/// password-recovery mechanism; if you forget this password the
/// vault is unreadable and every account inside it is permanently
/// inaccessible. Choose a password you can remember (or store it
/// in a separate password manager) BEFORE running this command.
#[derive(Debug, Args)]
pub struct VaultCreateArgs {
    /// Filesystem path where the new vault file will be created.
    /// The parent directory must exist; the path itself must not.
    /// Relative paths are resolved against the current working
    /// directory.
    #[arg(long)]
    pub path: PathBuf,

    /// Read the master password from the first line of stdin (CI
    /// / scripted use). Mutually exclusive with the default
    /// interactive prompt.
    #[arg(long)]
    pub password_stdin: bool,

    /// After a successful create, also print the new vault's
    /// 32-byte identifier as a 64-character lowercase hex string
    /// on a second stdout line. Default off (matches `git init`'s
    /// minimal-default convention).
    #[arg(long)]
    pub print_id: bool,
}

/// `account` subcommand — wraps the per-verb sub-subcommands.
///
/// Per P11A plan §A1 the verbs live under a nested
/// `pangolin-cli account <verb>` namespace. The flat verbs
/// (`status`, `publish`, `pull`, `resolve`) stay flat — they are
/// vault-level / chain-level orchestrators and don't share a noun.
#[derive(Debug, Args)]
pub struct AccountArgs {
    #[command(subcommand)]
    pub command: AccountCommand,
}

/// The five `account` sub-subcommands.
#[derive(Debug, Subcommand)]
pub enum AccountCommand {
    /// Add a new credential entry. Generates a fresh per-row
    /// identifier, seals the credential under the vault key, marks
    /// the new entry for the next publish run.
    Add(AccountAddArgs),

    /// List the credential entries in the vault. Default: active
    /// entries only (no frozen, no deleted). Optional flags surface
    /// frozen / deleted entries with a status suffix. Never emits
    /// secret fields.
    List(AccountListArgs),

    /// Display one credential entry. Default: identifier fields
    /// only (name, username, URL). Pass `--reveal-password`,
    /// `--reveal-notes`, or `--reveal-totp-secret` to print the
    /// corresponding secret to stdout; each requires a presence
    /// confirmation prompt.
    Show(AccountShowArgs),

    /// Modify an existing credential entry. Field flags are
    /// optional; unspecified fields are preserved unchanged.
    Update(AccountUpdateArgs),

    /// Delete a credential entry. Writes a tombstone revision
    /// (append-only — the entry is no longer readable but its
    /// historical record is preserved).
    Delete(AccountDeleteArgs),
}

/// `account add` — create a new credential entry.
///
/// Password input has three exclusive paths:
///
/// 1. `--generate-password` — auto-generate a 16-char password via
///    the library generator (`pangolin_core::pwgen`, strong
///    defaults: mixed case + digits + ASCII symbols, ambiguous
///    chars excluded, unbiased CSPRNG draws). The generated value
///    is printed to stderr inside a clearly-flagged save-this-now
///    block; copy it into the user's preferred password store.
/// 2. `--password-stdin` — read the first line of stdin as the
///    password (CI / scripted use). Trailing newline is trimmed.
/// 3. (default) Interactive prompt at the terminal without echo,
///    plus a confirmation re-prompt; aborts on mismatch after
///    bounded retry.
///
/// There is **NO** `--password <flag>` form. The flag form leaks
/// via process listing (`ps aux`) and Pangolin refuses to ship
/// that footgun. Same discipline applies to `--totp-stdin`
/// (`--totp-secret <flag>` is not accepted).
///
/// Notes accept the flag form `--notes <str>` because notes are a
/// lower-tier secret per the spec's reveal hierarchy; users who
/// want to avoid shell-history capture should use `--notes-stdin`.
#[allow(clippy::struct_excessive_bools)]
// The clap-derive args struct
// collects independent boolean flags by design; refactoring
// into a state machine would obscure the user-facing surface.
#[derive(Debug, Args)]
pub struct AccountAddArgs {
    /// Path to the `.pvf` vault file.
    #[arg(long)]
    pub vault_path: PathBuf,

    /// Vault password (echoes in `ps`; CI use only). If omitted,
    /// prompted at the terminal without echo.
    #[arg(long)]
    pub vault_password: Option<String>,

    /// Display name for the new entry. Required. Must be
    /// non-empty.
    #[arg(long, value_parser = parse_non_empty_string)]
    pub name: String,

    /// Login username for the new entry.
    #[arg(long)]
    pub username: Option<String>,

    /// Service URL the credential applies to.
    #[arg(long)]
    pub url: Option<String>,

    /// Free-form notes. Lower-tier secret per the reveal-class
    /// hierarchy; users running interactively should prefer
    /// `--notes-stdin`.
    #[arg(long, conflicts_with = "notes_stdin")]
    pub notes: Option<String>,

    /// Read notes from stdin. Recommended for multi-line notes or
    /// notes containing shell-special characters.
    #[arg(long, conflicts_with = "notes")]
    pub notes_stdin: bool,

    /// Read the password from stdin (CI / scripted use).
    /// Mutually exclusive with `--generate-password`.
    #[arg(long, conflicts_with = "generate_password")]
    pub password_stdin: bool,

    /// Auto-generate a 16-character password via the library
    /// generator (strong defaults: mixed case + digits + ASCII
    /// symbols, ambiguous chars excluded). The generated value is
    /// printed to stderr inside a save-this-now block. Mutually
    /// exclusive with `--password-stdin`.
    #[arg(long, conflicts_with = "password_stdin")]
    pub generate_password: bool,

    /// Read the TOTP shared secret from stdin (interactive
    /// prompt is the default when this flag is absent and the
    /// user has not specified `--no-totp`).
    #[arg(long)]
    pub totp_stdin: bool,

    /// Skip the TOTP prompt — create the entry without a TOTP
    /// secret. The entry can still be updated later to add one.
    #[arg(long, conflicts_with = "totp_stdin")]
    pub no_totp: bool,
}

/// `account list` — list credential entries.
#[derive(Debug, Args)]
pub struct AccountListArgs {
    /// Path to the `.pvf` vault file.
    #[arg(long)]
    pub vault_path: PathBuf,

    /// Vault password (echoes in `ps`; CI use only). If omitted,
    /// prompted at the terminal without echo.
    #[arg(long)]
    pub vault_password: Option<String>,

    /// Include entries that are frozen pending resolve. Each is
    /// suffixed with `[frozen]` in the human-readable output.
    #[arg(long)]
    pub include_frozen: bool,

    /// Include entries that have been deleted (tombstoned). Each
    /// is suffixed with `[deleted]` in the human-readable output.
    #[arg(long)]
    pub include_tombstoned: bool,
}

/// `account show` — display one credential entry.
///
/// Default behavior prints the identifier fields (display name,
/// username, URL) to stdout; secret fields are omitted. The three
/// `--reveal-*` flags opt into printing the corresponding secret;
/// each is gated by a presence-confirmation prompt before the
/// reveal call fires (per the spec's high-risk-action discipline).
///
/// Multiple `--reveal-*` flags in one invocation share a single
/// presence prompt — one user gesture authorizes the bundle.
#[derive(Debug, Args)]
pub struct AccountShowArgs {
    /// Path to the `.pvf` vault file.
    #[arg(long)]
    pub vault_path: PathBuf,

    /// Vault password (echoes in `ps`; CI use only). If omitted,
    /// prompted at the terminal without echo.
    #[arg(long)]
    pub vault_password: Option<String>,

    /// 32-byte account identifier as 64-char lowercase hex.
    #[arg(long, value_parser = clap::value_parser!(HexAccountId))]
    pub account_id: HexAccountId,

    /// Print the password to stdout. Presence-gated; the user
    /// must confirm at the prompt before any reveal call fires.
    #[arg(long)]
    pub reveal_password: bool,

    /// Print the notes to stdout. Same presence gate as
    /// `--reveal-password`.
    #[arg(long)]
    pub reveal_notes: bool,

    /// Print the TOTP shared secret to stdout. Same presence
    /// gate as `--reveal-password`.
    #[arg(long)]
    pub reveal_totp_secret: bool,
}

/// `account update` — modify an existing credential entry.
///
/// Field flags are all optional. Unspecified fields are
/// preserved by reading the current entry, layering the
/// specified updates on top, and writing a new revision pointing
/// at the previous head. **The implementation reveals every
/// secret field of the entry** (password, notes, TOTP) so it can
/// build a complete new snapshot — even if the user only changes
/// a non-secret field. As a consequence, `account update` is
/// always presence-gated. (`PoC` limitation; a future partial-
/// update API would skip the reveal calls for unspecified
/// fields.)
#[allow(clippy::struct_excessive_bools)] // Same rationale as
// AccountAddArgs — clap-derive shape mirrors the user surface.
#[derive(Debug, Args)]
pub struct AccountUpdateArgs {
    /// Path to the `.pvf` vault file.
    #[arg(long)]
    pub vault_path: PathBuf,

    /// Vault password (echoes in `ps`; CI use only). If omitted,
    /// prompted at the terminal without echo.
    #[arg(long)]
    pub vault_password: Option<String>,

    /// 32-byte account identifier as 64-char lowercase hex.
    #[arg(long, value_parser = clap::value_parser!(HexAccountId))]
    pub account_id: HexAccountId,

    /// New display name. Must be non-empty if specified.
    #[arg(long, value_parser = parse_non_empty_string)]
    pub name: Option<String>,

    /// New login username.
    #[arg(long)]
    pub username: Option<String>,

    /// New service URL.
    #[arg(long)]
    pub url: Option<String>,

    /// New free-form notes. Mutually exclusive with
    /// `--notes-stdin`.
    #[arg(long, conflicts_with = "notes_stdin")]
    pub notes: Option<String>,

    /// Read new notes from stdin. Mutually exclusive with
    /// `--notes`.
    #[arg(long, conflicts_with = "notes")]
    pub notes_stdin: bool,

    /// Read a new password from stdin (CI / scripted use).
    /// Mutually exclusive with `--password-prompt`.
    #[arg(long, conflicts_with = "password_prompt")]
    pub password_stdin: bool,

    /// Prompt at the terminal for a new password (interactive
    /// use). Disambiguates "I want to change the password" from
    /// "I left the password unchanged" — no flag means no
    /// password change. Mutually exclusive with
    /// `--password-stdin`.
    #[arg(long, conflicts_with = "password_stdin")]
    pub password_prompt: bool,

    /// Read a new TOTP secret from stdin. Mutually exclusive
    /// with `--totp-clear`.
    #[arg(long, conflicts_with = "totp_clear")]
    pub totp_stdin: bool,

    /// Clear the entry's TOTP secret (set it to empty). Mutually
    /// exclusive with `--totp-stdin`.
    #[arg(long, conflicts_with = "totp_stdin")]
    pub totp_clear: bool,
}

/// `account delete` — tombstone a credential entry.
///
/// Default behavior loads the entry, prints a confirmation
/// prompt that includes the display name (typo-prevention), and
/// reads a literal lowercase `"yes"` from stdin before writing
/// the tombstone. `--yes` skips the prompt for scripted use.
#[derive(Debug, Args)]
pub struct AccountDeleteArgs {
    /// Path to the `.pvf` vault file.
    #[arg(long)]
    pub vault_path: PathBuf,

    /// Vault password (echoes in `ps`; CI use only). If omitted,
    /// prompted at the terminal without echo.
    #[arg(long)]
    pub vault_password: Option<String>,

    /// 32-byte account identifier as 64-char lowercase hex.
    #[arg(long, value_parser = clap::value_parser!(HexAccountId))]
    pub account_id: HexAccountId,

    /// Skip the interactive confirmation prompt. Required for
    /// scripted / CI use. Without this flag, the user must type
    /// the literal lowercase string `"yes"` at the prompt.
    #[arg(long)]
    pub yes: bool,

    /// Optional free-form note. NOT cryptographically stored —
    /// only echoed in the eprintln summary line and in the JSON
    /// summary output. Useful for ad-hoc audit traces.
    #[arg(long)]
    pub why: Option<String>,
}

/// Reject empty strings at clap-arg-validation time. Used by the
/// `--name` flag on `account add` and `account update` so a
/// caller passing `--name ""` surfaces a clear error before any
/// vault open or session unlock fires.
fn parse_non_empty_string(s: &str) -> Result<String, String> {
    if s.is_empty() {
        return Err("must not be empty".to_string());
    }
    Ok(s.to_string())
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

    // -----------------------------------------------------------
    // P11A-1: account subcommand clap shape
    // -----------------------------------------------------------

    /// **P11A-1.** `account --help` renders.
    #[test]
    fn account_subcommand_parses_with_help() {
        let err = Cli::try_parse_from(["pangolin-cli", "account", "--help"]).unwrap_err();
        assert!(matches!(err.kind(), clap::error::ErrorKind::DisplayHelp));
    }

    /// **P11A-1.** `account add --vault-path <path> --name <str>`
    /// parses cleanly with the minimum required args.
    #[test]
    fn account_add_parses_with_name() {
        let cli = Cli::try_parse_from([
            "pangolin-cli",
            "account",
            "add",
            "--vault-path",
            "/tmp/v.pvf",
            "--name",
            "github work",
        ])
        .expect("account add parses");
        match cli.command {
            super::Command::Account(args) => match args.command {
                super::AccountCommand::Add(a) => {
                    assert_eq!(a.name, "github work");
                    assert!(a.username.is_none());
                    assert!(!a.password_stdin);
                    assert!(!a.generate_password);
                    assert!(!a.no_totp);
                }
                other => panic!("expected Add, got {other:?}"),
            },
            other => panic!("expected Account, got {other:?}"),
        }
    }

    /// **P11A-1.** `--name ""` is rejected at clap-arg-validation
    /// time. P11A-2 plan §A2 anti-empty-name guard.
    #[test]
    fn account_add_rejects_empty_name() {
        let err = Cli::try_parse_from([
            "pangolin-cli",
            "account",
            "add",
            "--vault-path",
            "/tmp/v.pvf",
            "--name",
            "",
        ])
        .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("must not be empty") || msg.contains("--name"),
            "expected empty-name rejection, got: {msg}"
        );
    }

    /// **P11A-1.** `account list --vault-path` parses.
    #[test]
    fn account_list_parses_with_vault_path() {
        let cli = Cli::try_parse_from([
            "pangolin-cli",
            "account",
            "list",
            "--vault-path",
            "/tmp/v.pvf",
        ])
        .expect("account list parses");
        match cli.command {
            super::Command::Account(args) => match args.command {
                super::AccountCommand::List(l) => {
                    assert!(!l.include_frozen);
                    assert!(!l.include_tombstoned);
                }
                _ => panic!("expected List"),
            },
            _ => panic!("expected Account"),
        }
    }

    /// **P11A-1.** `account show --account-id <hex>` parses.
    #[test]
    fn account_show_parses_with_account_id() {
        let hex = "ab".repeat(32);
        let cli = Cli::try_parse_from([
            "pangolin-cli",
            "account",
            "show",
            "--vault-path",
            "/tmp/v.pvf",
            "--account-id",
            &hex,
        ])
        .expect("account show parses");
        match cli.command {
            super::Command::Account(args) => match args.command {
                super::AccountCommand::Show(s) => {
                    assert_eq!(s.account_id.0, [0xAB; 32]);
                    assert!(!s.reveal_password);
                    assert!(!s.reveal_notes);
                    assert!(!s.reveal_totp_secret);
                }
                _ => panic!("expected Show"),
            },
            _ => panic!("expected Account"),
        }
    }

    /// **P11A-1.** `account update --account-id <hex>` parses.
    #[test]
    fn account_update_parses_with_account_id() {
        let hex = "12".repeat(32);
        let cli = Cli::try_parse_from([
            "pangolin-cli",
            "account",
            "update",
            "--vault-path",
            "/tmp/v.pvf",
            "--account-id",
            &hex,
            "--name",
            "renamed",
        ])
        .expect("account update parses");
        match cli.command {
            super::Command::Account(args) => match args.command {
                super::AccountCommand::Update(u) => {
                    assert_eq!(u.account_id.0, [0x12; 32]);
                    assert_eq!(u.name.as_deref(), Some("renamed"));
                }
                _ => panic!("expected Update"),
            },
            _ => panic!("expected Account"),
        }
    }

    /// **P11A-1.** `account delete --account-id <hex> --yes`
    /// parses.
    #[test]
    fn account_delete_parses_with_account_id_and_yes() {
        let hex = "cd".repeat(32);
        let cli = Cli::try_parse_from([
            "pangolin-cli",
            "account",
            "delete",
            "--vault-path",
            "/tmp/v.pvf",
            "--account-id",
            &hex,
            "--yes",
        ])
        .expect("account delete parses");
        match cli.command {
            super::Command::Account(args) => match args.command {
                super::AccountCommand::Delete(d) => {
                    assert_eq!(d.account_id.0, [0xCD; 32]);
                    assert!(d.yes);
                }
                _ => panic!("expected Delete"),
            },
            _ => panic!("expected Account"),
        }
    }

    /// **P11A-1.** `account add --password-stdin --generate-password`
    /// is rejected as a flag conflict (only one password-source
    /// path is allowed per invocation).
    #[test]
    fn account_add_password_stdin_and_generate_conflict() {
        let err = Cli::try_parse_from([
            "pangolin-cli",
            "account",
            "add",
            "--vault-path",
            "/tmp/v.pvf",
            "--name",
            "x",
            "--password-stdin",
            "--generate-password",
        ])
        .unwrap_err();
        assert!(matches!(
            err.kind(),
            clap::error::ErrorKind::ArgumentConflict
        ));
    }

    /// **P11A-1.** `account add --notes "..." --notes-stdin` is
    /// rejected (mutually exclusive notes-source flags).
    #[test]
    fn account_add_notes_and_notes_stdin_conflict() {
        let err = Cli::try_parse_from([
            "pangolin-cli",
            "account",
            "add",
            "--vault-path",
            "/tmp/v.pvf",
            "--name",
            "x",
            "--notes",
            "n",
            "--notes-stdin",
        ])
        .unwrap_err();
        assert!(matches!(
            err.kind(),
            clap::error::ErrorKind::ArgumentConflict
        ));
    }

    /// **P11A-1 / A16.** The rendered help for `account` and each
    /// of the five sub-verbs MUST NOT contain any of the §3.5
    /// forbidden user-facing terms ("blockchain", "gas",
    /// "transaction", "decentralized storage", "hashes",
    /// "revisions"). The clap-derive `--help` output is the
    /// audit-relevant surface.
    #[test]
    fn account_help_avoids_forbidden_user_facing_terms() {
        use clap::CommandFactory as _;
        let mut cmd = super::Cli::command();
        // Force clap to fully build subcommand help.
        cmd.build();
        // Render `account --help`.
        let account_subcmd = cmd
            .find_subcommand_mut("account")
            .expect("account subcommand exists");
        let mut buf = Vec::new();
        account_subcmd
            .write_help(&mut buf)
            .expect("write_help succeeds");
        let account_help = String::from_utf8(buf).expect("help is utf8");
        let forbidden = [
            "blockchain",
            "decentralized storage",
            // Surface-only check: `gas`/`transaction` would
            // appear in any help text that names those concepts;
            // enforce via case-sensitive substring.
            "gas ",
            " gas",
            "transaction",
            // "hashes" and "revisions" are spec-internal terms;
            // the user-facing help must avoid them.
            "hashes",
            "revisions",
        ];
        for term in forbidden {
            assert!(
                !account_help.to_lowercase().contains(term),
                "account --help contains forbidden term '{term}': {account_help}"
            );
        }
        // Also walk per-verb help.
        let verbs = ["add", "list", "show", "update", "delete"];
        for verb in verbs {
            let mut buf = Vec::new();
            let sub = account_subcmd
                .find_subcommand_mut(verb)
                .unwrap_or_else(|| panic!("subcommand {verb} exists"));
            sub.write_help(&mut buf).expect("write_help");
            let h = String::from_utf8(buf).expect("utf8");
            for term in forbidden {
                assert!(
                    !h.to_lowercase().contains(term),
                    "account {verb} --help contains forbidden term '{term}': {h}"
                );
            }
        }
    }

    // -----------------------------------------------------------
    // P11B-1: vault subcommand clap shape
    // -----------------------------------------------------------

    /// **P11B-1.** `vault --help` renders.
    #[test]
    fn vault_subcommand_parses_with_help() {
        let err = Cli::try_parse_from(["pangolin-cli", "vault", "--help"]).unwrap_err();
        assert!(matches!(err.kind(), clap::error::ErrorKind::DisplayHelp));
    }

    /// **P11B-1.** `vault create --path <path>` parses cleanly.
    #[test]
    fn vault_create_parses_with_path() {
        let cli =
            Cli::try_parse_from(["pangolin-cli", "vault", "create", "--path", "/tmp/new.pvf"])
                .expect("vault create parses");
        match cli.command {
            super::Command::Vault(args) => match args.command {
                super::VaultCommand::Create(c) => {
                    assert_eq!(c.path, std::path::PathBuf::from("/tmp/new.pvf"));
                    assert!(!c.password_stdin);
                    assert!(!c.print_id);
                }
                other => panic!("expected Create, got {other:?}"),
            },
            other => panic!("expected Vault, got {other:?}"),
        }
    }

    /// **P11B-1.** `vault create` requires `--path`.
    #[test]
    fn vault_create_path_is_required() {
        let err = Cli::try_parse_from(["pangolin-cli", "vault", "create"]).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("--path"),
            "expected missing --path, got: {msg}"
        );
    }

    /// **P11B-1 / A7.** `--print-id` flag is recognised and
    /// defaults to false.
    #[test]
    fn vault_create_print_id_flag_parses() {
        let cli = Cli::try_parse_from([
            "pangolin-cli",
            "vault",
            "create",
            "--path",
            "/tmp/new.pvf",
            "--print-id",
        ])
        .expect("--print-id parses");
        match cli.command {
            super::Command::Vault(args) => match args.command {
                super::VaultCommand::Create(c) => assert!(c.print_id),
                other => panic!("expected Create, got {other:?}"),
            },
            _ => panic!("expected Vault"),
        }
    }

    /// **P11B-1 / A2.** `--password-stdin` flag is recognised and
    /// defaults to false.
    #[test]
    fn vault_create_password_stdin_flag_parses() {
        let cli = Cli::try_parse_from([
            "pangolin-cli",
            "vault",
            "create",
            "--path",
            "/tmp/new.pvf",
            "--password-stdin",
        ])
        .expect("--password-stdin parses");
        match cli.command {
            super::Command::Vault(args) => match args.command {
                super::VaultCommand::Create(c) => assert!(c.password_stdin),
                other => panic!("expected Create, got {other:?}"),
            },
            _ => panic!("expected Vault"),
        }
    }

    /// **P11B-1 / A2.** There is NO `--password <flag>` form.
    /// Passing `--password ...` to `vault create` is rejected by
    /// clap with an "unexpected argument" error. Locks in the
    /// "no flag form for the vault password" discipline at the
    /// CLI surface (process-listing leak defense per §A2 + plan
    /// open question §3).
    #[test]
    fn vault_create_does_not_accept_password_flag() {
        let err = Cli::try_parse_from([
            "pangolin-cli",
            "vault",
            "create",
            "--path",
            "/tmp/new.pvf",
            "--password",
            "hunter2",
        ])
        .unwrap_err();
        // clap surfaces the unknown-arg error via UnknownArgument
        // (or InvalidValue depending on version); either way the
        // err message MUST mention `--password`.
        let msg = err.to_string();
        assert!(
            msg.contains("--password"),
            "expected unknown --password arg rejection, got: {msg}"
        );
    }

    /// **P11B-1 / A14.** The rendered help for `vault` and the
    /// `create` sub-verb MUST NOT contain any of the §3.5
    /// forbidden user-facing terms ("blockchain", "gas",
    /// "transaction", "decentralized storage", "hashes",
    /// "revisions"). Same audit gate as
    /// `account_help_avoids_forbidden_user_facing_terms`.
    #[test]
    fn vault_help_avoids_forbidden_user_facing_terms() {
        use clap::CommandFactory as _;
        let mut cmd = super::Cli::command();
        cmd.build();
        let vault_subcmd = cmd
            .find_subcommand_mut("vault")
            .expect("vault subcommand exists");
        let mut buf = Vec::new();
        vault_subcmd
            .write_help(&mut buf)
            .expect("write_help succeeds");
        let vault_help = String::from_utf8(buf).expect("help is utf8");
        let forbidden = [
            "blockchain",
            "decentralized storage",
            "gas ",
            " gas",
            "transaction",
            "hashes",
            "revisions",
        ];
        for term in forbidden {
            assert!(
                !vault_help.to_lowercase().contains(term),
                "vault --help contains forbidden term '{term}': {vault_help}"
            );
        }
        // Walk the per-verb help.
        let verbs = ["create"];
        for verb in verbs {
            let mut buf = Vec::new();
            let sub = vault_subcmd
                .find_subcommand_mut(verb)
                .unwrap_or_else(|| panic!("subcommand {verb} exists"));
            sub.write_help(&mut buf).expect("write_help");
            let h = String::from_utf8(buf).expect("utf8");
            for term in forbidden {
                assert!(
                    !h.to_lowercase().contains(term),
                    "vault {verb} --help contains forbidden term '{term}': {h}"
                );
            }
        }
    }

    /// **P11B-1 / Q5.** `vault create --help` includes the
    /// no-recovery warning explicitly. The warning is the
    /// load-bearing UX defense against "I forgot my master
    /// password" data loss.
    #[test]
    fn vault_create_help_warns_no_password_recovery() {
        use clap::CommandFactory as _;
        let mut cmd = super::Cli::command();
        cmd.build();
        let vault_subcmd = cmd
            .find_subcommand_mut("vault")
            .expect("vault subcommand exists");
        let create_subcmd = vault_subcmd
            .find_subcommand_mut("create")
            .expect("create sub-verb exists");
        let mut buf = Vec::new();
        create_subcmd.write_help(&mut buf).expect("write_help");
        let help = String::from_utf8(buf).expect("utf8");
        let lower = help.to_lowercase();
        // The plan-locked Q5 wording is "no
        // password-recovery mechanism; loss of this password is
        // permanent data loss". We assert two grep-able
        // substrings rather than the full sentence so a future
        // copy edit (e.g., reordered clauses) does not break the
        // test as long as the load-bearing concept survives.
        assert!(
            lower.contains("no password-recovery") || lower.contains("no password recovery"),
            "expected 'no password-recovery' phrase in help, got: {help}"
        );
        assert!(
            lower.contains("permanent data loss")
                || lower.contains("vault is unreadable")
                || lower.contains("vault is unrecoverable")
                || lower.contains("permanently inaccessible"),
            "expected data-loss warning in help, got: {help}"
        );
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
