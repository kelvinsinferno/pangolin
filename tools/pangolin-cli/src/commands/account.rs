//! `pangolin-cli account` — credential-entry management subcommands.
//!
//! Five verbs (`add`, `list`, `show`, `update`, `delete`) expose the
//! library's account-management API at the CLI boundary. All are
//! local-vault-only — no chain calls. The credential changes accumulate
//! as dirty entries; the user runs `pangolin-cli publish` to push
//! them on chain.
//!
//! ## Design notes (P11A plan §A1..§A16)
//!
//! - **Nested noun-then-verb hierarchy** (§A1) — `account add` /
//!   `account list` / etc., not flat `add-account`.
//! - **Password input** (§A3) — never via `--password <flag>`. Three
//!   exclusive paths: `--generate-password`, `--password-stdin`, or
//!   interactive prompt with confirmation.
//! - **TOTP input** (§A4) — same shape as password.
//! - **Notes input** (§A5) — `--notes <str>` is permitted because
//!   notes are a lower-tier secret per the reveal-class hierarchy;
//!   `--notes-stdin` is the recommended path for sensitive notes.
//! - **`update` partial-update presence escalation** (§A6) — the
//!   library API requires a complete snapshot; the CLI reveals
//!   every secret field of the entry to construct it. `update` is
//!   therefore always presence-gated even if the user only changes
//!   a non-secret field.
//! - **One-prompt-N-proof discipline** (§A7) — multiple `--reveal-*`
//!   flags share a single presence prompt, materialising N internal
//!   `PressYPresenceProof::confirmed()` instances.
//! - **Anti-resurrection** (§A4 in P10's plan, inherited unchanged) —
//!   `Vault::add_account` refuses to reuse a tombstoned id; the CLI
//!   forwards the resulting error.
//! - **Forbidden user-facing terms** (§A16) — the `--help` output
//!   uses "credential" / "account" / "password" / "vault" /
//!   "delete" / "reveal" terms exclusively. Internal doc-comments
//!   may use the Pangolin-internal terms (revision, tombstone,
//!   AEAD); the audit gate is the rendered help / printed strings.
//!
//! ## File-layout note (P11A-1 only)
//!
//! P11A-1 ships the clap scaffold + a per-verb `run_*` stub. Each
//! stub returns `bail!("not implemented yet")`. The real
//! implementations land in P11A-2..P11A-5.

use anyhow::{bail, Result};

use crate::cli::{
    AccountAddArgs, AccountArgs, AccountCommand, AccountDeleteArgs, AccountListArgs,
    AccountShowArgs, AccountUpdateArgs, GlobalArgs,
};

/// Top-level dispatch for `pangolin-cli account <verb>`.
#[allow(clippy::unused_async)]
pub async fn run(global: &GlobalArgs, args: AccountArgs) -> Result<()> {
    match args.command {
        AccountCommand::Add(sub) => run_add(global, sub).await,
        AccountCommand::List(sub) => run_list(global, sub).await,
        AccountCommand::Show(sub) => run_show(global, sub).await,
        AccountCommand::Update(sub) => run_update(global, sub).await,
        AccountCommand::Delete(sub) => run_delete(global, sub).await,
    }
}

#[allow(clippy::unused_async)]
async fn run_add(_global: &GlobalArgs, _args: AccountAddArgs) -> Result<()> {
    bail!("account add: not implemented yet (P11A-2)");
}

#[allow(clippy::unused_async)]
async fn run_list(_global: &GlobalArgs, _args: AccountListArgs) -> Result<()> {
    bail!("account list: not implemented yet (P11A-3)");
}

#[allow(clippy::unused_async)]
async fn run_show(_global: &GlobalArgs, _args: AccountShowArgs) -> Result<()> {
    bail!("account show: not implemented yet (P11A-3)");
}

#[allow(clippy::unused_async)]
async fn run_update(_global: &GlobalArgs, _args: AccountUpdateArgs) -> Result<()> {
    bail!("account update: not implemented yet (P11A-4)");
}

#[allow(clippy::unused_async)]
async fn run_delete(_global: &GlobalArgs, _args: AccountDeleteArgs) -> Result<()> {
    bail!("account delete: not implemented yet (P11A-5)");
}
