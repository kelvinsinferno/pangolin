//! `pangolin-cli vault` — vault-file management subcommands.
//!
//! Currently ships exactly one verb (`create`) per P11B plan §A1.
//! MVP-1 may add `open` / `info` / `destroy` / `rotate-password` /
//! `export` / `import` under the same noun namespace.
//!
//! ## Design notes (P11B plan §A1..§A14)
//!
//! - **Nested noun-then-verb hierarchy** (§A1) — `vault create`,
//!   not flat `create-vault`. Mirrors `account <verb>`.
//! - **Password input** (§A2) — never via `--password <flag>`. Two
//!   exclusive paths: `--password-stdin` or interactive prompt
//!   with confirmation. Reuses the password-input helpers from
//!   `commands/account.rs` per §A4.
//! - **Path canonicalization** (§A5) — canonicalize the parent
//!   directory; do NOT canonicalize the (non-existent) target.
//! - **Path-overwrite refusal** (§A3) — pre-flight `path.exists()`
//!   at the CLI boundary plus the library-side guard.
//! - **POSIX file-mode hardening** (Q4) — chmod 0600 on Unix.
//!
//! ## P11B-1 vs. P11B-2 split
//!
//! P11B-1 ships the clap scaffold (in `cli.rs`) plus this dispatch
//! module with a stubbed `run_create` that returns
//! `bail!("not implemented yet")`. P11B-2 fleshes out the body
//! and ships the per-create unit tests + integration test.

use anyhow::{bail, Result};

use crate::cli::{GlobalArgs, VaultArgs, VaultCommand, VaultCreateArgs};

/// Top-level dispatch for `pangolin-cli vault <verb>`.
#[allow(clippy::unused_async)]
pub async fn run(global: &GlobalArgs, args: VaultArgs) -> Result<()> {
    match args.command {
        VaultCommand::Create(sub) => run_create(global, sub).await,
    }
}

/// Run the `vault create` subcommand. P11B-1 stub — P11B-2 will
/// replace this with the canonicalize-parent + password-acquire +
/// `Vault::create` + chmod-0600 + close + print pipeline.
#[allow(clippy::unused_async)]
async fn run_create(_global: &GlobalArgs, _args: VaultCreateArgs) -> Result<()> {
    bail!(
        "vault create: not implemented yet (P11B-1 scaffold; P11B-2 will land the implementation)"
    )
}
