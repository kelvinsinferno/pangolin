//! `pangolin-cli` — user-facing `PoC` sync orchestrator.
//!
//! Drives `publish` + `pull` + `status` against a local vault and the
//! deployed `RevisionLogV0` (D-014). See `docs/issue-plans/P8.md` for
//! the full design.
//!
//! ## Subcommands
//!
//! - `pangolin-cli status --vault-path <path>` — read-only diagnostics
//!   (dirty count, account count, last-pulled-block, last-published-
//!   block, head count per account). Does NOT make any chain calls.
//! - `pangolin-cli publish --vault-path <path> [--rpc-url <url>]
//!   [--account <name> | --keystore-path <path>]` — walk the dirty
//!   list, sign each revision with the vault's device key, submit to
//!   chain, and clear the dirty marker on success. Per-account
//!   error isolation; A3 pre-publish check guards against duplicate
//!   publish after a partial-failure re-run.
//! - `pangolin-cli pull --vault-path <path> [--rpc-url <url>]` —
//!   incremental chunked pull from `last_pulled_block`; verifies every
//!   event's signature before persisting; surfaces forks (does not
//!   auto-resolve them — that's P9).
//!
//! ## Two-key model (P8 `PoC` deviation from D-006)
//!
//! Per P8 plan §A7 and Kelvin's Q4 answer, `pangolin-cli publish` uses
//! the same two-key model as `chaincli publish`:
//!
//! - **Gas-paying secp256k1 wallet** — Foundry keystore (`--account`).
//! - **Revision-signing Ed25519 key** — vault's `DeviceKey` (P3).
//!
//! D-006 mandates a single-key model where the device's keypair is
//! both signer and gas payer; `evm::derive_evm_wallet` (P7) implements
//! that derivation. MVP-1 will switch to the derived wallet (one-line
//! change in `commands/publish.rs`); the `PoC` stays on the funded-
//! keystore strategy because the dev's existing Coinbase Base Sepolia
//! faucet drips into the keystore address, not the derived address.

#![cfg_attr(not(test), forbid(unsafe_code))]
#![cfg_attr(test, deny(unsafe_code))]

use anyhow::Result;
use clap::Parser;

// Route everything through the library entry point. The binary is
// the orchestration shell; the library is what integration tests
// import.
use pangolin_cli::cli;
use pangolin_cli::commands;

fn main() -> Result<()> {
    let args = cli::Cli::parse();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        match args.command {
            cli::Command::Status(sub) => commands::status::run(&args.global, sub).await,
            cli::Command::Publish(sub) => commands::publish::run(&args.global, sub).await,
            cli::Command::Pull(sub) => commands::pull::run(&args.global, sub).await,
        }
    })
}
