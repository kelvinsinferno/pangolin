// SPDX-License-Identifier: AGPL-3.0-or-later
//! `pangolin-cli top-up` — request a top-up from the funder service.
//!
//! Reads a Credit attestation from a JSON file (the off-chain
//! billing service emits this payload), constructs the
//! device-binding signature via the vault's per-device wallet, and
//! POSTs to the funder. Records the `TopUpAttempt` on stdout
//! (or in JSON form with `--json`).
//!
//! Chain-touching command per R-h: graceful exit uses
//! `Vault::close` here because `lock_with_drain` requires a
//! `ChainAdapter` we don't construct in this path (no
//! `BaseSepoliaAdapter` needed for the funder request — the funder
//! talks to chain, not the CLI directly). The publish queue is NOT
//! drained by `top-up`; the user runs `pangolin sync flush` after
//! the top-up settles.

#![forbid(unsafe_code)]

use std::io::IsTerminal;
use std::io::Write as _;
use std::path::Path;

use alloy::primitives::{B256, U256};
use anyhow::{bail, Context, Result};
use pangolin_funder_client::{initiate_top_up, Credit};

use crate::cli::{GlobalArgs, TopUpArgs};
use crate::config::ResolvedConfig;
use crate::vault_open::open_and_unlock;

/// Run `top-up`.
#[allow(clippy::too_many_lines)]
pub async fn run(global: &GlobalArgs, args: TopUpArgs) -> Result<()> {
    let cfg = ResolvedConfig::from_args(global)?;

    let credit = read_credit_file(&args.credit_file)?;

    let vault = open_and_unlock(&args.vault_path, args.vault_password.as_deref())
        .context("vault open + unlock failed")?;

    // Confirmation prompt (skipped with --yes or non-TTY where
    // --yes is REQUIRED). L-top-up-rebroadcast-on-retry mitigation:
    // the funder dedups on `attestation_hash`, but we still gate
    // the call behind a user gesture so a typo'd retry surfaces.
    if !args.yes {
        if !std::io::stdin().is_terminal() {
            bail!(
                "non-TTY context: pass --yes to confirm the top-up request \
                 (avoids unintended duplicate funder calls)"
            );
        }
        eprintln!(
            "top-up: submitting credit (nonce={}, schema_version={}) to {}",
            credit.nonce, credit.schema_version, args.funder_url
        );
        eprint!("proceed? [y/N]: ");
        std::io::stderr().flush().ok();
        let mut buf = String::new();
        std::io::stdin()
            .read_line(&mut buf)
            .context("failed to read confirmation from stdin")?;
        let trimmed = buf.trim();
        if !trimmed.eq_ignore_ascii_case("y") && !trimmed.eq_ignore_ascii_case("yes") {
            bail!("aborted by user (no confirmation)");
        }
    }

    let wallet = vault
        .evm_wallet()
        .context("evm_wallet (vault locked or session expired?)")?;
    let signer = wallet.signer().clone();

    let attempt = initiate_top_up(&args.funder_url, credit, &signer)
        .await
        .context("initiate_top_up failed")?;

    if cfg.json {
        let value = serde_json::json!({
            "attempt_id": attempt.attempt_id.to_string(),
            "submitted_at_unix": attempt.submitted_at_unix,
            "redeem_tx_hash": format!("0x{}", hex::encode(attempt.funder_response.redeem_tx_hash.as_slice())),
            "eth_transfer_tx_hash": attempt
                .funder_response
                .eth_transfer_tx_hash
                .map(|h| format!("0x{}", hex::encode(h.as_slice()))),
            "eth_transferred_wei_hex": format!("0x{:x}", attempt.funder_response.eth_transferred_wei),
        });
        println!("{value}");
    } else {
        eprintln!("top-up attempt id: {}", attempt.attempt_id);
        eprintln!(
            "  redeem_tx_hash         0x{}",
            hex::encode(attempt.funder_response.redeem_tx_hash.as_slice())
        );
        match attempt.funder_response.eth_transfer_tx_hash {
            Some(h) => eprintln!("  eth_transfer_tx_hash   0x{}", hex::encode(h.as_slice())),
            None => eprintln!("  eth_transfer_tx_hash   (transfer leg failed)"),
        }
        eprintln!(
            "  eth_transferred_wei    0x{:x}",
            attempt.funder_response.eth_transferred_wei
        );
        eprintln!("  submitted_at_unix      {}", attempt.submitted_at_unix);
    }

    // R-h: this command touches the funder (a chain-adjacent
    // service) but does NOT itself broadcast revisions or drain
    // the publish queue. `Vault::close` is the right shutdown
    // primitive here; users run `pangolin sync flush` after the
    // top-up settles to drain any waiting publishes.
    vault.close().context("vault close failed")?;
    Ok(())
}

/// Parse a Credit attestation from a JSON file. The file format
/// mirrors the funder's wire shape (hex-string fields).
fn read_credit_file(path: &Path) -> Result<Credit> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read credit file at {}", path.display()))?;
    let value: serde_json::Value = serde_json::from_str(&raw)
        .with_context(|| format!("credit file {} is not valid JSON", path.display()))?;

    let user_id = read_hex_field(&value, "user_id", 32)?;
    let user_id_arr: [u8; 32] = user_id
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("user_id must be 32 bytes"))?;
    let amount_hex = value
        .get("amount")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("credit JSON missing string field `amount` (hex)"))?;
    let amount = parse_u256(amount_hex)
        .ok_or_else(|| anyhow::anyhow!("credit `amount` is not a valid hex U256"))?;
    let nonce = value
        .get("nonce")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| anyhow::anyhow!("credit JSON missing u64 field `nonce`"))?;
    let schema_version = value
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| anyhow::anyhow!("credit JSON missing u64 field `schema_version`"))?;
    let schema_version = u16::try_from(schema_version)
        .map_err(|_| anyhow::anyhow!("credit `schema_version` must fit in u16"))?;
    let expires_at = value
        .get("expires_at")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| anyhow::anyhow!("credit JSON missing u64 field `expires_at`"))?;
    let signature = read_hex_field(&value, "signature", 65)?;
    let signature_arr: [u8; 65] = signature
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("signature must be 65 bytes"))?;
    Ok(Credit {
        user_id: user_id_arr,
        amount,
        nonce,
        schema_version,
        expires_at,
        signature: signature_arr,
    })
}

fn read_hex_field(value: &serde_json::Value, name: &str, expected_len: usize) -> Result<Vec<u8>> {
    let s = value
        .get(name)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("credit JSON missing string field `{name}` (hex)"))?;
    let trimmed = s.strip_prefix("0x").unwrap_or(s);
    let bytes =
        hex::decode(trimmed).with_context(|| format!("credit `{name}` is not valid hex"))?;
    if bytes.len() != expected_len {
        bail!(
            "credit `{name}` length mismatch: expected {} bytes, got {}",
            expected_len,
            bytes.len()
        );
    }
    Ok(bytes)
}

fn parse_u256(s: &str) -> Option<U256> {
    let trimmed = s.strip_prefix("0x").unwrap_or(s);
    U256::from_str_radix(trimmed, 16).ok()
}

/// Type-erasure helper for `B256` import below — keeps the helper
/// usage explicit on hex display paths. Currently unused (kept
/// as documentation that the `B256` type is intentionally elided
/// from the parsed shape — the `Credit.signature` is a fixed
/// `[u8; 65]` rather than a `B256`).
#[allow(dead_code)]
fn _b256_unused(_: B256) {}
