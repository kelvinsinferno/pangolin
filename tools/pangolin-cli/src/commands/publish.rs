//! `pangolin-cli publish` — push dirty revisions to chain.
//!
//! End-to-end flow:
//!
//! 1. Resolve global config (deployment file path + RPC URL).
//! 2. Open + unlock the vault (P4 two-proof flow, prompted for
//!    password unless `--vault-password` was supplied).
//! 3. Resolve the keystore path + decrypt password (Foundry format,
//!    via `BaseSepoliaAdapter::new_with_keystore`).
//! 4. Build a `BaseSepoliaAdapter` (gas wallet + signed-revision RPC).
//! 5. Generate an ephemeral `DeviceKey` for revision signing (P8
//!    `PoC` two-key model — see crate docs).
//! 6. Drive `sync::publish_all` end-to-end. The orchestrator clears
//!    dirty markers per-success and accumulates errors per-failure.
//! 7. Print the per-row summary; exit 0 if every row succeeded,
//!    exit 1 otherwise.

use anyhow::{bail, Context, Result};
use pangolin_chain::BaseSepoliaAdapter;
use pangolin_crypto::keys::DeviceKey;
use pangolin_crypto::secret::SecretBytes;

use crate::cli::{GlobalArgs, PublishArgs};
use crate::config::ResolvedConfig;
use crate::keystore::{read_keystore_password, resolve_keystore_path};
use crate::sync::{publish_all, PublishOutcome};
use crate::vault_open::open_and_unlock;

/// Run the `publish` subcommand.
pub async fn run(global: &GlobalArgs, args: PublishArgs) -> Result<()> {
    let cfg = ResolvedConfig::from_args(global)?;
    let deployment_path = cfg.require_deployment_file()?.clone();

    // Resolve the keystore path (and validate `--account` shape) BEFORE
    // prompting for the password — fail-fast if the keystore file is
    // missing.
    let keystore_path = resolve_keystore_path(
        args.account.as_deref(),
        args.keystore_dir.as_deref(),
        args.keystore_path.as_deref(),
    )?;

    // Open + unlock the vault BEFORE the keystore prompt — same
    // fail-fast posture, and the two prompts (vault then keystore)
    // happen in a predictable order if the user typed nothing on the
    // command line.
    let mut vault = open_and_unlock(&args.vault_path, args.vault_password.as_deref())
        .context("vault open + unlock failed")?;

    // Read the keystore password (terminal prompt without echo, or
    // `--keystore-password` flag).
    let keystore_password =
        read_keystore_password(&keystore_path, args.keystore_password.as_deref())?;
    let password_secret = SecretBytes::new(keystore_password.as_bytes().to_vec());
    drop(keystore_password); // Zeroizing wrapper wipes here.

    // Build the adapter. Reads the deployment file, verifies chain id,
    // verifies live runtime keccak (P7 audit MED-2), decrypts the
    // keystore.
    let rpc_url_default = read_deployment_default_rpc(&deployment_path)?;
    let rpc_url = cfg.rpc_url_or_default(&rpc_url_default);
    let adapter = BaseSepoliaAdapter::new_with_keystore(
        &rpc_url,
        &deployment_path,
        &keystore_path,
        &password_secret,
    )
    .await
    .context("failed to construct BaseSepoliaAdapter")?;
    drop(password_secret);

    // Generate the ephemeral revision-signing key. PoC two-key model:
    // every run uses a fresh Ed25519 device key for signing. v0
    // contract doesn't verify anyway. MVP-1 will switch to a key
    // derived from the vault's persisted DeviceKey via
    // `pangolin_chain::evm::derive_evm_wallet`.
    let device = DeviceKey::generate();

    // Drive the orchestrator.
    let report = publish_all(&mut vault, &adapter, &device)
        .await
        .context("publish_all failed")?;

    // Print summary on stderr (humans), JSON-Lines on stdout if --json.
    if cfg.json {
        for row in &report.rows {
            let value = match &row.outcome {
                PublishOutcome::Published {
                    anchor,
                    was_already_on_chain,
                } => serde_json::json!({
                    "account_id": hex::encode(row.account_id.as_bytes()),
                    "revision_id": hex::encode(row.revision_id.as_bytes()),
                    "outcome": "published",
                    "was_already_on_chain": was_already_on_chain,
                    "tx_hash": format!("0x{}", hex::encode(anchor.tx_hash)),
                    "block_number": anchor.block_number,
                    "log_index": anchor.log_index,
                    "sequence": anchor.sequence,
                }),
                PublishOutcome::Failed { error } => serde_json::json!({
                    "account_id": hex::encode(row.account_id.as_bytes()),
                    "revision_id": hex::encode(row.revision_id.as_bytes()),
                    "outcome": "failed",
                    "error": error,
                }),
            };
            println!("{value}");
        }
    } else {
        eprintln!(
            "publish summary: {} published, {} failed (out of {} dirty entries)",
            report.published_count(),
            report.failed_count(),
            report.rows.len()
        );
        for row in &report.rows {
            match &row.outcome {
                PublishOutcome::Published {
                    anchor,
                    was_already_on_chain,
                } => {
                    let suffix = if *was_already_on_chain {
                        " (already on chain — A3)"
                    } else {
                        ""
                    };
                    eprintln!(
                        "  ok   {} block={} log={} seq={}{suffix}",
                        hex::encode(row.revision_id.as_bytes()),
                        anchor.block_number,
                        anchor.log_index,
                        anchor.sequence,
                    );
                }
                PublishOutcome::Failed { error } => {
                    eprintln!(
                        "  fail {}: {error}",
                        hex::encode(row.revision_id.as_bytes()),
                    );
                }
            }
        }
    }

    if !report.all_ok() {
        bail!(
            "{} of {} dirty entries failed to publish",
            report.failed_count(),
            report.rows.len()
        );
    }
    Ok(())
}

/// Read the deployment file and pluck out `chain.rpc_default`. Used
/// only as the third-stage fallback in the RPC-URL precedence chain
/// (after `--rpc-url` and `$BASE_SEPOLIA_RPC_URL`).
fn read_deployment_default_rpc(path: &std::path::Path) -> Result<String> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read deployment file at {}", path.display()))?;
    let value: serde_json::Value = serde_json::from_str(&raw)
        .with_context(|| format!("deployment file {} is not valid JSON", path.display()))?;
    let s = value
        .pointer("/chain/rpc_default")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("deployment file missing /chain/rpc_default (string)"))?;
    Ok(s.to_owned())
}
