// SPDX-License-Identifier: AGPL-3.0-or-later
//! `pangolin-cli sync flush` — drain the publish queue once.
//!
//! Per CLI-V1 R-b + R-h: calls `Vault::flush_publish_queue` with
//! `force = true` (bypasses the 30 s window), prints the per-row
//! `BatchFlushReport` summary, and uses `Vault::lock_with_drain` on
//! the graceful-exit path (chain-touching command per R-h).

#![forbid(unsafe_code)]

use anyhow::{bail, Context, Result};
use pangolin_chain::BaseSepoliaAdapter;
use pangolin_crypto::keys::DeviceKey;
use pangolin_crypto::secret::SecretBytes;
use pangolin_store::publish::{BatchFlushError, PublishOutcome};

use crate::cli::{GlobalArgs, SyncFlushArgs};
use crate::config::ResolvedConfig;
use crate::keystore::{read_keystore_password, resolve_keystore_path};
use crate::vault_open::open_and_unlock;

/// Run `sync flush`.
#[allow(clippy::too_many_lines)]
pub async fn run(global: &GlobalArgs, args: SyncFlushArgs) -> Result<()> {
    let cfg = ResolvedConfig::from_args(global)?;
    let deployment_path = cfg.require_deployment_file()?.clone();

    let keystore_path = resolve_keystore_path(
        args.account.as_deref(),
        args.keystore_dir.as_deref(),
        args.keystore_path.as_deref(),
    )?;

    let mut vault = open_and_unlock(&args.vault_path, args.vault_password.as_deref())
        .context("vault open + unlock failed")?;

    let keystore_password =
        read_keystore_password(&keystore_path, args.keystore_password.as_deref())?;
    let password_secret = SecretBytes::new(keystore_password.as_bytes().to_vec());
    drop(keystore_password);

    let rpc_url_default = read_deployment_default_rpc(&deployment_path)?;
    let rpc_url = cfg.rpc_url_or_default(&rpc_url_default);
    cfg.enforce_rpc_scheme(&rpc_url)?;
    let adapter = BaseSepoliaAdapter::new_with_keystore(
        &rpc_url,
        &deployment_path,
        &keystore_path,
        &password_secret,
    )
    .await
    .context("failed to construct BaseSepoliaAdapter")?;
    drop(password_secret);

    let device = DeviceKey::generate();

    // R-h: chain-touching command. Force-flush with force=true to
    // bypass the 30s window gate (this is an explicit drain
    // invocation, not the scheduled cadence).
    let flush_result = vault.flush_publish_queue(&adapter, &device, true).await;

    // R-h: graceful exit via lock_with_drain. We've already
    // drained above; lock_with_drain will run one more attempt
    // (which is essentially a no-op if everything succeeded), and
    // transitions the vault to Locked.
    //
    // The flush_result above is the one we surface to the user.
    let _ = vault.lock_with_drain(&adapter, &device).await;

    let report = match flush_result {
        Ok(r) => r,
        Err(BatchFlushError::BalanceInsufficientForBatch {
            needed,
            available,
            queued_count,
        }) => {
            if cfg.json {
                let value = serde_json::json!({
                    "outcome": "blocked_on_balance",
                    "needed_wei_hex": format!("0x{needed:x}"),
                    "available_wei_hex": format!("0x{available:x}"),
                    "queued_count": queued_count,
                });
                println!("{value}");
            } else {
                eprintln!(
                    "flush: blocked on balance — needed {needed} wei across {queued_count} \
                     queued accounts; available {available} wei (run `pangolin top-up`)"
                );
            }
            bail!(
                "publish queue blocked on insufficient balance: needed={needed}, \
                 available={available}, queued_count={queued_count}"
            );
        }
        Err(BatchFlushError::NoActiveSession) => {
            bail!("flush failed: vault is not unlocked (session expired?)")
        }
        Err(BatchFlushError::ChainError(e)) => {
            bail!("flush failed: chain error: {e}")
        }
        Err(BatchFlushError::Store(e)) => {
            bail!("flush failed: store error: {e}")
        }
    };

    if cfg.json {
        let rows: Vec<_> = report
            .publish_report
            .rows
            .iter()
            .map(|row| match &row.outcome {
                PublishOutcome::Published {
                    anchor,
                    was_already_on_chain,
                } => serde_json::json!({
                    "account_id": hex::encode(row.account_id.as_bytes()),
                    "revision_id": hex::encode(row.revision_id.as_bytes()),
                    "outcome": "published",
                    "was_already_on_chain": was_already_on_chain,
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
            })
            .collect();
        let summary = serde_json::json!({
            "coalesced_markers_pruned": report.coalesced_markers_pruned,
            "published_count": report.publish_report.published_count(),
            "failed_count": report.publish_report.failed_count(),
            "rows": rows,
        });
        println!("{summary}");
    } else {
        eprintln!(
            "flush summary: coalesced_pruned={} published={} failed={} (out of {} entries)",
            report.coalesced_markers_pruned,
            report.publish_report.published_count(),
            report.publish_report.failed_count(),
            report.publish_report.rows.len(),
        );
        for row in &report.publish_report.rows {
            match &row.outcome {
                PublishOutcome::Published {
                    anchor,
                    was_already_on_chain,
                } => {
                    let suffix = if *was_already_on_chain {
                        " (already on chain)"
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

    if !report.publish_report.all_ok() {
        bail!(
            "{} of {} dirty entries failed to publish",
            report.publish_report.failed_count(),
            report.publish_report.rows.len()
        );
    }
    Ok(())
}

/// Pluck `chain.rpc_default` from the deployment file. Duplicated
/// across `publish` / `pull` / `resolve` per the standing convention
/// in those commands.
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
