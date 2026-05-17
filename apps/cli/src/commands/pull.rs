//! `pangolin-cli pull` — ingest chain events into the local vault.
//!
//! End-to-end flow:
//!
//! 1. Resolve global config (deployment file path + RPC URL).
//! 2. Open + unlock the vault (the AAD on every revision binds
//!    `vault_id`, so we need an unlocked vault to verify any
//!    decrypt that happens later, even though the ingest path
//!    itself does not decrypt).
//! 3. Build a read-only `BaseSepoliaAdapter` (no signer needed for
//!    the pull path).
//! 4. Drive `sync::pull_all` end-to-end. Per-chunk checkpoint
//!    advancement guarantees a chunk failure preserves prior
//!    chunks' progress (A5 / MED-3).
//! 5. Print the per-run summary on stderr; print fork summaries
//!    individually (one line per forked account); exit 0 even
//!    when forks are present (forks are an expected outcome of
//!    concurrent edits, not an error condition).

use anyhow::{Context, Result};
use pangolin_chain::BaseSepoliaAdapter;

use crate::cli::{GlobalArgs, PullArgs};
use crate::config::ResolvedConfig;
use crate::sync::pull_all;
use crate::vault_open::open_and_unlock;

/// Run the `pull` subcommand.
pub async fn run(global: &GlobalArgs, args: PullArgs) -> Result<()> {
    let cfg = ResolvedConfig::from_args(global)?;
    let deployment_path = cfg.require_deployment_file()?.clone();

    let mut vault = open_and_unlock(&args.vault_path, args.vault_password.as_deref())
        .context("vault open + unlock failed")?;

    let rpc_url_default = read_deployment_default_rpc(&deployment_path)?;
    let rpc_url = cfg.rpc_url_or_default(&rpc_url_default);
    // P8 fix MED-2: refuse non-https RPC URLs unless --allow-insecure-rpc.
    cfg.enforce_rpc_scheme(&rpc_url)?;
    let adapter = BaseSepoliaAdapter::new_read_only(&rpc_url, &deployment_path)
        .await
        .context("failed to construct read-only BaseSepoliaAdapter")?;

    let report = pull_all(&mut vault, &adapter, args.from_block, args.until_block)
        .await
        .context("pull_all failed")?;

    // **CLI-V1 R-h.** Chain-touching command: graceful exit via
    // `Vault::lock_with_drain`. `pull` doesn't publish, but the
    // user may have queued markers from a concurrent CLI session;
    // the drain is best-effort and the lock transitions
    // regardless. We need an ephemeral DeviceKey for the
    // lock_with_drain signature; the same signing posture as
    // `publish_all` (PoC two-key model). Drop the wallet view we
    // had via `adapter` (read-only) — `lock_with_drain` reads the
    // adapter via `flush_publish_queue`; an adapter without a
    // signer + an empty publish queue is fine (no publishes
    // attempted).
    let device = pangolin_crypto::keys::DeviceKey::generate();
    if let Err(e) = vault.lock_with_drain(&adapter, &device).await {
        eprintln!("shutdown drain error (dirty markers persist): {e}");
    }

    if cfg.json {
        let summary = serde_json::json!({
            "applied": report.applied,
            "last_pulled_block": report.last_pulled_block,
            "forks": report
                .forks
                .iter()
                .map(|f| serde_json::json!({
                    "account_id": hex::encode(f.account_id.as_bytes()),
                    "head_revision_ids": f
                        .head_revision_ids
                        .iter()
                        .map(|r| hex::encode(r.as_bytes()))
                        .collect::<Vec<_>>(),
                }))
                .collect::<Vec<_>>(),
            "frozen": report
                .frozen
                .iter()
                .map(|id| hex::encode(id.as_bytes()))
                .collect::<Vec<_>>(),
        });
        println!("{summary}");
    } else {
        eprintln!(
            "pull summary: {} new events ingested; last_pulled_block = {}; \
             {} forked account(s); {} frozen account(s)",
            report.applied,
            report.last_pulled_block,
            report.forks.len(),
            report.frozen.len(),
        );
        for fork in &report.forks {
            eprintln!(
                "  fork: account {} has {} heads:",
                hex::encode(fork.account_id.as_bytes()),
                fork.head_revision_ids.len(),
            );
            for h in &fork.head_revision_ids {
                eprintln!("    {}", hex::encode(h.as_bytes()));
            }
        }
        for frozen in &report.frozen {
            // P8 fix CRIT-1: surface the frozen set so the user
            // knows which accounts to address with `pangolin-cli
            // resolve` (P9). We list the accounts individually so
            // a structured tool can grep them out.
            eprintln!(
                "  frozen: account {} is frozen pending resolve",
                hex::encode(frozen.as_bytes()),
            );
        }
    }
    // Forks and frozen accounts are NOT errors — exit 0 regardless.
    // P9 owns resolution.
    Ok(())
}

/// Same helper as in `commands/publish.rs` — pluck `chain.rpc_default`
/// out of the deployment file. Duplicated rather than shared because
/// the publish/pull commands are independent surfaces and we don't
/// want to factor out a `commands::common` module just for one
/// helper.
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
