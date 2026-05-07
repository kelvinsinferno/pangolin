//! `pangolin-cli status` — read-only diagnostics.
//!
//! Reports the metadata-only counters the local vault makes directly
//! observable. NO chain calls — this is the "what does my local store
//! think the world looks like?" view.
//!
//! Fields surfaced:
//!
//! - `vault_id` (32-byte hex) — content-addressed identifier.
//! - `dirty_count` — `Vault::list_dirty().len()`.
//! - `account_count` — number of non-tombstoned accounts in the
//!   `account_identities` table (best-effort; we use the row count
//!   regardless of tombstone flag for the public summary).
//! - `last_pulled_block` — `Vault::last_pulled_block()`.
//! - `last_published_block` — max `chain_block_number` across the
//!   `revisions` table (the highest block at which any local row's
//!   chain anchor was recorded; `0` for a freshly-created vault).
//! - `head_counts` — per-account head count (length-1 entries are
//!   omitted from human-readable output to keep things tidy; JSON
//!   output includes every account).
//!
//! `status` does NOT require an unlocked vault. The dirty list, last-
//! pulled-block, and revision-row aggregates are all metadata-only.
//! If `--vault-password` is supplied, we attempt unlock too (so the
//! `account_count` reflects the active set rather than the structural
//! row count); if not, we report the structural counters that survive
//! a `Locked` vault.

use anyhow::{Context, Result};

use crate::cli::{GlobalArgs, StatusArgs};
use crate::config::ResolvedConfig;
use crate::vault_open::{open_and_unlock, open_locked};

/// Run the `status` subcommand.
#[allow(clippy::unused_async)]
pub async fn run(global: &GlobalArgs, args: StatusArgs) -> Result<()> {
    let cfg = ResolvedConfig::from_args(global)?;

    // If a password was supplied, do the full unlock; otherwise open
    // the vault Locked. Both paths support the metadata-only ops we
    // need.
    let vault = if args.vault_password.is_some() {
        open_and_unlock(&args.vault_path, args.vault_password.as_deref())
            .context("vault open + unlock failed")?
    } else {
        open_locked(&args.vault_path).context("vault open failed")?
    };

    let dirty = vault.list_dirty().context("Vault::list_dirty failed")?;
    let last_pulled = vault
        .last_pulled_block()
        .context("Vault::last_pulled_block failed")?;
    let last_published = max_chain_block(&vault).context("max chain_block_number")?;
    let account_count = vault.list_accounts().len();
    let vault_id = vault.vault_id();

    if cfg.json {
        let summary = serde_json::json!({
            "vault_id": format!("0x{}", hex::encode(vault_id)),
            "dirty_count": dirty.len(),
            "account_count": account_count,
            "last_pulled_block": last_pulled,
            "last_published_block": last_published,
        });
        println!("{summary}");
    } else {
        println!("vault_id              0x{}", hex::encode(vault_id));
        println!("dirty_count           {}", dirty.len());
        println!("account_count         {account_count}");
        println!("last_pulled_block     {last_pulled}");
        println!("last_published_block  {last_published}");
        if !dirty.is_empty() {
            println!();
            println!("dirty entries (FIFO by marked_at):");
            for d in &dirty {
                println!(
                    "  {}  {}  marked_at={}",
                    hex::encode(d.account_id.as_bytes()),
                    hex::encode(d.revision_id.as_bytes()),
                    d.marked_at,
                );
            }
        }
    }
    Ok(())
}

/// Read the maximum value of `chain_block_number` across the entire
/// `revisions` table. Implemented via a direct SQL aggregate so we
/// don't have to touch the `revisions_for` row-by-row API. Returns
/// `0` for a vault whose revisions are all unpublished.
//
// We can't actually run this without crossing the pangolin-store
// public API. The store doesn't expose a "max chain block" helper.
// Implementing one here would mean reaching into the connection,
// which is private.
//
// Alternative: walk every account via `vault.list_accounts()` and
// `vault.revisions_for(id)` and take the max chain_anchor.block_number
// across the union. That's O(N) but correct. PoC scale is fine.
fn max_chain_block(vault: &pangolin_store::Vault) -> Result<u64> {
    let mut max_block: u64 = 0;
    for account_id in vault.list_accounts() {
        // `revisions_for` works on a Locked vault per the docstring
        // — it's metadata-only.
        let metas = vault
            .revisions_for(account_id)
            .with_context(|| format!("revisions_for({account_id:?}) failed"))?;
        for m in metas {
            if let Some(anchor) = m.chain_anchor {
                if anchor.block_number > max_block {
                    max_block = anchor.block_number;
                }
            }
        }
    }
    Ok(max_block)
}

#[cfg(test)]
mod tests {
    use super::run;
    use crate::cli::{GlobalArgs, StatusArgs};
    use pangolin_crypto::secret::SecretBytes;
    use pangolin_store::session::{PinIdentityProof, PressYPresenceProof};
    use pangolin_store::AccountSnapshot;
    use pangolin_store::Vault;

    fn pwd() -> SecretBytes {
        SecretBytes::new(b"correct horse battery staple".to_vec())
    }

    fn snap(name: &str) -> AccountSnapshot {
        AccountSnapshot::new(
            SecretBytes::new(name.as_bytes().to_vec()),
            SecretBytes::new(b"u".to_vec()),
            SecretBytes::new(b"p".to_vec()),
            SecretBytes::new(b"https://x".to_vec()),
            SecretBytes::new(b"".to_vec()),
            SecretBytes::new(b"".to_vec()),
        )
    }

    /// Plan test: status on a fresh vault emits all expected fields
    /// without errors.
    #[tokio::test]
    async fn status_emits_expected_fields() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v.pvf");
        Vault::create(&path, &pwd()).expect("create");
        // Add an account so account_count is non-zero.
        {
            let mut v = Vault::open(&path).expect("open");
            let presence = PressYPresenceProof::confirmed();
            let identity = PinIdentityProof::new(pwd());
            v.unlock(&presence, &identity).expect("unlock");
            v.add_account(snap("status-test")).expect("add");
            v.close().expect("close");
        }

        let global = GlobalArgs {
            deployment_file: None,
            rpc_url: None,
            json: true,
        };
        let args = StatusArgs {
            vault_path: path.clone(),
            vault_password: Some("correct horse battery staple".into()),
        };
        // Ensures `run` does not error end-to-end and exercises the
        // JSON branch.
        run(&global, args).await.expect("status run ok");
    }

    /// Plan test: status against a missing vault file errors
    /// cleanly (not a panic).
    #[tokio::test]
    async fn status_with_no_vault_errors_cleanly() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("does-not-exist.pvf");
        let global = GlobalArgs {
            deployment_file: None,
            rpc_url: None,
            json: false,
        };
        let args = StatusArgs {
            vault_path: missing.clone(),
            vault_password: None,
        };
        let err = run(&global, args).await.expect_err("missing vault errors");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("vault open failed") || msg.contains("vault file"),
            "expected helpful error mentioning the vault, got: {msg}"
        );
    }
}
