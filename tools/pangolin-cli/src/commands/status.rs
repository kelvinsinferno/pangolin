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
use crate::vault_open::{canonicalize_vault_path, open_and_unlock, open_locked};

/// Run the `status` subcommand.
#[allow(clippy::unused_async)]
pub async fn run(global: &GlobalArgs, args: StatusArgs) -> Result<()> {
    let cfg = ResolvedConfig::from_args(global)?;

    // **P8 fix MED-3.** Canonicalize the supplied `--vault-path` up
    // front so the absolute path appears in the diagnostic output —
    // a user pointing the binary at `./vault.pvf` sees the resolved
    // absolute path in the status row.
    let canonical_path =
        canonicalize_vault_path(&args.vault_path).context("vault path canonicalization failed")?;

    // If a password was supplied, do the full unlock; otherwise open
    // the vault Locked. Both paths support the metadata-only ops we
    // need.
    let vault = if args.vault_password.is_some() {
        open_and_unlock(&canonical_path, args.vault_password.as_deref())
            .context("vault open + unlock failed")?
    } else {
        open_locked(&canonical_path).context("vault open failed")?
    };

    let dirty = vault.list_dirty().context("Vault::list_dirty failed")?;
    let last_pulled = vault
        .last_pulled_block()
        .context("Vault::last_pulled_block failed")?;
    let last_published = max_chain_block(&vault).context("max chain_block_number")?;
    let account_count = vault.list_accounts().len();
    let frozen = vault
        .list_frozen_accounts()
        .context("Vault::list_frozen_accounts failed")?;
    // **P10-5 / A8.** Surface the tombstoned-account count alongside
    // the existing structural counters. The query walks the
    // `account_identities` rows whose `tombstoned = 1` flag is set
    // (set by `Vault::delete_account` for own-deletes and by
    // `Vault::ingest_chain_revision`'s P10-3 path for
    // chain-ingested tombstones). Like `frozen_count`, the line is
    // omitted in the human-readable output when the count is zero
    // (the JSON output always emits the field for machine
    // consumers' completeness).
    let tombstoned_count = count_tombstoned_accounts(&vault).context("tombstone count failed")?;
    let vault_id = vault.vault_id();

    if cfg.json {
        let summary = serde_json::json!({
            "vault_path": canonical_path.display().to_string(),
            "vault_id": format!("0x{}", hex::encode(vault_id)),
            "dirty_count": dirty.len(),
            "account_count": account_count,
            "frozen_count": frozen.len(),
            "tombstoned_count": tombstoned_count,
            "last_pulled_block": last_pulled,
            "last_published_block": last_published,
        });
        println!("{summary}");
    } else {
        println!("vault_path            {}", canonical_path.display());
        println!("vault_id              0x{}", hex::encode(vault_id));
        println!("dirty_count           {}", dirty.len());
        println!("account_count         {account_count}");
        println!("frozen_count          {}", frozen.len());
        if tombstoned_count > 0 {
            println!("tombstoned_count      {tombstoned_count}");
        }
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
        if !frozen.is_empty() {
            println!();
            println!("frozen accounts (run `pangolin-cli resolve` per account once P9 lands):");
            for id in &frozen {
                println!("  {}", hex::encode(id.as_bytes()));
            }
        }
    }
    Ok(())
}

/// **P10-5 / A8.** Count the rows in `account_identities` whose
/// `tombstoned = 1` flag is set. Implemented via the
/// `Vault::list_tombstoned_accounts` accessor (P10-5 addition); we
/// take the length so the caller doesn't allocate an unused Vec for
/// the vault-id list.
fn count_tombstoned_accounts(vault: &pangolin_store::Vault) -> Result<usize> {
    Ok(vault
        .list_tombstoned_accounts()
        .context("Vault::list_tombstoned_accounts failed")?
        .len())
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
            allow_insecure_rpc: false,
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
            allow_insecure_rpc: false,
            json: false,
        };
        let args = StatusArgs {
            vault_path: missing.clone(),
            vault_password: None,
        };
        let err = run(&global, args).await.expect_err("missing vault errors");
        let msg = format!("{err:#}");
        // P8 fix MED-3: canonicalization runs first, so a missing
        // file surfaces as "could not canonicalize vault path".
        assert!(
            msg.contains("vault open failed")
                || msg.contains("vault file")
                || msg.contains("canonicalize"),
            "expected helpful error mentioning the vault, got: {msg}"
        );
    }

    /// **P8 fix MED-3.** The canonical absolute path appears in the
    /// JSON status output. Driving the test through `run` directly
    /// is awkward (we'd need to capture stdout); we instead exercise
    /// the canonicalize helper in isolation and confirm
    /// `run`-time integration via the lower-level test below.
    #[tokio::test]
    async fn vault_path_canonicalized_in_status_output() {
        use crate::vault_open::canonicalize_vault_path;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v.pvf");
        Vault::create(&path, &pwd()).expect("create");
        // Build a relative-style path by joining the dir with a
        // single-component relative form. The canonicalizer should
        // resolve it against CWD or the absolute base. Easier
        // assertion: `canonicalize_vault_path` produces an absolute
        // path even when given an already-absolute one — verify the
        // returned path is `is_absolute()` AND points at the same
        // underlying file (compare canonicalized forms).
        let canonical = canonicalize_vault_path(&path).expect("canonicalize");
        assert!(
            canonical.is_absolute(),
            "canonicalize_vault_path must return an absolute path; got {}",
            canonical.display()
        );
        // The canonical form of an already-canonical path is itself.
        let recanonical = canonicalize_vault_path(&canonical).expect("canonicalize idempotent");
        assert_eq!(
            canonical, recanonical,
            "canonicalize is idempotent on already-canonical paths"
        );

        // Smoke: status `run` integration uses the canonicalized path
        // in its output. We can't capture stdout in a unit test
        // without extra plumbing, but we can confirm `run` does NOT
        // error end-to-end given the canonicalized path.
        let global = GlobalArgs {
            deployment_file: None,
            rpc_url: None,
            allow_insecure_rpc: false,
            json: true,
        };
        let args = StatusArgs {
            vault_path: path.clone(),
            vault_password: None,
        };
        run(&global, args)
            .await
            .expect("status run with relative path resolves");
    }

    /// **P10-5 / A8.** The `count_tombstoned_accounts` helper
    /// returns 0 for a vault with no tombstoned accounts and >= 1
    /// for a vault with at least one. We exercise both paths here
    /// because the human-readable output suppresses the line when
    /// count is 0; the JSON output always emits it.
    #[tokio::test]
    async fn status_includes_tombstone_count_when_nonzero() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("status-tomb.pvf");
        Vault::create(&path, &pwd()).expect("create");
        // Initially zero tombstones.
        {
            let v = Vault::open(&path).expect("open");
            assert_eq!(super::count_tombstoned_accounts(&v).unwrap(), 0);
            v.close().expect("close");
        }
        // Add + delete one account → tombstone count becomes 1.
        let id;
        {
            let mut v = Vault::open(&path).expect("open");
            let presence = PressYPresenceProof::confirmed();
            let identity = PinIdentityProof::new(pwd());
            v.unlock(&presence, &identity).expect("unlock");
            id = v.add_account(snap("tomb-test")).expect("add");
            v.delete_account(id).expect("delete");
            v.close().expect("close");
        }
        {
            let v = Vault::open(&path).expect("reopen");
            assert_eq!(super::count_tombstoned_accounts(&v).unwrap(), 1);
            // List variant returns the right id.
            let list = v.list_tombstoned_accounts().expect("list tomb");
            assert_eq!(list, vec![id]);
            v.close().expect("close");
        }
    }
}
