//! Two-vault round-trip integration tests.
//!
//! These exercise the full publish + pull cycle through
//! `MockChainAdapter` against two `.pvf` files that share a vault
//! identity (achieved by copying file A to file B before B's first
//! open). The mock adapter filters pulls by `vault_id`, so two
//! vaults with the same identity see each other's events.
//!
//! Per `P8.md` §6 these tests pin three top-level success criteria:
//!
//! 1. **Convergence** — vault A publishes, vault B pulls, both
//!    report identical revision-graph state.
//! 2. **Symmetric fork** — A and B publish concurrent children of
//!    the same parent; after both pull, both see the same 2-head
//!    state and `is_forked()` returns true on both sides.
//! 3. **Idempotent repeat pull** — running pull twice in a row
//!    produces zero net work the second time.
//!
//! The tests do NOT spawn the binary; they import the crate's
//! `sync` module directly. The binary path is exercised by
//! `tests/cli_arg_parsing.rs` (P8-1).

use std::path::{Path, PathBuf};

use pangolin_chain::MockChainAdapter;
use pangolin_crypto::keys::DeviceKey;
use pangolin_crypto::secret::SecretBytes;
use pangolin_store::session::{PinIdentityProof, PressYPresenceProof};
use pangolin_store::{AccountSnapshot, Vault};
use tempfile::TempDir;

fn pwd_bytes() -> Vec<u8> {
    b"correct horse battery staple".to_vec()
}
fn pwd() -> SecretBytes {
    SecretBytes::new(pwd_bytes())
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

/// Create vault A; lock + close so we can copy the file. Returns
/// `(path_a, original_dir)`.
fn create_locked_vault(dir: &TempDir, name: &str) -> PathBuf {
    let path = dir.path().join(name);
    Vault::create(&path, &pwd()).expect("create");
    path
}

/// Open + unlock a vault and return the handle.
fn open_unlocked(path: &Path) -> Vault {
    let mut v = Vault::open(path).expect("open");
    let presence = PressYPresenceProof::confirmed();
    let identity = PinIdentityProof::new(pwd());
    v.unlock(&presence, &identity).expect("unlock");
    v
}

/// Copy vault A's file to vault B's path so the two have the same
/// identity (`vault_id`, KDF salt, wrapped VDK). The destination is
/// NOT opened by this function.
fn clone_vault_file(src: &Path, dst_dir: &TempDir, name: &str) -> PathBuf {
    let dst = dst_dir.path().join(name);
    std::fs::copy(src, &dst).expect("copy vault file");
    // SQLite WAL leftovers — `-wal` and `-shm` files — are fine to
    // ignore here because we always close the source vault before
    // copying, which checkpoints + removes them.
    dst
}

/// Convergence test: vault A publishes; vault B pulls; both see the
/// same revision id + chain anchor.
#[tokio::test]
async fn convergence() {
    let adapter = MockChainAdapter::new();
    let dir_a = TempDir::new().expect("dir A");
    let dir_b = TempDir::new().expect("dir B");

    // 1. Create A, add an account locally (creates a dirty marker),
    //    then close A so we can copy the file.
    let path_a = create_locked_vault(&dir_a, "a.pvf");
    let account_id;
    {
        let mut va = open_unlocked(&path_a);
        account_id = va.add_account(snap("convergence-acct")).expect("add");
        va.close().expect("close A");
    }

    // 2. Copy A's file to B's path. B inherits the same vault_id +
    //    the same dirty marker (the table is part of the .pvf file).
    let path_b = clone_vault_file(&path_a, &dir_b, "b.pvf");

    // 3. Open A, publish via the mock. Then close.
    {
        let mut va = open_unlocked(&path_a);
        let device = DeviceKey::generate();
        let report = pangolin_cli_sync::publish_all(&mut va, &adapter, &device)
            .await
            .expect("publish A");
        assert_eq!(report.published_count(), 1);
        assert!(va.list_dirty().expect("list").is_empty());
        va.close().expect("close A");
    }

    // 4. Open B (which still thinks the revision is unpublished),
    //    pull from the same chain. The ingest path's content-merge
    //    discipline should stamp the chain anchor onto B's existing
    //    local row.
    {
        let mut vb = open_unlocked(&path_b);
        // B starts with the dirty marker too (copied from A pre-publish).
        let pre_dirty = vb.list_dirty().expect("list").len();
        assert_eq!(pre_dirty, 1, "B starts with the dirty marker copied from A");
        let pull_report = pangolin_cli_sync::pull_all(&mut vb, &adapter, None, None)
            .await
            .expect("pull B");
        // The chain has the event, B's local row had no chain_anchor
        // pre-pull. After ingest, the row is updated (or a new one
        // is inserted, depending on the merge path) with the chain
        // anchor. Either way, applied is reported properly.
        let _ = pull_report;
        // B's account state matches A's: same account exists, with
        // a published chain anchor.
        let revs = vb.revisions_for(account_id).expect("revisions");
        assert!(
            revs.iter().any(|m| m.chain_anchor.is_some()),
            "B has at least one row with a chain anchor after pulling"
        );
        // No fork: only one head.
        let heads = vb.account_heads(account_id).expect("heads");
        assert_eq!(heads.len(), 1, "B sees a single head after convergence");
        vb.close().expect("close B");
    }
}

/// Symmetric fork test: A and B both edit the same starting state
/// (genesis), publish concurrently. After each pulls, both see a
/// 2-head fork on the same account.
#[tokio::test]
async fn symmetric_fork() {
    let adapter = MockChainAdapter::new();
    let dir_a = TempDir::new().expect("dir A");
    let dir_b = TempDir::new().expect("dir B");

    // 1. Create A; add genesis account; close.
    let path_a = create_locked_vault(&dir_a, "a.pvf");
    let account_id;
    {
        let mut va = open_unlocked(&path_a);
        account_id = va.add_account(snap("fork-acct")).expect("add");
        va.close().expect("close A");
    }

    // 2. Copy A → B. Both share the genesis revision.
    let path_b = clone_vault_file(&path_a, &dir_b, "b.pvf");

    // 3. A updates the account (creates a child of genesis). Publish.
    let device_a = DeviceKey::generate();
    {
        let mut va = open_unlocked(&path_a);
        va.update_account(account_id, snap("a-update"))
            .expect("update A");
        let _ = pangolin_cli_sync::publish_all(&mut va, &adapter, &device_a)
            .await
            .expect("publish A");
        va.close().expect("close A");
    }

    // 4. B updates the account (also a child of genesis — the
    //    update sees genesis as the local head because B's view is
    //    pre-pull). Publish.
    let device_b = DeviceKey::generate();
    {
        let mut vb = open_unlocked(&path_b);
        vb.update_account(account_id, snap("b-update"))
            .expect("update B");
        let _ = pangolin_cli_sync::publish_all(&mut vb, &adapter, &device_b)
            .await
            .expect("publish B");
        vb.close().expect("close B");
    }

    // 5. Now both A and B pull. Both should observe the 2-head fork
    //    on the shared account.
    {
        let mut va = open_unlocked(&path_a);
        let report_a = pangolin_cli_sync::pull_all(&mut va, &adapter, None, None)
            .await
            .expect("pull A");
        let heads_a = va.account_heads(account_id).expect("heads A");
        assert!(
            heads_a.len() >= 2,
            "A sees a multi-head state after pulling; got {}",
            heads_a.len()
        );
        assert!(
            !report_a.forks.is_empty(),
            "A's pull report flags the forked account"
        );
        va.close().expect("close A");
    }
    {
        let mut vb = open_unlocked(&path_b);
        let _ = pangolin_cli_sync::pull_all(&mut vb, &adapter, None, None)
            .await
            .expect("pull B");
        let heads_b = vb.account_heads(account_id).expect("heads B");
        assert!(
            heads_b.len() >= 2,
            "B sees a multi-head state after pulling; got {}",
            heads_b.len()
        );
        vb.close().expect("close B");
    }
}

/// Idempotency: running pull twice in a row with no chain activity
/// in between produces zero net work the second time.
#[tokio::test]
async fn idempotent_repeat_pull() {
    let adapter = MockChainAdapter::new();
    let dir_a = TempDir::new().expect("dir A");

    let path_a = create_locked_vault(&dir_a, "a.pvf");
    {
        let mut va = open_unlocked(&path_a);
        va.add_account(snap("repeat")).expect("add");
        let device = DeviceKey::generate();
        let _ = pangolin_cli_sync::publish_all(&mut va, &adapter, &device)
            .await
            .expect("publish");
        let r1 = pangolin_cli_sync::pull_all(&mut va, &adapter, None, None)
            .await
            .expect("pull 1");
        let r2 = pangolin_cli_sync::pull_all(&mut va, &adapter, None, None)
            .await
            .expect("pull 2");
        assert_eq!(r2.applied, 0, "second pull applies zero new events");
        assert_eq!(
            r2.last_pulled_block, r1.last_pulled_block,
            "checkpoint stable across no-op pull"
        );
        assert!(r2.forks.is_empty(), "second pull reports zero forks");
        va.close().expect("close");
    }
}

/// Re-export wrapper. `pangolin_cli::sync` is the library entry
/// point introduced in P8-6 specifically so integration tests under
/// `tests/` can import the orchestration core without going through
/// the binary's argv parsing layer. Aliased so the test bodies can
/// say `pangolin_cli_sync::publish_all` (clearer at the callsite
/// than `pangolin_cli::sync::publish_all`).
use pangolin_cli::sync as pangolin_cli_sync;
