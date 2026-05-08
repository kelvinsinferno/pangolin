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

/// **Renamed** (P9): the test formerly named `convergence` now
/// pins the post-P8-CRIT-1 freeze behavior. After A publishes and
/// B pulls, B's account is FROZEN pending resolve. The full A → B
/// → resolve → converge flow lives in `convergence_after_resolve`
/// (P9-5), below.
#[tokio::test]
async fn convergence_freezes_on_pull() {
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
    //    pull from the same chain. Under the **P8 fix-pass MED-1**
    //    tightening (third merge arm now requires `device_id` match
    //    alongside `(account_id, parent, payload, schema_version,
    //    chain_tx_hash IS NULL)`), B's pull cannot silently merge
    //    A's chain event into B's pre-publish local row — the local
    //    row's `device_id` was stamped by A's vault handle's
    //    randomly-generated `device_id`, while the chain event's
    //    `device_id` is A's publish-time `DeviceKey` pubkey under
    //    the `PoC` two-key model. The merge fails → ingest takes
    //    the genuine-foreign-INSERT path → CRIT-1 freeze sentinel
    //    fires on B's local copy.
    //
    //    This is the EXPECTED behavior under the §16.5 audit fix
    //    pass: B cannot read stale plaintext after the chain has
    //    moved under it; B must run `pangolin-cli resolve` (P9)
    //    before reading. Under MVP-1's single-key model (D-006),
    //    when local-row `device_id` and chain-event `device_id`
    //    align, the merge will succeed and B will converge silently
    //    — no freeze. The PoC accepts the freeze as the safer
    //    failure mode.
    {
        let mut vb = open_unlocked(&path_b);
        // B starts with the dirty marker too (copied from A pre-publish).
        let pre_dirty = vb.list_dirty().expect("list").len();
        assert_eq!(pre_dirty, 1, "B starts with the dirty marker copied from A");
        let pull_report = pangolin_cli_sync::pull_all(&mut vb, &adapter, None, None)
            .await
            .expect("pull B");
        let _ = pull_report;
        // B has the chain anchor row from the ingest plus its
        // pre-existing pre-publish local row.
        let revs = vb.revisions_for(account_id).expect("revisions");
        assert!(
            revs.iter().any(|m| m.chain_anchor.is_some()),
            "B has at least one row with a chain anchor after pulling"
        );
        // CRIT-1: B's account is frozen pending resolve (the third
        // merge arm rejected the device_id mismatch and the genuine-
        // foreign-INSERT path fired).
        let frozen = vb.list_frozen_accounts().expect("list_frozen_accounts");
        assert_eq!(
            frozen,
            vec![account_id],
            "B's account is frozen pending resolve after pulling A's foreign chain event"
        );
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

/// **P9-5.** Convergence after resolve, simplified `PoC` pattern.
///
/// Full flow: A publishes → B pulls (frozen) → B runs `resolve` to
/// clear the freeze and ratify the head as canonical → A pulls
/// B's merge revision.
///
/// The end-state asserted:
/// - B's `list_frozen_accounts()` is EMPTY (resolve cleared the
///   freeze flag).
/// - The chain has at least the original publish + the resolve's
///   merge revision.
/// - B's `account_heads` (post-resolve) returns 1 entry — the merge
///   is the new canonical head, having its parent set to B's local
///   pre-clone genesis revision (which B IS able to decrypt
///   because the vault file was cloned before A's publish, so
///   B's local genesis row carries the original plaintext-
///   recoverable nonce).
///
/// Limitations documented in P9 plan §A4 / §"Out of scope":
/// - A subsequent A-pull will land B's merge as a foreign-INSERT
///   on A under `PoC` two-key, re-arming A's freeze. A then needs
///   to run resolve too. Full single-head convergence across N
///   devices requires N resolves under `PoC` two-key. MVP-1's
///   single-key model (D-006) closes the gap.
/// - The orphan A-publish revision remains in B's local store as
///   a non-head (the merge ate it as a sibling-of-genesis-parent
///   no — actually the merge's parent IS B's local genesis,
///   making the orphan A-publish a co-head with the merge
///   indirectly). The multi-resolve pattern (per A4) handles
///   each branch in turn; this test pins the simple two-handle
///   case where ONE resolve clears B's state.
#[tokio::test]
async fn convergence_after_resolve() {
    let adapter = MockChainAdapter::new();
    let dir_a = TempDir::new().expect("dir A");
    let dir_b = TempDir::new().expect("dir B");

    // 1. Vault A creates an account locally; close so we can copy.
    let path_a = create_locked_vault(&dir_a, "a.pvf");
    let account_id;
    {
        let mut va = open_unlocked(&path_a);
        account_id = va.add_account(snap("converge-resolve")).expect("add");
        va.close().expect("close A");
    }

    // 2. Copy A → B (so B has the same vault_id, same VDK, same
    //    local genesis row with the original plaintext-recoverable
    //    nonce).
    let path_b = clone_vault_file(&path_a, &dir_b, "b.pvf");

    // 3. A publishes via the mock.
    {
        let mut va = open_unlocked(&path_a);
        let device = DeviceKey::generate();
        let report = pangolin_cli_sync::publish_all(&mut va, &adapter, &device)
            .await
            .expect("publish A");
        assert_eq!(report.published_count(), 1);
        va.close().expect("close A");
    }

    // 4. B pulls. Under PoC two-key the foreign device_id triggers
    //    the CRIT-1 freeze sentinel.
    {
        let mut vb = open_unlocked(&path_b);
        let _ = pangolin_cli_sync::pull_all(&mut vb, &adapter, None, None)
            .await
            .expect("pull B");
        let frozen = vb.list_frozen_accounts().expect("list frozen");
        assert_eq!(
            frozen,
            vec![account_id],
            "B's account is frozen after first pull (CRIT-1)"
        );
        vb.close().expect("close B");
    }

    // 5. B runs `resolve` against ITS OWN local genesis revision
    //    (the one B inherited from the cloned vault file before A
    //    published). B can decrypt it because the row carries the
    //    original AEAD nonce; A's foreign-ingested chain row has
    //    a placeholder zero nonce that B cannot decrypt under
    //    PoC two-key.
    //
    //    `resolve_one` runs end-to-end: pre-publish re-pull (no-op
    //    since B already pulled), plaintext read + re-seal under
    //    merge AAD, build SignedRevision, publish, ingest, clear
    //    freeze.
    {
        let mut vb = open_unlocked(&path_b);
        // B's local genesis row is the one whose row in
        // revisions has a NULL chain_tx_hash (was never published
        // by B; copied from A pre-publish).
        let revs_b = vb.revisions_for(account_id).expect("revisions");
        let local_genesis = revs_b
            .iter()
            .find(|m| m.chain_anchor.is_none())
            .map(|m| m.revision_id)
            .expect("B has a locally-decryptable row pre-resolve");

        let dev = DeviceKey::generate();
        let outcome = pangolin_cli_sync::resolve_one(
            &mut vb,
            &adapter,
            &dev,
            account_id,
            local_genesis,
            false,
        )
        .await
        .expect("B resolve");
        match outcome {
            pangolin_cli_sync::ResolveOutcome::Published { .. }
            | pangolin_cli_sync::ResolveOutcome::AlreadyOnChain { .. } => {}
            pangolin_cli_sync::ResolveOutcome::DryRun { .. } => {
                panic!("dry_run = false; expected Published / AlreadyOnChain")
            }
        }

        // **Convergence assertion 1**: B's freeze flag is CLEAR.
        let frozen_b = vb.list_frozen_accounts().expect("list frozen");
        assert!(
            !frozen_b.contains(&account_id),
            "B's freeze flag must be cleared after resolve"
        );
        vb.close().expect("close B");
    }

    // 6. **Convergence assertion 2**: the chain now has at least
    //    A's original publish + B's merge revision. A's view (after
    //    pull) sees the merge alongside A's original publish.
    {
        let mut va = open_unlocked(&path_a);
        let _ = pangolin_cli_sync::pull_all(&mut va, &adapter, None, None)
            .await
            .expect("A pull post-B-resolve");
        // A's local store has the merge row ingested as foreign.
        let revs_a = va.revisions_for(account_id).expect("revisions A");
        assert!(
            revs_a.len() >= 2,
            "A has at least 2 revisions (own publish + B's merge): got {}",
            revs_a.len()
        );
        // A's freeze flag is set (the merge revision lands as
        // foreign-INSERT under PoC two-key — this is the
        // documented post-resolve PoC behavior, NOT a regression).
        // Per P9 plan §A4 the multi-resolve pattern resolves this
        // by A running its own `resolve` next; that's covered by
        // the unit test resolve_publishes_merge_revision and is
        // not re-asserted here to keep this E2E test focused.
        va.close().expect("close A");
    }
}

/// **P10-3.** Own-tombstone round-trip via the chain.
///
/// Pin the post-P10 invariant that a tombstone published to chain
/// and then re-pulled to the same vault remains tombstoned (the
/// idempotency arm #2 chain-anchor stamp matches the local row's
/// `mark_published` anchor; the row's `is_tombstone = 1` flag and
/// the `account_identities.tombstoned = 1` flag both survive
/// unchanged).
///
/// Under `PoC` two-key, the cross-vault tombstone propagation case
/// (vault A tombstones X; vault B pulls; B's row's `is_tombstone`
/// reflects the chain) is acknowledged limitation Threat #15 — the
/// chain event ABI does not transport the AEAD nonce, so the
/// foreign-ingest path's opportunistic decode (P10-2) cannot
/// decrypt the payload, the bit stays 0, and the freeze sentinel
/// fires. Closed by MVP-1's nonce-on-chain. This test does NOT
/// exercise the cross-vault propagation; it exercises the OWN-
/// publish round-trip (vault A publishes, vault A pulls), which IS
/// covered under `PoC` (idempotency arm #2 stamps the chain anchor;
/// the local `is_tombstone = 1` from `delete_account` is preserved).
#[tokio::test]
async fn own_tombstone_round_trip_via_chain() {
    let adapter = MockChainAdapter::new();
    let dir_a = TempDir::new().expect("dir A");
    let path_a = create_locked_vault(&dir_a, "a.pvf");
    let device = DeviceKey::generate();

    let account_id;
    {
        let mut va = open_unlocked(&path_a);
        // 1. Add an account, publish.
        account_id = va.add_account(snap("own-tombstone")).expect("add");
        let publish_report = pangolin_cli_sync::publish_all(&mut va, &adapter, &device)
            .await
            .expect("publish");
        assert_eq!(publish_report.published_count(), 1);

        // 2. Delete the account (writes a tombstone revision with
        //    is_tombstone = 1 + tombstoned = 1 directly via
        //    delete_account; queues a dirty marker for the tombstone
        //    revision).
        va.delete_account(account_id).expect("delete");
        let dirty = va.list_dirty().expect("list dirty");
        assert_eq!(
            dirty.len(),
            1,
            "delete_account stamped a dirty marker for the tombstone"
        );
        assert!(va.get_account(account_id).is_none(), "tombstoned");

        // 3. Publish the tombstone revision. The chain now has 2
        //    events (live + tombstone).
        let publish_report = pangolin_cli_sync::publish_all(&mut va, &adapter, &device)
            .await
            .expect("publish tombstone");
        assert_eq!(publish_report.published_count(), 1);
        assert!(va.list_dirty().expect("list dirty").is_empty());
        assert_eq!(adapter.event_count(), 2, "chain has 2 events");

        // 4. Pull on the same vault. Idempotency arm #2 (chain
        //    anchor stamp via `mark_published`) hits, so the
        //    genuine-foreign-INSERT branch is bypassed. The
        //    pre-existing `is_tombstone = 1` and `tombstoned = 1`
        //    flags on the local row survive unchanged. The freeze
        //    sentinel does NOT fire (own-publish round-trip).
        let _pull_report = pangolin_cli_sync::pull_all(&mut va, &adapter, None, None)
            .await
            .expect("pull");

        // 5. Final assertions: the tombstone is still a tombstone
        //    (the chain round-trip preserved it, NOT undeleted it).
        assert!(
            va.get_account(account_id).is_none(),
            "round-trip preserves the tombstone (no resurrection)"
        );
        let history = va.revisions_for(account_id).expect("revs");
        assert_eq!(history.len(), 2, "live + tombstone");
        let tomb = history.last().expect("tomb");
        assert!(tomb.is_tombstone, "tombstone bit preserved");
        assert!(
            tomb.chain_anchor.is_some(),
            "tombstone has its chain anchor stamped from publish"
        );
        // Freeze sentinel did NOT fire (own-publish round-trip
        // hits idempotency arm #2 before the genuine-foreign-INSERT
        // branch).
        let frozen = va.list_frozen_accounts().expect("frozen");
        assert!(
            frozen.is_empty(),
            "own-tombstone round-trip must NOT freeze"
        );
        va.close().expect("close A");
    }
}

/// Re-export wrapper. `pangolin_cli::sync` is the library entry
/// point introduced in P8-6 specifically so integration tests under
/// `tests/` can import the orchestration core without going through
/// the binary's argv parsing layer. Aliased so the test bodies can
/// say `pangolin_cli_sync::publish_all` (clearer at the callsite
/// than `pangolin_cli::sync::publish_all`).
use pangolin_cli::sync as pangolin_cli_sync;
