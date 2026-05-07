//! **P10-4.** Offline-mode end-to-end integration tests.
//!
//! Pin the master plan §3.7 P10-2 / §3.8 invariant: "All edits queue
//! locally when offline; reconnect publishes deterministically." The
//! tests use `MockChainAdapter::set_disconnected(bool)` (the
//! test-utilities-gated toggle introduced in P10-4) to simulate a
//! network outage; they exercise the full disconnect → edit →
//! reconnect → publish flow through the same `publish_all` /
//! `pull_all` orchestrators the user invokes via `pangolin-cli`.
//!
//! **Production-safety note.** The disconnect toggle is
//! test-utilities-feature-gated; the production binary cannot
//! construct a disconnected mock (and never links against
//! `MockChainAdapter` at all — the mock module is gated alongside).
//! An audit reviewer who finds `set_disconnected` in the binary's
//! symbol table is looking at a test build.
//!
//! ## E2E-005 reproducibility
//!
//! The manual-path reproducibility recipe lives in `E2E_TESTS.md`
//! E2E-005; this file is the automated-path companion.

use std::path::{Path, PathBuf};

use pangolin_chain::MockChainAdapter;
use pangolin_crypto::keys::DeviceKey;
use pangolin_crypto::secret::SecretBytes;
use pangolin_store::session::{PinIdentityProof, PressYPresenceProof};
use pangolin_store::{AccountSnapshot, Vault};
use tempfile::TempDir;

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

fn create_locked_vault(dir: &TempDir, name: &str) -> PathBuf {
    let path = dir.path().join(name);
    Vault::create(&path, &pwd()).expect("create");
    path
}

fn open_unlocked(path: &Path) -> Vault {
    let mut v = Vault::open(path).expect("open");
    let presence = PressYPresenceProof::confirmed();
    let identity = PinIdentityProof::new(pwd());
    v.unlock(&presence, &identity).expect("unlock");
    v
}

/// **P10-4.** End-to-end offline-edit-then-online-publish flow:
///
/// 1. **Connected.** Vault A creates one account; publish succeeds.
/// 2. **Disconnect.** Open vault, unlock, add 5 more accounts,
///    update one of them, delete one (writes a tombstone via the
///    P10-1 widened payload schema). All edits succeed locally;
///    `Vault::list_dirty()` returns the queued entries.
/// 3. **Publish-while-disconnected fails.** Every per-entry
///    `publish_all` attempt errors with `ChainError::Rpc`; dirty
///    markers PRESERVED (P8 invariant); freeze sentinel does NOT
///    fire (no chain ingest happened).
/// 4. **Reconnect.** Toggle `set_disconnected(false)`. `publish_all`
///    succeeds for every queued entry; the chain has 1+5+1+1 = 8
///    events.
/// 5. **Final state.** `Vault::list_dirty()` is empty;
///    `Vault::list_accounts().len() == 5` (genesis account
///    untouched + 5 added - 1 tombstoned, the genesis account being
///    the original publish from step 1).
async fn step1_connected_publish_initial(
    path: &Path,
    adapter: &MockChainAdapter,
    device: &DeviceKey,
) -> pangolin_store::AccountId {
    let mut v = open_unlocked(path);
    let id = v.add_account(snap("initial")).expect("add initial");
    let report = pangolin_cli_sync::publish_all(&mut v, adapter, device)
        .await
        .expect("publish initial");
    assert_eq!(report.published_count(), 1);
    assert!(v.list_dirty().expect("list dirty").is_empty());
    v.close().expect("close");
    id
}

fn step2_offline_edits(path: &Path) -> (Vec<pangolin_store::AccountId>, pangolin_store::AccountId) {
    let mut v = open_unlocked(path);
    let mut ids = Vec::new();
    for i in 0..5 {
        let id = v
            .add_account(snap(&format!("offline-add-{i}")))
            .expect("add while offline");
        ids.push(id);
    }
    let updated_id = ids[0];
    v.update_account(updated_id, snap("offline-updated"))
        .expect("update while offline");
    let deleted_id = ids[1];
    v.delete_account(deleted_id).expect("delete while offline");
    let dirty = v.list_dirty().expect("list dirty");
    assert!(
        dirty.len() >= 6,
        "expected at least 6 dirty entries after offline session, got {}",
        dirty.len()
    );
    v.close().expect("close offline-edit handle");
    (ids, deleted_id)
}

async fn step3_publish_while_offline_fails(
    path: &Path,
    adapter: &MockChainAdapter,
    device: &DeviceKey,
) {
    let mut v = open_unlocked(path);
    let report = pangolin_cli_sync::publish_all(&mut v, adapter, device)
        .await
        .expect("publish_all returns the report; per-entry failures are inside");
    assert_eq!(report.published_count(), 0);
    assert!(report.failed_count() >= 6);
    assert!(v.list_dirty().expect("list dirty").len() >= 6);
    assert!(v.list_frozen_accounts().expect("list frozen").is_empty());
    v.close().expect("close");
}

async fn step4_reconnect_publish_drains_queue(
    path: &Path,
    adapter: &MockChainAdapter,
    device: &DeviceKey,
) {
    let mut v = open_unlocked(path);
    let report = pangolin_cli_sync::publish_all(&mut v, adapter, device)
        .await
        .expect("publish_all on reconnect");
    assert_eq!(report.failed_count(), 0, "no entry fails on reconnect");
    assert!(v.list_dirty().expect("list dirty").is_empty());
    v.close().expect("close");
}

#[tokio::test]
async fn offline_edit_then_online_publish() {
    let adapter = MockChainAdapter::new();
    let dir = TempDir::new().expect("dir");
    let path = create_locked_vault(&dir, "v.pvf");
    let device = DeviceKey::generate();

    let initial_account_id = step1_connected_publish_initial(&path, &adapter, &device).await;
    assert_eq!(adapter.event_count(), 1, "chain has 1 event after step 1");

    adapter.set_disconnected(true);
    let (_added_ids, deleted_id) = step2_offline_edits(&path);
    step3_publish_while_offline_fails(&path, &adapter, &device).await;

    adapter.set_disconnected(false);
    step4_reconnect_publish_drains_queue(&path, &adapter, &device).await;

    // Final state: 1 initial + 5 added - 1 tombstoned = 5 visible.
    let v = open_unlocked(&path);
    let visible = v.list_accounts();
    assert_eq!(
        visible.len(),
        5,
        "1 initial + 5 added - 1 tombstoned = 5 visible accounts"
    );
    assert!(
        visible.contains(&initial_account_id),
        "initial account survives the offline session"
    );
    assert!(
        !visible.contains(&deleted_id),
        "deleted account is filtered out"
    );
    // Chain has at least 1 initial + 5 add + 1 update + 1 tombstone
    // = 8 events. (Could be more if dirty-list dedup produced
    // additional rows; the lower bound is what the plan specifies.)
    assert!(
        adapter.event_count() >= 8,
        "chain has at least 8 events (1 initial + 5 add + 1 update + 1 tombstone), got {}",
        adapter.event_count()
    );
    v.close().expect("close");
}

/// **P10-4 A7.** Offline `publish_all` against an empty dirty list
/// is a no-op (no per-entry attempts), so the report is empty AND
/// the connectivity-precheck never fires (the orchestrator's
/// pre-flight `pull_since` call does fail with `ChainError::Rpc`,
/// but `publish_all` swallows that into the `chain_view` None branch
/// and proceeds to the empty loop). This is the
/// counter-test to the plan's §A7 "publish requires connectivity"
/// statement: under the orchestrator's actual implementation, an
/// empty dirty list means there's nothing to publish, and the
/// chain-view precheck failure is non-fatal.
///
/// The user-facing surface (`pangolin-cli publish` subcommand) DOES
/// require connectivity for the underlying adapter constructor to
/// succeed, but that's at the binary's argv-parsing layer, not the
/// `sync::publish_all` library entry point. The §A7 invariant is
/// preserved at the binary boundary.
#[tokio::test]
async fn offline_publish_with_no_dirty_entries_is_noop_at_lib_layer() {
    let adapter = MockChainAdapter::new();
    let dir = TempDir::new().expect("dir");
    let path = create_locked_vault(&dir, "noop.pvf");
    let device = DeviceKey::generate();

    adapter.set_disconnected(true);
    let mut v = open_unlocked(&path);
    let report = pangolin_cli_sync::publish_all(&mut v, &adapter, &device)
        .await
        .expect("publish_all on empty dirty list");
    assert_eq!(report.published_count(), 0);
    assert_eq!(report.failed_count(), 0);
    assert!(v.list_dirty().expect("list dirty").is_empty());
}

/// **P10-4 A7 / A6.** During the offline session, no `pull_all`
/// call has been made (the user is offline), so the freeze
/// sentinel does NOT fire. This is structurally guaranteed
/// (`pull_all` would have errored with `ChainError::Rpc` before
/// invoking `Vault::ingest_chain_revision`), but pinning explicitly
/// catches a future refactor that, e.g., moves freeze-setting into
/// the publish path.
#[tokio::test]
async fn offline_session_does_not_set_freeze_sentinel() {
    let adapter = MockChainAdapter::new();
    let dir = TempDir::new().expect("dir");
    let path = create_locked_vault(&dir, "freeze.pvf");
    let device = DeviceKey::generate();

    // Connect, create, publish.
    {
        let mut v = open_unlocked(&path);
        v.add_account(snap("freeze-test")).expect("add");
        pangolin_cli_sync::publish_all(&mut v, &adapter, &device)
            .await
            .expect("publish");
        v.close().expect("close");
    }
    // Disconnect, edit locally.
    adapter.set_disconnected(true);
    {
        let mut v = open_unlocked(&path);
        v.add_account(snap("offline-extra")).expect("add offline");
        // Attempt publish_all — every entry fails.
        let _ = pangolin_cli_sync::publish_all(&mut v, &adapter, &device)
            .await
            .expect("publish_all returns even when disconnected");
        // Attempt pull_all — fails before `ingest_chain_revision`
        // is called.
        let pull = pangolin_cli_sync::pull_all(&mut v, &adapter, None, None).await;
        assert!(pull.is_err(), "pull_all must propagate the chain Rpc error");
        // Freeze sentinel: still empty.
        let frozen = v.list_frozen_accounts().expect("list frozen");
        assert!(
            frozen.is_empty(),
            "no chain ingest happened → freeze sentinel must NOT fire"
        );
        v.close().expect("close");
    }
}

/// Re-export wrapper. Same pattern as `two_vault_roundtrip.rs` —
/// tests under `tests/` import the orchestration core via
/// `pangolin_cli::sync` rather than going through the binary's argv
/// parsing layer.
use pangolin_cli::sync as pangolin_cli_sync;
