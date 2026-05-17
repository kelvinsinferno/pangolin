// SPDX-License-Identifier: AGPL-3.0-or-later
//! CLI-V1 per-verb integration smoke tests (R-f).
//!
//! Drives the engine surface that the CLI-V1 subcommands wrap —
//! without spawning the binary (the binary path is exercised by
//! `tests/cli_arg_parsing.rs`). Validates the load-bearing
//! behaviors per `docs/issue-plans/cli-v1.md`:
//!
//! - `flush_command_drains_dirty_queue`
//! - `queue_status_emits_dirty_count`
//! - `pull_status_emits_last_pulled_block`
//! - `sync_mode_show_emits_preference`
//! - `sync_mode_set_writes_preference`
//! - `wallet_show_emits_address`
//! - `balance_show_emits_state`

#![forbid(unsafe_code)]

use pangolin_chain::MockChainAdapter;
use pangolin_crypto::keys::DeviceKey;
use pangolin_crypto::secret::SecretBytes;
use pangolin_store::session::{PinIdentityProof, PressYPresenceProof};
use pangolin_store::{AccountSnapshot, SyncModePreference, Vault};
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

fn open_unlocked(path: &std::path::Path) -> Vault {
    let mut v = Vault::open(path).expect("open");
    v.unlock(
        &PressYPresenceProof::confirmed(),
        &PinIdentityProof::new(pwd()),
    )
    .expect("unlock");
    v
}

/// `flush` (via `Vault::flush_publish_queue`) drains the dirty
/// queue — after the call, `list_dirty()` is empty.
#[tokio::test]
async fn flush_command_drains_dirty_queue() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("v.pvf");
    Vault::create(&path, &pwd()).expect("create");
    let adapter = MockChainAdapter::new();
    let device = DeviceKey::generate();
    let mut v = open_unlocked(&path);
    v.add_account(snap("flush-test")).expect("add");
    assert!(!v.list_dirty().expect("list").is_empty());
    let report = v
        .flush_publish_queue(&adapter, &device, true)
        .await
        .expect("flush");
    assert_eq!(report.publish_report.failed_count(), 0);
    assert_eq!(report.publish_report.published_count(), 1);
    assert!(v.list_dirty().expect("list after").is_empty());
}

/// `queue-status` (via `Vault::publish_queue_state`) reports the
/// dirty count + byte size.
#[tokio::test]
async fn queue_status_emits_dirty_count() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("v.pvf");
    Vault::create(&path, &pwd()).expect("create");
    let mut v = open_unlocked(&path);
    v.add_account(snap("q-test")).expect("add");
    let state = v.publish_queue_state().expect("state");
    assert_eq!(state.dirty_count, 1);
    assert!(state.dirty_byte_size > 0);
    assert!(!state.blocked_on_balance);
}

/// `pull-status` (via `last_pulled_block` + `last_pull_at_unix_ms`)
/// emits the load-bearing fields. A fresh vault has
/// `last_pulled_block = 0` and `last_pull_at_unix_ms = None`.
#[tokio::test]
async fn pull_status_emits_last_pulled_block() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("v.pvf");
    Vault::create(&path, &pwd()).expect("create");
    let v = open_unlocked(&path);
    assert_eq!(v.last_pulled_block().expect("last_pulled"), 0);
    assert!(v.last_pull_at_unix_ms().is_none());
}

/// `sync-mode show` (via `Vault::sync_mode_preference`) emits the
/// persisted preference (default `Auto` on a fresh vault).
#[tokio::test]
async fn sync_mode_show_emits_preference() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("v.pvf");
    Vault::create(&path, &pwd()).expect("create");
    let v = open_unlocked(&path);
    let pref = v.sync_mode_preference().expect("pref");
    assert_eq!(pref, SyncModePreference::Auto);
}

/// `sync-mode set` (via `Vault::set_sync_mode_preference`)
/// persists the preference across close/reopen.
#[tokio::test]
async fn sync_mode_set_writes_preference() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("v.pvf");
    Vault::create(&path, &pwd()).expect("create");
    {
        let mut v = open_unlocked(&path);
        v.set_sync_mode_preference(SyncModePreference::AlwaysFast)
            .expect("set");
        v.close().expect("close");
    }
    // Reopen + verify persistence.
    let v = open_unlocked(&path);
    let pref = v.sync_mode_preference().expect("pref");
    assert_eq!(pref, SyncModePreference::AlwaysFast);
}

/// `wallet show` (via `Vault::evm_wallet_address`) emits the
/// 20-byte address.
#[tokio::test]
async fn wallet_show_emits_address() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("v.pvf");
    Vault::create(&path, &pwd()).expect("create");
    let v = open_unlocked(&path);
    let addr = v.evm_wallet_address().expect("address");
    assert_eq!(addr.len(), 20);
}

/// `balance show` (via `BalanceMonitor::current`) emits a typed
/// state — `Unknown` is acceptable for an unreachable RPC URL.
///
/// `BalanceMonitor::current` uses `RwLock::blocking_read` which
/// cannot be called from inside the runtime's worker thread —
/// production callers invoke it from the host's main thread (NOT
/// a tokio worker). Mirror the 3.5 FFI test pattern via
/// `spawn_blocking`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn balance_show_emits_state() {
    use core::time::Duration;

    use alloy::primitives::Address;
    use pangolin_chain::{BalanceMonitor, ChainEnv};

    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("v.pvf");
    Vault::create(&path, &pwd()).expect("create");
    let v = open_unlocked(&path);
    let bytes = v.evm_wallet_address().expect("address");
    let monitor = std::sync::Arc::new(BalanceMonitor::start(
        "http://127.0.0.1:1".to_string(),
        Address::from(bytes),
        ChainEnv::BaseSepolia,
        Duration::from_secs(30),
    ));
    tokio::time::sleep(Duration::from_millis(100)).await;
    // `current` runs on a blocking worker thread — calling it
    // from inside the runtime's worker would deadlock.
    let m_clone = std::sync::Arc::clone(&monitor);
    let _ = tokio::task::spawn_blocking(move || m_clone.current())
        .await
        .expect("spawn_blocking");
    monitor.stop().await;
}
