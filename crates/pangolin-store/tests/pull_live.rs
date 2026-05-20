// SPDX-License-Identifier: AGPL-3.0-or-later
//! 5.2 R-f `#[ignore]`'d live pull-loop test against D-017 (Option D
//! residue per issue #98).
//!
//! Verifies the end-to-end pull cycle against the live D-017
//! `RevisionPublished` event stream on Base Sepolia: the picker
//! re-runs each cycle (R-c), slow-mode delegates to 4.1's
//! `Vault::sync_from_chain` (L4), and the monotonic checkpoint
//! advances on success.
//!
//! ## Why `#[ignore]`'d (operator-visible failure mode)
//!
//! Sibling of the hermetic
//! `tests/replay_d017_pull_batch_advances_checkpoint.rs` (which runs
//! on every PR using the captured D-014 V0 event fixture + a mock
//! chain adapter). This live residue exercises (i) the slow-mode
//! `Vault::pull_once` path against the rolling D-017 chain tip, and
//! (ii) the checkpoint-monotonicity property under a real RPC's
//! finalization semantics.
//!
//! **Operator-visible failure mode:** if the test fails when run via
//! `scripts/run-live-tests.{sh,ps1}`, either (i) the live D-017
//! contract address or domain separator drifted (recovery: re-pin
//! `EXPECTED_DEPLOYED_ADDRESS_BASE_SEPOLIA` and the JSON record), or
//! (ii) the slow-mode checkpoint regressed below its prior value
//! (recovery: investigate `Vault::last_synced_block_v1` storage path).
//!
//! ## How to run
//!
//! ```text
//! BASE_SEPOLIA_RPC_URL=https://sepolia.base.org \
//!     PANGOLIN_PULL_LIVE_VAULT_ID=<64-char hex, no 0x prefix> \
//!     cargo test -p pangolin-store --test pull_live \
//!     -- --ignored
//! ```
//!
//! Or, easier: `bash scripts/run-live-tests.sh` (sources `.env.live`).
//!
//! ## Issue #98 fix-comment
//!
//! The previously-pinned D-017 deploy-block comment below referenced
//! `23640113` (the rotted Rust constant value). The authoritative
//! deploy block is `41_507_120` (cast-verified via `cast tx
//! 0x22e464123c7fc1c71a161350d521ed7946975b0a9a3b9fd232d8846327cacd19`).
//! See `pangolin_chain::d017_deploy_block` docstring for the rot-fix
//! history.

#![forbid(unsafe_code)]

use pangolin_crypto::secret::SecretBytes;
use pangolin_store::{
    PinIdentityProof, PressYPresenceProof, PullError, PullReport, SyncMode, SyncModePreference,
    Vault,
};

/// Live pull cycle against D-017. Requires:
///
/// - `BASE_SEPOLIA_RPC_URL` env var pointing at a Base Sepolia RPC.
/// - `PANGOLIN_PULL_LIVE_VAULT_ID` env var carrying a 64-char hex
///   (no `0x`) vault id known to exist in D-017's event history.
///
/// Without those env vars set, the test is a no-op return; the
/// `#[ignore]` keeps CI from running it by default.
#[tokio::test]
#[ignore = "requires BASE_SEPOLIA_RPC_URL + PANGOLIN_PULL_LIVE_VAULT_ID + captured event fixture"]
async fn live_pull_once_against_d017_advances_checkpoint() {
    // Issue #101 (R-b): parametrized over BaseSepolia (default) vs Dev /
    // local anvil (`PANGOLIN_CHAIN_ENV=dev`). The seam lives in
    // `pangolin_chain::test_env` (compiled here via the test-utilities
    // dev-dep). L6: in dev mode a missing RPC / vault id is a HARD error,
    // never a skip — `require_or_fail` panics in dev mode.
    use pangolin_chain::test_env;
    let target = test_env::target_chain_env();
    let rpc_url = match std::env::var("BASE_SEPOLIA_RPC_URL") {
        Ok(s) if !s.is_empty() => s,
        _ => {
            if !test_env::require_or_fail("BASE_SEPOLIA_RPC_URL not set") {
                return;
            }
            unreachable!("require_or_fail panics in dev mode");
        }
    };
    let vault_id_hex = match std::env::var("PANGOLIN_PULL_LIVE_VAULT_ID") {
        Ok(s) if !s.is_empty() => s,
        _ => {
            if !test_env::require_or_fail("PANGOLIN_PULL_LIVE_VAULT_ID not set") {
                return;
            }
            unreachable!("require_or_fail panics in dev mode");
        }
    };
    assert_eq!(vault_id_hex.len(), 64, "vault id must be 64 hex chars");
    let mut vault_id = [0u8; 32];
    for (i, byte) in vault_id.iter_mut().enumerate() {
        let hex = &vault_id_hex[i * 2..i * 2 + 2];
        *byte = u8::from_str_radix(hex, 16).expect("valid hex");
    }

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("live.pvf");
    let pwd = SecretBytes::new(b"correct horse battery staple".to_vec());
    Vault::create(&path, &pwd).expect("create");
    let mut v = Vault::open(&path).expect("open");
    let presence = PressYPresenceProof::confirmed();
    let identity = PinIdentityProof::new(pwd);
    v.unlock(&presence, &identity).expect("unlock");
    // Force Slow so the picker re-runs against a live RPC + actually
    // dispatches to `sync_from_chain` (the fresh-vault-no-checkpoint
    // path would otherwise return OfferFast).
    v.set_sync_mode_preference(SyncModePreference::AlwaysSlow)
        .expect("set preference");

    let pre_checkpoint = v.last_synced_block_v1().expect("read checkpoint");
    let report = v
        .pull_once(&rpc_url, target, &vault_id)
        .await
        .expect("pull cycle should succeed against live D-017");
    let post_checkpoint = v.last_synced_block_v1().expect("read checkpoint");
    eprintln!(
        "live pull: pre={pre_checkpoint:?} ⇒ post={post_checkpoint:?}, report.mode={:?}, sync_report={:?}",
        report.mode, report.sync_report
    );
    // Shape assertion: a successful slow-mode pull must have advanced
    // the checkpoint past whatever it was before (or kept it equal if
    // the chain head hadn't moved between ticks — production RPC
    // returns may produce either).
    let post = post_checkpoint.expect("checkpoint after slow pull should be Some");
    let pre = pre_checkpoint.unwrap_or(0);
    assert!(post >= pre, "checkpoint must be monotonic non-decreasing");
    // The wrapped 4.1 SyncReport must be present on a Slow cycle.
    assert!(
        report.sync_report.is_some(),
        "Slow dispatch must wrap a SyncReport"
    );
    // `last_pull_at_unix_ms` was stamped.
    assert!(v.last_pull_at_unix_ms().is_some());
    // Demonstrate teardown handling: lock + retry.
    v.lock();
    let err = v
        .pull_once(&rpc_url, target, &vault_id)
        .await
        .expect_err("locked ⇒ NoActiveSession");
    assert!(matches!(err, PullError::NoActiveSession));
    let _ = report.pulled_at_unix_ms; // unused-binding guard
    let _: PullReport = PullReport {
        mode: SyncMode::Slow,
        sync_report: None,
        pulled_at_unix_ms: 0,
        newly_frozen_accounts: Vec::new(),
        newly_forked_accounts: Vec::new(),
        newly_resolved_accounts: Vec::new(),
    }; // ensure PullReport public construction shape is honored
}
