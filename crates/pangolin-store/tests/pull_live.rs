// SPDX-License-Identifier: AGPL-3.0-or-later
//! 5.2 R-f `#[ignore]`'d live pull-loop test against D-017.
//!
//! Verifies the end-to-end pull cycle against the live D-017
//! `RevisionPublished` event stream on Base Sepolia: the picker
//! re-runs each cycle (R-c), slow-mode delegates to 4.1's
//! `Vault::sync_from_chain` (L4), and the monotonic checkpoint
//! advances on success.
//!
//! ## Why `#[ignore]`'d
//!
//! Same posture 4.1 R-g / 4.2 R-f / 4.3 R-f / 5.1 R-g took: the
//! production primitive (`Vault::pull_once`) is covered by ~14
//! hermetic tests in `crates/pangolin-store/src/pull.rs::tests`,
//! but the env-quirk #14 contract-semantics-drift defense requires
//! a captured `RevisionPublished` event payload from D-017's actual
//! history. Until the fixture-capture follow-up lands (an
//! operational item shared with 4.1 / 4.2 / 4.3 / 5.1's
//! `#[ignore]`'d tests), this test runs shape-only against a
//! configured RPC + vault id.
//!
//! ## How to run + capture a fixture
//!
//! ```text
//! # 1. Capture any historical RevisionPublished event from D-017:
//! cast logs --address 0x179362Ad7fb7dA664312aEFDdaa53431eb748E42 \
//!     --from-block 23640113 \
//!     --to-block latest \
//!     --rpc-url $BASE_SEPOLIA_RPC_URL
//!
//! # 2. Pin the resulting (vault_id, block, tx_hash) tuple as a
//! #    const at the top of this module.
//!
//! # 3. Run the test:
//! BASE_SEPOLIA_RPC_URL=https://sepolia.base.org \
//!     PANGOLIN_PULL_LIVE_VAULT_ID=<64-char hex, no 0x prefix> \
//!     cargo test -p pangolin-store --test pull_live \
//!     -- --ignored
//! ```

#![forbid(unsafe_code)]

use pangolin_chain::ChainEnv;
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
    let rpc_url = match std::env::var("BASE_SEPOLIA_RPC_URL") {
        Ok(s) if !s.is_empty() => s,
        _ => {
            eprintln!("SKIP: BASE_SEPOLIA_RPC_URL not set");
            return;
        }
    };
    let vault_id_hex = match std::env::var("PANGOLIN_PULL_LIVE_VAULT_ID") {
        Ok(s) if !s.is_empty() => s,
        _ => {
            eprintln!("SKIP: PANGOLIN_PULL_LIVE_VAULT_ID not set");
            return;
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
        .pull_once(&rpc_url, ChainEnv::BaseSepolia, &vault_id)
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
        .pull_once(&rpc_url, ChainEnv::BaseSepolia, &vault_id)
        .await
        .expect_err("locked ⇒ NoActiveSession");
    assert!(matches!(err, PullError::NoActiveSession));
    let _ = report.pulled_at_unix_ms; // unused-binding guard
    let _: PullReport = PullReport {
        mode: SyncMode::Slow,
        sync_report: None,
        pulled_at_unix_ms: 0,
    }; // ensure PullReport public construction shape is honored
}
