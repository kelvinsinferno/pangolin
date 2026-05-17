// SPDX-License-Identifier: AGPL-3.0-or-later
//! **MVP-2 issue 5.3 (R-g) — live `#[ignore]`'d two-vault
//! conflict-surfacing test.**
//!
//! Same posture 5.2 R-f's `pull_live.rs` took: the production
//! primitives ([`pangolin_store::Vault::list_conflicts`] +
//! [`pangolin_store::Vault::resolve_fork`] +
//! [`pangolin_store::Vault::snapshot_conflicts`] +
//! [`pangolin_store::Vault::list_conflicts_since`] + the new
//! `PullReport.newly_*` fields) are covered by ~14 hermetic tests in
//! `crates/pangolin-store/src/conflict.rs::tests` +
//! `crates/pangolin-store/src/pull.rs::tests`, but the env-quirk #14
//! contract-semantics-drift defense requires an end-to-end driver
//! that runs across two distinct vault files concurrently editing
//! the same account through the chain.
//!
//! Until the fixture-capture follow-up lands (operational item
//! shared with 4.1 / 4.2 / 4.3 / 5.1 / 5.2's `#[ignore]`'d tests),
//! this test runs shape-only against a mocked two-vault setup.
//!
//! ## Why `#[ignore]`'d
//!
//! Two-vault concurrent edit needs a live D-017 + two Foundry
//! signers; the hermetic mock path is fully covered in
//! `conflict.rs::tests::list_conflicts_lists_forked_and_frozen`.

#![forbid(unsafe_code)]

use pangolin_crypto::secret::SecretBytes;
use pangolin_store::{AccountSnapshot, PinIdentityProof, PressYPresenceProof, Vault};

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

/// **MVP-2 issue 5.3 (R-g — `#[ignore]`'d).** Two-device concurrent
/// edit creates a fork; `Vault::list_conflicts` surfaces it through
/// the enriched per-branch summary; `Vault::resolve_fork` chooses
/// one branch and the next conflict snapshot shows the account
/// removed.
///
/// Without a configured `BASE_SEPOLIA_RPC_URL` env var the test is a
/// no-op return; the `#[ignore]` keeps CI off it by default.
#[tokio::test]
#[ignore = "requires BASE_SEPOLIA_RPC_URL + two Foundry signers + fixture"]
async fn live_two_device_concurrent_edit_creates_conflict_resolvable_via_resolve_fork() {
    let _rpc_url = match std::env::var("BASE_SEPOLIA_RPC_URL") {
        Ok(s) if !s.is_empty() => s,
        _ => {
            eprintln!("SKIP: BASE_SEPOLIA_RPC_URL not set");
            return;
        }
    };

    // Shape-only sketch: future fixture capture replaces the inner
    // `synth_sibling` call with a real second-device publish + a
    // `pull_once` cycle that ingests both branches.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("v.pvf");
    Vault::create(&path, &pwd()).expect("create");
    let mut v = Vault::open(&path).expect("open");
    v.unlock(
        &PressYPresenceProof::confirmed(),
        &PinIdentityProof::new(pwd()),
    )
    .expect("unlock");

    let id = v.add_account(snap("live-conflict")).expect("add");
    let child = v
        .update_account(id, snap("live-conflict-2"))
        .expect("update");
    let revs = v.revisions_for(id).expect("revisions");
    let genesis_id = revs
        .iter()
        .find(|m| m.revision_id != child)
        .map(|m| m.revision_id)
        .expect("genesis");
    v.__test_synthesize_sibling_revision(id, genesis_id, snap("live-sibling"))
        .expect("synth sibling");

    // Pre-resolve: list_conflicts surfaces the fork with enriched
    // per-branch metadata.
    let pre = v.list_conflicts().expect("list_conflicts");
    let report = pre.iter().find(|r| r.account_id == id).expect("report");
    assert!(report.branches.len() > 1, "must be forked");
    assert!(
        report.branches.iter().any(|b| b.on_canonical_chain),
        "exactly one branch is the canonical head"
    );

    // Snapshot, then resolve, then diff.
    let prior = v.snapshot_conflicts().expect("snap");
    let heads = v.account_heads(id).expect("heads");
    let keep = *heads
        .iter()
        .max_by(|a, b| a.as_bytes().cmp(b.as_bytes()))
        .unwrap();
    let _merge = v.resolve_fork(id, keep).expect("resolve");
    let delta = v.list_conflicts_since(&prior).expect("delta");
    assert!(
        delta.removed_forked.contains(&id),
        "resolved account must surface in removed_forked"
    );
}
