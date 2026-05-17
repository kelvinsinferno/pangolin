// SPDX-License-Identifier: AGPL-3.0-or-later
//! Conflict-resolution surface for `pangolin-cli resolve` (P9) and the
//! 5.3 FFI binding (`vault_list_conflicts`).
//!
//! Single user-facing report shape that the resolve subcommand reads
//! out of [`crate::Vault::list_conflicts`]. The report joins fork
//! state and freeze state — both surface "this account needs the
//! user's attention" but they are structurally distinct conditions:
//!
//! - **Forked** (`branches.len() > 1`): the local revision graph has
//!   two or more revisions with no children for the same `account_id`.
//!   Either two local handles edited the same parent (no chain
//!   involvement yet) or the chain landed two children of the same
//!   parent that the local store ingested.
//! - **Frozen** (`frozen = true`): the chain landed a foreign event
//!   under the genuine-foreign-INSERT path of
//!   [`crate::Vault::ingest_chain_revision`] (none of the three
//!   idempotency-merge arms matched). The user-facing read paths
//!   refuse on this account until [`crate::Vault::clear_frozen`] runs
//!   (typically as the final step of `pangolin-cli resolve`).
//!
//! An account can be in either, both, or neither state. The
//! `list_conflicts` query unions the fork set and the freeze set so
//! the resolve UX shows everything that needs resolution in one
//! pass.
//!
//! ## Frozen-with-single-branch case
//!
//! When `ingest_chain_revision` runs the genuine-foreign-INSERT path
//! on a *fresh* foreign account (no prior local row), the just-
//! ingested revision becomes the only row in the local revision
//! graph for that account. The freeze flag is set; the conflict
//! report contains exactly one [`ConflictBranchSummary`]. The report
//! still includes this case (with `branches.len() == 1` and
//! `frozen = true`) because the user must run resolve to clear the
//! flag — the fact that the local graph is structurally linear does
//! NOT mean there is no conflict to resolve.
//!
//! ## MVP-2 issue 5.3 — enrichment (R-d) + delta accessor (R-c helper)
//!
//! Issue 5.3 replaced `heads: Vec<RevisionId>` with `branches:
//! Vec<ConflictBranchSummary>` so a host UI rendering the conflict
//! screen can lay out all the per-leaf metadata it needs (`parent`,
//! `device_id`, `observed_at_block`, `schema_version`,
//! `is_tombstone`, `on_canonical_chain`) in a single round-trip
//! rather than N+1 round-trips against
//! [`crate::Vault::revisions_for`].
//!
//! Issue 5.3 also introduced the [`ConflictSnapshot`] +
//! [`ConflictDelta`] types — a thin diff accessor that lets the host
//! (and the 5.4 indicator state machine) detect per-tick membership
//! changes in the conflict set without a full re-render.

use std::collections::HashSet;

use crate::account::AccountId;
use crate::revision::RevisionId;

/// **MVP-2 issue 5.3 (R-d).** Per-branch metadata for one leaf of a
/// conflicted account's revision graph.
///
/// Every field is metadata-class (already exposed via
/// [`crate::RevisionMeta`]); none of them carry plaintext / cipher
/// payload bytes. The host UI uses this record to lay out a
/// "branches" panel on the conflict-resolution screen and the user
/// picks one branch's `revision_id` to pass back into
/// [`crate::Vault::resolve_fork`] (or its FFI mirror
/// `account_resolve_fork`).
///
/// `on_canonical_chain` reflects the clock-free byte-lexicographic
/// largest-`revision_id` rule (1.6 R-c — `canonical_head`); a `true`
/// value means the leaf is (or shares an ancestor with) the elected
/// canonical head; `false` flags a losing branch that resolution
/// would supersede.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConflictBranchSummary {
    /// The leaf revision's id.
    pub revision_id: RevisionId,
    /// Parent revision id; `None` when the leaf is itself the
    /// genesis revision (parent == [`RevisionId::GENESIS_PARENT`]).
    pub parent: Option<RevisionId>,
    /// Authoring device id (32 raw bytes — matches the
    /// `DeviceId(.0)` shape used across the FFI surface).
    pub device_id: Vec<u8>,
    /// Block height at which the chain-sync ingest first observed
    /// this revision (chain-sync rows only). `None` for rows that
    /// were authored locally; for rows stamped via `mark_published`
    /// the fallback is the on-chain `chain_block_number` so the host
    /// always has *some* "first-seen-on-chain" anchor for display
    /// when it exists.
    pub observed_at_block: Option<u64>,
    /// AEAD payload schema version on this leaf row.
    pub schema_version: u32,
    /// `true` iff the leaf is a tombstone (deletion sentinel).
    pub is_tombstone: bool,
    /// `true` iff this leaf is on the canonical chain (= equals the
    /// canonical head OR is an ancestor of it). 1.6 R-c
    /// byte-lexicographic-largest-`revision_id` rule.
    pub on_canonical_chain: bool,
}

/// One row of [`crate::Vault::list_conflicts`]'s output.
///
/// Field semantics:
///
/// - `account_id` — the affected account.
/// - `branches` — one [`ConflictBranchSummary`] per current head of
///   the account's revision graph. Length 1 with `frozen = true` is
///   the freshly-foreign-account case described in the module docs.
///   Length > 1 is the forked case (with or without the freeze flag).
///   Iteration order is `revision_id` byte-order ASC for deterministic
///   output ordering.
/// - `frozen` — `true` iff the
///   `account_identities.frozen_pending_resolve` flag is set.
///
/// **MVP-2 issue 5.3 (R-d).** Replaced `heads: Vec<RevisionId>` with
/// `branches: Vec<ConflictBranchSummary>` so a host UI renders the
/// conflict-resolution screen in a single round-trip. The legacy
/// `heads` shape required N extra round-trips against
/// [`crate::Vault::revisions_for`] to flesh out per-branch metadata
/// the user needs to choose which branch to keep.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConflictReport {
    /// The affected account.
    pub account_id: AccountId,
    /// All current heads of `account_id`, each enriched with the
    /// metadata the host needs to render the per-branch picker. See
    /// module docs for the `branches.len() == 1 && frozen` case.
    pub branches: Vec<ConflictBranchSummary>,
    /// `true` iff `account_identities.frozen_pending_resolve = 1`
    /// for this row.
    pub frozen: bool,
}

/// **MVP-2 issue 5.3 (R-c helper).** Pre-tick snapshot of the
/// conflict set, suitable for passing to
/// [`crate::Vault::list_conflicts_since`].
///
/// The snapshot is two `HashSet`s — the frozen and the forked
/// account ids — taken at one consistent moment in time. The host
/// records one before a `pull_once` cycle (or any other dispatch
/// that may mutate the conflict set), then asks
/// [`crate::Vault::list_conflicts_since`] to diff the current state
/// against the snapshot to learn which accounts entered or left the
/// conflict surface.
///
/// The accessor pair complements
/// [`crate::pull::PullReport::newly_frozen_accounts`] et al. (which
/// already bake the per-cycle diff into the pull report itself);
/// [`ConflictSnapshot`] is the reusable building block when the host
/// needs to diff across a longer interval (e.g., across multiple
/// `pull_once` ticks for the 5.4 indicator state machine).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConflictSnapshot {
    /// Account ids whose `frozen_pending_resolve` flag was set at
    /// snapshot time.
    pub frozen: HashSet<AccountId>,
    /// Account ids that were forked (head count > 1) at snapshot
    /// time.
    pub forked: HashSet<AccountId>,
}

/// **MVP-2 issue 5.3 (R-c helper).** Per-account membership diff
/// computed by [`crate::Vault::list_conflicts_since`] against a prior
/// [`ConflictSnapshot`].
///
/// Set-difference semantics:
///
/// - `added_frozen` — `frozen NOW − frozen THEN`
/// - `removed_frozen` — `frozen THEN − frozen NOW` (i.e., resolved)
/// - `added_forked` — `forked NOW − forked THEN`
/// - `removed_forked` — `forked THEN − forked NOW`
///
/// The `removed_frozen` set is the load-bearing "an account was
/// resolved" channel for the 5.4 indicator state machine — these
/// are exactly the accounts whose conflict pill should disappear
/// from the host UI.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConflictDelta {
    /// Accounts that became frozen since the prior snapshot.
    pub added_frozen: Vec<AccountId>,
    /// Accounts that were frozen at the prior snapshot but are not
    /// frozen now (= resolved).
    pub removed_frozen: Vec<AccountId>,
    /// Accounts that became forked since the prior snapshot.
    pub added_forked: Vec<AccountId>,
    /// Accounts that were forked at the prior snapshot but are not
    /// forked now (= resolved or otherwise un-forked).
    pub removed_forked: Vec<AccountId>,
}

#[cfg(test)]
mod tests {
    //! P9-2 + 5.3 unit tests. All scenarios drive [`crate::Vault`]
    //! through its public API to set up the precondition (forked /
    //! frozen / both / neither) and then assert
    //! [`crate::Vault::list_conflicts`]'s output shape.

    use crate::account::AccountSnapshot;
    use crate::session::{PinIdentityProof, PressYPresenceProof};
    use crate::vault::Vault;
    use pangolin_crypto::secret::SecretBytes;
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

    fn fresh_unlocked() -> (Vault, TempDir) {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("v.pvf");
        Vault::create(&path, &pwd()).expect("create");
        let mut v = Vault::open(&path).expect("open");
        v.unlock(
            &PressYPresenceProof::confirmed(),
            &PinIdentityProof::new(pwd()),
        )
        .expect("unlock");
        (v, dir)
    }

    /// Build a `RevisionEvent` that takes the genuine-foreign-INSERT
    /// path inside `ingest_chain_revision` (different `device_id`
    /// from the local row's, distinct payload). Used here for the
    /// freeze-only and freeze+fork cases.
    fn foreign_event(
        vault_id: [u8; 32],
        account_id: [u8; 32],
        parent: [u8; 32],
        payload: &[u8],
        block: u64,
        log: u64,
    ) -> pangolin_chain::RevisionEvent {
        let device = pangolin_crypto::keys::DeviceKey::generate();
        pangolin_chain::RevisionEvent {
            vault_id,
            account_id,
            parent_revision: parent,
            device_id: device.verifying_key().to_bytes(),
            schema_version: 0,
            sequence: 0,
            enc_payload: payload.to_vec(),
            anchor: pangolin_chain::ChainAnchor {
                tx_hash: [0xAB; 32],
                block_number: block,
                log_index: log,
                sequence: 0,
            },
        }
    }

    /// **P9-2.** Clean vault: empty conflict list.
    #[test]
    fn list_conflicts_empty_on_clean_vault() {
        let (v, _d) = fresh_unlocked();
        let reports = v.list_conflicts().expect("list_conflicts ok");
        assert!(reports.is_empty(), "clean vault must have zero conflicts");
    }

    /// **P9-2.** Forked-only case: two local heads (no chain
    /// involvement), `frozen = false`, `branches.len() > 1`.
    ///
    /// Implementation note: a fork requires TWO revisions with the
    /// SAME parent. The genesis revision's parent is
    /// `RevisionId::GENESIS_PARENT` (all zeros), so we update once
    /// (producing a real child of genesis) and then synthesize a
    /// sibling sharing the same parent as that child — yielding a
    /// 2-head fork with no chain involvement.
    #[test]
    fn list_conflicts_lists_only_forked() {
        let (mut v, _d) = fresh_unlocked();
        let id = v.add_account(snap("forked-only")).expect("add");
        // First update produces a child of genesis. Now genesis
        // is no longer a head; the new revision is the head.
        let child_a = v.update_account(id, snap("forked-update")).expect("update");
        // Read the parent of `child_a` (= the genesis revision's id)
        // and synthesize a sibling under it. The sibling shares
        // genesis as parent ⇒ both `child_a` and `sibling` are heads.
        let revs = v.revisions_for(id).expect("revisions");
        let genesis_id = revs
            .iter()
            .find(|m| m.revision_id != child_a)
            .map(|m| m.revision_id)
            .expect("genesis row present");
        v.__test_synthesize_sibling_revision(id, genesis_id, snap("sibling"))
            .expect("synth sibling");

        let reports = v.list_conflicts().expect("list");
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].account_id, id);
        assert!(
            reports[0].branches.len() > 1,
            "forked must have ≥2 branches"
        );
        assert!(!reports[0].frozen, "forked-only must NOT be frozen");
    }

    /// **P9-2.** Freeze-only case (single branch + frozen). This is
    /// the CRIT-1-on-fresh-foreign-account scenario: a chain event
    /// for a brand-new account lands locally and sets the freeze.
    #[test]
    fn list_conflicts_lists_only_frozen() {
        let (mut v, _d) = fresh_unlocked();
        // Brand-new account_id, no prior local row. The genuine-
        // foreign-INSERT path creates the row + sets freeze.
        let foreign_acct = [0x99u8; 32];
        let ev = foreign_event(v.vault_id(), foreign_acct, [0u8; 32], b"foreign", 1, 0);
        v.ingest_chain_revision(&ev).expect("ingest");

        let reports = v.list_conflicts().expect("list");
        assert_eq!(reports.len(), 1);
        assert_eq!(*reports[0].account_id.as_bytes(), foreign_acct);
        assert_eq!(
            reports[0].branches.len(),
            1,
            "fresh foreign account ⇒ 1 branch"
        );
        assert!(reports[0].frozen, "freeze flag set on fresh foreign INSERT");
    }

    /// **P9-2.** Forked + frozen case: the local account already has
    /// revisions, then a chain event lands as a sibling of the local
    /// head (different parent ⇒ no merge, freeze fires, head count
    /// becomes 2).
    #[test]
    fn list_conflicts_lists_forked_and_frozen() {
        let (mut v, _d) = fresh_unlocked();
        let id = v.add_account(snap("both")).expect("add");
        // Same account_id, parent = genesis (matches the local
        // genesis row's parent), foreign device_id + payload —
        // forces the genuine-foreign-INSERT path. The local row's
        // own parent (genesis) has now sprouted a sibling, so heads
        // = {local_genesis, foreign_event}.
        let ev = foreign_event(v.vault_id(), *id.as_bytes(), [0u8; 32], b"foreign", 2, 0);
        v.ingest_chain_revision(&ev).expect("ingest");

        let reports = v.list_conflicts().expect("list");
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].account_id, id);
        assert!(reports[0].branches.len() > 1, "must be forked");
        assert!(reports[0].frozen, "must be frozen");
    }

    /// **P9-2.** The fresh-foreign-account case is documented
    /// explicitly: `frozen = true`, `branches.len() == 1`. Pinned as
    /// its own test because the resolve UX must surface it.
    #[test]
    fn list_conflicts_handles_frozen_with_single_branch() {
        let (mut v, _d) = fresh_unlocked();
        let foreign_acct = [0x77u8; 32];
        let ev = foreign_event(v.vault_id(), foreign_acct, [0u8; 32], b"f", 1, 0);
        v.ingest_chain_revision(&ev).expect("ingest");

        let reports = v.list_conflicts().expect("list");
        let report = reports
            .iter()
            .find(|r| *r.account_id.as_bytes() == foreign_acct)
            .expect("report present");
        assert!(report.frozen);
        assert_eq!(report.branches.len(), 1);
    }

    /// **P9-2.** An account that is BOTH forked AND frozen produces
    /// exactly ONE row in the report (not two — set-union, not
    /// concatenation).
    #[test]
    fn list_conflicts_dedup_when_account_is_both_forked_and_frozen() {
        let (mut v, _d) = fresh_unlocked();
        let id = v.add_account(snap("dedup")).expect("add");
        // Inject a foreign event that is a sibling of the local
        // genesis (so the account becomes forked AND frozen).
        let ev = foreign_event(v.vault_id(), *id.as_bytes(), [0u8; 32], b"foreign", 1, 0);
        v.ingest_chain_revision(&ev).expect("ingest");

        // Also stress: create a SECOND non-fork+non-frozen account so
        // the dedup logic isn't trivially exercised by a one-row
        // table.
        let _other = v.add_account(snap("other")).expect("add other");

        let reports = v.list_conflicts().expect("list");
        let matching: Vec<_> = reports.iter().filter(|r| r.account_id == id).collect();
        assert_eq!(matching.len(), 1, "dedup: account in BOTH sets ⇒ ONE row");
        assert!(matching[0].frozen);
        assert!(matching[0].branches.len() > 1);
    }

    // -----------------------------------------------------------------
    // MVP-2 issue 5.3 (R-d) — ConflictReport enrichment tests.
    // -----------------------------------------------------------------

    /// **5.3 R-d.** Forked report carries one `ConflictBranchSummary`
    /// per current head — parity with the old `heads` shape.
    #[test]
    fn list_conflicts_enriched_returns_branch_summary_per_head() {
        let (mut v, _d) = fresh_unlocked();
        let id = v.add_account(snap("enrich")).expect("add");
        let child = v.update_account(id, snap("enrich-2")).expect("update");
        let revs = v.revisions_for(id).expect("revisions");
        let genesis_id = revs
            .iter()
            .find(|m| m.revision_id != child)
            .map(|m| m.revision_id)
            .expect("genesis");
        v.__test_synthesize_sibling_revision(id, genesis_id, snap("sib"))
            .expect("synth");

        let reports = v.list_conflicts().expect("list");
        assert_eq!(reports.len(), 1);
        let heads = v.account_heads(id).expect("heads");
        assert_eq!(
            reports[0].branches.len(),
            heads.len(),
            "one summary per head — parity with the legacy heads shape"
        );
        // Every branch's revision_id must appear in the head set.
        for branch in &reports[0].branches {
            assert!(
                heads.contains(&branch.revision_id),
                "branch revision_id must be a current head"
            );
        }
    }

    /// **5.3 R-d.** The per-branch summary carries the `device_id`
    /// and `observed_at_block` fields populated from the underlying
    /// `revisions` row.
    #[test]
    fn list_conflicts_enriched_branch_summary_carries_device_id_and_observed_at_block() {
        let (mut v, _d) = fresh_unlocked();
        // Build a fresh-foreign-account freeze whose chain event has
        // a non-zero block number; ingest_chain_revision stamps
        // observed_at_block from the event's anchor.block_number.
        let foreign_acct = [0x44u8; 32];
        let ev = foreign_event(v.vault_id(), foreign_acct, [0u8; 32], b"obs", 9001, 0);
        v.ingest_chain_revision(&ev).expect("ingest");

        let reports = v.list_conflicts().expect("list");
        let report = reports
            .iter()
            .find(|r| *r.account_id.as_bytes() == foreign_acct)
            .expect("report");
        assert_eq!(report.branches.len(), 1);
        let branch = &report.branches[0];
        assert_eq!(branch.device_id, ev.device_id.to_vec(), "device_id wired");
        assert_eq!(
            branch.observed_at_block,
            Some(9001),
            "observed_at_block wired from the chain event's anchor"
        );
        assert!(!branch.is_tombstone, "non-deletion event ⇒ not tombstone");
        // A fresh-foreign-account single-branch case: the single
        // branch IS the canonical head (rule trivially yields the
        // only leaf), so on_canonical_chain == true.
        assert!(branch.on_canonical_chain);
    }

    /// **5.3 R-d.** A linearly-edited local account that becomes
    /// forked has branches whose `is_tombstone` matches the
    /// underlying revisions row — non-tombstone updates produce
    /// non-tombstone branches.
    #[test]
    fn list_conflicts_enriched_branch_summary_marks_is_tombstone_correctly() {
        let (mut v, _d) = fresh_unlocked();
        let id = v.add_account(snap("ts")).expect("add");
        let child = v.update_account(id, snap("ts-2")).expect("update");
        let revs = v.revisions_for(id).expect("revisions");
        let genesis_id = revs
            .iter()
            .find(|m| m.revision_id != child)
            .map(|m| m.revision_id)
            .expect("genesis");
        v.__test_synthesize_sibling_revision(id, genesis_id, snap("sib"))
            .expect("synth");

        let reports = v.list_conflicts().expect("list");
        let report = reports.iter().find(|r| r.account_id == id).expect("report");
        for branch in &report.branches {
            assert!(
                !branch.is_tombstone,
                "live edits + synth siblings are never tombstones in this fixture"
            );
        }
    }

    // -----------------------------------------------------------------
    // MVP-2 issue 5.3 (R-c helper) — snapshot_conflicts +
    // list_conflicts_since accessor tests.
    // -----------------------------------------------------------------

    /// **5.3 R-c helper.** Empty prior snapshot ⇒ every current
    /// conflicted account surfaces in the `added_*` sets.
    #[test]
    fn list_conflicts_since_empty_snapshot_returns_all_current_as_added() {
        let (mut v, _d) = fresh_unlocked();
        let foreign_acct = [0x55u8; 32];
        let ev = foreign_event(v.vault_id(), foreign_acct, [0u8; 32], b"x", 1, 0);
        v.ingest_chain_revision(&ev).expect("ingest");

        let empty = crate::conflict::ConflictSnapshot::default();
        let delta = v.list_conflicts_since(&empty).expect("delta");
        assert_eq!(delta.added_frozen.len(), 1, "fresh freeze surfaces");
        assert_eq!(*delta.added_frozen[0].as_bytes(), foreign_acct);
        assert!(delta.removed_frozen.is_empty());
    }

    /// **5.3 R-c helper.** Snapshot taken AFTER a freeze and diff
    /// against ITSELF ⇒ empty delta.
    #[test]
    fn list_conflicts_since_unchanged_returns_empty_delta() {
        let (mut v, _d) = fresh_unlocked();
        let foreign_acct = [0x66u8; 32];
        let ev = foreign_event(v.vault_id(), foreign_acct, [0u8; 32], b"x", 1, 0);
        v.ingest_chain_revision(&ev).expect("ingest");

        let snap = v.snapshot_conflicts().expect("snap");
        let delta = v.list_conflicts_since(&snap).expect("delta");
        assert!(
            delta.added_frozen.is_empty() && delta.removed_frozen.is_empty(),
            "no state change between snapshot and diff ⇒ empty delta"
        );
    }

    /// **5.3 R-c helper.** Snapshot a frozen account, then resolve
    /// it via `clear_frozen`, then diff ⇒ the account appears in
    /// `removed_frozen`.
    ///
    /// `clear_frozen` (not `resolve_fork`) is the right primitive
    /// here because `resolve_fork` decrypts the chosen branch's
    /// payload to re-seal a merge — and the foreign-event leaf's
    /// payload is NOT AEAD-decryptable with this vault's VDK (it
    /// was sealed by some other device's key). `clear_frozen` is
    /// the metadata-only step that clears the freeze flag once the
    /// caller has chosen a canonical head; it's the operation the
    /// resolve UX takes after picking a branch.
    #[test]
    fn list_conflicts_since_with_resolved_account_reports_in_removed() {
        let (mut v, _d) = fresh_unlocked();
        // Set up a freeze: a fresh foreign account whose first
        // revision lands locally as a single head (not forked) with
        // the freeze flag set. clear_frozen on that single head
        // clears the flag without needing to decrypt anything.
        let foreign_acct = [0xCCu8; 32];
        let ev = foreign_event(v.vault_id(), foreign_acct, [0u8; 32], b"r", 3, 0);
        v.ingest_chain_revision(&ev).expect("ingest");
        let id = crate::account::AccountId::from_bytes(foreign_acct);

        // Snapshot — the account is in frozen.
        let prior = v.snapshot_conflicts().expect("snap");
        assert!(prior.frozen.contains(&id));

        // Resolve by clearing the freeze flag on the (single)
        // current head. No decrypt; metadata-only.
        let heads = v.account_heads(id).expect("heads");
        assert_eq!(heads.len(), 1);
        v.clear_frozen(id, heads[0]).expect("clear_frozen");

        let delta = v.list_conflicts_since(&prior).expect("delta");
        assert!(
            delta.removed_frozen.contains(&id),
            "resolved account must surface in removed_frozen"
        );
    }
}
