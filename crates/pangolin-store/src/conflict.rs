//! Conflict-resolution surface for `pangolin-cli resolve` (P9).
//!
//! Single user-facing report shape that the resolve subcommand reads
//! out of [`crate::Vault::list_conflicts`]. The report joins fork
//! state and freeze state — both surface "this account needs the
//! user's attention" but they are structurally distinct conditions:
//!
//! - **Forked** (`heads.len() > 1`): the local revision graph has two
//!   or more revisions with no children for the same `account_id`.
//!   Either two local handles edited the same parent (no chain
//!   involvement yet) or the chain landed two children of the same
//!   parent that the local store ingested.
//! - **Frozen** (`frozen = true`): the chain landed a foreign event
//!   under the genuine-foreign-INSERT path of
//!   [`crate::Vault::ingest_chain_revision`] (none of the three
//!   idempotency-merge arms matched). The user-facing read paths
//!   refuse on this account until [`crate::Vault::clear_frozen`]
//!   runs (typically as the final step of `pangolin-cli resolve`).
//!
//! An account can be in either, both, or neither state. The
//! `list_conflicts` query unions the fork set and the freeze set so
//! the resolve UX shows everything that needs resolution in one
//! pass.
//!
//! ## Frozen-with-single-head case
//!
//! When `ingest_chain_revision` runs the genuine-foreign-INSERT path
//! on a *fresh* foreign account (no prior local row), the just-
//! ingested revision becomes the only row in the local revision
//! graph for that account. The freeze flag is set; `account_heads`
//! returns exactly 1 revision. The conflict report still includes
//! this case (with `heads.len() == 1` and `frozen = true`) because
//! the user must run resolve to clear the flag — the fact that the
//! local graph is structurally linear does NOT mean there is no
//! conflict to resolve.

use crate::account::AccountId;
use crate::revision::RevisionId;

/// One row of [`crate::Vault::list_conflicts`]'s output.
///
/// Field semantics:
///
/// - `account_id` — the affected account.
/// - `heads` — every current head of the account's revision graph.
///   Length 1 with `frozen = true` is the freshly-foreign-account
///   case described in the module docs. Length > 1 is the forked
///   case (with or without the freeze flag).
/// - `frozen` — `true` iff the
///   `account_identities.frozen_pending_resolve` flag is set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConflictReport {
    /// The affected account.
    pub account_id: AccountId,
    /// All current heads of `account_id`. Length 1 ⇒ structurally
    /// linear; length > 1 ⇒ forked. See module docs for the
    /// frozen-with-single-head case.
    pub heads: Vec<RevisionId>,
    /// `true` iff `account_identities.frozen_pending_resolve = 1`
    /// for this row.
    pub frozen: bool,
}

#[cfg(test)]
mod tests {
    //! P9-2 unit tests. All scenarios drive [`crate::Vault`] through
    //! its public API to set up the precondition (forked / frozen /
    //! both / neither) and then assert
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
    /// involvement), `frozen = false`, `heads.len() > 1`.
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
        assert!(reports[0].heads.len() > 1, "forked must have ≥2 heads");
        assert!(!reports[0].frozen, "forked-only must NOT be frozen");
    }

    /// **P9-2.** Freeze-only case (single head + frozen). This is
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
        assert_eq!(reports[0].heads.len(), 1, "fresh foreign account ⇒ 1 head");
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
        assert!(reports[0].heads.len() > 1, "must be forked");
        assert!(reports[0].frozen, "must be frozen");
    }

    /// **P9-2.** The fresh-foreign-account case is documented
    /// explicitly: `frozen = true`, `heads.len() == 1`. Pinned as
    /// its own test because the resolve UX must surface it.
    #[test]
    fn list_conflicts_handles_frozen_with_single_head() {
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
        assert_eq!(report.heads.len(), 1);
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
        assert!(matching[0].heads.len() > 1);
    }
}
