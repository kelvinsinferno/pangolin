//! Dirty-revision marker types.
//!
//! P8-2 introduces the `dirty_accounts` SQL table — a per-`(account,
//! revision)` marker stamped automatically inside
//! [`crate::vault::Vault::add_account`] /
//! [`crate::vault::Vault::update_account`] /
//! [`crate::vault::Vault::delete_account`] so
//! `pangolin-cli publish` (P8-3) can find every unpublished revision
//! across restarts. The associated [`crate::vault::Vault::mark_dirty`]
//! / `clear_dirty` / `list_dirty` API surface is exposed by
//! `pangolin-store` so external callers (the CLI orchestrator, future
//! UI layers) can reason about the publish queue without re-deriving
//! it from the `revisions` table.
//!
//! ## Why a separate table (per `P8.md` §A1)
//!
//! The existing `Vault::unpublished_revisions()` query (`SELECT
//! revision_id FROM revisions WHERE chain_tx_hash IS NULL`) returns
//! every chronologically-ordered unpublished revision regardless of
//! head/non-head status. P8 wants per-account "what's the latest
//! unpublished thing for THIS account" semantics, computable but
//! awkward through the existing query. A separate marker table also
//! makes "publish was attempted but the tx receipt never came back"
//! recoverable without inferring it from the absence of
//! `chain_tx_hash` (which could equally mean "edited offline, never
//! tried to publish").
//!
//! ## Privacy posture (threat model row #4)
//!
//! `dirty_accounts` stores `(account_id, revision_id, marked_at)`.
//! Both `account_id` and `revision_id` are already attacker-observable
//! on chain (the `RevisionPublished` event carries them as topics 2 +
//! 3); the only piece of NEW metadata is `marked_at`, a unix-ms
//! timestamp local to the device. `marked_at` leaks "when did this
//! device edit account X for the n-th time" only to an attacker who
//! has already compromised the local vault file — at which point they
//! also have the AEAD-protected ciphertext, dwarfing the timing leak.

use crate::account::AccountId;
use crate::revision::RevisionId;

/// A single `(account, revision, timestamp)` row in the
/// `dirty_accounts` table.
///
/// Returned by [`crate::vault::Vault::list_dirty`]. The
/// `marked_at` field is unix-ms (local device clock at the moment the
/// marker was stamped); see the module docs for its privacy posture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirtyEntry {
    /// Account this marker tracks.
    pub account_id: AccountId,
    /// Specific unpublished revision in that account.
    pub revision_id: RevisionId,
    /// Local-clock unix-ms at which the marker was stamped.
    pub marked_at: i64,
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use pangolin_crypto::secret::SecretBytes;
    use tempfile::TempDir;

    use crate::account::AccountSnapshot;
    use crate::session::{PinIdentityProof, PressYPresenceProof};
    use crate::vault::Vault;

    fn pwd() -> SecretBytes {
        SecretBytes::new(b"correct horse battery staple".to_vec())
    }

    /// Construct a fresh unlocked vault in a temp directory and return
    /// `(handle, dir)` so the dir lives until the test ends.
    fn fresh_vault() -> (Vault, TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v.pvf");
        Vault::create(&path, &pwd()).expect("create");
        let mut v = Vault::open(&path).expect("open");
        let presence = PressYPresenceProof::confirmed();
        let identity = PinIdentityProof::new(pwd());
        v.unlock(&presence, &identity).expect("unlock");
        (v, dir)
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

    /// Plan test: the auto-stamp inside `add_account` adds an entry
    /// to `list_dirty()`.
    #[test]
    fn auto_marked_on_create_revision() {
        let (mut v, _dir) = fresh_vault();
        assert!(
            v.list_dirty().expect("list").is_empty(),
            "fresh vault is clean"
        );
        let id = v.add_account(snap("acct-1")).expect("add");
        let dirty = v.list_dirty().expect("list");
        assert_eq!(dirty.len(), 1);
        assert_eq!(dirty[0].account_id, id);
    }

    /// Plan test: markers survive lock + unlock. Even though the
    /// dirty marker is metadata, this test pins the discipline that
    /// marker storage is in SQL, not in the volatile cache.
    #[test]
    fn dirty_persists_across_lock_unlock() {
        let (mut v, _dir) = fresh_vault();
        let id = v.add_account(snap("persist")).expect("add");
        v.lock();
        let presence = PressYPresenceProof::confirmed();
        let identity = PinIdentityProof::new(pwd());
        v.unlock(&presence, &identity).expect("re-unlock");
        let dirty = v.list_dirty().expect("list after re-unlock");
        assert_eq!(dirty.len(), 1);
        assert_eq!(dirty[0].account_id, id);
    }

    /// Plan test: markers survive close + open. This is the
    /// across-process-restart semantics — the `dirty_accounts` table
    /// is durable.
    #[test]
    fn dirty_persists_across_close_open() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v.pvf");
        Vault::create(&path, &pwd()).expect("create");
        let id;
        {
            let mut v = Vault::open(&path).expect("open");
            let presence = PressYPresenceProof::confirmed();
            let identity = PinIdentityProof::new(pwd());
            v.unlock(&presence, &identity).expect("unlock");
            id = v.add_account(snap("durable")).expect("add");
            v.close().expect("close");
        }
        // Re-open in a fresh handle. Markers should be intact.
        let v = Vault::open(&path).expect("re-open");
        let dirty = v.list_dirty().expect("list after re-open");
        assert_eq!(dirty.len(), 1);
        assert_eq!(dirty[0].account_id, id);
    }

    /// Plan test: `clear_dirty` removes the row.
    #[test]
    fn dirty_cleared_after_clear_dirty() {
        let (mut v, _dir) = fresh_vault();
        let id = v.add_account(snap("clear-me")).expect("add");
        let rev = v.list_dirty().expect("list")[0].revision_id;
        v.clear_dirty(id, rev).expect("clear");
        assert!(v.list_dirty().expect("list").is_empty());
    }

    /// Plan test: clearing twice (or clearing a non-existent marker)
    /// is a no-op, not an error.
    #[test]
    fn clear_is_idempotent() {
        let (mut v, _dir) = fresh_vault();
        let id = v.add_account(snap("idemp")).expect("add");
        let rev = v.list_dirty().expect("list")[0].revision_id;
        v.clear_dirty(id, rev).expect("first clear");
        // Second clear of the same pair — succeeds, no rows affected.
        v.clear_dirty(id, rev).expect("idempotent second clear");
        assert!(v.list_dirty().expect("list").is_empty());
    }

    /// Plan test: `clear_dirty(account_id, WRONG_revision_id)` does
    /// NOT remove the correct marker — A2 pair-key discipline.
    #[test]
    fn clear_with_wrong_revision_id_is_noop() {
        let (mut v, _dir) = fresh_vault();
        let id = v.add_account(snap("pair-key")).expect("add");
        let real_rev = v.list_dirty().expect("list")[0].revision_id;
        let bogus_rev = crate::revision::RevisionId::from_bytes([0xCC; 32]);
        // Clearing the wrong (account, revision) pair leaves the real
        // marker intact.
        v.clear_dirty(id, bogus_rev).expect("noop clear");
        let dirty = v.list_dirty().expect("list");
        assert_eq!(dirty.len(), 1, "real marker must survive a wrong-rev clear");
        assert_eq!(dirty[0].revision_id, real_rev);
    }

    /// Plan test: `list_dirty` yields entries in `marked_at` ASC
    /// order. Two consecutive `add_account` calls produce two markers
    /// with distinct timestamps (or equal-timestamp + secondary-key
    /// ordering).
    #[test]
    fn list_sorted_by_marked_at() {
        let (mut v, _dir) = fresh_vault();
        let id1 = v.add_account(snap("first")).expect("add 1");
        // SQLite stores integer timestamps with millisecond
        // resolution; two writes within the same millisecond are
        // possible. The secondary `account_id ASC` sort key inside
        // the SELECT makes the order deterministic regardless.
        let id2 = v.add_account(snap("second")).expect("add 2");
        let dirty = v.list_dirty().expect("list");
        assert_eq!(dirty.len(), 2);
        // Either id1 first (timestamp-ordered) or, if same ms, the
        // smaller AccountId comes first. The order is deterministic;
        // we just verify both are present and the ordering is a
        // valid total order over the set we expect.
        let seen: std::collections::HashSet<_> = dirty.iter().map(|d| d.account_id).collect();
        assert!(seen.contains(&id1));
        assert!(seen.contains(&id2));
        assert!(dirty[0].marked_at <= dirty[1].marked_at);
    }

    /// Update auto-stamps a marker for the new revision (separate
    /// from the genesis revision's marker).
    #[test]
    fn update_account_marks_new_revision() {
        let (mut v, _dir) = fresh_vault();
        let id = v.add_account(snap("upd")).expect("add");
        let _ = v.update_account(id, snap("upd-2")).expect("update");
        let dirty = v.list_dirty().expect("list");
        // Two revisions for one account → two markers.
        assert_eq!(dirty.len(), 2);
        assert!(dirty.iter().all(|d| d.account_id == id));
    }

    /// `delete_account` (tombstone) also stamps a dirty marker so the
    /// tombstone gets published like any other revision.
    #[test]
    fn delete_account_marks_tombstone() {
        let (mut v, _dir) = fresh_vault();
        let id = v.add_account(snap("dyn-del")).expect("add");
        v.delete_account(id).expect("delete");
        let dirty = v.list_dirty().expect("list");
        // Genesis + tombstone = two markers.
        assert_eq!(dirty.len(), 2);
    }

    /// `mark_dirty` is idempotent — a second call for the same pair
    /// does not create a duplicate row.
    #[test]
    fn mark_is_idempotent() {
        let (mut v, _dir) = fresh_vault();
        let id = v.add_account(snap("dup")).expect("add");
        let rev = v.list_dirty().expect("list")[0].revision_id;
        v.mark_dirty(id, rev).expect("idempotent mark");
        let dirty = v.list_dirty().expect("list");
        assert_eq!(
            dirty.len(),
            1,
            "duplicate mark must not create a second row"
        );
    }

    /// `mark_dirty` works on a `Locked` vault (metadata-only).
    #[test]
    fn mark_dirty_works_while_locked() {
        let (mut v, _dir) = fresh_vault();
        let id = v.add_account(snap("locked-mark")).expect("add");
        let rev = v.list_dirty().expect("list")[0].revision_id;
        v.lock();
        // Synthesize a fresh marker pair on a locked vault.
        let bogus = crate::revision::RevisionId::from_bytes([0x77; 32]);
        v.mark_dirty(id, bogus).expect("mark while locked");
        v.clear_dirty(id, rev).expect("clear while locked");
        let dirty = v.list_dirty().expect("list while locked");
        assert_eq!(dirty.len(), 1);
        assert_eq!(dirty[0].revision_id, bogus);
    }

    // Smoke test: paths in this module are reachable via the public
    // re-exports from `lib.rs`.
    #[test]
    fn dirty_entry_reexport_exists() {
        let _: fn() = || {
            // This block is never executed; compilation alone is the
            // assertion.
            let _: Option<crate::DirtyEntry> = None;
        };
        // `Path::new` smoke to silence the unused-import warning if
        // Rust ever optimizes the closure out.
        let _ = Path::new(".");
    }
}
