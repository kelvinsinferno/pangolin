// SPDX-License-Identifier: AGPL-3.0-or-later
//! Revision-lineage FFI shapes + entry points (MVP-1 issue 1.6).
//!
//! Scaffolded at issue 1.1 (`RevisionId` / `RevisionMeta` records with
//! "bodies finalize in 1.6"). Issue 1.6 promotes the lineage to a
//! production-grade implementation: the clock-free canonical-head rule,
//! fork detection, conflict resolution → canonical head, and the §18.7
//! schema-versioning policy. The new FFI surface added here —
//! `account_is_forked` / `account_fork_branches` / `account_resolve_fork`
//! / `account_status` and the `ForkBranch` / `AccountStatus` records —
//! is an **additive 1.1-surface amendment** (same posture as 1.2's
//! `AccountDraft` widening / 1.4's `reveal_*` / 1.5's `device_*`);
//! `docs/architecture/ffi-surface.md` records it.

use std::sync::Arc;

use crate::error::FfiError;
use crate::identity::AccountId;
use crate::session::{UnixTimestamp, VaultHandle};

/// Revision identifier. 32 bytes; `UniFFI` emits as `Data`/`ByteArray`.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct RevisionId {
    /// Issue 1.1 schema-version slot (widened from the on-disk `u8`).
    pub schema_version: u16,
    /// 32 bytes of revision id.
    pub bytes: Vec<u8>,
}

/// Read-only revision metadata. Finalised in 1.6.
#[derive(Debug, Clone, uniffi::Record)]
pub struct RevisionMeta {
    /// Issue 1.1 schema-version slot (widened from the on-disk `u8`).
    pub schema_version: u16,
    /// The revision's id.
    pub id: RevisionId,
    /// Wall-clock time the revision was created (unix milliseconds, as
    /// stamped by the authoring device — best-effort, NOT consulted in
    /// the canonical-head election). Foreign sides treat as opaque.
    pub created_at_unix: i64,
    /// Optional parent revision id (`None` for the genesis revision).
    pub parent_id: Option<RevisionId>,
    /// Device id that authored the revision.
    pub device_id: Vec<u8>,
    // --- 1.6 additions ---
    /// `true` if this revision is a tombstone (a deletion sentinel).
    pub is_tombstone: bool,
    /// `true` if this revision is a current leaf of the graph (no
    /// children). A linear account has exactly one such revision; a
    /// forked account has ≥ 2.
    pub is_head: bool,
    /// `true` if this revision is **the** canonical head per 1.6's
    /// clock-free rule (the leaf with the lexicographically-largest
    /// `revision_id`).
    pub is_canonical_head: bool,
    /// `true` if this revision is an ancestor of (or equal to) the
    /// canonical head — i.e., it lies on the canonical chain. `false`
    /// for a revision on a losing fork branch.
    pub on_canonical_chain: bool,
}

/// One branch (leaf) of a forked account's revision graph — enough
/// metadata for the user to choose which branch to keep when calling
/// `account_resolve_fork`.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ForkBranch {
    /// Schema-version slot.
    pub schema_version: u16,
    /// The leaf revision at the tip of this branch.
    pub leaf_revision_id: RevisionId,
    /// The device that authored the leaf revision.
    pub leaf_device_id: Vec<u8>,
    /// The leaf revision's `created_at` (unix milliseconds; best-effort
    /// — display only, not load-bearing).
    pub leaf_created_at: UnixTimestamp,
    /// Number of revisions from this branch's genesis to the leaf
    /// (inclusive) — a rough "how much history is on this branch" hint.
    pub depth: u32,
    /// `true` if this leaf is the canonical head per 1.6's rule (the
    /// branch that the cache/search index currently reflects).
    pub is_canonical_head: bool,
}

/// One-stop per-account status — which banners a host UI should show.
/// All fields non-secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct AccountStatus {
    /// Schema-version slot.
    pub schema_version: u16,
    /// `true` if the account has been deleted (tombstoned).
    pub is_tombstoned: bool,
    /// `true` if the revision graph has ≥ 2 leaves (a fork). Readable
    /// at the canonical head; resolve via `account_resolve_fork`.
    pub is_forked: bool,
    /// `true` if the P10 `frozen_pending_resolve` flag is set (a
    /// foreign-device chain event landed under this account via the
    /// dormant ingest path). Stricter than `is_forked`.
    pub is_frozen_pending_resolve: bool,
    /// `true` if the account's canonical head carries a schema version
    /// newer than this build understands (§18.7) — metadata-only reads
    /// keep working; reveals/edits are blocked. "This account needs a
    /// newer Pangolin."
    pub requires_upgrade: bool,
}

fn store_into_ffi(err: pangolin_store::StoreError) -> FfiError {
    FfiError::from(pangolin_core::Error::from(err))
}

/// `true` iff the account's revision graph has ≥ 2 leaves (a fork).
///
/// Works on a `Locked` vault that has been unlocked at least once
/// (graph queries are metadata-only).
///
/// # Errors
///
/// `FfiError::Session` if the handle has no vault; `FfiError::Store` if
/// the account is unknown or on a storage failure.
#[allow(clippy::significant_drop_tightening)]
#[uniffi::export]
pub fn account_is_forked(handle: Arc<VaultHandle>, id: AccountId) -> Result<bool, FfiError> {
    let mut guard = handle.lock_vault();
    let vault = guard.as_mut()?;
    let store_id = crate::identity_bridge::account_id_from_ffi(&id)?;
    vault.is_forked(store_id).map_err(store_into_ffi)
}

/// Enumerate the branches (leaves) of a forked account's revision
/// graph. Empty for a non-forked account.
///
/// # Errors
///
/// `FfiError::Session` if the handle has no vault; `FfiError::Store` if
/// the account is unknown or on a storage failure.
#[allow(clippy::significant_drop_tightening)]
#[uniffi::export]
pub fn account_fork_branches(
    handle: Arc<VaultHandle>,
    id: AccountId,
) -> Result<Vec<ForkBranch>, FfiError> {
    let mut guard = handle.lock_vault();
    let vault = guard.as_mut()?;
    let store_id = crate::identity_bridge::account_id_from_ffi(&id)?;
    let graph = vault.revision_graph(store_id).map_err(store_into_ffi)?;
    if !graph.is_forked() {
        return Ok(Vec::new());
    }
    let canonical = graph.canonical_head().copied();
    let mut out = Vec::with_capacity(graph.heads().len());
    for leaf in graph.heads() {
        let meta = graph.get(leaf).ok_or_else(|| {
            store_into_ffi(pangolin_store::StoreError::Corrupted(
                "head id not in graph".into(),
            ))
        })?;
        let depth = u32::try_from(graph.ancestors(leaf).len()).unwrap_or(u32::MAX);
        out.push(ForkBranch {
            schema_version: pangolin_core::ACCOUNT_IDENTITY_SCHEMA_VERSION,
            leaf_revision_id: crate::identity_bridge::revision_id_to_ffi(*leaf),
            leaf_device_id: meta.device_id.0.to_vec(),
            leaf_created_at: meta.created_at,
            depth,
            is_canonical_head: canonical == Some(*leaf),
        });
    }
    Ok(out)
}

/// Resolve a fork by ratifying `keep_revision_id` as the surviving
/// branch.
///
/// `keep_revision_id` must be a current head of the forked graph. The
/// call writes a new revision parented at it, un-forks the account,
/// clears any `frozen_pending_resolve` flag, keeps the losing branch's
/// revisions (audit), and prunes only the `pending_merges` stash.
/// Returns the new (merge) revision id.
///
/// **Requires an active (unlocked, non-expired) session only — NOT a
/// fresh presence proof.** Resolving a fork reparents the graph; it
/// reveals nothing (not a §5.4 reveal-class action).
///
/// # Errors
///
/// `FfiError::Session` for a locked / expired session or missing
/// handle; `FfiError::Validation` (`kind = "not-forked"`) if the
/// account is not forked; `FfiError::Store` if `keep_revision_id` is
/// not a current head, or the account is unknown / tombstoned, or on a
/// storage failure.
#[allow(clippy::significant_drop_tightening)]
#[uniffi::export]
pub fn account_resolve_fork(
    handle: Arc<VaultHandle>,
    id: AccountId,
    keep_revision_id: RevisionId,
) -> Result<RevisionId, FfiError> {
    let mut guard = handle.lock_vault();
    let vault = guard.as_mut()?;
    let store_id = crate::identity_bridge::account_id_from_ffi(&id)?;
    let keep = crate::identity_bridge::revision_id_from_ffi(&keep_revision_id)?;
    let new_rev = vault.resolve_fork(store_id, keep).map_err(store_into_ffi)?;
    Ok(crate::identity_bridge::revision_id_to_ffi(new_rev))
}

/// The one-stop status view for an account — `is_tombstoned`,
/// `is_forked`, `is_frozen_pending_resolve`, `requires_upgrade`.
///
/// Works on a `Locked` vault for the persisted bits; `requires_upgrade`
/// is only meaningful on an `Active` vault (`false` otherwise).
///
/// # Errors
///
/// `FfiError::Session` if the handle has no vault; `FfiError::Store` if
/// the account is unknown or on a storage failure.
#[allow(clippy::significant_drop_tightening)]
#[uniffi::export]
pub fn account_status(handle: Arc<VaultHandle>, id: AccountId) -> Result<AccountStatus, FfiError> {
    let mut guard = handle.lock_vault();
    let vault = guard.as_mut()?;
    let store_id = crate::identity_bridge::account_id_from_ffi(&id)?;
    let status = vault.account_status(store_id).map_err(store_into_ffi)?;
    Ok(AccountStatus {
        schema_version: pangolin_core::ACCOUNT_IDENTITY_SCHEMA_VERSION,
        is_tombstoned: status.is_tombstoned,
        is_forked: status.is_forked,
        is_frozen_pending_resolve: status.is_frozen_pending_resolve,
        requires_upgrade: status.requires_upgrade,
    })
}

#[cfg(test)]
mod tests {
    use super::{account_fork_branches, account_is_forked, account_resolve_fork, account_status};
    use crate::identity::account_history;
    use crate::identity::AccountId as FfiAccountId;
    use crate::session::VaultHandle;
    use pangolin_core::{PinIdentityProof, PressYPresenceProof, Vault};
    use pangolin_crypto::secret::SecretBytes;
    use std::sync::Arc;

    fn pwd() -> SecretBytes {
        SecretBytes::new(b"correct horse battery staple".to_vec())
    }

    fn fresh_snapshot() -> pangolin_core::AccountSnapshot {
        pangolin_core::AccountSnapshot::new(
            SecretBytes::new(b"github".to_vec()),
            SecretBytes::new(b"alice".to_vec()),
            SecretBytes::new(b"hunter2".to_vec()),
            SecretBytes::new(b"https://github.com".to_vec()),
            SecretBytes::new(b"notes".to_vec()),
            SecretBytes::new(b"".to_vec()),
        )
    }

    /// Build an unlocked handle with one linear account; returns the
    /// handle + the FFI account id + the head revision id (FFI form).
    fn linear_handle(
        dir: &tempfile::TempDir,
    ) -> (Arc<VaultHandle>, FfiAccountId, super::RevisionId) {
        let path = dir.path().join("v.pvf");
        Vault::create(&path, &pwd()).unwrap();
        let mut v = Vault::open(&path).unwrap();
        v.unlock(
            &PressYPresenceProof::confirmed(),
            &PinIdentityProof::new(pwd()),
        )
        .unwrap();
        let id = v.add_account(fresh_snapshot()).unwrap();
        let head = v.update_account(id, fresh_snapshot()).unwrap();
        let ffi_id = crate::identity_bridge::account_id_to_ffi(id);
        let ffi_head = crate::identity_bridge::revision_id_to_ffi(head);
        (VaultHandle::from_vault(v), ffi_id, ffi_head)
    }

    /// Linear account: not forked; no branches; status flags all false;
    /// `account_history` carries the enriched `RevisionMeta` with the
    /// head tagged.
    #[test]
    fn linear_account_status_and_enriched_history() {
        let dir = tempfile::TempDir::new().unwrap();
        let (h, id, head) = linear_handle(&dir);
        assert!(!account_is_forked(Arc::clone(&h), id.clone()).unwrap());
        assert!(account_fork_branches(Arc::clone(&h), id.clone())
            .unwrap()
            .is_empty());
        let st = account_status(Arc::clone(&h), id.clone()).unwrap();
        assert!(!st.is_tombstoned && !st.is_forked && !st.is_frozen_pending_resolve);
        assert!(!st.requires_upgrade);
        assert_eq!(st.schema_version, 1);
        let hist = account_history(h, id).unwrap();
        assert_eq!(hist.len(), 2); // genesis + 1 update
        let canon = hist
            .iter()
            .find(|m| m.is_canonical_head)
            .expect("a canonical head");
        assert_eq!(canon.id.bytes, head.bytes);
        assert!(canon.is_head && canon.on_canonical_chain && !canon.is_tombstone);
        // The genesis is on the canonical chain but not the head.
        let genesis = hist
            .iter()
            .find(|m| m.parent_id.is_none())
            .expect("genesis");
        assert!(genesis.on_canonical_chain && !genesis.is_canonical_head && !genesis.is_head);
    }

    /// `account_resolve_fork` error paths: empty handle / non-forked /
    /// locked vault — all surface typed `FfiError`s (no presence
    /// prompt).
    #[test]
    fn resolve_fork_error_paths() {
        // Empty handle → Session error.
        let empty = VaultHandle::new_placeholder();
        let bogus_id = FfiAccountId {
            schema_version: 1,
            bytes: vec![0u8; 32],
        };
        let bogus_rev = super::RevisionId {
            schema_version: 1,
            bytes: vec![0u8; 32],
        };
        assert!(matches!(
            account_resolve_fork(Arc::clone(&empty), bogus_id, bogus_rev).unwrap_err(),
            crate::error::FfiError::Session { .. }
        ));
        // Non-forked account → Validation(not-forked).
        let dir = tempfile::TempDir::new().unwrap();
        let (h, id, head) = linear_handle(&dir);
        assert!(matches!(
            account_resolve_fork(Arc::clone(&h), id.clone(), head).unwrap_err(),
            crate::error::FfiError::Validation { ref kind, .. } if kind == "not-forked"
        ));
        // Locked vault → Session error.
        {
            let mut g = h.lock_vault();
            g.as_mut().unwrap().lock();
        }
        let bogus_rev2 = super::RevisionId {
            schema_version: 1,
            bytes: vec![1u8; 32],
        };
        assert!(matches!(
            account_resolve_fork(h, id, bogus_rev2).unwrap_err(),
            crate::error::FfiError::Session { .. }
        ));
    }
}
