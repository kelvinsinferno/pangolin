//! Revision identifiers and metadata.
//!
//! A revision is an immutable, append-only entry on `RevisionLogV0` and
//! its corresponding row in the local `revisions` table. Locally, every
//! edit produces a new revision row that references its parent through
//! `parent_revision_id`; a *genesis* revision uses the all-zero parent
//! sentinel.
//!
//! The on-chain format anchored by P5-1 governs the chain side; this
//! module is the local-side mirror. P7's chain adapter will sync the
//! `chain_anchor_*` columns when the row lands on chain.
//!
//! ## Revision graph (P3)
//!
//! [`RevisionGraph`] indexes the parent→child structure across every
//! revision belonging to a single account. It is built from the SQL
//! revision rows by [`crate::vault::Vault::revision_graph`] and exposes
//! head detection, ancestry walking, and common-ancestor computation
//! for the P9 conflict-resolution UI to consume.
//!
//! Cardinal-principle 4 ("never silent merge") makes this a *detection-
//! only* primitive: the graph reports forks but never resolves them.
//! Resolution is the user's call, surfaced through P9.

use core::fmt;
use std::collections::{HashMap, HashSet, VecDeque};

use crate::error::{Result, StoreError};

/// Length of a [`RevisionId`] in bytes.
pub const REVISION_ID_LEN: usize = 32;
/// Length of a [`DeviceId`] in bytes.
pub const DEVICE_ID_LEN: usize = 32;

/// A 32-byte revision identifier.
///
/// Generated client-side as 32 random bytes for now (P2 scope). MVP-1
/// issue 1.4 will switch to a content-deterministic id (keccak256 of
/// the canonical revision body) so two devices that race-write the same
/// edit produce the same id; the storage layer treats both as the same
/// row.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct RevisionId(pub(crate) [u8; REVISION_ID_LEN]);

impl RevisionId {
    /// 32 zero bytes — the parent sentinel for a genesis revision.
    pub const GENESIS_PARENT: Self = Self([0u8; REVISION_ID_LEN]);

    /// Wrap caller-supplied bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; REVISION_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; REVISION_ID_LEN] {
        &self.0
    }
}

impl fmt::Debug for RevisionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RevisionId(")?;
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        write!(f, ")")
    }
}

/// 32-byte device identifier. Stub form for P2; P3 will replace with
/// the verifying-key bytes of the device's signing keypair.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeviceId(pub [u8; DEVICE_ID_LEN]);

impl fmt::Debug for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DeviceId(")?;
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        write!(f, ")")
    }
}

/// Non-secret per-revision metadata. Returned by
/// [`crate::vault::Vault::revisions_for`] for history walks.
///
/// `enc_payload` is **not** included — payload bytes can be recovered
/// from the SQL row but they are AEAD-sealed and only meaningful inside
/// the `Active`-state vault that holds the matching VDK; surfacing them
/// here would invite leakage.
#[derive(Debug, Clone)]
pub struct RevisionMeta {
    /// This revision's id.
    pub revision_id: RevisionId,
    /// Parent revision id; [`RevisionId::GENESIS_PARENT`] for genesis.
    pub parent_revision_id: RevisionId,
    /// Authoring device id.
    pub device_id: DeviceId,
    /// Schema version of the AEAD-sealed payload format.
    pub schema_version: u8,
    /// Wall-clock author time (unix milliseconds).
    pub created_at: i64,
    /// True when this revision is a tombstone (`{ "deleted": true }`).
    pub is_tombstone: bool,
    /// Chain anchor when the revision has been published; `None` until
    /// `mark_published` is called.
    pub chain_anchor: Option<ChainAnchor>,
}

/// Recorded position of a revision on chain. Filled by P7 once the
/// revision is observed in a confirmed `RevisionPublished` event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainAnchor {
    /// 32-byte transaction hash.
    pub tx_hash: [u8; 32],
    /// Block number (unsigned i64 — chains we target stay well below
    /// 2^63).
    pub block_number: i64,
    /// Index of the `RevisionPublished` log within the block's log
    /// stream.
    pub log_index: i64,
}

// ---------------------------------------------------------------------
// Revision graph (P3)
// ---------------------------------------------------------------------

/// Indexed parent→child structure for every revision belonging to a
/// single account.
///
/// Built from the SQL `revisions` rows of one account by
/// [`crate::vault::Vault::revision_graph`]. The graph carries only
/// non-secret metadata ([`RevisionMeta`] — never `enc_payload`) so it
/// can be passed across module boundaries without leaking ciphertext
/// alongside the structural index.
///
/// ## Heads and forks
///
/// A *head* is a revision with no children — i.e., no other row in the
/// account's revision history references this revision id as its
/// `parent_revision_id`. A well-formed (linearly-edited) account has
/// exactly one head; multiple heads mean two devices independently
/// advanced from the same parent and the divergence has not yet been
/// resolved. Per cardinal principle 4 the resolution is the user's
/// call (P9 surfaces it through the UI); this graph only DETECTS.
///
/// ## Genesis
///
/// A *genesis* revision is one whose `parent_revision_id` equals
/// [`RevisionId::GENESIS_PARENT`] (32 zero bytes). At most one is
/// expected per well-formed account; if the input contains multiple,
/// [`Self::genesis`] returns the earliest by `created_at` (with
/// `revision_id` byte-order as a tie-break) and all genesis revisions
/// surface as heads-without-parents in the graph index. Document this
/// case as "should never happen with well-formed data; if it does, it
/// is an attacker injection or storage corruption."
///
/// ## Empty / single-revision accounts
///
/// A graph for an account with zero revisions is empty:
/// `revisions().is_empty()`, `heads().is_empty()`, `is_forked()` is
/// false, `genesis()` is `None`. A graph with exactly one revision
/// (the genesis) reports a single head and no fork.
///
/// ## Failure modes detected at build time
///
/// - **Cycles** in the parent chain (a revision whose ancestry walk
///   returns to itself) surface as
///   [`StoreError::Corrupted`] when [`Self::build`] runs.
/// - **Dangling parents** (a non-genesis revision whose
///   `parent_revision_id` is not present in the graph) are tolerated:
///   the orphan is treated as a synthetic genesis. This handles partial
///   chain-side replay during P7 sync, where a revision may arrive
///   before its parent.
/// - **Tombstones** are first-class members of the graph and may be
///   heads. The UI layer (P9) decides what to do with a tombstoned
///   head.
#[derive(Debug, Clone)]
pub struct RevisionGraph {
    /// Topologically-ordered list of all revisions in this graph. The
    /// order is roots-first (genesis revisions and dangling-parent
    /// orphans), then breadth-first by ancestry depth, with ties broken
    /// by `created_at` ascending then `revision_id` byte-order. Stable
    /// across runs — useful for deterministic UI rendering.
    revisions: Vec<RevisionMeta>,
    /// child → parent index. Only present for non-genesis revisions
    /// whose parent IS in the graph; a dangling-parent orphan does NOT
    /// appear here as a key.
    parents: HashMap<RevisionId, RevisionId>,
    /// parent → ordered list of children. Order within a children-set
    /// is `created_at` ascending then `revision_id` byte-order.
    /// Deterministic for tests + UI.
    children: HashMap<RevisionId, Vec<RevisionId>>,
    /// The set of revision ids that have NO children — these are
    /// heads. Order: `created_at` ascending then `revision_id`
    /// byte-order.
    heads: Vec<RevisionId>,
    /// Genesis revision id (the earliest revision whose
    /// `parent_revision_id` equals [`RevisionId::GENESIS_PARENT`]). At
    /// most one per well-formed account; multi-genesis input still
    /// produces a single canonical pick (earliest `created_at`, then
    /// `revision_id` byte-order). `None` if the graph is empty or no
    /// row uses the all-zeros sentinel.
    genesis: Option<RevisionId>,
    /// Index from `revision_id` to its position in `revisions` for O(1)
    /// metadata lookup.
    by_id: HashMap<RevisionId, usize>,
}

impl RevisionGraph {
    /// Construct a graph from a flat list of revision metadata rows.
    ///
    /// The input order is irrelevant; the graph re-sorts and indexes.
    /// Repeated `revision_id`s in the input are an integrity violation
    /// and surface as [`StoreError::Corrupted`].
    ///
    /// # Errors
    ///
    /// - [`StoreError::Corrupted`] on duplicate `revision_id`.
    /// - [`StoreError::Corrupted`] on a cycle in the parent chain.
    pub fn build(rows: Vec<RevisionMeta>) -> Result<Self> {
        // 1. Deduplicate-check + by_id index (over the unsorted input;
        //    we'll resort once we know the topology).
        let mut by_id_unsorted: HashMap<RevisionId, RevisionMeta> =
            HashMap::with_capacity(rows.len());
        for row in rows {
            if by_id_unsorted.insert(row.revision_id, row).is_some() {
                return Err(StoreError::Corrupted(
                    "duplicate revision_id in graph input".into(),
                ));
            }
        }

        // 2. Build child-set and parent-of indices. A revision whose
        //    parent_revision_id is GENESIS_PARENT or whose parent is
        //    not in the input becomes a "root" for the topological
        //    walk; the parents index records only edges where both
        //    endpoints are present in the graph.
        let mut children: HashMap<RevisionId, Vec<RevisionId>> = HashMap::new();
        let mut parents: HashMap<RevisionId, RevisionId> = HashMap::new();
        let mut roots: Vec<RevisionId> = Vec::new();
        for (id, meta) in &by_id_unsorted {
            let parent = meta.parent_revision_id;
            if parent == RevisionId::GENESIS_PARENT || !by_id_unsorted.contains_key(&parent) {
                // Genesis OR dangling-parent orphan — treated as a
                // root for topological ordering. The dangling case is
                // documented at the type-level docstring.
                roots.push(*id);
            } else {
                parents.insert(*id, parent);
                children.entry(parent).or_default().push(*id);
            }
        }

        // 3. Deterministic ordering of children sets and the root list:
        //    sort by (created_at ASC, revision_id byte-order ASC). The
        //    revision_id tie-break protects against same-millisecond
        //    siblings producing different orderings on different runs.
        let order_key = |id: &RevisionId| -> (i64, [u8; REVISION_ID_LEN]) {
            let m = by_id_unsorted.get(id).expect("id is in unsorted map");
            (m.created_at, m.revision_id.0)
        };
        roots.sort_by_key(order_key);
        for kids in children.values_mut() {
            kids.sort_by_key(order_key);
        }

        // 4. BFS from roots to produce a topological order. While we
        //    walk we also detect cycles: if we ever revisit a node
        //    already in `seen`, we've found a back-edge. Forward
        //    progress (each node visited exactly once) guarantees
        //    termination at O(V + E).
        let mut topo: Vec<RevisionId> = Vec::with_capacity(by_id_unsorted.len());
        let mut seen: HashSet<RevisionId> = HashSet::with_capacity(by_id_unsorted.len());
        let mut queue: VecDeque<RevisionId> = VecDeque::with_capacity(roots.len());
        for r in &roots {
            queue.push_back(*r);
            seen.insert(*r);
        }
        while let Some(id) = queue.pop_front() {
            topo.push(id);
            if let Some(kids) = children.get(&id) {
                for kid in kids {
                    if !seen.insert(*kid) {
                        // The same child was already enqueued — that
                        // can only happen if `kid` has multiple parents
                        // OR if there is a cycle. The graph is a tree-
                        // of-trees with single-parent edges by
                        // construction (parents map is 1:1), so we
                        // know it's a cycle.
                        return Err(StoreError::Corrupted(
                            "revision lineage contains a cycle".into(),
                        ));
                    }
                    queue.push_back(*kid);
                }
            }
        }

        // If topo did not cover every node, some node is in a cycle
        // unreachable from any root. Surface that too.
        if topo.len() != by_id_unsorted.len() {
            return Err(StoreError::Corrupted(
                "revision lineage contains a cycle (unreachable component)".into(),
            ));
        }

        // 5. Build the final ordered Vec<RevisionMeta>, the by_id
        //    position map, and the heads list.
        let mut revisions: Vec<RevisionMeta> = Vec::with_capacity(topo.len());
        let mut by_id: HashMap<RevisionId, usize> = HashMap::with_capacity(topo.len());
        for (idx, id) in topo.iter().enumerate() {
            // Move out of the unsorted map; safe because each id is
            // unique (deduplication checked above).
            let meta = by_id_unsorted
                .remove(id)
                .expect("topo id is in unsorted map");
            by_id.insert(*id, idx);
            revisions.push(meta);
        }

        // Heads = revisions with no children entry OR an empty one.
        let mut heads: Vec<RevisionId> = revisions
            .iter()
            .filter(|m| children.get(&m.revision_id).is_none_or(Vec::is_empty))
            .map(|m| m.revision_id)
            .collect();
        heads.sort_by_key(|id| {
            let m = &revisions[by_id[id]];
            (m.created_at, m.revision_id.0)
        });

        // Genesis = earliest revision whose declared parent is the
        // all-zeros sentinel. Plan §"Failure modes considered" / multi-
        // genesis: tie-break by created_at ASC, then revision_id
        // byte-order ASC. Documented as "should never happen with
        // well-formed data; if it does, it is an attacker injection."
        let genesis = revisions
            .iter()
            .filter(|m| m.parent_revision_id == RevisionId::GENESIS_PARENT)
            .min_by_key(|m| (m.created_at, m.revision_id.0))
            .map(|m| m.revision_id);

        Ok(Self {
            revisions,
            parents,
            children,
            heads,
            genesis,
            by_id,
        })
    }

    /// Topologically-ordered metadata for every revision in the graph.
    #[must_use]
    pub fn revisions(&self) -> &[RevisionMeta] {
        &self.revisions
    }

    /// Look up a revision's metadata by id.
    #[must_use]
    pub fn get(&self, id: &RevisionId) -> Option<&RevisionMeta> {
        self.by_id.get(id).map(|&idx| &self.revisions[idx])
    }

    /// The set of revisions with no children. Length 0 only when the
    /// graph is empty; length 1 means the account is in a clean linear
    /// state; length > 1 means the account is forked.
    #[must_use]
    pub fn heads(&self) -> &[RevisionId] {
        &self.heads
    }

    /// `true` iff the head set has more than one element. Cheap
    /// boolean form of `heads().len() > 1`.
    #[must_use]
    pub fn is_forked(&self) -> bool {
        self.heads.len() > 1
    }

    /// The parent revision id of `id`, or `None` for a genesis or
    /// dangling-parent orphan.
    #[must_use]
    pub fn parent_of(&self, id: &RevisionId) -> Option<&RevisionId> {
        self.parents.get(id)
    }

    /// Children of `id` in deterministic order (`created_at` ASC, then
    /// `revision_id` byte-order ASC). Empty slice for a head or for an
    /// id that is not in the graph.
    #[must_use]
    pub fn children_of(&self, id: &RevisionId) -> &[RevisionId] {
        self.children.get(id).map_or(&[], Vec::as_slice)
    }

    /// The genesis revision (parent == all-zeros sentinel), if any.
    /// On multi-genesis input returns the earliest by `created_at`
    /// (`revision_id` byte-order tie-break). See type-level docs for the
    /// adversarial case.
    #[must_use]
    pub fn genesis(&self) -> Option<&RevisionId> {
        self.genesis.as_ref()
    }

    /// Number of revisions in the graph.
    #[must_use]
    pub fn len(&self) -> usize {
        self.revisions.len()
    }

    /// `true` iff the graph contains zero revisions.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.revisions.is_empty()
    }

    /// Walk the ancestry of `id` from `id` itself back toward the
    /// genesis. Returned chain is oldest→newest (genesis first, `id`
    /// last); a single-element vec for a genesis or dangling-parent
    /// orphan; an empty vec if `id` is not in the graph.
    ///
    /// Termination is guaranteed by the cycle check at build time.
    #[must_use]
    pub fn ancestors(&self, id: &RevisionId) -> Vec<RevisionId> {
        if !self.by_id.contains_key(id) {
            return Vec::new();
        }
        let mut chain: Vec<RevisionId> = Vec::new();
        let mut cursor = *id;
        loop {
            chain.push(cursor);
            match self.parents.get(&cursor) {
                Some(parent) => cursor = *parent,
                None => break,
            }
        }
        chain.reverse();
        chain
    }

    /// Lowest common ancestor of `a` and `b` — the fork point if both
    /// are heads of a forked account. Returns the deepest revision id
    /// that appears in both ancestor chains.
    ///
    /// Returns `None` when:
    /// - either `a` or `b` is not in the graph,
    /// - the two share no common ancestor (which can only happen if
    ///   the input includes multiple disconnected components — i.e.,
    ///   multi-genesis or dangling-parent orphans across distinct
    ///   sub-trees).
    #[must_use]
    pub fn common_ancestor(&self, a: &RevisionId, b: &RevisionId) -> Option<RevisionId> {
        if !self.by_id.contains_key(a) || !self.by_id.contains_key(b) {
            return None;
        }
        // Cheap path: equal heads.
        if a == b {
            return Some(*a);
        }
        // Walk one ancestry into a HashSet for O(1) lookup, then walk
        // the other from itself back toward its root and return the
        // first hit. The first hit is by construction the LOWEST common
        // ancestor (deepest shared node) because we walk b from itself
        // upward — the first ancestor we encounter that is also in a's
        // chain is the deepest one on b's path.
        let a_chain: HashSet<RevisionId> = self.ancestors(a).into_iter().collect();
        let mut cursor = *b;
        loop {
            if a_chain.contains(&cursor) {
                return Some(cursor);
            }
            match self.parents.get(&cursor) {
                Some(p) => cursor = *p,
                None => return None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DeviceId, RevisionGraph, RevisionId, RevisionMeta, REVISION_ID_LEN};
    use crate::error::StoreError;

    #[test]
    fn revision_id_genesis_is_zero() {
        assert_eq!(
            RevisionId::GENESIS_PARENT.as_bytes(),
            &[0u8; REVISION_ID_LEN]
        );
    }

    #[test]
    fn revision_id_debug_is_hex() {
        let id = RevisionId::from_bytes([0xCD; 32]);
        assert!(format!("{id:?}").contains("cd"));
    }

    /// P2-2 / success criterion 6: lineage walk traverses parent links
    /// from the head back to genesis without breaking.
    ///
    /// This unit lives here because it exercises only the in-memory
    /// data structures; the SQL-backed walk lives in `vault::tests` and
    /// is integration-tested in `tests/e2e.rs`.
    #[test]
    fn walk_lineage_in_memory() {
        // Build a synthetic chain: genesis -> r1 -> r2 -> r3 (head).
        let r1 = RevisionId::from_bytes([1u8; 32]);
        let r2 = RevisionId::from_bytes([2u8; 32]);
        let r3 = RevisionId::from_bytes([3u8; 32]);
        let parent =
            std::collections::HashMap::from([(r1, RevisionId::GENESIS_PARENT), (r2, r1), (r3, r2)]);

        // Walk back from head r3 until we hit genesis.
        let mut cursor = r3;
        let mut depth = 0;
        let max_depth = 10;
        while cursor != RevisionId::GENESIS_PARENT {
            let p = *parent.get(&cursor).expect("missing parent");
            cursor = p;
            depth += 1;
            assert!(depth <= max_depth, "lineage walk did not terminate");
        }
        assert_eq!(depth, 3, "expected exactly 3 parent links to genesis");
    }

    #[test]
    fn device_id_debug_is_hex() {
        let id = DeviceId([0xEF; 32]);
        assert!(format!("{id:?}").contains("ef"));
    }

    // -----------------------------------------------------------------
    // RevisionGraph unit tests (P3)
    // -----------------------------------------------------------------

    /// Build a [`RevisionMeta`] with the given id + parent + `created_at`.
    /// All other fields are filled with deterministic stub values so
    /// individual tests can focus on graph topology.
    fn meta(id: u8, parent: u8, created_at: i64) -> RevisionMeta {
        let parent_id = if parent == 0 {
            RevisionId::GENESIS_PARENT
        } else {
            RevisionId::from_bytes([parent; 32])
        };
        RevisionMeta {
            revision_id: RevisionId::from_bytes([id; 32]),
            parent_revision_id: parent_id,
            device_id: DeviceId([0xAA; 32]),
            schema_version: 0,
            created_at,
            is_tombstone: false,
            chain_anchor: None,
        }
    }

    fn rev(id: u8) -> RevisionId {
        RevisionId::from_bytes([id; 32])
    }

    /// Plan success criterion 2: a clean linear chain (genesis ->
    /// r1 -> r2 -> r3 -> r4 -> r5) reports exactly one head, the
    /// latest, and `is_forked()` returns false.
    #[test]
    fn linear_lineage_single_head() {
        // Six revisions, parents form a single straight chain.
        // genesis(R1, parent=ZERO) -> R2 -> R3 -> R4 -> R5 -> R6
        let rows = vec![
            meta(0x01, 0x00, 100),
            meta(0x02, 0x01, 200),
            meta(0x03, 0x02, 300),
            meta(0x04, 0x03, 400),
            meta(0x05, 0x04, 500),
            meta(0x06, 0x05, 600),
        ];
        let g = RevisionGraph::build(rows).unwrap();
        assert_eq!(
            g.heads().len(),
            1,
            "linear chain must have exactly one head"
        );
        assert_eq!(g.heads()[0], rev(0x06), "head is the latest revision");
        assert!(!g.is_forked());
        assert_eq!(g.genesis(), Some(&rev(0x01)));
        assert_eq!(g.len(), 6);
    }

    /// Plan success criterion 3: two children of the same parent
    /// produce two heads. Common-ancestor of the two heads is the
    /// shared parent (the fork point).
    #[test]
    fn two_way_fork_detection() {
        // Genesis R1 -> R2 -> {R3, R3'} (both children of R2)
        let rows = vec![
            meta(0x01, 0x00, 100),
            meta(0x02, 0x01, 200),
            meta(0x03, 0x02, 300),
            meta(0x04, 0x02, 350), // sibling of R3 — also parented by R2
        ];
        let g = RevisionGraph::build(rows).unwrap();
        assert!(g.is_forked(), "two-way fork must report is_forked()");
        let heads = g.heads();
        assert_eq!(heads.len(), 2);
        let head_set: std::collections::HashSet<RevisionId> = heads.iter().copied().collect();
        assert!(head_set.contains(&rev(0x03)));
        assert!(head_set.contains(&rev(0x04)));
        // Children of R2 should include both forked siblings.
        let r2_children: std::collections::HashSet<RevisionId> =
            g.children_of(&rev(0x02)).iter().copied().collect();
        assert_eq!(r2_children.len(), 2);
    }

    /// Plan success criterion 4: three children of the same parent
    /// produce three heads.
    #[test]
    fn three_way_fork_detection() {
        // Genesis R1 -> {R2, R3, R4}
        let rows = vec![
            meta(0x01, 0x00, 100),
            meta(0x02, 0x01, 200),
            meta(0x03, 0x01, 250),
            meta(0x04, 0x01, 300),
        ];
        let g = RevisionGraph::build(rows).unwrap();
        assert_eq!(g.heads().len(), 3);
        assert!(g.is_forked());
        let head_set: std::collections::HashSet<RevisionId> = g.heads().iter().copied().collect();
        assert!(head_set.contains(&rev(0x02)));
        assert!(head_set.contains(&rev(0x03)));
        assert!(head_set.contains(&rev(0x04)));
    }

    /// Plan success criterion 5: a revision with parent ==
    /// `GENESIS_PARENT` is identified as the genesis.
    #[test]
    fn genesis_detection() {
        let rows = vec![
            meta(0x01, 0x00, 100), // genesis
            meta(0x02, 0x01, 200),
        ];
        let g = RevisionGraph::build(rows).unwrap();
        assert_eq!(g.genesis(), Some(&rev(0x01)));
        // The non-genesis revision should NOT report as genesis.
        assert!(g.get(&rev(0x02)).unwrap().parent_revision_id != RevisionId::GENESIS_PARENT);
    }

    /// Plan success criterion 6: ancestors(head) returns the chain
    /// from genesis to the head, in oldest→newest order.
    #[test]
    fn ancestor_walk_correctness() {
        // Genesis R1 -> R2 -> R3 -> R4
        let rows = vec![
            meta(0x01, 0x00, 100),
            meta(0x02, 0x01, 200),
            meta(0x03, 0x02, 300),
            meta(0x04, 0x03, 400),
        ];
        let g = RevisionGraph::build(rows).unwrap();
        let chain = g.ancestors(&rev(0x04));
        assert_eq!(chain, vec![rev(0x01), rev(0x02), rev(0x03), rev(0x04)]);
        // Genesis itself produces a single-element chain.
        let genesis_chain = g.ancestors(&rev(0x01));
        assert_eq!(genesis_chain, vec![rev(0x01)]);
        // Unknown id returns empty chain.
        assert!(g.ancestors(&rev(0xFE)).is_empty());
    }

    /// Plan success criterion 3 (sub): the common ancestor of two
    /// forked heads is exactly the parent revision they diverged from.
    #[test]
    fn common_ancestor_at_fork_point() {
        // Genesis R1 -> R2 -> {R3 -> R4, R5 -> R6}
        // The fork point is R2; both R4 and R6 are heads.
        let rows = vec![
            meta(0x01, 0x00, 100),
            meta(0x02, 0x01, 200),
            meta(0x03, 0x02, 300),
            meta(0x04, 0x03, 400),
            meta(0x05, 0x02, 350),
            meta(0x06, 0x05, 500),
        ];
        let g = RevisionGraph::build(rows).unwrap();
        assert!(g.is_forked());
        assert_eq!(g.heads().len(), 2);
        let lca = g.common_ancestor(&rev(0x04), &rev(0x06));
        assert_eq!(
            lca,
            Some(rev(0x02)),
            "fork point must be the shared parent R2"
        );
        // Symmetry.
        let lca_swap = g.common_ancestor(&rev(0x06), &rev(0x04));
        assert_eq!(lca_swap, Some(rev(0x02)));
        // LCA of a node with itself is itself.
        assert_eq!(g.common_ancestor(&rev(0x04), &rev(0x04)), Some(rev(0x04)));
        // Genesis is the LCA for any pair whose shared root is the
        // genesis.
        let lca_genesis = g.common_ancestor(&rev(0x04), &rev(0x01));
        assert_eq!(lca_genesis, Some(rev(0x01)));
        // Unknown id returns None (criterion: "if no common ancestor").
        assert_eq!(g.common_ancestor(&rev(0x04), &rev(0xFF)), None);
    }

    /// Plan success criterion 7: documented behavior on multi-genesis
    /// input (which "should never happen with well-formed data; if it
    /// does, it is an attacker injection"). The graph reports both
    /// orphaned revisions as heads, and `genesis()` returns the
    /// earliest by `created_at` with `revision_id` byte-order tie-break.
    #[test]
    fn multi_genesis_documents_tie_break() {
        // Two revisions both with parent = ZERO. R1 is earlier than
        // R2 by created_at.
        let rows = vec![
            meta(0x01, 0x00, 100), // earliest genesis
            meta(0x02, 0x00, 200), // later genesis (corruption)
        ];
        let g = RevisionGraph::build(rows).unwrap();
        // Both have no children → both are heads.
        assert_eq!(g.heads().len(), 2);
        let head_set: std::collections::HashSet<RevisionId> = g.heads().iter().copied().collect();
        assert!(head_set.contains(&rev(0x01)));
        assert!(head_set.contains(&rev(0x02)));
        // Tie-break: the genesis pick is the earliest by created_at.
        assert_eq!(
            g.genesis(),
            Some(&rev(0x01)),
            "documented tie-break: earliest created_at wins"
        );
        // Two disconnected components → no common ancestor across
        // sub-trees. (We expose this case explicitly.)
        assert_eq!(g.common_ancestor(&rev(0x01), &rev(0x02)), None);
    }

    /// Cycle detection: a revision whose declared parent is itself
    /// (or a descendant) must surface as Corrupted at build time.
    #[test]
    fn cycle_detection_returns_corrupted() {
        // R1.parent = R2, R2.parent = R1. Both reachable only through
        // each other; neither has GENESIS_PARENT, so neither is a
        // root. The graph never enqueues anyone and topo.len() = 0,
        // which our final check catches.
        let rows = vec![meta(0x01, 0x02, 100), meta(0x02, 0x01, 200)];
        let err = RevisionGraph::build(rows).unwrap_err();
        assert!(
            matches!(err, StoreError::Corrupted(ref msg) if msg.contains("cycle")),
            "expected Corrupted/cycle, got {err:?}"
        );
    }

    /// Direct self-loop (R1 parent = R1) is a 1-node cycle.
    #[test]
    fn cycle_detection_self_loop() {
        let rows = vec![meta(0x01, 0x01, 100)];
        let err = RevisionGraph::build(rows).unwrap_err();
        assert!(matches!(err, StoreError::Corrupted(_)));
    }

    /// Duplicate revision ids in the input surface as Corrupted.
    #[test]
    fn duplicate_revision_id_rejected() {
        let rows = vec![meta(0x01, 0x00, 100), meta(0x01, 0x00, 200)];
        let err = RevisionGraph::build(rows).unwrap_err();
        assert!(matches!(err, StoreError::Corrupted(ref m) if m.contains("duplicate")));
    }

    /// Empty input → empty graph; `is_forked` false; `genesis` None.
    #[test]
    fn empty_graph() {
        let g = RevisionGraph::build(Vec::new()).unwrap();
        assert!(g.is_empty());
        assert_eq!(g.len(), 0);
        assert!(g.heads().is_empty());
        assert!(!g.is_forked());
        assert_eq!(g.genesis(), None);
    }

    /// Dangling-parent orphan: a non-genesis revision whose parent is
    /// not in the input is treated as a synthetic root, NOT as a
    /// build-time error. Documented at the type-level for partial-sync
    /// scenarios (P7 chain replay).
    #[test]
    fn dangling_parent_treated_as_root() {
        // R5 references parent R4, but R4 is not in the input.
        let rows = vec![meta(0x05, 0x04, 100)];
        let g = RevisionGraph::build(rows).unwrap();
        assert_eq!(g.len(), 1);
        // R5 is its own head (no children).
        assert_eq!(g.heads(), &[rev(0x05)]);
        // genesis() returns None because no row has parent =
        // GENESIS_PARENT.
        assert_eq!(g.genesis(), None);
        // parent_of returns None for orphans (parent not in graph).
        assert_eq!(g.parent_of(&rev(0x05)), None);
    }
}
