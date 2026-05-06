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

use core::fmt;

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

#[cfg(test)]
mod tests {
    use super::{DeviceId, RevisionId, REVISION_ID_LEN};

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
}
