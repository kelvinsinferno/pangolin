//! Revision-lineage FFI shapes (MVP-1 issue 1.6).
//!
//! Scaffolding-only at issue 1.1. Issue 1.6 promotes the lineage to a
//! production-grade implementation (including the §18.7 schema-
//! versioning policy).

/// Revision identifier. 32 bytes; `UniFFI` emits as `Data`/`ByteArray`.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct RevisionId {
    /// Issue 1.1 schema-version slot.
    pub schema_version: u16,
    /// 32 bytes of revision-id hash.
    pub bytes: Vec<u8>,
}

/// Read-only revision metadata. Body fields finalize in 1.6.
#[derive(Debug, Clone, uniffi::Record)]
pub struct RevisionMeta {
    /// Issue 1.1 schema-version slot.
    pub schema_version: u16,
    /// The revision's id.
    pub id: RevisionId,
    /// Wall-clock time the revision was created. Foreign-language
    /// sides treat as opaque.
    pub created_at_unix: i64,
    /// Optional parent revision id (`None` for the genesis revision).
    pub parent_id: Option<RevisionId>,
    /// Device id that authored the revision.
    pub device_id: Vec<u8>,
}
