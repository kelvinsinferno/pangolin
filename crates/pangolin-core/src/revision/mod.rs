//! Production revision lineage — landed by MVP-1 issue 1.6.
//!
//! Scaffolding-only for issue 1.1. Today the `RevisionId`,
//! `RevisionMeta`, and `RevisionGraph` types live in `pangolin-store`
//! and are re-exported at the crate root. Issue 1.6 promotes the
//! lineage to a production-grade implementation including the §18.7
//! schema-versioning policy.
