//! Sync orchestration — landed across MVP-1 issues 1.6 (revision
//! lineage production) and MVP-2 (chain-side activation).
//!
//! Scaffolding-only for issue 1.1. The `PoC`'s `pangolin-cli sync`
//! orchestration logic lives in `apps/cli/src/sync.rs` today and is
//! consumed via the binary, not via this crate. As 1.6 lands the
//! production revision lineage and 2.x activates chain code, the
//! library API for sync moves here.
