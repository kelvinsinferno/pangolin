//! Session state machine — landed by MVP-1 issue 1.4.
//!
//! Scaffolding-only for issue 1.1. Today the session types
//! (`SessionState`, `PresenceProof`, `IdentityProof`, `Clock`,
//! `SystemClock`) live in `pangolin-store` and are re-exported at the
//! crate root. Q2 of issue 1.1 deferred the physical relocation to
//! issue 1.4's session rewrite; the FFI namespace freezes today.
