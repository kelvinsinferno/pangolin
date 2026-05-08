//! Account identity model — landed by MVP-1 issue 1.2.
//!
//! Scaffolding-only for issue 1.1. Today the `AccountId` and
//! `AccountSnapshot` types live in `pangolin-store` and are re-exported
//! at the crate root (`pangolin_core::AccountId`). Issue 1.2 will land
//! the `AccountIdentity` model + draft / patch builders here and the
//! re-exports in `crate::lib` will shift to point at this module.
