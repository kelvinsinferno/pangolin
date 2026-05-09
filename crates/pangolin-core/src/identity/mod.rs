// SPDX-License-Identifier: AGPL-3.0-or-later
//! Account identity model — landed by MVP-1 issue 1.2.
//!
//! Per Q2 of `docs/issue-plans/1.2.md` the production
//! [`AccountIdentity`] model physically lives in
//! `pangolin-store::account` and `pangolin-core` re-exports. The
//! relocation to `pangolin-core::identity::*` ships in 1.4 alongside
//! the session rewrite. The re-exports below let downstream callers
//! (e.g., `pangolin-ffi`) refer to the model under the
//! `pangolin_core::identity::*` namespace today, in addition to the
//! crate-root re-exports surfaced by `crate::lib`.

pub use pangolin_store::{
    AccountId, AccountIdentity, AccountIdentityDraft, AccountIdentityPatch, AccountIdentitySummary,
    PasswordEntry, PasswordHistorySummaryEntry, ACCOUNT_IDENTITY_SCHEMA_VERSION,
    PAYLOAD_VERSION_V0, PAYLOAD_VERSION_V1,
};
