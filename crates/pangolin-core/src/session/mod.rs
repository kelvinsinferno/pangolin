//! Session state machine — promoted to production by MVP-1 issue 1.4.
//!
//! Per Q1 of `docs/issue-plans/1.4.md` the session/proof types
//! physically stay in `pangolin-store::session` (no relocation — a
//! `pangolin-store` → `pangolin-core` move would either be a 4 kLOC
//! diff churning the just-merged 1.2/1.3 work or create a dep cycle).
//! This module is the canonical import-path for them: the re-exports
//! below let downstream callers refer to the engine under
//! `pangolin_core::session::*`, satisfying §16.8's *namespace* intent
//! without the physical move. `pangolin-core` carries **no** `uniffi`
//! dep (Q3 invariant); the `uniffi::`-annotated wrappers live only in
//! `pangolin-ffi`.

pub use pangolin_store::{
    AuthError, Clock, IdentityProof, PinIdentityProof, PresenceProof, PressYPresenceProof,
    SessionDuration, SessionState, SystemClock, ABSOLUTE_MAX_DEFAULT, IDLE_TIMEOUT_DEFAULT,
    PRESENCE_FRESHNESS, PROMPT_TIMEOUT, SESSION_IDLE_UNTIL_DEVICE_LOCK,
};
