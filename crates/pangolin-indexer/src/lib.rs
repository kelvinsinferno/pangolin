// SPDX-License-Identifier: AGPL-3.0-or-later
//! Ephemeral local indexer for Pangolin (MVP-2 issue 4.2).
//!
//! Per D-007 + 4.2 R-a..R-f: no persistent indexer service. This
//! crate ships the **structural skeleton** for the opt-in fast-mode
//! sync path — a single crate that exposes both a library (mobile
//! in-process flow + tests) and a thin binary (desktop subprocess
//! flow). 4.2 is the lifecycle + stdio JSON protocol + cipher trait
//! stub; **4.3 ships the security hardening** of the temp DB
//! (ephemeral encryption key, explicit zero-fill before unlink,
//! `AeadCipher` impl).
//!
//! ## Resolved decisions (R-a..R-f — Kelvin sign-off 2026-05-16)
//!
//! - **R-a:** Single `pangolin-indexer` crate with `lib.rs` + `bin/`
//!   declaring `[lib]` and `[[bin]]` targets. No separate client
//!   crate.
//! - **R-b:** Stdio JSON protocol — line-delimited JSON requests on
//!   stdin, line-delimited JSON responses on stdout. Stderr reserved
//!   for `tracing` logs. Strict `serde(deny_unknown_fields)` on the
//!   request side; tagged enums for cross-platform greppability.
//! - **R-c:** `IDLE_TIMEOUT_DEFAULT_SECS = 300`; env override via
//!   `PANGOLIN_INDEXER_IDLE_TIMEOUT_SECS`; clamp `[60, 3_600]`.
//! - **R-d:** [`TempDbCipher`] trait + [`NoOpCipher`] passthrough
//!   stub. 4.3 swaps in the real impl.
//! - **R-e:** Both library + binary. Features: `default = ["bin"]`,
//!   `bin = ["dep:clap"]`. Mobile builds use
//!   `--no-default-features` to skip clap.
//! - **R-f:** Hermetic + cleanup-on-crash + `#[ignore]`'d live
//!   parity test (max coverage).
//!
//! ## L invariants (L1..L12 in `docs/issue-plans/4.2.md`)
//!
//! 1. Temp DB never persists past process exit (Drop +
//!    OS-temp-dir cleanup).
//! 2. Temp DB contains only the bound `vault_id`'s data.
//! 3. No external service.
//! 4. Identical revision-graph output vs 4.1 slow-mode.
//! 5. Idle timeout fires (`tokio::select!` on request + sleep).
//! 6. No new external crate dep beyond `tempfile`.
//! 7. Downstream of `pangolin-chain`; does NOT depend on
//!    `pangolin-store`.
//! 8. `forbid(unsafe_code)`.
//! 9. AGPL SPDX header on every `.rs` file.
//! 10. ZERO on-chain broadcast (read-only).
//! 11. Cleanup-on-crash via `tempfile`'s Drop + ctrlc handler.
//! 12. Same lifecycle code path in desktop subprocess + mobile
//!     in-process flows.

#![forbid(unsafe_code)]
#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]

pub mod cipher;
pub mod error;
pub mod protocol;
pub mod session;

#[cfg(any(test, feature = "test-utilities"))]
pub use cipher::NoOpCipher;
pub use cipher::{AeadCipher, CipherError, TempDbCipher, AEAD_KEY_LEN};
pub use error::IndexerError;
pub use protocol::{
    IndexedEvent, IndexerEvent, IndexerRequest, IndexerResponse, MAX_REQUEST_LINE_BYTES,
    PROTOCOL_VERSION,
};
pub use session::{
    resolve_idle_timeout, resolve_idle_timeout_from, IndexerConfig, IndexerSession,
    IDLE_TIMEOUT_DEFAULT_SECS, IDLE_TIMEOUT_ENV_VAR, IDLE_TIMEOUT_MAX_SECS, IDLE_TIMEOUT_MIN_SECS,
    PULL_BATCH_SIZE_MAX,
};

/// Returns the crate name. Useful for diagnostics and version
/// reporting; preserves the previous placeholder API surface.
#[must_use]
pub fn name() -> &'static str {
    "pangolin-indexer"
}

#[cfg(test)]
mod tests {
    use super::name;

    #[test]
    fn crate_name_is_set() {
        assert_eq!(name(), "pangolin-indexer");
    }
}
