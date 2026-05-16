// SPDX-License-Identifier: AGPL-3.0-or-later
//! 4.2 typed error taxonomy for the ephemeral indexer.
//!
//! Every variant maps to a load-bearing failure surface:
//!
//! - [`IndexerError::TempDbInit`] / [`IndexerError::TempDbIo`]:
//!   `NamedTempFile::new_in` failures or per-statement SQLite
//!   errors. L-temp-file-leak surface (operator must observe the
//!   error to know cleanup may be partial).
//! - [`IndexerError::ChainSync`]: bubble-through from
//!   `pangolin_chain::ChainError` (L4 + L5 verifier rejections,
//!   chain-id mismatches, RPC failures).
//! - [`IndexerError::ProtocolError`]: malformed JSON, unknown
//!   request variant, line-length exceeds
//!   `MAX_REQUEST_LINE_BYTES`, missing/invalid hex field. L-
//!   stdio-injection + L-host-indexer-mismatch surface.
//! - [`IndexerError::IdleTimeout`]: soft cap fired (L5).
//! - [`IndexerError::Stopped`]: graceful Stop request honored.
//! - [`IndexerError::Io`]: stdio I/O failure.
//! - [`IndexerError::Config`]: bad startup configuration.

use std::io;

use thiserror::Error;

/// Indexer-side error variants. Every variant is `Send + Sync` so it
/// can cross task boundaries (the lifecycle task in mobile in-process
/// flow, the binary entry's tokio runtime in desktop subprocess
/// flow).
#[derive(Debug, Error)]
pub enum IndexerError {
    /// Temp DB could not be initialised. Cleanup-on-drop is still
    /// active via `NamedTempFile`'s Drop impl.
    #[error("temp DB init failed: {message}")]
    TempDbInit { message: String },

    /// Temp DB hit an I/O / SQLite error mid-session.
    #[error("temp DB I/O failed: {message}")]
    TempDbIo { message: String },

    /// Chain-side fetch + verify failed (L4 + L5 defenses). Wraps
    /// the chain crate's typed error.
    #[error("chain sync failed: {0}")]
    ChainSync(#[from] pangolin_chain::ChainError),

    /// Malformed JSON, unknown request variant, line-length cap
    /// exceeded, or hex-decode failure on a field. L-stdio-injection
    /// + R-b strict-parse defense.
    #[error("protocol error: {message}")]
    ProtocolError { message: String },

    /// Idle-timeout fired (R-c / L5). The session has dropped the
    /// temp DB and exited cleanly; not a bug.
    #[error("indexer idle timeout fired")]
    IdleTimeout,

    /// Graceful Stop request was honored. Not strictly an error;
    /// surfaced so the lifecycle driver can exit-status accordingly.
    #[error("indexer stopped by host request")]
    Stopped,

    /// Stdio / process-side I/O failure.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// Startup configuration is invalid (e.g., the
    /// `PANGOLIN_INDEXER_IDLE_TIMEOUT_SECS` env var was parseable
    /// but out of range — clamped, not rejected — see R-c).
    #[error("invalid configuration: {message}")]
    Config { message: String },
}

impl IndexerError {
    /// Render the error as a one-line operator-readable message for
    /// the `IndexerResponse::Error { message }` wire variant. We
    /// avoid leaking the inner source's debug repr for two reasons:
    /// (a) the alloy/tokio source strings are noisy; (b) the
    /// protocol layer is text-only and the indexer never includes
    /// PII (chain-event data is non-secret) but the discipline
    /// stays consistent with `pangolin-funder`'s class-tag-only
    /// log shape.
    #[must_use]
    pub fn to_protocol_message(&self) -> String {
        self.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_error_renders_message() {
        let e = IndexerError::ProtocolError {
            message: "unknown request variant `fork_universe`".into(),
        };
        let s = e.to_protocol_message();
        assert!(s.contains("protocol error"));
        assert!(s.contains("fork_universe"));
    }

    #[test]
    fn idle_timeout_renders_message() {
        let e = IndexerError::IdleTimeout;
        assert!(e.to_protocol_message().contains("idle timeout"));
    }

    #[test]
    fn from_io_error_works() {
        let io_err = io::Error::new(io::ErrorKind::UnexpectedEof, "stdin closed");
        let e: IndexerError = io_err.into();
        assert!(matches!(e, IndexerError::Io(_)));
    }
}
