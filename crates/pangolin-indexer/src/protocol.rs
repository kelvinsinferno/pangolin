// SPDX-License-Identifier: AGPL-3.0-or-later
//! 4.2 R-b stdio JSON protocol shapes.
//!
//! The host writes one [`IndexerRequest`] per line on the indexer's
//! stdin; the indexer writes one [`IndexerResponse`] per line on
//! stdout. Stderr is reserved for `tracing` logs (kept clear of the
//! protocol). Mobile in-process callers skip the framing layer and
//! call `IndexerSession::handle_request` directly with the same
//! enums — same shapes, two transports (L12).
//!
//! ## Wire format (R-b)
//!
//! - Line-delimited JSON.
//! - Tag-discriminated enums via `#[serde(tag = "type")]` so the
//!   wire format stays greppable.
//! - All byte-bag fields (vault_id, signer, block_hash, tx_hash,
//!   parent_revision, device_id, account_id, enc_payload) are
//!   serialised as lowercase **hex strings without** an `0x` prefix
//!   for cross-platform JSON compat.
//!
//! ## L-host-indexer-mismatch defense
//!
//! Every [`IndexerResponse::Started`] carries a `protocol_version`
//! field equal to [`PROTOCOL_VERSION`]; the host MUST cross-check on
//! receipt and abort on mismatch.
//!
//! ## L-stdio-injection defense
//!
//! The session parses each line via `serde_json::from_str` into the
//! strict enum below — unknown variants are rejected as
//! [`crate::error::IndexerError::ProtocolError`]. Lines longer than
//! [`MAX_REQUEST_LINE_BYTES`] are dropped before any parse attempt.

use serde::{Deserialize, Serialize};

/// Protocol-version pin (R-b + L-host-indexer-mismatch). Bumped only
/// when the wire format gains an incompatible variant; additive
/// fields stay at this version because `#[serde(deny_unknown_fields)]`
/// is intentionally OFF on the response side (forward-compat with
/// future hosts) but ON on the request side (strict in what we
/// accept).
pub const PROTOCOL_VERSION: u16 = 1;

/// Defense-in-depth ceiling on the per-request line length (R-b L-
/// stdio-injection). Any line longer than this is rejected without
/// even attempting to parse. The largest legitimate line is a `Pull`
/// or `StartIndex` request, both well under this bound; the cap exists
/// to prevent an attacker-controlled stdin from forcing the indexer
/// to buffer an unbounded line.
pub const MAX_REQUEST_LINE_BYTES: usize = 65_536;

/// Host → indexer requests. R-b verbatim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum IndexerRequest {
    /// Begin indexing events for the named vault between
    /// `start_block` and `end_block` (inclusive). `end_block = None`
    /// ⇒ "follow the current chain tip" (resolved by the session at
    /// dispatch time).
    StartIndex {
        /// Lowercase hex (no `0x`) of the 32-byte `vault_id`.
        vault_id: String,
        start_block: u64,
        end_block: Option<u64>,
    },
    /// Drain up to `batch_size` events from the indexer's temp DB.
    /// The session returns an [`IndexerResponse::Batch`] containing
    /// the next slice of events.
    Pull {
        /// Maximum events to return in the response. Clamped to a
        /// sane upper bound by the session.
        batch_size: u32,
    },
    /// Host keep-alive ping (resets the idle-timeout clock). The
    /// session responds with [`IndexerResponse::Heartbeat`].
    Heartbeat,
    /// Graceful shutdown. Session drops the temp DB and replies with
    /// [`IndexerResponse::Stopped`] before exiting.
    Stop,
}

/// Indexer → host responses. R-b verbatim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum IndexerResponse {
    /// Acknowledges a [`IndexerRequest::StartIndex`]. The
    /// `protocol_version` field is the host's L-host-indexer-mismatch
    /// check; the host MUST abort on a mismatch.
    Started {
        protocol_version: u16,
        /// Lowercase hex (no `0x`) of the vault id the session is
        /// now bound to. Echo-back of the request value so the host
        /// can sanity-check.
        vault_id: String,
    },
    /// A drained slice of verified events. Empty `events` ⇒ "no
    /// more events available right now"; the host may retry on the
    /// next interval.
    Batch { events: Vec<IndexedEvent> },
    /// Progress beacon — chunks of blocks indexed so far + the
    /// total target window. Emitted via `IndexerResponse` to the
    /// host on demand (R-b future-extension; 4.2 emits this on
    /// every [`IndexerRequest::Pull`]).
    Progress {
        fetched_blocks: u64,
        total_blocks: u64,
        last_block_processed: u64,
    },
    /// Heartbeat acknowledgement. Session has reset its idle-timer.
    Heartbeat,
    /// Indexing reached the target block + the temp DB has been
    /// drained empty — host may now request [`IndexerRequest::Stop`]
    /// or keep the indexer alive for a future `StartIndex`.
    Complete { last_block: u64 },
    /// Graceful-shutdown acknowledgement.
    Stopped,
    /// Out-of-band error (malformed request, chain RPC failure,
    /// temp-DB write failure). Carries an operator-readable message;
    /// the typed taxonomy lives in [`crate::error::IndexerError`].
    Error { message: String },
}

/// Streamed event-bus payload — what the binary emits to stdout when
/// the host has requested a streamed (rather than pull-based) fetch.
/// 4.2 reserves this variant for symmetry with R-b's full surface;
/// the canonical 4.2 flow is pull-based (`IndexerRequest::Pull` →
/// `IndexerResponse::Batch`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum IndexerEvent {
    /// A batch of verified events ready for the host to ingest.
    Batch { events: Vec<IndexedEvent> },
    /// Progress beacon — block range advanced.
    Progress {
        fetched_blocks: u64,
        total_blocks: u64,
        last_block_processed: u64,
    },
    /// Indexing reached the target block.
    Complete { last_block: u64 },
    /// Fatal error during indexing.
    Error { message: String },
}

/// Wire shape for a single verified revision event.
///
/// Mirrors `pangolin_chain::chain_sync::VerifiedRevisionEvent` (the
/// chain-side decoded shape) with every binary field hex-encoded for
/// JSON transit. Lossless round-trip: hex strings decode back to the
/// same byte arrays the chain-side primitive produced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexedEvent {
    /// Lowercase hex (no `0x`) of the 32-byte vault id.
    pub vault_id: String,
    /// Lowercase hex (no `0x`) of the 32-byte account id.
    pub account_id: String,
    /// Lowercase hex (no `0x`) of the 32-byte parent revision hash.
    pub parent_revision: String,
    /// Lowercase hex (no `0x`) of the 32-byte device id (left-padded
    /// EVM address per 2.1 R-b semantics).
    pub device_id: String,
    /// `schemaVersion` decoded from the chain event. Bounded by
    /// `pangolin_chain::MAX_KNOWN_CLIENT_SCHEMA_VERSION` at decode
    /// time; values above that are rejected upstream.
    pub schema_version: u16,
    /// `sequence` decoded from the chain event.
    pub sequence: u64,
    /// Lowercase hex (no `0x`) of the encrypted payload bytes.
    pub enc_payload: String,
    /// Lowercase hex (no `0x`) of the 20-byte recovered signer
    /// address.
    pub signer: String,
    /// Block number the event was emitted in.
    pub block_number: u64,
    /// Lowercase hex (no `0x`) of the 32-byte block hash the event
    /// was observed in (used by the host for reorg detection).
    pub block_hash: String,
    /// Lowercase hex (no `0x`) of the 32-byte transaction hash.
    pub tx_hash: String,
    /// Log index of the event within the containing transaction.
    pub log_index: u64,
}

impl IndexedEvent {
    /// Build an [`IndexedEvent`] from a chain-side
    /// [`pangolin_chain::VerifiedRevisionEvent`].
    ///
    /// Hex encoding uses lowercase without an `0x` prefix per the
    /// wire-format contract documented at the top of this module.
    #[must_use]
    pub fn from_verified(verified: &pangolin_chain::VerifiedRevisionEvent) -> Self {
        let ev = &verified.event;
        Self {
            vault_id: hex::encode(ev.vault_id),
            account_id: hex::encode(ev.account_id),
            parent_revision: hex::encode(ev.parent_revision),
            device_id: hex::encode(ev.device_id),
            schema_version: verified.schema_version,
            sequence: ev.sequence,
            enc_payload: hex::encode(&ev.enc_payload),
            signer: hex::encode(verified.signer.as_slice()),
            block_number: ev.anchor.block_number,
            block_hash: hex::encode(verified.block_hash.as_slice()),
            tx_hash: hex::encode(ev.anchor.tx_hash),
            log_index: ev.anchor.log_index,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_version_pinned_at_1() {
        // L-host-indexer-mismatch: the version constant is the
        // host's only signal that the indexer matches its expected
        // protocol. Pin it so a silent bump is caught.
        assert_eq!(PROTOCOL_VERSION, 1);
    }

    #[test]
    fn max_request_line_bytes_is_64k() {
        // L-stdio-injection: the cap is part of the defense surface;
        // pin it so a silent loosening is caught.
        assert_eq!(MAX_REQUEST_LINE_BYTES, 65_536);
    }

    #[test]
    fn request_start_index_round_trips() {
        let req = IndexerRequest::StartIndex {
            vault_id: "aa".repeat(32),
            start_block: 100,
            end_block: Some(200),
        };
        let s = serde_json::to_string(&req).unwrap();
        let back: IndexerRequest = serde_json::from_str(&s).unwrap();
        assert_eq!(req, back);
    }

    #[test]
    fn request_pull_round_trips() {
        let req = IndexerRequest::Pull { batch_size: 64 };
        let s = serde_json::to_string(&req).unwrap();
        let back: IndexerRequest = serde_json::from_str(&s).unwrap();
        assert_eq!(req, back);
    }

    #[test]
    fn request_heartbeat_and_stop_round_trip() {
        for req in [IndexerRequest::Heartbeat, IndexerRequest::Stop] {
            let s = serde_json::to_string(&req).unwrap();
            let back: IndexerRequest = serde_json::from_str(&s).unwrap();
            assert_eq!(req, back);
        }
    }

    #[test]
    fn request_rejects_unknown_variant() {
        let bad = r#"{"type":"fork_universe","seed":42}"#;
        assert!(serde_json::from_str::<IndexerRequest>(bad).is_err());
    }

    #[test]
    fn request_rejects_unknown_field() {
        // `deny_unknown_fields` keeps the request side strict (R-b
        // L-stdio-injection).
        let bad = r#"{"type":"pull","batch_size":1,"extra":"poison"}"#;
        assert!(serde_json::from_str::<IndexerRequest>(bad).is_err());
    }

    #[test]
    fn request_rejects_malformed_json() {
        let bad = "not json at all";
        assert!(serde_json::from_str::<IndexerRequest>(bad).is_err());
    }

    #[test]
    fn response_started_carries_protocol_version() {
        let resp = IndexerResponse::Started {
            protocol_version: PROTOCOL_VERSION,
            vault_id: "ab".repeat(32),
        };
        let s = serde_json::to_string(&resp).unwrap();
        assert!(s.contains("\"protocol_version\":1"));
    }
}
