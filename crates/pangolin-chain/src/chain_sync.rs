// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::too_long_first_doc_paragraph, clippy::doc_markdown)]
//! Slow-mode chain sync — the default READ path for MVP-2 (§4 cluster).
//!
//! **Scope (MVP-2 issue 4.1, R-a..R-f signed off by Kelvin 2026-05-15):**
//! consume `RevisionPublished` events from D-017
//! (`RevisionLogV1` at `0x179362Ad7fb7dA664312aEFDdaa53431eb748E42` on
//! Base Sepolia, `chainId = 84_532`); filter by the caller's `vault_id`
//! (indexed event topic); per-event recover the secp256k1 signer via
//! the production verifier ([`crate::recover_signer_v1_raw`]); feed
//! verified events into the existing
//! `Vault::ingest_chain_revision(&pangolin_chain::RevisionEvent)` MVP-1
//! entry point; track a per-vault `last_synced_block` checkpoint so
//! subsequent syncs are bounded.
//!
//! ## R-a..R-f resolutions
//!
//! - **R-a:** Persist `last_synced_block` in `.pvf` (additive schema +
//!   §18.7 bump). Genesis-replay on first sync; checkpoint-resume on
//!   subsequent syncs. Force-from-genesis escape hatch via
//!   [`SyncOptions::from_genesis`].
//!
//! - **R-b:** WebSocket-preferred with HTTP-poll fallback. The
//!   [`ChainEventSource`] enum tracks which mode is active; the
//!   orchestrator opens WS first, falls back to HTTP-poll on WS-open
//!   failure or mid-session drop. NOTE: alloy's WS feature
//!   (`alloy::providers::ws`) is not currently enabled in the workspace
//!   `Cargo.toml` (see L8 — no new external crate dep). The WS-open
//!   path in [`mod@ws`] returns `WsUnavailable` immediately, forcing
//!   the HTTP-fallback branch in production; the orchestration shape +
//!   tests cover both branches so the WS upgrade is a future
//!   feature-flag flip + dep addition rather than a structural rewrite.
//!
//! - **R-c:** Two-stage rollback. [`RevisionStatus::Pending`] at 1-conf;
//!   promote to [`RevisionStatus::Finalized`] at depth ≥
//!   [`CONFIRMATION_DEPTH_FOR_FINALIZATION`]. Reorg detection compares
//!   the observed `block_hash` at each known pending block against the
//!   canonical chain's block-hash-at-that-height; mismatch → rollback
//!   the affected pending revisions via
//!   [`Vault::rollback_pending_revisions_in_range`].
//!
//! - **R-d:** Permissive auto-register. Recovered signer not in the
//!   local devices table → INSERT a fresh `DeviceIdentity` row with
//!   `discovered_via_chain_sync = true` + `discovered_at_block` for
//!   audit (see [`pangolin_store::auto_register_device_from_chain_sync`]).
//!
//! - **R-e:** The dep-direction concern (pangolin-chain depending on
//!   pangolin-store) lives in [`super::lib`]; we adopt the alternative
//!   in plan-gate Q-e: this crate exposes primitives + decoded-event
//!   types, the orchestration helper lives in
//!   [`pangolin_store::Vault::sync_from_chain`]. L7 preserved.
//!
//! - **R-f:** Hermetic + live + reorg simulator. The hermetic suite
//!   lives in [`tests`]; the live `#[ignore]`'d test lives at
//!   `crates/pangolin-chain/tests/integration.rs` (gated behind
//!   `--features integration-tests`); the reorg simulator extends the
//!   alloy `MockTransport` posture used by 3.3 hermetic tests.
//!
//! ## L1..L12 invariants
//!
//! See `docs/issue-plans/4.1.md` "Decisions locked" table for the
//! authoritative list. Salient ones embodied in this module:
//!
//! - L1: signer recovery uses byte-IDENTICAL EIP-712 digest to 3.1's
//!   signing — re-uses the existing `pub(crate)`
//!   [`crate::secp256k1_signing::struct_hash`] /
//!   [`crate::secp256k1_signing::eip712_digest`] /
//!   [`crate::secp256k1_signing::build_domain`] helpers.
//! - L2: event ABI decoding via reused
//!   [`crate::chain_submit::revision_log_v1_binding::RevisionLogV1::RevisionPublished`].
//! - L3: `eth_chainId` cross-check at provider construction.
//! - L4: contract address loaded via `load_deployed_address` +
//!   cross-checked against `EXPECTED_DEPLOYED_ADDRESS_BASE_SEPOLIA`.
//! - L5: per-revision verifier (signer recovery + on-event-`signer`
//!   cross-check + R-d disposition).
//! - L6: bounded fetch — [`LOG_BLOCK_CHUNK = 9_000`](LOG_BLOCK_CHUNK).
//! - L7: `pangolin-store -> pangolin-chain` direction preserved (no
//!   reverse dep).
//! - L8: NO new external crate dep beyond what's already in tree.
//!   See R-b note above for the WS-feature deferral consequence.
//! - L11: ZERO on-chain broadcast in 4.1. READ-only.
//! - L12: replay protection via existing MVP-1
//!   `Vault::ingest_chain_revision` idempotency (canonical-hash +
//!   chain-anchor match).

pub mod poll;
pub mod reorg;
pub mod ws;

use alloy::network::Ethereum;
use alloy::primitives::{Address, B256};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};

use crate::deployments::ChainEnv;
use crate::error::ChainError;
use crate::secp256k1_signing::{
    recover_signer_v1_raw, RevisionFieldsV1, EXPECTED_DEPLOYED_ADDRESS_BASE_SEPOLIA,
};
use crate::types::VaultId;
use crate::ChainAnchor;
use crate::{load_deployed_address, RevisionEvent};

// ---------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------

/// Number of confirmations required before promoting a `Pending`
/// revision to `Finalized` per R-c. `12` matches Ethereum mainnet's
/// "safe" heuristic; on Base Sepolia's ~2s block times this is ~24s.
pub const CONFIRMATION_DEPTH_FOR_FINALIZATION: u64 = 12;

/// Maximum block range per `eth_getLogs` chunk. Same constant the v0
/// `BaseSepoliaAdapter::pull_since` uses; matches the public Base
/// Sepolia RPC's 10k cap with a safety margin.
pub const LOG_BLOCK_CHUNK: u64 = 9_000;

/// Initial backoff for a WS reconnect attempt, in milliseconds. The
/// orchestrator doubles this on each failed reconnect up to
/// [`WS_RECONNECT_MAX_BACKOFF_MS`].
pub const WS_RECONNECT_INITIAL_BACKOFF_MS: u64 = 250;

/// Maximum backoff for a WS reconnect attempt, in milliseconds.
pub const WS_RECONNECT_MAX_BACKOFF_MS: u64 = 30_000;

/// Maximum `schemaVersion` value this client build understands. Events
/// with `schemaVersion > MAX_KNOWN_CLIENT_SCHEMA_VERSION` are rejected
/// per L-schemaVersion-future-poison.
pub const MAX_KNOWN_CLIENT_SCHEMA_VERSION: u16 = 1;

/// Default poll interval for the HTTP-fallback branch, in seconds. The
/// orchestrator caller (`Vault::sync_from_chain`) drives the loop
/// cadence; this constant is the default the caller picks up when no
/// override is supplied.
pub const HTTP_POLL_INTERVAL_SECS: u64 = 30;

// ---------------------------------------------------------------------
// SyncReport
// ---------------------------------------------------------------------

/// Summary of a `sync_vault_from_chain` invocation. Returned to the
/// caller so a host UI (CLI / FFI) can surface per-sync stats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SyncReport {
    /// Total events pulled from the chain (post server-side filter).
    pub revisions_pulled: u32,
    /// Events that successfully verified + landed (or merged into) the
    /// local revision graph as `Pending` or `Finalized`.
    pub revisions_applied: u32,
    /// Events rejected by a defense-in-depth check (signer recovery
    /// failed, signer-field mismatch, schema version too high,
    /// foreign vault id).
    pub revisions_rejected: u32,
    /// Final `last_synced_block` value at the end of the sync; the
    /// checkpoint write happens inside `Vault::sync_from_chain` after
    /// successful event ingest.
    pub last_block_synced: u64,
    /// Number of fresh `device_identities` rows inserted by the
    /// auto-register branch (R-d).
    pub new_devices_registered: u32,
    /// Number of pending revisions promoted to `Finalized` during this
    /// sync.
    pub revisions_finalized: u32,
    /// Number of pending revisions rolled back due to a detected reorg
    /// during this sync.
    pub revisions_rolled_back: u32,
    /// Which event source the sync ultimately used. WebSocket means
    /// the WS path stayed up for the entire sync; HttpPolling means
    /// either the WS path was never attempted (feature off) or it
    /// failed and the orchestrator fell back.
    pub event_source: ChainEventSource,
}

// ---------------------------------------------------------------------
// ChainEventSource
// ---------------------------------------------------------------------

/// Which event-fetch backend the sync orchestrator ultimately ran.
///
/// `SyncReport.event_source` lets the host distinguish a "WS connected,
/// receiving events live" sync from a "fell back to HTTP poll" sync.
/// Useful for UX telemetry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ChainEventSource {
    /// WebSocket subscription via `eth_subscribe("logs")`.
    WebSocket,
    /// HTTP polling via chunked `eth_getLogs`. The default fallback;
    /// also the default in builds where alloy WS support is not yet
    /// enabled (see R-b note in module docstring).
    #[default]
    HttpPolling,
}

// ---------------------------------------------------------------------
// RevisionStatus
// ---------------------------------------------------------------------

/// Two-stage finality state per R-c. The local revision graph carries
/// a status column whose values are:
///
/// - [`Self::Pending`] — applied optimistically at 1-conf, subject to
///   rollback on reorg detection.
/// - [`Self::Finalized`] — at depth ≥
///   [`CONFIRMATION_DEPTH_FOR_FINALIZATION`], no longer subject to
///   rollback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevisionStatus {
    /// Applied at 1-conf; observed at `observed_at_block` with hash
    /// `block_hash`. If the canonical chain's block-hash-at-that-height
    /// later diverges from `block_hash` (a reorg removed the event),
    /// the row is rolled back via
    /// `Vault::rollback_pending_revisions_in_range`.
    Pending {
        /// Block height the event was observed at.
        observed_at_block: u64,
        /// Block hash the event was observed in. Reorg detection
        /// compares this against the canonical chain's block-hash at
        /// that height on every subsequent sync iteration.
        block_hash: B256,
    },
    /// Promoted at depth ≥ [`CONFIRMATION_DEPTH_FOR_FINALIZATION`].
    /// No longer subject to rollback.
    Finalized,
}

impl RevisionStatus {
    /// Returns true iff the status is `Pending`.
    #[must_use]
    pub const fn is_pending(&self) -> bool {
        matches!(self, Self::Pending { .. })
    }

    /// Returns true iff the status is `Finalized`.
    #[must_use]
    pub const fn is_finalized(&self) -> bool {
        matches!(self, Self::Finalized)
    }
}

// ---------------------------------------------------------------------
// SyncOptions
// ---------------------------------------------------------------------

/// Caller-supplied tuning for the orchestration loop. `Default::default`
/// produces the production posture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncOptions {
    /// If `true`, ignore the persisted `last_synced_block` and start
    /// from the deploy block of D-017 (R-a Option C escape hatch).
    /// Useful for the user-facing `pangolin sync --from-genesis`
    /// command.
    pub from_genesis: bool,
    /// Bound the sync window above this block height. `None` ⇒ use
    /// the current chain tip.
    pub until_block: Option<u64>,
    /// If `true`, attempt WebSocket subscription first (R-b WS-preferred
    /// posture). Default `true`.
    pub prefer_websocket: bool,
}

impl Default for SyncOptions {
    fn default() -> Self {
        Self {
            from_genesis: false,
            until_block: None,
            prefer_websocket: true,
        }
    }
}

// ---------------------------------------------------------------------
// Verified-event type returned from a chunk fetch
// ---------------------------------------------------------------------

/// Output of [`fetch_and_verify_chunk`] — a decoded + signature-verified
/// `RevisionPublished` event that's ready to be ingested into the local
/// revision graph.
///
/// Carries the `RevisionEvent` (the existing MVP-1 ingest type for
/// [`pangolin_chain::RevisionEvent`]) plus the v1-specific extras (the
/// recovered `signer` address + the `block_hash` for reorg detection).
/// The MVP-1 `Vault::ingest_chain_revision` consumer reads only the
/// `event` field; the orchestration helper in pangolin-store uses
/// `signer` for R-d auto-register and `block_hash` for the pending-row
/// reorg-detection cache.
#[derive(Debug, Clone)]
pub struct VerifiedRevisionEvent {
    /// The shape `Vault::ingest_chain_revision` expects.
    pub event: RevisionEvent,
    /// Address recovered from the event's signature + EIP-712 digest
    /// (and cross-checked against the event's unindexed `signer` field
    /// per L5).
    pub signer: Address,
    /// Block hash the event was emitted in. Stored alongside the row
    /// as part of the `RevisionStatus::Pending { block_hash }` marker.
    pub block_hash: B256,
    /// Schema version decoded from the event. Used by the orchestrator
    /// for schema-version-rejection accounting.
    pub schema_version: u16,
}

// ---------------------------------------------------------------------
// Public entry — fetch + verify a chunk of events
// ---------------------------------------------------------------------

/// Fetch + verify a chunk of `RevisionPublished` events from
/// `from_block..=to_block`. Caller is the orchestration helper in
/// `pangolin-store::Vault::sync_from_chain` (R-e).
///
/// Implements:
///
/// 1. Provider construction (HTTP transport; `eth_chainId` cross-check
///    per L3).
/// 2. Contract address load + pinned-constant cross-check per L4.
/// 3. Chunked `eth_getLogs` per L6 (caller passes a chunk; this fn
///    issues one `eth_getLogs` per call).
/// 4. Per-event:
///    - Decode via reused alloy `sol!` binding per L2.
///    - Cross-check `vault_id` topic equals the requested vault per
///      L-malicious-vault-id-substitution.
///    - Cross-check `schemaVersion ≤ MAX_KNOWN_CLIENT_SCHEMA_VERSION`
///      per L-schemaVersion-future-poison.
///    - Cross-check `address == contract_address` per L4 + MED-4.
///    - Recover signer via [`recover_signer_v1_raw`] per L5.
///    - Cross-check recovered signer equals the unindexed `signer`
///      field per L5 second arm.
///    - Build `VerifiedRevisionEvent` with the recovered signer +
///      observed block_hash for the orchestrator's R-c / R-d
///      decisions.
///
/// Returns `(verified_events, chunk_rejected_count)`.
///
/// # Errors
///
/// - [`ChainError::ChainIdMismatch`] / [`ChainError::DeploymentAddressMismatch`]
///   / [`ChainError::DeploymentNotFound`] /
///   [`ChainError::DeploymentParseError`] — construction-time fail-closed.
/// - [`ChainError::Rpc`] — transport-layer failures.
/// - [`ChainError::Decode`] — log decode / topic-extraction failures.
pub async fn fetch_and_verify_chunk(
    rpc_url: &str,
    env: ChainEnv,
    vault_id: &VaultId,
    from_block: u64,
    to_block: u64,
) -> Result<(Vec<VerifiedRevisionEvent>, u32), ChainError> {
    let contract_address = resolve_and_check_contract(env)?;
    let provider = build_read_provider(rpc_url).await?;
    check_chain_id_matches(&provider, env).await?;
    poll::fetch_chunk(
        &provider,
        env,
        contract_address,
        vault_id,
        from_block,
        to_block,
    )
    .await
}

/// Resolve D-017's deploy block — the genesis cursor for first-time
/// syncs. Currently hard-pinned to the live deploy block of D-017 on
/// Base Sepolia (`41_507_120`); for `BaseMainnet` / `Dev` the helper
/// returns `0` so a fresh deployment's first sync replays from chain
/// genesis (acceptable for those envs since Base Sepolia is the only
/// pinned env in MVP-2).
///
/// **Why a constant.** Reading `eth_getCode` history to find a contract's
/// deploy block requires an archival RPC; pinning the value avoids the
/// extra RPC + works against pruned RPCs.
///
/// **Issue #98 (2026-05-18) — env-quirk #14 audit-class rot fix.**
/// Two prior values were both wrong:
///
/// - `23_640_113` (Rust, originally captured at 4.1 plan-gate) predates
///   Base Sepolia genesis by months and was an outright clerical error.
/// - `41_639_216` (`contracts/deployments/base-sepolia.json`,
///   `RevisionLogV1.deploy_block`) was the recorded deploy-pipeline
///   value but ALSO did not match the live chain.
///
/// The authoritative value `41_507_120` was re-derived by binary-search
/// over `cast code` against the live D-017 contract: at block
/// `41_507_119` `eth_getCode` returns `0x` (no contract); at
/// `41_507_120` it returns the deployed runtime bytecode. Confirmed via
/// `cast tx 0x22e464123c7fc1c71a161350d521ed7946975b0a9a3b9fd232d8846327cacd19`
/// which records `blockNumber = 41507120`. Same commit re-pinned the
/// JSON record + added the [`deployment_json_pins_match_rust_constants`]
/// CI test so the next rot fails at PR time, not in production.
///
/// Verification commands (run any time the constant is changed):
///
/// ```text
/// cast block-number --rpc-url $BASE_SEPOLIA_RPC_URL    # current tip
/// cast code 0x179362Ad7fb7dA664312aEFDdaa53431eb748E42 \
///     --block 41507120 --rpc-url $BASE_SEPOLIA_RPC_URL  # NON-empty
/// cast code 0x179362Ad7fb7dA664312aEFDdaa53431eb748E42 \
///     --block 41507119 --rpc-url $BASE_SEPOLIA_RPC_URL  # 0x (empty)
/// ```
#[must_use]
pub const fn d017_deploy_block(env: ChainEnv) -> u64 {
    match env {
        ChainEnv::BaseSepolia => 41_507_120,
        _ => 0,
    }
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

/// L4: load the contract address from `contracts/deployments/<env>.json`
/// and cross-check against the pinned `EXPECTED_DEPLOYED_ADDRESS_*`
/// constant. Mismatch → `DeploymentAddressMismatch`.
pub fn resolve_and_check_contract(env: ChainEnv) -> Result<Address, ChainError> {
    let contract_address = load_deployed_address(env, "RevisionLogV1")?;
    if matches!(env, ChainEnv::BaseSepolia)
        && contract_address != EXPECTED_DEPLOYED_ADDRESS_BASE_SEPOLIA
    {
        return Err(ChainError::DeploymentAddressMismatch {
            env,
            expected: EXPECTED_DEPLOYED_ADDRESS_BASE_SEPOLIA,
            actual: contract_address,
        });
    }
    Ok(contract_address)
}

/// L3: cross-check the RPC's reported `eth_chainId` against the build's
/// expected chain id. Fail-closed before any `eth_getLogs` is issued.
pub async fn check_chain_id_matches<P: Provider>(
    provider: &P,
    env: ChainEnv,
) -> Result<(), ChainError> {
    if let Some(expected) = env.chain_id() {
        let observed = provider
            .get_chain_id()
            .await
            .map_err(|e| ChainError::Rpc(format!("eth_chainId: {e}")))?;
        if observed != expected {
            return Err(ChainError::ChainIdMismatch { expected, observed });
        }
    }
    Ok(())
}

/// Build a read-only alloy provider (no wallet). The sync path does not
/// sign or broadcast anything (L11); a wallet-less provider is the
/// narrowest surface that satisfies the read use case.
pub async fn build_read_provider(rpc_url: &str) -> Result<DynProvider, ChainError> {
    let provider = ProviderBuilder::new()
        .network::<Ethereum>()
        .connect(rpc_url)
        .await
        .map_err(|e| ChainError::Rpc(format!("connect {rpc_url}: {e}")))?;
    Ok(provider.erased())
}

/// Fetch the current chain head block number. Convenience wrapper used
/// by `pangolin-store`'s orchestrator helper, which does not directly
/// depend on `alloy`.
pub async fn fetch_current_block_number(rpc_url: &str) -> Result<u64, ChainError> {
    let provider = build_read_provider(rpc_url).await?;
    provider
        .get_block_number()
        .await
        .map_err(|e| ChainError::Rpc(format!("eth_blockNumber: {e}")))
}

/// One-shot reorg check: build a fresh provider + query the canonical
/// block hash for each observation in `detector` + return the affected
/// window (if any). Used by `pangolin-store`'s orchestrator so it can
/// drive the reorg path without pulling alloy as a direct dep.
pub async fn detect_reorg_via_rpc(
    rpc_url: &str,
    detector: &reorg::ReorgDetector,
) -> Result<Option<reorg::ReorgInfo>, ChainError> {
    let provider = build_read_provider(rpc_url).await?;
    detector.detect_reorg(&provider).await
}

/// Map a recovered-signer error into the canonical `Decode` / typed
/// error variant per L5. Used by [`poll`] and [`ws`] when verifying
/// decoded events.
pub(crate) fn verify_signer_or_reject(
    fields: &RevisionFieldsV1,
    signature: &[u8; 65],
    claimed_signer: Address,
    env: ChainEnv,
) -> Result<Address, ChainError> {
    let recovered = recover_signer_v1_raw(fields, signature, env)?;
    if recovered != claimed_signer {
        return Err(ChainError::EventSignerMismatch {
            claimed: claimed_signer,
            recovered,
        });
    }
    Ok(recovered)
}

/// Reconstruct a `pangolin_chain::RevisionEvent` from the v1 decoded
/// event fields.
///
/// The v1 contract emits `deviceId` as a left-padded EVM address (per
/// 2.1 R-b semantics); `RevisionEvent.device_id` is `[u8; 32]` so we
/// pass the full 32 bytes through — the address sits in the rightmost
/// 20.
#[allow(clippy::too_many_arguments)]
pub(crate) fn event_to_revision_event(
    vault_id: VaultId,
    account_id: [u8; 32],
    parent_revision: [u8; 32],
    device_id: [u8; 32],
    schema_version: u16,
    sequence: u64,
    enc_payload: Vec<u8>,
    anchor: ChainAnchor,
) -> RevisionEvent {
    // The v0 `RevisionEvent` carries a `u8` schema_version; the v1
    // contract emits `uint16`. For v1 events that pass the schema-
    // version-rejection gate (≤ MAX_KNOWN_CLIENT_SCHEMA_VERSION = 1),
    // the value fits in `u8` losslessly. The orchestrator gates
    // `schema_version <= MAX_KNOWN_CLIENT_SCHEMA_VERSION` upstream.
    let schema_version_u8 = u8::try_from(schema_version).unwrap_or(0);
    RevisionEvent {
        vault_id,
        account_id,
        parent_revision,
        device_id,
        schema_version: schema_version_u8,
        sequence,
        enc_payload,
        anchor,
    }
}

#[cfg(test)]
mod tests;
