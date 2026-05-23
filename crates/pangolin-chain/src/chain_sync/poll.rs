// SPDX-License-Identifier: AGPL-3.0-or-later
//! HTTP-polling fallback for the chain-sync read path.
//!
//! Mirrors the v0 [`crate::base_sepolia::BaseSepoliaAdapter::pull_since`]
//! shape with the v1 typed binding + v1 verifier added per L1, L2, L5.

use alloy::eips::BlockNumberOrTag;
use alloy::primitives::{Address, B256, U256};
use alloy::providers::Provider;
use alloy::rpc::types::{Filter, Log as RpcLog};
use alloy::sol_types::SolEvent;

use crate::chain_submit::revision_log_v1_binding::RevisionLogV1;
use crate::deployments::ChainEnv;
use crate::error::ChainError;
use crate::secp256k1_signing::RevisionFieldsV1;
use crate::types::VaultId;
use crate::ChainAnchor;

use super::{
    event_to_revision_event, verify_signer_or_reject, VerifiedRevisionEvent,
    MAX_KNOWN_CLIENT_SCHEMA_VERSION,
};

/// Outcome of [`verify_alloy_log`] — either the event was successfully
/// decoded + passed every L2 defense, or it was rejected with a typed
/// reason. The HTTP polling path and the WS recv loop BOTH consume
/// this helper so verification is byte-identical across both
/// transports (issue #99 L2).
///
/// The `Rejected` variant carries no error — rejections at this layer
/// are silent (the orchestrator's `revisions_rejected` counter
/// increments, but the sync continues). Hard failures (e.g. an RPC
/// transport error) surface via `Result<…, ChainError>` from the
/// caller's I/O layer; this helper is pure decode + check.
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum VerifyOutcome {
    /// Log decoded + passed every defense. Ingest into the local
    /// revision graph.
    Verified(VerifiedRevisionEvent),
    /// Log was structurally invalid, or failed a defense-in-depth
    /// check (foreign address, wrong `vaultId` topic, future
    /// schemaVersion, missing block metadata, sequence overflow).
    /// Caller increments the rejection counter and moves on.
    Rejected,
}

/// L2 verification helper — decode + check a single alloy `Log` against
/// every defense the HTTP polling path applies, returning a
/// `VerifiedRevisionEvent` on success.
///
/// **Issue #99 L2.** Shared by `poll::fetch_chunk` (HTTP) and the WS
/// recv loop (`chain_sync::ws`) so verification is byte-identical
/// across both transports. The contract emits the same event shape
/// regardless of how we observe it; this helper enforces:
///
/// 1. **L4 + MED-4:** `log.address() == contract_address` (defense
///    against a misbehaving RPC splicing foreign logs into the
///    response).
/// 2. **L2 typed-binding decode:** via
///    `RevisionLogV1::RevisionPublished::decode_log`.
/// 3. **L-malicious-vault-id-substitution:** `decoded.vaultId ==
///    requested vault_id`.
/// 4. **L-schemaVersion-future-poison:** `decoded.schemaVersion <=
///    MAX_KNOWN_CLIENT_SCHEMA_VERSION`.
/// 5. **Anchor materialisation:** `log.block_number`,
///    `log.log_index`, `log.transaction_hash`, `log.block_hash` are
///    all Some (a log lacking any of these is a malformed RPC
///    response and is rejected).
/// 6. **Sequence range:** `u64::try_from(decoded.sequence)` succeeds.
///
/// The recovered-signer + signer-field cross-check (L5) is structurally
/// preserved via the [`super::verify_signer_or_reject`] helper but is
/// not invoked here because the v1 contract event surface does not
/// carry the inline signature bytes (the contract performs
/// `ecrecover` server-side at publish time and surfaces only the
/// recovered `signer` address). See the long comment block on the
/// `claimed_signer` line below + `docs/architecture/chain-sync.md` for
/// the L4+L3+contract-side-verification chain that makes this safe.
///
/// `env` is accepted for forward-compatibility with the L5 path that
/// will fire once a v1.1 event re-emits the signature bytes.
#[must_use]
pub fn verify_alloy_log(
    log: &RpcLog,
    vault_id: &VaultId,
    contract_address: &Address,
    _env: ChainEnv,
) -> VerifyOutcome {
    // (1) L4 + MED-4: filter is already address-pinned, but a
    // misbehaving RPC could splice in foreign logs. Drop silently.
    if log.address() != *contract_address {
        return VerifyOutcome::Rejected;
    }

    // (2) L2: typed-binding decode.
    let Ok(decoded) = RevisionLogV1::RevisionPublished::decode_log(&log.inner) else {
        return VerifyOutcome::Rejected;
    };

    // (3) L-malicious-vault-id-substitution: cross-check `vaultId`
    // topic against the requested vault. Server-side filter is the
    // first defense; this is defense-in-depth.
    let decoded_vault: [u8; 32] = decoded.vaultId.into();
    if decoded_vault != *vault_id {
        return VerifyOutcome::Rejected;
    }

    // (4) L-schemaVersion-future-poison: reject events with a
    // not-yet-known schema version.
    if decoded.schemaVersion > MAX_KNOWN_CLIENT_SCHEMA_VERSION {
        return VerifyOutcome::Rejected;
    }

    // The contract emits `signer` as the recovered address from its
    // server-side ecrecover; the event does not carry inline
    // signature bytes for v1. The L5 client-side verifier
    // (`verify_signer_or_reject`) is reachable via test fixtures
    // that synthesise the signature; production decode trusts the
    // L3 chain-id pin + L4 contract-address pin + contract-side
    // verification chain. See `fetch_chunk` for the canonical
    // long-form discussion.
    let claimed_signer = decoded.signer;

    // (5) Anchor materialisation.
    let Some(block_number) = log.block_number else {
        return VerifyOutcome::Rejected;
    };
    let Some(log_index) = log.log_index else {
        return VerifyOutcome::Rejected;
    };
    let Some(tx_hash) = log.transaction_hash else {
        return VerifyOutcome::Rejected;
    };
    let Some(block_hash) = log.block_hash else {
        return VerifyOutcome::Rejected;
    };

    // (6) Sequence range.
    let Ok(sequence) = u64::try_from(decoded.sequence) else {
        return VerifyOutcome::Rejected;
    };

    let device_id_bytes: [u8; 32] = decoded.deviceId.into();
    let account_id: [u8; 32] = decoded.accountId.into();
    let parent_revision: [u8; 32] = decoded.parentRevision.into();
    let enc_payload = decoded.encPayload.to_vec();

    let anchor = ChainAnchor {
        tx_hash: tx_hash.0,
        block_number,
        log_index,
        sequence,
    };
    let event = event_to_revision_event(
        *vault_id,
        account_id,
        parent_revision,
        device_id_bytes,
        decoded.schemaVersion,
        sequence,
        enc_payload,
        anchor,
    );
    VerifyOutcome::Verified(VerifiedRevisionEvent {
        event,
        signer: claimed_signer,
        block_hash,
        schema_version: decoded.schemaVersion,
    })
}

/// Issue a single `eth_getLogs` for the range `[from_block, to_block]`
/// filtered by D-017 + `RevisionPublished` topic0 + indexed `vaultId`
/// topic2, decode + verify each log, return the
/// `VerifiedRevisionEvent` set + the count of locally-rejected logs.
///
/// **V1 event topic layout** (`RevisionLogV1.RevisionPublished`):
/// `topic0 = signature`, `topic1 = sequence`, `topic2 = vaultId`,
/// `topic3 = accountId`. Server-side filter pins topic2; defense-in-depth
/// re-checks `decoded.vaultId` in [`verify_alloy_log`].
///
/// Per L6, the caller chunks at `LOG_BLOCK_CHUNK = 9_000`; this fn is
/// the per-chunk primitive (so the caller can chunk-loop without this
/// fn knowing about chunk boundaries).
pub async fn fetch_chunk<P: Provider>(
    provider: &P,
    env: ChainEnv,
    contract_address: Address,
    vault_id: &VaultId,
    from_block: u64,
    to_block: u64,
) -> Result<(Vec<VerifiedRevisionEvent>, u32), ChainError> {
    // Issue #107: V1's `RevisionPublished(uint256 indexed sequence,
    // bytes32 indexed vaultId, bytes32 indexed accountId, ...)` puts
    // `vaultId` at topic2, NOT topic1 (topic1 is `sequence`). Mirrors
    // `crate::chain_sync::v2::fetch_chunk_v2:~182`.
    let vault_topic: B256 = (*vault_id).into();
    let filter = Filter::new()
        .address(contract_address)
        .event_signature(RevisionLogV1::RevisionPublished::SIGNATURE_HASH)
        .from_block(BlockNumberOrTag::Number(from_block))
        .to_block(BlockNumberOrTag::Number(to_block))
        .topic2(vault_topic);

    let logs = provider
        .get_logs(&filter)
        .await
        .map_err(|e| ChainError::Rpc(format!("eth_getLogs {from_block}..={to_block}: {e}")))?;

    let mut verified = Vec::with_capacity(logs.len());
    let mut rejected: u32 = 0;
    // Issue #99 L2: WS recv loop calls the SAME `verify_alloy_log`
    // helper so verification is byte-identical across both transports.
    for log in &logs {
        match verify_alloy_log(log, vault_id, &contract_address, env) {
            VerifyOutcome::Verified(ev) => verified.push(ev),
            VerifyOutcome::Rejected => {
                rejected = rejected.saturating_add(1);
            }
        }
    }
    Ok((verified, rejected))
}

/// Verify a synthetic signed event from a test fixture or from a
/// hypothetical v1.1 event with an inline signature field. Threads
/// through the same L5 verifier the production path will use once the
/// contract event surface widens.
///
/// Defense-in-depth — the test suite uses this to cover the per-event
/// signer recovery + signer-field cross-check; the production decode
/// path defers to the contract's own `ecrecover` at publish time per
/// the doc-comment in [`fetch_chunk`].
#[allow(dead_code)]
pub(crate) fn verify_signed_event(
    fields: &RevisionFieldsV1,
    signature: &[u8; 65],
    claimed_signer: Address,
    env: ChainEnv,
) -> Result<Address, ChainError> {
    verify_signer_or_reject(fields, signature, claimed_signer, env)
}

/// Helper for translating a `U256` block number into a `u64`. Used in
/// tests where decoded fields come back as `U256`.
#[allow(dead_code)]
pub(crate) fn u256_to_u64_or_err(v: U256) -> Result<u64, ChainError> {
    u64::try_from(v).map_err(|_| ChainError::Decode("value does not fit in u64".into()))
}
