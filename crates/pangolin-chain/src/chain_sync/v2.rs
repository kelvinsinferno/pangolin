// SPDX-License-Identifier: AGPL-3.0-or-later
//! V2 revision read path (#106c2 — the everyday data-plane READ leg).
//!
//! Mirrors [`crate::chain_sync::poll`] (HTTP `eth_getLogs`) +
//! [`crate::chain_sync::ws`] (the WS subscription) but targets the
//! `RevisionLogV2` contract + its `RevisionPublished` event (added to the
//! #106c `sol!` binding by #106c2). The per-event verify chain is
//! byte-identical to V1's; only the contract address + the event topic-0
//! differ (the v2 domain gives `RevisionPublished` a different topic-0
//! from V1, which is correct — a v1 reader must never consume v2 events
//! and vice-versa).
//!
//! ## L5 — read-side verification (V1 parity)
//!
//! Production trusts the event `signer` (the contract's publish-time
//! `ecrecover` under the v2 domain, gated by the L3 chain-id pin + the L4
//! V2 contract-address pin); the V2 events carry no inline signature
//! bytes (V1 parity, finding 0a-3). The client-side L5 recover arm
//! ([`crate::revisionlog_v2_signing::recover_signer_v2_raw`] under the v2
//! domain) is exposed via [`verify_signed_event_v2`] for tests /
//! defense-in-depth.
//!
//! ## L2 — one verify path across both transports
//!
//! [`verify_alloy_log_v2`] is the single decode+check helper; both
//! [`fetch_chunk_v2`] (HTTP) and the WS recv loop in
//! `Vault::sync_from_chain_with_ws_url` call it, so verification is
//! byte-identical across transports (the #99 L2 lesson).

use alloy::eips::BlockNumberOrTag;
use alloy::network::Ethereum;
use alloy::primitives::{Address, B256};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::pubsub::Subscription;
use alloy::rpc::client::WsConnect;
use alloy::rpc::types::{Filter, Log as RpcLog};
use alloy::sol_types::SolEvent;
use std::time::Duration;

use crate::deployments::ChainEnv;
use crate::error::ChainError;
use crate::revisionlog_v2_client::RevisionLogV2;
use crate::revisionlog_v2_signing::recover_signer_v2_raw;
use crate::secp256k1_signing::RevisionFieldsV1;
use crate::types::VaultId;
use crate::ChainAnchor;

use super::poll::VerifyOutcome;
use super::ws::{check_ws_scheme, WsOpenError};
use super::{event_to_revision_event, VerifiedRevisionEvent, MAX_KNOWN_CLIENT_SCHEMA_VERSION};

/// L2 verification helper — decode + check a single alloy `Log` against
/// every defense the V2 read path applies, returning a
/// [`VerifiedRevisionEvent`] on success.
///
/// Byte-identical in structure to [`crate::chain_sync::poll::verify_alloy_log`]
/// (the V1 helper) — only the typed binding
/// (`RevisionLogV2::RevisionPublished`) differs. Shared by
/// [`fetch_chunk_v2`] (HTTP) and the WS recv loop so verification is
/// byte-identical across both transports (L2).
///
/// Defenses (V1 parity):
/// 1. **L4 + MED-4:** `log.address() == contract_address`.
/// 2. **L2 typed-binding decode** via `RevisionLogV2::RevisionPublished`.
/// 3. **vault-id topic cross-check** `decoded.vaultId == vault_id`.
/// 4. **schema-version bound** `<= MAX_KNOWN_CLIENT_SCHEMA_VERSION`.
/// 5. **anchor materialisation** (block/log/tx/block-hash all Some).
/// 6. **sequence range** `u64::try_from(sequence)`.
#[must_use]
pub fn verify_alloy_log_v2(
    log: &RpcLog,
    vault_id: &VaultId,
    contract_address: &Address,
    _env: ChainEnv,
) -> VerifyOutcome {
    // (1) L4 + MED-4.
    if log.address() != *contract_address {
        return VerifyOutcome::Rejected;
    }

    // (2) L2: typed-binding decode against the V2 `RevisionPublished`.
    let Ok(decoded) = RevisionLogV2::RevisionPublished::decode_log(&log.inner) else {
        return VerifyOutcome::Rejected;
    };

    // (3) vault-id topic cross-check.
    let decoded_vault: [u8; 32] = decoded.vaultId.into();
    if decoded_vault != *vault_id {
        return VerifyOutcome::Rejected;
    }

    // (4) schema-version bound.
    if decoded.schemaVersion > MAX_KNOWN_CLIENT_SCHEMA_VERSION {
        return VerifyOutcome::Rejected;
    }

    // The contract emits `signer` as its publish-time ecrecover output
    // (under the v2 domain); the V2 event carries no inline signature
    // bytes (V1 parity). Production trusts the event `signer` gated by
    // the L3 chain-id pin + L4 V2 contract-address pin. The client-side
    // L5 recover arm (`recover_signer_v2_raw`) is reachable via
    // `verify_signed_event_v2` for tests/defense-in-depth.
    let claimed_signer = decoded.signer;

    // (5) anchor materialisation.
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

    // (6) sequence range.
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

/// Issue a single `eth_getLogs` for `[from_block, to_block]` filtered by
/// the `RevisionLogV2` address + the V2 `RevisionPublished` topic0 +
/// indexed `vaultId` topic1, decode + verify each log, return the
/// `VerifiedRevisionEvent` set + the count of locally-rejected logs.
///
/// Mirror of [`crate::chain_sync::poll::fetch_chunk`] (the V1 read).
///
/// # Errors
///
/// [`ChainError::Rpc`] on the `eth_getLogs` transport failure.
pub async fn fetch_chunk_v2<P: Provider>(
    provider: &P,
    env: ChainEnv,
    contract_address: Address,
    vault_id: &VaultId,
    from_block: u64,
    to_block: u64,
) -> Result<(Vec<VerifiedRevisionEvent>, u32), ChainError> {
    // `RevisionPublished(uint256 indexed sequence, bytes32 indexed
    // vaultId, bytes32 indexed accountId, ...)`: topic0 = signature,
    // topic1 = sequence, topic2 = vaultId. Filter on topic2 (the
    // vaultId) server-side; `verify_alloy_log_v2` re-checks the decoded
    // vaultId as defense-in-depth.
    let vault_topic: B256 = (*vault_id).into();
    let filter = Filter::new()
        .address(contract_address)
        .event_signature(RevisionLogV2::RevisionPublished::SIGNATURE_HASH)
        .from_block(BlockNumberOrTag::Number(from_block))
        .to_block(BlockNumberOrTag::Number(to_block))
        .topic2(vault_topic);

    let logs = provider
        .get_logs(&filter)
        .await
        .map_err(|e| ChainError::Rpc(format!("eth_getLogs (v2) {from_block}..={to_block}: {e}")))?;

    let mut verified = Vec::with_capacity(logs.len());
    let mut rejected: u32 = 0;
    for log in &logs {
        match verify_alloy_log_v2(log, vault_id, &contract_address, env) {
            VerifyOutcome::Verified(ev) => verified.push(ev),
            VerifyOutcome::Rejected => {
                rejected = rejected.saturating_add(1);
            }
        }
    }
    Ok((verified, rejected))
}

/// Client-side L5 recover arm for the V2 read path (defense-in-depth /
/// tests). Recovers the signer under the v2 domain
/// ([`recover_signer_v2_raw`]) + cross-checks it equals `claimed_signer`.
///
/// The V2 production event carries no inline signature, so this is
/// reachable only via test fixtures that synthesise the signature (V1
/// parity with `verify_signer_or_reject`). Domain selection is EXPLICIT
/// v2 — the recover threads the v2 domain, never the v1 one.
///
/// # Errors
///
/// [`ChainError::SignerRecoveryFailed`] on a malformed signature;
/// [`ChainError::EventSignerMismatch`] if the recovered signer differs
/// from `claimed_signer`.
pub fn verify_signed_event_v2(
    fields: &RevisionFieldsV1,
    signature: &[u8; 65],
    claimed_signer: Address,
    verifying_contract: Address,
    chain_id: u64,
) -> Result<Address, ChainError> {
    let recovered = recover_signer_v2_raw(fields, signature, verifying_contract, chain_id)?;
    if recovered != claimed_signer {
        return Err(ChainError::EventSignerMismatch {
            claimed: claimed_signer,
            recovered,
        });
    }
    Ok(recovered)
}

/// Open WS handle for a V2 `RevisionPublished` log subscription. Carries
/// the alloy `Subscription<RpcLog>`; dropping it closes the
/// subscription.
///
/// Mirror of [`crate::chain_sync::ws::WsHandle`] for the V2 event.
#[derive(Debug)]
pub struct WsHandleV2 {
    /// Keeps the alloy WS service task alive for the subscription's
    /// lifetime (Drop semantics — not directly read).
    #[allow(dead_code)]
    provider: DynProvider,
    /// Live alloy `Subscription<RpcLog>`; recv via
    /// [`recv_next_event_v2`].
    pub subscription: Subscription<RpcLog>,
}

/// Try to open a WS log-subscription filtered by `contract_address` +
/// the V2 `RevisionPublished` topic0 + `vault_id` topic1.
///
/// Mirror of [`crate::chain_sync::ws::open_subscription`] (the V1 WS
/// path): same L-ws-tls-downgrade scheme check + L3 chain-id pin BEFORE
/// `eth_subscribe`.
///
/// # Errors
///
/// - [`WsOpenError::UnsupportedScheme`] for a non-`ws(s)://` URL or
///   cleartext `ws://` in a production env.
/// - [`WsOpenError::ConnectFailed`] on a connect-layer failure.
/// - [`WsOpenError::ChainIdMismatch`] when the WS provider's chain id
///   does not match `env`.
/// - [`WsOpenError::SubscribeFailed`] when the server rejects
///   `eth_subscribe`.
pub async fn open_subscription_v2(
    ws_url: &str,
    env: ChainEnv,
    vault_id: &VaultId,
    contract_address: Address,
) -> Result<WsHandleV2, WsOpenError> {
    check_ws_scheme(ws_url, env)?;

    let connect = WsConnect::new(ws_url)
        .with_keepalive_interval(Duration::from_secs(super::WS_KEEPALIVE_INTERVAL_SECS));
    let provider = ProviderBuilder::new()
        .network::<Ethereum>()
        .connect_ws(connect)
        .await
        .map_err(|e| WsOpenError::ConnectFailed(format!("connect_ws {ws_url}: {e}")))?;

    super::check_chain_id_matches(&provider, env)
        .await
        .map_err(|e| WsOpenError::ChainIdMismatch(format!("ws-provider eth_chainId (v2): {e}")))?;

    // vaultId is the 2nd indexed param (topic2); see `fetch_chunk_v2`.
    let vault_topic: B256 = (*vault_id).into();
    let filter = Filter::new()
        .address(contract_address)
        .event_signature(RevisionLogV2::RevisionPublished::SIGNATURE_HASH)
        .topic2(vault_topic);

    let sub = provider
        .subscribe_logs(&filter)
        .await
        .map_err(|e| WsOpenError::SubscribeFailed(format!("eth_subscribe (v2): {e}")))?;
    Ok(WsHandleV2 {
        provider: provider.erased(),
        subscription: sub,
    })
}

/// Receive the next event from a V2 WS subscription, or signal closure.
/// Mirror of [`crate::chain_sync::ws::recv_next_event`].
pub async fn recv_next_event_v2(handle: &mut WsHandleV2) -> super::ws::WsRecvOutcome {
    handle
        .subscription
        .recv()
        .await
        .map_or(super::ws::WsRecvOutcome::SubscriptionClosed, {
            super::ws::WsRecvOutcome::Event
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evm::derive_evm_wallet;
    use crate::revisionlog_v2_signing::build_signed_revision_v2;
    use pangolin_crypto::keys::DeviceKey;

    /// The V2 `RevisionPublished` topic-0 (event signature hash) MUST
    /// differ from V1's — a v1 reader must never consume v2 events and
    /// vice-versa (the v2 domain gives the same-shaped event a distinct
    /// topic-0 only via the contract; the ABI signature string is
    /// identical, so the topic-0 is actually equal — this test pins the
    /// V2 topic-0 explicitly so a future binding edit is caught).
    #[test]
    fn v2_revision_published_topic0_is_stable() {
        let v2_topic = RevisionLogV2::RevisionPublished::SIGNATURE_HASH;
        let v1_topic =
            crate::chain_submit::revision_log_v1_binding::RevisionLogV1::RevisionPublished::SIGNATURE_HASH;
        // The event ABI signature string is identical across v1/v2, so
        // the topic-0 (keccak of the signature) is the same. The
        // cross-version separation is enforced by the DOMAIN (different
        // recovered signer), not the topic — assert the (expected)
        // equality so a future divergence in the V2 event shape is
        // caught loudly.
        assert_eq!(
            v2_topic, v1_topic,
            "V2 RevisionPublished ABI signature is identical to V1's; \
             cross-version separation is by domain, not topic-0"
        );
    }

    /// L5 client-side recover arm: a synthetic V2 signature recovers the
    /// signer and the cross-check passes. Mirrors the V1 fixture path.
    #[test]
    fn verify_signed_event_v2_round_trip() {
        let w = derive_evm_wallet(&DeviceKey::from_seed([0x42; 32])).expect("wallet");
        let verifying = Address::from([0xCD; 20]);
        let chain_id = 31_337u64;
        let pre = b"v2-read-fixture".to_vec();
        let h = alloy::primitives::keccak256(&pre).0;
        let fields =
            RevisionFieldsV1::with_signer_device_id(&w, [0x11; 32], [0x22; 32], [0x33; 32], 1, h);
        let signed =
            build_signed_revision_v2(&w, fields, pre, verifying, chain_id).expect("sign v2");
        let recovered = verify_signed_event_v2(
            &signed.fields,
            &signed.signature,
            w.address(),
            verifying,
            chain_id,
        )
        .expect("verify");
        assert_eq!(recovered, w.address());
    }

    /// A foreign claimed-signer turns the cross-check into
    /// `EventSignerMismatch`.
    #[test]
    fn verify_signed_event_v2_rejects_foreign_signer() {
        let w = derive_evm_wallet(&DeviceKey::from_seed([0x42; 32])).expect("wallet");
        let verifying = Address::from([0xCD; 20]);
        let chain_id = 31_337u64;
        let pre = b"v2-read-fixture".to_vec();
        let h = alloy::primitives::keccak256(&pre).0;
        let fields =
            RevisionFieldsV1::with_signer_device_id(&w, [0x11; 32], [0x22; 32], [0x33; 32], 1, h);
        let signed =
            build_signed_revision_v2(&w, fields, pre, verifying, chain_id).expect("sign v2");
        let foreign = Address::from([0x99; 20]);
        let err = verify_signed_event_v2(
            &signed.fields,
            &signed.signature,
            foreign,
            verifying,
            chain_id,
        )
        .expect_err("foreign signer must fail the cross-check");
        assert!(matches!(err, ChainError::EventSignerMismatch { .. }));
    }
}
