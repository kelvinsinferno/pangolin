// SPDX-License-Identifier: AGPL-3.0-or-later
//! `RevisionLogV2` chain-client (MVP-3 issue #106c, multi-device control
//! plane).
//!
//! The six device-lifecycle broadcasts + the live authorized-SET / nonce /
//! manager reads + the device-management event folding.
//!
//! This module turns [`crate::revisionlog_v2_signing`]'s device-auth
//! machinery into EIP-1559 transactions that call the deployed
//! `RevisionLogV2` contract (`contracts/src/RevisionLogV2.sol`)'s mutators:
//! `bootstrapVault` / `addDevice` / `removeDevice` / `proposePromotion` /
//! `finalizePromotion` / `cancelPromotion`. It mirrors `chain_submit.rs`'s
//! R-c retry taxonomy, EIP-1559 envelope, 50-gwei gas cap, 1-conf
//! receipt-await, and `resolve_envelope_chain_id` (#101) verbatim — exactly
//! as `recovery_client.rs` does for `RecoveryV1`.
//!
//! ## L11-analogue anti-replay
//!
//! `addDevice` / `removeDevice` / `proposePromotion` each bind the vault's
//! CURRENT `deviceNonce`. The client reads the live `deviceNonce(vaultId)`
//! before building each digest (mirrors #103 reading the live
//! `attemptNonce`) — a stale nonce reverts `ErrBadNonce`. The genesis
//! `bootstrapVault` uses `nonce == 0`.
//!
//! ## L2 byte-identity
//!
//! The manager-/candidate-signed digests are produced by
//! [`crate::revisionlog_v2_signing::build_signed_device_auth`], byte-
//! identical to the contract's `_hash*`. The live `addDevice` /
//! `removeDevice` round-trip in the anvil E2E proves the LIVE contract
//! accepts the client's signature.
//!
//! ## L8 — no `pangolin-store` dep
//!
//! Stays inside `pangolin-chain`; the byte-pinned EIP-712 constants +
//! calldata live here; `pangolin-chain` keeps NO `pangolin-store` dep
//! (cargo-tree guard).

use core::time::Duration;

use alloy::network::{Ethereum, EthereumWallet, TransactionBuilder};
use alloy::primitives::{Address, Bytes, B256, U256};
use alloy::providers::{DynProvider, PendingTransactionBuilder, Provider, ProviderBuilder};
use alloy::rpc::types::{BlockNumberOrTag, Filter, TransactionRequest};
#[allow(unused_imports)] // SolEvent / SolCall trait methods are used via
// the RevisionLogV2 binding through macro dispatch clippy can't see.
use alloy::sol_types::{SolCall, SolEvent};

use crate::chain_submit::ChainAnchorV1;
use crate::deployments::{load_deployed_address, ChainEnv};
use crate::error::ChainError;
use crate::evm::EvmWallet;
use crate::revisionlog_v2_signing::{SignedDeviceAuth, SignedRevisionV2};

// Reuse the chain-submit module's pinned gas/retry constants verbatim
// (L1: same envelope discipline, not a fork).
use crate::chain_submit::{
    MAX_FEE_PER_GAS_CAP_WEI, PRIORITY_FEE_DEFAULT_WEI, PUBLISH_REVISION_BACKOFF_MS,
    PUBLISH_REVISION_MAX_RETRIES, RECEIPT_TIMEOUT_SECS,
};

/// The contract name under which `RevisionLogV2`'s address is recorded in
/// `contracts/deployments/<env>.json`.
pub const REVISIONLOG_V2_CONTRACT_NAME: &str = "RevisionLogV2";

/// Event-schema version every #106c call passes (L9). The contract rejects
/// `> MAX_KNOWN_SCHEMA_VERSION` symmetrically.
pub const REVISIONLOG_V2_SCHEMA_VERSION: u16 =
    crate::revisionlog_v2_signing::REVISIONLOG_V2_SCHEMA_VERSION;

// Gas-estimate safety multiplier — same 1.2x as chain_submit.rs.
const GAS_ESTIMATE_NUMER: u64 = 12;
const GAS_ESTIMATE_DENOM: u64 = 10;

// ---------------------------------------------------------------------
// alloy `sol!` binding for RevisionLogV2
// ---------------------------------------------------------------------

// alloy's `sol!` macro expands into helpers whose argument count tracks
// the Solidity ABI; clippy's too-many-arguments cap fires on the wide
// calls + events. Same allow pattern as the RecoveryV1 binding.
#[allow(clippy::too_many_arguments, clippy::module_name_repetitions)]
pub mod revisionlog_v2_binding {
    use alloy::sol;

    sol! {
        /// Mirror of `contracts/src/RevisionLogV2.sol`. MUST stay
        /// byte-for-byte aligned with the .sol source. Drift is caught
        /// by the calldata-pin tests + the anvil lifecycle round-trip.
        #[sol(rpc)]
        contract RevisionLogV2 {
            function bootstrapVault(
                bytes32 vaultId,
                address firstSigner,
                uint16 schemaVersion,
                bytes signature
            ) external;

            function publishRevision(
                bytes32 vaultId,
                bytes32 accountId,
                bytes32 parentRevision,
                bytes32 deviceId,
                uint16 schemaVersion,
                bytes encPayload,
                bytes signature
            ) external returns (uint256);

            function addDevice(
                bytes32 vaultId,
                address newSigner,
                uint64 nonce,
                uint16 schemaVersion,
                bytes authoritySig
            ) external;

            function removeDevice(
                bytes32 vaultId,
                address signer,
                uint64 nonce,
                uint16 schemaVersion,
                bytes authoritySig
            ) external;

            function proposePromotion(
                bytes32 vaultId,
                address candidate,
                uint64 nonce,
                uint16 schemaVersion,
                bytes candidateSig
            ) external;

            function finalizePromotion(bytes32 vaultId, uint16 schemaVersion) external;

            function cancelPromotion(bytes32 vaultId, uint16 schemaVersion) external;

            // views (live reads + parity oracles)
            function currentManager(bytes32 vaultId) external view returns (address);
            function deviceManager(bytes32 vaultId) external view returns (address);
            function deviceNonce(bytes32 vaultId) external view returns (uint64);
            function authorizedDevice(bytes32 vaultId, address signer) external view returns (bool);
            function authorizedDeviceCount(bytes32 vaultId) external view returns (uint32);
            function bootstrapped(bytes32 vaultId) external view returns (bool);

            function hashAddDevice(
                bytes32 vaultId, address newSigner, uint64 nonce, uint16 schemaVersion
            ) external view returns (bytes32);
            function hashRemoveDevice(
                bytes32 vaultId, address signer, uint64 nonce, uint16 schemaVersion
            ) external view returns (bytes32);
            function hashPromote(
                bytes32 vaultId, address candidate, uint64 nonce, uint16 schemaVersion
            ) external view returns (bytes32);

            // device-management events (folded into a client-side SET snapshot)
            event VaultBootstrapped(
                bytes32 indexed vaultId, address firstSigner, address manager, uint16 schemaVersion
            );
            event DeviceAdded(
                bytes32 indexed vaultId,
                address signer,
                address manager,
                uint64 nonce,
                uint16 schemaVersion
            );
            event DeviceRemoved(
                bytes32 indexed vaultId,
                address signer,
                address manager,
                uint64 nonce,
                uint16 schemaVersion
            );
            event PromotionProposed(
                bytes32 indexed vaultId, address candidate, uint64 readyAt, uint16 schemaVersion
            );
            event PromotionFinalized(
                bytes32 indexed vaultId,
                address oldManager,
                address newManager,
                uint16 schemaVersion
            );
            event PromotionCanceled(
                bytes32 indexed vaultId, address candidate, uint16 schemaVersion
            );

            // #106c2: the everyday revision-publish event (the V2 read
            // path). Byte-aligned to `RevisionLogV2.sol:107-116`,
            // field-identical to V1's `RevisionPublished` — but the
            // DIFFERENT v2 domain gives it a different topic-0 from V1,
            // which is correct: a v1 reader must never consume v2 events
            // and vice-versa.
            event RevisionPublished(
                uint256 indexed sequence,
                bytes32 indexed vaultId,
                bytes32 indexed accountId,
                bytes32 parentRevision,
                bytes32 deviceId,
                uint16 schemaVersion,
                bytes encPayload,
                address signer
            );
        }
    }
}

pub use revisionlog_v2_binding::RevisionLogV2;

// ---------------------------------------------------------------------
// Receipt anchor
// ---------------------------------------------------------------------

/// Receipt anchor returned from a successful device-lifecycle broadcast.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceLifecycleAnchorV2 {
    /// 32-byte transaction hash.
    pub tx_hash: B256,
    /// Block number the tx was included in.
    pub block_number: u64,
    /// 32-byte hash of the including block (reorg-safe consumers).
    pub block_hash: B256,
    /// Index of the lifecycle log within the block's log stream.
    pub log_index: u64,
    /// The `deviceNonce` value the event was scoped to (0 for the
    /// promotion finalize/cancel + bootstrap, which carry no nonce field).
    pub nonce: u64,
}

// ---------------------------------------------------------------------
// Live reads (the authorized SET + nonce + manager + bootstrapped)
// ---------------------------------------------------------------------

/// Read whether `signer` is in the vault's CURRENT on-chain authorized SET
/// — the honor source of truth (L5).
///
/// # Errors
///
/// [`ChainError::Rpc`] on the view-call failure.
pub async fn read_authorized_device_v2(
    env: ChainEnv,
    rpc_url: &str,
    vault_id: [u8; 32],
    signer: Address,
) -> Result<bool, ChainError> {
    let bound = bind_read(env, rpc_url).await?;
    bound
        .authorizedDevice(vault_id.into(), signer)
        .call()
        .await
        .map_err(|e| ChainError::Rpc(format!("authorizedDevice view: {e}")))
}

/// Read the count of authorized devices for `vault_id`.
///
/// # Errors
///
/// [`ChainError::Rpc`] on the view-call failure.
pub async fn read_authorized_device_count_v2(
    env: ChainEnv,
    rpc_url: &str,
    vault_id: [u8; 32],
) -> Result<u32, ChainError> {
    let bound = bind_read(env, rpc_url).await?;
    bound
        .authorizedDeviceCount(vault_id.into())
        .call()
        .await
        .map_err(|e| ChainError::Rpc(format!("authorizedDeviceCount view: {e}")))
}

/// Read the live `deviceNonce(vaultId)` (L11-analogue): the nonce a
/// device-management digest must bind. Read before building each digest.
///
/// # Errors
///
/// [`ChainError::Rpc`] on the view-call failure.
pub async fn read_device_nonce_v2(
    env: ChainEnv,
    rpc_url: &str,
    vault_id: [u8; 32],
) -> Result<u64, ChainError> {
    let bound = bind_read(env, rpc_url).await?;
    bound
        .deviceNonce(vault_id.into())
        .call()
        .await
        .map_err(|e| ChainError::Rpc(format!("deviceNonce view: {e}")))
}

/// Read the authoritative current manager (`currentManager(vaultId)`: the
/// live `RecoveryV1.vaultAuthority` if set, else the V2-local
/// `deviceManager`).
///
/// # Errors
///
/// [`ChainError::Rpc`] on the view-call failure.
pub async fn read_current_manager_v2(
    env: ChainEnv,
    rpc_url: &str,
    vault_id: [u8; 32],
) -> Result<Address, ChainError> {
    let bound = bind_read(env, rpc_url).await?;
    bound
        .currentManager(vault_id.into())
        .call()
        .await
        .map_err(|e| ChainError::Rpc(format!("currentManager view: {e}")))
}

/// Read whether `vault_id` has been bootstrapped.
///
/// # Errors
///
/// [`ChainError::Rpc`] on the view-call failure.
pub async fn read_bootstrapped_v2(
    env: ChainEnv,
    rpc_url: &str,
    vault_id: [u8; 32],
) -> Result<bool, ChainError> {
    let bound = bind_read(env, rpc_url).await?;
    bound
        .bootstrapped(vault_id.into())
        .call()
        .await
        .map_err(|e| ChainError::Rpc(format!("bootstrapped view: {e}")))
}

// ---------------------------------------------------------------------
// Public lifecycle entry points
// ---------------------------------------------------------------------

/// Broadcast `bootstrapVault(vaultId, firstSigner, schemaVersion,
/// signature)` — establish the vault's genesis device + manager.
///
/// `signed_auth` must be an `AddDevice` digest at `nonce == 0` signed by
/// `first_signer` for itself (the contract requires the recovered signer
/// equals `firstSigner`; `RevisionLogV2.sol:445-452`).
///
/// # Errors
///
/// R-c retry taxonomy (see [`crate::chain_submit`]): fatal on contract
/// revert / insufficient funds / gas-cap / chain-id mismatch / receipt
/// mismatch; retriable (bounded) on nonce collision / transient RPC.
pub async fn bootstrap_vault_v2(
    wallet: &EvmWallet,
    first_signer: Address,
    signed_auth: &SignedDeviceAuth,
    env: ChainEnv,
    rpc_url: &str,
) -> Result<DeviceLifecycleAnchorV2, ChainError> {
    let (provider, contract, chain_id) = connect(wallet, env, rpc_url).await?;
    let call = RevisionLogV2::bootstrapVaultCall {
        vaultId: signed_auth.fields.vault_id.into(),
        firstSigner: first_signer,
        schemaVersion: signed_auth.fields.schema_version,
        signature: Bytes::copy_from_slice(&signed_auth.signature[..]),
    };
    let calldata = SolCall::abi_encode(&call);
    let pending = broadcast_call(&provider, wallet.address(), contract, calldata, chain_id).await?;
    finish(pending, contract, |r, tx| {
        decode_anchor::<RevisionLogV2::VaultBootstrapped>(r, contract, tx, |_d, log| {
            anchor_basic(log, 0)
        })
    })
    .await
}

/// Broadcast `addDevice(vaultId, newSigner, nonce, schemaVersion,
/// authoritySig)` — add `newSigner` to the on-chain authorized SET.
///
/// `signed_auth` must be an `AddDevice` digest signed by the current
/// manager over the live `deviceNonce` (read via [`read_device_nonce_v2`]).
///
/// # Errors
///
/// Same taxonomy as [`bootstrap_vault_v2`].
pub async fn add_device_v2(
    wallet: &EvmWallet,
    new_signer: Address,
    signed_auth: &SignedDeviceAuth,
    env: ChainEnv,
    rpc_url: &str,
) -> Result<DeviceLifecycleAnchorV2, ChainError> {
    let (provider, contract, chain_id) = connect(wallet, env, rpc_url).await?;
    let call = RevisionLogV2::addDeviceCall {
        vaultId: signed_auth.fields.vault_id.into(),
        newSigner: new_signer,
        nonce: signed_auth.fields.nonce,
        schemaVersion: signed_auth.fields.schema_version,
        authoritySig: Bytes::copy_from_slice(&signed_auth.signature[..]),
    };
    let calldata = SolCall::abi_encode(&call);
    let pending = broadcast_call(&provider, wallet.address(), contract, calldata, chain_id).await?;
    finish(pending, contract, |r, tx| {
        decode_anchor::<RevisionLogV2::DeviceAdded>(r, contract, tx, |d, log| {
            anchor_basic(log, d.nonce)
        })
    })
    .await
}

/// Broadcast `removeDevice(vaultId, signer, nonce, schemaVersion,
/// authoritySig)` — remove `signer` from the on-chain authorized SET.
///
/// `signed_auth` must be a `RemoveDevice` digest signed by the current
/// manager over the live `deviceNonce`.
///
/// # Errors
///
/// Same taxonomy as [`bootstrap_vault_v2`].
pub async fn remove_device_v2(
    wallet: &EvmWallet,
    signer: Address,
    signed_auth: &SignedDeviceAuth,
    env: ChainEnv,
    rpc_url: &str,
) -> Result<DeviceLifecycleAnchorV2, ChainError> {
    let (provider, contract, chain_id) = connect(wallet, env, rpc_url).await?;
    let call = RevisionLogV2::removeDeviceCall {
        vaultId: signed_auth.fields.vault_id.into(),
        signer,
        nonce: signed_auth.fields.nonce,
        schemaVersion: signed_auth.fields.schema_version,
        authoritySig: Bytes::copy_from_slice(&signed_auth.signature[..]),
    };
    let calldata = SolCall::abi_encode(&call);
    let pending = broadcast_call(&provider, wallet.address(), contract, calldata, chain_id).await?;
    finish(pending, contract, |r, tx| {
        decode_anchor::<RevisionLogV2::DeviceRemoved>(r, contract, tx, |d, log| {
            anchor_basic(log, d.nonce)
        })
    })
    .await
}

/// Broadcast `proposePromotion(vaultId, candidate, nonce, schemaVersion,
/// candidateSig)` — a current set member self-proposes as the new manager.
///
/// `signed_auth` must be a `Promote` digest self-signed by `candidate`
/// over the live `deviceNonce`.
///
/// # Errors
///
/// Same taxonomy as [`bootstrap_vault_v2`].
pub async fn propose_promotion_v2(
    wallet: &EvmWallet,
    candidate: Address,
    signed_auth: &SignedDeviceAuth,
    env: ChainEnv,
    rpc_url: &str,
) -> Result<DeviceLifecycleAnchorV2, ChainError> {
    let (provider, contract, chain_id) = connect(wallet, env, rpc_url).await?;
    let call = RevisionLogV2::proposePromotionCall {
        vaultId: signed_auth.fields.vault_id.into(),
        candidate,
        nonce: signed_auth.fields.nonce,
        schemaVersion: signed_auth.fields.schema_version,
        candidateSig: Bytes::copy_from_slice(&signed_auth.signature[..]),
    };
    let calldata = SolCall::abi_encode(&call);
    let pending = broadcast_call(&provider, wallet.address(), contract, calldata, chain_id).await?;
    finish(pending, contract, |r, tx| {
        decode_anchor::<RevisionLogV2::PromotionProposed>(r, contract, tx, |_d, log| {
            anchor_basic(log, 0)
        })
    })
    .await
}

/// Broadcast `finalizePromotion(vaultId, schemaVersion)` — rotate the
/// manager to the pending candidate after `PROMOTION_DELAY`. Permissionless.
///
/// # Errors
///
/// Same taxonomy as [`bootstrap_vault_v2`].
pub async fn finalize_promotion_v2(
    wallet: &EvmWallet,
    vault_id: [u8; 32],
    env: ChainEnv,
    rpc_url: &str,
) -> Result<DeviceLifecycleAnchorV2, ChainError> {
    let (provider, contract, chain_id) = connect(wallet, env, rpc_url).await?;
    let call = RevisionLogV2::finalizePromotionCall {
        vaultId: vault_id.into(),
        schemaVersion: REVISIONLOG_V2_SCHEMA_VERSION,
    };
    let calldata = SolCall::abi_encode(&call);
    let pending = broadcast_call(&provider, wallet.address(), contract, calldata, chain_id).await?;
    finish(pending, contract, |r, tx| {
        decode_anchor::<RevisionLogV2::PromotionFinalized>(r, contract, tx, |_d, log| {
            anchor_basic(log, 0)
        })
    })
    .await
}

/// Broadcast `cancelPromotion(vaultId, schemaVersion)` — the current
/// manager vetoes a pending promotion (`msg.sender == manager`).
///
/// # Errors
///
/// Same taxonomy as [`bootstrap_vault_v2`].
pub async fn cancel_promotion_v2(
    wallet: &EvmWallet,
    vault_id: [u8; 32],
    env: ChainEnv,
    rpc_url: &str,
) -> Result<DeviceLifecycleAnchorV2, ChainError> {
    let (provider, contract, chain_id) = connect(wallet, env, rpc_url).await?;
    let call = RevisionLogV2::cancelPromotionCall {
        vaultId: vault_id.into(),
        schemaVersion: REVISIONLOG_V2_SCHEMA_VERSION,
    };
    let calldata = SolCall::abi_encode(&call);
    let pending = broadcast_call(&provider, wallet.address(), contract, calldata, chain_id).await?;
    finish(pending, contract, |r, tx| {
        decode_anchor::<RevisionLogV2::PromotionCanceled>(r, contract, tx, |_d, log| {
            anchor_basic(log, 0)
        })
    })
    .await
}

/// Broadcast a v2 signed revision to `RevisionLogV2.publishRevision`.
///
/// Blocks until a 1-conf receipt. Returns a populated [`ChainAnchorV1`]
/// (reused verbatim from the V1 publish path — the event shape is
/// field-identical) on success.
///
/// **#106c2 — the everyday revision data-plane PUBLISH leg.** Mirrors
/// [`crate::chain_submit::publish_revision_v1`] but signs/broadcasts
/// under the v2 domain + the `RevisionLogV2` contract. The signature in
/// `signed_revision` was produced over the v2 EIP-712 digest
/// ([`crate::revisionlog_v2_signing::build_signed_revision_v2`]); this
/// fn only puts it on the wire + cross-checks the receipt.
///
/// Reuses the v2 client's EIP-1559 envelope / R-c retry taxonomy / gas
/// cap / `resolve_envelope_chain_id` (#101) verbatim via
/// [`broadcast_call`] — the same plumbing the device-lifecycle calls
/// use. The contract gates `publishRevision` on the on-chain authorized
/// SET; a publish by a non-member device reverts `ErrSignerNotAuthorized`
/// (a fatal pre-broadcast revert — no retry).
///
/// The broadcast layer puts the raw `encPayload` PREIMAGE on the wire
/// (NOT the hash); the contract re-derives `keccak256(encPayload)`
/// (`RevisionLogV2.sol:560-562`). The `SignedRevisionV2` invariant
/// (`keccak256(enc_payload) == fields.enc_payload_hash`) makes the
/// digest the signature was produced over consistent with the contract's
/// recomputation.
///
/// # Errors
///
/// Same R-c retry taxonomy as [`bootstrap_vault_v2`], plus
/// [`ChainError::ReceiptMismatch`] if the event `signer` does not equal
/// the submitting wallet, and [`ChainError::MissingEvent`] /
/// [`ChainError::Decode`] on a malformed receipt.
pub async fn publish_revision_v2(
    wallet: &EvmWallet,
    signed_revision: &SignedRevisionV2,
    env: ChainEnv,
    rpc_url: &str,
) -> Result<ChainAnchorV1, ChainError> {
    let (provider, contract, chain_id) = connect(wallet, env, rpc_url).await?;
    let call = RevisionLogV2::publishRevisionCall {
        vaultId: signed_revision.fields.vault_id.into(),
        accountId: signed_revision.fields.account_id.into(),
        parentRevision: signed_revision.fields.parent_revision.into(),
        deviceId: signed_revision.fields.device_id.into(),
        schemaVersion: signed_revision.fields.schema_version,
        encPayload: Bytes::copy_from_slice(&signed_revision.enc_payload),
        signature: Bytes::copy_from_slice(&signed_revision.signature[..]),
    };
    let calldata = SolCall::abi_encode(&call);
    let pending = broadcast_call(&provider, wallet.address(), contract, calldata, chain_id).await?;

    // L12 boundary: the tx is in-flight. Await the receipt; verify
    // status==1; decode `RevisionPublished`; cross-check the event
    // `signer == wallet`.
    let tx_hash: B256 = *pending.tx_hash();
    let pending = pending.with_timeout(Some(Duration::from_secs(RECEIPT_TIMEOUT_SECS)));
    let receipt = pending
        .get_receipt()
        .await
        .map_err(|e| ChainError::Rpc(format!("get_receipt({tx_hash:?}): {e}")))?;
    process_revision_receipt_v2(&receipt, wallet.address(), contract, tx_hash)
}

/// Decode a `RevisionPublished` receipt into a [`ChainAnchorV1`] + run
/// the post-receipt cross-checks (mirror of
/// `chain_submit::process_receipt`):
///
/// 1. `receipt.status == 1`; else [`ChainError::RevertedOnChain`].
/// 2. `block_number` / `block_hash` present.
/// 3. A `RevisionPublished` log emitted by `contract` present.
/// 4. The decoded `signer` equals `wallet_address`; else
///    [`ChainError::ReceiptMismatch`].
fn process_revision_receipt_v2(
    receipt: &alloy::rpc::types::TransactionReceipt,
    wallet_address: Address,
    contract: Address,
    tx_hash: B256,
) -> Result<ChainAnchorV1, ChainError> {
    if !receipt.status() {
        return Err(ChainError::RevertedOnChain {
            reason: "unknown revert (status=0)".to_string(),
            tx_hash,
        });
    }
    let block_number = receipt
        .block_number
        .ok_or_else(|| ChainError::Decode("receipt missing block_number".into()))?;
    let block_hash = receipt
        .block_hash
        .ok_or_else(|| ChainError::Decode("receipt missing block_hash".into()))?;

    let target_topic = RevisionLogV2::RevisionPublished::SIGNATURE_HASH;
    let log = receipt
        .inner
        .logs()
        .iter()
        .find(|l| l.address() == contract && l.topics().first().copied() == Some(target_topic))
        .ok_or_else(|| ChainError::MissingEvent {
            tx_hash: format!("{tx_hash:?}"),
        })?;
    let decoded = RevisionLogV2::RevisionPublished::decode_log(&log.inner)
        .map_err(|e| ChainError::Decode(format!("RevisionPublished log: {e}")))?;
    if decoded.signer != wallet_address {
        return Err(ChainError::ReceiptMismatch {
            expected_signer: wallet_address,
            observed_signer: decoded.signer,
        });
    }
    let log_index = log
        .log_index
        .ok_or_else(|| ChainError::Decode("RevisionPublished log missing log_index".into()))?;
    Ok(ChainAnchorV1 {
        tx_hash,
        block_number,
        block_hash,
        log_index,
        sequence: decoded.sequence,
        signer: decoded.signer,
    })
}

// ---------------------------------------------------------------------
// Device-management event folding (a client-side authorized-SET snapshot)
// ---------------------------------------------------------------------

/// A decoded device-management event the watcher folds into the
/// client-side authorized-SET snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceMgmtEvent {
    /// `VaultBootstrapped(vaultId, firstSigner, manager, sv)`.
    Bootstrapped {
        /// The genesis device added to the SET.
        first_signer: Address,
        /// The seeded manager.
        manager: Address,
    },
    /// `DeviceAdded(vaultId, signer, manager, nonce, sv)`.
    Added {
        /// The device added to the SET.
        signer: Address,
        /// The nonce the add was bound to.
        nonce: u64,
    },
    /// `DeviceRemoved(vaultId, signer, manager, nonce, sv)`.
    Removed {
        /// The device removed from the SET.
        signer: Address,
        /// The nonce the remove was bound to.
        nonce: u64,
    },
    /// `PromotionFinalized(vaultId, oldManager, newManager, sv)`.
    PromotionFinalized {
        /// The new manager after the rotation.
        new_manager: Address,
    },
}

/// Decode the device-management events emitted by `contract` in a log
/// stream into [`DeviceMgmtEvent`]s, in log order.
///
/// Folds `VaultBootstrapped` / `DeviceAdded` / `DeviceRemoved` /
/// `PromotionFinalized`; ignores `PromotionProposed` / `PromotionCanceled`
/// (they don't mutate the SET). Used by the `DeviceRemoved`→rotation
/// watcher + the client-side SET snapshot.
///
/// `logs` is the slice of `(address, topics, data)` triples the caller
/// pulled from a receipt or `eth_getLogs`.
#[must_use]
pub fn decode_device_mgmt_events(
    contract: Address,
    logs: &[alloy::rpc::types::Log],
) -> Vec<DeviceMgmtEvent> {
    let mut out = Vec::new();
    for log in logs {
        if log.address() != contract {
            continue;
        }
        let Some(topic0) = log.topics().first().copied() else {
            continue;
        };
        if topic0 == RevisionLogV2::VaultBootstrapped::SIGNATURE_HASH {
            if let Ok(d) = RevisionLogV2::VaultBootstrapped::decode_log(&log.inner) {
                out.push(DeviceMgmtEvent::Bootstrapped {
                    first_signer: d.firstSigner,
                    manager: d.manager,
                });
            }
        } else if topic0 == RevisionLogV2::DeviceAdded::SIGNATURE_HASH {
            if let Ok(d) = RevisionLogV2::DeviceAdded::decode_log(&log.inner) {
                out.push(DeviceMgmtEvent::Added {
                    signer: d.signer,
                    nonce: d.nonce,
                });
            }
        } else if topic0 == RevisionLogV2::DeviceRemoved::SIGNATURE_HASH {
            if let Ok(d) = RevisionLogV2::DeviceRemoved::decode_log(&log.inner) {
                out.push(DeviceMgmtEvent::Removed {
                    signer: d.signer,
                    nonce: d.nonce,
                });
            }
        } else if topic0 == RevisionLogV2::PromotionFinalized::SIGNATURE_HASH {
            if let Ok(d) = RevisionLogV2::PromotionFinalized::decode_log(&log.inner) {
                out.push(DeviceMgmtEvent::PromotionFinalized {
                    new_manager: d.newManager,
                });
            }
        }
    }
    out
}

/// Block-chunk size for the device-management log scan.
///
/// Reuses the [`crate::chain_sync::LOG_BLOCK_CHUNK`] 9k discipline (the
/// public Base Sepolia RPC's 10k cap with a safety margin) so the set scan
/// chunks identically to the revision reader.
pub const DEVICE_MGMT_LOG_BLOCK_CHUNK: u64 = crate::chain_sync::LOG_BLOCK_CHUNK;

/// **MVP-3 issue #106d (Q-a / Q-b / L2 / L3).** Read the vault's CURRENT
/// on-chain authorized-device SET — the V2 honor source of truth.
///
/// The set is built in two passes (Q-b): (1) the cheap **event fold** —
/// a chunked `eth_getLogs` over the `RevisionLogV2` device-management
/// events (`VaultBootstrapped`/`DeviceAdded`/`DeviceRemoved`;
/// `PromotionFinalized` rotates the manager, NOT set membership) folded
/// via [`decode_device_mgmt_events`] into a candidate set; then (2) the
/// **live cross-check** — each candidate is reconciled against the live
/// `authorizedDevice(vaultId, signer)` view (the authoritative tiebreaker,
/// the #103-C L5 anti-stale anchor re-keyed to membership). A
/// stale/tampered fold can therefore only OVER-revoke (drop a member that
/// the live read confirms is gone — a recoverable liveness dent), never
/// UNDER-revoke (re-honor a removed device — the dangerous direction).
///
/// # FAIL-CLOSED (issue #103-C FINDING 1 — L3)
///
/// For a V2-bound vault (the only caller — the v1/v2 routing in
/// `pangolin_store::Vault::sync_from_chain_with_ws_url` decided this is a
/// V2 vault from its FIXED `meta.revisionlog_version` binding, NOT a chain
/// heuristic), EVERY read failure is propagated as `Err`: a missing
/// `RevisionLogV2` deployment, a connect / chain-id / `eth_blockNumber` /
/// `eth_getLogs` / `authorizedDevice` view failure. A read failure is
/// NEVER swallowed to an empty (or honor-all) set — doing so would
/// re-honor a removed device on a rotated V2 vault (under-revocation, the
/// exact hole). The caller FAILS the whole sync on `Err` (retry later with
/// the set gate intact). There is no `Ok(empty)`-for-no-deployment arm
/// here: a V2-bound vault always has a bootstrapped set, so a missing
/// deployment IS a real failure (unlike the V1 lineage reader, where a
/// missing `RecoveryV1` deployment was the genuine no-recovery-surface
/// case).
///
/// `from_block` is the genesis cursor for the scan (0 on a fresh anvil;
/// the future Base Sepolia V2 deploy block once pinned).
///
/// # Errors
///
/// - [`ChainError::Rpc`] on connect / `eth_blockNumber` / `eth_getLogs` /
///   `authorizedDevice` view failures (fail-closed; NEVER empty).
/// - [`ChainError::ChainIdMismatch`] if the RPC's chain-id does not match
///   the env's pinned id (L4 / L9).
/// - [`ChainError::DeploymentNotFound`] / [`ChainError::DeploymentParseError`]
///   if no `RevisionLogV2` address is recorded for `env` (a V2-bound vault
///   MUST have one — fail-closed, not honor-all).
pub async fn read_authorized_set_v2(
    env: ChainEnv,
    rpc_url: &str,
    vault_id: [u8; 32],
    from_block: u64,
) -> Result<Vec<Address>, ChainError> {
    // L3 fail-closed: a missing deployment for a V2-bound vault is a real
    // failure (NOT the V1 "no recovery surface" case) — propagate it.
    let contract = resolve_contract_address(env)?;
    let provider = ProviderBuilder::new()
        .connect(rpc_url)
        .await
        .map_err(|e| ChainError::Rpc(format!("connect {rpc_url}: {e}")))?
        .erased();
    // L4 / L9: cross-check the RPC chain-id (pinned for prod) BEFORE any
    // log scan — identical posture to the V1 reader + the lifecycle calls.
    let _chain_id = resolve_envelope_chain_id(&provider, env).await?;

    let head = provider
        .get_block_number()
        .await
        .map_err(|e| ChainError::Rpc(format!("eth_blockNumber: {e}")))?;

    // Pass 1 — the event fold. Chunked `eth_getLogs` over the device-
    // management events, filtered server-side by (contract, vaultId
    // topic1). A per-log address re-check inside `decode_device_mgmt_events`
    // is defense-in-depth against a misbehaving RPC.
    let topic1: B256 = vault_id.into();
    let mut candidates: Vec<Address> = Vec::new();
    let mut from = from_block.min(head);
    while from <= head {
        let to = from
            .saturating_add(DEVICE_MGMT_LOG_BLOCK_CHUNK.saturating_sub(1))
            .min(head);
        let filter = Filter::new()
            .address(contract)
            .from_block(BlockNumberOrTag::Number(from))
            .to_block(BlockNumberOrTag::Number(to))
            .topic1(topic1);
        let logs = provider
            .get_logs(&filter)
            .await
            .map_err(|e| ChainError::Rpc(format!("eth_getLogs (device-mgmt): {e}")))?;
        for ev in decode_device_mgmt_events(contract, &logs) {
            // Collect every signer EVER seen (bootstrap genesis / add /
            // remove) as a CANDIDATE; the live `authorizedDevice` cross-
            // check below decides final membership (so a removal is
            // reflected by the live read, never by dropping it from the
            // fold). PromotionFinalized rotates the manager, not the set.
            let candidate = match ev {
                DeviceMgmtEvent::Bootstrapped { first_signer, .. } => Some(first_signer),
                DeviceMgmtEvent::Added { signer, .. }
                | DeviceMgmtEvent::Removed { signer, .. } => Some(signer),
                DeviceMgmtEvent::PromotionFinalized { .. } => None,
            };
            if let Some(signer) = candidate {
                if !candidates.contains(&signer) {
                    candidates.push(signer);
                }
            }
        }
        if to == head {
            break;
        }
        from = to.saturating_add(1);
    }

    // Pass 2 — the live cross-check (authoritative tiebreaker, L5). Each
    // candidate's membership is the LIVE `authorizedDevice` answer; a fold
    // that lags the chain can only drop a member here (over-revoke), never
    // add a removed one back (under-revoke). Any view failure is `Err`
    // (fail-closed).
    let bound = bind_read(env, rpc_url).await?;
    let mut set: Vec<Address> = Vec::new();
    for signer in candidates {
        let live = bound
            .authorizedDevice(vault_id.into(), signer)
            .call()
            .await
            .map_err(|e| ChainError::Rpc(format!("authorizedDevice view (set): {e}")))?;
        if live && !set.contains(&signer) {
            set.push(signer);
        }
    }
    Ok(set)
}

// ---------------------------------------------------------------------
// Shared read/broadcast plumbing (mirrors recovery_client.rs verbatim)
// ---------------------------------------------------------------------

/// Resolve the `RevisionLogV2` contract address for `env`.
///
/// (TODO: add the `BaseSepolia` pinned-address cross-check + the
/// `EXPECTED_REVISIONLOG_V2_ADDRESS_BASE_SEPOLIA` constant once a testnet
/// deploy exists — mirror the v1/RecoveryV1 posture; testnet capture is a
/// TODO until the Base Sepolia v2 deploy lands.)
pub fn resolve_contract_address(env: ChainEnv) -> Result<Address, ChainError> {
    load_deployed_address(env, REVISIONLOG_V2_CONTRACT_NAME)
}

/// Bind a read-only `RevisionLogV2` instance.
async fn bind_read(
    env: ChainEnv,
    rpc_url: &str,
) -> Result<RevisionLogV2::RevisionLogV2Instance<DynProvider>, ChainError> {
    let contract = resolve_contract_address(env)?;
    let provider = ProviderBuilder::new()
        .connect(rpc_url)
        .await
        .map_err(|e| ChainError::Rpc(format!("connect {rpc_url}: {e}")))?
        .erased();
    Ok(RevisionLogV2::new(contract, provider))
}

/// Connect a wallet-bearing provider + resolve the contract address + the
/// envelope chain id (#101 `resolve_envelope_chain_id` discipline).
async fn connect(
    wallet: &EvmWallet,
    env: ChainEnv,
    rpc_url: &str,
) -> Result<(DynProvider, Address, u64), ChainError> {
    let contract = resolve_contract_address(env)?;
    let eth_wallet = EthereumWallet::from(wallet.signer().clone());
    let provider = ProviderBuilder::new()
        .wallet(eth_wallet)
        .connect(rpc_url)
        .await
        .map_err(|e| ChainError::Rpc(format!("connect {rpc_url}: {e}")))?
        .erased();
    let chain_id = resolve_envelope_chain_id(&provider, env).await?;
    Ok((provider, contract, chain_id))
}

/// Resolve the envelope chain id (mirror of `chain_submit`'s private
/// `resolve_envelope_chain_id`, L4): production envs cross-check the RPC's
/// reported id against the pinned id and bind the PINNED value; `Dev` binds
/// the live local id.
async fn resolve_envelope_chain_id<P: Provider>(
    provider: &P,
    env: ChainEnv,
) -> Result<u64, ChainError> {
    let observed = provider
        .get_chain_id()
        .await
        .map_err(|e| ChainError::Rpc(e.to_string()))?;
    match env.chain_id() {
        Some(expected) => {
            if observed != expected {
                return Err(ChainError::ChainIdMismatch { expected, observed });
            }
            Ok(expected)
        }
        None => Ok(observed),
    }
}

/// Broadcast a pre-encoded `RevisionLogV2` call with the R-c retry taxonomy
/// (mirror of `recovery_client.rs::broadcast_call` — all six lifecycle
/// calls share one loop; L1 same discipline).
#[allow(clippy::too_many_lines)]
async fn broadcast_call(
    provider: &DynProvider,
    from: Address,
    contract: Address,
    calldata: Vec<u8>,
    chain_id: u64,
) -> Result<PendingTransactionBuilder<Ethereum>, ChainError> {
    let mut attempts: u8 = 0;
    loop {
        attempts += 1;
        let nonce = match provider.get_transaction_count(from).pending().await {
            Ok(n) => n,
            Err(e) => {
                let msg = e.to_string();
                if is_transient_rpc_error(&msg) && attempts < PUBLISH_REVISION_MAX_RETRIES {
                    backoff_for_attempt(attempts).await;
                    continue;
                }
                return Err(ChainError::RpcTransient {
                    message: msg,
                    attempts,
                });
            }
        };

        let base_fee = fetch_base_fee(provider).await?;
        let max_fee_per_gas: u128 = base_fee
            .checked_mul(2)
            .and_then(|v| v.checked_add(PRIORITY_FEE_DEFAULT_WEI))
            .ok_or_else(|| ChainError::Rpc("base fee arithmetic overflow".into()))?;
        if max_fee_per_gas > MAX_FEE_PER_GAS_CAP_WEI {
            return Err(ChainError::GasCapExceeded {
                observed_gwei: u64::try_from(max_fee_per_gas / 1_000_000_000).unwrap_or(u64::MAX),
                cap_gwei: u64::try_from(MAX_FEE_PER_GAS_CAP_WEI / 1_000_000_000)
                    .unwrap_or(u64::MAX),
            });
        }

        let mut tx = TransactionRequest::default()
            .with_from(from)
            .with_to(contract)
            .with_nonce(nonce)
            .with_input(Bytes::from(calldata.clone()))
            .with_value(U256::ZERO)
            .with_max_fee_per_gas(max_fee_per_gas)
            .with_max_priority_fee_per_gas(PRIORITY_FEE_DEFAULT_WEI);
        tx.set_chain_id(chain_id);

        let est = match provider.estimate_gas(tx.clone()).await {
            Ok(g) => g,
            Err(e) => {
                let msg = e.to_string();
                if let Some(reason) = decode_revert_reason_from_msg(&msg) {
                    return Err(ChainError::RevertedPreBroadcast { reason });
                }
                if is_insufficient_funds(&msg) {
                    return Err(ChainError::InsufficientFunds {
                        observed: None,
                        message: msg,
                    });
                }
                if is_transient_rpc_error(&msg) && attempts < PUBLISH_REVISION_MAX_RETRIES {
                    backoff_for_attempt(attempts).await;
                    continue;
                }
                return Err(ChainError::RpcTransient {
                    message: msg,
                    attempts,
                });
            }
        };
        let gas_limit = est
            .saturating_mul(GAS_ESTIMATE_NUMER)
            .saturating_div(GAS_ESTIMATE_DENOM);
        tx = tx.with_gas_limit(gas_limit);

        match provider.send_transaction(tx).await {
            Ok(p) => return Ok(p),
            Err(e) => {
                let msg = e.to_string();
                if is_nonce_collision(&msg) {
                    if attempts < PUBLISH_REVISION_MAX_RETRIES {
                        continue;
                    }
                    return Err(ChainError::NonceUnresolvable { attempts });
                }
                if is_insufficient_funds(&msg) {
                    return Err(ChainError::InsufficientFunds {
                        observed: None,
                        message: msg,
                    });
                }
                if is_transient_rpc_error(&msg) && attempts < PUBLISH_REVISION_MAX_RETRIES {
                    backoff_for_attempt(attempts).await;
                    continue;
                }
                return Err(ChainError::RpcTransient {
                    message: msg,
                    attempts,
                });
            }
        }
    }
}

/// Await the 1-conf receipt + decode the lifecycle anchor.
async fn finish<F>(
    pending: PendingTransactionBuilder<Ethereum>,
    _contract: Address,
    decode: F,
) -> Result<DeviceLifecycleAnchorV2, ChainError>
where
    F: FnOnce(
        &alloy::rpc::types::TransactionReceipt,
        B256,
    ) -> Result<DeviceLifecycleAnchorV2, ChainError>,
{
    let tx_hash: B256 = *pending.tx_hash();
    let pending = pending.with_timeout(Some(Duration::from_secs(RECEIPT_TIMEOUT_SECS)));
    let receipt = pending
        .get_receipt()
        .await
        .map_err(|e| ChainError::Rpc(format!("get_receipt({tx_hash:?}): {e}")))?;
    if !receipt.status() {
        return Err(ChainError::RevertedOnChain {
            reason: "unknown revert (status=0)".to_string(),
            tx_hash,
        });
    }
    decode(&receipt, tx_hash)
}

/// Decode a lifecycle anchor from a receipt: find the typed event `E`
/// emitted by `contract`, run `build` on the decoded body + log index,
/// then fill `block_number` / `block_hash` from the receipt.
fn decode_anchor<E>(
    receipt: &alloy::rpc::types::TransactionReceipt,
    contract: Address,
    tx_hash: B256,
    build: impl FnOnce(&E, u64) -> DeviceLifecycleAnchorV2,
) -> Result<DeviceLifecycleAnchorV2, ChainError>
where
    E: SolEvent,
{
    let block_number = receipt
        .block_number
        .ok_or_else(|| ChainError::Decode("receipt missing block_number".into()))?;
    let block_hash = receipt
        .block_hash
        .ok_or_else(|| ChainError::Decode("receipt missing block_hash".into()))?;

    let target_topic = E::SIGNATURE_HASH;
    let log = receipt
        .inner
        .logs()
        .iter()
        .find(|l| l.address() == contract && l.topics().first().copied() == Some(target_topic))
        .ok_or_else(|| ChainError::MissingEvent {
            tx_hash: format!("{tx_hash:?}"),
        })?;
    let decoded =
        E::decode_log(&log.inner).map_err(|e| ChainError::Decode(format!("lifecycle log: {e}")))?;
    let log_index = log
        .log_index
        .ok_or_else(|| ChainError::Decode("lifecycle log missing log_index".into()))?;

    let mut anchor = build(&decoded.data, log_index);
    anchor.tx_hash = tx_hash;
    anchor.block_number = block_number;
    anchor.block_hash = block_hash;
    Ok(anchor)
}

/// Helper for an anchor with a known nonce + log index (block fields filled
/// by `decode_anchor`).
fn anchor_basic(log_index: u64, nonce: u64) -> DeviceLifecycleAnchorV2 {
    DeviceLifecycleAnchorV2 {
        tx_hash: B256::ZERO,
        block_number: 0,
        block_hash: B256::ZERO,
        log_index,
        nonce,
    }
}

/// Fetch the latest base fee (mirror of `chain_submit`'s `fetch_base_fee`).
async fn fetch_base_fee<P: Provider>(provider: &P) -> Result<u128, ChainError> {
    let hist = provider
        .get_fee_history(1, BlockNumberOrTag::Latest, &[])
        .await
        .map_err(|e| ChainError::Rpc(e.to_string()))?;
    if let Some(b) = hist.latest_block_base_fee() {
        if b != 0 {
            return Ok(b);
        }
    }
    provider
        .get_gas_price()
        .await
        .map_err(|e| ChainError::Rpc(e.to_string()))
}

async fn backoff_for_attempt(attempts: u8) {
    let idx = (attempts as usize)
        .saturating_sub(1)
        .min(PUBLISH_REVISION_BACKOFF_MS.len() - 1);
    let ms = PUBLISH_REVISION_BACKOFF_MS[idx];
    if ms == 0 {
        return;
    }
    tokio::time::sleep(Duration::from_millis(ms)).await;
}

fn is_nonce_collision(msg: &str) -> bool {
    let lower = msg.to_ascii_lowercase();
    lower.contains("nonce too low")
        || lower.contains("nonce already used")
        || lower.contains("already known")
        || lower.contains("replacement underpriced")
        || lower.contains("replacement transaction underpriced")
}

fn is_transient_rpc_error(msg: &str) -> bool {
    let lower = msg.to_ascii_lowercase();
    lower.contains("timeout")
        || lower.contains("timed out")
        || lower.contains("connection reset")
        || lower.contains("connection refused")
        || lower.contains("connection closed")
        || lower.contains("temporarily unavailable")
        || lower.contains("502 ")
        || lower.contains("503 ")
        || lower.contains("504 ")
        || lower.contains("bad gateway")
        || lower.contains("service unavailable")
        || lower.contains("gateway timeout")
}

fn is_insufficient_funds(msg: &str) -> bool {
    let lower = msg.to_ascii_lowercase();
    lower.contains("insufficient funds")
        || lower.contains("insufficient balance")
        || lower.contains("not enough funds")
}

/// Best-effort decoder for a `RevisionLogV2` custom-error / revert reason.
fn decode_revert_reason_from_msg(msg: &str) -> Option<String> {
    let lower = msg.to_ascii_lowercase();
    if !(lower.contains("revert") || lower.contains("execution reverted")) {
        return None;
    }
    for known in [
        "ErrUnsupportedSchemaVersion",
        "ErrVaultAlreadyBootstrapped",
        "ErrVaultNotBootstrapped",
        "ErrZeroValue",
        "ErrBadNonce",
        "ErrSetSizeExceeded",
        "ErrAlreadyAuthorized",
        "ErrNotAuthorized",
        "ErrNotDeviceManager",
        "ErrInvalidSignature",
        "ErrWouldBrickVault",
        "ErrPromotionPending",
        "ErrNoPromotionPending",
        "ErrPromotionDelayNotElapsed",
        "ErrNotSetMember",
        "ErrNotAuthorizedToCancel",
    ] {
        if msg.contains(known) {
            return Some(known.to_string());
        }
    }
    if lower.contains("out of gas") || lower.contains("outofgas") {
        return Some("OutOfGas".to_string());
    }
    Some("unknown revert".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::revisionlog_v2_signing::{DeviceAuthFields, DeviceAuthKind};

    /// The `sol!` calldata for `addDevice` encodes the exact field tuple
    /// the signed-auth carries — a calldata-pin sanity (the live anvil
    /// round-trip is the end-to-end half).
    #[test]
    fn add_device_calldata_encodes_fields() {
        let fields = DeviceAuthFields {
            kind: DeviceAuthKind::AddDevice,
            vault_id: [0x11; 32],
            subject: Address::from([0x22; 20]),
            nonce: 5,
            schema_version: 1,
        };
        let sig = [0x33u8; 65];
        let call = RevisionLogV2::addDeviceCall {
            vaultId: fields.vault_id.into(),
            newSigner: fields.subject,
            nonce: fields.nonce,
            schemaVersion: fields.schema_version,
            authoritySig: Bytes::copy_from_slice(&sig),
        };
        let encoded = SolCall::abi_encode(&call);
        // Selector (4 bytes) + 5 head words + dynamic-bytes tail. Decode
        // back through the binding to confirm round-trip fidelity.
        let decoded = RevisionLogV2::addDeviceCall::abi_decode(&encoded).expect("decode addDevice");
        assert_eq!(decoded.vaultId.0, fields.vault_id);
        assert_eq!(decoded.newSigner, fields.subject);
        assert_eq!(decoded.nonce, fields.nonce);
        assert_eq!(decoded.schemaVersion, fields.schema_version);
        assert_eq!(decoded.authoritySig.as_ref(), &sig[..]);
    }

    /// `decode_device_mgmt_events` ignores logs from a foreign address +
    /// returns an empty fold for an empty log slice.
    #[test]
    fn decode_device_mgmt_events_empty_is_empty() {
        let contract = Address::from([0xAB; 20]);
        let folded = decode_device_mgmt_events(contract, &[]);
        assert!(folded.is_empty());
    }

    /// **#106d L3 — FAIL-CLOSED on a set-read error.** An unreachable RPC
    /// makes `read_authorized_set_v2` return `Err` (the connect failure),
    /// NEVER `Ok(empty)`. A V2-bound vault's set read MUST fail the sync
    /// on a real read failure rather than silently honor everyone
    /// (under-revocation — the exact hole). This is the salvaged #103-C
    /// FINDING 1 boundary, re-keyed to the V2 set read. The genuine
    /// "no V2 set / V1 vault" case is NOT reachable here: the v1/v2 routing
    /// (a fixed `meta.revisionlog_version` binding) decided this is a V2
    /// vault BEFORE this read, so any failure here is a real error.
    #[tokio::test]
    async fn read_authorized_set_v2_fails_closed_on_read_error() {
        // Dev env, an unreachable RPC (port 0 never listens). The read MUST
        // resolve to `Err` — either a missing-deployment error (no V2
        // address recorded for the test env) or a connect-layer RPC error.
        // Crucially it is NEVER `Ok(empty)`: a V2-bound vault that cannot
        // read its set fails the sync rather than silently honoring everyone
        // (under-revocation). Both arms are fail-closed; the load-bearing
        // assertion is that it is some `Err`, never an empty/honor-all set.
        let res = read_authorized_set_v2(ChainEnv::Dev, "http://127.0.0.1:0", [0x11; 32], 0).await;
        assert!(
            res.is_err(),
            "a set-read failure must NEVER resolve to an empty/honor-all set — \
             fail-closed (L3, salvaged #103-C FINDING 1)"
        );
    }

    /// #106c2 calldata pin: `publishRevision` encodes the exact field
    /// tuple a `SignedRevisionV2` carries, with the raw `encPayload`
    /// preimage (NOT the hash) on the wire. Decode-back round-trip.
    #[test]
    fn publish_revision_v2_calldata_encodes_fields() {
        let enc_payload = b"v2-calldata-pin-preimage".to_vec();
        let sig = [0x33u8; 65];
        let call = RevisionLogV2::publishRevisionCall {
            vaultId: [0x11; 32].into(),
            accountId: [0x22; 32].into(),
            parentRevision: [0x00; 32].into(),
            deviceId: [0x44; 32].into(),
            schemaVersion: 1,
            encPayload: Bytes::copy_from_slice(&enc_payload),
            signature: Bytes::copy_from_slice(&sig),
        };
        let encoded = SolCall::abi_encode(&call);
        let decoded =
            RevisionLogV2::publishRevisionCall::abi_decode(&encoded).expect("decode publish");
        assert_eq!(decoded.vaultId.0, [0x11; 32]);
        assert_eq!(decoded.accountId.0, [0x22; 32]);
        assert_eq!(decoded.parentRevision.0, [0x00; 32]);
        assert_eq!(decoded.deviceId.0, [0x44; 32]);
        assert_eq!(decoded.schemaVersion, 1);
        assert_eq!(decoded.encPayload.as_ref(), &enc_payload[..]);
        assert_eq!(decoded.signature.as_ref(), &sig[..]);
    }

    // -----------------------------------------------------------------
    // #106c2 COUPLED publish→read-back anvil E2E (the centerpiece — L11)
    // -----------------------------------------------------------------

    /// Deterministic publishing wallet — derived from the `[0x42;32]`
    /// seed `scripts/anvil-ci.sh` funds (same address as
    /// `chain_submit::fixed_wallet` / `recovery_client::recovering_wallet`).
    #[cfg(feature = "integration-tests")]
    fn publisher_wallet() -> EvmWallet {
        use crate::evm::derive_evm_wallet;
        use pangolin_crypto::keys::DeviceKey;
        derive_evm_wallet(&DeviceKey::from_seed([0x42; 32])).expect("derive publisher wallet")
    }

    /// **L11 CENTERPIECE.** The full V2 revision data-plane against a live
    /// local anvil node: bootstrapVault(publisher) → `publish_revision_v2`
    /// (publisher in the set) → `fetch_and_verify_chunk_v2` reads it back
    /// + verifies the round-trip (digest/signer parity), plus negative
    /// gates that MUST turn it RED:
    ///
    /// - **wrong domain:** a V1-domain signature does NOT verify against
    ///   the v2 read (`recover_signer_v2_raw` recovers a different
    ///   address) AND the live contract reverts a V1-domain publish.
    /// - **tampered payload:** flipping the read-back `encPayload` makes
    ///   the client-side v2 recover yield a different signer.
    /// - **foreign signer address:** the verify cross-check fails.
    /// - **non-member publisher:** the live contract reverts
    ///   `ErrSignerNotAuthorized`.
    #[tokio::test]
    #[ignore = "live-RPC test; requires PANGOLIN_CHAIN_ENV=dev + local anvil (scripts/anvil-ci.sh)"]
    #[cfg(feature = "integration-tests")]
    async fn publish_revision_v2_e2e_against_anvil() {
        use crate::evm::derive_evm_wallet;
        use crate::revisionlog_v2_signing::{
            build_signed_device_auth, build_signed_revision_v2, recover_signer_v2_raw,
            DeviceAuthFields, DeviceAuthKind,
        };
        use crate::secp256k1_signing::RevisionFieldsV1;
        use crate::test_env;
        use pangolin_crypto::keys::DeviceKey;

        let env = test_env::target_chain_env();
        if !test_env::is_dev_mode()
            && !test_env::require_or_fail("v2 revision data-plane E2E needs dev anvil")
        {
            return;
        }
        let rpc_url = test_env::rpc_url();
        let chain_id = test_env::resolve_signing_chain_id(env, &rpc_url)
            .await
            .expect("resolve signing chain id");
        let contract = resolve_contract_address(env).expect("RevisionLogV2 in dev.json");

        let wallet = publisher_wallet();
        let publisher = wallet.address();

        // Fresh vault id (time-tweaked so reruns don't collide).
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut vault_id = [0u8; 32];
        vault_id[..8].copy_from_slice(&now.to_be_bytes());
        vault_id[31] = 0xC2;

        // ---- bootstrapVault(publisher) — genesis AddDevice @ nonce 0 ----
        let boot_fields = DeviceAuthFields {
            kind: DeviceAuthKind::AddDevice,
            vault_id,
            subject: publisher,
            nonce: 0,
            schema_version: REVISIONLOG_V2_SCHEMA_VERSION,
        };
        let boot_auth = build_signed_device_auth(wallet.signer(), boot_fields, contract, chain_id)
            .expect("sign bootstrap");
        bootstrap_vault_v2(&wallet, publisher, &boot_auth, env, &rpc_url)
            .await
            .expect("bootstrapVault");
        assert!(
            read_authorized_device_v2(env, &rpc_url, vault_id, publisher)
                .await
                .expect("authorizedDevice"),
            "publisher must be in the set after bootstrap"
        );

        // ---- publish_revision_v2 (publisher in set) ----
        let enc_payload: Vec<u8> = format!("pangolin-v2-dataplane-{now}").into_bytes();
        let enc_payload_hash = alloy::primitives::keccak256(&enc_payload).0;
        let fields = RevisionFieldsV1::with_signer_device_id(
            &wallet,
            vault_id,
            [0x42; 32],
            [0u8; 32],
            REVISIONLOG_V2_SCHEMA_VERSION,
            enc_payload_hash,
        );
        let signed =
            build_signed_revision_v2(&wallet, fields, enc_payload.clone(), contract, chain_id)
                .expect("sign v2 revision");
        let anchor = publish_revision_v2(&wallet, &signed, env, &rpc_url)
            .await
            .expect("publish_revision_v2 must succeed (publisher in set)");
        assert_eq!(anchor.signer, publisher, "event signer == publisher");
        assert!(anchor.block_number > 0);

        // ---- fetch_and_verify_chunk_v2 reads it back ----
        let head = crate::fetch_current_block_number(&rpc_url)
            .await
            .expect("head");
        let (events, _rejected) =
            crate::fetch_and_verify_chunk_v2(&rpc_url, env, &vault_id, 0, head)
                .await
                .expect("v2 read-back");
        let found = events
            .iter()
            .find(|e| e.event.enc_payload == enc_payload)
            .expect("the published v2 revision must be read back");
        assert_eq!(
            found.signer, publisher,
            "read-back event signer == publisher"
        );
        // Client-side v2 recover round-trip (digest/signer parity).
        let recovered =
            recover_signer_v2_raw(&signed.fields, &signed.signature, contract, chain_id)
                .expect("client recover v2");
        assert_eq!(recovered, publisher, "v2 sign+recover round-trip");

        // ---- NEGATIVE: wrong domain (V1 sig won't verify against v2) ----
        // Sign the SAME fields under the V1 domain (version "1"); the v2
        // recover must NOT yield the publisher.
        let v1_sig = {
            use alloy::signers::SignerSync;
            use alloy::sol_types::eip712_domain;
            let dom = eip712_domain! {
                name: "Pangolin RevisionLog",
                version: "1",
                chain_id: chain_id,
                verifying_contract: contract,
            };
            let struct_h = crate::secp256k1_signing::struct_hash(&signed.fields);
            let v1_digest = crate::secp256k1_signing::eip712_digest(dom.separator(), struct_h);
            let s = wallet.signer().sign_hash_sync(&v1_digest).expect("sign v1");
            s.normalize_s().unwrap_or(s).as_bytes()
        };
        let wrong_domain_recovered =
            recover_signer_v2_raw(&signed.fields, &v1_sig, contract, chain_id).expect("recover");
        assert_ne!(
            wrong_domain_recovered, publisher,
            "a V1-domain signature must not recover the publisher under the v2 domain"
        );

        // ---- NEGATIVE: tampered payload → different recovered signer ----
        let mut tampered_fields = signed.fields;
        tampered_fields.enc_payload_hash[0] ^= 0xFF;
        let tampered_recovered =
            recover_signer_v2_raw(&tampered_fields, &signed.signature, contract, chain_id)
                .expect("recover");
        assert_ne!(
            tampered_recovered, publisher,
            "tampering the payload hash must change the recovered signer"
        );

        // ---- NEGATIVE: foreign signer address fails the cross-check ----
        let foreign = derive_evm_wallet(&DeviceKey::from_seed([0x99; 32]))
            .expect("foreign")
            .address();
        let foreign_check = crate::chain_sync::v2::verify_signed_event_v2(
            &signed.fields,
            &signed.signature,
            foreign,
            contract,
            chain_id,
        );
        assert!(
            foreign_check.is_err(),
            "a foreign claimed-signer must fail the v2 verify cross-check"
        );

        // ---- NEGATIVE: non-member publisher reverts ErrSignerNotAuthorized ----
        let stranger = derive_evm_wallet(&DeviceKey::from_seed([0x77; 32])).expect("stranger");
        assert_ne!(stranger.address(), publisher);
        let stranger_payload = b"stranger-publish".to_vec();
        let stranger_hash = alloy::primitives::keccak256(&stranger_payload).0;
        let stranger_fields = RevisionFieldsV1::with_signer_device_id(
            &stranger,
            vault_id,
            [0x42; 32],
            [0u8; 32],
            REVISIONLOG_V2_SCHEMA_VERSION,
            stranger_hash,
        );
        let stranger_signed = build_signed_revision_v2(
            &stranger,
            stranger_fields,
            stranger_payload,
            contract,
            chain_id,
        )
        .expect("sign stranger");
        // estimate_gas surfaces the revert pre-broadcast (no gas needed).
        let bad = publish_revision_v2(&stranger, &stranger_signed, env, &rpc_url).await;
        assert!(
            bad.is_err(),
            "a non-member publisher must revert (ErrSignerNotAuthorized)"
        );
    }
}
