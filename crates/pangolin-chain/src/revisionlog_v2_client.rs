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
use alloy::rpc::types::{BlockNumberOrTag, TransactionRequest};
#[allow(unused_imports)] // SolEvent / SolCall trait methods are used via
// the RevisionLogV2 binding through macro dispatch clippy can't see.
use alloy::sol_types::{SolCall, SolEvent};

use crate::deployments::{load_deployed_address, ChainEnv};
use crate::error::ChainError;
use crate::evm::EvmWallet;
use crate::revisionlog_v2_signing::SignedDeviceAuth;

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

// ---------------------------------------------------------------------
// Shared read/broadcast plumbing (mirrors recovery_client.rs verbatim)
// ---------------------------------------------------------------------

/// Resolve the `RevisionLogV2` contract address for `env`.
/// (TODO: add the `BaseSepolia` pinned-address cross-check + the
/// `EXPECTED_REVISIONLOG_V2_ADDRESS_BASE_SEPOLIA` constant once a testnet
/// deploy exists — mirror the v1/RecoveryV1 posture; testnet capture is a
/// TODO until the Base Sepolia v2 deploy lands.)
fn resolve_contract_address(env: ChainEnv) -> Result<Address, ChainError> {
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
}
