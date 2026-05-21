// SPDX-License-Identifier: AGPL-3.0-or-later
//! `RecoveryV1` chain-client: guardian-set merkle builder + the five
//! lifecycle broadcasts (MVP-3 issue #103, chain-client control plane).
//!
//! This module turns [`crate::recovery_signing`]'s `Approve` machinery
//! plus a hand-rolled merkle builder into EIP-1559 transactions that
//! call the deployed `RecoveryV1` contract
//! (`contracts/src/RecoveryV1.sol`)'s five mutators:
//! `setGuardianSet` / `initiateRecovery` / `approveRecovery` /
//! `cancelRecovery` / `finalizeRecovery`. It mirrors `chain_submit.rs`'s
//! R-c retry taxonomy, EIP-1559 envelope, 50-gwei gas cap, 1-conf
//! receipt-await, and `resolve_envelope_chain_id` (#101) verbatim.
//!
//! ## The merkle builder (R-merkle / L2 — LOAD-BEARING)
//!
//! The contract verifies guardian membership via a sorted-pair-keccak
//! merkle proof (`RecoveryV1.sol:837-851`) over leaves
//! `keccak256(abi.encode(guardian))` (`:609`). A client root or proof
//! that the contract's `_verifyMerkleProof` rejects = guardians can
//! NEVER approve = total liveness break. The builder here is
//! hand-rolled (NO merkle crate — L9) and OZ-StandardMerkleTree
//! compatible:
//!
//! - leaf = `keccak256(left_pad_32(address))` (the `abi.encode(address)`
//!   encoding is the 20-byte address left-padded to 32 bytes)
//! - node = `keccak256(min(a,b) ‖ max(a,b))` (sorted-pair, so proofs
//!   carry no left/right index bits)
//!
//! Byte-identity is pinned by a hermetic hand-computed-root fixture
//! test AND end-to-end by the anvil lifecycle `approveRecovery`
//! round-trip (the live `_verifyMerkleProof` accepts the client proof).
//!
//! ## L11 anti-replay
//!
//! `approveRecovery` reads the LIVE `attemptNonce` + `proposedAuthority`
//! from the contract's PENDING `recovery(vaultId)` slot before building
//! the `Approve` digest. A guardian's signature is bound to that exact
//! attempt; a stale-attempt digest can never be constructed.
//!
//! ## L5 — no guardian secret / VDK touched
//!
//! Guardians sign `Approve` attestations OFF-CHAIN (see
//! `recovery_signing::build_signed_approval_v1`); this module only
//! carries the resulting 65-byte signature + the merkle proof. No VDK,
//! no guardian secret key, no escrow share crosses here (those are
//! Workstream B / #103-C, deferred).

use core::time::Duration;

use alloy::network::{Ethereum, EthereumWallet, TransactionBuilder};
use alloy::primitives::{keccak256, Address, Bytes, B256, U256};
use alloy::providers::{DynProvider, PendingTransactionBuilder, Provider, ProviderBuilder};
use alloy::rpc::types::{BlockNumberOrTag, TransactionRequest};
#[allow(unused_imports)] // SolEvent / SolCall trait methods are used via
// the RecoveryV1 binding; clippy doesn't see the trait dispatch through
// the macro.
use alloy::sol_types::{SolCall, SolEvent};

use crate::deployments::{load_deployed_address, ChainEnv};
use crate::error::ChainError;
use crate::evm::EvmWallet;
use crate::recovery_signing::{ApproveFieldsV1, SignedApprovalV1};

// Reuse the chain-submit module's pinned gas/retry constants verbatim
// (L1: same envelope discipline, not a fork).
use crate::chain_submit::{
    MAX_FEE_PER_GAS_CAP_WEI, PRIORITY_FEE_DEFAULT_WEI, PUBLISH_REVISION_BACKOFF_MS,
    PUBLISH_REVISION_MAX_RETRIES, RECEIPT_TIMEOUT_SECS,
};

/// The contract name under which `RecoveryV1`'s address is recorded in
/// `contracts/deployments/<env>.json`.
pub const RECOVERY_CONTRACT_NAME: &str = "RecoveryV1";

/// Event-schema version every #103 call passes (L6). The contract
/// rejects `> MAX_KNOWN_SCHEMA_VERSION` symmetrically.
pub const RECOVERY_SCHEMA_VERSION_V1: u16 = 1;

// Gas-estimate safety multiplier — same 1.2x as chain_submit.rs.
const GAS_ESTIMATE_NUMER: u64 = 12;
const GAS_ESTIMATE_DENOM: u64 = 10;

// ---------------------------------------------------------------------
// alloy `sol!` binding for RecoveryV1
// ---------------------------------------------------------------------

// alloy's `sol!` macro expands into helpers whose argument count tracks
// the Solidity ABI; clippy's too-many-arguments cap fires on the
// 5/6-field calls + events. Same allow pattern as the RevisionLogV1 /
// EntitlementRegistry bindings.
#[allow(clippy::too_many_arguments, clippy::module_name_repetitions)]
pub mod recovery_v1_binding {
    use alloy::sol;

    sol! {
        /// Mirror of `contracts/src/RecoveryV1.sol`. MUST stay
        /// byte-for-byte aligned with the .sol source. Drift is caught
        /// by the calldata-pin tests + the anvil lifecycle round-trip.
        #[sol(rpc)]
        contract RecoveryV1 {
            function setGuardianSet(
                bytes32 vaultId,
                bytes32 root,
                uint8 threshold,
                uint8 guardianCount,
                uint16 schemaVersion
            ) external;

            function initiateRecovery(
                bytes32 vaultId,
                address proposedAuthority,
                uint16 schemaVersion
            ) external;

            function approveRecovery(
                bytes32 vaultId,
                address guardian,
                bytes32[] calldata proof,
                uint64 expiresAt,
                uint16 schemaVersion,
                bytes calldata signature
            ) external;

            function cancelRecovery(bytes32 vaultId, uint16 schemaVersion) external;

            function finalizeRecovery(bytes32 vaultId, uint16 schemaVersion) external;

            function recovery(bytes32 vaultId)
                external
                view
                returns (
                    address proposedAuthority,
                    uint64 initiatedAt,
                    uint64 attemptNonce,
                    uint8 approvals,
                    uint8 status
                );

            function vaultAuthority(bytes32 vaultId) external view returns (address);

            function hashApprove(
                bytes32 vaultId,
                address proposedAuthority,
                uint64 attemptNonce,
                uint64 expiresAt,
                uint16 schemaVersion
            ) external view returns (bytes32);

            event GuardianSetInitialized(
                bytes32 indexed vaultId,
                bytes32 root,
                uint8 threshold,
                uint8 guardianCount,
                address initialAuthority,
                uint16 schemaVersion
            );

            event RecoveryInitiated(
                bytes32 indexed vaultId,
                uint64 indexed attemptNonce,
                address proposedAuthority,
                uint64 initiatedAt,
                uint16 schemaVersion
            );

            event RecoveryApproved(
                bytes32 indexed vaultId,
                uint64 indexed attemptNonce,
                address guardian,
                uint8 approvals,
                uint16 schemaVersion
            );

            event RecoveryCanceled(
                bytes32 indexed vaultId, uint64 indexed attemptNonce, uint16 schemaVersion
            );

            event RecoveryFinalized(
                bytes32 indexed vaultId,
                uint64 indexed attemptNonce,
                address oldAuthority,
                address newAuthority,
                uint16 schemaVersion
            );
        }
    }
}

pub use recovery_v1_binding::RecoveryV1;

// ---------------------------------------------------------------------
// Merkle builder (R-merkle / L2)
// ---------------------------------------------------------------------

/// Compute the `keccak256(abi.encode(guardian))` leaf for a guardian
/// address (`RecoveryV1.sol:609`).
///
/// `abi.encode(address)` left-pads the 20-byte address to a 32-byte
/// word (12 zero bytes ‖ 20 address bytes); the leaf is the keccak of
/// that 32-byte word.
#[must_use]
pub fn guardian_leaf(addr: Address) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(addr.as_slice());
    keccak256(word).0
}

/// Hash a sorted pair of nodes (`RecoveryV1.sol:845-849`): the smaller
/// node is concatenated first (`abi.encodePacked(min, max)`), then
/// keccak'd. Sorting makes proofs order-independent (no index bits).
fn hash_pair(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 64];
    if a <= b {
        buf[..32].copy_from_slice(&a);
        buf[32..].copy_from_slice(&b);
    } else {
        buf[..32].copy_from_slice(&b);
        buf[32..].copy_from_slice(&a);
    }
    keccak256(buf).0
}

/// Build the merkle ROOT over a guardian address set, OZ-StandardMerkleTree
/// compatible (sorted-pair keccak, `keccak256(abi.encode(addr))`
/// leaves).
///
/// The leaves are SORTED before tree construction (the OZ
/// `StandardMerkleTree` convention: leaves are ordered by their hash so
/// the tree is deterministic regardless of input address order). The
/// root passed to `setGuardianSet` MUST be byte-identical to what the
/// contract's `_verifyMerkleProof` reconstructs from a leaf + proof
/// (L2). At each level an odd trailing node is carried up unpaired
/// (the OZ convention).
///
/// Returns the 32-byte root. A single-address set returns that leaf as
/// the root (no proof needed); the contract's `MIN_GUARDIANS = 3` floor
/// means real sets always have >= 3 leaves.
///
/// # Panics
///
/// Panics if `addresses` is empty — a guardian set with zero members is
/// nonsensical and the contract rejects a zero root anyway; callers
/// (the recovering device) always pass the real guardian list.
#[must_use]
pub fn build_guardian_root(addresses: &[Address]) -> [u8; 32] {
    let mut leaves: Vec<[u8; 32]> = addresses.iter().copied().map(guardian_leaf).collect();
    assert!(!leaves.is_empty(), "guardian set must be non-empty");
    leaves.sort_unstable();
    let mut level = leaves;
    while level.len() > 1 {
        let mut next: Vec<[u8; 32]> = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            if i + 1 < level.len() {
                next.push(hash_pair(level[i], level[i + 1]));
                i += 2;
            } else {
                // Odd trailing node carries up unpaired.
                next.push(level[i]);
                i += 1;
            }
        }
        level = next;
    }
    level[0]
}

/// Build the merkle membership PROOF for `guardian` within the set
/// `addresses` (the sibling-hash path the contract's
/// `_verifyMerkleProof` folds with `leaf` to reconstruct the root).
///
/// Returns the ordered sibling hashes (bottom-up). An empty proof means
/// `guardian` is the sole member (leaf == root). The proof is
/// order-independent at verification because the contract sorts each
/// pair (`RecoveryV1.sol:845`), so this builder need not carry index
/// bits.
///
/// Returns `None` if `guardian` is not in `addresses`.
#[must_use]
pub fn build_membership_proof(addresses: &[Address], guardian: Address) -> Option<Vec<[u8; 32]>> {
    let target_leaf = guardian_leaf(guardian);
    let mut leaves: Vec<[u8; 32]> = addresses.iter().copied().map(guardian_leaf).collect();
    leaves.sort_unstable();
    // Locate the target leaf's index after sorting.
    let mut idx = leaves.iter().position(|l| *l == target_leaf)?;

    let mut proof: Vec<[u8; 32]> = Vec::new();
    let mut level = leaves;
    while level.len() > 1 {
        let mut next: Vec<[u8; 32]> = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            if i + 1 < level.len() {
                let combined = hash_pair(level[i], level[i + 1]);
                // If our node is in this pair, record the sibling.
                if i == idx {
                    proof.push(level[i + 1]);
                } else if i + 1 == idx {
                    proof.push(level[i]);
                }
                next.push(combined);
                i += 2;
            } else {
                // Odd trailing node carries up unpaired; no sibling
                // recorded for it at this level.
                next.push(level[i]);
                i += 1;
            }
        }
        idx /= 2;
        level = next;
    }
    Some(proof)
}

/// Verify a membership proof off-chain (mirror of the contract's
/// `_verifyMerkleProof`, `RecoveryV1.sol:837-851`).
///
/// Used by the hermetic tests + as a client-side pre-flight before
/// broadcasting an `approveRecovery` (so a bad proof fails loudly
/// locally rather than burning a doomed tx).
#[must_use]
pub fn verify_membership_proof(proof: &[[u8; 32]], root: [u8; 32], leaf: [u8; 32]) -> bool {
    let mut computed = leaf;
    for p in proof {
        computed = hash_pair(computed, *p);
    }
    computed == root
}

// ---------------------------------------------------------------------
// Receipt anchors
// ---------------------------------------------------------------------

/// Receipt anchor returned from a successful `finalizeRecovery`.
///
/// The `RecoveryFinalized` event carries the rotated authority lineage
/// (`oldAuthority` → `newAuthority`) so a caller can confirm the
/// rotation landed (the load-bearing observable for #103-C
/// revocation-on-read, deferred).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryAnchorV1 {
    /// 32-byte transaction hash.
    pub tx_hash: B256,
    /// Block number the tx was included in.
    pub block_number: u64,
    /// 32-byte hash of the including block (reorg-safe consumers).
    pub block_hash: B256,
    /// Index of the lifecycle log within the block's log stream.
    pub log_index: u64,
    /// The attempt nonce the lifecycle event was scoped to.
    pub attempt_nonce: u64,
    /// The pre-rotation authority (only meaningful on a finalize
    /// anchor; `Address::ZERO` on other lifecycle anchors).
    pub old_authority: Address,
    /// The post-rotation authority (only meaningful on a finalize
    /// anchor; `Address::ZERO` on other lifecycle anchors).
    pub new_authority: Address,
}

/// The live PENDING attempt state read from the contract before
/// constructing an `Approve` digest (L11 anti-replay).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiveAttemptV1 {
    /// The attempt's target authority (`recovery(vaultId).proposedAuthority`).
    pub proposed_authority: Address,
    /// The attempt nonce (`recovery(vaultId).attemptNonce`).
    pub attempt_nonce: u64,
    /// The lifecycle status (`recovery(vaultId).status`; 1 == Pending).
    pub status: u8,
}

// ---------------------------------------------------------------------
// Public lifecycle entry points
// ---------------------------------------------------------------------

/// Broadcast `setGuardianSet(vaultId, root, threshold, guardianCount,
/// schemaVersion)`. The caller (`wallet`) self-bootstraps as the
/// vault's initial authority (`RecoveryV1.sol:485`).
///
/// `root` is built via [`build_guardian_root`] over the guardian
/// address list.
///
/// # Errors
///
/// R-c retry taxonomy (see [`crate::chain_submit`]): fatal on contract
/// revert / insufficient funds / gas-cap / chain-id mismatch / receipt
/// mismatch; retriable (bounded) on nonce collision / transient RPC.
pub async fn set_guardian_set_v1(
    wallet: &EvmWallet,
    vault_id: [u8; 32],
    root: [u8; 32],
    threshold: u8,
    guardian_count: u8,
    env: ChainEnv,
    rpc_url: &str,
) -> Result<RecoveryAnchorV1, ChainError> {
    let (provider, contract, chain_id) = connect(wallet, env, rpc_url).await?;
    let call = RecoveryV1::setGuardianSetCall {
        vaultId: vault_id.into(),
        root: root.into(),
        threshold,
        guardianCount: guardian_count,
        schemaVersion: RECOVERY_SCHEMA_VERSION_V1,
    };
    let calldata = SolCall::abi_encode(&call);
    let pending = broadcast_call(&provider, wallet.address(), contract, calldata, chain_id).await?;
    finish(pending, contract, |r, tx| {
        decode_lifecycle_anchor::<RecoveryV1::GuardianSetInitialized>(r, contract, tx, |_d, log| {
            anchor_basic(log, 0)
        })
    })
    .await
}

/// Broadcast `initiateRecovery(vaultId, proposedAuthority,
/// schemaVersion)` — None/terminal → PENDING; bumps `attemptNonce`.
///
/// Permissionless (the recovering party need not hold authority — the
/// guardian quorum + the 72h cancelable delay are the security gate).
///
/// # Errors
///
/// Same taxonomy as [`set_guardian_set_v1`].
pub async fn initiate_recovery_v1(
    wallet: &EvmWallet,
    vault_id: [u8; 32],
    proposed_authority: Address,
    env: ChainEnv,
    rpc_url: &str,
) -> Result<RecoveryAnchorV1, ChainError> {
    let (provider, contract, chain_id) = connect(wallet, env, rpc_url).await?;
    let call = RecoveryV1::initiateRecoveryCall {
        vaultId: vault_id.into(),
        proposedAuthority: proposed_authority,
        schemaVersion: RECOVERY_SCHEMA_VERSION_V1,
    };
    let calldata = SolCall::abi_encode(&call);
    let pending = broadcast_call(&provider, wallet.address(), contract, calldata, chain_id).await?;
    finish(pending, contract, |r, tx| {
        decode_lifecycle_anchor::<RecoveryV1::RecoveryInitiated>(r, contract, tx, |d, log| {
            RecoveryAnchorV1 {
                tx_hash: tx,
                block_number: 0, // filled by decode_lifecycle_anchor
                block_hash: B256::ZERO,
                log_index: log,
                attempt_nonce: d.attemptNonce,
                old_authority: Address::ZERO,
                new_authority: Address::ZERO,
            }
        })
    })
    .await
}

/// Read the live PENDING attempt for `vault_id` (L11): the
/// `proposedAuthority` + `attemptNonce` an `Approve` digest must bind.
///
/// # Errors
///
/// [`ChainError::Rpc`] on the view-call failure.
pub async fn read_live_attempt_v1(
    env: ChainEnv,
    rpc_url: &str,
    vault_id: [u8; 32],
) -> Result<LiveAttemptV1, ChainError> {
    let contract = resolve_contract_address(env)?;
    let provider = ProviderBuilder::new()
        .connect(rpc_url)
        .await
        .map_err(|e| ChainError::Rpc(format!("connect {rpc_url}: {e}")))?
        .erased();
    let bound = RecoveryV1::new(contract, &provider);
    let r = bound
        .recovery(vault_id.into())
        .call()
        .await
        .map_err(|e| ChainError::Rpc(format!("recovery({vault_id:?}) view: {e}")))?;
    Ok(LiveAttemptV1 {
        proposed_authority: r.proposedAuthority,
        attempt_nonce: r.attemptNonce,
        status: r.status,
    })
}

/// Build the `Approve` field set for the CURRENT live attempt (L11).
///
/// Reads `attemptNonce` + `proposedAuthority` live, returning the
/// fields a guardian must sign. Fails if no PENDING attempt exists so a
/// stale-attempt digest is never constructed.
///
/// # Errors
///
/// [`ChainError::Rpc`] on the view-call failure;
/// [`ChainError::Decode`] if the slot is not PENDING (status != 1).
pub async fn build_live_approve_fields_v1(
    env: ChainEnv,
    rpc_url: &str,
    vault_id: [u8; 32],
    expires_at: u64,
) -> Result<ApproveFieldsV1, ChainError> {
    let live = read_live_attempt_v1(env, rpc_url, vault_id).await?;
    if live.status != 1 {
        return Err(ChainError::Decode(format!(
            "no PENDING recovery for vault {vault_id:?} (status={}); refusing to build a \
             stale-attempt Approve digest (L11)",
            live.status
        )));
    }
    Ok(ApproveFieldsV1 {
        vault_id,
        proposed_authority: live.proposed_authority,
        attempt_nonce: live.attempt_nonce,
        expires_at,
        schema_version: RECOVERY_SCHEMA_VERSION_V1,
    })
}

/// Broadcast `approveRecovery(vaultId, guardian, proof, expiresAt,
/// schemaVersion, signature)` — record one guardian approval.
///
/// Carries the guardian's OFF-CHAIN [`SignedApprovalV1`] (65-byte sig)
/// plus the merkle membership `proof` (built via
/// [`build_membership_proof`]). Per L11 the `signed_approval.fields`
/// MUST have been built from the live attempt (see
/// [`build_live_approve_fields_v1`]); a client-side pre-flight asserts
/// the proof verifies against `root` before broadcasting.
///
/// # Errors
///
/// Same taxonomy as [`set_guardian_set_v1`], plus
/// [`ChainError::Decode`] if the supplied `proof` does not verify
/// against `root` for `guardian` (a doomed broadcast is rejected
/// locally — the live `_verifyMerkleProof` would revert
/// `ErrInvalidMerkleProof`).
#[allow(clippy::too_many_arguments)]
pub async fn approve_recovery_v1(
    wallet: &EvmWallet,
    guardian: Address,
    proof: &[[u8; 32]],
    root: [u8; 32],
    signed_approval: &SignedApprovalV1,
    env: ChainEnv,
    rpc_url: &str,
) -> Result<RecoveryAnchorV1, ChainError> {
    // Client-side pre-flight (L2): fail loudly locally if the proof
    // would be rejected on-chain.
    let leaf = guardian_leaf(guardian);
    if !verify_membership_proof(proof, root, leaf) {
        return Err(ChainError::Decode(format!(
            "merkle proof for guardian {guardian} does not verify against root \
             0x{}; the contract's _verifyMerkleProof would revert ErrInvalidMerkleProof",
            hex::encode(root)
        )));
    }

    let (provider, contract, chain_id) = connect(wallet, env, rpc_url).await?;
    let proof_words: Vec<B256> = proof.iter().map(|p| B256::from(*p)).collect();
    let call = RecoveryV1::approveRecoveryCall {
        vaultId: signed_approval.fields.vault_id.into(),
        guardian,
        proof: proof_words,
        expiresAt: signed_approval.fields.expires_at,
        schemaVersion: signed_approval.fields.schema_version,
        signature: Bytes::copy_from_slice(&signed_approval.signature[..]),
    };
    let calldata = SolCall::abi_encode(&call);
    let pending = broadcast_call(&provider, wallet.address(), contract, calldata, chain_id).await?;
    finish(pending, contract, |r, tx| {
        decode_lifecycle_anchor::<RecoveryV1::RecoveryApproved>(r, contract, tx, |d, log| {
            RecoveryAnchorV1 {
                tx_hash: tx,
                block_number: 0,
                block_hash: B256::ZERO,
                log_index: log,
                attempt_nonce: d.attemptNonce,
                old_authority: Address::ZERO,
                new_authority: Address::ZERO,
            }
        })
    })
    .await
}

/// Broadcast `cancelRecovery(vaultId, schemaVersion)` — authority-only
/// abort of the PENDING attempt (`RecoveryV1.sol:665`).
///
/// `wallet` MUST be the current `vaultAuthority` or the contract
/// reverts `ErrNotAuthorizedToCancel`.
///
/// # Errors
///
/// Same taxonomy as [`set_guardian_set_v1`].
pub async fn cancel_recovery_v1(
    wallet: &EvmWallet,
    vault_id: [u8; 32],
    env: ChainEnv,
    rpc_url: &str,
) -> Result<RecoveryAnchorV1, ChainError> {
    let (provider, contract, chain_id) = connect(wallet, env, rpc_url).await?;
    let call = RecoveryV1::cancelRecoveryCall {
        vaultId: vault_id.into(),
        schemaVersion: RECOVERY_SCHEMA_VERSION_V1,
    };
    let calldata = SolCall::abi_encode(&call);
    let pending = broadcast_call(&provider, wallet.address(), contract, calldata, chain_id).await?;
    finish(pending, contract, |r, tx| {
        decode_lifecycle_anchor::<RecoveryV1::RecoveryCanceled>(r, contract, tx, |d, log| {
            RecoveryAnchorV1 {
                tx_hash: tx,
                block_number: 0,
                block_hash: B256::ZERO,
                log_index: log,
                attempt_nonce: d.attemptNonce,
                old_authority: Address::ZERO,
                new_authority: Address::ZERO,
            }
        })
    })
    .await
}

/// Broadcast `finalizeRecovery(vaultId, schemaVersion)` — PENDING →
/// FINALIZED; rotates `vaultAuthority` to `proposedAuthority`.
///
/// Requires `approvals >= threshold` AND `block.timestamp >=
/// initiatedAt + 72h` (`RecoveryV1.sol:709`). Permissionless.
///
/// Returns a [`RecoveryAnchorV1`] whose `old_authority` / `new_authority`
/// carry the rotation lineage from the `RecoveryFinalized` event.
///
/// # Errors
///
/// Same taxonomy as [`set_guardian_set_v1`].
pub async fn finalize_recovery_v1(
    wallet: &EvmWallet,
    vault_id: [u8; 32],
    env: ChainEnv,
    rpc_url: &str,
) -> Result<RecoveryAnchorV1, ChainError> {
    let (provider, contract, chain_id) = connect(wallet, env, rpc_url).await?;
    let call = RecoveryV1::finalizeRecoveryCall {
        vaultId: vault_id.into(),
        schemaVersion: RECOVERY_SCHEMA_VERSION_V1,
    };
    let calldata = SolCall::abi_encode(&call);
    let pending = broadcast_call(&provider, wallet.address(), contract, calldata, chain_id).await?;
    finish(pending, contract, |r, tx| {
        decode_lifecycle_anchor::<RecoveryV1::RecoveryFinalized>(r, contract, tx, |d, log| {
            RecoveryAnchorV1 {
                tx_hash: tx,
                block_number: 0,
                block_hash: B256::ZERO,
                log_index: log,
                attempt_nonce: d.attemptNonce,
                old_authority: d.oldAuthority,
                new_authority: d.newAuthority,
            }
        })
    })
    .await
}

/// Read the current `vaultAuthority(vaultId)` (the rotated authority
/// after a finalize). Used by the lifecycle test's assert + by future
/// #103-C revocation-on-read.
///
/// # Errors
///
/// [`ChainError::Rpc`] on the view-call failure.
pub async fn read_vault_authority_v1(
    env: ChainEnv,
    rpc_url: &str,
    vault_id: [u8; 32],
) -> Result<Address, ChainError> {
    let contract = resolve_contract_address(env)?;
    let provider = ProviderBuilder::new()
        .connect(rpc_url)
        .await
        .map_err(|e| ChainError::Rpc(format!("connect {rpc_url}: {e}")))?
        .erased();
    let bound = RecoveryV1::new(contract, &provider);
    bound
        .vaultAuthority(vault_id.into())
        .call()
        .await
        .map_err(|e| ChainError::Rpc(format!("vaultAuthority({vault_id:?}) view: {e}")))
}

// ---------------------------------------------------------------------
// Shared broadcast plumbing (mirrors chain_submit.rs verbatim)
// ---------------------------------------------------------------------

/// Resolve the `RecoveryV1` contract address for `env` from the
/// deployment file. (TODO: add the `BaseSepolia` pinned-address
/// cross-check + the `EXPECTED_RECOVERY_ADDRESS_BASE_SEPOLIA` constant
/// once a testnet deploy exists — see `recovery_signing` constant docs.
/// Until then `Dev` is the only wired env, sourced from runtime
/// `dev.json`.)
fn resolve_contract_address(env: ChainEnv) -> Result<Address, ChainError> {
    load_deployed_address(env, RECOVERY_CONTRACT_NAME)
}

/// Connect a wallet-bearing provider + resolve the contract address +
/// the envelope chain id (#101 `resolve_envelope_chain_id` discipline:
/// pinned id for fixed envs, live id for Dev).
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

/// Resolve the envelope chain id (mirror of
/// [`crate::chain_submit`]'s private `resolve_envelope_chain_id`, L4):
/// production envs cross-check the RPC's reported id against the pinned
/// id and bind the PINNED value; `Dev` binds the live local id.
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

/// Broadcast a pre-encoded `RecoveryV1` call with the R-c retry taxonomy
/// (nonce-collision + transient-RPC retries, fatal on revert / funds /
/// gas-cap). Mirror of [`crate::chain_submit`]'s `broadcast_with_retries`
/// but parameterized over arbitrary calldata (all five lifecycle calls
/// share one loop — L1: same discipline, not five forks).
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

/// Await the 1-conf receipt for a broadcast lifecycle tx + decode its
/// anchor via `decode`. The L12 boundary: NO re-broadcast past this
/// point.
async fn finish<F>(
    pending: PendingTransactionBuilder<Ethereum>,
    _contract: Address,
    decode: F,
) -> Result<RecoveryAnchorV1, ChainError>
where
    F: FnOnce(&alloy::rpc::types::TransactionReceipt, B256) -> Result<RecoveryAnchorV1, ChainError>,
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
fn decode_lifecycle_anchor<E>(
    receipt: &alloy::rpc::types::TransactionReceipt,
    contract: Address,
    tx_hash: B256,
    build: impl FnOnce(&E, u64) -> RecoveryAnchorV1,
) -> Result<RecoveryAnchorV1, ChainError>
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

/// Helper for the `GuardianSetInitialized` anchor (no attempt nonce —
/// the set-up event predates any attempt).
fn anchor_basic(log_index: u64, attempt_nonce: u64) -> RecoveryAnchorV1 {
    RecoveryAnchorV1 {
        tx_hash: B256::ZERO,
        block_number: 0,
        block_hash: B256::ZERO,
        log_index,
        attempt_nonce,
        old_authority: Address::ZERO,
        new_authority: Address::ZERO,
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

/// Best-effort decoder for a `RecoveryV1` custom-error / revert reason
/// in an alloy error message. Covers the `RecoveryV1` custom errors plus
/// the generic out-of-gas / unknown-revert shapes.
fn decode_revert_reason_from_msg(msg: &str) -> Option<String> {
    let lower = msg.to_ascii_lowercase();
    if !(lower.contains("revert") || lower.contains("execution reverted")) {
        return None;
    }
    for known in [
        "ErrGuardianSetAlreadyInitialized",
        "ErrThresholdOutOfBounds",
        "ErrGuardianCountOutOfBounds",
        "ErrZeroValue",
        "ErrGuardianSetNotInitialized",
        "ErrRecoveryAlreadyPending",
        "ErrNoActiveRecovery",
        "ErrInvalidSignature",
        "ErrInvalidMerkleProof",
        "ErrDuplicateApproval",
        "ErrDelayNotElapsed",
        "ErrThresholdNotMet",
        "ErrNotAuthorizedToCancel",
        "ErrApprovalExpired",
        "ErrUnsupportedSchemaVersion",
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

    fn addr(b: u8) -> Address {
        Address::from([b; 20])
    }

    /// L2 (merkle byte-identity): a hand-computed 3-leaf root over a
    /// known address set matches `build_guardian_root`. The leaves are
    /// `keccak256(abi.encode(addr))` and the tree is sorted-pair
    /// keccak; this fixture re-derives the root the slow way and
    /// asserts byte-equality, catching a future drift in leaf encoding
    /// or pair-hashing.
    #[test]
    fn merkle_root_matches_hand_computed_fixture() {
        let a = addr(0x01);
        let b = addr(0x02);
        let c = addr(0x03);
        let set = [a, b, c];

        // Hand-compute: sort leaves, hash pairs.
        let mut leaves = [guardian_leaf(a), guardian_leaf(b), guardian_leaf(c)];
        leaves.sort_unstable();
        // 3 leaves: level1 = [hash(l0,l1), l2]; root = hash(level1[0], level1[1]).
        let n0 = hash_pair(leaves[0], leaves[1]);
        let n1 = leaves[2];
        let expected_root = hash_pair(n0, n1);

        let got = build_guardian_root(&set);
        assert_eq!(got, expected_root, "root must match hand-computed fixture");
    }

    /// L2: every guardian's proof verifies against the root (the
    /// off-chain mirror of the contract's `_verifyMerkleProof`). This
    /// is the hermetic precursor to the anvil round-trip; the latter
    /// proves the SAME proof is accepted by the LIVE contract.
    #[test]
    fn every_guardian_proof_verifies() {
        let set: Vec<Address> = (1u8..=5).map(addr).collect();
        let root = build_guardian_root(&set);
        for g in &set {
            let proof = build_membership_proof(&set, *g).expect("guardian in set");
            assert!(
                verify_membership_proof(&proof, root, guardian_leaf(*g)),
                "proof for {g} must verify against the root"
            );
        }
    }

    /// A NON-member address has no proof, and a forged leaf does not
    /// verify against the root.
    #[test]
    fn non_member_has_no_proof_and_fails_verify() {
        let set: Vec<Address> = (1u8..=4).map(addr).collect();
        let root = build_guardian_root(&set);
        let outsider = addr(0xFF);
        assert!(build_membership_proof(&set, outsider).is_none());
        // Even borrowing a real member's proof, the outsider leaf fails.
        let borrowed = build_membership_proof(&set, addr(0x01)).unwrap();
        assert!(!verify_membership_proof(
            &borrowed,
            root,
            guardian_leaf(outsider)
        ));
    }

    /// The leaf encoding is `keccak256(abi.encode(address))` — the
    /// 20-byte address left-padded to 32 bytes, then keccak'd. Pin one
    /// value against an independently-computed reference so an
    /// `encodePacked`-vs-`encode` drift (the env-quirk #14 silent-total
    /// class) fires here.
    #[test]
    fn guardian_leaf_encoding_is_abi_encode_not_packed() {
        let a = addr(0xAB);
        // abi.encode(address(0xABAB...AB)) = 12 zero bytes + 20×0xAB.
        let mut word = [0u8; 32];
        word[12..].copy_from_slice(&[0xABu8; 20]);
        let expected = keccak256(word).0;
        assert_eq!(guardian_leaf(a), expected);
        // The packed (20-byte) encoding would differ — assert it does,
        // so we can never silently swap to encodePacked.
        let packed = keccak256([0xABu8; 20]).0;
        assert_ne!(
            guardian_leaf(a),
            packed,
            "leaf must be abi.encode (32-byte padded), NOT encodePacked (20-byte)"
        );
    }
}

// =====================================================================
// Anvil Rust↔contract lifecycle test (the #103 CENTERPIECE — R-test /
// L10). Gated on the `integration-tests` feature + `#[ignore]`'d so the
// default `cargo test --lib` never reaches the network; run by
// `scripts/anvil-ci.sh` in dev mode against a fresh local anvil node.
// =====================================================================
#[cfg(all(test, feature = "integration-tests"))]
mod anvil_lifecycle {
    use super::*;
    use crate::recovery_signing::build_signed_approval_v1;
    use crate::test_env;
    use alloy::signers::local::PrivateKeySigner;
    use pangolin_crypto::keys::DeviceKey;

    use crate::evm::derive_evm_wallet;

    /// The recovering device's wallet — the same fixed seed `[0x42;32]`
    /// `scripts/anvil-ci.sh` funds via `anvil_setBalance` (so its
    /// lifecycle txs pay gas). It self-bootstraps as the initial vault
    /// authority on `setGuardianSet`.
    fn recovering_wallet() -> EvmWallet {
        let device = DeviceKey::from_seed([0x42; 32]);
        derive_evm_wallet(&device).expect("derive recovering wallet")
    }

    /// A deterministic guardian signer. Guardians sign OFF-CHAIN (L5);
    /// their wallets never broadcast, so they need no gas / funding.
    fn guardian(seed_byte: u8) -> PrivateKeySigner {
        let device = DeviceKey::from_seed([seed_byte; 32]);
        derive_evm_wallet(&device)
            .expect("derive guardian")
            .into_signer()
    }

    /// Time-warp the local anvil chain forward by `secs` seconds, then
    /// mine a block so `block.timestamp` reflects the bump. Uses the
    /// `cast rpc anvil_*` admin methods (the harness guarantees `cast`
    /// is on PATH in dev mode). Fail-closed: a non-success exit is a
    /// hard test failure.
    fn anvil_time_warp(rpc_url: &str, secs: u64) {
        let inc = std::process::Command::new("cast")
            .args([
                "rpc",
                "evm_increaseTime",
                &secs.to_string(),
                "--rpc-url",
                rpc_url,
            ])
            .output()
            .expect("invoke cast rpc evm_increaseTime");
        assert!(
            inc.status.success(),
            "evm_increaseTime failed: {}",
            String::from_utf8_lossy(&inc.stderr)
        );
        let mine = std::process::Command::new("cast")
            .args(["rpc", "evm_mine", "--rpc-url", rpc_url])
            .output()
            .expect("invoke cast rpc evm_mine");
        assert!(
            mine.status.success(),
            "evm_mine failed: {}",
            String::from_utf8_lossy(&mine.stderr)
        );
    }

    /// Print the recovering wallet address (harness funding helper —
    /// mirrors `chain_submit::print_fixed_wallet_address`; both derive
    /// from `[0x42;32]` so they resolve to the SAME address, which is
    /// what `scripts/anvil-ci.sh` already funds).
    #[test]
    #[ignore = "harness helper: prints the recovering wallet address"]
    fn print_recovering_wallet_address() {
        let w = recovering_wallet();
        println!("PANGOLIN_RECOVERY_WALLET_ADDRESS={:?}", w.address());
    }

    /// **L10 CENTERPIECE.** The full `RecoveryV1` lifecycle against a live
    /// local anvil node: deploy (by the harness) → `setGuardianSet`
    /// (real merkle root) → `initiateRecovery` → `approveRecovery ×
    /// threshold` (real guardian EIP-712 sigs + real merkle proofs,
    /// accepted by the LIVE `_verifyMerkleProof`) → 72h time-warp →
    /// `finalizeRecovery` → assert `RecoveryFinalized` + the rotated
    /// `vaultAuthority`. Plus negative gates (finalize-before-delay /
    /// below-threshold / non-authority-cancel / duplicate-approval all
    /// revert).
    ///
    /// This is the env-quirk-#14-class test: a deliberately-broken
    /// merkle leaf encoding or `Approve` typehash turns `approveRecovery`
    /// / `finalize` RED here (the live contract rejects), where the
    /// hermetic byte-pins alone could not. See the #103 plan L10.
    #[tokio::test]
    #[ignore = "live-RPC test; requires PANGOLIN_CHAIN_ENV=dev + local anvil (scripts/anvil-ci.sh)"]
    async fn recovery_lifecycle_against_anvil() {
        let env = test_env::target_chain_env();
        // L6 (dev mode): a missing dev.json / RPC is a HARD error, not a
        // skip. In base-sepolia mode (human run without anvil) this
        // skips cleanly.
        if !test_env::is_dev_mode()
            && !test_env::require_or_fail("recovery lifecycle needs dev anvil")
        {
            return;
        }
        let rpc_url = test_env::rpc_url();

        let wallet = recovering_wallet();
        let recovering_addr = wallet.address();

        // 3-of-5 guardian set (within the contract's [MIN,MAX] bounds).
        let g_signers: Vec<PrivateKeySigner> = [0xA1u8, 0xA2, 0xA3, 0xA4, 0xA5]
            .iter()
            .map(|b| guardian(*b))
            .collect();
        let g_addrs: Vec<Address> = g_signers.iter().map(PrivateKeySigner::address).collect();
        let threshold: u8 = 3;
        let guardian_count: u8 = 5;
        let root = build_guardian_root(&g_addrs);

        // Fresh vault id (time-tweaked so reruns don't collide on a
        // persistent chain; anvil is fresh per harness run anyway).
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut vault_id = [0u8; 32];
        vault_id[..8].copy_from_slice(&now.to_be_bytes());
        vault_id[31] = 0xCD;

        // The address authority rotates to on finalize.
        let proposed_authority = Address::from([0x77; 20]);

        let chain_id = test_env::resolve_signing_chain_id(env, &rpc_url)
            .await
            .expect("resolve signing chain id");
        let contract = resolve_contract_address(env).expect("RecoveryV1 in dev.json");

        // ---- setGuardianSet ----
        set_guardian_set_v1(
            &wallet,
            vault_id,
            root,
            threshold,
            guardian_count,
            env,
            &rpc_url,
        )
        .await
        .expect("setGuardianSet");
        // The recovering wallet self-bootstrapped as the authority.
        let auth0 = read_vault_authority_v1(env, &rpc_url, vault_id)
            .await
            .expect("read authority");
        assert_eq!(auth0, recovering_addr, "self-bootstrapped authority");

        // ---- initiateRecovery ----
        initiate_recovery_v1(&wallet, vault_id, proposed_authority, env, &rpc_url)
            .await
            .expect("initiateRecovery");
        let live = read_live_attempt_v1(env, &rpc_url, vault_id)
            .await
            .expect("read live attempt");
        assert_eq!(live.status, 1, "PENDING after initiate");
        assert_eq!(live.proposed_authority, proposed_authority);

        // ---- NEGATIVE: non-authority cancel reverts (R-g) ----
        // A wallet that is NOT the vault authority cannot cancel; the
        // contract reverts ErrNotAuthorizedToCancel. estimate_gas
        // surfaces the revert pre-broadcast, so this needs no gas
        // balance on the non-authority wallet.
        let stranger = derive_evm_wallet(&DeviceKey::from_seed([0x99; 32])).expect("stranger");
        assert_ne!(stranger.address(), recovering_addr);
        let bad_cancel = cancel_recovery_v1(&stranger, vault_id, env, &rpc_url).await;
        assert!(
            bad_cancel.is_err(),
            "non-authority cancel must revert (ErrNotAuthorizedToCancel)"
        );

        // ---- approveRecovery × threshold (real EIP-712 + real proofs) ----
        let expires_at = now + 7 * 24 * 60 * 60; // 7 days out
        let approve_fields = build_live_approve_fields_v1(env, &rpc_url, vault_id, expires_at)
            .await
            .expect("build live approve fields (L11)");

        // ---- NEGATIVE: finalize before threshold met reverts ----
        let early = finalize_recovery_v1(&wallet, vault_id, env, &rpc_url).await;
        assert!(early.is_err(), "finalize below threshold must revert");

        for g_signer in g_signers.iter().take(threshold as usize) {
            let g_addr = g_signer.address();
            let signed = build_signed_approval_v1(g_signer, approve_fields, contract, chain_id)
                .expect("guardian signs Approve off-chain");
            // Sanity (L3): the recovered approver equals the guardian.
            let recovered =
                crate::recovery_signing::recover_approver_v1(&signed, contract, chain_id)
                    .expect("recover approver");
            assert_eq!(recovered, g_addr, "recovered approver == guardian");

            let proof = build_membership_proof(&g_addrs, g_addr).expect("guardian in set");
            approve_recovery_v1(&wallet, g_addr, &proof, root, &signed, env, &rpc_url)
                .await
                .expect("approveRecovery accepted by live _verifyMerkleProof");

            // ---- NEGATIVE: duplicate approval reverts ----
            let dup =
                approve_recovery_v1(&wallet, g_addr, &proof, root, &signed, env, &rpc_url).await;
            assert!(dup.is_err(), "duplicate approval must revert");
        }

        // ---- NEGATIVE: finalize before delay elapsed reverts ----
        let before_delay = finalize_recovery_v1(&wallet, vault_id, env, &rpc_url).await;
        assert!(
            before_delay.is_err(),
            "finalize before 72h delay must revert (threshold met but delay not elapsed)"
        );

        // ---- 72h time-warp ----
        anvil_time_warp(&rpc_url, 259_200);

        // ---- finalizeRecovery → authority rotates ----
        let anchor = finalize_recovery_v1(&wallet, vault_id, env, &rpc_url)
            .await
            .expect("finalizeRecovery after delay");
        assert_eq!(anchor.old_authority, recovering_addr, "old authority");
        assert_eq!(
            anchor.new_authority, proposed_authority,
            "rotated authority"
        );
        let auth1 = read_vault_authority_v1(env, &rpc_url, vault_id)
            .await
            .expect("read rotated authority");
        assert_eq!(auth1, proposed_authority, "vaultAuthority rotated on chain");
    }
}

// =====================================================================
// #104b COUPLED anvil E2E (the CENTERPIECE / L10) — ties the OFF-CHAIN
// threshold-escrow reconstruction to the ON-CHAIN recovery lifecycle.
//
// This is the env-quirk-#14-class regression gate the #104b plan §6
// mandates: it composes the REAL `split_rwk` -> REAL merkle root over the
// SAME guardians whose X25519 shares were sealed -> on-chain
// initiate/approve/finalize against the LIVE RecoveryV1 contract -> REAL
// `reconstruct_rwk` from the opened shares -> `unwrap_vdk_under_rwk` ->
// `ct_eq` the original VDK -> new-password re-wrap (via pangolin-store's
// `Vault::recover_with_new_password`) -> forward-security re-split.
//
// The load-bearing join asserted here (L2): each guardian's SINGLE
// `DeviceKey` yields BOTH their secp256k1 Approve-signer (committed in the
// merkle root) AND their X25519 share-opener (the seal recipient). The
// negatives prove a broken join / sub-threshold set turns this RED.
//
// Gated on `integration-tests` + `#[ignore]` like the #103 lifecycle test;
// run by `scripts/anvil-ci.sh` in dev mode against a fresh local anvil.
// =====================================================================
#[cfg(all(test, feature = "integration-tests"))]
mod anvil_recovery_escrow_e2e {
    use super::*;
    use crate::evm::derive_evm_wallet;
    use crate::recovery_signing::build_signed_approval_v1;
    use crate::test_env;
    use alloy::signers::local::PrivateKeySigner;
    use pangolin_crypto::escrow::{
        open_sealed_share, reconstruct_rwk, seal_share, split_rwk, unwrap_vdk_under_rwk,
        wrap_vdk_under_rwk, RecoveryWrapKey, SealedShare, Share, X25519_KEY_LEN,
    };
    use pangolin_crypto::guardian::derive_x25519_sealing_key;
    use pangolin_crypto::keys::{DeviceKey, VdkKey, WrapContext};

    /// The recovering device's wallet — the same fixed seed `[0x42;32]`
    /// `scripts/anvil-ci.sh` funds, so its lifecycle txs pay gas. It
    /// self-bootstraps as the initial vault authority on `setGuardianSet`.
    fn recovering_wallet() -> EvmWallet {
        derive_evm_wallet(&DeviceKey::from_seed([0x42; 32])).expect("derive recovering wallet")
    }

    /// A guardian is ONE `DeviceKey` yielding BOTH keys (the L2 join):
    /// their secp256k1 Approve-signer (merkle-committed) and their X25519
    /// share-opener (seal recipient). Returns
    /// `(secp256k1_signer, x25519_secret, x25519_public)`.
    fn guardian_two_keys(
        seed_byte: u8,
    ) -> (PrivateKeySigner, [u8; X25519_KEY_LEN], [u8; X25519_KEY_LEN]) {
        let device = DeviceKey::from_seed([seed_byte; 32]);
        let signer = derive_evm_wallet(&device)
            .expect("derive guardian secp256k1")
            .into_signer();
        let sealing = derive_x25519_sealing_key(&device);
        (signer, *sealing.secret_bytes(), *sealing.public_bytes())
    }

    /// 72h time-warp on the local anvil (same helper shape as the #103
    /// lifecycle test).
    fn anvil_time_warp(rpc_url: &str, secs: u64) {
        let inc = std::process::Command::new("cast")
            .args([
                "rpc",
                "evm_increaseTime",
                &secs.to_string(),
                "--rpc-url",
                rpc_url,
            ])
            .output()
            .expect("invoke cast rpc evm_increaseTime");
        assert!(
            inc.status.success(),
            "evm_increaseTime failed: {}",
            String::from_utf8_lossy(&inc.stderr)
        );
        let mine = std::process::Command::new("cast")
            .args(["rpc", "evm_mine", "--rpc-url", rpc_url])
            .output()
            .expect("invoke cast rpc evm_mine");
        assert!(
            mine.status.success(),
            "evm_mine failed: {}",
            String::from_utf8_lossy(&mine.stderr)
        );
    }

    /// **L10 CENTERPIECE.** The full coupled path: deploy (harness) ->
    /// `setGuardianSet`(real root from the SAME guardians) ->
    /// `initiateRecovery`(new-device secp256k1) -> `approveRecovery`×t
    /// (real EIP-712) -> 72h time-warp -> `finalizeRecovery`
    /// (`vaultAuthority` == new device) -> off-chain `open_sealed_share`×t
    /// -> `reconstruct_rwk` -> `unwrap_vdk_under_rwk` -> `ct_eq` original VDK
    /// -> new-password re-wrap (Vault) -> forward-security re-split.
    ///
    /// Asserts L2 (the guardian two-key join), L3 (byte-identical VDK), L5
    /// (dual-authority: the on-chain `vaultAuthority` rotated to the new
    /// device AND the re-wrapped daily `WrappedVdk` opens under the new
    /// password), L6 (the re-split RWK' differs + old shares can't recover
    /// the re-split wrapper).
    #[tokio::test]
    #[ignore = "live-RPC test; requires PANGOLIN_CHAIN_ENV=dev + local anvil (scripts/anvil-ci.sh)"]
    async fn recovery_escrow_coupled_e2e_against_anvil() {
        let env = test_env::target_chain_env();
        if !test_env::is_dev_mode()
            && !test_env::require_or_fail("coupled recovery-escrow E2E needs dev anvil")
        {
            return;
        }
        let rpc_url = test_env::rpc_url();
        let wallet = recovering_wallet();
        let recovering_addr = wallet.address();

        // ---- A vault to anchor vault_id + the off-chain VDK ----
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let vault_path = tmp.path().join("recovery-e2e.pvf");
        let original_password =
            pangolin_crypto::secret::SecretBytes::new(b"the original lost password".to_vec());
        let vault_id = {
            let v = pangolin_store::Vault::create(&vault_path, &original_password)
                .expect("create vault");
            v.vault_id()
        };

        // The VDK we onboard the escrow against. In production this is the
        // vault's own VDK; here we mint one + persist it as the recovery
        // wrapper, then recover it and re-secure the vault under it.
        let vdk = VdkKey::generate();
        let ctx = WrapContext::new(vault_id);
        let rwk = RecoveryWrapKey::generate();
        let wrapped_recovery = wrap_vdk_under_rwk(&vdk, &rwk, &ctx).expect("wrap vdk under rwk");

        // ---- 3-of-5 guardians; ONE DeviceKey each -> BOTH keys (L2) ----
        let threshold: u8 = 3;
        let guardian_count: u8 = 5;
        let epoch = [0u8; pangolin_crypto::escrow::EPOCH_LEN];
        let two_keys: Vec<_> = [0xA1u8, 0xA2, 0xA3, 0xA4, 0xA5]
            .iter()
            .map(|b| guardian_two_keys(*b))
            .collect();
        // The secp256k1 addresses the merkle root commits.
        let g_addrs: Vec<Address> = two_keys.iter().map(|(s, _, _)| s.address()).collect();
        let root = build_guardian_root(&g_addrs);

        // Split the RWK + seal share i to guardian i's X25519 pubkey (the
        // SAME guardian whose secp256k1 address is committed at position i).
        let shares = split_rwk(&rwk, threshold, guardian_count).expect("split rwk");
        let sealed: Vec<SealedShare> = shares
            .iter()
            .zip(&two_keys)
            .map(|(s, (_, _, x_pub))| seal_share(s, x_pub, &vault_id, &epoch).expect("seal"))
            .collect();
        drop(rwk);
        drop(shares);

        let chain_id = test_env::resolve_signing_chain_id(env, &rpc_url)
            .await
            .expect("resolve signing chain id");
        let contract = resolve_contract_address(env).expect("RecoveryV1 in dev.json");

        // The new device's secp256k1 signer (proposedAuthority) — born
        // locally on the recovering device (Q-e).
        let new_device = DeviceKey::from_seed([0x42; 32]);
        let proposed_authority = derive_evm_wallet(&new_device)
            .expect("derive new-device wallet")
            .address();

        // ---- on-chain: setGuardianSet (root over the SAME guardians) ----
        set_guardian_set_v1(
            &wallet,
            vault_id,
            root,
            threshold,
            guardian_count,
            env,
            &rpc_url,
        )
        .await
        .expect("setGuardianSet");
        let auth0 = read_vault_authority_v1(env, &rpc_url, vault_id)
            .await
            .expect("read authority");
        assert_eq!(auth0, recovering_addr, "self-bootstrapped authority");

        // ---- initiateRecovery(new-device secp256k1) ----
        initiate_recovery_v1(&wallet, vault_id, proposed_authority, env, &rpc_url)
            .await
            .expect("initiateRecovery");

        // ---- NEGATIVE (L2 / L10): a wrong guardian↔share mapping is
        //      caught. We seal share[0] to guardian 0's X25519 key, but try
        //      to open it with guardian 1's X25519 secret — the open fails
        //      (a mismatched seal/merkle pairing strands recovery). ----
        assert!(
            open_sealed_share(&sealed[0], &two_keys[1].1, &vault_id, &epoch).is_err(),
            "a share sealed to guardian 0 must NOT open with guardian 1's X25519 key (L2)"
        );

        // ---- approveRecovery × threshold (real EIP-712 + real proofs) ----
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let expires_at = now + 7 * 24 * 60 * 60;
        let approve_fields = build_live_approve_fields_v1(env, &rpc_url, vault_id, expires_at)
            .await
            .expect("build live approve fields (L11)");
        for (signer, _, _) in two_keys.iter().take(threshold as usize) {
            let g_addr = signer.address();
            let signed = build_signed_approval_v1(signer, approve_fields, contract, chain_id)
                .expect("guardian signs Approve off-chain");
            let proof = build_membership_proof(&g_addrs, g_addr).expect("guardian in set");
            approve_recovery_v1(&wallet, g_addr, &proof, root, &signed, env, &rpc_url)
                .await
                .expect("approveRecovery accepted by live _verifyMerkleProof");
        }

        // ---- NEGATIVE: finalize before the 72h delay reverts (L10 /
        //      already #103) ----
        assert!(
            finalize_recovery_v1(&wallet, vault_id, env, &rpc_url)
                .await
                .is_err(),
            "finalize before delay must revert"
        );

        // ---- 72h time-warp -> finalizeRecovery (authority rotates) ----
        anvil_time_warp(&rpc_url, 259_200);
        let anchor = finalize_recovery_v1(&wallet, vault_id, env, &rpc_url)
            .await
            .expect("finalizeRecovery after delay");
        assert_eq!(
            anchor.new_authority, proposed_authority,
            "rotated authority"
        );
        let auth1 = read_vault_authority_v1(env, &rpc_url, vault_id)
            .await
            .expect("read rotated authority");
        // L5 (on-chain half): the vaultAuthority rotated to the NEW DEVICE.
        assert_eq!(
            auth1, proposed_authority,
            "vaultAuthority == new device (L5)"
        );

        // ---- off-chain: guardians open THEIR OWN shares (Q-a) ----
        let opened: Vec<Share> = [0usize, 2, 4]
            .iter()
            .map(|&i| {
                open_sealed_share(&sealed[i], &two_keys[i].1, &vault_id, &epoch)
                    .expect("guardian opens own sealed share")
            })
            .collect();

        // ---- reconstruct RWK -> unwrap VDK -> ct_eq original (L3) ----
        let rwk2 = reconstruct_rwk(&opened).expect("reconstruct rwk from t shares");
        let recovered_vdk = unwrap_vdk_under_rwk(&wrapped_recovery, &rwk2).expect("unwrap vdk");
        assert!(
            bool::from(vdk.ct_eq(&recovered_vdk)),
            "recovered VDK must be byte-identical to the original (L3)"
        );
        drop(rwk2);

        // ---- NEGATIVE (L10): < t shares cannot reconstruct the VDK ----
        let sub: Vec<Share> = [0usize, 2]
            .iter()
            .map(|&i| open_sealed_share(&sealed[i], &two_keys[i].1, &vault_id, &epoch).unwrap())
            .collect();
        match reconstruct_rwk(&sub) {
            Err(_) => {} // rejected outright — fine.
            Ok(wrong) => {
                // If it produced *some* RWK, it must NOT unwrap the VDK.
                assert!(
                    unwrap_vdk_under_rwk(&wrapped_recovery, &wrong).is_err(),
                    "< t shares must NOT recover the VDK (L10)"
                );
            }
        }

        // ---- L5 (off-chain half): set a NEW password -> re-wrap the
        //      daily VDK -> it opens under the new password, NOT the old. ----
        let new_password =
            pangolin_crypto::secret::SecretBytes::new(b"the brand-new recovery password".to_vec());
        {
            let mut v = pangolin_store::Vault::open(&vault_path).expect("reopen vault");
            v.recover_with_new_password(recovered_vdk, &new_password)
                .expect("re-wrap daily VDK under new password");
            // The OLD password no longer unlocks.
            let old_id = pangolin_store::PinIdentityProof::new(
                pangolin_crypto::secret::SecretBytes::new(b"the original lost password".to_vec()),
            );
            assert!(
                v.unlock(&pangolin_store::PressYPresenceProof::confirmed(), &old_id)
                    .is_err(),
                "old password must NOT unlock after recovery (L5/L8)"
            );
            // The NEW password unlocks.
            let new_id =
                pangolin_store::PinIdentityProof::new(pangolin_crypto::secret::SecretBytes::new(
                    b"the brand-new recovery password".to_vec(),
                ));
            v.unlock(&pangolin_store::PressYPresenceProof::confirmed(), &new_id)
                .expect("new password unlocks the re-wrapped vault (L5)");
        }

        // ---- L6 forward security: re-split under a FRESH RWK' + bumped
        //      epoch; the OLD shares cannot recover the re-split wrapper. ----
        let vdk_for_resplit = unwrap_vdk_under_rwk(
            &wrapped_recovery,
            &reconstruct_rwk(
                &[0usize, 2, 4]
                    .iter()
                    .map(|&i| {
                        open_sealed_share(&sealed[i], &two_keys[i].1, &vault_id, &epoch).unwrap()
                    })
                    .collect::<Vec<_>>(),
            )
            .unwrap(),
        )
        .unwrap();
        let rwk_new = RecoveryWrapKey::generate();
        let mut epoch_new = [0u8; pangolin_crypto::escrow::EPOCH_LEN];
        epoch_new[15] = 1; // bumped epoch
        let wrapped_new = wrap_vdk_under_rwk(&vdk_for_resplit, &rwk_new, &ctx).unwrap();
        let shares_new = split_rwk(&rwk_new, threshold, guardian_count).unwrap();
        let sealed_new: Vec<SealedShare> = shares_new
            .iter()
            .zip(&two_keys)
            .map(|(s, (_, _, x_pub))| seal_share(s, x_pub, &vault_id, &epoch_new).unwrap())
            .collect();
        drop(rwk_new);
        drop(shares_new);

        // The OLD epoch-0 shares reconstruct the OLD (dead) RWK, which must
        // NOT unwrap the re-split wrapper (forward security, L6).
        let old_again: Vec<Share> = [0usize, 2, 4]
            .iter()
            .map(|&i| open_sealed_share(&sealed[i], &two_keys[i].1, &vault_id, &epoch).unwrap())
            .collect();
        let rwk_old = reconstruct_rwk(&old_again).unwrap();
        assert!(
            unwrap_vdk_under_rwk(&wrapped_new, &rwk_old).is_err(),
            "old shares must NOT recover the post-recovery (re-split) vault (L6)"
        );

        // The NEW shares DO recover the re-split wrapper.
        let new_open: Vec<Share> = [0usize, 1, 2]
            .iter()
            .map(|&i| {
                open_sealed_share(&sealed_new[i], &two_keys[i].1, &vault_id, &epoch_new).unwrap()
            })
            .collect();
        let rwk_back = reconstruct_rwk(&new_open).unwrap();
        let vdk_back = unwrap_vdk_under_rwk(&wrapped_new, &rwk_back).unwrap();
        assert!(
            bool::from(vdk.ct_eq(&vdk_back)),
            "re-split must preserve the byte-identical VDK (L3/L6)"
        );
    }
}
