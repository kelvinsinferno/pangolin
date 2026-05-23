// SPDX-License-Identifier: AGPL-3.0-or-later
//! **MVP-3 issue #108: the thin uniffi layer over the merged-and-audited
//! `RecoveryV1` chain primitives.**
//!
//! Closes the remaining FFI gap so a host app can drive the full
//! `RecoveryV1` lifecycle end-to-end:
//!
//! - [`vault_set_guardian_set`] — manager onboards the on-chain merkle
//!   root over the M guardian EVM addresses + records the threshold.
//! - [`vault_initiate_recovery`] — recovering (post-loss) device opens
//!   the PENDING attempt against a target vault.
//! - [`vault_approve_recovery`] — guardian-side approval. Engine
//!   computes the leaf + merkle proof for the active signer and builds
//!   the `Approve` EIP-712 digest bound to the LIVE `(attempt_nonce,
//!   proposed_authority, expires_at)`.
//! - [`vault_cancel_recovery`] — vault-authority-only abort of the
//!   pending attempt (contract enforces `msg.sender == vaultAuthority`).
//! - [`vault_finalize_recovery`] — permissionless completion after the
//!   72h delay + threshold. Loaded-only (not Active): a Locked vault is
//!   acceptable — the security is the quorum + the delay, not local
//!   session state.
//! - [`vault_read_vault_authority`] — read-side: the current on-chain
//!   `vaultAuthority`.
//! - [`vault_read_recovery_status`] — read-side: the live attempt
//!   status / nonce / proposed authority / approvals / `initiated_at`.
//!
//! ## L1 — ZERO secret crosses the FFI
//!
//! Master passwords cross IN behind [`SecretPassword`]; the active
//! session's EVM signer comes from `Vault::evm_wallet()` and never leaves
//! the engine. Outputs are 32-byte tx hashes / `block_number` / a
//! non-secret status enum / the attempt nonce / a 20-byte EVM address.
//! Merkle proofs + leaves are computed engine-side from the guardian set
//! the host passes; the host never holds a proof.
//!
//! ## L2 — no new atomic surface
//!
//! Each binding wraps EXACTLY ONE primitive in
//! [`pangolin_chain::recovery_client`]; the file adds no new multi-step
//! state machine.
//!
//! ## L3 — fail-closed on chain-read errors
//!
//! Reads (`vault_read_vault_authority`, `vault_read_recovery_status`)
//! and the live-attempt fetch inside `vault_approve_recovery` map every
//! chain failure to [`FfiError::Chain`]; the bindings NEVER proceed with
//! partial / guessed state (mirrors `vault_complete_rotation`).
//!
//! ## L4 — per-binding session-gating
//!
//! - `set_guardian_set` / `initiate` / `approve` / `cancel` require
//!   Active (the signer / VDK ride the active session).
//! - `finalize` is **loaded-only**: `as_mut()?` accepts any non-
//!   placeholder vault. Per the plan (Q-c) any device with a configured
//!   RPC + the target vault id may finalize.
//! - Reads accept any non-placeholder handle (Q-b: yes-handle).
//!
//! ## L5 — uniffi pinned `=0.31.1`; `forbid(unsafe)`; AGPL SPDX.
//!
//! ## L6 — testnet-only (D-011)
//!
//! `ChainEnv` is resolved via [`crate::chain_config::ffi_chain_env_and_id`]:
//! production hardcodes `BaseSepolia` + its pinned chain id; the
//! `integration-tests` feature opts into `ChainEnv::Dev`. Compiled OUT
//! of shipped builds.

#![forbid(unsafe_code)]
// Module-level docs are heavily annotated with the L1..L6 invariants; the
// substantive lints stay enforced.
#![allow(
    clippy::doc_markdown,
    clippy::too_long_first_doc_paragraph,
    clippy::doc_lazy_continuation
)]

use std::sync::Arc;

use pangolin_chain::{
    approve_recovery_v1, build_guardian_root, build_live_approve_fields_v1, build_membership_proof,
    build_signed_approval_v1, cancel_recovery_v1, finalize_recovery_v1, initiate_recovery_v1,
    read_live_attempt_v1, read_vault_authority_v1, set_guardian_set_v1, Address, EvmWallet,
};
use pangolin_core::EVM_ADDRESS_LEN;
use pangolin_crypto::keys::VAULT_ID_LEN;
use pangolin_crypto::secret::SecretBytes;

use crate::chain_config::{block_on_local, chain_into_ffi, FfiChainConfig};
use crate::error::FfiError;
use crate::session::{SecretPassword, VaultHandle};

/// Schema-version slot value for the #108 FFI result records.
pub const RECOVERY_LIFECYCLE_FFI_SCHEMA_VERSION: u16 = 1;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Map a [`pangolin_store::StoreError`] through the total
/// `StoreError → pangolin_core::Error → FfiError` mapping.
fn store_into_ffi(err: pangolin_store::StoreError) -> FfiError {
    FfiError::from(pangolin_core::Error::from(err))
}

/// Validate a host-supplied `Vec<u8>` is exactly `N` bytes, returning the
/// fixed-size array or [`FfiError::Validation`] (`kind = "argument"`).
fn fixed_bytes<const N: usize>(bytes: &[u8], what: &str) -> Result<[u8; N], FfiError> {
    bytes.try_into().map_err(|_| FfiError::Validation {
        kind: "argument".into(),
        message: format!("{what} must be {N} bytes (got {})", bytes.len()),
    })
}

/// Validate + collect a `Vec<Vec<u8>>` of 20-byte EVM guardian
/// addresses into `[u8; 20]` → [`Address`]s.
fn collect_guardian_addrs(guardians: &[Vec<u8>], what: &str) -> Result<Vec<Address>, FfiError> {
    guardians
        .iter()
        .map(|g| fixed_bytes::<EVM_ADDRESS_LEN>(g, what).map(Address::from))
        .collect()
}

// ---------------------------------------------------------------------------
// FFI result records
// ---------------------------------------------------------------------------

/// Non-secret receipt anchor returned from a chain-mutating lifecycle
/// binding.
///
/// Mirrors the public fields of [`pangolin_chain::RecoveryAnchorV1`]
/// that are useful to the host: the 32-byte tx hash and the including
/// block number. Lineage fields (`old_authority` / `new_authority` on
/// finalize, `attempt_nonce`) are deliberately NOT surfaced here — the
/// host re-reads them via [`vault_read_recovery_status`] /
/// [`vault_read_vault_authority`] post-confirmation if it needs them, so
/// the result record stays uniform across all five mutating bindings.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiTxOutcome {
    /// 32-byte transaction hash.
    pub tx_hash: Vec<u8>,
    /// Block number the tx was included in (1-conf receipt).
    pub block_number: u64,
    /// Schema-version slot.
    pub schema_version: u16,
}

/// Non-secret read of the current on-chain `vaultAuthority(vaultId)`.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiVaultAuthority {
    /// The 20-byte EVM address currently authorized to cancel a recovery
    /// attempt + the rotated authority after a successful finalize.
    pub address: Vec<u8>,
    /// Schema-version slot.
    pub schema_version: u16,
}

/// Non-secret read of the live recovery attempt slot
/// (`RecoveryV1.recovery(vaultId)`).
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiRecoveryStatus {
    /// Lifecycle status mirroring the contract enum
    /// (`0 = None`, `1 = Pending`, `2 = Finalized`, `3 = Canceled`).
    pub status: u8,
    /// 20-byte target authority of the live attempt (`Address::ZERO` if
    /// no attempt has ever been opened).
    pub proposed_authority: Vec<u8>,
    /// Per-attempt scope; bumps on each `initiateRecovery`.
    pub attempt_nonce: u64,
    /// Unix timestamp the live attempt was opened
    /// (`recovery.initiatedAt`). Always `0` in this v0 surface — the
    /// chain-side `LiveAttemptV1` view does not yet expose it; the host
    /// can re-derive it from the receipt block of the `initiate` tx if
    /// it needs absolute time. Reserved for a future expansion of the
    /// chain read primitive.
    pub initiated_at: u64,
    /// Approval count accumulated on the live attempt.
    pub approval_count: u8,
    /// Schema-version slot.
    pub schema_version: u16,
}

// ---------------------------------------------------------------------------
// Shared internals
// ---------------------------------------------------------------------------

/// Build an [`FfiTxOutcome`] from a [`pangolin_chain::RecoveryAnchorV1`].
fn tx_outcome_from_anchor(anchor: pangolin_chain::RecoveryAnchorV1) -> FfiTxOutcome {
    FfiTxOutcome {
        tx_hash: anchor.tx_hash.0.to_vec(),
        block_number: anchor.block_number,
        schema_version: RECOVERY_LIFECYCLE_FFI_SCHEMA_VERSION,
    }
}

/// Require the vault be Active. Used by every Active-gated lifecycle
/// binding (set_guardian_set / initiate / approve / cancel).
fn require_active(vault: &pangolin_store::Vault) -> Result<(), FfiError> {
    if vault.state() != pangolin_store::VaultState::Active {
        return Err(FfiError::Session {
            message: "vault is not unlocked".to_owned(),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 1. vault_set_guardian_set — manager onboards the guardian merkle root
// ---------------------------------------------------------------------------

/// **Active-gated.** Onboard the on-chain guardian merkle root + the
/// `(threshold, guardian_count)` constants for the active vault, driving
/// [`pangolin_chain::set_guardian_set_v1`].
///
/// Engine wiring:
/// 1. Length-validates each guardian EVM address (20 B).
/// 2. Active-session gate (L4).
/// 3. Computes the merkle root via [`pangolin_chain::build_guardian_root`].
/// 4. Block-on-local: resolves `(env, chain_id)` and broadcasts
///    `setGuardianSet`. The active vault's `EvmWallet` self-bootstraps
///    as the initial `vaultAuthority`.
///
/// **L1.** `master_password` crosses behind the opaque
/// [`SecretPassword`] (forward-compat parity with the other Active-gated
/// chain-mutating bindings — the broadcast itself uses the engine-held
/// EVM signer, not the password). The signer never crosses out.
///
/// # Errors
///
/// - [`FfiError::Validation`] (`kind = "argument"`) for any
///   non-20-byte guardian address.
/// - [`FfiError::Session`] for a placeholder / Locked vault.
/// - [`FfiError::Chain`] for ANY chain-side failure (deployment-file
///   load, RPC connect, broadcast, receipt, or contract revert —
///   `ErrGuardianSetAlreadyInitialized` / `ErrThresholdOutOfBounds` /
///   `ErrGuardianCountOutOfBounds` / `ErrZeroValue`).
/// - [`FfiError::Store`] on an engine-side wallet/signing failure.
#[allow(clippy::significant_drop_tightening, clippy::needless_pass_by_value)]
#[uniffi::export]
pub fn vault_set_guardian_set(
    handle: Arc<VaultHandle>,
    master_password: Arc<SecretPassword>,
    config: FfiChainConfig,
    guardian_evm_addrs: Vec<Vec<u8>>,
    threshold: u8,
) -> Result<FfiTxOutcome, FfiError> {
    // Bridge + zeroize the password (consumed for forward-compat parity
    // with the rest of the chain-mutating surface).
    let mut pw = zeroize::Zeroizing::new(master_password.bytes_for_bridge().to_vec());
    let secret = SecretBytes::new(std::mem::take(&mut *pw));

    // Length-validate inputs BEFORE the L4 gate / chain ops so a malformed
    // host call fails fast.
    let addrs = collect_guardian_addrs(&guardian_evm_addrs, "guardian EVM address")?;
    if addrs.is_empty() {
        return Err(FfiError::Validation {
            kind: "argument".into(),
            message: "guardian_evm_addrs must be non-empty (contract requires \
                      MIN_GUARDIANS = 3; bounds checked on-chain)"
                .into(),
        });
    }
    let guardian_count = u8::try_from(addrs.len()).map_err(|_| FfiError::Validation {
        kind: "argument".into(),
        message: "guardian_evm_addrs length must fit in u8 (contract caps at MAX_GUARDIANS = 15)"
            .into(),
    })?;

    // L4 session gate BEFORE any chain primitive.
    let mut guard = handle.lock_vault();
    let vault = guard.as_mut()?;
    require_active(vault)?;
    let vault_id = vault.vault_id();
    let signer = vault.evm_wallet().map_err(store_into_ffi)?.signer().clone();

    // Engine computes the merkle root (Q-a: never host-supplied).
    let root = build_guardian_root(&addrs);

    let outcome = block_on_local(async {
        let (env, _chain_id) = crate::chain_config::ffi_chain_env_and_id(&config.rpc_url)
            .await
            .map_err(chain_into_ffi)?;
        let wallet = EvmWallet::from_signer(signer);
        let anchor = set_guardian_set_v1(
            &wallet,
            vault_id,
            root,
            threshold,
            guardian_count,
            env,
            &config.rpc_url,
        )
        .await
        .map_err(chain_into_ffi)?;
        Ok::<FfiTxOutcome, FfiError>(tx_outcome_from_anchor(anchor))
    })??;
    drop(secret);
    Ok(outcome)
}

// ---------------------------------------------------------------------------
// 2. vault_initiate_recovery — recovering device opens a PENDING attempt
// ---------------------------------------------------------------------------

/// **Active-gated.** Open the PENDING recovery attempt for `target_vault_id`,
/// driving [`pangolin_chain::initiate_recovery_v1`].
///
/// Per the plan: driven by the NEW (post-loss) device, which has a fresh
/// vault unlocked under its own master password BEFORE initiating recovery
/// on a target vault. The active session's `EvmWallet` is the gas-paying
/// signer; the contract is permissionless on the `initiate` step (the
/// 72h cancelable delay + the guardian quorum are the security gate).
///
/// # Errors
///
/// - [`FfiError::Validation`] (`kind = "argument"`) for a non-32-byte
///   `target_vault_id` or non-20-byte `proposed_authority`.
/// - [`FfiError::Session`] for a placeholder / Locked vault.
/// - [`FfiError::Chain`] for any chain-side failure (RPC, broadcast,
///   contract revert — e.g. `ErrRecoveryAlreadyPending`).
/// - [`FfiError::Store`] on an engine-side wallet/signing failure.
#[allow(clippy::significant_drop_tightening, clippy::needless_pass_by_value)]
#[uniffi::export]
pub fn vault_initiate_recovery(
    handle: Arc<VaultHandle>,
    master_password: Arc<SecretPassword>,
    config: FfiChainConfig,
    target_vault_id: Vec<u8>,
    proposed_authority: Vec<u8>,
    expires_at_unix: u64,
) -> Result<FfiTxOutcome, FfiError> {
    // The `expires_at_unix` parameter is documented in the plan + on the
    // shared binding shape but is consumed only by `approve_recovery`'s
    // EIP-712 signing path — `initiate_recovery_v1` itself does not take
    // an expiry. Accepted here for surface uniformity with the rest of
    // the lifecycle FFI; the chain-side contract has no `expiresAt`
    // field on `initiateRecovery`.
    let _ = expires_at_unix;

    let mut pw = zeroize::Zeroizing::new(master_password.bytes_for_bridge().to_vec());
    let secret = SecretBytes::new(std::mem::take(&mut *pw));

    let vault_id_arr: [u8; VAULT_ID_LEN] = fixed_bytes(&target_vault_id, "target_vault_id")?;
    let proposed_authority_arr: [u8; EVM_ADDRESS_LEN] =
        fixed_bytes(&proposed_authority, "proposed_authority")?;
    let proposed_authority_addr = Address::from(proposed_authority_arr);

    let mut guard = handle.lock_vault();
    let vault = guard.as_mut()?;
    require_active(vault)?;
    let signer = vault.evm_wallet().map_err(store_into_ffi)?.signer().clone();

    let outcome = block_on_local(async {
        let (env, _chain_id) = crate::chain_config::ffi_chain_env_and_id(&config.rpc_url)
            .await
            .map_err(chain_into_ffi)?;
        let wallet = EvmWallet::from_signer(signer);
        let anchor = initiate_recovery_v1(
            &wallet,
            vault_id_arr,
            proposed_authority_addr,
            env,
            &config.rpc_url,
        )
        .await
        .map_err(chain_into_ffi)?;
        Ok::<FfiTxOutcome, FfiError>(tx_outcome_from_anchor(anchor))
    })??;
    drop(secret);
    Ok(outcome)
}

// ---------------------------------------------------------------------------
// 3. vault_approve_recovery — guardian-side approval (engine computes proof)
// ---------------------------------------------------------------------------

/// **Active-gated.** Record one guardian approval against the live
/// PENDING attempt, driving [`pangolin_chain::approve_recovery_v1`].
///
/// The active vault is the GUARDIAN's vault — the engine pulls its
/// secp256k1 signer (`Vault::evm_wallet`), computes the leaf for THIS
/// signer and the merkle proof against the supplied `guardian_set`,
/// reads the LIVE PENDING attempt via
/// [`pangolin_chain::build_live_approve_fields_v1`] (L11 fail-closed:
/// refuses to build a digest if the on-chain status is not PENDING),
/// asserts the host-supplied `(attempt_nonce, proposed_authority)`
/// match the live values (fail-closed `Chain` on mismatch so the host
/// can re-fetch + re-confirm rather than signing a stale digest), and
/// signs the LIVE `(attempt_nonce, proposed_authority, expires_at)`
/// (Q-a — engine is the source of truth; host never holds derived
/// data). The contract enforces the merkle proof; if the active
/// signer isn't actually a guardian under the set, the broadcast
/// fails fast at the client-side pre-flight inside
/// [`pangolin_chain::approve_recovery_v1`] (`ErrInvalidMerkleProof` mirror).
///
/// No `master_password` param — the approval is a guardian-DEVICE
/// operation that doesn't re-wrap any local state. (Mirrors the
/// guardian's role: signature only, no vault-side mutation.)
///
/// # Errors
///
/// - [`FfiError::Validation`] (`kind = "argument"`) for bad length
///   inputs (`target_vault_id` ≠ 32 B, `proposed_authority` ≠ 20 B, or
///   any guardian address ≠ 20 B).
/// - [`FfiError::Session`] for a placeholder / Locked vault.
/// - [`FfiError::Chain`] for any chain-side failure: a doomed merkle
///   proof (pre-flight `ErrInvalidMerkleProof` mirror — active signer
///   not in the supplied set), RPC, broadcast, or contract revert
///   (`ErrInvalidSignature`, `ErrDuplicateApproval`, etc.).
/// - [`FfiError::Store`] on an engine-side wallet/signing failure.
#[allow(clippy::significant_drop_tightening, clippy::needless_pass_by_value)]
#[uniffi::export]
pub fn vault_approve_recovery(
    handle: Arc<VaultHandle>,
    config: FfiChainConfig,
    target_vault_id: Vec<u8>,
    attempt_nonce: u64,
    proposed_authority: Vec<u8>,
    expires_at_unix: u64,
    guardian_set: Vec<Vec<u8>>,
) -> Result<FfiTxOutcome, FfiError> {
    let vault_id_arr: [u8; VAULT_ID_LEN] = fixed_bytes(&target_vault_id, "target_vault_id")?;
    let proposed_authority_arr: [u8; EVM_ADDRESS_LEN] =
        fixed_bytes(&proposed_authority, "proposed_authority")?;
    let proposed_authority_addr = Address::from(proposed_authority_arr);
    let guardians = collect_guardian_addrs(&guardian_set, "guardian_set entry")?;
    if guardians.is_empty() {
        return Err(FfiError::Validation {
            kind: "argument".into(),
            message: "guardian_set must be non-empty".into(),
        });
    }

    // L4 session gate BEFORE any chain primitive (Active — the guardian
    // signs from THEIR OWN unlocked vault's signer).
    let mut guard = handle.lock_vault();
    let vault = guard.as_mut()?;
    require_active(vault)?;
    let signer = vault.evm_wallet().map_err(store_into_ffi)?.signer().clone();
    let guardian_addr = signer.address();

    // Engine computes the leaf + proof for THIS active signer against the
    // supplied set (Q-a). If the signer is not in the set, the proof
    // builder returns `None` — surface as Chain class so the failure mode
    // matches the contract's `ErrInvalidMerkleProof` revert (which is the
    // class the broadcast would otherwise have hit). Note: building a
    // proof and verifying it locally happens inside `approve_recovery_v1`
    // itself; here we only build it and pass it through.
    let proof =
        build_membership_proof(&guardians, guardian_addr).ok_or_else(|| FfiError::Chain {
            message: "active signer is not in the supplied guardian_set; the contract would \
                      revert ErrInvalidMerkleProof on broadcast"
                .into(),
        })?;
    let root = build_guardian_root(&guardians);

    let outcome = block_on_local(async {
        let (env, chain_id) = crate::chain_config::ffi_chain_env_and_id(&config.rpc_url)
            .await
            .map_err(chain_into_ffi)?;
        let contract =
            pangolin_chain::load_deployed_address(env, pangolin_chain::RECOVERY_CONTRACT_NAME)
                .map_err(chain_into_ffi)?;

        // Read the LIVE PENDING attempt via `build_live_approve_fields_v1`
        // (L11 fail-closed: refuses to build a digest if the on-chain
        // status is not PENDING). The host's `(attempt_nonce,
        // proposed_authority)` params are then asserted against the live
        // values — a mismatch means the on-chain state shifted between
        // the host's intent-formation and this call (a new attempt
        // started, the prior was finalized/cancelled, etc.); fail-closed
        // `Chain` so the host can re-fetch + re-confirm instead of
        // signing a stale digest. Plan Q-a / "engine is source of truth".
        let live_fields =
            build_live_approve_fields_v1(env, &config.rpc_url, vault_id_arr, expires_at_unix)
                .await
                .map_err(chain_into_ffi)?;
        if live_fields.attempt_nonce != attempt_nonce
            || live_fields.proposed_authority != proposed_authority_addr
        {
            return Err(FfiError::Chain {
                message: format!(
                    "approve_recovery: host-supplied (attempt_nonce={attempt_nonce}, \
                     proposed_authority={proposed_authority_addr}) does not match the LIVE \
                     PENDING attempt (attempt_nonce={}, proposed_authority={}); on-chain state \
                     shifted — host must re-read recovery status before re-approving",
                    live_fields.attempt_nonce, live_fields.proposed_authority
                ),
            });
        }
        let signed_approval = build_signed_approval_v1(&signer, live_fields, contract, chain_id)
            .map_err(chain_into_ffi)?;

        let wallet = EvmWallet::from_signer(signer.clone());
        let anchor = approve_recovery_v1(
            &wallet,
            guardian_addr,
            &proof,
            root,
            &signed_approval,
            env,
            &config.rpc_url,
        )
        .await
        .map_err(chain_into_ffi)?;
        Ok::<FfiTxOutcome, FfiError>(tx_outcome_from_anchor(anchor))
    })??;
    Ok(outcome)
}

// ---------------------------------------------------------------------------
// 4. vault_cancel_recovery — authority-only abort
// ---------------------------------------------------------------------------

/// **Active-gated.** Abort the live PENDING attempt; driving
/// [`pangolin_chain::cancel_recovery_v1`].
///
/// The contract enforces `msg.sender == vaultAuthority`
/// (`ErrNotAuthorizedToCancel` otherwise). The FFI does NOT pre-check
/// this — the chain layer is the authoritative gate; a non-authority
/// caller surfaces a [`FfiError::Chain`] for the revert.
///
/// # Errors
///
/// - [`FfiError::Validation`] (`kind = "argument"`) for a non-32-byte
///   `target_vault_id`.
/// - [`FfiError::Session`] for a placeholder / Locked vault.
/// - [`FfiError::Chain`] for any chain-side failure (RPC, broadcast,
///   `ErrNotAuthorizedToCancel`, `ErrNoActiveRecovery`).
/// - [`FfiError::Store`] on an engine-side wallet/signing failure.
#[allow(clippy::significant_drop_tightening, clippy::needless_pass_by_value)]
#[uniffi::export]
pub fn vault_cancel_recovery(
    handle: Arc<VaultHandle>,
    master_password: Arc<SecretPassword>,
    config: FfiChainConfig,
    target_vault_id: Vec<u8>,
) -> Result<FfiTxOutcome, FfiError> {
    let mut pw = zeroize::Zeroizing::new(master_password.bytes_for_bridge().to_vec());
    let secret = SecretBytes::new(std::mem::take(&mut *pw));

    let vault_id_arr: [u8; VAULT_ID_LEN] = fixed_bytes(&target_vault_id, "target_vault_id")?;

    let mut guard = handle.lock_vault();
    let vault = guard.as_mut()?;
    require_active(vault)?;
    let signer = vault.evm_wallet().map_err(store_into_ffi)?.signer().clone();

    let outcome = block_on_local(async {
        let (env, _chain_id) = crate::chain_config::ffi_chain_env_and_id(&config.rpc_url)
            .await
            .map_err(chain_into_ffi)?;
        let wallet = EvmWallet::from_signer(signer);
        let anchor = cancel_recovery_v1(&wallet, vault_id_arr, env, &config.rpc_url)
            .await
            .map_err(chain_into_ffi)?;
        Ok::<FfiTxOutcome, FfiError>(tx_outcome_from_anchor(anchor))
    })??;
    drop(secret);
    Ok(outcome)
}

// ---------------------------------------------------------------------------
// 5. vault_finalize_recovery — permissionless completion (loaded-only)
// ---------------------------------------------------------------------------

/// **Loaded-only (NOT Active-gated).** Complete the lifecycle:
/// PENDING → FINALIZED, rotating `vaultAuthority` to `proposedAuthority`.
/// Drives [`pangolin_chain::finalize_recovery_v1`].
///
/// Per the plan (Q-c) the session gate relaxes here: any device with a
/// configured RPC + the target `vault_id` may finalize after the 72h
/// delay (the contract enforces the timing + the threshold). A Locked
/// vault is acceptable so a recovery can finalize even if the local
/// session has expired.
///
/// The active session is still required to source a gas-paying signer
/// (`Vault::evm_wallet()` requires Active in `pangolin-store`). On a
/// Locked vault the binding still proceeds past the L4 relaxation and
/// fails at the wallet read instead — surface as `FfiError::Store` /
/// `FfiError::Session` (the engine's mapping).
///
/// Note (Q-c amendment, observed during the #108 build): `evm_wallet()`
/// returns `StoreError::NotUnlocked` on a Locked vault. The store
/// mapping collapses this to `FfiError::Session`. The L4 RELAXATION
/// here is for the `as_mut()?` step (placeholder rejection only); the
/// chain layer itself still needs a signer that lives in an Active
/// session. A guardian doing the finalize from a Locked vault is
/// therefore unsupported under the current `Vault` model — a follow-up
/// could expose a non-session-gated signer (e.g. a re-derivable ephemeral
/// signer for finalize-only) but that is out of scope.
///
/// # Errors
///
/// - [`FfiError::Validation`] (`kind = "argument"`) for a non-32-byte
///   `target_vault_id`.
/// - [`FfiError::Session`] for a placeholder handle.
/// - [`FfiError::Chain`] for any chain-side failure (RPC, broadcast,
///   `ErrDelayNotElapsed`, `ErrThresholdNotMet`).
/// - [`FfiError::Store`] on an engine-side wallet/signing failure.
#[allow(clippy::significant_drop_tightening, clippy::needless_pass_by_value)]
#[uniffi::export]
pub fn vault_finalize_recovery(
    handle: Arc<VaultHandle>,
    config: FfiChainConfig,
    target_vault_id: Vec<u8>,
) -> Result<FfiTxOutcome, FfiError> {
    let vault_id_arr: [u8; VAULT_ID_LEN] = fixed_bytes(&target_vault_id, "target_vault_id")?;

    // L4 RELAXATION: `as_mut()?` only — no Active gate. A Locked vault is
    // accepted here at the FFI layer; the underlying `evm_wallet()` will
    // still reject if Locked (see binding doc). Placeholder handles fail
    // at `as_mut()?`.
    let mut guard = handle.lock_vault();
    let vault = guard.as_mut()?;
    let signer = vault.evm_wallet().map_err(store_into_ffi)?.signer().clone();

    let outcome = block_on_local(async {
        let (env, _chain_id) = crate::chain_config::ffi_chain_env_and_id(&config.rpc_url)
            .await
            .map_err(chain_into_ffi)?;
        let wallet = EvmWallet::from_signer(signer);
        let anchor = finalize_recovery_v1(&wallet, vault_id_arr, env, &config.rpc_url)
            .await
            .map_err(chain_into_ffi)?;
        Ok::<FfiTxOutcome, FfiError>(tx_outcome_from_anchor(anchor))
    })??;
    Ok(outcome)
}

// ---------------------------------------------------------------------------
// 6. vault_read_vault_authority — current `vaultAuthority(vaultId)`
// ---------------------------------------------------------------------------

/// **Loaded-handle (placeholder-gated only).** Read the current on-chain
/// `vaultAuthority(target_vault_id)`. Drives
/// [`pangolin_chain::read_vault_authority_v1`].
///
/// Fail-closed on chain-read errors per L3: any RPC / deployment failure
/// returns [`FfiError::Chain`], never `Address::ZERO`.
///
/// # Errors
///
/// - [`FfiError::Validation`] (`kind = "argument"`) for a non-32-byte
///   `target_vault_id`.
/// - [`FfiError::Session`] for a placeholder handle.
/// - [`FfiError::Chain`] for any chain-side read failure.
#[allow(clippy::significant_drop_tightening, clippy::needless_pass_by_value)]
#[uniffi::export]
pub fn vault_read_vault_authority(
    handle: Arc<VaultHandle>,
    config: FfiChainConfig,
    target_vault_id: Vec<u8>,
) -> Result<FfiVaultAuthority, FfiError> {
    let vault_id_arr: [u8; VAULT_ID_LEN] = fixed_bytes(&target_vault_id, "target_vault_id")?;

    // Placeholder rejection only (Q-b: handle is required for future
    // telemetry / placeholder gating but no Active check).
    let mut guard = handle.lock_vault();
    let _vault = guard.as_mut()?;
    drop(guard);

    let address = block_on_local(async {
        let (env, _chain_id) = crate::chain_config::ffi_chain_env_and_id(&config.rpc_url)
            .await
            .map_err(chain_into_ffi)?;
        read_vault_authority_v1(env, &config.rpc_url, vault_id_arr)
            .await
            .map_err(chain_into_ffi)
    })??;
    Ok(FfiVaultAuthority {
        address: address.into_array().to_vec(),
        schema_version: RECOVERY_LIFECYCLE_FFI_SCHEMA_VERSION,
    })
}

// ---------------------------------------------------------------------------
// 7. vault_read_recovery_status — live attempt slot
// ---------------------------------------------------------------------------

/// **Loaded-handle (placeholder-gated only).** Read the live recovery
/// attempt slot for `target_vault_id`. Drives
/// [`pangolin_chain::read_live_attempt_v1`].
///
/// Fail-closed on chain-read errors per L3.
///
/// Note: the chain-side `LiveAttemptV1` view does not (yet) expose
/// `initiatedAt` or `approvals`; these surface as `0` here. The
/// `RecoveryV1.recovery()` view returns them, so a future chain-side
/// expansion is mechanical; for #108 the binding surfaces what the
/// existing client primitive returns and pins the FFI record shape
/// against the eventual expansion via `schema_version`. (Flagged below
/// in #108's surrounding-code notes.)
///
/// # Errors
///
/// - [`FfiError::Validation`] (`kind = "argument"`) for a non-32-byte
///   `target_vault_id`.
/// - [`FfiError::Session`] for a placeholder handle.
/// - [`FfiError::Chain`] for any chain-side read failure.
#[allow(clippy::significant_drop_tightening, clippy::needless_pass_by_value)]
#[uniffi::export]
pub fn vault_read_recovery_status(
    handle: Arc<VaultHandle>,
    config: FfiChainConfig,
    target_vault_id: Vec<u8>,
) -> Result<FfiRecoveryStatus, FfiError> {
    let vault_id_arr: [u8; VAULT_ID_LEN] = fixed_bytes(&target_vault_id, "target_vault_id")?;

    let mut guard = handle.lock_vault();
    let _vault = guard.as_mut()?;
    drop(guard);

    let live = block_on_local(async {
        let (env, _chain_id) = crate::chain_config::ffi_chain_env_and_id(&config.rpc_url)
            .await
            .map_err(chain_into_ffi)?;
        read_live_attempt_v1(env, &config.rpc_url, vault_id_arr)
            .await
            .map_err(chain_into_ffi)
    })??;
    Ok(FfiRecoveryStatus {
        status: live.status,
        proposed_authority: live.proposed_authority.into_array().to_vec(),
        attempt_nonce: live.attempt_nonce,
        initiated_at: 0,
        approval_count: 0,
        schema_version: RECOVERY_LIFECYCLE_FFI_SCHEMA_VERSION,
    })
}

// ---------------------------------------------------------------------------
// Tests — hermetic only (no chain). The lifecycle is anvil-covered by
// `pangolin_chain::recovery_client::tests::recovery_lifecycle_against_anvil`.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain_config::FFI_CHAIN_CONFIG_SCHEMA_VERSION;
    use pangolin_store::{PinIdentityProof, PressYPresenceProof, Vault};

    fn pwd_bytes() -> Vec<u8> {
        b"correct horse battery staple".to_vec()
    }

    fn unlocked_handle(dir: &tempfile::TempDir, name: &str) -> Arc<VaultHandle> {
        let path = dir.path().join(name);
        Vault::create(&path, &SecretBytes::new(pwd_bytes())).unwrap();
        let mut v = Vault::open(&path).unwrap();
        v.unlock(
            &PressYPresenceProof::confirmed(),
            &PinIdentityProof::new(SecretBytes::new(pwd_bytes())),
        )
        .unwrap();
        VaultHandle::from_vault(v)
    }

    fn locked_handle(dir: &tempfile::TempDir, name: &str) -> Arc<VaultHandle> {
        let h = unlocked_handle(dir, name);
        {
            let mut g = h.lock_vault();
            g.as_mut().unwrap().lock();
        }
        h
    }

    fn bogus_config() -> FfiChainConfig {
        FfiChainConfig {
            schema_version: FFI_CHAIN_CONFIG_SCHEMA_VERSION,
            rpc_url: "http://127.0.0.1:1".into(),
            deployment_path: "/no/such/path/base-sepolia.json".into(),
            prefer_websocket: false,
        }
    }

    fn good_vault_id() -> Vec<u8> {
        vec![0u8; VAULT_ID_LEN]
    }

    fn good_addr() -> Vec<u8> {
        vec![0u8; EVM_ADDRESS_LEN]
    }

    fn good_guardian_set() -> Vec<Vec<u8>> {
        // 3 distinct addresses (the contract's MIN_GUARDIANS floor).
        vec![
            vec![0x01u8; EVM_ADDRESS_LEN],
            vec![0x02u8; EVM_ADDRESS_LEN],
            vec![0x03u8; EVM_ADDRESS_LEN],
        ]
    }

    // -----------------------------------------------------------------
    // Length-validation negatives — all 5 mutating + 2 read bindings.
    // -----------------------------------------------------------------

    /// `set_guardian_set`: a non-20-byte guardian address surfaces as
    /// `Validation { kind: "argument" }` BEFORE any chain hit.
    #[test]
    fn set_guardian_set_rejects_bad_guardian_addr_length() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        let bad = vec![vec![0u8; 19], vec![0u8; 20], vec![0u8; 20]];
        let err =
            vault_set_guardian_set(h, SecretPassword::new(pwd_bytes()), bogus_config(), bad, 2)
                .unwrap_err();
        assert!(matches!(err, FfiError::Validation { ref kind, .. } if kind == "argument"));
    }

    /// `set_guardian_set`: empty guardian set rejected.
    #[test]
    fn set_guardian_set_rejects_empty_set() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        let err = vault_set_guardian_set(
            h,
            SecretPassword::new(pwd_bytes()),
            bogus_config(),
            Vec::new(),
            2,
        )
        .unwrap_err();
        assert!(matches!(err, FfiError::Validation { ref kind, .. } if kind == "argument"));
    }

    /// `initiate_recovery`: bad vault_id length.
    #[test]
    fn initiate_recovery_rejects_bad_vault_id_length() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        let err = vault_initiate_recovery(
            h,
            SecretPassword::new(pwd_bytes()),
            bogus_config(),
            vec![0u8; 31],
            good_addr(),
            0,
        )
        .unwrap_err();
        assert!(matches!(err, FfiError::Validation { ref kind, .. } if kind == "argument"));
    }

    /// `initiate_recovery`: bad proposed_authority length.
    #[test]
    fn initiate_recovery_rejects_bad_proposed_authority_length() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        let err = vault_initiate_recovery(
            h,
            SecretPassword::new(pwd_bytes()),
            bogus_config(),
            good_vault_id(),
            vec![0u8; 19],
            0,
        )
        .unwrap_err();
        assert!(matches!(err, FfiError::Validation { ref kind, .. } if kind == "argument"));
    }

    /// `approve_recovery`: bad vault_id length.
    #[test]
    fn approve_recovery_rejects_bad_vault_id_length() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        let err = vault_approve_recovery(
            h,
            bogus_config(),
            vec![0u8; 31],
            0,
            good_addr(),
            0,
            good_guardian_set(),
        )
        .unwrap_err();
        assert!(matches!(err, FfiError::Validation { ref kind, .. } if kind == "argument"));
    }

    /// `approve_recovery`: bad guardian-set member length.
    #[test]
    fn approve_recovery_rejects_bad_guardian_set_member_length() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        let bad_set = vec![vec![0u8; 20], vec![0u8; 19], vec![0u8; 20]];
        let err = vault_approve_recovery(
            h,
            bogus_config(),
            good_vault_id(),
            0,
            good_addr(),
            0,
            bad_set,
        )
        .unwrap_err();
        assert!(matches!(err, FfiError::Validation { ref kind, .. } if kind == "argument"));
    }

    /// `approve_recovery`: bad proposed_authority length.
    #[test]
    fn approve_recovery_rejects_bad_proposed_authority_length() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        let err = vault_approve_recovery(
            h,
            bogus_config(),
            good_vault_id(),
            0,
            vec![0u8; 21],
            0,
            good_guardian_set(),
        )
        .unwrap_err();
        assert!(matches!(err, FfiError::Validation { ref kind, .. } if kind == "argument"));
    }

    /// `approve_recovery`: empty guardian_set rejected.
    #[test]
    fn approve_recovery_rejects_empty_guardian_set() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        let err = vault_approve_recovery(
            h,
            bogus_config(),
            good_vault_id(),
            0,
            good_addr(),
            0,
            Vec::new(),
        )
        .unwrap_err();
        assert!(matches!(err, FfiError::Validation { ref kind, .. } if kind == "argument"));
    }

    /// `cancel_recovery`: bad vault_id length.
    #[test]
    fn cancel_recovery_rejects_bad_vault_id_length() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        let err = vault_cancel_recovery(
            h,
            SecretPassword::new(pwd_bytes()),
            bogus_config(),
            vec![0u8; 31],
        )
        .unwrap_err();
        assert!(matches!(err, FfiError::Validation { ref kind, .. } if kind == "argument"));
    }

    /// `finalize_recovery`: bad vault_id length.
    #[test]
    fn finalize_recovery_rejects_bad_vault_id_length() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        let err = vault_finalize_recovery(h, bogus_config(), vec![0u8; 31]).unwrap_err();
        assert!(matches!(err, FfiError::Validation { ref kind, .. } if kind == "argument"));
    }

    /// `read_vault_authority`: bad vault_id length.
    #[test]
    fn read_vault_authority_rejects_bad_vault_id_length() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        let err = vault_read_vault_authority(h, bogus_config(), vec![0u8; 31]).unwrap_err();
        assert!(matches!(err, FfiError::Validation { ref kind, .. } if kind == "argument"));
    }

    /// `read_recovery_status`: bad vault_id length.
    #[test]
    fn read_recovery_status_rejects_bad_vault_id_length() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        let err = vault_read_recovery_status(h, bogus_config(), vec![0u8; 31]).unwrap_err();
        assert!(matches!(err, FfiError::Validation { ref kind, .. } if kind == "argument"));
    }

    // -----------------------------------------------------------------
    // Session-gate negatives — each Active-gated binding rejects Locked
    // and Placeholder; `finalize` accepts Locked but rejects Placeholder
    // (engine-side `evm_wallet()` on a Locked vault collapses to
    // FfiError::Session via the store-mapping, which matches the L4
    // intent — the binding itself accepts Locked but the chain step
    // requires a session-held signer); reads accept Locked but reject
    // Placeholder.
    // -----------------------------------------------------------------

    /// `set_guardian_set` on a Locked vault → Session.
    #[test]
    fn set_guardian_set_rejects_locked() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = locked_handle(&dir, "v.pvf");
        let err = vault_set_guardian_set(
            h,
            SecretPassword::new(pwd_bytes()),
            bogus_config(),
            good_guardian_set(),
            2,
        )
        .unwrap_err();
        assert!(matches!(err, FfiError::Session { .. }));
    }

    /// `set_guardian_set` on a placeholder → Session.
    #[test]
    fn set_guardian_set_rejects_placeholder() {
        let empty = VaultHandle::new_placeholder();
        let err = vault_set_guardian_set(
            empty,
            SecretPassword::new(pwd_bytes()),
            bogus_config(),
            good_guardian_set(),
            2,
        )
        .unwrap_err();
        assert!(matches!(err, FfiError::Session { .. }));
    }

    /// `initiate_recovery` on a Locked vault → Session.
    #[test]
    fn initiate_recovery_rejects_locked() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = locked_handle(&dir, "v.pvf");
        let err = vault_initiate_recovery(
            h,
            SecretPassword::new(pwd_bytes()),
            bogus_config(),
            good_vault_id(),
            good_addr(),
            0,
        )
        .unwrap_err();
        assert!(matches!(err, FfiError::Session { .. }));
    }

    /// `initiate_recovery` on a placeholder → Session.
    #[test]
    fn initiate_recovery_rejects_placeholder() {
        let empty = VaultHandle::new_placeholder();
        let err = vault_initiate_recovery(
            empty,
            SecretPassword::new(pwd_bytes()),
            bogus_config(),
            good_vault_id(),
            good_addr(),
            0,
        )
        .unwrap_err();
        assert!(matches!(err, FfiError::Session { .. }));
    }

    /// `approve_recovery` on a Locked vault → Session.
    #[test]
    fn approve_recovery_rejects_locked() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = locked_handle(&dir, "v.pvf");
        let err = vault_approve_recovery(
            h,
            bogus_config(),
            good_vault_id(),
            0,
            good_addr(),
            0,
            good_guardian_set(),
        )
        .unwrap_err();
        assert!(matches!(err, FfiError::Session { .. }));
    }

    /// `approve_recovery` on a placeholder → Session.
    #[test]
    fn approve_recovery_rejects_placeholder() {
        let empty = VaultHandle::new_placeholder();
        let err = vault_approve_recovery(
            empty,
            bogus_config(),
            good_vault_id(),
            0,
            good_addr(),
            0,
            good_guardian_set(),
        )
        .unwrap_err();
        assert!(matches!(err, FfiError::Session { .. }));
    }

    /// `cancel_recovery` on a Locked vault → Session.
    #[test]
    fn cancel_recovery_rejects_locked() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = locked_handle(&dir, "v.pvf");
        let err = vault_cancel_recovery(
            h,
            SecretPassword::new(pwd_bytes()),
            bogus_config(),
            good_vault_id(),
        )
        .unwrap_err();
        assert!(matches!(err, FfiError::Session { .. }));
    }

    /// `cancel_recovery` on a placeholder → Session.
    #[test]
    fn cancel_recovery_rejects_placeholder() {
        let empty = VaultHandle::new_placeholder();
        let err = vault_cancel_recovery(
            empty,
            SecretPassword::new(pwd_bytes()),
            bogus_config(),
            good_vault_id(),
        )
        .unwrap_err();
        assert!(matches!(err, FfiError::Session { .. }));
    }

    /// `finalize_recovery` on a placeholder → Session (`as_mut()?`
    /// rejects the placeholder; this is the only L4 gate finalize
    /// performs).
    #[test]
    fn finalize_recovery_rejects_placeholder() {
        let empty = VaultHandle::new_placeholder();
        let err = vault_finalize_recovery(empty, bogus_config(), good_vault_id()).unwrap_err();
        assert!(matches!(err, FfiError::Session { .. }));
    }

    /// `finalize_recovery` on a Locked vault: the FFI L4 gate is
    /// relaxed (Q-c), so `as_mut()?` succeeds; the chain step then
    /// requires `evm_wallet()` which the store collapses to Session on a
    /// Locked vault. Either way the error is structurally Session — the
    /// load-bearing property is that finalize is NOT chain-class on a
    /// Locked vault (it never reaches RPC). A future signer-without-
    /// session API could unblock this; the assertion documents today's
    /// behaviour.
    #[test]
    fn finalize_recovery_session_class_on_locked() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = locked_handle(&dir, "v.pvf");
        let err = vault_finalize_recovery(h, bogus_config(), good_vault_id()).unwrap_err();
        assert!(
            matches!(err, FfiError::Session { .. }),
            "finalize on Locked: Session class (no chain RPC), got {err:?}"
        );
    }

    /// `read_vault_authority` accepts Locked but rejects Placeholder.
    /// On Locked it proceeds to the chain step and fails fail-closed
    /// with `FfiError::Chain` against the bogus RPC (L3).
    #[test]
    fn read_vault_authority_accepts_locked_fails_closed_on_bad_rpc() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = locked_handle(&dir, "v.pvf");
        let err = vault_read_vault_authority(h, bogus_config(), good_vault_id()).unwrap_err();
        assert!(
            matches!(err, FfiError::Chain { .. }),
            "read_vault_authority on Locked must fail-closed at the chain layer, got {err:?}"
        );
    }

    /// `read_vault_authority` on a placeholder → Session.
    #[test]
    fn read_vault_authority_rejects_placeholder() {
        let empty = VaultHandle::new_placeholder();
        let err = vault_read_vault_authority(empty, bogus_config(), good_vault_id()).unwrap_err();
        assert!(matches!(err, FfiError::Session { .. }));
    }

    /// `read_recovery_status` accepts Locked but rejects Placeholder.
    /// On Locked it proceeds to the chain step and fails fail-closed.
    #[test]
    fn read_recovery_status_accepts_locked_fails_closed_on_bad_rpc() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = locked_handle(&dir, "v.pvf");
        let err = vault_read_recovery_status(h, bogus_config(), good_vault_id()).unwrap_err();
        assert!(
            matches!(err, FfiError::Chain { .. }),
            "read_recovery_status on Locked must fail-closed at the chain layer, got {err:?}"
        );
    }

    /// `read_recovery_status` on a placeholder → Session.
    #[test]
    fn read_recovery_status_rejects_placeholder() {
        let empty = VaultHandle::new_placeholder();
        let err = vault_read_recovery_status(empty, bogus_config(), good_vault_id()).unwrap_err();
        assert!(matches!(err, FfiError::Session { .. }));
    }

    // -----------------------------------------------------------------
    // Fail-closed-on-bad-RPC: each chain-mutating binding fails with
    // `FfiError::Chain` once past the L4 gate (mirrors pairing.rs +
    // rotation_ffi.rs's `bogus_config` discipline). Confirms the
    // binding actually reaches the chain layer — the L4 gate is not the
    // only thing keeping the binding in Session territory.
    // -----------------------------------------------------------------

    /// `set_guardian_set` against a bogus RPC on Active → Chain.
    #[test]
    fn set_guardian_set_fails_closed_on_bad_rpc() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        let err = vault_set_guardian_set(
            h,
            SecretPassword::new(pwd_bytes()),
            bogus_config(),
            good_guardian_set(),
            2,
        )
        .unwrap_err();
        assert!(
            matches!(err, FfiError::Chain { .. }),
            "expected chain failure once L4 cleared, got {err:?}"
        );
    }

    /// `initiate_recovery` against a bogus RPC on Active → Chain.
    #[test]
    fn initiate_recovery_fails_closed_on_bad_rpc() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        let err = vault_initiate_recovery(
            h,
            SecretPassword::new(pwd_bytes()),
            bogus_config(),
            good_vault_id(),
            good_addr(),
            0,
        )
        .unwrap_err();
        assert!(
            matches!(err, FfiError::Chain { .. }),
            "expected chain failure once L4 cleared, got {err:?}"
        );
    }

    /// `approve_recovery` against a bogus RPC: the active signer is
    /// (overwhelmingly likely) not in the supplied guardian_set, so the
    /// engine-side proof builder collapses the call to `FfiError::Chain`
    /// (the `ErrInvalidMerkleProof` mirror). The point of this test is
    /// that the binding gets PAST the L4 gate to the engine-side merkle
    /// machinery (no Validation, no Session) — the chain class for a
    /// not-in-set signer is the documented surface.
    #[test]
    fn approve_recovery_fails_chain_class_for_not_in_set_signer() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        // The active signer's address is derived from a freshly-created
        // vault; the chance it collides with one of `good_guardian_set()`'s
        // pinned 0x01/0x02/0x03 fixtures is negligibly small.
        let err = vault_approve_recovery(
            h,
            bogus_config(),
            good_vault_id(),
            0,
            good_addr(),
            0,
            good_guardian_set(),
        )
        .unwrap_err();
        assert!(
            matches!(err, FfiError::Chain { .. }),
            "expected chain failure (signer-not-in-set mirror) once L4 cleared, got {err:?}"
        );
    }

    /// `cancel_recovery` against a bogus RPC on Active → Chain.
    #[test]
    fn cancel_recovery_fails_closed_on_bad_rpc() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        let err = vault_cancel_recovery(
            h,
            SecretPassword::new(pwd_bytes()),
            bogus_config(),
            good_vault_id(),
        )
        .unwrap_err();
        assert!(
            matches!(err, FfiError::Chain { .. }),
            "expected chain failure once L4 cleared, got {err:?}"
        );
    }

    /// `finalize_recovery` against a bogus RPC on Active → Chain.
    #[test]
    fn finalize_recovery_fails_closed_on_bad_rpc_when_active() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        let err = vault_finalize_recovery(h, bogus_config(), good_vault_id()).unwrap_err();
        assert!(
            matches!(err, FfiError::Chain { .. }),
            "expected chain failure on Active, got {err:?}"
        );
    }
}
