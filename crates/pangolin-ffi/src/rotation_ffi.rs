// SPDX-License-Identifier: AGPL-3.0-or-later
//! **MVP-3 issue #106e-1: the thin uniffi layer over the #106e-0 rotation
//! composition — pending-rotation read + complete-rotation bindings.**
//!
//! - [`vault_pending_rotations`] — read the crash-durable rotation-pending
//!   rows so the host can render "rotation pending — enter master password".
//! - [`vault_complete_rotation`] — drive
//!   [`pangolin_core::composition::complete_rotation`]. Per §0a Q-b the ENGINE
//!   reads the live on-chain authorized set ITSELF (fail-closed) — a buggy /
//!   malicious host cannot inject a wrong set that strands a survivor or skips
//!   a revocation.
//!
//! ## The async fail-closed set-read (Q-b)
//!
//! `complete_rotation` is SYNC, but obtaining its `current_onchain_set` (the
//! live `RevisionLogV2` authorized set) is an async chain READ. The binding
//! mirrors [`crate::session::vault_lock_with_drain`] / `vault_pull_once`:
//! `ChainEnv` is hardcoded `BaseSepolia` (testnet-only / D-011, never crossed
//! FFI), and [`crate::chain_config::block_on_local`] drives the `!Send`
//! [`pangolin_chain::read_authorized_set_v2`] future to completion on a local
//! current-thread runtime. The read is **FAIL-CLOSED**: any chain error
//! (connect / chain-id / `eth_getLogs` / missing deployment / view) returns
//! [`FfiError::Chain`] and the rotation NEVER proceeds with a guessed / empty
//! / partial set. The set is read FIRST (releasing the borrow), THEN the sync
//! `complete_rotation` runs (the borrow dance).
//!
//! The master password crosses IN behind the opaque
//! [`crate::session::SecretPassword`] Object; nothing secret crosses OUT
//! (only the new epoch + the non-secret unknown-survivor signer list).

#![forbid(unsafe_code)]

use std::sync::Arc;

use pangolin_crypto::secret::SecretBytes;

use crate::error::FfiError;
use crate::recovery_ffi::{composition_error_into_ffi, RECOVERY_FFI_SCHEMA_VERSION};
use crate::session::{SecretPassword, VaultHandle};

/// Wire-form length of a 20-byte secp256k1 signer (the EVM address form).
const SIGNER_LEN: usize = pangolin_core::EVM_ADDRESS_LEN;

fn store_into_ffi(err: pangolin_store::StoreError) -> FfiError {
    FfiError::from(pangolin_core::Error::from(err))
}

/// One outstanding rotation-pending row.
///
/// Mirrors [`pangolin_store::RotationPending`] (a device was removed on-chain
/// and the local VDK gap has NOT yet been closed by a rotation). All
/// non-secret.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiRotationPending {
    /// The 20-byte secp256k1 signer that was removed on-chain.
    pub removed_signer: Vec<u8>,
    /// The vault epoch observed at detection time.
    pub observed_epoch: u64,
    /// Wall-clock unix-ms observation time. (The store row is signed `i64`
    /// ms-since-epoch; observation times are always non-negative, so the
    /// `u64` widening is loss-free for any real timestamp.)
    pub observed_at: u64,
    /// Schema-version slot.
    pub schema_version: u16,
}

/// Non-secret result of [`vault_complete_rotation`].
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiRotationResult {
    /// The advanced shared per-vault epoch the rotation landed at.
    pub new_epoch: u64,
    /// GAP-A: in-set survivors (20-byte signers) whose pairing pubkey the
    /// LOCAL directory does not yet know — surfaced, never silently stranded.
    /// Each entry is exactly 20 bytes.
    pub unknown_survivors: Vec<Vec<u8>>,
    /// Schema-version slot.
    pub schema_version: u16,
}

/// **Read the crash-durable rotation-pending rows** — drives
/// [`pangolin_store::Vault::pending_rotations`].
///
/// Session-gated. Non-secret. The host renders "rotation pending — enter
/// master password" off these rows, then calls [`vault_complete_rotation`].
///
/// # Errors
///
/// - [`FfiError::Session`] for a locked / placeholder handle.
/// - [`FfiError::Store`] on a DB error.
#[allow(clippy::significant_drop_tightening)]
#[uniffi::export]
pub fn vault_pending_rotations(
    handle: Arc<VaultHandle>,
) -> Result<Vec<FfiRotationPending>, FfiError> {
    let mut guard = handle.lock_vault();
    let vault = guard.as_mut()?;
    let pending = vault.pending_rotations().map_err(store_into_ffi)?;
    Ok(pending
        .into_iter()
        .map(|p| FfiRotationPending {
            removed_signer: p.removed_signer.to_vec(),
            observed_epoch: p.observed_epoch,
            // i64 ms-since-epoch → u64; clamp a (never-expected) negative to 0.
            observed_at: u64::try_from(p.observed_at).unwrap_or(0),
            schema_version: RECOVERY_FFI_SCHEMA_VERSION,
        })
        .collect())
}

/// **Complete a VDK rotation after a device revoke** — drives
/// [`pangolin_core::composition::complete_rotation`].
///
/// Session-gated (Active — the rotation re-keys against the current session's
/// VDK store-internal). The master password crosses IN behind the opaque
/// [`SecretPassword`] Object. Per §0a Q-b the engine READS the live
/// authorized set itself (fail-closed) — the host supplies only the chain
/// `config` (RPC URL), never the set.
///
/// Out: [`FfiRotationResult`] — the new epoch + the GAP-A unknown-survivor
/// signer list (non-secret). Nothing secret crosses out.
///
/// # Errors
///
/// - [`FfiError::Session`] for a locked / placeholder handle (the L4 gate,
///   BEFORE any chain primitive).
/// - [`FfiError::Chain`] for ANY live-set read failure (fail-closed — the
///   rotation never proceeds against a guessed / empty / partial set).
/// - [`FfiError::Recovery`] / [`FfiError::Validation`] (`authentication`) /
///   [`FfiError::Store`] for a composition failure (see
///   `composition_error_into_ffi`).
#[allow(clippy::significant_drop_tightening, clippy::needless_pass_by_value)]
#[uniffi::export]
pub fn vault_complete_rotation(
    handle: Arc<VaultHandle>,
    master_password: Arc<SecretPassword>,
    config: crate::chain_config::FfiChainConfig,
) -> Result<FfiRotationResult, FfiError> {
    // Bridge the password engine-side into a zeroizing SecretBytes.
    let mut pw = zeroize::Zeroizing::new(master_password.bytes_for_bridge().to_vec());
    let secret = SecretBytes::new(std::mem::take(&mut *pw));

    // Active-session gate at the FFI boundary (L4), BEFORE any chain primitive.
    // `as_mut()?` rejects a handle with no vault loaded; additionally require an
    // ACTIVE (unlocked) session — `complete_rotation` reads the escrow params +
    // re-keys via the active VDK, so a locked vault cannot proceed. Fail fast
    // with Session here so we never spend a chain RPC on a locked vault.
    let mut guard = handle.lock_vault();
    let vault = guard.as_mut()?;
    if vault.state() != pangolin_store::VaultState::Active {
        return Err(FfiError::Session {
            message: "vault is not unlocked".to_owned(),
        });
    }
    let vault_id = vault.vault_id();

    // The borrow dance (Q-b): the live-set read is ASYNC (block_on_local) but
    // `complete_rotation` is SYNC. Read the set FIRST into an owned Vec
    // (releasing the chain borrow), THEN run the sync composition. `env` is
    // resolved via [`crate::chain_config::ffi_chain_env_and_id`]: production
    // hardcodes BaseSepolia (testnet-only / D-011; not crossed FFI); the
    // `integration-tests` feature opts into `ChainEnv::Dev` via the
    // `test_env` seam. The read is FAIL-CLOSED: any chain error →
    // FfiError::Chain, never an empty set.
    let current_set: Vec<[u8; SIGNER_LEN]> = crate::chain_config::block_on_local(async {
        let (env, _chain_id) = crate::chain_config::ffi_chain_env_and_id(&config.rpc_url)
            .await
            .map_err(crate::chain_config::chain_into_ffi)?;
        pangolin_chain::read_authorized_set_v2(env, &config.rpc_url, vault_id, 0)
            .await
            .map(|addrs| {
                addrs
                    .into_iter()
                    .map(pangolin_chain::Address::into_array)
                    .collect()
            })
            .map_err(crate::chain_config::chain_into_ffi)
    })??;

    let outcome = pangolin_core::composition::complete_rotation(vault, &secret, &current_set)
        .map_err(composition_error_into_ffi)?;
    drop(secret);

    Ok(FfiRotationResult {
        new_epoch: outcome.new_epoch,
        unknown_survivors: outcome
            .unknown_survivors
            .into_iter()
            .map(|s| s.to_vec())
            .collect(),
        schema_version: RECOVERY_FFI_SCHEMA_VERSION,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain_config::FfiChainConfig;
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

    fn bogus_config() -> FfiChainConfig {
        FfiChainConfig {
            schema_version: 1,
            rpc_url: "http://127.0.0.1:1".into(),
            deployment_path: "/no/such/path/base-sepolia.json".into(),
            prefer_websocket: false,
        }
    }

    /// `vault_pending_rotations` reads on an unlocked vault (no pending rows
    /// on a fresh vault → empty vec).
    #[test]
    fn pending_rotations_reads_empty_on_fresh_vault() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        let rows = vault_pending_rotations(h).expect("read pending rotations");
        assert!(rows.is_empty(), "fresh vault has no pending rotations");
    }

    /// `vault_pending_rotations` on a placeholder handle → Session.
    #[test]
    fn pending_rotations_rejects_placeholder() {
        let empty = VaultHandle::new_placeholder();
        let err = vault_pending_rotations(empty).unwrap_err();
        assert!(matches!(err, FfiError::Session { .. }));
    }

    /// **§0a Q-b fail-closed.** `vault_complete_rotation` against a bogus RPC
    /// fails the live-set read → `FfiError::Chain` (NEVER proceeds with an
    /// empty/guessed set). The L4 session gate runs first, so an unlocked
    /// vault is required to reach the chain read.
    #[test]
    fn complete_rotation_fail_closed_on_bad_rpc_maps_to_chain() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        let err = vault_complete_rotation(h, SecretPassword::new(pwd_bytes()), bogus_config())
            .unwrap_err();
        assert!(
            matches!(err, FfiError::Chain { .. }),
            "a bad-rpc live-set read must fail closed to FfiError::Chain, got {err:?}"
        );
    }

    /// **L4 session gate BEFORE chain.** A locked vault errors
    /// `FfiError::Session` before any chain primitive.
    #[test]
    fn complete_rotation_rejects_locked_before_chain() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        {
            let mut g = h.lock_vault();
            g.as_mut().unwrap().lock();
        }
        let err = vault_complete_rotation(h, SecretPassword::new(pwd_bytes()), bogus_config())
            .unwrap_err();
        assert!(matches!(err, FfiError::Session { .. }));
    }

    /// Placeholder handle → Session.
    #[test]
    fn complete_rotation_rejects_placeholder() {
        let empty = VaultHandle::new_placeholder();
        let err = vault_complete_rotation(empty, SecretPassword::new(pwd_bytes()), bogus_config())
            .unwrap_err();
        assert!(matches!(err, FfiError::Session { .. }));
    }
}
