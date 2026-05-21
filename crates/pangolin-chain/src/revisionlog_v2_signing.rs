// SPDX-License-Identifier: AGPL-3.0-or-later
//! EIP-712 v2 device-management builders for the `RevisionLogV2` contract
//! (MVP-3 issue #106c, multi-device control plane).
//!
//! **Scope (§0a / L2 — `docs/issue-plans/106c-device-add-flow.md`):**
//! produce + recover the 65-byte secp256k1 signatures (`r ‖ s ‖ v`,
//! canonical-s, `v ∈ {27,28}`) over the EIP-712 typed-data digests the
//! deployed `RevisionLogV2` contract verifies in `_hashAddDevice` /
//! `_hashRemoveDevice` / `_hashPromote` (`contracts/src/RevisionLogV2.sol:
//! 981/992/1003`). The manager (Option B `deviceManager`) signs an
//! `AddDevice` / `RemoveDevice`; a candidate self-signs a `Promote`; the
//! genesis `bootstrapVault` reuses the `AddDevice` typehash at `nonce == 0`
//! signed by the first device for itself.
//!
//! ## Why this is security-critical (L2 — LOAD-BEARING, the #103 L2/L3 class)
//!
//! This module produces the bytes the on-chain contract `ecrecover`s. Any
//! drift from the contract's `_hash*` is silent and total: a wrong
//! typehash, wrong domain (`name`/`version`/`chainId`/`verifyingContract`),
//! wrong field order, or a non-canonical `s` makes the contract recover a
//! *wrong* address → `addDevice` reverts `ErrNotDeviceManager` /
//! `ErrInvalidSignature` → device-add is unreachable. The byte-identity is
//! pinned by the `*_typehash_matches_pinned_constant` hermetic tests + the
//! anvil `addDevice` / `removeDevice` round-trip
//! (`scripts/anvil-ci.sh`), which submits a real signature to the LIVE
//! contract.
//!
//! ## EIP-712 envelope (L2 verbatim, from `RevisionLogV2.sol:383-391`)
//!
//! - `name = "Pangolin RevisionLog"`
//! - `version = "2"` (DISTINCT from `RevisionLogV1`'s `"1"`, so a v1
//!   signature can never replay against v2 and vice-versa — Q-j / L4)
//! - `chainId` — bound per env (`84_532` `BaseSepolia`; live anvil id for
//!   Dev)
//! - `verifyingContract` — the `RevisionLogV2` deployment address
//!
//! Typehash strings (the literal byte strings fed into the spec keccak,
//! `RevisionLogV2.sol:276-287`):
//!
//! ```text
//! AddDevice(bytes32 vaultId,address newSigner,uint64 nonce,uint16 schemaVersion)
//! RemoveDevice(bytes32 vaultId,address signer,uint64 nonce,uint16 schemaVersion)
//! Promote(bytes32 vaultId,address candidate,uint64 nonce,uint16 schemaVersion)
//! ```
//!
//! ## Reuse, not re-implementation (L2)
//!
//! The digest is built with [`crate::secp256k1_signing::eip712_digest`]
//! and the canonical-s gate is
//! [`crate::secp256k1_signing::is_canonical_s`] — REUSED verbatim from the
//! audited `secp256k1_signing.rs` so there is exactly one digest / one
//! canonical-s implementation in the crate. Only the struct-hashes (the
//! three field sets) and the v2 domain (`name = "Pangolin RevisionLog"`,
//! `version = "2"`) are new here.

use alloy::primitives::{keccak256, Address, B256, U256};
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::SignerSync;
use alloy::sol_types::{eip712_domain, Eip712Domain};

use crate::error::ChainError;
use crate::secp256k1_signing::{eip712_digest, is_canonical_s};

/// Pinned EIP-712 typehash for the `AddDevice` struct (L2 verbatim).
///
/// Equals
/// `keccak256("AddDevice(bytes32 vaultId,address newSigner,uint64 nonce,uint16 schemaVersion)")`,
/// independently verified by [`tests::add_device_typehash_matches_pinned_constant`]
/// (which re-keccaks the literal). The literal is copied verbatim from
/// `contracts/src/RevisionLogV2.sol:276-277`.
pub const ADD_DEVICE_TYPEHASH_V2: [u8; 32] =
    alloy::primitives::hex!("279755e7721a61f392c6808f60242717f80776f95a7a209bbcece753e878465b");

/// Pinned EIP-712 typehash for the `RemoveDevice` struct (L2 verbatim).
///
/// Equals
/// `keccak256("RemoveDevice(bytes32 vaultId,address signer,uint64 nonce,uint16 schemaVersion)")`,
/// from `contracts/src/RevisionLogV2.sol:280-281`. Verified by
/// [`tests::remove_device_typehash_matches_pinned_constant`].
pub const REMOVE_DEVICE_TYPEHASH_V2: [u8; 32] =
    alloy::primitives::hex!("747a3f87853a374441ba222dac7e7cda1a2b79f37db2af06c1a7d64f025ebb69");

/// Pinned EIP-712 typehash for the `Promote` struct (L2 verbatim).
///
/// Equals
/// `keccak256("Promote(bytes32 vaultId,address candidate,uint64 nonce,uint16 schemaVersion)")`,
/// from `contracts/src/RevisionLogV2.sol:286-287`. Verified by
/// [`tests::promote_typehash_matches_pinned_constant`].
pub const PROMOTE_TYPEHASH_V2: [u8; 32] =
    alloy::primitives::hex!("843d7972ce26d17fc4887717ffd5efe23ff95263d4dc8a7dd733c71486c3be4b");

/// The literal struct-definition strings (the single source the typehash
/// pin tests re-keccak). Test-only — the production digest path uses the
/// pre-computed [`ADD_DEVICE_TYPEHASH_V2`] etc.
#[cfg(test)]
pub(crate) const ADD_DEVICE_TYPE_STRING: &str =
    "AddDevice(bytes32 vaultId,address newSigner,uint64 nonce,uint16 schemaVersion)";
#[cfg(test)]
pub(crate) const REMOVE_DEVICE_TYPE_STRING: &str =
    "RemoveDevice(bytes32 vaultId,address signer,uint64 nonce,uint16 schemaVersion)";
#[cfg(test)]
pub(crate) const PROMOTE_TYPE_STRING: &str =
    "Promote(bytes32 vaultId,address candidate,uint64 nonce,uint16 schemaVersion)";

/// EIP-712 domain string for the contract `name` field (L2 verbatim,
/// `RevisionLogV2.sol:386`).
const DOMAIN_NAME: &str = "Pangolin RevisionLog";

/// EIP-712 domain string for the contract `version` field (L2 verbatim,
/// `RevisionLogV2.sol:387`). DISTINCT from `RevisionLogV1`'s `"1"`.
const DOMAIN_VERSION: &str = "2";

/// Event-schema version every #106c device-management call passes (L9).
/// The contract rejects `> MAX_KNOWN_SCHEMA_VERSION` symmetrically.
pub const REVISIONLOG_V2_SCHEMA_VERSION: u16 = 1;

/// Which device-management digest a [`DeviceAuthFields`] is for.
///
/// Selects the typehash; the field set is otherwise identical across all
/// three (`vaultId`, `signer/candidate` address, `nonce`, `schemaVersion`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceAuthKind {
    /// `AddDevice` (manager-signed; genesis reuses it at `nonce == 0`).
    AddDevice,
    /// `RemoveDevice` (manager-signed).
    RemoveDevice,
    /// `Promote` (candidate self-signed).
    Promote,
}

impl DeviceAuthKind {
    /// The pinned typehash for this digest kind (L2).
    #[must_use]
    pub const fn typehash(self) -> [u8; 32] {
        match self {
            Self::AddDevice => ADD_DEVICE_TYPEHASH_V2,
            Self::RemoveDevice => REMOVE_DEVICE_TYPEHASH_V2,
            Self::Promote => PROMOTE_TYPEHASH_V2,
        }
    }
}

/// The four EIP-712 device-auth struct fields. Identical layout across
/// `AddDevice` / `RemoveDevice` / `Promote` (`RevisionLogV2.sol:981/992/
/// 1003`); the `kind` selects the typehash.
///
/// `nonce` is read LIVE from the contract's `deviceNonce(vaultId)` by the
/// caller before constructing this (L11-analogue anti-replay): a
/// stale-nonce digest must never be built (the genesis bootstrap uses
/// `nonce == 0`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceAuthFields {
    /// Which of the three digests this is (selects the typehash).
    pub kind: DeviceAuthKind,
    /// 32-byte opaque vault identifier.
    pub vault_id: [u8; 32],
    /// The subject device address: the `newSigner` (add), the `signer`
    /// (remove), or the `candidate` (promote).
    pub subject: Address,
    /// Per-vault current `deviceNonce` (read live — L11-analogue). The
    /// genesis `bootstrapVault` uses `0`.
    pub nonce: u64,
    /// Event-schema version. `1` for v2; the contract rejects
    /// `> MAX_KNOWN_SCHEMA_VERSION` (L9).
    pub schema_version: u16,
}

/// A signed device-auth authorization: the field set + the 65-byte
/// secp256k1 signature.
///
/// `AddDevice` / `RemoveDevice` are signed by the manager; `Promote` is
/// self-signed by the candidate. The broadcaster
/// ([`crate::revisionlog_v2_client`]) carries only these public bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedDeviceAuth {
    /// The same field set the digest was computed over.
    pub fields: DeviceAuthFields,
    /// Exactly 65 bytes: `r (32) || s (32) || v (1)`; `v ∈ {27,28}`;
    /// `s ≤ secp256k1n/2`.
    pub signature: [u8; 65],
}

/// Construct the EIP-712 v2 `RevisionLog` domain.
///
/// `chain_id` is threaded explicitly, mirroring
/// [`crate::recovery_signing::build_domain_recovery`]: the caller passes
/// the pinned id for a fixed env (never an untrusted RPC report) or the
/// live local id for `Dev` / anvil.
#[must_use]
pub fn build_domain_revisionlog_v2(verifying_contract: Address, chain_id: u64) -> Eip712Domain {
    eip712_domain! {
        name: DOMAIN_NAME,
        version: DOMAIN_VERSION,
        chain_id: chain_id,
        verifying_contract: verifying_contract,
    }
}

/// Compute the EIP-712 struct-hash for a [`DeviceAuthFields`].
///
/// Mirrors the contract's `_hashAddDevice` / `_hashRemoveDevice` /
/// `_hashPromote` struct-hash (`RevisionLogV2.sol:987/998/1009`):
///
/// ```text
/// structHash = keccak256(
///     abi.encode(
///         TYPEHASH,       // bytes32 (kind-dependent)
///         vaultId,        // bytes32
///         subject,        // address (left-padded to bytes32)
///         nonce,          // uint64  (left-padded to bytes32)
///         schemaVersion   // uint16  (left-padded to bytes32)
///     )
/// )
/// ```
#[must_use]
pub fn device_auth_struct_hash(fields: &DeviceAuthFields) -> B256 {
    // 5 × 32 bytes = 160 bytes.
    let mut buf = [0u8; 5 * 32];
    let mut o = 0usize;
    buf[o..o + 32].copy_from_slice(&fields.kind.typehash());
    o += 32;
    buf[o..o + 32].copy_from_slice(&fields.vault_id);
    o += 32;
    // `address` ABI-encodes to a left-padded 32-byte word.
    buf[o + 12..o + 32].copy_from_slice(fields.subject.as_slice());
    o += 32;
    // `uint64` ABI-encodes to a left-padded 32-byte word.
    buf[o + 24..o + 32].copy_from_slice(&fields.nonce.to_be_bytes());
    o += 32;
    // `uint16` ABI-encodes to a left-padded 32-byte word.
    buf[o + 30..o + 32].copy_from_slice(&fields.schema_version.to_be_bytes());
    o += 32;
    debug_assert_eq!(o, buf.len(), "device_auth_struct_hash buffer drift");
    keccak256(buf)
}

/// Compute the EIP-712 device-auth digest the contract verifies
/// (`RevisionLogV2.sol:_hash*`): `keccak256(0x1901 ‖ domainSeparator ‖
/// structHash)`.
///
/// REUSES [`crate::secp256k1_signing::eip712_digest`] verbatim — the crate
/// has exactly one digest implementation (L2: no silent-drift surface).
#[must_use]
pub fn device_auth_digest(
    verifying_contract: Address,
    chain_id: u64,
    fields: &DeviceAuthFields,
) -> B256 {
    let domain = build_domain_revisionlog_v2(verifying_contract, chain_id);
    let domain_sep = domain.separator();
    let s_hash = device_auth_struct_hash(fields);
    eip712_digest(domain_sep, s_hash)
}

/// Sign a device-auth authorization with a `PrivateKeySigner`, returning a
/// [`SignedDeviceAuth`] with a 65-byte `r ‖ s ‖ v` signature
/// (`v ∈ {27,28}`, `s ≤ secp256k1n/2`).
///
/// For `AddDevice` / `RemoveDevice` the signer MUST be the current device
/// manager; for `Promote` it MUST be the candidate; for genesis it MUST be
/// the first device. The recovered signer being `address(0)` is impossible
/// here (a real signer always produces a recoverable signature), but the
/// contract rejects `address(0)` recovery defensively.
///
/// `chain_id` MUST equal the chain id the contract was deployed on (the
/// contract bakes `block.chainid` into its `DOMAIN_SEPARATOR`).
///
/// # Errors
///
/// [`ChainError::Wallet`] if the signer's internal `sign_hash_sync`
/// returns an error (vanishingly rare under k256 0.13.x).
pub fn build_signed_device_auth(
    signer: &PrivateKeySigner,
    fields: DeviceAuthFields,
    verifying_contract: Address,
    chain_id: u64,
) -> Result<SignedDeviceAuth, ChainError> {
    let digest = device_auth_digest(verifying_contract, chain_id, &fields);
    let sig = signer
        .sign_hash_sync(&digest)
        .map_err(|_e| ChainError::Wallet("alloy signer error signing device-auth digest"))?;
    let canonical = sig.normalize_s().unwrap_or(sig);
    let signature = canonical.as_bytes();

    debug_assert!(
        signature[64] == 27 || signature[64] == 28,
        "v must be in {{27,28}} for EIP-712"
    );
    let mut s_be = [0u8; 32];
    s_be.copy_from_slice(&signature[32..64]);
    debug_assert!(is_canonical_s(&s_be), "s must be canonical-low (s <= n/2)");
    let _ = s_be;

    Ok(SignedDeviceAuth { fields, signature })
}

/// Recover the EVM address that signed a device-auth authorization.
///
/// REUSES the exact `device_auth_digest` (and therefore the shared
/// `eip712_digest`) the signing path ran, so a sign + recover round-trip
/// recovers the signer's own address (L2). Rejects high-s
/// (`is_canonical_s`) + non-`{27,28}` `v` BEFORE recovery — the same
/// defense-in-depth posture as
/// [`crate::recovery_signing::recover_approver_v1`].
///
/// # Errors
///
/// [`ChainError::SignerRecoveryFailed`] on high-s, bad `v`, or a
/// curve-level malformed signature.
pub fn recover_device_auth_signer(
    auth: &SignedDeviceAuth,
    verifying_contract: Address,
    chain_id: u64,
) -> Result<Address, ChainError> {
    let digest = device_auth_digest(verifying_contract, chain_id, &auth.fields);

    let mut s_be = [0u8; 32];
    s_be.copy_from_slice(&auth.signature[32..64]);
    if !is_canonical_s(&s_be) {
        return Err(ChainError::SignerRecoveryFailed {
            detail: "device-auth signature s component is non-canonical (high-s)".to_string(),
        });
    }
    let v_byte = auth.signature[64];
    if v_byte != 27 && v_byte != 28 {
        return Err(ChainError::SignerRecoveryFailed {
            detail: format!("device-auth signature v byte not in {{27,28}}: got {v_byte}"),
        });
    }

    let r = U256::from_be_slice(&auth.signature[0..32]);
    let s = U256::from_be_slice(&auth.signature[32..64]);
    let y_parity = v_byte == 28;
    let sig = alloy::primitives::Signature::new(r, s, y_parity);
    sig.recover_address_from_prehash(&digest)
        .map_err(|e| ChainError::SignerRecoveryFailed {
            detail: format!("alloy recover_address_from_prehash failed: {e}"),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pangolin_crypto::keys::DeviceKey;

    use crate::evm::derive_evm_wallet;

    fn wallet(seed_byte: u8) -> PrivateKeySigner {
        derive_evm_wallet(&DeviceKey::from_seed([seed_byte; 32]))
            .expect("derive wallet")
            .into_signer()
    }

    fn sample(kind: DeviceAuthKind) -> DeviceAuthFields {
        DeviceAuthFields {
            kind,
            vault_id: [0x11; 32],
            subject: Address::from([0x22; 20]),
            nonce: 7,
            schema_version: 1,
        }
    }

    /// L2: the pinned `ADD_DEVICE_TYPEHASH_V2` equals the keccak of the
    /// literal struct-definition string from the contract
    /// (`RevisionLogV2.sol:276-277`).
    #[test]
    fn add_device_typehash_matches_pinned_constant() {
        let computed = keccak256(ADD_DEVICE_TYPE_STRING.as_bytes());
        assert_eq!(
            computed.0, ADD_DEVICE_TYPEHASH_V2,
            "AddDevice typehash literal must keccak to the pinned constant"
        );
    }

    /// L2: the pinned `REMOVE_DEVICE_TYPEHASH_V2` matches its literal.
    #[test]
    fn remove_device_typehash_matches_pinned_constant() {
        let computed = keccak256(REMOVE_DEVICE_TYPE_STRING.as_bytes());
        assert_eq!(
            computed.0, REMOVE_DEVICE_TYPEHASH_V2,
            "RemoveDevice typehash literal must keccak to the pinned constant"
        );
    }

    /// L2: the pinned `PROMOTE_TYPEHASH_V2` matches its literal.
    #[test]
    fn promote_typehash_matches_pinned_constant() {
        let computed = keccak256(PROMOTE_TYPE_STRING.as_bytes());
        assert_eq!(
            computed.0, PROMOTE_TYPEHASH_V2,
            "Promote typehash literal must keccak to the pinned constant"
        );
    }

    /// L4 (cross-version replay defense): the v2 domain separator MUST
    /// differ from the v1 `RevisionLog` domain (same name, version "1" vs
    /// "2"), so a v1 signature can never replay against v2.
    #[test]
    fn v2_domain_separator_differs_from_v1() {
        let addr = Address::from([0xAB; 20]);
        let v2 = build_domain_revisionlog_v2(addr, 31_337).separator();
        // Reconstruct the v1 RevisionLog domain (name same, version "1").
        let v1 = eip712_domain! {
            name: "Pangolin RevisionLog",
            version: "1",
            chain_id: 31_337u64,
            verifying_contract: addr,
        }
        .separator();
        assert_ne!(
            v2, v1,
            "v2 domain (version \"2\") must differ from v1 (version \"1\")"
        );
    }

    /// L2: sign + recover round-trip recovers the signer's own address,
    /// for each of the three digest kinds.
    #[test]
    fn sign_recover_round_trip_all_kinds() {
        let signer = wallet(0x42);
        let verifying = Address::from([0xCD; 20]);
        let chain_id = 31_337;
        for kind in [
            DeviceAuthKind::AddDevice,
            DeviceAuthKind::RemoveDevice,
            DeviceAuthKind::Promote,
        ] {
            let auth = build_signed_device_auth(&signer, sample(kind), verifying, chain_id)
                .expect("sign device auth");
            assert_eq!(auth.signature.len(), 65);
            let recovered =
                recover_device_auth_signer(&auth, verifying, chain_id).expect("recover");
            assert_eq!(
                recovered,
                signer.address(),
                "recovered signer must equal the device signer ({kind:?})"
            );
        }
    }

    /// The three kinds produce DISTINCT digests for the same fields (the
    /// typehash is the only differing input), so an `AddDevice` signature
    /// can never be replayed as a `RemoveDevice`/`Promote`.
    #[test]
    fn distinct_kinds_distinct_digests() {
        let verifying = Address::from([0x01; 20]);
        let base = DeviceAuthFields {
            kind: DeviceAuthKind::AddDevice,
            vault_id: [0x33; 32],
            subject: Address::from([0x44; 20]),
            nonce: 1,
            schema_version: 1,
        };
        let add = device_auth_digest(verifying, 1, &base);
        let remove = device_auth_digest(
            verifying,
            1,
            &DeviceAuthFields {
                kind: DeviceAuthKind::RemoveDevice,
                ..base
            },
        );
        let promote = device_auth_digest(
            verifying,
            1,
            &DeviceAuthFields {
                kind: DeviceAuthKind::Promote,
                ..base
            },
        );
        assert_ne!(add, remove);
        assert_ne!(add, promote);
        assert_ne!(remove, promote);
    }

    /// A signature recovered under a DIFFERENT chain id must NOT recover
    /// the same signer — confirms the chain id is bound into the digest
    /// (cross-chain replay defense).
    #[test]
    fn wrong_chain_id_recovers_different_signer() {
        let signer = wallet(0x43);
        let verifying = Address::from([0xEF; 20]);
        let auth = build_signed_device_auth(
            &signer,
            sample(DeviceAuthKind::AddDevice),
            verifying,
            31_337,
        )
        .expect("sign");
        let recovered = recover_device_auth_signer(&auth, verifying, 84_532).expect("recover");
        assert_ne!(
            recovered,
            signer.address(),
            "a different chain id must bind a different digest → different recovered signer"
        );
    }

    /// `v ∈ {27,28}` and `s` canonical-low on a freshly produced signature.
    #[test]
    fn signature_shape_is_canonical() {
        let signer = wallet(0x44);
        let auth = build_signed_device_auth(
            &signer,
            sample(DeviceAuthKind::Promote),
            Address::from([0x02; 20]),
            31_337,
        )
        .expect("sign");
        let v = auth.signature[64];
        assert!(v == 27 || v == 28, "v must be 27 or 28, got {v}");
        let mut s_be = [0u8; 32];
        s_be.copy_from_slice(&auth.signature[32..64]);
        assert!(is_canonical_s(&s_be), "s must be canonical-low");
    }
}
