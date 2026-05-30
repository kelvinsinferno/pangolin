// SPDX-License-Identifier: AGPL-3.0-or-later
//! EIP-712 v1 `Approve` builder/verifier for the `RecoveryV1` contract
//! (MVP-3 issue #103, chain-client control plane).
//!
//! **Scope (R-where / L3 — `docs/issue-plans/103-recovery-client.md`):**
//! produce + recover the 65-byte secp256k1 signatures (`r ‖ s ‖ v`,
//! canonical-s, `v ∈ {27,28}`) over the EIP-712 typed-data digest the
//! deployed `RecoveryV1` contract verifies in `_hashApprove`
//! (`contracts/src/RecoveryV1.sol:813`). A guardian signs an `Approve`
//! attestation OFF-CHAIN; the recovering device collects the 65-byte
//! signature + a merkle membership proof and submits them via
//! [`crate::recovery_client::approve_recovery_v1`]. The guardian's
//! secret key NEVER touches the recovering device (L5).
//!
//! ## Why this is security-critical (L3 — load-bearing)
//!
//! This module produces the bytes the on-chain contract `ecrecover`s.
//! Any drift from the contract's `_hashApprove` is silent and total:
//! a wrong typehash, wrong domain (`name`/`version`/`chainId`/
//! `verifyingContract`), wrong field order, or a non-canonical `s`
//! makes the contract recover a *wrong* address → `approveRecovery`
//! reverts `ErrInvalidSignature` → every guardian approval fails →
//! recovery is unreachable. The byte-identity is pinned by the
//! `approve_typehash_matches_pinned_constant` hermetic test + the
//! anvil lifecycle round-trip (`scripts/anvil-ci.sh`), which submits
//! a real `Approve` signature to the LIVE contract.
//!
//! ## EIP-712 envelope (L3 verbatim, from `RecoveryV1.sol:330-332,389-398`)
//!
//! - `name = "Pangolin Recovery"`
//! - `version = "1"`
//! - `chainId` — bound per env (`84_532` `BaseSepolia`; live anvil id for Dev)
//! - `verifyingContract` — the `RecoveryV1` deployment address
//!
//! Typehash string (the literal byte string fed into the spec keccak,
//! `RecoveryV1.sol:330-332`):
//!
//! ```text
//! Approve(bytes32 vaultId,address proposedAuthority,uint64 attemptNonce,uint64 expiresAt,uint16 schemaVersion)
//! ```
//!
//! ## Reuse, not re-implementation (L3)
//!
//! The digest is built with [`crate::secp256k1_signing::eip712_digest`]
//! and the canonical-s gate is
//! [`crate::secp256k1_signing::is_canonical_s`] — REUSED verbatim from
//! the audited `secp256k1_signing.rs` so there is exactly one digest /
//! one canonical-s implementation in the crate. Only the struct-hash
//! (the `Approve` field set, distinct from `Revision`) and the domain
//! `name` (`"Pangolin Recovery"`) are new here.

use alloy::primitives::{keccak256, Address, B256, U256};
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::SignerSync;
use alloy::sol_types::{eip712_domain, Eip712Domain};

use crate::error::ChainError;
use crate::secp256k1_signing::{eip712_digest, is_canonical_s};

/// Pinned EIP-712 typehash for the `Approve` struct (L3 verbatim).
///
/// Equals `keccak256("Approve(bytes32 vaultId,address proposedAuthority,uint64 attemptNonce,uint64 expiresAt,uint16 schemaVersion)")`,
/// independently verified by the `approve_typehash_matches_pinned_constant`
/// hermetic test (which re-keccaks the literal). The literal is copied
/// verbatim from `contracts/src/RecoveryV1.sol:330-332`. A future
/// drift in either the literal or the contract source fires loudly in
/// CI before merge.
pub const APPROVE_TYPEHASH_V1: [u8; 32] =
    alloy::primitives::hex!("2d50d9bb83a24b2700f4d752384ad02f0b24549ca3d91247428f3b54eaa24113");

/// Pinned EIP-712 domain separator for the `RecoveryV1` contract.
///
/// Captured for a **fresh anvil dev chain** (`chainId = 31337`, the
/// CREATE2-deterministic address `forge`/anvil mints for the first
/// deploy from anvil acct[0]).
///
/// **TODO (testnet capture):** no Base Sepolia `RecoveryV1` deploy
/// exists as of #103 plan-gate (2026-05-20). When `RecoveryV1` lands on
/// Base Sepolia, capture `cast call <addr> "DOMAIN_SEPARATOR()(bytes32)"
/// --rpc-url https://sepolia.base.org`, add a
/// `RECOVERY_DOMAIN_SEPARATOR_BASE_SEPOLIA_V1` constant + an
/// `EXPECTED_RECOVERY_ADDRESS_BASE_SEPOLIA` pin, and wire the
/// `deployment_json_pins_match_rust_constants` cross-check (mirror the
/// `RevisionLogV1` / `EntitlementRegistry` posture). For now the only
/// pinned separator is the anvil-derived one below, validated by the
/// `recovery_domain_separator_matches_pinned_anvil_value` hermetic test
/// (which reconstructs it from `name`/`version`/`chainId`/`verifying`)
/// AND end-to-end by the anvil lifecycle round-trip.
///
/// The address pinned below (`0x5FbDB2315678afecb367f032d93F642f64180aa3`,
/// anvil acct[0] nonce-0 CREATE address) is a STABLE reference for the
/// hermetic reconstruction test ONLY — it is NOT where the harness
/// actually deploys `RecoveryV1` (`anvil-ci.sh` deploys it after two
/// other contracts, so its real nonce differs). The lifecycle test
/// reads the real deployed address from `dev.json`; the domain
/// separator is bound to that real address at runtime. This constant
/// exists so the `eip712_domain!` construction is byte-pinned against a
/// deterministic fixture (`name`/`version`/`chainId` drift fires
/// loudly), the same posture as `DOMAIN_SEPARATOR_BASE_SEPOLIA_V1`.
pub const RECOVERY_DOMAIN_SEPARATOR_ANVIL_DEV_V1: [u8; 32] =
    alloy::primitives::hex!("aeeea61ac426f08c0b36279db1b9eb67f2dca8673099fe0fcaf9754bb6e71f78");

/// Pinned EIP-712 domain separator for the `RecoveryV2` contract on Base
/// Sepolia (MVP-4-L L-0a-1 deploy; D-NNN in DECISIONS pending).
///
/// Captured via `cast call 0xf0E08fd009d8a33ba844610dAdD90450C1C206CA
/// "DOMAIN_SEPARATOR()(bytes32)" --rpc-url https://sepolia.base.org` at
/// 2026-05-30T18:42Z. Cross-checked against
/// `contracts/deployments/base-sepolia.json` by the hermetic test
/// `rust_recovery_v2_domain_separator_matches_json`; reconstructed via the
/// alloy `eip712_domain!` macro by
/// [`tests::recovery_v2_domain_separator_matches_pinned_base_sepolia_value`]
/// so a drift in either the literal or the JSON or the live contract fires
/// loudly in CI before merge.
pub const RECOVERY_DOMAIN_SEPARATOR_BASE_SEPOLIA_V2: [u8; 32] =
    alloy::primitives::hex!("e6f9f29b0aa9de091dfdefb3768bd18598bfd7cf5171fe9b2bc324056eaf542b");

/// Pinned `RecoveryV2` contract address on Base Sepolia.
///
/// Cross-checked against `contracts/deployments/base-sepolia.json` by the
/// hermetic test `rust_recovery_v2_address_matches_json`. A future drift
/// (either an out-of-band redeploy or a constant rot) fires at PR review
/// time, not on a fresh-vault first sync — the issue #98 L-rotted-constant
/// posture extended to recovery.
pub const EXPECTED_RECOVERY_V2_ADDRESS_BASE_SEPOLIA: Address = Address::new(
    alloy::primitives::hex!("f0E08fd009d8a33ba844610dAdD90450C1C206CA"),
);

/// EIP-712 domain string for the contract `name` field (L3 verbatim,
/// `RecoveryV1.sol:393`).
const DOMAIN_NAME: &str = "Pangolin Recovery";

/// EIP-712 domain string for the contract `version` field (L3 verbatim,
/// `RecoveryV1.sol:394`).
const DOMAIN_VERSION: &str = "1";

/// The five EIP-712 `Approve` struct fields (`RecoveryV1.sol:813-826`).
///
/// `attempt_nonce` + `proposed_authority` are read LIVE from the
/// contract's PENDING attempt by the caller before constructing this
/// (L11 anti-replay): a stale-attempt digest must never be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApproveFieldsV1 {
    /// 32-byte opaque vault identifier.
    pub vault_id: [u8; 32],
    /// The attempt's target authority (read from the live PENDING
    /// attempt — L11).
    pub proposed_authority: Address,
    /// Per-attempt scope (read from the live PENDING attempt — L11).
    pub attempt_nonce: u64,
    /// Unix timestamp after which the contract rejects the signature
    /// (`ErrApprovalExpired`, R-c anti-stale).
    pub expires_at: u64,
    /// Event-schema version. `1` for v1; the contract rejects
    /// `> MAX_KNOWN_SCHEMA_VERSION` (L6).
    pub schema_version: u16,
}

/// A guardian's signed `Approve` attestation: the field set + the
/// 65-byte secp256k1 signature.
///
/// The recovering device transports this (plus the merkle proof,
/// carried separately) to `approveRecovery`. Per L5 the guardian's
/// secret key produced the signature off-device; only these public
/// bytes cross the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedApprovalV1 {
    /// The same field set the digest was computed over.
    pub fields: ApproveFieldsV1,
    /// Exactly 65 bytes: `r (32) || s (32) || v (1)`; `v ∈ {27,28}`;
    /// `s ≤ secp256k1n/2`.
    pub signature: [u8; 65],
}

/// Construct the EIP-712 recovery domain via the same alloy primitive
/// the `recovery_domain_separator_matches_pinned_anvil_value` test
/// exercises.
///
/// `chain_id` is threaded explicitly, mirroring
/// [`crate::secp256k1_signing::build_domain`] (the #101 amendment): the
/// caller passes the pinned id for a fixed env (never an untrusted RPC
/// report) or the live local id for `Dev` / anvil.
#[must_use]
pub fn build_domain_recovery(verifying_contract: Address, chain_id: u64) -> Eip712Domain {
    eip712_domain! {
        name: DOMAIN_NAME,
        version: DOMAIN_VERSION,
        chain_id: chain_id,
        verifying_contract: verifying_contract,
    }
}

/// Compute the EIP-712 struct-hash for an [`ApproveFieldsV1`].
///
/// Mirrors the contract's `_hashApprove` struct-hash
/// (`RecoveryV1.sol:820-823`):
///
/// ```text
/// structHash = keccak256(
///     abi.encode(
///         APPROVE_TYPEHASH,
///         vaultId,           // bytes32
///         proposedAuthority, // address (left-padded to bytes32)
///         attemptNonce,      // uint64  (left-padded to bytes32)
///         expiresAt,         // uint64  (left-padded to bytes32)
///         schemaVersion      // uint16  (left-padded to bytes32)
///     )
/// )
/// ```
#[must_use]
pub fn approve_struct_hash(fields: &ApproveFieldsV1) -> B256 {
    // 6 × 32 bytes = 192 bytes.
    let mut buf = [0u8; 6 * 32];
    let mut o = 0usize;
    buf[o..o + 32].copy_from_slice(&APPROVE_TYPEHASH_V1);
    o += 32;
    buf[o..o + 32].copy_from_slice(&fields.vault_id);
    o += 32;
    // `address` ABI-encodes to a left-padded 32-byte word: 12 zero
    // bytes ‖ 20 address bytes.
    buf[o + 12..o + 32].copy_from_slice(fields.proposed_authority.as_slice());
    o += 32;
    // `uint64` ABI-encodes to a left-padded 32-byte word.
    buf[o + 24..o + 32].copy_from_slice(&fields.attempt_nonce.to_be_bytes());
    o += 32;
    buf[o + 24..o + 32].copy_from_slice(&fields.expires_at.to_be_bytes());
    o += 32;
    // `uint16` ABI-encodes to a left-padded 32-byte word.
    buf[o + 30..o + 32].copy_from_slice(&fields.schema_version.to_be_bytes());
    o += 32;
    debug_assert_eq!(o, buf.len(), "approve_struct_hash buffer drift");
    keccak256(buf)
}

/// Compute the EIP-712 `Approve` digest the contract verifies
/// (`RecoveryV1.sol:_hashApprove`): `keccak256(0x1901 ‖ domainSeparator
/// ‖ structHash)`.
///
/// REUSES [`crate::secp256k1_signing::eip712_digest`] verbatim — the
/// crate has exactly one digest implementation (L3: no silent-drift
/// surface).
#[must_use]
pub fn approve_digest(
    verifying_contract: Address,
    chain_id: u64,
    fields: &ApproveFieldsV1,
) -> B256 {
    let domain = build_domain_recovery(verifying_contract, chain_id);
    let domain_sep = domain.separator();
    let s_hash = approve_struct_hash(fields);
    eip712_digest(domain_sep, s_hash)
}

/// Sign an `Approve` attestation with a guardian's `PrivateKeySigner`,
/// returning a [`SignedApprovalV1`] with a 65-byte `r ‖ s ‖ v`
/// signature (`v ∈ {27,28}`, `s ≤ secp256k1n/2`).
///
/// This is the OFF-CHAIN guardian-side primitive (L5): a guardian runs
/// it on their own device with their own key; the recovering device
/// never sees the key, only the resulting [`SignedApprovalV1`].
///
/// `chain_id` MUST equal the chain id the contract was deployed on
/// (the contract bakes `block.chainid` into its `DOMAIN_SEPARATOR`);
/// pass the pinned id for a fixed env or the live local id for Dev.
///
/// # Errors
///
/// [`ChainError::Wallet`] if the signer's internal `sign_hash_sync`
/// returns an error (vanishingly rare under k256 0.13.x).
pub fn build_signed_approval_v1(
    signer: &PrivateKeySigner,
    fields: ApproveFieldsV1,
    verifying_contract: Address,
    chain_id: u64,
) -> Result<SignedApprovalV1, ChainError> {
    let digest = approve_digest(verifying_contract, chain_id, &fields);
    let sig = signer
        .sign_hash_sync(&digest)
        .map_err(|_e| ChainError::Wallet("alloy signer error signing Approve digest"))?;
    // Defensively normalise to low-s (idempotent under k256 0.13.x).
    let canonical = sig.normalize_s().unwrap_or(sig);
    let signature = canonical.as_bytes();

    // Structural invariants the bytes MUST satisfy (mirror
    // build_signed_revision_v1's source-side asserts).
    debug_assert!(
        signature[64] == 27 || signature[64] == 28,
        "v must be in {{27,28}} for EIP-712"
    );
    let mut s_be = [0u8; 32];
    s_be.copy_from_slice(&signature[32..64]);
    debug_assert!(is_canonical_s(&s_be), "s must be canonical-low (s <= n/2)");
    let _ = s_be;

    Ok(SignedApprovalV1 { fields, signature })
}

/// Recover the EVM address that signed an `Approve` attestation.
///
/// REUSES the exact `approve_digest` (and therefore the shared
/// `eip712_digest`) the signing path ran, so a sign + recover
/// round-trip recovers the signer's own address (L3). Rejects high-s
/// (`is_canonical_s`) + non-`{27,28}` `v` BEFORE recovery — the same
/// defense-in-depth posture as
/// [`crate::secp256k1_signing::recover_signer_v1_raw`].
///
/// The caller is responsible for the join the contract enforces
/// (`RecoveryV1.sol:627`): the recovered signer must equal the
/// merkle-proven guardian address. This fn returns only the recovered
/// address; the merkle check lives in [`crate::recovery_client`].
///
/// # Errors
///
/// [`ChainError::SignerRecoveryFailed`] on high-s, bad `v`, or a
/// curve-level malformed signature.
pub fn recover_approver_v1(
    approval: &SignedApprovalV1,
    verifying_contract: Address,
    chain_id: u64,
) -> Result<Address, ChainError> {
    let digest = approve_digest(verifying_contract, chain_id, &approval.fields);

    let mut s_be = [0u8; 32];
    s_be.copy_from_slice(&approval.signature[32..64]);
    if !is_canonical_s(&s_be) {
        return Err(ChainError::SignerRecoveryFailed {
            detail: "Approve signature s component is non-canonical (high-s)".to_string(),
        });
    }
    let v_byte = approval.signature[64];
    if v_byte != 27 && v_byte != 28 {
        return Err(ChainError::SignerRecoveryFailed {
            detail: format!("Approve signature v byte not in {{27,28}}: got {v_byte}"),
        });
    }

    let r = U256::from_be_slice(&approval.signature[0..32]);
    let s = U256::from_be_slice(&approval.signature[32..64]);
    let y_parity = v_byte == 28;
    let sig = alloy::primitives::Signature::new(r, s, y_parity);
    sig.recover_address_from_prehash(&digest)
        .map_err(|e| ChainError::SignerRecoveryFailed {
            detail: format!("alloy recover_address_from_prehash failed: {e}"),
        })
}

// ---------------------------------------------------------------------------
// MVP-4-L L-0a-1 — RecoveryV2 EIP-712 surface (Approve gains
// `recipientCommitment`; the new typehash means a V1-shape approval can
// never validate against V2).
// ---------------------------------------------------------------------------

/// Pinned EIP-712 typehash for the **V2** `Approve` struct
/// (`contracts/src/RecoveryV2.sol`'s `APPROVE_TYPEHASH` literal).
///
/// Equals `keccak256("Approve(bytes32 vaultId,address proposedAuthority,uint64 attemptNonce,uint64 expiresAt,bytes32 recipientCommitment,uint16 schemaVersion)")`,
/// independently verified by `approve_typehash_v2_matches_pinned_constant`
/// (which re-keccaks the literal). Drift in either the literal or the
/// contract source fires loudly in CI.
pub const APPROVE_TYPEHASH_V2: [u8; 32] =
    alloy::primitives::hex!("8035ba2c3e373fe0071228b32e9b133bd20163069315c2af924dc620245d0f28");

/// The six EIP-712 `Approve` struct fields for V2.
///
/// Identical to [`ApproveFieldsV1`] plus the on-chain-committed
/// `recipient_commitment` (the strongest available anti-redirect binding;
/// locked in the share-transport design Decision B). Mirrors
/// `RecoveryV2.sol`'s `_hashApprove` field set verbatim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApproveFieldsV2 {
    /// 32-byte opaque vault identifier.
    pub vault_id: [u8; 32],
    /// The attempt's target authority (read from the live PENDING attempt).
    pub proposed_authority: Address,
    /// Per-attempt scope (read from the live PENDING attempt).
    pub attempt_nonce: u64,
    /// Unix timestamp after which the contract rejects the signature.
    pub expires_at: u64,
    /// The recovering user's 32-byte X25519 pubkey for this attempt (read
    /// from `rec.recipientCommitment` on-chain). A guardian's signature
    /// attests to both `proposed_authority` and `recipient_commitment`.
    pub recipient_commitment: [u8; 32],
    /// Event-schema version. `1`; the contract rejects
    /// `> MAX_KNOWN_SCHEMA_VERSION`.
    pub schema_version: u16,
}

/// A guardian's signed V2 `Approve` attestation: the field set + the
/// 65-byte secp256k1 signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedApprovalV2 {
    /// The same field set the digest was computed over.
    pub fields: ApproveFieldsV2,
    /// Exactly 65 bytes: `r (32) || s (32) || v (1)`.
    pub signature: [u8; 65],
}

/// Compute the EIP-712 struct-hash for an [`ApproveFieldsV2`].
///
/// Mirrors `RecoveryV2.sol::_hashApprove`'s struct-hash (7 abi-encoded
/// 32-byte words: typehash + 6 fields). Drift in the buffer size or field
/// order fires loudly because `approve_typehash_v2_matches_pinned_constant`
/// + the anvil E2E would diverge.
#[must_use]
pub fn approve_struct_hash_v2(fields: &ApproveFieldsV2) -> B256 {
    // 7 × 32 bytes = 224 bytes (V1 was 6×32 = 192).
    let mut buf = [0u8; 7 * 32];
    let mut o = 0usize;
    buf[o..o + 32].copy_from_slice(&APPROVE_TYPEHASH_V2);
    o += 32;
    buf[o..o + 32].copy_from_slice(&fields.vault_id);
    o += 32;
    buf[o + 12..o + 32].copy_from_slice(fields.proposed_authority.as_slice());
    o += 32;
    buf[o + 24..o + 32].copy_from_slice(&fields.attempt_nonce.to_be_bytes());
    o += 32;
    buf[o + 24..o + 32].copy_from_slice(&fields.expires_at.to_be_bytes());
    o += 32;
    buf[o..o + 32].copy_from_slice(&fields.recipient_commitment);
    o += 32;
    buf[o + 30..o + 32].copy_from_slice(&fields.schema_version.to_be_bytes());
    o += 32;
    debug_assert_eq!(o, buf.len(), "approve_struct_hash_v2 buffer drift");
    keccak256(buf)
}

/// Compute the V2 EIP-712 `Approve` digest the V2 contract verifies.
#[must_use]
pub fn approve_digest_v2(
    verifying_contract: Address,
    chain_id: u64,
    fields: &ApproveFieldsV2,
) -> B256 {
    let domain = build_domain_recovery(verifying_contract, chain_id);
    let domain_sep = domain.separator();
    let s_hash = approve_struct_hash_v2(fields);
    eip712_digest(domain_sep, s_hash)
}

/// Sign a V2 `Approve` attestation with a guardian's `PrivateKeySigner`,
/// returning a [`SignedApprovalV2`].
///
/// # Errors
///
/// [`ChainError::Wallet`] if the signer's internal `sign_hash_sync`
/// returns an error.
pub fn build_signed_approval_v2(
    signer: &PrivateKeySigner,
    fields: ApproveFieldsV2,
    verifying_contract: Address,
    chain_id: u64,
) -> Result<SignedApprovalV2, ChainError> {
    let digest = approve_digest_v2(verifying_contract, chain_id, &fields);
    let sig = signer
        .sign_hash_sync(&digest)
        .map_err(|_e| ChainError::Wallet("alloy signer error signing V2 Approve digest"))?;
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

    Ok(SignedApprovalV2 { fields, signature })
}

/// Recover the EVM address that signed a V2 `Approve` attestation.
///
/// # Errors
///
/// [`ChainError::SignerRecoveryFailed`] on high-s, bad `v`, or a
/// curve-level malformed signature.
pub fn recover_approver_v2(
    approval: &SignedApprovalV2,
    verifying_contract: Address,
    chain_id: u64,
) -> Result<Address, ChainError> {
    let digest = approve_digest_v2(verifying_contract, chain_id, &approval.fields);

    let mut s_be = [0u8; 32];
    s_be.copy_from_slice(&approval.signature[32..64]);
    if !is_canonical_s(&s_be) {
        return Err(ChainError::SignerRecoveryFailed {
            detail: "V2 Approve signature s component is non-canonical (high-s)".to_string(),
        });
    }
    let v_byte = approval.signature[64];
    if v_byte != 27 && v_byte != 28 {
        return Err(ChainError::SignerRecoveryFailed {
            detail: format!("V2 Approve signature v byte not in {{27,28}}: got {v_byte}"),
        });
    }

    let r = U256::from_be_slice(&approval.signature[0..32]);
    let s = U256::from_be_slice(&approval.signature[32..64]);
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

    /// Deterministic guardian wallet for tests, derived from a pinned
    /// seed so signatures are byte-stable across runs.
    fn guardian_wallet(seed_byte: u8) -> PrivateKeySigner {
        let device = DeviceKey::from_seed([seed_byte; 32]);
        derive_evm_wallet(&device)
            .expect("derive guardian wallet")
            .into_signer()
    }

    fn sample_fields() -> ApproveFieldsV1 {
        ApproveFieldsV1 {
            vault_id: [0x11; 32],
            proposed_authority: Address::from([0x22; 20]),
            attempt_nonce: 7,
            expires_at: 1_900_000_000,
            schema_version: 1,
        }
    }

    /// L3: the pinned `APPROVE_TYPEHASH_V1` equals the keccak of the
    /// literal struct-definition string from the contract
    /// (`RecoveryV1.sol:330-332`). Cheapest test possible; catches a
    /// future contributor mis-typing the literal.
    #[test]
    fn approve_typehash_matches_pinned_constant() {
        let literal = "Approve(bytes32 vaultId,address proposedAuthority,uint64 attemptNonce,uint64 expiresAt,uint16 schemaVersion)";
        let computed = keccak256(literal.as_bytes());
        assert_eq!(
            computed.0, APPROVE_TYPEHASH_V1,
            "Approve typehash literal must keccak to the pinned constant"
        );
    }

    /// L3: the recovery domain separator constructed via
    /// `eip712_domain!` for the anvil first-deploy address + chainId
    /// 31337 matches the pinned anvil-dev constant. This is the
    /// hermetic half of the domain-separator pin; the anvil lifecycle
    /// round-trip is the end-to-end half.
    #[test]
    fn recovery_domain_separator_matches_pinned_anvil_value() {
        let anvil_addr: Address = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
            .parse()
            .unwrap();
        let domain = build_domain_recovery(anvil_addr, 31_337);
        let sep = domain.separator();
        assert_eq!(
            sep.0, RECOVERY_DOMAIN_SEPARATOR_ANVIL_DEV_V1,
            "alloy-constructed recovery domain separator must equal pinned anvil-dev value"
        );
    }

    /// L3 `BaseSepolia` capture (L-0a-1 deploy): the recovery domain
    /// separator constructed via `eip712_domain!` for the deployed
    /// `RecoveryV2` address + Base Sepolia chain id 84532 matches the
    /// pinned constant. The hermetic half of the `BaseSepolia` separator
    /// pin; the live-contract `cast call` (recorded in the deployment
    /// JSON) is the on-chain half — both must agree byte-for-byte.
    #[test]
    fn recovery_v2_domain_separator_matches_pinned_base_sepolia_value() {
        let domain = build_domain_recovery(EXPECTED_RECOVERY_V2_ADDRESS_BASE_SEPOLIA, 84_532);
        let sep = domain.separator();
        assert_eq!(
            sep.0, RECOVERY_DOMAIN_SEPARATOR_BASE_SEPOLIA_V2,
            "alloy-constructed RecoveryV2 domain separator must equal pinned Base Sepolia value \
             (chain_id 84532 + contract 0xf0E08fd009d8a33ba844610dAdD90450C1C206CA)"
        );
    }

    /// L3: sign + recover round-trip recovers the guardian's own
    /// address. The load-bearing property that the off-chain signer +
    /// the recovery verifier share one digest construction.
    #[test]
    fn sign_recover_round_trip() {
        let signer = guardian_wallet(0x42);
        let verifying = Address::from([0xAB; 20]);
        let chain_id = 31_337;
        let fields = sample_fields();
        let approval =
            build_signed_approval_v1(&signer, fields, verifying, chain_id).expect("sign approval");
        assert_eq!(approval.signature.len(), 65);
        let recovered = recover_approver_v1(&approval, verifying, chain_id).expect("recover");
        assert_eq!(
            recovered,
            signer.address(),
            "recovered approver must equal the guardian signer"
        );
    }

    /// A signature recovered under a DIFFERENT chain id must NOT
    /// recover the same signer — confirms the chain id is bound into
    /// the digest (cross-chain replay defense).
    #[test]
    fn wrong_chain_id_recovers_different_signer() {
        let signer = guardian_wallet(0x43);
        let verifying = Address::from([0xCD; 20]);
        let fields = sample_fields();
        let approval =
            build_signed_approval_v1(&signer, fields, verifying, 31_337).expect("sign approval");
        let recovered = recover_approver_v1(&approval, verifying, 84_532).expect("recover");
        assert_ne!(
            recovered,
            signer.address(),
            "a different chain id must bind a different digest → different recovered signer"
        );
    }

    /// `v ∈ {27,28}` and `s` canonical-low on a freshly produced
    /// signature.
    #[test]
    fn signature_shape_is_canonical() {
        let signer = guardian_wallet(0x44);
        let approval =
            build_signed_approval_v1(&signer, sample_fields(), Address::from([0x01; 20]), 31_337)
                .expect("sign");
        let v = approval.signature[64];
        assert!(v == 27 || v == 28, "v must be 27 or 28, got {v}");
        let mut s_be = [0u8; 32];
        s_be.copy_from_slice(&approval.signature[32..64]);
        assert!(is_canonical_s(&s_be), "s must be canonical-low");
    }

    // -----------------------------------------------------------------
    // V2 surface tests
    // -----------------------------------------------------------------

    fn sample_fields_v2() -> ApproveFieldsV2 {
        ApproveFieldsV2 {
            vault_id: [0x11; 32],
            proposed_authority: Address::from([0x22; 20]),
            attempt_nonce: 7,
            expires_at: 1_900_000_000,
            recipient_commitment: [0xC0; 32],
            schema_version: 1,
        }
    }

    /// L3: the pinned `APPROVE_TYPEHASH_V2` equals the keccak of the V2
    /// literal string from `RecoveryV2.sol`'s `APPROVE_TYPEHASH`. Drift
    /// in either the contract literal or the Rust pin fires here.
    #[test]
    fn approve_typehash_v2_matches_pinned_constant() {
        let literal = "Approve(bytes32 vaultId,address proposedAuthority,uint64 attemptNonce,uint64 expiresAt,bytes32 recipientCommitment,uint16 schemaVersion)";
        let computed = keccak256(literal.as_bytes());
        assert_eq!(
            computed.0, APPROVE_TYPEHASH_V2,
            "V2 Approve typehash literal must keccak to the pinned constant"
        );
    }

    /// The V1 and V2 typehashes are deliberately distinct (V2 added
    /// `bytes32 recipientCommitment`). This pin closes any future
    /// accidental same-hash collision.
    #[test]
    fn v1_and_v2_typehashes_are_distinct() {
        assert_ne!(
            APPROVE_TYPEHASH_V1, APPROVE_TYPEHASH_V2,
            "V1 and V2 Approve typehashes must differ — anti-cross-version-replay"
        );
    }

    /// L3: V2 sign + recover round-trip recovers the guardian's own
    /// address.
    #[test]
    fn sign_recover_round_trip_v2() {
        let signer = guardian_wallet(0x45);
        let verifying = Address::from([0xAB; 20]);
        let chain_id = 31_337;
        let fields = sample_fields_v2();
        let approval =
            build_signed_approval_v2(&signer, fields, verifying, chain_id).expect("sign V2");
        assert_eq!(approval.signature.len(), 65);
        let recovered = recover_approver_v2(&approval, verifying, chain_id).expect("recover V2");
        assert_eq!(
            recovered,
            signer.address(),
            "V2 recovered approver must equal the guardian signer"
        );
    }

    /// V2 digest changes if the commitment changes — concrete anti-redirect
    /// pin: a sig over commitment A is NOT valid against an attempt
    /// with stored commitment B.
    #[test]
    fn v2_digest_changes_with_commitment() {
        let signer = guardian_wallet(0x46);
        let verifying = Address::from([0xCD; 20]);
        let chain_id = 31_337;
        let mut f1 = sample_fields_v2();
        f1.recipient_commitment = [0xAA; 32];
        let mut f2 = sample_fields_v2();
        f2.recipient_commitment = [0xBB; 32];
        let d1 = approve_digest_v2(verifying, chain_id, &f1);
        let d2 = approve_digest_v2(verifying, chain_id, &f2);
        assert_ne!(d1, d2, "V2 digest must depend on recipient_commitment");
        // And a sig over d1 recovered against the d2 digest's verifier
        // recovers a DIFFERENT address (i.e. the on-chain check fails).
        let a1 = build_signed_approval_v2(&signer, f1, verifying, chain_id).expect("sign f1");
        let mismatched = SignedApprovalV2 {
            fields: f2,
            signature: a1.signature,
        };
        let recovered = recover_approver_v2(&mismatched, verifying, chain_id).expect("recover");
        assert_ne!(
            recovered,
            signer.address(),
            "a commitment mismatch must recover a different signer (anti-redirect binding holds)"
        );
    }
}
