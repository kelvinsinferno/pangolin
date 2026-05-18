// SPDX-License-Identifier: AGPL-3.0-or-later
//! EIP-712 v1 secp256k1 signed-revision builder.
//!
//! **Scope (MVP-2 issue 3.1, R-a..R-e signed off by Kelvin 2026-05-14):**
//! produce 65-byte secp256k1 signatures (`r ‖ s ‖ v`, canonical-s, `v ∈
//! {27,28}`) over the EIP-712 typed-data digest that the deployed
//! `RevisionLogV1` contract at
//! `0x179362Ad7fb7dA664312aEFDdaa53431eb748E42` (D-017, Base Sepolia,
//! `chainId=84_532`) verifies via its `_recover` function. This module is
//! the **client-side** half of 2.1's chain-side substrate; the
//! broadcast layer (`eth_sendRawTransaction`) lands in MVP-2 issue 3.3,
//! and the verifier (off-chain `recover`) ships with MVP-2 issue 4.1
//! per R-d.
//!
//! ## Clean-break v0 → v1 (R-a verbatim)
//!
//! v0 `SignedRevision` records in legacy `.pvf` files stay readable
//! via the retained Ed25519 path in [`crate::signing`] (R-b) but are
//! NEVER re-broadcast under v1. New v1 publishes start at a fresh
//! per-vault sequence on chain; legacy v0 lineage is severed by
//! design. The two modules do not share types — [`SignedRevisionV1`]
//! here is a separate struct from `crate::types::SignedRevision`.
//!
//! ## Why this is security-critical
//!
//! This module produces the bytes the on-chain contract `ecrecover`s.
//! Any drift from the contract's expectations is silent and total:
//!
//! - Wrong typehash, wrong domain, wrong `v` byte, non-canonical `s`,
//!   or a wrong-`chainId` binding => the contract recovers a *wrong*
//!   address; every publish reverts; every user is broken.
//! - Per R-b self-bootstrap (2.1 R-b), a domain-binding misconfig that
//!   happens to land on a fresh `vaultId` silently registers the
//!   wrong device for that vault on-chain; v1 has no revocation
//!   (MVP-3 territory). See `docs/issue-plans/3.1.md` L-domain-binding
//!   for the worst-case adversary leverage.
//!
//! The L1..L11 invariants in `docs/issue-plans/3.1.md` enumerate the
//! load-bearing properties; this module enforces them mechanically
//! (constants + tests + the
//! [`ChainError::DeploymentAddressMismatch`](crate::ChainError) cross-check).
//!
//! ## EIP-712 envelope (L2, L3 verbatim)
//!
//! - `name = "Pangolin RevisionLog"`
//! - `version = "1"`
//! - `chainId = 84_532` (Base Sepolia, D-017)
//! - `verifyingContract = 0x179362Ad7fb7dA664312aEFDdaa53431eb748E42`
//!
//! Typehash string (the literal byte string fed into the spec keccak):
//!
//! ```text
//! Revision(bytes32 vaultId,bytes32 accountId,bytes32 parentRevision,bytes32 deviceId,uint16 schemaVersion,bytes32 encPayloadHash)
//! ```
//!
//! Both the typehash and the resulting domain separator are pinned
//! per R-e as `[u8; 32]` constants captured from the live D-017
//! contract at plan-gate time (2026-05-14). Two hermetic tests
//! (`typehash_matches_pinned_constant` +
//! `domain_separator_matches_pinned_constant`) keccak the spec
//! literal / construct the domain via the same alloy primitives the
//! production path uses and assert byte-equality with the constants;
//! a future drift in either the literal string or the alloy macro
//! fires loudly in CI before merge.
//!
//! ## Signature shape (L1 verbatim)
//!
//! 65 bytes laid out as `r (32) || s (32) || v (1)` with `v ∈
//! {27,28}` (the legacy non-EIP-155 form, since EIP-712 typed-data
//! binds the chain id into the domain separator, not into `v`). The
//! `s` component is canonical-low — `s ≤ secp256k1n/2` — enforced
//! defensively even though k256's `sign_prehash_recoverable` produces
//! low-s by default.

use alloy::primitives::{address, hex, keccak256, Address, B256, U256};
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::SignerSync;
use alloy::sol_types::{eip712_domain, Eip712Domain};

use crate::deployments::{load_deployed_address, ChainEnv};
use crate::error::ChainError;
use crate::evm::EvmWallet;

/// Off-chain Rust-side domain-prefix marker (L4 verbatim).
///
/// **NOT** read by the on-chain contract — the contract verifies the
/// EIP-712 typed-data digest, period. This constant exists for
/// internal bookkeeping: an attacker who steals a v0 Ed25519 signature
/// CANNOT replay it as a v1 secp256k1 signature, because (a) the
/// primitives differ and (b) the Rust-side domain prefix differs.
/// Off-chain consumers (the eventual chain-sync indexer, the ingest
/// replay check) tag v1 records with this string to refuse a cross-
/// version replay at the storage boundary.
pub const SIGNED_REVISION_DOMAIN_V1: &str = "pangolin-chain-signed-revision-v1";

/// Pinned EIP-712 typehash for the `Revision` struct (L3 + R-e
/// verbatim).
///
/// Equals `keccak256("Revision(bytes32 vaultId,bytes32 accountId,bytes32 parentRevision,bytes32 deviceId,uint16 schemaVersion,bytes32 encPayloadHash)")`,
/// independently verified by the `typehash_matches_pinned_constant`
/// hermetic test (which re-keccaks the literal). Captured at 3.1
/// plan-gate time (2026-05-14).
pub const REVISION_TYPEHASH_V1: [u8; 32] =
    hex!("240c1b72b1e92476cf861a8c19ed0f617734c55e97342ad6f99ed18467b8d211");

/// Pinned EIP-712 domain separator for D-017 on Base Sepolia (R-e
/// verbatim).
///
/// Captured from `cast call 0x179362Ad7fb7dA664312aEFDdaa53431eb748E42
/// "domainSeparator()(bytes32)" --rpc-url https://sepolia.base.org` at
/// 3.1 plan-gate time (2026-05-14 18:50 ET). The
/// `domain_separator_matches_pinned_constant` hermetic test
/// constructs the same domain via [`eip712_domain!`] + asserts
/// byte-equality with this constant; a future drift in any of `name`,
/// `version`, `chainId`, or `verifyingContract` fires loudly in CI.
pub const DOMAIN_SEPARATOR_BASE_SEPOLIA_V1: [u8; 32] =
    hex!("9d1538887c3954f21ebe2602655bba85334719e130e5ba4a5c729bde968f0c62");

/// Pinned-at-source expected deployment address for D-017 on Base
/// Sepolia (L-domain-binding defense).
///
/// [`build_signed_revision_v1`] cross-checks the
/// `load_deployed_address(BaseSepolia, "RevisionLogV1")` result
/// against this constant before producing a signature; mismatch fails
/// closed with [`ChainError::DeploymentAddressMismatch`]. Defends
/// against both a tampered `contracts/deployments/base-sepolia.json`
/// and a legitimate redeploy without a coordinated binary rebuild.
pub const EXPECTED_DEPLOYED_ADDRESS_BASE_SEPOLIA: Address =
    address!("0x179362Ad7fb7dA664312aEFDdaa53431eb748E42");

/// EIP-712 domain string for the contract `name` field (L2 verbatim).
const DOMAIN_NAME: &str = "Pangolin RevisionLog";

/// EIP-712 domain string for the contract `version` field (L2
/// verbatim).
const DOMAIN_VERSION: &str = "1";

/// Half-order constant for secp256k1's group order `n` — the upper
/// bound for canonical-low-s sigs (EIP-2). Equals `n/2`.
const SECP256K1_HALF_N: [u8; 32] =
    hex!("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0");

/// Inputs to the v1 signed-revision builder.
///
/// The six EIP-712 `Revision` struct fields, all reduced to
/// fixed-width `bytes32` (the contract's `_hashRevision` reads them
/// as `bytes32` / `uint16`). The payload is **pre-reduced** to
/// `keccak256(encPayload)` by the caller — see L-payload-hash-prereduction
/// in `docs/issue-plans/3.1.md` for why the EIP-712 struct binds the
/// digest, not the raw payload.
///
/// Per R-a (Path B device-id semantics): `device_id` is the
/// secp256k1 EVM address of the signing wallet, left-padded with 12
/// zero bytes into a `bytes32`. Helpers
/// [`RevisionFieldsV1::device_id_from_address`] +
/// [`RevisionFieldsV1::with_signer_device_id`] make this explicit at
/// the construction site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevisionFieldsV1 {
    /// 32-byte vault identifier (the AEAD-AAD-bound id of the vault
    /// the revision belongs to).
    pub vault_id: [u8; 32],
    /// 32-byte account identifier within the vault.
    pub account_id: [u8; 32],
    /// 32-byte parent revision id (zero for a genesis revision).
    pub parent_revision: [u8; 32],
    /// 32-byte device id. Under Path B (R-a) this is the secp256k1
    /// EVM address of the signing wallet, left-padded with 12 zero
    /// bytes (12 leading zeros || 20 address bytes).
    pub device_id: [u8; 32],
    /// `schema_version` widened to `u16` per 2.1 L5 (was `u8` in v0).
    pub schema_version: u16,
    /// `keccak256(encPayload)` — the EIP-712 struct binds the digest,
    /// not the raw bytes (L-payload-hash-prereduction).
    pub enc_payload_hash: [u8; 32],
}

impl RevisionFieldsV1 {
    /// Left-pad an EVM address into a `bytes32` per the v1 contract's
    /// `deviceId` semantics: 12 zero bytes ‖ 20 address bytes.
    #[must_use]
    pub fn device_id_from_address(addr: Address) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[12..].copy_from_slice(addr.as_slice());
        out
    }

    /// Convenience: build a `RevisionFieldsV1` whose `device_id` is
    /// derived from the given wallet's EVM address. Mirrors the Path B
    /// semantics the v1 contract assumes.
    #[must_use]
    pub fn with_signer_device_id(
        wallet: &EvmWallet,
        vault_id: [u8; 32],
        account_id: [u8; 32],
        parent_revision: [u8; 32],
        schema_version: u16,
        enc_payload_hash: [u8; 32],
    ) -> Self {
        Self {
            vault_id,
            account_id,
            parent_revision,
            device_id: Self::device_id_from_address(wallet.address()),
            schema_version,
            enc_payload_hash,
        }
    }
}

/// Output of [`build_signed_revision_v1`]: the input fields plus the
/// raw `encPayload` preimage plus the 65-byte `r ‖ s ‖ v` signature.
///
/// Not a variant of [`crate::types::SignedRevision`] — that one is
/// Ed25519-shaped (64-byte sig over a `keccak`-of-fixed-fields digest,
/// retained for v0 read-back per R-b). The clean-break v0 → v1
/// boundary is at the type level here so a caller cannot accidentally
/// publish a v0 record under v1's API or vice versa.
///
/// ## INVARIANT (3.3 audit-HIGH fix, 2026-05-14)
///
/// `keccak256(enc_payload) == fields.enc_payload_hash`. The EIP-712
/// digest the signature was produced over binds the 32-byte
/// `enc_payload_hash` (cheap on-chain) — but the on-chain contract
/// re-derives that hash from the raw `encPayload` calldata bytes the
/// broadcast layer sends (`contracts/src/RevisionLogV1.sol:312-314`).
/// The broadcast layer MUST forward the preimage on the wire, not the
/// hash; otherwise the contract computes `keccak256(hash)` and recovers
/// a wrong signer → `ErrInvalidSignature` revert on every live publish.
///
/// The invariant is checked at construction in
/// [`build_signed_revision_v1`] via `debug_assert!`; the broadcast leg
/// in `chain_submit::broadcast_with_retries` reads `enc_payload` (not
/// `fields.enc_payload_hash`) when filling the `publishRevision` call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRevisionV1 {
    /// The same field set the digest was computed over.
    pub fields: RevisionFieldsV1,
    /// The raw `encPayload` preimage bytes the broadcast layer puts on
    /// the wire as the `bytes encPayload` calldata argument to
    /// `publishRevision`. INVARIANT: `keccak256(self.enc_payload) ==
    /// self.fields.enc_payload_hash`. Owning the preimage on
    /// `SignedRevisionV1` makes the "what gets broadcast" question
    /// answered at the type — drift between signer + broadcaster is
    /// impossible by construction.
    pub enc_payload: Vec<u8>,
    /// Exactly 65 bytes: `r (32) || s (32) || v (1)`; `v ∈ {27,28}`;
    /// `s ≤ secp256k1n/2`.
    pub signature: [u8; 65],
}

/// Construct the EIP-712 domain for a given env via the same alloy
/// primitive the test path uses.
///
/// `BaseSepolia` is the only env whose `verifyingContract` is locked
/// today (D-017). `BaseMainnet` / `Dev` are placeholders that read
/// their `verifyingContract` from the deployment file too; the
/// pinned-constant cross-check in [`build_signed_revision_v1`] only
/// applies to `BaseSepolia`.
pub(crate) fn build_domain(env: ChainEnv, verifying_contract: Address) -> Eip712Domain {
    let chain_id = env.chain_id().unwrap_or(0);
    // The macro stamps `name` / `version` into a `Cow<'static, str>`
    // — passing the literal directly via `String::from(...)` would be
    // wasteful; pass the const slot so the macro picks the
    // `Cow::Borrowed` arm.
    eip712_domain! {
        name: DOMAIN_NAME,
        version: DOMAIN_VERSION,
        chain_id: chain_id,
        verifying_contract: verifying_contract,
    }
}

/// Compute the EIP-712 struct-hash for a [`RevisionFieldsV1`].
///
/// Mirrors the contract's `_hashRevision`:
///
/// ```text
/// structHash = keccak256(
///     abi.encode(
///         REVISION_TYPEHASH,
///         vaultId,        // bytes32
///         accountId,      // bytes32
///         parentRevision, // bytes32
///         deviceId,       // bytes32
///         schemaVersion,  // uint16 (encoded left-padded to bytes32)
///         encPayloadHash  // bytes32
///     )
/// )
/// ```
pub(crate) fn struct_hash(fields: &RevisionFieldsV1) -> B256 {
    // 7 × 32 bytes = 224 bytes.
    let mut buf = [0u8; 7 * 32];
    let mut o = 0usize;
    buf[o..o + 32].copy_from_slice(&REVISION_TYPEHASH_V1);
    o += 32;
    buf[o..o + 32].copy_from_slice(&fields.vault_id);
    o += 32;
    buf[o..o + 32].copy_from_slice(&fields.account_id);
    o += 32;
    buf[o..o + 32].copy_from_slice(&fields.parent_revision);
    o += 32;
    buf[o..o + 32].copy_from_slice(&fields.device_id);
    o += 32;
    // `uint16` ABI-encodes to a left-padded 32-byte word. Bytes
    // [o..o+30] stay zero; the two-byte big-endian value lands at
    // [o+30..o+32].
    buf[o + 30..o + 32].copy_from_slice(&fields.schema_version.to_be_bytes());
    o += 32;
    buf[o..o + 32].copy_from_slice(&fields.enc_payload_hash);
    debug_assert_eq!(o + 32, buf.len(), "struct_hash buffer drift");
    keccak256(buf)
}

/// EIP-712 final digest: `keccak256(0x1901 ‖ domainSeparator ‖
/// structHash)`.
pub(crate) fn eip712_digest(domain_sep: B256, struct_hash_value: B256) -> B256 {
    // 2 + 32 + 32 = 66 bytes.
    let mut buf = [0u8; 66];
    buf[0] = 0x19;
    buf[1] = 0x01;
    buf[2..34].copy_from_slice(domain_sep.as_slice());
    buf[34..66].copy_from_slice(struct_hash_value.as_slice());
    keccak256(buf)
}

/// Assert that `s ≤ secp256k1n/2` (canonical-low-s per EIP-2). Returns
/// `true` if the input is canonical-low.
///
/// Public so client-side verifiers (e.g., the funder's Credit-sig
/// verifier, audit LOW#3 defense-in-depth) can reject high-s sigs at
/// the HTTP layer before consuming chain resources. Same constant
/// (`SECP256K1_HALF_N`) every other call site uses.
#[must_use]
pub fn is_canonical_s(s_be: &[u8; 32]) -> bool {
    // Compare as big-endian unsigned ints. `<=` is a constant-time
    // pattern on the [u8; 32] representation; the comparison value is
    // public (a curve constant) so timing leakage is moot, but the
    // pattern is the audit-friendly form.
    for i in 0..32 {
        match s_be[i].cmp(&SECP256K1_HALF_N[i]) {
            core::cmp::Ordering::Less => return true,
            core::cmp::Ordering::Greater => return false,
            core::cmp::Ordering::Equal => {}
        }
    }
    true // exact equality is canonical (s == n/2).
}

/// Recover the secp256k1 EVM address that signed the EIP-712 digest
/// built from `signed_revision.fields` under `chain_env`.
///
/// **MVP-2 issue 4.1 R-d (productionised 3.1 R-d's test-only helper).**
/// Reuses the exact same `build_domain` / `struct_hash` /
/// `eip712_digest` helpers the signing path uses — byte-identical
/// digest construction is the load-bearing property that lets a sign +
/// recover round-trip recover the wallet's own address (L1 invariant).
///
/// Per L-domain-binding (and the
/// [`EXPECTED_DEPLOYED_ADDRESS_BASE_SEPOLIA`] cross-check): for
/// `BaseSepolia`, the helper expects the on-disk deployment file's
/// `RevisionLogV1` address to equal the pinned constant. Mismatch
/// fails closed with [`ChainError::DeploymentAddressMismatch`] (same
/// posture as [`build_signed_revision_v1`]).
///
/// # Errors
///
/// - [`ChainError::DeploymentNotFound`] /
///   [`ChainError::DeploymentParseError`] if the env's deployment file
///   is missing / malformed.
/// - [`ChainError::DeploymentAddressMismatch`] for `BaseSepolia` if the
///   deployment file points anywhere other than D-017.
/// - [`ChainError::SignerRecoveryFailed`] if alloy's
///   `recover_address_from_prehash` fails to recover a well-formed
///   address (e.g., the signature bytes are malformed at the curve
///   level — `r` is zero, `s` is zero, etc.).
pub fn recover_signer_v1(
    signed_revision: &SignedRevisionV1,
    chain_env: ChainEnv,
) -> Result<Address, ChainError> {
    recover_signer_v1_raw(
        &signed_revision.fields,
        &signed_revision.signature,
        chain_env,
    )
}

/// Lower-level variant of [`recover_signer_v1`]: raw inputs entry.
///
/// Takes the raw fields + signature bytes directly. Used by the
/// event-decode path in [`crate::chain_sync`] which naturally produces
/// these inputs from decoded `RevisionPublished` log fields rather
/// than from a [`SignedRevisionV1`] struct.
///
/// Per LOW#3 defense-in-depth (mirrors 3.5's `is_canonical_s` posture):
/// the recovery side asserts `s ≤ secp256k1n/2` BEFORE attempting
/// `recover_address_from_prehash`. A high-s sig from a misbehaving
/// publisher / RPC is rejected with
/// [`ChainError::SignerRecoveryFailed`] rather than silently malleating
/// to a different recovered address.
///
/// # Errors
///
/// Same taxonomy as [`recover_signer_v1`].
pub fn recover_signer_v1_raw(
    fields: &RevisionFieldsV1,
    signature: &[u8; 65],
    chain_env: ChainEnv,
) -> Result<Address, ChainError> {
    // R-c: deployment-file sourcing of `verifyingContract`. Same load
    // helper the signing path uses → digest reconstruction is identical
    // by construction.
    let verifying_contract = load_deployed_address(chain_env, "RevisionLogV1")?;
    // L-domain-binding defense: the pinned-at-source constant is the
    // ground-truth address; mismatch fails closed.
    if matches!(chain_env, ChainEnv::BaseSepolia)
        && verifying_contract != EXPECTED_DEPLOYED_ADDRESS_BASE_SEPOLIA
    {
        return Err(ChainError::DeploymentAddressMismatch {
            env: chain_env,
            expected: EXPECTED_DEPLOYED_ADDRESS_BASE_SEPOLIA,
            actual: verifying_contract,
        });
    }

    // L1 verbatim: re-use the same helpers the signing side ran;
    // re-implementing the digest would create silent-drift surface.
    let domain = build_domain(chain_env, verifying_contract);
    let domain_sep = domain.separator();
    let s_hash = struct_hash(fields);
    let digest = eip712_digest(domain_sep, s_hash);

    // LOW#3 defense-in-depth: a malicious publisher / RPC could submit
    // a high-s signature that the on-chain `ecrecover` would tolerate
    // (Ethereum's precompile is permissive); the client-side recovery
    // is canonical-only so the local revision-graph never absorbs a
    // malleability twin.
    let mut s_be = [0u8; 32];
    s_be.copy_from_slice(&signature[32..64]);
    if !is_canonical_s(&s_be) {
        return Err(ChainError::SignerRecoveryFailed {
            detail: "signature s component is non-canonical (high-s)".to_string(),
        });
    }
    // `v` byte sanity — alloy's `Signature::new(y_parity: bool)`
    // accepts either parity but EIP-712 binds `v ∈ {27,28}`. Reject
    // anything else early so a malformed publish fires loudly here
    // rather than landing under a wrong address downstream.
    let v_byte = signature[64];
    if v_byte != 27 && v_byte != 28 {
        return Err(ChainError::SignerRecoveryFailed {
            detail: format!("signature v byte not in {{27,28}}: got {v_byte}"),
        });
    }

    let r = U256::from_be_slice(&signature[0..32]);
    let s = U256::from_be_slice(&signature[32..64]);
    let y_parity = v_byte == 28;
    let sig = alloy::primitives::Signature::new(r, s, y_parity);
    sig.recover_address_from_prehash(&digest)
        .map_err(|e| ChainError::SignerRecoveryFailed {
            detail: format!("alloy recover_address_from_prehash failed: {e}"),
        })
}

/// Sign the EIP-712 digest with `signer`, returning a 65-byte
/// `r ‖ s ‖ v` signature with `v ∈ {27,28}` and `s ≤ secp256k1n/2`.
///
/// Uses alloy's `SignerSync::sign_hash_sync`, which under the hood
/// calls k256's `sign_prehash_recoverable` and exposes the resulting
/// `(r, s, y_parity)` via alloy's `Signature` type. We then:
///
/// 1. Defensively normalise to low-s via the alloy `normalize_s`
///    surface — idempotent if k256 already returned low-s, which it
///    does in 0.13.x; the call is a safety belt for future k256
///    versions.
/// 2. Serialise via `Signature::as_bytes()` which already encodes
///    `27 + y_parity` for the `v` byte (the legacy non-EIP-155
///    form EIP-712 expects).
fn sign_digest_to_rsv(signer: &PrivateKeySigner, digest: B256) -> Result<[u8; 65], ChainError> {
    let sig = signer
        .sign_hash_sync(&digest)
        .map_err(|e| ChainError::Wallet(leak_proof_signer_error(&e)))?;
    // alloy's `normalize_s` returns `Some(...)` only if a change was
    // needed; otherwise the signature was already canonical. Either
    // way we end up with the low-s representative.
    let canonical = sig.normalize_s().unwrap_or(sig);
    let bytes = canonical.as_bytes();
    Ok(bytes)
}

/// Map an alloy signer error into a static `&'static str` for
/// [`ChainError::Wallet`]. We deliberately ignore the dynamic message
/// because `Wallet` carries a `&'static str` and the signer's own
/// `Display` already redacts secret material; the static label below
/// suffices for the audit-friendly failure path. Any new
/// surface-shaping the alloy team adds upstream will land via the
/// integration tests.
fn leak_proof_signer_error(_e: &alloy::signers::Error) -> &'static str {
    "alloy signer returned an error while signing EIP-712 digest"
}

/// Build a v1 signed-revision over `fields` using `wallet`'s signing
/// key, binding to `chain_env`'s deployed `verifyingContract`.
///
/// Per R-a (Path B): caller is expected to set `fields.device_id` to
/// the left-padded EVM address of `wallet` (see
/// [`RevisionFieldsV1::with_signer_device_id`]); this fn does NOT
/// rewrite the supplied `device_id` on the caller's behalf —
/// preserves caller intent so a mis-aligned `device_id` fires loudly
/// in the round-trip recovery test rather than silently being
/// "fixed".
///
/// Per L-domain-binding (and the
/// [`EXPECTED_DEPLOYED_ADDRESS_BASE_SEPOLIA`] cross-check): for
/// `BaseSepolia`, asserts the on-disk deployment file's
/// `RevisionLogV1` address equals the source-pinned constant before
/// signing.
///
/// # Arguments
///
/// - `wallet` — the active session's `EvmWallet`.
/// - `fields` — the six EIP-712 `Revision` struct fields. Caller is
///   responsible for populating `fields.enc_payload_hash` =
///   `keccak256(enc_payload)`.
/// - `enc_payload` — the **raw** `encPayload` preimage. Stored on the
///   returned [`SignedRevisionV1`] so the broadcast layer puts the
///   preimage (not the hash) on the wire when calling
///   `publishRevision`. INVARIANT: `keccak256(enc_payload) ==
///   fields.enc_payload_hash` (`debug_assert!` in debug builds; the
///   3.3 audit-HIGH fix is the load-bearing reason this is required).
/// - `chain_env` — which env to bind the EIP-712 domain to.
///
/// # Errors
///
/// - [`ChainError::DeploymentNotFound`] / [`ChainError::DeploymentParseError`]
///   if `contracts/deployments/<env>.json` is missing / malformed.
/// - [`ChainError::DeploymentAddressMismatch`] for `BaseSepolia` if
///   the deployment file points anywhere other than D-017.
/// - [`ChainError::Wallet`] if the signer's internal `sign_prehash`
///   returns an error — vanishingly rare under k256 0.13.x.
pub fn build_signed_revision_v1(
    wallet: &EvmWallet,
    fields: RevisionFieldsV1,
    enc_payload: Vec<u8>,
    chain_env: ChainEnv,
) -> Result<SignedRevisionV1, ChainError> {
    // 3.3 audit-HIGH fix: the on-chain contract recomputes
    // `keccak256(encPayload)` on the calldata bytes; the EIP-712 digest
    // we sign here binds `fields.enc_payload_hash`. If the two are not
    // identical, the contract recovers a wrong signer at submit time
    // → `ErrInvalidSignature` revert. `debug_assert!` so cargo test
    // catches construction-site drift cheaply.
    debug_assert_eq!(
        keccak256(&enc_payload).0,
        fields.enc_payload_hash,
        "SignedRevisionV1 INVARIANT: keccak256(enc_payload) must equal fields.enc_payload_hash"
    );

    // R-c: deployment-file sourcing of `verifyingContract`.
    let verifying_contract = load_deployed_address(chain_env, "RevisionLogV1")?;
    // L-domain-binding defense: the pinned-at-source constant is the
    // ground-truth address; mismatch fails closed.
    if matches!(chain_env, ChainEnv::BaseSepolia)
        && verifying_contract != EXPECTED_DEPLOYED_ADDRESS_BASE_SEPOLIA
    {
        return Err(ChainError::DeploymentAddressMismatch {
            env: chain_env,
            expected: EXPECTED_DEPLOYED_ADDRESS_BASE_SEPOLIA,
            actual: verifying_contract,
        });
    }

    // Build the EIP-712 domain separator via the same alloy primitive
    // the hermetic `domain_separator_matches_pinned_constant` test
    // exercises; that test is the byte-equality cross-check against
    // the live D-017 contract's `domainSeparator()` view fn.
    let domain = build_domain(chain_env, verifying_contract);
    let domain_sep = domain.separator();
    let s_hash = struct_hash(&fields);
    let digest = eip712_digest(domain_sep, s_hash);

    // Sign + serialise to `r ‖ s ‖ v`. The `v` byte lands in {27,28}
    // by alloy's `as_bytes` impl; `s` is low-s after `normalize_s`.
    let signature = sign_digest_to_rsv(wallet.signer(), digest)?;

    // Defensive structural asserts — these are invariants the bytes
    // we just produced MUST satisfy; if any fails it's a bug in the
    // builder, not user input. Asserts catch L1 drift at the source.
    debug_assert!(
        signature[64] == 27 || signature[64] == 28,
        "v must be in {{27,28}} for EIP-712"
    );
    let mut s_be = [0u8; 32];
    s_be.copy_from_slice(&signature[32..64]);
    debug_assert!(is_canonical_s(&s_be), "s must be canonical-low (s <= n/2)");

    // Defense-in-depth: zero the local `s_be` view (already a copy of
    // public sig bytes, but the pattern keeps the invariant explicit).
    let _ = s_be;
    Ok(SignedRevisionV1 {
        fields,
        enc_payload,
        signature,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{Address, U256};
    use pangolin_crypto::keys::DeviceKey;

    use crate::evm::derive_evm_wallet;

    /// Build a deterministic `EvmWallet` for tests by deriving from
    /// a pinned `DeviceKey` seed. The seed is fixed so signatures are
    /// byte-stable across test runs (catches a silent change to the
    /// derivation path).
    fn fixed_wallet() -> EvmWallet {
        let seed: [u8; 32] = [
            0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
            0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
            0x42, 0x42, 0x42, 0x42,
        ];
        let device = DeviceKey::from_seed(seed);
        derive_evm_wallet(&device).expect("derive fixed wallet")
    }

    /// Test-only recovery helper per R-d: recover the signer address
    /// from a v1 signed revision. Lives ONLY in tests; the production
    /// verifier lands with MVP-2 issue 4.1.
    fn recover_v1_for_test(
        signed: &SignedRevisionV1,
        chain_env: ChainEnv,
    ) -> Result<Address, alloy::primitives::SignatureError> {
        let verifying_contract = match chain_env {
            ChainEnv::BaseSepolia => EXPECTED_DEPLOYED_ADDRESS_BASE_SEPOLIA,
            _ => {
                // For non-Sepolia envs the test cross-check derives
                // the verifyingContract via the same load helper the
                // production path uses, so domain construction
                // matches. If the file is missing we fall back to
                // the all-zero address; the only caller using
                // non-Sepolia in tests is `wrong_chain_id_produces_different_signer`,
                // which deliberately swaps env and expects a different
                // signer regardless.
                load_deployed_address(chain_env, "RevisionLogV1").unwrap_or(Address::ZERO)
            }
        };
        let domain = build_domain(chain_env, verifying_contract);
        let domain_sep = domain.separator();
        let s_hash = struct_hash(&signed.fields);
        let digest = eip712_digest(domain_sep, s_hash);

        // Reconstruct the alloy `Signature` from the 65-byte rsv.
        let r = U256::from_be_slice(&signed.signature[0..32]);
        let s = U256::from_be_slice(&signed.signature[32..64]);
        let v_byte = signed.signature[64];
        let y_parity = v_byte == 28;
        let sig = alloy::primitives::Signature::new(r, s, y_parity);
        sig.recover_address_from_prehash(&digest)
    }

    /// R-e + L3: the pinned `REVISION_TYPEHASH_V1` equals the
    /// keccak of the literal struct definition string from the
    /// contract. Cheapest test possible; catches a future
    /// contributor mis-typing the literal.
    #[test]
    fn typehash_matches_pinned_constant() {
        let literal = "Revision(bytes32 vaultId,bytes32 accountId,bytes32 parentRevision,bytes32 deviceId,uint16 schemaVersion,bytes32 encPayloadHash)";
        let computed = keccak256(literal.as_bytes());
        assert_eq!(
            computed.0, REVISION_TYPEHASH_V1,
            "typehash literal must keccak to the pinned constant"
        );
    }

    /// R-e + L2: the EIP-712 domain separator constructed via
    /// `eip712_domain!` for D-017 matches the constant captured from
    /// the live contract's `domainSeparator()` view fn at plan-gate
    /// time. Catches drift in `name` / `version` / `chainId` /
    /// `verifyingContract`.
    #[test]
    fn domain_separator_matches_pinned_constant() {
        let domain = build_domain(
            ChainEnv::BaseSepolia,
            EXPECTED_DEPLOYED_ADDRESS_BASE_SEPOLIA,
        );
        let sep = domain.separator();
        assert_eq!(
            sep.0, DOMAIN_SEPARATOR_BASE_SEPOLIA_V1,
            "alloy-constructed domain separator must equal pinned D-017 value"
        );
    }

    /// Test helper: produce `(enc_payload, enc_payload_hash)` for a
    /// canonical multi-byte preimage. Used wherever a hermetic test
    /// needs a `RevisionFieldsV1` + matching preimage to satisfy the
    /// [`SignedRevisionV1`] invariant.
    fn sample_enc_payload() -> (Vec<u8>, [u8; 32]) {
        let pre = b"pangolin-test-encpayload-preimage".to_vec();
        let h = keccak256(&pre).0;
        (pre, h)
    }

    /// L1: signature is exactly 65 bytes.
    #[test]
    fn build_signed_revision_v1_produces_65_byte_sig() {
        let wallet = fixed_wallet();
        let (pre, h) = sample_enc_payload();
        let fields = RevisionFieldsV1::with_signer_device_id(
            &wallet, [0x11; 32], [0x22; 32], [0x33; 32], 1, h,
        );
        let signed =
            build_signed_revision_v1(&wallet, fields, pre, ChainEnv::BaseSepolia).expect("sign");
        assert_eq!(signed.signature.len(), 65, "EIP-712 sig is 65 bytes");
    }

    /// L1 + L-canonical-s: `s ≤ n/2`.
    #[test]
    fn build_signed_revision_v1_canonical_s() {
        let wallet = fixed_wallet();
        let (pre, h) = sample_enc_payload();
        let fields = RevisionFieldsV1::with_signer_device_id(
            &wallet, [0x11; 32], [0x22; 32], [0x33; 32], 1, h,
        );
        let signed =
            build_signed_revision_v1(&wallet, fields, pre, ChainEnv::BaseSepolia).expect("sign");
        let mut s_be = [0u8; 32];
        s_be.copy_from_slice(&signed.signature[32..64]);
        assert!(
            is_canonical_s(&s_be),
            "s must be canonical-low (s <= secp256k1n/2)"
        );
    }

    /// L1 + L-v-byte: `v ∈ {27,28}` (legacy non-EIP-155 form).
    #[test]
    fn build_signed_revision_v1_v_in_27_or_28() {
        let wallet = fixed_wallet();
        let (pre, h) = sample_enc_payload();
        let fields = RevisionFieldsV1::with_signer_device_id(
            &wallet, [0x11; 32], [0x22; 32], [0x33; 32], 1, h,
        );
        let signed =
            build_signed_revision_v1(&wallet, fields, pre, ChainEnv::BaseSepolia).expect("sign");
        let v = signed.signature[64];
        assert!(v == 27 || v == 28, "v must be 27 or 28, got {v}");
    }

    /// 3.3 audit-HIGH regression guard: `SignedRevisionV1` ships with
    /// the preimage; `build_signed_revision_v1` carries the
    /// caller-supplied `enc_payload` verbatim onto the output. The
    /// downstream broadcast layer reads `enc_payload` (not
    /// `fields.enc_payload_hash`) when filling `publishRevision`'s
    /// `bytes encPayload` calldata argument; this test pins the
    /// pass-through.
    #[test]
    fn build_signed_revision_v1_carries_preimage() {
        let wallet = fixed_wallet();
        let pre: Vec<u8> = b"audit-HIGH-preimage-pass-through".to_vec();
        let h = keccak256(&pre).0;
        let fields = RevisionFieldsV1::with_signer_device_id(
            &wallet, [0x11; 32], [0x22; 32], [0x33; 32], 1, h,
        );
        let signed = build_signed_revision_v1(&wallet, fields, pre.clone(), ChainEnv::BaseSepolia)
            .expect("sign");
        assert_eq!(
            signed.enc_payload, pre,
            "enc_payload must round-trip onto SignedRevisionV1 verbatim"
        );
        // INVARIANT pinned at the type-level.
        assert_eq!(
            keccak256(&signed.enc_payload).0,
            signed.fields.enc_payload_hash,
            "SignedRevisionV1 invariant must hold: keccak(enc_payload) == fields.enc_payload_hash"
        );
    }

    /// 3.3 audit-HIGH: in debug builds (which `cargo test` always
    /// uses), supplying a mismatched (`enc_payload`,
    /// `fields.enc_payload_hash`) pair panics via the construction
    /// `debug_assert!`. Catches caller-side drift between the hash the
    /// EIP-712 digest binds and the preimage the broadcast layer puts
    /// on the wire.
    #[test]
    #[should_panic(expected = "SignedRevisionV1 INVARIANT")]
    fn build_signed_revision_v1_debug_asserts_preimage_consistency() {
        let wallet = fixed_wallet();
        let pre: Vec<u8> = b"some-preimage".to_vec();
        // Deliberately wrong hash — not keccak256(pre).
        let wrong_hash = [0xCCu8; 32];
        let fields = RevisionFieldsV1::with_signer_device_id(
            &wallet, [0x11; 32], [0x22; 32], [0x33; 32], 1, wrong_hash,
        );
        let _ = build_signed_revision_v1(&wallet, fields, pre, ChainEnv::BaseSepolia);
    }

    /// R-d / round-trip: sign + recover via the test helper; the
    /// recovered signer must equal `wallet.address()`. This is the
    /// load-bearing hermetic coverage for L3 + L-typehash-drift +
    /// L-domain-binding under matched-env conditions.
    #[test]
    fn recover_v1_for_test_round_trip() {
        let wallet = fixed_wallet();
        let (pre, h) = sample_enc_payload();
        let fields = RevisionFieldsV1::with_signer_device_id(
            &wallet, [0x11; 32], [0x22; 32], [0x33; 32], 1, h,
        );
        let signed =
            build_signed_revision_v1(&wallet, fields, pre, ChainEnv::BaseSepolia).expect("sign");
        let recovered = recover_v1_for_test(&signed, ChainEnv::BaseSepolia).expect("recover");
        assert_eq!(
            recovered,
            wallet.address(),
            "round-trip recovery must yield the signer's EVM address"
        );
    }

    /// Per-field tamper: flipping any of the six struct fields
    /// changes the recovered signer (NOT address(0) — ecrecover
    /// always returns *some* address for a well-formed r/s/v).
    /// Covers L-typehash-drift indirectly: a wrong typehash + a
    /// flipped field both produce the same "different signer"
    /// observable.
    #[test]
    fn per_field_tamper_changes_signer() {
        let wallet = fixed_wallet();
        let (pre, h) = sample_enc_payload();
        let base_fields = RevisionFieldsV1::with_signer_device_id(
            &wallet, [0x11; 32], [0x22; 32], [0x33; 32], 1, h,
        );
        let signed = build_signed_revision_v1(&wallet, base_fields, pre, ChainEnv::BaseSepolia)
            .expect("sign baseline");
        let baseline_signer =
            recover_v1_for_test(&signed, ChainEnv::BaseSepolia).expect("recover baseline");
        assert_eq!(baseline_signer, wallet.address());

        // Helper: produce a tampered `SignedRevisionV1` (same sig
        // bytes; one field flipped) and assert recovered signer
        // differs from the original wallet address.
        let assert_tamper_changes_signer = |tamper: SignedRevisionV1| {
            let recovered =
                recover_v1_for_test(&tamper, ChainEnv::BaseSepolia).expect("recover tampered");
            assert_ne!(
                recovered,
                wallet.address(),
                "field tamper must produce a different recovered signer"
            );
        };

        // Field 1: vault_id
        let mut t = signed.clone();
        t.fields.vault_id[0] ^= 0x01;
        assert_tamper_changes_signer(t);

        // Field 2: account_id
        let mut t = signed.clone();
        t.fields.account_id[0] ^= 0x01;
        assert_tamper_changes_signer(t);

        // Field 3: parent_revision
        let mut t = signed.clone();
        t.fields.parent_revision[0] ^= 0x01;
        assert_tamper_changes_signer(t);

        // Field 4: device_id
        let mut t = signed.clone();
        t.fields.device_id[31] ^= 0x01;
        assert_tamper_changes_signer(t);

        // Field 5: schema_version
        let mut t = signed.clone();
        t.fields.schema_version = 2;
        assert_tamper_changes_signer(t);

        // Field 6: enc_payload_hash — last use of `signed`, so we
        // move it directly instead of cloning (clippy::redundant_clone).
        let mut t = signed;
        t.fields.enc_payload_hash[0] ^= 0x01;
        assert_tamper_changes_signer(t);
    }

    /// L-domain-binding: signing the same fields against a different
    /// chain id (via a different env) recovers to a different signer.
    /// We sign once against `BaseSepolia`, once against `Dev`, and
    /// assert the recovered signers differ. The `Dev` env's
    /// `verifying_contract` is `Address::ZERO` here (no Dev
    /// deployment file shipped), which is fine for the test: the
    /// only property we need is "domain differs ⇒ recovery
    /// differs".
    #[test]
    fn wrong_chain_id_produces_different_signer() {
        let wallet = fixed_wallet();
        let (pre, h) = sample_enc_payload();
        let fields = RevisionFieldsV1::with_signer_device_id(
            &wallet, [0x11; 32], [0x22; 32], [0x33; 32], 1, h,
        );
        let signed_sepolia =
            build_signed_revision_v1(&wallet, fields, pre.clone(), ChainEnv::BaseSepolia)
                .expect("sign sepolia");

        // Manually build a `SignedRevisionV1` against the Dev env by
        // signing a digest computed for Dev's domain. We bypass
        // `build_signed_revision_v1` because Dev has no deployment
        // file; the test exercises only the digest construction's
        // chain-id binding.
        let dev_verifying = Address::ZERO;
        let dev_domain = build_domain(ChainEnv::Dev, dev_verifying);
        let dev_sep = dev_domain.separator();
        let s_hash = struct_hash(&fields);
        let dev_digest = eip712_digest(dev_sep, s_hash);
        let dev_sig = sign_digest_to_rsv(wallet.signer(), dev_digest).expect("sign dev");
        let signed_dev = SignedRevisionV1 {
            fields,
            enc_payload: pre,
            signature: dev_sig,
        };

        // Cross-recover: each signed record must recover to the
        // wallet under ITS OWN env, but recovering one against the
        // OTHER env must yield a different signer.
        let recovered_sepolia_under_sepolia =
            recover_v1_for_test(&signed_sepolia, ChainEnv::BaseSepolia).expect("ssep");
        let recovered_dev_under_dev =
            recover_v1_for_test(&signed_dev, ChainEnv::Dev).expect("sdev");
        assert_eq!(recovered_sepolia_under_sepolia, wallet.address());
        assert_eq!(recovered_dev_under_dev, wallet.address());

        let recovered_sepolia_under_dev =
            recover_v1_for_test(&signed_sepolia, ChainEnv::Dev).expect("ssep-vs-dev");
        let recovered_dev_under_sepolia =
            recover_v1_for_test(&signed_dev, ChainEnv::BaseSepolia).expect("sdev-vs-sep");
        assert_ne!(
            recovered_sepolia_under_dev,
            wallet.address(),
            "cross-env recovery must yield a different signer"
        );
        assert_ne!(
            recovered_dev_under_sepolia,
            wallet.address(),
            "cross-env recovery must yield a different signer (reverse direction)"
        );
    }

    /// Sanity: the canonical-s helper accepts `s = n/2` and rejects
    /// `s = n/2 + 1`. Boundary check on the comparator since this is
    /// the load-bearing low-s gate.
    #[test]
    fn canonical_s_boundary() {
        assert!(is_canonical_s(&SECP256K1_HALF_N));
        let mut just_over = SECP256K1_HALF_N;
        // Increment the low byte by 1 (no carry needed; the low byte
        // is 0xA0).
        just_over[31] = just_over[31].wrapping_add(1);
        assert!(!is_canonical_s(&just_over));
    }

    // Issue #98 (2026-05-18) — REMOVED: `cross_check_against_live_d017`
    // was an empty `#[test]` body that "passed" doing nothing
    // (L-empty-test-body class). Its runbook content migrated to
    // `crates/pangolin-chain/RUNBOOK.md` § "RevisionLogV1 domain
    // separator cross-check". The hermetic
    // `domain_separator_matches_pinned_constant` test above remains
    // the load-bearing CI-side check; the operator-facing live cast
    // call lives in the runbook so operators see real guidance
    // instead of a green tick on no work.
}

// =====================================================================
// MVP-2 issue 3.4 — `Redemption` typehash + signer for `EntitlementRegistry`
// =====================================================================
//
// Per docs/issue-plans/3.4.md (Kelvin sign-off 2026-05-15):
// the funder service signs `Redemption` attestations against the
// `EntitlementRegistry`'s `REDEMPTION_AUTHORITY`. This is a separate
// codepath from the revision-publish signer above (L11 verbatim):
// `Redemption` binds a distinct typehash, distinct domain separator
// (the `EntitlementRegistry` contract, NOT RevisionLogV1), and a
// distinct field set. The discipline (canonical-low s, v ∈ {27,28},
// 65-byte rsv) is shared.
//
// The on-chain typehash literal is taken VERBATIM from
// `contracts/src/EntitlementRegistry.sol:173-175`:
//   Redemption(bytes32 userId,uint256 amount,uint64 nonce,uint16 schemaVersion,uint64 expiresAt)
// Field ORDER is load-bearing (env-quirk #14): the contract's
// `_hashRedemption` ABI-encodes in the order (userId, amount, nonce,
// schemaVersion, expiresAt); the builder below ABI-encodes in the
// SAME order. A mismatch is the 3.3 `encPayload` regression class of
// bug — invisible to hermetic tests, fatal on every live submit.

/// Pinned EIP-712 typehash for `Redemption`.
///
/// Equals `keccak256("Redemption(bytes32 userId,uint256 amount,uint64 nonce,uint16 schemaVersion,uint64 expiresAt)")`.
/// Computed via `cast keccak "Redemption(...)"` at 3.4 builder time
/// (2026-05-15) and pinned here so the `redemption_typehash_matches_pinned_constant`
/// hermetic test re-keccaks the literal + asserts byte-equality.
///
/// **DO NOT** edit the field list / order without redeploying the
/// contract — the bytes on the wire MUST equal what the contract's
/// `REDEMPTION_TYPEHASH` constant resolves to.
pub const REDEMPTION_TYPEHASH_V1: [u8; 32] =
    hex!("2a1614246eddcb4b1915f697272835ba7c8fefd0ff42b3eae7692c9fc2977663");

/// Pinned EIP-712 domain separator for `EntitlementRegistry` on Base
/// Sepolia. Captured from the LIVE D-018 contract at 3.4 builder time
/// (2026-05-15) via:
///
/// ```text
/// cast call 0x08F8c394EB0c04ba0A4FBA1e64507b88F4b59D8d \
///     "DOMAIN_SEPARATOR()(bytes32)" \
///     --rpc-url https://sepolia.base.org
/// ```
///
/// The `redemption_domain_separator_matches_pinned_constant` hermetic
/// test constructs the same domain via [`eip712_domain!`] + asserts
/// byte-equality.
///
/// **Note on D-019 redeploy:** when Kelvin runs the operational redeploy
/// (R-d), the new D-019 contract will have a DIFFERENT
/// `verifyingContract` field (the new contract address) and therefore
/// a DIFFERENT `DOMAIN_SEPARATOR`. The pinned constant here is for
/// D-019 (the split-key production-grade redeploy currently at
/// `0xdDa04e427e95e50Cfd22703A76CAE2E1Da4F5fCD`). Captured 2026-05-17
/// via `cast call <D-019> "DOMAIN_SEPARATOR()(bytes32)"` post-deploy.
/// Supersedes D-018's collapsed-authority smoke-test instance per
/// 3.4 R-d production-grade key separation. The
/// `redemption_domain_separator_matches_pinned_constant` test catches
/// drift at CI time; any future redeploy MUST update this constant +
/// the `EXPECTED_ENTITLEMENT_REGISTRY_ADDRESS_BASE_SEPOLIA` constant
/// below to match the new deployment's `DOMAIN_SEPARATOR()` view fn
/// output.
pub const ENTITLEMENT_DOMAIN_SEPARATOR_BASE_SEPOLIA_V1: [u8; 32] =
    hex!("b33d25188e5fc32cf5021ce63f28ee4ffb13d1d9a4ca720c46272f4c87c42fd0");

/// Pinned-at-source expected deployment address for the
/// `EntitlementRegistry` on Base Sepolia (mirror of
/// [`EXPECTED_DEPLOYED_ADDRESS_BASE_SEPOLIA`] for `RevisionLogV1`).
///
/// D-019 split-key production-grade redeploy (2026-05-17):
/// `PAYMENT_AUTHORITY` = pangolin-dev (`0x89e7...5c54`),
/// `REDEMPTION_AUTHORITY` = pangolin-funder-dev (`0xaeE7...55AC`).
/// Supersedes D-018's collapsed-authority smoke-test instance
/// (`0x08F8...8d`) per 3.4 R-d production-grade key separation.
/// The [`build_signed_redemption_v1`] entry point cross-checks the
/// deployment-file address against this constant before signing.
pub const EXPECTED_ENTITLEMENT_REGISTRY_ADDRESS_BASE_SEPOLIA: Address =
    address!("0xdDa04e427e95e50Cfd22703A76CAE2E1Da4F5fCD");

/// EIP-712 domain string for the `EntitlementRegistry` `name` field.
/// Taken VERBATIM from `EntitlementRegistry.sol:240` — a future
/// contract revision changing this name would invalidate the pinned
/// constant + fire `redemption_domain_separator_matches_pinned_constant`.
const ENTITLEMENT_DOMAIN_NAME: &str = "Pangolin EntitlementRegistry";

/// EIP-712 domain string for the `EntitlementRegistry` `version` field.
const ENTITLEMENT_DOMAIN_VERSION: &str = "1";

/// Inputs to the v1 signed-redemption builder.
///
/// Five fields, byte-for-byte matching `EntitlementRegistry.sol`'s
/// `Redemption` struct (typehash literal pinned above). Field order
/// follows the typehash — the ABI-encoded struct hash MUST match the
/// contract's `_hashRedemption`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedemptionFieldsV1 {
    /// Opaque user identifier (2.2 R-b; bytes32).
    pub user_id: [u8; 32],
    /// Credits to decrement (uint256). Funder's view is "the user
    /// just received this much value off-chain — decrement their
    /// on-chain balance by the same amount".
    pub amount: U256,
    /// Attestation nonce. MUST equal `nonce[userId]` at submit time
    /// (strict equality, contract-enforced).
    pub nonce: u64,
    /// Event-schema version. Contract rejects values >
    /// `MAX_KNOWN_SCHEMA_VERSION`.
    pub schema_version: u16,
    /// Unix timestamp after which the attestation is rejected by the
    /// contract.
    pub expires_at: u64,
}

/// Output of [`build_signed_redemption_v1`]: the field set + the
/// 65-byte secp256k1 signature.
///
/// Mirror of [`SignedRevisionV1`]'s shape minus the `enc_payload`
/// preimage (Redemption has no variable-length bytes field; the
/// contract's `redeem(...)` calldata reproduces every field directly
/// from the typed inputs, so there is no preimage drift class).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignedRedemptionV1 {
    /// The same field set the digest was computed over.
    pub fields: RedemptionFieldsV1,
    /// 65-byte `r || s || v` signature. v ∈ {27, 28}; s canonical-low.
    pub signature: [u8; 65],
}

/// Build the EIP-712 domain for the `EntitlementRegistry` on a given env.
///
/// Mirror of `build_domain` for `RevisionLogV1` — same alloy primitive,
/// different `name` constant. The `chain_id` source is the same
/// `ChainEnv::chain_id()` helper; the `verifying_contract` is loaded
/// from the deployment file at the call site.
fn build_entitlement_domain(env: ChainEnv, verifying_contract: Address) -> Eip712Domain {
    let chain_id = env.chain_id().unwrap_or(0);
    eip712_domain! {
        name: ENTITLEMENT_DOMAIN_NAME,
        version: ENTITLEMENT_DOMAIN_VERSION,
        chain_id: chain_id,
        verifying_contract: verifying_contract,
    }
}

/// Compute the EIP-712 struct-hash for a [`RedemptionFieldsV1`].
///
/// Mirrors the contract's `_hashRedemption`:
///
/// ```text
/// structHash = keccak256(
///     abi.encode(
///         REDEMPTION_TYPEHASH,
///         userId,         // bytes32
///         amount,         // uint256 (32-byte word, big-endian)
///         nonce,          // uint64 (left-padded to 32-byte word)
///         schemaVersion,  // uint16 (left-padded to 32-byte word)
///         expiresAt       // uint64 (left-padded to 32-byte word)
///     )
/// )
/// ```
///
/// ABI-encoding rules: every elementary type pads UP to a 32-byte
/// word; `uintN` left-pads with zeros. The buffer layout below is the
/// audit-friendly explicit form; alloy's `SolValue::abi_encode` would
/// also work but produces the same bytes.
fn redemption_struct_hash(fields: &RedemptionFieldsV1) -> B256 {
    // 6 × 32 bytes = 192 bytes. (typehash + 5 fields, each padded to
    // a 32-byte word.)
    let mut buf = [0u8; 6 * 32];
    let mut o = 0usize;
    buf[o..o + 32].copy_from_slice(&REDEMPTION_TYPEHASH_V1);
    o += 32;
    // userId — already 32 bytes.
    buf[o..o + 32].copy_from_slice(&fields.user_id);
    o += 32;
    // amount — uint256 fits exactly 32 bytes (big-endian).
    buf[o..o + 32].copy_from_slice(&fields.amount.to_be_bytes::<32>());
    o += 32;
    // nonce — uint64 left-padded to 32 bytes (bytes [o..o+24] stay
    // zero; the 8-byte BE value lands at [o+24..o+32]).
    buf[o + 24..o + 32].copy_from_slice(&fields.nonce.to_be_bytes());
    o += 32;
    // schemaVersion — uint16 left-padded to 32 bytes.
    buf[o + 30..o + 32].copy_from_slice(&fields.schema_version.to_be_bytes());
    o += 32;
    // expiresAt — uint64 left-padded to 32 bytes.
    buf[o + 24..o + 32].copy_from_slice(&fields.expires_at.to_be_bytes());
    debug_assert_eq!(o + 32, buf.len(), "redemption_struct_hash buffer drift");
    keccak256(buf)
}

/// Build a v1 signed-redemption over `fields` using `signer`'s key,
/// binding to `chain_env`'s deployed `EntitlementRegistry` contract.
///
/// Per R-d: the deployment-file `EntitlementRegistry` address is
/// loaded via [`load_deployed_address`] + cross-checked against
/// [`EXPECTED_ENTITLEMENT_REGISTRY_ADDRESS_BASE_SEPOLIA`] for
/// `BaseSepolia`. Mismatch fails closed with
/// [`ChainError::DeploymentAddressMismatch`] (mirror of the
/// `build_signed_revision_v1` guard).
///
/// Takes a `&PrivateKeySigner` rather than `&EvmWallet` because the
/// funder service holds an alloy-native signer (loaded from a Foundry
/// keystore at startup, NOT derived from a Pangolin device key —
/// L1 + L7 isolation).
///
/// # Errors
///
/// - [`ChainError::DeploymentNotFound`] / [`ChainError::DeploymentParseError`]
///   if the deployment file is missing / malformed.
/// - [`ChainError::DeploymentAddressMismatch`] for `BaseSepolia` if
///   the deployment file points at an unexpected address.
/// - [`ChainError::Wallet`] if alloy's signer surfaces an error
///   (vanishingly rare).
pub fn build_signed_redemption_v1(
    signer: &PrivateKeySigner,
    fields: RedemptionFieldsV1,
    chain_env: ChainEnv,
) -> Result<SignedRedemptionV1, ChainError> {
    // R-d: deployment-file sourcing of `verifyingContract`.
    let verifying_contract = load_deployed_address(chain_env, "EntitlementRegistry")?;
    // L-domain-binding defense: the pinned-at-source constant is the
    // ground-truth address; mismatch fails closed.
    if matches!(chain_env, ChainEnv::BaseSepolia)
        && verifying_contract != EXPECTED_ENTITLEMENT_REGISTRY_ADDRESS_BASE_SEPOLIA
    {
        return Err(ChainError::DeploymentAddressMismatch {
            env: chain_env,
            expected: EXPECTED_ENTITLEMENT_REGISTRY_ADDRESS_BASE_SEPOLIA,
            actual: verifying_contract,
        });
    }

    let domain = build_entitlement_domain(chain_env, verifying_contract);
    let domain_sep = domain.separator();
    let s_hash = redemption_struct_hash(&fields);
    let digest = eip712_digest(domain_sep, s_hash);

    let signature = sign_digest_to_rsv(signer, digest)?;

    // Defensive structural asserts mirroring the revision-signer.
    debug_assert!(
        signature[64] == 27 || signature[64] == 28,
        "v must be in {{27,28}} for EIP-712"
    );
    let mut s_be = [0u8; 32];
    s_be.copy_from_slice(&signature[32..64]);
    debug_assert!(is_canonical_s(&s_be), "s must be canonical-low (s <= n/2)");
    let _ = s_be;

    Ok(SignedRedemptionV1 { fields, signature })
}

#[cfg(test)]
#[allow(clippy::similar_names)] // `signer` + `signed` is the canonical
                                //                                 alloy/3.1 vocabulary; renaming
                                //                                 for the linter is pure noise.
mod redemption_tests {
    use super::*;
    use alloy::primitives::{Address, U256};

    /// Build a deterministic local signer for hermetic tests. Same
    /// scalar the funder-client tests use, so cross-crate audit
    /// recognises it.
    fn fixed_local_signer() -> PrivateKeySigner {
        let hex = "0x4242424242424242424242424242424242424242424242424242424242424242";
        hex.parse::<PrivateKeySigner>().expect("parse fixed signer")
    }

    /// L3-equivalent + R-e: the pinned `REDEMPTION_TYPEHASH_V1`
    /// equals the keccak of the literal struct definition string
    /// taken verbatim from `EntitlementRegistry.sol:174`.
    #[test]
    fn redemption_typehash_matches_pinned_constant() {
        let literal = "Redemption(bytes32 userId,uint256 amount,uint64 nonce,uint16 schemaVersion,uint64 expiresAt)";
        let computed = keccak256(literal.as_bytes());
        assert_eq!(
            computed.0, REDEMPTION_TYPEHASH_V1,
            "Redemption typehash literal must keccak to the pinned constant"
        );
    }

    /// L2-equivalent + R-e: the EIP-712 domain separator constructed
    /// via `eip712_domain!` for D-018 matches the value captured
    /// from the live contract's `DOMAIN_SEPARATOR()` view fn at
    /// builder time. Catches drift in name / version / chainId /
    /// verifyingContract.
    #[test]
    fn redemption_domain_separator_matches_pinned_constant() {
        let domain = build_entitlement_domain(
            ChainEnv::BaseSepolia,
            EXPECTED_ENTITLEMENT_REGISTRY_ADDRESS_BASE_SEPOLIA,
        );
        let sep = domain.separator();
        assert_eq!(
            sep.0, ENTITLEMENT_DOMAIN_SEPARATOR_BASE_SEPOLIA_V1,
            "alloy-constructed entitlement domain separator must equal pinned D-018 value"
        );
    }

    /// L1-equivalent: signature is exactly 65 bytes.
    #[test]
    fn build_signed_redemption_v1_produces_65_byte_sig() {
        let signer = fixed_local_signer();
        let fields = RedemptionFieldsV1 {
            user_id: [0x11; 32],
            amount: U256::from(100u64),
            nonce: 0,
            schema_version: 1,
            expires_at: 2_000_000_000,
        };
        let signed =
            build_signed_redemption_v1(&signer, fields, ChainEnv::BaseSepolia).expect("sign");
        assert_eq!(signed.signature.len(), 65);
    }

    /// Canonical-low s.
    #[test]
    fn build_signed_redemption_v1_canonical_s() {
        let signer = fixed_local_signer();
        let fields = RedemptionFieldsV1 {
            user_id: [0x22; 32],
            amount: U256::from(50u64),
            nonce: 3,
            schema_version: 1,
            expires_at: 2_000_000_000,
        };
        let signed =
            build_signed_redemption_v1(&signer, fields, ChainEnv::BaseSepolia).expect("sign");
        let mut s_be = [0u8; 32];
        s_be.copy_from_slice(&signed.signature[32..64]);
        assert!(is_canonical_s(&s_be));
    }

    /// v ∈ {27, 28} (legacy non-EIP-155 form).
    #[test]
    fn build_signed_redemption_v1_v_in_27_or_28() {
        let signer = fixed_local_signer();
        let fields = RedemptionFieldsV1 {
            user_id: [0x33; 32],
            amount: U256::from(75u64),
            nonce: 1,
            schema_version: 1,
            expires_at: 2_000_000_000,
        };
        let signed =
            build_signed_redemption_v1(&signer, fields, ChainEnv::BaseSepolia).expect("sign");
        let v = signed.signature[64];
        assert!(v == 27 || v == 28, "v must be 27 or 28, got {v}");
    }

    /// Recover the signer over the same digest the builder produced;
    /// must equal `signer.address()`. Hermetic cross-check that the
    /// digest construction matches between sign-side and verify-side
    /// (this is the round-trip the contract's `_recover` performs).
    fn recover_redemption_for_test(
        signed: &SignedRedemptionV1,
        chain_env: ChainEnv,
    ) -> Result<Address, alloy::primitives::SignatureError> {
        let verifying_contract = match chain_env {
            ChainEnv::BaseSepolia => EXPECTED_ENTITLEMENT_REGISTRY_ADDRESS_BASE_SEPOLIA,
            _ => load_deployed_address(chain_env, "EntitlementRegistry").unwrap_or(Address::ZERO),
        };
        let domain = build_entitlement_domain(chain_env, verifying_contract);
        let domain_sep = domain.separator();
        let s_hash = redemption_struct_hash(&signed.fields);
        let digest = eip712_digest(domain_sep, s_hash);

        let r = U256::from_be_slice(&signed.signature[0..32]);
        let s = U256::from_be_slice(&signed.signature[32..64]);
        let v_byte = signed.signature[64];
        let y_parity = v_byte == 28;
        let sig = alloy::primitives::Signature::new(r, s, y_parity);
        sig.recover_address_from_prehash(&digest)
    }

    #[test]
    fn redemption_round_trip_recover_v1() {
        let signer = fixed_local_signer();
        let fields = RedemptionFieldsV1 {
            user_id: [0x44; 32],
            amount: U256::from(42u64),
            nonce: 0,
            schema_version: 1,
            expires_at: 2_000_000_000,
        };
        let signed =
            build_signed_redemption_v1(&signer, fields, ChainEnv::BaseSepolia).expect("sign");
        let recovered =
            recover_redemption_for_test(&signed, ChainEnv::BaseSepolia).expect("recover");
        assert_eq!(recovered, signer.address());
    }

    /// Per-field tamper: flipping any of the five struct fields
    /// changes the recovered signer. Indirect coverage of typehash
    /// drift + field-order errors (env-quirk #14).
    #[test]
    fn redemption_per_field_tamper_changes_signer() {
        let signer = fixed_local_signer();
        let base_fields = RedemptionFieldsV1 {
            user_id: [0x55; 32],
            amount: U256::from(99u64),
            nonce: 5,
            schema_version: 1,
            expires_at: 2_000_000_000,
        };
        let signed = build_signed_redemption_v1(&signer, base_fields, ChainEnv::BaseSepolia)
            .expect("sign baseline");
        let baseline =
            recover_redemption_for_test(&signed, ChainEnv::BaseSepolia).expect("recover baseline");
        assert_eq!(baseline, signer.address());

        let mut t = signed;
        t.fields.user_id[0] ^= 0x01;
        let recovered = recover_redemption_for_test(&t, ChainEnv::BaseSepolia).expect("recover");
        assert_ne!(recovered, signer.address(), "user_id tamper");

        let mut t = signed;
        t.fields.amount = U256::from(100u64);
        let recovered = recover_redemption_for_test(&t, ChainEnv::BaseSepolia).expect("recover");
        assert_ne!(recovered, signer.address(), "amount tamper");

        let mut t = signed;
        t.fields.nonce = 6;
        let recovered = recover_redemption_for_test(&t, ChainEnv::BaseSepolia).expect("recover");
        assert_ne!(recovered, signer.address(), "nonce tamper");

        let mut t = signed;
        t.fields.schema_version = 2;
        let recovered = recover_redemption_for_test(&t, ChainEnv::BaseSepolia).expect("recover");
        assert_ne!(recovered, signer.address(), "schema_version tamper");

        let mut t = signed;
        t.fields.expires_at = 2_000_000_001;
        let recovered = recover_redemption_for_test(&t, ChainEnv::BaseSepolia).expect("recover");
        assert_ne!(recovered, signer.address(), "expires_at tamper");
    }

    // Issue #98 (2026-05-18) — REMOVED: `redemption_cross_check_against_live_d018`
    // was an empty `#[test]` body (L-empty-test-body class) + the
    // name still referenced D-018 (the smoke-test instance superseded
    // by D-019 on 2026-05-17). Its runbook content migrated to
    // `crates/pangolin-chain/RUNBOOK.md` § "EntitlementRegistry
    // domain separator cross-check (D-019)" — references the
    // current D-019 redemption-authority `0xaeE7E9bf859d938CB087D1e567221cffba9455AC`.
    // The hermetic `redemption_domain_separator_matches_pinned_constant`
    // test above remains the load-bearing CI-side check.

    /// MVP-2 issue 3.6 (R-c distributed-impl touchpoint).
    ///
    /// Build a `SignedRevisionV1` whose wallet is sourced via
    /// `DefaultStrategy::derive_wallet_for_revision` (instead of
    /// directly via `derive_evm_wallet`) and assert the produced
    /// signed-revision equals the one built with `derive_evm_wallet`
    /// directly. Pins the byte-identity property at the signing-
    /// primitive consumer boundary (3.6 L1 + L4).
    ///
    /// The deeper byte-identity proof against the pre-3.6 baseline
    /// lives in `crates/pangolin-chain/src/privacy/tests.rs`
    /// (`default_strategy_revision_signature_matches_pre_3_6_baseline`).
    /// This sibling test pins the structural-equivalence property at
    /// the signing-module boundary so a regression here fires next to
    /// the signing primitive too.
    #[test]
    fn issue_3_6_default_strategy_yields_same_signed_revision() {
        use crate::evm::derive_evm_wallet;
        use crate::privacy::{DefaultStrategy, PrivacyStrategy};
        use pangolin_crypto::keys::DeviceKey;

        let device = DeviceKey::from_seed([0x42u8; 32]);

        let direct_wallet = derive_evm_wallet(&device).expect("direct derive");
        let via_default_wallet = DefaultStrategy
            .derive_wallet_for_revision(&device, 0)
            .expect("derive via default strategy");

        let enc_payload = b"3.6 secp256k1_signing parity check".to_vec();
        let enc_payload_hash = keccak256(&enc_payload).0;
        let fields_direct = RevisionFieldsV1::with_signer_device_id(
            &direct_wallet,
            [0x77u8; 32],
            [0x88u8; 32],
            [0u8; 32],
            1,
            enc_payload_hash,
        );
        let fields_via_default = RevisionFieldsV1::with_signer_device_id(
            &via_default_wallet,
            [0x77u8; 32],
            [0x88u8; 32],
            [0u8; 32],
            1,
            enc_payload_hash,
        );

        let direct = build_signed_revision_v1(
            &direct_wallet,
            fields_direct,
            enc_payload.clone(),
            ChainEnv::BaseSepolia,
        )
        .expect("sign via direct wallet");
        let via_default = build_signed_revision_v1(
            &via_default_wallet,
            fields_via_default,
            enc_payload,
            ChainEnv::BaseSepolia,
        )
        .expect("sign via default-strategy wallet");

        assert_eq!(
            direct, via_default,
            "DefaultStrategy must produce a byte-identical SignedRevisionV1 \
             at the secp256k1_signing consumer boundary (3.6 L1 + L4)"
        );
    }
}
