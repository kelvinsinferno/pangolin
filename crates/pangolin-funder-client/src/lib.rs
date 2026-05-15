// SPDX-License-Identifier: AGPL-3.0-or-later
//! Client-side shared types + helpers for the Pangolin funder service.
//!
//! Per D-006: the funder is a one-way ETH dispenser. Per MVP-2 issue
//! 3.4 R-g (Kelvin sign-off 2026-05-15): every top-up request carries
//! a **device-binding signature** produced by the user's device wallet
//! over the Credit attestation hash + the claimed device address, so a
//! leaked Credit cannot be redirected to an attacker-controlled
//! address. This crate is the canonical owner of:
//!
//! - The wire shapes [`TopUpRequest`] / [`TopUpResponse`] / [`Credit`]
//!   used by both the funder server (`services/funder/`) and the
//!   eventual CLI subcommand (`apps/cli` — 3.5 territory).
//! - The [`FUNDER_DEVICE_BINDING_DOMAIN_V1`] domain constant (R-g
//!   verbatim).
//! - The [`sign_device_binding`] / [`verify_device_binding`] helpers
//!   that produce / check the 65-byte secp256k1 signature.
//!
//! This crate does NOT depend on `pangolin-store` / `pangolin-core` /
//! `pangolin-crypto` / `pangolin-ffi` — L1 invariant. It is reachable
//! from `apps/cli` (when 3.5 lands) and from `services/funder` (the
//! server side of the protocol). HTTP-client logic (the actual POST
//! to the funder URL) is intentionally NOT in this crate today; that
//! belongs in 3.5 along with the CLI subcommand.

#![cfg_attr(not(test), forbid(unsafe_code))]

use alloy::primitives::{keccak256, Address, B256, U256};
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::SignerSync;

/// **R-g verbatim.** Domain prefix bound into the device-binding
/// digest the user device wallet signs alongside every funder request.
///
/// The string includes `\x01` separators between the protocol name
/// (`"PangolinFunderDeviceBinding"`), the version (`"v1"`), and the
/// trailing payload so a future v2 with the same fields but different
/// semantics cannot replay against v1's binding. The constant lives in
/// this client crate (rather than in `pangolin-chain`) because both
/// sides of the protocol — the device that signs (apps/cli, 3.5
/// territory) and the funder that verifies (`services/funder/`) —
/// import it from here as a single source of truth.
pub const FUNDER_DEVICE_BINDING_DOMAIN_V1: &str = "PangolinFunderDeviceBinding\x01v1\x01";

/// Maximum supported event-schema version for `Credit` / `Redemption`.
///
/// Matches `EntitlementRegistry.MAX_KNOWN_SCHEMA_VERSION` at the time
/// of 3.4 plan-gate (1). Re-pinned here so a client + a funder built
/// against the same release can refuse unknown future values BEFORE
/// submission, mirroring the contract's `ErrUnsupportedSchemaVersion`
/// guard (defense-in-depth + saves the gas a doomed `redeem` would
/// burn).
pub const MAX_KNOWN_SCHEMA_VERSION: u16 = 1;

/// Credit attestation as the funder receives it from the user.
///
/// Mirrors the EIP-712 `Credit` typed-data struct from
/// `contracts/src/EntitlementRegistry.sol` (typehash literal:
/// `Credit(bytes32 userId,uint256 amount,uint64 nonce,uint16 schemaVersion,uint64 expiresAt)`),
/// plus the 65-byte `signature` produced by `PAYMENT_AUTHORITY`. The
/// funder verifies (a) the sig recovers to the cached authority
/// address read on-chain at startup, (b) `block.timestamp <=
/// expires_at` (anti-stale per 2.2 R-e), (c) `schema_version <=
/// MAX_KNOWN_SCHEMA_VERSION`. The contract performs the same checks
/// + the strict-equality nonce check at submit time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credit {
    /// Opaque user identifier (2.2 R-b — bytes32 only, never derived
    /// from PII off-chain).
    pub user_id: [u8; 32],
    /// Credits to add (uint256). Off-chain billing service maps
    /// credits → revisions per the pricing spec.
    pub amount: U256,
    /// Nonce embedded in the attestation. Must equal the contract's
    /// `nonce[user_id]` at submit time (strict-equality, 2.2 R-c).
    pub nonce: u64,
    /// Event-schema version. The funder rejects values >
    /// [`MAX_KNOWN_SCHEMA_VERSION`] before submission.
    pub schema_version: u16,
    /// Unix timestamp after which the attestation expires. The funder
    /// AND the contract both reject `block.timestamp > expires_at`.
    pub expires_at: u64,
    /// 65-byte `r || s || v` signature from `PAYMENT_AUTHORITY`. v ∈
    /// {27, 28}; `s` canonical-low.
    pub signature: [u8; 65],
}

impl Credit {
    /// Compute the attestation hash used both as the off-chain replay
    /// key (the funder's `SQLite` ledger `attestation_hash UNIQUE`
    /// column) and as the input to the device-binding digest the
    /// device wallet signs.
    ///
    /// **Choice of hash:** `keccak256` over a fixed-layout concatenation
    /// of the canonical fields + the signature. The signature is
    /// included so semantically-distinct attestations with the same
    /// fields but different signatures (e.g., a rotated signing key
    /// after a v2 redeploy) hash to different values — the ledger's
    /// `UNIQUE` constraint is on the BYTE-EXACT attestation, not on
    /// the logical (userId, nonce) pair (the contract enforces that
    /// pair separately via `nonce[userId]` strict equality).
    ///
    /// The layout is NOT the EIP-712 digest the contract recovers; it's
    /// a separate "client-replay-key" hash. The EIP-712 digest the
    /// contract verifies is computed independently from `user_id` +
    /// `amount` + `nonce` + `schema_version` + `expires_at` via
    /// `EntitlementRegistry._hashCredit` and is owned by
    /// `pangolin-chain` (the EIP-712 builders).
    #[must_use]
    pub fn attestation_hash(&self) -> B256 {
        // Layout: user_id(32) || amount(32) || nonce(8) || schemaVersion(2)
        //        || expiresAt(8) || signature(65) = 147 bytes.
        let mut buf = [0u8; 32 + 32 + 8 + 2 + 8 + 65];
        let mut o = 0;
        buf[o..o + 32].copy_from_slice(&self.user_id);
        o += 32;
        buf[o..o + 32].copy_from_slice(&self.amount.to_be_bytes::<32>());
        o += 32;
        buf[o..o + 8].copy_from_slice(&self.nonce.to_be_bytes());
        o += 8;
        buf[o..o + 2].copy_from_slice(&self.schema_version.to_be_bytes());
        o += 2;
        buf[o..o + 8].copy_from_slice(&self.expires_at.to_be_bytes());
        o += 8;
        buf[o..o + 65].copy_from_slice(&self.signature);
        debug_assert_eq!(o + 65, buf.len(), "attestation_hash buffer drift");
        keccak256(buf)
    }
}

/// Request body for `POST /funder/v1/top-up`.
///
/// Per R-c: the funder accepts ONLY signed Credit attestations from
/// `PAYMENT_AUTHORITY`. Per R-g: every request carries a separate
/// 65-byte signature from the user's device wallet over
/// `keccak256(FUNDER_DEVICE_BINDING_DOMAIN_V1 || attestation_hash ||
/// device_address)`. The funder verifies both signatures + asserts the
/// device-binding signer == `device_address`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopUpRequest {
    /// Signed `Credit` attestation from `PAYMENT_AUTHORITY` (off-chain
    /// payment processor).
    pub credit: Credit,
    /// 65-byte device-binding signature per R-g. Recovers to
    /// `device_address`.
    pub device_binding_sig: [u8; 65],
    /// EVM address that will receive the ETH transfer. Verified to
    /// match the device-binding signature signer.
    pub device_address: Address,
}

/// Response body for a successful `POST /funder/v1/top-up`.
///
/// Per the master plan §5 funder protocol + the 3.4 audit fix-pass
/// (2026-05-15): returns the redeem tx hash and — when the ETH
/// transfer succeeded — the transfer tx hash. When
/// `eth_transfer_tx_hash` is `None` but `redeem_tx_hash` is populated,
/// the user's on-chain balance was debited but the ETH transfer
/// failed; **manual recovery via the funder runbook is required**.
/// The funder also returns HTTP 500 with class `eth_transfer_failed`
/// in that scenario, so a typed client distinguishes the partial
/// state from the success case without inspecting the body alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TopUpResponse {
    /// Tx hash of the `redeem(...)` call to the `EntitlementRegistry`.
    pub redeem_tx_hash: B256,
    /// Tx hash of the ETH-transfer to `device_address`. `None` when
    /// the redeem succeeded but the transfer leg failed (operator
    /// reconciliation required).
    pub eth_transfer_tx_hash: Option<B256>,
    /// ETH transferred (wei). `U256::ZERO` when the transfer leg
    /// failed. Cross-check against the explorer.
    pub eth_transferred_wei: U256,
}

/// Compute the digest the device wallet signs to bind a Credit
/// attestation to a specific device address.
///
/// Per R-g verbatim:
/// `keccak256(FUNDER_DEVICE_BINDING_DOMAIN_V1 || attestation_hash || device_address)`.
///
/// Exposed so both sides (signer + verifier) compute the same value
/// from the same module — eliminating "I copied the formula" drift
/// between the device-side signer (in 3.5's CLI subcommand) and the
/// funder-side verifier (in `services/funder/`).
#[must_use]
pub fn device_binding_digest(attestation_hash: B256, device_address: Address) -> B256 {
    // Layout: domain bytes || attestation_hash(32) || device_address(20).
    let domain_bytes = FUNDER_DEVICE_BINDING_DOMAIN_V1.as_bytes();
    let mut buf = Vec::with_capacity(domain_bytes.len() + 32 + 20);
    buf.extend_from_slice(domain_bytes);
    buf.extend_from_slice(attestation_hash.as_slice());
    buf.extend_from_slice(device_address.as_slice());
    keccak256(buf)
}

/// Sign the device-binding digest for a given attestation hash + device
/// address with `signer`. Returns the 65-byte `r || s || v` signature
/// (canonical-low s, v ∈ {27, 28}).
///
/// `signer` is the device's secp256k1 `PrivateKeySigner` (alloy local
/// signer); on the client side in 3.5, the CLI will pass its derived
/// wallet's signer in. We take a `&PrivateKeySigner` directly to
/// avoid a dep on `pangolin-chain` (which would make this crate
/// transitively depend on `pangolin-crypto` via `EvmWallet`).
///
/// Returns `None` if alloy's signer returns an error — vanishingly
/// rare under k256 0.13.x. Caller treats `None` as a hard fail.
#[must_use]
pub fn sign_device_binding(
    signer: &PrivateKeySigner,
    attestation_hash: B256,
    device_address: Address,
) -> Option<[u8; 65]> {
    let digest = device_binding_digest(attestation_hash, device_address);
    let sig = signer.sign_hash_sync(&digest).ok()?;
    let canonical = sig.normalize_s().unwrap_or(sig);
    Some(canonical.as_bytes())
}

/// Verify a device-binding signature: recover the secp256k1 signer
/// over the device-binding digest and assert it equals `device_address`.
///
/// Returns `true` only if the signature is structurally valid AND the
/// recovered address matches `device_address`. Mismatches in any of:
/// (a) signature shape, (b) `v` out of {27, 28}, (c) `s` non-canonical
/// (rejected by alloy's recovery path), (d) recovered address !=
/// `device_address` — all collapse to `false`. The funder treats `false`
/// uniformly as HTTP 400 `device_binding_invalid` with no leak of which
/// sub-check failed (R-g verbatim).
#[must_use]
pub fn verify_device_binding(
    sig: [u8; 65],
    attestation_hash: B256,
    device_address: Address,
) -> bool {
    let digest = device_binding_digest(attestation_hash, device_address);
    let r = U256::from_be_slice(&sig[0..32]);
    let s = U256::from_be_slice(&sig[32..64]);
    let v_byte = sig[64];
    if v_byte != 27 && v_byte != 28 {
        return false;
    }
    let y_parity = v_byte == 28;
    let alloy_sig = alloy::primitives::Signature::new(r, s, y_parity);
    alloy_sig
        .recover_address_from_prehash(&digest)
        .is_ok_and(|recovered| recovered == device_address)
}

/// Returns the crate name. Useful for diagnostics and version
/// reporting.
#[must_use]
pub fn name() -> &'static str {
    "pangolin-funder-client"
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{address, b256, U256};
    use alloy::signers::local::PrivateKeySigner;

    /// Build a deterministic signer for hermetic tests by parsing a
    /// fixed 32-byte hex scalar. Same pattern as `pangolin-chain`'s
    /// `fixed_wallet` but kept local to avoid a `pangolin-chain` dep.
    fn fixed_signer() -> PrivateKeySigner {
        // `0x42` repeated 32 times — same value the chain crate uses
        // for its hermetic fixtures, so cross-crate audit recognises
        // it.
        let hex = "0x4242424242424242424242424242424242424242424242424242424242424242";
        hex.parse::<PrivateKeySigner>().expect("parse fixed signer")
    }

    fn sample_credit() -> Credit {
        Credit {
            user_id: [0xAAu8; 32],
            amount: U256::from(123_456u64),
            nonce: 7,
            schema_version: 1,
            expires_at: 2_000_000_000,
            signature: [0xBBu8; 65],
        }
    }

    #[test]
    fn crate_name_is_set() {
        assert_eq!(name(), "pangolin-funder-client");
    }

    #[test]
    fn device_binding_domain_is_pinned() {
        // Pinning the literal at the bytes level so a future contributor
        // can't silently retune the separator and break version-skew
        // detection. The bytes are: "PangolinFunderDeviceBinding"
        // (27 bytes) || 0x01 || "v1" (2 bytes) || 0x01.
        let expected: &[u8] = b"PangolinFunderDeviceBinding\x01v1\x01";
        assert_eq!(FUNDER_DEVICE_BINDING_DOMAIN_V1.as_bytes(), expected);
    }

    #[test]
    fn attestation_hash_is_deterministic() {
        let c1 = sample_credit();
        let c2 = sample_credit();
        assert_eq!(c1.attestation_hash(), c2.attestation_hash());
    }

    #[test]
    fn attestation_hash_changes_when_any_field_flips() {
        let base = sample_credit().attestation_hash();
        let mut c = sample_credit();
        c.amount = U256::from(123_457u64);
        assert_ne!(base, c.attestation_hash());

        let mut c = sample_credit();
        c.nonce = 8;
        assert_ne!(base, c.attestation_hash());

        let mut c = sample_credit();
        c.signature[0] ^= 0x01;
        assert_ne!(base, c.attestation_hash());
    }

    #[test]
    fn device_binding_round_trip() {
        let signer = fixed_signer();
        let device_address = signer.address();
        let credit = sample_credit();
        let h = credit.attestation_hash();
        let sig = sign_device_binding(&signer, h, device_address).expect("sign");
        assert!(verify_device_binding(sig, h, device_address));
    }

    #[test]
    fn device_binding_wrong_address_rejects() {
        let signer = fixed_signer();
        let credit = sample_credit();
        let h = credit.attestation_hash();
        let sig = sign_device_binding(&signer, h, signer.address()).expect("sign");
        // Verify against a DIFFERENT address — must fail closed.
        let other_address = address!("0x0000000000000000000000000000000000001234");
        assert!(!verify_device_binding(sig, h, other_address));
    }

    #[test]
    fn device_binding_wrong_attestation_hash_rejects() {
        let signer = fixed_signer();
        let credit = sample_credit();
        let h = credit.attestation_hash();
        let sig = sign_device_binding(&signer, h, signer.address()).expect("sign");
        // Verify against a DIFFERENT attestation hash — must fail closed.
        let wrong_h = b256!("0x1111111111111111111111111111111111111111111111111111111111111111");
        assert!(!verify_device_binding(sig, wrong_h, signer.address()));
    }

    #[test]
    fn device_binding_tampered_sig_rejects() {
        let signer = fixed_signer();
        let credit = sample_credit();
        let h = credit.attestation_hash();
        let mut sig = sign_device_binding(&signer, h, signer.address()).expect("sign");
        sig[0] ^= 0x01;
        assert!(!verify_device_binding(sig, h, signer.address()));
    }

    #[test]
    fn device_binding_rejects_unsupported_v_byte() {
        // v=29 is not one of the canonical {27,28} values; ecrecover
        // accepts only these. Defense-in-depth: even a structurally-
        // valid r/s with v=29 must reject.
        let signer = fixed_signer();
        let credit = sample_credit();
        let h = credit.attestation_hash();
        let mut sig = sign_device_binding(&signer, h, signer.address()).expect("sign");
        sig[64] = 29;
        assert!(!verify_device_binding(sig, h, signer.address()));
    }
}
