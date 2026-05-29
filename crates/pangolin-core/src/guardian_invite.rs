// SPDX-License-Identifier: AGPL-3.0-or-later
//! Guardian-invite TRANSPORT codec (L-0b / gap G-2).
//!
//! A vault owner onboarding social-recovery guardians needs each guardian's
//! IDENTITY: the guardian's 32-byte X25519 SEALING pubkey (what the owner
//! seals that guardian's recovery share to at onboarding) plus the guardian's
//! 20-byte secp256k1 EVM address (the on-chain guardian-set member). This codec
//! is the shareable payload a guardian's device EXPORTS so the owner can
//! collect it — the social-recovery analog of the device-pairing payload.
//!
//! Structurally identical to [`crate::pairing_transport::PairingPayload`]
//! (fixed-layout, zero-serde, length- + checksum-validated, version-gated) and
//! it RE-USES that module's public base32 + 4-byte-checksum text codec
//! ([`crate::pairing_transport::encode_text_with_checksum`] /
//! [`decode_text_with_checksum`](crate::pairing_transport::decode_text_with_checksum))
//! so the host has ONE text-form shape across pairing AND guardian invites.
//! It differs in WHAT it carries: the guardian SEALING key (NOT the
//! device-pairing key) and no vault/device id — a guardian identity is
//! vault-independent; the owner binds it to a specific vault at onboarding.
//!
//! ## Wire layout
//!
//! ```text
//! payload_bytes =
//!     DOMAIN(D bytes, fixed)
//!  || schema_version    (1 B, == SCHEMA_VERSION)
//!  || x25519_sealing_pub (X25519_KEY_LEN = 32 B)
//!  || signer            (SIGNER_LEN = 20 B, the guardian's secp256k1 EVM address)
//! ```
//!
//! Total = [`PAYLOAD_LEN`] = `DOMAIN.len() + 1 + 32 + 20`. The TEXT form is
//! `base32_lowercase_nopad(payload_bytes || sha256(payload_bytes)[..4])`.
//!
//! ## Invariants (L1, L4)
//!
//! - **L1.** Every field is NON-secret: the X25519 sealing PUBLIC key + the
//!   EVM address. The X25519 sealing SECRET and the `DeviceKey` stay
//!   engine-side (the FFI derives the pubkey via a session-gated `Vault`
//!   accessor and never returns the secret).
//! - **L4.** Fixed-offset, length-strict, version-gated. A drifted byte does
//!   NOT silently re-parse; every decode runs length → domain → version gates
//!   and fails CLOSED with a typed [`PairingTransportError`].

#![forbid(unsafe_code)]
// Heavily-documented transport module (the wire layout + invariants belong
// in-source). The doc-style pedantic lints below would contort the docs with
// no security/correctness benefit; allow them at module level. Substantive
// lints stay enforced. Matches `crate::pairing_transport`.
#![allow(
    clippy::doc_markdown,
    clippy::too_long_first_doc_paragraph,
    clippy::doc_lazy_continuation
)]

use pangolin_crypto::escrow::X25519_KEY_LEN;

use crate::pairing_transport::{
    decode_text_with_checksum, encode_text_with_checksum, PairingTransportError, SIGNER_LEN,
};

/// The guardian-invite domain-separator prefix. Distinct from every other
/// domain string in the codebase (pinned by
/// [`tests::guardian_invite_domain_distinct_from_other_domains`]).
pub const DOMAIN: &[u8] = b"pangolin-guardian-invite-v0";

/// Guardian-invite schema version. First version of this payload (its own
/// versioning namespace — the distinct [`DOMAIN`] prevents any collision with
/// the pairing payload's `SCHEMA_VERSION`). A decode against any other version
/// fails CLOSED with [`PairingTransportError::UnsupportedVersion`].
pub const SCHEMA_VERSION: u8 = 1;

/// Total exact byte length of an encoded guardian invite (zero-serde,
/// fixed-layout). Decoding any slice whose length ≠ [`PAYLOAD_LEN`] fails
/// CLOSED with [`PairingTransportError::WrongLength`].
pub const PAYLOAD_LEN: usize = DOMAIN.len() + 1 + X25519_KEY_LEN + SIGNER_LEN;

/// The fixed-offset start of `schema_version`.
const OFFSET_SCHEMA_VERSION: usize = DOMAIN.len();
/// The fixed-offset start of `x25519_sealing_pub`.
const OFFSET_SEALING_PUB: usize = OFFSET_SCHEMA_VERSION + 1;
/// The fixed-offset start of `signer`.
const OFFSET_SIGNER: usize = OFFSET_SEALING_PUB + X25519_KEY_LEN;

/// The NON-secret guardian invite — what the BYTE form encodes / the TEXT form
/// encodes after checksum-appending.
///
/// Both fields are public context (a sealing PUBLIC key + an EVM address). No
/// `Drop`/zeroize discipline is needed (zero secret-bearing field). Zero serde
/// — encode/decode go through [`encode_bytes`] / [`decode_bytes`] (and their
/// `_string` variants).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuardianInvite {
    /// The schema version this invite was encoded under — currently the pinned
    /// [`SCHEMA_VERSION`]. A decode of a different version fails CLOSED.
    pub schema_version: u8,
    /// The guardian device's 32-byte X25519 SEALING pubkey
    /// ([`pangolin_crypto::guardian::derive_x25519_sealing_key`]). What the
    /// vault owner seals this guardian's recovery share to at onboarding.
    pub x25519_sealing_pub: [u8; X25519_KEY_LEN],
    /// The guardian device's 20-byte secp256k1 EVM address
    /// ([`pangolin_chain::evm::derive_evm_wallet`]). The on-chain
    /// `RecoveryV*` guardian-set member.
    pub signer: [u8; SIGNER_LEN],
}

/// Encode a [`GuardianInvite`] to its fixed-layout byte form (exactly
/// [`PAYLOAD_LEN`] bytes). The encoder stamps `invite.schema_version` verbatim
/// — callers building a NEW invite MUST set it to [`SCHEMA_VERSION`] (the FFI
/// does this for them). Deterministic; re-encoding a decoded invite round-trips
/// byte-identical.
#[must_use]
pub fn encode_bytes(invite: &GuardianInvite) -> Vec<u8> {
    let mut out = Vec::with_capacity(PAYLOAD_LEN);
    out.extend_from_slice(DOMAIN);
    out.push(invite.schema_version);
    out.extend_from_slice(&invite.x25519_sealing_pub);
    out.extend_from_slice(&invite.signer);
    debug_assert_eq!(
        out.len(),
        PAYLOAD_LEN,
        "encode_bytes drift — PAYLOAD_LEN constant out of sync with the layout"
    );
    out
}

/// Decode a fixed-layout byte invite back into a [`GuardianInvite`].
///
/// Three-step gate (each failure CLOSED with a typed error): length →
/// [`PairingTransportError::WrongLength`]; domain →
/// [`PairingTransportError::DomainMismatch`]; schema version →
/// [`PairingTransportError::UnsupportedVersion`]. Field extraction itself
/// cannot fail (the length check guaranteed the slices are valid).
///
/// # Errors
///
/// [`PairingTransportError::WrongLength`] / `DomainMismatch` /
/// `UnsupportedVersion`. NEVER `ChecksumMismatch` / `InvalidEncoding` (those
/// are text-form only).
pub fn decode_bytes(bytes: &[u8]) -> Result<GuardianInvite, PairingTransportError> {
    if bytes.len() != PAYLOAD_LEN {
        return Err(PairingTransportError::WrongLength);
    }
    if &bytes[..DOMAIN.len()] != DOMAIN {
        return Err(PairingTransportError::DomainMismatch);
    }
    let schema_version = bytes[OFFSET_SCHEMA_VERSION];
    if schema_version != SCHEMA_VERSION {
        return Err(PairingTransportError::UnsupportedVersion);
    }
    let mut x25519_sealing_pub = [0u8; X25519_KEY_LEN];
    x25519_sealing_pub
        .copy_from_slice(&bytes[OFFSET_SEALING_PUB..OFFSET_SEALING_PUB + X25519_KEY_LEN]);
    let mut signer = [0u8; SIGNER_LEN];
    signer.copy_from_slice(&bytes[OFFSET_SIGNER..OFFSET_SIGNER + SIGNER_LEN]);
    Ok(GuardianInvite {
        schema_version,
        x25519_sealing_pub,
        signer,
    })
}

/// Encode a [`GuardianInvite`] to its TEXT form — lowercase base32-no-padding
/// of `payload_bytes || sha256(payload_bytes)[..4]`. Re-uses the
/// pairing-transport text codec so the host has ONE decoder shape.
#[must_use]
pub fn encode_string(invite: &GuardianInvite) -> String {
    encode_text_with_checksum(&encode_bytes(invite))
}

/// Decode a TEXT-form guardian invite back into a [`GuardianInvite`]. The host
/// normalizes / strips whitespace BEFORE calling.
///
/// # Errors
///
/// [`PairingTransportError::InvalidEncoding`] / `ChecksumMismatch` (text
/// layer) then `WrongLength` / `DomainMismatch` / `UnsupportedVersion` (byte
/// gate).
pub fn decode_string(s: &str) -> Result<GuardianInvite, PairingTransportError> {
    let bytes = decode_text_with_checksum(s)?;
    decode_bytes(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_invite() -> GuardianInvite {
        GuardianInvite {
            schema_version: SCHEMA_VERSION,
            x25519_sealing_pub: [0x33; X25519_KEY_LEN],
            signer: [0x44; SIGNER_LEN],
        }
    }

    /// L4: the payload length is exactly the documented constant.
    #[test]
    fn payload_length_is_exact_constant() {
        // 27 (DOMAIN) + 1 + 32 + 20 = 80 bytes.
        assert_eq!(DOMAIN.len(), 27, "domain prefix length pin");
        assert_eq!(PAYLOAD_LEN, 80, "guardian-invite byte length pin");
        assert_eq!(encode_bytes(&sample_invite()).len(), PAYLOAD_LEN);
    }

    /// L4 round-trip: byte form encode → decode reconstructs the identical
    /// invite, and the re-encode is byte-identical.
    #[test]
    fn byte_form_round_trip_is_byte_identical() {
        let inv = sample_invite();
        let b1 = encode_bytes(&inv);
        let decoded = decode_bytes(&b1).unwrap();
        assert_eq!(decoded, inv);
        assert_eq!(
            b1,
            encode_bytes(&decoded),
            "round-trip must be byte-identical"
        );
    }

    /// The TEXT form round-trips byte-identical AND yields the same invite as
    /// the BYTE form; the text alphabet is lowercase base32 (`a-z` + `2-7`).
    #[test]
    fn text_form_round_trip_is_byte_identical() {
        let inv = sample_invite();
        let s = encode_string(&inv);
        assert_eq!(decode_string(&s).unwrap(), inv);
        assert_eq!(s, encode_string(&decode_string(&s).unwrap()));
        for c in s.bytes() {
            assert!(
                c.is_ascii_lowercase() || (b'2'..=b'7').contains(&c),
                "text-form byte outside base32 alphabet: {c}"
            );
        }
    }

    /// Length-negative: a too-short / too-long / empty byte buffer rejects with
    /// `WrongLength`.
    #[test]
    fn decode_bytes_wrong_length_rejected() {
        let inv = sample_invite();
        let mut short = encode_bytes(&inv);
        short.pop();
        assert_eq!(
            decode_bytes(&short),
            Err(PairingTransportError::WrongLength)
        );
        let mut long = encode_bytes(&inv);
        long.push(0);
        assert_eq!(decode_bytes(&long), Err(PairingTransportError::WrongLength));
        assert_eq!(decode_bytes(&[]), Err(PairingTransportError::WrongLength));
    }

    /// Domain-negative: a buffer whose leading prefix is NOT [`DOMAIN`] rejects
    /// with `DomainMismatch`.
    #[test]
    fn decode_bytes_domain_mismatch_rejected() {
        let mut tampered = encode_bytes(&sample_invite());
        tampered[0] ^= 0x01;
        assert_eq!(
            decode_bytes(&tampered),
            Err(PairingTransportError::DomainMismatch)
        );
    }

    /// Version-negative: a buffer whose schema_version byte is not
    /// [`SCHEMA_VERSION`] rejects with `UnsupportedVersion`.
    #[test]
    fn decode_bytes_unsupported_version_rejected() {
        let mut tampered = encode_bytes(&sample_invite());
        tampered[OFFSET_SCHEMA_VERSION] = SCHEMA_VERSION.wrapping_add(1);
        assert_eq!(
            decode_bytes(&tampered),
            Err(PairingTransportError::UnsupportedVersion)
        );
        tampered[OFFSET_SCHEMA_VERSION] = 0;
        assert_eq!(
            decode_bytes(&tampered),
            Err(PairingTransportError::UnsupportedVersion)
        );
    }

    /// Text-form checksum-negative: flipping a single character in the text
    /// body rejects with `ChecksumMismatch`.
    #[test]
    fn decode_string_checksum_mismatch_rejected() {
        let s = encode_string(&sample_invite());
        let mut tampered: Vec<u8> = s.into_bytes();
        let mid = tampered.len() / 2;
        let original = tampered[mid];
        tampered[mid] = if original == b'a' { b'b' } else { b'a' };
        assert_eq!(
            decode_string(std::str::from_utf8(&tampered).unwrap()),
            Err(PairingTransportError::ChecksumMismatch)
        );
    }

    /// Text-form encoding-negative: a character outside `a-z2-7` (uppercase,
    /// whitespace, empty) is rejected with `InvalidEncoding`.
    #[test]
    fn decode_string_invalid_encoding_rejected() {
        assert_eq!(
            decode_string("ABCDEF"),
            Err(PairingTransportError::InvalidEncoding)
        );
        assert_eq!(
            decode_string("abc def"),
            Err(PairingTransportError::InvalidEncoding)
        );
        assert_eq!(
            decode_string(""),
            Err(PairingTransportError::InvalidEncoding)
        );
    }

    /// L4 byte-pin: the `DOMAIN` is distinct from every other domain string in
    /// the codebase (incl. the pairing-payload domain — same length, MUST
    /// differ). A drift collapses a domain-separation invariant.
    ///
    /// Cross-crate constants without a `pub` path (e.g. `pangolin-crypto`'s
    /// private `SEALED_SHARE_DOMAIN` / `WRAP_AAD_DOMAIN`, `pangolin-chain`'s
    /// chain-not-a-dep-here strings, `pangolin-store::recovery_backup::DOMAIN`)
    /// are checked as byte literals — for distinctness the bytes are what
    /// matters.
    #[test]
    fn guardian_invite_domain_distinct_from_other_domains() {
        let others: &[&[u8]] = &[
            // Reachable via pub items in this crate's deps.
            crate::pairing_transport::DOMAIN,
            pangolin_crypto::pairing::DEVICE_PAIR_X25519_HKDF_INFO,
            pangolin_crypto::pairing::DEVICE_PAIR_X25519_DERIVATION_MESSAGE,
            pangolin_crypto::pairing::DEVICE_WRAP_KEY_INFO,
            pangolin_crypto::pairing::SAS_DOMAIN,
            // Private constants in pangolin-crypto / pangolin-chain /
            // pangolin-store — mirrored here as byte literals (distinctness
            // is a property of the bytes, not the constant identifier).
            b"pangolin-vdk-wrap-v0",
            b"pangolin-vdk-wrap-aad-v0",
            b"pangolin-recovery-wrap-v0",
            b"pangolin-recovery-seal-v0",
            b"pangolin-guardian-x25519-v0",
            b"pangolin-guardian-x25519-derive-v0",
            b"pangolin-device-pair-seal-v0",
            b"pangolin-chain-signed-revision-v0",
            b"pangolin-chain-evm-wallet-derive-v0",
            b"pangolin-chain-evm-wallet-v0",
            b"pangolin-recovery-backup-v0\0",
        ];
        for o in others {
            assert_ne!(DOMAIN, *o, "guardian-invite DOMAIN must be distinct");
        }
    }

    /// L4: the schema version is pinned to 1. A future bump must update this
    /// constant + this test together.
    #[test]
    fn schema_version_is_pinned_to_one() {
        assert_eq!(SCHEMA_VERSION, 1, "guardian-invite schema version pin");
    }

    /// The transport error maps to a coarse `Validation { kind: "argument" }`
    /// on the `pangolin_core::Error` join (re-used from pairing_transport).
    #[test]
    fn error_maps_to_validation_argument() {
        let core_err: crate::Error = PairingTransportError::WrongLength.into();
        assert!(
            matches!(core_err, crate::Error::Validation { ref kind, .. } if kind == "argument"),
            "guardian-invite decode error must map to Validation(argument)"
        );
    }
}
