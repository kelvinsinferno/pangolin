// SPDX-License-Identifier: AGPL-3.0-or-later
//! **MVP-4-L L-0b (gap G-2): the thin uniffi layer over
//! [`pangolin_core::guardian_invite`].**
//!
//! A vault owner onboarding social-recovery guardians needs each guardian's
//! identity (X25519 sealing pubkey + EVM address) so the engine can seal that
//! guardian's recovery share to them and add their EVM address to the on-chain
//! guardian set. This FFI lets a guardian device EXPORT its identity as a
//! shareable invite, and lets the OWNER decode a received invite — the
//! social-recovery analog of `pairing::pairing_begin_new_device` /
//! `pairing::pairing_decode_*`.
//!
//! ## Invariants
//!
//! - **L1 (no secret crosses).** The X25519 sealing PUBKEY + the EVM address
//!   are non-secret (the on-chain guardian set publishes the address; the
//!   sealing pubkey is exactly what the owner stores per-guardian, already a
//!   parameter of [`vault_onboard_guardians`]). The X25519 sealing SECRET and
//!   the `DeviceKey` stay engine-side: the export reads them via the
//!   session-gated `Vault::guardian_sealing_pubkey` + `Vault::evm_wallet`
//!   accessors, which never return the secret material.
//! - **L4 (session-gated).** [`vault_export_guardian_identity`] requires an
//!   Active session (same gate as the pairing exports).
//! - **L4 (fail-closed decode).** [`guardian_invite_decode_bytes`] /
//!   [`guardian_invite_decode_string`] are PURE (no handle); every decode
//!   failure surfaces as [`FfiError::Validation`] (`kind = "argument"`) — no
//!   oracle on the reason.

#![forbid(unsafe_code)]
// Heavily-documented FFI module; allow the doc-style pedantic lints (matches
// the pairing.rs / recovery_ffi.rs precedent). Substantive lints stay
// enforced.
#![allow(
    clippy::doc_markdown,
    clippy::too_long_first_doc_paragraph,
    clippy::doc_lazy_continuation
)]

use std::sync::Arc;

use pangolin_core::guardian_invite::{
    decode_bytes as decode_invite_bytes, decode_string as decode_invite_string, encode_bytes,
    encode_string, GuardianInvite, SCHEMA_VERSION as GUARDIAN_INVITE_SCHEMA_VERSION,
};
use pangolin_core::pairing_transport::{PairingTransportError, SIGNER_LEN};
use pangolin_crypto::escrow::X25519_KEY_LEN;

use crate::error::FfiError;
use crate::session::VaultHandle;

/// Schema-version slot pinning the `FfiGuardianInvite` Record's shape
/// (the `Vec<u8>` / `String` / `u16` field layout the foreign-language
/// binding sees). Bumped INDEPENDENTLY from the wire-form
/// [`GUARDIAN_INVITE_SCHEMA_VERSION`] — the wire form pins the
/// on-the-air byte layout; this version pins the FFI record shape. They
/// are two distinct concerns: a host can be on V1 of the record shape
/// while consuming V2 wire bytes (or vice versa) without ambiguity.
pub const GUARDIAN_IDENTITY_FFI_SCHEMA_VERSION: u16 = 1;

// ---------------------------------------------------------------------------
// Helpers (mirror the per-module copies in pairing.rs / recovery_ffi.rs)
// ---------------------------------------------------------------------------

fn store_into_ffi(err: pangolin_store::StoreError) -> FfiError {
    FfiError::from(pangolin_core::Error::from(err))
}

fn transport_into_ffi(err: PairingTransportError) -> FfiError {
    FfiError::from(pangolin_core::Error::from(err))
}

// ---------------------------------------------------------------------------
// FfiGuardianInvite — the non-secret guardian-identity record (Q-carrier)
// ---------------------------------------------------------------------------

/// The non-secret guardian invite + its two transport forms (byte form for
/// QR-rendering, text form for copy-paste). Mirrors the shape of
/// [`crate::pairing::FfiPairingPayload`] but carries the guardian SEALING
/// pubkey + EVM address only (no vault/device id / nonce — a guardian identity
/// is vault-independent; the owner binds it at onboarding).
///
/// Every field is non-secret (L1). The host transports `bytes` (e.g. by
/// rendering as a QR) AND/OR `string_form` (by copy-paste); the receiver
/// passes EITHER back to [`guardian_invite_decode_bytes`] /
/// [`guardian_invite_decode_string`] to reconstruct the same record.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiGuardianInvite {
    /// Schema-version slot for the FFI Record shape (independent of
    /// `payload_schema_version`).
    pub schema_version: u16,
    /// The invite byte form (length-strict [`PAYLOAD_LEN`]). Host renders as
    /// a QR.
    pub bytes: Vec<u8>,
    /// The invite text form (lowercase base32 + 4-byte truncated-SHA-256
    /// checksum). Host copy-pastes it.
    pub string_form: String,
    /// The wire-form schema version this invite was produced under (currently
    /// [`GUARDIAN_INVITE_SCHEMA_VERSION`] = 1). The foreign-language binding
    /// can branch on this for migration; an unknown version is rejected on
    /// the next decode.
    pub payload_schema_version: u16,
    /// The guardian's 32-byte X25519 SEALING pubkey. Non-secret. The owner
    /// passes this exact value into
    /// [`crate::recovery_ffi::vault_onboard_guardians`].
    pub x25519_sealing_pub: Vec<u8>,
    /// The guardian's 20-byte secp256k1 EVM address. Non-secret. The owner
    /// passes this value into the on-chain `RecoveryV*.setGuardianSet` merkle
    /// root.
    pub signer: Vec<u8>,
}

impl FfiGuardianInvite {
    /// Build an [`FfiGuardianInvite`] from the engine-native
    /// [`GuardianInvite`] (the producer chain for [`vault_export_guardian_identity`]
    /// + the two pure decoders).
    fn from_invite(invite: &GuardianInvite) -> Self {
        let bytes = encode_bytes(invite);
        let string_form = encode_string(invite);
        Self {
            schema_version: GUARDIAN_IDENTITY_FFI_SCHEMA_VERSION,
            bytes,
            string_form,
            payload_schema_version: u16::from(invite.schema_version),
            x25519_sealing_pub: invite.x25519_sealing_pub.to_vec(),
            signer: invite.signer.to_vec(),
        }
    }
}

// ---------------------------------------------------------------------------
// 1. vault_export_guardian_identity — GUARDIAN device builds its invite
// ---------------------------------------------------------------------------

/// **GUARDIAN device.** Build this device's guardian invite — the non-secret
/// `(x25519_sealing_pub, signer)` pair — and return it in both BYTE and
/// TEXT-STRING forms.
///
/// Session-gated (Active — the engine reads the active session's `DeviceKey`
/// to derive the sealing pubkey via
/// [`pangolin_crypto::guardian::derive_x25519_sealing_key`] and the EVM
/// address via [`pangolin_chain::evm::derive_evm_wallet`]; the device-key
/// secret never crosses out).
///
/// # Errors
///
/// [`FfiError::Session`] for a placeholder / locked vault. Underlying store
/// errors propagate through the standard `StoreError → pangolin_core::Error →
/// FfiError` mapping.
#[allow(clippy::significant_drop_tightening)]
#[uniffi::export]
pub fn vault_export_guardian_identity(
    handle: Arc<VaultHandle>,
) -> Result<FfiGuardianInvite, FfiError> {
    let mut guard = handle.lock_vault();
    let vault = guard.as_mut()?;
    if vault.state() != pangolin_store::VaultState::Active {
        return Err(FfiError::Session {
            message: "vault is not unlocked".to_owned(),
        });
    }

    // Both derivations are session-gated `Vault` accessors — neither returns
    // the underlying secret.
    let x25519_sealing_pub_arr: [u8; X25519_KEY_LEN] =
        vault.guardian_sealing_pubkey().map_err(store_into_ffi)?;
    let signer_addr = vault.evm_wallet().map_err(store_into_ffi)?.address();
    let signer_arr: [u8; SIGNER_LEN] = signer_addr.into_array();

    let invite = GuardianInvite {
        schema_version: GUARDIAN_INVITE_SCHEMA_VERSION,
        x25519_sealing_pub: x25519_sealing_pub_arr,
        signer: signer_arr,
    };
    Ok(FfiGuardianInvite::from_invite(&invite))
}

// ---------------------------------------------------------------------------
// 2. guardian_invite_decode_{bytes,string} — pure decoders (no handle)
// ---------------------------------------------------------------------------

/// **Pure decode** (no handle). Decode a BYTE-form guardian invite into an
/// [`FfiGuardianInvite`]. Length-strict + domain-checked + version-gated.
///
/// # Errors
///
/// [`FfiError::Validation`] (`kind = "argument"`) for any decode failure —
/// `WrongLength` / `DomainMismatch` / `UnsupportedVersion`.
#[uniffi::export]
pub fn guardian_invite_decode_bytes(bytes: Vec<u8>) -> Result<FfiGuardianInvite, FfiError> {
    let invite = decode_invite_bytes(&bytes).map_err(transport_into_ffi)?;
    Ok(FfiGuardianInvite::from_invite(&invite))
}

/// **Pure decode** (no handle). Decode the TEXT-form (base32 + truncated-
/// SHA-256 checksum) guardian invite into an [`FfiGuardianInvite`]. The host
/// normalizes / strips whitespace BEFORE calling.
///
/// # Errors
///
/// [`FfiError::Validation`] (`kind = "argument"`) for any decode failure —
/// `InvalidEncoding` / `WrongLength` / `ChecksumMismatch` / `DomainMismatch`
/// / `UnsupportedVersion`.
#[uniffi::export]
pub fn guardian_invite_decode_string(s: String) -> Result<FfiGuardianInvite, FfiError> {
    let invite = decode_invite_string(&s).map_err(transport_into_ffi)?;
    Ok(FfiGuardianInvite::from_invite(&invite))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pangolin_core::guardian_invite::PAYLOAD_LEN;
    use pangolin_crypto::secret::SecretBytes;
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

    /// Export on an Active vault returns a well-formed invite (correct
    /// lengths, schema versions, byte/text round-trip through the pure
    /// decoders), and the convenience fields equal the engine-derived
    /// pubkey/address.
    #[allow(clippy::significant_drop_tightening)]
    #[test]
    fn export_returns_well_formed_invite() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        let fi = vault_export_guardian_identity(Arc::clone(&h)).expect("export");

        assert_eq!(fi.schema_version, GUARDIAN_IDENTITY_FFI_SCHEMA_VERSION);
        assert_eq!(
            fi.payload_schema_version,
            u16::from(GUARDIAN_INVITE_SCHEMA_VERSION)
        );
        assert_eq!(fi.bytes.len(), PAYLOAD_LEN, "byte length pin");
        assert_eq!(fi.x25519_sealing_pub.len(), X25519_KEY_LEN);
        assert_eq!(fi.signer.len(), SIGNER_LEN);
        assert!(
            !fi.string_form.is_empty()
                && fi
                    .string_form
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || (b'2'..=b'7').contains(&c)),
            "string_form must be lowercase base32"
        );

        // Both decoders reconstruct the SAME invite. Pinning the round-trip
        // is exactly the plan §3 "export → decode → fields match" check.
        let decoded_b = guardian_invite_decode_bytes(fi.bytes.clone()).unwrap();
        assert_eq!(decoded_b.x25519_sealing_pub, fi.x25519_sealing_pub);
        assert_eq!(decoded_b.signer, fi.signer);
        let decoded_s = guardian_invite_decode_string(fi.string_form.clone()).unwrap();
        assert_eq!(decoded_s.bytes, decoded_b.bytes);

        // The exported pubkey/address EQUAL what the engine derives directly
        // from the active session's DeviceKey (the underlying invariant the
        // owner relies on at onboarding). Scoped so the lock guard drops
        // before the asserts (clippy::significant_drop_tightening).
        let (expected_pub, expected_addr) = {
            let mut guard = h.lock_vault();
            let vault = guard.as_mut().unwrap();
            let p = vault.guardian_sealing_pubkey().unwrap();
            let a = vault.evm_wallet().unwrap().address().into_array();
            (p, a)
        };
        assert_eq!(fi.x25519_sealing_pub, expected_pub.to_vec());
        assert_eq!(fi.signer, expected_addr.to_vec());
    }

    /// Export on a locked vault → `Session` (L4 session gate).
    #[test]
    fn export_rejects_locked() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        {
            let mut g = h.lock_vault();
            g.as_mut().unwrap().lock();
        }
        let err = vault_export_guardian_identity(h).unwrap_err();
        assert!(matches!(err, FfiError::Session { .. }));
    }

    /// Export on a placeholder handle → `Session`.
    #[test]
    fn export_rejects_placeholder() {
        let h = VaultHandle::new_placeholder();
        let err = vault_export_guardian_identity(h).unwrap_err();
        assert!(matches!(err, FfiError::Session { .. }));
    }

    /// Pure-decode negative paths surface as `Validation { kind: "argument" }`
    /// — no oracle, fail-closed (the same shape as the pairing decoders).
    #[test]
    fn decode_negative_paths_validate_argument() {
        // Length: zero-length bytes.
        let err = guardian_invite_decode_bytes(vec![]).unwrap_err();
        assert!(matches!(err, FfiError::Validation { ref kind, .. } if kind == "argument"));
        // Domain: bytes of the right length but with a tampered domain prefix.
        let mut tampered = vec![0u8; PAYLOAD_LEN];
        tampered[0] = b'X';
        let err = guardian_invite_decode_bytes(tampered).unwrap_err();
        assert!(matches!(err, FfiError::Validation { ref kind, .. } if kind == "argument"));
        // Text: empty string.
        let err = guardian_invite_decode_string(String::new()).unwrap_err();
        assert!(matches!(err, FfiError::Validation { ref kind, .. } if kind == "argument"));
    }
}
