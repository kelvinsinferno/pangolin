// SPDX-License-Identifier: AGPL-3.0-or-later
//! Recovery opened-share TRANSPORT primitive (MVP-4-L L-0a-2 / G-1 off-chain).
//!
//! Provides the cross-device transport for a guardian's *opened* recovery
//! share: re-seal it to the recovering user's per-attempt X25519 public key so
//! the cleartext share never crosses a channel an attacker could intercept,
//! and the sealed blob is bound to a specific
//! `(vault, attempt_nonce, recoverer_pubkey, share_identifier)` context.
//!
//! Structurally identical to [`crate::pairing::seal_vdk_to_device`] (which
//! is structurally identical to #104a [`crate::escrow::seal_share`]) — the
//! same `crypto_box` anonymous sealed-box primitive (X25519 ECDH →
//! HSalsa20 KDF → XSalsa20-Poly1305) with a different recipient role,
//! different payload (a 33-byte Shamir piece instead of the 32-byte VDK or
//! the same piece sealed to a guardian), and a different authenticated
//! header that binds the recovery-attempt context.
//!
//! ## Wire layout
//!
//! `crypto_box` sealed boxes have no associated-data channel, so the context
//! is authenticated by prepending it INSIDE the sealed plaintext (the
//! Poly1305 tag covers the whole plaintext):
//!
//! ```text
//! plaintext =
//!     SHARE_TRANSPORT_DOMAIN(36 B, fixed)
//!  || vault_id                      (VAULT_ID_LEN = 32 B)
//!  || attempt_nonce                 (8 B, big-endian u64)
//!  || recoverer_x25519_pub          (X25519_KEY_LEN = 32 B)
//!  || share_identifier              (1 B; equals piece_bytes[0], pinned)
//!  || piece_bytes                   (SHARE_ENCODED_LEN = 33 B)
//! ```
//!
//! Total plaintext = 142 bytes. The sealed-box ciphertext adds 32 bytes
//! (ephemeral X25519 sender pubkey) + 16 bytes (Poly1305 tag) = 190 bytes.
//!
//! ## Invariants (L1, L4)
//!
//! - **L1 (no cleartext share crosses).** The 33-byte cleartext piece is
//!   the secret. It NEVER crosses out of the engine as readable bytes: the
//!   guardian's open-and-re-seal happens in ONE engine call producing only
//!   a sealed blob, and the recoverer's ingest unseals inside the engine
//!   into a [`Share`] (which itself has no host-reachable serializer).
//! - **L4 (fail-closed, no oracle).** Every open failure path collapses
//!   to a single undifferentiated [`ShareTransportError::OpenFailed`] (no
//!   oracle on which header field, ciphertext byte, or AEAD tag caused
//!   the failure — same posture as
//!   [`crate::escrow::open_sealed_share`] / [`crate::pairing::open_vdk_from_pairing`]).
//!
//! ## Domain separation (L4)
//!
//! A new versioned domain string [`SHARE_TRANSPORT_DOMAIN`] is introduced
//! and pinned distinct from every other domain/HKDF-info string in the
//! crate (see `domain_strings_are_versioned_and_distinct` in the audit).
//!
//! ## Forward security
//!
//! Untouched: reconstruction still re-splits a fresh RWK to all M after
//! recovery (the existing `pangolin-core::recovery::orchestration` path).
//! This primitive only transports already-opened pieces.

// Heavily documented crypto module (the wire layout + L1/L4 invariants need
// in-source docs). Doc-style pedantic lints stay allowed at module level;
// substantive lints stay enforced. Matches `pairing.rs` / `escrow.rs`.
#![allow(
    clippy::doc_markdown,
    clippy::too_long_first_doc_paragraph,
    clippy::doc_lazy_continuation
)]

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::escrow::{Share, SHARE_ENCODED_LEN, X25519_KEY_LEN};
use crate::keys::VAULT_ID_LEN;
use crate::rng::os_rng;

/// Domain-separator prefix for the recovery share-transport sealed box.
///
/// Versioned (`-v0`); any change must bump the suffix + document the
/// migration. Pinned distinct from every other in-crate domain string by
/// [`tests::domain_string_distinct_from_other_domains`].
pub const SHARE_TRANSPORT_DOMAIN: &[u8] = b"pangolin-recovery-share-transport-v0";

/// 8-byte big-endian encoding of the on-chain `attemptNonce`.
const ATTEMPT_NONCE_LEN: usize = 8;
/// 1-byte share identifier (the Shamir x-coord; equals piece bytes[0]).
const SHARE_IDENTIFIER_LEN: usize = 1;
/// Fixed-layout header length (sum of all context fields).
const HEADER_LEN: usize = SHARE_TRANSPORT_DOMAIN.len()
    + VAULT_ID_LEN
    + ATTEMPT_NONCE_LEN
    + X25519_KEY_LEN
    + SHARE_IDENTIFIER_LEN;
/// Total sealed plaintext length (header + 33-byte Shamir piece).
const PLAINTEXT_LEN: usize = HEADER_LEN + SHARE_ENCODED_LEN;

/// Errors a recovery share-transport seal or open can surface.
/// Deliberately COARSE — no oracle on the failing field/byte (L4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareTransportError {
    /// The `crypto_box::seal` operation failed (vanishingly rare; could
    /// only happen on a CSPRNG fault).
    SealFailed,
    /// Undifferentiated open/verify failure: bad ciphertext / wrong
    /// recipient secret / context mismatch / malformed inner share. No
    /// oracle on which (L4).
    OpenFailed,
}

impl core::fmt::Display for ShareTransportError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SealFailed => f.write_str("recovery share-transport seal failed"),
            Self::OpenFailed => f.write_str("recovery share-transport open failed"),
        }
    }
}

impl std::error::Error for ShareTransportError {}

/// A [`Share`] sealed to the recovering user's X25519 public key, bound to
/// a recovery-attempt context via an authenticated header.
///
/// Non-secret at rest (the piece inside is sealed); safe to transport over
/// the untrusted channel. The bytes ship via the existing
/// `pangolin-core::pairing_transport::{encode,decode}_text_with_checksum`
/// codec — the host has ONE text-form shape across pairing, sealed-VDK,
/// guardian-invite, and now recovery share transport.
#[derive(Clone)]
pub struct SealedShareForRecoverer {
    /// `crypto_box` anonymous sealed box: `ephemeral_pk(32) || ct + tag`.
    ciphertext: Vec<u8>,
}

impl SealedShareForRecoverer {
    /// Wrap raw sealed bytes (e.g., decoded from the transport codec).
    #[must_use]
    pub fn from_bytes(ciphertext: Vec<u8>) -> Self {
        Self { ciphertext }
    }

    /// Raw sealed bytes for transport/persistence.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.ciphertext
    }
}

impl core::fmt::Debug for SealedShareForRecoverer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Sealed bytes are non-secret but a hex dump clutters logs;
        // report only the length (same posture as SealedVdkForDevice).
        f.debug_struct("SealedShareForRecoverer")
            .field("len", &self.ciphertext.len())
            .finish()
    }
}

/// Build the fixed-layout authenticated header that prepends every
/// transport-sealed share's plaintext. Order matches the wire layout
/// documented at the module level.
fn build_header(
    vault_id: &[u8; VAULT_ID_LEN],
    attempt_nonce: u64,
    recoverer_pub: &[u8; X25519_KEY_LEN],
    share_identifier: u8,
) -> Vec<u8> {
    let mut h = Vec::with_capacity(HEADER_LEN);
    h.extend_from_slice(SHARE_TRANSPORT_DOMAIN);
    h.extend_from_slice(vault_id);
    h.extend_from_slice(&attempt_nonce.to_be_bytes());
    h.extend_from_slice(recoverer_pub);
    h.push(share_identifier);
    debug_assert_eq!(h.len(), HEADER_LEN, "share-transport header length drift");
    h
}

/// Seal a guardian's opened [`Share`] to the recovering user's X25519 public
/// key, binding the recovery-attempt context into the authenticated header.
///
/// The header authenticates `(SHARE_TRANSPORT_DOMAIN, vault_id,
/// attempt_nonce, recoverer_pub, share_identifier)`; `share_identifier` is
/// read from `piece.identifier()` (the Shamir x-coordinate). The 33-byte
/// piece bytes follow inside the sealed plaintext (the Poly1305 tag covers
/// the entire plaintext, header + piece).
///
/// This function does NOT itself check that `recoverer_pub` equals an
/// on-chain `recipientCommitment` — that binding lives in the FFI's
/// `vault_guardian_release_share` engine call (Decision B). This primitive
/// is the cryptographic sealing layer; the binding-to-the-right-recipient
/// is the layer above.
///
/// # Errors
///
/// [`ShareTransportError::SealFailed`] if the sealing operation fails
/// (vanishingly rare; CSPRNG fault).
pub fn seal_share_to_recoverer(
    piece: &Share,
    recoverer_pub: &[u8; X25519_KEY_LEN],
    vault_id: &[u8; VAULT_ID_LEN],
    attempt_nonce: u64,
) -> Result<SealedShareForRecoverer, ShareTransportError> {
    let share_identifier = piece.identifier();
    let mut plaintext = Zeroizing::new(build_header(
        vault_id,
        attempt_nonce,
        recoverer_pub,
        share_identifier,
    ));
    plaintext.extend_from_slice(piece.as_bytes());
    debug_assert_eq!(
        plaintext.len(),
        PLAINTEXT_LEN,
        "share-transport plaintext length drift"
    );

    let pk = crypto_box::PublicKey::from_bytes(*recoverer_pub);
    let ciphertext = pk
        .seal(&mut os_rng(), &plaintext)
        .map_err(|_| ShareTransportError::SealFailed)?;
    Ok(SealedShareForRecoverer { ciphertext })
}

/// Open a [`SealedShareForRecoverer`] with the recovering user's X25519
/// secret key, verify the authenticated header against `(vault_id,
/// attempt_nonce)` + the secret's own derived public key, and return the
/// byte-identical [`Share`].
///
/// Every open/verify failure — wrong secret, tampered ciphertext, wrong
/// `vault_id` / `attempt_nonce` (e.g., a blob from attempt N replayed into
/// attempt N+1), or a header bound to a different recoverer pubkey —
/// collapses to a single undifferentiated [`ShareTransportError::OpenFailed`]
/// (L4: no oracle on the cause).
///
/// Authenticity of the SENDER (i.e., that this blob came from a guardian
/// authorized for the on-chain attempt) is NOT established here — the
/// `crypto_box` sealed-box primitive is one-way anonymous by design. The
/// guardian-identity binding lives at the FFI/contract layer above (the
/// recoverer's client verifies each accepted blob's origin via the on-chain
/// guardian set + the merkle proof carried alongside).
///
/// # Errors
///
/// [`ShareTransportError::OpenFailed`] — undifferentiated — for any
/// open/verify failure.
pub fn open_share_from_recoverer(
    sealed: &SealedShareForRecoverer,
    recoverer_secret: &[u8; X25519_KEY_LEN],
    vault_id: &[u8; VAULT_ID_LEN],
    attempt_nonce: u64,
) -> Result<Share, ShareTransportError> {
    let sk = crypto_box::SecretKey::from_bytes(*recoverer_secret);
    let mut plaintext = Zeroizing::new(
        sk.unseal(&sealed.ciphertext)
            .map_err(|_| ShareTransportError::OpenFailed)?,
    );

    if plaintext.len() != PLAINTEXT_LEN {
        plaintext.zeroize();
        return Err(ShareTransportError::OpenFailed);
    }

    // The 33-byte piece sits at [HEADER_LEN..]; byte 0 of the piece is
    // the Shamir x-coord (the share identifier). The header has the same
    // identifier byte prepended — re-derive the expected header from the
    // piece's identifier so the self-consistency check catches any
    // (theoretical, post-AEAD) skew. The piece bytes are post-AEAD so
    // they are exactly what the sealer wrote.
    let piece_identifier = plaintext[HEADER_LEN];
    let derived_pub = *sk.public_key().as_bytes();
    let expected_header = build_header(vault_id, attempt_nonce, &derived_pub, piece_identifier);

    // Constant-time compare (the header is non-secret context but the
    // posture avoids any field-level short-circuit oracle — mirrors
    // pairing.rs / escrow.rs).
    if !bool::from(plaintext[..HEADER_LEN].ct_eq(&expected_header)) {
        plaintext.zeroize();
        return Err(ShareTransportError::OpenFailed);
    }

    let piece_bytes: Vec<u8> = plaintext[HEADER_LEN..].to_vec();
    plaintext.zeroize();
    Share::from_bytes(piece_bytes).map_err(|_| ShareTransportError::OpenFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::escrow::{reconstruct_rwk, split_rwk, RecoveryWrapKey};

    /// Generate a deterministic X25519 keypair for tests via the same
    /// `crypto_box` primitive `seal`/`unseal` exercise. Returns
    /// `(secret, public)`.
    fn x25519_keypair(seed: u8) -> ([u8; X25519_KEY_LEN], [u8; X25519_KEY_LEN]) {
        let secret = [seed; X25519_KEY_LEN];
        let sk = crypto_box::SecretKey::from_bytes(secret);
        let public = *sk.public_key().as_bytes();
        (secret, public)
    }

    /// Build a deterministic Shamir share via the real `split_rwk` path so
    /// the test seals/opens REAL Shamir pieces (not synthetic 33-byte
    /// noise that wouldn't survive `Share::from_bytes`'s validation).
    fn sample_share() -> Share {
        let rwk = RecoveryWrapKey::generate();
        let shares = split_rwk(&rwk, 2, 3).unwrap();
        // Move the first share out by cloning bytes; Share is !Clone, so
        // round-trip through `from_bytes`.
        Share::from_bytes(shares[0].as_bytes().to_vec()).unwrap()
    }

    /// Happy path: a sealed share opens back to the byte-identical Share.
    #[test]
    fn round_trip_recovers_byte_identical_share() {
        let (sk, pk) = x25519_keypair(0xA1);
        let vault_id = [0x11; VAULT_ID_LEN];
        let attempt_nonce: u64 = 7;
        let piece = sample_share();
        let original_bytes: Vec<u8> = piece.as_bytes().to_vec();

        let sealed = seal_share_to_recoverer(&piece, &pk, &vault_id, attempt_nonce).expect("seal");
        let opened =
            open_share_from_recoverer(&sealed, &sk, &vault_id, attempt_nonce).expect("open");
        assert_eq!(opened.as_bytes(), &original_bytes);
        assert_eq!(opened.identifier(), piece.identifier());
    }

    /// Wrong recoverer secret cannot open (`crypto_box` ECDH mismatch).
    #[test]
    fn wrong_recoverer_secret_fails_open() {
        let (_, pk_a) = x25519_keypair(0xA2);
        let (sk_b, _) = x25519_keypair(0xB2);
        let vault_id = [0x22; VAULT_ID_LEN];
        let piece = sample_share();

        let sealed = seal_share_to_recoverer(&piece, &pk_a, &vault_id, 1).expect("seal");
        let err = open_share_from_recoverer(&sealed, &sk_b, &vault_id, 1).unwrap_err();
        assert_eq!(err, ShareTransportError::OpenFailed);
    }

    /// Wrong `vault_id` on open fails (header binding catches it).
    #[test]
    fn wrong_vault_id_fails_open() {
        let (sk, pk) = x25519_keypair(0xA3);
        let vault_a = [0x33; VAULT_ID_LEN];
        let vault_b = [0x44; VAULT_ID_LEN];
        let piece = sample_share();

        let sealed = seal_share_to_recoverer(&piece, &pk, &vault_a, 1).expect("seal");
        let err = open_share_from_recoverer(&sealed, &sk, &vault_b, 1).unwrap_err();
        assert_eq!(err, ShareTransportError::OpenFailed);
    }

    /// Anti-replay: a blob sealed at attempt N cannot open under attempt
    /// N+1 (the attempt_nonce binding catches it).
    #[test]
    fn wrong_attempt_nonce_fails_open() {
        let (sk, pk) = x25519_keypair(0xA4);
        let vault_id = [0x55; VAULT_ID_LEN];
        let piece = sample_share();

        let sealed = seal_share_to_recoverer(&piece, &pk, &vault_id, 5).expect("seal");
        let err = open_share_from_recoverer(&sealed, &sk, &vault_id, 6).unwrap_err();
        assert_eq!(err, ShareTransportError::OpenFailed);
    }

    /// A single byte flip in the ciphertext is caught by the Poly1305 tag.
    #[test]
    fn tampered_ciphertext_fails_open() {
        let (sk, pk) = x25519_keypair(0xA5);
        let vault_id = [0x66; VAULT_ID_LEN];
        let piece = sample_share();

        let mut sealed_bytes = seal_share_to_recoverer(&piece, &pk, &vault_id, 1)
            .expect("seal")
            .as_bytes()
            .to_vec();
        // Flip a byte well into the ciphertext (past the ephemeral pubkey
        // header at bytes 0..32) — anywhere in the AEAD-covered portion
        // collapses to OpenFailed.
        let idx = sealed_bytes.len() / 2;
        sealed_bytes[idx] ^= 0xFF;
        let sealed = SealedShareForRecoverer::from_bytes(sealed_bytes);
        let err = open_share_from_recoverer(&sealed, &sk, &vault_id, 1).unwrap_err();
        assert_eq!(err, ShareTransportError::OpenFailed);
    }

    /// A too-short (truncated) ciphertext fails closed.
    #[test]
    fn truncated_ciphertext_fails_open() {
        let (sk, _) = x25519_keypair(0xA6);
        let vault_id = [0x77; VAULT_ID_LEN];
        let truncated = SealedShareForRecoverer::from_bytes(vec![0u8; 8]);
        let err = open_share_from_recoverer(&truncated, &sk, &vault_id, 1).unwrap_err();
        assert_eq!(err, ShareTransportError::OpenFailed);
    }

    /// The threshold-secret-sharing property survives the transport: t
    /// pieces re-sealed + opened back rebuild the SAME `RecoveryWrapKey`.
    #[test]
    fn t_of_m_reconstruct_via_transport_recovers_rwk() {
        let (sk, pk) = x25519_keypair(0xC1);
        let vault_id = [0x88; VAULT_ID_LEN];
        let attempt_nonce: u64 = 42;

        let rwk = RecoveryWrapKey::generate();
        let shares = split_rwk(&rwk, 2, 3).unwrap();

        // Seal pieces 0 and 1 (a 2-of-3 quorum) to the recoverer.
        let sealed_a =
            seal_share_to_recoverer(&shares[0], &pk, &vault_id, attempt_nonce).expect("seal a");
        let sealed_b =
            seal_share_to_recoverer(&shares[1], &pk, &vault_id, attempt_nonce).expect("seal b");

        // Recoverer opens both.
        let piece_a =
            open_share_from_recoverer(&sealed_a, &sk, &vault_id, attempt_nonce).expect("open a");
        let piece_b =
            open_share_from_recoverer(&sealed_b, &sk, &vault_id, attempt_nonce).expect("open b");

        // Reconstruct the RWK from the transported pieces.
        let rebuilt = reconstruct_rwk(&[piece_a, piece_b]).expect("reconstruct");

        // Byte-identical recovery.
        assert!(
            bool::from(rwk.ct_eq(&rebuilt)),
            "t-of-m reconstruction via transport must recover the byte-identical RWK"
        );
    }

    /// Domain string is distinct from every other in-crate domain/HKDF
    /// info string. (The pangolin-core grep test in `pairing_transport`
    /// covers the cross-crate domains.)
    #[test]
    fn domain_string_distinct_from_other_domains() {
        let others: &[&[u8]] = &[
            b"pangolin-vdk-wrap-v0",
            b"pangolin-vdk-wrap-aad-v0",
            b"pangolin-recovery-wrap-v0",
            b"pangolin-recovery-seal-v0",
            b"pangolin-guardian-x25519-v0",
            b"pangolin-guardian-x25519-derive-v0",
            crate::pairing::DEVICE_PAIR_X25519_HKDF_INFO,
            crate::pairing::DEVICE_PAIR_X25519_DERIVATION_MESSAGE,
            crate::pairing::DEVICE_WRAP_KEY_INFO,
            b"pangolin-device-pair-seal-v0",
            crate::pairing::SAS_DOMAIN,
        ];
        for o in others {
            assert_ne!(
                SHARE_TRANSPORT_DOMAIN, *o,
                "share-transport DOMAIN must be distinct from every other domain string"
            );
        }
    }

    /// Length pins: any drift in HEADER_LEN / PLAINTEXT_LEN fires loudly.
    #[test]
    fn length_constants_are_pinned() {
        assert_eq!(SHARE_TRANSPORT_DOMAIN.len(), 36, "domain prefix length pin");
        assert_eq!(
            HEADER_LEN,
            36 + 32 + 8 + 32 + 1,
            "header length pin (D + vault_id + nonce + recoverer_pub + share_id)"
        );
        assert_eq!(
            PLAINTEXT_LEN,
            HEADER_LEN + SHARE_ENCODED_LEN,
            "plaintext length pin (header + 33-byte Shamir piece)"
        );
        assert_eq!(
            PLAINTEXT_LEN,
            109 + 33,
            "plaintext length numeric pin (142 B)"
        );
    }

    /// Paranoia: an attacker-forged blob whose plaintext has identifier=0
    /// (both in the header and as `piece_bytes[0]`) must fail closed at the
    /// post-AEAD `Share::from_bytes` rejection. The header self-consistency
    /// check passes (identifier_in_header == piece[0] == 0), the AEAD passes
    /// (the attacker sealed validly), but `Share::from_bytes` rejects
    /// identifier=0 (the Shamir x-coord zero is reserved). Confirms the
    /// last fail-closed gate downstream of the AEAD.
    #[test]
    fn attacker_forged_blob_with_zero_identifier_fails_closed() {
        let (sk, pk) = x25519_keypair(0xE1);
        let vault_id = [0xAA; VAULT_ID_LEN];
        let attempt_nonce: u64 = 17;

        // Hand-craft the plaintext with identifier=0 in BOTH the header AND
        // the piece bytes (so the self-consistency check would pass).
        let mut forged_plaintext = build_header(&vault_id, attempt_nonce, &pk, 0);
        // 33-byte piece with identifier=0 + 32 zero y-bytes (any content;
        // identifier=0 is what `Share::from_bytes` rejects).
        forged_plaintext.extend_from_slice(&[0u8; SHARE_ENCODED_LEN]);
        assert_eq!(forged_plaintext.len(), PLAINTEXT_LEN);

        // Seal it directly via crypto_box (bypassing seal_share_to_recoverer
        // which won't accept a Share with identifier=0).
        let pub_key = crypto_box::PublicKey::from_bytes(pk);
        let ciphertext = pub_key
            .seal(&mut os_rng(), &forged_plaintext)
            .expect("attacker seal");
        let sealed = SealedShareForRecoverer::from_bytes(ciphertext);

        // Open MUST fail closed at Share::from_bytes (post-AEAD).
        let err = open_share_from_recoverer(&sealed, &sk, &vault_id, attempt_nonce).unwrap_err();
        assert_eq!(err, ShareTransportError::OpenFailed);
    }

    /// `SealedShareForRecoverer`'s Debug redacts the bytes — only `len` is
    /// surfaced. Matches the SealedVdkForDevice posture.
    #[test]
    fn debug_redacts_ciphertext_bytes() {
        let (_, pk) = x25519_keypair(0xD1);
        let vault_id = [0x99; VAULT_ID_LEN];
        let piece = sample_share();
        let sealed = seal_share_to_recoverer(&piece, &pk, &vault_id, 1).expect("seal");
        let s = format!("{sealed:?}");
        assert!(s.contains("SealedShareForRecoverer"));
        assert!(s.contains("len"));
        // No raw hex bytes leaked.
        assert!(!s.contains("ciphertext"));
    }
}
