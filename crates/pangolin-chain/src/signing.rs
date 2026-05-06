//! Canonical hash + Ed25519 signed-revision builder.
//!
//! The on-chain `RevisionLogV0` (P5-1) does NOT verify a revision
//! signature today — that's planned for MVP-2 issue 2.1. The client
//! signs every revision with its Ed25519 device key anyway, but the
//! degree to which v1 can consume those signatures unchanged depends
//! on how v1 elects to verify them.
//!
//! ## What transfers to v1 (P7 audit HIGH-2)
//!
//! - **The canonical-hash construction transfers in every plausible
//!   v1 path.** keccak256 over fixed-width fields with the payload
//!   reduced to its keccak digest is what a Solidity verifier
//!   computes natively, and it's what any practical secp256k1
//!   verifier would also compute (so a v1 that swaps the signature
//!   primitive can still bind to the same digest layout).
//! - **The Ed25519 signature itself transfers only if v1 uses an
//!   on-chain Ed25519 verifier** (Path A in the crate-level
//!   docstring). Path A is viable on L2 (~500k gas per verify ≈
//!   $0.01–0.02 on Base mainnet) but not on L1 mainnet at typical
//!   2026 fees (~$25–50/verify). If v1 instead chooses secp256k1
//!   (Path B — most likely the L1 path because `ecrecover` is the
//!   3 000-gas precompile), the existing Ed25519 signatures would
//!   need to be **re-signed** under the secp256k1 identity before
//!   they can verify under v1, and `device_id` would need to be
//!   re-keyed (Ed25519 verifying-key bytes → secp256k1 EVM-address
//!   or a separately-registered v1 device key).
//!
//! The honest claim is therefore "the canonical-hash construction
//! transfers; the signature primitive may not". The current
//! `signing.rs` API surface is Path-A-shaped; Path B would require a
//! new `secp256k1_signing.rs` (or a refactor to a generic `Signer`
//! trait abstracting over both primitives).
//!
//! ## Canonical-hash construction
//!
//! The hash that the device key signs is built from the same six call
//! arguments that go into `publishRevision` — vault id, account id,
//! parent revision, device id, schema version, and `enc_payload`. The
//! payload bytes are reduced to a fixed-width keccak digest first so
//! the input fed to the signing primitive has a stable size regardless
//! of the AEAD-sealed body length. This is the same shape the v1
//! contract is expected to verify (per the master-plan §3.7
//! discussion).
//!
//! ```text
//! domain  = "pangolin-chain-signed-revision-v0"  (33 B literal)
//! body    = vault_id (32 B)
//!         || account_id (32 B)
//!         || parent_revision (32 B)
//!         || device_id (32 B)
//!         || schema_version (1 B)
//!         || keccak256(enc_payload) (32 B)
//! hash    = keccak256(domain || body)
//! ```
//!
//! Why keccak (Ethereum's flavor of SHA-3) rather than SHA-256: it
//! matches what the v1 contract will compute on-chain via Solidity's
//! `keccak256` builtin, so a client and contract verify the exact
//! same digest with no encoding-skew risk. We pull `keccak256` from
//! `alloy::primitives` rather than adding a separate sha3 crate (the
//! plan's instruction).
//!
//! ## Why the payload is hashed before being fed in
//!
//! Two reasons:
//! 1. The signer always sees a fixed-size 32-byte digest, so the cost
//!    of signing is independent of payload size. Important when v1
//!    contracts compute the same hash inside the EVM where every byte
//!    of `calldata` costs gas.
//! 2. The intermediate keccak provides domain-separation for the
//!    payload itself — the payload bytes are never adjacent to the
//!    metadata fields in the input fed to the outer keccak, so any
//!    boundary-confusion attack would have to produce a length-extended
//!    keccak collision (computationally infeasible).
//!
//! ## Domain separation
//!
//! The literal `"pangolin-chain-signed-revision-v0"` is **versioned**.
//! Any future change to the canonical encoding bumps the suffix
//! (`-v1`) and forces a planned migration. This mirrors the same
//! discipline used for `pangolin-crypto`'s `WRAP_KEY_INFO` and
//! `WRAP_AAD_DOMAIN`.

use alloy::primitives::keccak256;
use pangolin_crypto::keys::DeviceKey;
use pangolin_crypto::sign::{Signature, VerifyingKey};

use crate::types::SignedRevision;

/// Domain-separator for the signed-revision canonical hash.
///
/// **Versioned** — see module docs. Any future change to the canonical
/// encoding bumps the `-v0` suffix.
pub const SIGNED_REVISION_DOMAIN: &[u8] = b"pangolin-chain-signed-revision-v0";

/// Length of the encoded message body (after the domain prefix) in bytes.
///
/// `4 * 32` (the four 32-byte ids) + `1` (schema version byte) + `32`
/// (the payload keccak digest) = 161.
const BODY_LEN: usize = 32 * 4 + 1 + 32;

/// Encode the canonical body of a signed revision into a fixed-size
/// buffer. Pulled into its own function so the layout is testable
/// independently of the keccak step.
fn encode_canonical_body(
    vault_id: &[u8; 32],
    account_id: &[u8; 32],
    parent_revision: &[u8; 32],
    device_id: &[u8; 32],
    schema_version: u8,
    payload_keccak: &[u8; 32],
) -> [u8; BODY_LEN] {
    let mut buf = [0u8; BODY_LEN];
    let mut o = 0usize;
    buf[o..o + 32].copy_from_slice(vault_id);
    o += 32;
    buf[o..o + 32].copy_from_slice(account_id);
    o += 32;
    buf[o..o + 32].copy_from_slice(parent_revision);
    o += 32;
    buf[o..o + 32].copy_from_slice(device_id);
    o += 32;
    buf[o] = schema_version;
    o += 1;
    buf[o..o + 32].copy_from_slice(payload_keccak);
    o += 32;
    debug_assert_eq!(o, BODY_LEN, "canonical body length drift");
    buf
}

/// Compute the canonical hash for a candidate signed revision.
///
/// The hash is `keccak256(SIGNED_REVISION_DOMAIN || body)` where
/// `body` is the fixed-width concatenation documented at the module
/// level. Returns the 32-byte digest as a plain byte array (not
/// `alloy::primitives::B256`) so callers don't need to depend on
/// alloy's primitive types.
///
/// This function is `pub` so the upcoming MVP-2 contract integration
/// (and any external verifier — e.g., `pangolin-indexer`) can compute
/// the same digest without re-deriving it from the signature surface.
#[must_use]
pub fn canonical_hash(
    vault_id: &[u8; 32],
    account_id: &[u8; 32],
    parent_revision: &[u8; 32],
    device_id: &[u8; 32],
    schema_version: u8,
    enc_payload: &[u8],
) -> [u8; 32] {
    let payload_keccak: [u8; 32] = keccak256(enc_payload).0;
    let body = encode_canonical_body(
        vault_id,
        account_id,
        parent_revision,
        device_id,
        schema_version,
        &payload_keccak,
    );
    let mut to_hash = Vec::with_capacity(SIGNED_REVISION_DOMAIN.len() + body.len());
    to_hash.extend_from_slice(SIGNED_REVISION_DOMAIN);
    to_hash.extend_from_slice(&body);
    keccak256(&to_hash).0
}

/// Build a [`SignedRevision`] from the raw fields by signing the
/// canonical hash with the device's Ed25519 key.
///
/// The `device_id` field of the produced `SignedRevision` is set to
/// `device.verifying_key().to_bytes()` — i.e., the device's public
/// signing-key bytes. This ties the signature to a public key the
/// chain (or any external verifier) can independently fetch.
///
/// The `enc_payload` is moved into the result; the caller does not
/// retain ownership.
pub fn build_signed_revision(
    device: &DeviceKey,
    vault_id: [u8; 32],
    account_id: [u8; 32],
    parent_revision: [u8; 32],
    schema_version: u8,
    enc_payload: Vec<u8>,
) -> SignedRevision {
    let device_id: [u8; 32] = device.verifying_key().to_bytes();
    let hash = canonical_hash(
        &vault_id,
        &account_id,
        &parent_revision,
        &device_id,
        schema_version,
        &enc_payload,
    );
    let signature: Signature = device.signing_key().sign(&hash);
    SignedRevision {
        vault_id,
        account_id,
        parent_revision,
        device_id,
        schema_version,
        enc_payload,
        signature,
    }
}

/// Verify a [`SignedRevision`] under the public verifying key embedded
/// in its `device_id`.
///
/// Used by tests + external verifiers (e.g., `pangolin-indexer` will
/// run this on every event). All failure causes collapse to a single
/// [`SignatureInvalid`] variant by design (no timing oracle on the
/// failure mode); the underlying primitive in `pangolin-crypto` makes
/// the same choice for the same reason.
///
/// # Errors
///
/// Returns [`SignatureInvalid`] if the embedded `device_id` is not a
/// canonical Ed25519 verifying key, OR if the signature does not
/// verify under it for the canonical hash of the surrounding fields.
pub fn verify_signed_revision(signed: &SignedRevision) -> Result<(), SignatureInvalid> {
    let pk = VerifyingKey::from_bytes(signed.device_id).map_err(|_| SignatureInvalid)?;
    let hash = canonical_hash(
        &signed.vault_id,
        &signed.account_id,
        &signed.parent_revision,
        &signed.device_id,
        signed.schema_version,
        &signed.enc_payload,
    );
    pk.verify(&hash, &signed.signature)
        .map_err(|_| SignatureInvalid)
}

/// Sentinel error returned by [`verify_signed_revision`].
///
/// Carries no payload — the underlying Ed25519 strict-mode verifier
/// collapses every failure cause into a single variant so a timing
/// attacker cannot tell wrong-key from wrong-message from wrong-
/// signature from non-canonical-encoding. This wrapper preserves that
/// discipline at the `pangolin-chain` layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("signed revision did not verify")]
pub struct SignatureInvalid;

#[cfg(test)]
mod tests {
    use super::{
        build_signed_revision, canonical_hash, encode_canonical_body, verify_signed_revision,
        BODY_LEN, SIGNED_REVISION_DOMAIN,
    };
    use pangolin_crypto::keys::DeviceKey;
    use pangolin_crypto::sign::{Signature, SIGNATURE_LEN};

    /// Plan test: `signing::tests::canonical_hash_is_deterministic`.
    /// Two calls with identical inputs MUST produce the same digest
    /// across runs and process boundaries. This is the core property
    /// that makes the signature byte-stable.
    #[test]
    fn canonical_hash_is_deterministic() {
        let vault = [0x11; 32];
        let account = [0x22; 32];
        let parent = [0x33; 32];
        let device = [0x44; 32];
        let payload = b"hello pangolin";
        let h1 = canonical_hash(&vault, &account, &parent, &device, 0, payload);
        let h2 = canonical_hash(&vault, &account, &parent, &device, 0, payload);
        assert_eq!(h1, h2, "canonical hash must be deterministic per input");
    }

    /// Hash changes if any field flips. We test each field
    /// individually so a regression that accidentally drops a field
    /// from the encoding fails loudly.
    #[test]
    fn canonical_hash_changes_per_field() {
        let v = [0x11; 32];
        let a = [0x22; 32];
        let p = [0x33; 32];
        let d = [0x44; 32];
        let payload = b"baseline";
        let base = canonical_hash(&v, &a, &p, &d, 0, payload);

        // Change vault id.
        let mut v2 = v;
        v2[0] ^= 0x01;
        assert_ne!(base, canonical_hash(&v2, &a, &p, &d, 0, payload));
        // Change account id.
        let mut a2 = a;
        a2[0] ^= 0x01;
        assert_ne!(base, canonical_hash(&v, &a2, &p, &d, 0, payload));
        // Change parent.
        let mut p2 = p;
        p2[0] ^= 0x01;
        assert_ne!(base, canonical_hash(&v, &a, &p2, &d, 0, payload));
        // Change device id.
        let mut d2 = d;
        d2[0] ^= 0x01;
        assert_ne!(base, canonical_hash(&v, &a, &p, &d2, 0, payload));
        // Change schema version.
        assert_ne!(base, canonical_hash(&v, &a, &p, &d, 1, payload));
        // Change payload bytes.
        assert_ne!(
            base,
            canonical_hash(&v, &a, &p, &d, 0, b"different payload")
        );
    }

    /// The encoded body has the documented length 4*32 + 1 + 32.
    #[test]
    fn canonical_body_layout_constants() {
        assert_eq!(BODY_LEN, 4 * 32 + 1 + 32);
        let body = encode_canonical_body(&[0; 32], &[0; 32], &[0; 32], &[0; 32], 0, &[0; 32]);
        assert_eq!(body.len(), BODY_LEN);
    }

    /// Domain separator is versioned at v0.
    #[test]
    fn domain_is_versioned() {
        assert_eq!(SIGNED_REVISION_DOMAIN, b"pangolin-chain-signed-revision-v0");
    }

    /// Plan test:
    /// `signing::tests::signed_revision_verifies_under_device_pubkey`.
    /// Round-trip: build, then verify under the same device — must
    /// succeed.
    #[test]
    fn signed_revision_verifies_under_device_pubkey() {
        let device = DeviceKey::generate();
        let signed = build_signed_revision(
            &device,
            [0x01; 32],
            [0x02; 32],
            [0x03; 32],
            0,
            b"some encrypted payload bytes".to_vec(),
        );
        verify_signed_revision(&signed).expect("freshly-built revision must verify");
    }

    /// Tampered `vault_id` must invalidate the signature.
    #[test]
    fn tampered_vault_id_fails_verification() {
        let device = DeviceKey::generate();
        let mut signed = build_signed_revision(
            &device,
            [0x01; 32],
            [0x02; 32],
            [0x03; 32],
            0,
            b"payload".to_vec(),
        );
        signed.vault_id[0] ^= 0x01;
        verify_signed_revision(&signed).expect_err("tampered vault_id must fail");
    }

    /// Tampered `enc_payload` must invalidate the signature.
    #[test]
    fn tampered_payload_fails_verification() {
        let device = DeviceKey::generate();
        let mut signed = build_signed_revision(
            &device,
            [0x01; 32],
            [0x02; 32],
            [0x03; 32],
            0,
            b"payload-original".to_vec(),
        );
        signed.enc_payload[0] ^= 0x01;
        verify_signed_revision(&signed).expect_err("tampered payload must fail");
    }

    /// Tampered `schema_version` must invalidate the signature.
    #[test]
    fn tampered_schema_version_fails_verification() {
        let device = DeviceKey::generate();
        let mut signed = build_signed_revision(
            &device,
            [0x01; 32],
            [0x02; 32],
            [0x03; 32],
            0,
            b"payload".to_vec(),
        );
        signed.schema_version = 1;
        verify_signed_revision(&signed).expect_err("tampered schema_version must fail");
    }

    /// Tampered signature bytes must fail.
    #[test]
    fn tampered_signature_fails_verification() {
        let device = DeviceKey::generate();
        let mut signed = build_signed_revision(
            &device,
            [0x01; 32],
            [0x02; 32],
            [0x03; 32],
            0,
            b"payload".to_vec(),
        );
        let mut sig_bytes = signed.signature.to_bytes();
        sig_bytes[0] ^= 0x01;
        signed.signature = Signature::from_bytes(sig_bytes);
        verify_signed_revision(&signed).expect_err("tampered signature must fail");
    }

    /// Wrong `device_id` (substituted with a different valid pubkey)
    /// must fail — the signature was made under the original device
    /// key, not the substituted one. Defends against a swap-the-pubkey
    /// attack where an adversary tries to claim authorship of someone
    /// else's revision by stuffing their own pubkey into `device_id`.
    #[test]
    fn substituted_device_id_fails_verification() {
        let device_a = DeviceKey::generate();
        let device_b = DeviceKey::generate();
        let mut signed = build_signed_revision(
            &device_a,
            [0x01; 32],
            [0x02; 32],
            [0x03; 32],
            0,
            b"payload".to_vec(),
        );
        // Replace the device_id with device_b's pubkey, leaving
        // signature alone (it was made by device_a).
        signed.device_id = device_b.verifying_key().to_bytes();
        verify_signed_revision(&signed).expect_err("substituted device_id must fail verification");
    }

    /// Bogus `device_id` bytes (not a canonical Ed25519 point) must
    /// fail at the `from_bytes` step, not panic.
    #[test]
    fn invalid_device_id_bytes_fails_verification() {
        let device = DeviceKey::generate();
        let mut signed = build_signed_revision(
            &device,
            [0x01; 32],
            [0x02; 32],
            [0x03; 32],
            0,
            b"payload".to_vec(),
        );
        // Force a non-canonical pubkey — y = all 0xFF, sign-bit
        // cleared. dalek's `from_bytes` rejects this.
        signed.device_id = [0xFF; 32];
        signed.device_id[31] = 0x7F;
        // Most random non-canonical bytes will be rejected at
        // VerifyingKey::from_bytes; some pass that and fail at
        // verify(). Either is a verification failure from our POV.
        verify_signed_revision(&signed).expect_err("non-canonical device_id must fail");
    }

    /// Sanity: signature length is the Ed25519 64-byte size
    /// (compile-time assertion at the type level too, but a runtime
    /// guard catches accidental future bumps in pangolin-crypto).
    #[test]
    fn signature_byte_length_is_64() {
        assert_eq!(SIGNATURE_LEN, 64);
        let device = DeviceKey::generate();
        let signed = build_signed_revision(&device, [0; 32], [0; 32], [0; 32], 0, b"".to_vec());
        assert_eq!(signed.signature.to_bytes().len(), 64);
    }
}
