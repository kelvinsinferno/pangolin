//! Canonical CBOR + AEAD seal/open layer for revision payloads.
//!
//! Every encrypted revision blob is the AEAD ciphertext of a
//! deterministic CBOR encoding of an [`crate::account::AccountSnapshot`]
//! (live entry) or the tombstone sentinel `{ "deleted": true }` (deleted
//! entry).
//!
//! ## CBOR canonicalization rules
//!
//! - The top-level value is always a CBOR Map.
//! - Live snapshots emit exactly six entries in this fixed key order:
//!   `display_name, username, password, url, notes, totp_secret`. Each
//!   value is a CBOR byte string (`Major::Bytes`) carrying the raw
//!   plaintext bytes of the secret field.
//! - Tombstones emit exactly one entry: text key `"deleted"` -> simple
//!   `true`. The shape `{ "deleted": true }` is what the plan §3.5
//!   tombstone discipline calls for.
//! - The map uses keys of type `Header::Text` (UTF-8) for stability when
//!   the format is read by future tooling — they're not strictly
//!   self-describing CBOR (numeric keys would be smaller) but the cost
//!   in bytes is negligible and the audit value of human-readable keys
//!   in the canonical encoding is high.
//!
//! ## AAD encoding (deterministic, fixed-width 105 bytes)
//!
//! ```text
//! WRAP_AAD_DOMAIN_REV (8 B) || vault_id (32 B) || account_id (32 B)
//!                            || parent_revision_id (32 B) || schema_version (1 B)
//! ```
//!
//! `WRAP_AAD_DOMAIN_REV = b"pgrev0\0\0"` — 8 bytes, version-locked. The
//! domain separator distinguishes revision-payload AAD from the
//! VDK-wrap AAD used by `pangolin_crypto::keys::WrapContext`.

use ciborium_io::{Read as _, Write as _};
use ciborium_ll::{Decoder, Encoder, Header};
use pangolin_crypto::aead::{AeadKey, Ciphertext, Nonce};
use pangolin_crypto::secret::SecretBytes;
use zeroize::Zeroizing;

use crate::account::{AccountId, AccountSnapshot, ACCOUNT_ID_LEN};
use crate::error::{Result, StoreError};
use crate::revision::{RevisionId, REVISION_ID_LEN};

/// 8-byte AAD domain separator. Distinct from `pangolin-crypto`'s
/// VDK-wrap domain separator so a wrap-AEAD blob cannot be replayed as
/// a revision blob. Versioned trailing-zero padding (`v0` + nuls) so a
/// future format bump moves to `b"pgrev1\0\0"` etc.
pub const WRAP_AAD_DOMAIN_REV: [u8; 8] = *b"pgrev0\0\0";

/// Length of the encoded revision AAD blob in bytes. Fixed-width by
/// construction.
pub const REV_AAD_LEN: usize =
    WRAP_AAD_DOMAIN_REV.len() + 32 + ACCOUNT_ID_LEN + REVISION_ID_LEN + 1;

/// Map keys (CBOR Text) for live snapshots. Order is load-bearing for
/// the canonical encoding — every encoder run emits keys in this order.
const FIELD_DISPLAY_NAME: &str = "display_name";
const FIELD_USERNAME: &str = "username";
const FIELD_PASSWORD: &str = "password";
const FIELD_URL: &str = "url";
const FIELD_NOTES: &str = "notes";
const FIELD_TOTP_SECRET: &str = "totp_secret";
/// Tombstone discriminator key.
const FIELD_DELETED: &str = "deleted";

/// Build the deterministic AAD blob for a revision encryption.
#[must_use]
pub fn build_aad(
    vault_id: &[u8; 32],
    account_id: &AccountId,
    parent_revision_id: &RevisionId,
    schema_version: u8,
) -> [u8; REV_AAD_LEN] {
    let mut out = [0u8; REV_AAD_LEN];
    let mut cursor = 0;
    out[cursor..cursor + WRAP_AAD_DOMAIN_REV.len()].copy_from_slice(&WRAP_AAD_DOMAIN_REV);
    cursor += WRAP_AAD_DOMAIN_REV.len();
    out[cursor..cursor + 32].copy_from_slice(vault_id);
    cursor += 32;
    out[cursor..cursor + ACCOUNT_ID_LEN].copy_from_slice(account_id.as_bytes());
    cursor += ACCOUNT_ID_LEN;
    out[cursor..cursor + REVISION_ID_LEN].copy_from_slice(parent_revision_id.as_bytes());
    cursor += REVISION_ID_LEN;
    out[cursor] = schema_version;
    out
}

/// Encode an `AccountSnapshot` as canonical CBOR.
///
/// The result is wrapped in [`Zeroizing`] because it carries every
/// secret-field plaintext and must be wiped as soon as the AEAD seal
/// path consumes it.
fn encode_snapshot_cbor(snapshot: &AccountSnapshot) -> Zeroizing<Vec<u8>> {
    let mut out: Vec<u8> = Vec::with_capacity(256);
    {
        let mut enc = Encoder::from(&mut out);
        // Map with 6 entries — fixed length so the wire form is stable.
        enc.push(Header::Map(Some(6)))
            .expect("Vec<u8> writer is infallible");
        write_text_kv(&mut enc, FIELD_DISPLAY_NAME, snapshot.display_name.expose());
        write_text_kv(&mut enc, FIELD_USERNAME, snapshot.username.expose());
        write_text_kv(&mut enc, FIELD_PASSWORD, snapshot.password.expose());
        write_text_kv(&mut enc, FIELD_URL, snapshot.url.expose());
        write_text_kv(&mut enc, FIELD_NOTES, snapshot.notes.expose());
        write_text_kv(&mut enc, FIELD_TOTP_SECRET, snapshot.totp_secret.expose());
    }
    Zeroizing::new(out)
}

/// Encode the tombstone sentinel `{ "deleted": true }`.
fn encode_tombstone_cbor() -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(16);
    {
        let mut enc = Encoder::from(&mut out);
        enc.push(Header::Map(Some(1))).expect("infallible");
        enc.text(FIELD_DELETED, None).expect("infallible");
        enc.push(Header::Simple(ciborium_ll::simple::TRUE))
            .expect("infallible");
    }
    out
}

/// Helper: write a (text-key, bytes-value) pair to the encoder.
fn write_text_kv<W>(enc: &mut Encoder<W>, key: &str, value: &[u8])
where
    W: ciborium_io::Write,
    W::Error: core::fmt::Debug,
{
    // The writer here is `&mut Vec<u8>`, whose error type is
    // `core::convert::Infallible`. We unwrap because the only failure
    // mode would be allocator OOM, which would already have aborted.
    enc.text(key, None).expect("infallible vec writer");
    enc.push(Header::Bytes(Some(value.len())))
        .expect("infallible vec writer");
    enc.write_all(value).expect("infallible vec writer");
}

/// Decoded payload variants. Live snapshots return [`Self::Live`];
/// tombstones return [`Self::Tombstone`].
#[derive(Debug)]
pub enum DecodedPayload {
    Live(AccountSnapshot),
    Tombstone,
}

/// Seal a live `AccountSnapshot` into an AEAD ciphertext + nonce pair.
///
/// The plaintext CBOR encoding is held in a [`Zeroizing`] buffer for
/// the duration of the seal call and dropped (wiped) on the way out.
///
/// # Errors
///
/// Surfaces [`StoreError::AuthenticationFailed`] if the underlying AEAD
/// rejects the seal (only theoretically possible on a payload exceeding
/// the AEAD's block limit, which is unreachable in practice).
pub fn seal_snapshot(
    vdk_aead: &AeadKey,
    snapshot: &AccountSnapshot,
    aad: &[u8; REV_AAD_LEN],
) -> Result<(Ciphertext, Nonce)> {
    let plaintext = encode_snapshot_cbor(snapshot);
    let nonce = Nonce::random();
    let ct = vdk_aead.seal(&nonce, &plaintext, aad)?;
    Ok((ct, nonce))
}

/// Seal a tombstone sentinel.
///
/// Same AEAD path as [`seal_snapshot`] but with the fixed
/// `{ "deleted": true }` plaintext. Marker payloads aren't secret per
/// se (an attacker observing the row would already know the account
/// has been tombstoned from the row's `is_tombstone` flag) but they
/// MUST still authenticate so a tampered row that swaps a live payload
/// for a tombstone is detected.
pub fn seal_tombstone(vdk_aead: &AeadKey, aad: &[u8; REV_AAD_LEN]) -> Result<(Ciphertext, Nonce)> {
    let plaintext = encode_tombstone_cbor();
    let nonce = Nonce::random();
    let ct = vdk_aead.seal(&nonce, &plaintext, aad)?;
    Ok((ct, nonce))
}

/// Authenticate-and-decode a sealed payload.
///
/// On success the returned [`DecodedPayload`] is either a live
/// snapshot or a tombstone marker. The caller retains the secret
/// plaintext only inside the returned `AccountSnapshot` (which zeros on
/// drop). The intermediate decrypted CBOR buffer is wiped before this
/// function returns.
pub fn open_payload(
    vdk_aead: &AeadKey,
    nonce: &Nonce,
    ciphertext: &Ciphertext,
    aad: &[u8; REV_AAD_LEN],
) -> Result<DecodedPayload> {
    let plaintext_vec = vdk_aead.open(nonce, ciphertext, aad)?;
    let plaintext = Zeroizing::new(plaintext_vec);
    decode_payload(&plaintext)
}

/// Parse a CBOR-encoded payload buffer into [`DecodedPayload`].
///
/// Errors map to [`StoreError::Cbor`] with a non-secret cause string.
fn decode_payload(buf: &[u8]) -> Result<DecodedPayload> {
    let mut dec = Decoder::from(buf);
    let map_header = pull_header(&mut dec)?;
    let entries = match map_header {
        Header::Map(Some(n)) => n,
        Header::Map(None) => {
            return Err(StoreError::Cbor("indefinite-length maps rejected".into()))
        }
        other => {
            return Err(StoreError::Cbor(format!(
                "expected top-level map, got {other:?}"
            )))
        }
    };

    if entries == 1 {
        // Tombstone candidate.
        let key = pull_text(&mut dec)?;
        if key != FIELD_DELETED {
            return Err(StoreError::Cbor(format!(
                "single-entry map with key {key:?}, expected {FIELD_DELETED:?}"
            )));
        }
        match pull_header(&mut dec)? {
            Header::Simple(s) if s == ciborium_ll::simple::TRUE => Ok(DecodedPayload::Tombstone),
            other => Err(StoreError::Cbor(format!(
                "tombstone value not boolean true: {other:?}"
            ))),
        }
    } else if entries == 6 {
        let mut display_name: Option<SecretBytes> = None;
        let mut username: Option<SecretBytes> = None;
        let mut password: Option<SecretBytes> = None;
        let mut url: Option<SecretBytes> = None;
        let mut notes: Option<SecretBytes> = None;
        let mut totp_secret: Option<SecretBytes> = None;
        let mut last_key: Option<String> = None;

        for _ in 0..entries {
            let key = pull_text(&mut dec)?;
            // Enforce fixed key order — drift = corruption.
            if let Some(prev) = &last_key {
                if !is_after_in_canonical_order(prev, &key) {
                    return Err(StoreError::Cbor(format!(
                        "non-canonical key order: {prev:?} then {key:?}"
                    )));
                }
            }
            let value = pull_bytes(&mut dec)?;
            let secret = SecretBytes::new(value);
            match key.as_str() {
                FIELD_DISPLAY_NAME => display_name = Some(secret),
                FIELD_USERNAME => username = Some(secret),
                FIELD_PASSWORD => password = Some(secret),
                FIELD_URL => url = Some(secret),
                FIELD_NOTES => notes = Some(secret),
                FIELD_TOTP_SECRET => totp_secret = Some(secret),
                other => {
                    return Err(StoreError::Cbor(format!(
                        "unknown snapshot field {other:?}"
                    )))
                }
            }
            last_key = Some(key);
        }

        Ok(DecodedPayload::Live(AccountSnapshot::new(
            display_name.ok_or_else(|| StoreError::Cbor("missing display_name".into()))?,
            username.ok_or_else(|| StoreError::Cbor("missing username".into()))?,
            password.ok_or_else(|| StoreError::Cbor("missing password".into()))?,
            url.ok_or_else(|| StoreError::Cbor("missing url".into()))?,
            notes.ok_or_else(|| StoreError::Cbor("missing notes".into()))?,
            totp_secret.ok_or_else(|| StoreError::Cbor("missing totp_secret".into()))?,
        )))
    } else {
        Err(StoreError::Cbor(format!("unexpected map arity: {entries}")))
    }
}

/// Canonical key order for live-snapshot fields. `prev` came earlier in
/// the wire than `curr`; this returns true if `curr`'s declared
/// canonical position is after `prev`'s.
fn is_after_in_canonical_order(prev: &str, curr: &str) -> bool {
    fn pos(s: &str) -> Option<u8> {
        match s {
            FIELD_DISPLAY_NAME => Some(0),
            FIELD_USERNAME => Some(1),
            FIELD_PASSWORD => Some(2),
            FIELD_URL => Some(3),
            FIELD_NOTES => Some(4),
            FIELD_TOTP_SECRET => Some(5),
            _ => None,
        }
    }
    match (pos(prev), pos(curr)) {
        (Some(a), Some(b)) => b > a,
        _ => false,
    }
}

/// Pull a single CBOR header from the decoder, mapping the underlying
/// error type into [`StoreError::Cbor`]. Borrowing `&mut Decoder<&[u8]>`
/// keeps the slice-reader's `Error = core::convert::Infallible` so the
/// `Io` arm of `ciborium_ll::Error` is unreachable; we handle it
/// defensively anyway.
fn pull_header(dec: &mut Decoder<&[u8]>) -> Result<Header> {
    dec.pull().map_err(|e| match e {
        ciborium_ll::Error::Io(_) => StoreError::Cbor("input ended prematurely".into()),
        ciborium_ll::Error::Syntax(off) => {
            StoreError::Cbor(format!("syntax error at offset {off}"))
        }
    })
}

fn pull_text(dec: &mut Decoder<&[u8]>) -> Result<String> {
    let header = pull_header(dec)?;
    match header {
        Header::Text(Some(len)) => {
            let mut buf = vec![0u8; len];
            dec.read_exact(&mut buf)
                .map_err(|_| StoreError::Cbor("text read truncated".into()))?;
            String::from_utf8(buf).map_err(|_| StoreError::Cbor("text not valid UTF-8".into()))
        }
        Header::Text(None) => Err(StoreError::Cbor(
            "indefinite-length text strings rejected".into(),
        )),
        other => Err(StoreError::Cbor(format!(
            "expected text key, got {other:?}"
        ))),
    }
}

fn pull_bytes(dec: &mut Decoder<&[u8]>) -> Result<Vec<u8>> {
    let header = pull_header(dec)?;
    match header {
        Header::Bytes(Some(len)) => {
            let mut buf = vec![0u8; len];
            dec.read_exact(&mut buf)
                .map_err(|_| StoreError::Cbor("bytes read truncated".into()))?;
            Ok(buf)
        }
        Header::Bytes(None) => Err(StoreError::Cbor(
            "indefinite-length byte strings rejected".into(),
        )),
        other => Err(StoreError::Cbor(format!(
            "expected bytes value, got {other:?}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_aad, decode_payload, encode_snapshot_cbor, encode_tombstone_cbor, open_payload,
        seal_snapshot, seal_tombstone, DecodedPayload, REV_AAD_LEN, WRAP_AAD_DOMAIN_REV,
    };
    use crate::account::{AccountId, AccountSnapshot};
    use crate::revision::RevisionId;
    use pangolin_crypto::aead::AeadKey;
    use pangolin_crypto::secret::SecretBytes;

    fn fixture_snapshot() -> AccountSnapshot {
        AccountSnapshot::new(
            SecretBytes::new(b"github".to_vec()),
            SecretBytes::new(b"alice".to_vec()),
            SecretBytes::new(b"hunter2".to_vec()),
            SecretBytes::new(b"https://github.com".to_vec()),
            SecretBytes::new(b"some notes".to_vec()),
            SecretBytes::new(b"".to_vec()),
        )
    }

    #[test]
    fn aad_is_fixed_width_105_bytes() {
        assert_eq!(REV_AAD_LEN, 105);
    }

    #[test]
    fn aad_domain_is_versioned_8_bytes() {
        assert_eq!(WRAP_AAD_DOMAIN_REV.len(), 8);
        assert_eq!(&WRAP_AAD_DOMAIN_REV, b"pgrev0\0\0");
    }

    #[test]
    fn aad_round_trip_layout() {
        let vault = [0xAAu8; 32];
        let acct = AccountId::from_bytes([0xBBu8; 32]);
        let parent = RevisionId::from_bytes([0xCCu8; 32]);
        let aad = build_aad(&vault, &acct, &parent, 7);
        // First 8 bytes = domain.
        assert_eq!(&aad[..8], &WRAP_AAD_DOMAIN_REV);
        // Next 32 = vault id.
        assert_eq!(&aad[8..40], &vault);
        // Next 32 = account id.
        assert_eq!(&aad[40..72], acct.as_bytes());
        // Next 32 = parent revision id.
        assert_eq!(&aad[72..104], parent.as_bytes());
        // Last byte = schema version.
        assert_eq!(aad[104], 7);
    }

    /// Determinism: encoding the same snapshot twice yields byte-equal
    /// CBOR. Required so that two devices can produce identical
    /// `RevisionPublished` payloads when racing.
    #[test]
    fn cbor_encoding_is_deterministic() {
        let s1 = fixture_snapshot();
        let s2 = fixture_snapshot();
        let a = encode_snapshot_cbor(&s1);
        let b = encode_snapshot_cbor(&s2);
        assert_eq!(*a, *b);
    }

    #[test]
    fn snapshot_round_trips_through_seal_open() {
        let key = AeadKey::generate();
        let vault = [0x11u8; 32];
        let acct = AccountId::from_bytes([0x22u8; 32]);
        let parent = RevisionId::GENESIS_PARENT;
        let aad = build_aad(&vault, &acct, &parent, 0);
        let snap = fixture_snapshot();
        let (ct, nonce) = seal_snapshot(&key, &snap, &aad).unwrap();
        match open_payload(&key, &nonce, &ct, &aad).unwrap() {
            DecodedPayload::Live(recovered) => {
                assert!(bool::from(snap.ct_eq(&recovered)));
            }
            DecodedPayload::Tombstone => panic!("expected Live"),
        }
    }

    #[test]
    fn tombstone_round_trips() {
        let key = AeadKey::generate();
        let vault = [0x11u8; 32];
        let acct = AccountId::from_bytes([0x22u8; 32]);
        let aad = build_aad(&vault, &acct, &RevisionId::GENESIS_PARENT, 0);
        let (ct, nonce) = seal_tombstone(&key, &aad).unwrap();
        match open_payload(&key, &nonce, &ct, &aad).unwrap() {
            DecodedPayload::Tombstone => {}
            DecodedPayload::Live(_) => panic!("expected Tombstone"),
        }
    }

    #[test]
    fn cross_account_aad_substitution_fails() {
        // Take a sealed payload bound to acct_a and try to open it
        // under acct_b's AAD: must fail with AuthenticationFailed.
        let key = AeadKey::generate();
        let vault = [0xAAu8; 32];
        let acct_a = AccountId::from_bytes([0xA1u8; 32]);
        let acct_b = AccountId::from_bytes([0xB1u8; 32]);
        let parent = RevisionId::GENESIS_PARENT;
        let aad_a = build_aad(&vault, &acct_a, &parent, 0);
        let aad_b = build_aad(&vault, &acct_b, &parent, 0);

        let (ct, nonce) = seal_snapshot(&key, &fixture_snapshot(), &aad_a).unwrap();
        assert!(open_payload(&key, &nonce, &ct, &aad_b).is_err());
    }

    #[test]
    fn tombstone_decoder_recognizes_marker() {
        let bytes = encode_tombstone_cbor();
        match decode_payload(&bytes).unwrap() {
            DecodedPayload::Tombstone => {}
            DecodedPayload::Live(_) => panic!("decoded tombstone as Live"),
        }
    }

    #[test]
    fn malformed_cbor_rejected() {
        let bytes = vec![0xFFu8; 4]; // not a valid CBOR map header
        assert!(decode_payload(&bytes).is_err());
    }
}
