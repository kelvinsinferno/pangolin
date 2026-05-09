//! Canonical CBOR + AEAD seal/open layer for revision payloads.
//!
//! Every encrypted revision blob is the AEAD ciphertext of a
//! deterministic CBOR encoding of an [`crate::account::AccountSnapshot`]
//! (live entry) or a [`TombstonePayload`] (deleted entry).
//!
//! ## CBOR canonicalization rules
//!
//! - The top-level value is always a CBOR Map.
//! - Live snapshots emit exactly six entries in this fixed key order:
//!   `display_name, username, password, url, notes, totp_secret`. Each
//!   value is a CBOR byte string (`Major::Bytes`) carrying the raw
//!   plaintext bytes of the secret field.
//! - Tombstones emit exactly three entries (P10-1 widened shape) in
//!   alphabetical key order: `account_id`, `deleted`, `tombstoned_at_ms`.
//!   `account_id` is a CBOR Bytes value of length
//!   [`crate::account::ACCOUNT_ID_LEN`] (32). `deleted` is the CBOR
//!   `true` simple value. `tombstoned_at_ms` is a CBOR positive integer.
//!   Legacy P3-era single-entry payloads `{ "deleted": true }` continue
//!   to decode for forward-compat with vault files written before P10
//!   (the legacy shape produces a [`TombstonePayload`] with all-zeros
//!   `account_id` and `tombstoned_at_ms = 0`).
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

use crate::account::{
    AccountId, AccountIdentity, AccountSnapshot, PasswordEntry, ACCOUNT_ID_LEN, PAYLOAD_VERSION_V1,
};
use crate::error::{Result, StoreError};
use crate::revision::{DeviceId, RevisionId, DEVICE_ID_LEN, REVISION_ID_LEN};

/// 8-byte AAD domain separator. Distinct from `pangolin-crypto`'s
/// VDK-wrap domain separator so a wrap-AEAD blob cannot be replayed as
/// a revision blob. Versioned trailing-zero padding (`v0` + nuls) so a
/// future format bump moves to `b"pgrev1\0\0"` etc.
pub const WRAP_AAD_DOMAIN_REV: [u8; 8] = *b"pgrev0\0\0";

/// Length of the encoded revision AAD blob in bytes. Fixed-width by
/// construction.
pub const REV_AAD_LEN: usize =
    WRAP_AAD_DOMAIN_REV.len() + 32 + ACCOUNT_ID_LEN + REVISION_ID_LEN + 1;

/// Map keys (CBOR Text) for live V0 snapshots. Order is load-bearing
/// for the canonical encoding — every encoder run emits keys in this
/// order.
const FIELD_DISPLAY_NAME: &str = "display_name";
const FIELD_USERNAME: &str = "username";
const FIELD_PASSWORD: &str = "password";
const FIELD_URL: &str = "url";
const FIELD_NOTES: &str = "notes";
const FIELD_TOTP_SECRET: &str = "totp_secret";

/// MVP-1 issue 1.2: V1 payload field keys. Keys appear in canonical
/// alphabetical order in the encoded map, fixed arity 8.
///
/// Order: `display_name`, `notes`, `password_history`, `payload_version`,
/// `tags`, `totp_secret`, `urls`, `usernames`.
const FIELD_TAGS: &str = "tags";
const FIELD_USERNAMES: &str = "usernames";
const FIELD_URLS: &str = "urls";
const FIELD_PASSWORD_HISTORY: &str = "password_history";
const FIELD_PAYLOAD_VERSION: &str = "payload_version";
/// Tombstone discriminator key. Also second alphabetically in the
/// widened three-entry tombstone payload (after `account_id`, before
/// `tombstoned_at_ms`).
const FIELD_DELETED: &str = "deleted";
/// Tombstone payload first alphabetical key — the 32-byte account id
/// the tombstone applies to. Carried as a defense-in-depth cross-check
/// against the AEAD AAD's `account_id` (mismatch → decode error).
const FIELD_ACCOUNT_ID: &str = "account_id";
/// Tombstone payload third alphabetical key — the unix-ms timestamp at
/// which the tombstone was sealed. Forensic-only field (the local row's
/// `last_modified_at` is a redundant source); load-bearing only for
/// MVP-1 cross-device sync where the seal time on device A may differ
/// from the ingest time on device B.
const FIELD_TOMBSTONED_AT_MS: &str = "tombstoned_at_ms";

/// Decoded tombstone payload. Master plan §3.7 P10-1 specifies
/// `{ "deleted": true, "account_id": <id>, "tombstoned_at": <ts> }`;
/// this struct is the in-memory form.
///
/// Legacy P3-era single-entry `{ "deleted": true }` payloads decode to
/// [`Self::legacy`]: `deleted: true`, `account_id: [0; 32]`,
/// `tombstoned_at_ms: 0`. The all-zeros `account_id` documents the
/// legacy origin (a real `account_id` is cryptographically negligible
/// to match the all-zeros sentinel).
///
/// Fields are private; accessors are provided so the struct can grow
/// (e.g., MVP-1's potential `device_id` forensic-attribution field)
/// without breaking the API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TombstonePayload {
    deleted: bool,
    account_id: [u8; ACCOUNT_ID_LEN],
    tombstoned_at_ms: u64,
}

impl TombstonePayload {
    /// Construct a fresh tombstone payload for a delete operation.
    /// `tombstoned_at_ms` is the unix-ms timestamp of the seal.
    #[must_use]
    pub fn new(account_id: AccountId, tombstoned_at_ms: u64) -> Self {
        Self {
            deleted: true,
            account_id: *account_id.as_bytes(),
            tombstoned_at_ms,
        }
    }

    /// Construct a legacy-shape payload (single `{ "deleted": true }`).
    /// Used only by the decode path for forward-compat; new tombstones
    /// MUST go through [`Self::new`].
    #[must_use]
    pub(crate) fn legacy() -> Self {
        Self {
            deleted: true,
            account_id: [0; ACCOUNT_ID_LEN],
            tombstoned_at_ms: 0,
        }
    }

    /// True iff this payload represents a tombstone (always `true` for
    /// values produced by [`Self::new`] or [`Self::legacy`]; the field
    /// is read back from the wire to authenticate the discriminator).
    #[must_use]
    pub fn is_deleted(&self) -> bool {
        self.deleted
    }

    /// The 32-byte `account_id` carried in the payload. Zero for
    /// legacy-shape payloads.
    #[must_use]
    pub fn account_id(&self) -> &[u8; ACCOUNT_ID_LEN] {
        &self.account_id
    }

    /// Unix-ms timestamp at which the tombstone was sealed. Zero for
    /// legacy-shape payloads.
    #[must_use]
    pub fn tombstoned_at_ms(&self) -> u64 {
        self.tombstoned_at_ms
    }
}

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

/// Encode the widened (P10-1) tombstone payload as deterministic CBOR.
///
/// The wire shape is a fixed three-entry map with text keys in
/// alphabetical order: `account_id` (CBOR Bytes, length 32), `deleted`
/// (CBOR `true` simple value), `tombstoned_at_ms` (CBOR positive
/// integer). Determinism: the same payload through this encoder twice
/// is byte-equal.
fn encode_tombstone_cbor(payload: &TombstonePayload) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(64);
    {
        let mut enc = Encoder::from(&mut out);
        enc.push(Header::Map(Some(3))).expect("infallible");
        // 1. account_id (alphabetical position 1).
        enc.text(FIELD_ACCOUNT_ID, None).expect("infallible");
        enc.push(Header::Bytes(Some(ACCOUNT_ID_LEN)))
            .expect("infallible");
        enc.write_all(&payload.account_id).expect("infallible");
        // 2. deleted (alphabetical position 2).
        enc.text(FIELD_DELETED, None).expect("infallible");
        enc.push(Header::Simple(if payload.deleted {
            ciborium_ll::simple::TRUE
        } else {
            ciborium_ll::simple::FALSE
        }))
        .expect("infallible");
        // 3. tombstoned_at_ms (alphabetical position 3).
        enc.text(FIELD_TOMBSTONED_AT_MS, None).expect("infallible");
        enc.push(Header::Positive(payload.tombstoned_at_ms))
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
/// tombstones return [`Self::Tombstone`] carrying the parsed
/// [`TombstonePayload`] (P10-1 widening — was `Tombstone` with no
/// data; the variant now carries the payload so callers, in particular
/// [`crate::vault::Vault::ingest_chain_revision`]'s tombstone-bit
/// detection branch (P10-2), can introspect).
#[derive(Debug)]
pub enum DecodedPayload {
    Live(AccountSnapshot),
    Tombstone(TombstonePayload),
}

/// MVP-1 issue 1.2 decoded V1 payload — the production
/// [`AccountIdentity`] (V1) shape. Returned by
/// [`open_identity_payload`] which is the V1-aware open path used by
/// [`crate::vault::Vault::account_*`]. Tombstones decode through
/// [`open_payload`] as before.
#[derive(Debug)]
pub enum DecodedIdentityPayload {
    /// Live V1 (or hydrated-from-V0) account identity.
    Live(AccountIdentity),
    /// Tombstone marker. Carries the parsed payload so callers can
    /// inspect the `account_id` / `tombstoned_at_ms` bytes if needed.
    #[allow(dead_code)]
    Tombstone(TombstonePayload),
}

impl DecodedIdentityPayload {
    /// True for live (non-tombstone) variants.
    #[allow(dead_code)]
    #[must_use]
    pub fn is_live(&self) -> bool {
        matches!(self, Self::Live(_))
    }
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

/// Seal a tombstone payload.
///
/// Same AEAD path as [`seal_snapshot`] but with a deterministic-CBOR
/// encoding of [`TombstonePayload`] as the plaintext. P10-1 widened
/// the signature from no-payload to `&TombstonePayload`; the caller
/// supplies the `account_id` and `tombstoned_at_ms` that get baked
/// into the sealed plaintext.
///
/// Marker payloads aren't secret per se (an attacker observing the row
/// would already know the account has been tombstoned from the row's
/// `is_tombstone` flag) but they MUST still authenticate so a tampered
/// row that swaps a live payload for a tombstone is detected. The
/// in-payload `account_id` cross-checks against the AAD's `account_id`
/// at decode time as a defense-in-depth layer (see `decode_payload`).
pub fn seal_tombstone(
    vdk_aead: &AeadKey,
    aad: &[u8; REV_AAD_LEN],
    payload: &TombstonePayload,
) -> Result<(Ciphertext, Nonce)> {
    let plaintext = encode_tombstone_cbor(payload);
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

/// Decode the legacy P3-era tombstone shape `{ "deleted": true }`.
/// Forward-compat: existing vault files written before P10 continue
/// to open cleanly. The decoded payload has the legacy origin
/// documented via `account_id = [0; 32]` and `tombstoned_at_ms = 0`.
fn decode_tombstone_legacy(dec: &mut Decoder<&[u8]>) -> Result<DecodedPayload> {
    let key = pull_text(dec)?;
    if key != FIELD_DELETED {
        return Err(StoreError::Cbor(format!(
            "single-entry map with key {key:?}, expected {FIELD_DELETED:?}"
        )));
    }
    match pull_header(dec)? {
        Header::Simple(s) if s == ciborium_ll::simple::TRUE => {
            Ok(DecodedPayload::Tombstone(TombstonePayload::legacy()))
        }
        other => Err(StoreError::Cbor(format!(
            "tombstone value not boolean true: {other:?}"
        ))),
    }
}

/// Decode the P10-1 widened three-entry tombstone shape: alphabetical
/// keys `account_id` (CBOR Bytes, 32), `deleted` (true),
/// `tombstoned_at_ms` (u64). Drift in key order = corruption.
fn decode_tombstone_widened(dec: &mut Decoder<&[u8]>) -> Result<DecodedPayload> {
    let key1 = pull_text(dec)?;
    if key1 != FIELD_ACCOUNT_ID {
        return Err(StoreError::Cbor(format!(
            "tombstone first key {key1:?}, expected {FIELD_ACCOUNT_ID:?}"
        )));
    }
    let acct_bytes = pull_bytes(dec)?;
    let account_id: [u8; ACCOUNT_ID_LEN] = acct_bytes.as_slice().try_into().map_err(|_| {
        StoreError::Cbor(format!(
            "tombstone account_id wrong length: {} bytes, expected {ACCOUNT_ID_LEN}",
            acct_bytes.len()
        ))
    })?;

    let key2 = pull_text(dec)?;
    if key2 != FIELD_DELETED {
        return Err(StoreError::Cbor(format!(
            "tombstone second key {key2:?}, expected {FIELD_DELETED:?}"
        )));
    }
    let deleted = match pull_header(dec)? {
        Header::Simple(s) if s == ciborium_ll::simple::TRUE => true,
        other => {
            return Err(StoreError::Cbor(format!(
                "tombstone deleted value not boolean true: {other:?}"
            )))
        }
    };

    let key3 = pull_text(dec)?;
    if key3 != FIELD_TOMBSTONED_AT_MS {
        return Err(StoreError::Cbor(format!(
            "tombstone third key {key3:?}, expected {FIELD_TOMBSTONED_AT_MS:?}"
        )));
    }
    let tombstoned_at_ms = match pull_header(dec)? {
        Header::Positive(v) => v,
        other => {
            return Err(StoreError::Cbor(format!(
                "tombstone tombstoned_at_ms not positive integer: {other:?}"
            )))
        }
    };

    Ok(DecodedPayload::Tombstone(TombstonePayload {
        deleted,
        account_id,
        tombstoned_at_ms,
    }))
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
        decode_tombstone_legacy(&mut dec)
    } else if entries == 3 {
        decode_tombstone_widened(&mut dec)
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

// =============================================================================
// MVP-1 issue 1.2: V1 payload codec
// =============================================================================

/// Encode an [`AccountIdentity`] as canonical V1 CBOR.
///
/// Wire shape (per `docs/issue-plans/1.2.md` §B): a fixed-arity 8 map
/// with text keys in alphabetical order:
/// ```text
/// display_name      => text
/// notes             => text
/// password_history  => array of [bytes (password), i64 (set_at_ms),
///                                bytes32 (originating_device)]
/// payload_version   => positive integer (always 1 for this encoder)
/// tags              => array of text
/// totp_secret       => bytes
/// urls              => array of text
/// usernames         => array of text
/// ```
///
/// The result is wrapped in [`Zeroizing`] because every secret-bearing
/// byte (`passwords`, `totp_secret`, `notes`, `display_name`) is in
/// the buffer.
fn encode_identity_cbor(identity: &AccountIdentity) -> Zeroizing<Vec<u8>> {
    let mut out: Vec<u8> = Vec::with_capacity(512);
    {
        let mut enc = Encoder::from(&mut out);
        // Map of 8 entries.
        enc.push(Header::Map(Some(8)))
            .expect("infallible vec writer");

        // 1. display_name (text)
        enc.text(FIELD_DISPLAY_NAME, None).expect("infallible");
        write_text_value(&mut enc, identity.display_name.expose());

        // 2. notes (text)
        enc.text(FIELD_NOTES, None).expect("infallible");
        write_text_value(&mut enc, identity.notes.expose());

        // 3. password_history (array)
        enc.text(FIELD_PASSWORD_HISTORY, None).expect("infallible");
        enc.push(Header::Array(Some(identity.password_history.len())))
            .expect("infallible");
        for entry in &identity.password_history {
            // Each entry: array of 3 elements [password (bytes),
            // set_at_ms (positive integer), originating_device (bytes32)].
            enc.push(Header::Array(Some(3))).expect("infallible");
            // password
            enc.push(Header::Bytes(Some(entry.password.expose().len())))
                .expect("infallible");
            enc.write_all(entry.password.expose()).expect("infallible");
            // set_at_ms — encode as Positive for >= 0; Negative for negatives.
            if entry.set_at_ms >= 0 {
                enc.push(Header::Positive(
                    u64::try_from(entry.set_at_ms).unwrap_or(u64::MAX),
                ))
                .expect("infallible");
            } else {
                // CBOR negative integers are encoded as -1 - x.
                let n = u64::try_from(-(entry.set_at_ms + 1)).unwrap_or(u64::MAX);
                enc.push(Header::Negative(n)).expect("infallible");
            }
            // originating_device (bytes32)
            enc.push(Header::Bytes(Some(DEVICE_ID_LEN)))
                .expect("infallible");
            enc.write_all(&entry.originating_device.0)
                .expect("infallible");
        }

        // 4. payload_version (positive integer)
        enc.text(FIELD_PAYLOAD_VERSION, None).expect("infallible");
        enc.push(Header::Positive(u64::from(PAYLOAD_VERSION_V1)))
            .expect("infallible");

        // 5. tags (array of text)
        enc.text(FIELD_TAGS, None).expect("infallible");
        enc.push(Header::Array(Some(identity.tags.len())))
            .expect("infallible");
        for t in &identity.tags {
            write_text_value(&mut enc, t.expose());
        }

        // 6. totp_secret (bytes)
        enc.text(FIELD_TOTP_SECRET, None).expect("infallible");
        enc.push(Header::Bytes(Some(identity.totp_secret.expose().len())))
            .expect("infallible");
        enc.write_all(identity.totp_secret.expose())
            .expect("infallible");

        // 7. urls (array of text)
        enc.text(FIELD_URLS, None).expect("infallible");
        enc.push(Header::Array(Some(identity.urls.len())))
            .expect("infallible");
        for u in &identity.urls {
            write_text_value(&mut enc, u.expose());
        }

        // 8. usernames (array of text)
        enc.text(FIELD_USERNAMES, None).expect("infallible");
        enc.push(Header::Array(Some(identity.usernames.len())))
            .expect("infallible");
        for u in &identity.usernames {
            write_text_value(&mut enc, u.expose());
        }
    }
    Zeroizing::new(out)
}

/// Helper: write a text-string value (header + bytes). Caller already
/// emitted the corresponding key.
fn write_text_value<W>(enc: &mut Encoder<W>, value: &[u8])
where
    W: ciborium_io::Write,
    W::Error: core::fmt::Debug,
{
    enc.push(Header::Text(Some(value.len())))
        .expect("infallible vec writer");
    enc.write_all(value).expect("infallible vec writer");
}

/// Seal an [`AccountIdentity`] V1 payload into AEAD ciphertext.
///
/// Mirrors [`seal_snapshot`] for the V0 path; same AAD shape, different
/// plaintext encoding. Per-blob nonce; the plaintext CBOR is held in a
/// [`Zeroizing`] buffer.
pub fn seal_identity(
    vdk_aead: &AeadKey,
    identity: &AccountIdentity,
    aad: &[u8; REV_AAD_LEN],
) -> Result<(Ciphertext, Nonce)> {
    let plaintext = encode_identity_cbor(identity);
    let nonce = Nonce::random();
    let ct = vdk_aead.seal(&nonce, &plaintext, aad)?;
    Ok((ct, nonce))
}

/// V1-aware authenticate-and-decode. Returns [`DecodedIdentityPayload`]:
/// either a live [`AccountIdentity`] (hydrated from V0 if the on-disk
/// payload is V0 arity-6, or decoded from V1 arity-8) or a tombstone.
///
/// The intermediate decrypted CBOR buffer is wiped before returning.
pub fn open_identity_payload(
    vdk_aead: &AeadKey,
    nonce: &Nonce,
    ciphertext: &Ciphertext,
    aad: &[u8; REV_AAD_LEN],
) -> Result<DecodedIdentityPayload> {
    let plaintext_vec = vdk_aead.open(nonce, ciphertext, aad)?;
    let plaintext = Zeroizing::new(plaintext_vec);
    decode_identity_payload(&plaintext)
}

/// Parse a CBOR-encoded plaintext into [`DecodedIdentityPayload`].
///
/// Routes by map arity:
/// - 1 entry → legacy V0 tombstone.
/// - 3 entries → P10-1 widened tombstone.
/// - 6 entries → V0 live snapshot — hydrated to V1 [`AccountIdentity`]
///   per the [`crate::account::schemata`] mapping rules.
/// - 8 entries → V1 live identity payload — decoded directly.
fn decode_identity_payload(buf: &[u8]) -> Result<DecodedIdentityPayload> {
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
        match decode_tombstone_legacy(&mut dec)? {
            DecodedPayload::Tombstone(t) => Ok(DecodedIdentityPayload::Tombstone(t)),
            DecodedPayload::Live(_) => Err(StoreError::Cbor(
                "single-entry map decoded as Live; expected Tombstone".into(),
            )),
        }
    } else if entries == 3 {
        match decode_tombstone_widened(&mut dec)? {
            DecodedPayload::Tombstone(t) => Ok(DecodedIdentityPayload::Tombstone(t)),
            DecodedPayload::Live(_) => Err(StoreError::Cbor(
                "three-entry map decoded as Live; expected Tombstone".into(),
            )),
        }
    } else if entries == 6 {
        // V0 live snapshot — decode the legacy 6-field shape and
        // hydrate to V1.
        let snapshot = decode_v0_live_inline(&mut dec, entries)?;
        Ok(DecodedIdentityPayload::Live(hydrate_v0_to_v1(&snapshot)))
    } else if entries == 8 {
        decode_v1_live_inline(&mut dec)
    } else {
        Err(StoreError::Cbor(format!(
            "unexpected map arity for identity payload: {entries}"
        )))
    }
}

/// Decode the V0 6-entry map (after the map header has been consumed).
fn decode_v0_live_inline(dec: &mut Decoder<&[u8]>, entries: usize) -> Result<AccountSnapshot> {
    let mut display_name: Option<SecretBytes> = None;
    let mut username: Option<SecretBytes> = None;
    let mut password: Option<SecretBytes> = None;
    let mut url: Option<SecretBytes> = None;
    let mut notes: Option<SecretBytes> = None;
    let mut totp_secret: Option<SecretBytes> = None;
    let mut last_key: Option<String> = None;

    for _ in 0..entries {
        let key = pull_text(dec)?;
        if let Some(prev) = &last_key {
            if !is_after_in_canonical_order(prev, &key) {
                return Err(StoreError::Cbor(format!(
                    "non-canonical key order: {prev:?} then {key:?}"
                )));
            }
        }
        let value = pull_bytes(dec)?;
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
                    "unknown V0 snapshot field {other:?}"
                )))
            }
        }
        last_key = Some(key);
    }

    Ok(AccountSnapshot::new(
        display_name.ok_or_else(|| StoreError::Cbor("missing display_name".into()))?,
        username.ok_or_else(|| StoreError::Cbor("missing username".into()))?,
        password.ok_or_else(|| StoreError::Cbor("missing password".into()))?,
        url.ok_or_else(|| StoreError::Cbor("missing url".into()))?,
        notes.ok_or_else(|| StoreError::Cbor("missing notes".into()))?,
        totp_secret.ok_or_else(|| StoreError::Cbor("missing totp_secret".into()))?,
    ))
}

/// Hydrate a V0 [`AccountSnapshot`] into a V1 [`AccountIdentity`] per
/// the §B mapping in `docs/issue-plans/1.2.md`.
fn hydrate_v0_to_v1(snapshot: &AccountSnapshot) -> AccountIdentity {
    let usernames = if snapshot.username.expose().is_empty() {
        Vec::new()
    } else {
        vec![SecretBytes::new(snapshot.username.expose().to_vec())]
    };
    let urls = if snapshot.url.expose().is_empty() {
        Vec::new()
    } else {
        vec![SecretBytes::new(snapshot.url.expose().to_vec())]
    };
    let password_history = if snapshot.password.expose().is_empty() {
        Vec::new()
    } else {
        vec![PasswordEntry::new(
            SecretBytes::new(snapshot.password.expose().to_vec()),
            0,
            DeviceId([0u8; DEVICE_ID_LEN]),
        )]
    };

    AccountIdentity::new_unchecked(
        SecretBytes::new(snapshot.display_name.expose().to_vec()),
        Vec::new(), // tags: none in V0
        SecretBytes::new(snapshot.notes.expose().to_vec()),
        urls,
        usernames,
        password_history,
        SecretBytes::new(snapshot.totp_secret.expose().to_vec()),
    )
}

/// Decode the V1 8-entry map (after the map header has been consumed).
/// Strict alphabetical key order; arity exactly 8.
fn decode_v1_live_inline(dec: &mut Decoder<&[u8]>) -> Result<DecodedIdentityPayload> {
    let mut display_name: Option<Vec<u8>> = None;
    let mut notes: Option<Vec<u8>> = None;
    let mut password_history: Option<Vec<PasswordEntry>> = None;
    let mut payload_version: Option<u8> = None;
    let mut tags: Option<Vec<SecretBytes>> = None;
    let mut totp_secret: Option<Vec<u8>> = None;
    let mut urls: Option<Vec<SecretBytes>> = None;
    let mut usernames: Option<Vec<SecretBytes>> = None;
    let mut last_key: Option<String> = None;

    for _ in 0..8usize {
        let key = pull_text(dec)?;
        if let Some(prev) = &last_key {
            if prev.as_str() >= key.as_str() {
                return Err(StoreError::Cbor(format!(
                    "non-canonical V1 key order: {prev:?} then {key:?}"
                )));
            }
        }
        match key.as_str() {
            FIELD_DISPLAY_NAME => {
                display_name = Some(pull_text_as_bytes(dec)?);
            }
            FIELD_NOTES => {
                notes = Some(pull_text_as_bytes(dec)?);
            }
            FIELD_PASSWORD_HISTORY => {
                password_history = Some(pull_password_history(dec)?);
            }
            FIELD_PAYLOAD_VERSION => match pull_header(dec)? {
                Header::Positive(v) => {
                    payload_version = Some(u8::try_from(v).map_err(|_| {
                        StoreError::Cbor(format!("payload_version {v} out of u8 range"))
                    })?);
                }
                other => {
                    return Err(StoreError::Cbor(format!(
                        "payload_version not positive integer: {other:?}"
                    )))
                }
            },
            FIELD_TAGS => {
                tags = Some(pull_text_array(dec)?);
            }
            FIELD_TOTP_SECRET => {
                totp_secret = Some(pull_bytes(dec)?);
            }
            FIELD_URLS => {
                urls = Some(pull_text_array(dec)?);
            }
            FIELD_USERNAMES => {
                usernames = Some(pull_text_array(dec)?);
            }
            other => {
                return Err(StoreError::Cbor(format!(
                    "unknown V1 identity field {other:?}"
                )))
            }
        }
        last_key = Some(key);
    }

    let display_name =
        display_name.ok_or_else(|| StoreError::Cbor("V1: missing display_name".into()))?;
    let notes = notes.ok_or_else(|| StoreError::Cbor("V1: missing notes".into()))?;
    let password_history =
        password_history.ok_or_else(|| StoreError::Cbor("V1: missing password_history".into()))?;
    // Q4: accept-and-record. We do NOT reject unknown payload_versions
    // — 1.6 owns the reject policy. The version is read but not
    // currently propagated upward (the caller owns the FFI
    // schema_version slot).
    let _ =
        payload_version.ok_or_else(|| StoreError::Cbor("V1: missing payload_version".into()))?;
    let tags = tags.ok_or_else(|| StoreError::Cbor("V1: missing tags".into()))?;
    let totp_secret =
        totp_secret.ok_or_else(|| StoreError::Cbor("V1: missing totp_secret".into()))?;
    let urls = urls.ok_or_else(|| StoreError::Cbor("V1: missing urls".into()))?;
    let usernames = usernames.ok_or_else(|| StoreError::Cbor("V1: missing usernames".into()))?;

    let identity = AccountIdentity::new_unchecked(
        SecretBytes::new(display_name),
        tags,
        SecretBytes::new(notes),
        urls,
        usernames,
        password_history,
        SecretBytes::new(totp_secret),
    );
    Ok(DecodedIdentityPayload::Live(identity))
}

/// Pull a CBOR text string and return the underlying bytes.
fn pull_text_as_bytes(dec: &mut Decoder<&[u8]>) -> Result<Vec<u8>> {
    let header = pull_header(dec)?;
    match header {
        Header::Text(Some(len)) => {
            let mut buf = vec![0u8; len];
            dec.read_exact(&mut buf)
                .map_err(|_| StoreError::Cbor("text read truncated".into()))?;
            Ok(buf)
        }
        Header::Text(None) => Err(StoreError::Cbor(
            "indefinite-length text strings rejected".into(),
        )),
        other => Err(StoreError::Cbor(format!(
            "expected text value, got {other:?}"
        ))),
    }
}

/// Pull a CBOR array of text strings as `Vec<SecretBytes>`.
fn pull_text_array(dec: &mut Decoder<&[u8]>) -> Result<Vec<SecretBytes>> {
    let header = pull_header(dec)?;
    let count = match header {
        Header::Array(Some(n)) => n,
        Header::Array(None) => {
            return Err(StoreError::Cbor("indefinite-length arrays rejected".into()))
        }
        other => return Err(StoreError::Cbor(format!("expected array, got {other:?}"))),
    };
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let bytes = pull_text_as_bytes(dec)?;
        out.push(SecretBytes::new(bytes));
    }
    Ok(out)
}

/// Pull a CBOR array of password history entries.
fn pull_password_history(dec: &mut Decoder<&[u8]>) -> Result<Vec<PasswordEntry>> {
    let header = pull_header(dec)?;
    let count = match header {
        Header::Array(Some(n)) => n,
        Header::Array(None) => {
            return Err(StoreError::Cbor("indefinite-length arrays rejected".into()))
        }
        other => {
            return Err(StoreError::Cbor(format!(
                "expected password_history array, got {other:?}"
            )))
        }
    };
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        // Each entry: array of 3.
        let entry_header = pull_header(dec)?;
        match entry_header {
            Header::Array(Some(3)) => {}
            other => {
                return Err(StoreError::Cbor(format!(
                    "password history entry not 3-array: {other:?}"
                )))
            }
        }
        let pw = pull_bytes(dec)?;
        let set_at_ms = match pull_header(dec)? {
            Header::Positive(v) => i64::try_from(v).map_err(|_| {
                StoreError::Cbor(format!("set_at_ms positive {v} out of i64 range"))
            })?,
            Header::Negative(v) => -1i64
                .checked_sub(i64::try_from(v).map_err(|_| {
                    StoreError::Cbor(format!("set_at_ms negative {v} out of i64 range"))
                })?)
                .ok_or_else(|| StoreError::Cbor("set_at_ms negative overflow".into()))?,
            other => {
                return Err(StoreError::Cbor(format!(
                    "set_at_ms not integer: {other:?}"
                )))
            }
        };
        let dev_bytes = pull_bytes(dec)?;
        let dev_arr: [u8; DEVICE_ID_LEN] = dev_bytes.as_slice().try_into().map_err(|_| {
            StoreError::Cbor(format!(
                "originating_device wrong length: {} bytes, expected {DEVICE_ID_LEN}",
                dev_bytes.len()
            ))
        })?;
        out.push(PasswordEntry::new(
            SecretBytes::new(pw),
            set_at_ms,
            DeviceId(dev_arr),
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{
        build_aad, decode_payload, encode_snapshot_cbor, encode_tombstone_cbor, open_payload,
        seal_snapshot, seal_tombstone, DecodedPayload, TombstonePayload, ACCOUNT_ID_LEN,
        REV_AAD_LEN, WRAP_AAD_DOMAIN_REV,
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
            DecodedPayload::Tombstone(_) => panic!("expected Live"),
        }
    }

    #[test]
    fn tombstone_round_trips() {
        let key = AeadKey::generate();
        let vault = [0x11u8; 32];
        let acct = AccountId::from_bytes([0x22u8; 32]);
        let aad = build_aad(&vault, &acct, &RevisionId::GENESIS_PARENT, 0);
        let payload = TombstonePayload::new(acct, 1_700_000_000_000);
        let (ct, nonce) = seal_tombstone(&key, &aad, &payload).unwrap();
        match open_payload(&key, &nonce, &ct, &aad).unwrap() {
            DecodedPayload::Tombstone(p) => {
                assert!(p.is_deleted());
                assert_eq!(p.account_id(), acct.as_bytes());
                assert_eq!(p.tombstoned_at_ms(), 1_700_000_000_000);
            }
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
        let acct = AccountId::from_bytes([0xCCu8; 32]);
        let bytes = encode_tombstone_cbor(&TombstonePayload::new(acct, 42));
        match decode_payload(&bytes).unwrap() {
            DecodedPayload::Tombstone(p) => {
                assert!(p.is_deleted());
                assert_eq!(p.account_id(), acct.as_bytes());
                assert_eq!(p.tombstoned_at_ms(), 42);
            }
            DecodedPayload::Live(_) => panic!("decoded tombstone as Live"),
        }
    }

    #[test]
    fn malformed_cbor_rejected() {
        let bytes = vec![0xFFu8; 4]; // not a valid CBOR map header
        assert!(decode_payload(&bytes).is_err());
    }

    /// P10-1 A1: round-trip the widened three-entry payload through
    /// the encoder + decoder; structural equality.
    #[test]
    fn tombstone_payload_round_trip_three_field() {
        let acct = AccountId::from_bytes([0xDEu8; 32]);
        let payload = TombstonePayload::new(acct, 1_234_567_890);
        let bytes = encode_tombstone_cbor(&payload);
        let decoded = decode_payload(&bytes).expect("decode");
        match decoded {
            DecodedPayload::Tombstone(p) => assert_eq!(p, payload),
            DecodedPayload::Live(_) => panic!("expected Tombstone"),
        }
    }

    /// P10-1 A1: encoding the same payload twice is byte-identical
    /// (deterministic CBOR, fixed key order).
    #[test]
    fn tombstone_payload_encoding_is_deterministic() {
        let acct = AccountId::from_bytes([0x55u8; 32]);
        let payload = TombstonePayload::new(acct, 1_000);
        let a = encode_tombstone_cbor(&payload);
        let b = encode_tombstone_cbor(&payload);
        assert_eq!(a, b);
    }

    /// P10-1 A1: legacy `{ "deleted": true }` payloads from P3-era
    /// vault files continue to decode (forward-compat).
    #[test]
    fn tombstone_payload_legacy_single_entry_decodes() {
        // Hand-craft the legacy CBOR: map(1) + text("deleted") + true.
        let mut bytes = Vec::new();
        bytes.push(0xA1); // Map of 1 entry
        bytes.push(0x67); // Text of length 7
        bytes.extend_from_slice(b"deleted");
        bytes.push(0xF5); // true
        match decode_payload(&bytes).expect("legacy decode") {
            DecodedPayload::Tombstone(p) => {
                assert!(p.is_deleted());
                assert_eq!(p.account_id(), &[0u8; ACCOUNT_ID_LEN]);
                assert_eq!(p.tombstoned_at_ms(), 0);
            }
            DecodedPayload::Live(_) => panic!("legacy decoded as Live"),
        }
    }

    /// P10-1 A1: arity-2 payloads are rejected (not legacy, not P10-1
    /// shape — this is the structural discipline that lets MVP-1 add
    /// fields by widening to arity 4).
    #[test]
    fn tombstone_payload_rejects_arity_two() {
        let mut bytes = Vec::new();
        bytes.push(0xA2); // Map of 2 entries
        bytes.push(0x67); // Text len 7
        bytes.extend_from_slice(b"deleted");
        bytes.push(0xF5); // true
        bytes.push(0x6A); // Text len 10
        bytes.extend_from_slice(b"account_id");
        bytes.push(0x40); // empty Bytes
        let err = decode_payload(&bytes).expect_err("arity 2 must reject");
        match err {
            crate::error::StoreError::Cbor(_) => {}
            other => panic!("expected Cbor error, got {other:?}"),
        }
    }

    /// P10-1 A1: arity-4-or-more payloads are rejected. MVP-1 may
    /// widen to arity 4 with `device_id`, at which point this test
    /// is updated; for v0 the discipline is exact.
    #[test]
    fn tombstone_payload_rejects_arity_four_or_more() {
        let mut bytes = Vec::new();
        bytes.push(0xA4); // Map of 4 entries
        bytes.push(0x67);
        bytes.extend_from_slice(b"deleted");
        bytes.push(0xF5);
        // The remaining entries don't matter; arity check fires first.
        let err = decode_payload(&bytes).expect_err("arity 4 must reject");
        match err {
            crate::error::StoreError::Cbor(_) => {}
            other => panic!("expected Cbor error, got {other:?}"),
        }
    }

    /// P10-1 A1: the widened payload's keys MUST appear in the
    /// alphabetical order `account_id`, `deleted`, `tombstoned_at_ms`.
    /// A drift = corruption = decode error.
    #[test]
    fn tombstone_payload_rejects_non_canonical_key_order() {
        // Build a 3-entry map with `deleted` first (out of order).
        let mut bytes = Vec::new();
        bytes.push(0xA3); // Map of 3
                          // Wrong: deleted first.
        bytes.push(0x67);
        bytes.extend_from_slice(b"deleted");
        bytes.push(0xF5);
        // account_id second.
        bytes.push(0x6A);
        bytes.extend_from_slice(b"account_id");
        bytes.push(0x58); // Bytes(len follows in 1 byte)
        bytes.push(32);
        bytes.extend_from_slice(&[0xAA; 32]);
        // tombstoned_at_ms third.
        bytes.push(0x70); // Text len 16
        bytes.extend_from_slice(b"tombstoned_at_ms");
        bytes.push(0x00);
        let err = decode_payload(&bytes).expect_err("wrong order must reject");
        match err {
            crate::error::StoreError::Cbor(_) => {}
            other => panic!("expected Cbor error, got {other:?}"),
        }
    }

    /// P10-1 A1: `account_id` must be exactly 32 bytes.
    #[test]
    fn tombstone_payload_rejects_account_id_wrong_length() {
        let mut bytes = Vec::new();
        bytes.push(0xA3);
        bytes.push(0x6A);
        bytes.extend_from_slice(b"account_id");
        bytes.push(0x44); // Bytes len 4 (wrong; must be 32)
        bytes.extend_from_slice(&[0; 4]);
        bytes.push(0x67);
        bytes.extend_from_slice(b"deleted");
        bytes.push(0xF5);
        bytes.push(0x70);
        bytes.extend_from_slice(b"tombstoned_at_ms");
        bytes.push(0x00);
        let err = decode_payload(&bytes).expect_err("short account_id must reject");
        match err {
            crate::error::StoreError::Cbor(_) => {}
            other => panic!("expected Cbor error, got {other:?}"),
        }
    }

    /// P10-1 A1: `tombstoned_at_ms` is u64 (CBOR Positive). A negative
    /// (CBOR `Major::Negative`) value is rejected.
    #[test]
    fn tombstone_payload_rejects_tombstoned_at_negative() {
        let mut bytes = Vec::new();
        bytes.push(0xA3);
        bytes.push(0x6A);
        bytes.extend_from_slice(b"account_id");
        bytes.push(0x58);
        bytes.push(32);
        bytes.extend_from_slice(&[0u8; 32]);
        bytes.push(0x67);
        bytes.extend_from_slice(b"deleted");
        bytes.push(0xF5);
        bytes.push(0x70);
        bytes.extend_from_slice(b"tombstoned_at_ms");
        // CBOR Negative(0) = -1: major=1 (0b001), shortcount=0 → 0x20.
        bytes.push(0x20);
        let err = decode_payload(&bytes).expect_err("negative ts must reject");
        match err {
            crate::error::StoreError::Cbor(_) => {}
            other => panic!("expected Cbor error, got {other:?}"),
        }
    }

    /// P10-1 A1: full seal/open round-trip with the three-field
    /// payload through the AEAD layer.
    #[test]
    fn seal_tombstone_with_payload_round_trips_through_open_payload() {
        let key = AeadKey::generate();
        let vault = [0xEEu8; 32];
        let acct = AccountId::from_bytes([0xFFu8; 32]);
        let aad = build_aad(&vault, &acct, &RevisionId::GENESIS_PARENT, 0);
        let payload = TombstonePayload::new(acct, 9_999);
        let (ct, nonce) = seal_tombstone(&key, &aad, &payload).unwrap();
        match open_payload(&key, &nonce, &ct, &aad).unwrap() {
            DecodedPayload::Tombstone(p) => {
                assert_eq!(p, payload);
            }
            DecodedPayload::Live(_) => panic!("expected Tombstone"),
        }
    }

    /// Authentication still fires if the tombstone ciphertext is
    /// transplanted to a different account's AAD.
    #[test]
    fn tombstone_aad_substitution_fails() {
        let key = AeadKey::generate();
        let vault = [0xAAu8; 32];
        let acct_a = AccountId::from_bytes([0xA1u8; 32]);
        let acct_b = AccountId::from_bytes([0xB1u8; 32]);
        let aad_a = build_aad(&vault, &acct_a, &RevisionId::GENESIS_PARENT, 0);
        let aad_b = build_aad(&vault, &acct_b, &RevisionId::GENESIS_PARENT, 0);
        let payload = TombstonePayload::new(acct_a, 1);
        let (ct, nonce) = seal_tombstone(&key, &aad_a, &payload).unwrap();
        assert!(open_payload(&key, &nonce, &ct, &aad_b).is_err());
    }

    // -- MVP-1 issue 1.2: V1 codec tests ----------------------------------

    use crate::account::{AccountIdentity, AccountIdentityDraft, ACCOUNT_IDENTITY_SCHEMA_VERSION};
    use crate::revision::DeviceId;

    fn fixture_identity() -> AccountIdentity {
        let draft = AccountIdentityDraft {
            schema_version: ACCOUNT_IDENTITY_SCHEMA_VERSION,
            display_name: "GitHub – Main".into(),
            tags: vec!["work".into(), "shared".into()],
            usernames: vec!["alice@example.com".into(), "alt@example.com".into()],
            urls: vec!["https://github.com".into()],
            notes: "test notes".into(),
            password: SecretBytes::new(b"hunter2".to_vec()),
            totp_secret: SecretBytes::new(b"totp-bytes".to_vec()),
        };
        draft
            .validate_into_identity(1_700_000_000_000, DeviceId([0x33u8; 32]))
            .expect("validate")
    }

    #[test]
    fn identity_v1_round_trips_through_seal_open() {
        let key = AeadKey::generate();
        let vault = [0x11u8; 32];
        let acct = AccountId::from_bytes([0x22u8; 32]);
        let aad = build_aad(&vault, &acct, &RevisionId::GENESIS_PARENT, 0);
        // Build a fixture with a 2-entry password history so the
        // ordering pin (audit M-1) actually has something to pin.
        // HEAD == newest, then older.
        let mut identity = fixture_identity();
        // Append an older entry by inserting at index 1 (older than HEAD).
        let older = crate::account::PasswordEntry::new(
            SecretBytes::new(b"old-hunter1".to_vec()),
            1_600_000_000_000,
            DeviceId([0x44u8; 32]),
        );
        identity.password_history.push(older);
        // Now the order is `[hunter2 (newer), old-hunter1 (older)]`
        // because the genesis password from fixture_identity is at
        // index 0 with set_at_ms=1_700_000_000_000.

        let (ct, nonce) = super::seal_identity(&key, &identity, &aad).unwrap();
        match super::open_identity_payload(&key, &nonce, &ct, &aad).unwrap() {
            super::DecodedIdentityPayload::Live(recovered) => {
                assert!(bool::from(identity.ct_eq(&recovered)));
                // Audit M-1: pin password_history head-is-newest
                // ordering through the round-trip. AccountIdentity's
                // password_history is `pub(crate)`, so this assertion
                // lives in the crate-internal blob.rs tests.
                assert_eq!(
                    recovered.password_history.len(),
                    2,
                    "expected 2 history entries"
                );
                assert_eq!(
                    recovered.password_history[0].password.expose(),
                    b"hunter2",
                    "HEAD entry must be the newest password"
                );
                assert_eq!(
                    recovered.password_history[1].password.expose(),
                    b"old-hunter1",
                    "older entry must follow HEAD"
                );
                assert!(
                    recovered.password_history[0].set_at_ms
                        > recovered.password_history[1].set_at_ms,
                    "HEAD set_at_ms must be greater than older entry's set_at_ms"
                );
            }
            super::DecodedIdentityPayload::Tombstone(_) => panic!("expected Live"),
        }
    }

    /// V0 → V1 auto-migration: a synthesised V0 6-field payload
    /// decodes through the V1 path and yields a hydrated identity
    /// with `usernames=[username]`, `urls=[url]`,
    /// `password_history=[head]`, `tags=[]`.
    #[test]
    fn legacy_v0_payload_decodes_through_v1_path() {
        let snap = AccountSnapshot::new(
            SecretBytes::new(b"GitHub".to_vec()),
            SecretBytes::new(b"alice".to_vec()),
            SecretBytes::new(b"hunter2".to_vec()),
            SecretBytes::new(b"https://github.com".to_vec()),
            SecretBytes::new(b"test notes".to_vec()),
            SecretBytes::new(b"".to_vec()),
        );
        let cbor = encode_snapshot_cbor(&snap);
        let decoded = super::decode_identity_payload(&cbor).expect("decode V0 via V1 path");
        match decoded {
            super::DecodedIdentityPayload::Live(identity) => {
                assert_eq!(identity.usernames.len(), 1);
                assert_eq!(identity.urls.len(), 1);
                assert_eq!(identity.tags.len(), 0);
                assert_eq!(identity.password_history.len(), 1);
                assert_eq!(identity.password_history[0].password.expose(), b"hunter2");
                assert_eq!(identity.usernames[0].expose(), b"alice");
                assert_eq!(identity.urls[0].expose(), b"https://github.com");
                assert!(!identity.has_totp());
            }
            super::DecodedIdentityPayload::Tombstone(_) => panic!("expected Live"),
        }
    }

    /// V0 payload with empty username / url / totp → hydrate to
    /// empty Vecs (no spurious singleton entries).
    #[test]
    fn legacy_v0_with_empty_optional_fields_hydrates_to_empty_vecs() {
        let snap = AccountSnapshot::new(
            SecretBytes::new(b"X".to_vec()),
            SecretBytes::new(b"".to_vec()), // username empty
            SecretBytes::new(b"hunter2".to_vec()),
            SecretBytes::new(b"".to_vec()), // url empty
            SecretBytes::new(b"".to_vec()),
            SecretBytes::new(b"".to_vec()),
        );
        let cbor = encode_snapshot_cbor(&snap);
        match super::decode_identity_payload(&cbor).unwrap() {
            super::DecodedIdentityPayload::Live(identity) => {
                assert_eq!(identity.usernames.len(), 0);
                assert_eq!(identity.urls.len(), 0);
            }
            super::DecodedIdentityPayload::Tombstone(_) => panic!("expected Live"),
        }
    }

    /// V1 encoding deterministic — same identity → same bytes.
    #[test]
    fn v1_encoding_is_deterministic() {
        let a = fixture_identity();
        let b = fixture_identity();
        let ea = super::encode_identity_cbor(&a);
        let eb = super::encode_identity_cbor(&b);
        assert_eq!(*ea, *eb);
    }

    /// V1 payload size is small for a typical record.
    #[test]
    fn v1_encoded_size_is_bounded() {
        let identity = fixture_identity();
        let bytes = super::encode_identity_cbor(&identity);
        assert!(
            bytes.len() < 4096,
            "V1 encoding too big: {} bytes",
            bytes.len()
        );
    }
}
