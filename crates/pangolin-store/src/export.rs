// SPDX-License-Identifier: AGPL-3.0-or-later
//! Pangolin-native encrypted vault archive (MVP-1 issue 1.10).
//!
//! A self-contained, portable, AEAD-sealed snapshot of a vault — the
//! current head of every account, the per-account password history (the
//! historical password bytes + change timestamps + originating-device
//! ids), the device trust list (ids + labels), the vault `meta` settings,
//! and the `vault_id` + a provenance fingerprint (`source_device_id`,
//! `exported_at`). The archive is encrypted under a 256-bit key derived
//! (Argon2id, `KdfParams::RECOMMENDED`) from a *fresh user-supplied
//! export passphrase* — independent of the vault master password. The
//! plaintext header (magic, format version, KDF params, salt, nonce,
//! ciphertext-length frame) is the AEAD AAD, so a tampered header fails
//! authentication.
//!
//! The format/codec/decoder lives here; the presence-gated `Vault::
//! export_encrypted` / `Vault::export_plaintext` / `Vault::
//! restore_to_new_vault` entry points live in [`crate::vault`] (they need
//! the `Vault` internals). See `docs/architecture/encrypted-export.md`.
//!
//! HIGH-1: the CBOR codec is `ciborium-ll` (already in `pangolin-store`'s
//! tree) — nothing pulls serde into `pangolin-crypto`.

use ciborium_io::{Read as _, Write as _};
use ciborium_ll::{Decoder, Encoder, Header};
use pangolin_crypto::aead::{Ciphertext, Nonce, NONCE_LEN};
use pangolin_crypto::kdf::{derive_key, KdfParams, KdfSalt, SALT_LEN};
use pangolin_crypto::secret::SecretBytes;
use zeroize::Zeroizing;

use crate::account::{TotpAlgorithm, TotpParams};
use crate::error::{Result, StoreError};
use crate::revision::{DeviceId, DEVICE_ID_LEN};

/// Magic bytes at the head of every Pangolin encrypted archive.
pub const ARCHIVE_MAGIC: [u8; 12] = *b"PANGOLIN-VEA";

/// Container format version. Bumped on any header-layout change.
pub const ARCHIVE_FORMAT_VERSION: u8 = 1;

/// Payload schema version (the CBOR snapshot shape). Independent of
/// [`ARCHIVE_FORMAT_VERSION`].
pub const ARCHIVE_SNAPSHOT_SCHEMA_VERSION: u16 = 1;

/// KDF algorithm id slot. `1` = Argon2id. Future-proofing for a v2.
pub const KDF_ALGO_ARGON2ID: u8 = 1;

/// Hard ceiling on the AEAD ciphertext length we will accept on decode
/// (256 MiB). Bounds a hostile/lying-length archive before any
/// allocation or Argon2 derivation.
pub const MAX_CIPHERTEXT_LEN: u64 = 256 * 1024 * 1024;

/// Upper clamp on Argon2 memory cost (KiB) we will accept on decode:
/// 1 GiB. A hostile archive can't make us allocate more than ~1 GiB.
pub const MAX_KDF_MEMORY_KIB: u32 = 1024 * 1024;

/// Upper clamp on Argon2 time cost we will accept on decode. Combined
/// with [`MAX_KDF_MEMORY_KIB_TIME_COST_PRODUCT`] this bounds a hostile
/// header to ~a couple seconds of Argon2 work.
pub const MAX_KDF_TIME_COST: u32 = 8;

/// Upper clamp on Argon2 parallelism we will accept on decode.
pub const MAX_KDF_PARALLELISM: u32 = 8;

/// Combined ceiling on `memory_kib * time_cost` we accept on decode
/// (≈3 GiB-KiB-passes ≈ a couple seconds of Argon2id).
///
/// Even at the 1-GiB memory ceiling a hostile header can't crank
/// `time_cost` to make the derive run for minutes. `KdfParams::
/// RECOMMENDED` is 256 MiB × t=3 = 768 K, comfortably under; a paranoid
/// 512 MiB × t=3 = 1.5 M is also under.
pub const MAX_KDF_MEMORY_KIB_TIME_COST_PRODUCT: u64 = 3 * 1024 * 1024;

/// Length of the fixed-size plaintext archive header (everything before
/// the ciphertext).
///
/// Layout: `magic(12)` + `format_version(1)` + `kdf_algo(1)` +
/// `kdf_memory_kib(4)` + `kdf_time_cost(4)` + `kdf_parallelism(4)` +
/// `salt(16)` + `nonce(24)` + `ct_len(8)`.
pub const ARCHIVE_HEADER_LEN: usize =
    ARCHIVE_MAGIC.len() + 1 + 1 + 4 + 4 + 4 + SALT_LEN + NONCE_LEN + 8;

/// In-file marker line at the head of a `--plaintext` export. Loud and
/// unmistakable.
pub const PLAINTEXT_EXPORT_BANNER: &str =
    "*** WARNING: THIS FILE CONTAINS YOUR VAULT PASSWORDS IN CLEARTEXT ***";

// ---------------------------------------------------------------------
// Header
// ---------------------------------------------------------------------

/// Parsed plaintext archive header. The byte form is also the AEAD AAD.
#[derive(Debug, Clone)]
pub struct ArchiveHeader {
    /// Container format version.
    pub format_version: u8,
    /// KDF algorithm id (`1` = Argon2id).
    pub kdf_algo_id: u8,
    /// KDF parameters used to derive the archive key.
    pub kdf_params: KdfParams,
    /// 16-byte KDF salt.
    pub salt: KdfSalt,
    /// 24-byte XChaCha20-Poly1305 nonce.
    pub nonce: Nonce,
    /// AEAD ciphertext length (bytes).
    pub ct_len: u64,
}

impl ArchiveHeader {
    /// Serialize the header to its canonical fixed-length byte form.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; ARCHIVE_HEADER_LEN] {
        let mut out = [0u8; ARCHIVE_HEADER_LEN];
        let mut c = 0;
        out[c..c + ARCHIVE_MAGIC.len()].copy_from_slice(&ARCHIVE_MAGIC);
        c += ARCHIVE_MAGIC.len();
        out[c] = self.format_version;
        c += 1;
        out[c] = self.kdf_algo_id;
        c += 1;
        out[c..c + 4].copy_from_slice(&self.kdf_params.memory_kib.to_be_bytes());
        c += 4;
        out[c..c + 4].copy_from_slice(&self.kdf_params.time_cost.to_be_bytes());
        c += 4;
        out[c..c + 4].copy_from_slice(&self.kdf_params.parallelism.to_be_bytes());
        c += 4;
        out[c..c + SALT_LEN].copy_from_slice(self.salt.as_bytes());
        c += SALT_LEN;
        out[c..c + NONCE_LEN].copy_from_slice(self.nonce.as_bytes());
        c += NONCE_LEN;
        out[c..c + 8].copy_from_slice(&self.ct_len.to_be_bytes());
        out
    }

    /// Parse a header from the head of `bytes`, returning the header and
    /// the remaining slice (the ciphertext region). Strict bounds +
    /// sanity checks: truncation, magic mismatch, unknown version /
    /// algo, hostile KDF params, lying `ct_len`.
    ///
    /// # Errors
    ///
    /// [`StoreError::Validation`] with a `kind = "export_format"` label
    /// for any structural problem; never panics.
    pub fn parse(bytes: &[u8]) -> Result<(Self, &[u8])> {
        if bytes.len() < ARCHIVE_HEADER_LEN {
            return Err(fmt_err("archive truncated: header incomplete"));
        }
        let (header_bytes, rest) = bytes.split_at(ARCHIVE_HEADER_LEN);
        let mut c = 0;
        if header_bytes[..ARCHIVE_MAGIC.len()] != ARCHIVE_MAGIC {
            return Err(fmt_err("not a Pangolin encrypted archive"));
        }
        c += ARCHIVE_MAGIC.len();
        let format_version = header_bytes[c];
        c += 1;
        if format_version != ARCHIVE_FORMAT_VERSION {
            return Err(fmt_err(
                "unsupported archive format version (need a newer Pangolin)",
            ));
        }
        let kdf_algo_id = header_bytes[c];
        c += 1;
        if kdf_algo_id != KDF_ALGO_ARGON2ID {
            return Err(fmt_err("unsupported archive KDF algorithm"));
        }
        let memory_kib = u32::from_be_bytes(header_bytes[c..c + 4].try_into().expect("4 bytes"));
        c += 4;
        let time_cost = u32::from_be_bytes(header_bytes[c..c + 4].try_into().expect("4 bytes"));
        c += 4;
        let parallelism = u32::from_be_bytes(header_bytes[c..c + 4].try_into().expect("4 bytes"));
        c += 4;
        let kdf_params = KdfParams {
            memory_kib,
            time_cost,
            parallelism,
        };
        // Clamp BEFORE any Argon2 call: reject anything below the
        // crypto-crate floor or above our DoS ceiling (each axis plus a
        // combined memory×time-cost cap, so a hostile header can't make
        // `derive_key` run for more than ~a couple seconds or allocate
        // more than ~1 GiB).
        if kdf_params.validate().is_err()
            || memory_kib > MAX_KDF_MEMORY_KIB
            || time_cost > MAX_KDF_TIME_COST
            || parallelism > MAX_KDF_PARALLELISM
            || u64::from(memory_kib).saturating_mul(u64::from(time_cost))
                > MAX_KDF_MEMORY_KIB_TIME_COST_PRODUCT
        {
            return Err(fmt_err("archive KDF parameters out of supported range"));
        }
        let salt_arr: [u8; SALT_LEN] = header_bytes[c..c + SALT_LEN]
            .try_into()
            .expect("salt slice length");
        c += SALT_LEN;
        let nonce_arr: [u8; NONCE_LEN] = header_bytes[c..c + NONCE_LEN]
            .try_into()
            .expect("nonce slice length");
        c += NONCE_LEN;
        let ct_len = u64::from_be_bytes(header_bytes[c..c + 8].try_into().expect("8 bytes"));
        if ct_len > MAX_CIPHERTEXT_LEN {
            return Err(fmt_err("archive ciphertext length exceeds the maximum"));
        }
        if u64::try_from(rest.len()).unwrap_or(u64::MAX) != ct_len {
            return Err(fmt_err(
                "archive ciphertext length does not match file size",
            ));
        }
        Ok((
            Self {
                format_version,
                kdf_algo_id,
                kdf_params,
                salt: KdfSalt::from_bytes(salt_arr),
                nonce: Nonce::from_storage_bytes(nonce_arr),
                ct_len,
            },
            rest,
        ))
    }
}

// ---------------------------------------------------------------------
// Snapshot types
// ---------------------------------------------------------------------

/// One password-history entry inside an archived account.
pub struct ArchivedPasswordEntry {
    /// The password bytes.
    pub password: SecretBytes,
    /// Wall-clock unix-ms timestamp at which this password was set.
    pub set_at_ms: i64,
    /// 32-byte originating device id.
    pub originating_device: DeviceId,
}

impl zeroize::ZeroizeOnDrop for ArchivedPasswordEntry {}

impl core::fmt::Debug for ArchivedPasswordEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ArchivedPasswordEntry")
            .field("password", &"<redacted>")
            .field("set_at_ms", &self.set_at_ms)
            .field("originating_device", &self.originating_device)
            .finish()
    }
}

/// One account inside an archive snapshot. Carries the full V1 identity
/// (display name, tags, urls, usernames, notes, TOTP) plus the complete
/// password history (head first).
pub struct ArchivedAccount {
    /// Stable 32-byte account id (as in the source vault).
    pub account_id: [u8; 32],
    /// Wall-clock unix-ms creation timestamp.
    pub created_at_ms: i64,
    /// Display name.
    pub display_name: SecretBytes,
    /// Tags.
    pub tags: Vec<SecretBytes>,
    /// Associated URLs.
    pub urls: Vec<SecretBytes>,
    /// Usernames / emails.
    pub usernames: Vec<SecretBytes>,
    /// Free-form notes.
    pub notes: SecretBytes,
    /// Password history, head (current) first.
    pub password_history: Vec<ArchivedPasswordEntry>,
    /// TOTP shared-secret seed (empty = none).
    pub totp_secret: SecretBytes,
    /// TOTP parameters.
    pub totp_params: TotpParams,
}

impl zeroize::ZeroizeOnDrop for ArchivedAccount {}

impl core::fmt::Debug for ArchivedAccount {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ArchivedAccount")
            .field("account_id", &self.account_id)
            .field("created_at_ms", &self.created_at_ms)
            .field("display_name", &"<redacted>")
            .field("tags", &format_args!("<{} tags>", self.tags.len()))
            .field("urls", &format_args!("<{} urls>", self.urls.len()))
            .field(
                "usernames",
                &format_args!("<{} usernames>", self.usernames.len()),
            )
            .field("notes", &"<redacted>")
            .field(
                "password_history",
                &format_args!("<{} entries>", self.password_history.len()),
            )
            .field("totp_secret", &"<redacted>")
            .field("totp_params", &self.totp_params)
            .finish()
    }
}

/// One entry in the archived device trust list.
#[derive(Debug, Clone)]
pub struct ArchivedDevice {
    /// 32-byte device id.
    pub device_id: [u8; 32],
    /// Human-readable label.
    pub label: String,
    /// Wall-clock unix-ms timestamp the device was added.
    pub added_at_ms: i64,
}

/// The decoded archive payload — everything inside the AEAD ciphertext.
pub struct ArchiveSnapshot {
    /// Payload schema version.
    pub schema_version: u16,
    /// Provenance: when the export ran (unix seconds).
    pub exported_at: i64,
    /// Provenance: the device that produced the export.
    pub source_device_id: [u8; 32],
    /// The source vault's id.
    pub vault_id: [u8; 32],
    /// Session idle timeout (seconds) from the vault `meta`; `None` =
    /// vault default.
    pub session_idle_secs: Option<i64>,
    /// The archived accounts.
    pub accounts: Vec<ArchivedAccount>,
    /// The archived device trust list.
    pub devices: Vec<ArchivedDevice>,
}

impl zeroize::ZeroizeOnDrop for ArchiveSnapshot {}

impl core::fmt::Debug for ArchiveSnapshot {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ArchiveSnapshot")
            .field("schema_version", &self.schema_version)
            .field("exported_at", &self.exported_at)
            .field("source_device_id", &self.source_device_id)
            .field("vault_id", &self.vault_id)
            .field("session_idle_secs", &self.session_idle_secs)
            .field(
                "accounts",
                &format_args!("<{} accounts>", self.accounts.len()),
            )
            .field("devices", &self.devices)
            .finish()
    }
}

// ---------------------------------------------------------------------
// CBOR codec
// ---------------------------------------------------------------------

type Enc<'a> = Encoder<&'a mut Vec<u8>>;

fn push<W: ciborium_io::Write>(enc: &mut Encoder<W>, h: Header)
where
    W::Error: core::fmt::Debug,
{
    enc.push(h).expect("Vec<u8> writer is infallible");
}

fn put_bytes(enc: &mut Enc<'_>, b: &[u8]) {
    push(enc, Header::Bytes(Some(b.len())));
    enc.write_all(b).expect("infallible");
}

fn put_text(enc: &mut Enc<'_>, s: &str) {
    push(enc, Header::Text(Some(s.len())));
    enc.write_all(s.as_bytes()).expect("infallible");
}

#[allow(clippy::cast_sign_loss)]
fn put_int(enc: &mut Enc<'_>, v: i64) {
    if v >= 0 {
        push(enc, Header::Positive(v as u64));
    } else {
        // CBOR negative encoding: -1 - n.
        push(enc, Header::Negative((-1 - v) as u64));
    }
}

/// Encode the snapshot to a `Zeroizing<Vec<u8>>` CBOR document (it
/// carries every secret).
#[must_use]
pub fn encode_snapshot(snap: &ArchiveSnapshot) -> Zeroizing<Vec<u8>> {
    let mut out: Vec<u8> = Vec::with_capacity(1024);
    {
        let mut enc = Encoder::from(&mut out);
        // Top-level array of 7 items.
        push(&mut enc, Header::Array(Some(7)));
        push(&mut enc, Header::Positive(u64::from(snap.schema_version)));
        put_int(&mut enc, snap.exported_at);
        put_bytes(&mut enc, &snap.source_device_id);
        put_bytes(&mut enc, &snap.vault_id);
        // session_idle_secs: array [present?, value]
        push(&mut enc, Header::Array(Some(2)));
        if let Some(v) = snap.session_idle_secs {
            push(&mut enc, Header::Simple(ciborium_ll::simple::TRUE));
            put_int(&mut enc, v);
        } else {
            push(&mut enc, Header::Simple(ciborium_ll::simple::FALSE));
            put_int(&mut enc, 0);
        }
        // accounts
        push(&mut enc, Header::Array(Some(snap.accounts.len())));
        for a in &snap.accounts {
            push(&mut enc, Header::Array(Some(9)));
            put_bytes(&mut enc, &a.account_id);
            put_int(&mut enc, a.created_at_ms);
            put_bytes(&mut enc, a.display_name.expose());
            // tags
            push(&mut enc, Header::Array(Some(a.tags.len())));
            for t in &a.tags {
                put_bytes(&mut enc, t.expose());
            }
            // urls
            push(&mut enc, Header::Array(Some(a.urls.len())));
            for u in &a.urls {
                put_bytes(&mut enc, u.expose());
            }
            // usernames
            push(&mut enc, Header::Array(Some(a.usernames.len())));
            for u in &a.usernames {
                put_bytes(&mut enc, u.expose());
            }
            put_bytes(&mut enc, a.notes.expose());
            // password_history
            push(&mut enc, Header::Array(Some(a.password_history.len())));
            for e in &a.password_history {
                push(&mut enc, Header::Array(Some(3)));
                put_bytes(&mut enc, e.password.expose());
                put_int(&mut enc, e.set_at_ms);
                put_bytes(&mut enc, &e.originating_device.0);
            }
            // totp: [secret, algo_u8, digits, period_seconds]
            push(&mut enc, Header::Array(Some(4)));
            put_bytes(&mut enc, a.totp_secret.expose());
            push(
                &mut enc,
                Header::Positive(u64::from(a.totp_params.algorithm.to_wire())),
            );
            push(&mut enc, Header::Positive(u64::from(a.totp_params.digits)));
            push(
                &mut enc,
                Header::Positive(u64::from(a.totp_params.period_seconds)),
            );
        }
        // devices
        push(&mut enc, Header::Array(Some(snap.devices.len())));
        for d in &snap.devices {
            push(&mut enc, Header::Array(Some(3)));
            put_bytes(&mut enc, &d.device_id);
            put_text(&mut enc, &d.label);
            put_int(&mut enc, d.added_at_ms);
        }
    }
    Zeroizing::new(out)
}

// --- decode helpers --------------------------------------------------

fn cbor_err(msg: impl Into<String>) -> StoreError {
    StoreError::Validation {
        kind: "export_format".into(),
        message: msg.into(),
    }
}

type Dec<'a> = Decoder<&'a [u8]>;

fn pull(dec: &mut Dec<'_>) -> Result<Header> {
    dec.pull().map_err(|_| cbor_err("malformed archive CBOR"))
}

fn expect_array(dec: &mut Dec<'_>, want: usize) -> Result<()> {
    match pull(dec)? {
        Header::Array(Some(n)) if n == want => Ok(()),
        _ => Err(cbor_err("archive CBOR: unexpected array shape")),
    }
}

fn pull_array_len(dec: &mut Dec<'_>) -> Result<usize> {
    match pull(dec)? {
        Header::Array(Some(n)) => Ok(n),
        _ => Err(cbor_err("archive CBOR: expected definite-length array")),
    }
}

fn pull_uint(dec: &mut Dec<'_>) -> Result<u64> {
    match pull(dec)? {
        Header::Positive(v) => Ok(v),
        _ => Err(cbor_err("archive CBOR: expected unsigned integer")),
    }
}

#[allow(clippy::cast_possible_wrap)]
fn pull_int(dec: &mut Dec<'_>) -> Result<i64> {
    match pull(dec)? {
        Header::Positive(v) => {
            i64::try_from(v).map_err(|_| cbor_err("archive CBOR: integer overflow"))
        }
        Header::Negative(v) => {
            let n = i64::try_from(v).map_err(|_| cbor_err("archive CBOR: integer overflow"))?;
            Ok(-1 - n)
        }
        _ => Err(cbor_err("archive CBOR: expected integer")),
    }
}

fn pull_bool(dec: &mut Dec<'_>) -> Result<bool> {
    match pull(dec)? {
        Header::Simple(s) if s == ciborium_ll::simple::TRUE => Ok(true),
        Header::Simple(s) if s == ciborium_ll::simple::FALSE => Ok(false),
        _ => Err(cbor_err("archive CBOR: expected boolean")),
    }
}

const MAX_BLOB_LEN: usize = 64 * 1024 * 1024;

fn pull_bytes(dec: &mut Dec<'_>) -> Result<Vec<u8>> {
    match pull(dec)? {
        Header::Bytes(Some(len)) => {
            if len > MAX_BLOB_LEN {
                return Err(cbor_err("archive CBOR: byte string too long"));
            }
            let mut buf = vec![0u8; len];
            dec.read_exact(&mut buf)
                .map_err(|_| cbor_err("archive CBOR: truncated byte string"))?;
            Ok(buf)
        }
        _ => Err(cbor_err("archive CBOR: expected definite byte string")),
    }
}

fn pull_text(dec: &mut Dec<'_>) -> Result<String> {
    match pull(dec)? {
        Header::Text(Some(len)) => {
            if len > MAX_BLOB_LEN {
                return Err(cbor_err("archive CBOR: text string too long"));
            }
            let mut buf = vec![0u8; len];
            dec.read_exact(&mut buf)
                .map_err(|_| cbor_err("archive CBOR: truncated text string"))?;
            String::from_utf8(buf).map_err(|_| cbor_err("archive CBOR: invalid UTF-8"))
        }
        _ => Err(cbor_err("archive CBOR: expected definite text string")),
    }
}

fn pull_array32(dec: &mut Dec<'_>) -> Result<[u8; 32]> {
    let b = pull_bytes(dec)?;
    b.as_slice()
        .try_into()
        .map_err(|_| cbor_err("archive CBOR: expected 32-byte id"))
}

/// Sanity cap on the number of accounts / devices in an archive.
const MAX_ITEMS: usize = 2_000_000;

/// Pull a definite-length array of byte strings into `Vec<SecretBytes>`,
/// bounded by [`MAX_ITEMS`].
fn pull_secret_bytes_vec(dec: &mut Dec<'_>, what: &'static str) -> Result<Vec<SecretBytes>> {
    let n = pull_array_len(dec)?;
    if n > MAX_ITEMS {
        return Err(cbor_err(format!("archive CBOR: too many {what}")));
    }
    let mut out = Vec::with_capacity(n.min(64));
    for _ in 0..n {
        out.push(SecretBytes::new(pull_bytes(dec)?));
    }
    Ok(out)
}

/// Decode one [`ArchivedAccount`] from the decoder. Strict bounds; never
/// panics.
fn decode_account(dec: &mut Dec<'_>) -> Result<ArchivedAccount> {
    expect_array(dec, 9)?;
    let account_id = pull_array32(dec)?;
    let created_at_ms = pull_int(dec)?;
    let display_name = SecretBytes::new(pull_bytes(dec)?);
    let tags = pull_secret_bytes_vec(dec, "tags")?;
    let urls = pull_secret_bytes_vec(dec, "urls")?;
    let usernames = pull_secret_bytes_vec(dec, "usernames")?;
    let notes = SecretBytes::new(pull_bytes(dec)?);
    let hist_n = pull_array_len(dec)?;
    if hist_n > MAX_ITEMS {
        return Err(cbor_err("archive CBOR: too many history entries"));
    }
    let mut password_history = Vec::with_capacity(hist_n.min(64));
    for _ in 0..hist_n {
        expect_array(dec, 3)?;
        let password = SecretBytes::new(pull_bytes(dec)?);
        let set_at_ms = pull_int(dec)?;
        let dev = pull_array32(dec)?;
        password_history.push(ArchivedPasswordEntry {
            password,
            set_at_ms,
            originating_device: DeviceId(dev),
        });
    }
    expect_array(dec, 4)?;
    let totp_secret = SecretBytes::new(pull_bytes(dec)?);
    let algo_u = pull_uint(dec)?;
    let algo = TotpAlgorithm::from_wire(
        u8::try_from(algo_u).map_err(|_| cbor_err("archive CBOR: bad TOTP algorithm"))?,
    )
    .map_err(|_| cbor_err("archive CBOR: unknown TOTP algorithm"))?;
    let digits =
        u8::try_from(pull_uint(dec)?).map_err(|_| cbor_err("archive CBOR: bad TOTP digits"))?;
    let period_seconds =
        u32::try_from(pull_uint(dec)?).map_err(|_| cbor_err("archive CBOR: bad TOTP period"))?;
    Ok(ArchivedAccount {
        account_id,
        created_at_ms,
        display_name,
        tags,
        urls,
        usernames,
        notes,
        password_history,
        totp_secret,
        totp_params: TotpParams {
            algorithm: algo,
            digits,
            period_seconds,
        },
    })
}

/// Decode a CBOR snapshot document (the AEAD plaintext). Strict bounds;
/// never panics.
///
/// # Errors
///
/// [`StoreError::Validation`] with `kind = "export_format"` for any
/// malformed input.
pub fn decode_snapshot(buf: &[u8]) -> Result<ArchiveSnapshot> {
    let mut dec = Decoder::from(buf);
    expect_array(&mut dec, 7)?;
    let schema_version_u = pull_uint(&mut dec)?;
    let schema_version = u16::try_from(schema_version_u)
        .map_err(|_| cbor_err("archive payload schema version out of range"))?;
    if schema_version != ARCHIVE_SNAPSHOT_SCHEMA_VERSION {
        return Err(cbor_err(
            "unsupported archive payload schema version (need a newer Pangolin)",
        ));
    }
    let exported_at = pull_int(&mut dec)?;
    let source_device_id = pull_array32(&mut dec)?;
    let vault_id = pull_array32(&mut dec)?;
    // session_idle_secs
    expect_array(&mut dec, 2)?;
    let present = pull_bool(&mut dec)?;
    let idle_val = pull_int(&mut dec)?;
    let session_idle_secs = if present { Some(idle_val) } else { None };
    // accounts
    let acct_n = pull_array_len(&mut dec)?;
    if acct_n > MAX_ITEMS {
        return Err(cbor_err("archive CBOR: too many accounts"));
    }
    let mut accounts = Vec::with_capacity(acct_n.min(4096));
    for _ in 0..acct_n {
        accounts.push(decode_account(&mut dec)?);
    }
    // devices
    let dev_n = pull_array_len(&mut dec)?;
    if dev_n > MAX_ITEMS {
        return Err(cbor_err("archive CBOR: too many devices"));
    }
    let mut devices = Vec::with_capacity(dev_n.min(64));
    for _ in 0..dev_n {
        expect_array(&mut dec, 3)?;
        let device_id = pull_array32(&mut dec)?;
        let label = pull_text(&mut dec)?;
        let added_at_ms = pull_int(&mut dec)?;
        devices.push(ArchivedDevice {
            device_id,
            label,
            added_at_ms,
        });
    }
    Ok(ArchiveSnapshot {
        schema_version,
        exported_at,
        source_device_id,
        vault_id,
        session_idle_secs,
        accounts,
        devices,
    })
}

// ---------------------------------------------------------------------
// Seal / open
// ---------------------------------------------------------------------

/// Build a complete encrypted archive.
///
/// Derives the archive key from `passphrase` + a fresh random salt
/// (Argon2id, `KdfParams::RECOMMENDED`), AEAD-seals the CBOR `plaintext`
/// with the header as AAD, and assembles `header || ciphertext`.
///
/// # Errors
///
/// [`StoreError::Validation`] with `kind = "export_internal"` on a
/// crypto failure (should not happen with valid inputs).
pub fn seal_archive(passphrase: &SecretBytes, plaintext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let salt = KdfSalt::random();
    let params = KdfParams::RECOMMENDED;
    let key = derive_key(passphrase, &salt, &params).map_err(|_| StoreError::Validation {
        kind: "export_internal".into(),
        message: "archive key derivation failed".into(),
    })?;
    let nonce = Nonce::random();
    // Build the header with ct_len = 0 first to compute the AAD bytes,
    // then re-emit with the real ct_len AND re-seal — actually we need
    // ct_len in the AAD, so: ct_len = plaintext.len() + TAG_LEN (16).
    let ct_len_guess = u64::try_from(plaintext.len())
        .ok()
        .and_then(|n| n.checked_add(16))
        .ok_or_else(|| StoreError::Validation {
            kind: "export_internal".into(),
            message: "archive too large".into(),
        })?;
    let header = ArchiveHeader {
        format_version: ARCHIVE_FORMAT_VERSION,
        kdf_algo_id: KDF_ALGO_ARGON2ID,
        kdf_params: params,
        salt,
        nonce,
        ct_len: ct_len_guess,
    };
    let aad = header.to_bytes();
    let ct = key
        .seal(&nonce, plaintext, &aad)
        .map_err(|_| StoreError::Validation {
            kind: "export_internal".into(),
            message: "archive sealing failed".into(),
        })?;
    // ct.len() should equal ct_len_guess; if not (paranoia), rebuild.
    let ct_bytes = ct.into_vec();
    debug_assert_eq!(u64::try_from(ct_bytes.len()).unwrap_or(0), ct_len_guess);
    let mut out = Vec::with_capacity(ARCHIVE_HEADER_LEN + ct_bytes.len());
    out.extend_from_slice(&aad);
    out.extend_from_slice(&ct_bytes);
    Ok(Zeroizing::new(out))
}

/// Parse + decrypt + CBOR-decode an encrypted archive.
///
/// A wrong passphrase and a tampered archive both surface as
/// [`StoreError::Validation`] with `kind = "export_credentials"` — one
/// error, no oracle.
///
/// # Errors
///
/// - `kind = "export_format"` for a malformed header / CBOR / unknown
///   version.
/// - `kind = "export_credentials"` for a wrong passphrase or any
///   authentication failure (tampered bytes).
/// - `kind = "export_internal"` on a KDF failure.
pub fn decode_archive(bytes: &[u8], passphrase: &SecretBytes) -> Result<ArchiveSnapshot> {
    let (header, ct_region) = ArchiveHeader::parse(bytes)?;
    let key = derive_key(passphrase, &header.salt, &header.kdf_params).map_err(|_| {
        StoreError::Validation {
            kind: "export_internal".into(),
            message: "archive key derivation failed".into(),
        }
    })?;
    let aad = header.to_bytes();
    let ct = Ciphertext::from_vec(ct_region.to_vec());
    let plain =
        Zeroizing::new(
            key.open(&header.nonce, &ct, &aad)
                .map_err(|_| StoreError::Validation {
                    kind: "export_credentials".into(),
                    message: "wrong export passphrase, or the archive is corrupt".into(),
                })?,
        );
    decode_snapshot(&plain)
}

// ---------------------------------------------------------------------
// Plaintext (`--plaintext`) serialization
// ---------------------------------------------------------------------

/// Best-effort UTF-8 view of `s` with JSON-string-style escaping.
fn json_esc(s: &[u8]) -> String {
    use core::fmt::Write as _;
    let text = String::from_utf8_lossy(s);
    let mut o = String::with_capacity(text.len() + 2);
    for ch in text.chars() {
        match ch {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(o, "\\u{:04x}", c as u32);
            }
            c => o.push(c),
        }
    }
    o
}

/// Lowercase-hex of a 32-byte id.
fn hex32(b: &[u8; 32]) -> String {
    use core::fmt::Write as _;
    let mut s = String::with_capacity(64);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

/// Render a JSON-ish array of escaped strings (`[ "a", "b" ]`).
fn json_str_array(items: &[SecretBytes]) -> String {
    let mut o = String::from("[");
    for (j, v) in items.iter().enumerate() {
        if j > 0 {
            o.push_str(", ");
        }
        o.push('"');
        o.push_str(&json_esc(v.expose()));
        o.push('"');
    }
    o.push(']');
    o
}

/// Render one account block for [`render_plaintext`].
fn render_plaintext_account(out: &mut String, a: &ArchivedAccount) {
    use core::fmt::Write as _;
    let _ = writeln!(out, "      \"account_id\": \"{}\",", hex32(&a.account_id));
    let _ = writeln!(out, "      \"created_at_ms\": {},", a.created_at_ms);
    let _ = writeln!(
        out,
        "      \"display_name\": \"{}\",",
        json_esc(a.display_name.expose())
    );
    let _ = writeln!(out, "      \"tags\": {},", json_str_array(&a.tags));
    let _ = writeln!(out, "      \"urls\": {},", json_str_array(&a.urls));
    let _ = writeln!(
        out,
        "      \"usernames\": {},",
        json_str_array(&a.usernames)
    );
    let _ = writeln!(out, "      \"notes\": \"{}\",", json_esc(a.notes.expose()));
    out.push_str("      \"password_history\": [\n");
    for (j, e) in a.password_history.iter().enumerate() {
        let sep = if j + 1 < a.password_history.len() {
            ","
        } else {
            ""
        };
        let _ = writeln!(
            out,
            "        {{ \"password\": \"{}\", \"set_at_ms\": {}, \"originating_device\": \"{}\" }}{sep}",
            json_esc(e.password.expose()),
            e.set_at_ms,
            hex32(&e.originating_device.0)
        );
    }
    out.push_str("      ],\n");
    let _ = writeln!(
        out,
        "      \"totp_secret\": \"{}\",",
        json_esc(a.totp_secret.expose())
    );
    let _ = writeln!(
        out,
        "      \"totp_params\": {{ \"algorithm\": \"{}\", \"digits\": {}, \"period_seconds\": {} }}",
        a.totp_params.algorithm.as_str(),
        a.totp_params.digits,
        a.totp_params.period_seconds
    );
}

/// Render the snapshot as an unmistakable cleartext document — JSON-like,
/// with a loud in-file banner. **Every secret is in cleartext.** No KDF,
/// no AEAD.
#[must_use]
pub fn render_plaintext(snap: &ArchiveSnapshot) -> Zeroizing<Vec<u8>> {
    use core::fmt::Write as _;
    let mut out = String::with_capacity(4096);
    let _ = writeln!(out, "// {PLAINTEXT_EXPORT_BANNER}");
    out.push_str("// Anyone who can read this file can read every password in your vault.\n");
    out.push_str("// Store it nowhere; delete it as soon as you no longer need it.\n");
    out.push_str("{\n");
    let _ = writeln!(out, "  \"WARNING\": \"{PLAINTEXT_EXPORT_BANNER}\",");
    let _ = writeln!(out, "  \"schema_version\": {},", snap.schema_version);
    let _ = writeln!(out, "  \"exported_at\": {},", snap.exported_at);
    let _ = writeln!(
        out,
        "  \"source_device_id\": \"{}\",",
        hex32(&snap.source_device_id)
    );
    let _ = writeln!(out, "  \"vault_id\": \"{}\",", hex32(&snap.vault_id));
    let _ = writeln!(
        out,
        "  \"session_idle_secs\": {},",
        snap.session_idle_secs
            .map_or_else(|| "null".to_string(), |v| v.to_string())
    );
    out.push_str("  \"accounts\": [\n");
    for (i, a) in snap.accounts.iter().enumerate() {
        out.push_str("    {\n");
        render_plaintext_account(&mut out, a);
        out.push_str(if i + 1 < snap.accounts.len() {
            "    },\n"
        } else {
            "    }\n"
        });
    }
    out.push_str("  ],\n");
    out.push_str("  \"devices\": [\n");
    for (i, d) in snap.devices.iter().enumerate() {
        let sep = if i + 1 < snap.devices.len() { "," } else { "" };
        let _ = writeln!(
            out,
            "    {{ \"device_id\": \"{}\", \"label\": \"{}\", \"added_at_ms\": {} }}{sep}",
            hex32(&d.device_id),
            json_esc(d.label.as_bytes()),
            d.added_at_ms
        );
    }
    out.push_str("  ]\n");
    out.push_str("}\n");
    Zeroizing::new(out.into_bytes())
}

// ---------------------------------------------------------------------

fn fmt_err(msg: &str) -> StoreError {
    StoreError::Validation {
        kind: "export_format".into(),
        message: msg.into(),
    }
}

/// Selection of which accounts to include in an export.
#[derive(Debug, Clone, Default)]
pub enum AccountSelection {
    /// Every (non-tombstoned) account — the full move-to-new-device
    /// backup.
    #[default]
    All,
    /// Only the listed account ids.
    Subset(Vec<[u8; 32]>),
}

impl AccountSelection {
    /// Whether `id` is in this selection.
    #[must_use]
    pub fn includes(&self, id: &[u8; 32]) -> bool {
        match self {
            Self::All => true,
            Self::Subset(ids) => ids.iter().any(|x| x == id),
        }
    }
}

/// A single-use confirmation token for the plaintext-export path. The
/// FFI requires a structurally-valid (non-empty) token; the CLI/UI owns
/// the double-confirmation + 30 s delay + warning copy.
#[derive(Debug, Clone)]
pub struct PlaintextExportConfirmationData {
    /// Schema version of the confirmation record.
    pub schema_version: u16,
    /// Opaque single-use token captured at the moment of confirmation.
    pub token: Vec<u8>,
}

impl PlaintextExportConfirmationData {
    /// Whether the token is structurally valid (non-empty).
    #[must_use]
    pub fn is_valid(&self) -> bool {
        !self.token.is_empty()
    }
}

const _DEVICE_ID_LEN_CHECK: usize = DEVICE_ID_LEN;

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ArchiveSnapshot {
        ArchiveSnapshot {
            schema_version: ARCHIVE_SNAPSHOT_SCHEMA_VERSION,
            exported_at: 1_700_000_000,
            source_device_id: [7u8; 32],
            vault_id: [9u8; 32],
            session_idle_secs: Some(900),
            accounts: vec![ArchivedAccount {
                account_id: [1u8; 32],
                created_at_ms: 1_600_000_000_000,
                display_name: SecretBytes::new(b"GitHub".to_vec()),
                tags: vec![SecretBytes::new(b"work".to_vec())],
                urls: vec![SecretBytes::new(b"https://github.com".to_vec())],
                usernames: vec![SecretBytes::new(b"octocat".to_vec())],
                notes: SecretBytes::new(b"recovery: hunter2".to_vec()),
                password_history: vec![
                    ArchivedPasswordEntry {
                        password: SecretBytes::new(b"new-pw".to_vec()),
                        set_at_ms: 1_650_000_000_000,
                        originating_device: DeviceId([2u8; 32]),
                    },
                    ArchivedPasswordEntry {
                        password: SecretBytes::new(b"old-pw".to_vec()),
                        set_at_ms: 1_600_000_000_000,
                        originating_device: DeviceId([3u8; 32]),
                    },
                ],
                totp_secret: SecretBytes::new(b"JBSWY3DPEHPK3PXP".to_vec()),
                totp_params: TotpParams::default(),
            }],
            devices: vec![ArchivedDevice {
                device_id: [2u8; 32],
                label: "laptop".into(),
                added_at_ms: 1_600_000_000_000,
            }],
        }
    }

    #[test]
    fn cbor_round_trip() {
        let s = sample();
        let bytes = encode_snapshot(&s);
        let back = decode_snapshot(&bytes).expect("decode");
        assert_eq!(back.schema_version, s.schema_version);
        assert_eq!(back.exported_at, s.exported_at);
        assert_eq!(back.source_device_id, s.source_device_id);
        assert_eq!(back.vault_id, s.vault_id);
        assert_eq!(back.session_idle_secs, s.session_idle_secs);
        assert_eq!(back.accounts.len(), 1);
        let a = &back.accounts[0];
        assert_eq!(a.account_id, [1u8; 32]);
        assert_eq!(a.display_name.expose(), b"GitHub");
        assert_eq!(a.password_history.len(), 2);
        assert_eq!(a.password_history[0].password.expose(), b"new-pw");
        assert_eq!(a.password_history[1].originating_device.0, [3u8; 32]);
        assert_eq!(back.devices.len(), 1);
        assert_eq!(back.devices[0].label, "laptop");
    }

    #[test]
    fn seal_open_round_trip() {
        let s = sample();
        let plain = encode_snapshot(&s);
        let pw = SecretBytes::new(b"a-strong-export-passphrase".to_vec());
        let archive = seal_archive(&pw, &plain).expect("seal");
        // Header parses.
        let (h, _) = ArchiveHeader::parse(&archive).expect("parse header");
        assert_eq!(h.format_version, ARCHIVE_FORMAT_VERSION);
        let back = decode_archive(&archive, &pw).expect("decode");
        assert_eq!(
            back.accounts[0].password_history[0].password.expose(),
            b"new-pw"
        );
    }

    #[test]
    fn wrong_passphrase_no_oracle() {
        let s = sample();
        let plain = encode_snapshot(&s);
        let pw = SecretBytes::new(b"correct".to_vec());
        let archive = seal_archive(&pw, &plain).expect("seal");
        let bad = SecretBytes::new(b"wrong".to_vec());
        let err = decode_archive(&archive, &bad).unwrap_err();
        match err {
            StoreError::Validation { kind, .. } => assert_eq!(kind, "export_credentials"),
            other => panic!("unexpected: {other:?}"),
        }
        // Tampered ciphertext byte → same error variant.
        let mut tampered = archive.to_vec();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        let err2 = decode_archive(&tampered, &pw).unwrap_err();
        match err2 {
            StoreError::Validation { kind, .. } => assert_eq!(kind, "export_credentials"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn tampered_header_byte_fails_auth() {
        let s = sample();
        let plain = encode_snapshot(&s);
        let pw = SecretBytes::new(b"pw".to_vec());
        let archive = seal_archive(&pw, &plain).expect("seal");
        // Flip a salt byte (in-AAD): the header still parses but the
        // open fails authentication.
        let mut t = archive.to_vec();
        // salt starts at magic(12)+1+1+4+4+4 = 26
        t[26] ^= 0x01;
        let err = decode_archive(&t, &pw).unwrap_err();
        match err {
            StoreError::Validation { kind, .. } => assert_eq!(kind, "export_credentials"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn hostile_header_rejected_before_kdf() {
        let s = sample();
        let plain = encode_snapshot(&s);
        let pw = SecretBytes::new(b"pw".to_vec());
        let archive = seal_archive(&pw, &plain).expect("seal");
        // Header offsets: magic(12) + format_version(1) + kdf_algo(1) =>
        // memory_kib at 14..18, time_cost at 18..22, parallelism at 22..26.
        let expect_export_format = |bytes: &[u8]| match decode_archive(bytes, &pw) {
            Err(StoreError::Validation { kind, .. }) => assert_eq!(kind, "export_format"),
            other => panic!("unexpected: {other:?}"),
        };

        // (a) memory_kib = 64 GiB → over MAX_KDF_MEMORY_KIB.
        let mut t = archive.to_vec();
        t[14..18].copy_from_slice(&(64u32 * 1024 * 1024).to_be_bytes());
        expect_export_format(&t);

        // (b) time_cost = 9 → over MAX_KDF_TIME_COST (8).
        let mut t = archive.to_vec();
        t[18..22].copy_from_slice(&9u32.to_be_bytes());
        expect_export_format(&t);

        // (c) parallelism = 9 → over MAX_KDF_PARALLELISM (8).
        let mut t = archive.to_vec();
        t[22..26].copy_from_slice(&9u32.to_be_bytes());
        expect_export_format(&t);

        // (d) memory_kib = 1 GiB, time_cost = 8 — each axis is at its
        //     individual ceiling, but the product (8 Gi) blows the
        //     combined memory×time-cost cap.
        let mut t = archive.to_vec();
        t[14..18].copy_from_slice(&(1024u32 * 1024).to_be_bytes());
        t[18..22].copy_from_slice(&8u32.to_be_bytes());
        expect_export_format(&t);

        // The unmodified archive uses KdfParams::RECOMMENDED — its params
        // pass the clamp (a Pangolin-produced archive must always decode).
        // We only assert the clamp accepts them, without running the real
        // (expensive) Argon2 derive here; the full round-trip through
        // decode_archive is covered by `export_decode_restore_round_trip`.
        let (parsed, _ct) = ArchiveHeader::parse(&archive).expect("RECOMMENDED params accepted");
        assert_eq!(parsed.kdf_params, KdfParams::RECOMMENDED);
    }

    #[test]
    fn truncated_and_bad_magic() {
        assert!(ArchiveHeader::parse(b"too short").is_err());
        let mut junk = vec![0u8; ARCHIVE_HEADER_LEN + 16];
        junk[..12].copy_from_slice(b"NOTPANGOLIN!");
        assert!(ArchiveHeader::parse(&junk).is_err());
    }

    #[test]
    fn plaintext_render_contains_secrets_and_banner() {
        let s = sample();
        let txt = render_plaintext(&s);
        let body = String::from_utf8(txt.to_vec()).unwrap();
        assert!(body.contains(PLAINTEXT_EXPORT_BANNER));
        assert!(body.contains("new-pw"));
        assert!(body.contains("octocat"));
        assert!(body.contains("recovery: hunter2"));
    }
}
