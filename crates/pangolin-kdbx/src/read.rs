// SPDX-License-Identifier: AGPL-3.0-or-later
//! Public reader surface: parse + decrypt a `.kdbx` byte buffer into a
//! [`KdbxDatabase`] of entries (with their `<History>` sub-entries).

use zeroize::Zeroizing;

use crate::crypto;
use crate::error::KdbxError;
use crate::header::{parse_outer_header, KdbxFormat};
use crate::kdf;
use crate::payload::{parse_inner_payload, InnerStream};
use crate::xml::parse_kdbx_xml;
use crate::Secret;

/// Credentials for opening a `.kdbx`. At least one of `password` /
/// `keyfile` must be present (else [`KdbxError::UnsupportedCredential`]).
///
/// Both fields wrap their bytes in [`zeroize::Zeroizing`]; `Debug` is
/// redacting.
pub struct KdbxCredentials {
    /// The master password's UTF-8 bytes, or `None` for a keyfile-only DB.
    pub password: Option<Secret>,
    /// The raw bytes of the keyfile (`.keyx` XML / 32-raw / 64-hex /
    /// arbitrary), or `None`.
    pub keyfile: Option<Secret>,
}

impl KdbxCredentials {
    /// Password-only credentials from a UTF-8 string.
    #[must_use]
    pub fn from_password(password: &str) -> Self {
        Self {
            password: Some(Zeroizing::new(password.as_bytes().to_vec())),
            keyfile: None,
        }
    }

    /// Password + keyfile.
    #[must_use]
    pub fn with_keyfile(password: Option<&str>, keyfile_bytes: Vec<u8>) -> Self {
        Self {
            password: password.map(|p| Zeroizing::new(p.as_bytes().to_vec())),
            keyfile: Some(Zeroizing::new(keyfile_bytes)),
        }
    }
}

impl core::fmt::Debug for KdbxCredentials {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KdbxCredentials")
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("keyfile", &self.keyfile.as_ref().map(|b| b.len()))
            .finish()
    }
}

/// One `<String>` Key/Value pair from a KDBX entry. `value` is held in
/// [`zeroize::Zeroizing`] (a `Protected` value's plaintext is secret;
/// even un-protected ones may be).
pub struct KdbxStringValue {
    /// The field key (`Title`, `UserName`, `Password`, `URL`, `Notes`,
    /// `otp`, `TimeOtp-*`, or a custom key).
    pub key: String,
    /// The (decoded, un-masked) value bytes.
    pub value: Secret,
    /// Whether the value carried `Protected="True"` in the XML.
    pub protected: bool,
}

impl core::fmt::Debug for KdbxStringValue {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KdbxStringValue")
            .field("key", &self.key)
            .field("value_len", &self.value.len())
            .field("protected", &self.protected)
            .finish()
    }
}

impl KdbxStringValue {
    /// The value as a UTF-8 string, lossily (KeePass values are UTF-8 in
    /// practice; a hostile non-UTF-8 value is replacement-charactered
    /// rather than dropped — the mapping layer will still skip an empty
    /// password etc.).
    #[must_use]
    pub fn as_str_lossy(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.value)
    }
}

/// `<Times>` we extract from an entry (only the bits we map).
#[derive(Debug, Default)]
pub(crate) struct KdbxTimes {
    pub expires: bool,
    pub expiry_time_raw: Option<String>,
    pub last_mod_raw: Option<String>,
}

/// One live KDBX entry (recycle-bin entries are excluded by the parser).
pub struct KdbxEntry {
    /// All `<String>` Key/Value pairs, in document order.
    pub strings: Vec<KdbxStringValue>,
    /// KeePass `<Tags>` (split on `;` / `,`).
    pub tags: Vec<String>,
    /// The group-path components (KeePass folders), excluding `Root`.
    pub group_path: Vec<String>,
    /// `<Times><Expires>`.
    pub expires: bool,
    /// `<Times><ExpiryTime>` as a Unix timestamp, if parseable.
    pub expiry_time_unix: Option<i64>,
    /// Historical `Password` values from `<History>`, with their
    /// `LastModificationTime` (Unix seconds) where parseable, in
    /// document order (KeePass writes them oldest-first).
    pub history_passwords: Vec<(Secret, Option<i64>)>,
}

impl core::fmt::Debug for KdbxEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KdbxEntry")
            .field("string_count", &self.strings.len())
            .field("tags", &self.tags)
            .field("group_path", &self.group_path)
            .field("expires", &self.expires)
            .field("history_len", &self.history_passwords.len())
            .finish()
    }
}

impl KdbxEntry {
    /// Look up the first `<String>` value for `key`.
    #[must_use]
    pub fn field(&self, key: &str) -> Option<&KdbxStringValue> {
        self.strings.iter().find(|s| s.key == key)
    }
}

/// A parsed + decrypted KDBX database (just the entries we care about).
pub struct KdbxDatabase {
    /// KDBX 3.1 or 4.x.
    pub format_v4: bool,
    /// All live entries.
    pub entries: Vec<KdbxEntry>,
    /// Number of entries skipped because they were in the recycle bin.
    pub recycle_bin_entries: usize,
    /// Number of (dropped) binary attachments declared in the inner
    /// header — used only for a redacted note. KDBX3 attachments live in
    /// `<Meta><Binaries>` which we do not parse; they appear as `0` for
    /// KDBX3 (their bytes are still never touched).
    pub binary_count: usize,
    /// Total size of the (dropped) binary attachments, in bytes.
    pub binary_total_bytes: usize,
}

impl core::fmt::Debug for KdbxDatabase {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KdbxDatabase")
            .field("format_v4", &self.format_v4)
            .field("entry_count", &self.entries.len())
            .field("recycle_bin_entries", &self.recycle_bin_entries)
            .field("binary_count", &self.binary_count)
            .finish()
    }
}

/// Parse + decrypt a `.kdbx` byte buffer.
///
/// `password` / `keyfile` follow the [`KdbxCredentials`] semantics. All
/// credential failures (wrong password, wrong/missing keyfile, bad
/// block-MAC, bad header-HMAC, bad stream-start-bytes) collapse to
/// [`KdbxError::WrongCredentials`] — no decryption oracle.
///
/// # Errors
/// Any [`KdbxError`].
pub fn read_kdbx(
    bytes: &[u8],
    password: Option<&Secret>,
    keyfile: Option<&[u8]>,
) -> Result<KdbxDatabase, KdbxError> {
    if bytes.len() > crate::KDBX_MAX_FILE_BYTES {
        return Err(KdbxError::FileTooLarge {
            len: bytes.len() as u64,
            max: crate::KDBX_MAX_FILE_BYTES as u64,
        });
    }
    let header = parse_outer_header(bytes)?;
    let composite = kdf::composite_key(password.map(|p| p.as_slice()), keyfile)?;

    let after_header = bytes
        .get(header.header_len..)
        .ok_or_else(|| KdbxError::CorruptHeader("no payload after header".into()))?;

    let (decrypted, format_v4): (Secret, bool) = match header.format {
        KdbxFormat::V3 => (
            crypto::decrypt_kdbx3_payload(&header, &composite, after_header)
                .map_err(fold_oracle)?,
            false,
        ),
        KdbxFormat::V4 => (
            crypto::decrypt_kdbx4_payload(&header, &composite, after_header)
                .map_err(fold_oracle)?,
            true,
        ),
    };

    let inner = parse_inner_payload(&header, &decrypted)?;
    let mut stream = InnerStream::new(inner.inner_stream_cipher, &inner.inner_stream_key)?;
    let parsed = parse_kdbx_xml(&inner.xml, &mut stream)?;

    Ok(KdbxDatabase {
        format_v4,
        entries: parsed.entries,
        recycle_bin_entries: parsed.recycle_bin_entries,
        binary_count: inner.binary_count,
        binary_total_bytes: inner.binary_total_bytes,
    })
}

/// Fold the internal `BlockHmacMismatch` into the no-oracle
/// `WrongCredentials` at the public boundary.
fn fold_oracle(e: KdbxError) -> KdbxError {
    match e {
        KdbxError::BlockHmacMismatch => KdbxError::WrongCredentials,
        other => other,
    }
}
