// SPDX-License-Identifier: AGPL-3.0-or-later
//! KDBX parser error taxonomy.
//!
//! None of these variants' `Debug` / `Display` ever echoes secret
//! bytes, entry titles, usernames, or the master password — only
//! non-secret category labels and structural facts (lengths, version
//! words, KDF/cipher UUIDs).

/// Errors from the hand-rolled KDBX reader and the mapping layer.
///
/// Wrong-password **and** wrong/missing-keyfile **and** bad block-MAC
/// all collapse to [`KdbxError::WrongCredentials`] — there is no
/// decryption oracle.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum KdbxError {
    /// An OS-level I/O error reading the file (message is the OS string,
    /// never file *contents*).
    #[error("I/O error: {0}")]
    Io(String),

    /// The input does not begin with the KDBX magic signature.
    #[error("not a KDBX file (bad magic)")]
    NotKdbx,

    /// A KDBX 1.x / 2.x file, or a major/minor version this reader does
    /// not implement.
    #[error("unsupported KDBX version {major}.{minor}")]
    UnsupportedVersion {
        /// The major version word.
        major: u16,
        /// The minor version word.
        minor: u16,
    },

    /// The input is too large to parse safely.
    #[error("file too large ({len} bytes, max {max})")]
    FileTooLarge {
        /// Observed length.
        len: u64,
        /// Maximum allowed.
        max: u64,
    },

    /// The outer header is malformed, truncated, has a lying length
    /// field, or is missing a required field.
    #[error("corrupt KDBX header: {0}")]
    CorruptHeader(String),

    /// The decrypted/decompressed payload is malformed, truncated, or
    /// has a lying length / size field.
    #[error("corrupt KDBX payload: {0}")]
    CorruptPayload(String),

    /// A KDBX4 block's HMAC-SHA256 tag did not verify. Folded into the
    /// no-oracle [`KdbxError::WrongCredentials`] at the public boundary,
    /// kept distinct internally for tests.
    #[error("KDBX block authentication failed")]
    BlockHmacMismatch,

    /// The master password / keyfile combination did not decrypt the
    /// database (or the header-HMAC / block-MAC did not verify). One
    /// variant for every credential failure — no oracle.
    #[error("wrong password or keyfile for the KeePass database")]
    WrongCredentials,

    /// The database needs a credential type this reader does not
    /// support (hardware challenge-response, etc.).
    #[error("unsupported credential type: {0}")]
    UnsupportedCredential(String),

    /// The KDF named in the header is not implemented.
    #[error("unsupported KDF: {0}")]
    UnsupportedKdf(String),

    /// The KDF parameters are outside the sane range we will run
    /// (memory / iteration explosion).
    #[error("KDF parameters out of range: {0}")]
    KdfParamsRejected(String),

    /// The outer cipher named in the header is not implemented.
    #[error("unsupported cipher: {0}")]
    UnsupportedCipher(String),

    /// The inner-payload XML is malformed (un-parseable, entity-bomb,
    /// nesting too deep, non-UTF-8 where text is required, etc.).
    #[error("malformed KDBX XML: {0}")]
    XmlMalformed(String),

    /// The file declares (or contains) more entries than
    /// [`crate::KDBX_MAX_ENTRIES`].
    #[error("too many entries (limit {limit})")]
    TooManyEntries {
        /// The configured limit.
        limit: usize,
    },

    /// The inflated inner payload exceeded [`crate::KDBX_MAX_INFLATED_BYTES`]
    /// (gzip-bomb guard).
    #[error("inflated payload too large (limit {limit} bytes)")]
    InflatedTooLarge {
        /// The configured limit.
        limit: usize,
    },
}

impl KdbxError {
    /// A short, non-secret category label suitable for a UI / report
    /// (`failure_kinds` entry). Never contains entry data.
    #[must_use]
    pub fn kind_label(&self) -> &'static str {
        match self {
            Self::Io(_) => "io",
            Self::NotKdbx => "not_kdbx",
            Self::UnsupportedVersion { .. } => "unsupported_version",
            Self::FileTooLarge { .. } => "file_too_large",
            Self::CorruptHeader(_) => "corrupt_header",
            Self::CorruptPayload(_) => "corrupt_payload",
            Self::BlockHmacMismatch | Self::WrongCredentials => "wrong_credentials",
            Self::UnsupportedCredential(_) => "unsupported_credential",
            Self::UnsupportedKdf(_) => "unsupported_kdf",
            Self::KdfParamsRejected(_) => "kdf_params_rejected",
            Self::UnsupportedCipher(_) => "unsupported_cipher",
            Self::XmlMalformed(_) => "malformed_xml",
            Self::TooManyEntries { .. } => "too_many_entries",
            Self::InflatedTooLarge { .. } => "inflated_too_large",
        }
    }
}
