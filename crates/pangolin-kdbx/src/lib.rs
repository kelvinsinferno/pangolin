// SPDX-License-Identifier: AGPL-3.0-or-later
//! Hand-rolled, read-only KDBX (`KeePass` 2.x) parser and a mapping
//! layer from `KeePassXC` entries onto Pangolin's `AccountIdentity`
//! draft shape.
//!
//! Per MVP-1 issue 1.9 (and §16.8 footnote 2 of the master plan), this
//! crate is a **leaf** depended on only by `pangolin-ffi` and the CLI:
//! the XML / gzip / KDBX-container dependency surface never reaches
//! `pangolin-core` / `pangolin-crypto`, and the per-crate
//! `forbid(unsafe_code)` keeps a parser bug blast-contained. The
//! KDF/cipher primitives are the same audited RustCrypto crates
//! `pangolin-crypto` already vendors; only the container-format glue
//! (headers, `VariantDict`, block-MAC framing, inner-random-stream
//! un-masking, gzip'd XML) is ours.
//!
//! # Scope
//!
//! - KDBX **3.1** — AES-KDF; AES-256-CBC outer cipher; Salsa20 inner
//!   random stream; stream-start-bytes integrity check.
//! - KDBX **4.x** — Argon2d/Argon2id KDF (params from the
//!   `VariantDict`); AES-256-CBC or ChaCha20 outer cipher; HMAC-SHA256
//!   block-MAC; gzip'd XML inner payload; ChaCha20 inner random stream.
//! - Credentials: a master password and/or a keyfile (raw-32 / 64-hex /
//!   `.keyx` XML / arbitrary-file-hash). A hardware-challenge-response
//!   database → [`KdbxError::UnsupportedCredential`] (no YubiKey CR).
//! - KDBX 1.x / 2.x → [`KdbxError::UnsupportedVersion`].
//!
//! # Secret discipline
//!
//! Every parsed password / TOTP seed / notes value stays in
//! [`zeroize::Zeroizing`]; secret-bearing types redact their `Debug`;
//! no error / log line ever echoes secret bytes, entry titles or
//! usernames.

#![cfg_attr(not(test), forbid(unsafe_code))]
// The container-format parsing here is inherently long-ish and arithmetic-
// heavy (TLV walks, byte/length juggling). The workspace `pedantic` /
// `nursery` groups are `warn`; CI promotes them with `-D warnings`. We
// allow the genuinely-noisy ones at the crate scope rather than
// peppering the parser with attributes — the security-relevant lints
// (`unsafe_code` is `forbid`'d, the `clippy::all` correctness group is
// untouched) still apply.
#![allow(
    clippy::doc_markdown,
    clippy::too_many_lines,
    clippy::too_many_arguments,
    clippy::manual_let_else,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::cast_lossless,
    clippy::similar_names,
    clippy::redundant_pub_crate,
    clippy::struct_field_names,
    clippy::if_not_else,
    clippy::match_same_arms,
    clippy::manual_is_multiple_of,
    clippy::format_push_string,
    clippy::missing_panics_doc,
    clippy::wildcard_imports,
    clippy::needless_pass_by_value,
    clippy::items_after_statements,
    clippy::single_match_else,
    clippy::option_if_let_else,
    clippy::unnested_or_patterns,
    clippy::large_stack_arrays,
    clippy::missing_fields_in_debug,
    clippy::ref_option
)]

mod crypto;
mod error;
mod header;
mod kdf;
mod map;
mod payload;
mod read;
mod xml;

/// A self-contained KDBX 3.1 / 4.x **encoder** for building fixture
/// `.kdbx` byte streams in tests. Behind the `test-writer` feature;
/// not part of the production surface. (Lint allows for the encoder
/// live in its own module-level inner attribute block.)
#[cfg(feature = "test-writer")]
pub mod test_writer;

pub use error::KdbxError;
pub use map::{map_database, EntrySkip, MapResult, MappedEntry};
pub use read::{read_kdbx, KdbxCredentials, KdbxDatabase, KdbxEntry, KdbxStringValue};

use zeroize::Zeroizing;

/// Re-export so consumers can normalise/feed TOTP themselves if needed.
pub use pangolin_totp;

/// Hard ceiling on entries we will ever materialise from a single file —
/// bounds memory against a hostile entry count. Well past the
/// 500-entry MVP-1 exit criterion.
pub const KDBX_MAX_ENTRIES: usize = 100_000;

/// Hard ceiling on the inflated inner-XML payload — refuse to inflate a
/// gzip bomb past this many bytes. 256 MiB.
pub const KDBX_MAX_INFLATED_BYTES: usize = 256 * 1024 * 1024;

/// Hard ceiling on the raw input file we will even attempt to parse.
/// 64 MiB — a KeePass DB that large is pathological.
pub const KDBX_MAX_FILE_BYTES: usize = 64 * 1024 * 1024;

/// Cap on imported historical passwords per entry (Q-d). Bounds
/// revision-count blow-up on a pathological `<History>`.
pub const KDBX_MAX_HISTORY_PER_ENTRY: usize = 64;

/// Returns the crate name. Diagnostic; not part of the public surface.
#[must_use]
pub fn name() -> &'static str {
    "pangolin-kdbx"
}

/// A `Zeroizing<Vec<u8>>` alias used throughout for transient secret
/// material that must wipe on drop.
pub(crate) type Secret = Zeroizing<Vec<u8>>;

/// Read a `.kdbx` file's bytes from `path`, refusing pathologically
/// large files up front.
///
/// # Errors
/// [`KdbxError::Io`] on a read error; [`KdbxError::FileTooLarge`] if
/// the file exceeds [`KDBX_MAX_FILE_BYTES`].
pub fn read_kdbx_file(path: &std::path::Path) -> Result<Vec<u8>, KdbxError> {
    let meta = std::fs::metadata(path).map_err(|e| KdbxError::Io(e.to_string()))?;
    if meta.len() > KDBX_MAX_FILE_BYTES as u64 {
        return Err(KdbxError::FileTooLarge {
            len: meta.len(),
            max: KDBX_MAX_FILE_BYTES as u64,
        });
    }
    std::fs::read(path).map_err(|e| KdbxError::Io(e.to_string()))
}

/// One-shot helper: read the file, parse + decrypt with the given
/// credentials, and map every entry to a [`MappedEntry`].
///
/// # Errors
/// Any [`KdbxError`] from the file read, the container parse, the
/// decryption (all credential failures collapse to
/// [`KdbxError::WrongCredentials`]), or the XML walk. Per-entry mapping
/// failures are *not* errors — they appear as [`EntrySkip`] entries in
/// the returned [`MapResult`]'s skip list.
pub fn import_kdbx_path(
    path: &std::path::Path,
    creds: &KdbxCredentials,
) -> Result<MapResult, KdbxError> {
    let bytes = read_kdbx_file(path)?;
    let db = read_kdbx(
        &bytes,
        creds.password.as_ref(),
        creds.keyfile.as_ref().map(|z| z.as_slice()),
    )?;
    Ok(map_database(&db))
}

#[cfg(test)]
mod tests {
    use super::name;

    #[test]
    fn crate_name_is_set() {
        assert_eq!(name(), "pangolin-kdbx");
    }
}
