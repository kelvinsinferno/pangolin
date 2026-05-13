// SPDX-License-Identifier: AGPL-3.0-or-later
//! KDBX-import FFI shape (MVP-1 issue 1.9), backed by `pangolin-kdbx`.
//!
//! 1.9 implements the 1.1-frozen `kdbx_import` body — the one additive
//! amendment (per `docs/issue-plans/1.9.md` L11/L13) is the optional
//! `keyfile_path: Option<String>` argument; the `KdbxImportReport`
//! Record stays frozen. The `pangolin-kdbx` reader + mapper produce
//! plain owned drafts; the store-side ingestion loop lives **here**
//! (`pangolin-store` gains no `pangolin-kdbx` dep — HIGH-1 /
//! uniffi-isolation invariants).
//!
//! **MVP-1 issue 1.11 cleanup.** The 1.1 scaffold parked the
//! `CaptureAuthority` / `CaptureContext` placeholders + the
//! `capture_authority_register` entry-point declaration in this file
//! because the 1.1 freeze hadn't yet decided where they belonged. 1.11
//! finalises the shapes and moves them to a dedicated
//! [`crate::capture_authority`] module — these types don't belong
//! with the KDBX import surface. `lib.rs` re-exports are updated to
//! match.

use std::sync::Arc;

use zeroize::Zeroize as _;

use crate::error::FfiError;
use crate::session::{SecretPassword, VaultHandle};

/// Schema-version slot value for `KdbxImportReport`. Matches the
/// account-identity schema (`1`).
const KDBX_REPORT_SCHEMA_VERSION: u16 = pangolin_core::ACCOUNT_IDENTITY_SCHEMA_VERSION;

/// Per-account import outcome (errors carry a UI-safe category label).
#[derive(Debug, Clone, uniffi::Record)]
pub struct KdbxImportReport {
    /// Issue 1.1 schema-version slot.
    pub schema_version: u16,
    /// Number of accounts imported successfully.
    pub imported: u32,
    /// Number of accounts skipped (e.g., recycle-bin entries, entries
    /// with no password).
    pub skipped: u32,
    /// Number of accounts whose import failed (validation rejection on
    /// `Vault::account_add`).
    pub failed: u32,
    /// Per-failure category labels (non-secret; never entry data). Safe
    /// to render.
    pub failure_kinds: Vec<String>,
}

// -- Locked-in-1.1 entry points ---------------------------------------

/// Import a KDBX (`KeePass` 2.x) file into an unlocked vault.
///
/// Reads `path`'s bytes, parses + decrypts with `kdbx_password` (+ the
/// optional `keyfile_path`), and ingests every mapped entry via
/// `Vault::account_add`, replaying each entry's `<History>` password
/// trail via `account_update`. Returns a [`KdbxImportReport`]. The KDBX
/// master password bytes are zeroized after the KDF consumes them.
///
/// # Errors
/// - [`FfiError::Session`] if the vault is locked.
/// - [`FfiError::Validation`] with `kind = "kdbx_credentials"` on a
///   wrong password / wrong-or-missing keyfile (no oracle), `kind =
///   "kdbx_format"` on a corrupt / unsupported / not-KDBX file, `kind =
///   "kdbx_unsupported_credential"` for a hardware-CR-protected DB,
///   `kind = "kdbx_too_large"` / `"kdbx_io"` for the size / I/O guards.
#[allow(clippy::significant_drop_tightening, clippy::needless_pass_by_value)]
#[uniffi::export]
pub fn kdbx_import(
    handle: Arc<VaultHandle>,
    path: String,
    kdbx_password: Arc<SecretPassword>,
    keyfile_path: Option<String>,
) -> Result<KdbxImportReport, FfiError> {
    // Parse + decrypt + map up front — a failure here fails the whole
    // import (nothing written to the vault yet).
    let mut pw_bytes = zeroize::Zeroizing::new(kdbx_password.bytes_for_bridge().to_vec());
    let creds = match &keyfile_path {
        Some(kp) => {
            // Cap the keyfile size before reading it — a realistic
            // keyfile is at most a few KiB; reuse the `.kdbx` ceiling so
            // a multi-GB path can't OOM us. Fold a too-large keyfile into
            // the no-oracle credentials error (it must not be a
            // credential oracle).
            if let Ok(meta) = std::fs::metadata(kp) {
                if meta.len() > pangolin_kdbx::KDBX_MAX_FILE_BYTES as u64 {
                    pw_bytes.zeroize();
                    return Err(FfiError::Validation {
                        kind: "kdbx_credentials".into(),
                        message: "wrong password or keyfile for the KeePass database".into(),
                    });
                }
            }
            let mut kf = std::fs::read(kp).map_err(|e| FfiError::Validation {
                kind: "kdbx_io".into(),
                message: format!("could not read keyfile: {e}"),
            })?;
            let creds = pangolin_kdbx::KdbxCredentials {
                password: if pw_bytes.is_empty() {
                    None
                } else {
                    Some(zeroize::Zeroizing::new(pw_bytes.to_vec()))
                },
                keyfile: Some(zeroize::Zeroizing::new(kf.clone())),
            };
            kf.zeroize();
            creds
        }
        None => pangolin_kdbx::KdbxCredentials {
            password: Some(zeroize::Zeroizing::new(pw_bytes.to_vec())),
            keyfile: None,
        },
    };
    let map_result =
        pangolin_kdbx::import_kdbx_path(std::path::Path::new(&path), &creds).map_err(map_kdbx_err);
    // Zeroize the password copies regardless of outcome.
    pw_bytes.zeroize();
    drop(creds);
    let map_result = map_result?;

    // Now ingest into the (unlocked) vault.
    let mut guard = handle.lock_vault();
    let vault = guard.as_mut()?;

    let mut imported: u32 = 0;
    let mut failed: u32 = 0;
    let mut skipped: u32 = u32::try_from(map_result.recycle_bin_entries).unwrap_or(u32::MAX);
    let mut failure_kinds: Vec<String> = Vec::new();
    for s in &map_result.skipped {
        skipped = skipped.saturating_add(1);
        push_kind(&mut failure_kinds, s.kind_label());
    }

    for entry in map_result.entries {
        match ingest_one(vault, entry) {
            Ok(()) => imported = imported.saturating_add(1),
            Err(e) => {
                failed = failed.saturating_add(1);
                push_kind(&mut failure_kinds, &kind_of(&e));
            }
        }
    }

    Ok(KdbxImportReport {
        schema_version: KDBX_REPORT_SCHEMA_VERSION,
        imported,
        skipped,
        failed,
        failure_kinds,
    })
}

/// Ingest one mapped entry: `account_add` the current state, then replay
/// the historical passwords (oldest→newest) so they land in Pangolin's
/// password-history slot.
fn ingest_one(
    vault: &mut pangolin_core::Vault,
    entry: pangolin_kdbx::MappedEntry,
) -> Result<(), pangolin_store::StoreError> {
    use pangolin_crypto::secret::SecretBytes;

    let pangolin_kdbx::MappedEntry {
        display_name,
        usernames,
        urls,
        notes,
        password,
        totp,
        tags,
        history_passwords,
    } = entry;

    let (totp_secret, totp_params) = match totp {
        // `pangolin_kdbx`'s `ParsedTotpSecret` reuses `pangolin_totp`'s
        // `TotpParams`, which is the same type `pangolin_core` re-exports.
        Some(t) => (SecretBytes::new(t.secret_bytes.to_vec()), t.params),
        None => (
            SecretBytes::new(Vec::new()),
            pangolin_core::TotpParams::default(),
        ),
    };

    // If there is history, install the OLDEST historical password as the
    // genesis and replay the remaining historical passwords forward;
    // otherwise install the current password directly. `account_update`
    // with a new password moves the prior head into history[0].
    //
    // The historical replays are best-effort — if one fails the trail is
    // simply truncated — but the *current* password is **always** applied
    // last, and *its* failure is the entry's failure. Without that, a
    // mid-replay failure would silently leave an old historical password
    // as the account head (a silent wrong-import).
    let (genesis_pw, historical_rotations): (Vec<u8>, Vec<Vec<u8>>) =
        if history_passwords.is_empty() {
            (password.to_vec(), Vec::new())
        } else {
            let mut iter = history_passwords.iter();
            let genesis = iter.next().expect("non-empty").0.to_vec();
            let rot: Vec<Vec<u8>> = iter.map(|(p, _)| p.to_vec()).collect();
            (genesis, rot)
        };

    let draft = pangolin_core::AccountIdentityDraft {
        schema_version: pangolin_core::ACCOUNT_IDENTITY_SCHEMA_VERSION,
        display_name,
        tags,
        usernames,
        urls,
        notes,
        password: SecretBytes::new(genesis_pw),
        totp_secret,
        totp_params,
    };
    let id = vault.account_add(draft)?;

    let mk_patch = |pw: Vec<u8>| pangolin_core::AccountIdentityPatch {
        schema_version: pangolin_core::ACCOUNT_IDENTITY_SCHEMA_VERSION,
        display_name: None,
        tags: None,
        usernames: None,
        urls: None,
        notes: None,
        password: Some(SecretBytes::new(pw)),
        totp_secret: None,
        totp_params: None,
    };

    // Best-effort: replay historical passwords; on the first failure the
    // history trail is truncated but the entry is not lost.
    for pw in historical_rotations {
        if vault.account_update(id, mk_patch(pw)).is_err() {
            break;
        }
    }
    // Always apply the *current* password last. If this fails the entry's
    // head is wrong — propagate it so the entry is reported `failed`
    // rather than silently mis-imported (only relevant when there was
    // history; with no history `genesis_pw` already *is* the current
    // password and this is a no-op patch we skip).
    if !history_passwords.is_empty() {
        vault.account_update(id, mk_patch(password.to_vec()))?;
    }
    Ok(())
}

fn push_kind(kinds: &mut Vec<String>, label: &str) {
    if !kinds.iter().any(|k| k == label) {
        kinds.push(label.to_string());
    }
}

/// Best-effort non-secret category label for a `StoreError` from
/// `account_add` (validation rejection). Never echoes entry data — only
/// the `kind` discriminator, which is a fixed structural label.
fn kind_of(e: &pangolin_store::StoreError) -> String {
    match e {
        pangolin_store::StoreError::Validation { kind, .. } => format!("validation_{kind}"),
        _ => "store_error".to_string(),
    }
}

/// Map a `pangolin_kdbx::KdbxError` to an `FfiError`. Wrong-credentials
/// is the no-oracle collapse; everything structural is `kdbx_format`.
#[allow(clippy::match_same_arms)]
fn map_kdbx_err(e: pangolin_kdbx::KdbxError) -> FfiError {
    use pangolin_kdbx::KdbxError as K;
    match e {
        K::Io(m) => FfiError::Validation {
            kind: "kdbx_io".into(),
            message: format!("KDBX I/O error: {m}"),
        },
        K::WrongCredentials | K::BlockHmacMismatch => FfiError::Validation {
            kind: "kdbx_credentials".into(),
            message: "wrong password or keyfile for the KeePass database".into(),
        },
        K::UnsupportedCredential(m) => FfiError::Validation {
            kind: "kdbx_unsupported_credential".into(),
            message: format!("unsupported KeePass credential type: {m}"),
        },
        K::FileTooLarge { .. } | K::TooManyEntries { .. } | K::InflatedTooLarge { .. } => {
            FfiError::Validation {
                kind: "kdbx_too_large".into(),
                message: e.to_string(),
            }
        }
        // Everything else — `NotKdbx`, `UnsupportedVersion`,
        // `CorruptHeader`/`CorruptPayload`, `UnsupportedKdf`/Cipher,
        // `KdfParamsRejected`, `XmlMalformed`, and (since `KdbxError`
        // is `#[non_exhaustive]`) any future variant — is a structural
        // / format problem.
        K::NotKdbx
        | K::UnsupportedVersion { .. }
        | K::CorruptHeader(_)
        | K::CorruptPayload(_)
        | K::UnsupportedKdf(_)
        | K::KdfParamsRejected(_)
        | K::UnsupportedCipher(_)
        | K::XmlMalformed(_) => FfiError::Validation {
            kind: "kdbx_format".into(),
            message: format!("invalid or unsupported KDBX file ({})", e.kind_label()),
        },
        // `#[non_exhaustive]` catch-all (kept distinct to satisfy the
        // exhaustiveness check; same UI-safe mapping).
        _ => FfiError::Validation {
            kind: "kdbx_format".into(),
            message: format!("invalid or unsupported KDBX file ({})", e.kind_label()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::map_kdbx_err;
    use crate::error::FfiError;
    use pangolin_kdbx::KdbxError as K;

    /// Every `KdbxError` variant maps to a `Validation`-class `FfiError`
    /// (never `Internal`), with a fixed non-secret `kind` label, and
    /// every credential failure collapses to the same `kdbx_credentials`
    /// kind (no oracle).
    #[test]
    fn kdbx_error_taxonomy_is_total_and_no_oracle() {
        let cases: Vec<(K, &str)> = vec![
            (K::Io("x".into()), "kdbx_io"),
            (K::NotKdbx, "kdbx_format"),
            (K::UnsupportedVersion { major: 1, minor: 0 }, "kdbx_format"),
            (K::FileTooLarge { len: 1, max: 0 }, "kdbx_too_large"),
            (K::CorruptHeader("x".into()), "kdbx_format"),
            (K::CorruptPayload("x".into()), "kdbx_format"),
            (K::BlockHmacMismatch, "kdbx_credentials"),
            (K::WrongCredentials, "kdbx_credentials"),
            (
                K::UnsupportedCredential("hw".into()),
                "kdbx_unsupported_credential",
            ),
            (K::UnsupportedKdf("x".into()), "kdbx_format"),
            (K::KdfParamsRejected("x".into()), "kdbx_format"),
            (K::UnsupportedCipher("x".into()), "kdbx_format"),
            (K::XmlMalformed("x".into()), "kdbx_format"),
            (K::TooManyEntries { limit: 1 }, "kdbx_too_large"),
            (K::InflatedTooLarge { limit: 1 }, "kdbx_too_large"),
        ];
        for (err, expected_kind) in cases {
            match map_kdbx_err(err) {
                FfiError::Validation { kind, message } => {
                    assert_eq!(kind, expected_kind, "kind for variant");
                    // Message is UI-safe (a fixed string / structural
                    // facts) — never echoes secret bytes.
                    assert!(!message.is_empty());
                }
                other => panic!("expected Validation, got {other:?}"),
            }
        }
        // The no-oracle property: BlockHmacMismatch and WrongCredentials
        // are indistinguishable at the FFI boundary.
        let a = map_kdbx_err(K::BlockHmacMismatch);
        let b = map_kdbx_err(K::WrongCredentials);
        assert_eq!(format!("{a:?}"), format!("{b:?}"));
    }
}
