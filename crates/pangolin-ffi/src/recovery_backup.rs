// SPDX-License-Identifier: AGPL-3.0-or-later
//! **MVP-3 issue #109: thin uniffi layer over the merged-and-audited
//! `pangolin_store::recovery_backup` envelope codec.**
//!
//! Three host-facing bindings:
//!
//! - [`vault_create_backup`] — Active-gated. Generates a fresh 24-word
//!   BIP-39 seed phrase, reads the live recovery escrow under the
//!   active VDK's column-AEAD, packages it into the canonical
//!   encrypted envelope (sealed under the seed phrase), and returns
//!   the bytes + text form + the seed-phrase words for the host to
//!   display once to the user.
//! - [`vault_decode_backup`] — pure (no handle). Decrypts + decodes
//!   the envelope given the seed-phrase words; returns the
//!   non-secret metadata (vault id, epoch, roster, display name,
//!   creation timestamp). Wrong seed / tampered envelope / bad
//!   length / unknown schema all collapse to fail-closed typed
//!   errors per the store module's discipline.
//! - [`vault_recover_from_backup`] — convenience: decode + drive
//!   [`pangolin_core::composition::recover_from_shares`] against the
//!   host-supplied opened guardian shares + the user's new master
//!   password. Wraps the existing #106e-1 recovery surface so the
//!   host doesn't have to wire backup → wrapped_recovery → roster
//!   itself.
//!
//! ## L1 — secret hygiene
//!
//! The seed phrase is the ONE new secret that crosses out (at backup
//! creation) and back in (at decode / recover). It crosses as
//! `Vec<String>` for surface simplicity: the user MUST see it to
//! record it (an opaque Object that hid the words would be useless),
//! and at decode / recover time the user types them back in from
//! paper — so they're already in the host's hands. The master
//! password crosses behind [`SecretPassword`] (already-opaque). The
//! opened-share secrets stay behind [`FfiOpenedShare`] (already
//! opaque). Backup bytes / text / metadata are non-secret post-seal.
//!
//! ## L4 — session-gating
//!
//! - `vault_create_backup` is Active-gated (needs the active VDK's
//!   column-AEAD to read the escrow).
//! - `vault_decode_backup` is pure (no handle / no session).
//! - `vault_recover_from_backup` rides on the existing
//!   [`crate::recovery_ffi::vault_recover_from_shares`] session
//!   posture (the engine's `recover_from_shares` drives the commit
//!   into the supplied handle — accepts any non-placeholder handle;
//!   the post-recover vault is left Locked).

#![forbid(unsafe_code)]
#![allow(
    clippy::doc_markdown,
    clippy::too_long_first_doc_paragraph,
    clippy::doc_lazy_continuation
)]

use std::sync::Arc;

use pangolin_core::composition::{recover_from_shares as core_recover_from_shares, GuardianRoster};
use pangolin_crypto::escrow::Share;
use pangolin_crypto::secret::SecretBytes;
use pangolin_store::recovery_backup::{
    decode_backup as core_decode_backup, encode_text as core_encode_text, BackupContents,
    BackupError,
};

use crate::error::FfiError;
use crate::recovery_ffi::{
    composition_error_into_ffi, decode_wrapped_recovery, FfiOpenedShare, FfiRecoveryResult,
    RECOVERY_FFI_SCHEMA_VERSION,
};
use crate::session::{SecretPassword, VaultHandle};

/// Schema-version slot value for the #109 FFI result records.
pub const RECOVERY_BACKUP_FFI_SCHEMA_VERSION: u16 = 1;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Map a [`BackupError`] into the FFI taxonomy. Length / schema /
/// integrity-hash / KDF-clamp / wire-format errors collapse to
/// `Validation { kind = "argument" }`; the AEAD-open + wrong-seed
/// arms collapse to `Validation { kind = "authentication" }` (no
/// oracle on the cause).
fn backup_into_ffi(err: BackupError) -> FfiError {
    match err {
        BackupError::Validation { kind, message } => FfiError::Validation {
            kind: kind.to_owned(),
            message,
        },
        BackupError::IntegrityFailed
        | BackupError::TextInvalidEncoding
        | BackupError::TextChecksumMismatch
        | BackupError::UnknownSchemaVersion(_, _)
        | BackupError::SeedPhraseMalformed(_)
        | BackupError::KdfParamOutOfRange { .. } => FfiError::Validation {
            kind: "argument".to_owned(),
            message: err.to_string(),
        },
        BackupError::AuthenticationFailed => FfiError::Validation {
            kind: "authentication".to_owned(),
            message: err.to_string(),
        },
    }
}

/// Length-validate a host-supplied `Vec<u8>` is exactly `N` bytes.
/// (Test-only here — production paths use the store-side length checks
/// inside `decode_backup` / `decode_wrapped_recovery`.)
#[cfg(test)]
fn fixed_bytes<const N: usize>(bytes: &[u8], what: &str) -> Result<[u8; N], FfiError> {
    bytes.try_into().map_err(|_| FfiError::Validation {
        kind: "argument".into(),
        message: format!("{what} must be {N} bytes (got {})", bytes.len()),
    })
}

// ---------------------------------------------------------------------------
// FFI result records
// ---------------------------------------------------------------------------

/// **The one-shot backup record.** Returned by [`vault_create_backup`].
///
/// `bytes` + `text` are the SAME envelope in two forms — bytes for
/// persisting to a file / cloud / QR, text for copy-paste UX. They
/// round-trip 1:1 through [`vault_decode_backup`]. `seed_phrase_words`
/// is the 24-word phrase the user MUST record out-of-band before
/// dropping this record — once dropped, the phrase is gone (the engine
/// does not retain it).
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiBackup {
    /// Canonical byte form (DOMAIN-prefixed; what
    /// [`vault_decode_backup`] consumes when handed bytes).
    pub bytes: Vec<u8>,
    /// Bech32-style lowercase text form (RFC 4648 base32 + 4-byte
    /// SHA-256 checksum). Also accepted by [`vault_decode_backup`]
    /// (the engine detects byte-vs-text via the leading DOMAIN
    /// prefix).
    pub text: String,
    /// The 24-word BIP-39 seed phrase the user must record. The host
    /// displays these to the user once and then drops the record.
    pub seed_phrase_words: Vec<String>,
    /// Schema-version slot.
    pub schema_version: u16,
}

/// Decoded backup metadata, returned by [`vault_decode_backup`].
///
/// All fields are non-secret (they're inside the AEAD-sealed body, so
/// you only see them post-unlock — but once decoded, they describe
/// the vault topology and the recovery roster, which the host needs
/// to render UX + assemble the recovery flow).
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiBackupContents {
    /// User-set display name for the vault. Empty-string when the
    /// host did not supply one at backup creation time.
    pub vault_display_name: String,
    /// Wall-clock unix-seconds timestamp the backup was sealed.
    pub created_at_unix: u64,
    /// The vault's 32-byte stable id.
    pub vault_id: Vec<u8>,
    /// The recovery generation epoch the escrow was tagged with.
    pub epoch: u64,
    /// The reconstruction threshold (`t`).
    pub threshold: u8,
    /// The guardian count (`M`).
    pub guardian_count: u8,
    /// The `M` guardians' 32-byte X25519 SEALING pubkeys, ordered by
    /// index (`0..M`).
    pub guardian_x25519_pubs: Vec<Vec<u8>>,
    /// Schema-version slot.
    pub schema_version: u16,
}

// ---------------------------------------------------------------------------
// 1. vault_create_backup
// ---------------------------------------------------------------------------

/// **Active-gated.** Build a canonical recovery-backup envelope from
/// the live recovery escrow + seal it under a freshly-generated
/// 24-word BIP-39 seed phrase.
///
/// Returns the byte form + text form + the seed-phrase words. The
/// host MUST display the words to the user once (so they can record
/// them on paper / metal / safe) and drop the record afterward —
/// nothing in the engine retains the phrase.
///
/// Returns `Err(FfiError::Validation { kind: "argument", .. })` if no
/// recovery escrow has been onboarded for the active vault (without
/// an escrow there is nothing to back up; the host should drive the
/// onboard-guardians flow first via the #106e-1 surface).
///
/// # Errors
///
/// - [`FfiError::Session`] for a placeholder / Locked vault (L4
///   gate before any crypto).
/// - [`FfiError::Validation`] (`kind = "argument"`) if no recovery
///   escrow is onboarded.
/// - [`FfiError::Store`] on a DB / escrow-read failure.
/// - [`FfiError::Validation`] (mapped from [`BackupError`]) on a
///   KDF / AEAD / wire-format failure inside the seal path.
#[allow(clippy::significant_drop_tightening, clippy::needless_pass_by_value)]
#[uniffi::export]
pub fn vault_create_backup(
    handle: Arc<VaultHandle>,
    master_password: Arc<SecretPassword>,
) -> Result<FfiBackup, FfiError> {
    // Bridge + zeroize the master password (consumed for surface
    // symmetry with the other recovery bindings; the seal uses the
    // seed phrase as the wrap authority).
    let mut pw = zeroize::Zeroizing::new(master_password.bytes_for_bridge().to_vec());
    let secret = SecretBytes::new(std::mem::take(&mut *pw));

    let mut guard = handle.lock_vault();
    let vault = guard.as_mut()?;

    // Drive the store-side seal. `create_recovery_backup` returns
    // `Ok(None)` if no escrow is onboarded; surface that as
    // `Validation { kind = "argument" }` so the host sees a clear
    // "onboard guardians first" signal instead of an opaque inner
    // error.
    let Some((seed_phrase, bytes)) = vault
        .create_recovery_backup(&secret)
        .map_err(|e| match e {
            pangolin_store::StoreError::RecoveryBackup(be) => backup_into_ffi(be),
            other => FfiError::from(pangolin_core::Error::from(other)),
        })?
    else {
        return Err(FfiError::Validation {
            kind: "argument".into(),
            message: "vault has no recovery escrow onboarded; onboard guardians via \
                      vault_onboard_guardians before creating a backup"
                .into(),
        });
    };

    let text = core_encode_text(&bytes);
    let seed_phrase_words: Vec<String> = seed_phrase.as_slice().to_vec();

    drop(secret);
    Ok(FfiBackup {
        bytes,
        text,
        seed_phrase_words,
        schema_version: RECOVERY_BACKUP_FFI_SCHEMA_VERSION,
    })
}

// ---------------------------------------------------------------------------
// 2. vault_decode_backup
// ---------------------------------------------------------------------------

/// **Pure (no handle).** Decrypt + decode an encrypted backup envelope
/// given the seed-phrase words the user recorded at backup creation.
///
/// `backup_bytes_or_text` accepts EITHER the canonical byte form OR
/// the UTF-8 text form (the engine detects via the leading DOMAIN
/// prefix). Wrong seed phrase, tampered ciphertext, bad length, or
/// unknown schema version all collapse to typed `Validation` errors
/// (no oracle on the cause).
///
/// # Errors
///
/// - [`FfiError::Validation`] (`kind = "argument"`) for length /
///   wire-format / schema / integrity / seed-malformed failures.
/// - [`FfiError::Validation`] (`kind = "authentication"`) for AEAD /
///   wrong-seed / KDF failures (indistinguishable by design).
#[uniffi::export]
pub fn vault_decode_backup(
    backup_bytes_or_text: Vec<u8>,
    seed_phrase: Vec<String>,
) -> Result<FfiBackupContents, FfiError> {
    let contents = core_decode_backup(&backup_bytes_or_text, &seed_phrase)
        .map_err(backup_into_ffi)?;
    Ok(into_ffi_contents(&contents))
}

fn into_ffi_contents(contents: &BackupContents) -> FfiBackupContents {
    FfiBackupContents {
        vault_display_name: contents.vault_display_name.clone(),
        created_at_unix: contents.created_at_unix,
        vault_id: contents.vault_id.to_vec(),
        epoch: contents.epoch,
        threshold: contents.threshold,
        guardian_count: contents.guardian_count,
        guardian_x25519_pubs: contents
            .guardian_x25519_pubs
            .iter()
            .map(|p| p.to_vec())
            .collect(),
        schema_version: RECOVERY_BACKUP_FFI_SCHEMA_VERSION,
    }
}

// ---------------------------------------------------------------------------
// 3. vault_recover_from_backup
// ---------------------------------------------------------------------------

/// **Lost-everything recovery convenience.** Decode the backup +
/// drive the existing
/// [`pangolin_core::composition::recover_from_shares`] driver against
/// the host-supplied opened guardian shares + the user's new master
/// password. Combines #109's decode with the #106e-1 recovery surface
/// so the host doesn't have to re-derive the `wrapped_recovery` /
/// `roster` / `vault_id` / `epoch` plumbing itself.
///
/// `opened_shares` follows the same `Arc<FfiOpenedShare>` posture as
/// [`crate::recovery_ffi::vault_recover_from_shares`]: each Arc must
/// be uniquely held (the host drops all other clones); the
/// zeroizing `Share` is moved out, never copied past a redacted
/// boundary.
///
/// # Errors
///
/// Union of [`vault_decode_backup`] errors (backup decode) and
/// [`crate::recovery_ffi::vault_recover_from_shares`] errors
/// (driver + commit). See those for the exhaustive taxonomy.
#[allow(clippy::significant_drop_tightening, clippy::needless_pass_by_value)]
#[uniffi::export]
pub fn vault_recover_from_backup(
    handle: Arc<VaultHandle>,
    backup_bytes_or_text: Vec<u8>,
    seed_phrase: Vec<String>,
    opened_shares: Vec<Arc<FfiOpenedShare>>,
    new_password: Arc<SecretPassword>,
) -> Result<FfiRecoveryResult, FfiError> {
    // Decode the envelope FIRST so the wrong-seed / tampered-envelope
    // case fails before we touch the handle or the opened shares.
    let contents = core_decode_backup(&backup_bytes_or_text, &seed_phrase)
        .map_err(backup_into_ffi)?;

    // Re-decode the wrapped_recovery wire form (schema || nonce ||
    // ciphertext) into a `WrappedVdkRecovery` via the existing
    // recovery_ffi byte-form decoder (shared shape, see
    // `recovery_ffi::decode_wrapped_recovery` docs). The store-side
    // create path produced the bytes via the same wire form, so the
    // round-trip is byte-identical.
    let wrapped = decode_wrapped_recovery(&contents.wrapped_recovery, contents.vault_id)?;

    let roster = GuardianRoster {
        threshold: contents.threshold,
        guardian_count: contents.guardian_count,
        x25519_pubs: contents.guardian_x25519_pubs.clone(),
    };

    // Extract owned `Share`s engine-side (mirrors
    // vault_recover_from_shares).
    let mut shares: Vec<Share> = Vec::with_capacity(opened_shares.len());
    for s in opened_shares {
        shares.push(s.into_inner()?);
    }

    // Bridge the password engine-side into a zeroizing SecretBytes.
    let mut pw = zeroize::Zeroizing::new(new_password.bytes_for_bridge().to_vec());
    let secret = SecretBytes::new(std::mem::take(&mut *pw));

    let mut guard = handle.lock_vault();
    let vault = guard.as_mut()?;
    let outcome = core_recover_from_shares(
        vault,
        &wrapped,
        shares,
        &roster,
        &secret,
        contents.epoch,
        contents.vault_id,
    )
    .map_err(composition_error_into_ffi)?;
    drop(secret);
    Ok(FfiRecoveryResult {
        new_epoch: outcome.new_epoch,
        schema_version: RECOVERY_FFI_SCHEMA_VERSION,
    })
}

// ---------------------------------------------------------------------------
// hermetic tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{vault_create, vault_open, vault_unlock, PresenceProof};
    use pangolin_crypto::keys::VAULT_ID_LEN;
    use tempfile::TempDir;

    fn presence() -> PresenceProof {
        PresenceProof {
            schema_version: 1,
            bytes: vec![],
        }
    }

    fn pwd() -> Arc<SecretPassword> {
        SecretPassword::new(b"hermetic master password".to_vec())
    }

    fn unlocked_handle(dir: &TempDir) -> Arc<VaultHandle> {
        let path = dir.path().join("v.pvf").to_string_lossy().into_owned();
        vault_create(path.clone(), pwd()).expect("create");
        let h = vault_open(path).expect("open");
        vault_unlock(Arc::clone(&h), pwd(), presence()).expect("unlock");
        h
    }

    /// `vault_create_backup` on a placeholder handle → Session.
    #[test]
    fn create_backup_rejects_placeholder() {
        let h = VaultHandle::new_placeholder();
        let err = vault_create_backup(h, pwd()).unwrap_err();
        assert!(matches!(err, FfiError::Session { .. }));
    }

    /// `vault_create_backup` on a Locked vault → Session.
    #[test]
    fn create_backup_rejects_locked() {
        let dir = TempDir::new().unwrap();
        let h = unlocked_handle(&dir);
        {
            let mut g = h.lock_vault();
            g.as_mut().unwrap().lock();
        }
        let err = vault_create_backup(h, pwd()).unwrap_err();
        assert!(matches!(err, FfiError::Session { .. }));
    }

    /// `vault_create_backup` on an Active vault without an onboarded
    /// recovery escrow → Validation { kind = "argument", .. }.
    #[test]
    fn create_backup_without_escrow_returns_validation() {
        let dir = TempDir::new().unwrap();
        let h = unlocked_handle(&dir);
        let err = vault_create_backup(h, pwd()).unwrap_err();
        assert!(
            matches!(err, FfiError::Validation { ref kind, .. } if kind == "argument"),
            "expected Validation kind=argument, got {err:?}"
        );
    }

    /// `vault_decode_backup` on truncated bytes → Validation
    /// `{ kind = "argument", .. }` (a DOMAIN-prefixed-but-short blob
    /// surfaces the byte-form size check from the store-side parser).
    #[test]
    fn decode_backup_rejects_truncated_bytes() {
        let mut blob = pangolin_store::recovery_backup::DOMAIN.to_vec();
        blob.extend_from_slice(&[0u8; 4]);
        let words: Vec<String> = (0..24).map(|_| "abandon".to_string()).collect();
        let err = vault_decode_backup(blob, words).unwrap_err();
        assert!(
            matches!(err, FfiError::Validation { ref kind, .. } if kind == "argument"),
            "expected Validation kind=argument, got {err:?}"
        );
    }

    /// `vault_decode_backup` on a clearly-bogus byte buffer (no DOMAIN
    /// prefix; very short) routes through the text-form path and
    /// surfaces a `Validation { kind = "argument" }` (the text-encoding
    /// failure maps to Validation per [`backup_into_ffi`]).
    #[test]
    fn decode_backup_rejects_random_short_bytes() {
        let words: Vec<String> = (0..24).map(|_| "abandon".to_string()).collect();
        let err = vault_decode_backup(b"garbage input".to_vec(), words).unwrap_err();
        assert!(
            matches!(err, FfiError::Validation { ref kind, .. } if kind == "argument"),
            "expected Validation kind=argument for non-DOMAIN garbage, got {err:?}"
        );
    }

    /// `vault_decode_backup` with the wrong number of seed phrase
    /// words → Validation { kind = "argument" } (the store-side
    /// `SeedPhraseMalformed` mapping).
    #[test]
    fn decode_backup_rejects_wrong_word_count() {
        let mut blob = pangolin_store::recovery_backup::DOMAIN.to_vec();
        blob.extend_from_slice(&[0u8; 64]);
        let short_words: Vec<String> = (0..10).map(|_| "abandon".to_string()).collect();
        let err = vault_decode_backup(blob, short_words).unwrap_err();
        assert!(
            matches!(err, FfiError::Validation { ref kind, .. } if kind == "argument"),
            "expected Validation kind=argument, got {err:?}"
        );
    }

    /// Length validator helper smoke-test (the FFI module's own
    /// `fixed_bytes` mirror of the recovery_lifecycle pattern).
    #[test]
    fn fixed_bytes_rejects_wrong_length() {
        let r: Result<[u8; VAULT_ID_LEN], FfiError> = fixed_bytes(&[0u8; 31], "vault_id");
        assert!(matches!(r, Err(FfiError::Validation { ref kind, .. }) if kind == "argument"));
    }
}
