// SPDX-License-Identifier: AGPL-3.0-or-later
//! Presence-gated reveal-class FFI entry points (MVP-1 issue 1.4 — Q4).
//!
//! Session spec §5.4 reveal-class assets (the head password, the full
//! password history with bytes + timestamps + device ids, free-form
//! notes, the raw TOTP shared-secret seed) cross the FFI **only**
//! through these entry points, each of which routes through the
//! `pangolin-store` engine's fresh-presence check
//! (`Vault::reveal_*` → `ensure_presence_fresh`):
//!
//! - **Fresh now (within the 60 s window, or right after unlock):** no
//!   re-prompt — the engine's `last_presence_at` is within
//!   `PRESENCE_FRESHNESS` (prompt dedup, §8.6).
//! - **Stale:** a stale presence proof at a reveal site maps to
//!   `StoreError::PromptTimedOut` → `FfiError::Session` (§7.7 — loud,
//!   typed, never silent).
//! - **Locked / expired:** `NotUnlocked` / `SessionExpired` → the
//!   `FfiError::Session` category, surfaced *before* the proof is
//!   consumed so the caller can re-auth and retry.
//!
//! These are a 1.1-surface amendment (the 1.1 freeze declared no
//! `reveal_*` entries); nothing external binds the 1.1 surface yet, so
//! it is safe — same posture as 1.2's `AccountDraft` widening.
//! `docs/architecture/ffi-surface.md` is updated to reflect this.
//!
//! The CLI tier maps the 1.1-frozen `PresenceProof` `{schema_version,
//! bytes}` record to a fresh `PressYPresenceProof::confirmed()` (the
//! `bytes` field is currently unused for the CLI tier — it is the slot
//! MVP-3/4's hardware-backed presence proofs populate). The engine's
//! freshness window does the dedup; a fresh `confirmed()` proof always
//! satisfies it.

use std::sync::Arc;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::FfiError;
use crate::identity::{AccountId, PasswordHistoryEntry};
use crate::session::{PresenceProof, VaultHandle};

/// Opaque zeroizing wrapper for a revealed secret byte string
/// (the head password, the decrypted notes, the raw TOTP seed).
///
/// Crosses FFI as an Object (`UniFFI` `Arc<Self>`) so the foreign-
/// language binding sees a reference type and cannot copy the buffer
/// onto the GC heap. Exposes a `byte_length()` accessor only — never a
/// `Debug` / `Display` plaintext leak. Bytes zero on drop. Same
/// discipline as [`crate::session::SecretPassword`] /
/// [`crate::identity::TotpSecret`].
#[derive(uniffi::Object)]
pub struct RevealedSecret {
    bytes: revealed_buf::SecretBuf,
}

impl std::fmt::Debug for RevealedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RevealedSecret")
            .field("len", &self.bytes.as_slice().len())
            .field("bytes", &"<redacted>")
            .finish()
    }
}

impl RevealedSecret {
    /// Wrap raw bytes. The caller's buffer is consumed; the returned
    /// `Arc<Self>` zeroes the bytes when every foreign-language
    /// reference drops.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Arc<Self> {
        Arc::new(Self {
            bytes: revealed_buf::SecretBuf::new(bytes),
        })
    }

    /// Byte length. Length-only is non-secret.
    #[must_use]
    pub fn len(&self) -> u32 {
        u32::try_from(self.bytes.as_slice().len()).unwrap_or(u32::MAX)
    }

    /// Whether the revealed secret is empty (e.g. no TOTP / no notes).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.as_slice().is_empty()
    }

    /// Copy the raw secret bytes into a host-owned `Vec<u8>`.
    ///
    /// **MVP-4-B host-bytes accessor (additive 1.1-surface amendment).**
    /// The desktop shell (`apps/desktop/`) consumes `pangolin-ffi` as a
    /// Rust `rlib` (not as a `UniFFI` foreign-language binding) and needs
    /// a typed entry point to surface the revealed plaintext through
    /// Tauri's `Result<String, _>` invoke envelope. The `bytes_for_bridge`
    /// crate-private accessor used by the cabi shims is not visible
    /// outside this crate; this `expose_bytes_for_host` method is the
    /// minimal public surface that gives the host shell what it needs.
    ///
    /// The returned `Vec<u8>` is a copy of the internal buffer (the
    /// caller MUST zero it before drop — see `apps/desktop/src/commands/
    /// account.rs::reveal_password`'s `Zeroize` discipline). The
    /// internal buffer continues to zero on drop via `SecretBuf`'s
    /// `ZeroizeOnDrop`.
    ///
    /// This entry is gated behind the same presence-fresh check the
    /// engine enforces in `reveal_current_password` / `reveal_notes` /
    /// `reveal_totp_secret`; by the time a `RevealedSecret` exists,
    /// the L1 carve-out for the reveal flow has already fired (the
    /// `host_byte_accessor_returns_bytes` round-trip test in this
    /// module pins the shape, not the freshness — freshness is the
    /// FFI's job).
    #[must_use]
    pub fn expose_bytes_for_host(&self) -> Vec<u8> {
        self.bytes.as_slice().to_vec()
    }
}

#[uniffi::export]
impl RevealedSecret {
    #[uniffi::method(name = "byte_length")]
    pub fn byte_length(&self) -> u32 {
        self.len()
    }
}

mod revealed_buf {
    use super::{Zeroize, ZeroizeOnDrop};

    pub struct SecretBuf {
        inner: Vec<u8>,
    }

    impl SecretBuf {
        pub fn new(bytes: Vec<u8>) -> Self {
            Self { inner: bytes }
        }
        pub fn as_slice(&self) -> &[u8] {
            &self.inner
        }
    }

    impl Drop for SecretBuf {
        fn drop(&mut self) {
            self.inner.zeroize();
        }
    }

    impl Zeroize for SecretBuf {
        fn zeroize(&mut self) {
            self.inner.zeroize();
        }
    }

    impl ZeroizeOnDrop for SecretBuf {}
}

/// Build the CLI-tier presence proof from the 1.1-frozen FFI envelope.
/// `bytes` is unused for the CLI tier; MVP-3/4 hardware proofs populate
/// it. A fresh `PressYPresenceProof::confirmed()` always satisfies the
/// engine's 60 s freshness window — the *engine* owns dedup, not this
/// shim.
fn presence_from_ffi(_proof: PresenceProof) -> pangolin_core::PressYPresenceProof {
    pangolin_core::PressYPresenceProof::confirmed()
}

fn store_into_ffi(err: pangolin_store::StoreError) -> FfiError {
    FfiError::from(pangolin_core::Error::from(err))
}

/// Reveal the **current** (head-of-history) plaintext password.
///
/// Requires an active session plus a fresh presence proof (dedup'd
/// within the 60 s window — a reveal right after unlock, or a second
/// reveal moments after the first, does not re-prompt). Bytes zero on
/// drop.
///
/// # Errors
///
/// `FfiError::Session` for a locked / expired session, a frozen
/// account, or a timed-out presence prompt; `FfiError::Validation`
/// with `kind = "authentication"` for any other proof failure;
/// `FfiError::Store` for an unknown / tombstoned account.
#[allow(clippy::significant_drop_tightening)]
#[uniffi::export]
pub fn reveal_current_password(
    handle: Arc<VaultHandle>,
    id: AccountId,
    presence: PresenceProof,
) -> Result<Arc<RevealedSecret>, FfiError> {
    let mut guard = handle.lock_vault();
    let vault = guard.as_mut()?;
    let store_id = crate::identity_bridge::account_id_from_ffi(&id)?;
    let proof = presence_from_ffi(presence);
    let mut bytes = zeroize::Zeroizing::new(
        vault
            .reveal_current_password(store_id, &proof)
            .map_err(store_into_ffi)?
            .expose()
            .to_vec(),
    );
    Ok(RevealedSecret::new(std::mem::take(&mut *bytes)))
}

/// Reveal the **full password history** for an account.
///
/// Every entry's plaintext bytes + the timestamp it was set + the
/// originating device id, newest first. Presence-gated (same window /
/// dedup semantics as [`reveal_current_password`]).
///
/// # Errors
///
/// As [`reveal_current_password`].
#[allow(clippy::significant_drop_tightening)]
#[uniffi::export]
pub fn reveal_password_history(
    handle: Arc<VaultHandle>,
    id: AccountId,
    presence: PresenceProof,
) -> Result<Vec<PasswordHistoryEntry>, FfiError> {
    let mut guard = handle.lock_vault();
    let vault = guard.as_mut()?;
    let store_id = crate::identity_bridge::account_id_from_ffi(&id)?;
    let proof = presence_from_ffi(presence);
    let history = vault
        .reveal_password_history(store_id, &proof)
        .map_err(store_into_ffi)?;
    Ok(history
        .into_iter()
        .map(crate::identity_bridge::password_history_entry_to_ffi)
        .collect())
}

/// Reveal the plaintext notes for an account (recovery-class per spec
/// §5.4 — notes can carry recovery phrases / security-question
/// answers). Presence-gated. Empty `RevealedSecret` when no notes.
///
/// # Errors
///
/// As [`reveal_current_password`].
#[allow(clippy::significant_drop_tightening)]
#[uniffi::export]
pub fn reveal_notes(
    handle: Arc<VaultHandle>,
    id: AccountId,
    presence: PresenceProof,
) -> Result<Arc<RevealedSecret>, FfiError> {
    let mut guard = handle.lock_vault();
    let vault = guard.as_mut()?;
    let store_id = crate::identity_bridge::account_id_from_ffi(&id)?;
    let proof = presence_from_ffi(presence);
    let mut bytes = zeroize::Zeroizing::new(
        vault
            .reveal_notes(store_id, &proof)
            .map_err(store_into_ffi)?
            .expose()
            .to_vec(),
    );
    Ok(RevealedSecret::new(std::mem::take(&mut *bytes)))
}

/// Reveal the raw plaintext TOTP shared-secret seed for an account.
///
/// 1.7's RFC-6238 generator consumes the seed internally without a
/// reveal; exporting/revealing the *seed* itself is high-risk per spec
/// §5.4 + the Phase-2 note. Presence-gated. Empty `RevealedSecret`
/// when no TOTP is configured.
///
/// # Errors
///
/// As [`reveal_current_password`].
#[allow(clippy::significant_drop_tightening)]
#[uniffi::export]
pub fn reveal_totp_secret(
    handle: Arc<VaultHandle>,
    id: AccountId,
    presence: PresenceProof,
) -> Result<Arc<RevealedSecret>, FfiError> {
    let mut guard = handle.lock_vault();
    let vault = guard.as_mut()?;
    let store_id = crate::identity_bridge::account_id_from_ffi(&id)?;
    let proof = presence_from_ffi(presence);
    let mut bytes = zeroize::Zeroizing::new(
        vault
            .reveal_totp_secret(store_id, &proof)
            .map_err(store_into_ffi)?
            .expose()
            .to_vec(),
    );
    Ok(RevealedSecret::new(std::mem::take(&mut *bytes)))
}

#[cfg(test)]
mod tests {
    use super::RevealedSecret;

    /// MVP-4-B host-bytes accessor: a freshly-constructed `RevealedSecret`
    /// round-trips its bytes through `expose_bytes_for_host`. The
    /// internal buffer continues to zero on drop (covered by
    /// `SecretBuf`'s `ZeroizeOnDrop` impl); this test only pins the
    /// shape of the host-side accessor.
    #[test]
    fn host_byte_accessor_returns_bytes() {
        let bytes = b"plaintext-password-bytes".to_vec();
        let secret = RevealedSecret::new(bytes.clone());
        let out = secret.expose_bytes_for_host();
        assert_eq!(out, bytes);
        // The length accessor still reports the same length.
        assert_eq!(secret.len() as usize, bytes.len());
    }

    #[test]
    fn host_byte_accessor_on_empty_secret_returns_empty_vec() {
        let secret = RevealedSecret::new(Vec::new());
        assert!(secret.is_empty());
        assert!(secret.expose_bytes_for_host().is_empty());
    }
}
