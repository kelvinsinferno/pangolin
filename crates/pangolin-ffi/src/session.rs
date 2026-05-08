//! Session-related FFI shapes (vault lifecycle + session metadata).
//!
//! Bodies arrive in MVP-1 issue 1.4 (Session state machine). The
//! signatures and record shapes are frozen at issue 1.1 so the FFI
//! consumer (Tauri / Swift / Kotlin) can build against known slots.
//!
//! ## Schema-versioning slot
//!
//! Every record that crosses FFI **and** carries user data exposes a
//! `schema_version: u16` field. The §18.7 policy text is locked at
//! issue 1.6; 1.1 commits only to the slot.

use std::sync::Arc;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::FfiError;

/// Wrapper around password bytes. Bytes are zeroed on drop. Never logged.
///
/// Crosses FFI as an `Object` (`UniFFI` `Arc<Self>`) so the foreign-
/// language binding sees a reference type and cannot copy the underlying
/// buffer onto the GC heap.
#[derive(uniffi::Object)]
pub struct SecretPassword {
    bytes: secret_buf::SecretBuf,
}

// Manual `Debug` impl that never reveals plaintext. Per Design Spec
// §15, no FFI surface ever leaks plaintext through a debug or display
// path; this impl renders only the byte length, matching the
// discipline used by `pangolin_crypto::secret::SecretBytes`.
impl std::fmt::Debug for SecretPassword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretPassword")
            .field("len", &self.bytes.as_slice().len())
            .field("bytes", &"<redacted>")
            .finish()
    }
}

impl SecretPassword {
    /// Construct from raw bytes. The caller's buffer is consumed; it
    /// is the caller's responsibility to zero any prior copy. The
    /// returned `Arc<Self>` lives until every foreign-language reference
    /// drops, at which point the bytes are zeroed.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Arc<Self> {
        Arc::new(Self {
            bytes: secret_buf::SecretBuf::new(bytes),
        })
    }

    /// Returns the underlying byte length. Provided so foreign-language
    /// callers can validate password-length policy without exposing the
    /// raw bytes. Constant-time semantics not required for the length
    /// field.
    #[must_use]
    pub fn len(&self) -> u32 {
        u32::try_from(self.bytes.as_slice().len()).unwrap_or(u32::MAX)
    }

    /// Returns whether the wrapper is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.as_slice().is_empty()
    }
}

#[uniffi::export]
impl SecretPassword {
    /// `UniFFI` exposes a `len`-named accessor on the foreign-language
    /// side. Mirrors [`SecretPassword::len`].
    #[uniffi::method(name = "byte_length")]
    pub fn byte_length(&self) -> u32 {
        self.len()
    }
}

// `secret_buf` is an inline Zeroize wrapper kept local to this module
// so the `SecretPassword` type stays self-contained and we avoid an
// extra crate dependency just for a zero-on-drop `Vec<u8>`. The shim
// wraps `Vec<u8>` with manual `Zeroize` + `ZeroizeOnDrop` impls; same
// discipline as `pangolin_crypto::secret::SecretBytes`.
mod secret_buf {
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

/// Presence-proof envelope (master plan §4.3 / Session spec §5.3).
///
/// Crosses FFI as a value record. The `PoC`'s
/// `PressYPresenceProof::confirmed()` is what populates the field; the
/// production `PresenceProof` enum lands in 1.4.
#[derive(Debug, Clone, uniffi::Record)]
pub struct PresenceProof {
    /// Issue 1.1 schema-version slot (§18.7 policy locked in 1.6).
    pub schema_version: u16,
    /// Opaque proof bytes. The shape depends on the platform's biometric
    /// subsystem; the FFI surface treats the field as bytes.
    pub bytes: Vec<u8>,
}

/// Vault state + session metadata returned from `vault_unlock` /
/// `session_status`. Field set is the locked-in-1.1 minimum;
/// 1.4 may add fields (additive only — no field removals after lock).
#[derive(Debug, Clone, uniffi::Record)]
pub struct SessionInfo {
    /// Issue 1.1 schema-version slot.
    pub schema_version: u16,
    /// Wall-clock timestamp the session was last refreshed. Foreign-
    /// language sides treat this as opaque.
    pub last_refresh_unix: i64,
    /// Whether the session is currently active. `false` means the
    /// caller must re-supply both proofs to resume.
    pub is_active: bool,
}

/// Opaque vault handle. `UniFFI` Object; not cloneable on the foreign
/// side (refcount lives on the Rust side via `Arc<VaultHandle>`).
///
/// Issue 1.1 ships an empty handle so the FFI scaffolding compiles;
/// 1.3 / 1.4 add the real backing state (a guarded `pangolin_core::Vault`
/// reference + an unlock-cache slot).
#[derive(Debug, uniffi::Object)]
pub struct VaultHandle;

impl VaultHandle {
    /// Construct an empty handle (scaffolding only). Real construction
    /// happens via `vault_open` / `vault_create` in 1.3 / 1.4.
    #[must_use]
    pub fn new_placeholder() -> Arc<Self> {
        Arc::new(Self)
    }
}

#[uniffi::export]
impl VaultHandle {
    /// Marker method so `UniFFI` emits a non-empty interface for the
    /// handle. Real operations land in 1.3 / 1.4.
    #[uniffi::method(name = "is_placeholder")]
    pub fn is_placeholder(&self) -> bool {
        true
    }
}

/// Unix-epoch seconds, UTC. Crosses FFI as a plain `i64`. Used by
/// `totp_generate` and `vault_export_*` paths.
pub type UnixTimestamp = i64;

/// Password-generator policy. Body lands in MVP-1 issue 1.8.
#[derive(Debug, Clone, uniffi::Record)]
pub struct PasswordPolicy {
    /// Issue 1.1 schema-version slot.
    pub schema_version: u16,
    /// Total password length in characters.
    pub length: u16,
    /// Whether to include uppercase letters.
    pub uppercase: bool,
    /// Whether to include lowercase letters.
    pub lowercase: bool,
    /// Whether to include digits.
    pub digits: bool,
    /// Whether to include symbol characters.
    pub symbols: bool,
}

/// Plaintext-export second-confirmation envelope (Design Spec §11). The
/// caller passes through the user's explicit "yes I really mean it"
/// gesture. Body lands in 1.10.
#[derive(Debug, Clone, uniffi::Record)]
pub struct PlaintextExportConfirmation {
    /// Issue 1.1 schema-version slot.
    pub schema_version: u16,
    /// Opaque token captured at the moment of confirmation. Single-use
    /// in 1.10's implementation.
    pub token: Vec<u8>,
}

// -- Locked-in-1.1 vault lifecycle entry points -----------------------
//
// Bodies are `todo!()` until 1.3 / 1.4 land. `tests/roundtrip.rs`
// asserts the FFI bindgen sees these signatures and emits non-empty
// Swift / Kotlin scaffolding for them; the runtime panic is irrelevant
// to that smoke test.

/// Create a fresh vault on disk. Body lands in 1.3.
///
/// # Panics
/// Panics with `todo!()` until 1.3 lands.
#[uniffi::export]
pub fn vault_create(path: String, password: Arc<SecretPassword>) -> Result<(), FfiError> {
    let _ = (path, password);
    todo!("vault_create body lands in MVP-1 issue 1.3")
}

/// Open a previously-created vault file. Body lands in 1.3.
///
/// # Panics
/// Panics with `todo!()` until 1.3 lands.
#[uniffi::export]
pub fn vault_open(path: String) -> Result<Arc<VaultHandle>, FfiError> {
    let _ = path;
    todo!("vault_open body lands in MVP-1 issue 1.3")
}

/// Unlock a vault with password + presence proof. Body lands in 1.4.
///
/// # Panics
/// Panics with `todo!()` until 1.4 lands.
#[uniffi::export]
pub fn vault_unlock(
    handle: Arc<VaultHandle>,
    password: Arc<SecretPassword>,
    presence: PresenceProof,
) -> Result<SessionInfo, FfiError> {
    let _ = (handle, password, presence);
    todo!("vault_unlock body lands in MVP-1 issue 1.4")
}

/// Lock a vault, zeroing in-memory secrets. Body lands in 1.4.
///
/// # Panics
/// Panics with `todo!()` until 1.4 lands.
#[uniffi::export]
pub fn vault_lock(handle: Arc<VaultHandle>) -> Result<(), FfiError> {
    let _ = handle;
    todo!("vault_lock body lands in MVP-1 issue 1.4")
}

/// Close a vault handle. Body lands in 1.4.
///
/// # Panics
/// Panics with `todo!()` until 1.4 lands.
#[uniffi::export]
pub fn vault_close(handle: Arc<VaultHandle>) -> Result<(), FfiError> {
    let _ = handle;
    todo!("vault_close body lands in MVP-1 issue 1.4")
}

/// Read session status without mutating the vault. Body lands in 1.4.
///
/// # Panics
/// Panics with `todo!()` until 1.4 lands.
#[uniffi::export]
pub fn session_status(handle: Arc<VaultHandle>) -> SessionInfo {
    let _ = handle;
    todo!("session_status body lands in MVP-1 issue 1.4")
}

/// Extend the active session's idle timer. Body lands in 1.4.
///
/// # Panics
/// Panics with `todo!()` until 1.4 lands.
#[uniffi::export]
pub fn session_extend(handle: Arc<VaultHandle>) -> Result<SessionInfo, FfiError> {
    let _ = handle;
    todo!("session_extend body lands in MVP-1 issue 1.4")
}

/// Generate a password matching the supplied policy. Body lands in 1.8.
///
/// # Panics
/// Panics with `todo!()` until 1.8 lands.
#[uniffi::export]
pub fn password_generate(policy: PasswordPolicy) -> Arc<SecretPassword> {
    let _ = policy;
    todo!("password_generate body lands in MVP-1 issue 1.8")
}

/// Export the vault encrypted with a fresh key (e.g., for backup).
/// Body lands in 1.10.
///
/// # Panics
/// Panics with `todo!()` until 1.10 lands.
#[uniffi::export]
pub fn vault_export_encrypted(handle: Arc<VaultHandle>, dest: String) -> Result<(), FfiError> {
    let _ = (handle, dest);
    todo!("vault_export_encrypted body lands in MVP-1 issue 1.10")
}

/// Export the vault as plaintext. Requires an explicit second
/// confirmation; Design Spec §11 mandates this branch be visually
/// distinct from the encrypted-export path. Body lands in 1.10.
///
/// # Panics
/// Panics with `todo!()` until 1.10 lands.
#[uniffi::export]
pub fn vault_export_plaintext(
    handle: Arc<VaultHandle>,
    dest: String,
    confirmation: PlaintextExportConfirmation,
) -> Result<(), FfiError> {
    let _ = (handle, dest, confirmation);
    todo!("vault_export_plaintext body lands in MVP-1 issue 1.10")
}
