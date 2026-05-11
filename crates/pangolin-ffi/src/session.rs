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

    /// Crate-private: borrow the raw bytes for the FFI bridge module.
    /// External callers cannot reach the bytes directly off a
    /// `&SecretPassword` reference — the only way out is through this
    /// crate-private accessor or a presence-gated reveal entry point.
    pub(crate) fn bytes_for_bridge(&self) -> &[u8] {
        self.bytes.as_slice()
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
/// `session_status` / `session_extend`.
///
/// The first three fields are the locked-in-1.1 minimum; MVP-1 issue
/// 1.4 adds the deadline / config fields (additive only — no field
/// removals after lock; flagged in `docs/architecture/ffi-surface.md`
/// as an additive amendment, same posture as 1.2's record widenings).
#[derive(Debug, Clone, uniffi::Record)]
pub struct SessionInfo {
    /// Issue 1.1 schema-version slot.
    pub schema_version: u16,
    /// Wall-clock unix-second timestamp the session was last refreshed
    /// (the most recent activity touch / proof). `0` when not active.
    pub last_refresh_unix: i64,
    /// Whether the session is currently active. `false` means the
    /// caller must re-supply both proofs to resume.
    pub is_active: bool,
    /// **1.4 (additive).** Wall-clock unix-second instant the idle
    /// timer fires. `0` when not active. For `SessionDuration::UntilDeviceLock`
    /// this equals `absolute_deadline_unix` (no idle leg).
    pub idle_deadline_unix: i64,
    /// **1.4 (additive).** Wall-clock unix-second instant the absolute-
    /// max ceiling (4 h, not configurable) fires regardless of
    /// activity. `0` when not active.
    pub absolute_deadline_unix: i64,
    /// **1.4 (additive).** The configured idle duration in seconds
    /// (Session spec §7.2: one of 300 / 900 / 1800 / 3600 / 14400) or
    /// `-1` for "until device lock". Always present (a property of the
    /// vault file, valid even when locked).
    pub configured_idle_secs: i64,
    /// **1.4 (additive).** Wall-clock unix-second instant until which
    /// the last successful presence proof remains "fresh" (the 60 s
    /// dedup window — a reveal-class op before this instant does not
    /// re-prompt). `0` when not active.
    pub last_presence_fresh_until_unix: i64,
}

/// Opaque vault handle. `UniFFI` Object; not cloneable on the foreign
/// side (refcount lives on the Rust side via `Arc<VaultHandle>`).
///
/// Issue 1.2 widens the handle to carry an optional `Vault` slot so
/// the `account_*` FFI bodies can route through real persistence.
/// Production unlock (`vault_unlock`) and session lifecycle bodies
/// still land in 1.3 / 1.4; 1.2 only commits to the *slot*.
#[derive(uniffi::Object)]
pub struct VaultHandle {
    inner: std::sync::Mutex<Option<pangolin_core::Vault>>,
}

impl std::fmt::Debug for VaultHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultHandle")
            .field("vault", &"<opaque>")
            .finish()
    }
}

impl VaultHandle {
    /// Construct an empty handle (scaffolding only). Real construction
    /// happens via `vault_open` / `vault_create` in 1.3 / 1.4.
    #[must_use]
    pub fn new_placeholder() -> Arc<Self> {
        Arc::new(Self {
            inner: std::sync::Mutex::new(None),
        })
    }

    /// Issue 1.2 helper: install a fully-prepared `Vault` (already
    /// unlocked by the caller) into a fresh handle. Used by the
    /// `account_*` FFI integration tests until 1.4's session-aware
    /// `vault_open` / `vault_unlock` bodies land.
    #[must_use]
    pub fn from_vault(vault: pangolin_core::Vault) -> Arc<Self> {
        Arc::new(Self {
            inner: std::sync::Mutex::new(Some(vault)),
        })
    }

    /// Acquire a guard on the inner vault slot. The guard yields
    /// `Some(&mut Vault)` when a vault has been installed and `None`
    /// when the handle is still a placeholder.
    pub(crate) fn lock_vault(&self) -> VaultGuard<'_> {
        VaultGuard {
            inner: self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        }
    }

    /// True when the handle currently has no vault installed (i.e., it
    /// was constructed via [`Self::new_placeholder`] and the unlock
    /// path has not yet wired a real vault in).
    #[must_use]
    pub fn is_placeholder_inner(&self) -> bool {
        self.inner
            .lock()
            .map(|guard| guard.is_none())
            .unwrap_or(true)
    }
}

/// RAII guard around the inner `Option<Vault>`. Crate-private so
/// callers go through the typed `account_*` FFI surface.
pub(crate) struct VaultGuard<'a> {
    inner: std::sync::MutexGuard<'a, Option<pangolin_core::Vault>>,
}

impl VaultGuard<'_> {
    /// Borrow the vault as `&mut`. Returns
    /// `Err(FfiError::Session { .. })` when no vault is installed.
    pub fn as_mut(&mut self) -> Result<&mut pangolin_core::Vault, FfiError> {
        self.inner.as_mut().ok_or_else(|| FfiError::Session {
            message: "vault is not unlocked".to_owned(),
        })
    }

    /// Take the inner `Vault` out, leaving the handle empty. Used by
    /// `vault_close` (which consumes the `Vault` to release the
    /// `SQLite` connection). Returns `None` if the handle was already
    /// empty (idempotent close).
    pub fn take(&mut self) -> Option<pangolin_core::Vault> {
        self.inner.take()
    }
}

#[uniffi::export]
impl VaultHandle {
    /// Marker method retained for the round-trip smoke test in
    /// `tests/roundtrip.rs`.
    #[uniffi::method(name = "is_placeholder")]
    pub fn is_placeholder(&self) -> bool {
        self.is_placeholder_inner()
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

// -- Vault lifecycle + session entry points (bodies: MVP-1 issue 1.4) -

fn store_into_ffi(err: pangolin_store::StoreError) -> FfiError {
    FfiError::from(pangolin_core::Error::from(err))
}

/// Convert a `SystemTime` to whole unix seconds, or `0` on under/overflow.
fn system_time_to_unix(t: std::time::SystemTime) -> i64 {
    t.duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .unwrap_or(0)
}

/// A "not active" [`SessionInfo`] (vault locked / expired / no handle),
/// carrying only the configured idle duration.
fn not_active_session_info(configured_idle_secs: i64) -> SessionInfo {
    SessionInfo {
        schema_version: pangolin_core::ACCOUNT_IDENTITY_SCHEMA_VERSION,
        last_refresh_unix: 0,
        is_active: false,
        idle_deadline_unix: 0,
        absolute_deadline_unix: 0,
        configured_idle_secs,
        last_presence_fresh_until_unix: 0,
    }
}

/// Build the FFI [`SessionInfo`] from a `pangolin_core::Vault`'s
/// current session state. Read-only; never touches the proof.
fn session_info_from_vault(vault: &pangolin_core::Vault) -> SessionInfo {
    use pangolin_core::SessionState;
    let configured_idle_secs = vault.session_idle().to_meta_secs();
    let SessionState::Active {
        expires_at,
        last_proof_at,
        ..
    } = vault.session_state()
    else {
        return not_active_session_info(configured_idle_secs);
    };
    let absolute = vault
        .session_absolute_deadline()
        .map_or(0, system_time_to_unix);
    let presence_fresh_until = vault.last_presence_at().map_or(0, |p| {
        system_time_to_unix(p + pangolin_core::PRESENCE_FRESHNESS)
    });
    SessionInfo {
        schema_version: pangolin_core::ACCOUNT_IDENTITY_SCHEMA_VERSION,
        last_refresh_unix: system_time_to_unix(last_proof_at),
        is_active: vault.is_session_active(),
        idle_deadline_unix: system_time_to_unix(expires_at),
        absolute_deadline_unix: absolute,
        configured_idle_secs,
        last_presence_fresh_until_unix: presence_fresh_until,
    }
}

/// Create a fresh vault on disk at `path`.
///
/// Derives the authority from `password`. Returns the vault `Locked`
/// (the caller must [`vault_open`] + [`vault_unlock`] before adding
/// accounts). The password bytes zero on drop after the call returns.
///
/// # Errors
///
/// `FfiError::Store` for an I/O / `SQLite` failure (e.g. the file
/// already exists); `FfiError::Validation { kind: "authentication" }`
/// for a crypto-class failure.
#[uniffi::export]
pub fn vault_create(path: String, password: Arc<SecretPassword>) -> Result<(), FfiError> {
    let mut pw = zeroize::Zeroizing::new(password.bytes_for_bridge().to_vec());
    let secret = pangolin_crypto::secret::SecretBytes::new(std::mem::take(&mut *pw));
    pangolin_core::Vault::create(std::path::Path::new(&path), &secret).map_err(store_into_ffi)?;
    Ok(())
}

/// Open a previously-created vault file. Returns an opaque
/// [`VaultHandle`] holding the locked `Vault`.
///
/// # Errors
///
/// `FfiError::Store` for a bad magic / unsupported format version /
/// already-open / `SQLite` failure.
#[uniffi::export]
pub fn vault_open(path: String) -> Result<Arc<VaultHandle>, FfiError> {
    let vault = pangolin_core::Vault::open(std::path::Path::new(&path)).map_err(store_into_ffi)?;
    Ok(VaultHandle::from_vault(vault))
}

/// Unlock a vault — the 2-proof start of the session invariant.
///
/// The password is the identity proof; `presence` is the presence
/// proof (the CLI tier maps it to a fresh `PressYPresenceProof::confirmed()`;
/// the `presence.bytes` field is the slot MVP-3/4 hardware proofs
/// fill). Returns the resulting [`SessionInfo`]. The password bytes
/// zero on drop after the call returns.
///
/// # Errors
///
/// `FfiError::Validation { kind: "authentication" }` for any proof- or
/// crypto-class failure (wrong password, replayed/stale presence,
/// tampered meta — all collapse, MEDIUM-1 indistinguishability);
/// `FfiError::Session` if the handle has no vault installed.
#[allow(clippy::significant_drop_tightening)]
#[uniffi::export]
pub fn vault_unlock(
    handle: Arc<VaultHandle>,
    password: Arc<SecretPassword>,
    presence: PresenceProof,
) -> Result<SessionInfo, FfiError> {
    let _ = presence; // CLI tier ignores the bytes; see module note.
    let mut guard = handle.lock_vault();
    let vault = guard.as_mut()?;
    let mut pw = zeroize::Zeroizing::new(password.bytes_for_bridge().to_vec());
    let identity = pangolin_core::PinIdentityProof::new(pangolin_crypto::secret::SecretBytes::new(
        std::mem::take(&mut *pw),
    ));
    let presence_proof = pangolin_core::PressYPresenceProof::confirmed();
    vault
        .unlock(&presence_proof, &identity)
        .map_err(store_into_ffi)?;
    Ok(session_info_from_vault(vault))
}

/// Lock a vault, zeroing the in-memory cache + VDK and tearing down the
/// `:memory:` search index. Idempotent. The handle stays valid; a
/// subsequent [`vault_unlock`] re-activates the session.
///
/// # Errors
///
/// `FfiError::Session` if the handle has no vault installed.
#[allow(clippy::significant_drop_tightening)]
#[uniffi::export]
pub fn vault_lock(handle: Arc<VaultHandle>) -> Result<(), FfiError> {
    let mut guard = handle.lock_vault();
    let vault = guard.as_mut()?;
    vault.lock();
    Ok(())
}

/// Close a vault handle — locks it, then releases the `SQLite`
/// connection (the inner `Vault` is consumed; the handle is left
/// empty). Idempotent: closing an already-empty handle is a no-op.
///
/// # Errors
///
/// `FfiError::Store` on a close-path storage failure (rare).
#[allow(clippy::significant_drop_tightening)]
#[uniffi::export]
pub fn vault_close(handle: Arc<VaultHandle>) -> Result<(), FfiError> {
    let mut guard = handle.lock_vault();
    if let Some(vault) = guard.take() {
        vault.close().map_err(store_into_ffi)?;
    }
    Ok(())
}

/// Read the current session status without mutating the vault.
///
/// Infallible (matches the 1.1-frozen signature): a handle with no
/// vault installed reports a "not active" status with the default
/// configured idle duration.
#[allow(clippy::significant_drop_tightening)]
#[uniffi::export]
pub fn session_status(handle: Arc<VaultHandle>) -> SessionInfo {
    let mut guard = handle.lock_vault();
    guard.as_mut().map_or_else(
        |_| not_active_session_info(pangolin_core::SessionDuration::DEFAULT.to_meta_secs()),
        |vault| session_info_from_vault(vault),
    )
}

/// Extend the active session's idle timer — the single-proof
/// "maintain" leg of the session invariant.
///
/// **High-risk per Session spec §5.4 ("extend long sessions"):**
/// requires a presence proof (1.4 amends the 1.1 signature to take one
/// — additive argument, safe because nothing external binds the 1.1
/// surface yet; flagged in `ffi-surface.md`). Re-extends the idle
/// deadline (still capped at the absolute-max ceiling). Within the
/// 60 s freshness window of the last successful presence (including
/// the unlock's) no re-prompt is needed.
///
/// # Errors
///
/// `FfiError::Session` for a locked / expired session or a timed-out
/// presence prompt; `FfiError::Validation { kind: "authentication" }`
/// for any other proof failure.
#[allow(clippy::significant_drop_tightening)]
#[uniffi::export]
pub fn session_extend(
    handle: Arc<VaultHandle>,
    presence: PresenceProof,
) -> Result<SessionInfo, FfiError> {
    let _ = presence; // CLI tier ignores the bytes; see module note.
    let mut guard = handle.lock_vault();
    let vault = guard.as_mut()?;
    let proof = pangolin_core::PressYPresenceProof::confirmed();
    vault
        .touch_session_explicit(&proof)
        .map_err(store_into_ffi)?;
    Ok(session_info_from_vault(vault))
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
