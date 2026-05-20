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

/// Schema-version slot value for [`PasswordPolicy`] / [`PasswordStrength`].
pub const PASSWORD_POLICY_SCHEMA_VERSION: u16 = 1;

/// Password-generator policy. Implemented in MVP-1 issue 1.8.
///
/// `exclude_ambiguous` was added in 1.8 (additive — nothing external
/// binds the record yet). [`password_policy_default`] returns the
/// strong-defaults shape.
#[derive(Debug, Clone, uniffi::Record)]
pub struct PasswordPolicy {
    /// Issue 1.1 schema-version slot.
    pub schema_version: u16,
    /// Total password length in characters. Generator-valid range
    /// `[8, 128]`; default 16.
    pub length: u16,
    /// Whether to include uppercase letters.
    pub uppercase: bool,
    /// Whether to include lowercase letters.
    pub lowercase: bool,
    /// Whether to include digits.
    pub digits: bool,
    /// Whether to include symbol characters (the 32 ASCII punctuation
    /// chars; `|` is also dropped when `exclude_ambiguous` is set).
    pub symbols: bool,
    /// Drop visually-confusable characters (`0 O 1 l I |`) from the
    /// enabled classes. Defaults to `true` in [`password_policy_default`].
    pub exclude_ambiguous: bool,
}

impl PasswordPolicy {
    /// Convert to the `pangolin-core` plain policy (drops the FFI-wire
    /// `schema_version` slot — a transport concern the generator never
    /// reads).
    fn to_core(&self) -> pangolin_core::pwgen::PwgenPolicy {
        pangolin_core::pwgen::PwgenPolicy {
            length: self.length,
            uppercase: self.uppercase,
            lowercase: self.lowercase,
            digits: self.digits,
            symbols: self.symbols,
            exclude_ambiguous: self.exclude_ambiguous,
        }
    }

    fn from_core(p: pangolin_core::pwgen::PwgenPolicy) -> Self {
        Self {
            schema_version: PASSWORD_POLICY_SCHEMA_VERSION,
            length: p.length,
            uppercase: p.uppercase,
            lowercase: p.lowercase,
            digits: p.digits,
            symbols: p.symbols,
            exclude_ambiguous: p.exclude_ambiguous,
        }
    }
}

/// Strength estimate for an arbitrary (typed/imported) password.
///
/// A zxcvbn-style heuristic. Added in MVP-1 issue 1.8. Not sensitive
/// (no secret in the record itself — the input password is consumed and
/// zeroized by [`password_strength`]).
#[derive(Debug, Clone, uniffi::Record)]
pub struct PasswordStrength {
    /// Schema-version slot.
    pub schema_version: u16,
    /// zxcvbn score, 0 (weakest) .. 4 (strongest).
    pub score: u8,
    /// Base-10 logarithm of the estimated guess count.
    pub guesses_log10: f64,
    /// Conservative crack-time estimate, in seconds: an attacker with
    /// the offline hash at 10k guesses/second.
    pub crack_time_seconds: f64,
    /// A top-level warning, if zxcvbn produced one.
    pub feedback_warning: Option<String>,
    /// Actionable suggestions for a stronger password.
    pub feedback_suggestions: Vec<String>,
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

/// Pre-lock drain.
///
/// Calls [`pangolin_core::Vault::lock_with_drain`] BEFORE
/// transitioning to Locked. Closes the 5.1 L1 deviation by draining
/// any dirty markers (with `force = true` bypassing the 30 s window)
/// before the lock.
///
/// **MVP-3 issue #100.** Builds a `BaseSepoliaAdapter` engine-side
/// from the unlocked vault's per-device gas wallet (the signer is
/// read via `Vault::evm_wallet().signer()` and cloned engine-side —
/// **no secret material crosses FFI**, L1) plus the host-supplied
/// non-secret `config`, then drives the `!Send`
/// `Vault::lock_with_drain` future to completion on a local
/// current-thread runtime.
///
/// # Errors
///
/// `FfiError::Session` for a locked / placeholder handle (the L4
/// session gate, before any chain primitive); `FfiError::Store` /
/// `FfiError::Chain` for adapter-construction or drain failures.
/// Note: the vault transitions to Locked regardless of the drain
/// outcome (best-effort drain; teardown wins) — a returned error
/// reports the drain result, not a still-unlocked state.
#[allow(clippy::significant_drop_tightening, clippy::needless_pass_by_value)]
#[uniffi::export]
pub fn vault_lock_with_drain(
    handle: Arc<VaultHandle>,
    config: crate::chain_config::FfiChainConfig,
) -> Result<(), FfiError> {
    use pangolin_chain::BaseSepoliaAdapter;
    use pangolin_crypto::keys::DeviceKey;

    // Active-session gate at the FFI boundary (L4), BEFORE any chain
    // primitive.
    let mut guard = handle.lock_vault();
    let vault = guard.as_mut()?;
    // L1: read the gas-paying signer engine-side from the unlocked
    // vault and clone it. Never crosses FFI.
    let signer = vault.evm_wallet().map_err(store_into_ffi)?.signer().clone();
    // Throwaway device key (the gas wallet is internal to the adapter,
    // two-key PoC model); SEPARATE from the gas wallet sourced above.
    // NOT a host input.
    let throwaway_device_key = DeviceKey::generate();
    crate::chain_config::block_on_local(async {
        let adapter = BaseSepoliaAdapter::new_with_signer(
            &config.rpc_url,
            std::path::Path::new(&config.deployment_path),
            signer,
        )
        .await
        .map_err(crate::chain_config::chain_into_ffi)?;
        vault
            .lock_with_drain(&adapter, &throwaway_device_key)
            .await
            .map_err(crate::chain_config::batch_flush_into_ffi)
    })?
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

/// Generate a password matching the supplied policy.
///
/// Draws entropy exclusively from the OS CSPRNG (via
/// `pangolin_crypto::rng`), selects characters without modulo bias
/// (rejection sampling), and guarantees ≥1 char of each enabled class.
/// See `docs/architecture/password-generator.md`.
///
/// # Errors
/// `FfiError::Validation { kind: "password_policy" }` for an invalid
/// policy (no character class enabled; `length` outside `[8, 128]`;
/// `length` below the count of enabled classes). The generator fails
/// loudly rather than clamping — a generated password that silently
/// matched a *different* policy than the caller asked for is a bad
/// failure mode for a security artifact.
#[uniffi::export]
pub fn password_generate(policy: PasswordPolicy) -> Result<Arc<SecretPassword>, FfiError> {
    let mut generated = pangolin_core::pwgen::generate(&policy.to_core())?;
    // Move the bytes out of the `Zeroizing<String>` into `SecretPassword`'s
    // own zeroizing buffer; the (now-empty) `Zeroizing<String>` zeroes its
    // freed allocation on drop, and `SecretPassword` zeroizes the bytes.
    let bytes = std::mem::take(&mut *generated).into_bytes();
    Ok(SecretPassword::new(bytes))
}

/// Exact bit-entropy of a password produced by `policy` —
/// `length × log2(alphabet_size)`. A pure function of the policy;
/// computable without generating.
///
/// # Errors
/// `FfiError::Validation { kind: "password_policy" }` for an invalid
/// policy (so this and [`password_generate`] agree on validity).
#[uniffi::export]
pub fn password_entropy_bits(policy: PasswordPolicy) -> Result<f64, FfiError> {
    Ok(pangolin_core::pwgen::entropy_bits(&policy.to_core())?)
}

/// Heuristic (zxcvbn-style) strength estimate for an arbitrary
/// (typed/imported) password.
///
/// Infallible — always returns a [`PasswordStrength`]. The `password`
/// argument is consumed into Rust-owned memory and zeroized before this
/// function returns.
#[uniffi::export]
pub fn password_strength(password: String) -> PasswordStrength {
    let password = zeroize::Zeroizing::new(password);
    let s = pangolin_core::pwgen::strength(&password);
    PasswordStrength {
        schema_version: PASSWORD_POLICY_SCHEMA_VERSION,
        score: s.score,
        guesses_log10: s.guesses_log10,
        crack_time_seconds: s.crack_time_seconds,
        feedback_warning: s.feedback_warning,
        feedback_suggestions: s.feedback_suggestions,
    }
}

/// The strong-defaults [`PasswordPolicy`]: length 16, all four
/// character classes enabled, ambiguous characters excluded.
#[uniffi::export]
pub fn password_policy_default() -> PasswordPolicy {
    PasswordPolicy::from_core(pangolin_core::pwgen::PwgenPolicy::default())
}

// -- MVP-1 issue 1.10: encrypted export / restore-to-fresh-vault -------
//
// Additive 1.1-surface amendment (same posture as 1.2/1.4/1.7/1.9):
// - `vault_export_encrypted` grows `presence`, an export `passphrase`,
//   and an optional `accounts` subset selector (D1/D5/D9).
// - `vault_export_plaintext` grows `presence` + the `accounts` selector;
//   keeps its frozen `PlaintextExportConfirmation` Record (the FFI
//   requires a structurally-valid single-use token; the CLI/UI owns the
//   30 s delay + double-y/N + warning copy per master plan §4 row 1.10).
// - new `vault_restore_from_archive` entry (D2/D4) — operates on a file
//   path + archive passphrase, not an unlocked vault; creates a brand-new
//   `.pvf` from a decoded archive (no merge into an existing vault).
//
// `ffi-surface.md` records the amendments.

/// Build the CLI-tier presence proof from the 1.1-frozen FFI envelope.
/// (`bytes` is unused for the CLI tier; the engine owns dedup.)
fn presence_from_ffi(_proof: PresenceProof) -> pangolin_core::PressYPresenceProof {
    pangolin_core::PressYPresenceProof::confirmed()
}

/// Parse the FFI `accounts: Option<Vec<String>>` (hex-encoded 32-byte
/// account ids) into an [`pangolin_core::AccountSelection`].
fn parse_account_selection(
    accounts: Option<Vec<String>>,
) -> Result<pangolin_core::AccountSelection, FfiError> {
    match accounts {
        None => Ok(pangolin_core::AccountSelection::All),
        Some(list) => {
            let mut out = Vec::with_capacity(list.len());
            for s in list {
                let bytes = decode_hex32(&s).ok_or_else(|| FfiError::Validation {
                    kind: "export_account_id".into(),
                    message: "account id must be 64 hex characters".into(),
                })?;
                out.push(bytes);
            }
            Ok(pangolin_core::AccountSelection::Subset(out))
        }
    }
}

fn decode_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        let hi = (s.as_bytes()[2 * i] as char).to_digit(16)?;
        let lo = (s.as_bytes()[2 * i + 1] as char).to_digit(16)?;
        *b = u8::try_from(hi * 16 + lo).ok()?;
    }
    Some(out)
}

/// Write `bytes` to `dest`, never clobbering an existing file. On Unix,
/// the umask-respecting create plus an explicit `0o600` chmod restricts
/// the file to the owner (env-quirk #1: on CI Linux umask 0o077 the file
/// already lands ~0o600). A partial file is removed if the write fails.
fn write_export_file(dest: &str, bytes: &[u8]) -> Result<(), FfiError> {
    use std::io::Write as _;
    let path = std::path::Path::new(dest);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| FfiError::Validation {
            kind: "export_io".into(),
            message: format!("cannot create export file: {e}"),
        })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mut perms = f
            .metadata()
            .map_err(|e| FfiError::Validation {
                kind: "export_io".into(),
                message: format!("cannot stat export file: {e}"),
            })?
            .permissions();
        perms.set_mode(0o600);
        let _ = f.set_permissions(perms);
    }
    if let Err(e) = f.write_all(bytes).and_then(|()| f.flush()) {
        drop(f);
        let _ = std::fs::remove_file(path);
        return Err(FfiError::Validation {
            kind: "export_io".into(),
            message: format!("cannot write export file: {e}"),
        });
    }
    Ok(())
}

/// Non-secret report returned by the export FFI ops.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ExportReport {
    /// Schema-version slot.
    pub schema_version: u16,
    /// Number of accounts written into the archive.
    pub account_count: u32,
    /// Number of bytes written to the destination file.
    pub bytes_written: u64,
    /// Whether the file is the *encrypted* archive (`true`) or the
    /// guarded *plaintext* dump (`false`).
    pub encrypted: bool,
}

/// Non-secret report returned by [`vault_restore_from_archive`].
#[derive(Debug, Clone, uniffi::Record)]
pub struct RestoreReport {
    /// Schema-version slot.
    pub schema_version: u16,
    /// Number of accounts restored into the new vault.
    pub account_count: u32,
    /// Number of devices present in the decoded archive. (The restore
    /// path does **not** carry the device trust list over into the new
    /// vault — see [`pangolin_store::Vault::restore_to_new_vault`] — this
    /// is purely the count from the decoded archive payload.)
    pub device_count: u32,
}

/// Export a self-contained **encrypted** Pangolin vault archive to
/// `dest`. **High-risk operation** (Session spec §5.4) — presence-gated.
///
/// The archive is AEAD-sealed under a 256-bit key derived (Argon2id,
/// `RECOMMENDED`) from `passphrase` — a *fresh* export passphrase,
/// independent of the vault master password — over a random salt stored
/// in the archive's plaintext header (the AEAD AAD). `passphrase` is
/// consumed into Rust-owned memory and zeroized before returning.
/// `accounts` (hex-encoded 32-byte ids) narrows the export to a subset;
/// `None` = the whole vault. The archive is written to `dest` with
/// restrictive permissions; `dest` is never clobbered.
///
/// # Errors
///
/// `FfiError::Session` for a locked/expired session or a timed-out
/// presence prompt; `FfiError::Validation` with an `export_*` `kind`
/// for an IO / serialization / crypto failure.
#[allow(clippy::significant_drop_tightening)]
#[uniffi::export]
pub fn vault_export_encrypted(
    handle: Arc<VaultHandle>,
    dest: String,
    passphrase: Arc<SecretPassword>,
    accounts: Option<Vec<String>>,
    presence: PresenceProof,
) -> Result<ExportReport, FfiError> {
    let selection = parse_account_selection(accounts)?;
    let mut pw = zeroize::Zeroizing::new(passphrase.bytes_for_bridge().to_vec());
    let secret = pangolin_crypto::secret::SecretBytes::new(std::mem::take(&mut *pw));
    let mut guard = handle.lock_vault();
    let vault = guard.as_mut()?;
    let proof = presence_from_ffi(presence);
    let archive = vault
        .export_encrypted(&secret, &selection, &proof)
        .map_err(store_into_ffi)?;
    let count = match &selection {
        pangolin_core::AccountSelection::All => vault.list_accounts().len(),
        pangolin_core::AccountSelection::Subset(ids) => ids.len(),
    };
    drop(secret);
    write_export_file(&dest, &archive)?;
    let bytes_written = u64::try_from(archive.len()).unwrap_or(u64::MAX);
    Ok(ExportReport {
        schema_version: PASSWORD_POLICY_SCHEMA_VERSION,
        account_count: u32::try_from(count).unwrap_or(u32::MAX),
        bytes_written,
        encrypted: true,
    })
}

/// Export the vault as an **unencrypted cleartext** dump to `dest`.
///
/// The spec-guarded `--plaintext` branch (Design Spec §11). **This
/// writes every secret in cleartext.** Presence-gated *and* requires a
/// structurally-valid single-use `confirmation` token (the CLI/UI owns
/// the double-confirmation + 30 s delay + warning copy). `accounts`
/// narrows the export; `None` = the whole vault. The file is written
/// with restrictive permissions; `dest` is never clobbered.
///
/// # Errors
///
/// As [`vault_export_encrypted`], plus `FfiError::Validation` with
/// `kind = "export_not_confirmed"` for a missing/invalid token.
#[allow(clippy::significant_drop_tightening)]
#[uniffi::export]
pub fn vault_export_plaintext(
    handle: Arc<VaultHandle>,
    dest: String,
    confirmation: PlaintextExportConfirmation,
    accounts: Option<Vec<String>>,
    presence: PresenceProof,
) -> Result<ExportReport, FfiError> {
    let selection = parse_account_selection(accounts)?;
    let conf = pangolin_core::PlaintextExportConfirmationData {
        schema_version: confirmation.schema_version,
        token: confirmation.token,
    };
    let mut guard = handle.lock_vault();
    let vault = guard.as_mut()?;
    let proof = presence_from_ffi(presence);
    let bytes = vault
        .export_plaintext(&conf, &selection, &proof)
        .map_err(store_into_ffi)?;
    let count = match &selection {
        pangolin_core::AccountSelection::All => vault.list_accounts().len(),
        pangolin_core::AccountSelection::Subset(ids) => ids.len(),
    };
    write_export_file(&dest, &bytes)?;
    let bytes_written = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    Ok(ExportReport {
        schema_version: PASSWORD_POLICY_SCHEMA_VERSION,
        account_count: u32::try_from(count).unwrap_or(u32::MAX),
        bytes_written,
        encrypted: false,
    })
}

/// Restore a **brand-new** `.pvf` vault at `dest` from the encrypted
/// archive at `archive_path`.
///
/// Uses `new_vault_password` as the new vault's master password. Does
/// **not** touch any existing vault and does **not** merge an archive
/// into an existing vault (deferred to MVP-2). `archive_passphrase` +
/// `new_vault_password` are consumed into Rust-owned memory and zeroized
/// before returning. `dest` is never clobbered.
///
/// # Errors
///
/// `FfiError::Validation` with `kind = "export_format"` for a malformed
/// archive, `kind = "export_credentials"` for a wrong archive passphrase
/// or a tampered archive (one error — no oracle), `kind = "export_io"`
/// for an IO failure, `kind = "export_too_large"` for an oversized
/// archive file; storage-level errors otherwise.
#[uniffi::export]
pub fn vault_restore_from_archive(
    archive_path: String,
    dest: String,
    archive_passphrase: Arc<SecretPassword>,
    new_vault_password: Arc<SecretPassword>,
) -> Result<RestoreReport, FfiError> {
    // Bounded read of the archive file (256 MiB ceiling — env-quirk: a
    // hostile "archive" must not OOM us).
    const MAX_ARCHIVE_FILE: u64 = 256 * 1024 * 1024;
    let meta = std::fs::metadata(&archive_path).map_err(|e| FfiError::Validation {
        kind: "export_io".into(),
        message: format!("cannot open archive: {e}"),
    })?;
    if meta.len() > MAX_ARCHIVE_FILE {
        return Err(FfiError::Validation {
            kind: "export_too_large".into(),
            message: "archive file exceeds the maximum size".into(),
        });
    }
    let bytes = std::fs::read(&archive_path).map_err(|e| FfiError::Validation {
        kind: "export_io".into(),
        message: format!("cannot read archive: {e}"),
    })?;
    let mut ap = zeroize::Zeroizing::new(archive_passphrase.bytes_for_bridge().to_vec());
    let archive_pw = pangolin_crypto::secret::SecretBytes::new(std::mem::take(&mut *ap));
    let snapshot = pangolin_core::decode_archive(&bytes, &archive_pw).map_err(store_into_ffi)?;
    drop(archive_pw);
    let account_count = u32::try_from(snapshot.accounts.len()).unwrap_or(u32::MAX);
    let device_count = u32::try_from(snapshot.devices.len()).unwrap_or(u32::MAX);
    let mut np = zeroize::Zeroizing::new(new_vault_password.bytes_for_bridge().to_vec());
    let new_pw = pangolin_crypto::secret::SecretBytes::new(std::mem::take(&mut *np));
    pangolin_core::Vault::restore_to_new_vault(std::path::Path::new(&dest), snapshot, &new_pw)
        .map_err(store_into_ffi)?;
    drop(new_pw);
    Ok(RestoreReport {
        schema_version: PASSWORD_POLICY_SCHEMA_VERSION,
        account_count,
        device_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain_config::FfiChainConfig;
    use pangolin_core::{PinIdentityProof, PressYPresenceProof, Vault};
    use pangolin_crypto::secret::SecretBytes;

    fn pwd() -> SecretBytes {
        SecretBytes::new(b"correct horse battery staple".to_vec())
    }

    fn unlocked_handle(dir: &tempfile::TempDir, name: &str) -> Arc<VaultHandle> {
        let path = dir.path().join(name);
        Vault::create(&path, &pwd()).unwrap();
        let mut v = Vault::open(&path).unwrap();
        v.unlock(
            &PressYPresenceProof::confirmed(),
            &PinIdentityProof::new(pwd()),
        )
        .unwrap();
        VaultHandle::from_vault(v)
    }

    fn bogus_config() -> FfiChainConfig {
        FfiChainConfig {
            schema_version: 1,
            rpc_url: "http://127.0.0.1:1".into(),
            deployment_path: "/no/such/path/base-sepolia.json".into(),
            prefer_websocket: false,
        }
    }

    /// **MVP-3 #100 (R-f) — REAL-path stub-parity flip.** With an
    /// empty publish queue + a bogus chain config, the REAL
    /// lock-with-drain path runs: it sources the gas signer
    /// engine-side and attempts adapter construction, which fails fast
    /// on the missing deployment file → `FfiError::Chain` (NOT the old
    /// `Internal` stub).
    #[test]
    fn lock_with_drain_real_path_maps_adapter_error_to_chain() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        let err = vault_lock_with_drain(h, bogus_config()).unwrap_err();
        assert!(
            matches!(err, FfiError::Chain { .. }),
            "expected FfiError::Chain from adapter construction, got {err:?}"
        );
    }

    /// **MVP-3 #100 (R-f) — per-binding session gate (L4).** A locked
    /// vault errors `FfiError::Session` BEFORE any chain primitive.
    #[test]
    fn lock_with_drain_rejects_locked_vault_before_chain() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        {
            let mut g = h.lock_vault();
            g.as_mut().unwrap().lock();
        }
        let err = vault_lock_with_drain(h, bogus_config()).unwrap_err();
        assert!(
            matches!(err, FfiError::Session { .. }),
            "expected FfiError::Session (L4 gate before chain), got {err:?}"
        );
    }

    /// **MVP-3 #100 (R-f) — per-binding session gate (placeholder).**
    #[test]
    fn lock_with_drain_rejects_placeholder() {
        let empty = VaultHandle::new_placeholder();
        let err = vault_lock_with_drain(empty, bogus_config()).unwrap_err();
        assert!(
            matches!(err, FfiError::Session { .. }),
            "expected FfiError::Session, got {err:?}"
        );
    }
}
