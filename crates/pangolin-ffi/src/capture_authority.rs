// SPDX-License-Identifier: AGPL-3.0-or-later
//! Capture-authority FFI shapes + entry points (MVP-1 issue 1.11).
//!
//! Browser-Ext spec §2.3 / Threat Model invariant #8 / API contract
//! §16. The `pangolin-store` engine owns the registry; this module
//! is the FFI shim that maps the validated FFI Records to the store
//! types and back, with the [`FfiError`] mapping going through
//! `pangolin-core`'s `From<StoreError>` (which routes the new
//! `CaptureAuthorityValidation` / `CaptureAuthorityExclusivity`
//! `StoreError` variants to `Validation { kind: "capture_authority" /
//! "capture_authority_exclusivity" }` per the §15 no-info-leak
//! discipline).
//!
//! ## Auth tier (L6, R-c — HYBRID)
//!
//! `capture_authority_register` is the **single FFI entry that
//! requires a presence proof argument even though only one of its
//! three outcomes (`Replaced`) actually consumes it**:
//!
//! - **`Created`** (first registration for a `(kind, platform_hint)`
//!   key) — session-class. Active non-expired session; the presence
//!   proof argument is held but never verified.
//! - **`NoOp`** (re-register with byte-identical payload) —
//!   session-class. Same posture as `Created`.
//! - **`Replaced`** (existing row overwritten; caller opted in via
//!   `replace_existing=true`) — reveal-class. The store routes
//!   through `ensure_presence_fresh` BEFORE the REPLACE commits.
//!   A stale proof surfaces `PromptTimedOut` → `FfiError::Session`.
//!
//! The 1.11 FFI body collapses every successful outcome to `Ok(())`;
//! the per-outcome `RegistrationOutcome` discriminator is kept on the
//! store side for tests + a future MVP-2 amendment that may surface
//! the `prior` payload on Replaced (out of scope for 1.11).
//!
//! ## 1.1 surface cleanup
//!
//! The 1.1 scaffold parked `CaptureAuthority`/`CaptureContext` in
//! `kdbx.rs` (where they don't belong). 1.11 moves them here +
//! finalises the shape per L5: closed `uniffi::Enum` discriminators,
//! NFC + length + character-class + allowlist validation for the
//! identifier strings. Nothing external binds the 1.1 surface yet
//! (the original `register` body was `todo!()`), so this is an
//! additive amendment — same posture as 1.2/1.4/1.7/1.9/1.10.

use std::sync::Arc;

use crate::error::FfiError;
use crate::session::{PresenceProof, UnixTimestamp, VaultHandle};

/// Which kind of component owns capture for a context.
///
/// Closed enum (master plan L129 / Browser-Ext spec §2.3). Adding a
/// 4th kind is a §18.7 minor bump (additive enum-value addition).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum CaptureAuthorityKind {
    /// The desktop client owns capture (Browser-Ext spec §2.3 desktop
    /// fallback when no extension is active).
    Desktop,
    /// A browser extension owns capture (the canonical browser case).
    BrowserExtension,
    /// The mobile-OS autofill subsystem owns capture (iOS / Android).
    MobileOsAutofill,
}

impl From<CaptureAuthorityKind> for pangolin_core::CaptureAuthorityKind {
    fn from(value: CaptureAuthorityKind) -> Self {
        match value {
            CaptureAuthorityKind::Desktop => Self::Desktop,
            CaptureAuthorityKind::BrowserExtension => Self::BrowserExtension,
            CaptureAuthorityKind::MobileOsAutofill => Self::MobileOsAutofill,
        }
    }
}

impl From<pangolin_core::CaptureAuthorityKind> for CaptureAuthorityKind {
    fn from(value: pangolin_core::CaptureAuthorityKind) -> Self {
        match value {
            pangolin_core::CaptureAuthorityKind::Desktop => Self::Desktop,
            pangolin_core::CaptureAuthorityKind::BrowserExtension => Self::BrowserExtension,
            pangolin_core::CaptureAuthorityKind::MobileOsAutofill => Self::MobileOsAutofill,
        }
    }
}

/// Which context the capture authority applies to.
///
/// Closed enum on the same discipline as [`CaptureAuthorityKind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum CaptureContextKind {
    /// Native desktop application context.
    Desktop,
    /// Browser (web) context.
    Browser,
    /// Mobile-OS app context (iOS / Android autofill).
    MobileOs,
}

impl From<CaptureContextKind> for pangolin_core::CaptureContextKind {
    fn from(value: CaptureContextKind) -> Self {
        match value {
            CaptureContextKind::Desktop => Self::Desktop,
            CaptureContextKind::Browser => Self::Browser,
            CaptureContextKind::MobileOs => Self::MobileOs,
        }
    }
}

impl From<pangolin_core::CaptureContextKind> for CaptureContextKind {
    fn from(value: pangolin_core::CaptureContextKind) -> Self {
        match value {
            pangolin_core::CaptureContextKind::Desktop => Self::Desktop,
            pangolin_core::CaptureContextKind::Browser => Self::Browser,
            pangolin_core::CaptureContextKind::MobileOs => Self::MobileOs,
        }
    }
}

/// The component owning credential capture for a context.
///
/// Replaces the 1.1 placeholder `{ schema_version, origin }` shape per
/// L5. Validated at the engine layer
/// ([`pangolin_core::capture_authority::validate_authority`]) so the
/// FFI body is pure plumbing. The 1.1-frozen `schema_version` slot is
/// preserved (§18.7 ladder).
#[derive(Debug, Clone, uniffi::Record)]
pub struct CaptureAuthority {
    /// Issue 1.1 schema-version slot (§18.7 ladder; locked by 1.6).
    pub schema_version: u16,
    /// Which kind of component owns capture.
    pub kind: CaptureAuthorityKind,
    /// Component identifier — NFC-normalised; non-empty after trim;
    /// ≤256 chars; no control / surrogate chars; no leading/trailing
    /// whitespace. Validated engine-side; an empty / overlong / non-
    /// NFC / control-charactered input surfaces as
    /// `FfiError::Validation { kind: "capture_authority" }`.
    pub component_id: String,
    /// Component version string — NFC-normalised; ≤64 chars; same
    /// character classes as `component_id`. May be empty (some
    /// components have no well-defined version yet).
    pub component_version: String,
}

impl From<CaptureAuthority> for pangolin_core::CaptureAuthority {
    fn from(value: CaptureAuthority) -> Self {
        Self {
            schema_version: value.schema_version,
            kind: value.kind.into(),
            component_id: value.component_id,
            component_version: value.component_version,
        }
    }
}

impl From<pangolin_core::CaptureAuthority> for CaptureAuthority {
    fn from(value: pangolin_core::CaptureAuthority) -> Self {
        Self {
            schema_version: value.schema_version,
            kind: value.kind.into(),
            component_id: value.component_id,
            component_version: value.component_version,
        }
    }
}

/// The context a capture authority applies to.
///
/// Replaces the 1.1 placeholder `{ schema_version, label }` shape per
/// L5.
#[derive(Debug, Clone, uniffi::Record)]
pub struct CaptureContext {
    /// Issue 1.1 schema-version slot.
    pub schema_version: u16,
    /// Which context kind.
    pub kind: CaptureContextKind,
    /// Optional finer-grained platform identifier. Lowercased ASCII;
    /// must be on the allowlist (`chrome` / `firefox` / `edge` /
    /// `safari` / `chromium` / `webview` / `ios` / `android` /
    /// `windows` / `macos` / `linux`). `None` means "the kind itself
    /// without a finer split".
    pub platform_hint: Option<String>,
}

impl From<CaptureContext> for pangolin_core::CaptureContext {
    fn from(value: CaptureContext) -> Self {
        Self {
            schema_version: value.schema_version,
            kind: value.kind.into(),
            platform_hint: value.platform_hint,
        }
    }
}

impl From<pangolin_core::CaptureContext> for CaptureContext {
    fn from(value: pangolin_core::CaptureContext) -> Self {
        Self {
            schema_version: value.schema_version,
            kind: value.kind.into(),
            platform_hint: value.platform_hint,
        }
    }
}

/// One row of the registered registry, returned by
/// [`capture_authority_query`] and [`capture_authority_list`].
#[derive(Debug, Clone, uniffi::Record)]
pub struct CaptureAuthorityEntry {
    /// Issue 1.1 schema-version slot.
    pub schema_version: u16,
    /// The context this registration applies to.
    pub context: CaptureContext,
    /// Which component owns capture for that context.
    pub authority: CaptureAuthority,
    /// Wall-clock unix-second timestamp the registration was last
    /// written (advances on every `Replaced`). Truncated from the
    /// store's unix-ms — matches the `DeviceInfo` discipline.
    pub registered_at: UnixTimestamp,
}

impl From<pangolin_core::CaptureAuthorityEntry> for CaptureAuthorityEntry {
    fn from(value: pangolin_core::CaptureAuthorityEntry) -> Self {
        Self {
            schema_version: value.schema_version,
            context: value.context.into(),
            authority: value.authority.into(),
            // ms → s, integer-truncated (matches the `DeviceInfo`
            // timestamp-conversion discipline; audit L-4).
            registered_at: value.registered_at / 1000,
        }
    }
}

fn store_into_ffi(err: pangolin_store::StoreError) -> FfiError {
    FfiError::from(pangolin_core::Error::from(err))
}

fn presence_from_ffi(_proof: PresenceProof) -> pangolin_core::PressYPresenceProof {
    // Same shim as `reveal::presence_from_ffi`. The CLI-tier presence
    // proof is currently a unit gesture; the bytes field is the
    // MVP-3/4 hardware-attested slot.
    pangolin_core::PressYPresenceProof::confirmed()
}

/// Register a capture authority for a context.
///
/// **L6 hybrid (R-c).** First registrations and idempotent re-
/// registrations (matching payload) are session-class — an active
/// unlocked session is sufficient, the `presence` argument is held
/// but not verified. Replacements (existing row, different payload,
/// `replace_existing=true`) are reveal-class — `presence` MUST be
/// fresh (within the engine's 60 s window or a fresh confirmation),
/// or the call surfaces `FfiError::Session` with the `PromptTimedOut`
/// underlying reason.
///
/// Exclusivity (L8): an existing row with a *different* payload AND
/// `replace_existing=false` surfaces `FfiError::Validation { kind:
/// "capture_authority_exclusivity" }` (the message names the context
/// kind only — no info-leak on the existing `component_id`).
///
/// # Errors
/// - `FfiError::Session` — locked / expired session or timed-out
///   presence prompt (Replaced branch only).
/// - `FfiError::Validation { kind: "capture_authority" }` — payload
///   rejected (empty / overlong / non-allowlisted `platform_hint` /
///   future `schema_version`).
/// - `FfiError::Validation { kind: "capture_authority_exclusivity" }`
///   — existing different registration; caller must set
///   `replace_existing=true` and supply a fresh presence proof.
/// - `FfiError::Validation { kind: "authentication" }` — any other
///   proof failure on the Replaced branch (collapses with the rest of
///   the indistinguishability discipline).
/// - `FfiError::Store` — storage failure.
#[allow(clippy::significant_drop_tightening, clippy::needless_pass_by_value)]
#[uniffi::export]
pub fn capture_authority_register(
    handle: Arc<VaultHandle>,
    presence: PresenceProof,
    authority: CaptureAuthority,
    context: CaptureContext,
    replace_existing: bool,
) -> Result<(), FfiError> {
    let mut guard = handle.lock_vault();
    let vault = guard.as_mut()?;
    let proof = presence_from_ffi(presence);
    let _outcome = vault
        .capture_authority_register(&proof, authority.into(), context.into(), replace_existing)
        .map_err(store_into_ffi)?;
    // 1.11 collapses every success outcome to Ok(()); the
    // RegistrationOutcome discriminator is kept on the store side for
    // tests + a future MVP-2 surface amendment.
    Ok(())
}

/// Look up the registered capture authority for `context`. Session-
/// class — no presence required. `Ok(None)` when no row matches.
///
/// # Errors
/// - `FfiError::Session` — locked / expired session.
/// - `FfiError::Validation { kind: "capture_authority" }` — context
///   payload rejected.
/// - `FfiError::Store` — storage failure.
#[allow(clippy::significant_drop_tightening)]
#[uniffi::export]
pub fn capture_authority_query(
    handle: Arc<VaultHandle>,
    context: CaptureContext,
) -> Result<Option<CaptureAuthorityEntry>, FfiError> {
    let mut guard = handle.lock_vault();
    let vault = guard.as_mut()?;
    let entry = vault
        .capture_authority_query(context.into())
        .map_err(store_into_ffi)?;
    Ok(entry.map(CaptureAuthorityEntry::from))
}

/// Every registered capture authority, sorted by
/// `(context_kind, platform_hint)`. Session-class.
///
/// # Errors
/// - `FfiError::Session` — locked / expired session.
/// - `FfiError::Validation { kind: "capture_authority" }` — a row
///   from the future (per-row §18.7 ladder reject; the rest of the
///   vault remains fully usable).
/// - `FfiError::Store` — storage failure.
#[allow(clippy::significant_drop_tightening)]
#[uniffi::export]
pub fn capture_authority_list(
    handle: Arc<VaultHandle>,
) -> Result<Vec<CaptureAuthorityEntry>, FfiError> {
    let mut guard = handle.lock_vault();
    let vault = guard.as_mut()?;
    let entries = vault.capture_authority_list().map_err(store_into_ffi)?;
    Ok(entries
        .into_iter()
        .map(CaptureAuthorityEntry::from)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::{
        capture_authority_list, capture_authority_query, capture_authority_register,
        CaptureAuthority, CaptureAuthorityKind, CaptureContext, CaptureContextKind,
    };
    use crate::error::FfiError;
    use crate::session::{PresenceProof, VaultHandle};
    use pangolin_core::{PinIdentityProof, PressYPresenceProof, Vault};
    use pangolin_crypto::secret::SecretBytes;
    use std::sync::Arc;

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

    fn fresh_proof() -> PresenceProof {
        PresenceProof {
            schema_version: 0,
            bytes: Vec::new(),
        }
    }

    fn sample_authority() -> CaptureAuthority {
        CaptureAuthority {
            schema_version: 1,
            kind: CaptureAuthorityKind::BrowserExtension,
            component_id: "com.example.ext".into(),
            component_version: "1.0".into(),
        }
    }

    fn sample_context() -> CaptureContext {
        CaptureContext {
            schema_version: 1,
            kind: CaptureContextKind::Browser,
            platform_hint: Some("chrome".into()),
        }
    }

    #[test]
    fn register_query_list_round_trip() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");

        // Empty list initially.
        let listed = capture_authority_list(Arc::clone(&h)).unwrap();
        assert!(listed.is_empty());

        // Register Created.
        capture_authority_register(
            Arc::clone(&h),
            fresh_proof(),
            sample_authority(),
            sample_context(),
            false,
        )
        .unwrap();

        // Query finds it.
        let found = capture_authority_query(Arc::clone(&h), sample_context())
            .unwrap()
            .expect("registered");
        assert_eq!(found.authority.component_id, "com.example.ext");
        assert_eq!(found.authority.kind, CaptureAuthorityKind::BrowserExtension);
        assert_eq!(found.context.kind, CaptureContextKind::Browser);
        assert_eq!(found.context.platform_hint.as_deref(), Some("chrome"));

        // List has one entry.
        let listed = capture_authority_list(Arc::clone(&h)).unwrap();
        assert_eq!(listed.len(), 1);

        // Re-register byte-identical = NoOp (no error).
        capture_authority_register(
            Arc::clone(&h),
            fresh_proof(),
            sample_authority(),
            sample_context(),
            false,
        )
        .unwrap();
        assert_eq!(
            capture_authority_list(Arc::clone(&h)).unwrap().len(),
            1,
            "NoOp did not duplicate the row"
        );
    }

    #[test]
    fn register_rejects_exclusivity_without_replace_flag() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        capture_authority_register(
            Arc::clone(&h),
            fresh_proof(),
            sample_authority(),
            sample_context(),
            false,
        )
        .unwrap();
        let mut other = sample_authority();
        other.component_id = "com.different.ext".into();
        let err = capture_authority_register(
            Arc::clone(&h),
            fresh_proof(),
            other.clone(),
            sample_context(),
            false,
        )
        .unwrap_err();
        match err {
            FfiError::Validation { kind, message } => {
                assert_eq!(kind, "capture_authority_exclusivity");
                // No-info-leak: the message names the context but NOT
                // the existing component_id.
                assert!(!message.contains("com.example.ext"));
                assert!(!message.contains("com.different.ext"));
            }
            other => panic!("expected Validation, got {other:?}"),
        }

        // With replace_existing=true, the overwrite succeeds.
        capture_authority_register(Arc::clone(&h), fresh_proof(), other, sample_context(), true)
            .unwrap();
        let found = capture_authority_query(Arc::clone(&h), sample_context())
            .unwrap()
            .expect("registered");
        assert_eq!(found.authority.component_id, "com.different.ext");
    }

    #[test]
    fn register_rejects_invalid_payload() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        let mut bad = sample_context();
        bad.platform_hint = Some("Chrome".into()); // uppercase rejected
        let err = capture_authority_register(
            Arc::clone(&h),
            fresh_proof(),
            sample_authority(),
            bad,
            false,
        )
        .unwrap_err();
        match err {
            FfiError::Validation { kind, .. } => assert_eq!(kind, "capture_authority"),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn reads_on_locked_vault_error() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        {
            let mut guard = h.lock_vault();
            guard.as_mut().unwrap().lock();
        }
        assert!(matches!(
            capture_authority_list(Arc::clone(&h)).unwrap_err(),
            FfiError::Session { .. }
        ));
        assert!(matches!(
            capture_authority_query(Arc::clone(&h), sample_context()).unwrap_err(),
            FfiError::Session { .. }
        ));
    }
}
