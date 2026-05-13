// SPDX-License-Identifier: AGPL-3.0-or-later
//! Capture-authority registry (MVP-1 issue 1.11).
//!
//! Browser-Ext spec §2.3 / API contract §16 / Threat Model invariant
//! #8: at most one component (browser-ext / desktop / mobile-OS
//! autofill) owns credential capture per context. This module persists
//! that registration in a new vault-level SQL table
//! `capture_authorities` (additive `CREATE TABLE IF NOT EXISTS` — no
//! `format_version` bump, mirroring the 1.5 `devices` / `device_key`
//! posture).
//!
//! The contents are non-secret metadata: component identifier
//! strings, version strings, and the closed-enum context
//! discriminator. Same on-disk posture as the `devices` table's
//! `label` (plaintext; the AEAD-sealed material lives elsewhere).
//! Per L7, identifiers are NFC-normalised then length-checked then
//! character-class-rejected; `platform_hint` is held to a lowercased
//! ASCII allowlist that defeats Unicode-homoglyph impersonation
//! (`chr<ZWSP>ome` with a zero-width space, etc.).
//!
//! On the Rust API, [`crate::Vault`] grows three session-class entries
//! (`capture_authority_register` / `_query` / `_list`) plus a
//! test/MVP-2 helper (`capture_authority_clear`). `_register` is the
//! L6 hybrid: `Created` and `NoOp` are session-class (active non-
//! expired session, no presence proof); `Replaced` is reveal-class
//! (routes through 1.4's `ensure_presence_fresh`). See the
//! [`crate::Vault::capture_authority_register`] doc-comment for the
//! exact order of operations.

use unicode_normalization::UnicodeNormalization;

use crate::error::{Result, StoreError};

/// Schema-version slot for `capture_authorities` rows (§18.7 ladder).
///
/// A row whose `schema_version > CAPTURE_AUTHORITY_SCHEMA_VERSION_MAX`
/// is rejected at decode for that row only — the rest of the vault is
/// fine. Mirrors [`crate::ACCOUNT_IDENTITY_SCHEMA_VERSION`] /
/// [`crate::DEVICE_IDENTITY_SCHEMA_VERSION`].
pub const CAPTURE_AUTHORITY_SCHEMA_VERSION_MAX: u16 = 1;

/// Maximum length (post-NFC, post-trim) of a `component_id`.
pub const COMPONENT_ID_MAX_CHARS: usize = 256;

/// Maximum length (post-NFC, post-trim) of a `component_version`.
pub const COMPONENT_VERSION_MAX_CHARS: usize = 64;

/// Maximum length of a `platform_hint` (ASCII allowlist enforces a
/// tight bound, but defence in depth: the length check fires before
/// any allocation downstream).
pub const PLATFORM_HINT_MAX_CHARS: usize = 64;

/// Closed lowercased-ASCII allowlist for `platform_hint`. Adding a new
/// hint is a §18.7 minor bump (additive enum-value addition).
pub const PLATFORM_HINT_ALLOWLIST: &[&str] = &[
    "chrome", "firefox", "edge", "safari", "chromium", "webview", "ios", "android", "windows",
    "macos", "linux",
];

/// Which component owns capture for a given context.
///
/// Closed enum — making Threat Model invariant #8 a type-system
/// invariant rather than a string convention. MVP-2 wanting a 4th
/// kind is a §18.7 minor bump (additive variant).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i64)]
pub enum CaptureAuthorityKind {
    /// The desktop client owns capture (Browser-Ext spec §2.3 desktop
    /// fallback when no extension is active).
    Desktop = 0,
    /// A browser extension owns capture (the canonical browser case).
    BrowserExtension = 1,
    /// The mobile-OS autofill subsystem owns capture (iOS / Android).
    MobileOsAutofill = 2,
}

impl CaptureAuthorityKind {
    /// The stored integer for this kind.
    #[must_use]
    pub fn to_repr(self) -> i64 {
        self as i64
    }

    /// Decode a stored integer. Errors on an unknown variant — unlike
    /// `DeviceCapabilities::from_repr` (which is forward-compat-tolerant
    /// for a single-variant enum), a wrong kind here would silently
    /// corrupt the exclusivity invariant. Surfaced as a typed
    /// validation error so the caller knows the row is from a future
    /// build (§18.7 — per-row ladder).
    ///
    /// # Errors
    /// [`StoreError::CaptureAuthorityValidation`] for any unknown value.
    pub fn from_repr(value: i64) -> Result<Self> {
        match value {
            0 => Ok(Self::Desktop),
            1 => Ok(Self::BrowserExtension),
            2 => Ok(Self::MobileOsAutofill),
            other => Err(StoreError::CaptureAuthorityValidation {
                reason: format!("unknown capture-authority kind {other}"),
            }),
        }
    }
}

/// Which context the capture authority applies to.
///
/// Closed enum on the same discipline as [`CaptureAuthorityKind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i64)]
pub enum CaptureContextKind {
    /// Native desktop application context.
    Desktop = 0,
    /// Browser (web) context.
    Browser = 1,
    /// Mobile-OS app context (iOS / Android autofill).
    MobileOs = 2,
}

impl CaptureContextKind {
    /// The stored integer for this context kind.
    #[must_use]
    pub fn to_repr(self) -> i64 {
        self as i64
    }

    /// Decode a stored integer.
    ///
    /// # Errors
    /// [`StoreError::CaptureAuthorityValidation`] for any unknown value.
    pub fn from_repr(value: i64) -> Result<Self> {
        match value {
            0 => Ok(Self::Desktop),
            1 => Ok(Self::Browser),
            2 => Ok(Self::MobileOs),
            other => Err(StoreError::CaptureAuthorityValidation {
                reason: format!("unknown capture-context kind {other}"),
            }),
        }
    }

    /// Stable label used in error messages (no info-leak — the kind is
    /// the public discriminator).
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Desktop => "desktop",
            Self::Browser => "browser",
            Self::MobileOs => "mobile_os",
        }
    }
}

/// The component owning credential capture for a context.
///
/// Validated form returned from [`validate_authority`] /
/// [`crate::Vault::capture_authority_query`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureAuthority {
    /// Schema-version slot (§18.7 ladder). Always
    /// [`CAPTURE_AUTHORITY_SCHEMA_VERSION_MAX`] when written by this
    /// build; rejected at decode if greater.
    pub schema_version: u16,
    /// Which kind of component owns capture.
    pub kind: CaptureAuthorityKind,
    /// Component identifier (NFC-normalised; non-empty after trim;
    /// ≤[`COMPONENT_ID_MAX_CHARS`] chars; no control / surrogate
    /// chars; no leading/trailing whitespace).
    pub component_id: String,
    /// Component version string (NFC-normalised;
    /// ≤[`COMPONENT_VERSION_MAX_CHARS`] chars; same character classes
    /// as `component_id`).
    pub component_version: String,
}

/// The context a capture authority applies to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureContext {
    /// Schema-version slot (§18.7 ladder).
    pub schema_version: u16,
    /// Which context kind.
    pub kind: CaptureContextKind,
    /// Optional finer-grained hint (one of [`PLATFORM_HINT_ALLOWLIST`];
    /// lowercased ASCII). NULL `platform_hint` is coalesced to `''`
    /// for the PRIMARY KEY check (Q-e: a `(kind, None)` key is
    /// distinct from `(kind, Some("chrome"))`).
    pub platform_hint: Option<String>,
}

/// One row of the registry — context + authority + when it was
/// registered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureAuthorityEntry {
    /// Schema-version slot (§18.7 ladder).
    pub schema_version: u16,
    /// The context this registration applies to.
    pub context: CaptureContext,
    /// Which component owns capture for that context.
    pub authority: CaptureAuthority,
    /// Wall-clock unix-ms timestamp the registration was last written
    /// (advances on every `Replaced`).
    pub registered_at: i64,
}

/// Outcome of a [`crate::Vault::capture_authority_register`] call.
///
/// `Created` (first registration for the key) and `NoOp` (re-register
/// with identical payload) are the session-class branches. `Replaced`
/// is the reveal-class branch — presence is already consumed by the
/// time the variant is constructed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistrationOutcome {
    /// No prior row existed for the `(kind, platform_hint)` key; a
    /// fresh row was inserted.
    Created,
    /// A prior row existed for the key; it was replaced with the new
    /// payload (presence proof was consumed).
    Replaced {
        /// The previous authority that was overwritten. Carried for
        /// tests + a future MVP-2 amendment that may surface it on
        /// the FFI; 1.11 collapses Created/Replaced to `Ok(())` over
        /// FFI.
        prior: CaptureAuthority,
    },
    /// A prior row existed and is byte-identical to the new payload;
    /// the registration was a no-op.
    NoOp {
        /// The existing (and identical) authority.
        existing: CaptureAuthority,
    },
}

/// CBOR archive shape for one registered authority — what 1.10's
/// [`crate::export::ArchiveSnapshot`] carries.
///
/// Mirrors the `capture_authorities` row 1:1 (no derived fields).
/// Per Q-f / L10, [`crate::Vault::restore_to_new_vault`] does NOT
/// re-register these — the new vault starts with an empty registry —
/// but the field is carried so a future MVP-3+ "advanced restore"
/// flow could opt to honour them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedCaptureAuthority {
    /// `CaptureContextKind` as `i64` (stable on-disk repr).
    pub context_kind: i64,
    /// Platform hint (`""` when None — same coalescing as the SQL key).
    pub platform_hint: String,
    /// Authority kind as `i64`.
    pub authority_kind: i64,
    /// Component identifier.
    pub component_id: String,
    /// Component version.
    pub component_version: String,
    /// Wall-clock unix-ms timestamp.
    pub registered_at: i64,
    /// Per-row schema version (§18.7 ladder).
    pub schema_version: u16,
}

/// Validate + canonicalise a `component_id` per L7.
///
/// NFC-normalise first; reject empty-after-trim; length-check;
/// character-class-reject (Cc range, surrogates, `\0..\x1f`);
/// reject leading/trailing whitespace (which `trim` strips, but we
/// surface the rejection rather than silently mutate caller input —
/// the canonical form must be the input minus normalisation, not
/// minus trimming).
///
/// # Errors
/// [`StoreError::CaptureAuthorityValidation`] for any violation.
pub fn validate_component_id(input: &str) -> Result<String> {
    let normalised: String = input.nfc().collect();
    if normalised.is_empty() {
        return Err(StoreError::CaptureAuthorityValidation {
            reason: "component_id must not be empty".into(),
        });
    }
    if normalised.chars().count() > COMPONENT_ID_MAX_CHARS {
        return Err(StoreError::CaptureAuthorityValidation {
            reason: format!("component_id exceeds {COMPONENT_ID_MAX_CHARS} chars"),
        });
    }
    if normalised.chars().next().is_some_and(char::is_whitespace)
        || normalised
            .chars()
            .next_back()
            .is_some_and(char::is_whitespace)
    {
        return Err(StoreError::CaptureAuthorityValidation {
            reason: "component_id must not have leading or trailing whitespace".into(),
        });
    }
    if normalised.chars().any(disallowed_char) {
        return Err(StoreError::CaptureAuthorityValidation {
            reason: "component_id contains disallowed control characters".into(),
        });
    }
    Ok(normalised)
}

/// Validate + canonicalise a `component_version` per L7.
///
/// Same character-class discipline as [`validate_component_id`]; an
/// empty version string is permitted (some components have no
/// well-defined version yet) but if present it must satisfy the
/// character classes + length cap.
///
/// # Errors
/// [`StoreError::CaptureAuthorityValidation`] for any violation.
pub fn validate_component_version(input: &str) -> Result<String> {
    let normalised: String = input.nfc().collect();
    if normalised.chars().count() > COMPONENT_VERSION_MAX_CHARS {
        return Err(StoreError::CaptureAuthorityValidation {
            reason: format!("component_version exceeds {COMPONENT_VERSION_MAX_CHARS} chars"),
        });
    }
    if !normalised.is_empty()
        && (normalised.chars().next().is_some_and(char::is_whitespace)
            || normalised
                .chars()
                .next_back()
                .is_some_and(char::is_whitespace))
    {
        return Err(StoreError::CaptureAuthorityValidation {
            reason: "component_version must not have leading or trailing whitespace".into(),
        });
    }
    if normalised.chars().any(disallowed_char) {
        return Err(StoreError::CaptureAuthorityValidation {
            reason: "component_version contains disallowed control characters".into(),
        });
    }
    Ok(normalised)
}

/// Validate + canonicalise an optional `platform_hint` per L7.
///
/// `None` passes through unchanged. `Some(...)` is length-checked,
/// lowercased-ASCII-required, and must appear in
/// [`PLATFORM_HINT_ALLOWLIST`].
///
/// # Errors
/// [`StoreError::CaptureAuthorityValidation`] for any violation.
pub fn validate_platform_hint(input: Option<&str>) -> Result<Option<String>> {
    let Some(s) = input else {
        return Ok(None);
    };
    if s.is_empty() {
        // An empty Some(...) is a caller error; allowlist gates it
        // explicitly. (We also want `None` and `Some("")` to be
        // distinguishable at the API; the latter is invalid.)
        return Err(StoreError::CaptureAuthorityValidation {
            reason: "platform_hint must not be empty (use None to omit)".into(),
        });
    }
    if s.chars().count() > PLATFORM_HINT_MAX_CHARS {
        return Err(StoreError::CaptureAuthorityValidation {
            reason: format!("platform_hint exceeds {PLATFORM_HINT_MAX_CHARS} chars"),
        });
    }
    if !s.chars().all(|c| c.is_ascii_lowercase()) {
        return Err(StoreError::CaptureAuthorityValidation {
            reason: "platform_hint must be lowercased ASCII".into(),
        });
    }
    if !PLATFORM_HINT_ALLOWLIST.contains(&s) {
        return Err(StoreError::CaptureAuthorityValidation {
            reason: format!("platform_hint must be one of the allowlisted values (got {s:?})"),
        });
    }
    Ok(Some(s.to_owned()))
}

/// Validate (and return the canonical form of) the FFI-facing
/// `CaptureAuthority` payload. The returned shape is what the
/// register / read paths write + return.
///
/// # Errors
/// [`StoreError::CaptureAuthorityValidation`] on any rule violation.
pub fn validate_authority(authority: &CaptureAuthority) -> Result<CaptureAuthority> {
    if authority.schema_version > CAPTURE_AUTHORITY_SCHEMA_VERSION_MAX {
        return Err(StoreError::CaptureAuthorityValidation {
            reason: format!(
                "schema_version {} > {}",
                authority.schema_version, CAPTURE_AUTHORITY_SCHEMA_VERSION_MAX
            ),
        });
    }
    let component_id = validate_component_id(&authority.component_id)?;
    let component_version = validate_component_version(&authority.component_version)?;
    Ok(CaptureAuthority {
        schema_version: authority.schema_version,
        kind: authority.kind,
        component_id,
        component_version,
    })
}

/// Validate (and return the canonical form of) the FFI-facing
/// `CaptureContext` payload.
///
/// # Errors
/// [`StoreError::CaptureAuthorityValidation`] on any rule violation.
pub fn validate_context(context: &CaptureContext) -> Result<CaptureContext> {
    if context.schema_version > CAPTURE_AUTHORITY_SCHEMA_VERSION_MAX {
        return Err(StoreError::CaptureAuthorityValidation {
            reason: format!(
                "schema_version {} > {}",
                context.schema_version, CAPTURE_AUTHORITY_SCHEMA_VERSION_MAX
            ),
        });
    }
    let platform_hint = validate_platform_hint(context.platform_hint.as_deref())?;
    Ok(CaptureContext {
        schema_version: context.schema_version,
        kind: context.kind,
        platform_hint,
    })
}

/// `c.is_control()` is the canonical reject — covers C0 (`\0..\x1f`),
/// DEL, the C1 range, and Unicode `Cc` more generally. Surrogates in
/// Rust `&str` are impossible (the type guarantees valid UTF-8), but
/// we keep the predicate self-documenting per the plan's L7 spec.
fn disallowed_char(c: char) -> bool {
    c.is_control()
}

// ----------------------------------------------------------------- SQL

/// Coalesce an optional platform hint into the PRIMARY-KEY form
/// (`''` for None, the canonical string otherwise).
#[must_use]
pub fn coalesce_platform_hint(hint: &Option<String>) -> &str {
    hint.as_deref().unwrap_or("")
}

/// Restore the optional form from the PRIMARY-KEY string.
#[must_use]
pub fn uncoalesce_platform_hint(stored: String) -> Option<String> {
    if stored.is_empty() {
        None
    } else {
        Some(stored)
    }
}

/// Decode one row from the `capture_authorities` table. Rejects rows
/// whose `schema_version` is from the future (§18.7 ladder — per-row
/// reject, rest of vault fine) and rows whose kind discriminator is
/// unknown.
pub(crate) fn decode_row(
    context_kind_i: i64,
    platform_hint: String,
    authority_kind_i: i64,
    component_id: String,
    component_version: String,
    registered_at: i64,
    schema_version_i: i64,
) -> Result<CaptureAuthorityEntry> {
    let schema_version =
        u16::try_from(schema_version_i).map_err(|_| StoreError::CaptureAuthorityValidation {
            reason: "schema_version out of u16 range".into(),
        })?;
    if schema_version > CAPTURE_AUTHORITY_SCHEMA_VERSION_MAX {
        return Err(StoreError::CaptureAuthorityValidation {
            reason: format!(
                "row schema_version {schema_version} > {CAPTURE_AUTHORITY_SCHEMA_VERSION_MAX} \
                 (requires newer Pangolin)"
            ),
        });
    }
    let context_kind = CaptureContextKind::from_repr(context_kind_i)?;
    let authority_kind = CaptureAuthorityKind::from_repr(authority_kind_i)?;
    Ok(CaptureAuthorityEntry {
        schema_version,
        context: CaptureContext {
            schema_version,
            kind: context_kind,
            platform_hint: uncoalesce_platform_hint(platform_hint),
        },
        authority: CaptureAuthority {
            schema_version,
            kind: authority_kind,
            component_id,
            component_version,
        },
        registered_at,
    })
}

/// SQL SELECT-column list for `capture_authorities`. Order matters —
/// keep in sync with [`decode_row`].
pub(crate) const CAPTURE_AUTHORITIES_SELECT_COLS: &str =
    "context_kind, platform_hint, authority_kind, component_id, component_version, \
     registered_at, schema_version";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_round_trip_repr() {
        for k in [
            CaptureAuthorityKind::Desktop,
            CaptureAuthorityKind::BrowserExtension,
            CaptureAuthorityKind::MobileOsAutofill,
        ] {
            assert_eq!(CaptureAuthorityKind::from_repr(k.to_repr()).unwrap(), k);
        }
        assert!(matches!(
            CaptureAuthorityKind::from_repr(99).unwrap_err(),
            StoreError::CaptureAuthorityValidation { .. }
        ));
        for c in [
            CaptureContextKind::Desktop,
            CaptureContextKind::Browser,
            CaptureContextKind::MobileOs,
        ] {
            assert_eq!(CaptureContextKind::from_repr(c.to_repr()).unwrap(), c);
        }
        assert!(matches!(
            CaptureContextKind::from_repr(-1).unwrap_err(),
            StoreError::CaptureAuthorityValidation { .. }
        ));
    }

    #[test]
    fn validate_component_id_basics() {
        assert_eq!(validate_component_id("ext").unwrap(), "ext");
        // NFC normalisation: composed and decomposed forms collapse.
        assert_eq!(validate_component_id("Cafe\u{0301}").unwrap(), "Café");
        // Empty rejected.
        assert!(matches!(
            validate_component_id("").unwrap_err(),
            StoreError::CaptureAuthorityValidation { .. }
        ));
        // Whitespace boundary rejected.
        assert!(matches!(
            validate_component_id(" foo").unwrap_err(),
            StoreError::CaptureAuthorityValidation { .. }
        ));
        assert!(matches!(
            validate_component_id("foo ").unwrap_err(),
            StoreError::CaptureAuthorityValidation { .. }
        ));
        // Control char rejected.
        assert!(matches!(
            validate_component_id("foo\u{0007}bar").unwrap_err(),
            StoreError::CaptureAuthorityValidation { .. }
        ));
        // Overlong rejected.
        let long = "x".repeat(COMPONENT_ID_MAX_CHARS + 1);
        assert!(matches!(
            validate_component_id(&long).unwrap_err(),
            StoreError::CaptureAuthorityValidation { .. }
        ));
    }

    #[test]
    fn validate_component_version_basics() {
        assert_eq!(validate_component_version("1.2.3").unwrap(), "1.2.3");
        assert_eq!(validate_component_version("").unwrap(), "");
        let long = "x".repeat(COMPONENT_VERSION_MAX_CHARS + 1);
        assert!(matches!(
            validate_component_version(&long).unwrap_err(),
            StoreError::CaptureAuthorityValidation { .. }
        ));
        assert!(matches!(
            validate_component_version("\u{0001}1.0").unwrap_err(),
            StoreError::CaptureAuthorityValidation { .. }
        ));
    }

    #[test]
    fn validate_platform_hint_allowlist() {
        assert_eq!(validate_platform_hint(None).unwrap(), None);
        for h in PLATFORM_HINT_ALLOWLIST {
            assert_eq!(validate_platform_hint(Some(h)).unwrap(), Some((*h).into()));
        }
        // Not in allowlist.
        assert!(matches!(
            validate_platform_hint(Some("opera")).unwrap_err(),
            StoreError::CaptureAuthorityValidation { .. }
        ));
        // Uppercase rejected (must be lowercased ASCII).
        assert!(matches!(
            validate_platform_hint(Some("Chrome")).unwrap_err(),
            StoreError::CaptureAuthorityValidation { .. }
        ));
        // Homoglyph: `chr` + zero-width-space + `ome` is not ASCII →
        // rejected before any allowlist comparison.
        assert!(matches!(
            validate_platform_hint(Some("chr\u{200B}ome")).unwrap_err(),
            StoreError::CaptureAuthorityValidation { .. }
        ));
        // Empty Some is rejected (use None).
        assert!(matches!(
            validate_platform_hint(Some("")).unwrap_err(),
            StoreError::CaptureAuthorityValidation { .. }
        ));
    }

    #[test]
    fn validate_authority_canonicalises() {
        let a = CaptureAuthority {
            schema_version: 1,
            kind: CaptureAuthorityKind::BrowserExtension,
            component_id: "Cafe\u{0301}".into(),
            component_version: "1.0".into(),
        };
        let v = validate_authority(&a).unwrap();
        assert_eq!(v.component_id, "Café");
        assert_eq!(v.kind, CaptureAuthorityKind::BrowserExtension);
    }

    #[test]
    fn validate_authority_rejects_future_schema() {
        let a = CaptureAuthority {
            schema_version: CAPTURE_AUTHORITY_SCHEMA_VERSION_MAX + 1,
            kind: CaptureAuthorityKind::Desktop,
            component_id: "x".into(),
            component_version: "1".into(),
        };
        assert!(matches!(
            validate_authority(&a).unwrap_err(),
            StoreError::CaptureAuthorityValidation { .. }
        ));
    }

    #[test]
    fn coalesce_round_trip() {
        let none: Option<String> = None;
        let some: Option<String> = Some("chrome".into());
        assert_eq!(coalesce_platform_hint(&none), "");
        assert_eq!(coalesce_platform_hint(&some), "chrome");
        assert_eq!(uncoalesce_platform_hint(String::new()), None);
        assert_eq!(
            uncoalesce_platform_hint("chrome".into()),
            Some("chrome".into())
        );
    }

    #[test]
    fn decode_row_rejects_future_schema_version() {
        let err = decode_row(
            1,
            String::new(),
            1,
            "ext".into(),
            "1.0".into(),
            1,
            i64::from(CAPTURE_AUTHORITY_SCHEMA_VERSION_MAX + 1),
        )
        .unwrap_err();
        assert!(matches!(err, StoreError::CaptureAuthorityValidation { .. }));
    }

    #[test]
    fn decode_row_rejects_bogus_kind() {
        let err = decode_row(99, String::new(), 1, "x".into(), "1".into(), 1, 1).unwrap_err();
        assert!(matches!(err, StoreError::CaptureAuthorityValidation { .. }));
        let err = decode_row(1, String::new(), 42, "x".into(), "1".into(), 1, 1).unwrap_err();
        assert!(matches!(err, StoreError::CaptureAuthorityValidation { .. }));
    }
}
