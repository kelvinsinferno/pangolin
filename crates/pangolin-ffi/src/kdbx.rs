//! KDBX-import + capture-authority FFI shapes (MVP-1 issues 1.9 +
//! 1.11), backed by `pangolin-kdbx`.
//!
//! Scaffolding-only at issue 1.1.

use std::sync::Arc;

use crate::error::FfiError;
use crate::session::{SecretPassword, VaultHandle};

/// Per-account import outcome (errors carry a UI-safe category label).
#[derive(Debug, Clone, uniffi::Record)]
pub struct KdbxImportReport {
    /// Issue 1.1 schema-version slot.
    pub schema_version: u16,
    /// Number of accounts imported successfully.
    pub imported: u32,
    /// Number of accounts skipped (e.g., duplicates).
    pub skipped: u32,
    /// Number of accounts whose import failed.
    pub failed: u32,
    /// Per-failure category labels. Non-secret; safe to render.
    pub failure_kinds: Vec<String>,
}

/// Capture-authority registration metadata (MVP-1 issue 1.11). The
/// `CaptureAuthority` and `CaptureContext` records are scaffolded
/// here and finalised in 1.11 — additive only after lock.
#[derive(Debug, Clone, uniffi::Record)]
pub struct CaptureAuthority {
    /// Issue 1.1 schema-version slot.
    pub schema_version: u16,
    /// Origin URL or platform identifier (non-secret).
    pub origin: String,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct CaptureContext {
    /// Issue 1.1 schema-version slot.
    pub schema_version: u16,
    /// Free-form context label. 1.11 finalises the encoding.
    pub label: String,
}

// -- Locked-in-1.1 entry points ---------------------------------------

/// Import a KDBX file into the vault. Body lands in 1.9.
///
/// # Panics
/// Panics with `todo!()` until 1.9 lands.
#[uniffi::export]
pub fn kdbx_import(
    handle: Arc<VaultHandle>,
    path: String,
    kdbx_password: Arc<SecretPassword>,
) -> Result<KdbxImportReport, FfiError> {
    let _ = (handle, path, kdbx_password);
    todo!("kdbx_import body lands in MVP-1 issue 1.9 (pangolin-kdbx)")
}

/// Register a new capture authority. Body lands in 1.11.
///
/// # Panics
/// Panics with `todo!()` until 1.11 lands.
#[uniffi::export]
pub fn capture_authority_register(
    handle: Arc<VaultHandle>,
    authority: CaptureAuthority,
    context: CaptureContext,
) -> Result<(), FfiError> {
    let _ = (handle, authority, context);
    todo!("capture_authority_register body lands in MVP-1 issue 1.11")
}
