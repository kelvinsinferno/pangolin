//! TOTP FFI shapes (MVP-1 issue 1.7), backed by `pangolin-totp`.
//!
//! Scaffolding-only at issue 1.1. The body lives in `pangolin-totp`
//! once 1.7 lands; the FFI surface here is the thin wrapper so Tauri
//! / Swift / Kotlin call into the same RFC 6238 implementation.

use std::sync::Arc;

use crate::error::FfiError;
use crate::identity::AccountId;
use crate::session::{UnixTimestamp, VaultHandle};

/// A 6-or-8-digit TOTP code wrapped with its time-window for replay
/// detection on the UI side. The code field is plain digits (no
/// punctuation) so the foreign-language side can render directly.
#[derive(Debug, Clone, uniffi::Record)]
pub struct TotpCode {
    /// Issue 1.1 schema-version slot.
    pub schema_version: u16,
    /// The decimal code (e.g., `"123456"`). RFC 6238 default is 6
    /// digits; provider-specific TOTPs (Steam, etc.) override.
    pub code: String,
    /// Number of seconds remaining in the current TOTP window.
    pub seconds_remaining: u16,
}

/// Generate a TOTP code for the given account at the given timestamp.
/// Body lands in 1.7. Backed by `pangolin-totp`.
///
/// # Panics
/// Panics with `todo!()` until 1.7 lands.
#[uniffi::export]
pub fn totp_generate(
    handle: Arc<VaultHandle>,
    id: AccountId,
    at: UnixTimestamp,
) -> Result<TotpCode, FfiError> {
    let _ = (handle, id, at);
    todo!("totp_generate body lands in MVP-1 issue 1.7 (pangolin-totp)")
}
