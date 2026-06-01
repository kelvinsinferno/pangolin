// SPDX-License-Identifier: AGPL-3.0-or-later
//! **Windows native password widget — placeholder.**
//!
//! Layer-1 plan §7 step 2 replaces this with a real
//! `TaskDialogIndirect` + edit control implementation. Until then,
//! the build target compiles + returns `Unavailable` so the rest of
//! the wire-up can land + integrate.

use super::SecureInputError;
use zeroize::Zeroizing;

/// Placeholder for the Win32 TaskDialog native password dialog.
/// Returns [`SecureInputError::Unavailable`] until Layer 1 part 2
/// ships the real impl.
pub fn prompt_password(
    _app: &tauri::AppHandle,
    _title: &str,
    _body: &str,
) -> Result<Zeroizing<Vec<u8>>, SecureInputError> {
    Err(SecureInputError::Unavailable {
        reason: "windows native widget not yet implemented (Layer 1 part 2)".into(),
    })
}
