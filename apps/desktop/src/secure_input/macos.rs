// SPDX-License-Identifier: AGPL-3.0-or-later
//! **macOS native password widget — placeholder.**
//!
//! Layer-1 plan §7 step 2 replaces this with a real `NSAlert` +
//! `NSSecureTextField` accessoryView implementation. Until then, the
//! build target compiles + returns `Unavailable` so the rest of the
//! wire-up can land + integrate.

use super::SecureInputError;
use zeroize::Zeroizing;

/// Placeholder for the NSAlert native password dialog. Returns
/// [`SecureInputError::Unavailable`] until Layer 1 part 2 ships the
/// real impl.
#[allow(clippy::needless_pass_by_value)]
pub fn prompt_password(_title: &str, _body: &str) -> Result<Zeroizing<Vec<u8>>, SecureInputError> {
    Err(SecureInputError::Unavailable {
        reason: "macos native widget not yet implemented (Layer 1 part 2)".into(),
    })
}
