// SPDX-License-Identifier: AGPL-3.0-or-later
//! **Linux native password widget — placeholder.**
//!
//! Layer-1 plan §7 step 2 replaces this with a real GTK
//! `Dialog` + `GtkEntry visibility=FALSE` implementation. Until then,
//! the build target compiles + returns `Unavailable` so the rest of
//! the wire-up (Layer 2 commands, Layer 3 button, Layer 4 test-hook)
//! can land + integrate. Tests use the stub instead so they don't go
//! red here.

use super::SecureInputError;
use zeroize::Zeroizing;

/// Placeholder for the GTK native password dialog. Returns
/// [`SecureInputError::Unavailable`] until Layer 1 part 2 ships the
/// real impl.
#[allow(clippy::needless_pass_by_value)]
pub fn prompt_password(_title: &str, _body: &str) -> Result<Zeroizing<Vec<u8>>, SecureInputError> {
    Err(SecureInputError::Unavailable {
        reason: "linux native widget not yet implemented (Layer 1 part 2)".into(),
    })
}
