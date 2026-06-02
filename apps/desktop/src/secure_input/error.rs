// SPDX-License-Identifier: AGPL-3.0-or-later
//! Typed errors from the MVP-4-H secure-input plugin.
//!
//! These collapse to [`crate::DesktopError::Validation`] at the
//! command layer so the host sees the same envelope shape as every
//! other Validation error. The discriminator is the `kind` field of
//! the Validation envelope; messages are non-secret + safe to surface
//! in toasts.

use serde::Serialize;

/// Errors returned by [`crate::secure_input::prompt_password`].
///
/// All variants are NON-SECRET — they describe the dialog's lifecycle
/// or the plugin's load state, not any user-typed content. Safe to
/// surface in toasts + log.
#[derive(Debug, Clone, Serialize, thiserror::Error)]
pub enum SecureInputError {
    /// The user closed the dialog without typing (ESC, Cancel button,
    /// window close). Maps to a benign UX state; the caller should
    /// return to the previous step.
    #[error("secure-input: dialog was cancelled by the user")]
    Cancelled,

    /// The plugin failed to load. Missing OS support, sandbox
    /// restriction, library symbol not resolvable, parent window not
    /// available. Per Q-c (plan §0a) this is a HARD FAIL — the host
    /// must NOT fall back to the option-1 invoke path.
    #[error("secure-input: unavailable ({reason})")]
    Unavailable {
        /// Human-readable reason; safe to log + surface in a toast.
        reason: String,
    },

    /// An unrecoverable OS error from the widget itself (e.g. failed
    /// to spawn the dialog, OS reported an unexpected state). Distinct
    /// from `Unavailable` because the plugin loaded + reached the
    /// native call site but the OS rejected the operation.
    #[error("secure-input: internal OS error ({reason})")]
    Internal {
        /// Human-readable reason; safe to log + surface in a toast.
        reason: String,
    },

    /// **Test-stub only.** The wdio harness called `prompt_password`
    /// without first queueing a password via
    /// `__test__secure_input_inject`. This is a test-bug signal — in
    /// production this variant cannot fire (the stub module is
    /// compiled out of release builds).
    #[error("secure-input: test-stub queue is empty")]
    TestHookEmpty,
}

impl SecureInputError {
    /// Stable `kind` tag for the Validation envelope. Mirrors the
    /// `kind` field used elsewhere in `commands::recovery` etc.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Cancelled => "secure_input_cancelled",
            Self::Unavailable { .. } => "secure_input_unavailable",
            Self::Internal { .. } => "secure_input_internal",
            Self::TestHookEmpty => "secure_input_test_hook_empty",
        }
    }
}
