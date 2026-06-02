// SPDX-License-Identifier: AGPL-3.0-or-later
//! **Windows native password widget — CredUIPromptForCredentialsW.**
//!
//! Uses the Win32 credential-prompt API to display a system-styled
//! modal password dialog. The user types into a native edit control
//! that never crosses the WebView's V8 heap — the bytes go directly
//! from the OS edit-control buffer into a `Zeroizing<Vec<u8>>` in
//! Rust.
//!
//! ## UX trade-off vs. plan §3.1
//!
//! The plan-LOCK originally suggested `TaskDialogIndirect` with a
//! custom edit control. In practice TaskDialog doesn't host arbitrary
//! controls cleanly (its slots are predefined: header / body /
//! footer / verification-checkbox). The simplest production-grade
//! Win32 password prompt is `CredUIPromptForCredentialsW`:
//!
//! - System-styled dialog (matches the OS credential-prompt UI users
//!   already see for UAC / network shares / etc.)
//! - Native password edit control with proper masking + IME / paste
//!   support
//! - Returns immediately on OK / Cancel; no main-loop wiring required
//!
//! The only UX quirk is that `CredUIPromptForCredentialsW` ALWAYS
//! shows a username field above the password field. We pre-populate
//! the username with a fixed sentinel + the `CREDUI_FLAGS_KEEP_USERNAME`
//! flag so the field is locked (read-only). Users see a single
//! editable password field with a static label above. This is a
//! known acceptable trade vs. hand-rolling a `DialogBoxIndirectParamW`
//! template (which would let us hide the username field but requires
//! ~300 lines of dialog-template-struct serialization + a DLGPROC
//! callback — sizable surface for a marginal UX improvement).
//!
//! ## Threading
//!
//! The Credential UI APIs can be called from any thread that has a
//! message queue, but for symmetry with the macOS + Linux paths we
//! dispatch onto the Tauri main thread via
//! `app.run_on_main_thread`. The mpsc channel pattern matches the
//! other OS impls.
//!
//! ## L1 secret hygiene
//!
//! `CredUIPromptForCredentialsW` writes the password into a wide
//! `[u16]` buffer we allocate on the stack. We immediately convert
//! the buffer to UTF-8 bytes wrapped in `Zeroizing<Vec<u8>>` and
//! explicitly zero the wide buffer via `zeroize::Zeroize::zeroize`
//! before letting it drop. `Zeroize::zeroize` uses volatile writes
//! that the optimizer cannot elide as dead stores (plain `[u16]::fill`
//! is DCE-eligible once the buffer leaves scope). `String::into_bytes`
//! transfers the intermediate `String`'s heap allocation directly into
//! the `Zeroizing<Vec<u8>>` without copying, so the same buffer is
//! protected end-to-end.

#![allow(unsafe_code)]

use std::sync::mpsc;

use super::SecureInputError;
use zeroize::{Zeroize, Zeroizing};

use windows::core::PCWSTR;
use windows::Win32::Foundation::{ERROR_CANCELLED, ERROR_SUCCESS, HWND};
use windows::Win32::Security::Credentials::{
    CredUIPromptForCredentialsW, CREDUI_FLAGS, CREDUI_FLAGS_ALWAYS_SHOW_UI,
    CREDUI_FLAGS_DO_NOT_PERSIST, CREDUI_FLAGS_GENERIC_CREDENTIALS, CREDUI_FLAGS_KEEP_USERNAME,
    CREDUI_INFOW,
};

/// **Open a CredUIPromptForCredentials modal password dialog.**
/// Dispatches onto the Tauri main thread via `app.run_on_main_thread`,
/// blocks the caller via mpsc until the user hits OK / Cancel.
pub fn prompt_password(
    app: &tauri::AppHandle,
    title: &str,
    body: &str,
) -> Result<Zeroizing<Vec<u8>>, SecureInputError> {
    let (tx, rx) = mpsc::channel::<Result<Zeroizing<Vec<u8>>, SecureInputError>>();
    let title_owned = title.to_string();
    let body_owned = body.to_string();

    app.run_on_main_thread(move || {
        let result = run_creduidialog(&title_owned, &body_owned);
        let _ = tx.send(result);
    })
    .map_err(|e| SecureInputError::Unavailable {
        reason: format!("secure_input: run_on_main_thread failed: {e}"),
    })?;

    rx.recv().map_err(|e| SecureInputError::Internal {
        reason: format!("secure_input: main-thread result channel closed: {e}"),
    })?
}

/// **Run the CredUI prompt on the main thread.** Caller MUST be on a
/// thread with a message queue (Tauri's main thread satisfies this).
fn run_creduidialog(title: &str, body: &str) -> Result<Zeroizing<Vec<u8>>, SecureInputError> {
    // UI metadata strings — title (caption) and body (message banner).
    let title_wide = to_wide_null_terminated(title);
    let body_wide = to_wide_null_terminated(body);

    // Target name is required + cannot be empty. We don't tie this to
    // a real credential-manager entry (we use
    // `CREDUI_FLAGS_DO_NOT_PERSIST` below), so a fixed sentinel works.
    let target_wide = to_wide_null_terminated("pangolin-master-password");

    // Pre-populate the username field with a fixed label so users see
    // a useful description above the password input. The
    // `CREDUI_FLAGS_KEEP_USERNAME` flag below locks the field so users
    // can't edit it — visually it's just a static label.
    let mut username_buf: [u16; CREDUI_MAX_USERNAME_LENGTH + 1] =
        [0; CREDUI_MAX_USERNAME_LENGTH + 1];
    let user_label = to_wide_chars("Pangolin vault");
    for (i, ch) in user_label.iter().enumerate() {
        if i >= CREDUI_MAX_USERNAME_LENGTH {
            break;
        }
        username_buf[i] = *ch;
    }

    // Password output buffer. 256 wide chars = 256 UTF-16 code units,
    // which covers any realistic master password (master passwords
    // in our threat model are bounded by `KDFParams::RECOMMENDED`'s
    // input length; if a user types past 256 chars the field clamps).
    const PASSWORD_BUF_LEN: usize = 256;
    let mut password_buf: [u16; PASSWORD_BUF_LEN] = [0; PASSWORD_BUF_LEN];

    // Compile-time guard: CREDUI_INFOW is ~24 bytes; this assert pins
    // that to u32 range so a future windows-rs struct change can't
    // silently truncate cbSize. The `.expect` below is then defensive
    // belt-and-braces (the const_assert already statically guarantees
    // success).
    const _CBSIZE_FITS_U32: () = assert!(std::mem::size_of::<CREDUI_INFOW>() <= u32::MAX as usize);
    let ui_info = CREDUI_INFOW {
        cbSize: u32::try_from(std::mem::size_of::<CREDUI_INFOW>())
            .expect("CREDUI_INFOW size fits in u32 (statically asserted above)"),
        hwndParent: HWND(std::ptr::null_mut()),
        pszMessageText: PCWSTR(body_wide.as_ptr()),
        pszCaptionText: PCWSTR(title_wide.as_ptr()),
        hbmBanner: Default::default(),
    };

    // Flags:
    // - GENERIC_CREDENTIALS: this isn't a domain login; we want a
    //   simple username+password prompt with no PIN / smart-card UI.
    // - DO_NOT_PERSIST: never offer to save in Credential Manager.
    // - KEEP_USERNAME: lock the username field so users can't edit it.
    // - ALWAYS_SHOW_UI: never bypass the dialog (the API can short-
    //   circuit and silently return cached creds if the target name
    //   matches an existing entry; we don't want that).
    let flags = CREDUI_FLAGS(
        CREDUI_FLAGS_GENERIC_CREDENTIALS.0
            | CREDUI_FLAGS_DO_NOT_PERSIST.0
            | CREDUI_FLAGS_KEEP_USERNAME.0
            | CREDUI_FLAGS_ALWAYS_SHOW_UI.0,
    );

    // SAFETY: All pointers passed below are valid for the duration of
    // the call: title_wide / body_wide / target_wide / username_buf /
    // password_buf all live in our stack frame across the
    // CredUIPromptForCredentialsW invocation. The `windows` 0.61
    // wrapper takes the username/password buffers as `&mut [u16]`
    // slices (it derives ptr + length internally); the call is
    // marked `unsafe` because it dereferences the `ui_info` raw
    // pointer.
    let result = unsafe {
        CredUIPromptForCredentialsW(
            Some(&ui_info as *const _),
            PCWSTR(target_wide.as_ptr()),
            None,
            0,
            &mut username_buf,
            &mut password_buf,
            None,
            flags,
        )
    };

    let outcome = match result {
        // ERROR_SUCCESS (0) = user clicked OK. The wrapper returns
        // `WIN32_ERROR`, a newtype around u32 — compare directly.
        ERROR_SUCCESS => {
            let pw_utf16_len = password_buf
                .iter()
                .position(|c| *c == 0)
                .unwrap_or(password_buf.len());
            // `String::from_utf16_lossy` allocates a fresh heap buffer
            // for the UTF-8 result. `into_bytes()` is documented to
            // transfer that same allocation to the Vec<u8> without
            // copying or re-allocating — the `Zeroizing<Vec<u8>>`
            // wrapper then owns the bytes and reliably zeros them on
            // drop. There is no residue-window between the two
            // statements: the heap allocation that holds the password
            // bytes is wrapped before any other code runs.
            let pw_str = String::from_utf16_lossy(&password_buf[..pw_utf16_len]);
            Ok(Zeroizing::new(pw_str.into_bytes()))
        }
        // ERROR_CANCELLED = user clicked Cancel / Esc / close.
        ERROR_CANCELLED => Err(SecureInputError::Cancelled),
        // Anything else = unexpected OS error. `WIN32_ERROR` does
        // not implement `LowerHex`; format the inner u32 (`.0`).
        other => Err(SecureInputError::Internal {
            reason: format!("CredUIPromptForCredentialsW returned 0x{:08x}", other.0),
        }),
    };

    // L1: explicitly scrub the wide password buffer before it drops.
    // The `Zeroizing<Vec<u8>>` covers the UTF-8 path; the UTF-16
    // buffer also held the password and would otherwise leak through
    // the stack allocator's reuse. Use `Zeroize::zeroize` (volatile
    // writes) rather than `[u16]::fill(0)`, which the optimizer is
    // allowed to elide as dead-store elimination once the buffer
    // leaves scope.
    Zeroize::zeroize(&mut password_buf[..]);

    outcome
}

/// Convert `s` to a null-terminated UTF-16 sequence. Used for the
/// `PCWSTR` / `PWSTR` arguments the Credential UI API expects.
fn to_wide_null_terminated(s: &str) -> Vec<u16> {
    let mut v: Vec<u16> = s.encode_utf16().collect();
    v.push(0);
    v
}

/// Convert `s` to a UTF-16 sequence without a null terminator. Used
/// when manually populating a fixed-size buffer where the
/// terminator is already present (zero-initialized buffer).
fn to_wide_chars(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

/// Maximum username length Win32 credential UI accepts (per
/// CredUIPromptForCredentialsW docs). Defined as a constant here to
/// avoid the magic number in the buffer-declaration call site.
const CREDUI_MAX_USERNAME_LENGTH: usize = 513;
