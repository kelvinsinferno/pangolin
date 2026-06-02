// SPDX-License-Identifier: AGPL-3.0-or-later
//! **macOS native password widget — NSAlert + NSSecureTextField.**
//!
//! Builds a modal `NSAlert` with the prompt text + an
//! `NSSecureTextField` as `accessoryView`. `runModal()` blocks until
//! the user clicks OK (returns the typed bytes) or Cancel / Esc
//! (returns [`SecureInputError::Cancelled`]).
//!
//! ## Threading
//!
//! AppKit widgets are STRICTLY main-thread-only. Tauri commands run on
//! Tokio's blocking pool, NOT the main thread. The impl uses
//! `tauri::AppHandle::run_on_main_thread` to dispatch the AppKit calls
//! onto the GUI thread, with a `std::sync::mpsc` channel handing the
//! result back to the calling Tokio thread. The closure obtains a
//! `MainThreadMarker` via `MainThreadMarker::new()` (which only
//! succeeds on the main thread — defense-in-depth on top of the
//! `run_on_main_thread` guarantee).
//!
//! ## L1 secret hygiene
//!
//! `NSSecureTextField::stringValue` returns a `Retained<NSString>`
//! which holds the password in Apple's non-zeroizing UTF-16 buffer
//! for the lifetime of the field. We immediately extract the bytes
//! via `to_string()` + `into_bytes()` into a `Zeroizing<Vec<u8>>` —
//! `String::into_bytes` transfers the heap allocation directly
//! without copying, so the same buffer is protected end-to-end on
//! the success path. The cancel path explicitly calls
//! `Zeroize::zeroize` on the intermediate `String` (volatile writes
//! the optimizer cannot elide). The dropped `NSString`'s UTF-16
//! buffer is the only remaining residue — Apple does not zero it
//! on dealloc, and `objc2-app-kit` doesn't expose the raw buffer
//! pointer needed to scrub it ourselves. This is the same hazard
//! the Linux GTK impl has (see `linux.rs` §L1) and the V8 string
//! we're replacing — known trade-off; the secure widget closes the
//! keylogger / screen-grab vector that motivates the epic.

// Verified against objc2-app-kit 0.3.2 source: NSAlert::new(mtm),
// setMessageText/setInformativeText/setAlertStyle/addButtonWithTitle/
// setAccessoryView/runModal, NSSecureTextField::initWithFrame, and
// NSControl::stringValue are all `pub fn` (safe) in this binding.
// `NSSecureTextField::alloc(mtm)` comes from the `MainThreadOnly`
// trait — must be imported for the method to be visible on the type.

use std::sync::mpsc;

use objc2::rc::Retained;
use objc2::{MainThreadMarker, MainThreadOnly};
use objc2_app_kit::{
    NSAlert, NSAlertStyle, NSApplication, NSModalResponse, NSSecureTextField, NSTextField, NSView,
};
use objc2_foundation::{NSPoint, NSRect, NSSize, NSString};

use super::SecureInputError;
use zeroize::{Zeroize, Zeroizing};

/// **Open an NSAlert modal password dialog.** Dispatches onto the
/// AppKit main thread via `app.run_on_main_thread`, blocks the caller
/// via mpsc until the user hits OK / Cancel / Esc.
pub fn prompt_password(
    app: &tauri::AppHandle,
    title: &str,
    body: &str,
) -> Result<Zeroizing<Vec<u8>>, SecureInputError> {
    let (tx, rx) = mpsc::channel::<Result<Zeroizing<Vec<u8>>, SecureInputError>>();
    let title_owned = title.to_string();
    let body_owned = body.to_string();

    app.run_on_main_thread(move || {
        let result = run_nsalert(&title_owned, &body_owned);
        let _ = tx.send(result);
    })
    .map_err(|e| SecureInputError::Unavailable {
        reason: format!("secure_input: run_on_main_thread failed: {e}"),
    })?;

    rx.recv().map_err(|e| SecureInputError::Internal {
        reason: format!("secure_input: main-thread result channel closed: {e}"),
    })?
}

/// **Run the NSAlert on the main thread.** Caller MUST be the AppKit
/// main thread (the public [`prompt_password`] dispatches via
/// `run_on_main_thread` to satisfy this).
///
/// Returns the typed password bytes on OK, `Cancelled` on
/// Cancel / Esc, `Unavailable` if we couldn't acquire the
/// `MainThreadMarker` (would only happen if Tauri's main-thread
/// dispatcher is broken, but defense-in-depth).
fn run_nsalert(title: &str, body: &str) -> Result<Zeroizing<Vec<u8>>, SecureInputError> {
    // Defense in depth: confirm we are on the AppKit main thread
    // before touching any NSObject. Tauri's `run_on_main_thread`
    // already guarantees this; if it ever stops, fail closed.
    let Some(mtm) = MainThreadMarker::new() else {
        return Err(SecureInputError::Unavailable {
            reason: "secure_input: macos run_nsalert called off the main thread".into(),
        });
    };

    // All AppKit interactions below are SAFE because the per-method
    // objc2-app-kit bindings prove main-thread + nullability invariants
    // at the type system level (each method here is `pub fn`, not
    // `pub unsafe fn` — verified against objc2-app-kit 0.3.2 source).
    // Bytes flow into a Zeroizing<Vec<u8>> at the end so the password
    // lifetime in non-zeroizing buffers is minimal.

    // Ensure the app is running. NSApp may not yet be wired up if
    // this is called extremely early in the lifecycle. We don't
    // assume any setup state beyond that mtm is valid.
    let _ = NSApplication::sharedApplication(mtm);

    let alert: Retained<NSAlert> = NSAlert::new(mtm);
    let title_ns = NSString::from_str(title);
    let body_ns = NSString::from_str(body);

    alert.setMessageText(&title_ns);
    alert.setInformativeText(&body_ns);
    alert.setAlertStyle(NSAlertStyle::Informational);

    let ok_title = NSString::from_str("OK");
    let cancel_title = NSString::from_str("Cancel");
    // The first added button is the default (Enter key); second is
    // typically Cancel / Esc.
    alert.addButtonWithTitle(&ok_title);
    alert.addButtonWithTitle(&cancel_title);

    // NSSecureTextField for the password input. 24-pt height, 240-pt
    // width — fits NSAlert's default content layout cleanly. The
    // `alloc(mtm)` method comes from the `MainThreadOnly` trait.
    let frame = NSRect {
        origin: NSPoint { x: 0.0, y: 0.0 },
        size: NSSize {
            width: 240.0,
            height: 24.0,
        },
    };
    let field: Retained<NSSecureTextField> =
        NSSecureTextField::initWithFrame(NSSecureTextField::alloc(mtm), frame);

    // Set the accessory view so the field appears inside the alert
    // and the user can start typing immediately.
    let field_view: &NSView = field.as_ref();
    alert.setAccessoryView(Some(field_view));

    // Run the modal. `runModal` returns NSModalResponse (i64); the
    // first button's response is NSAlertFirstButtonReturn (1000), the
    // second is NSAlertSecondButtonReturn (1001).
    let response: NSModalResponse = alert.runModal();

    // Capture the field text BEFORE dropping the alert (which would
    // destroy the accessory view + its NSString buffer).
    let text_ns: Retained<NSString> = {
        let parent: &NSTextField = field.as_ref();
        parent.stringValue()
    };
    // `to_string()` allocates a fresh UTF-8 `String` whose heap
    // buffer holds the password. `let mut` so the cancel path can
    // explicitly zeroize it before drop (the success path consumes it
    // via `into_bytes()` → `Zeroizing<Vec<u8>>`, which transfers the
    // same allocation without copying).
    let mut text = text_ns.to_string();
    drop(text_ns);
    drop(field);
    drop(alert);

    // NSAlertFirstButtonReturn = 1000 (OK), NSAlertSecondButtonReturn = 1001 (Cancel).
    const NS_ALERT_FIRST_BUTTON_RETURN: NSModalResponse = 1000;
    if response == NS_ALERT_FIRST_BUTTON_RETURN {
        // `into_bytes()` transfers the `String`'s heap allocation to
        // the returned `Vec<u8>` without copying or re-allocating — the
        // `Zeroizing<Vec<u8>>` wrapper then owns the same buffer that
        // held the password as a `String` and reliably zeros it on
        // drop. No residue-window between the two statements.
        Ok(Zeroizing::new(text.into_bytes()))
    } else {
        // Cancel path: `text` is not consumed, so its heap allocation
        // would otherwise drop without being scrubbed. Zero it
        // explicitly before letting it go out of scope (volatile
        // writes via the `Zeroize` impl for `String` — uncuttable by
        // DCE, unlike `String::clear()` which the optimizer may elide).
        text.zeroize();
        Err(SecureInputError::Cancelled)
    }
}
