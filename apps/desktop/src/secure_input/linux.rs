// SPDX-License-Identifier: AGPL-3.0-or-later
//! **Linux native password widget — GTK3 modal Dialog + GtkEntry.**
//!
//! Spawns a modal `gtk::Dialog` with an OK / Cancel button bar and a
//! single `gtk::Entry` whose `visibility` is OFF (i.e. the field
//! masks every typed character) and whose `input_purpose` is set to
//! `InputPurpose::Password` (a hint to assistive tech + IMEs to treat
//! the field as secret — disables suggestion history, autofill,
//! clipboard scrubbers).
//!
//! ## Threading
//!
//! GTK widgets are STRICTLY tied to the GTK main thread. Tauri
//! commands run on Tokio's blocking pool, NOT the main thread, so a
//! direct `dialog.run()` from a command handler would panic. The
//! impl uses `tauri::AppHandle::run_on_main_thread` to dispatch the
//! GTK call onto the main loop, with a `std::sync::mpsc` channel
//! handing the result back to the calling Tokio thread.
//!
//! ## L1 secret hygiene
//!
//! The `GtkEntry::text` call returns a `glib::GString` which is a
//! reference-counted buffer that is NOT zeroizing. We immediately
//! copy the bytes into a `Zeroizing<Vec<u8>>` and let the GString
//! drop. The temporary copy in the GString reference count is the
//! same residue hazard that NSSecureTextField has on macOS — both
//! widgets briefly hold the password in a non-zeroizing OS buffer
//! during the dialog's lifetime. This is a known acceptable trade
//! relative to keeping the password in a V8 JS string for ms-seconds.

use std::sync::mpsc;

use super::SecureInputError;
use zeroize::Zeroizing;

/// **Open a GTK modal password Dialog.** Dispatches onto the GTK main
/// thread via `app.run_on_main_thread`, blocks the caller via mpsc
/// until the user hits OK / Cancel / closes the dialog.
pub fn prompt_password(
    app: &tauri::AppHandle,
    title: &str,
    body: &str,
) -> Result<Zeroizing<Vec<u8>>, SecureInputError> {
    let (tx, rx) = mpsc::channel::<Result<Zeroizing<Vec<u8>>, SecureInputError>>();
    let title_owned = title.to_string();
    let body_owned = body.to_string();

    app.run_on_main_thread(move || {
        let result = run_gtk_dialog(&title_owned, &body_owned);
        // If the receiver was dropped (Tokio task was cancelled), we
        // can't deliver the result anyway — silently discard. The
        // `let _ = ` suppresses the unused-result warning.
        let _ = tx.send(result);
    })
    .map_err(|e| SecureInputError::Unavailable {
        reason: format!("secure_input: run_on_main_thread failed: {e}"),
    })?;

    rx.recv().map_err(|e| SecureInputError::Internal {
        reason: format!("secure_input: main-thread result channel closed: {e}"),
    })?
}

/// **Run the GTK dialog on the main thread.** Caller MUST be the GTK
/// main thread (the public [`prompt_password`] dispatches via
/// `run_on_main_thread` to satisfy this).
///
/// Returns the typed password bytes on OK, `Cancelled` on
/// Cancel / close-window / ESC, `Internal` on a GTK call failure.
fn run_gtk_dialog(title: &str, body: &str) -> Result<Zeroizing<Vec<u8>>, SecureInputError> {
    use gtk::prelude::*;

    let dialog = gtk::Dialog::with_buttons(
        Some(title),
        None::<&gtk::Window>,
        gtk::DialogFlags::MODAL | gtk::DialogFlags::DESTROY_WITH_PARENT,
        &[
            ("Cancel", gtk::ResponseType::Cancel),
            ("OK", gtk::ResponseType::Ok),
        ],
    );
    dialog.set_default_response(gtk::ResponseType::Ok);

    let content = dialog.content_area();
    content.set_spacing(8);
    content.set_margin_start(16);
    content.set_margin_end(16);
    content.set_margin_top(12);
    content.set_margin_bottom(12);

    let label = gtk::Label::new(Some(body));
    label.set_xalign(0.0);
    label.set_max_width_chars(60);
    label.set_line_wrap(true);

    let entry = gtk::Entry::new();
    entry.set_visibility(false); // password mask
    entry.set_input_purpose(gtk::InputPurpose::Password);
    entry.set_activates_default(true); // Enter triggers default-response (OK)
    entry.set_width_chars(40);

    content.pack_start(&label, false, false, 0);
    content.pack_start(&entry, false, false, 0);

    dialog.show_all();
    let response = dialog.run();
    // Capture the text BEFORE we close + drop the dialog — once the
    // GtkEntry is destroyed its buffer is freed.
    let text = entry.text().to_string();
    // Hide + destroy. GTK3 needs explicit close on a Dialog after
    // dialog.run() to break out of the modal loop properly.
    dialog.close();
    // Help GTK release its reference; redundant given the variable
    // scope but cheap insurance against the explicit-drop expectation
    // of older gtk-rs versions.
    drop(dialog);

    match response {
        gtk::ResponseType::Ok => {
            // Move the bytes into a Zeroizing<Vec<u8>>; the original
            // String (`text`) drops at end-of-scope but its allocator
            // doesn't zero on drop. The shorter the temporary's
            // lifetime, the smaller the V8-equivalent residue
            // window — we consume `text` directly via `into_bytes`.
            Ok(Zeroizing::new(text.into_bytes()))
        }
        // ESC / Cancel / close-window / DeleteEvent all surface here.
        _ => Err(SecureInputError::Cancelled),
    }
}
