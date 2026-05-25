// SPDX-License-Identifier: AGPL-3.0-or-later
//! Binary entry for `pangolin-desktop`.
//!
//! Thin shim that wires the library-side `build_app()` against the
//! current process. The `#[cfg_attr(not(debug_assertions), windows_subsystem = "windows")]`
//! attribute keeps a release build from popping a console window on
//! Windows (Tauri's standard pattern); debug builds keep the console
//! attached for `println!` / `eprintln!`-style diagnostics.

#![forbid(unsafe_code)]
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    pangolin_desktop_lib::build_app()
        .run(tauri::generate_context!())
        .expect("error while running pangolin-desktop");
}
