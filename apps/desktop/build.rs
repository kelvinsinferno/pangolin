// SPDX-License-Identifier: AGPL-3.0-or-later
// Tauri v2 build script. `tauri_build::build()` reads the sibling
// `tauri.conf.json` + the `capabilities/` directory and emits the
// per-platform resource bundles + the capability allow-list that the
// runtime enforces. Required by every Tauri v2 binary crate.

fn main() {
    tauri_build::build();
}
