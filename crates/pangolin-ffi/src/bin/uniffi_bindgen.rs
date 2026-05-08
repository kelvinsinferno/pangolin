//! `UniFFI` bindgen entry point — emits Swift / Kotlin / Python bindings.
//!
//! Standard `UniFFI` 0.31+ pattern: each crate that wants foreign-language
//! bindings ships its own bindgen binary that delegates to `UniFFI`'s
//! library-mode CLI. Run with:
//!
//! ```bash
//! cargo run -p pangolin-ffi --bin uniffi-bindgen --features uniffi-cli -- \
//!     generate \
//!     --library target/debug/libpangolin_ffi.<so|dylib|dll> \
//!     --language swift \
//!     --out-dir target/ffi-bindings/swift
//! ```
//!
//! See `docs/architecture/ffi-surface.md` for the full bindgen
//! pipeline documentation.

fn main() {
    uniffi::uniffi_bindgen_main();
}
