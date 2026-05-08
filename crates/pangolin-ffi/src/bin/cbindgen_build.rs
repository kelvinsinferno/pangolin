//! `cbindgen-build` — emits `pangolin.h` from the `extern "C"` surface
//! in `src/cabi.rs`.
//!
//! Run with:
//!
//! ```bash
//! cargo run -p pangolin-ffi --bin cbindgen-build --features cbindgen-cli
//! ```
//!
//! Output lands at `target/ffi-bindings/c/pangolin.h`. The CI step
//! `ffi-bindings` runs `cc -fsyntax-only` on the emitted header to
//! verify it parses.

use std::env;
use std::path::PathBuf;

fn main() {
    // CARGO_MANIFEST_DIR is set by `cargo run` to point at the crate
    // that contains the binary's package — i.e., this crate's root.
    // We resolve the workspace root by walking two levels up
    // (`crates/pangolin-ffi/` → workspace root) so the emitted header
    // lands under `target/ffi-bindings/c/` relative to the workspace
    // build dir, regardless of the caller's cwd.
    let crate_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let workspace_root = crate_dir
        .parent()
        .and_then(std::path::Path::parent)
        .expect("workspace root from crates/pangolin-ffi/")
        .to_path_buf();

    let out_dir = workspace_root.join("target").join("ffi-bindings").join("c");
    std::fs::create_dir_all(&out_dir).expect("create output dir");
    let out_path = out_dir.join("pangolin.h");

    let config_path = crate_dir.join("cbindgen.toml");
    let config = cbindgen::Config::from_file(&config_path)
        .unwrap_or_else(|_| panic!("read cbindgen.toml at {}", config_path.display()));

    cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(config)
        .generate()
        .expect("cbindgen generate")
        .write_to_file(&out_path);

    println!("cbindgen wrote {}", out_path.display());
}
