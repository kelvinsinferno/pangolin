// MVP-1 issue 1.1 (Q3 — separate `pangolin-ffi` crate). The build script
// invokes UniFFI's scaffolding generator. In proc-macro mode the
// scaffolding is largely emitted by `#[uniffi::export]` etc. at compile
// time; this hook is reserved for the legacy UDL-driven path and any
// crate-wide setup the proc-macros expect to find. We keep it as a thin
// shim today so wiring lands once and grows in lockstep with the FFI
// surface as 1.2-1.11 fill in real types.

fn main() {
    // Re-run if the FFI source files change. UniFFI's proc-macros do
    // their own compile-time work; this println keeps cargo's
    // change-tracking honest if a future revision introduces a UDL
    // file or an out-of-tree generator step.
    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=src/cabi.rs");
    println!("cargo:rerun-if-changed=src/error.rs");
    println!("cargo:rerun-if-changed=src/identity.rs");
    println!("cargo:rerun-if-changed=src/session.rs");
    println!("cargo:rerun-if-changed=src/revision.rs");
    println!("cargo:rerun-if-changed=src/totp.rs");
    println!("cargo:rerun-if-changed=src/kdbx.rs");
}
