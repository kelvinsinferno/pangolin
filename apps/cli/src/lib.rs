//! Library entry point for `pangolin-cli`.
//!
//! `pangolin-cli` is primarily a binary crate; this `lib.rs` exists
//! to expose the orchestration modules (`sync`, `keystore`,
//! `vault_open`, `config`, `cli`) to integration tests under
//! `apps/cli/tests/*.rs`. Cargo's binary-crate model does
//! not allow integration tests to import a binary's modules; making
//! the same source files compile as both library AND binary is the
//! standard idiom for this case.
//!
//! ## Public surface
//!
//! Only `sync` is `pub` because the integration tests under `tests/`
//! drive `publish_all` / `pull_all` directly. The other modules
//! (`cli`, `commands`, `keystore`, `config`, `vault_open`) are
//! `pub(crate)`-equivalent and intentionally not re-exported through
//! this entry point. External consumers should not import this
//! library; if you need pangolin orchestration in a different
//! binary, lift the relevant code into a `pangolin-sync` crate first.

// **P8 fix MED-4.** `forbid(unsafe_code)` is now unconditional —
// see `main.rs` for the same fix and rationale.
#![forbid(unsafe_code)]

// `sync` is the orchestration core that integration tests drive
// directly.
pub mod sync;

// Surfaces required by `main.rs`. The binary entry point lives in a
// separate compilation unit from this library; Rust's visibility
// rules require these modules to be `pub` here for `main.rs` to
// reach them. They are not part of the documented external API —
// `pangolin-cli` is a binary crate, and the library exists only as
// a re-target for integration tests + the binary's own dispatch.
pub mod cli;
pub mod commands;
pub mod config;
pub mod keystore;
pub mod vault_open;
