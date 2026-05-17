//! FFI surface for Pangolin.
//!
//! This crate is the boundary between the Pangolin Rust core and every
//! shell that consumes it: Tauri (desktop, via cbindgen-emitted C ABI),
//! iOS (via `UniFFI`-emitted Swift bindings), Android (via `UniFFI`-emitted
//! Kotlin bindings), and the browser-extension native messaging host
//! (MVP-4).
//!
//! ## Invariants (MVP-1 issue 1.1)
//!
//! - **Q3.** `UniFFI` lives **here** and only here — no other crate
//!   depends on `uniffi`. `cargo tree -p pangolin-core | grep -ci uniffi`
//!   must stay `0`.
//! - **Q4.** TOTP lives in `pangolin-totp` and KDBX import lives in
//!   `pangolin-kdbx`; this crate re-exports their FFI shapes.
//! - **HIGH-1.** `pangolin-crypto` never reaches `uniffi`'s tree.
//!   Dependency arrow goes ffi → crypto, never the reverse.
//! - **No plaintext through `Debug`/`Display`.** `FfiError` carries
//!   only UI-safe strings; the `From<pangolin_core::Error>` mapping
//!   collapses every authentication-class failure into a single
//!   `Validation` or `Internal` variant per Design Spec §15.
//! - **`unsafe_code` policy.** This is the only workspace crate that
//!   allows `unsafe`. Per-crate `[lints]` block in `Cargo.toml`
//!   overrides the workspace `unsafe_code = "deny"`. The
//!   `deny(unsafe_op_in_unsafe_fn)` discipline below means every unsafe
//!   operation must be at a documented call site, never implicitly via
//!   `unsafe fn` body inheritance.
//!
//! ## Schema-versioning policy slot
//!
//! Per master plan §18.7 (locked by MVP-1 issue 1.6 — Revision lineage
//! production), every record that crosses this FFI **and** carries user
//! data carries a `schema_version: u16` field. The policy text itself
//! is not yet committed; 1.1 commits to the **slot** by ensuring every
//! such record exposes the field, and to the locking issue (1.6) being
//! the place where the migration / read-only-old-versions semantics
//! are nailed down.
//!
//! ## Build pipeline
//!
//! - `cargo build -p pangolin-ffi` — produces `staticlib`, `cdylib`,
//!   and `rlib` artefacts (see `[lib].crate-type` in `Cargo.toml`).
//! - `cargo run -p pangolin-ffi --bin uniffi-bindgen --features uniffi-cli -- \
//!     generate --library target/debug/libpangolin_ffi.<so|dylib|dll> \
//!     --language swift --out-dir target/ffi-bindings/swift` — emits
//!   `pangolin.swift` for iOS shells.
//! - Same with `--language kotlin` for the Android shell.
//! - `cargo run -p pangolin-ffi --bin cbindgen-build --features cbindgen-cli` —
//!   emits `pangolin.h` for the Tauri / native-messaging-host shells
//!   from the `extern "C"` surface in [`cabi`].
//!
//! ## Surface freeze
//!
//! The frozen-this-issue surface is documented in
//! `docs/architecture/ffi-surface.md`. 1.2-1.11 land bodies into the
//! per-domain modules below; the *signatures* are locked.

#![deny(unsafe_op_in_unsafe_fn)]

pub mod balance;
pub mod cabi;
pub mod capture_authority;
pub mod device;
pub mod error;
pub mod identity;
mod identity_bridge;
pub mod kdbx;
pub mod publish_queue;
pub mod reveal;
pub mod revision;
pub mod session;
pub mod sync_mode;
pub mod sync_status;
pub mod totp;

pub use error::FfiError;

// MVP-1 issue 1.1: scaffolding-only re-export so 1.2-1.11 have a single
// import path for FFI types. Bodies arrive in the per-domain modules.
//
// MVP-1 issue 1.2 widens AccountDraft / AccountPatch / AccountSnapshot
// to the production multi-* shape (see docs/issue-plans/1.2.md Q1) and
// adds DeviceId, PasswordHistoryEntry, TotpSecret.
pub use identity::{
    AccountDraft, AccountId, AccountPatch, AccountSnapshot, DeviceId, PasswordHistoryEntry,
    TotpSecret,
};
// MVP-1 issue 1.11: capture-authority FFI shapes + entry points
// (additive 1.1-surface amendment — see capture_authority.rs /
// ffi-surface.md). The 1.1-frozen placeholders previously lived in
// kdbx.rs and are now finalised + relocated.
pub use capture_authority::{
    CaptureAuthority, CaptureAuthorityEntry, CaptureAuthorityKind, CaptureContext,
    CaptureContextKind,
};
// MVP-2 issue 3.5: gas-balance state machine + balance monitor FFI
// shapes + entry points (additive 1.1-surface amendment — see
// balance.rs / ffi-surface.md).
pub use balance::{
    balance_monitor_start, balance_monitor_stop, gas_balance_state, vault_initiate_top_up,
    FfiTopUpAttempt, GasBalanceStateFfi, MonitorHandle,
};
// CLI-V1 (R-g) — publish-queue FFI surface.
pub use publish_queue::{
    vault_coalesce_dirty_markers, vault_enable_window_elapsed_flush, vault_flush_publish_queue,
    vault_publish_queue_state, FfiBatchFlushReport, FfiPublishQueueState,
};
// CLI-V1 (R-g) — sync-mode FFI surface.
pub use sync_mode::{
    vault_select_sync_mode, vault_set_sync_mode_preference, vault_sync_mode_preference,
    FfiSyncModePreference,
};
// MVP-1 issue 1.5: device-identity FFI shapes + entry points (additive
// 1.1-surface amendment — see device.rs / ffi-surface.md).
pub use device::{vault_evm_wallet_address, DeviceCapabilities, DeviceInfo};
pub use kdbx::KdbxImportReport;
// MVP-1 issue 1.4: presence-gated reveal-class entry points + the
// zeroizing `RevealedSecret` wrapper they return (Q4 amendment).
pub use reveal::RevealedSecret;
// MVP-1 issue 1.6: revision-lineage finalisation — enriched RevisionMeta
// + the fork/resolve/status FFI shapes (additive 1.1-surface amendment;
// see revision.rs / ffi-surface.md).
pub use revision::{
    AccountStatus, FfiConflictBranchSummary, FfiConflictReport, ForkBranch, RevisionId,
    RevisionMeta,
};
pub use session::{
    vault_lock_with_drain, PasswordPolicy, PasswordStrength, PlaintextExportConfirmation,
    PresenceProof, SecretPassword, SessionInfo, UnixTimestamp, VaultHandle,
    PASSWORD_POLICY_SCHEMA_VERSION,
};
// MVP-2 issue 5.4: sync orchestrator FFI surface — `vault_sync_status`
// + `FfiSyncStatus` enum + `FfiSyncMode` mirror + the host-supplied
// input record + the snapshot record (additive 1.1-surface amendment —
// see sync_status.rs / ffi-surface.md).
pub use sync_status::{
    vault_last_pull_at_unix_ms, vault_pull_once, vault_sync_status, FfiBatchFlushErrorKind,
    FfiLastFlushOutcome, FfiLastPullOutcome, FfiPullErrorKind, FfiPullReport, FfiSyncMode,
    FfiSyncStatus, FfiSyncStatusInputs, FfiSyncStatusSnapshot,
};
// MVP-1 issue 1.7: TOTP engine wired — `totp_generate` body +
// `parse_totp_secret` helper + the `ParsedTotpSecretFfi` /
// `TotpParamsFfi` / `TotpAlgorithm` shapes (additive 1.1-surface
// amendment; see totp.rs / ffi-surface.md).
pub use totp::{ParsedTotpSecretFfi, TotpAlgorithm, TotpCode, TotpParamsFfi};

// UniFFI scaffolding macro. Emits the `uniffi_pangolin_ffi_uniffi_contract_version`
// symbol and other crate-internal book-keeping. This must appear exactly
// once per crate.
uniffi::setup_scaffolding!();

/// Returns the crate name. Diagnostic; not part of the FFI surface.
#[must_use]
pub fn name() -> &'static str {
    "pangolin-ffi"
}

#[cfg(test)]
mod tests {
    use super::name;

    #[test]
    fn crate_name_is_set() {
        assert_eq!(name(), "pangolin-ffi");
    }
}
