// SPDX-License-Identifier: AGPL-3.0-or-later
//! Pangolin funder service — one-way ETH dispenser.
//!
//! Per MVP-2 issue 3.4 (Kelvin sign-off 2026-05-15): an axum HTTP
//! server that accepts top-up requests from devices, verifies a
//! `PAYMENT_AUTHORITY`-signed Credit attestation plus a client-signed
//! device-binding proof, signs and submits a `Redemption` attestation
//! as the contract `REDEMPTION_AUTHORITY` to decrement the user's
//! on-chain balance, and sends ETH to the requesting device wallet
//! from a funder-owned wallet. Rate-limited per address plus globally;
//! stateless beyond a small `SQLite` payment ledger; incapable of
//! signing revisions or touching vault data (L1 + L7 + L11
//! mechanical defense).
//!
//! ## Module layout
//!
//! - [`http`] — axum routes, request handlers, and the `AppState` the
//!   handlers close over.
//! - [`rate_limit`] — per-address token bucket + global hourly cap.
//! - [`ledger`] — `SQLite`-backed payment ledger (off-chain replay
//!   defense surviving restart).
//! - [`signer`] — `FunderSigner` trait + `FileKeystoreSigner` impl;
//!   `MockSigner` behind `#[cfg(test)]`.
//! - [`config`] — environment-variable parsing.
//! - [`error`] — typed `FunderError` enum + `IntoResponse` impl.
//!
//! ## R-a..R-g resolutions
//!
//! Kelvin's 2026-05-15 decisions are summarised here so a future
//! reader has the full architectural context without bouncing through
//! the plan-gate doc. Source of truth: `docs/issue-plans/3.4.md`.
//!
//! - **R-a HTTP framework: axum.** Tokio-native; tower middleware;
//!   smallest review surface that gets the job done.
//! - **R-b persistence: hybrid.** Rate limit in-memory (resets clean
//!   on restart, conservative posture); `SQLite` payment ledger
//!   (durable, replays defended across restart).
//! - **R-c verification: signed Credit attestation only.** No
//!   chain-balance fallback. Attestation hash UNIQUE in the ledger.
//! - **R-d D-019 split-key redeploy.** Operational follow-up after
//!   merge; this crate reads address via `load_deployed_address`.
//! - **R-e layered rate limit.** 10 tokens / 10-min replenish per
//!   address; global cap 200/hour. Env overrides via
//!   `FUNDER_RATE_LIMIT_*`.
//! - **R-f `FunderSigner` trait + `FileKeystoreSigner` impl.** HSM
//!   scaffolded but not implemented (mainnet deferred).
//! - **R-g client-signed device-binding.** Domain constant +
//!   verifier in `pangolin-funder-client`; this crate consumes both.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
// The pedantic + nursery lint sets are inherited from the workspace
// `[lints]` block. The explicit allows below silence patterns that
// are intentional in this service crate but trip the strict workspace
// configuration:
//
//   `clippy::missing_errors_doc` — every error path is enumerated by
//   `FunderError` + the docstring on the relevant fn already names
//   the variant; per-call-site docstrings would be redundant.
//
//   `clippy::module_name_repetitions` — `http::routes` returning a
//   `http::AppState` is the canonical idiom; renaming purely to
//   avoid the lint would hurt readability.
//
//   `clippy::significant_drop_tightening` — the ledger writes hold a
//   `tokio::sync::Mutex` lock guard across the `rusqlite::execute`
//   call. The "tightening" the lint suggests would split the borrow
//   chain and break the await-point boundaries; SQLite serialises
//   writes anyway, so the lock-held window doesn't add contention.
//
//   `clippy::similar_names` — pairing `signer` + `signed` is the
//   canonical alloy / 3.1 vocabulary; renaming for the linter is
//   pure noise.
//
//   `clippy::option_if_let_else` — every error mapping path was
//   originally written in `match` form for readability; the
//   `map_or` collapse is a pure stylistic preference + nursery
//   lint.
//
//   `clippy::too_long_first_doc_paragraph` — multiple module / type
//   docstrings open with a full architectural paragraph; the lint
//   prefers a one-line summary, which would force two-tier writing
//   that worsens the audit-readability.
//
//   `clippy::missing_fields_in_debug` — `AppState` redacts the
//   ledger + rate_limiter fields from `Debug` deliberately (the
//   `finish_non_exhaustive` alternative would obscure the redaction
//   intent).
#![allow(
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    clippy::significant_drop_tightening,
    clippy::similar_names,
    clippy::option_if_let_else,
    clippy::too_long_first_doc_paragraph,
    clippy::missing_fields_in_debug
)]

pub mod config;
pub mod error;
pub mod http;
pub mod ledger;
pub mod rate_limit;
pub mod signer;

pub use config::FunderConfig;
pub use error::FunderError;
pub use http::AppState;
pub use ledger::PaymentLedger;
pub use rate_limit::{RateLimitConfig, RateLimitOutcome, RateLimiter};
pub use signer::{FileKeystoreSigner, FunderSigner};

/// Crate name. Useful for diagnostics + version reporting (e.g., the
/// `/funder/v1/health` response embeds the build commit but the name
/// is here as the canonical service identifier).
#[must_use]
pub fn name() -> &'static str {
    "pangolin-funder"
}
