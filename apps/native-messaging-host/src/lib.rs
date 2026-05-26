// SPDX-License-Identifier: AGPL-3.0-or-later
//! `pangolin-native-messaging-host` library crate.
//!
//! The binary entry (`src/main.rs`) is a thin shim around the
//! re-exported `run()` future. Splitting lib + bin makes the frame
//! codec / auth path / IPC client / error mapping unit-testable
//! without a tokio runtime spun up by the `main` shim.
//!
//! See `docs/issue-plans/mvp4-e-native-messaging-host.md` for the full
//! plan. Cross-cuts:
//!
//! - **L1** zero-secret-crosses. The handshake token is the ONLY
//!   secret the host carries; vault VDK / passwords stay in the
//!   desktop process. See `auth.rs`.
//! - **L3** fail-closed: bad token / bad frame / unknown method all
//!   produce typed JSON-RPC errors and exit.
//! - **L7** errors carry no secret material: the `data` field on a
//!   JSON-RPC error is always `null` or a non-secret category string.

#![forbid(unsafe_code)]
#![deny(unused_must_use)]

pub mod auth;
pub mod error;
pub mod frame;
pub mod ipc;
pub mod manifest;
pub mod paths;

pub use error::HostError;

/// Protocol version advertised in the `auth.handshake` success
/// response. Bumped only when the wire shape between the host and
/// desktop changes incompatibly.
pub const PROTOCOL_VERSION: u32 = 1;

/// Crate version string surfaced in the handshake response.
pub const HOST_VERSION: &str = env!("CARGO_PKG_VERSION");
