// SPDX-License-Identifier: AGPL-3.0-or-later
//! Tauri command surface for the Pangolin desktop shell.
//!
//! See MVP-4-B plan §3.2 for the canonical list:
//!
//! - `vault::vault_open` / `vault::vault_unlock` / `vault::vault_lock`
//!   / `vault::vault_close` — the lifecycle commands.
//! - `account::accounts_list` / `account::account_show` /
//!   `account::reveal_password` / `account::copy_to_clipboard` — the
//!   minimum first surface for the closed-beta UX.
//!
//! Each command takes owned argument types (no refs) and returns
//! `Result<T, crate::error::DesktopError>` so Tauri's bridge serializes
//! both arms through its standard `Result` envelope.

#![forbid(unsafe_code)]

pub mod account;
pub mod install_native_host;
pub mod pairing;
pub mod recovery;
pub mod vault;
