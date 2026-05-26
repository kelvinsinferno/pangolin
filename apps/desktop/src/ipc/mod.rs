// SPDX-License-Identifier: AGPL-3.0-or-later
//! Desktop-side IPC server for the native-messaging host.
//!
//! See MVP-4-E plan §1 (Desktop-side IPC server). The server is spun
//! up as a background tokio task at Tauri-builder setup time
//! (`lib.rs::build_app`). It listens on the per-user pipe/socket path
//! the host expects, accepts ONE connection at a time (single-host
//! pattern; if a second host tries to connect while the first is
//! active, the new connection replaces the old one), parses framed
//! JSON-RPC requests, and dispatches them to a fixed set of methods
//! that wrap the existing `commands::` handlers.
//!
//! ## Single-host semantics
//!
//! The plan §6 bullet 4 documents "ONE connection at a time". The
//! implementation here REPLACES the prior connection: the listener
//! accept loop sends an abort signal to any in-flight handler when a
//! new connection arrives. Rationale: Chrome's `connectNative` will
//! happily spawn a second host if the user opens the popup twice in
//! the same Chrome profile; failing the SECOND connection would
//! produce a misleading "auth failed" toast for the user, whereas
//! cleanly handing off matches the user mental model ("the most
//! recent popup talks to the desktop").
//!
//! ## Wire shape
//!
//! Same as the host side (see
//! `apps/native-messaging-host/src/frame.rs`): 4-byte LE length
//! prefix + UTF-8 JSON-RPC 2.0 body. ≤1 MB per frame.
//!
//! ## Methods this slice ships
//!
//! - `session.status` → `{ vault_open: bool, vault_unlocked: bool }`.
//! - `vault.list_accounts` → `[AccountSummaryDto]`.
//! - `vault.account_show(id)` → `AccountSummaryDto`.
//! - `vault.copy_password(id)` → `null` (Rust-side clipboard write;
//!   H-1 carve-out from MVP-4-B).
//!
//! Per plan §1 last bullet: `reveal_password` is NOT exposed — the
//! extension never holds plaintext.

#![forbid(unsafe_code)]

pub mod dispatch;

use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::Mutex;

/// Per-user IPC channel path (named-pipe on Win; UDS elsewhere).
///
/// Mirrors `pangolin_native_messaging_host::paths::ipc_channel_path`;
/// kept here as a separate definition to avoid the desktop crate
/// depending on the host crate (different build matrices — the
/// desktop is excluded from workspace clippy/test due to Tauri Linux
/// deps; the host is included). Any drift is caught by the per-OS
/// integration test in `install_native_host.rs`.
#[must_use]
pub fn ipc_channel_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        let user = std::env::var("USERNAME").unwrap_or_else(|_| "default".to_string());
        PathBuf::from(format!(r"\\.\pipe\studio.kelvinsinferno.pangolin\{user}"))
    }
    #[cfg(target_os = "macos")]
    {
        std::env::var_os("HOME")
            .map(|h| PathBuf::from(h).join("Library/Application Support/Pangolin/native-host.sock"))
            .unwrap_or_else(|| PathBuf::from("pangolin-native-host.sock"))
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR") {
            return PathBuf::from(runtime).join("pangolin/native-host.sock");
        }
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(".local/share/pangolin/native-host.sock");
        }
        PathBuf::from("pangolin-native-host.sock")
    }
}

/// Spawn the IPC server task on the current tokio runtime, holding
/// a clone of Tauri's `AppHandle`.
///
/// The `AppHandle` is used for two things on the IPC side:
///
/// - state lookup: each dispatched request reads `VaultState` via
///   `app.state::<VaultState>()` (Tauri's `State` lookup is cheap +
///   ensures coherence with the React UI's view of the same state),
/// - clipboard: the `vault.copy_password` path needs the clipboard
///   plugin which is reached via `app.clipboard()`.
///
/// Idempotent in the sense that calling twice will replace the
/// prior task; the caller (`build_app::setup`) only calls once.
/// Errors during bind are logged via `eprintln!` (Tauri's host
/// process has stderr attached on debug builds; release builds use
/// the platform's native logging — out of scope for this slice).
pub fn spawn_with_app_handle(app: tauri::AppHandle) {
    let path = ipc_channel_path();
    tokio::spawn(async move {
        if let Err(e) = run(app, path).await {
            eprintln!("[pangolin-desktop] IPC server stopped: {e}");
        }
    });
}

/// IPC-server top-level error.
#[derive(Debug)]
pub enum IpcServerError {
    /// Listener bind failed (path conflict, permission denied,
    /// runtime-dir missing).
    BindFailed(String),
}

impl std::fmt::Display for IpcServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BindFailed(s) => write!(f, "bind failed: {s}"),
        }
    }
}

impl std::error::Error for IpcServerError {}

/// Run the IPC server. Returns on bind failure or unrecoverable
/// accept-loop error.
async fn run(app: tauri::AppHandle, path: PathBuf) -> Result<(), IpcServerError> {
    use interprocess::local_socket::{
        tokio::Listener as IpcListener, traits::tokio::Listener as _, GenericFilePath,
        GenericNamespaced, ListenerOptions, ToFsName, ToNsName,
    };

    // Clean stale socket files on Unix (a previous desktop instance
    // crashed leaving the socket on disk). Idempotent: not-found is
    // not an error.
    #[cfg(unix)]
    {
        let _ = std::fs::remove_file(&path);
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
    }

    let p = path.to_string_lossy();
    let name = if cfg!(windows) && p.starts_with(r"\\.\pipe\") {
        let stripped = p.trim_start_matches(r"\\.\pipe\");
        stripped
            .to_ns_name::<GenericNamespaced>()
            .map_err(|e| IpcServerError::BindFailed(e.to_string()))?
    } else {
        p.as_ref()
            .to_fs_name::<GenericFilePath>()
            .map_err(|e| IpcServerError::BindFailed(e.to_string()))?
    };
    let opts = ListenerOptions::new().name(name);
    let listener: IpcListener = opts
        .create_tokio()
        .map_err(|e| IpcServerError::BindFailed(e.to_string()))?;

    // Single-host slot: FIRST-WINS arbitration (audit M-2 hardening,
    // 2026-05-26). When a new connection arrives WHILE the prior
    // handler is still running, drop the new connection immediately —
    // the prior handler keeps its grip on the desktop state. The
    // earlier implementation aborted the prior handler at the next
    // .await point, which could interrupt a `vault.copy_password`
    // between the FFI plaintext-read and the clipboard write (no
    // secret leak — plaintext stays Rust-side under Zeroizing — but
    // a UX hazard: clipboard ended up with whichever account's
    // copy_password finished last, not the one the user last clicked).
    //
    // First-wins makes the semantics deterministic: a second popup
    // click that races a slow first call gets a clean "host busy"
    // rejection and Chrome surfaces it as a connection error; the
    // user retries after the first call completes. The slot clears
    // automatically when the active handler returns (the inner
    // `slot.take()` after `handle_connection` does the cleanup).
    let current: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>> = Arc::new(Mutex::new(None));

    loop {
        let Ok(conn) = listener.accept().await else {
            // ephemeral accept failure; keep going
            continue;
        };

        // First-wins gate: if the prior handler is still running,
        // refuse the new connection without disturbing it.
        {
            let mut slot = current.lock().await;
            if let Some(prev) = slot.as_ref() {
                if !prev.is_finished() {
                    // Drop `conn` immediately so the new peer sees an
                    // EOF on read; the host translates that into an
                    // `ipc_disconnect` JSON-RPC error and Chrome
                    // surfaces it to the popup.
                    drop(conn);
                    continue;
                }
                // Prior handler finished — clear the slot so this new
                // connection can take ownership.
                slot.take();
            }
        }

        let app_clone = app.clone();
        let slot_clone = Arc::clone(&current);
        let handle = tokio::spawn(async move {
            handle_connection(app_clone, conn).await;
            // Clear our own slot when finished. We're the only writer
            // (the accept loop only enters this block after confirming
            // the previous slot is finished), so a simple take is safe.
            let mut slot = slot_clone.lock().await;
            slot.take();
        });
        let mut slot = current.lock().await;
        *slot = Some(handle);
    }
}

/// Handle a single accepted IPC connection. Reads framed JSON-RPC
/// requests in a loop, dispatches each to `dispatch::handle_request`,
/// writes the result back. Exits when the peer closes the channel.
async fn handle_connection(app: tauri::AppHandle, conn: interprocess::local_socket::tokio::Stream) {
    let (mut r, mut w) = tokio::io::split(conn);
    loop {
        let Ok(body) = read_frame(&mut r).await else {
            // EOF or framing error; close out
            return;
        };
        let response = dispatch::handle_request_with_app(&app, &body).await;
        if write_frame(&mut w, &response).await.is_err() {
            return;
        }
    }
}

/// Read one framed body from the IPC stream. Same wire shape as the
/// host crate's `frame.rs`; duplicated locally to keep the desktop's
/// build independent of the host crate's compilation (see Cargo
/// graph note in `mod docs` above).
async fn read_frame<R: tokio::io::AsyncRead + Unpin>(reader: &mut R) -> std::io::Result<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    let mut len_bytes = [0u8; 4];
    reader.read_exact(&mut len_bytes).await?;
    let len = u32::from_le_bytes(len_bytes);
    if len > 1024 * 1024 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "frame oversize",
        ));
    }
    let mut body = vec![0u8; len as usize];
    reader.read_exact(&mut body).await?;
    Ok(body)
}

/// Write a framed body to the IPC stream.
async fn write_frame<W: tokio::io::AsyncWrite + Unpin>(
    writer: &mut W,
    body: &[u8],
) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let len = u32::try_from(body.len())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "frame too long"))?;
    if len > 1024 * 1024 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "frame oversize",
        ));
    }
    writer.write_all(&len.to_le_bytes()).await?;
    writer.write_all(body).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `ipc_channel_path()` helper resolves to a non-empty path on
    /// every supported OS. We do not assert a specific format because
    /// the env vars differ — just that the result is non-empty.
    #[test]
    fn ipc_channel_path_is_non_empty() {
        let p = ipc_channel_path();
        assert!(!p.as_os_str().is_empty());
    }
}
