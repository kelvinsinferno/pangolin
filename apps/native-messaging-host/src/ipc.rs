// SPDX-License-Identifier: AGPL-3.0-or-later
//! IPC client to the running desktop's per-user pipe/socket.
//!
//! Per plan §3.1 + §6: the host connects to the desktop's IPC
//! endpoint after the handshake-token check passes; from there on the
//! host is a transparent JSON-RPC relay. ONE connection at a time
//! (single-host pattern); the desktop's accept side closes any
//! previous connection when a new one arrives.
//!
//! The wire on the IPC channel is the SAME framed JSON-RPC envelope
//! the extension speaks (see `frame.rs`). No re-encoding; the host
//! literally reads a frame from one channel and writes it verbatim
//! to the other (modulo the handshake exchange which never crosses
//! to the desktop).
//!
//! Owner-EUID / per-user-ACL discipline (plan §6 bullet 4):
//!
//! - On Unix the desktop's IPC server `bind`s with mode 0600 and a
//!   pathname under the user's `$XDG_RUNTIME_DIR`. Any peer that can
//!   `connect()` to that path must already be running as the same
//!   UID. We additionally verify the file metadata's owner matches
//!   the current EUID on the host side as a belt-and-braces check.
//! - On Windows the named pipe is created with no explicit security
//!   descriptor; the OS default ACL grants access only to the
//!   current logon SID. The pipe name itself is per-user (encodes
//!   `%USERNAME%`) to avoid cross-user name collisions.

#![forbid(unsafe_code)]

use std::path::Path;

use interprocess::local_socket::{
    tokio::Stream as IpcStream, traits::tokio::Stream as IpcStreamTrait, GenericFilePath,
    GenericNamespaced, ToFsName, ToNsName,
};

use crate::error::HostError;

/// Connect to the desktop's IPC endpoint at `path`.
///
/// Returns an open async stream supporting `AsyncRead + AsyncWrite`.
/// The caller frames JSON-RPC bodies via `frame::write_frame` /
/// `frame::read_frame`.
///
/// # Errors
///
/// [`HostError::IpcConnectFailed`] if the underlying connect fails
/// (peer not running, path missing, permission denied, etc.).
pub async fn connect(path: &Path) -> Result<IpcStream, HostError> {
    // `interprocess::local_socket` accepts either a filesystem-style
    // pathname (Unix-domain socket on Unix; Windows named pipe via
    // the `\\.\pipe\<name>` path) or a namespaced name. We prefer the
    // path form everywhere because the desktop's bind side writes a
    // concrete per-user path that's easy to validate ownership on.
    let p = path.to_string_lossy();
    let name = if cfg!(windows) && p.starts_with(r"\\.\pipe\") {
        // Windows named-pipe path: use the namespaced ctor (the path
        // form is what Windows expects for a pipe).
        // Strip the `\\.\pipe\` prefix; interprocess wants the pipe
        // basename in namespaced mode.
        let stripped = p.trim_start_matches(r"\\.\pipe\");
        stripped
            .to_ns_name::<GenericNamespaced>()
            .map_err(|_| HostError::IpcConnectFailed)?
    } else {
        p.to_fs_name::<GenericFilePath>()
            .map_err(|_| HostError::IpcConnectFailed)?
    };

    // On Unix, validate the socket file's owner = current EUID.
    // Plan §6 belt-and-braces. We do this BEFORE connect so a
    // hijacked path (a malicious user pre-creating the socket as a
    // different UID) never sees our first byte.
    #[cfg(unix)]
    {
        verify_unix_socket_owner(path)?;
    }

    let stream = IpcStream::connect(name)
        .await
        .map_err(|_| HostError::IpcConnectFailed)?;
    Ok(stream)
}

/// Verify the IPC socket file at `path` is owned by the current
/// effective UID (Unix only).
///
/// Audit HIGH H-1 hardening (2026-05-26). The previous implementation
/// read `$UID` from the environment + fell back to `unwrap_or(owner_uid)`
/// — a FAIL-OPEN check: when `$UID` is unset (the common case when
/// Chrome is launched from a desktop-environment session manager like
/// systemd `gnome-session`, KDE `plasma-session`, GDM/SDDM autostart,
/// or `xdg-open`), the comparison passed regardless of who owned the
/// socket. `$UID` is a shell builtin (bash/zsh), NOT a POSIX env var.
///
/// Replaced with `rustix::process::geteuid()` — zero-unsafe public API,
/// already in the workspace transitively, gated on `cfg(unix)`. The
/// new check fails CLOSED on UID mismatch + does NOT have an
/// environment-variable fallback at all.
#[cfg(unix)]
fn verify_unix_socket_owner(path: &Path) -> Result<(), HostError> {
    use std::os::unix::fs::MetadataExt;
    let md = std::fs::metadata(path).map_err(|_| HostError::IpcConnectFailed)?;
    let owner_uid = md.uid();
    // `rustix::process::geteuid()` is infallible on all platforms it
    // supports (returns `Uid`; never errors). `.as_raw()` gives the
    // numeric UID for direct comparison with the std-filesystem uid.
    let my_euid = rustix::process::geteuid().as_raw();
    if owner_uid != my_euid {
        return Err(HostError::IpcConnectFailed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{read_frame, write_frame};
    use interprocess::local_socket::{
        tokio::Listener as IpcListener, traits::tokio::Listener as _, ListenerOptions,
    };
    use tempfile::TempDir;
    use tokio::io::AsyncWriteExt;

    /// Spin up a one-shot fake desktop IPC server in a tempdir,
    /// connect from the host, round-trip a JSON-RPC envelope, and
    /// close cleanly.
    ///
    /// On Unix this uses a UDS at `tmpdir/native-host.sock`. On
    /// Windows it uses a namespaced pipe (the path-form ctor would
    /// also work, but the namespaced form is more idiomatic on
    /// Windows). For the hermetic test we use a unique
    /// per-pid + per-test pipe name.
    #[tokio::test]
    async fn round_trip_request_response_over_local_socket() {
        let tmp = TempDir::new().expect("tmp");
        #[cfg(unix)]
        let sock_path = tmp.path().join("test.sock");
        #[cfg(windows)]
        let sock_path = std::path::PathBuf::from(format!(
            r"\\.\pipe\pangolin-host-ipc-test-{}",
            std::process::id()
        ));
        // Silence the unused-variable warning on Windows where `tmp`
        // is unused once the path is synthesized. Same pattern as
        // `connect_to_missing_path_is_ipc_connect_failed` below. The
        // underscore-prefix form (`_tmp`) trips clippy's
        // `used_underscore_binding` lint on Linux (CI runner image
        // clippy 1.94.0, caught on 2026-05-26 MVP-4-F runs), so we
        // use a plain name + the reference self-drop.
        let _ = &tmp;

        // Bind the fake desktop side.
        let sock_path_for_bind = sock_path.clone();
        let listener: IpcListener = {
            let p = sock_path_for_bind.to_string_lossy().into_owned();
            let opts = if cfg!(windows) {
                let stripped = p.trim_start_matches(r"\\.\pipe\").to_string();
                let name = stripped.to_ns_name::<GenericNamespaced>().expect("ns name");
                ListenerOptions::new().name(name)
            } else {
                let name = p.as_str().to_fs_name::<GenericFilePath>().expect("fs name");
                ListenerOptions::new().name(name)
            };
            opts.create_tokio().expect("bind listener")
        };

        // Spawn the server side: accept, read one framed JSON-RPC
        // request, write a framed JSON-RPC response, drop.
        let server = tokio::spawn(async move {
            let conn = listener.accept().await.expect("server accept");
            let (mut r, mut w) = tokio::io::split(conn);
            let body = read_frame(&mut r).await.expect("server read");
            let req: serde_json::Value = serde_json::from_slice(&body).expect("server json");
            // Echo-style response: take the request's `id`, emit a
            // result with the method that was called.
            let resp = serde_json::json!({
                "jsonrpc": "2.0",
                "id": req["id"],
                "result": { "echoed_method": req["method"] }
            });
            let resp_bytes = serde_json::to_vec(&resp).expect("serialize resp");
            write_frame(&mut w, &resp_bytes)
                .await
                .expect("server write");
            w.shutdown().await.ok();
        });

        // Client side: the host's `connect`. We bypass
        // `verify_unix_socket_owner` here because tempdir-created
        // sockets are owned by the test runner anyway.
        let stream = connect(&sock_path).await.expect("client connect");
        let (mut r, mut w) = tokio::io::split(stream);

        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 42,
            "method": "session.status",
            "params": {}
        });
        let req_bytes = serde_json::to_vec(&req).expect("serialize req");
        write_frame(&mut w, &req_bytes).await.expect("client write");

        let resp_bytes = read_frame(&mut r).await.expect("client read");
        let resp: serde_json::Value = serde_json::from_slice(&resp_bytes).expect("parse resp");
        assert_eq!(resp["id"], 42);
        assert_eq!(resp["result"]["echoed_method"], "session.status");

        server.await.expect("server task");
    }

    /// Connecting to a non-existent path surfaces `IpcConnectFailed`.
    #[tokio::test]
    async fn connect_to_missing_path_is_ipc_connect_failed() {
        let tmp = TempDir::new().expect("tmp");
        #[cfg(unix)]
        let missing = tmp.path().join("does-not-exist.sock");
        #[cfg(windows)]
        let missing = std::path::PathBuf::from(format!(
            r"\\.\pipe\pangolin-host-ipc-missing-{}",
            std::process::id()
        ));
        // Silence the unused-variable warning on Windows where tmp
        // is unused once the path is synthesized.
        let _ = &tmp;
        let err = connect(&missing).await.expect_err("missing path rejected");
        assert!(matches!(err, HostError::IpcConnectFailed));
    }
}
