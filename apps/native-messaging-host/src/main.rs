// SPDX-License-Identifier: AGPL-3.0-or-later
//! Binary entry for `pangolin-native-messaging-host`.
//!
//! Chrome launches this binary as a subprocess when the extension
//! calls `chrome.runtime.connectNative('studio.kelvinsinferno.pangolin.host')`.
//! Lifecycle per plan §3.1:
//!
//! 1. Read first framed JSON-RPC frame from stdin.
//! 2. Validate it's an `auth.handshake` call carrying a base64url
//!    32-byte token.
//! 3. Load the expected token from the OS keychain (sibling-file
//!    fallback); constant-time compare.
//! 4. On success, write a `result` frame back to stdout AND open the
//!    IPC channel to the desktop process.
//! 5. From here on, relay JSON-RPC bytes transparently in both
//!    directions until either Chrome closes stdin or the desktop
//!    closes the IPC channel.
//! 6. On any error, write a typed JSON-RPC error frame back to stdout
//!    AND exit 1.
//!
//! The host has NO long-running state — every Chrome `connectNative`
//! call spawns a fresh process. All state lives in the desktop.

#![forbid(unsafe_code)]
#![deny(unused_must_use)]

use serde_json::{json, Value};
use tokio::io::{stdin, stdout, AsyncWriteExt};

use pangolin_native_messaging_host::auth::{load_expected_token, verify_token_b64};
use pangolin_native_messaging_host::error::HostError;
use pangolin_native_messaging_host::frame::{read_frame, write_frame};
use pangolin_native_messaging_host::ipc::connect as ipc_connect;
use pangolin_native_messaging_host::paths::ipc_channel_path;
use pangolin_native_messaging_host::{HOST_VERSION, PROTOCOL_VERSION};

fn main() {
    // Use a single-thread runtime — the host is a tiny I/O-bound
    // relay; the multi-threaded runtime would just add overhead per
    // Chrome subprocess spawn.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .expect("build tokio runtime");
    let exit_code = rt.block_on(run_host());
    std::process::exit(exit_code);
}

/// Async entry. Returns the process exit code.
async fn run_host() -> i32 {
    let mut stdin = stdin();
    let mut stdout = stdout();

    // Phase 1: handshake.
    match do_handshake(&mut stdin, &mut stdout).await {
        Ok(()) => {}
        Err(err) => {
            // Emit a typed error frame; exit 1.
            emit_error_frame(&mut stdout, None, &err).await;
            return 1;
        }
    }

    // Phase 2: open IPC to the desktop.
    let ipc_path = ipc_channel_path(None);
    let stream = match ipc_connect(&ipc_path).await {
        Ok(s) => s,
        Err(err) => {
            emit_error_frame(&mut stdout, None, &err).await;
            return 1;
        }
    };
    let (mut ipc_r, mut ipc_w) = tokio::io::split(stream);

    // Phase 3: bidirectional relay.
    //
    // Two tasks: stdin -> ipc, ipc -> stdout. They run concurrently
    // until either side EOFs. The first task that returns brings the
    // whole relay down (Chrome's subprocess discipline).
    let stdin_task = async {
        loop {
            match read_frame(&mut stdin).await {
                Ok(body) => {
                    write_frame(&mut ipc_w, &body).await?;
                }
                Err(HostError::FrameLengthRead) => {
                    // Clean EOF: Chrome closed stdin.
                    return Ok(());
                }
                Err(e) => return Err(e),
            }
        }
    };
    let ipc_task = async {
        loop {
            match read_frame(&mut ipc_r).await {
                Ok(body) => {
                    write_frame(&mut stdout, &body).await?;
                }
                Err(HostError::FrameLengthRead) => {
                    // Desktop closed the IPC channel.
                    return Ok(());
                }
                Err(e) => return Err(e),
            }
        }
    };

    let result = tokio::select! {
        r = stdin_task => r,
        r = ipc_task => r,
    };

    match result {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

/// Do the handshake exchange. Reads one frame, validates it's an
/// `auth.handshake`, loads the expected token, constant-time-compares,
/// and on success writes a `result` frame back.
async fn do_handshake<R, W>(stdin: &mut R, stdout: &mut W) -> Result<(), HostError>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let body = read_frame(stdin).await?;
    let req: Value = serde_json::from_slice(&body).map_err(|_| HostError::JsonParse)?;

    // Validate JSON-RPC envelope: `jsonrpc == "2.0"`, has `id`,
    // `method == "auth.handshake"`, `params.token` is a string.
    if req["jsonrpc"] != "2.0" {
        return Err(HostError::InvalidRequest("jsonrpc != 2.0"));
    }
    if req["id"].is_null() {
        return Err(HostError::InvalidRequest("missing id"));
    }
    if req["method"] != "auth.handshake" {
        return Err(HostError::InvalidRequest(
            "first method must be auth.handshake",
        ));
    }
    let presented = req["params"]["token"]
        .as_str()
        .ok_or(HostError::InvalidRequest("missing params.token"))?;

    let expected = load_expected_token(None)?;
    verify_token_b64(presented, &expected)?;

    // Success: emit a JSON-RPC result frame.
    let resp = json!({
        "jsonrpc": "2.0",
        "id": req["id"].clone(),
        "result": {
            "host_version": HOST_VERSION,
            "protocol_version": PROTOCOL_VERSION,
        }
    });
    let bytes =
        serde_json::to_vec(&resp).map_err(|_| HostError::Io("serialize handshake response"))?;
    write_frame(stdout, &bytes).await?;
    Ok(())
}

/// Emit a JSON-RPC error frame to stdout. `id` is `null` when we
/// don't have one yet (frame parse failures, etc.). Best-effort:
/// I/O failures here are dropped — the process is exiting anyway.
async fn emit_error_frame<W: tokio::io::AsyncWrite + Unpin>(
    stdout: &mut W,
    id: Option<Value>,
    err: &HostError,
) {
    let envelope = json!({
        "jsonrpc": "2.0",
        "id": id.unwrap_or(Value::Null),
        "error": err.to_jsonrpc_error(),
    });
    if let Ok(bytes) = serde_json::to_vec(&envelope) {
        let _ = write_frame(stdout, &bytes).await;
        let _ = stdout.flush().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use tokio::io::BufReader;

    /// `do_handshake` rejects a non-2.0 jsonrpc.
    #[tokio::test]
    async fn handshake_rejects_non_2_0_jsonrpc() {
        let req = serde_json::json!({
            "jsonrpc": "1.0",
            "id": 1,
            "method": "auth.handshake",
            "params": { "token": "x" }
        });
        let mut buf: Vec<u8> = Vec::new();
        let body = serde_json::to_vec(&req).unwrap();
        write_frame(&mut buf, &body).await.unwrap();
        let mut r = BufReader::new(Cursor::new(buf));
        let mut w: Vec<u8> = Vec::new();
        let err = do_handshake(&mut r, &mut w).await.expect_err("rejected");
        match err {
            HostError::InvalidRequest(msg) => assert!(msg.contains("jsonrpc")),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    /// `do_handshake` rejects a method that isn't auth.handshake.
    #[tokio::test]
    async fn handshake_rejects_wrong_method() {
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "session.status",
            "params": {}
        });
        let mut buf: Vec<u8> = Vec::new();
        let body = serde_json::to_vec(&req).unwrap();
        write_frame(&mut buf, &body).await.unwrap();
        let mut r = BufReader::new(Cursor::new(buf));
        let mut w: Vec<u8> = Vec::new();
        let err = do_handshake(&mut r, &mut w).await.expect_err("rejected");
        match err {
            HostError::InvalidRequest(msg) => assert!(msg.contains("auth.handshake")),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    /// `do_handshake` rejects a missing `params.token`.
    #[tokio::test]
    async fn handshake_rejects_missing_token() {
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "auth.handshake",
            "params": {}
        });
        let mut buf: Vec<u8> = Vec::new();
        let body = serde_json::to_vec(&req).unwrap();
        write_frame(&mut buf, &body).await.unwrap();
        let mut r = BufReader::new(Cursor::new(buf));
        let mut w: Vec<u8> = Vec::new();
        let err = do_handshake(&mut r, &mut w).await.expect_err("rejected");
        match err {
            HostError::InvalidRequest(msg) => assert!(msg.contains("token")),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    /// `emit_error_frame` produces a parseable JSON-RPC error
    /// envelope.
    #[tokio::test]
    async fn emit_error_frame_writes_jsonrpc_error_shape() {
        let mut w: Vec<u8> = Vec::new();
        emit_error_frame(&mut w, Some(serde_json::json!(7)), &HostError::AuthFailed).await;

        // The output is a framed JSON-RPC error.
        let mut r = BufReader::new(Cursor::new(w));
        let body = read_frame(&mut r).await.expect("read framed");
        let v: serde_json::Value = serde_json::from_slice(&body).expect("parse json");
        assert_eq!(v["jsonrpc"], "2.0");
        assert_eq!(v["id"], 7);
        assert_eq!(v["error"]["code"], -32001); // CODE_AUTH_FAILED
        assert_eq!(v["error"]["message"], "auth_failed");
    }
}
