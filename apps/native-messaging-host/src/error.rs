// SPDX-License-Identifier: AGPL-3.0-or-later
//! Typed `HostError` enum + JSON-RPC error-code mapping.
//!
//! Per MVP-4-E plan §1 + §6:
//!
//! - Every variant maps to a JSON-RPC error code via
//!   [`HostError::to_jsonrpc_error`].
//! - `data` is ALWAYS either `null` or a non-secret category string
//!   (L7). The handshake token is never embedded; raw bytes are never
//!   embedded.
//! - The variants cover the four primary failure surfaces the host
//!   hits: frame I/O (parse / oversize), auth (mismatch / load), IPC
//!   (connect / disconnect), and JSON-RPC validation (parse / unknown
//!   method).

#![forbid(unsafe_code)]

use serde_json::{json, Value};

/// JSON-RPC error code: invalid request envelope.
pub const CODE_INVALID_REQUEST: i32 = -32600;
/// JSON-RPC error code: method not found.
pub const CODE_METHOD_NOT_FOUND: i32 = -32601;
/// JSON-RPC error code: parse error.
pub const CODE_PARSE_ERROR: i32 = -32700;
/// Application-class: handshake token verification failed.
pub const CODE_AUTH_FAILED: i32 = -32001;
/// Application-class: IPC channel disconnected mid-session.
pub const CODE_IPC_DISCONNECT: i32 = -32002;
/// Application-class: vault is locked.
pub const CODE_SESSION_LOCKED: i32 = -32003;
/// Application-class: frame exceeds Chrome's 1 MB native-messaging
/// limit OR malformed length prefix.
pub const CODE_FRAME_INVALID: i32 = -32004;
/// Application-class: the OS keychain + sibling-file fallback both
/// failed to surface the handshake token.
pub const CODE_AUTH_LOAD_FAILED: i32 = -32005;
/// Application-class: IPC connect / setup failure (peer not running,
/// path missing, owner-EUID mismatch).
pub const CODE_IPC_CONNECT_FAILED: i32 = -32006;

/// Top-level host error.
///
/// Each variant maps to a JSON-RPC `{code, message, data}` envelope
/// via [`HostError::to_jsonrpc_error`]. The `Display` form is also a
/// non-secret category string suitable for log lines.
#[derive(Debug, thiserror::Error)]
pub enum HostError {
    /// 4-byte length prefix could not be read (EOF / short read).
    #[error("frame: failed to read length prefix")]
    FrameLengthRead,

    /// Frame body exceeded Chrome's 1 MB native-messaging limit.
    #[error("frame: body exceeded 1 MB limit ({0} bytes)")]
    FrameOversize(u32),

    /// Frame body could not be read in full.
    #[error("frame: failed to read body")]
    FrameBodyRead,

    /// Frame body was not valid UTF-8.
    #[error("frame: body is not valid UTF-8")]
    FrameNotUtf8,

    /// Frame body did not parse as JSON.
    #[error("parse: body is not valid JSON")]
    JsonParse,

    /// JSON-RPC envelope was missing a required field / had wrong type.
    #[error("invalid request: {0}")]
    InvalidRequest(&'static str),

    /// Handshake token verification failed (constant-time mismatch /
    /// empty / wrong length / wrong base64).
    #[error("auth: handshake token verification failed")]
    AuthFailed,

    /// Token loading from keychain AND sibling-file fallback failed.
    #[error("auth: failed to load handshake token from any source")]
    AuthLoadFailed,

    /// JSON-RPC method is not exposed to the extension.
    #[error("method not found: {0}")]
    MethodNotFound(String),

    /// IPC channel connect / setup failed.
    #[error("ipc: connect failed")]
    IpcConnectFailed,

    /// IPC channel disconnected after handshake.
    #[error("ipc: peer disconnected")]
    IpcDisconnect,

    /// Vault session is locked (re-route from desktop's typed error).
    #[error("session: vault is locked")]
    SessionLocked,

    /// I/O failure on stdin / stdout / IPC. The inner kind is a
    /// non-secret label.
    #[error("io: {0}")]
    Io(&'static str),
}

impl HostError {
    /// Map to the JSON-RPC error code.
    #[must_use]
    pub fn jsonrpc_code(&self) -> i32 {
        match self {
            Self::FrameLengthRead
            | Self::FrameOversize(_)
            | Self::FrameBodyRead
            | Self::FrameNotUtf8 => CODE_FRAME_INVALID,
            Self::JsonParse => CODE_PARSE_ERROR,
            Self::InvalidRequest(_) | Self::Io(_) => CODE_INVALID_REQUEST,
            Self::AuthFailed => CODE_AUTH_FAILED,
            Self::AuthLoadFailed => CODE_AUTH_LOAD_FAILED,
            Self::MethodNotFound(_) => CODE_METHOD_NOT_FOUND,
            Self::IpcConnectFailed => CODE_IPC_CONNECT_FAILED,
            Self::IpcDisconnect => CODE_IPC_DISCONNECT,
            Self::SessionLocked => CODE_SESSION_LOCKED,
        }
    }

    /// JSON-RPC short message slot. Category strings only — never
    /// embeds secret material (L7).
    #[must_use]
    pub fn jsonrpc_message(&self) -> &'static str {
        match self {
            Self::FrameLengthRead
            | Self::FrameOversize(_)
            | Self::FrameBodyRead
            | Self::FrameNotUtf8 => "frame_invalid",
            Self::JsonParse => "parse_error",
            Self::InvalidRequest(_) => "invalid_request",
            Self::AuthFailed => "auth_failed",
            Self::AuthLoadFailed => "auth_load_failed",
            Self::MethodNotFound(_) => "method_not_found",
            Self::IpcConnectFailed => "ipc_connect_failed",
            Self::IpcDisconnect => "ipc_disconnect",
            Self::SessionLocked => "session_locked",
            Self::Io(_) => "io_error",
        }
    }

    /// Render to a JSON-RPC `{code, message, data}` value.
    ///
    /// `data` is intentionally `null` for every variant; the rich
    /// `Display` form goes only to local logs, never to the wire. L7
    /// invariant: the response that crosses to the extension carries
    /// no operational detail beyond the category string.
    #[must_use]
    pub fn to_jsonrpc_error(&self) -> Value {
        json!({
            "code": self.jsonrpc_code(),
            "message": self.jsonrpc_message(),
            "data": Value::Null,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each variant's `code` field matches the documented JSON-RPC
    /// constant.
    #[test]
    fn jsonrpc_codes_are_stable() {
        assert_eq!(
            HostError::FrameOversize(2 * 1024 * 1024).jsonrpc_code(),
            CODE_FRAME_INVALID
        );
        assert_eq!(HostError::JsonParse.jsonrpc_code(), CODE_PARSE_ERROR);
        assert_eq!(
            HostError::InvalidRequest("no id").jsonrpc_code(),
            CODE_INVALID_REQUEST
        );
        assert_eq!(HostError::AuthFailed.jsonrpc_code(), CODE_AUTH_FAILED);
        assert_eq!(
            HostError::AuthLoadFailed.jsonrpc_code(),
            CODE_AUTH_LOAD_FAILED
        );
        assert_eq!(
            HostError::MethodNotFound("x".into()).jsonrpc_code(),
            CODE_METHOD_NOT_FOUND
        );
        assert_eq!(
            HostError::IpcConnectFailed.jsonrpc_code(),
            CODE_IPC_CONNECT_FAILED
        );
        assert_eq!(HostError::IpcDisconnect.jsonrpc_code(), CODE_IPC_DISCONNECT);
        assert_eq!(HostError::SessionLocked.jsonrpc_code(), CODE_SESSION_LOCKED);
    }

    /// Each variant produces a `{code, message, data}` shape with
    /// `data == null` — no leaked secret bytes can reach the wire.
    #[test]
    fn jsonrpc_data_is_always_null() {
        let cases = [
            HostError::FrameLengthRead,
            HostError::FrameOversize(u32::MAX),
            HostError::FrameBodyRead,
            HostError::FrameNotUtf8,
            HostError::JsonParse,
            HostError::InvalidRequest("oops"),
            HostError::AuthFailed,
            HostError::AuthLoadFailed,
            HostError::MethodNotFound("evil.method".into()),
            HostError::IpcConnectFailed,
            HostError::IpcDisconnect,
            HostError::SessionLocked,
            HostError::Io("stdin"),
        ];
        for err in &cases {
            let v = err.to_jsonrpc_error();
            assert_eq!(v["data"], Value::Null);
            assert!(v["code"].is_i64());
            assert!(v["message"].is_string());
        }
    }

    /// L7: a `MethodNotFound("vault.copy_password id=secret")`-style
    /// payload would leak data through `Display`; the JSON-RPC `message`
    /// must stay a fixed category label, not the inner string.
    #[test]
    fn method_not_found_jsonrpc_message_is_a_category_label() {
        let err = HostError::MethodNotFound("anything_we_dont_want_on_the_wire".into());
        let v = err.to_jsonrpc_error();
        assert_eq!(v["message"], "method_not_found");
    }
}
