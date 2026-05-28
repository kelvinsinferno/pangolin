// SPDX-License-Identifier: AGPL-3.0-or-later
//! JSON-RPC method dispatch for the desktop's IPC server.
//!
//! See MVP-4-E plan §1 (Desktop-side IPC server) for the four
//! exposed methods. The dispatch logic mirrors what each
//! `#[tauri::command]` body does, but does NOT route through the
//! Tauri runtime — the IPC server holds a plain `Arc<VaultState>` so
//! the FFI calls happen on the IPC task directly. This keeps the
//! desktop's Tauri runtime out of the per-request fast path and means
//! the host can talk to the desktop without the React UI being open.
//!
//! ## L1 carve-out (security-load-bearing)
//!
//! `vault.copy_password` writes the plaintext directly to the OS
//! clipboard from Rust; the extension only ever sees `{ "result":
//! null }` on success. The plaintext NEVER crosses the IPC channel —
//! the H-1 carve-out from MVP-4-B applies verbatim.
//!
//! `vault.reveal_password` is DELIBERATELY NOT exposed. The extension
//! never holds password plaintext; if the user wants to see the
//! password, they open the desktop UI's account-detail screen
//! (MVP-4-F surface), not the extension popup.
//!
//! ## L7 — errors carry no secret material
//!
//! Every error path collapses the underlying `DesktopError` /
//! `FfiError` into a category code + label. Concrete details (vault
//! file path, account ID, password byte) NEVER reach the wire.

#![forbid(unsafe_code)]

use std::sync::Arc;

use serde_json::{json, Value};
use tauri::Manager;
use tauri_plugin_clipboard_manager::ClipboardExt;

use crate::commands::account::{
    account_id_from_hex_for_ipc, account_show_inner, accounts_list_inner, copy_password_via,
};
use crate::error::DesktopError;
use crate::state::VaultState;

/// JSON-RPC error codes (mirror `pangolin_native_messaging_host::error`).
const CODE_INVALID_REQUEST: i32 = -32600;
const CODE_METHOD_NOT_FOUND: i32 = -32601;
const CODE_PARSE_ERROR: i32 = -32700;
const CODE_SESSION_LOCKED: i32 = -32003;
const CODE_INTERNAL_ERROR: i32 = -32000;
const CODE_VALIDATION_FAILED: i32 = -32011;
const CODE_STORE_ERROR: i32 = -32012;
const CODE_CRYPTO_ERROR: i32 = -32013;
const CODE_AUTH_FAILED: i32 = -32001;

/// Production entry: dispatches using the live Tauri `AppHandle`.
///
/// The handle gives the dispatch access to:
///
/// - the managed `VaultState` (via `app.state::<VaultState>()`),
/// - the OS clipboard (via `app.clipboard().write_text(...)`).
pub async fn handle_request_with_app(app: &tauri::AppHandle, body: &[u8]) -> Vec<u8> {
    let state = app.state::<VaultState>();
    let clipboard_writer: Box<dyn Fn(String) -> Result<(), DesktopError> + Send + Sync> = {
        let app = app.clone();
        Box::new(move |s: String| {
            app.clipboard()
                .write_text(s)
                .map_err(|e| DesktopError::Internal(format!("clipboard write failed: {e}")))
        })
    };
    handle_request_inner(state.inner(), Some(&clipboard_writer), body).await
}

/// Test entry: dispatches against a raw [`Arc<VaultState>`].
///
/// The `vault.copy_password` path uses a no-op clipboard writer
/// (which still validates auth + session + id, so the typed-error
/// contract is exercised). Production callers must go through
/// [`handle_request_with_app`] instead so the real OS clipboard
/// participates in the L1 H-1 carve-out.
pub async fn handle_request(state: &Arc<VaultState>, body: &[u8]) -> Vec<u8> {
    handle_request_inner(state, None, body).await
}

type ClipboardFn = dyn Fn(String) -> Result<(), DesktopError> + Send + Sync;

async fn handle_request_inner(
    state: &VaultState,
    clipboard: Option<&ClipboardFn>,
    body: &[u8],
) -> Vec<u8> {
    let req: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => {
            return error_response(&Value::Null, CODE_PARSE_ERROR, "parse_error");
        }
    };

    let id = req.get("id").cloned().unwrap_or(Value::Null);

    if req.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return error_response(&id, CODE_INVALID_REQUEST, "invalid_request");
    }
    let Some(method) = req.get("method").and_then(Value::as_str) else {
        return error_response(&id, CODE_INVALID_REQUEST, "invalid_request");
    };
    let params = req.get("params").cloned().unwrap_or(Value::Null);

    let result: Result<Value, DesktopError> = match method {
        "session.status" => Ok(session_status_value(state)),
        "vault.list_accounts" => vault_list_accounts(state).await,
        "vault.account_show" => vault_account_show(state, &params).await,
        "vault.copy_password" => vault_copy_password(state, clipboard, &params).await,
        // Explicitly NOT exposed (plan §1): reveal_password,
        // autofill methods, etc. Treat as method_not_found.
        _ => {
            return error_response(&id, CODE_METHOD_NOT_FOUND, "method_not_found");
        }
    };

    match result {
        Ok(value) => success_response(&id, &value),
        Err(de) => {
            let (code, label) = map_desktop_error(&de);
            error_response(&id, code, label)
        }
    }
}

fn session_status_value(state: &VaultState) -> Value {
    // L4 — `is_open` is the cheapest possible read. There's no
    // `is_unlocked` separately tracked on the host side this slice
    // because the FFI's `session_status` requires a handle, and we
    // don't want to expose an unlocked-vs-locked oracle to the
    // popup until the lock UI exists (deferred to MVP-4-G).
    let open = state.is_open();
    // For unlock-state probing, we attempt `require_open()` and
    // call `session_status` if we have a handle. A failure is
    // treated as "not unlocked" rather than propagating an error to
    // the popup; the popup just wants to know whether the desktop
    // is reachable + unlocked, NOT what the failure mode is.
    let unlocked = if open {
        state
            .require_open()
            .is_ok_and(|handle| pangolin_ffi::session::session_status(handle).is_active)
    } else {
        false
    };
    json!({ "vault_open": open, "vault_unlocked": unlocked })
}

async fn vault_list_accounts(state: &VaultState) -> Result<Value, DesktopError> {
    let dtos = accounts_list_inner(state).await?;
    Ok(serde_json::to_value(dtos).unwrap_or(Value::Null))
}

async fn vault_account_show(state: &VaultState, params: &Value) -> Result<Value, DesktopError> {
    let id = params
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| DesktopError::Validation {
            kind: "params".into(),
            message: "missing string `id`".into(),
        })?;
    let dto = account_show_inner(state, id.to_string()).await?;
    Ok(serde_json::to_value(dto).unwrap_or(Value::Null))
}

async fn vault_copy_password(
    state: &VaultState,
    clipboard: Option<&ClipboardFn>,
    params: &Value,
) -> Result<Value, DesktopError> {
    // MVP-4-G: feature-gated invocation log so the Puppeteer-driven
    // extension-e2e suite can assert that the Rust-side clipboard
    // path fired when the popup-side vault.copy_password request
    // arrives over the native-messaging channel. Mirrors the same
    // record() call inside the production Tauri command body so
    // both suites see the same canonical name. L7 -- records the
    // command NAME only.
    #[cfg(feature = "test-hooks")]
    crate::test_hooks::record("copy_password_to_clipboard");

    let id = params
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| DesktopError::Validation {
            kind: "params".into(),
            message: "missing string `id`".into(),
        })?;
    // Validate the id format up-front so a malformed id surfaces a
    // typed Validation error before the FFI call.
    let _account_id = account_id_from_hex_for_ipc(id)?;
    // Run the reveal + clipboard-write Rust-side. When `clipboard`
    // is `None` (test path), the closure is a no-op — the reveal
    // contract is still exercised; only the final OS-clipboard hop
    // is skipped.
    copy_password_via(state, id.to_string(), |s| {
        clipboard.map_or(Ok(()), |cb| cb(s))
    })
    .await?;
    // L1: plaintext stays Rust-side. Wire result is `null`.
    Ok(Value::Null)
}

/// Map `DesktopError` to a JSON-RPC code + label. The category
/// labels mirror the host-side `HostError::jsonrpc_message` strings
/// so the popup's typed-error UI sees a stable shape regardless of
/// which side surfaced the failure.
fn map_desktop_error(de: &DesktopError) -> (i32, &'static str) {
    match de {
        DesktopError::Session(_) => (CODE_SESSION_LOCKED, "session_locked"),
        DesktopError::Validation { .. } => (CODE_VALIDATION_FAILED, "validation_failed"),
        DesktopError::Chain(_) => (CODE_INTERNAL_ERROR, "chain_error"),
        DesktopError::Store(_) => (CODE_STORE_ERROR, "store_error"),
        DesktopError::Recovery(_) => (CODE_INTERNAL_ERROR, "recovery_error"),
        DesktopError::Sync(_) => (CODE_INTERNAL_ERROR, "sync_error"),
        DesktopError::Crypto(_) => (CODE_CRYPTO_ERROR, "crypto_error"),
        DesktopError::Internal(_) => (CODE_INTERNAL_ERROR, "internal_error"),
        DesktopError::AuthenticationFailed => (CODE_AUTH_FAILED, "authentication_failed"),
    }
}

fn success_response(id: &Value, result: &Value) -> Vec<u8> {
    let envelope = json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result,
    });
    serde_json::to_vec(&envelope).expect("serde_json::to_vec on Value never fails")
}

fn error_response(id: &Value, code: i32, label: &str) -> Vec<u8> {
    let envelope = json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": label,
            "data": Value::Null,
        }
    });
    serde_json::to_vec(&envelope).expect("serde_json::to_vec on Value never fails")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// Helper: build a fresh state and run one request through
    /// `handle_request`, parsing the response.
    async fn invoke(req: Value) -> Value {
        let state = Arc::new(VaultState::default());
        let body = serde_json::to_vec(&req).unwrap();
        let resp = handle_request(&state, &body).await;
        serde_json::from_slice(&resp).unwrap()
    }

    #[tokio::test]
    async fn unknown_method_is_method_not_found() {
        let req = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "totally.invented",
            "params": {}
        });
        let v = invoke(req).await;
        assert_eq!(v["error"]["code"], CODE_METHOD_NOT_FOUND);
        assert_eq!(v["error"]["message"], "method_not_found");
    }

    /// Plan §1 last bullet: `reveal_password` is explicitly NOT
    /// exposed. Asserting `method_not_found` is the load-bearing
    /// audit pin.
    #[tokio::test]
    async fn reveal_password_is_explicitly_not_exposed() {
        let req = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "vault.reveal_password",
            "params": { "id": "a".repeat(64) }
        });
        let v = invoke(req).await;
        assert_eq!(v["error"]["code"], CODE_METHOD_NOT_FOUND);
    }

    #[tokio::test]
    async fn malformed_json_is_parse_error() {
        let state = Arc::new(VaultState::default());
        let resp = handle_request(&state, b"not json at all {{").await;
        let v: Value = serde_json::from_slice(&resp).unwrap();
        assert_eq!(v["error"]["code"], CODE_PARSE_ERROR);
        assert_eq!(v["error"]["message"], "parse_error");
        assert_eq!(v["id"], Value::Null);
    }

    #[tokio::test]
    async fn missing_jsonrpc_field_is_invalid_request() {
        let req = json!({
            "id": 1,
            "method": "session.status",
            "params": {}
        });
        let v = invoke(req).await;
        assert_eq!(v["error"]["code"], CODE_INVALID_REQUEST);
    }

    #[tokio::test]
    async fn missing_method_field_is_invalid_request() {
        let req = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "params": {}
        });
        let v = invoke(req).await;
        assert_eq!(v["error"]["code"], CODE_INVALID_REQUEST);
    }

    /// session.status against a closed-vault state returns
    /// `{ vault_open: false, vault_unlocked: false }` — the popup's
    /// "Desktop not connected" treatment will see this and offer the
    /// "Open vault" CTA.
    #[tokio::test]
    async fn session_status_when_closed_returns_both_false() {
        let req = json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "session.status",
            "params": {}
        });
        let v = invoke(req).await;
        assert_eq!(v["id"], 5);
        assert_eq!(v["result"]["vault_open"], false);
        assert_eq!(v["result"]["vault_unlocked"], false);
    }

    /// `list_accounts` against a closed vault errors with
    /// `session_locked` (the `require_open()` guard collapses to a
    /// `Session` `DesktopError`).
    #[tokio::test]
    async fn list_accounts_closed_vault_is_session_locked() {
        let req = json!({
            "jsonrpc": "2.0",
            "id": 9,
            "method": "vault.list_accounts",
            "params": {}
        });
        let v = invoke(req).await;
        assert_eq!(v["error"]["code"], CODE_SESSION_LOCKED);
        assert_eq!(v["error"]["message"], "session_locked");
    }

    /// `account_show` with a missing `id` is a validation error.
    #[tokio::test]
    async fn account_show_missing_id_is_validation_failed() {
        let req = json!({
            "jsonrpc": "2.0",
            "id": 11,
            "method": "vault.account_show",
            "params": {}
        });
        let v = invoke(req).await;
        assert_eq!(v["error"]["code"], CODE_VALIDATION_FAILED);
        assert_eq!(v["error"]["message"], "validation_failed");
    }

    /// `copy_password` with a malformed `id` is a validation error
    /// BEFORE the FFI call. (The id-format check fires first, even
    /// before the vault-open check.)
    #[tokio::test]
    async fn copy_password_malformed_id_is_validation_failed() {
        let req = json!({
            "jsonrpc": "2.0",
            "id": 13,
            "method": "vault.copy_password",
            "params": { "id": "not-hex" }
        });
        let v = invoke(req).await;
        assert_eq!(v["error"]["code"], CODE_VALIDATION_FAILED);
    }

    /// L7: error responses carry `data: null`. No secret material.
    #[tokio::test]
    async fn error_responses_have_null_data() {
        let req = json!({
            "jsonrpc": "2.0",
            "id": 17,
            "method": "vault.list_accounts",
            "params": {}
        });
        let v = invoke(req).await;
        assert!(v["error"]["data"].is_null());
    }
}
