//! Hand-written C-ABI surface, consumed by Tauri (and the future
//! browser-extension native messaging host in MVP-4).
//!
//! ## Why a hand-written shim
//!
//! `UniFFI` is the canonical source of truth for the FFI surface (Q3 of
//! issue 1.1). Tauri runs in-process Rust and could call the regular
//! `pangolin-core` API directly — but for parity with the iOS / Android
//! shells (which use `UniFFI`) and for the eventual native-messaging-host
//! bridge, a small `extern "C"` mirror is exposed here.
//!
//! `cbindgen` reads this module's `extern "C"` items and emits
//! `pangolin.h`. Run via:
//!
//! ```bash
//! cargo run -p pangolin-ffi --bin cbindgen-build --features cbindgen-cli
//! ```
//!
//! ## Drift discipline
//!
//! `tests/roundtrip.rs` walks every `UniFFI`-exported function and
//! asserts the C-ABI surface either mirrors it or is explicitly marked
//! "`UniFFI`-only" with a reason. Today the C-ABI surface is intentionally
//! tiny (`vault_open` + `vault_close`) so the drift surface is small;
//! 1.3 / 1.4 will grow it as the corresponding `UniFFI` exports stabilise.
//!
//! ## Memory-safety contract
//!
//! - The caller owns every `*const c_char` it passes in. The FFI does
//!   not free them.
//! - The FFI owns every `*mut PangolinVaultHandle` it returns. The
//!   caller MUST call `pangolin_vault_close` on every successfully
//!   opened handle to release the underlying `Arc`.
//! - Strings are NUL-terminated UTF-8; non-UTF-8 input returns
//!   `PANGOLIN_ERR_VALIDATION`.

use std::ffi::{c_char, CStr};
use std::ptr;
use std::sync::Arc;

use crate::session::VaultHandle;

/// Opaque handle for the C ABI.
///
/// The `[u8; 0]` zero-sized private field makes this a true opaque
/// type from the C side: cbindgen emits
/// `struct PangolinVaultHandle { uint8_t _private[0]; };`, callers
/// can only manipulate it through `*mut PangolinVaultHandle`
/// pointers, and the inner Rust state (an `Arc<VaultHandle>` cast to
/// a pointer) is not part of the public ABI.
#[repr(C)]
#[derive(Debug)]
pub struct PangolinVaultHandle {
    _private: [u8; 0],
}

/// FFI-side error codes mirroring [`crate::FfiError`]'s discriminants.
/// Numbered explicitly so adding variants in the future is additive
/// (never reorder).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum PangolinErrorCode {
    /// No error; the operation succeeded.
    PANGOLIN_OK = 0,
    /// Cryptographic failure.
    PANGOLIN_ERR_CRYPTO = 1,
    /// Storage-layer failure.
    PANGOLIN_ERR_STORE = 2,
    /// Session-state failure.
    PANGOLIN_ERR_SESSION = 3,
    /// Sync / chain-event failure.
    PANGOLIN_ERR_SYNC = 4,
    /// EVM chain failure.
    PANGOLIN_ERR_CHAIN = 5,
    /// Social-recovery failure.
    PANGOLIN_ERR_RECOVERY = 6,
    /// Caller-input validation failure (covers authentication-class
    /// collapse).
    PANGOLIN_ERR_VALIDATION = 7,
    /// Internal-state failure; should never happen in normal operation.
    PANGOLIN_ERR_INTERNAL = 8,
}

/// Open a vault file at `path_utf8`. Returns `PANGOLIN_OK` and stores
/// a handle into `*out_handle` on success; on failure stores `null` and
/// returns the error code.
///
/// # Safety
///
/// The caller MUST ensure:
/// - `path_utf8` is a valid pointer to a NUL-terminated UTF-8 string.
/// - `out_handle` is a valid pointer to writable memory of size
///   `sizeof(PangolinVaultHandle*)`.
/// - The returned handle is released with [`pangolin_vault_close`].
#[no_mangle]
pub unsafe extern "C" fn pangolin_vault_open(
    path_utf8: *const c_char,
    out_handle: *mut *mut PangolinVaultHandle,
) -> PangolinErrorCode {
    if path_utf8.is_null() || out_handle.is_null() {
        return PangolinErrorCode::PANGOLIN_ERR_VALIDATION;
    }
    // SAFETY: caller-supplied invariant — `path_utf8` is a valid
    // NUL-terminated UTF-8 string (documented above).
    let cstr = unsafe { CStr::from_ptr(path_utf8) };
    let Ok(_path) = cstr.to_str() else {
        // SAFETY: caller-supplied invariant — `out_handle` is writable.
        unsafe { *out_handle = ptr::null_mut() };
        return PangolinErrorCode::PANGOLIN_ERR_VALIDATION;
    };

    // Body lands in 1.3. For now the shim leaks an `Arc<VaultHandle>`
    // placeholder so the round-trip test can verify the close path.
    //
    // The opaque `*mut PangolinVaultHandle` returned to C is the raw
    // `Arc<VaultHandle>` pointer cast to the opaque type. The Rust
    // side reinterprets it back to `Arc::from_raw` in
    // `pangolin_vault_close`. The inner `Arc` layout is therefore an
    // implementation detail that is NOT part of the C ABI.
    let handle = VaultHandle::new_placeholder();
    let raw: *const VaultHandle = Arc::into_raw(handle);
    // SAFETY: caller-supplied invariant — `out_handle` is writable.
    unsafe { *out_handle = raw.cast::<PangolinVaultHandle>().cast_mut() };
    PangolinErrorCode::PANGOLIN_OK
}

/// Release a handle previously obtained from [`pangolin_vault_open`].
///
/// # Safety
///
/// The caller MUST ensure:
/// - `handle` was returned by `pangolin_vault_open` and has not been
///   passed to `pangolin_vault_close` already.
/// - No other thread is currently accessing the handle.
#[no_mangle]
pub unsafe extern "C" fn pangolin_vault_close(
    handle: *mut PangolinVaultHandle,
) -> PangolinErrorCode {
    if handle.is_null() {
        return PangolinErrorCode::PANGOLIN_ERR_VALIDATION;
    }
    // The opaque pointer is an `Arc<VaultHandle>` raw pointer in
    // disguise (see `pangolin_vault_open`). Cast back and let the
    // reconstructed `Arc` drop to release the underlying handle.
    let raw: *const VaultHandle = handle.cast::<VaultHandle>().cast_const();
    // SAFETY: caller-supplied invariant — `handle` was produced by
    // `pangolin_vault_open` (where the opaque pointer was the raw
    // result of `Arc::into_raw`) and has not been released elsewhere.
    let _ = unsafe { Arc::from_raw(raw) };
    PangolinErrorCode::PANGOLIN_OK
}

#[cfg(test)]
mod tests {
    use super::{
        pangolin_vault_close, pangolin_vault_open, PangolinErrorCode, PangolinVaultHandle,
    };
    use std::ffi::CString;
    use std::ptr;

    #[test]
    fn open_close_round_trip() {
        let path = CString::new("/tmp/does-not-matter.pvf").unwrap();
        let mut handle: *mut PangolinVaultHandle = ptr::null_mut();
        // SAFETY: pointer arguments are valid for the duration of the
        // call.
        let rc = unsafe { pangolin_vault_open(path.as_ptr(), &raw mut handle) };
        assert!(matches!(rc, PangolinErrorCode::PANGOLIN_OK));
        assert!(!handle.is_null());
        // SAFETY: handle was just produced by `pangolin_vault_open`.
        let rc = unsafe { pangolin_vault_close(handle) };
        assert!(matches!(rc, PangolinErrorCode::PANGOLIN_OK));
    }

    #[test]
    fn null_path_is_validation_error() {
        let mut handle: *mut PangolinVaultHandle = ptr::null_mut();
        // SAFETY: passing null is the documented sentinel; the function
        // refuses without dereferencing.
        let rc = unsafe { pangolin_vault_open(ptr::null(), &raw mut handle) };
        assert!(matches!(rc, PangolinErrorCode::PANGOLIN_ERR_VALIDATION));
        assert!(handle.is_null());
    }

    #[test]
    fn null_handle_close_is_validation_error() {
        // SAFETY: passing null is the documented sentinel.
        let rc = unsafe { pangolin_vault_close(ptr::null_mut()) };
        assert!(matches!(rc, PangolinErrorCode::PANGOLIN_ERR_VALIDATION));
    }
}
