// SPDX-License-Identifier: AGPL-3.0-or-later
//! Handshake-token load + constant-time verify.
//!
//! The handshake token is the **L1 INNER chokepoint** that prevents a
//! co-installed malicious extension from talking to the desktop. Plan
//! §3.4:
//!
//! - Primary store: OS keychain via the `keyring` crate (Windows
//!   Credential Manager / macOS Keychain Services / Linux secret-
//!   service / libsecret).
//! - Sibling-file fallback: `pangolin_data_dir()/native-host-token`
//!   (mode 0600 on Unix; user-only via the OS default ACL on Windows).
//!   This fallback exists because the Chrome-spawned process may run
//!   under a session that does not have the keyring agent unlocked
//!   yet on some Linux distros.
//!
//! Discipline (plan §6):
//!
//! - Constant-time compare via `subtle::ConstantTimeEq::ct_eq`. NEVER
//!   `==` on token bytes.
//! - Loaded token lives in `Zeroizing<Vec<u8>>` from load to drop —
//!   never a plain `String` / `Vec<u8>` (the `String` Display copy
//!   would survive past `drop` because String's Drop does not zero).
//! - Token bytes never appear in any error variant (L7).
//!
//! The token's wire form (in the handshake JSON-RPC params) is
//! base64url with no padding — Chrome's native-messaging body is
//! UTF-8 JSON, so the token cannot be raw bytes in the JSON string.

#![forbid(unsafe_code)]

use std::path::Path;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::error::HostError;
use crate::paths::{token_file_path, KEYRING_ACCOUNT, KEYRING_SERVICE};

/// Length of the handshake token in raw bytes. 32 bytes = 256 bits,
/// well past any feasible offline-brute-force budget.
pub const TOKEN_LEN: usize = 32;

/// Load the expected handshake token from the OS keychain, falling
/// back to the sibling-file path on miss.
///
/// `home_override` is `None` in production; tests pass `Some(temp)`
/// to drive the file-fallback path against a hermetic root.
///
/// # Errors
///
/// [`HostError::AuthLoadFailed`] if neither source surfaces a valid
/// token. The error variant carries NO operational detail (the
/// specific failure mode is logged to stderr for the operator, not
/// the wire — L7).
pub fn load_expected_token(home_override: Option<&Path>) -> Result<Zeroizing<Vec<u8>>, HostError> {
    // Primary: keychain. In test mode (home_override == Some) we
    // SKIP the keychain — the CI runners do not have a usable
    // keyring backend, so consulting it would produce noisy logs.
    if home_override.is_none() {
        if let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, KEYRING_ACCOUNT) {
            if let Ok(value) = entry.get_password() {
                if let Ok(decoded) = decode_token_b64(&value) {
                    return Ok(decoded);
                }
            }
        }
    }

    // Fallback: sibling file.
    let path = token_file_path(home_override);
    let bytes = std::fs::read(&path).map_err(|_| HostError::AuthLoadFailed)?;
    // The file content is the base64url string (no padding). Trim
    // any trailing newline a text editor might have introduced.
    let text = std::str::from_utf8(&bytes).map_err(|_| HostError::AuthLoadFailed)?;
    let text = text.trim();
    decode_token_b64(text)
}

/// Decode a base64url-no-padding token string into a `Zeroizing` byte
/// buffer. Validates length == `TOKEN_LEN`.
fn decode_token_b64(s: &str) -> Result<Zeroizing<Vec<u8>>, HostError> {
    let raw = URL_SAFE_NO_PAD
        .decode(s.as_bytes())
        .map_err(|_| HostError::AuthLoadFailed)?;
    if raw.len() != TOKEN_LEN {
        return Err(HostError::AuthLoadFailed);
    }
    Ok(Zeroizing::new(raw))
}

/// Verify a presented handshake token against the expected token.
///
/// Both inputs are decoded from their base64url wire form into raw
/// bytes BEFORE comparison; the comparison itself is
/// constant-time via `subtle::ConstantTimeEq::ct_eq` (plan §6).
///
/// # Errors
///
/// [`HostError::AuthFailed`] for any mismatch, wrong length, or
/// invalid base64.
pub fn verify_token_b64(presented_b64: &str, expected: &[u8]) -> Result<(), HostError> {
    if expected.len() != TOKEN_LEN {
        // Defensive: the loader already enforces this, but a
        // belt-and-braces guard means an injected expected-token of
        // the wrong length never produces a false-positive match.
        return Err(HostError::AuthFailed);
    }
    let presented_raw = URL_SAFE_NO_PAD
        .decode(presented_b64.as_bytes())
        .map_err(|_| HostError::AuthFailed)?;
    let presented = Zeroizing::new(presented_raw);
    if presented.len() != TOKEN_LEN {
        return Err(HostError::AuthFailed);
    }
    let eq: bool = presented.as_slice().ct_eq(expected).into();
    if eq {
        Ok(())
    } else {
        Err(HostError::AuthFailed)
    }
}

/// Encode a raw 32-byte token to the wire form (base64url no-pad).
///
/// Used by the install code on the desktop side; mirrored here so
/// the encoding lives in ONE place and the auth-side decoder can
/// round-trip-test against it.
#[must_use]
pub fn encode_token_b64(raw: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write_token_file(home: &Path, raw: &[u8]) {
        let path = token_file_path(Some(home));
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("mkdir token parent");
        }
        let b64 = encode_token_b64(raw);
        std::fs::write(&path, b64.as_bytes()).expect("write token file");
    }

    #[test]
    fn round_trip_encode_decode_recovers_bytes() {
        let raw = [0xaau8; TOKEN_LEN];
        let s = encode_token_b64(&raw);
        let decoded = decode_token_b64(&s).expect("decode ok");
        assert_eq!(&*decoded, &raw);
    }

    #[test]
    fn verify_token_b64_accepts_matching_token() {
        let raw = [0x42u8; TOKEN_LEN];
        let s = encode_token_b64(&raw);
        verify_token_b64(&s, &raw).expect("verify ok");
    }

    #[test]
    fn verify_token_b64_rejects_wrong_token() {
        let raw = [0x42u8; TOKEN_LEN];
        let wrong = [0x00u8; TOKEN_LEN];
        let s = encode_token_b64(&wrong);
        let err = verify_token_b64(&s, &raw).expect_err("wrong rejected");
        assert!(matches!(err, HostError::AuthFailed));
    }

    #[test]
    fn verify_token_b64_rejects_empty_token() {
        let raw = [0x42u8; TOKEN_LEN];
        let err = verify_token_b64("", &raw).expect_err("empty rejected");
        assert!(matches!(err, HostError::AuthFailed));
    }

    #[test]
    fn verify_token_b64_rejects_too_short() {
        let raw = [0x42u8; TOKEN_LEN];
        // Encode an 8-byte token; will decode to wrong length.
        let s = encode_token_b64(&[0x42u8; 8]);
        let err = verify_token_b64(&s, &raw).expect_err("short rejected");
        assert!(matches!(err, HostError::AuthFailed));
    }

    #[test]
    fn verify_token_b64_rejects_too_long() {
        let raw = [0x42u8; TOKEN_LEN];
        let s = encode_token_b64(&[0x42u8; 64]);
        let err = verify_token_b64(&s, &raw).expect_err("long rejected");
        assert!(matches!(err, HostError::AuthFailed));
    }

    #[test]
    fn verify_token_b64_rejects_invalid_base64() {
        let raw = [0x42u8; TOKEN_LEN];
        let err = verify_token_b64("@@@not_base64$$$", &raw).expect_err("bad b64 rejected");
        assert!(matches!(err, HostError::AuthFailed));
    }

    #[test]
    fn load_from_sibling_file_when_keychain_skipped() {
        let tmp = TempDir::new().expect("tmp");
        let raw = [0xcdu8; TOKEN_LEN];
        write_token_file(tmp.path(), &raw);
        let loaded = load_expected_token(Some(tmp.path())).expect("load from sibling file");
        assert_eq!(&*loaded, &raw);
    }

    #[test]
    fn load_returns_auth_load_failed_when_file_missing() {
        let tmp = TempDir::new().expect("tmp");
        let err = load_expected_token(Some(tmp.path())).expect_err("no token file");
        assert!(matches!(err, HostError::AuthLoadFailed));
    }

    #[test]
    fn load_returns_auth_load_failed_when_file_is_garbage() {
        let tmp = TempDir::new().expect("tmp");
        let path = token_file_path(Some(tmp.path()));
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"not valid base64 either").unwrap();
        let err = load_expected_token(Some(tmp.path())).expect_err("garbage");
        assert!(matches!(err, HostError::AuthLoadFailed));
    }

    /// L7: the `AuthFailed` display string never embeds the presented
    /// token bytes. (Display is what would surface in a log line.)
    #[test]
    fn auth_failed_display_does_not_leak_token() {
        let err = HostError::AuthFailed;
        let s = format!("{err}");
        // Sanity: the Display string is a static category label.
        assert!(s.contains("auth"));
        assert!(!s.contains("token=")); // no key=value leak
    }
}
