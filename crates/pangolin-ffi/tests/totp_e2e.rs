// SPDX-License-Identifier: AGPL-3.0-or-later
//! MVP-1 issue 1.7 — `totp_generate` end-to-end integration tests over
//! the FFI surface, plus the `MAX_SECRET_BYTES ↔ TOTP_SECRET_MAX_BYTES`
//! cross-check and the `parse_totp_secret` helper.
//!
//! `totp_generate` is session-class: an unlocked, non-expired vault is
//! enough — no presence proof. The seed never crosses FFI; only the
//! digit string does. These tests set the seed via `account_update`
//! (whose `totp_params` field carries the algorithm/digits/period) and
//! confirm the RFC 6238 Appendix B vectors come back exactly.

use std::sync::Arc;

use pangolin_core::{PinIdentityProof, PressYPresenceProof, Vault};
use pangolin_crypto::secret::SecretBytes;
use pangolin_ffi::identity::{account_add, account_update};
use pangolin_ffi::session::vault_lock;
use pangolin_ffi::totp::{parse_totp_secret, totp_generate, TotpAlgorithm, TotpParamsFfi};
use pangolin_ffi::{AccountDraft, AccountPatch, FfiError, SecretPassword, TotpSecret, VaultHandle};
use tempfile::TempDir;

fn fresh_handle() -> (TempDir, Arc<VaultHandle>) {
    let tmp = TempDir::new().expect("tempdir");
    let path = tmp.path().join("totp.pvf");
    let pwd = SecretBytes::new(b"correct horse battery staple".to_vec());
    Vault::create(&path, &pwd).expect("create");
    let mut v = Vault::open(&path).expect("open");
    v.unlock(
        &PressYPresenceProof::confirmed(),
        &PinIdentityProof::new(SecretBytes::new(b"correct horse battery staple".to_vec())),
    )
    .expect("unlock");
    (tmp, VaultHandle::from_vault(v))
}

fn draft(display: &str) -> AccountDraft {
    AccountDraft {
        schema_version: 1,
        display_name: display.into(),
        tags: vec![],
        usernames: vec!["a@b.c".into()],
        urls: vec![],
        notes: None,
        current_password: SecretPassword::new(b"hunter2".to_vec()),
        totp_secret: None,
        totp_params: None,
    }
}

fn set_totp(
    handle: &Arc<VaultHandle>,
    id: &pangolin_ffi::AccountId,
    seed: &[u8],
    params: Option<TotpParamsFfi>,
) {
    let patch = AccountPatch {
        schema_version: 1,
        display_name: None,
        tags: None,
        usernames: None,
        urls: None,
        notes: None,
        current_password: None,
        totp_secret: Some(Some(TotpSecret::new(seed.to_vec()))),
        totp_params: params,
    };
    account_update(handle.clone(), id.clone(), patch).expect("account_update");
}

fn params(alg: TotpAlgorithm, digits: u8) -> TotpParamsFfi {
    TotpParamsFfi {
        schema_version: 1,
        algorithm: alg,
        digits,
        period_seconds: 30,
    }
}

// RFC 6238 Appendix B secrets.
const SECRET_SHA1: &[u8] = b"12345678901234567890";
const SECRET_SHA256: &[u8] = b"12345678901234567890123456789012";

#[test]
fn totp_generate_rfc6238_sha1_8digit() {
    let (_tmp, handle) = fresh_handle();
    let id = account_add(handle.clone(), draft("acct")).expect("add");
    set_totp(&handle, &id, SECRET_SHA1, Some(params(TotpAlgorithm::Sha1, 8)));
    // RFC 6238 SHA-1 @ T=59 → counter 1 → 8-digit 94287082.
    let code = totp_generate(handle.clone(), id.clone(), 59).expect("totp_generate");
    assert_eq!(code.code, "94287082");
    assert_eq!(code.seconds_remaining, 30 - (59 % 30)); // == 1
    // @ T=1111111109 → 07081804.
    let c2 = totp_generate(handle.clone(), id.clone(), 1_111_111_109).expect("ok");
    assert_eq!(c2.code, "07081804");
}

#[test]
fn totp_generate_rfc6238_sha256_8digit() {
    let (_tmp, handle) = fresh_handle();
    let id = account_add(handle.clone(), draft("acct")).expect("add");
    set_totp(&handle, &id, SECRET_SHA256, Some(params(TotpAlgorithm::Sha256, 8)));
    // RFC 6238 SHA-256 @ T=59 → 46119246.
    let code = totp_generate(handle.clone(), id.clone(), 59).expect("ok");
    assert_eq!(code.code, "46119246");
}

#[test]
fn totp_generate_default_params_6digit_and_window_boundary() {
    let (_tmp, handle) = fresh_handle();
    let id = account_add(handle.clone(), draft("acct")).expect("add");
    // Default params (SHA-1 / 6 / 30): @ T=59 → 287082 (last 6 of 94287082).
    set_totp(&handle, &id, SECRET_SHA1, None);
    let c59 = totp_generate(handle.clone(), id.clone(), 59).expect("ok");
    assert_eq!(c59.code, "287082");
    // Window boundary: 29 and 0 share window 0; 30 is window 1.
    let c0 = totp_generate(handle.clone(), id.clone(), 0).expect("ok");
    let c29 = totp_generate(handle.clone(), id.clone(), 29).expect("ok");
    let c30 = totp_generate(handle.clone(), id.clone(), 30).expect("ok");
    assert_eq!(c0.code, c29.code);
    assert_ne!(c0.code, c30.code);
    assert_eq!(c0.seconds_remaining, 30);
}

#[test]
fn totp_generate_seven_digit() {
    let (_tmp, handle) = fresh_handle();
    let id = account_add(handle.clone(), draft("acct")).expect("add");
    set_totp(&handle, &id, SECRET_SHA1, Some(params(TotpAlgorithm::Sha1, 7)));
    // 7-digit @ T=59 → last 7 of 94287082 → 4287082.
    let c = totp_generate(handle.clone(), id.clone(), 59).expect("ok");
    assert_eq!(c.code, "4287082");
}

#[test]
fn totp_generate_no_totp_errors_cleanly() {
    let (_tmp, handle) = fresh_handle();
    let id = account_add(handle.clone(), draft("acct")).expect("add");
    match totp_generate(handle.clone(), id.clone(), 59) {
        Err(FfiError::Validation { kind, .. }) => assert_eq!(kind, "totp_not_configured"),
        other => panic!("expected Validation(totp_not_configured), got {other:?}"),
    }
}

#[test]
fn totp_generate_locked_vault_errors() {
    let (_tmp, handle) = fresh_handle();
    let id = account_add(handle.clone(), draft("acct")).expect("add");
    set_totp(&handle, &id, SECRET_SHA1, None);
    vault_lock(handle.clone()).expect("vault_lock");
    match totp_generate(handle.clone(), id.clone(), 59) {
        Err(FfiError::Session { .. }) => {}
        other => panic!("expected Session error on locked vault, got {other:?}"),
    }
}

#[test]
fn totp_generate_negative_timestamp_errors() {
    let (_tmp, handle) = fresh_handle();
    let id = account_add(handle.clone(), draft("acct")).expect("add");
    set_totp(&handle, &id, SECRET_SHA1, None);
    match totp_generate(handle.clone(), id.clone(), -1) {
        Err(FfiError::Validation { kind, .. }) => assert_eq!(kind, "totp"),
        other => panic!("expected Validation(totp), got {other:?}"),
    }
}

#[test]
fn parse_totp_secret_base32_and_uri() {
    // Bare base32 → default params.
    let p = parse_totp_secret("JBSWY3DPEHPK3PXP".to_string()).expect("parse");
    assert_eq!(p.params.algorithm, TotpAlgorithm::Sha1);
    assert_eq!(p.params.digits, 6);
    assert_eq!(p.secret.byte_length(), 10);
    // Full otpauth:// URI with params.
    let q = parse_totp_secret(
        "otpauth://totp/ACME:alice?secret=JBSWY3DPEHPK3PXP&algorithm=SHA512&digits=8&period=45"
            .to_string(),
    )
    .expect("parse uri");
    assert_eq!(q.params.algorithm, TotpAlgorithm::Sha512);
    assert_eq!(q.params.digits, 8);
    assert_eq!(q.params.period_seconds, 45);
    // Garbage → typed error.
    assert!(parse_totp_secret("not!base32!".to_string()).is_err());
    assert!(parse_totp_secret("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP".to_string()).is_err());
}

#[test]
fn max_secret_bytes_matches_store_limit() {
    assert_eq!(
        pangolin_totp::MAX_SECRET_BYTES,
        pangolin_store::account::limits::TOTP_SECRET_MAX_BYTES
    );
}

#[test]
fn parsed_then_generate_round_trips() {
    // The full shell flow: parse an otpauth:// URI → set on the account
    // via account_update with the parsed params → generate a code.
    let (_tmp, handle) = fresh_handle();
    let id = account_add(handle.clone(), draft("acct")).expect("add");
    // RFC SHA-1 secret "12345678901234567890" base32-encoded is
    // "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".
    let parsed = parse_totp_secret(
        "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8".to_string(),
    )
    .expect("parse");
    assert_eq!(parsed.params.digits, 8);
    let patch = AccountPatch {
        schema_version: 1,
        display_name: None,
        tags: None,
        usernames: None,
        urls: None,
        notes: None,
        current_password: None,
        totp_secret: Some(Some(parsed.secret)),
        totp_params: Some(parsed.params),
    };
    account_update(handle.clone(), id.clone(), patch).expect("update");
    let code = totp_generate(handle.clone(), id.clone(), 59).expect("generate");
    assert_eq!(code.code, "94287082");
}
