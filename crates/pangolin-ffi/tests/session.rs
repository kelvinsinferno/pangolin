// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(
    clippy::redundant_clone,
    clippy::cast_possible_truncation,
    clippy::missing_panics_doc,
    clippy::doc_markdown
)]
//! MVP-1 issue 1.4 integration tests for the wired vault-lifecycle +
//! session FFI bodies (`vault_create` / `vault_open` / `vault_unlock` /
//! `vault_lock` / `vault_close` / `session_status` / `session_extend`).

use pangolin_ffi::identity::account_add;
use pangolin_ffi::reveal::reveal_notes;
use pangolin_ffi::session::{
    session_extend, session_status, vault_close, vault_create, vault_lock, vault_open, vault_unlock,
};
use pangolin_ffi::{AccountDraft, PresenceProof, SecretPassword, TotpSecret};
use tempfile::TempDir;

fn presence() -> PresenceProof {
    PresenceProof {
        schema_version: 1,
        bytes: Vec::new(),
    }
}

fn draft(display: &str) -> AccountDraft {
    AccountDraft {
        schema_version: 1,
        display_name: display.into(),
        tags: vec!["work".into()],
        usernames: vec!["alice@example.com".into()],
        urls: vec!["https://github.com".into()],
        notes: Some("secret notes".into()),
        current_password: SecretPassword::new(b"hunter2".to_vec()),
        totp_secret: Some(TotpSecret::new(b"jbswy3dpehpk3pxp".to_vec())),
        totp_params: None,
    }
}

/// `vault_create → vault_open → vault_unlock → account_add → reveal_notes
/// → vault_lock → vault_close` — the full FFI session loop. No `todo!()`
/// remains in `session.rs` / `reveal.rs`.
#[test]
fn ffi_vault_lifecycle_round_trip() {
    let tmp = TempDir::new().expect("tempdir");
    let path = tmp.path().join("ffi.pvf");
    let path_str = path.to_str().unwrap().to_owned();

    vault_create(
        path_str.clone(),
        SecretPassword::new(b"correct horse".to_vec()),
    )
    .expect("vault_create");
    let handle = vault_open(path_str.clone()).expect("vault_open");

    // Before unlock: not active.
    let before = session_status(handle.clone());
    assert!(!before.is_active);

    let info = vault_unlock(
        handle.clone(),
        SecretPassword::new(b"correct horse".to_vec()),
        presence(),
    )
    .expect("vault_unlock");
    assert!(info.is_active);
    assert!(info.idle_deadline_unix > 0);
    assert!(info.absolute_deadline_unix >= info.idle_deadline_unix);
    // Default configured idle = 15 min = 900 s.
    assert_eq!(info.configured_idle_secs, 900);
    assert!(info.last_presence_fresh_until_unix > 0);

    let id = account_add(handle.clone(), draft("GitHub")).expect("account_add");

    // reveal_notes works while the unlock's presence is still fresh.
    let notes = reveal_notes(handle.clone(), id.clone(), presence()).expect("reveal_notes");
    assert_eq!(notes.byte_length(), b"secret notes".len() as u32);

    vault_lock(handle.clone()).expect("vault_lock");
    assert!(!session_status(handle.clone()).is_active);

    // reveal after lock → session error.
    let err = reveal_notes(handle.clone(), id.clone(), presence()).expect_err("locked");
    assert!(err.message().contains("session") || err.message().contains("unlock"));

    vault_close(handle.clone()).expect("vault_close");
    // Idempotent: closing again is a no-op.
    vault_close(handle).expect("vault_close (idempotent)");
}

/// `session_status` reports the idle / absolute deadlines and the
/// presence-freshness horizon.
#[test]
fn ffi_session_status_reports_deadlines() {
    let tmp = TempDir::new().expect("tempdir");
    let path = tmp.path().join("status.pvf");
    let path_str = path.to_str().unwrap().to_owned();
    vault_create(path_str.clone(), SecretPassword::new(b"pw".to_vec())).expect("create");
    let handle = vault_open(path_str).expect("open");
    vault_unlock(
        handle.clone(),
        SecretPassword::new(b"pw".to_vec()),
        presence(),
    )
    .expect("unlock");

    let s = session_status(handle.clone());
    assert!(s.is_active);
    assert!(s.idle_deadline_unix > s.last_refresh_unix);
    assert!(s.absolute_deadline_unix >= s.idle_deadline_unix);
    assert_eq!(s.configured_idle_secs, 900);
    assert!(s.last_presence_fresh_until_unix >= s.last_refresh_unix);
}

/// `session_extend` takes a presence proof (1.4 amends the 1.1
/// signature — §5.4 "extend long sessions" is high-risk) and re-extends
/// the idle deadline. On a locked vault it errors.
#[test]
fn ffi_session_extend_requires_presence() {
    let tmp = TempDir::new().expect("tempdir");
    let path = tmp.path().join("extend.pvf");
    let path_str = path.to_str().unwrap().to_owned();
    vault_create(path_str.clone(), SecretPassword::new(b"pw".to_vec())).expect("create");
    let handle = vault_open(path_str).expect("open");

    // Locked: extend errors (session not active).
    let err = session_extend(handle.clone(), presence()).expect_err("locked extend");
    assert!(err.message().contains("session") || err.message().contains("unlock"));

    vault_unlock(
        handle.clone(),
        SecretPassword::new(b"pw".to_vec()),
        presence(),
    )
    .expect("unlock");
    let extended = session_extend(handle.clone(), presence()).expect("session_extend");
    assert!(extended.is_active);
    assert!(extended.idle_deadline_unix > 0);
}
