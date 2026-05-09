// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::redundant_clone)]
//! MVP-1 issue 1.2 integration tests for the `account_*` FFI bodies.
//!
//! These tests build a real (unlocked) `Vault`, install it into a
//! `VaultHandle`, and exercise the FFI surface end-to-end. The
//! presence-gated reveal entry points are 1.4's scope; the tests here
//! cover only the non-secret read-back path.

use std::sync::Arc;

use pangolin_core::{PinIdentityProof, PressYPresenceProof, Vault};
use pangolin_crypto::secret::SecretBytes;
use pangolin_ffi::identity::{
    account_add, account_get, account_history, account_search, account_update,
};
use pangolin_ffi::{AccountDraft, AccountPatch, SecretPassword, TotpSecret, VaultHandle};
use tempfile::TempDir;

fn make_unlocked_vault() -> (TempDir, Vault) {
    let tmp = TempDir::new().expect("tempdir");
    let path = tmp.path().join("test.pvf");
    let pwd = SecretBytes::new(b"correct horse battery staple".to_vec());
    Vault::create(&path, &pwd).expect("create");
    let mut v = Vault::open(&path).expect("open");
    let presence = PressYPresenceProof::confirmed();
    let identity =
        PinIdentityProof::new(SecretBytes::new(b"correct horse battery staple".to_vec()));
    v.unlock(&presence, &identity).expect("unlock");
    (tmp, v)
}

fn fresh_handle() -> (TempDir, Arc<VaultHandle>) {
    let (tmp, vault) = make_unlocked_vault();
    let handle = VaultHandle::from_vault(vault);
    (tmp, handle)
}

fn fresh_draft(display: &str) -> AccountDraft {
    AccountDraft {
        schema_version: 1,
        display_name: display.into(),
        tags: vec!["work".into(), "shared".into()],
        usernames: vec!["alice@example.com".into(), "alt@example.com".into()],
        urls: vec!["https://github.com/alice".into()],
        notes: Some("test notes".into()),
        current_password: SecretPassword::new(b"hunter2".to_vec()),
        totp_secret: Some(TotpSecret::new(b"jbswy3dpehpk3pxp".to_vec())),
    }
}

#[test]
fn account_add_get_roundtrip() {
    let (_tmp, handle) = fresh_handle();
    let draft = fresh_draft("GitHub – Main");
    let id = account_add(handle.clone(), draft).expect("account_add");
    assert_eq!(id.bytes.len(), 32);

    let snap = account_get(handle.clone(), id.clone()).expect("account_get");
    assert_eq!(snap.display_name, "GitHub – Main");
    assert_eq!(snap.tags.len(), 2);
    assert_eq!(snap.usernames.len(), 2);
    assert_eq!(snap.urls.len(), 1);
    assert_eq!(snap.password_history.len(), 1);
    assert!(snap.totp_secret.is_some());
}

#[test]
fn account_update_appends_password_history() {
    let (_tmp, handle) = fresh_handle();
    let draft = fresh_draft("GitHub");
    let id = account_add(handle.clone(), draft).expect("account_add");

    let patch = AccountPatch {
        schema_version: 1,
        display_name: None,
        tags: None,
        usernames: None,
        urls: None,
        notes: None,
        current_password: Some(SecretPassword::new(b"hunter3".to_vec())),
        totp_secret: None,
    };
    let _rev = account_update(handle.clone(), id.clone(), patch).expect("account_update");

    let snap = account_get(handle.clone(), id.clone()).expect("account_get");
    assert_eq!(snap.password_history.len(), 2);
}

#[test]
fn account_history_lists_revisions() {
    let (_tmp, handle) = fresh_handle();
    let draft = fresh_draft("GitHub");
    let id = account_add(handle.clone(), draft).expect("account_add");

    // First read: 1 revision.
    let history = account_history(handle.clone(), id.clone()).expect("history");
    assert_eq!(history.len(), 1);

    // Bump password, expect 2 revisions.
    let patch = AccountPatch {
        schema_version: 1,
        display_name: None,
        tags: None,
        usernames: None,
        urls: None,
        notes: None,
        current_password: Some(SecretPassword::new(b"hunter3".to_vec())),
        totp_secret: None,
    };
    account_update(handle.clone(), id.clone(), patch).expect("update");
    let history = account_history(handle.clone(), id.clone()).expect("history");
    assert_eq!(history.len(), 2);
}

#[test]
fn account_search_finds_by_display_name_tag_url() {
    let (_tmp, handle) = fresh_handle();

    let mut d1 = fresh_draft("GitHub – Main");
    d1.tags = vec!["work".into()];
    d1.urls = vec!["https://github.com".into()];
    account_add(handle.clone(), d1).expect("add 1");

    let mut d2 = fresh_draft("Some Other Site");
    d2.tags = vec!["github-dev".into()];
    d2.urls = vec!["https://example.com".into()];
    account_add(handle.clone(), d2).expect("add 2");

    let mut d3 = fresh_draft("Random");
    d3.tags = vec!["personal".into()];
    d3.urls = vec!["https://github.com/issue/1".into()];
    account_add(handle.clone(), d3).expect("add 3");

    let hits = account_search(handle.clone(), "github".into()).expect("search");
    // All 3 should match: d1 by display_name, d2 by tag, d3 by url.
    assert_eq!(hits.len(), 3);
}

#[test]
fn account_add_rejects_invalid_url() {
    let (_tmp, handle) = fresh_handle();
    let mut draft = fresh_draft("Bad");
    draft.urls = vec!["not a url".into()];
    let err = account_add(handle.clone(), draft).expect_err("must reject");
    let msg = err.message();
    assert!(msg.contains("url"), "expected url validation, got {msg}");
}

#[test]
fn account_add_rejects_empty_display_name() {
    let (_tmp, handle) = fresh_handle();
    let mut draft = fresh_draft("");
    draft.display_name = "  ".into();
    let err = account_add(handle.clone(), draft).expect_err("must reject");
    let msg = err.message();
    assert!(msg.contains("display_name"), "got {msg}");
}

#[test]
fn account_add_rejects_too_many_usernames() {
    let (_tmp, handle) = fresh_handle();
    let mut draft = fresh_draft("X");
    draft.usernames = (0..17).map(|i| format!("u{i}@x.com")).collect();
    let err = account_add(handle.clone(), draft).expect_err("must reject");
    let msg = err.message();
    assert!(msg.contains("usernames"), "got {msg}");
}
