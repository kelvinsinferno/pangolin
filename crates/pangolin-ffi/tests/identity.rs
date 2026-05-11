// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(
    clippy::redundant_clone,
    clippy::cast_possible_truncation,
    clippy::doc_markdown
)]
//! MVP-1 issue 1.2 + 1.4 integration tests for the `account_*` FFI
//! bodies and the presence-gated `reveal_*` entry points.
//!
//! These tests build a real (unlocked) `Vault`, install it into a
//! `VaultHandle`, and exercise the FFI surface end-to-end. As of 1.4
//! (Q5b) the `account_get` / `account_search` snapshot carries zero
//! secret material; the password / history / notes / TOTP-seed bytes
//! cross FFI only through the presence-gated `reveal_*` entries.

use std::sync::Arc;

use pangolin_core::{PinIdentityProof, PressYPresenceProof, Vault};
use pangolin_crypto::secret::SecretBytes;
use pangolin_ffi::identity::{
    account_add, account_get, account_history, account_search, account_update,
};
use pangolin_ffi::reveal::{
    reveal_current_password, reveal_notes, reveal_password_history, reveal_totp_secret,
};
use pangolin_ffi::{
    AccountDraft, AccountPatch, PresenceProof, SecretPassword, TotpSecret, VaultHandle,
};
use tempfile::TempDir;

fn presence_envelope() -> PresenceProof {
    PresenceProof {
        schema_version: 1,
        bytes: Vec::new(),
    }
}

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
    // Q5b: metadata only — count + flag, no secret bytes.
    assert_eq!(snap.password_history_count, 1);
    assert!(snap.has_totp);
    assert!(snap.current_password_changed_at > 0);
}

/// MVP-1 issue 1.4 (Q5b): the FFI `AccountSnapshot` from `account_get`
/// carries zero secret material — the head password, the full history
/// bytes, the notes and the raw TOTP seed come ONLY from the
/// presence-gated `reveal_*` entries. (The struct shape is checked at
/// compile time in `roundtrip.rs`; this test confirms the runtime
/// data flow: the snapshot has the metadata, the reveals have the
/// secrets.)
#[test]
fn ffi_account_snapshot_has_no_plaintext_secrets() {
    let (_tmp, handle) = fresh_handle();
    let id = account_add(handle.clone(), fresh_draft("Reveal Test")).expect("add");

    let snap = account_get(handle.clone(), id.clone()).expect("get");
    assert_eq!(snap.password_history_count, 1);
    assert!(snap.has_totp);

    // The secrets come from the presence-gated reveals.
    let pwd = reveal_current_password(handle.clone(), id.clone(), presence_envelope())
        .expect("reveal_current_password");
    assert_eq!(pwd.byte_length(), b"hunter2".len() as u32);

    let totp = reveal_totp_secret(handle.clone(), id.clone(), presence_envelope())
        .expect("reveal_totp_secret");
    assert_eq!(totp.byte_length(), b"jbswy3dpehpk3pxp".len() as u32);

    let notes =
        reveal_notes(handle.clone(), id.clone(), presence_envelope()).expect("reveal_notes");
    assert_eq!(notes.byte_length(), b"test notes".len() as u32);
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
    assert_eq!(snap.password_history_count, 2);
}

/// MVP-1 issue 1.4 (Q4): the presence-gated `reveal_password_history`
/// returns the full history — head password + every superseded value,
/// each with its timestamp + originating device. Newest first.
#[test]
fn ffi_reveal_password_history_round_trip() {
    let (_tmp, handle) = fresh_handle();
    let id = account_add(handle.clone(), fresh_draft("History")).expect("add");
    // Rotate the password twice.
    for new in [b"hunter3".as_slice(), b"hunter4".as_slice()] {
        let patch = AccountPatch {
            schema_version: 1,
            display_name: None,
            tags: None,
            usernames: None,
            urls: None,
            notes: None,
            current_password: Some(SecretPassword::new(new.to_vec())),
            totp_secret: None,
        };
        account_update(handle.clone(), id.clone(), patch).expect("update");
    }
    let history = reveal_password_history(handle.clone(), id.clone(), presence_envelope())
        .expect("reveal_password_history");
    assert_eq!(history.len(), 3);
    // Newest first: hunter4, hunter3, hunter2.
    assert_eq!(history[0].password.byte_length(), b"hunter4".len() as u32);
    assert_eq!(history[2].password.byte_length(), b"hunter2".len() as u32);
    // Each entry carries a 32-byte device id and a timestamp.
    assert_eq!(history[0].originating_device.bytes.len(), 32);
    assert!(history[0].set_at >= history[2].set_at);
}

/// MVP-1 issue 1.4: `reveal_*` on a locked vault surfaces a session
/// error (NotUnlocked) — and the FFI maps it to the Session category.
#[test]
fn ffi_reveal_on_locked_vault_errors() {
    use pangolin_ffi::session::vault_lock;
    let (_tmp, handle) = fresh_handle();
    let id = account_add(handle.clone(), fresh_draft("Locked")).expect("add");
    vault_lock(handle.clone()).expect("vault_lock");
    let err = reveal_current_password(handle.clone(), id.clone(), presence_envelope())
        .expect_err("must error on locked vault");
    let msg = err.message();
    assert!(
        msg.contains("session") || msg.contains("unlock"),
        "expected a session error, got {msg}"
    );
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
    // Audit M-2: pin oldest-first temporal ordering. `Vault::
    // account_history` routes through `revisions_for` which uses
    // `ORDER BY created_at ASC` — so index 0 is the genesis revision
    // and index 1 is the password-rotation revision. The sequence
    // must satisfy `created_at_unix[0] <= created_at_unix[1]`.
    assert!(
        history[0].created_at_unix <= history[1].created_at_unix,
        "account_history must be oldest-first: got {} then {}",
        history[0].created_at_unix,
        history[1].created_at_unix
    );
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
