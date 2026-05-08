//! Smoke test: every record / object the FFI surface freezes at issue
//! 1.1 can be constructed, dropped, and round-tripped through the
//! `UniFFI` scaffolding without panic. This is the build-time
//! verification that the bindgen sees every type; the actual
//! `uniffi-bindgen generate` invocation lives in CI's `ffi-bindings`
//! job.
//!
//! The function bodies in `pangolin-ffi` panic with `todo!()` until
//! 1.2 / 1.3 / 1.4 / 1.7 / 1.8 / 1.9 / 1.10 / 1.11 land. This test
//! deliberately does NOT call any of them — the build-time `UniFFI`
//! scaffolding is what we're verifying.

use pangolin_ffi::{
    AccountDraft, AccountId, AccountPatch, AccountSnapshot, KdbxImportReport, PasswordPolicy,
    PlaintextExportConfirmation, PresenceProof, RevisionId, RevisionMeta, SecretPassword,
    SessionInfo, TotpCode, UnixTimestamp, VaultHandle,
};

#[test]
fn secret_password_construction_and_drop() {
    let pw = SecretPassword::new(b"correct horse battery staple".to_vec());
    assert_eq!(pw.len(), 28);
    assert!(!pw.is_empty());
    drop(pw);
}

#[test]
fn vault_handle_placeholder_round_trip() {
    let h = VaultHandle::new_placeholder();
    assert!(h.is_placeholder());
    drop(h);
}

#[test]
fn presence_proof_record_round_trip() {
    let original = PresenceProof {
        schema_version: 0,
        bytes: vec![1, 2, 3],
    };
    let cloned = original.clone();
    assert_eq!(original.bytes, cloned.bytes);
    assert_eq!(original.schema_version, cloned.schema_version);
}

#[test]
fn session_info_record_round_trip() {
    let original = SessionInfo {
        schema_version: 0,
        last_refresh_unix: 1_700_000_000,
        is_active: true,
    };
    let cloned = original.clone();
    assert_eq!(original.is_active, cloned.is_active);
    assert_eq!(original.last_refresh_unix, cloned.last_refresh_unix);
}

#[test]
fn account_id_record_round_trip() {
    let original = AccountId {
        schema_version: 0,
        bytes: vec![0xAA; 32],
    };
    let cloned = original.clone();
    assert_eq!(original, cloned);
    assert_eq!(cloned.bytes.len(), 32);
}

#[test]
fn account_draft_record_round_trip() {
    let original = AccountDraft {
        schema_version: 0,
        display_name: "GitHub".into(),
        username: "alice".into(),
        url: Some("https://github.com".into()),
        notes: None,
        password: b"s3cret".to_vec(),
    };
    let cloned = original.clone();
    assert_eq!(original.display_name, cloned.display_name);
    assert_eq!(original.password, cloned.password);
}

#[test]
fn account_patch_record_round_trip() {
    let original = AccountPatch {
        schema_version: 0,
        display_name: Some("GitLab".into()),
        username: None,
        url: None,
        notes: None,
        password: None,
    };
    let cloned = original.clone();
    assert_eq!(original.display_name, cloned.display_name);
    assert_eq!(original.username, cloned.username);
}

#[test]
fn account_snapshot_record_round_trip() {
    let head = RevisionId {
        schema_version: 0,
        bytes: vec![0xBB; 32],
    };
    let original = AccountSnapshot {
        schema_version: 0,
        id: AccountId {
            schema_version: 0,
            bytes: vec![0xAA; 32],
        },
        display_name: "GitHub".into(),
        username: "alice".into(),
        url: None,
        notes: None,
        head_revision_id: head.clone(),
    };
    let cloned = original.clone();
    assert_eq!(original.head_revision_id, cloned.head_revision_id);
    assert_eq!(cloned.head_revision_id, head);
}

#[test]
fn revision_meta_record_round_trip() {
    let original = RevisionMeta {
        schema_version: 0,
        id: RevisionId {
            schema_version: 0,
            bytes: vec![0xCC; 32],
        },
        created_at_unix: 1_700_000_000,
        parent_id: None,
        device_id: vec![0xDD; 16],
    };
    let cloned = original.clone();
    assert_eq!(original.parent_id, cloned.parent_id);
    assert_eq!(original.device_id, cloned.device_id);
}

#[test]
fn totp_code_record_round_trip() {
    let original = TotpCode {
        schema_version: 0,
        code: "123456".into(),
        seconds_remaining: 25,
    };
    let cloned = original.clone();
    assert_eq!(original.code, cloned.code);
    assert_eq!(original.seconds_remaining, cloned.seconds_remaining);
}

#[test]
fn password_policy_record_round_trip() {
    let original = PasswordPolicy {
        schema_version: 0,
        length: 24,
        uppercase: true,
        lowercase: true,
        digits: true,
        symbols: false,
    };
    let cloned = original.clone();
    assert_eq!(original.length, cloned.length);
    assert_eq!(original.symbols, cloned.symbols);
}

#[test]
fn plaintext_export_confirmation_record_round_trip() {
    let original = PlaintextExportConfirmation {
        schema_version: 0,
        token: vec![0xEE; 8],
    };
    let cloned = original.clone();
    assert_eq!(original.token, cloned.token);
}

#[test]
fn kdbx_import_report_record_round_trip() {
    let original = KdbxImportReport {
        schema_version: 0,
        imported: 10,
        skipped: 1,
        failed: 0,
        failure_kinds: vec![],
    };
    let cloned = original.clone();
    assert_eq!(original.imported, cloned.imported);
    assert_eq!(original.failure_kinds, cloned.failure_kinds);
}

#[test]
fn unix_timestamp_alias_round_trip() {
    let t: UnixTimestamp = 1_700_000_000;
    assert_eq!(t, 1_700_000_000_i64);
}
