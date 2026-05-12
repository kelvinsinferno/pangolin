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
    AccountDraft, AccountId, AccountPatch, AccountSnapshot, CaptureAuthority, CaptureContext,
    DeviceCapabilities, DeviceId, DeviceInfo, KdbxImportReport, PasswordHistoryEntry,
    PasswordPolicy, PlaintextExportConfirmation, PresenceProof, RevealedSecret, RevisionId,
    RevisionMeta, SecretPassword, SessionInfo, TotpCode, TotpSecret, UnixTimestamp, VaultHandle,
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
    // MVP-1 issue 1.4 widened SessionInfo (additive fields).
    let original = SessionInfo {
        schema_version: 1,
        last_refresh_unix: 1_700_000_000,
        is_active: true,
        idle_deadline_unix: 1_700_000_900,
        absolute_deadline_unix: 1_700_014_400,
        configured_idle_secs: 900,
        last_presence_fresh_until_unix: 1_700_000_060,
    };
    let cloned = original.clone();
    assert_eq!(original.is_active, cloned.is_active);
    assert_eq!(original.last_refresh_unix, cloned.last_refresh_unix);
    assert_eq!(original.idle_deadline_unix, cloned.idle_deadline_unix);
    assert_eq!(original.configured_idle_secs, 900);
}

#[test]
fn revealed_secret_object_round_trip() {
    // MVP-1 issue 1.4: the zeroizing wrapper the reveal_* entries
    // return. Length-only accessor; bytes zero on drop.
    let s = RevealedSecret::new(b"top secret".to_vec());
    assert_eq!(s.byte_length(), 10);
    assert!(!s.is_empty());
    drop(s);
    let empty = RevealedSecret::new(Vec::new());
    assert_eq!(empty.byte_length(), 0);
    assert!(empty.is_empty());
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
        schema_version: 1,
        display_name: "GitHub".into(),
        tags: vec!["work".into()],
        usernames: vec!["alice".into()],
        urls: vec!["https://github.com".into()],
        notes: None,
        current_password: SecretPassword::new(b"s3cret".to_vec()),
        totp_secret: None,
        totp_params: None,
    };
    let cloned = original.clone();
    assert_eq!(original.display_name, cloned.display_name);
    assert_eq!(original.usernames, cloned.usernames);
    assert_eq!(original.urls, cloned.urls);
}

#[test]
fn account_patch_record_round_trip() {
    let original = AccountPatch {
        schema_version: 1,
        display_name: Some("GitLab".into()),
        tags: None,
        usernames: None,
        urls: None,
        notes: None,
        current_password: None,
        totp_secret: None,
        totp_params: None,
    };
    let cloned = original.clone();
    assert_eq!(original.display_name, cloned.display_name);
    assert_eq!(original.usernames, cloned.usernames);
}

#[test]
fn account_snapshot_record_round_trip() {
    // MVP-1 issue 1.4 (Q5b): the FFI AccountSnapshot is metadata-only —
    // no secret-bearing fields. Display name / tags / usernames / URLs
    // are non-secret per the V1 model; the password / history / notes /
    // TOTP-seed bytes reach the binding ONLY through the presence-gated
    // reveal_* entry points.
    let head = RevisionId {
        schema_version: 1,
        bytes: vec![0xBB; 32],
    };
    let original = AccountSnapshot {
        schema_version: 1,
        id: AccountId {
            schema_version: 1,
            bytes: vec![0xAA; 32],
        },
        display_name: "GitHub".into(),
        tags: vec!["work".into()],
        usernames: vec!["alice".into()],
        urls: vec!["https://github.com".into()],
        head_revision_id: head.clone(),
        password_history_count: 2,
        has_totp: true,
        current_password_changed_at: 1_700_000_000,
    };
    let cloned = original.clone();
    assert_eq!(original.head_revision_id, cloned.head_revision_id);
    assert_eq!(cloned.head_revision_id, head);
    assert_eq!(cloned.password_history_count, 2);
    assert!(cloned.has_totp);
    assert_eq!(cloned.current_password_changed_at, 1_700_000_000);
}

/// Regression test for audit C-1 (`notes`) **and** MVP-1 issue 1.4
/// Q5b (`current_password` / `password_history` / `totp_secret`): the
/// FFI `AccountSnapshot` carries **zero secret-bearing fields**. This
/// struct literal lists every field; if a secret-bearing field were
/// re-added (without a default) this would fail to compile and the
/// regression is caught at build time. Constructing it requires no
/// secret material whatsoever.
#[test]
fn account_snapshot_has_no_secret_fields() {
    let _snap = AccountSnapshot {
        schema_version: 1,
        id: AccountId {
            schema_version: 1,
            bytes: vec![0xAA; 32],
        },
        display_name: "X".into(),
        tags: vec![],
        usernames: vec!["u".into()],
        urls: vec![],
        head_revision_id: RevisionId {
            schema_version: 1,
            bytes: vec![0xBB; 32],
        },
        password_history_count: 0,
        has_totp: false,
        current_password_changed_at: 0,
    };
}

#[test]
fn device_id_record_round_trip() {
    let original = DeviceId {
        schema_version: 1,
        bytes: vec![0xCD; 32],
    };
    let cloned = original.clone();
    assert_eq!(original, cloned);
    assert_eq!(cloned.bytes.len(), 32);
}

#[test]
fn device_info_record_round_trip() {
    // MVP-1 issue 1.5: the device-identity record returned by
    // device_current / device_list. Carries only non-secret material;
    // last_sync_at is dormant (always None in MVP-1).
    let original = DeviceInfo {
        schema_version: 1,
        id: DeviceId {
            schema_version: 1,
            bytes: vec![0xAB; 32],
        },
        label: "Kelvin's MacBook".into(),
        registered_at: 1_700_000_000,
        last_sync_at: None,
        capabilities: DeviceCapabilities::Full,
        is_current: true,
        public_key: vec![0xAB; 32],
    };
    let cloned = original.clone();
    assert_eq!(original.id, cloned.id);
    assert_eq!(cloned.last_sync_at, None);
    assert_eq!(cloned.capabilities, DeviceCapabilities::Full);
    assert!(cloned.is_current);
    assert_eq!(cloned.public_key, cloned.id.bytes);
}

#[test]
fn totp_secret_object_round_trip() {
    let secret = TotpSecret::new(b"jbswy3dpehpk3pxp".to_vec());
    assert_eq!(secret.len(), 16);
    assert!(!secret.is_empty());
    drop(secret);
}

#[test]
fn password_history_entry_record_round_trip() {
    let entry = PasswordHistoryEntry {
        schema_version: 1,
        password: SecretPassword::new(b"hunter2".to_vec()),
        set_at: 1_700_000_000,
        originating_device: DeviceId {
            schema_version: 1,
            bytes: vec![0xAA; 32],
        },
    };
    let cloned = entry.clone();
    assert_eq!(entry.set_at, cloned.set_at);
    assert_eq!(
        entry.originating_device.bytes,
        cloned.originating_device.bytes
    );
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
        is_tombstone: false,
        is_head: true,
        is_canonical_head: true,
        on_canonical_chain: true,
    };
    let cloned = original.clone();
    assert_eq!(original.parent_id, cloned.parent_id);
    assert_eq!(original.device_id, cloned.device_id);
    assert!(cloned.is_canonical_head);
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
fn capture_authority_record_round_trip() {
    let original = CaptureAuthority {
        schema_version: 0,
        origin: "https://example.com".into(),
    };
    let cloned = original.clone();
    assert_eq!(original.origin, cloned.origin);
    assert_eq!(original.schema_version, cloned.schema_version);
}

#[test]
fn capture_context_record_round_trip() {
    let original = CaptureContext {
        schema_version: 0,
        label: "login-form".into(),
    };
    let cloned = original.clone();
    assert_eq!(original.label, cloned.label);
    assert_eq!(original.schema_version, cloned.schema_version);
}

#[test]
fn unix_timestamp_alias_round_trip() {
    let t: UnixTimestamp = 1_700_000_000;
    assert_eq!(t, 1_700_000_000_i64);
}
