// SPDX-License-Identifier: AGPL-3.0-or-later
//! Round-trip + adversarial tests for the hand-rolled KDBX reader.
//!
//! Fixture `.kdbx` byte streams are built in memory by the `writer`
//! helper module (`tests/writer/mod.rs`), a self-contained KDBX 3.1 /
//! 4.x encoder; the reader decodes them and we assert every field.

#![allow(
    clippy::doc_markdown,
    clippy::field_reassign_with_default,
    clippy::too_many_lines,
    clippy::missing_panics_doc
)]

mod writer;

use pangolin_kdbx::{read_kdbx, EntrySkip, KdbxError};
use writer::{build_kdbx3, build_kdbx4, TestEntry, WriteCipher};

fn entry_field(db: &pangolin_kdbx::KdbxDatabase, idx: usize, key: &str) -> String {
    db.entries[idx]
        .field(key)
        .map(|v| v.as_str_lossy().into_owned())
        .unwrap_or_default()
}

#[test]
fn roundtrip_kdbx4_aes() {
    let entries = vec![
        {
            let mut e = TestEntry::simple("GitHub", "octocat", "hunter2");
            e.url = "https://github.com".into();
            e.notes = "my notes".into();
            e.tags = vec!["dev".into(), "code".into()];
            e.group_path = vec!["Work".into(), "Banking".into()];
            e
        },
        TestEntry::simple("Email", "me@example.com", "correct-horse"),
    ];
    let bytes = build_kdbx4(&entries, Some("master-pw"), None, WriteCipher::Aes256Cbc);
    let db = read_kdbx(
        &bytes,
        Some(&zeroize::Zeroizing::new(b"master-pw".to_vec())),
        None,
    )
    .expect("read kdbx4-aes");
    assert!(db.format_v4);
    assert_eq!(db.entries.len(), 2);
    assert_eq!(entry_field(&db, 0, "Title"), "GitHub");
    assert_eq!(entry_field(&db, 0, "UserName"), "octocat");
    assert_eq!(entry_field(&db, 0, "Password"), "hunter2");
    assert_eq!(entry_field(&db, 0, "URL"), "https://github.com");
    assert_eq!(entry_field(&db, 0, "Notes"), "my notes");
    assert_eq!(db.entries[0].group_path, vec!["Work", "Banking"]);
    assert_eq!(entry_field(&db, 1, "Password"), "correct-horse");

    // Mapping layer.
    let mapped = pangolin_kdbx::map_database(&db);
    assert_eq!(mapped.entries.len(), 2);
    let m0 = &mapped.entries[0];
    assert_eq!(m0.display_name, "GitHub");
    assert_eq!(m0.usernames, vec!["octocat"]);
    assert_eq!(m0.urls, vec!["https://github.com"]);
    assert_eq!(&*m0.password, b"hunter2");
    // group path folded into tags
    assert!(m0.tags.contains(&"Work".to_string()));
    assert!(m0.tags.contains(&"Banking".to_string()));
    assert!(m0.tags.contains(&"dev".to_string()));
}

#[test]
fn roundtrip_kdbx4_chacha20() {
    let entries = vec![TestEntry::simple("Bank", "acct123", "s3cr3t!")];
    let bytes = build_kdbx4(&entries, Some("pw"), None, WriteCipher::ChaCha20);
    let db = read_kdbx(&bytes, Some(&zeroize::Zeroizing::new(b"pw".to_vec())), None)
        .expect("read kdbx4-chacha20");
    assert_eq!(entry_field(&db, 0, "Password"), "s3cr3t!");
}

#[test]
fn roundtrip_kdbx3_aes() {
    let mut e = TestEntry::simple("Legacy", "olduser", "oldpass");
    e.notes = "kdbx3 notes".into();
    let entries = vec![e];
    let bytes = build_kdbx3(&entries, "kp3-pw");
    let db = read_kdbx(
        &bytes,
        Some(&zeroize::Zeroizing::new(b"kp3-pw".to_vec())),
        None,
    )
    .expect("read kdbx3");
    assert!(!db.format_v4);
    assert_eq!(entry_field(&db, 0, "Title"), "Legacy");
    assert_eq!(entry_field(&db, 0, "Password"), "oldpass");
    assert_eq!(entry_field(&db, 0, "Notes"), "kdbx3 notes");
}

#[test]
fn totp_otp_uri_and_timeotp_fields() {
    let entries = vec![
        {
            let mut e = TestEntry::simple("TOTP-URI", "u", "p");
            e.extra.push((
                "otp".into(),
                "otpauth://totp/Example:u?secret=JBSWY3DPEHPK3PXP&issuer=Example".into(),
                true,
            ));
            e
        },
        {
            let mut e = TestEntry::simple("TOTP-Native", "u2", "p2");
            e.extra.push((
                "TimeOtp-Secret-Base32".into(),
                "JBSWY3DPEHPK3PXP".into(),
                true,
            ));
            e.extra.push(("TimeOtp-Period".into(), "60".into(), false));
            e.extra.push(("TimeOtp-Digits".into(), "8".into(), false));
            e.extra
                .push(("TimeOtp-Algorithm".into(), "HMAC-SHA-256".into(), false));
            e
        },
        {
            let mut e = TestEntry::simple("HOTP", "u3", "p3");
            e.extra.push((
                "otp".into(),
                "otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=0".into(),
                true,
            ));
            e
        },
    ];
    let bytes = build_kdbx4(&entries, Some("pw"), None, WriteCipher::Aes256Cbc);
    let db = read_kdbx(&bytes, Some(&zeroize::Zeroizing::new(b"pw".to_vec())), None).unwrap();
    let mapped = pangolin_kdbx::map_database(&db);
    assert_eq!(mapped.entries.len(), 3);
    // otpauth:// URI → TOTP present.
    let m0 = &mapped.entries[0];
    let t0 = m0.totp.as_ref().expect("totp from otp uri");
    assert!(!t0.secret_bytes.is_empty());
    assert_eq!(t0.params.digits, 6);
    // TimeOtp-* native → params honoured.
    let m1 = &mapped.entries[1];
    let t1 = m1.totp.as_ref().expect("totp from TimeOtp-*");
    assert_eq!(t1.params.period_seconds, 60);
    assert_eq!(t1.params.digits, 8);
    assert_eq!(
        t1.params.algorithm,
        pangolin_kdbx::pangolin_totp::TotpAlgorithm::Sha256
    );
    // HOTP → no TOTP, but the entry still imports.
    assert!(mapped.entries[2].totp.is_none());
}

#[test]
fn recycle_bin_entries_are_skipped() {
    let entries = vec![
        TestEntry::simple("Live1", "a", "p1"),
        TestEntry::simple("Live2", "b", "p2"),
        {
            let mut e = TestEntry::simple("Deleted", "c", "p3");
            e.recycled = true;
            e
        },
    ];
    let bytes = build_kdbx4(&entries, Some("pw"), None, WriteCipher::Aes256Cbc);
    let db = read_kdbx(&bytes, Some(&zeroize::Zeroizing::new(b"pw".to_vec())), None).unwrap();
    assert_eq!(db.entries.len(), 2);
    assert_eq!(db.recycle_bin_entries, 1);
}

#[test]
fn empty_title_and_username_and_password_handling() {
    let entries = vec![
        {
            // empty title, has username
            let mut e = TestEntry::default();
            e.username = "user-only".into();
            e.password = "pw".into();
            e
        },
        {
            // empty title + empty username
            let mut e = TestEntry::default();
            e.password = "pw2".into();
            e
        },
        {
            // empty password → skipped
            let mut e = TestEntry::default();
            e.title = "NoPass".into();
            e.password = String::new();
            e
        },
    ];
    let bytes = build_kdbx4(&entries, Some("pw"), None, WriteCipher::Aes256Cbc);
    let db = read_kdbx(&bytes, Some(&zeroize::Zeroizing::new(b"pw".to_vec())), None).unwrap();
    let mapped = pangolin_kdbx::map_database(&db);
    assert_eq!(
        mapped.entries.len(),
        2,
        "the empty-password entry is skipped"
    );
    assert_eq!(mapped.skipped, vec![EntrySkip::EmptyPassword]);
    assert!(!mapped.entries[0].display_name.is_empty());
    assert_eq!(mapped.entries[1].usernames, vec!["(no username)"]);
}

#[test]
fn expired_entry_gets_expired_tag() {
    let mut e = TestEntry::simple("Old", "u", "p");
    e.expires = true;
    e.expiry_time = Some("2000-01-01T00:00:00Z".into());
    let bytes = build_kdbx4(&[e], Some("pw"), None, WriteCipher::Aes256Cbc);
    let db = read_kdbx(&bytes, Some(&zeroize::Zeroizing::new(b"pw".to_vec())), None).unwrap();
    let mapped = pangolin_kdbx::map_database(&db);
    assert!(mapped.entries[0].tags.contains(&"expired".to_string()));
}

#[test]
fn history_passwords_preserved() {
    let mut e = TestEntry::simple("Rotated", "u", "current-pw");
    e.history = vec![
        ("oldest".into(), Some("2020-01-01T00:00:00Z".into())),
        ("middle".into(), Some("2021-01-01T00:00:00Z".into())),
        ("middle".into(), Some("2021-06-01T00:00:00Z".into())), // dup-consecutive
    ];
    let bytes = build_kdbx4(&[e], Some("pw"), None, WriteCipher::Aes256Cbc);
    let db = read_kdbx(&bytes, Some(&zeroize::Zeroizing::new(b"pw".to_vec())), None).unwrap();
    let mapped = pangolin_kdbx::map_database(&db);
    let m = &mapped.entries[0];
    // distinct historical passwords, oldest→newest, dup-consecutive collapsed.
    let hist: Vec<&[u8]> = m
        .history_passwords
        .iter()
        .map(|(p, _)| p.as_slice())
        .collect();
    assert_eq!(hist, vec![b"oldest".as_slice(), b"middle".as_slice()]);
    assert!(m.history_passwords[0].1.is_some());
}

#[test]
fn custom_fields_appended_to_notes() {
    let mut e = TestEntry::simple("WithCustom", "u", "p");
    e.notes = "base note".into();
    e.extra
        .push(("CustomKey".into(), "custom value".into(), false));
    e.extra.push(("Secret-Field".into(), "shh".into(), true));
    let bytes = build_kdbx4(&[e], Some("pw"), None, WriteCipher::Aes256Cbc);
    let db = read_kdbx(&bytes, Some(&zeroize::Zeroizing::new(b"pw".to_vec())), None).unwrap();
    let mapped = pangolin_kdbx::map_database(&db);
    let n = &mapped.entries[0].notes;
    assert!(n.contains("base note"));
    assert!(n.contains("Imported custom fields"));
    assert!(n.contains("CustomKey: custom value"));
    assert!(n.contains("Secret-Field: shh"));
}

#[test]
fn keyfile_raw32_composite_key() {
    let kf = [0x77u8; 32];
    let entries = vec![TestEntry::simple("KF", "u", "p")];
    let bytes = build_kdbx4(&entries, Some("pw"), Some(&kf), WriteCipher::Aes256Cbc);
    // wrong: password only → WrongCredentials.
    let err = read_kdbx(&bytes, Some(&zeroize::Zeroizing::new(b"pw".to_vec())), None).unwrap_err();
    assert_eq!(err, KdbxError::WrongCredentials);
    // right: password + keyfile bytes.
    let db = read_kdbx(
        &bytes,
        Some(&zeroize::Zeroizing::new(b"pw".to_vec())),
        Some(&kf),
    )
    .expect("password + keyfile");
    assert_eq!(entry_field(&db, 0, "Password"), "p");
}

#[test]
fn wrong_password_no_oracle() {
    let entries = vec![TestEntry::simple("X", "u", "p")];
    let bytes = build_kdbx4(&entries, Some("right-pw"), None, WriteCipher::Aes256Cbc);
    let e1 = read_kdbx(
        &bytes,
        Some(&zeroize::Zeroizing::new(b"wrong".to_vec())),
        None,
    )
    .unwrap_err();
    assert_eq!(e1, KdbxError::WrongCredentials);
    // KDBX3 too.
    let b3 = build_kdbx3(&entries, "right-pw");
    let e2 = read_kdbx(&b3, Some(&zeroize::Zeroizing::new(b"wrong".to_vec())), None).unwrap_err();
    assert_eq!(e2, KdbxError::WrongCredentials);
}

#[test]
fn corrupt_inputs_typed_errors_no_panic() {
    // random bytes
    assert!(matches!(
        read_kdbx(
            &[0u8; 64],
            Some(&zeroize::Zeroizing::new(b"x".to_vec())),
            None
        ),
        Err(KdbxError::NotKdbx)
    ));
    // KeePass 1.x signature
    let mut kdb1 = Vec::new();
    kdb1.extend_from_slice(&0x9AA2_D903u32.to_le_bytes());
    kdb1.extend_from_slice(&0xB54B_FB65u32.to_le_bytes());
    kdb1.extend_from_slice(&[0u8; 64]);
    assert!(matches!(
        read_kdbx(&kdb1, Some(&zeroize::Zeroizing::new(b"x".to_vec())), None),
        Err(KdbxError::UnsupportedVersion { major: 1, .. })
    ));
    // truncated header
    let mut tr = Vec::new();
    tr.extend_from_slice(&0x9AA2_D903u32.to_le_bytes());
    tr.extend_from_slice(&0xB54B_FB67u32.to_le_bytes());
    tr.extend_from_slice(&1u16.to_le_bytes());
    tr.extend_from_slice(&4u16.to_le_bytes());
    tr.push(2u8); // CIPHER_ID field id, then truncate
    assert!(matches!(
        read_kdbx(&tr, Some(&zeroize::Zeroizing::new(b"x".to_vec())), None),
        Err(KdbxError::CorruptHeader(_))
    ));
    // empty input
    assert!(read_kdbx(&[], Some(&zeroize::Zeroizing::new(b"x".to_vec())), None).is_err());
}

#[test]
fn flipped_block_mac_byte_rejected() {
    let entries = vec![TestEntry::simple("X", "u", "p")];
    let mut bytes = build_kdbx4(&entries, Some("pw"), None, WriteCipher::Aes256Cbc);
    // Flip a byte deep in the ciphertext region (well past the header +
    // the two 32-byte integrity tags). The block-MAC must reject.
    let n = bytes.len();
    bytes[n - 10] ^= 0xFF;
    let err = read_kdbx(&bytes, Some(&zeroize::Zeroizing::new(b"pw".to_vec())), None).unwrap_err();
    assert_eq!(err, KdbxError::WrongCredentials);
}

#[test]
fn no_password_no_keyfile_rejected() {
    let entries = vec![TestEntry::simple("X", "u", "p")];
    let bytes = build_kdbx4(&entries, Some("pw"), None, WriteCipher::Aes256Cbc);
    let err = read_kdbx(&bytes, None, None).unwrap_err();
    assert!(matches!(err, KdbxError::UnsupportedCredential(_)));
}
