// SPDX-License-Identifier: AGPL-3.0-or-later
//! 500-entry generated-fixture scale test for the parser + mapper.
//!
//! **Correctness assertions only — NO hard timing assertion**
//! (env-quirk #11: this runs in debug mode under
//! `cargo test --workspace`; any release-mode perf smoke would be
//! `#[ignore]`'d, but there is none here).

#![allow(clippy::doc_markdown, clippy::missing_panics_doc)]

mod writer;

use writer::{build_kdbx4, TestEntry, WriteCipher};

#[test]
fn import_500_entry_kdbx() {
    let mut entries = Vec::with_capacity(500);
    for i in 0..500u32 {
        let mut e = TestEntry::simple(
            &format!("Entry {i}"),
            &format!("user{i}@example.com"),
            &format!("password-{i:04}"),
        );
        e.url = format!("https://site{i}.example.com");
        e.notes = format!("note for entry {i}");
        if i % 10 == 0 {
            e.extra.push((
                "otp".into(),
                "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP".into(),
                true,
            ));
        }
        if i % 10 == 1 {
            e.history = vec![(
                format!("old-password-{i}"),
                Some("2022-01-01T00:00:00Z".into()),
            )];
        }
        if i % 7 == 0 {
            e.group_path = vec![format!("Folder{}", i % 5)];
        }
        entries.push(e);
    }
    let bytes = build_kdbx4(&entries, Some("scale-pw"), None, WriteCipher::Aes256Cbc);
    let db = pangolin_kdbx::read_kdbx(
        &bytes,
        Some(&zeroize::Zeroizing::new(b"scale-pw".to_vec())),
        None,
    )
    .expect("parse 500-entry kdbx");
    assert_eq!(db.entries.len(), 500);
    let mapped = pangolin_kdbx::map_database(&db);
    assert_eq!(mapped.entries.len(), 500);
    // Spot-check a few.
    let m0 = &mapped.entries[0];
    assert_eq!(m0.display_name, "Entry 0");
    assert_eq!(m0.usernames, vec!["user0@example.com"]);
    assert_eq!(&*m0.password, b"password-0000");
    assert!(m0.totp.is_some()); // i % 10 == 0
    let m1 = &mapped.entries[1];
    assert!(!m1.history_passwords.is_empty()); // i % 10 == 1
    let m499 = &mapped.entries[499];
    assert_eq!(m499.display_name, "Entry 499");
    assert_eq!(&*m499.password, b"password-0499");
}
