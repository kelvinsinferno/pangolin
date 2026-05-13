// SPDX-License-Identifier: AGPL-3.0-or-later
//! MVP-1 issue 1.10: encrypted-export / restore-to-fresh-vault
//! end-to-end tests at the `pangolin-store` level.

use pangolin_crypto::secret::SecretBytes;
use pangolin_store::session::{PinIdentityProof, PressYPresenceProof};
use pangolin_store::{decode_archive, AccountSelection, Vault};
use tempfile::TempDir;

fn pw(s: &str) -> SecretBytes {
    SecretBytes::new(s.as_bytes().to_vec())
}

fn unlock(v: &mut Vault, p: &str) {
    let presence = PressYPresenceProof::confirmed();
    let identity = PinIdentityProof::new(pw(p));
    if let Err(e) = v.unlock(&presence, &identity) {
        panic!("unlock failed with {p:?}: {e:?}");
    }
}

#[test]
fn export_decode_restore_round_trip() {
    let dir = TempDir::new().expect("tempdir");
    let src_path = dir.path().join("src.pvf");
    Vault::create(&src_path, &pw("master-1")).expect("create");
    let acct_id;
    {
        let mut v = Vault::open(&src_path).expect("open");
        unlock(&mut v, "master-1");
        let draft = pangolin_store::AccountIdentityDraft {
            schema_version: pangolin_store::ACCOUNT_IDENTITY_SCHEMA_VERSION,
            display_name: "GitHub".into(),
            tags: vec!["work".into()],
            usernames: vec!["octocat".into()],
            urls: vec!["https://github.com".into()],
            notes: "recovery code: abc".into(),
            password: pw("super-secret-pw"),
            totp_secret: SecretBytes::new(Vec::new()),
            totp_params: pangolin_store::TotpParams::default(),
        };
        acct_id = v.account_add(draft).expect("add");
        // Bump the password once so there's history.
        let patch = pangolin_store::AccountIdentityPatch {
            schema_version: pangolin_store::ACCOUNT_IDENTITY_SCHEMA_VERSION,
            display_name: None,
            tags: None,
            usernames: None,
            urls: None,
            notes: None,
            password: Some(pw("new-secret-pw")),
            totp_secret: None,
            totp_params: None,
        };
        v.account_update(acct_id, patch).expect("update");
        v.close().expect("close");
    }

    // Export encrypted.
    let archive = {
        let mut v = Vault::open(&src_path).expect("re-open src");
        unlock(&mut v, "master-1");
        let presence = PressYPresenceProof::confirmed();
        let bytes = v
            .export_encrypted(&pw("archive-pass-xyz"), &AccountSelection::All, &presence)
            .expect("export");
        v.close().expect("close");
        bytes.to_vec()
    };
    assert_eq!(&archive[..12], b"PANGOLIN-VEA");
    // No plaintext markers in the archive.
    let has = |hay: &[u8], needle: &[u8]| hay.windows(needle.len()).any(|w| w == needle);
    assert!(!has(&archive, b"super-secret-pw"));
    assert!(!has(&archive, b"new-secret-pw"));
    assert!(!has(&archive, b"octocat"));

    // Decode.
    let snap = decode_archive(&archive, &pw("archive-pass-xyz")).expect("decode");
    assert_eq!(snap.accounts.len(), 1);
    let a = &snap.accounts[0];
    assert_eq!(a.account_id, *acct_id.as_bytes());
    assert_eq!(a.display_name.expose(), b"GitHub");
    assert_eq!(a.usernames[0].expose(), b"octocat");
    assert_eq!(a.password_history.len(), 2);
    assert_eq!(a.password_history[0].password.expose(), b"new-secret-pw");
    assert_eq!(a.password_history[1].password.expose(), b"super-secret-pw");

    // Wrong passphrase = no oracle (one error kind).
    let err = decode_archive(&archive, &pw("wrong")).unwrap_err();
    match err {
        pangolin_store::StoreError::Validation { kind, .. } => {
            assert_eq!(kind, "export_credentials");
        }
        other => panic!("unexpected: {other:?}"),
    }

    // Restore to a fresh vault under a NEW master password.
    let dst_path = dir.path().join("restored.pvf");
    let snap2 = decode_archive(&archive, &pw("archive-pass-xyz")).expect("decode2");
    Vault::restore_to_new_vault(&dst_path, snap2, &pw("master-2")).expect("restore");
    {
        let mut v = Vault::open(&dst_path).expect("open restored");
        unlock(&mut v, "master-2");
        let ids = v.list_accounts();
        assert_eq!(ids.len(), 1);
        let cur = v
            .reveal_current_password(ids[0], &PressYPresenceProof::confirmed())
            .expect("reveal");
        assert_eq!(cur.expose(), b"new-secret-pw");
        let hist = v
            .reveal_password_history(ids[0], &PressYPresenceProof::confirmed())
            .expect("history");
        assert_eq!(hist.len(), 2);
        v.close().expect("close");
    }
}

#[test]
fn export_accounts_subset() {
    let dir = TempDir::new().expect("tempdir");
    let src_path = dir.path().join("src.pvf");
    Vault::create(&src_path, &pw("master-1")).expect("create");
    let mut v = Vault::open(&src_path).expect("open");
    unlock(&mut v, "master-1");
    let mk = |name: &str| pangolin_store::AccountIdentityDraft {
        schema_version: pangolin_store::ACCOUNT_IDENTITY_SCHEMA_VERSION,
        display_name: name.into(),
        tags: vec![],
        usernames: vec!["u@e.test".into()],
        urls: vec![],
        notes: String::new(),
        password: pw("pw"),
        totp_secret: SecretBytes::new(Vec::new()),
        totp_params: pangolin_store::TotpParams::default(),
    };
    let a = v.account_add(mk("A")).expect("add a");
    let _b = v.account_add(mk("B")).expect("add b");
    let c = v.account_add(mk("C")).expect("add c");
    let presence = PressYPresenceProof::confirmed();
    let sel = AccountSelection::Subset(vec![*a.as_bytes(), *c.as_bytes()]);
    let archive = v
        .export_encrypted(&pw("ap"), &sel, &presence)
        .expect("export subset");
    v.close().expect("close");
    let snap = decode_archive(&archive, &pw("ap")).expect("decode");
    assert_eq!(
        snap.accounts.len(),
        2,
        "subset archive has exactly the two selected accounts"
    );
    let names: Vec<Vec<u8>> = snap
        .accounts
        .iter()
        .map(|x| x.display_name.expose().to_vec())
        .collect();
    assert!(names.contains(&b"A".to_vec()));
    assert!(names.contains(&b"C".to_vec()));
    assert!(!names.contains(&b"B".to_vec()));
}
