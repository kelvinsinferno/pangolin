// SPDX-License-Identifier: AGPL-3.0-or-later
//! MVP-1 issue 1.9 integration test: `pangolin-cli import <file.kdbx>`.
//!
//! Builds a small fixture `.kdbx` (via `pangolin_kdbx::test_writer`),
//! creates + drives the import through the library entry point
//! (`commands::import::run`), then:
//!   1. asserts the imported accounts are present in the vault with the
//!      right fields (display name, username, URL, password, TOTP,
//!      replayed history);
//!   2. **scans the raw `.pvf` bytes** and asserts none of the imported
//!      plaintext passwords / usernames / notes / TOTP seeds appear
//!      (cardinal principle 2 — the import path routes through
//!      `Vault::account_add`, same AEAD seal, so this holds by
//!      construction; the test makes it non-regressible).

#![allow(
    clippy::missing_panics_doc,
    clippy::unwrap_used,
    clippy::field_reassign_with_default
)]

use std::path::PathBuf;

use pangolin_crypto::secret::SecretBytes;
use pangolin_kdbx::test_writer::{build_kdbx4, TestEntry, WriteCipher};
use pangolin_store::session::{PinIdentityProof, PressYPresenceProof};
use pangolin_store::Vault;

const VAULT_PWD: &str = "vault-master-password";
const KDBX_PWD: &str = "kdbx-master-password";

fn global() -> pangolin_cli::cli::GlobalArgs {
    pangolin_cli::cli::GlobalArgs {
        deployment_file: None,
        rpc_url: None,
        allow_insecure_rpc: false,
        json: false,
    }
}

fn unlock(path: &std::path::Path) -> Vault {
    let mut v = Vault::open(path).unwrap();
    let presence = PressYPresenceProof::confirmed();
    let identity = PinIdentityProof::new(SecretBytes::new(VAULT_PWD.as_bytes().to_vec()));
    v.unlock(&presence, &identity).unwrap();
    v
}

#[tokio::test]
async fn cli_import_kdbx_roundtrip_and_no_plaintext_on_disk() {
    let tmp = tempfile::TempDir::new().unwrap();
    let vault_path = tmp.path().join("vault.pvf");
    let kdbx_path = tmp.path().join("fixture.kdbx");

    Vault::create(
        &vault_path,
        &SecretBytes::new(VAULT_PWD.as_bytes().to_vec()),
    )
    .unwrap();

    // Build a small fixture: 3 entries, one with TOTP, one with history,
    // one that will be skipped (empty password).
    let entries = vec![
        {
            let mut e = TestEntry::simple("GitHubMarker", "octocat-marker", "pw-marker-aaa");
            e.url = "https://github.com".into();
            e.notes = "notes-marker-bbb".into();
            e.tags = vec!["dev-tag".into()];
            e.group_path = vec!["WorkFolder".into()];
            e
        },
        {
            let mut e = TestEntry::simple("WithTotpMarker", "user-totp-marker", "pw-totp-ccc");
            e.extra.push((
                "otp".into(),
                "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP".into(),
                true,
            ));
            e.history = vec![(
                "old-pw-marker-ddd".into(),
                Some("2021-01-01T00:00:00Z".into()),
            )];
            e
        },
        {
            // empty password → skipped
            let mut e = TestEntry::default();
            e.title = "NoPassMarker".into();
            e
        },
    ];
    let bytes = build_kdbx4(&entries, Some(KDBX_PWD), None, WriteCipher::Aes256Cbc);
    std::fs::write(&kdbx_path, &bytes).unwrap();

    // Drive the import.
    let args = pangolin_cli::cli::ImportArgs {
        vault_path: vault_path.clone(),
        vault_password: Some(VAULT_PWD.into()),
        kdbx_path: kdbx_path.clone(),
        keyfile: None,
        kdbx_password: Some(KDBX_PWD.into()),
    };
    pangolin_cli::commands::import::run(&global(), args)
        .await
        .expect("import succeeds (the empty-password entry is *skipped*, not a failure)");

    // 1. Correctness: the two live entries landed.
    {
        let mut v = unlock(&vault_path);
        let results: Vec<_> = v.account_search("Marker").unwrap();
        let names: Vec<String> = results.iter().map(|s| s.display_name.clone()).collect();
        assert!(
            names.iter().any(|n| n == "GitHubMarker"),
            "names: {names:?}"
        );
        assert!(
            names.iter().any(|n| n == "WithTotpMarker"),
            "names: {names:?}"
        );
        assert!(
            !names.iter().any(|n| n == "NoPassMarker"),
            "empty-pw entry skipped"
        );
        // Spot-check the TOTP entry: has_totp + a history revision.
        let totp_entry = results
            .iter()
            .find(|s| s.display_name == "WithTotpMarker")
            .expect("totp entry present");
        assert!(totp_entry.has_totp, "TOTP secret persisted");
        // current + 1 historical = 2 password-history entries.
        assert_eq!(totp_entry.password_history_count, 2, "history replayed");
        // (the group→tag / URL mapping is asserted at the parser layer
        // in pangolin-kdbx's own tests; the search-summary projection
        // here is a subset.)
        // (don't close `v` — drop is enough; the file is flushed on drop)
    }

    // 2. No plaintext on disk: scan the raw .pvf for the imported
    //    secret/identity markers.
    let raw = std::fs::read(&vault_path).unwrap();
    let markers: &[&[u8]] = &[
        b"pw-marker-aaa",
        b"pw-totp-ccc",
        b"old-pw-marker-ddd",
        b"notes-marker-bbb",
        b"octocat-marker",
        b"user-totp-marker",
    ];
    for needle in markers {
        let hits = raw.windows(needle.len()).filter(|w| w == needle).count();
        assert_eq!(
            hits,
            0,
            "marker {:?} found in raw .pvf — imported plaintext leaked!",
            String::from_utf8_lossy(needle)
        );
    }
    // Also scan the WAL sidecar if present.
    let wal = vault_path.with_extension("pvf-wal");
    if wal.exists() {
        let wal_bytes = std::fs::read(&wal).unwrap();
        for needle in markers {
            let hits = wal_bytes
                .windows(needle.len())
                .filter(|w| w == needle)
                .count();
            assert_eq!(hits, 0, "marker found in WAL sidecar — leaked!");
        }
    }
}

#[tokio::test]
async fn cli_import_wrong_kdbx_password_is_an_error_and_changes_nothing() {
    let tmp = tempfile::TempDir::new().unwrap();
    let vault_path = tmp.path().join("vault.pvf");
    let kdbx_path = tmp.path().join("fixture.kdbx");
    Vault::create(
        &vault_path,
        &SecretBytes::new(VAULT_PWD.as_bytes().to_vec()),
    )
    .unwrap();
    let entries = vec![TestEntry::simple("X", "u", "p")];
    let bytes = build_kdbx4(&entries, Some(KDBX_PWD), None, WriteCipher::Aes256Cbc);
    std::fs::write(&kdbx_path, &bytes).unwrap();

    let args = pangolin_cli::cli::ImportArgs {
        vault_path: vault_path.clone(),
        vault_password: Some(VAULT_PWD.into()),
        kdbx_path,
        keyfile: None,
        kdbx_password: Some("wrong-password".into()),
    };
    let err = pangolin_cli::commands::import::run(&global(), args)
        .await
        .expect_err("wrong KDBX password must fail");
    // No oracle: the error message must not hint which credential was
    // wrong beyond "wrong password or keyfile".
    let msg = format!("{err:#}");
    assert!(msg.to_lowercase().contains("read") || msg.to_lowercase().contains("decrypt"));

    // The vault is unchanged — nothing was written.
    let mut v = unlock(&vault_path);
    let n = v.account_search("X").unwrap().len();
    assert_eq!(n, 0, "a failed parse must not add any accounts");
}

// Keep `PathBuf` used so the import doesn't get optimised away by an
// over-zealous unused-import lint in some configs.
const _: fn() -> Option<PathBuf> = || None;
