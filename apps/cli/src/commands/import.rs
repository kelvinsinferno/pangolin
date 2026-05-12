// SPDX-License-Identifier: AGPL-3.0-or-later
//! `pangolin-cli import <file.kdbx>` — import a `KeePass` 2.x `.kdbx`
//! into an unlocked vault (MVP-1 issue 1.9, Q-e / L16).
//!
//! Prompts for the KDBX file's own password on stderr (via the
//! existing `rpassword` helper), parses + decrypts via `pangolin-kdbx`,
//! and ingests each mapped entry through `Vault::account_add` (+ the
//! `<History>` replay via `account_update`). The import counts —
//! imported / skipped / per-category failures — go to **stdout**; the
//! password prompt and all diagnostics go to **stderr**. Exit code is
//! non-zero if any entry failed.
//!
//! Secret discipline: the KDBX password / parsed credential bytes never
//! touch stdout; the printed counts + `failure_kinds` are non-secret
//! category labels only.

#![allow(clippy::doc_markdown)]

use anyhow::{Context, Result};
use pangolin_crypto::secret::SecretBytes;
use zeroize::Zeroizing;

use crate::cli::{GlobalArgs, ImportArgs};
use crate::vault_open::open_and_unlock;

/// Run the `import` subcommand.
#[allow(clippy::unused_async)]
pub async fn run(global: &GlobalArgs, args: ImportArgs) -> Result<()> {
    // 1. Open + unlock the destination vault.
    let mut vault = open_and_unlock(&args.vault_path, args.vault_password.as_deref())
        .context("vault open + unlock failed")?;

    // 2. Gather the KDBX credentials. The KDBX password is read without
    //    echo (prompt on stderr) unless --kdbx-password was supplied.
    let kdbx_pw: Zeroizing<String> = match args.kdbx_password {
        Some(p) => Zeroizing::new(p),
        None => Zeroizing::new(
            rpassword::prompt_password("KeePass (.kdbx) password: ")
                .context("failed to read KDBX password")?,
        ),
    };
    let keyfile_bytes: Option<Vec<u8>> = match &args.keyfile {
        Some(p) => {
            // Cap the keyfile size before reading — a realistic keyfile
            // is a few KiB; reuse the `.kdbx` ceiling so a giant path
            // can't OOM us.
            if let Ok(meta) = std::fs::metadata(p) {
                anyhow::ensure!(
                    meta.len() <= pangolin_kdbx::KDBX_MAX_FILE_BYTES as u64,
                    "keyfile {} is too large (max {} bytes)",
                    p.display(),
                    pangolin_kdbx::KDBX_MAX_FILE_BYTES
                );
            }
            Some(
                std::fs::read(p)
                    .with_context(|| format!("failed to read keyfile {}", p.display()))?,
            )
        }
        None => None,
    };
    let creds = pangolin_kdbx::KdbxCredentials {
        password: if kdbx_pw.is_empty() {
            None
        } else {
            Some(Zeroizing::new(kdbx_pw.as_bytes().to_vec()))
        },
        keyfile: keyfile_bytes.map(Zeroizing::new),
    };
    drop(kdbx_pw);

    // 3. Parse + decrypt + map.
    let map_result = pangolin_kdbx::import_kdbx_path(&args.kdbx_path, &creds)
        .context("failed to read/decrypt the .kdbx file")?;
    drop(creds);

    // 4. Ingest.
    let mut imported: u64 = 0;
    let mut failed: u64 = 0;
    let mut skipped: u64 = map_result.recycle_bin_entries as u64;
    let mut failure_kinds: Vec<String> = Vec::new();
    let push_kind = |k: &str, kinds: &mut Vec<String>| {
        if !kinds.iter().any(|x| x == k) {
            kinds.push(k.to_string());
        }
    };
    for s in &map_result.skipped {
        skipped += 1;
        push_kind(s.kind_label(), &mut failure_kinds);
    }
    for entry in map_result.entries {
        match ingest_one(&mut vault, entry) {
            Ok(()) => imported += 1,
            Err(e) => {
                failed += 1;
                let label = match &e {
                    pangolin_store::StoreError::Validation { kind, .. } => {
                        format!("validation_{kind}")
                    }
                    _ => "store_error".to_string(),
                };
                push_kind(&label, &mut failure_kinds);
            }
        }
    }
    vault.close().context("Vault::close failed")?;

    // 5. Report — counts to stdout.
    if global.json {
        let summary = serde_json::json!({
            "outcome": "imported",
            "imported": imported,
            "skipped": skipped,
            "failed": failed,
            "failure_kinds": failure_kinds,
        });
        println!("{summary}");
    } else {
        println!("imported {imported}");
        println!("skipped {skipped}");
        println!("failed {failed}");
        if !failure_kinds.is_empty() {
            println!("failure_kinds {}", failure_kinds.join(","));
        }
    }
    eprintln!("import complete: {imported} added, {skipped} skipped, {failed} failed");

    if failed > 0 {
        anyhow::bail!(
            "{failed} entr{} failed to import (see failure_kinds above)",
            if failed == 1 { "y" } else { "ies" }
        );
    }
    Ok(())
}

/// Ingest one mapped entry into the vault: `account_add` the current
/// state, then replay the historical passwords (oldest→newest).
fn ingest_one(
    vault: &mut pangolin_store::Vault,
    entry: pangolin_kdbx::MappedEntry,
) -> Result<(), pangolin_store::StoreError> {
    let pangolin_kdbx::MappedEntry {
        display_name,
        usernames,
        urls,
        notes,
        password,
        totp,
        tags,
        history_passwords,
    } = entry;

    let (totp_secret, totp_params) = match totp {
        Some(t) => (
            SecretBytes::new(t.secret_bytes.to_vec()),
            pangolin_store::TotpParams {
                algorithm: t.params.algorithm,
                digits: t.params.digits,
                period_seconds: t.params.period_seconds,
            },
        ),
        None => (
            SecretBytes::new(Vec::new()),
            pangolin_store::TotpParams::default(),
        ),
    };

    // Install the OLDEST historical password as the genesis, replay the
    // remaining historical passwords best-effort, then **always** apply
    // the current password last (its failure is the entry's failure) —
    // mirrors the FFI copy. Without the unconditional final update, a
    // mid-replay failure would silently leave an old historical password
    // as the account head.
    let (genesis_pw, historical_rotations): (Vec<u8>, Vec<Vec<u8>>) =
        if history_passwords.is_empty() {
            (password.to_vec(), Vec::new())
        } else {
            let mut iter = history_passwords.iter();
            let genesis = iter.next().expect("non-empty").0.to_vec();
            let rot: Vec<Vec<u8>> = iter.map(|(p, _)| p.to_vec()).collect();
            (genesis, rot)
        };

    let draft = pangolin_store::AccountIdentityDraft {
        schema_version: pangolin_store::ACCOUNT_IDENTITY_SCHEMA_VERSION,
        display_name,
        tags,
        usernames,
        urls,
        notes,
        password: SecretBytes::new(genesis_pw),
        totp_secret,
        totp_params,
    };
    let id = vault.account_add(draft)?;

    let mk_patch = |pw: Vec<u8>| pangolin_store::AccountIdentityPatch {
        schema_version: pangolin_store::ACCOUNT_IDENTITY_SCHEMA_VERSION,
        display_name: None,
        tags: None,
        usernames: None,
        urls: None,
        notes: None,
        password: Some(SecretBytes::new(pw)),
        totp_secret: None,
        totp_params: None,
    };

    for pw in historical_rotations {
        if vault.account_update(id, mk_patch(pw)).is_err() {
            break;
        }
    }
    if !history_passwords.is_empty() {
        vault.account_update(id, mk_patch(password.to_vec()))?;
    }
    Ok(())
}
