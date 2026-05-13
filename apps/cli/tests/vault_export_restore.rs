// SPDX-License-Identifier: AGPL-3.0-or-later
//! MVP-1 issue 1.10 integration test: `vault create` → `account add` →
//! `vault export` → `vault restore` round trip via the `pangolin-cli`
//! binary, plus the `no_plaintext_on_disk` scan of the encrypted
//! archive and the `--plaintext` (cleartext) branch.
//!
//! Spawns the real binary (via `CARGO_BIN_EXE_pangolin-cli`), feeding
//! passwords/passphrases through stdin — never an argv flag for a
//! passphrase. Capture is via Rust pipes, never a shell pipe
//! (env-quirks #5/#6).

use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use pangolin_crypto::secret::SecretBytes;
use pangolin_store::session::{PinIdentityProof, PressYPresenceProof};
use pangolin_store::Vault;
use tempfile::TempDir;

const VAULT_PWD: &str = "round-trip-vault-master";
const EXPORT_PASSPHRASE: &str = "an-independent-strong-archive-passphrase-42";
const NEW_VAULT_PWD: &str = "the-restored-vaults-new-master";
const KNOWN_PASSWORD: &str = "ZZ-marker-password-1234567890";

fn binary_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_pangolin-cli"))
}

fn run_with_stdin(args: &[&std::ffi::OsStr], stdin: &[u8]) -> std::process::Output {
    let mut child = Command::new(binary_path())
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn pangolin-cli");
    child
        .stdin
        .as_mut()
        .expect("stdin pipe")
        .write_all(stdin)
        .expect("write stdin");
    child.wait_with_output().expect("wait")
}

fn os(s: &str) -> &std::ffi::OsStr {
    std::ffi::OsStr::new(s)
}

fn create_vault_with_account(dir: &TempDir) -> PathBuf {
    let path = dir.path().join("source.pvf");
    let out = run_with_stdin(
        &[
            os("vault"),
            os("create"),
            os("--path"),
            path.as_os_str(),
            os("--password-stdin"),
        ],
        format!("{VAULT_PWD}\n").as_bytes(),
    );
    assert!(
        out.status.success(),
        "vault create: {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Add an account with a known password (so we can scan for it).
    // The credential password comes from stdin (`--password-stdin`);
    // the vault password is the CI-acceptable `--vault-password` flag.
    let add = run_with_stdin(
        &[
            os("account"),
            os("add"),
            os("--vault-path"),
            path.as_os_str(),
            os("--vault-password"),
            os(VAULT_PWD),
            os("--name"),
            os("Marker Account"),
            os("--username"),
            os("marker-user@example.test"),
            os("--password-stdin"),
            os("--no-totp"),
        ],
        format!("{KNOWN_PASSWORD}\n").as_bytes(),
    );
    assert!(
        add.status.success(),
        "account add: {:?}",
        String::from_utf8_lossy(&add.stderr)
    );
    path
}

#[test]
fn encrypted_export_then_restore_round_trip_and_no_plaintext_on_disk() {
    let dir = TempDir::new().expect("tempdir");
    let src = create_vault_with_account(&dir);
    let archive = dir.path().join("backup.pvea");

    // vault export (encrypted): vault password via flag, export
    // passphrase via stdin.
    let exp = run_with_stdin(
        &[
            os("vault"),
            os("export"),
            os("--vault-path"),
            src.as_os_str(),
            os("--vault-password"),
            os(VAULT_PWD),
            os("--export-passphrase-stdin"),
            archive.as_os_str(),
        ],
        format!("{EXPORT_PASSPHRASE}\n").as_bytes(),
    );
    assert!(
        exp.status.success(),
        "vault export failed. stdout={} stderr={}",
        String::from_utf8_lossy(&exp.stdout),
        String::from_utf8_lossy(&exp.stderr),
    );
    assert!(archive.exists(), "archive file exists");

    // no_plaintext_on_disk: the known password must not appear in the
    // archive bytes (only ciphertext + the non-secret header).
    let bytes = std::fs::read(&archive).expect("read archive");
    assert!(
        !contains_subslice(&bytes, KNOWN_PASSWORD.as_bytes()),
        "encrypted archive leaked the plaintext password"
    );
    assert!(
        !contains_subslice(&bytes, b"Marker Account"),
        "encrypted archive leaked the plaintext display name"
    );
    // It should start with the magic.
    assert_eq!(&bytes[..12], b"PANGOLIN-VEA");

    // vault restore: archive passphrase (line 1) + new master (line 2)
    // via stdin.
    let restored = dir.path().join("restored.pvf");
    let res = run_with_stdin(
        &[
            os("vault"),
            os("restore"),
            archive.as_os_str(),
            os("--out"),
            restored.as_os_str(),
            os("--archive-passphrase-stdin"),
        ],
        format!("{EXPORT_PASSPHRASE}\n{NEW_VAULT_PWD}\n").as_bytes(),
    );
    assert!(
        res.status.success(),
        "vault restore failed. stdout={} stderr={}",
        String::from_utf8_lossy(&res.stdout),
        String::from_utf8_lossy(&res.stderr),
    );
    assert!(restored.exists(), "restored vault exists");

    // Open the restored vault under the NEW master password; the
    // account + its password must round-trip.
    let mut v = Vault::open(&restored).expect("open restored");
    let presence = PressYPresenceProof::confirmed();
    let identity = PinIdentityProof::new(SecretBytes::new(NEW_VAULT_PWD.as_bytes().to_vec()));
    v.unlock(&presence, &identity).expect("unlock restored");
    let ids = v.list_accounts();
    assert_eq!(ids.len(), 1, "one account in the restored vault");
    let pw = v
        .reveal_current_password(ids[0], &PressYPresenceProof::confirmed())
        .expect("reveal");
    assert_eq!(
        pw.expose(),
        KNOWN_PASSWORD.as_bytes(),
        "restored password matches"
    );
    v.close().expect("close");
}

#[test]
fn wrong_archive_passphrase_fails_cleanly() {
    let dir = TempDir::new().expect("tempdir");
    let src = create_vault_with_account(&dir);
    let archive = dir.path().join("backup.pvea");
    let exp = run_with_stdin(
        &[
            os("vault"),
            os("export"),
            os("--vault-path"),
            src.as_os_str(),
            os("--vault-password"),
            os(VAULT_PWD),
            os("--export-passphrase-stdin"),
            archive.as_os_str(),
        ],
        format!("{EXPORT_PASSPHRASE}\n").as_bytes(),
    );
    assert!(exp.status.success());

    let restored = dir.path().join("restored.pvf");
    let res = run_with_stdin(
        &[
            os("vault"),
            os("restore"),
            archive.as_os_str(),
            os("--out"),
            restored.as_os_str(),
            os("--archive-passphrase-stdin"),
        ],
        format!("WRONG-PASSPHRASE\n{NEW_VAULT_PWD}\n").as_bytes(),
    );
    assert!(
        !res.status.success(),
        "restore with wrong passphrase must fail"
    );
    assert!(
        !restored.exists(),
        "no vault file written on a failed restore"
    );
}

#[test]
fn tampered_archive_fails_restore() {
    let dir = TempDir::new().expect("tempdir");
    let src = create_vault_with_account(&dir);
    let archive = dir.path().join("backup.pvea");
    let exp = run_with_stdin(
        &[
            os("vault"),
            os("export"),
            os("--vault-path"),
            src.as_os_str(),
            os("--vault-password"),
            os(VAULT_PWD),
            os("--export-passphrase-stdin"),
            archive.as_os_str(),
        ],
        format!("{EXPORT_PASSPHRASE}\n").as_bytes(),
    );
    assert!(exp.status.success());
    // Flip the last ciphertext byte.
    let mut bytes = std::fs::read(&archive).expect("read");
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    std::fs::write(&archive, &bytes).expect("rewrite");

    let restored = dir.path().join("restored.pvf");
    let res = run_with_stdin(
        &[
            os("vault"),
            os("restore"),
            archive.as_os_str(),
            os("--out"),
            restored.as_os_str(),
            os("--archive-passphrase-stdin"),
        ],
        format!("{EXPORT_PASSPHRASE}\n{NEW_VAULT_PWD}\n").as_bytes(),
    );
    assert!(
        !res.status.success(),
        "restore of a tampered archive must fail"
    );
    assert!(!restored.exists());
}

#[test]
fn plaintext_export_writes_cleartext_with_banner() {
    let dir = TempDir::new().expect("tempdir");
    let src = create_vault_with_account(&dir);
    let out = dir.path().join("dump.pvtxt");
    // --plaintext: confirmation phrase, then (--no-delay skips the 30s),
    // then `y`. All on stdin.
    let res = run_with_stdin(
        &[
            os("vault"),
            os("export"),
            os("--vault-path"),
            src.as_os_str(),
            os("--vault-password"),
            os(VAULT_PWD),
            os("--plaintext"),
            os("--no-delay"),
            out.as_os_str(),
        ],
        b"i understand\ny\n",
    );
    assert!(
        res.status.success(),
        "plaintext export failed. stdout={} stderr={}",
        String::from_utf8_lossy(&res.stdout),
        String::from_utf8_lossy(&res.stderr),
    );
    let body = std::fs::read_to_string(&out).expect("read plaintext dump");
    assert!(
        body.contains("CONTAINS YOUR VAULT PASSWORDS IN CLEARTEXT"),
        "plaintext dump must carry the in-file warning banner"
    );
    assert!(
        body.contains(KNOWN_PASSWORD),
        "plaintext dump must contain the cleartext password"
    );
    assert!(
        body.contains("Marker Account"),
        "plaintext dump must contain the display name"
    );
}

#[test]
fn plaintext_export_aborts_on_wrong_confirmation() {
    let dir = TempDir::new().expect("tempdir");
    let src = create_vault_with_account(&dir);
    let out = dir.path().join("dump.pvtxt");
    let res = run_with_stdin(
        &[
            os("vault"),
            os("export"),
            os("--vault-path"),
            src.as_os_str(),
            os("--vault-password"),
            os(VAULT_PWD),
            os("--plaintext"),
            os("--no-delay"),
            out.as_os_str(),
        ],
        b"nope\ny\n",
    );
    assert!(
        !res.status.success(),
        "plaintext export must abort on a wrong confirmation phrase"
    );
    assert!(
        !out.exists(),
        "no file written when the confirmation phrase did not match"
    );
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}
