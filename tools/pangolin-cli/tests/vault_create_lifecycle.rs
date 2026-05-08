//! P11B-2 integration test: `vault create` → `account add` round
//! trip via the `pangolin-cli` binary.
//!
//! Plan §"Test plan" line item
//! `vault_create_then_account_add_round_trip`. Spawns the
//! `pangolin-cli` binary (via Cargo's
//! `CARGO_BIN_EXE_pangolin-cli` env-var) with
//! `vault create --path <tmp> --password-stdin`, pipes the
//! master password through stdin, then re-spawns the same binary
//! with `account add` against the freshly-created vault. Asserts
//! both subprocesses exit 0 and the vault contains exactly one
//! account afterwards.
//!
//! ## Why a real subprocess (not a library-entry-point invocation)
//!
//! The `commands::vault::run` library function is unit-tested in
//! `commands/vault.rs::tests` via the `cfg(test)`-only
//! `WithInjectedPassword` thread-local seam, which an integration
//! test (compiled as a separate crate) cannot reach. The
//! load-bearing property pinned here is the FULL CLI surface:
//! that the binary, invoked exactly as a user / CI would invoke
//! it, produces a vault file that the same binary's `account
//! add` subcommand can consume. A library-only round-trip would
//! miss the binary-shell layer (clap arg parsing, stdin
//! redirection, exit-code semantics).
//!
//! ## Why `account add --vault-password` (not `--password-stdin`)
//!
//! `account add` reads the vault password from `--vault-password
//! <flag>` if the flag is present, OR from `rpassword` (no
//! `--password-stdin` for the VAULT password is supported on
//! `account add`; that flag is for the per-row credential
//! password). The flag form is acceptable in CI scripts where
//! the script's process-listing exposure is bounded by the same
//! filesystem permissions that protect the script itself.
//! Mirrors the existing `account_lifecycle.rs` integration-test
//! pattern.

use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use pangolin_crypto::secret::SecretBytes;
use pangolin_store::session::{PinIdentityProof, PressYPresenceProof};
use pangolin_store::Vault;
use tempfile::TempDir;

const TEST_PWD: &str = "round-trip-master-password";

fn binary_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_pangolin-cli"))
}

/// **P11B-2 / Plan §Test plan.** End-to-end CLI round trip:
///
/// 1. Spawn `pangolin-cli vault create --path <tmp>
///    --password-stdin` with `TEST_PWD` piped to stdin. Assert
///    exit 0 and the vault file exists.
/// 2. Re-open the vault via the library API (using the same
///    `TEST_PWD`) and confirm it unlocks cleanly. Verifies the
///    binary actually produced a valid Pangolin vault under the
///    supplied password.
/// 3. Spawn `pangolin-cli account add --vault-path <tmp>
///    --vault-password <TEST_PWD> --name <...> --generate-password
///    --no-totp`. Assert exit 0.
/// 4. Re-open + unlock + verify the new account is queryable.
///
/// The structural property pinned by this test: a vault produced
/// by the CLI's `vault create` verb is immediately consumable by
/// the CLI's `account add` verb under the same password — the
/// non-author developer's first interaction with Pangolin no
/// longer needs the `Vault::create` library escape hatch.
#[test]
fn vault_create_then_account_add_round_trip() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("round-trip.pvf");

    // --- 1. vault create via the binary, password piped via stdin. ---
    let mut child = Command::new(binary_path())
        .arg("vault")
        .arg("create")
        .arg("--path")
        .arg(&path)
        .arg("--password-stdin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn pangolin-cli vault create");
    {
        let stdin = child.stdin.as_mut().expect("stdin pipe");
        stdin
            .write_all(TEST_PWD.as_bytes())
            .expect("write password");
        stdin.write_all(b"\n").expect("write newline");
    }
    let create_out = child.wait_with_output().expect("wait vault create");
    assert!(
        create_out.status.success(),
        "vault create exited non-zero. stdout={} stderr={}",
        String::from_utf8_lossy(&create_out.stdout),
        String::from_utf8_lossy(&create_out.stderr),
    );
    let stdout = String::from_utf8(create_out.stdout).expect("stdout utf8");
    assert!(
        stdout.contains("vault created at"),
        "expected success line on stdout, got: {stdout}"
    );
    assert!(path.exists(), "vault file exists after vault create");

    // --- 2. Re-open + unlock via the library to confirm the
    //        password the CLI used actually unlocks the produced
    //        vault. ---
    {
        let mut v = Vault::open(&path).expect("open after vault create");
        let presence = PressYPresenceProof::confirmed();
        let identity = PinIdentityProof::new(SecretBytes::new(TEST_PWD.as_bytes().to_vec()));
        v.unlock(&presence, &identity)
            .expect("unlock with the password the CLI used");
        v.close().expect("close");
    }

    // --- 3. account add via the binary against the freshly-created
    //        vault. The flag-form `--vault-password` is the
    //        acceptable CI shape (file-scoped exposure, not
    //        process-listing exposure beyond the user's own
    //        argv visibility). `--generate-password` + `--no-totp`
    //        avoid `rpassword` calls in the headless test run. ---
    let add_out = Command::new(binary_path())
        .arg("account")
        .arg("add")
        .arg("--vault-path")
        .arg(&path)
        .arg("--vault-password")
        .arg(TEST_PWD)
        .arg("--name")
        .arg("round-trip-account")
        .arg("--generate-password")
        .arg("--no-totp")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn account add");
    assert!(
        add_out.status.success(),
        "account add exited non-zero. stdout={} stderr={}",
        String::from_utf8_lossy(&add_out.stdout),
        String::from_utf8_lossy(&add_out.stderr),
    );

    // --- 4. Re-open + unlock + verify the new account is queryable. ---
    let mut v = Vault::open(&path).expect("re-open");
    let presence = PressYPresenceProof::confirmed();
    let identity = PinIdentityProof::new(SecretBytes::new(TEST_PWD.as_bytes().to_vec()));
    v.unlock(&presence, &identity).expect("re-unlock");
    let ids = v.list_accounts();
    assert_eq!(
        ids.len(),
        1,
        "exactly one account in the round-trip vault after add"
    );
    v.close().expect("close");
}
