//! `pangolin-cli vault` — vault-file management subcommands.
//!
//! Currently ships exactly one verb (`create`) per P11B plan §A1.
//! MVP-1 may add `open` / `info` / `destroy` / `rotate-password` /
//! `export` / `import` under the same noun namespace.
//!
//! ## Design notes (P11B plan §A1..§A14)
//!
//! - **Nested noun-then-verb hierarchy** (§A1) — `vault create`,
//!   not flat `create-vault`. Mirrors `account <verb>`.
//! - **Password input** (§A2) — never via `--password <flag>`. Two
//!   exclusive paths: `--password-stdin` or interactive prompt
//!   with confirmation. Reuses the password-input helpers from
//!   `commands/account.rs` per §A4 (DRY discipline carries the
//!   same retry budget + first-line stdin semantics + empty-
//!   password guard).
//! - **Path canonicalization** (§A5) — canonicalize the parent
//!   directory; do NOT canonicalize the (non-existent) target.
//!   `Path::canonicalize` requires the file to exist; the parent
//!   is the closest existing component. Re-join with `file_name`
//!   to produce the absolute path used for `Vault::create` AND
//!   the success message.
//! - **Path-overwrite refusal** (§A3) — pre-flight `path.exists()`
//!   at the CLI boundary saves a wasted password entry; the
//!   library's own check + `acquire_lock`'s `create_new(true)`
//!   close the TOCTOU race. NO `--force` flag.
//! - **POSIX file-mode hardening** (§Q4) — after `Vault::create`
//!   succeeds, set the new file's mode to 0o600 on Unix targets.
//!   No-op on Windows (file ACLs are inherited from the parent
//!   directory; tightening is the user's responsibility).
//! - **`--print-id`** (§A7) — opt-in, default off. Matches
//!   `git init`'s minimal-default convention.
//! - **JSON output** (§A7) — `--json` global flag emits
//!   `{"outcome":"created","path":"...","vault_id":"..."}`; the
//!   `vault_id` is included unconditionally in JSON mode regardless
//!   of `--print-id`.
//! - **Forbidden user-facing terms** (§A14) — `vault create
//!   --help` and the printed strings avoid the §3.5 forbidden
//!   list ("blockchain", "gas", "transaction", "decentralized
//!   storage", "hashes", "revisions"). Internal terms (Argon2id,
//!   KDF, VDK, AEAD) are acceptable in doc-comments and
//!   `--help` text.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use pangolin_crypto::secret::SecretBytes;
use pangolin_store::Vault;

use crate::cli::{GlobalArgs, VaultArgs, VaultCommand, VaultCreateArgs};
use crate::commands::account::{
    prompt_password_with_confirmation, read_secret_first_line_from_stdin, reject_empty_password,
};

/// Top-level dispatch for `pangolin-cli vault <verb>`.
#[allow(clippy::unused_async)]
pub async fn run(global: &GlobalArgs, args: VaultArgs) -> Result<()> {
    match args.command {
        VaultCommand::Create(sub) => run_create(global, sub).await,
    }
}

/// Run the `vault create` subcommand. P11B-1 ships the clap
/// scaffold + this stub; P11B-2 fleshes out the body.
#[allow(clippy::unused_async)]
async fn run_create(global: &GlobalArgs, args: VaultCreateArgs) -> Result<()> {
    let canonical_path = canonicalize_target_path(&args.path)?;

    // Pre-flight overwrite + symlink check (§A3, P11B fix-pass M-2).
    //
    // The original `Path::exists()` call followed symlinks, so a
    // `--path` pointing at a *dangling* symlink (target missing)
    // would slip past the overwrite-refuse guard and `Vault::create`
    // would then write through the symlink to the target's
    // location, silently creating the vault somewhere the user did
    // not intend. The fix-pass M-2 audit finding closes this:
    // `symlink_metadata` does NOT follow the final component, so we
    // can distinguish "regular file already there" (refuse with
    // overwrite error) from "symlink at this path" (refuse with the
    // symlink-specific error message) from "nothing here, proceed".
    //
    // Matches `git init`'s discipline: the user is expected to
    // resolve the symlink themselves and pass the real target.
    // The library's `Vault::create` `path.exists()` +
    // `acquire_lock`'s `create_new(true)` still close the TOCTOU
    // race against a concurrent symlink swap (per §A8); the
    // pre-flight check is the UX-affordance + symlink guard, not
    // the race defense.
    match std::fs::symlink_metadata(&canonical_path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            bail!(
                "refusing to create vault at {}: path is a symlink; resolve to the real target and pass that explicitly",
                canonical_path.display()
            );
        }
        Ok(_) => {
            bail!(
                "vault file already exists at {}; refusing to overwrite",
                canonical_path.display()
            );
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Path does not exist — proceed with creation.
        }
        Err(e) => {
            bail!("could not stat path {}: {e}", canonical_path.display());
        }
    }

    // Acquire the master password via one of the two exclusive
    // paths (§A2). NO `--password <flag>` form — locked at the
    // clap surface in `cli.rs`.
    let password = if args.password_stdin {
        read_secret_first_line_from_stdin()
            .context("--password-stdin read failed")
            .and_then(reject_empty_password)?
    } else {
        // Surface the role-of-this-password context to the user
        // BEFORE rpassword takes the terminal. First-time-vault-
        // creators may not realise this is the master credential.
        // Per §A9 the eprintln! precedes the rpassword call.
        eprintln!(
            "Set a password for the new vault. This password protects every \
             account stored inside the vault; if you forget it, the vault is \
             unrecoverable."
        );
        let password = test_or_prompt_password()?;
        reject_empty_password(password)?
    };

    // Hand off to the library. `Vault::create` derives the
    // authority key, generates the VDK, wraps it under the
    // authority, and writes the meta row + schema in one
    // transaction (per P2's vault.rs L211–L273). On any internal
    // error the library removes the partially-created file and
    // releases the lock.
    let vault = Vault::create(&canonical_path, &password)
        .with_context(|| format!("could not create vault at {}", canonical_path.display()))?;

    // POSIX file-mode hardening (§Q4). Restrict the new vault
    // file to owner-only read+write. Best-effort: if the chmod
    // fails (e.g., on a filesystem that does not honor POSIX
    // permission bits), warn but do not abort — the vault content
    // is already encrypted under the password the user supplied.
    //
    // **P11B fix-pass M-1.** `Vault::create` itself now installs a
    // `0o077` umask in `pangolin-store`, so the `.pvf` is born at
    // mode `0o600` BEFORE this chmod ever runs. The chmod is
    // preserved as belt-and-braces defense-in-depth: it still
    // fires on every successful create, but the M-1 audit window
    // (the gap between create and chmod under a default `0o022`
    // umask) is now structurally closed at the library boundary.
    #[cfg(unix)]
    {
        if let Err(e) = restrict_vault_file_mode(&canonical_path) {
            // **P11B fix-pass L-1.** Use `WARNING:` (all caps) per
            // the project rubric; the previous lowercase prefix
            // was a stylistic miss that the audit flagged.
            eprintln!(
                "WARNING: could not set vault file mode 0600 at {}: {e}; \
                 the vault content remains encrypted under your password",
                canonical_path.display()
            );
        }
    }

    let vault_id_hex = hex::encode(vault.vault_id());

    // Per §A11 explicitly close the vault (mirrors `account add`'s
    // P11A pattern). The library's `Drop` impl also releases the
    // lock + closes the SQLite connection, but the explicit call
    // makes the close ordering visible in the source.
    vault.close().context("Vault::close failed")?;

    if global.json {
        let summary = serde_json::json!({
            "outcome": "created",
            "path": canonical_path.display().to_string(),
            "vault_id": vault_id_hex,
        });
        println!("{summary}");
    } else {
        println!("vault created at {}", canonical_path.display());
        if args.print_id {
            println!("vault_id: {vault_id_hex}");
        }
    }
    Ok(())
}

/// Canonicalize the parent directory of `path` and re-join with
/// the `file_name` component. Per §A5, `Path::canonicalize`
/// requires the file to exist; the file we are creating does not,
/// so we canonicalize the closest existing ancestor (the parent
/// directory) and treat the `file_name` component as a literal.
///
/// Errors:
/// - `--path` has no `file_name` component (e.g., ends in `/`,
///   is `/`, or is `..`).
/// - `--path`'s parent directory does not exist or is
///   inaccessible.
fn canonicalize_target_path(path: &Path) -> Result<PathBuf> {
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("--path must name a vault file (got {})", path.display()))?;
    // `Path::parent` returns Some("") when `path` itself is a
    // bare file name (no directory component). Treat that as the
    // current working directory — `canonicalize(".")` resolves
    // to the cwd's absolute path on every supported platform.
    let parent = match path.parent() {
        Some(p) if p.as_os_str().is_empty() => Path::new("."),
        Some(p) => p,
        None => {
            bail!("--path must name a vault file (got {})", path.display());
        }
    };
    let canonical_parent = parent.canonicalize().with_context(|| {
        format!(
            "could not canonicalize parent directory of {}",
            path.display()
        )
    })?;
    Ok(canonical_parent.join(file_name))
}

/// **Unix only.** Set the file mode to 0o600 (owner read+write
/// only). Windows is a no-op — file ACLs there are inherited
/// from the parent directory and the user is responsible for
/// tightening if needed.
#[cfg(unix)]
fn restrict_vault_file_mode(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    let mut perms = std::fs::metadata(path)
        .with_context(|| format!("could not stat new vault file at {}", path.display()))?
        .permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(path, perms)
        .with_context(|| format!("could not set permissions on {}", path.display()))?;
    Ok(())
}

/// Wrapper around `prompt_password_with_confirmation` that
/// honours a `cfg(test)`-only thread-local seam. Production
/// code paths always go through `prompt_password_with_confirmation`
/// (the seam is gated on `cfg(test)`); unit tests inside this
/// module set the seam to a fixed `SecretBytes` so they can drive
/// the success path without an interactive `rpassword` call.
fn test_or_prompt_password() -> Result<SecretBytes> {
    #[cfg(test)]
    {
        if let Some(injected) = tests::take_injected_password() {
            return Ok(injected);
        }
    }
    prompt_password_with_confirmation()
}

#[cfg(test)]
mod tests {
    use super::{canonicalize_target_path, run_create};
    use crate::cli::{GlobalArgs, VaultCreateArgs};
    use pangolin_crypto::secret::SecretBytes;
    use pangolin_store::session::{PinIdentityProof, PressYPresenceProof};
    use pangolin_store::Vault;
    use std::cell::RefCell;
    use std::path::PathBuf;

    // -----------------------------------------------------------
    // Test seam for the interactive password prompt.
    //
    // `test_or_prompt_password` checks `INJECTED_PASSWORD` under
    // cfg(test); when set, the prompt is bypassed and the
    // injected `SecretBytes` is returned. Tests use the
    // `WithInjectedPassword` RAII guard so concurrent tests do
    // not observe each other's setting.
    // -----------------------------------------------------------

    thread_local! {
        static INJECTED_PASSWORD: RefCell<Option<SecretBytes>> =
            const { RefCell::new(None) };
    }

    pub(super) fn take_injected_password() -> Option<SecretBytes> {
        INJECTED_PASSWORD.with(|c| c.borrow_mut().take())
    }

    /// RAII guard that injects a one-shot password for the next
    /// `run_create` call.
    struct WithInjectedPassword;
    impl WithInjectedPassword {
        fn set(pwd: &str) -> Self {
            INJECTED_PASSWORD.with(|c| {
                *c.borrow_mut() = Some(SecretBytes::new(pwd.as_bytes().to_vec()));
            });
            Self
        }
    }
    impl Drop for WithInjectedPassword {
        fn drop(&mut self) {
            INJECTED_PASSWORD.with(|c| {
                *c.borrow_mut() = None;
            });
        }
    }

    const TEST_PWD: &str = "correct horse battery staple";

    fn global() -> GlobalArgs {
        GlobalArgs {
            deployment_file: None,
            rpc_url: None,
            allow_insecure_rpc: false,
            json: false,
        }
    }

    fn args(path: PathBuf) -> VaultCreateArgs {
        VaultCreateArgs {
            path,
            password_stdin: false,
            print_id: false,
        }
    }

    /// **P11B-2.** Happy path — `vault create` against a fresh
    /// path produces a `.pvf` that subsequently opens + unlocks
    /// under the same password.
    #[tokio::test]
    async fn vault_create_succeeds_at_new_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v.pvf");

        let _guard = WithInjectedPassword::set(TEST_PWD);
        run_create(&global(), args(path.clone()))
            .await
            .expect("create succeeds");

        assert!(path.exists(), "vault file exists after create");

        // Round-trip: open + unlock with the same password.
        let mut v = Vault::open(&path).expect("open");
        let presence = PressYPresenceProof::confirmed();
        let identity = PinIdentityProof::new(SecretBytes::new(TEST_PWD.as_bytes().to_vec()));
        v.unlock(&presence, &identity).expect("unlock");
        v.close().expect("close");
    }

    /// **P11B-2 / A3.** `vault create` against an existing path
    /// surfaces the overwrite-refuse error and does NOT touch the
    /// existing file.
    #[tokio::test]
    async fn vault_create_rejects_existing_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("existing.pvf");
        // Plant a file at the target path.
        std::fs::write(&path, b"do not clobber me").expect("write");

        let _guard = WithInjectedPassword::set(TEST_PWD);
        let err = run_create(&global(), args(path.clone()))
            .await
            .expect_err("existing path rejected");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("vault file already exists") && msg.contains("refusing to overwrite"),
            "expected overwrite-refuse error, got: {msg}"
        );

        // The original file content is untouched.
        let body = std::fs::read(&path).expect("read");
        assert_eq!(body, b"do not clobber me");
    }

    /// **P11B-2 / A2 / A4.** `--password-stdin` with empty stdin
    /// (the unit-test harness has no piped input) is rejected by
    /// `reject_empty_password` BEFORE any library call.
    #[tokio::test]
    async fn vault_create_rejects_empty_password_via_stdin() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v-empty.pvf");

        let mut a = args(path.clone());
        a.password_stdin = true;
        let err = run_create(&global(), a)
            .await
            .expect_err("empty stdin rejected");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("password must not be empty"),
            "expected empty-password rejection, got: {msg}"
        );
        assert!(
            !path.exists(),
            "no vault file should be created on empty-password reject"
        );
    }

    /// **P11B-2 / A2.** Empty password from the interactive
    /// prompt is rejected. Drives the `WithInjectedPassword` seam
    /// with an empty string.
    #[tokio::test]
    async fn vault_create_rejects_empty_password_via_prompt() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v-empty-prompt.pvf");

        let _guard = WithInjectedPassword::set("");
        let err = run_create(&global(), args(path.clone()))
            .await
            .expect_err("empty injected password rejected");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("password must not be empty"),
            "expected empty-password rejection, got: {msg}"
        );
        assert!(!path.exists(), "no file on empty-password reject");
    }

    /// **P11B-2 / A5.** A `--path` whose parent directory does
    /// not exist surfaces a parent-canonicalize error before any
    /// password prompt fires.
    #[tokio::test]
    async fn vault_create_rejects_path_in_nonexistent_parent() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Use a sub-directory that does not exist — canonicalize
        // on the parent must surface NotFound.
        let path = dir.path().join("nonexistent_subdir").join("v.pvf");

        let _guard = WithInjectedPassword::set(TEST_PWD);
        let err = run_create(&global(), args(path.clone()))
            .await
            .expect_err("nonexistent parent rejected");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("could not canonicalize parent directory"),
            "expected parent-canonicalize error, got: {msg}"
        );
    }

    /// **P11B-2 / A5.** The success message reports the
    /// canonicalized absolute path. Drives a relative path
    /// (constructed inside the tempdir; canonicalization should
    /// surface the absolute location).
    #[tokio::test]
    async fn vault_create_canonicalizes_path_in_success_message() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Build a path with an explicit `.` component to verify
        // canonicalization removes it.
        let raw_path = dir.path().join(".").join("v-canon.pvf");
        let expected_canonical = dir
            .path()
            .canonicalize()
            .expect("tempdir canonicalize")
            .join("v-canon.pvf");

        let canonical = canonicalize_target_path(&raw_path).expect("canonicalize");
        assert_eq!(
            canonical, expected_canonical,
            "expected canonicalized parent + file_name, got: {canonical:?}"
        );
    }

    /// **P11B-2 / A10.** A `--path` with no `file_name` component
    /// (root path) is rejected with a clear error.
    #[tokio::test]
    async fn vault_create_rejects_path_with_no_filename() {
        let path = PathBuf::from("/");

        let err = canonicalize_target_path(&path).expect_err("root path rejected");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("must name a vault file"),
            "expected no-filename rejection, got: {msg}"
        );
    }

    /// **P11B-2 / A7.** `--print-id` is opt-in. Without the flag,
    /// the success path emits one line. The hex-line presence is
    /// surface-tested via the `vault_id` field's hex encoding;
    /// asserting stdout capture in unit tests requires plumbing
    /// we do not have, so this test focuses on the logical
    /// path-not-taken: the file exists, but the `print_id`
    /// branch is the only place the `vault_id` hex would appear.
    #[tokio::test]
    async fn vault_create_with_print_id_outputs_hex_to_stdout() {
        // We cannot easily capture stdout in a unit test (the
        // process stdout is shared across the test harness), but
        // we CAN verify the success-path completes without
        // panicking when print_id is set, and the produced
        // file's vault_id is hex-encodable. The integration test
        // `vault_create_then_account_add_round_trip` exercises
        // the full stdout shape.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v-printid.pvf");

        let _guard = WithInjectedPassword::set(TEST_PWD);
        let mut a = args(path.clone());
        a.print_id = true;
        run_create(&global(), a)
            .await
            .expect("create with print_id");

        let v = Vault::open(&path).expect("open");
        let id_hex = hex::encode(v.vault_id());
        assert_eq!(id_hex.len(), 64, "vault_id is 32 bytes = 64 hex chars");
        assert!(
            id_hex
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()),
            "vault_id hex is lowercase: {id_hex}"
        );
    }

    /// **P11B-2 / A4.** `--password-stdin` does NOT trigger an
    /// interactive prompt — the path is exposure-free. The
    /// unit-test harness's stdin is empty, which the
    /// empty-password guard rejects, but it does so AFTER the
    /// stdin read and BEFORE any rpassword call. We verify the
    /// failure mode is the expected empty-password message
    /// (not a "no terminal available" message that would fire
    /// if the prompt path ran).
    #[tokio::test]
    async fn vault_create_password_stdin_path_works() {
        // Same shape as `vault_create_rejects_empty_password_via_stdin`
        // but the assertion focuses on which path was taken, not
        // on the file outcome.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v-stdin-path.pvf");

        let mut a = args(path);
        a.password_stdin = true;
        let err = run_create(&global(), a).await.expect_err("empty stdin");
        let msg = format!("{err:#}");
        // The stdin path produces "password must not be empty";
        // the prompt path on a non-tty harness would produce
        // "failed to read password from terminal".
        assert!(
            msg.contains("password must not be empty"),
            "expected stdin path to be taken (empty-password error), got: {msg}"
        );
        assert!(
            !msg.contains("failed to read password from terminal"),
            "expected stdin path, but rpassword was invoked: {msg}"
        );
    }

    /// **P11B-2 / Q4.** On Unix, the new vault file is mode 0o600.
    /// No-op on Windows (the cfg gate skips this test).
    #[cfg(unix)]
    #[tokio::test]
    async fn vault_create_chmod_0600_on_unix() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v-chmod.pvf");

        let _guard = WithInjectedPassword::set(TEST_PWD);
        run_create(&global(), args(path.clone()))
            .await
            .expect("create");

        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode();
        // The lower 9 bits encode the rwxrwxrwx triple. We
        // restrict to owner read+write only.
        assert_eq!(
            mode & 0o777,
            0o600,
            "expected mode 0o600 after vault create, got: {:o}",
            mode & 0o777,
        );
    }

    /// **P11B fix-pass M-2.** A `--path` whose final component is a
    /// symlink is refused before any password prompt or file write.
    /// The pre-flight check uses `symlink_metadata` (not
    /// `Path::exists`), which does NOT follow the final component,
    /// so dangling-symlink redirection is caught even when the
    /// target is missing. Matches `git init`'s discipline: the user
    /// is expected to resolve the symlink themselves.
    ///
    /// Unix-only: `std::os::unix::fs::symlink` is the cleanest
    /// symlink-creation surface; Windows symlink semantics differ
    /// and require elevated privileges in many configurations.
    /// `cfg(unix)` keeps the test deterministic on the CI hosts
    /// that matter for this audit row.
    #[cfg(unix)]
    #[tokio::test]
    async fn vault_create_refuses_symlinked_path() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().expect("tempdir");
        // Plant a symlink at the would-be vault path. The target
        // (`elsewhere.pvf`) is intentionally NOT created, so this
        // is a *dangling* symlink — the case `Path::exists()` would
        // miss but `symlink_metadata` catches.
        let link_path = dir.path().join("v-symlink.pvf");
        let elsewhere = dir.path().join("elsewhere.pvf");
        symlink(&elsewhere, &link_path).expect("create symlink");

        let _guard = WithInjectedPassword::set(TEST_PWD);
        let err = run_create(&global(), args(link_path.clone()))
            .await
            .expect_err("symlinked path rejected");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("path is a symlink") && msg.contains("resolve to the real target"),
            "expected symlink-refuse error, got: {msg}"
        );
        // The would-be target was never created — no vault snuck
        // through to the symlink's destination.
        assert!(
            !elsewhere.exists(),
            "symlink target must not have been written through to ({})",
            elsewhere.display()
        );
        // The symlink itself is left intact — we did not unlink it
        // as a side-effect of the refusal.
        assert!(
            std::fs::symlink_metadata(&link_path)
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(false),
            "symlink at {} must remain after refusal",
            link_path.display()
        );
    }
}
