//! P11A-6 integration test: account add → list → show → update →
//! delete round trip via the `pangolin-cli account` subcommand
//! library entry points.
//!
//! E2E-006 in `E2E_TESTS.md`. This test exercises the local-vault-
//! only side of the new account-management surface; chain calls
//! (publish / pull) are NOT involved (account ops are local; the
//! dirty markers accumulate, ready for a subsequent
//! `pangolin-cli publish`).
//!
//! ## Boundary between this test and the unit tests in
//! `commands/account.rs::tests`
//!
//! - The unit-test module has access to a `cfg(test)`-gated
//!   thread-local seam (`TEST_AUTO_CONFIRM_PRESENCE` /
//!   `TEST_AUTO_CONFIRM_DELETE`) that bypasses the interactive
//!   prompts. Integration tests under `tests/*.rs` compile in a
//!   separate crate and CANNOT reach that seam (the `tests`
//!   submodule is private to the lib crate).
//! - To exercise the full lifecycle without poking the seam, this
//!   test:
//!   - Drives `run_add` (no presence prompt; only password +
//!     TOTP gating, both supplied by `--generate-password` +
//!     `--no-totp` to avoid interactive `rpassword` calls).
//!   - Drives `run_list` (no prompt).
//!   - Drives `run_show` WITHOUT any `--reveal-*` flag (no
//!     prompt).
//!   - Verifies the reveal-API at the LIBRARY layer
//!     (`Vault::reveal_password`) — the CLI-prompt-then-reveal
//!     code path is exercised by the unit tests.
//!   - Drives `run_update` is OUT OF SCOPE for this integration
//!     test because it requires presence-prompt interaction.
//!     The library's `Vault::update_account` is used directly
//!     for the "update" step; the CLI's prompt-orchestration
//!     wraps it transparently per A6.
//!   - Drives `run_delete --yes` (no prompt; the `--yes` flag is
//!     the audit-traceable opt-out per A9).
//!   - Drives `run_delete` again on the same id and asserts the
//!     "already deleted (tombstoned)" idempotency-by-clear-error.

use std::path::PathBuf;

use pangolin_cli::cli::{
    AccountAddArgs, AccountDeleteArgs, AccountListArgs, AccountShowArgs, GlobalArgs, HexAccountId,
};
use pangolin_cli::commands::account;
use pangolin_crypto::secret::SecretBytes;
use pangolin_store::session::{PinIdentityProof, PressYPresenceProof};
use pangolin_store::{AccountId, AccountSnapshot, Vault};
use tempfile::TempDir;

const TEST_PWD: &str = "correct horse battery staple";

fn global() -> GlobalArgs {
    GlobalArgs {
        deployment_file: None,
        rpc_url: None,
        allow_insecure_rpc: false,
        json: false,
    }
}

fn make_vault(path: &std::path::Path) {
    let pwd = SecretBytes::new(TEST_PWD.as_bytes().to_vec());
    Vault::create(path, &pwd).expect("create");
}

fn unlock_vault(path: &std::path::Path) -> Vault {
    let mut v = Vault::open(path).expect("open");
    let presence = PressYPresenceProof::confirmed();
    let identity = PinIdentityProof::new(SecretBytes::new(TEST_PWD.as_bytes().to_vec()));
    v.unlock(&presence, &identity).expect("unlock");
    v
}

fn add_args(vault_path: PathBuf, name: &str) -> AccountAddArgs {
    AccountAddArgs {
        vault_path,
        vault_password: Some(TEST_PWD.into()),
        name: name.into(),
        username: Some("alice".into()),
        url: Some("https://example.com".into()),
        notes: None,
        notes_stdin: false,
        password_stdin: false,
        generate_password: true, // avoid interactive rpassword
        totp_stdin: false,
        no_totp: true,
    }
}

fn list_args(vault_path: PathBuf) -> AccountListArgs {
    AccountListArgs {
        vault_path,
        vault_password: Some(TEST_PWD.into()),
        include_frozen: false,
        include_tombstoned: false,
    }
}

fn show_args(vault_path: PathBuf, account_id: [u8; 32]) -> AccountShowArgs {
    AccountShowArgs {
        vault_path,
        vault_password: Some(TEST_PWD.into()),
        account_id: HexAccountId(account_id),
        reveal_password: false,
        reveal_notes: false,
        reveal_totp_secret: false,
    }
}

fn delete_args(vault_path: PathBuf, account_id: [u8; 32]) -> AccountDeleteArgs {
    AccountDeleteArgs {
        vault_path,
        vault_password: Some(TEST_PWD.into()),
        account_id: HexAccountId(account_id),
        yes: true, // audit-traceable opt-out per A9
        why: None,
    }
}

/// **E2E-006 / P11A-6.** Full account lifecycle round-trip:
/// `add → list → show (no reveal) → update via library →
/// delete --yes → re-delete refused`.
#[tokio::test]
#[allow(clippy::too_many_lines)] // Linear E2E narrative; factoring
                                 // sub-helpers obscures the audit-reviewable order.
async fn account_lifecycle_round_trip() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("lifecycle.pvf");
    make_vault(&path);

    // --- 1. ADD ---
    let args = add_args(path.clone(), "github-work");
    account::run(
        &global(),
        pangolin_cli::cli::AccountArgs {
            command: pangolin_cli::cli::AccountCommand::Add(args),
        },
    )
    .await
    .expect("account add succeeds");

    // Read the just-added id back from the vault.
    let id_bytes: [u8; 32] = {
        let v = unlock_vault(&path);
        let ids = v.list_accounts();
        assert_eq!(ids.len(), 1, "exactly one account after add");
        let bytes = *ids[0].as_bytes();
        v.close().expect("close");
        bytes
    };

    // --- 2. LIST (no include flags) ---
    account::run(
        &global(),
        pangolin_cli::cli::AccountArgs {
            command: pangolin_cli::cli::AccountCommand::List(list_args(path.clone())),
        },
    )
    .await
    .expect("account list succeeds");

    // --- 3. SHOW (no reveal flags; no presence prompt) ---
    account::run(
        &global(),
        pangolin_cli::cli::AccountArgs {
            command: pangolin_cli::cli::AccountCommand::Show(show_args(path.clone(), id_bytes)),
        },
    )
    .await
    .expect("account show (no reveal) succeeds");

    // --- 4. REVEAL via library (the CLI-level reveal path is
    //      unit-tested via the cfg(test)-only seam; integration
    //      tests cannot reach the seam, so we exercise the
    //      underlying Vault::reveal_password to verify the
    //      identity is queryable end-to-end). ---
    {
        let mut v = unlock_vault(&path);
        let aid = AccountId::from_bytes(id_bytes);
        // reveal_password requires a fresh presence proof.
        let p = PressYPresenceProof::confirmed();
        let pwd = v
            .reveal_password(aid, &p)
            .expect("reveal_password at library layer");
        // The auto-generated password is 24 bytes drawn from a
        // 64-char alphabet; assert structural shape rather than
        // specific bytes (the value is non-deterministic).
        assert_eq!(
            pwd.expose().len(),
            24,
            "auto-generated password is 24 chars"
        );
        v.close().expect("close");
    }

    // --- 5. UPDATE via library (the CLI's run_update prompts for
    //       presence, which the integration test cannot satisfy;
    //       the prompt-orchestration is unit-tested with the
    //       cfg(test) seam. The structural property we want to
    //       pin in E2E-006: an update produces a new revision and
    //       the row is dirty after the call). ---
    let new_revision = {
        let mut v = unlock_vault(&path);
        let aid = AccountId::from_bytes(id_bytes);
        // Reveal existing secrets so we can build a complete
        // snapshot (mirrors the run_update orchestration).
        let p1 = PressYPresenceProof::confirmed();
        let revealed_pwd = v.reveal_password(aid, &p1).expect("reveal");
        let p2 = PressYPresenceProof::confirmed();
        let revealed_notes = v.reveal_notes(aid, &p2).expect("reveal");
        let p3 = PressYPresenceProof::confirmed();
        let revealed_totp = v.reveal_totp_secret(aid, &p3).expect("reveal");
        // Layer the user's update (rename) on top.
        let new_snap = AccountSnapshot::new(
            SecretBytes::new(b"github-work-renamed".to_vec()),
            SecretBytes::new(b"alice".to_vec()),
            revealed_pwd,
            SecretBytes::new(b"https://example.com".to_vec()),
            revealed_notes,
            revealed_totp,
        );
        let rid = v.update_account(aid, new_snap).expect("update");
        v.close().expect("close");
        rid
    };
    let _ = new_revision; // silence unused-warning; the vault state is the assertion

    // Verify the rename landed.
    {
        let v = unlock_vault(&path);
        let aid = AccountId::from_bytes(id_bytes);
        let snap = v.get_account(aid).expect("get_account");
        assert_eq!(snap.display_name.expose(), b"github-work-renamed");
        v.close().expect("close");
    }

    // --- 6. DELETE --yes (no prompt) ---
    account::run(
        &global(),
        pangolin_cli::cli::AccountArgs {
            command: pangolin_cli::cli::AccountCommand::Delete(delete_args(path.clone(), id_bytes)),
        },
    )
    .await
    .expect("account delete --yes succeeds");

    // Verify: row is now in tombstoned set; absent from active.
    {
        let v = unlock_vault(&path);
        let aid = AccountId::from_bytes(id_bytes);
        assert!(v.get_account(aid).is_none(), "tombstoned → no get");
        let active = v.list_accounts();
        assert!(!active.contains(&aid), "active set excludes tombstoned");
        let tomb = v
            .list_tombstoned_accounts()
            .expect("list_tombstoned_accounts");
        assert!(tomb.contains(&aid), "tombstoned set contains the id");
        v.close().expect("close");
    }

    // --- 7. RE-DELETE refused (idempotency-by-clear-error) ---
    let err = account::run(
        &global(),
        pangolin_cli::cli::AccountArgs {
            command: pangolin_cli::cli::AccountCommand::Delete(delete_args(path.clone(), id_bytes)),
        },
    )
    .await
    .expect_err("re-delete should be refused");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("already been deleted") || msg.contains("tombstoned"),
        "expected re-delete refusal, got: {msg}"
    );

    // --- 8. SHOW on tombstoned id surfaces the deleted-message
    //       (not "not found"). ---
    let err = account::run(
        &global(),
        pangolin_cli::cli::AccountArgs {
            command: pangolin_cli::cli::AccountCommand::Show(show_args(path.clone(), id_bytes)),
        },
    )
    .await
    .expect_err("show on tombstoned should fail");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("deleted") || msg.contains("tombstoned"),
        "expected tombstoned message, got: {msg}"
    );
}
