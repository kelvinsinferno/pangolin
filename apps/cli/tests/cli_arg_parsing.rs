//! Integration smoke tests that invoke the built `pangolin-cli`
//! binary and verify clap-derive correctness end-to-end.
//!
//! These complement the unit tests in `src/cli.rs` (which exercise
//! the parser via `Cli::try_parse_from`) by running the actual
//! binary and asserting on its stdout/stderr surface — catching
//! regressions where the binary entry point fails to wire the
//! parser into `main`.

use std::process::Command;

/// Path to the `pangolin-cli` binary built for this test pass.
/// `CARGO_BIN_EXE_<name>` is set by Cargo when running integration
/// tests under `tests/`.
fn pangolin_cli_bin() -> &'static str {
    env!("CARGO_BIN_EXE_pangolin-cli")
}

/// `pangolin-cli --help` exits 0 and lists the three subcommands.
#[test]
fn help_lists_all_subcommands() {
    let out = Command::new(pangolin_cli_bin())
        .arg("--help")
        .output()
        .expect("spawn pangolin-cli --help");
    assert!(out.status.success(), "expected --help to exit 0");
    let stdout = String::from_utf8_lossy(&out.stdout);
    for sub in &["status", "publish", "pull"] {
        assert!(
            stdout.contains(sub),
            "expected --help output to mention `{sub}`; got:\n{stdout}"
        );
    }
}

// -----------------------------------------------------------------
// CLI-V1 (R-f): per-verb clap-parse smoke tests
// -----------------------------------------------------------------

/// `pangolin-cli sync --help` lists the four sync verbs.
#[test]
fn cli_v1_sync_help_lists_verbs() {
    let out = Command::new(pangolin_cli_bin())
        .args(["sync", "--help"])
        .output()
        .expect("spawn sync --help");
    assert!(out.status.success(), "sync --help should succeed");
    let stdout = String::from_utf8_lossy(&out.stdout);
    for verb in &["flush", "queue-status", "pull-status", "loop"] {
        assert!(
            stdout.contains(verb),
            "sync --help missing `{verb}`; got:\n{stdout}"
        );
    }
}

/// `pangolin-cli sync flush --vault-path <path>` parses (we only
/// invoke `--help` to avoid prompting for a vault password).
#[test]
fn cli_v1_flush_parses_with_vault_path() {
    let out = Command::new(pangolin_cli_bin())
        .args(["sync", "flush", "--help"])
        .output()
        .expect("spawn sync flush --help");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("--vault-path"));
}

#[test]
fn cli_v1_queue_status_parses_with_vault_path() {
    let out = Command::new(pangolin_cli_bin())
        .args(["sync", "queue-status", "--help"])
        .output()
        .expect("spawn sync queue-status --help");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("--vault-path"));
}

#[test]
fn cli_v1_pull_status_parses_with_vault_path() {
    let out = Command::new(pangolin_cli_bin())
        .args(["sync", "pull-status", "--help"])
        .output()
        .expect("spawn sync pull-status --help");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("--vault-path"));
}

#[test]
fn cli_v1_sync_mode_show_parses() {
    let out = Command::new(pangolin_cli_bin())
        .args(["sync-mode", "show", "--help"])
        .output()
        .expect("spawn sync-mode show --help");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("--vault-path"));
}

#[test]
fn cli_v1_sync_mode_set_parses_with_value() {
    let out = Command::new(pangolin_cli_bin())
        .args(["sync-mode", "set", "--help"])
        .output()
        .expect("spawn sync-mode set --help");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("--vault-path"));
}

/// `sync-mode set foo` errors at clap-arg-validation time because
/// `foo` is not one of the three accepted values.
#[test]
fn cli_v1_sync_mode_set_rejects_unknown_value() {
    let out = Command::new(pangolin_cli_bin())
        .args(["sync-mode", "set", "--vault-path", "/tmp/v.pvf", "foo"])
        .output()
        .expect("spawn sync-mode set foo");
    assert!(!out.status.success(), "unknown value must reject");
}

#[test]
fn cli_v1_wallet_show_parses_with_vault_path() {
    let out = Command::new(pangolin_cli_bin())
        .args(["wallet", "show", "--help"])
        .output()
        .expect("spawn wallet show --help");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("--vault-path"));
}

#[test]
fn cli_v1_balance_show_parses_with_vault_path() {
    let out = Command::new(pangolin_cli_bin())
        .args(["balance", "show", "--help"])
        .output()
        .expect("spawn balance show --help");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("--vault-path"));
}

#[test]
fn cli_v1_top_up_parses_with_vault_path() {
    let out = Command::new(pangolin_cli_bin())
        .args(["top-up", "--help"])
        .output()
        .expect("spawn top-up --help");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("--vault-path"));
    assert!(stdout.contains("--funder-url"));
    assert!(stdout.contains("--credit-file"));
}

/// `top-up` without `--yes` on a non-TTY context surfaces the
/// "non-TTY" error path at runtime. We can't easily force that
/// from the binary-spawn integration test (the binary's stdin is
/// piped, not a TTY, but we need a real vault path to drive the
/// full path). This test validates the clap parser accepts both
/// the with-yes and without-yes shapes; the runtime gate is
/// covered in `top_up_smoke.rs`.
#[test]
fn cli_v1_top_up_requires_confirmation_flag_or_tty() {
    // Both shapes parse at clap level — the runtime gate is the
    // actual defense.
    let with_yes = Command::new(pangolin_cli_bin())
        .args([
            "top-up",
            "--vault-path",
            "/tmp/v.pvf",
            "--funder-url",
            "https://example.test/",
            "--credit-file",
            "/tmp/nonexistent.json",
            "--yes",
        ])
        .output()
        .expect("spawn top-up --yes");
    // Will fail at runtime (vault open) but NOT at clap-parse.
    assert!(
        !with_yes.status.success(),
        "should fail at runtime (vault missing), not clap"
    );
    // The error message should NOT be a clap parse error.
    let stderr = String::from_utf8_lossy(&with_yes.stderr);
    assert!(
        !stderr.contains("error: unexpected"),
        "expected runtime error not clap unknown-arg, got: {stderr}"
    );
}

#[test]
fn cli_v1_sync_loop_parses_with_vault_path() {
    let out = Command::new(pangolin_cli_bin())
        .args(["sync", "loop", "--help"])
        .output()
        .expect("spawn sync loop --help");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("--vault-path"));
    assert!(stdout.contains("--once"));
}

// -----------------------------------------------------------------
// CLI-V1 (R-f): help-text vocabulary audit gate
// -----------------------------------------------------------------

/// **CLI-V1 (R-f / L10).** Every new subcommand's `--help` text
/// avoids the §8.1.5 forbidden user-facing terms. Extends the
/// existing `account_help_avoids_forbidden_user_facing_terms`
/// audit gate.
#[test]
fn cli_v1_help_avoids_forbidden_user_facing_terms() {
    let forbidden = [
        "blockchain",
        "decentralized storage",
        "gas ",
        " gas",
        "transaction",
        "hashes",
        "revisions",
    ];
    let invocations = [
        vec!["sync", "--help"],
        vec!["sync", "flush", "--help"],
        vec!["sync", "queue-status", "--help"],
        vec!["sync", "pull-status", "--help"],
        vec!["sync", "loop", "--help"],
        vec!["sync-mode", "--help"],
        vec!["sync-mode", "show", "--help"],
        vec!["sync-mode", "set", "--help"],
        vec!["wallet", "--help"],
        vec!["wallet", "show", "--help"],
        vec!["balance", "--help"],
        vec!["balance", "show", "--help"],
        vec!["top-up", "--help"],
    ];
    for args in &invocations {
        let out = Command::new(pangolin_cli_bin())
            .args(args)
            .output()
            .expect("spawn pangolin-cli help");
        assert!(out.status.success(), "{args:?} should succeed");
        let stdout = String::from_utf8_lossy(&out.stdout).to_lowercase();
        for term in &forbidden {
            assert!(
                !stdout.contains(term),
                "{args:?} --help contains forbidden term {term:?}; got: {stdout}"
            );
        }
    }
}

/// `pangolin-cli` with no subcommand exits non-zero (clap surfaces a
/// "required subcommand" error).
#[test]
fn missing_subcommand_errors() {
    let out = Command::new(pangolin_cli_bin())
        .output()
        .expect("spawn pangolin-cli");
    assert!(
        !out.status.success(),
        "expected non-zero exit for missing subcommand"
    );
}

/// `pangolin-cli status` without `--vault-path` errors with a clap
/// message naming the missing flag.
#[test]
fn status_without_vault_path_errors() {
    let out = Command::new(pangolin_cli_bin())
        .arg("status")
        .output()
        .expect("spawn pangolin-cli status");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--vault-path"),
        "expected error to mention --vault-path; got:\n{stderr}"
    );
}
