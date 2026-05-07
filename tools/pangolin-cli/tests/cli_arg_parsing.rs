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
