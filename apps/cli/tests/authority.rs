//! Integration test for `pangolin-cli authority list` (MVP-1 issue
//! 1.11, R-d).
//!
//! Registers an authority via the engine API on a temp vault, then
//! exec's the built CLI binary with `authority list` against the same
//! vault file and asserts the stdout contains the expected entry. The
//! CLI binary is located via `env!("CARGO_BIN_EXE_<name>")` so the
//! test does not depend on PATH.

use std::path::Path;
use std::process::Command;

use pangolin_core::{
    CaptureAuthority, CaptureAuthorityKind, CaptureContext, CaptureContextKind, PinIdentityProof,
    PressYPresenceProof, Vault,
};
use pangolin_crypto::secret::SecretBytes;

const PWD: &str = "correct horse battery staple";

fn pwd() -> SecretBytes {
    SecretBytes::new(PWD.as_bytes().to_vec())
}

fn register_one(path: &Path) {
    Vault::create(path, &pwd()).unwrap();
    let mut v = Vault::open(path).unwrap();
    let presence = PressYPresenceProof::confirmed();
    let identity = PinIdentityProof::new(pwd());
    v.unlock(&presence, &identity).unwrap();
    let authority = CaptureAuthority {
        schema_version: 1,
        kind: CaptureAuthorityKind::BrowserExtension,
        component_id: "com.example.test-ext".into(),
        component_version: "0.1.0".into(),
    };
    let context = CaptureContext {
        schema_version: 1,
        kind: CaptureContextKind::Browser,
        platform_hint: Some("firefox".into()),
    };
    v.capture_authority_register(&presence, authority, context, false)
        .unwrap();
    v.close().unwrap();
}

fn run_cli(vault_path: &Path, json: bool) -> (String, String) {
    let bin = env!("CARGO_BIN_EXE_pangolin-cli");
    let mut cmd = Command::new(bin);
    cmd.arg("authority")
        .arg("list")
        .arg("--vault-path")
        .arg(vault_path)
        .arg("--vault-password")
        .arg(PWD);
    if json {
        cmd.arg("--json");
    }
    let out = cmd.output().expect("spawn pangolin-cli");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        out.status.success(),
        "pangolin-cli authority list failed; stderr: {stderr}; stdout: {stdout}"
    );
    (stdout, stderr)
}

#[test]
fn authority_list_emits_human_readable_lines() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("v.pvf");
    register_one(&path);
    let (stdout, _stderr) = run_cli(&path, false);
    assert!(
        stdout.contains("browser") && stdout.contains("firefox"),
        "human-readable output should name the context kind + hint; got: {stdout}"
    );
    assert!(
        stdout.contains("com.example.test-ext"),
        "human-readable output should include the component_id; got: {stdout}"
    );
    assert!(
        stdout.contains("browser_extension"),
        "human-readable output should include the authority kind; got: {stdout}"
    );
}

#[test]
fn authority_list_emits_json_lines() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("v.pvf");
    register_one(&path);
    let (stdout, _stderr) = run_cli(&path, true);
    let line = stdout.lines().next().expect("at least one JSON line");
    let parsed: serde_json::Value = serde_json::from_str(line).expect("each line is valid JSON");
    assert_eq!(parsed["context_kind"], "browser");
    assert_eq!(parsed["platform_hint"], "firefox");
    assert_eq!(parsed["authority_kind"], "browser_extension");
    assert_eq!(parsed["component_id"], "com.example.test-ext");
    assert_eq!(parsed["component_version"], "0.1.0");
}

#[test]
fn authority_list_empty_vault_emits_placeholder() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("v.pvf");
    // Create + unlock once (registers the device row, no auth row).
    Vault::create(&path, &pwd()).unwrap();
    let mut v = Vault::open(&path).unwrap();
    let presence = PressYPresenceProof::confirmed();
    let identity = PinIdentityProof::new(pwd());
    v.unlock(&presence, &identity).unwrap();
    v.close().unwrap();
    let (stdout, _stderr) = run_cli(&path, false);
    assert!(
        stdout.contains("no capture authorities"),
        "empty vault should emit a placeholder line; got: {stdout}"
    );
}
