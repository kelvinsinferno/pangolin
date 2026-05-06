//! End-to-end integration tests for chaincli, gated behind the
//! `integration-tests` cargo feature so default `cargo test` does not
//! hit the public Base Sepolia RPC.
//!
//! Run with:
//! ```bash
//! cargo test -p chaincli --features integration-tests
//! ```
//!
//! These tests are network-dependent and may fail transiently if Base
//! Sepolia is rate-limiting or down. They are NOT run in CI.

#![cfg(feature = "integration-tests")]

use std::path::PathBuf;
use std::process::Command;

/// Path to the freshly-built chaincli binary. Cargo sets
/// `CARGO_BIN_EXE_chaincli` for tests in the same package.
fn chaincli_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_chaincli"))
}

#[test]
fn status_against_base_sepolia() {
    let out = Command::new(chaincli_bin())
        .arg("status")
        .output()
        .expect("spawn chaincli");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "chaincli status exited non-zero.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    // Required output lines per docs/issue-plans/P6.md "chaincli status" example.
    for needle in &[
        "contract_address   : 0x8566d3de653ee55775783bd7918fe91b66373896",
        "chain_id           : 84532",
        "abi_cross_check    : OK",
        // Live-bytecode keccak cross-check (audit M-1).
        "bytecode_keccak    : 0xdbab504e86eca48cbedf61bb1fbc04ab17a5bb880d5a468cbb64e4b64e95c6fe",
        "nextSequence       :",
    ] {
        assert!(
            stdout.contains(needle),
            "missing `{needle}` in chaincli status output:\n{stdout}"
        );
    }
}

#[test]
fn list_returns_smoke_test_revision() {
    let out = Command::new(chaincli_bin())
        .args([
            "list",
            "--vault-id",
            "0xaaaa000000000000000000000000000000000000000000000000000000000000",
            "--from-block",
            "41133000",
            "--to-block",
            "41134000",
        ])
        .output()
        .expect("spawn chaincli");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "chaincli list exited non-zero.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    // Must contain the P5-4 smoke-test revision tx.
    assert!(
        stdout.contains("0x5cb4a7f4242838303964a7196b5326380b72d803d5d2e8f73d2c9d46664f7ba6"),
        "expected smoke-test tx hash in list output:\n{stdout}"
    );
    assert!(
        stdout.contains("0xdeadbeefdeadbeefdeadbeefdeadbeef"),
        "expected smoke-test payload bytes in list output:\n{stdout}"
    );
}

#[test]
fn dump_smoke_test_tx() {
    let out = Command::new(chaincli_bin())
        .args([
            "dump",
            "--tx",
            "0x5cb4a7f4242838303964a7196b5326380b72d803d5d2e8f73d2c9d46664f7ba6",
        ])
        .output()
        .expect("spawn chaincli");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "chaincli dump exited non-zero.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    // All 6 documented fields plus the dual-encoded payload.
    for needle in &[
        "vaultId           : 0xaaaa",
        "accountId         : 0xbbbb",
        "parentRevision    : 0x0000",
        "deviceId          : 0xcccc",
        "schemaVersion     : 0",
        "sequence          : 0",
        "encPayload (hex)  : deadbeefdeadbeefdeadbeefdeadbeef",
        "encPayload (b64)  : 3q2+796tvu/erb7v3q2+7w==",
    ] {
        assert!(
            stdout.contains(needle),
            "missing `{needle}` in chaincli dump output:\n{stdout}"
        );
    }
}
