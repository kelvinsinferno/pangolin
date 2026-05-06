//! Provider construction, ABI loading, and deployment-metadata parsing.
//!
//! Per `docs/issue-plans/P6.md`:
//!
//! - The contract address is **read from
//!   `contracts/deployments/base-sepolia.json`** (the canonical
//!   record); chaincli does NOT accept a `--contract-address` flag.
//!   This is the "truth serum" discipline — chaincli refuses to talk
//!   to an unexpected contract.
//! - The RPC URL resolves with priority: `--rpc-url` flag, then
//!   `BASE_SEPOLIA_RPC_URL` env var, then the public Base Sepolia
//!   endpoint baked into the deployment file as `chain.rpc_default`.
//! - The ABI is **read from `contracts/abi/RevisionLogV0.json`**, not
//!   embedded as a Rust string. The deployment file references the
//!   ABI path; chaincli resolves it relative to the deployment file's
//!   directory.

use std::path::{Path, PathBuf};

use alloy::json_abi::JsonAbi;
use alloy::primitives::{Address, B256};
use anyhow::{anyhow, bail, Context, Result};

/// The deployer-recorded chain id we expect for Base Sepolia. If
/// `chain.chain_id` in the deployment file is anything other than this,
/// chaincli refuses to proceed — see `docs/issue-plans/P6.md` failure
/// mode "Adversary-controlled `encPayload` containing exotic bytes."
/// (Same defensive posture: fail closed when metadata diverges from
/// expectations.)
pub const EXPECTED_CHAIN_ID: u64 = 84_532;

/// Name under which `RevisionLogV0` is recorded in the deployment file.
pub const CONTRACT_NAME: &str = "RevisionLogV0";

/// Parsed view of the canonical deployment metadata file
/// (`contracts/deployments/base-sepolia.json`). Only the fields chaincli
/// actually reads are populated; everything else in the JSON is
/// passed-through as opaque data. We deliberately do NOT
/// `serde::Deserialize` an `encPayload`-bearing type — see plan §
/// "Constraints (non-negotiable)."
///
/// Fields that aren't yet wired up to a sub-command in this commit
/// carry `#[allow(dead_code)]` because clippy's `dead_code` lint runs
/// per-build-unit and doesn't yet see the consumer in
/// `commands/status.rs` (P6-3) or `commands/publish.rs` (P6-5). The
/// allow is removed once the field has a live consumer.
#[derive(Debug, Clone)]
pub struct Deployment {
    /// Path to the deployment file we loaded; used to resolve relative
    /// paths (e.g., the ABI reference).
    pub source_path: PathBuf,
    /// `chain.chain_id` as declared in the deployment file.
    pub chain_id: u64,
    /// `chain.rpc_default` — the public RPC endpoint for the chain.
    pub rpc_default: String,
    /// `contracts.RevisionLogV0.address`.
    pub contract_address: Address,
    /// `contracts.RevisionLogV0.deployer`.
    #[allow(dead_code)]
    pub deployer: Address,
    /// `contracts.RevisionLogV0.deploy_block`.
    #[allow(dead_code)]
    pub deploy_block: u64,
    /// `contracts.RevisionLogV0.bytecode.runtime_size_bytes`.
    #[allow(dead_code)]
    pub runtime_size_bytes: u64,
    /// `contracts.RevisionLogV0.bytecode.deployed_runtime_keccak256` —
    /// the keccak256 hash of the on-chain runtime bytecode at deploy
    /// time. `chaincli status` cross-checks this against the live
    /// `eth_getCode` result so a tampered deployment file (or a CREATE2
    /// collision) cannot redirect chaincli to a foreign contract on the
    /// right chain that happens to expose the same selectors.
    pub runtime_keccak: B256,
    /// Resolved absolute path to the ABI file referenced from the
    /// deployment file.
    #[allow(dead_code)]
    pub abi_path: PathBuf,
}

impl Deployment {
    /// Load and validate the deployment file at `path`.
    ///
    /// Validation rules:
    /// - The file parses as JSON.
    /// - `chain.chain_id` equals `EXPECTED_CHAIN_ID` (84532 for Base
    ///   Sepolia). If not, fail closed.
    /// - `contracts.RevisionLogV0.address` parses as an EVM address.
    /// - The ABI path referenced from the file resolves to an existing
    ///   file on disk.
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read deployment file at {}", path.display()))?;
        let value: serde_json::Value = serde_json::from_str(&raw)
            .with_context(|| format!("deployment file {} is not valid JSON", path.display()))?;

        let chain_id = value
            .pointer("/chain/chain_id")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| anyhow!("deployment file missing /chain/chain_id (u64)"))?;
        if chain_id != EXPECTED_CHAIN_ID {
            bail!(
                "deployment chain_id mismatch: expected {EXPECTED_CHAIN_ID} \
                (Base Sepolia), file declares {chain_id}. Refusing to proceed."
            );
        }
        let rpc_default = value
            .pointer("/chain/rpc_default")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| anyhow!("deployment file missing /chain/rpc_default (string)"))?
            .to_owned();

        let contract_path = format!("/contracts/{CONTRACT_NAME}");
        let contract = value
            .pointer(&contract_path)
            .ok_or_else(|| anyhow!("deployment file missing /contracts/{CONTRACT_NAME}"))?;

        let contract_address = parse_address_field(contract, "address")?;
        let deployer = parse_address_field(contract, "deployer")?;
        let deploy_block = contract
            .pointer("/deploy_block")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| {
                anyhow!(
                    "deployment file missing /contracts/{CONTRACT_NAME}\
                     /deploy_block (u64)"
                )
            })?;
        let runtime_size_bytes = contract
            .pointer("/bytecode/runtime_size_bytes")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| {
                anyhow!(
                    "deployment file missing /contracts/{CONTRACT_NAME}\
                     /bytecode/runtime_size_bytes (u64)"
                )
            })?;
        let runtime_keccak_str = contract
            .pointer("/bytecode/deployed_runtime_keccak256")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                anyhow!(
                    "deployment file missing /contracts/{CONTRACT_NAME}\
                     /bytecode/deployed_runtime_keccak256 (string)"
                )
            })?;
        let runtime_keccak = runtime_keccak_str.parse::<B256>().with_context(|| {
            format!(
                "deployed_runtime_keccak256 is not a valid 0x-prefixed \
                     32-byte hex value: {runtime_keccak_str}"
            )
        })?;
        let abi_rel = contract
            .pointer("/abi")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                anyhow!(
                    "deployment file missing /contracts/{CONTRACT_NAME}\
                     /abi (string)"
                )
            })?;

        let parent = path.parent().ok_or_else(|| {
            anyhow!(
                "deployment file path {} has no parent directory",
                path.display()
            )
        })?;
        let abi_path = parent.join(abi_rel);
        let abi_path = abi_path.canonicalize().with_context(|| {
            format!(
                "ABI file referenced as {abi_rel} (resolved to {}) \
                 does not exist",
                abi_path.display()
            )
        })?;

        Ok(Self {
            source_path: path.to_path_buf(),
            chain_id,
            rpc_default,
            contract_address,
            deployer,
            deploy_block,
            runtime_size_bytes,
            runtime_keccak,
            abi_path,
        })
    }

    /// Locate `contracts/deployments/base-sepolia.json` by walking up
    /// from `start` until a `contracts/deployments/base-sepolia.json`
    /// is found. This makes chaincli runnable from any subdirectory
    /// inside the workspace without needing an absolute path.
    pub fn find_default(start: &Path) -> Result<PathBuf> {
        let mut cur: Option<&Path> = Some(start);
        while let Some(dir) = cur {
            let candidate = dir
                .join("contracts")
                .join("deployments")
                .join("base-sepolia.json");
            if candidate.is_file() {
                return Ok(candidate);
            }
            cur = dir.parent();
        }
        Err(anyhow!(
            "could not find contracts/deployments/base-sepolia.json by \
             walking up from {}. Run chaincli from the Pangolin \
             workspace, or pass --deployment-file <path>.",
            start.display()
        ))
    }

    /// Parse the ABI JSON file referenced by this deployment record.
    #[allow(dead_code)]
    pub fn load_abi(&self) -> Result<JsonAbi> {
        let raw = std::fs::read_to_string(&self.abi_path)
            .with_context(|| format!("failed to read ABI file at {}", self.abi_path.display()))?;
        let abi: JsonAbi = serde_json::from_str(&raw).with_context(|| {
            format!(
                "ABI file {} is not a valid JSON ABI",
                self.abi_path.display()
            )
        })?;
        Ok(abi)
    }
}

fn parse_address_field(contract: &serde_json::Value, field: &str) -> Result<Address> {
    let s = contract
        .pointer(&format!("/{field}"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            anyhow!(
                "deployment file missing /contracts/{CONTRACT_NAME}/{field} \
                 (string)"
            )
        })?;
    // P7 audit MED-1 (carried back to chaincli for consistency):
    // validate the EIP-55 (mixed-case) checksum, not just hex shape.
    // Pass `None` for chain id so we accept plain EIP-55 — the form
    // Foundry / Etherscan / the rest of the EVM toolchain emit by
    // default. EIP-1191 (chain-id-bound) is for RSK-style deployments
    // and is not what the Pangolin deployment file records.
    Address::parse_checksummed(s, None)
        .with_context(|| format!("{field} is not a valid EIP-55 checksummed EVM address: {s}"))
}

/// Resolve the RPC URL with the documented priority: `--rpc-url` flag,
/// then `BASE_SEPOLIA_RPC_URL` env var, then the deployment file's
/// `chain.rpc_default` (the public Base Sepolia endpoint).
///
/// Reads the env var via `std::env::var` rather than `clap`'s `env`
/// feature so the resolution order is testable end-to-end and so the
/// CLI's `--help` output documents all three sources.
pub fn resolve_rpc_url(flag: Option<&str>, env_var_name: &str, deployment: &Deployment) -> String {
    if let Some(s) = flag {
        return s.to_owned();
    }
    if let Ok(v) = std::env::var(env_var_name) {
        if !v.is_empty() {
            return v;
        }
    }
    deployment.rpc_default.clone()
}

#[cfg(test)]
mod tests {
    use super::{parse_address_field, resolve_rpc_url, Deployment, EXPECTED_CHAIN_ID};
    use std::io::Write;

    /// Path to the canonical deployment file in this workspace,
    /// resolved at compile time so the test does not depend on the
    /// process CWD.
    fn workspace_deployment_path() -> std::path::PathBuf {
        let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        manifest
            .parent()
            .and_then(std::path::Path::parent)
            .expect("CARGO_MANIFEST_DIR has at least two ancestors")
            .join("contracts")
            .join("deployments")
            .join("base-sepolia.json")
    }

    #[test]
    fn deployment_file_parses() {
        let path = workspace_deployment_path();
        let dep = Deployment::load(&path).expect("real deployment file parses");
        assert_eq!(dep.chain_id, EXPECTED_CHAIN_ID);
        assert_eq!(dep.rpc_default, "https://sepolia.base.org");
        assert_eq!(
            format!("{:?}", dep.contract_address).to_ascii_lowercase(),
            "0x8566d3de653ee55775783bd7918fe91b66373896"
        );
        // The bytecode hash field must parse as a 32-byte 0x-prefixed
        // value. The exact value is asserted against the canonical
        // file recorded for the deployed contract.
        assert_eq!(
            format!("{:?}", dep.runtime_keccak).to_ascii_lowercase(),
            "0xdbab504e86eca48cbedf61bb1fbc04ab17a5bb880d5a468cbb64e4b64e95c6fe"
        );
        assert!(dep.abi_path.is_file());
        // ABI loads as a JsonAbi.
        let abi = dep.load_abi().expect("ABI parses");
        assert!(abi.functions.contains_key("nextSequence"));
        assert!(abi.functions.contains_key("publishRevision"));
        assert!(abi.events.contains_key("RevisionPublished"));
    }

    #[test]
    fn deployment_file_missing_runtime_keccak_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let abi_path = dir.path().join("abi.json");
        std::fs::write(&abi_path, "[]").expect("write abi");
        let json = format!(
            r#"{{
                "chain": {{ "chain_id": {EXPECTED_CHAIN_ID}, "rpc_default": "https://example.com" }},
                "contracts": {{
                    "RevisionLogV0": {{
                        "address": "0x8566D3de653ee55775783bD7918Fe91b66373896",
                        "deployer": "0x89e720238A3913688CB0E025ef03a64539575c54",
                        "deploy_block": 1,
                        "bytecode": {{ "runtime_size_bytes": 443 }},
                        "abi": "{}"
                    }}
                }}
            }}"#,
            abi_path.file_name().unwrap().to_str().unwrap()
        );
        let p = dir.path().join("base-sepolia.json");
        std::fs::write(&p, json).expect("write deployment");
        let err = Deployment::load(&p).expect_err("missing runtime keccak rejected");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("deployed_runtime_keccak256"),
            "expected runtime-keccak missing error, got: {msg}"
        );
    }

    #[test]
    fn deployment_file_malformed_runtime_keccak_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let abi_path = dir.path().join("abi.json");
        std::fs::write(&abi_path, "[]").expect("write abi");
        let json = format!(
            r#"{{
                "chain": {{ "chain_id": {EXPECTED_CHAIN_ID}, "rpc_default": "https://example.com" }},
                "contracts": {{
                    "RevisionLogV0": {{
                        "address": "0x8566D3de653ee55775783bD7918Fe91b66373896",
                        "deployer": "0x89e720238A3913688CB0E025ef03a64539575c54",
                        "deploy_block": 1,
                        "bytecode": {{
                            "runtime_size_bytes": 443,
                            "deployed_runtime_keccak256": "not-a-hash"
                        }},
                        "abi": "{}"
                    }}
                }}
            }}"#,
            abi_path.file_name().unwrap().to_str().unwrap()
        );
        let p = dir.path().join("base-sepolia.json");
        std::fs::write(&p, json).expect("write deployment");
        let err = Deployment::load(&p).expect_err("malformed runtime keccak rejected");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("not a valid 0x-prefixed"),
            "expected hex-parse error, got: {msg}"
        );
    }

    #[test]
    fn deployment_file_chain_id_mismatch_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let abi_path = dir.path().join("abi.json");
        std::fs::write(&abi_path, "[]").expect("write abi");
        let json = format!(
            r#"{{
                "chain": {{ "chain_id": 1, "rpc_default": "https://example.com" }},
                "contracts": {{
                    "RevisionLogV0": {{
                        "address": "0x8566D3de653ee55775783bD7918Fe91b66373896",
                        "deployer": "0x89e720238A3913688CB0E025ef03a64539575c54",
                        "deploy_block": 1,
                        "bytecode": {{
                            "runtime_size_bytes": 443,
                            "deployed_runtime_keccak256": "0x0000000000000000000000000000000000000000000000000000000000000000"
                        }},
                        "abi": "{}"
                    }}
                }}
            }}"#,
            abi_path.file_name().unwrap().to_str().unwrap()
        );
        let p = dir.path().join("base-sepolia.json");
        std::fs::write(&p, json).expect("write deployment");
        let err = Deployment::load(&p).expect_err("chain_id mismatch rejected");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("chain_id mismatch"),
            "expected chain_id mismatch error, got: {msg}"
        );
    }

    #[test]
    fn deployment_file_missing_rejected() {
        let p = std::path::Path::new("/no/such/file.json");
        let err = Deployment::load(p).expect_err("missing file rejected");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("failed to read deployment file"),
            "expected file-read error, got: {msg}"
        );
    }

    #[test]
    fn deployment_file_malformed_json_rejected() {
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        writeln!(f, "{{ not json").expect("write");
        let err = Deployment::load(f.path()).expect_err("bad json rejected");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("not valid JSON"),
            "expected JSON parse error, got: {msg}"
        );
    }

    #[test]
    fn parse_address_field_rejects_bad_hex() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{ "address": "not-an-address" }"#).unwrap();
        let err = parse_address_field(&v, "address").expect_err("bad address rejected");
        assert!(format!("{err:#}").contains("not a valid EIP-55"));
    }

    /// P7 audit MED-1: an address whose hex bytes are valid but
    /// whose EIP-55 checksum is wrong (e.g., all-lowercase variant of
    /// a mixed-case canonical address) must be rejected. Plain
    /// `parse::<Address>()` would accept this; the upgraded
    /// `Address::parse_checksummed` rejects it.
    #[test]
    fn parse_address_field_rejects_mis_checksummed() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{ "address": "0x8566d3de653ee55775783bd7918fe91b66373896" }"#)
                .unwrap();
        let err = parse_address_field(&v, "address").expect_err("mis-checksummed address rejected");
        let msg = format!("{err:#}");
        assert!(msg.contains("EIP-55"), "expected EIP-55 error, got: {msg}");
    }

    #[test]
    fn rpc_url_priority_flag_wins() {
        let dep = stub_deployment("https://default.example.com/");
        let url = resolve_rpc_url(
            Some("https://flag.example.com/"),
            "CHAINCLI_TEST_RPC_URL_FLAG_WINS",
            &dep,
        );
        assert_eq!(url, "https://flag.example.com/");
    }

    #[test]
    fn rpc_url_priority_env_beats_default() {
        // Each env-mutating test acquires the shared mutex below to
        // serialize across the test runner's parallel threads.
        // `std::env::set_var` is `unsafe` on Rust 1.83+ because the
        // process environment is not thread-safe; we cannot use it
        // here under workspace `unsafe_code = deny`. Instead we run
        // this case via a sub-process so the parent's environment is
        // untouched.
        let key = "CHAINCLI_TEST_RPC_URL_ENV_BEATS_DEFAULT";
        run_subprocess_assert(
            &[(key, "https://env.example.com/")],
            key,
            "https://default.example.com/",
            "https://env.example.com/",
        );
    }

    #[test]
    fn rpc_url_priority_default_when_no_flag_no_env() {
        let key = "CHAINCLI_TEST_RPC_URL_DEFAULT";
        // No env mutation needed; run in-process. The key chosen is
        // unique per test, so unrelated process-wide env state can
        // never leak in.
        let dep = stub_deployment("https://default.example.com/");
        let url = resolve_rpc_url(None, key, &dep);
        assert_eq!(url, "https://default.example.com/");
    }

    #[test]
    fn rpc_url_priority_empty_env_falls_back_to_default() {
        let key = "CHAINCLI_TEST_RPC_URL_EMPTY_ENV";
        run_subprocess_assert(
            &[(key, "")],
            key,
            "https://default.example.com/",
            "https://default.example.com/",
        );
    }

    /// Spawn the test binary as a sub-process with the requested env
    /// vars set, recursing into the same test-case's pure body. Avoids
    /// `unsafe { env::set_var }` while still validating the
    /// env-priority resolution.
    ///
    /// We achieve "recursion into the same case" by exec'ing the test
    /// binary with a hidden marker env var: the marker arms a
    /// `#[test]`-eligible helper that exits 0 on assert pass and
    /// non-zero on assert fail. This keeps the assertion loop entirely
    /// pure-Rust and avoids `unsafe`.
    fn run_subprocess_assert(
        env_vars: &[(&str, &str)],
        key: &str,
        default_rpc: &str,
        expected: &str,
    ) {
        // The runner test process is the same binary as `cargo test`.
        // Re-execing it with `--exact` and our marker env var causes
        // `assert_via_marker_helper` to fire.
        let exe = std::env::current_exe().expect("current_exe");
        let mut cmd = std::process::Command::new(exe);
        cmd.arg("--exact")
            .arg("--nocapture")
            .arg("client::tests::__assert_env_priority_marker");
        for (k, v) in env_vars {
            cmd.env(k, v);
        }
        cmd.env("CHAINCLI_TEST_MARKER_KEY", key);
        cmd.env("CHAINCLI_TEST_MARKER_DEFAULT", default_rpc);
        cmd.env("CHAINCLI_TEST_MARKER_EXPECTED", expected);
        let status = cmd.status().expect("spawn child test process");
        assert!(
            status.success(),
            "child test process for env-priority case failed: {status}"
        );
    }

    /// Helper test fired by `run_subprocess_assert` via re-exec. The
    /// outer wrapper only runs when the marker env vars are set.
    #[test]
    #[allow(non_snake_case, clippy::used_underscore_items)]
    fn __assert_env_priority_marker() {
        let Ok(key) = std::env::var("CHAINCLI_TEST_MARKER_KEY") else {
            return; // Not the child run; nothing to do.
        };
        let default_rpc = std::env::var("CHAINCLI_TEST_MARKER_DEFAULT")
            .expect("CHAINCLI_TEST_MARKER_DEFAULT set in child");
        let expected = std::env::var("CHAINCLI_TEST_MARKER_EXPECTED")
            .expect("CHAINCLI_TEST_MARKER_EXPECTED set in child");
        let dep = stub_deployment(&default_rpc);
        let url = resolve_rpc_url(None, &key, &dep);
        assert_eq!(url, expected, "env priority resolution mismatch");
    }

    fn stub_deployment(rpc: &str) -> Deployment {
        Deployment {
            source_path: std::path::PathBuf::from("/dev/null"),
            chain_id: EXPECTED_CHAIN_ID,
            rpc_default: rpc.to_owned(),
            contract_address: alloy::primitives::Address::ZERO,
            deployer: alloy::primitives::Address::ZERO,
            deploy_block: 0,
            runtime_size_bytes: 0,
            runtime_keccak: alloy::primitives::B256::ZERO,
            abi_path: std::path::PathBuf::from("/dev/null"),
        }
    }
}
