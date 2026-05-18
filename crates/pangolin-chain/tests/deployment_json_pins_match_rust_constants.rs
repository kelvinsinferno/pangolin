// SPDX-License-Identifier: AGPL-3.0-or-later
//! Issue #98 R-e Option K — L-rotted-constant-class defense.
//!
//! Parses `contracts/deployments/base-sepolia.json` and asserts every
//! Rust constant that mirrors a JSON field stays byte-equal. The
//! audit-class severity of issue #98's Q-d (where the Rust
//! `d017_deploy_block` had rotted to a value that predated Base
//! Sepolia genesis, AND the JSON `RevisionLogV1.deploy_block` was
//! also wrong) is closed by this hermetic test: a future drift fires
//! at PR time, not on a fresh-vault first sync.
//!
//! L1 (issue #98): JSON is the SINGLE SOURCE OF TRUTH for chain-state
//! pins; Rust constants are downstream. This test enforces that
//! invariant.

#![forbid(unsafe_code)]
#![allow(clippy::doc_markdown, clippy::format_push_string)]

use pangolin_chain::{
    d017_deploy_block, ChainEnv, ENTITLEMENT_DOMAIN_SEPARATOR_BASE_SEPOLIA_V1,
    EXPECTED_DEPLOYED_ADDRESS_BASE_SEPOLIA, EXPECTED_ENTITLEMENT_REGISTRY_ADDRESS_BASE_SEPOLIA,
};
use std::path::PathBuf;

fn deployment_path() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(std::path::Path::parent)
        .expect("CARGO_MANIFEST_DIR has at least two ancestors")
        .join("contracts")
        .join("deployments")
        .join("base-sepolia.json")
}

fn load_json() -> serde_json::Value {
    let bytes = std::fs::read(deployment_path()).expect("read deployment file");
    serde_json::from_slice(&bytes).expect("deployment file is valid JSON")
}

#[test]
fn rust_d017_deploy_block_matches_json_deploy_block() {
    let json = load_json();
    let json_value = json["contracts"]["RevisionLogV1"]["deploy_block"]
        .as_u64()
        .expect("RevisionLogV1.deploy_block is a u64");
    let rust_value = d017_deploy_block(ChainEnv::BaseSepolia);
    assert_eq!(
        rust_value, json_value,
        "Rust constant d017_deploy_block(BaseSepolia) = {rust_value} \
         must equal JSON RevisionLogV1.deploy_block = {json_value}. \
         If this fails, EITHER the constant or the JSON drifted. \
         Issue #98 history: pre-fix had `23_640_113` (Rust) vs \
         `41_639_216` (JSON); the authoritative value re-derived via \
         `cast tx 0x22e464123c7fc1c71a161350d521ed7946975b0a9a3b9fd232d8846327cacd19` \
         is `41_507_120`. See crates/pangolin-chain/RUNBOOK.md § 4."
    );
}

#[test]
fn rust_revision_log_v1_address_matches_json_address() {
    let json = load_json();
    let json_addr = json["contracts"]["RevisionLogV1"]["address"]
        .as_str()
        .expect("RevisionLogV1.address is a string");
    let rust_addr = format!("{EXPECTED_DEPLOYED_ADDRESS_BASE_SEPOLIA:?}");
    assert_eq!(
        rust_addr.to_lowercase(),
        json_addr.to_lowercase(),
        "EXPECTED_DEPLOYED_ADDRESS_BASE_SEPOLIA must match \
         contracts.RevisionLogV1.address in the deployment JSON"
    );
}

#[test]
fn rust_entitlement_registry_address_matches_json() {
    let json = load_json();
    let json_addr = json["contracts"]["EntitlementRegistry"]["address"]
        .as_str()
        .expect("EntitlementRegistry.address is a string");
    let rust_addr = format!("{EXPECTED_ENTITLEMENT_REGISTRY_ADDRESS_BASE_SEPOLIA:?}");
    assert_eq!(
        rust_addr.to_lowercase(),
        json_addr.to_lowercase(),
        "EXPECTED_ENTITLEMENT_REGISTRY_ADDRESS_BASE_SEPOLIA must match \
         contracts.EntitlementRegistry.address in the deployment JSON"
    );
}

#[test]
fn rust_entitlement_domain_separator_matches_json() {
    let json = load_json();
    let json_sep = json["contracts"]["EntitlementRegistry"]["domain_separator"]["value"]
        .as_str()
        .expect("EntitlementRegistry.domain_separator.value is a string");
    let rust_sep = format!(
        "0x{}",
        hex_encode(&ENTITLEMENT_DOMAIN_SEPARATOR_BASE_SEPOLIA_V1)
    );
    assert_eq!(
        rust_sep.to_lowercase(),
        json_sep.to_lowercase(),
        "ENTITLEMENT_DOMAIN_SEPARATOR_BASE_SEPOLIA_V1 must match \
         contracts.EntitlementRegistry.domain_separator.value in the deployment JSON"
    );
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Issue #99 §2f + L-ws-tls-downgrade. The deployment JSON's
/// `chain.ws_default` field MUST start with `wss://` for the BaseSepolia
/// production env. The Rust `check_ws_scheme(env, url)` helper rejects
/// `ws://` for production envs at runtime; this test enforces that the
/// source-of-truth pin in the JSON is also TLS so a misconfigured
/// runtime override is the only way to land cleartext WS.
#[test]
fn deployment_json_ws_default_uses_wss_scheme_for_base_sepolia() {
    let json = load_json();
    let ws_default = json["chain"]["ws_default"]
        .as_str()
        .expect("chain.ws_default is a string");
    assert!(
        ws_default.starts_with("wss://"),
        "L-ws-tls-downgrade: chain.ws_default = {ws_default:?} must start with wss:// \
         (production env BaseSepolia requires TLS-encrypted WebSocket; cleartext ws:// \
         leaks the requested vault_id topic + subscription metadata on-wire). \
         If a future provider migration forces a different scheme, the Rust \
         `check_ws_scheme` helper must be updated in lockstep."
    );
}
