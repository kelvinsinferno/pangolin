// SPDX-License-Identifier: AGPL-3.0-or-later
//! Issue #98 L-secrets-in-fixtures defense.
//!
//! Walks every file under `crates/*/tests/fixtures/**` (excluding
//! `.meta.toml` provenance records) and scans for 32-byte hex
//! sequences that could be private key material. Any 64-hex-char
//! span IS suspicious by default; matches are checked against a
//! known-public-address / known-public-hash allowlist (contract
//! addresses, deployer wallets, recorded tx hashes, domain
//! separators).
//!
//! Defense rationale: cast's public APIs (`cast logs`, `cast call`,
//! `cast block`, `cast tx`) cannot expose private key material
//! against public RPCs — but an inadvertent paste from a Foundry
//! keystore export or a `cast wallet` output COULD. This sweep
//! catches that class.

#![forbid(unsafe_code)]
#![allow(clippy::doc_markdown, clippy::manual_let_else)]

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(Path::parent)
        .expect("CARGO_MANIFEST_DIR has at least two ancestors")
        .to_path_buf()
}

/// Known-public hex values that may legitimately appear in fixture
/// bytes. All values are lowercase + un-prefixed (the regex strips
/// `0x` before matching).
const ALLOWED_HEX_64: &[&str] = &[
    // D-014 RevisionLogV0 deployment (block hash, tx hash, runtime
    // bytecode hash).
    "e50cd232b65b638d7abc2015332591d40aab29a4849dd0d3fc038c3f4d7fbd7f", // block hash
    "5cb4a7f4242838303964a7196b5326380b72d803d5d2e8f73d2c9d46664f7ba6", // tx hash
    "dbab504e86eca48cbedf61bb1fbc04ab17a5bb880d5a468cbb64e4b64e95c6fe", // runtime keccak
    "0569d60324c504bdacba08c309b85a54793b9002c97c4de22c9f8598e5e54b6a", // deploy tx
    "e68ebcbbd342f71ae2e1766904c70f8fd2860c02c2c38142caad6bffc35d48c3", // V0 redeploy tx
    // D-014 V0 event signature hash.
    "6562412104cd03f86bf4f5184aa68e9d47cdb237b31b1de9d2fe1904eddcae8f",
    // D-014 V0 smoke test fixed bytes.
    "aaaa000000000000000000000000000000000000000000000000000000000000",
    "bbbb000000000000000000000000000000000000000000000000000000000000",
    "cccc000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    // D-017 RevisionLogV1 deployment.
    "22e464123c7fc1c71a161350d521ed7946975b0a9a3b9fd232d8846327cacd19", // deploy tx
    "5220ac27b023082183b62e9739ae40692551aa4495e94bfe1f4c8da4cf727f43", // runtime keccak
    "9d1538887c3954f21ebe2602655bba85334719e130e5ba4a5c729bde968f0c62", // V1 domain separator
    // D-017 deploy block (sync_status fixture).
    "11aa1f470401e4777a9a9b1bf26becc978de22a665f63adf9679ef36ca13c68a", // block hash
    "eae03759d12c75c1d51fc893de51df628017f33fa44b1fb5c518c5ba568c5573", // parent block hash (D-017 deploy block - 1)
    // D-018 + D-019 EntitlementRegistry.
    "ca252c6eaa70553a3fb040b9493c2b9db2a34fb7abc782a3ddeb74b1b35dd1f7", // runtime keccak
    "b33d25188e5fc32cf5021ce63f28ee4ffb13d1d9a4ca720c46272f4c87c42fd0", // D-019 DOMAIN_SEPARATOR
    "914f5d97dc4b7c78e85ef3ab0d33d0e5c0fa741e3aaa407fc83461e028e94cd0", // D-018 deploy tx
    "06ab93d4b121a80283b1b6b035c4cc004f5e9859126e3039d7984d03981ba4b1", // D-019 deploy tx
];

fn allowed_hex_match(needle: &str) -> bool {
    let lower = needle.to_lowercase();
    if ALLOWED_HEX_64.contains(&lower.as_str()) {
        return true;
    }
    // Allow long zero runs (padded structured data) + the
    // PADDING_FF idiom for solidity uint256-max sentinels.
    if lower.chars().all(|c| c == '0') {
        return true;
    }
    if lower.chars().all(|c| c == 'f') {
        return true;
    }
    // Allow values that contain the d017-deploy-block (0x279bfb0)
    // padded — these are block_number bytes in the sync_status
    // fixture.
    if lower.contains("00000000000000000000000000000000000000000000000000000000000000")
        || lower.contains("0000000000000000000000000000000000000000000000000000000000000001")
    {
        return true;
    }
    // Allow common gas-related hex (0x...00, 0x...01 — sequence
    // numbers, log indices, etc. encoded as left-padded uint256).
    false
}

fn find_fixture_files(root: &Path, out: &mut Vec<PathBuf>) {
    let read = match std::fs::read_dir(root) {
        Ok(r) => r,
        Err(_) => return,
    };
    for entry in read.flatten() {
        let p = entry.path();
        if p.is_dir() {
            let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if matches!(
                name,
                "target" | ".git" | ".claude" | "node_modules" | "dist" | "build"
            ) || name.starts_with('.')
            {
                continue;
            }
            find_fixture_files(&p, out);
        } else {
            let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if name.ends_with(".meta.toml") {
                continue;
            }
            out.push(p);
        }
    }
}

/// Scan `content` for runs of EXACTLY 64 lowercase-hex chars
/// (case-folded) bounded by non-hex characters on both sides. This
/// matches the canonical wire-format shape of a 32-byte EVM value
/// (block hash, tx hash, keccak digest, etc.) AND a 32-byte private
/// key.
///
/// Longer hex runs (e.g., the 512-byte `logsBloom` field on an EVM
/// block header, or a contract's runtime bytecode encoding) are
/// EXCLUDED — those are structurally not 32-byte values, so a
/// hypothetical private key splice would have to be the whole run
/// (in which case it'd be a 64-char standalone run and caught).
/// The 32-bytes-padded-in-larger-blob case is genuinely a
/// false-negative class but is bounded by the recapture cadence
/// (any future fixture that DOES contain a 32-byte secret embedded
/// in a longer blob is something the operator chose to capture and
/// will surface in PR review).
fn find_64_hex_tokens(content: &str) -> Vec<String> {
    let bytes = content.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if b.is_ascii_hexdigit() {
            // Find run length.
            let mut j = i;
            while j < bytes.len() && bytes[j].is_ascii_hexdigit() {
                j += 1;
            }
            // Match runs of EXACTLY 64 chars (= 32-byte value).
            // Longer runs are structurally blobs (bytecode,
            // logsBloom, etc.); shorter runs aren't 32-byte values.
            if j - i == 64 {
                let token = &content[i..j];
                out.push(token.to_lowercase());
            }
            i = j;
        } else {
            i += 1;
        }
    }
    out
}

#[test]
fn no_fixture_file_contains_suspicious_64_hex_tokens() {
    let root = repo_root().join("crates");
    let mut fixture_files = Vec::new();
    // Only check fixture dirs to avoid the entire workspace.
    walk_for_fixtures(&root, &mut fixture_files);
    assert!(
        !fixture_files.is_empty(),
        "expected at least one fixture file under crates/*/tests/fixtures/** — \
         the issue #98 fixture-capture cycle should have placed several. \
         Searched root: {}",
        root.display()
    );

    let mut violations: Vec<(PathBuf, String)> = Vec::new();
    for path in &fixture_files {
        let Ok(content) = std::fs::read_to_string(path) else {
            // Binary file or unreadable; skip — bytes scans not
            // useful for non-UTF-8 content (no fixtures should be
            // pure binary anyway).
            continue;
        };
        let tokens = find_64_hex_tokens(&content);
        for token in tokens {
            if !allowed_hex_match(&token) {
                violations.push((path.clone(), token));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "L-secrets-in-fixtures violations:\n{violations:#?}\n\n\
         Each is a 64-char hex token in a fixture file that is NOT \
         in the known-public-address / known-public-hash allowlist. \
         If a value is genuinely public chain data (block hash, tx \
         hash, runtime keccak, etc.), add it to ALLOWED_HEX_64 in \
         this test. Otherwise REMOVE the fixture and recapture via \
         a cast command that does not expose private material."
    );
}

fn walk_for_fixtures(root: &Path, out: &mut Vec<PathBuf>) {
    let read = match std::fs::read_dir(root) {
        Ok(r) => r,
        Err(_) => return,
    };
    for entry in read.flatten() {
        let p = entry.path();
        if p.is_dir() {
            let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if matches!(name, "target" | ".git" | ".claude" | "node_modules")
                || name.starts_with('.')
            {
                continue;
            }
            if name == "fixtures" {
                find_fixture_files(&p, out);
            } else {
                walk_for_fixtures(&p, out);
            }
        }
    }
}
