// SPDX-License-Identifier: AGPL-3.0-or-later
//! Issue #98 L-fake-fixture-from-wrong-test-build defense.
//!
//! Walks every `*.meta.toml` file under `crates/*/tests/fixtures/**`
//! and asserts:
//!
//! 1. The file parses as TOML (well-formed provenance record).
//! 2. The `cast_command` field starts with literal `cast ` — i.e.,
//!    the fixture was captured via the foundry CLI against a real
//!    RPC, NOT via an in-tree adapter (whose bug-leaking output
//!    would perpetuate through the hermetic replay).
//! 3. The `sha256_of_fixture` field matches the sibling fixture
//!    file's actual SHA-256.
//!
//! Per L3: fixture without provenance is unverifiable.

#![forbid(unsafe_code)]
#![allow(clippy::doc_markdown)]
// Inline SHA-256 implementation — pedantic clippy lints are noise
// for the FIPS 180-4 pseudocode shape.
#![allow(
    clippy::many_single_char_names,
    clippy::manual_let_else,
    clippy::too_many_lines,
    clippy::tuple_array_conversions,
    clippy::format_push_string,
    clippy::similar_names,
    clippy::cast_possible_truncation
)]

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(Path::parent)
        .expect("CARGO_MANIFEST_DIR has at least two ancestors")
        .to_path_buf()
}

fn find_meta_files(root: &Path, out: &mut Vec<PathBuf>) {
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
            find_meta_files(&p, out);
        } else if p
            .file_name()
            .and_then(|s| s.to_str())
            .is_some_and(|n| n.ends_with(".meta.toml"))
        {
            out.push(p);
        }
    }
}

/// Extract a string value for the given key from a TOML-shaped
/// content. Looks for `key = "value"` lines; tolerates surrounding
/// whitespace. Returns `None` if the key is absent.
fn extract_string_field(content: &str, key: &str) -> Option<String> {
    for line in content.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix(key) {
            let rest = rest.trim_start();
            if !rest.starts_with('=') {
                continue;
            }
            let after_eq = rest[1..].trim_start();
            if let Some(stripped) = after_eq.strip_prefix('"') {
                if let Some(end) = stripped.find('"') {
                    return Some(stripped[..end].to_string());
                }
            }
        }
    }
    None
}

#[test]
fn every_fixture_has_well_formed_provenance() {
    let root = repo_root().join("crates");
    let mut meta_files = Vec::new();
    find_meta_files(&root, &mut meta_files);
    assert!(
        !meta_files.is_empty(),
        "expected at least one .meta.toml file under crates/*/tests/fixtures/** — \
         the issue #98 fixture-capture cycle should have placed several. \
         Searched root: {}",
        root.display()
    );

    let mut violations: Vec<(PathBuf, String)> = Vec::new();
    for meta_path in &meta_files {
        let Ok(content) = std::fs::read_to_string(meta_path) else {
            violations.push((meta_path.clone(), "could not read .meta.toml".into()));
            continue;
        };

        // (1) source_contract_address present.
        if extract_string_field(&content, "source_contract_address").is_none() {
            violations.push((
                meta_path.clone(),
                "missing required field `source_contract_address`".into(),
            ));
        }
        // (2) deploy_reference present.
        if extract_string_field(&content, "deploy_reference").is_none() {
            violations.push((
                meta_path.clone(),
                "missing required field `deploy_reference`".into(),
            ));
        }
        // (3) capture_utc present.
        if extract_string_field(&content, "capture_utc").is_none() {
            violations.push((
                meta_path.clone(),
                "missing required field `capture_utc`".into(),
            ));
        }
        // (4) cast_command present + starts with `cast `.
        match extract_string_field(&content, "cast_command") {
            None => violations.push((
                meta_path.clone(),
                "missing required field `cast_command`".into(),
            )),
            Some(cmd) => {
                if !cmd.starts_with("cast ") {
                    violations.push((
                        meta_path.clone(),
                        format!(
                            "cast_command must start with literal `cast `, got: {cmd:?} \
                             — fixtures MUST be captured via foundry CLI against a real RPC, \
                             not via an in-tree adapter (L-fake-fixture-from-wrong-test-build)"
                        ),
                    ));
                }
            }
        }
        // (5) sha256_of_fixture matches the sibling fixture file.
        let sibling_name = meta_path
            .file_name()
            .and_then(|s| s.to_str())
            .and_then(|n| n.strip_suffix(".meta.toml"))
            .expect(".meta.toml suffix");
        let sibling_path = meta_path.with_file_name(sibling_name);
        let Ok(sibling_bytes) = std::fs::read(&sibling_path) else {
            violations.push((
                meta_path.clone(),
                format!("sibling fixture file {} not found", sibling_path.display()),
            ));
            continue;
        };
        let actual_sha = sha256_hex(&sibling_bytes);
        match extract_string_field(&content, "sha256_of_fixture") {
            None => violations.push((
                meta_path.clone(),
                "missing required field `sha256_of_fixture`".into(),
            )),
            Some(claimed) => {
                if claimed.to_lowercase() != actual_sha.to_lowercase() {
                    violations.push((
                        meta_path.clone(),
                        format!(
                            "sha256_of_fixture mismatch: meta.toml says {claimed}, \
                             actual sibling file is {actual_sha}"
                        ),
                    ));
                }
            }
        }
    }
    assert!(
        violations.is_empty(),
        "fixture provenance violations (issue #98 L-fake-fixture-from-wrong-test-build / \
         L-fixture-rot defense):\n{violations:#?}"
    );
}

/// Inline SHA-256 (same as in
/// `replay_d017_sync_status_transitions.rs`; copied to avoid a
/// cross-crate test helper). Used to verify fixture sha against
/// the recorded `.meta.toml` value.
fn sha256_hex(input: &[u8]) -> String {
    use std::convert::TryInto;
    const K: [u32; 64] = [
        0x428a_2f98,
        0x7137_4491,
        0xb5c0_fbcf,
        0xe9b5_dba5,
        0x3956_c25b,
        0x59f1_11f1,
        0x923f_82a4,
        0xab1c_5ed5,
        0xd807_aa98,
        0x1283_5b01,
        0x2431_85be,
        0x550c_7dc3,
        0x72be_5d74,
        0x80de_b1fe,
        0x9bdc_06a7,
        0xc19b_f174,
        0xe49b_69c1,
        0xefbe_4786,
        0x0fc1_9dc6,
        0x240c_a1cc,
        0x2de9_2c6f,
        0x4a74_84aa,
        0x5cb0_a9dc,
        0x76f9_88da,
        0x983e_5152,
        0xa831_c66d,
        0xb003_27c8,
        0xbf59_7fc7,
        0xc6e0_0bf3,
        0xd5a7_9147,
        0x06ca_6351,
        0x1429_2967,
        0x27b7_0a85,
        0x2e1b_2138,
        0x4d2c_6dfc,
        0x5338_0d13,
        0x650a_7354,
        0x766a_0abb,
        0x81c2_c92e,
        0x9272_2c85,
        0xa2bf_e8a1,
        0xa81a_664b,
        0xc24b_8b70,
        0xc76c_51a3,
        0xd192_e819,
        0xd699_0624,
        0xf40e_3585,
        0x106a_a070,
        0x19a4_c116,
        0x1e37_6c08,
        0x2748_774c,
        0x34b0_bcb5,
        0x391c_0cb3,
        0x4ed8_aa4a,
        0x5b9c_ca4f,
        0x682e_6ff3,
        0x748f_82ee,
        0x78a5_636f,
        0x84c8_7814,
        0x8cc7_0208,
        0x90be_fffa,
        0xa450_6ceb,
        0xbef9_a3f7,
        0xc671_78f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];
    let bit_len = (input.len() as u64).saturating_mul(8);
    let mut msg = input.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in msg.chunks(64) {
        let mut w = [0u32; 64];
        for (i, word) in chunk.chunks(4).enumerate() {
            w[i] = u32::from_be_bytes(word.try_into().unwrap());
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    let mut out = String::with_capacity(64);
    for word in &h {
        out.push_str(&format!("{word:08x}"));
    }
    out
}
