// SPDX-License-Identifier: AGPL-3.0-or-later
//! Issue #98 L-empty-test-body defense.
//!
//! Sweeps the workspace for `#[test]` / `#[tokio::test]` functions
//! whose bodies are `{}` or `{ //... }`-only — these "pass" doing
//! nothing and create a false coverage signal.
//!
//! ## Scope
//!
//! Walks every `.rs` file in the workspace (rooted at this crate's
//! parent-of-parent = the repo root) and asserts no test fn has an
//! empty / comment-only body. The check is intentionally text-grep-
//! based (not `syn`-based) to keep the dependency surface tiny —
//! issue #98 L8 (no new external dep) applies.
//!
//! ## Exceptions
//!
//! `initiate_top_up_live_d019_placeholder` in pangolin-funder-client
//! is the only known-allowed exception (its body comment is
//! load-bearing — it documents the future-live-test slot reservation
//! per L6). The exception list is intentionally narrow + named here
//! so any new empty body fires the sweep + forces a deliberate add
//! to this list.

#![forbid(unsafe_code)]
#![allow(
    clippy::doc_markdown,
    clippy::manual_let_else,
    clippy::single_match_else
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

/// Known exceptions — load-bearing empty bodies per L6 contract.
const ALLOWED_EMPTY: &[&str] = &[
    // The funder-client placeholder is documented in its docstring
    // as the L6-load-bearing slot for the future D-019 live exercise.
    // Body is empty by design until a paid Credit attestation is
    // available for testing.
    "initiate_top_up_live_d019_placeholder",
    // pangolin-crypto compile-time-assertion documentation marker.
    // The real `static_assertions::assert_not_impl_any!` checks run
    // during compile; this fn body is empty by design (its docstring
    // documents the assertion location). See `keys.rs` line ~857.
    "no_serialize_compile_time_assertions_present",
];

fn collect_rs_files(root: &Path, out: &mut Vec<PathBuf>) {
    let read = match std::fs::read_dir(root) {
        Ok(r) => r,
        Err(_) => return,
    };
    for entry in read.flatten() {
        let p = entry.path();
        if p.is_dir() {
            // Skip target/, .git/, .claude/, node_modules/, and
            // workspace-foreign dirs.
            let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if matches!(
                name,
                "target" | ".git" | ".claude" | "node_modules" | ".openclaw" | "dist" | "build"
            ) || name.starts_with('.')
            {
                continue;
            }
            collect_rs_files(&p, out);
        } else if p.extension().and_then(|s| s.to_str()) == Some("rs") {
            out.push(p);
        }
    }
}

/// Returns `Some(fn_name)` if `body` is empty / comment-only;
/// otherwise `None`.
///
/// The "body" passed in is the content between the matching `{` and
/// `}` braces (caller already stripped them). We strip line + block
/// comments + whitespace, then check if the residue is empty.
fn body_is_empty_or_comment_only(body: &str) -> bool {
    let mut s = String::with_capacity(body.len());
    // Strip /* ... */ block comments (single-line only to keep this
    // simple).
    let mut chars = body.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '/' && chars.peek() == Some(&'/') {
            // Line comment — skip to end of line.
            while let Some(&n) = chars.peek() {
                if n == '\n' {
                    break;
                }
                chars.next();
            }
        } else if c == '/' && chars.peek() == Some(&'*') {
            chars.next();
            // Block comment.
            while let Some(c2) = chars.next() {
                if c2 == '*' && chars.peek() == Some(&'/') {
                    chars.next();
                    break;
                }
            }
        } else {
            s.push(c);
        }
    }
    s.trim().is_empty()
}

/// Finds `#[test]` or `#[tokio::test]` attrs followed by an `async
/// fn` or `fn` declaration; returns `(fn_name, body)` pairs.
///
/// The function is over the clippy `too_many_lines` threshold (100)
/// because the raw-string-aware brace counter is intentionally
/// open-coded in-line rather than split out — fragmenting it across
/// helper fns obscures the linear scanner state machine that's
/// load-bearing for the F-3 fix. The block is comprehensively
/// commented + covered by 4 unit tests.
#[allow(clippy::too_many_lines)]
fn find_test_fns(content: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut idx = 0usize;
    let bytes = content.as_bytes();
    while idx < bytes.len() {
        // Find next `#[test]` or `#[tokio::test]` attr.
        let rest = &content[idx..];
        let test_at = rest.find("#[test]");
        let tokio_at = rest.find("#[tokio::test");
        let attr_offset = match (test_at, tokio_at) {
            (None, None) => break,
            (Some(a), None) => a,
            (None, Some(b)) => b,
            (Some(a), Some(b)) => a.min(b),
        };
        let cursor = idx + attr_offset;
        // Skip past the attribute line.
        let after_attr = content[cursor..]
            .find('\n')
            .map_or(content.len(), |n| cursor + n + 1);
        // Find `fn ` after any further attributes.
        let lookahead = &content[after_attr..];
        let mut scan = 0;
        let mut found_fn_at = None;
        while scan < lookahead.len() {
            let line_end = lookahead[scan..]
                .find('\n')
                .map_or(lookahead.len(), |n| scan + n + 1);
            let line = &lookahead[scan..line_end];
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || trimmed.starts_with("#[") || trimmed.is_empty() {
                scan = line_end;
                continue;
            }
            // Look for `fn ` or `async fn ` in this line.
            if let Some(fn_pos) = trimmed.find("fn ") {
                found_fn_at = Some(scan + (line.len() - trimmed.len()) + fn_pos);
            }
            break;
        }
        let Some(fn_offset) = found_fn_at else {
            idx = after_attr;
            continue;
        };
        let fn_start = after_attr + fn_offset + 3; // past "fn "
                                                   // Extract fn name: up to `(` or whitespace.
        let mut name_end = fn_start;
        while name_end < content.len() {
            let c = content.as_bytes()[name_end];
            if c == b'(' || c == b'<' || c == b' ' || c == b'\n' || c == b'\t' {
                break;
            }
            name_end += 1;
        }
        let fn_name = content[fn_start..name_end].trim().to_string();
        // Find opening `{`.
        let brace_open = match content[name_end..].find('{') {
            Some(b) => name_end + b,
            None => {
                idx = name_end;
                continue;
            }
        };
        // Find matching `}` with depth counting. The scanner skips
        // contents of regular string literals (`"..."`) and raw
        // string literals (`r"..."`, `r#"..."#`, `r##"..."##`, ...,
        // also `br...` byte raw strings) so that braces appearing
        // INSIDE strings don't perturb the depth count. Raw strings
        // are load-bearing because their content cannot use `\` to
        // escape a `"`, and JSON / contract-bytecode literals
        // commonly embedded in tests do contain `{` / `}` chars
        // (issue #98 F-3 audit finding).
        let mut depth = 1i32;
        let mut i = brace_open + 1;
        let bytes2 = content.as_bytes();
        while i < bytes2.len() && depth > 0 {
            // Raw string detection: `r"...`, `r#"..."#`, `br"...`,
            // `br#"..."#`, etc. The `r` (or `br`) must be at a
            // token-start position — i.e., the preceding byte must
            // not be an ASCII identifier-continuation byte (letter,
            // digit, or underscore). Conservative: false-negative
            // (treating `var` followed by `"` as a regular string
            // boundary) is safe; false-positive (treating an
            // identifier ending in `r` as a raw-string start) is
            // the hazard, so the prev-byte check forbids it.
            let is_token_start = i == brace_open + 1
                || !matches!(bytes2[i - 1], b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_');
            if is_token_start {
                // Optional `b` prefix for byte raw strings.
                let mut probe = i;
                if probe < bytes2.len() && bytes2[probe] == b'b' {
                    probe += 1;
                }
                if probe < bytes2.len() && bytes2[probe] == b'r' {
                    probe += 1;
                    // Count `#` chars.
                    let hash_start = probe;
                    while probe < bytes2.len() && bytes2[probe] == b'#' {
                        probe += 1;
                    }
                    let n_hashes = probe - hash_start;
                    if probe < bytes2.len() && bytes2[probe] == b'"' {
                        // Confirmed raw-string open. Skip to matching
                        // `"` followed by exactly `n_hashes` `#`.
                        // (`r"..."` with `n_hashes == 0` closes on
                        // the next `"`.)
                        let mut j = probe + 1;
                        loop {
                            if j >= bytes2.len() {
                                // Unterminated raw string — fall
                                // through and let the outer loop
                                // resolve. Best-effort.
                                break;
                            }
                            if bytes2[j] == b'"' {
                                // Check trailing `#` run.
                                let mut k = 0;
                                while k < n_hashes
                                    && j + 1 + k < bytes2.len()
                                    && bytes2[j + 1 + k] == b'#'
                                {
                                    k += 1;
                                }
                                if k == n_hashes {
                                    j += 1 + n_hashes; // past the closing `"` + hashes
                                    break;
                                }
                            }
                            j += 1;
                        }
                        i = j;
                        continue;
                    }
                }
            }

            match bytes2[i] {
                b'{' => depth += 1,
                b'}' => depth -= 1,
                b'"' => {
                    // Skip regular string literals (simple — no
                    // escape handling needed for typical test
                    // bodies; `\"` is the only relevant escape).
                    i += 1;
                    while i < bytes2.len() && bytes2[i] != b'"' {
                        if bytes2[i] == b'\\' && i + 1 < bytes2.len() {
                            i += 2;
                            continue;
                        }
                        i += 1;
                    }
                }
                _ => {}
            }
            i += 1;
        }
        if depth != 0 {
            idx = brace_open + 1;
            continue;
        }
        let body = &content[brace_open + 1..i - 1];
        out.push((fn_name, body.to_string()));
        idx = i;
    }
    out
}

#[test]
fn no_empty_test_bodies_workspace_wide() {
    let root = repo_root();
    let mut files = Vec::new();
    collect_rs_files(&root, &mut files);
    assert!(
        !files.is_empty(),
        "should have collected at least one .rs file under {}",
        root.display()
    );

    let mut violations: Vec<(PathBuf, String)> = Vec::new();
    for path in &files {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        for (fn_name, body) in find_test_fns(&content) {
            if ALLOWED_EMPTY.contains(&fn_name.as_str()) {
                continue;
            }
            if body_is_empty_or_comment_only(&body) {
                violations.push((path.clone(), fn_name));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "L-empty-test-body violations found: {violations:#?}\n\
         These `#[test]` fns have empty or comment-only bodies — they \
         \"pass\" doing nothing. Either: (a) populate the body with a \
         real assertion, (b) remove the fn + migrate intent to a \
         RUNBOOK.md section (issue #98 precedent), or (c) add the \
         function name to ALLOWED_EMPTY in this test if its empty \
         body is genuinely load-bearing (e.g., the funder-client D-019 \
         placeholder)."
    );
}

// ──────────────────────────────────────────────────────────────────
// Issue #98 F-3 fix-pass: raw-string awareness in the brace-counter.
//
// Before F-3 the scanner skipped regular `"..."` literals only;
// raw strings (`r#"..."#`, `br#"..."#`, etc.) were scanned
// byte-by-byte, so any `{` or `}` inside the raw-string content
// perturbed the depth counter. If a test fn body contained a raw
// string with unbalanced braces (very common in tests that pin
// JSON or contract-bytecode fragments), the scanner could either
// miss an empty body (depth never reaches 0 inside the fn) or —
// worse — false-positive a non-empty body by terminating early at
// a stray `}` inside the raw string and treating the rest of the
// fn as outside.
//
// The two tests below feed synthetic Rust source through
// `find_test_fns` and assert it correctly identifies the fn name
// + body for raw strings whose content contains unbalanced braces.
// ──────────────────────────────────────────────────────────────────

#[test]
fn raw_string_with_unbalanced_braces_does_not_corrupt_scanner() {
    // A test fn whose body contains a raw string with three opening
    // `{` and no closing `}`, followed by `panic!()`. Before F-3 the
    // depth counter would over-count and the scanner would over-run
    // (or under-shoot) the fn body. After F-3 the raw-string
    // content is skipped entirely and the body is correctly
    // identified.
    let src = "\
#[test]
fn raw_unbalanced() {
    let s = r#\"{{{ unbalanced {{ braces\"#;
    panic!(\"body is non-empty\");
}
";
    let fns = find_test_fns(src);
    assert_eq!(fns.len(), 1, "scanner must find exactly one test fn");
    let (name, body) = &fns[0];
    assert_eq!(name, "raw_unbalanced");
    assert!(
        body.contains("panic!"),
        "scanner must capture the post-raw-string body content; got: {body:?}"
    );
    assert!(
        !body_is_empty_or_comment_only(body),
        "body must register as NON-empty"
    );
}

#[test]
fn byte_raw_string_handled_correctly() {
    // Same shape but with a byte raw string `br#"..."#`. The
    // `b` prefix MUST be recognized — otherwise a test pinning
    // binary fixture bytes inline would corrupt the scanner.
    let src = "\
#[test]
fn byte_raw_unbalanced() {
    let s: &[u8] = br#\"}}} more {{ unbalanced\"#;
    assert!(!s.is_empty());
}
";
    let fns = find_test_fns(src);
    assert_eq!(fns.len(), 1);
    let (name, body) = &fns[0];
    assert_eq!(name, "byte_raw_unbalanced");
    assert!(
        body.contains("assert!"),
        "scanner must capture the post-byte-raw-string body; got: {body:?}"
    );
    assert!(
        !body_is_empty_or_comment_only(body),
        "body must register as NON-empty"
    );
}

#[test]
fn raw_string_with_multiple_hashes_handled() {
    // Defense for `r##"..."##` (two hashes) — the matching close
    // must consume exactly two `#`, not one. If the scanner closed
    // on the first `"#`, content past that point would be
    // re-scanned (and any embedded `}` would close the fn early).
    let src = "\
#[test]
fn multi_hash_raw() {
    let s = r##\"close-only-with-double-hash \"# still inside }}}\"##;
    let _ = s;
    assert_eq!(1 + 1, 2);
}
";
    let fns = find_test_fns(src);
    assert_eq!(fns.len(), 1);
    let (name, body) = &fns[0];
    assert_eq!(name, "multi_hash_raw");
    assert!(
        body.contains("assert_eq!"),
        "scanner must reach the post-raw-string assert; got: {body:?}"
    );
}

#[test]
fn identifier_ending_in_r_not_treated_as_raw_string() {
    // Conservative-correctness check: `var"..."` — where `var` is
    // an identifier ending in `r` — must NOT be misread as a
    // raw-string open. (Real Rust forbids this construct entirely;
    // the scanner's job is to not generate a false-positive that
    // would over-skip content.) The previous-byte-is-id-continuation
    // check guards this case.
    let src = "\
#[test]
fn ident_then_string() {
    let var = \"hello\";
    let _ = var;
    assert!(true);
}
";
    let fns = find_test_fns(src);
    assert_eq!(fns.len(), 1);
    let (name, body) = &fns[0];
    assert_eq!(name, "ident_then_string");
    assert!(
        body.contains("assert!"),
        "body must include the post-string assert; got: {body:?}"
    );
}
