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
        // Find matching `}` with depth counting.
        let mut depth = 1i32;
        let mut i = brace_open + 1;
        let bytes2 = content.as_bytes();
        while i < bytes2.len() && depth > 0 {
            match bytes2[i] {
                b'{' => depth += 1,
                b'}' => depth -= 1,
                b'"' => {
                    // Skip string literals (simple — no escape
                    // handling needed for typical test bodies).
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
