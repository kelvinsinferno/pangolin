// SPDX-License-Identifier: AGPL-3.0-or-later
//! §4.3 per-column AEAD (ARCH-1): integration tests for the binary
//! handshake IPC surface.
//!
//! The in-source unit tests in `src/handshake.rs::tests` cover the
//! pure round-trip + boundary-rejection properties via in-memory
//! cursors. This file exercises the IPC surface end-to-end via
//! `std::process::Command` to spawn the real `pangolin-indexer`
//! binary + write the handshake to its stdin.
//!
//! ## Test posture
//!
//! The binary expects a successful handshake BEFORE any protocol
//! line. If the handshake fails, the binary exits non-zero with a
//! stderr error. The tests below pin:
//!
//! 1. **Round-trip:** a well-formed handshake lets the binary reach
//!    the protocol loop. We confirm by sending a `Heartbeat`
//!    request after the handshake and observing the `Heartbeat`
//!    response on stdout.
//! 2. **Truncated prefix:** closing stdin after writing 2 of the
//!    4 length-prefix bytes causes the binary to exit with a
//!    non-zero status + a stderr message naming the handshake
//!    failure.
//! 3. **Oversize prefix:** writing a length prefix > 256 causes
//!    the binary to fail-closed without OOMing.
//!
//! ## Why these are integration tests + not subprocess unit tests
//!
//! The binary's stdio loop uses tokio's async stdin, which requires
//! a real child process to exercise the FD multiplexing between the
//! synchronous handshake read + the async line reader. In-source
//! `tokio::test` cases can't drive that path because they share the
//! parent test process's stdin.
//!
//! ## Skip mode
//!
//! On platforms / CI environments where the workspace binary can't
//! be located (e.g., `cargo test --no-run` outputs but the bin
//! target hasn't been built yet), each test SKIPs with a stderr
//! note + `return`. This keeps the suite green in incremental
//! builds; CI runs `cargo build --bin pangolin-indexer` before
//! `cargo test` so the binary is reliably available there.

#![forbid(unsafe_code)]
#![allow(clippy::doc_markdown, clippy::uninlined_format_args)]

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use pangolin_indexer::{write_handshake, IndexerHandshake};

/// Locate the freshly-built `pangolin-indexer` binary. Cargo sets
/// `CARGO_BIN_EXE_pangolin-indexer` for integration tests when
/// the binary target is present.
fn binary_path() -> Option<PathBuf> {
    option_env!("CARGO_BIN_EXE_pangolin-indexer").map(PathBuf::from)
}

/// Build a fresh handshake with well-known bytes.
fn sample_handshake() -> IndexerHandshake {
    let mut k = [0u8; 32];
    for (i, b) in k.iter_mut().enumerate() {
        *b = u8::try_from(i).unwrap();
    }
    let n = [0xABu8; 16];
    IndexerHandshake::new(k, n)
}

/// **Round-trip:** a well-formed handshake lets the binary reach
/// the protocol loop. We then send a `Heartbeat` request + observe
/// the `Heartbeat` response on stdout.
#[test]
fn well_formed_handshake_unlocks_protocol_loop() {
    let Some(bin) = binary_path() else {
        eprintln!("SKIP: pangolin-indexer binary not available (CARGO_BIN_EXE not set)");
        return;
    };

    let mut child = Command::new(&bin)
        .arg("--rpc-url")
        .arg("http://localhost:1") // any URL — we don't drive StartIndex
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("PANGOLIN_INDEXER_IDLE_TIMEOUT_SECS", "60")
        .spawn()
        .expect("spawn pangolin-indexer");

    let mut stdin = child.stdin.take().expect("child stdin");
    let mut stdout = child.stdout.take().expect("child stdout");

    // Write the handshake.
    let h = sample_handshake();
    write_handshake(&mut stdin, &h).expect("write handshake");

    // Send a Heartbeat line on the same FD (the protocol stream
    // begins immediately after the handshake bytes).
    stdin
        .write_all(b"{\"type\":\"heartbeat\"}\n")
        .expect("write heartbeat");
    stdin.flush().expect("flush");

    // Read one line of response. We use a small read budget +
    // a short timeout via spawned reader thread.
    let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
    std::thread::spawn(move || {
        let mut buf = vec![0u8; 4096];
        if let Ok(n) = stdout.read(&mut buf) {
            buf.truncate(n);
            let _ = tx.send(buf);
        }
    });
    let raw = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("response within timeout");
    let line = String::from_utf8(raw).expect("utf8 response");
    assert!(
        line.contains("\"heartbeat\""),
        "expected heartbeat response, got: {line}",
    );

    // Tell the binary to stop so the worker exits cleanly.
    let _ = stdin.write_all(b"{\"type\":\"stop\"}\n");
    let _ = stdin.flush();
    let _ = child.kill();
    let _ = child.wait();
}

/// **Truncated prefix:** closing stdin after writing 2 of the 4
/// length-prefix bytes causes the binary to exit with a non-zero
/// status. The exit message names the handshake failure.
#[test]
fn truncated_handshake_prefix_fails_binary() {
    let Some(bin) = binary_path() else {
        eprintln!("SKIP: pangolin-indexer binary not available");
        return;
    };

    let mut child = Command::new(&bin)
        .arg("--rpc-url")
        .arg("http://localhost:1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("PANGOLIN_INDEXER_IDLE_TIMEOUT_SECS", "60")
        .spawn()
        .expect("spawn pangolin-indexer");

    {
        let mut stdin = child.stdin.take().expect("child stdin");
        stdin.write_all(&[0u8, 0u8]).expect("write partial prefix");
        // Drop stdin to close it.
        drop(stdin);
    }

    let status = child.wait_with_output().expect("wait");
    assert!(
        !status.status.success(),
        "binary must exit non-zero on truncated handshake prefix"
    );
    let stderr = String::from_utf8_lossy(&status.stderr);
    assert!(
        stderr.contains("handshake") || stderr.contains("Config"),
        "stderr must name the handshake failure: {stderr}",
    );
}

/// **Oversize prefix:** writing a length prefix > 256 causes the
/// binary to fail-closed without OOMing.
#[test]
fn oversize_handshake_prefix_fails_binary() {
    let Some(bin) = binary_path() else {
        eprintln!("SKIP: pangolin-indexer binary not available");
        return;
    };

    let mut child = Command::new(&bin)
        .arg("--rpc-url")
        .arg("http://localhost:1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("PANGOLIN_INDEXER_IDLE_TIMEOUT_SECS", "60")
        .spawn()
        .expect("spawn pangolin-indexer");

    {
        let mut stdin = child.stdin.take().expect("child stdin");
        // 4MiB length prefix — well over the 256-byte cap.
        let huge: u32 = 4 * 1024 * 1024;
        stdin
            .write_all(&huge.to_be_bytes())
            .expect("write oversize prefix");
        // Close stdin. The binary should reject BEFORE attempting
        // to allocate 4MiB.
        drop(stdin);
    }

    let status = child.wait_with_output().expect("wait");
    assert!(
        !status.status.success(),
        "binary must exit non-zero on oversize handshake prefix"
    );
}

/// **Binary random-key sweep:** the binary's main.rs no longer
/// invokes `OsRng::fill_bytes` / `fill_random` to mint a key —
/// it consumes the key from the handshake. We verify this by
/// grep-scanning the binary source file.
///
/// This is a structural test (not a runtime test) — if a future
/// refactor reintroduces the random-key path, this fails at the
/// build-stage. Mirrors the spec's "Binary random-key sweep"
/// invariant.
#[test]
fn binary_random_key_path_removed() {
    let bin_src = include_str!("../src/bin/pangolin-indexer.rs");
    // The pre-§4.3-per-column-AEAD path called `fill_random(&mut
    // key_bytes)`. The post-cycle path uses `read_handshake` and
    // `handshake.derived_key`. We scan ONLY non-comment lines so a
    // doc comment that legitimately mentions the removed call
    // (e.g., "the OsRng::fill_bytes path is gone") does not trip
    // the regression check.
    let mut offending: Vec<(usize, String)> = Vec::new();
    for (i, line) in bin_src.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") {
            continue; // doc / line comment
        }
        if trimmed.starts_with("/*") || trimmed.starts_with('*') {
            continue; // block-comment continuation
        }
        if trimmed.contains("fill_random(") || trimmed.contains("OsRng::fill_bytes") {
            offending.push((i + 1, line.to_string()));
        }
    }
    assert!(
        offending.is_empty(),
        "L-binary-random-key-leak REGRESSION: pangolin-indexer binary main.rs has \
         non-comment lines using the random-key path: {:?}\n\nThe §4.3 per-column AEAD \
         ARCH-1 contract requires the binary to consume the derived key via the \
         handshake instead.",
        offending,
    );
    // Positive assertion: the handshake consumer is wired.
    assert!(
        bin_src.contains("read_handshake"),
        "pangolin-indexer binary must call read_handshake on startup",
    );
}
