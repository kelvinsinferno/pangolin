// SPDX-License-Identifier: AGPL-3.0-or-later
//! Unit tests for the secure-input stub queue.
//!
//! Unit tests can't construct a `tauri::AppHandle` without spinning up
//! the full Tauri runtime, so these tests exercise the stub queue
//! mechanics directly via [`stub::pop_one`] / [`stub::inject`] /
//! [`stub::clear`]. The cfg-dispatched
//! [`crate::secure_input::prompt_password`] is a thin pass-through to
//! `pop_one` under `cfg(test) || feature = "test-hooks"`, so unit-level
//! confidence transfers to the test-feature wizard E2Es.

use super::{stub, SecureInputError};

/// Tests share the global queue singleton — without serialization a
/// parallel test runner can interleave `inject` / `pop_one` / `clear`
/// across tests + race the FIFO ordering. This guard acquires a
/// process-wide lock at test start; only one test runs at a time.
fn test_guard() -> std::sync::MutexGuard<'static, ()> {
    static GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());
    GUARD
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// A queued password round-trips: inject, then pop_one returns the
/// same bytes. The `Zeroizing<Vec<u8>>` wrapper preserves the bytes
/// across the FIFO pop.
#[test]
fn injected_password_round_trips() {
    let _g = test_guard();
    stub::clear();
    stub::inject("hunter2".into());
    let pw = stub::pop_one().expect("queued password");
    assert_eq!(pw.as_slice(), b"hunter2");
}

/// Multiple injections come back in FIFO order (the recoverer wizard
/// fires init-password then finalize-password sequentially).
#[test]
fn fifo_ordering_across_multiple_prompts() {
    let _g = test_guard();
    stub::clear();
    stub::inject("first".into());
    stub::inject("second".into());
    stub::inject("third".into());
    let a = stub::pop_one().unwrap();
    let b = stub::pop_one().unwrap();
    let c = stub::pop_one().unwrap();
    assert_eq!(a.as_slice(), b"first");
    assert_eq!(b.as_slice(), b"second");
    assert_eq!(c.as_slice(), b"third");
}

/// An empty queue returns the typed `TestHookEmpty` error so a wizard
/// E2E that forgets to inject sees a clear test-bug signal.
#[test]
fn empty_queue_returns_test_hook_empty() {
    let _g = test_guard();
    stub::clear();
    let err = stub::pop_one().unwrap_err();
    assert!(matches!(err, SecureInputError::TestHookEmpty));
}

/// `clear()` drains everything in the queue.
#[test]
fn clear_drains_pending_passwords() {
    let _g = test_guard();
    stub::inject("leaked".into());
    stub::clear();
    let err = stub::pop_one().unwrap_err();
    assert!(matches!(err, SecureInputError::TestHookEmpty));
}

/// The `kind` tags are stable strings (the host expects them in the
/// Validation envelope's `kind` field).
#[test]
fn kind_tags_are_stable() {
    assert_eq!(SecureInputError::Cancelled.kind(), "secure_input_cancelled");
    assert_eq!(
        SecureInputError::Unavailable { reason: "x".into() }.kind(),
        "secure_input_unavailable",
    );
    assert_eq!(
        SecureInputError::Internal { reason: "y".into() }.kind(),
        "secure_input_internal",
    );
    assert_eq!(
        SecureInputError::TestHookEmpty.kind(),
        "secure_input_test_hook_empty",
    );
}
