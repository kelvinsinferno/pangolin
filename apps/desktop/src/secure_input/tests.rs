// SPDX-License-Identifier: AGPL-3.0-or-later
//! Unit tests for the secure-input stub. Compiled under `cfg(test)`,
//! shares the queue with the test-hook command in `crate::test_hooks`
//! (no separate queue — the singleton in [`stub::queue`] is the only
//! one).

use super::{prompt_password, stub, SecureInputError};

/// A queued password round-trips: inject, then prompt returns the
/// same bytes. The `Zeroizing<Vec<u8>>` wrapper preserves the bytes
/// across the FIFO pop.
#[test]
fn injected_password_round_trips() {
    stub::clear();
    stub::inject("hunter2".into());
    let pw = prompt_password("Unlock", "Enter master password").unwrap();
    assert_eq!(pw.as_slice(), b"hunter2");
}

/// Multiple injections come back in FIFO order (the recoverer wizard
/// fires init-password then finalize-password sequentially).
#[test]
fn fifo_ordering_across_multiple_prompts() {
    stub::clear();
    stub::inject("first".into());
    stub::inject("second".into());
    stub::inject("third".into());
    let a = prompt_password("a", "a").unwrap();
    let b = prompt_password("b", "b").unwrap();
    let c = prompt_password("c", "c").unwrap();
    assert_eq!(a.as_slice(), b"first");
    assert_eq!(b.as_slice(), b"second");
    assert_eq!(c.as_slice(), b"third");
}

/// An empty queue returns the typed `TestHookEmpty` error so a wizard
/// E2E that forgets to inject sees a clear test-bug signal.
#[test]
fn empty_queue_returns_test_hook_empty() {
    stub::clear();
    let err = prompt_password("Unlock", "...").unwrap_err();
    assert!(matches!(err, SecureInputError::TestHookEmpty));
}

/// `clear()` drains everything in the queue.
#[test]
fn clear_drains_pending_passwords() {
    stub::inject("leaked".into());
    stub::clear();
    let err = prompt_password("Unlock", "...").unwrap_err();
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
