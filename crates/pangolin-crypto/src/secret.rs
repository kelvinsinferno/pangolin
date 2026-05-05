//! Secret-bearing primitive types.
//!
//! [`SecretBytes`] is the canonical owner of arbitrary-length secret data
//! (e.g., user passwords passed to the KDF). It zeroes its memory on drop
//! via the [`zeroize`] crate and never exposes its contents through
//! [`core::fmt::Debug`].
//!
//! Equality on secret material is **not** provided through [`PartialEq`] —
//! callers that legitimately need to compare two secret values must use
//! [`subtle::ConstantTimeEq`] explicitly.

use core::fmt;

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Owned, heap-allocated secret bytes that zero on drop.
///
/// Used for inputs like user passwords passed to the KDF. The internal
/// buffer is wrapped in [`zeroize::Zeroizing`] so that any `Drop` — including
/// drops triggered by panic unwinding — clears the memory.
pub struct SecretBytes {
    inner: zeroize::Zeroizing<Vec<u8>>,
}

impl SecretBytes {
    /// Wraps an existing byte vector. The original `Vec` is moved in and
    /// will be zeroed when this `SecretBytes` is dropped.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            inner: zeroize::Zeroizing::new(bytes),
        }
    }

    /// Borrows the secret bytes for use by a cryptographic operation.
    ///
    /// Callers must avoid copying the slice into another non-zeroizing
    /// buffer, logging it, or otherwise extending the secret's lifetime.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.inner
    }

    /// Returns the byte length of the secret without revealing its contents.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns `true` when the secret holds zero bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Constant-time equality with another secret value.
    ///
    /// Returns a [`subtle::Choice`] rather than a `bool` so that unwary
    /// callers cannot branch on the outcome and create a timing oracle.
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.inner.as_slice().ct_eq(other.inner.as_slice())
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretBytes")
            .field("len", &self.inner.len())
            .field("data", &"<redacted>")
            .finish()
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        // `Zeroizing` already handles this, but we keep an explicit `Drop`
        // impl so the type cannot accidentally implement `Copy` and to
        // guarantee `Zeroize::zeroize` runs even if a future refactor
        // removes the `Zeroizing` wrapper.
        self.inner.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::SecretBytes;

    #[test]
    fn debug_redacts_contents() {
        let s = SecretBytes::new(b"hunter2".to_vec());
        let printed = format!("{s:?}");
        assert!(printed.contains("<redacted>"));
        assert!(!printed.contains("hunter2"));
        assert!(printed.contains("len: 7"));
    }

    #[test]
    fn ct_eq_matches_actual_equality() {
        let a = SecretBytes::new(b"correct".to_vec());
        let b = SecretBytes::new(b"correct".to_vec());
        let c = SecretBytes::new(b"correcz".to_vec());
        assert!(bool::from(a.ct_eq(&b)));
        assert!(!bool::from(a.ct_eq(&c)));
    }

    #[test]
    fn len_and_empty_are_consistent() {
        let s = SecretBytes::new(vec![]);
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
        let s = SecretBytes::new(vec![0u8; 32]);
        assert!(!s.is_empty());
        assert_eq!(s.len(), 32);
    }
}
