//! Secret-bearing primitive types.
//!
//! [`SecretBytes`] is the canonical owner of arbitrary-length secret data
//! (e.g., user passwords passed to the KDF). It zeroes its memory on drop
//! via the [`zeroize`] crate and never exposes its contents through
//! [`core::fmt::Debug`].
//!
//! [`BoxedSecret`] is a heap-allocated owner of a fixed-size secret array
//! used by `AeadKey` and `VdkKey` (per MEDIUM-8) — heap allocation gives
//! stronger move-semantics safety because the secret bytes never move
//! through stack frames during a return-by-value chain.
//!
//! Equality on secret material is **not** provided through [`PartialEq`] —
//! callers that legitimately need to compare two secret values must use
//! [`subtle::ConstantTimeEq`] explicitly.

use core::fmt;

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Heap-allocated, zero-on-drop, fixed-size secret buffer.
///
/// The standard `Zeroizing<Box<[u8; N]>>` pattern doesn't work directly
/// because `zeroize 1.8` does not provide a `Zeroize` impl on
/// `Box<[u8; N]>` (it covers `Box<[u8]>` slices, but not boxed arrays).
/// `BoxedSecret` is a thin newtype around `Box<[u8; N]>` with a manual
/// `Zeroize` impl that wipes the heap allocation in place — the address
/// is stable because the value is owned and not moved.
///
/// The dereference accessors deliberately go through `&[u8; N]` rather
/// than handing out a raw pointer so that the type system can't be
/// bypassed by accident.
///
/// Heap-allocation cost is `N` bytes per instance — for `KEY_LEN = 32`
/// this is a single 32-byte allocation per key, negligible compared to
/// the AEAD context that holds it.
pub struct BoxedSecret<const N: usize> {
    inner: Box<[u8; N]>,
}

impl<const N: usize> BoxedSecret<N> {
    /// Wraps caller-supplied bytes by moving them onto the heap. The
    /// caller's stack-allocated array is the caller's responsibility to
    /// zeroize after this call returns.
    #[must_use]
    pub fn new(bytes: [u8; N]) -> Self {
        Self {
            inner: Box::new(bytes),
        }
    }

    /// Returns a reference to the stored bytes.
    #[must_use]
    pub fn as_array(&self) -> &[u8; N] {
        &self.inner
    }

    /// Returns a slice view of the stored bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        self.inner.as_slice()
    }
}

impl<const N: usize> Zeroize for BoxedSecret<N> {
    fn zeroize(&mut self) {
        // `[u8; N]` implements `Zeroize`; `Box::deref_mut` gives us a
        // stable mutable reference to the heap allocation, so the wipe
        // hits the same bytes that any borrow has been seeing.
        (*self.inner).zeroize();
    }
}

impl<const N: usize> Drop for BoxedSecret<N> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// Marker trait — runtime contract is fulfilled by the `Drop` impl above;
// implementing the marker makes the intent self-documenting and lets
// downstream callers `assert_impl_all!(BoxedSecret<32>: ZeroizeOnDrop)`
// at compile time if they want extra defense-in-depth.
impl<const N: usize> ZeroizeOnDrop for BoxedSecret<N> {}

impl<const N: usize> fmt::Debug for BoxedSecret<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoxedSecret")
            .field("len", &N)
            .field("data", &"<redacted>")
            .finish()
    }
}

// `BoxedSecret` carries the same "no Clone, no Copy, no PartialEq, no
// Serialize" discipline as the rest of the secret-bearing surface.
// We deliberately do not derive any of those traits.

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

impl ZeroizeOnDrop for SecretBytes {}

#[cfg(test)]
mod tests {
    use super::{BoxedSecret, SecretBytes};
    use zeroize::Zeroize;

    #[test]
    fn boxed_secret_round_trips_bytes() {
        let bs: BoxedSecret<32> = BoxedSecret::new([0x42; 32]);
        assert_eq!(bs.as_array(), &[0x42u8; 32]);
        assert_eq!(bs.as_slice().len(), 32);
    }

    #[test]
    fn boxed_secret_zeroizes_in_place() {
        let mut bs: BoxedSecret<8> = BoxedSecret::new([0xFFu8; 8]);
        assert_eq!(bs.as_array(), &[0xFFu8; 8]);
        bs.zeroize();
        assert_eq!(bs.as_array(), &[0u8; 8]);
    }

    #[test]
    fn boxed_secret_debug_redacts() {
        let bs: BoxedSecret<32> = BoxedSecret::new([0xAB; 32]);
        let printed = format!("{bs:?}");
        assert!(printed.contains("<redacted>"));
        assert!(!printed.contains("ab"));
        assert!(printed.contains("len: 32"));
    }

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
