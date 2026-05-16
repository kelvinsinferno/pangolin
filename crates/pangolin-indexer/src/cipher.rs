// SPDX-License-Identifier: AGPL-3.0-or-later
//! 4.2 R-d temp-DB cipher hook.
//!
//! 4.2 ships the trait surface + a passthrough no-op implementation;
//! 4.3 swaps in the real `AeadCipher` impl (ephemeral per-run key,
//! XChaCha20-Poly1305, explicit zero-fill before unlink). The
//! architectural-locking property is that the lifecycle code in
//! [`crate::session`] holds an `Arc<dyn TempDbCipher>` — 4.3 changes
//! the constructor wiring (`NoOpCipher::new` → `AeadCipher::new`) and
//! nothing else.
//!
//! Per L8 of 4.2: every fn forbids unsafe. Per L9: AGPL SPDX header.
//!
//! ## L-temp-file-leak posture in 4.2 vs 4.3
//!
//! - **4.2 (this file):** [`NoOpCipher::encrypt_page`] returns the
//!   plaintext unchanged; [`NoOpCipher::decrypt_page`] returns the
//!   ciphertext unchanged. The trait surface is reachable from the
//!   session lifecycle but is currently a no-op; a recovered temp
//!   file leaks plaintext metadata (mitigated only by
//!   `tempfile::NamedTempFile`'s random path + Drop-based cleanup).
//! - **4.3 (deferred):** real `AeadCipher` impl wraps each SQLite
//!   page in a fresh AEAD seal; the temp file contains only
//!   ciphertext + nonces; the ephemeral key never persists.
//!
//! The trait surface is intentionally minimal so 4.3 can replace
//! the impl without changing the trait or the session.

use std::sync::Arc;

/// Per-page block cipher used by the temp DB. `encrypt_page` is
/// called before each page write; `decrypt_page` is called after
/// each page read. The trait is `Send + Sync` so it can be shared
/// across the lifecycle task in both the desktop subprocess and
/// mobile in-process flows (L12).
///
/// 4.2 ships the no-op [`NoOpCipher`]; 4.3 implements the real
/// `AeadCipher` against this exact trait shape.
pub trait TempDbCipher: Send + Sync + std::fmt::Debug {
    /// Transform a plaintext page into the ciphertext to write on
    /// disk. 4.2 [`NoOpCipher`] returns `plaintext.to_vec()`.
    fn encrypt_page(&self, plaintext: &[u8]) -> Vec<u8>;

    /// Transform a ciphertext page read off disk back into
    /// plaintext. 4.2 [`NoOpCipher`] returns `ciphertext.to_vec()`.
    fn decrypt_page(&self, ciphertext: &[u8]) -> Vec<u8>;
}

/// 4.2 R-d no-op cipher — identity functions on both sides.
///
/// This impl is the placeholder that lets the session lifecycle
/// hold an `Arc<dyn TempDbCipher>` today. The 4.3 hardening pass
/// will swap this for an `AeadCipher` impl with no callsite churn.
///
/// **DO NOT** ship `NoOpCipher` in any production sync path beyond
/// 4.2's skeleton scope. 4.3's `AeadCipher` is the real defense.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoOpCipher;

impl NoOpCipher {
    /// Constructor convenience. Returns an `Arc<dyn TempDbCipher>`
    /// in the shape the session expects.
    #[must_use]
    pub fn new_arc() -> Arc<dyn TempDbCipher> {
        Arc::new(Self)
    }
}

impl TempDbCipher for NoOpCipher {
    fn encrypt_page(&self, plaintext: &[u8]) -> Vec<u8> {
        plaintext.to_vec()
    }

    fn decrypt_page(&self, ciphertext: &[u8]) -> Vec<u8> {
        ciphertext.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_encrypt_is_identity_on_empty_input() {
        let c = NoOpCipher;
        assert_eq!(c.encrypt_page(&[]), Vec::<u8>::new());
    }

    #[test]
    fn noop_encrypt_is_identity_on_arbitrary_input() {
        let c = NoOpCipher;
        let plaintext = b"the temp DB is full of pancakes";
        assert_eq!(c.encrypt_page(plaintext), plaintext.to_vec());
    }

    #[test]
    fn noop_decrypt_is_identity() {
        let c = NoOpCipher;
        let ciphertext = vec![1, 2, 3, 4, 5];
        assert_eq!(c.decrypt_page(&ciphertext), ciphertext);
    }

    #[test]
    fn noop_round_trips() {
        // 4.2 R-d test contract: NoOpCipher must round-trip
        // identically. This is the scaffolding-correctness check
        // that 4.3's AeadCipher must also satisfy (with the
        // ephemeral key threaded through).
        let c = NoOpCipher;
        for n in [0usize, 1, 16, 4096, 1 << 16] {
            let buf: Vec<u8> = (0..n).map(|i| u8::try_from(i & 0xFF).unwrap()).collect();
            let enc = c.encrypt_page(&buf);
            let dec = c.decrypt_page(&enc);
            assert_eq!(buf, dec, "round-trip failed for n = {n}");
        }
    }

    #[test]
    fn noop_cipher_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<NoOpCipher>();
        // The Arc<dyn TempDbCipher> shape the session uses.
        let arc: Arc<dyn TempDbCipher> = NoOpCipher::new_arc();
        assert_eq!(arc.encrypt_page(b"x"), b"x".to_vec());
    }
}
