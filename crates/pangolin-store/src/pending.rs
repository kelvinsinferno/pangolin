//! P9 fix-pass HIGH-1 — partial-failure recovery stash.
//!
//! The `pending_merges` SQL table (defined in [`crate::schema`])
//! persists the ephemeral merge-revision-build state BEFORE the
//! resolve flow calls `adapter.publish`. On retry, the resolve flow
//! reconstructs the SAME `DeviceKey` (from the stashed seed) and
//! re-uses the SAME AEAD nonce + ciphertext, so the canonical hash
//! is identical across runs and the chain event from a prior run can
//! be matched on retry via the existing A3 idempotency scan.
//!
//! Without this stash, every retry of `resolve_one` generates a fresh
//! ephemeral `DeviceKey` AND a fresh AEAD nonce, so the canonical
//! hash differs every run. The chain event from the prior partially-
//! completed run (publish succeeded, `clear_frozen` killed) cannot be
//! matched on retry — leaving the user **permanently stuck with a
//! frozen account**. See `THREAT_MODEL.md` row #13 + `DEVLOG.md` P9
//! fix-pass entry.
//!
//! ## At-rest discipline
//!
//! `device_secret` is the 32-byte Ed25519 secret seed of the
//! ephemeral merge-revision signing key. It lives at rest in the
//! `SQLite` vault file as a BLOB column, NOT additionally AEAD-sealed.
//! The reasoning is bounded-marginal-exposure: at-rest exposure of
//! the `.pvf` file already compromises the VDK and worse (every
//! account's encrypted ciphertext, every chain anchor, every
//! `account_identities` row), so the marginal exposure of an
//! ephemeral merge-signing key is bounded — and the ephemeral key
//! is discarded after `clear_frozen` succeeds (the row is deleted
//! by [`crate::Vault::clear_pending_merge`]).
//!
//! `enc_payload` is the AEAD-sealed merge revision ciphertext
//! produced by [`crate::Vault::build_merge_payload_for_resolve`]
//! BEFORE the stash; it is NOT plaintext (cardinal principle 2 holds).
//!
//! ## Memory hygiene
//!
//! [`PendingMerge::device_secret`] is a [`SecretBytes`] that zeroizes
//! on drop. The struct itself derives no `Clone` / `Debug`-with-
//! secrets and the `device_secret` field is not exposed by `Debug` —
//! the impl below redacts it.

use pangolin_crypto::secret::SecretBytes;

/// Length in bytes of the AEAD nonce stored alongside a pending merge.
///
/// Must equal [`pangolin_crypto::aead::NONCE_LEN`]. We re-export the
/// constant locally so call-sites in `pangolin-store` don't need to
/// reach across the crate boundary for the basic length check.
pub const PENDING_MERGE_NONCE_LEN: usize = pangolin_crypto::aead::NONCE_LEN;

/// Length in bytes of the Ed25519 secret seed stashed for an
/// ephemeral merge-revision signing key.
///
/// Must equal [`pangolin_crypto::sign::SECRET_KEY_LEN`].
pub const PENDING_MERGE_SECRET_LEN: usize = pangolin_crypto::sign::SECRET_KEY_LEN;

/// One stashed merge-revision-build state.
///
/// Returned by [`crate::Vault::take_pending_merge`]. The `device_secret`
/// field is a [`SecretBytes`] that zeroizes on drop. The other fields
/// (`aead_nonce`, `enc_payload`, `schema_version`) are not strictly
/// secret — they are AEAD ciphertext + a nonce that pairs with it,
/// which an attacker holding the vault file already sees — but they
/// are load-bearing for the recovery: every retry of `resolve_one`
/// MUST use the SAME nonce + ciphertext bytes so the canonical hash
/// is stable across retries.
pub struct PendingMerge {
    /// 32-byte Ed25519 secret seed for the ephemeral merge-revision
    /// signing key. Reconstructed via [`pangolin_crypto::keys::DeviceKey::from_seed`].
    /// Zeroizes on drop.
    pub device_secret: SecretBytes,
    /// 24-byte XChaCha20-Poly1305 nonce that the seal call inside
    /// [`crate::Vault::build_merge_payload_for_resolve`] used to
    /// produce the stashed `enc_payload`. The retry path passes both
    /// straight through the publish step without re-sealing.
    pub aead_nonce: [u8; PENDING_MERGE_NONCE_LEN],
    /// AEAD-sealed merge revision payload bytes. Forwarded into
    /// [`pangolin_chain::signing::build_signed_revision`] verbatim on
    /// retry.
    pub enc_payload: Vec<u8>,
    /// Schema version inherited from the chosen revision; baked into
    /// the merge revision's AAD at seal time.
    pub schema_version: u8,
}

impl core::fmt::Debug for PendingMerge {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // device_secret + aead_nonce are sensitive; redact them. The
        // payload's length is informative for debugging without
        // leaking ciphertext bytes (which an attacker holding the
        // vault file already sees, but our discipline is conservative).
        f.debug_struct("PendingMerge")
            .field("device_secret", &"<redacted>")
            .field("aead_nonce", &"<redacted>")
            .field("enc_payload_len", &self.enc_payload.len())
            .field("schema_version", &self.schema_version)
            .finish()
    }
}
