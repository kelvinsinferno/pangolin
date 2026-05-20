// SPDX-License-Identifier: AGPL-3.0-or-later
//! Guardian-escrow / threshold-VDK-recovery primitive (#104a, Scheme A).
//!
//! This module is the catastrophic-if-wrong heart of Pangolin's social
//! recovery: it threshold-splits a fresh **`RecoveryWrapKey` (RWK)** across
//! guardians so that any `t`-of-`M` of them can reconstruct it (and hence
//! the VDK), while **fewer than `t` learn nothing**. It is the only
//! net-new primitive-level crypto in a crate that otherwise "reuses vetted
//! libraries, never invents." Every byte here is composition over two
//! audited libraries — `vsss-rs` (constant-time GF(2^8) Shamir) and
//! `crypto_box` (libsodium sealed boxes) — plus the crate's own existing
//! AEAD wrap machinery.
//!
//! ### Scheme A (locked — see `docs/issue-plans/104-recovery-escrow-crypto.md`)
//!
//! The VDK is wrapped **twice**: once under the password-derived
//! [`crate::keys::AuthorityKey`] (the daily path, in `keys.rs`, unchanged)
//! and once here under a fresh 32-byte RWK ([`WrappedVdkRecovery`]). RWK is
//! `t`-of-`M` Shamir-split over GF(2^8) into [`Share`]s; each share is
//! sealed to a guardian's X25519 public key ([`SealedShare`]). Recovery
//! collects `>= t` shares, reconstructs RWK, and unwraps the
//! byte-identical VDK. Recovery never needs the old password.
//!
//! ### Security properties (the in-house adversarial audit is the ONLY review)
//!
//! - **L1/L2 — `< t` reveals nothing.** Shamir over a field is
//!   information-theoretically secure below threshold: any `t-1` shares are
//!   consistent with *every* possible RWK. The library samples polynomial
//!   coefficients uniformly (its own audit findings #1/#2 fixed in 5.4.0);
//!   we exercise this hard in tests.
//! - **L5 — byte-identical VDK.** Reconstructing RWK and unwrapping yields
//!   a VDK that `ct_eq`s the original bit-for-bit; the VDK is re-wrapped,
//!   never re-derived.
//! - **L6 — zero-serde / secret discipline.** No serde anywhere (both deps
//!   added `default-features = false`); [`RecoveryWrapKey`] is `!Clone`,
//!   `!Copy`, zeroizing, redacted-`Debug`, `ct_eq`. Fixed-layout byte
//!   encodings, never serde derives.
//! - **L8 — domain separation / replay.** Both the RWK→VDK wrap (via the
//!   existing [`crate::keys::WrapContext`] AAD) and the sealed-share
//!   envelope bind `vault_id` + an `epoch` so a share/wrapper for vault A /
//!   a stale epoch cannot be replayed against vault B / a fresh epoch.
//!
//! Constant-time note: the Gf256 field is constant-time by construction (no
//! lookup tables — see `vsss-rs` `gf256.rs`). The only non-constant-time
//! paths this module introduces are *public-data* checks: the share-count /
//! bounds validation and the sealed-share domain-header comparison (the
//! header is non-secret context, not key material). Secret comparisons go
//! through `subtle`.

use static_assertions::assert_not_impl_any;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::aead::{AeadKey, KEY_LEN};
use crate::keys::{VdkKey, WrapContext, WrappedVdk, VAULT_ID_LEN};
use crate::rng::{fill_random, os_rng};

/// HKDF-SHA512 info string for the recovery-wrap AEAD key.
///
/// Derives the recovery-wrap AEAD key from the [`RecoveryWrapKey`] bytes.
/// **Versioned** — mirrors [`crate::keys::WRAP_KEY_INFO`]; any change bumps
/// the suffix and forces a planned migration. Distinct from the
/// authority-wrap info so the two wrap keys never collide.
pub const RECOVERY_WRAP_KEY_INFO: &[u8] = b"pangolin-recovery-wrap-v0";

/// Domain separator prepended to the sealed-share plaintext before sealing.
///
/// Because `crypto_box`'s anonymous sealed box has **no associated-data
/// channel**, replay/domain binding is achieved by authenticating a
/// fixed-layout header *inside* the sealed plaintext: the XSalsa20-Poly1305
/// tag covers the whole plaintext, so a wrong `vault_id`/`epoch` either
/// fails to decrypt (wrong recipient key) or trips the header check on
/// open. Versioned the same way as the wrap info.
const SEALED_SHARE_DOMAIN: &[u8] = b"pangolin-recovery-seal-v0";

/// Length of the recovery epoch / attempt identifier in bytes.
///
/// The epoch is bound into the sealed-share header and the wrap context. A
/// fresh epoch on every onboarding + recovery re-split provides
/// forward-security domain separation (L7/L8) — a released share from epoch
/// `n` is rejected when presented for epoch `n+1`.
pub const EPOCH_LEN: usize = 16;

/// Length of an X25519 public/secret key in bytes (matches
/// `crypto_box::KEY_SIZE`).
pub const X25519_KEY_LEN: usize = 32;

/// On-chain threshold lower bound (inclusive). Mirrors the
/// `RecoveryV1` contract's `guardianSet.threshold` range.
pub const MIN_THRESHOLD: u8 = 2;
/// On-chain threshold upper bound (inclusive).
pub const MAX_THRESHOLD: u8 = 9;
/// On-chain guardian-count lower bound (inclusive).
pub const MIN_GUARDIANS: u8 = 3;
/// On-chain guardian-count upper bound (inclusive).
pub const MAX_GUARDIANS: u8 = 15;

/// A single Shamir share of the RWK as emitted by [`split_rwk`].
///
/// Encoding is exactly what `vsss-rs`'s `Gf256::split_array` produces for a
/// 32-byte secret: a `1 + 32 = 33`-byte buffer whose first byte is the
/// non-zero GF(2^8) x-coordinate (share identifier) and whose remaining 32
/// bytes are the per-byte y-coordinates. The buffer is **not** secret in
/// the sense that the VDK is — a single share is information-theoretically
/// independent of the RWK (L2) — but it is still the keying contribution of
/// one guardian, so it zeroizes on drop and never derives `Clone`/`Copy`.
pub struct Share {
    bytes: Zeroizing<Vec<u8>>,
}

assert_not_impl_any!(Share: Clone, Copy);
assert_not_impl_any!(RecoveryWrapKey: Clone, Copy);

/// Expected encoded length of one [`Share`]: one identifier byte plus one
/// y-coordinate byte per RWK byte.
const SHARE_ENCODED_LEN: usize = 1 + KEY_LEN;

impl Share {
    /// Wraps raw share bytes produced by [`split_rwk`] / persisted by a
    /// store layer. Rejects any buffer that is not the canonical
    /// `SHARE_ENCODED_LEN` so malformed input fails fast and typed rather
    /// than corrupting a reconstruction.
    ///
    /// # Errors
    ///
    /// [`EscrowError::MalformedShare`] if `bytes` is not exactly
    /// [`SHARE_ENCODED_LEN`] long or its identifier byte is zero (zero is
    /// reserved for the secret `f(0)` and is never a valid x-coordinate).
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, EscrowError> {
        if bytes.len() != SHARE_ENCODED_LEN || bytes[0] == 0 {
            // Zeroize the rejected buffer; it may be partial key material.
            // Wrap in `Zeroizing` so the wipe runs on drop (and clippy sees
            // the value as consumed, not a never-read local).
            let _wiped = Zeroizing::new(bytes);
            return Err(EscrowError::MalformedShare);
        }
        Ok(Self {
            bytes: Zeroizing::new(bytes),
        })
    }

    /// The share's x-coordinate (Shamir identifier). Non-secret; useful for
    /// duplicate detection and ordering by an orchestration layer.
    #[must_use]
    pub fn identifier(&self) -> u8 {
        self.bytes[0]
    }

    /// Borrows the raw share bytes for sealing / persistence. The slice
    /// borrows from `self`, which zeroizes on drop.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl core::fmt::Debug for Share {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The identifier (x-coordinate) is non-secret context; the value
        // bytes are redacted.
        f.debug_struct("Share")
            .field("identifier", &self.bytes.first().copied().unwrap_or(0))
            .field("value", &"<redacted>")
            .finish()
    }
}

/// A fresh 32-byte recovery-wrap key (RWK).
///
/// The second of the two keys that wrap the VDK (the first being the
/// password-derived authority). Its reconstruction capability is what gets
/// threshold-shared across guardians. Carries the full secret-type
/// discipline: heap-resident via [`AeadKey`], `!Clone`, `!Copy`, zeroizing,
/// redacted `Debug`, constant-time equality only.
pub struct RecoveryWrapKey {
    inner: AeadKey,
}

impl RecoveryWrapKey {
    /// Generates a fresh random RWK from the OS CSPRNG.
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0u8; KEY_LEN];
        fill_random(&mut bytes);
        let inner = AeadKey::from_bytes(bytes);
        bytes.zeroize();
        Self { inner }
    }

    /// Reconstructs an RWK from raw bytes. Crate-internal: the only
    /// legitimate producers are [`Self::generate`] and [`reconstruct_rwk`]
    /// (which feeds Shamir-combined bytes here). Not exposed to consumers —
    /// downstream code must go through the split/reconstruct API so it can
    /// never inject a weak/known RWK.
    fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self {
            inner: AeadKey::from_bytes(bytes),
        }
    }

    /// Constant-time equality with another RWK.
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.inner.ct_eq(&other.inner)
    }

    /// Derives the recovery-VDK-wrap AEAD key from this RWK using
    /// HKDF-SHA512 with the versioned [`RECOVERY_WRAP_KEY_INFO`] context,
    /// mirroring [`crate::keys::AuthorityKey`]'s wrap-key derivation.
    ///
    /// Crate-private: only the wrap/unwrap path may invoke it so the
    /// derived AEAD key never escapes outside controlled sealing.
    fn derive_wrap_key(&self) -> AeadKey {
        use hkdf::Hkdf;
        use sha2::Sha512;

        // The RWK *is* a 32-byte secret; run it through HKDF rather than
        // using it directly as the AEAD key (mirrors the authority path —
        // keeps "RWK" and "RWK-derived AEAD key" as distinct keyed values
        // under a versioned info string).
        let ikm = Zeroizing::new(*self.inner.expose_bytes_for_keys());
        let hk = Hkdf::<Sha512>::new(None, &*ikm);
        let mut okm = [0u8; KEY_LEN];
        hk.expand(RECOVERY_WRAP_KEY_INFO, &mut okm)
            .expect("HKDF expand with 32-byte output cannot fail for SHA-512");
        AeadKey::from_bytes(okm)
    }
}

impl core::fmt::Debug for RecoveryWrapKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RecoveryWrapKey")
            .field("data", &"<redacted>")
            .finish()
    }
}

/// A VDK wrapped under an [`RecoveryWrapKey`]-derived AEAD key.
///
/// The recovery-path peer of [`crate::keys::WrappedVdk`]: same
/// XChaCha20-Poly1305 machinery, same [`WrapContext`] AAD binding, but keyed
/// by the RWK rather than the password authority. Stored alongside the
/// daily `WrappedVdk` in vault meta (#104b). Non-secret; `Debug` redacts
/// the ciphertext for log hygiene.
pub struct WrappedVdkRecovery {
    inner: WrappedVdk,
}

impl WrappedVdkRecovery {
    /// Returns the underlying [`WrappedVdk`] for persistence
    /// (`ciphertext`/`nonce`/`context` accessors live there).
    #[must_use]
    pub fn as_wrapped(&self) -> &WrappedVdk {
        &self.inner
    }

    /// Reconstructs a `WrappedVdkRecovery` from a [`WrappedVdk`] previously
    /// produced by [`wrap_vdk_under_rwk`] and round-tripped through a store
    /// layer. Performs no validation beyond field assignment — it
    /// authenticates only when passed to [`unwrap_vdk_under_rwk`] under the
    /// matching RWK and context.
    #[must_use]
    pub fn from_wrapped(inner: WrappedVdk) -> Self {
        Self { inner }
    }
}

impl core::fmt::Debug for WrappedVdkRecovery {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WrappedVdkRecovery")
            .field("inner", &self.inner)
            .finish()
    }
}

/// A Shamir [`Share`] sealed to a single guardian's X25519 public key,
/// bound to a recovery context (vault + epoch) via an authenticated header.
///
/// The on-the-wire bytes are `crypto_box`'s anonymous sealed box over the
/// fixed-layout plaintext `SEALED_SHARE_DOMAIN || vault_id || epoch ||
/// share_bytes`. The recipient guardian decrypts with their X25519 secret
/// and the header is re-checked, so a sealed share minted for vault A /
/// epoch n cannot be opened-and-accepted for vault B / epoch m. Non-secret
/// at rest (it's encrypted to the guardian); safe to transport/persist.
#[derive(Clone)]
pub struct SealedShare {
    /// `crypto_box` sealed box: `ephemeral_pk(32) || ciphertext+tag`.
    ciphertext: Vec<u8>,
}

impl SealedShare {
    /// Wraps existing sealed-share bytes (e.g., loaded from a store layer).
    #[must_use]
    pub fn from_bytes(ciphertext: Vec<u8>) -> Self {
        Self { ciphertext }
    }

    /// Returns the raw sealed-box bytes for transport/persistence.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.ciphertext
    }
}

impl core::fmt::Debug for SealedShare {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Sealed bytes are non-secret (encrypted to the guardian) but a hex
        // dump clutters logs; report only the length.
        f.debug_struct("SealedShare")
            .field("len", &self.ciphertext.len())
            .finish()
    }
}

/// Errors returned by the escrow primitive.
///
/// Failures collapse to coarse typed variants; in particular every
/// sealed-share open / share-decode failure surfaces as a single variant so
/// callers cannot build an oracle on *why* a guardian's release was
/// rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EscrowError {
    /// `threshold` / `guardian_count` outside the on-chain bounds
    /// (`t ∈ 2..=9`, `M ∈ 3..=15`, `t ≤ M`).
    InvalidThreshold,
    /// The underlying Shamir split failed (e.g., the library rejected the
    /// parameters). Should be unreachable once [`Self::InvalidThreshold`]
    /// has passed; kept for defense in depth.
    SplitFailed,
    /// Reconstruction failed — too few shares, duplicate identifiers,
    /// mismatched lengths, or a malformed share set.
    ReconstructFailed,
    /// A share buffer was the wrong length / had a zero identifier.
    MalformedShare,
    /// Sealing a share to a guardian public key failed.
    SealFailed,
    /// Opening a sealed share failed — wrong guardian key, tampered
    /// ciphertext, or the bound context (`vault_id`/`epoch`) did not match.
    /// Deliberately undifferentiated (no oracle on the cause).
    OpenFailed,
    /// Wrapping/unwrapping the VDK under the RWK failed (AEAD tamper, wrong
    /// RWK, or cross-context replay).
    WrapFailed,
}

impl core::fmt::Display for EscrowError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidThreshold => f.write_str("threshold/guardian-count out of bounds"),
            Self::SplitFailed => f.write_str("Shamir split failed"),
            Self::ReconstructFailed => f.write_str("RWK reconstruction failed"),
            Self::MalformedShare => f.write_str("malformed share"),
            Self::SealFailed => f.write_str("sealing share to guardian failed"),
            Self::OpenFailed => f.write_str("opening sealed share failed"),
            Self::WrapFailed => f.write_str("VDK wrap/unwrap under RWK failed"),
        }
    }
}

impl std::error::Error for EscrowError {}

/// Validates `threshold` (`t`) and `guardian_count` (`M`) against the
/// on-chain `RecoveryV1` bounds: `t ∈ 2..=9`, `M ∈ 3..=15`, `t ≤ M`.
fn check_bounds(threshold: u8, guardian_count: u8) -> Result<(), EscrowError> {
    if !(MIN_THRESHOLD..=MAX_THRESHOLD).contains(&threshold)
        || !(MIN_GUARDIANS..=MAX_GUARDIANS).contains(&guardian_count)
        || threshold > guardian_count
    {
        return Err(EscrowError::InvalidThreshold);
    }
    Ok(())
}

/// Splits an [`RecoveryWrapKey`] into `guardian_count` Shamir [`Share`]s
/// with reconstruction threshold `threshold`, over the constant-time
/// GF(2^8) field.
///
/// Validates `(threshold, guardian_count)` against the on-chain bounds
/// before splitting. The returned shares are ordered by ascending
/// identifier `1..=guardian_count` (the `vsss-rs` default participant
/// generator); orchestration maps share `i` to guardian `i`.
///
/// # Errors
///
/// [`EscrowError::InvalidThreshold`] if the parameters are out of bounds;
/// [`EscrowError::SplitFailed`] if the library split fails.
pub fn split_rwk(
    rwk: &RecoveryWrapKey,
    threshold: u8,
    guardian_count: u8,
) -> Result<Vec<Share>, EscrowError> {
    check_bounds(threshold, guardian_count)?;

    // Expose the RWK bytes only into a zeroizing buffer for the split call.
    let secret = Zeroizing::new(*rwk.inner.expose_bytes_for_keys());

    let raw_shares = vsss_rs::Gf256::split_array(
        usize::from(threshold),
        usize::from(guardian_count),
        &secret[..],
        os_rng(),
    )
    .map_err(|_| EscrowError::SplitFailed)?;

    // Wrap each raw share into the typed, zeroizing `Share`. The library
    // emits exactly SHARE_ENCODED_LEN-byte buffers for a 32-byte secret;
    // `Share::from_bytes` re-validates that invariant.
    raw_shares
        .into_iter()
        .map(Share::from_bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| EscrowError::SplitFailed)
}

/// Reconstructs the [`RecoveryWrapKey`] from a set of `>= threshold`
/// [`Share`]s.
///
/// Constant-time GF(2^8) Lagrange interpolation via `vsss-rs`. The caller
/// supplies any subset of distinct shares; with `< threshold` shares the
/// result is information-theoretically independent of the true RWK
/// (Shamir), so this either errors or yields a wrong value — never the real
/// RWK. With duplicate identifiers or mismatched lengths it errors.
///
/// # Errors
///
/// [`EscrowError::ReconstructFailed`] if the share set is too small,
/// malformed, has duplicate identifiers, or the combine yields the wrong
/// secret length.
pub fn reconstruct_rwk(shares: &[Share]) -> Result<RecoveryWrapKey, EscrowError> {
    // `Gf256::combine_array` wants `&[Vec<u8>]`; build a transient view.
    // (The bytes are already in zeroizing `Share`s; the transient Vec of
    // references does not copy the secret values out.)
    let view: Vec<Vec<u8>> = shares.iter().map(|s| s.bytes.to_vec()).collect();
    // Ensure the transient copies are wiped after combine.
    let mut view = Zeroizing::new(view);

    let combined = vsss_rs::Gf256::combine_array(&view[..]).map_err(|_| {
        view.zeroize();
        EscrowError::ReconstructFailed
    })?;
    let mut combined = Zeroizing::new(combined);
    view.zeroize();

    if combined.len() != KEY_LEN {
        return Err(EscrowError::ReconstructFailed);
    }
    let mut buf = [0u8; KEY_LEN];
    buf.copy_from_slice(&combined);
    combined.zeroize();
    let rwk = RecoveryWrapKey::from_bytes(buf);
    buf.zeroize();
    Ok(rwk)
}

/// Fixed-layout sealed-share header: `SEALED_SHARE_DOMAIN || vault_id ||
/// epoch`. Mirrors [`WrapContext::encode`]'s deterministic concatenation
/// discipline (NO serde).
fn sealed_share_header(vault_id: &[u8; VAULT_ID_LEN], epoch: &[u8; EPOCH_LEN]) -> Vec<u8> {
    let mut h = Vec::with_capacity(SEALED_SHARE_DOMAIN.len() + VAULT_ID_LEN + EPOCH_LEN);
    h.extend_from_slice(SEALED_SHARE_DOMAIN);
    h.extend_from_slice(vault_id);
    h.extend_from_slice(epoch);
    h
}

/// Seals a [`Share`] to a guardian's X25519 public key, binding the
/// recovery context (`vault_id` + `epoch`) into the authenticated payload.
///
/// `crypto_box`'s sealed box is an anonymous one-shot (ephemeral-X25519 →
/// `HSalsa20` KDF → XSalsa20-Poly1305): only the holder of the matching X25519
/// secret can open it, and the sender is anonymous. Since the sealed box
/// has no associated-data channel, the `vault_id`/`epoch` are authenticated
/// by prepending them as a fixed-layout header *inside* the sealed
/// plaintext (the Poly1305 tag covers the whole plaintext), and re-checked
/// by [`open_sealed_share`]. This is the replay/domain-separation defense
/// (L8): a share sealed for vault A / epoch n is rejected when opened for
/// vault B / epoch m.
///
/// # Errors
///
/// [`EscrowError::SealFailed`] if the sealing operation fails.
pub fn seal_share(
    share: &Share,
    guardian_x25519_pub: &[u8; X25519_KEY_LEN],
    vault_id: &[u8; VAULT_ID_LEN],
    epoch: &[u8; EPOCH_LEN],
) -> Result<SealedShare, EscrowError> {
    let mut plaintext = Zeroizing::new(sealed_share_header(vault_id, epoch));
    plaintext.extend_from_slice(share.as_bytes());

    let pk = crypto_box::PublicKey::from_bytes(*guardian_x25519_pub);
    let ciphertext = pk
        .seal(&mut os_rng(), &plaintext)
        .map_err(|_| EscrowError::SealFailed)?;

    Ok(SealedShare { ciphertext })
}

/// Opens a [`SealedShare`] with a guardian's X25519 secret key, verifies the
/// bound recovery context, and returns the plaintext [`Share`].
///
/// # Errors
///
/// [`EscrowError::OpenFailed`] — undifferentiated — if the guardian key is
/// wrong, the ciphertext was tampered, the recovered plaintext is too
/// short, or the bound `vault_id`/`epoch` header does not match the
/// supplied context (replay defense). No oracle is exposed on the cause.
pub fn open_sealed_share(
    sealed: &SealedShare,
    guardian_x25519_secret: &[u8; X25519_KEY_LEN],
    vault_id: &[u8; VAULT_ID_LEN],
    epoch: &[u8; EPOCH_LEN],
) -> Result<Share, EscrowError> {
    let sk = crypto_box::SecretKey::from_bytes(*guardian_x25519_secret);
    let mut plaintext = Zeroizing::new(sk.unseal(&sealed.ciphertext).map_err(|_| {
        // SecretKey is dropped (zeroizes) at end of fn regardless.
        EscrowError::OpenFailed
    })?);

    let expected_header = sealed_share_header(vault_id, epoch);
    let header_len = expected_header.len();
    if plaintext.len() != header_len + SHARE_ENCODED_LEN {
        plaintext.zeroize();
        return Err(EscrowError::OpenFailed);
    }

    // Constant-time compare of the (non-secret) header via subtle, avoiding
    // any accidental short-circuit oracle on which context field mismatched.
    // The header is public context, not key material, so this is
    // belt-and-suspenders rather than a strict requirement.
    if !bool::from(plaintext[..header_len].ct_eq(&expected_header)) {
        plaintext.zeroize();
        return Err(EscrowError::OpenFailed);
    }

    let share = Share::from_bytes(plaintext[header_len..].to_vec());
    plaintext.zeroize();
    share.map_err(|_| EscrowError::OpenFailed)
}

/// Wraps a [`VdkKey`] under an [`RecoveryWrapKey`], bound to `ctx`
/// (`vault_id` + `schema_version`) as AEAD AAD.
///
/// Reuses the existing [`WrappedVdk`] machinery so the recovered VDK is
/// byte-identical to the original (L5). This is the "second wrap" of
/// Scheme A — the same VDK is already wrapped under the password authority
/// in `keys.rs`; here it is additionally wrapped under the RWK.
///
/// # Errors
///
/// [`EscrowError::WrapFailed`] if the underlying AEAD seal fails.
pub fn wrap_vdk_under_rwk(
    vdk: &VdkKey,
    rwk: &RecoveryWrapKey,
    ctx: &WrapContext,
) -> Result<WrappedVdkRecovery, EscrowError> {
    let wrap_key = rwk.derive_wrap_key();
    let inner =
        WrappedVdk::seal_under_key(vdk, &wrap_key, ctx).map_err(|_| EscrowError::WrapFailed)?;
    Ok(WrappedVdkRecovery { inner })
}

/// Unwraps a [`WrappedVdkRecovery`] under the reconstructed
/// [`RecoveryWrapKey`], recovering the byte-identical [`VdkKey`].
///
/// The context **stored on the wrapper** is fed back into the AEAD AAD
/// (exactly as [`crate::keys::WrappedVdk::unwrap_with`] does), so a wrapper
/// whose stored context was forged to a different vault/schema fails
/// authentication (cross-context replay defense, L8). The caller does not
/// pass a context — the wrapper carries the one it was sealed with.
///
/// # Errors
///
/// [`EscrowError::WrapFailed`] if the RWK is wrong, the ciphertext was
/// tampered, or the wrapper's stored context was edited.
pub fn unwrap_vdk_under_rwk(
    wrapped: &WrappedVdkRecovery,
    rwk: &RecoveryWrapKey,
) -> Result<VdkKey, EscrowError> {
    let wrap_key = rwk.derive_wrap_key();
    let ctx = *wrapped.inner.context();
    wrapped
        .inner
        .open_with_key(&wrap_key, &ctx)
        .map_err(|_| EscrowError::WrapFailed)
}

#[cfg(test)]
mod tests;
