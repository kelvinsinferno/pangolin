// SPDX-License-Identifier: AGPL-3.0-or-later
//! Device-pairing VDK-handoff + per-device VDK wrap primitive (#106b-1).
//!
//! This module is the catastrophic-if-wrong core of Pangolin's multi-device
//! epic. It provides exactly two compositions over the already-audited
//! #104a sealed-box (`crypto_box`, in [`crate::escrow`]) and the `keys.rs`
//! AEAD wrap machinery — **it introduces no novel primitive**:
//!
//! 1. **Device-pairing handoff** ([`X25519PairingKey`],
//!    [`seal_vdk_to_device`], [`open_vdk_from_pairing`]). When a device is
//!    added to the on-chain set (#106a), an existing unlocked device seals
//!    the 32-byte [`VdkKey`] to the *new* device's X25519 pairing public key
//!    using the #104a anonymous sealed box, domain-bound to
//!    `vault_id‖device_id‖epoch`. The new device opens it with the X25519
//!    secret derived one-way from its own [`DeviceKey`]. The VDK **never
//!    crosses in the clear** and the password never crosses the wire. This
//!    is structurally identical to #104a's [`crate::escrow::seal_share`],
//!    sealing the 32-byte VDK instead of a 33-byte Shamir share, with the
//!    recipient `device_id` added to the authenticated header (Q-e).
//!
//! 2. **Per-device VDK wrap** ([`DeviceWrappedVdk`], [`wrap_vdk_for_device`],
//!    [`unwrap_vdk_for_device`]). The at-rest form of the VDK on a single
//!    device: the VDK sealed under an AEAD key derived from that device's
//!    [`DeviceKey`] seed via HKDF-SHA512 under the versioned info string
//!    [`DEVICE_WRAP_KEY_INFO`], reusing the crate-private
//!    [`crate::keys::WrappedVdk::seal_under_key`] /
//!    [`crate::keys::WrappedVdk::open_with_key`] (the same generic-AEAD-key
//!    path the #104a recovery wrap reuses). This is **additive** — it does
//!    NOT touch the password [`crate::keys::WrappedVdk`] / recovery /
//!    guardian code paths (Q-a Option 1: per-device wrap is layered on the
//!    password anchor for biometric fast-unlock).
//!
//! ### Domain separation (L4)
//!
//! Two new versioned HKDF info strings are introduced, and an audit test
//! asserts they are distinct from one another AND from all three existing
//! ones (`pangolin-vdk-wrap-v0`, `pangolin-recovery-wrap-v0`,
//! `pangolin-guardian-x25519-v0`):
//!
//! - [`DEVICE_PAIR_X25519_HKDF_INFO`] = `"pangolin-device-pair-x25519-v0"`
//!   (the pairing recipient X25519 scalar expansion);
//! - [`DEVICE_WRAP_KEY_INFO`] = `"pangolin-device-wrap-v0"` (the per-device
//!   wrap AEAD key derivation).
//!
//! The pairing seal additionally binds `vault_id‖device_id‖epoch` into the
//! authenticated sealed-box header (re-checked on open), and the per-device
//! wrap binds [`crate::keys::WrapContext`] (`vault_id` + `schema_version`)
//! as AEAD AAD — so a seal/wrap from one (vault, device, epoch) is rejected
//! anywhere else.
//!
//! ### Secret-type discipline (L6)
//!
//! [`X25519PairingKey`] carries the full discipline: heap-resident secret
//! scalar, `!Clone`, `!Copy`, zeroizing, redacted `Debug`, constant-time
//! equality, zero-serde. [`SealedVdkForDevice`] / [`DeviceWrappedVdk`] are
//! non-secret at rest (the VDK inside is sealed/wrapped) but still redact
//! their bytes in `Debug` for log hygiene and use fixed-layout byte
//! encodings, never serde derives.

use static_assertions::assert_not_impl_any;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::aead::{AeadKey, KEY_LEN};
use crate::escrow::{EPOCH_LEN, X25519_KEY_LEN};
use crate::keys::{DeviceKey, VdkKey, WrapContext, WrappedVdk, VAULT_ID_LEN};
use crate::rng::os_rng;

/// Fixed message signed by the new device's Ed25519 key to produce the
/// X25519 pairing-recipient derivation IKM.
///
/// **Versioned** — any change must bump the `-v0` suffix and document the
/// migration; a device would otherwise derive a different X25519 pairing
/// key under the new version and be unable to open VDKs sealed to its old
/// pairing pubkey.
///
/// DISTINCT from `guardian::X25519_DERIVATION_MESSAGE`
/// (`"pangolin-guardian-x25519-derive-v0"`) so the guardian share-opener
/// and the device pairing-recipient never share IKM even when one device is
/// simultaneously a guardian.
pub const DEVICE_PAIR_X25519_DERIVATION_MESSAGE: &[u8] = b"pangolin-device-pair-x25519-derive-v0";

/// HKDF-SHA512 info string for the device pairing-recipient X25519 scalar
/// expansion. **Versioned** alongside
/// [`DEVICE_PAIR_X25519_DERIVATION_MESSAGE`].
///
/// DISTINCT from every other HKDF info string in the codebase:
/// `"pangolin-vdk-wrap-v0"` (authority wrap), `"pangolin-recovery-wrap-v0"`
/// (RWK wrap), `"pangolin-guardian-x25519-v0"` (guardian sealing key), and
/// [`DEVICE_WRAP_KEY_INFO`] (the per-device wrap below). The
/// [`tests::domain_strings_are_versioned_and_distinct`] test greps these.
pub const DEVICE_PAIR_X25519_HKDF_INFO: &[u8] = b"pangolin-device-pair-x25519-v0";

/// HKDF-SHA512 info string for the per-device wrap AEAD key, derived from
/// the device's [`DeviceKey`] seed. **Versioned.**
///
/// DISTINCT from `"pangolin-vdk-wrap-v0"`, `"pangolin-recovery-wrap-v0"`,
/// `"pangolin-guardian-x25519-v0"`, and
/// [`DEVICE_PAIR_X25519_HKDF_INFO`] — so the per-device wrap key can never
/// collide with the password-wrap, the recovery-wrap, the guardian sealing
/// key, or the device pairing key, even though several of them anchor in
/// the same device/authority seed material.
pub const DEVICE_WRAP_KEY_INFO: &[u8] = b"pangolin-device-wrap-v0";

/// Domain separator prepended to the sealed-VDK plaintext before sealing.
///
/// Like the #104a [`crate::escrow`] sealed-share path, `crypto_box`'s
/// anonymous sealed box has **no associated-data channel**, so replay /
/// domain binding is achieved by authenticating a fixed-layout header
/// *inside* the sealed plaintext (the XSalsa20-Poly1305 tag covers the
/// whole plaintext). Versioned the same way as the info strings.
const SEALED_VDK_DOMAIN: &[u8] = b"pangolin-device-pair-seal-v0";

/// Domain-separator hash input prefix for the device-pairing SAS (Short Authentication String).
///
/// The human-comparable 6-digit code the #106e-2 pairing flow derives over
/// both devices' X25519 pairing pubkeys + the freshness nonce.
///
/// **Versioned** alongside [`SEALED_VDK_DOMAIN`] /
/// [`DEVICE_PAIR_X25519_HKDF_INFO`]. **DISTINCT** from every other domain
/// string in the codebase (the byte-identity pin lives in
/// [`tests::sas_domain_distinct_from_other_pairing_domains`] +
/// `pangolin_core::pairing_transport`'s
/// `pairing_transport_domain_distinct_from_other_domains`).
///
/// The SAS hash is `SHA-256(SAS_DOMAIN || lo || hi || freshness_nonce)`,
/// where `(lo, hi)` is the lexicographically-sorted pair of the two
/// devices' 32-byte X25519 pairing pubkeys (canonical-symmetric — both
/// devices derive the identical code regardless of which was A / B, L3).
/// Truncated to a 6-digit decimal via `u32::from_be_bytes(H[..4]) %
/// 1_000_000`.
pub const SAS_DOMAIN: &[u8] = b"pangolin-pairing-sas-v0";

/// Length of a stable device identifier in bytes, bound into the
/// [`SealedVdkForDevice`] header (Q-e).
///
/// A 32-byte content/address-derived identifier matching the `device_id`
/// shape the orchestration layer (#106c) carries.
pub const DEVICE_ID_LEN: usize = 32;

/// Errors returned by the device-pairing primitive.
///
/// Failures collapse to coarse typed variants; in particular every
/// sealed-VDK open failure (wrong recipient key, tampered ciphertext, wrong
/// `vault_id`/`device_id`/`epoch`, truncation) surfaces as a single variant
/// so callers cannot build an oracle on *why* an open was rejected. The
/// per-device wrap unwrap failures collapse the same way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingError {
    /// Sealing the VDK to a recipient pairing public key failed.
    SealFailed,
    /// Opening a [`SealedVdkForDevice`] failed — wrong recipient pairing
    /// key, tampered ciphertext, truncated buffer, or the bound
    /// `vault_id`/`device_id`/`epoch` header did not match the supplied
    /// context (replay/domain-binding defense). Deliberately
    /// undifferentiated (no oracle on the cause).
    OpenFailed,
    /// Wrapping/unwrapping the VDK under the device-derived wrap key failed
    /// (AEAD tamper, wrong device key, or cross-context replay).
    WrapFailed,
}

impl core::fmt::Display for PairingError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SealFailed => f.write_str("sealing VDK to device pairing key failed"),
            Self::OpenFailed => f.write_str("opening sealed VDK failed"),
            Self::WrapFailed => f.write_str("per-device VDK wrap/unwrap failed"),
        }
    }
}

impl std::error::Error for PairingError {}

// ---------------------------------------------------------------------------
// 1. Device pairing-recipient X25519 key derivation
// ---------------------------------------------------------------------------

/// A device's X25519 **pairing-recipient** keypair, derived one-way from
/// its Pangolin [`DeviceKey`].
///
/// The secret scalar is the recipient key for [`SealedVdkForDevice`]
/// ([`open_vdk_from_pairing`] consumes [`Self::secret_bytes`]); the public
/// key ([`Self::public_bytes`]) is what an existing device seals the VDK to
/// via [`seal_vdk_to_device`]. Mirrors
/// [`crate::guardian::X25519SealingKey`] exactly — same derivation recipe
/// (deterministic Ed25519 sign of a fixed domain-separator message → HKDF
/// IKM → 32-byte scalar interpreted by `crypto_box`, no rejection loop),
/// but a DISTINCT message + info string so the pairing key and the guardian
/// sealing key are independent even when one device is also a guardian.
///
/// Secret-type discipline: `!Clone`, `!Copy`, zeroizing secret, redacted
/// `Debug`, `ct_eq` only, zero-serde.
pub struct X25519PairingKey {
    /// 32-byte X25519 secret scalar (heap-resident, zeroizing).
    secret: Zeroizing<[u8; X25519_KEY_LEN]>,
    /// 32-byte X25519 public key (non-secret).
    public: [u8; X25519_KEY_LEN],
}

assert_not_impl_any!(X25519PairingKey: Clone, Copy);

impl X25519PairingKey {
    /// The device's 32-byte X25519 **public** pairing key — the value
    /// [`seal_vdk_to_device`] seals a VDK to. Non-secret.
    #[must_use]
    pub fn public_bytes(&self) -> &[u8; X25519_KEY_LEN] {
        &self.public
    }

    /// A zeroizing copy of the device's 32-byte X25519 **secret** pairing
    /// scalar — the value [`open_vdk_from_pairing`] needs to open a sealed
    /// VDK. The returned buffer wipes on drop; callers must pass it
    /// straight into `open_vdk_from_pairing` without copying it into a
    /// non-zeroizing buffer.
    #[must_use]
    pub fn secret_bytes(&self) -> Zeroizing<[u8; X25519_KEY_LEN]> {
        Zeroizing::new(*self.secret)
    }

    /// Constant-time equality on the secret scalar (the public key is a
    /// pure function of it, so comparing the secret suffices).
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.secret.as_slice().ct_eq(other.secret.as_slice())
    }
}

impl core::fmt::Debug for X25519PairingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The public key is non-secret; the scalar is redacted.
        f.debug_struct("X25519PairingKey")
            .field("public", &hex_short(&self.public))
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// Short hex preview of a public key for `Debug` (non-secret).
fn hex_short(bytes: &[u8; X25519_KEY_LEN]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(10);
    for b in &bytes[..4] {
        s.push(char::from(HEX[usize::from(b >> 4)]));
        s.push(char::from(HEX[usize::from(b & 0x0f)]));
    }
    s.push_str("..");
    s
}

/// Derive a device's [`X25519PairingKey`] from its Pangolin [`DeviceKey`].
///
/// Mirrors [`crate::guardian::derive_x25519_sealing_key`] exactly, under a
/// DISTINCT domain-separator message + HKDF info:
///
/// 1. Deterministically sign [`DEVICE_PAIR_X25519_DERIVATION_MESSAGE`] with
///    the device's Ed25519 key (RFC 8032 §5.1.6 — same seed → same
///    signature; the signature is a PRF of the seed for a fixed message but
///    does not reveal it).
/// 2. HKDF-SHA512-expand 32 bytes under [`DEVICE_PAIR_X25519_HKDF_INFO`].
/// 3. Interpret the 32 bytes as an X25519 secret scalar via `crypto_box`
///    (clamped inside the Montgomery ladder — every 32-byte string is a
///    valid scalar, so no rejection-sampling loop). The public key is
///    materialized through `crypto_box` so it matches exactly what
///    [`seal_vdk_to_device`] seals to.
///
/// Determinism: same `DeviceKey` → same pairing keypair (so a device can
/// re-derive its pairing recipient on any device that holds its seed).
/// Distinct `DeviceKey`s → distinct pairing keypairs (overwhelming
/// probability). The composition is one-way: an attacker who recovers the
/// X25519 scalar cannot recover the Ed25519 seed (HMAC-SHA512 preimage
/// resistance), so a compromised pairing recipient never endangers the
/// device's revision-signing identity. This derivation cannot fail.
#[must_use]
pub fn derive_x25519_pairing_key(device: &DeviceKey) -> X25519PairingKey {
    use hkdf::Hkdf;
    use sha2::Sha512;

    // Step 1: deterministically sign the fixed domain-separator message.
    let ikm = device
        .signing_key()
        .sign(DEVICE_PAIR_X25519_DERIVATION_MESSAGE);
    let ikm_bytes = Zeroizing::new(ikm.to_bytes());

    // Step 2: HKDF-SHA512 expand 32 bytes under the versioned info string.
    let hk = Hkdf::<Sha512>::new(None, &ikm_bytes[..]);
    let mut scalar = Zeroizing::new([0u8; X25519_KEY_LEN]);
    hk.expand(DEVICE_PAIR_X25519_HKDF_INFO, &mut scalar[..])
        .expect("HKDF-SHA512 expand with 32-byte output cannot fail");

    // Step 3: interpret as an X25519 secret scalar (crypto_box clamps inside
    // the ladder, so every 32-byte string is valid — no rejection loop).
    let sk = crypto_box::SecretKey::from_bytes(*scalar);
    let public = *sk.public_key().as_bytes();
    X25519PairingKey {
        secret: scalar,
        public,
    }
}

// ---------------------------------------------------------------------------
// 2. Device-pairing VDK handoff (seal / open)
// ---------------------------------------------------------------------------

/// A [`VdkKey`] sealed to a single device's X25519 pairing public key,
/// bound to a pairing context (`vault_id` + recipient `device_id` + `epoch`)
/// via an authenticated header.
///
/// The on-the-wire bytes are `crypto_box`'s anonymous sealed box over the
/// fixed-layout plaintext
/// `SEALED_VDK_DOMAIN || vault_id || device_id || epoch || vdk_bytes`. The
/// recipient device decrypts with its X25519 pairing secret and the header
/// is re-checked, so a sealed VDK minted for (vault A, device B, epoch n)
/// cannot be opened-and-accepted for (vault B / device C / epoch m).
/// Non-secret at rest (the VDK is sealed to the recipient); safe to
/// transport over the untrusted pairing channel / relay. Zero-serde:
/// fixed-layout encode, no serde derive.
#[derive(Clone)]
pub struct SealedVdkForDevice {
    /// `crypto_box` sealed box: `ephemeral_pk(32) || ciphertext+tag`.
    ciphertext: Vec<u8>,
}

impl SealedVdkForDevice {
    /// Wraps existing sealed-VDK bytes (e.g., loaded from a relay / store).
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

impl core::fmt::Debug for SealedVdkForDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Sealed bytes are non-secret (encrypted to the recipient) but a hex
        // dump clutters logs; report only the length.
        f.debug_struct("SealedVdkForDevice")
            .field("len", &self.ciphertext.len())
            .finish()
    }
}

/// Fixed-layout sealed-VDK header:
/// `SEALED_VDK_DOMAIN || vault_id || device_id || epoch`. Mirrors the #104a
/// [`crate::escrow`] header discipline (deterministic concatenation, NO
/// serde), with the recipient `device_id` added (Q-e).
fn sealed_vdk_header(
    vault_id: &[u8; VAULT_ID_LEN],
    device_id: &[u8; DEVICE_ID_LEN],
    epoch: &[u8; EPOCH_LEN],
) -> Vec<u8> {
    let mut h =
        Vec::with_capacity(SEALED_VDK_DOMAIN.len() + VAULT_ID_LEN + DEVICE_ID_LEN + EPOCH_LEN);
    h.extend_from_slice(SEALED_VDK_DOMAIN);
    h.extend_from_slice(vault_id);
    h.extend_from_slice(device_id);
    h.extend_from_slice(epoch);
    h
}

/// Seals a [`VdkKey`] to a recipient device's X25519 pairing public key,
/// binding the pairing context (`vault_id` + recipient `device_id` +
/// `epoch`) into the authenticated payload.
///
/// `crypto_box`'s sealed box is an anonymous one-shot (ephemeral-X25519 →
/// `HSalsa20` KDF → XSalsa20-Poly1305): only the holder of the matching
/// X25519 secret can open it, and the sender is anonymous. Since the sealed
/// box has no associated-data channel, the context is authenticated by
/// prepending it as a fixed-layout header *inside* the sealed plaintext (the
/// Poly1305 tag covers the whole plaintext), re-checked by
/// [`open_vdk_from_pairing`]. This is the replay/domain-separation defense
/// (L1/L4): the VDK NEVER crosses in the clear, and a VDK sealed for (vault
/// A, device B, epoch n) is rejected when opened for any other context.
///
/// This is the exact #104a [`crate::escrow::seal_share`] construction with
/// the 32-byte VDK as the payload instead of a 33-byte Shamir share, and
/// `device_id` added to the header.
///
/// # Errors
///
/// [`PairingError::SealFailed`] if the sealing operation fails.
pub fn seal_vdk_to_device(
    vdk: &VdkKey,
    recipient_x25519_pub: &[u8; X25519_KEY_LEN],
    vault_id: &[u8; VAULT_ID_LEN],
    device_id: &[u8; DEVICE_ID_LEN],
    epoch: &[u8; EPOCH_LEN],
) -> Result<SealedVdkForDevice, PairingError> {
    let mut plaintext = Zeroizing::new(sealed_vdk_header(vault_id, device_id, epoch));
    // The VDK plaintext is the 32-byte AEAD key bytes; pull them through the
    // crate-private accessor into the zeroizing plaintext buffer.
    let vdk_bytes = vdk.expose_vdk_bytes();
    plaintext.extend_from_slice(&*vdk_bytes);

    let pk = crypto_box::PublicKey::from_bytes(*recipient_x25519_pub);
    let ciphertext = pk
        .seal(&mut os_rng(), &plaintext)
        .map_err(|_| PairingError::SealFailed)?;

    Ok(SealedVdkForDevice { ciphertext })
}

/// Opens a [`SealedVdkForDevice`] with the recipient device's X25519
/// pairing secret key, verifies the bound pairing context, and returns the
/// byte-identical [`VdkKey`].
///
/// The recovered VDK `ct_eq`s the original sealed VDK (L2 — pairing hands
/// the VDK over, never re-derives it). A wrong recipient key, a tampered
/// ciphertext, a truncated buffer, or a `vault_id`/`device_id`/`epoch`
/// mismatch all collapse to a single undifferentiated
/// [`PairingError::OpenFailed`] (no oracle on the cause).
///
/// # Errors
///
/// [`PairingError::OpenFailed`] — undifferentiated — for any open/verify
/// failure.
pub fn open_vdk_from_pairing(
    sealed: &SealedVdkForDevice,
    recipient_x25519_secret: &[u8; X25519_KEY_LEN],
    vault_id: &[u8; VAULT_ID_LEN],
    device_id: &[u8; DEVICE_ID_LEN],
    epoch: &[u8; EPOCH_LEN],
) -> Result<VdkKey, PairingError> {
    let sk = crypto_box::SecretKey::from_bytes(*recipient_x25519_secret);
    let mut plaintext = Zeroizing::new(
        sk.unseal(&sealed.ciphertext)
            .map_err(|_| PairingError::OpenFailed)?,
    );

    let expected_header = sealed_vdk_header(vault_id, device_id, epoch);
    let header_len = expected_header.len();
    if plaintext.len() != header_len + KEY_LEN {
        plaintext.zeroize();
        return Err(PairingError::OpenFailed);
    }

    // Constant-time compare of the (non-secret) header via subtle, avoiding
    // any short-circuit oracle on which context field mismatched. The header
    // is public context, not key material, so this is belt-and-suspenders.
    if !bool::from(plaintext[..header_len].ct_eq(&expected_header)) {
        plaintext.zeroize();
        return Err(PairingError::OpenFailed);
    }

    let mut vdk_bytes = [0u8; KEY_LEN];
    vdk_bytes.copy_from_slice(&plaintext[header_len..]);
    plaintext.zeroize();
    let vdk = VdkKey::from_aead_bytes(vdk_bytes);
    vdk_bytes.zeroize();
    Ok(vdk)
}

// ---------------------------------------------------------------------------
// 3. Per-device VDK wrap (wrap / unwrap)
// ---------------------------------------------------------------------------

/// A [`VdkKey`] wrapped under an AEAD key derived from a single device's
/// [`DeviceKey`] seed.
///
/// The per-device peer of [`crate::escrow::WrappedVdkRecovery`]: same
/// XChaCha20-Poly1305 machinery, same [`WrapContext`] AAD binding, but keyed
/// by an HKDF-SHA512 derivation off the device seed under the versioned
/// [`DEVICE_WRAP_KEY_INFO`] info string rather than the RWK or the password
/// authority. This is the device's biometric fast-unlock at-rest form
/// (Q-a Option 1 — layered on the password anchor, additive). Non-secret;
/// `Debug` redacts the ciphertext for log hygiene. Zero-serde.
pub struct DeviceWrappedVdk {
    inner: WrappedVdk,
}

impl DeviceWrappedVdk {
    /// Returns the underlying [`WrappedVdk`] for persistence
    /// (`ciphertext`/`nonce`/`context` accessors live there).
    #[must_use]
    pub fn as_wrapped(&self) -> &WrappedVdk {
        &self.inner
    }

    /// Reconstructs a `DeviceWrappedVdk` from a [`WrappedVdk`] previously
    /// produced by [`wrap_vdk_for_device`] and round-tripped through a store
    /// layer. Performs no validation beyond field assignment — it
    /// authenticates only when passed to [`unwrap_vdk_for_device`] under the
    /// matching device key and context.
    #[must_use]
    pub fn from_wrapped(inner: WrappedVdk) -> Self {
        Self { inner }
    }
}

impl core::fmt::Debug for DeviceWrappedVdk {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DeviceWrappedVdk")
            .field("inner", &self.inner)
            .finish()
    }
}

/// Derives the per-device wrap AEAD key from a [`DeviceKey`]'s 32-byte seed
/// via HKDF-SHA512 under the versioned [`DEVICE_WRAP_KEY_INFO`] context.
///
/// Mirrors [`crate::escrow::RecoveryWrapKey::derive_wrap_key`] /
/// [`crate::keys::AuthorityKey::derive_wrap_key`] — runs the seed through
/// HKDF rather than using it directly as the AEAD key, under an info string
/// distinct from every other derivation so the device-wrap key can never
/// collide with the password-wrap, recovery-wrap, guardian-sealing, or
/// device-pairing keys. Crate-private: only the wrap/unwrap path invokes it,
/// so the derived AEAD key never escapes outside controlled sealing.
fn derive_device_wrap_key(device: &DeviceKey) -> AeadKey {
    use hkdf::Hkdf;
    use sha2::Sha512;

    let seed = device.secret_seed_bytes();
    let hk = Hkdf::<Sha512>::new(None, &*seed);
    let mut okm = [0u8; KEY_LEN];
    hk.expand(DEVICE_WRAP_KEY_INFO, &mut okm)
        .expect("HKDF expand with 32-byte output cannot fail for SHA-512");
    AeadKey::from_bytes(okm)
}

/// Wraps a [`VdkKey`] under a device-derived AEAD key, bound to `ctx`
/// (`vault_id` + `schema_version`) as AEAD AAD.
///
/// Reuses the existing [`WrappedVdk`] machinery so the recovered VDK is
/// byte-identical to the original. This is the per-device at-rest wrap of
/// Q-a Option 1 — the same VDK is already wrapped under the password
/// authority in `keys.rs` (and the RWK in `escrow.rs`); here it is
/// additionally wrapped under the device's own derived key for biometric
/// fast-unlock. ADDITIVE: touches no existing wrap path.
///
/// # Errors
///
/// [`PairingError::WrapFailed`] if the underlying AEAD seal fails.
pub fn wrap_vdk_for_device(
    vdk: &VdkKey,
    device_key: &DeviceKey,
    ctx: &WrapContext,
) -> Result<DeviceWrappedVdk, PairingError> {
    let wrap_key = derive_device_wrap_key(device_key);
    let inner =
        WrappedVdk::seal_under_key(vdk, &wrap_key, ctx).map_err(|_| PairingError::WrapFailed)?;
    Ok(DeviceWrappedVdk { inner })
}

/// Unwraps a [`DeviceWrappedVdk`] under the device's derived wrap key,
/// recovering the byte-identical [`VdkKey`].
///
/// The context **stored on the wrapper** is fed back into the AEAD AAD
/// (exactly as [`crate::escrow::unwrap_vdk_under_rwk`] does), so a wrapper
/// whose stored context was forged to a different vault/schema fails
/// authentication (cross-context replay defense). A wrong device key fails
/// the same way. The caller does not pass a context — the wrapper carries
/// the one it was sealed with.
///
/// # Errors
///
/// [`PairingError::WrapFailed`] if the device key is wrong, the ciphertext
/// was tampered, or the wrapper's stored context was edited.
pub fn unwrap_vdk_for_device(
    wrapped: &DeviceWrappedVdk,
    device_key: &DeviceKey,
) -> Result<VdkKey, PairingError> {
    let wrap_key = derive_device_wrap_key(device_key);
    let ctx = *wrapped.inner.context();
    wrapped
        .inner
        .open_with_key(&wrap_key, &ctx)
        .map_err(|_| PairingError::WrapFailed)
}

// ---------------------------------------------------------------------------
// 4. Short Authentication String (SAS) — the #106e-2 anti-MITM primitive
// ---------------------------------------------------------------------------

/// Length of the [`SAS_DOMAIN`]-bound freshness nonce the SAS hash binds (16 bytes).
///
/// Matches `pangolin_core::pairing_transport::FRESHNESS_NONCE_LEN`. The
/// crypto layer pins the length here so a future SAS-format change cannot
/// accidentally desync from the transport codec.
pub const SAS_FRESHNESS_NONCE_LEN: usize = 16;

/// A human-comparable Short Authentication String — the 6-decimal-digit
/// code the #106e-2 pairing flow derives over both devices' X25519
/// pairing pubkeys + the freshness nonce.
///
/// **The SAS is NON-SECRET.** It is what the human READS off both screens
/// and compares; it is the public anti-MITM anchor (L2). A 6-digit
/// decimal code is ~ 20 bits of comparison value — sufficient against an
/// online attacker who must guess the code BEFORE the user dismisses the
/// confirmation, and easy to read aloud / compare across two devices
/// (ZRTP-class). `Debug` / `Display` are fine because the value is not a
/// secret. Always exactly 6 ASCII digits (`000000`..=`999999`), zero-
/// padded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sas(pub String);

impl core::fmt::Display for Sas {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl Sas {
    /// The 6-digit SAS string, e.g. `"472913"`. Always 6 ASCII digits.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Derive the 6-digit decimal [`Sas`] over both devices' 32-byte X25519
/// pairing pubkeys + the 16-byte freshness nonce.
///
/// ## Canonical-symmetric (L3 — `106e2-pairing-transport-sas.md`)
///
/// The two pubkeys are sorted lexicographically as fixed-length byte
/// strings — assign `(lo, hi)` with `lo <= hi`. This guarantees
/// `derive_sas(a, b, n) == derive_sas(b, a, n)` for any `(a, b, n)`:
/// both devices derive the IDENTICAL code regardless of role (new-device
/// B or existing-device A). The byte-pin test
/// [`tests::sas_is_canonical_symmetric`] turns the gate RED if the
/// ordering ever silently changes.
///
/// ## The hash construction (the load-bearing L2 byte-identity)
///
/// ```text
/// H = SHA-256( SAS_DOMAIN || lo || hi || freshness_nonce )
/// digits_u32 = u32::from_be_bytes(H[..4])
/// sas = format!("{:06}", digits_u32 % 1_000_000)
/// ```
///
/// The 4-byte truncation provides 32 bits of input to the `% 1_000_000`
/// modulo (~ 20 bits of usable output); the negligible modulo bias
/// (`2^32 % 10^6 = 96`) is well below the audit-relevant threshold for
/// 6-digit codes (~ 2.2e-5 per code). The `freshness_nonce` is the
/// per-pairing entropy that makes a pre-computed table over `(lo, hi)`
/// pairs useless to a MITM (L5 — anti-replay).
///
/// ## Why a SHA-256 hash (not HKDF / not an HMAC)
///
/// The SAS is a NON-secret comparison code, not key material. There is
/// no extraction-from-non-uniform-IKM step (the pubkeys + nonce are
/// already uniformly random over their domains for any non-malicious
/// derivation), and there is no need for an authentication tag (no
/// secret to authenticate with). A single domain-prefixed SHA-256 is
/// sufficient + obviously-correct + matches the ZRTP `sas-base256`
/// shape. Using `sha2::Sha256` (already pulled at the workspace level
/// via the existing crypto deps); NO new external crate (L6).
///
/// ## L2 (LOAD-BEARING): a swapped pubkey ⇒ a different SAS
///
/// A MITM that substitutes its OWN pairing pubkey for B's gets a
/// DIFFERENT `(lo, hi)` lexicographic sort, hence a DIFFERENT
/// SHA-256 input, hence a DIFFERENT 6-digit code — surfaced on the
/// human comparison. The byte-pin test
/// [`tests::sas_defeats_pubkey_swap_mitm`] turns the gate RED if the SAS
/// ever stops binding BOTH pubkeys.
#[must_use]
pub fn derive_sas(
    pub_a: &[u8; X25519_KEY_LEN],
    pub_b: &[u8; X25519_KEY_LEN],
    freshness_nonce: &[u8; SAS_FRESHNESS_NONCE_LEN],
) -> Sas {
    use sha2::{Digest, Sha256};

    // L3 canonical-symmetric ordering: byte-lexicographic sort assigns
    // `(lo, hi)` so the SAS is independent of role. `<=` is fine for the
    // degenerate `a == b` case (whichever order the caller passed, lo ==
    // hi); the value is non-secret, so a non-constant-time compare is
    // acceptable here.
    let (lo, hi) = if pub_a.as_slice() <= pub_b.as_slice() {
        (pub_a, pub_b)
    } else {
        (pub_b, pub_a)
    };

    let mut hasher = Sha256::new();
    hasher.update(SAS_DOMAIN);
    hasher.update(&lo[..]);
    hasher.update(&hi[..]);
    hasher.update(&freshness_nonce[..]);
    let digest = hasher.finalize();

    // Take the first 4 bytes as a big-endian u32, reduce modulo 1_000_000,
    // format with leading zeros. The result is always 6 ASCII digits.
    let mut be4 = [0u8; 4];
    be4.copy_from_slice(&digest[..4]);
    let value = u32::from_be_bytes(be4);
    let digits = value % 1_000_000;
    Sas(format!("{digits:06}"))
}

#[cfg(test)]
mod tests;
