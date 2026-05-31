// SPDX-License-Identifier: AGPL-3.0-or-later
//! **MVP-3 issue #106e-1: the thin uniffi layer over the #106e-0 / #106e-0b
//! composition layer — recovery + guardian-open + onboarding bindings.**
//!
//! Wraps the merged-and-audited production methods so host apps can drive the
//! multi-device social-recovery flows:
//!
//! - [`vault_guardian_open_share`] — a guardian opens a sealed share; the
//!   opened [`pangolin_crypto::escrow::Share`] is the ONLY secret that ever
//!   leaves the engine, and it crosses ONLY as an opaque
//!   [`FfiOpenedShare`] `Arc` Object (length-only — no readable-bytes
//!   accessor, L1).
//! - [`vault_recover_from_shares`] — the LOST-EVERYTHING recovery (works on a
//!   loaded-but-Locked vault; it CREATES the unlockable state).
//! - [`vault_onboard_guardians`] — set up social recovery on a vault.
//!
//! The companion rotation binding (`vault_complete_rotation`) +
//! `vault_pending_rotations` live in [`crate::rotation_ffi`].
//!
//! ## L1 — ZERO secret crosses FFI as readable bytes
//!
//! The opened guardian `Share` crosses out behind [`FfiOpenedShare`], an
//! opaque zeroizing Object exposing only `byte_length()` (the
//! [`crate::session::SecretPassword`] template). Passwords cross IN behind
//! the same opaque-`Arc` discipline. Only epochs / non-secret recovery
//! results leave as plain values. `pangolin-core` / `pangolin-store` never
//! gain a `uniffi` dependency — the FFI lives ONLY here.

#![forbid(unsafe_code)]
// Heavily-documented FFI module — the share-transport section in particular
// needs in-source docs for the Decision-B anti-redirect gate. Allow the
// doc-style pedantic lints at module level (matches `recovery_lifecycle.rs`).
#![allow(
    clippy::doc_markdown,
    clippy::too_long_first_doc_paragraph,
    clippy::doc_lazy_continuation
)]

use std::sync::Arc;

use pangolin_crypto::aead::{Ciphertext, Nonce};
use pangolin_crypto::escrow::{SealedShare, Share, WrappedVdkRecovery, EPOCH_LEN};
use pangolin_crypto::keys::{WrapContext, WrappedVdk, VAULT_ID_LEN};
use pangolin_crypto::secret::SecretBytes;

use crate::error::FfiError;
use crate::session::{SecretPassword, VaultHandle};

/// Wire-form length of a guardian X25519 pubkey (the SEALING pubkey).
const X25519_PUB_LEN: usize = 32;

/// Map a [`pangolin_store::StoreError`] through the total
/// `StoreError → pangolin_core::Error → FfiError` mapping (the established
/// session.rs / device.rs discipline — collapses `AuthenticationFailed` to
/// `Validation { kind: "authentication" }` and `NotUnlocked` to `Session`).
fn store_into_ffi(err: pangolin_store::StoreError) -> FfiError {
    FfiError::from(pangolin_core::Error::from(err))
}

/// Validate a host-supplied `Vec<u8>` is exactly `N` bytes, returning the
/// fixed-size array or [`FfiError::Validation`] (`kind = "argument"`).
fn fixed_bytes<const N: usize>(bytes: &[u8], what: &str) -> Result<[u8; N], FfiError> {
    bytes.try_into().map_err(|_| FfiError::Validation {
        kind: "argument".into(),
        message: format!("{what} must be {N} bytes (got {})", bytes.len()),
    })
}

/// Validate + collect a `Vec<Vec<u8>>` of X25519 pubkeys into `[u8; 32]`s.
fn collect_x25519_pubs(pubs: &[Vec<u8>]) -> Result<Vec<[u8; X25519_PUB_LEN]>, FfiError> {
    pubs.iter()
        .map(|p| fixed_bytes::<X25519_PUB_LEN>(p, "guardian X25519 pubkey"))
        .collect()
}

// ---------------------------------------------------------------------------
// FfiOpenedShare — the ONE secret that crosses out, kept opaque (L1 / Q-c)
// ---------------------------------------------------------------------------

/// An opened guardian [`Share`], wrapped opaque for the FFI boundary.
///
/// Crosses FFI as a `UniFFI` Object (`Arc<Self>`) so the foreign-language
/// binding sees a reference type it can hold + pass back to
/// [`vault_recover_from_shares`] but can NEVER read. The exported surface
/// exposes ONLY [`FfiOpenedShare::byte_length`] — there is deliberately no
/// `Vec<u8>` getter (L1, the audit's central FFI check). The wrapped `Share`
/// is itself zeroizing; this wrapper additionally zeroizes any cached length
/// metadata on drop and renders only the length through `Debug`.
#[derive(uniffi::Object)]
pub struct FfiOpenedShare {
    /// The opened share. `pangolin_crypto::escrow::Share` is `!Clone`,
    /// `!Copy`, and zeroizes its buffer on drop.
    inner: Share,
}

impl std::fmt::Debug for FfiOpenedShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never reveal the share bytes; report only the length (matches the
        // SecretPassword / Share redaction discipline).
        f.debug_struct("FfiOpenedShare")
            .field("len", &self.inner.as_bytes().len())
            .field("bytes", &"<redacted>")
            .finish()
    }
}

impl FfiOpenedShare {
    /// Construct from an opened [`Share`]. Crate-private — the only producer
    /// is [`vault_guardian_open_share`].
    fn new(inner: Share) -> Arc<Self> {
        Arc::new(Self { inner })
    }

    /// Crate-private: move the wrapped [`Share`] out for the engine-side
    /// `recover_from_shares` call. Consumes the `Arc` (the host must have
    /// dropped every other clone — see [`vault_recover_from_shares`]). The
    /// `Share`'s zeroizing buffer is preserved across the move (no copy of
    /// the scalar leaves a redacted boundary).
    pub(crate) fn into_inner(self: Arc<Self>) -> Result<Share, FfiError> {
        Arc::try_unwrap(self)
            .map(|s| s.inner)
            .map_err(|_| FfiError::Validation {
                kind: "argument".into(),
                message: "opened share is still referenced elsewhere; \
                          drop every other reference before recovery"
                    .into(),
            })
    }
}

#[uniffi::export]
impl FfiOpenedShare {
    /// The opened share's byte length. The ONLY thing the exported API
    /// reveals about the share (L1) — never the bytes themselves.
    #[must_use]
    #[uniffi::method(name = "byte_length")]
    pub fn byte_length(&self) -> u32 {
        u32::try_from(self.inner.as_bytes().len()).unwrap_or(u32::MAX)
    }
}

// ---------------------------------------------------------------------------
// FfiGuardianRoster + FfiRecoveryResult records
// ---------------------------------------------------------------------------

/// Schema-version slot value for the recovery / rotation / onboarding records.
pub const RECOVERY_FFI_SCHEMA_VERSION: u16 = 1;

/// The host-supplied guardian roster for a LOST-EVERYTHING recovery.
///
/// Mirrors [`pangolin_core::composition::GuardianRoster`]: the threshold
/// `(t)`, the guardian count `(M)`, and the `M` guardians' 32-byte X25519
/// SEALING pubkeys (host-supplied from a backup; the backup FORMAT stays
/// deferred to 6.x). All non-secret.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiGuardianRoster {
    /// Schema-version slot.
    pub schema_version: u16,
    /// The reconstruction threshold `(t)`.
    pub threshold: u8,
    /// The guardian count `(M)`.
    pub guardian_count: u8,
    /// The `M` guardians' 32-byte X25519 SEALING pubkeys, ordered by index
    /// (`0..M`). Each MUST be exactly 32 bytes.
    pub x25519_pubs: Vec<Vec<u8>>,
}

/// Non-secret result of [`vault_recover_from_shares`].
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiRecoveryResult {
    /// The new recovery-generation epoch the post-recovery re-split was
    /// tagged with.
    pub new_epoch: u64,
    /// Schema-version slot.
    pub schema_version: u16,
}

/// Non-secret result of [`vault_onboard_guardians`].
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiOnboardingResult {
    /// The recovery-generation epoch the escrow was written at (GENESIS `0`
    /// for the first onboard).
    pub epoch: u64,
    /// Schema-version slot.
    pub schema_version: u16,
}

// ---------------------------------------------------------------------------
// wrapped_recovery byte (de)serialization for the lost-everything backup
// ---------------------------------------------------------------------------

/// Decode a host-supplied `wrapped_recovery` blob into a
/// [`WrappedVdkRecovery`].
///
/// The blob format mirrors how `pangolin-store` round-trips the escrow's
/// `WrappedVdk` parts (`recovery_escrow.rs`): the second-wrap is the
/// `(ciphertext, nonce, WrapContext)` triple. On the lost-everything path the
/// `vault_id` and the wrap `schema_version` travel out-of-band (the
/// `vault_id` is its own FFI parameter; the schema byte is the leading byte
/// of the blob), so the blob is the deterministic concatenation:
///
/// ```text
/// wrapped_recovery = wrap_schema_version (1 B) || nonce (NONCE_LEN B) || ciphertext (rest)
/// ```
///
/// The reconstructed wrapper authenticates only when the recovery driver
/// unwraps it under the reconstructed RWK + this exact `WrapContext`; a
/// tampered/short blob fails closed there (or here on a length check).
pub(crate) fn decode_wrapped_recovery(
    bytes: &[u8],
    vault_id: [u8; VAULT_ID_LEN],
) -> Result<WrappedVdkRecovery, FfiError> {
    use pangolin_crypto::aead::NONCE_LEN;

    // 1 schema byte + the nonce + at least one ciphertext byte (an empty
    // ciphertext can never authenticate).
    if bytes.len() <= 1 + NONCE_LEN {
        return Err(FfiError::Validation {
            kind: "argument".into(),
            message: format!(
                "wrapped_recovery must be at least {} bytes (got {})",
                1 + NONCE_LEN + 1,
                bytes.len()
            ),
        });
    }
    let schema_version = bytes[0];
    let nonce_bytes: [u8; NONCE_LEN] =
        fixed_bytes(&bytes[1..=NONCE_LEN], "wrapped_recovery nonce")?;
    let ciphertext = bytes[1 + NONCE_LEN..].to_vec();

    Ok(WrappedVdkRecovery::from_wrapped(WrappedVdk::from_parts(
        Ciphertext::from_vec(ciphertext),
        Nonce::from_storage_bytes(nonce_bytes),
        WrapContext {
            vault_id,
            schema_version,
        },
    )))
}

// ---------------------------------------------------------------------------
// 3. vault_guardian_open_share
// ---------------------------------------------------------------------------

/// **A guardian opens a sealed share** — drives
/// [`pangolin_store::Vault::guardian_open_sealed_share`].
///
/// Session-gated (Active — the open derives the guardian X25519 sealing
/// secret from the active session's `DeviceKey`). `sealed_share` is the
/// non-secret sealed-box bytes; `vault_id` (32 B) + `epoch` (the 16-byte
/// [`EPOCH_LEN`] form) bind the recovery context. The returned opened
/// [`Share`] is the ONE secret out — it crosses behind the opaque
/// [`FfiOpenedShare`] Object (L1).
///
/// # Errors
///
/// - [`FfiError::Session`] for a locked / placeholder handle (no active
///   session).
/// - [`FfiError::Validation`] (`kind = "argument"`) for a bad `vault_id` /
///   `epoch` length.
/// - [`FfiError::Validation`] (`kind = "authentication"`) for an open failure
///   (wrong key / tampered ciphertext / `vault_id` / `epoch` mismatch — the
///   undifferentiated indistinguishability collapse).
#[allow(clippy::significant_drop_tightening)]
#[uniffi::export]
pub fn vault_guardian_open_share(
    handle: Arc<VaultHandle>,
    sealed_share: Vec<u8>,
    vault_id: Vec<u8>,
    epoch: Vec<u8>,
) -> Result<Arc<FfiOpenedShare>, FfiError> {
    let vault_id_arr: [u8; VAULT_ID_LEN] = fixed_bytes(&vault_id, "vault_id")?;
    let epoch_arr: [u8; EPOCH_LEN] = fixed_bytes(&epoch, "epoch")?;
    let sealed = SealedShare::from_bytes(sealed_share);

    let mut guard = handle.lock_vault();
    let vault = guard.as_mut()?;
    let share = vault
        .guardian_open_sealed_share(&sealed, &vault_id_arr, &epoch_arr)
        .map_err(store_into_ffi)?;
    Ok(FfiOpenedShare::new(share))
}

// ---------------------------------------------------------------------------
// 4. vault_recover_from_shares (LOST-EVERYTHING — works on a Locked vault)
// ---------------------------------------------------------------------------

/// **Recover a vault from guardian shares on a LOST-EVERYTHING device** —
/// drives [`pangolin_core::composition::recover_from_shares`].
///
/// Works on a loaded-but-Locked vault (`as_mut()?` yields the vault even when
/// not Active — recovery CREATES the unlockable state, it does not require a
/// prior session). `wrapped_recovery` (host-supplied backup blob),
/// `current_epoch`, and `vault_id` (32 B) all cross as length-validated
/// params (Q-d). `roster` carries `(t, M)` + the `M` guardian X25519 pubkeys
/// (each 32 B). `new_password` crosses IN behind the opaque
/// [`SecretPassword`] Object; the opened `Share`s cross IN behind the opaque
/// [`FfiOpenedShare`] Objects (engine-side extraction — see
/// [`FfiOpenedShare::into_inner`]). Nothing secret crosses OUT.
///
/// # Errors
///
/// - [`FfiError::Session`] if the handle has no vault installed.
/// - [`FfiError::Validation`] (`kind = "argument"`) for a bad `vault_id` /
///   pubkey length, a malformed `wrapped_recovery` blob, or a still-shared
///   `FfiOpenedShare`.
/// - [`FfiError::Recovery`] / [`FfiError::Validation`] (`authentication`) for
///   a driver / commit failure (see [`composition_error_into_ffi`]).
#[allow(clippy::significant_drop_tightening, clippy::needless_pass_by_value)]
#[uniffi::export]
pub fn vault_recover_from_shares(
    handle: Arc<VaultHandle>,
    wrapped_recovery: Vec<u8>,
    opened_shares: Vec<Arc<FfiOpenedShare>>,
    roster: FfiGuardianRoster,
    new_password: Arc<SecretPassword>,
    current_epoch: u64,
    vault_id: Vec<u8>,
) -> Result<FfiRecoveryResult, FfiError> {
    let vault_id_arr: [u8; VAULT_ID_LEN] = fixed_bytes(&vault_id, "vault_id")?;
    let pubs = collect_x25519_pubs(&roster.x25519_pubs)?;
    let core_roster = pangolin_core::composition::GuardianRoster {
        threshold: roster.threshold,
        guardian_count: roster.guardian_count,
        x25519_pubs: pubs,
    };
    let wrapped = decode_wrapped_recovery(&wrapped_recovery, vault_id_arr)?;

    // Extract the owned `Share`s engine-side. Each `Arc<FfiOpenedShare>` must
    // be uniquely held (the host dropped every other clone); the zeroizing
    // `Share` is moved out, never copied past a redacted boundary.
    let mut shares: Vec<Share> = Vec::with_capacity(opened_shares.len());
    for s in opened_shares {
        shares.push(s.into_inner()?);
    }

    // Bridge the password engine-side into a zeroizing SecretBytes.
    let mut pw = zeroize::Zeroizing::new(new_password.bytes_for_bridge().to_vec());
    let secret = SecretBytes::new(std::mem::take(&mut *pw));

    let mut guard = handle.lock_vault();
    let vault = guard.as_mut()?;
    let outcome = pangolin_core::composition::recover_from_shares(
        vault,
        &wrapped,
        shares,
        &core_roster,
        &secret,
        current_epoch,
        vault_id_arr,
    )
    .map_err(composition_error_into_ffi)?;
    drop(secret);
    Ok(FfiRecoveryResult {
        new_epoch: outcome.new_epoch,
        schema_version: RECOVERY_FFI_SCHEMA_VERSION,
    })
}

// ---------------------------------------------------------------------------
// 5. vault_onboard_guardians
// ---------------------------------------------------------------------------

/// **Set up social recovery on a vault** — drives
/// [`pangolin_store::Vault::onboard_guardians`].
///
/// Session-gated (Active — the onboard reads the active VDK store-internal).
/// `guardian_x25519_pubs` are the `M` guardian SEALING pubkeys (each 32 B);
/// the threshold `(t)` and `M = guardian_x25519_pubs.len()` must satisfy the
/// on-chain bounds (`t ∈ 2..=9`, `M ∈ 3..=15`, `t ≤ M`). Non-secret: guardian
/// pubkeys in, the recovery-generation epoch out.
///
/// # Self-as-guardian — NOT enforced here
///
/// This FFI does **NOT** refuse `THIS` device's own sealing pubkey (the one
/// `vault_export_guardian_identity` would return for the active session). A
/// self-onboard defeats the recovery threat model — if the owner loses all
/// devices, the share sealed to the owner's device is unrecoverable, so the
/// effective threshold becomes `t` of `M-1`. The check is intentionally
/// UI-side (MVP-4-L L-A wizard, Q-d) because the engine has no concept of
/// "this device's identity vs another's" beyond the active session's derived
/// sealing key; pushing the check into the engine would couple the recovery
/// composition to the session-derivation path.
///
/// **Every new caller** of this FFI (a future second UI surface, a CLI, an
/// E2E harness) MUST replicate the self-as-guardian gate at its own layer.
/// Plan-LOCK: `docs/issue-plans/mvp4-l-a-guardian-onboarding.md` §5.
///
/// # Errors
///
/// - [`FfiError::Session`] for a locked / placeholder handle.
/// - [`FfiError::Validation`] (`kind = "argument"`) for a bad pubkey length.
/// - [`FfiError::Validation`] (`kind = "authentication"`) if the onboard
///   composition fails (e.g. an out-of-bounds `(t, M)`).
/// - [`FfiError::Store`] on a DB / transaction error.
#[allow(clippy::significant_drop_tightening, clippy::needless_pass_by_value)]
#[uniffi::export]
pub fn vault_onboard_guardians(
    handle: Arc<VaultHandle>,
    threshold: u8,
    guardian_x25519_pubs: Vec<Vec<u8>>,
) -> Result<FfiOnboardingResult, FfiError> {
    let pubs = collect_x25519_pubs(&guardian_x25519_pubs)?;
    let mut guard = handle.lock_vault();
    let vault = guard.as_mut()?;
    let outcome = vault
        .onboard_guardians(threshold, &pubs)
        .map_err(store_into_ffi)?;
    Ok(FfiOnboardingResult {
        epoch: outcome.epoch,
        schema_version: RECOVERY_FFI_SCHEMA_VERSION,
    })
}

// ---------------------------------------------------------------------------
// CompositionError → FfiError mapping (L6 — errors carry no secret)
// ---------------------------------------------------------------------------

/// Map a [`pangolin_core::composition::CompositionError`] into the FFI
/// taxonomy.
///
/// - `Store(e)` → routed through the total `StoreError` mapping (collapses
///   `AuthenticationFailed` → `Validation { kind: "authentication" }`,
///   `NotUnlocked` → `Session`).
/// - `NoRecoveryEscrow` → a clear [`FfiError::Recovery`] message.
/// - `Rotation(_)` / `Recovery(_)` → [`FfiError::Recovery`], EXCEPT an
///   authentication-class crypto failure (a sealed-share open / RWK
///   reconstruct / VDK unwrap), which collapses to
///   `Validation { kind: "authentication" }` so the FFI cannot become a
///   distinguishing oracle.
///
/// No secret material is in any `Display` of these errors (the escrow errors
/// are deliberately coarse + undifferentiated).
pub(crate) fn composition_error_into_ffi(
    err: pangolin_core::composition::CompositionError,
) -> FfiError {
    use pangolin_core::composition::CompositionError as CE;
    use pangolin_core::recovery::orchestration::RecoveryOrchestrationError as RErr;
    use pangolin_core::rotation::RotationError as RotErr;
    use pangolin_crypto::escrow::EscrowError;

    // An EscrowError is authentication-class iff it is an open / reconstruct /
    // wrap failure (the indistinguishability collapse). Structural parameter
    // errors (bounds / split / seal / malformed) stay Recovery-class.
    fn escrow_is_auth(e: EscrowError) -> bool {
        matches!(
            e,
            EscrowError::OpenFailed | EscrowError::ReconstructFailed | EscrowError::WrapFailed
        )
    }
    fn orchestration_is_auth(e: &RErr) -> bool {
        matches!(e, RErr::Escrow(inner) if escrow_is_auth(*inner))
    }

    match err {
        CE::Store(e) => store_into_ffi(e),
        CE::NoRecoveryEscrow => FfiError::Recovery {
            message: "cannot rotate: no recovery escrow is onboarded to re-point".into(),
        },
        CE::Rotation(rot) => match &rot {
            RotErr::EscrowRePoint(inner) if orchestration_is_auth(inner) => {
                FfiError::authentication_failed()
            }
            _ => FfiError::Recovery {
                message: rot.to_string(),
            },
        },
        CE::Recovery(rec) if orchestration_is_auth(&rec) => FfiError::authentication_failed(),
        CE::Recovery(rec) => FfiError::Recovery {
            message: rec.to_string(),
        },
    }
}

// =====================================================================
// MVP-4-L L-0a-2.2 — recovery share-transport FFI surface
//
// Three bindings implementing the cross-device share-release protocol
// (the LOCKED share-transport design's off-chain core):
//
//   1. vault_recovery_recipient_identity — the recovering device's
//      per-attempt X25519 pubkey (the on-chain `recipientCommitment`),
//      for the L2 human SAS check.
//   2. vault_guardian_release_share — the guardian's "open-and-reseal"
//      atomic engine call: opens the stored sealed-share, verifies the
//      host-supplied recipient_commitment EQUALS the on-chain commitment
//      (Decision B anti-redirect — refuses to release if the chain says
//      otherwise), re-seals to the recipient pubkey. Cleartext piece
//      NEVER materializes in the host.
//   3. vault_recovery_ingest_share — the recoverer's unseal: opens a
//      transported sealed blob using the recovery-recipient secret +
//      returns the opened share as the existing opaque FfiOpenedShare
//      Object (which the host then accumulates + feeds into
//      vault_recover_from_shares).
// =====================================================================

/// Schema-version slot value for [`FfiRecipientIdentity`]. Independent of
/// the wire-form bytes (the recipient pubkey is just 32 bytes; the slot
/// here pins the FFI record shape).
pub const RECOVERY_RECIPIENT_FFI_SCHEMA_VERSION: u16 = 1;

/// The non-secret per-attempt recipient identity for an active recovery
/// attempt on the recovering device. The pubkey is the on-chain
/// `recipientCommitment`; the L2 SAS/QR human gate uses the bytes
/// directly. Returned by [`vault_recovery_recipient_identity`].
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiRecipientIdentity {
    /// The recovering device's 32-byte X25519 public key for this attempt
    /// (the on-chain `recipientCommitment`).
    pub recipient_pubkey: Vec<u8>,
    /// The attempt nonce this keypair was bound to at persist time.
    pub attempt_nonce: u64,
    /// Schema-version slot.
    pub schema_version: u16,
}

/// **Recovering device — read the per-attempt recipient identity.**
///
/// Returns the recoverer's ephemeral X25519 pubkey for the active attempt
/// on `target_vault_id`. The pubkey IS the on-chain `recipientCommitment`
/// — surface it for the L2 SAS / QR human check (the guardian's UX shows
/// the same bytes; the user eyeballs them).
///
/// Returns [`FfiError::Validation`] (`kind = "argument"`) if no LOCAL row
/// exists for `target_vault_id`. **NOTE:** local absence does NOT mean
/// no on-chain attempt — the post-broadcast persist-failure orphan path
/// in `vault_initiate_recovery` (see its doc) can leave an on-chain
/// PENDING attempt with no matching local secret. The host should
/// cross-check via `vault_read_recovery_status` to distinguish "never
/// initiated" from "initiated but secret lost" / "initiated by a
/// different device."
///
/// Loaded-only (any non-placeholder handle — no VDK required for this
/// read; the secret is NOT decrypted here).
///
/// # Errors
///
/// - [`FfiError::Validation`] for a non-32-byte `target_vault_id` or no
///   active attempt.
/// - [`FfiError::Session`] for a placeholder handle.
/// - [`FfiError::Store`] on a DB error.
#[allow(clippy::significant_drop_tightening, clippy::needless_pass_by_value)]
#[uniffi::export]
pub fn vault_recovery_recipient_identity(
    handle: Arc<VaultHandle>,
    target_vault_id: Vec<u8>,
) -> Result<FfiRecipientIdentity, FfiError> {
    let vault_id_arr: [u8; VAULT_ID_LEN] = fixed_bytes(&target_vault_id, "target_vault_id")?;
    let mut guard = handle.lock_vault();
    let vault = guard.as_mut()?;
    let identity = vault
        .recovery_recipient_pubkey(vault_id_arr)
        .map_err(store_into_ffi)?;
    let Some(id) = identity else {
        return Err(FfiError::Validation {
            kind: "argument".into(),
            message: "no active recovery attempt recorded for the supplied target_vault_id"
                .to_string(),
        });
    };
    Ok(FfiRecipientIdentity {
        recipient_pubkey: id.x25519_pub.to_vec(),
        attempt_nonce: id.attempt_nonce,
        schema_version: RECOVERY_RECIPIENT_FFI_SCHEMA_VERSION,
    })
}

/// **Guardian device — open-and-re-seal in one engine call.**
///
/// The cross-device path's guardian-side primitive (Decision B anti-
/// redirect). Steps performed in-engine, in ONE atomic call:
///
///  1. **Fetch the on-chain live attempt** for `target_vault_id` via
///     [`pangolin_chain::read_live_attempt_v2`].
///  2. **Verify the on-chain commitment matches the host-supplied one**:
///     the live attempt must be PENDING, the `attempt_nonce` must match,
///     and the on-chain `recipient_commitment` MUST byte-equal the
///     supplied `recipient_commitment`. If any check fails the function
///     errors out **before opening the share** — the cleartext piece
///     never materializes on a mis-targeted release. This is the
///     load-bearing anti-redirect gate.
///  3. **Open the guardian's stored sealed share** via
///     [`pangolin_store::Vault::guardian_open_sealed_share`] (uses the
///     active session's X25519 sealing secret).
///  4. **Re-seal** the opened piece to `recipient_commitment` via
///     [`pangolin_crypto::share_transport::seal_share_to_recoverer`],
///     binding `(target_vault_id, attempt_nonce, recipient_pub,
///     share_identifier)` into the authenticated header.
///
/// Returns the `SealedShareForRecoverer` ciphertext bytes (non-secret;
/// safe over any transport). The cleartext piece never crosses the FFI.
///
/// `epoch` is the escrow generation epoch (16 bytes — same form
/// `vault_guardian_open_share` takes), needed to open the guardian's
/// stored sealed share.
///
/// Session-gated (Active — the guardian's vault).
///
/// # Errors
///
/// - [`FfiError::Validation`] (`kind = "argument"`) for a bad length or a
///   commitment/nonce/status mismatch ("not redirected" pre-check failed).
/// - [`FfiError::Session`] for a non-Active / placeholder vault.
/// - [`FfiError::Chain`] for an RPC or read failure during the on-chain
///   commitment fetch.
/// - [`FfiError::Validation`] (`kind = "authentication"`) for an open or
///   seal cryptographic failure.
#[allow(
    clippy::significant_drop_tightening,
    clippy::needless_pass_by_value,
    clippy::too_many_arguments
)]
#[uniffi::export]
pub fn vault_guardian_release_share(
    handle: Arc<VaultHandle>,
    sealed_share: Vec<u8>,
    target_vault_id: Vec<u8>,
    epoch: Vec<u8>,
    attempt_nonce: u64,
    recipient_commitment: Vec<u8>,
    config: crate::chain_config::FfiChainConfig,
) -> Result<Vec<u8>, FfiError> {
    let vault_id_arr: [u8; VAULT_ID_LEN] = fixed_bytes(&target_vault_id, "target_vault_id")?;
    let epoch_arr: [u8; EPOCH_LEN] = fixed_bytes(&epoch, "epoch")?;
    let recipient_commitment_arr: [u8; 32] =
        fixed_bytes(&recipient_commitment, "recipient_commitment")?;

    // Phase 0: assert Active BEFORE the chain RPC (L-0a-2.2 audit LOW-1).
    // Without this hoist, a Locked-vault caller would issue a view-call
    // exposing the target vault_id to the configured RPC node before
    // failing closed at the share-open. The inner
    // `guardian_open_sealed_share` re-asserts Active (so the open is still
    // gated end-to-end), but doing the check up front avoids the metadata
    // leak. Mirror of `recovery_lifecycle.rs`'s pre-RPC gate pattern.
    {
        let mut g = handle.lock_vault();
        let v = g.as_mut()?;
        if v.state() != pangolin_store::VaultState::Active {
            return Err(FfiError::Session {
                message: "vault is not unlocked".to_owned(),
            });
        }
        drop(g);
    }

    // Phase 1: on-chain commitment verification (BEFORE opening the
    // cleartext piece). This is the load-bearing Decision B gate; if the
    // chain says the attempt's committed recipient differs, REFUSE to
    // release the piece — the host cannot have been tricked into sealing
    // to an attacker key.
    let live = crate::chain_config::block_on_local(async {
        let (env, _chain_id) = crate::chain_config::ffi_chain_env_and_id(&config.rpc_url)
            .await
            .map_err(crate::chain_config::chain_into_ffi)?;
        pangolin_chain::read_live_attempt_v2(env, &config.rpc_url, vault_id_arr)
            .await
            .map_err(crate::chain_config::chain_into_ffi)
    })??;
    if live.status != 1 {
        return Err(FfiError::Validation {
            kind: "argument".into(),
            message: format!(
                "no PENDING recovery attempt on-chain for target vault (status={})",
                live.status
            ),
        });
    }
    if live.attempt_nonce != attempt_nonce {
        return Err(FfiError::Validation {
            kind: "argument".into(),
            message: format!(
                "attempt_nonce mismatch: host supplied {attempt_nonce}, on-chain is {}",
                live.attempt_nonce
            ),
        });
    }
    if live.recipient_commitment != recipient_commitment_arr {
        return Err(FfiError::Validation {
            kind: "argument".into(),
            message: "recipient_commitment does not match on-chain RecoveryV2.recipientCommitment \
                      — REFUSING to release a share (anti-redirect, Decision B)"
                .into(),
        });
    }

    // Phase 2: open the guardian's sealed share (Active session required).
    let sealed = pangolin_crypto::escrow::SealedShare::from_bytes(sealed_share);
    let mut guard = handle.lock_vault();
    let vault = guard.as_mut()?;
    let piece = vault
        .guardian_open_sealed_share(&sealed, &vault_id_arr, &epoch_arr)
        .map_err(store_into_ffi)?;

    // Phase 3: re-seal to the on-chain-committed recipient. The cleartext
    // `piece` lives only inside this function frame; `seal_share_to_recoverer`
    // produces non-secret sealed bytes; the piece is dropped (zeroized) at
    // the end of this expression.
    let sealed_for_recoverer = pangolin_crypto::share_transport::seal_share_to_recoverer(
        &piece,
        &recipient_commitment_arr,
        &vault_id_arr,
        attempt_nonce,
    )
    .map_err(|_| FfiError::authentication_failed())?;
    drop(piece);
    Ok(sealed_for_recoverer.as_bytes().to_vec())
}

/// **Recovering device — ingest a transported sealed share.**
///
/// Unseals a `SealedShareForRecoverer` blob using the stored recovery
/// recipient secret + returns the opened piece as the existing opaque
/// [`FfiOpenedShare`] Object. The host then accumulates these handles
/// and feeds them into [`vault_recover_from_shares`] when the quorum is
/// reached.
///
/// Session-gated (Active — the recoverer's vault; needs the VDK to
/// decrypt the persisted ephemeral secret).
///
/// `attempt_nonce` MUST match BOTH the nonce recorded in the persisted
/// `recovery_recipient` row AND the on-chain live attempt's nonce. The
/// chain re-check (L-0a-2.2 audit LOW-3 follow-up) catches the
/// state-divergence case where the attempt was finalized / cancelled
/// out-of-band (e.g., the authority cancelled while this device was
/// offline) but the local row wasn't yet cleared.
///
/// # Errors
///
/// - [`FfiError::Validation`] (`kind = "argument"`) for a bad
///   `target_vault_id` length, no persisted recipient row, an
///   attempt_nonce mismatch, or an on-chain attempt that is no longer
///   PENDING.
/// - [`FfiError::Session`] for a non-Active / placeholder vault.
/// - [`FfiError::Chain`] for the on-chain status re-check failure (RPC
///   down / deployment missing). Fail-closed: refuse to ingest if we
///   can't confirm the attempt is still live.
/// - [`FfiError::Validation`] (`kind = "authentication"`) for an unseal
///   failure (wrong secret, tampered blob, wrong vault_id / nonce
///   binding) — the undifferentiated indistinguishability collapse.
#[allow(clippy::significant_drop_tightening, clippy::needless_pass_by_value)]
#[uniffi::export]
pub fn vault_recovery_ingest_share(
    handle: Arc<VaultHandle>,
    sealed_blob: Vec<u8>,
    target_vault_id: Vec<u8>,
    attempt_nonce: u64,
    config: crate::chain_config::FfiChainConfig,
) -> Result<Arc<FfiOpenedShare>, FfiError> {
    let vault_id_arr: [u8; VAULT_ID_LEN] = fixed_bytes(&target_vault_id, "target_vault_id")?;

    // Phase 0: Active check BEFORE the chain RPC (mirror LOW-1 fix in
    // vault_guardian_release_share — a Locked-vault caller would
    // otherwise leak the target vault_id to the RPC node before failing
    // closed at the secret peek).
    {
        let mut g = handle.lock_vault();
        let v = g.as_mut()?;
        if v.state() != pangolin_store::VaultState::Active {
            return Err(FfiError::Session {
                message: "vault is not unlocked".to_owned(),
            });
        }
        drop(g);
    }

    // Phase 1: on-chain liveness re-check (LOW-3 follow-up). Refuse to
    // ingest if the attempt has reached a terminal state — a stale
    // delayed blob from a now-cancelled/finalized attempt would feed
    // vault_recover_from_shares but cannot reconstruct anything useful;
    // catching divergence here is a defense-in-depth UX win + closes the
    // state-divergence window between local row + on-chain status.
    let live = crate::chain_config::block_on_local(async {
        let (env, _chain_id) = crate::chain_config::ffi_chain_env_and_id(&config.rpc_url)
            .await
            .map_err(crate::chain_config::chain_into_ffi)?;
        pangolin_chain::read_live_attempt_v2(env, &config.rpc_url, vault_id_arr)
            .await
            .map_err(crate::chain_config::chain_into_ffi)
    })??;
    if live.status != 1 {
        return Err(FfiError::Validation {
            kind: "argument".into(),
            message: format!(
                "on-chain recovery attempt is no longer PENDING (status={}) — refusing to ingest \
                 a share; the attempt has reached a terminal state",
                live.status
            ),
        });
    }
    if live.attempt_nonce != attempt_nonce {
        return Err(FfiError::Validation {
            kind: "argument".into(),
            message: format!(
                "on-chain attempt_nonce ({}) does not match host-supplied ({attempt_nonce})",
                live.attempt_nonce
            ),
        });
    }

    // Phase 2: peek + verify the locally-recorded nonce.
    let mut guard = handle.lock_vault();
    let vault = guard.as_mut()?;
    let peek = vault
        .peek_recovery_recipient_secret(vault_id_arr)
        .map_err(store_into_ffi)?;
    let Some((recorded_nonce, secret, _public)) = peek else {
        return Err(FfiError::Validation {
            kind: "argument".into(),
            message: "no active recovery attempt recorded for the supplied target_vault_id"
                .to_string(),
        });
    };
    if recorded_nonce != attempt_nonce {
        return Err(FfiError::Validation {
            kind: "argument".into(),
            message: format!(
                "locally-recorded attempt_nonce mismatch: host supplied {attempt_nonce}, \
                 recorded {recorded_nonce}"
            ),
        });
    }

    // Phase 3: unseal in-engine.
    let sealed = pangolin_crypto::share_transport::SealedShareForRecoverer::from_bytes(sealed_blob);
    let piece = pangolin_crypto::share_transport::open_share_from_recoverer(
        &sealed,
        &secret,
        &vault_id_arr,
        attempt_nonce,
    )
    .map_err(|_| FfiError::authentication_failed())?;
    drop(secret);
    Ok(FfiOpenedShare::new(piece))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pangolin_core::recovery::orchestration::RecoveryEpoch;
    use pangolin_core::recovery::{onboard_guardian_escrow, GuardianSetConfig};
    use pangolin_crypto::guardian::derive_x25519_sealing_key;
    use pangolin_crypto::keys::{DeviceKey, VdkKey};
    use pangolin_store::{PinIdentityProof, PressYPresenceProof, Vault, VaultState};

    const T: u8 = 2;
    const M: u8 = 3;

    fn unlock(vault: &mut Vault, password: &[u8]) {
        let presence = PressYPresenceProof::confirmed();
        let identity = PinIdentityProof::new(SecretBytes::new(password.to_vec()));
        vault.unlock(&presence, &identity).expect("unlock");
    }

    fn unlocked_handle(dir: &tempfile::TempDir, name: &str, pw: &[u8]) -> Arc<VaultHandle> {
        let path = dir.path().join(name);
        Vault::create(&path, &SecretBytes::new(pw.to_vec())).unwrap();
        let mut v = Vault::open(&path).unwrap();
        unlock(&mut v, pw);
        VaultHandle::from_vault(v)
    }

    /// Build `M` guardian vaults; return (sealing pubkey, handle) pairs. Each
    /// guardian opens shares via the FFI `vault_guardian_open_share`, which
    /// derives the sealing secret from the vault's OWN active device key.
    #[allow(clippy::significant_drop_tightening)]
    fn guardian_handles(dirs: &[tempfile::TempDir]) -> (Vec<[u8; 32]>, Vec<Arc<VaultHandle>>) {
        let mut pubs = Vec::new();
        let mut handles = Vec::new();
        for (i, dir) in dirs.iter().enumerate() {
            let pw = format!("guardian {i} master pw");
            let h = unlocked_handle(dir, "guardian.pvf", pw.as_bytes());
            let seed = {
                let mut g = h.lock_vault();
                let v = g.as_mut().unwrap();
                *v.device_key_secret_seed()
                    .expect("active session exposes the seed (test-utilities)")
            };
            let device = DeviceKey::from_seed(seed);
            pubs.push(*derive_x25519_sealing_key(&device).public_bytes());
            handles.push(h);
        }
        (pubs, handles)
    }

    /// Re-encode a `WrappedVdkRecovery` into the FFI blob layout the
    /// host would carry in its backup (the inverse of
    /// [`decode_wrapped_recovery`]).
    fn encode_wrapped_recovery(w: &WrappedVdkRecovery) -> Vec<u8> {
        let inner = w.as_wrapped();
        let mut out = Vec::new();
        out.push(inner.context().schema_version);
        out.extend_from_slice(inner.nonce().as_bytes());
        out.extend_from_slice(inner.ciphertext().as_bytes());
        out
    }

    #[test]
    fn opened_share_object_exposes_only_length() {
        // The opaque Object exposes byte_length() and NOTHING that returns
        // the raw bytes. (Compile-time: there is no `Vec<u8>` getter on the
        // #[uniffi::export] surface — this asserts the length is sane.)
        let dirs: Vec<tempfile::TempDir> =
            (0..M).map(|_| tempfile::TempDir::new().unwrap()).collect();
        let (pubs, handles) = guardian_handles(&dirs);
        let vdk = VdkKey::generate();
        let vault_id = [0x42u8; VAULT_ID_LEN];
        let escrow = onboard_guardian_escrow(
            &vdk,
            &vault_id,
            GuardianSetConfig {
                threshold: T,
                guardian_count: M,
            },
            &pubs,
            RecoveryEpoch(0),
        )
        .unwrap();
        let epoch_bytes = RecoveryEpoch(0).to_escrow_bytes();
        let opened = vault_guardian_open_share(
            Arc::clone(&handles[0]),
            escrow.assignments[0].sealed_share.as_bytes().to_vec(),
            vault_id.to_vec(),
            epoch_bytes.to_vec(),
        )
        .expect("guardian opens its share");
        // The ONLY thing observable is a positive length.
        assert!(
            opened.byte_length() > 0,
            "opened share has a positive length"
        );
    }

    #[test]
    fn guardian_open_rejects_bad_lengths_and_locked() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "g.pvf", b"correct horse battery staple");
        // Bad vault_id length.
        let err = vault_guardian_open_share(
            Arc::clone(&h),
            vec![0u8; 80],
            vec![0u8; 31],
            vec![0u8; EPOCH_LEN],
        )
        .unwrap_err();
        assert!(matches!(err, FfiError::Validation { ref kind, .. } if kind == "argument"));
        // Locked vault → Session.
        {
            let mut g = h.lock_vault();
            g.as_mut().unwrap().lock();
        }
        let err = vault_guardian_open_share(
            h,
            vec![0u8; 80],
            vec![0u8; VAULT_ID_LEN],
            vec![0u8; EPOCH_LEN],
        )
        .unwrap_err();
        assert!(matches!(err, FfiError::Session { .. }));
    }

    #[test]
    #[allow(clippy::significant_drop_tightening)]
    fn onboard_then_open_then_recover_round_trips_through_ffi() {
        // Guardians.
        let dirs: Vec<tempfile::TempDir> =
            (0..M).map(|_| tempfile::TempDir::new().unwrap()).collect();
        let (pubs, handles) = guardian_handles(&dirs);

        // The "lost" vault's VDK + id (travel in the backup).
        let vdk = VdkKey::generate();
        let vault_id = [0x5Cu8; VAULT_ID_LEN];
        let escrow = onboard_guardian_escrow(
            &vdk,
            &vault_id,
            GuardianSetConfig {
                threshold: T,
                guardian_count: M,
            },
            &pubs,
            RecoveryEpoch(0),
        )
        .unwrap();
        let wrapped_blob = encode_wrapped_recovery(&escrow.wrapped_recovery);
        let epoch_bytes = RecoveryEpoch(0).to_escrow_bytes();

        // T guardians open their shares through the FFI.
        let mut opened: Vec<Arc<FfiOpenedShare>> = Vec::new();
        for (h, assignment) in handles.iter().zip(&escrow.assignments).take(usize::from(T)) {
            let s = vault_guardian_open_share(
                Arc::clone(h),
                assignment.sealed_share.as_bytes().to_vec(),
                vault_id.to_vec(),
                epoch_bytes.to_vec(),
            )
            .expect("open share");
            opened.push(s);
        }

        // A fresh lost-everything vault (Locked, never recovered).
        let fresh_dir = tempfile::TempDir::new().unwrap();
        let fresh_path = fresh_dir.path().join("recovered.pvf");
        Vault::create(&fresh_path, &SecretBytes::new(b"placeholder".to_vec())).unwrap();
        let fresh = Vault::open(&fresh_path).unwrap();
        let fresh_h = VaultHandle::from_vault(fresh);

        let roster = FfiGuardianRoster {
            schema_version: RECOVERY_FFI_SCHEMA_VERSION,
            threshold: T,
            guardian_count: M,
            x25519_pubs: pubs.iter().map(|p| p.to_vec()).collect(),
        };
        let result = vault_recover_from_shares(
            Arc::clone(&fresh_h),
            wrapped_blob,
            opened,
            roster,
            SecretPassword::new(b"post-recovery master password".to_vec()),
            0,
            vault_id.to_vec(),
        )
        .expect("recover_from_shares through the FFI");
        assert_eq!(result.new_epoch, 1, "the re-split bumps the epoch");

        // The NEW password unlocks the recovered vault.
        {
            let mut g = fresh_h.lock_vault();
            let v = g.as_mut().unwrap();
            assert_eq!(v.state(), VaultState::Locked);
            unlock(v, b"post-recovery master password");
            assert_eq!(v.state(), VaultState::Active);
        }
    }

    #[test]
    fn onboard_guardians_through_ffi_returns_genesis_epoch() {
        let dirs: Vec<tempfile::TempDir> =
            (0..M).map(|_| tempfile::TempDir::new().unwrap()).collect();
        let (pubs, _handles) = guardian_handles(&dirs);
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf", b"correct horse battery staple");
        let res =
            vault_onboard_guardians(Arc::clone(&h), T, pubs.iter().map(|p| p.to_vec()).collect())
                .expect("onboard through the FFI");
        assert_eq!(res.epoch, 0, "first onboard writes GENESIS epoch");

        // A bad-length pubkey is rejected.
        let err = vault_onboard_guardians(h, T, vec![vec![0u8; 31]]).unwrap_err();
        assert!(matches!(err, FfiError::Validation { ref kind, .. } if kind == "argument"));
    }

    #[test]
    fn onboard_guardians_rejects_placeholder() {
        let empty = VaultHandle::new_placeholder();
        let err = vault_onboard_guardians(empty, T, vec![vec![0u8; 32]; 3]).unwrap_err();
        assert!(matches!(err, FfiError::Session { .. }));
    }

    #[test]
    fn composition_error_mapping_is_exhaustive() {
        use pangolin_core::composition::CompositionError as CE;
        use pangolin_core::recovery::orchestration::RecoveryOrchestrationError as RErr;
        use pangolin_core::recovery::GuardianSetError;
        use pangolin_core::rotation::RotationError as RotErr;
        use pangolin_crypto::escrow::EscrowError;

        // Exhaustive constructor-side match: adding a CompositionError
        // variant without an arm here is a compile error.
        fn category(e: &CE) -> &'static str {
            match e {
                CE::Store(_) => "Store",
                CE::Rotation(_) => "Rotation",
                CE::Recovery(_) => "Recovery",
                CE::NoRecoveryEscrow => "NoRecoveryEscrow",
            }
        }

        // Store → routed (NotUnlocked → Session).
        let store = CE::Store(pangolin_store::StoreError::NotUnlocked);
        assert_eq!(category(&store), "Store");
        assert!(matches!(
            composition_error_into_ffi(store),
            FfiError::Session { .. }
        ));

        // Store auth → Validation(authentication).
        let store_auth = CE::Store(pangolin_store::StoreError::AuthenticationFailed);
        assert!(matches!(
            composition_error_into_ffi(store_auth),
            FfiError::Validation { kind, .. } if kind == "authentication"
        ));

        // NoRecoveryEscrow → Recovery.
        assert!(matches!(
            composition_error_into_ffi(CE::NoRecoveryEscrow),
            FfiError::Recovery { .. }
        ));

        // Rotation structural → Recovery.
        assert!(matches!(
            composition_error_into_ffi(CE::Rotation(RotErr::NoSurvivors)),
            FfiError::Recovery { .. }
        ));

        // Rotation escrow-open (auth-class) → Validation(authentication).
        let rot_auth = CE::Rotation(RotErr::EscrowRePoint(RErr::Escrow(EscrowError::OpenFailed)));
        assert!(matches!(
            composition_error_into_ffi(rot_auth),
            FfiError::Validation { kind, .. } if kind == "authentication"
        ));

        // Recovery structural → Recovery.
        let rec_struct = CE::Recovery(RErr::InsufficientShares {
            threshold: 2,
            got: 1,
        });
        assert!(matches!(
            composition_error_into_ffi(rec_struct),
            FfiError::Recovery { .. }
        ));

        // Recovery invalid-guardian-set (structural) → Recovery.
        let rec_set = CE::Recovery(RErr::InvalidGuardianSet(
            GuardianSetError::ThresholdOutOfBounds,
        ));
        assert!(matches!(
            composition_error_into_ffi(rec_set),
            FfiError::Recovery { .. }
        ));

        // Recovery escrow-reconstruct (auth-class) → Validation(authentication).
        let rec_auth = CE::Recovery(RErr::Escrow(EscrowError::ReconstructFailed));
        assert!(matches!(
            composition_error_into_ffi(rec_auth),
            FfiError::Validation { kind, .. } if kind == "authentication"
        ));
    }
}
