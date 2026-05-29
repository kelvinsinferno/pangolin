// SPDX-License-Identifier: AGPL-3.0-or-later
//! **MVP-3 issue #106e-2: the thin uniffi layer over the #106e-2 pairing
//! transport codec + SAS derivation + the existing #106c device-add
//! crypto / chain primitives.**
//!
//! Wraps the merged-and-audited pairing primitives so host apps can drive the
//! device-add handshake end-to-end:
//!
//! - [`pairing_begin_new_device`] / [`pairing_local_payload`] —
//!   each side produces its non-secret pairing payload (BYTE + TEXT-STRING
//!   forms) for the host to QR / copy-paste to the peer.
//! - [`pairing_decode_string`] / [`pairing_decode_bytes`] — pure decode
//!   (length / domain / version / checksum-validated; no handle).
//! - [`pairing_derive_sas`] — pure SAS derivation over both decoded
//!   payloads (no handle).
//! - [`vault_add_device`] — existing-device (manager) flow: validate the
//!   new device's payload, broadcast `addDevice` on-chain, seal the VDK,
//!   record the directory entry, return the sealed envelope.
//! - [`pairing_open_and_join`] — new-device flow: open the manager's
//!   sealed envelope, install the recovered VDK + adopt the joining
//!   vault's id, re-wrap under the user's master password.
//!
//! ## L1 — ZERO secret crosses FFI as readable bytes (`106e2-...md`)
//!
//! - The X25519 PAIRING SECRET stays inside `pangolin_store::Vault` — it
//!   is derived inside `device_pairing_pubkey` / `open_paired_vdk_seal`
//!   and dropped at the end of each call. Only the pairing PUBKEY crosses.
//! - The VDK is the OPAQUE secret the new device receives. It crosses
//!   between the engine's `open_paired_vdk_seal` and `install_paired_vdk`
//!   methods by VALUE — NEVER as readable bytes through any FFI binding.
//! - The master password crosses IN behind the opaque
//!   [`SecretPassword`] Object.
//! - The QR payload (pubkeys / ids / signer / nonce), the SAS string,
//!   and the `SealedVdkForDevice` envelope are all NON-secret.
//! - `pangolin-core` / `pangolin-store` / `pangolin-crypto` never gain a
//!   `uniffi` dependency — `grep -ci uniffi` on each stays 0.
//!
//! ## L2 — the SAS gate (the load-bearing anti-MITM property)
//!
//! [`pairing_derive_sas`] is a pure derivation. The HOST UI compares the
//! two displayed codes BEFORE calling [`vault_add_device`]; the engine
//! cannot enforce the eyeball check itself, but the spec is explicit
//! that `vault_add_device` is the "I confirmed, proceed" step. Per §0a
//! Q-d we deliberately do NOT sign the payload — the seal-binding (the
//! VDK is sealed to the recipient `device_id` + pubkey) is the belt-
//! and-suspenders defense the SAS rides on top of.

#![forbid(unsafe_code)]
// Heavily-documented FFI module (the pairing handshake + L1/L2/L4 invariants
// need in-source docs). Doc-style pedantic lints are allowed at module level;
// substantive lints stay enforced.
#![allow(
    clippy::doc_markdown,
    clippy::too_long_first_doc_paragraph,
    clippy::doc_lazy_continuation
)]

use std::sync::Arc;

use pangolin_chain::{
    add_device_v2, bootstrap_vault_v2, build_signed_device_auth, cancel_promotion_v2,
    finalize_promotion_v2, load_deployed_address, propose_promotion_v2, read_authorized_set_v2,
    read_current_manager_v2, read_device_nonce_v2, read_pending_promotion_v2, remove_device_v2,
    Address, DeviceAuthFields, DeviceAuthKind,
};
use pangolin_core::pairing_transport::{
    decode_bytes as decode_payload_bytes, decode_string as decode_payload_string, encode_bytes,
    encode_string, encode_text_with_checksum, PairingPayload, PairingTransportError,
    FRESHNESS_NONCE_LEN, SCHEMA_VERSION as PAIRING_PAYLOAD_SCHEMA_VERSION, SIGNER_LEN,
};
use pangolin_crypto::escrow::X25519_KEY_LEN;
use pangolin_crypto::keys::VAULT_ID_LEN;
use pangolin_crypto::pairing::{derive_sas, SealedVdkForDevice};
use pangolin_crypto::secret::SecretBytes;

#[cfg(test)]
use crate::chain_config::FFI_CHAIN_CONFIG_SCHEMA_VERSION;
use crate::chain_config::{block_on_local, chain_into_ffi, FfiChainConfig};
use crate::error::FfiError;
use crate::session::{SecretPassword, VaultHandle};
#[cfg(test)]
use pangolin_core::pairing_transport::PAYLOAD_LEN;

/// Schema-version slot value for the #106e-2 FFI records (`FfiPairingPayload`
/// + `FfiSealedVdkEnvelope`). Bumped independently from the wire-form
/// payload's [`PAIRING_PAYLOAD_SCHEMA_VERSION`] (=2): the wire form pins
/// the on-the-air byte layout, the FFI record pins the foreign-language
/// Record shape.
pub const PAIRING_FFI_SCHEMA_VERSION: u16 = 1;

/// `RevisionLogV2` event-schema version every #106e-2 `addDevice`
/// passes — mirrors `pangolin_chain::REVISIONLOG_V2_SCHEMA_VERSION`. The
/// contract rejects `> MAX_KNOWN_SCHEMA_VERSION` symmetrically.
const REVISIONLOG_V2_SCHEMA_VERSION: u16 = 1;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Map a [`pangolin_store::StoreError`] through the total
/// `StoreError → pangolin_core::Error → FfiError` mapping (the established
/// session.rs / recovery_ffi.rs discipline).
fn store_into_ffi(err: pangolin_store::StoreError) -> FfiError {
    FfiError::from(pangolin_core::Error::from(err))
}

/// Map a [`pangolin_core::Error`] to [`FfiError`] (the established
/// downstream mapping). Used for the pairing-transport decode errors,
/// which collapse to `Validation { kind: "argument" }`.
fn core_into_ffi(err: pangolin_core::Error) -> FfiError {
    FfiError::from(err)
}

/// Validate a host-supplied `Vec<u8>` is exactly `N` bytes, returning the
/// fixed-size array or [`FfiError::Validation`] (`kind = "argument"`). The
/// shared length-validation helper (mirrors `recovery_ffi::fixed_bytes`).
fn fixed_bytes<const N: usize>(bytes: &[u8], what: &str) -> Result<[u8; N], FfiError> {
    bytes.try_into().map_err(|_| FfiError::Validation {
        kind: "argument".into(),
        message: format!("{what} must be {N} bytes (got {})", bytes.len()),
    })
}

/// Map a pairing-transport decode error to the FFI taxonomy. Every
/// decode failure (length / domain / version / checksum / encoding)
/// surfaces as `Validation { kind: "argument" }` — the same shape the
/// rest of the FFI uses for malformed host bytes (no oracle).
fn transport_into_ffi(err: PairingTransportError) -> FfiError {
    core_into_ffi(pangolin_core::Error::from(err))
}

// ---------------------------------------------------------------------------
// FfiPairingPayload — the non-secret pairing record (Q-carrier)
// ---------------------------------------------------------------------------

/// The non-secret pairing payload + its two transport forms (the byte form
/// the host renders as a QR + the copy-pasteable text form).
///
/// **Every field is non-secret.** Pubkeys / ids / signer / nonce are
/// public context (L1); the FFI carries them by VALUE through a
/// `uniffi::Record`. Round-trips through any FFI binding are
/// byte-identical (the producer always builds the bytes / string via
/// [`pangolin_core::pairing_transport::encode_bytes`] /
/// [`encode_string`]).
///
/// The host transports `bytes` (e.g. by rendering as a QR) AND/OR
/// `string_form` (by copy-paste). The receiving side passes EITHER back
/// to [`pairing_decode_bytes`] / [`pairing_decode_string`] to reconstruct
/// the same [`FfiPairingPayload`].
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiPairingPayload {
    /// Schema-version slot for the FFI Record shape (independent of
    /// `payload_schema_version`).
    pub schema_version: u16,
    /// The payload byte-form (length-strict
    /// [`pangolin_core::pairing_transport::PAYLOAD_LEN`]). Host renders
    /// as a QR.
    pub bytes: Vec<u8>,
    /// The payload text-form (lowercase base32 + 4-byte truncated-SHA-256
    /// checksum). Host copy-pastes it.
    pub string_form: String,
    /// The wire-form schema version this payload was produced under
    /// (currently
    /// [`pangolin_core::pairing_transport::SCHEMA_VERSION`] = 2). The
    /// foreign-language binding can branch on this for migration; an
    /// unknown version is rejected on the next decode.
    pub payload_schema_version: u16,
    /// The 32-byte vault id this payload joins (the existing vault A
    /// the new device is being added to). Surfaced as a non-secret
    /// convenience field — same as the value embedded in `bytes`.
    pub vault_id: Vec<u8>,
    /// The 32-byte stable device id (GAP B). Non-secret.
    pub device_id: Vec<u8>,
    /// The 32-byte X25519 pairing pubkey. Non-secret.
    pub x25519_pairing_pub: Vec<u8>,
    /// The 20-byte secp256k1 EVM signer address. Non-secret (the
    /// on-chain `addDevice` authorizes this exact address).
    pub signer: Vec<u8>,
    /// The 16-byte freshness nonce — generated by the NEW device, then
    /// re-bound into the manager's local payload so both sides' SAS
    /// derives over the SAME nonce (§0a Q-c).
    pub freshness_nonce: Vec<u8>,
}

impl FfiPairingPayload {
    /// Build an [`FfiPairingPayload`] from the engine-native
    /// [`PairingPayload`] (the producer chain for both
    /// [`pairing_begin_new_device`] / [`pairing_local_payload`]).
    fn from_payload(payload: &PairingPayload) -> Self {
        let bytes = encode_bytes(payload);
        let string_form = encode_string(payload);
        Self {
            schema_version: PAIRING_FFI_SCHEMA_VERSION,
            bytes,
            string_form,
            payload_schema_version: u16::from(payload.schema_version),
            vault_id: payload.vault_id.to_vec(),
            device_id: payload.device_id.to_vec(),
            x25519_pairing_pub: payload.x25519_pairing_pub.to_vec(),
            signer: payload.signer.to_vec(),
            freshness_nonce: payload.freshness_nonce.to_vec(),
        }
    }

    /// Validate the [`FfiPairingPayload`]'s per-field byte lengths and
    /// reconstruct the engine-native [`PairingPayload`]. Used by
    /// [`pairing_derive_sas`] + [`vault_add_device`] when the host
    /// passes back a previously-emitted record.
    fn to_payload(&self) -> Result<PairingPayload, FfiError> {
        let vault_id = fixed_bytes::<VAULT_ID_LEN>(&self.vault_id, "FfiPairingPayload.vault_id")?;
        let device_id = fixed_bytes::<32>(&self.device_id, "FfiPairingPayload.device_id")?;
        let x25519_pairing_pub = fixed_bytes::<X25519_KEY_LEN>(
            &self.x25519_pairing_pub,
            "FfiPairingPayload.x25519_pairing_pub",
        )?;
        let signer = fixed_bytes::<SIGNER_LEN>(&self.signer, "FfiPairingPayload.signer")?;
        let freshness_nonce = fixed_bytes::<FRESHNESS_NONCE_LEN>(
            &self.freshness_nonce,
            "FfiPairingPayload.freshness_nonce",
        )?;
        let schema_version =
            u8::try_from(self.payload_schema_version).map_err(|_| FfiError::Validation {
                kind: "argument".into(),
                message: "FfiPairingPayload.payload_schema_version must fit in u8".into(),
            })?;
        Ok(PairingPayload {
            schema_version,
            vault_id,
            device_id,
            x25519_pairing_pub,
            signer,
            freshness_nonce,
        })
    }
}

/// The non-secret sealed-VDK envelope the manager hands back to the new
/// device. NON-secret (the VDK is sealed to the new device's X25519
/// pairing pubkey).
///
/// Carries both a byte form (length-prefixed by transport — actually the
/// raw sealed-box bytes, variable-length) AND a copy-paste-friendly text
/// form (base32 + 4-byte checksum, the same encoding the pairing payload
/// uses for symmetry).
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiSealedVdkEnvelope {
    /// Schema-version slot.
    pub schema_version: u16,
    /// Raw sealed-VDK bytes (the host renders as a QR or moves over a
    /// secure-enough channel — the seal is bound to the new device's
    /// pairing pubkey, so a wire-level interceptor cannot open it). The
    /// inner `crypto_box` sealed box is `ephemeral_pk(32) ‖ ciphertext +
    /// tag(16) ‖ encrypted_plaintext` — variable length.
    pub bytes: Vec<u8>,
    /// Copy-pasteable text form: lowercase base32 of `bytes ‖
    /// sha256(bytes)[..4]`, no padding. Symmetric with the pairing-
    /// payload text form.
    pub string_form: String,
}

fn envelope_build(bytes: Vec<u8>) -> FfiSealedVdkEnvelope {
    // Re-use the pairing-transport's checksummed-text encoder so the
    // host has ONE decoder shape for both artifacts (pairing payload
    // + sealed-VDK envelope) — base32 + 4-byte truncated SHA-256.
    let string_form = encode_text_with_checksum(&bytes);
    FfiSealedVdkEnvelope {
        schema_version: PAIRING_FFI_SCHEMA_VERSION,
        bytes,
        string_form,
    }
}

// ---------------------------------------------------------------------------
// 1. pairing_begin_new_device — NEW device generates its pairing payload
// ---------------------------------------------------------------------------

/// **NEW device, step 1.** Build the new device's pairing payload — its
/// `(device_id, x25519_pairing_pub, signer, vault_id, freshness_nonce)`
/// triple — and return it in both BYTE and TEXT-STRING forms.
///
/// Session-gated (Active — the engine reads the active session's
/// `DeviceKey` to derive the pairing pubkey + the signer; the device key
/// secret never crosses out). The `vault_id` of the new device's
/// freshly-created `.pvf` (its local vault id BEFORE it adopts the
/// joining vault's id in step 3) is carried in the payload.
///
/// **Freshness-nonce continuity discipline (decided by this builder).**
/// Each call generates a FRESH random nonce. The host MUST therefore
/// either (a) cache the [`FfiPairingPayload`] from the FIRST call and
/// re-display the same payload until pairing completes, or (b) re-emit
/// the payload on every retry and force the manager to scan the LATEST
/// one. The SAS-derive step
/// ([`pairing_derive_sas`]) validates that BOTH payloads carry the SAME
/// nonce — a host that re-calls `pairing_begin_new_device` between A's
/// scan and the SAS check will surface a mismatched-nonce error instead
/// of a silent-confusion failure. Option (a) is the recommended flow
/// (the spec-prescribed "hold and re-display the same code until
/// done").
///
/// # Errors
///
/// [`FfiError::Session`] for a placeholder / locked vault.
/// [`FfiError::Validation`] for an internal length mismatch (shouldn't
/// happen — the engine guarantees fixed lengths).
#[allow(clippy::significant_drop_tightening)]
#[uniffi::export]
pub fn pairing_begin_new_device(handle: Arc<VaultHandle>) -> Result<FfiPairingPayload, FfiError> {
    let mut guard = handle.lock_vault();
    let vault = guard.as_mut()?;
    // Active-session gate (the device key derivation requires `Active`).
    if vault.state() != pangolin_store::VaultState::Active {
        return Err(FfiError::Session {
            message: "vault is not unlocked".to_owned(),
        });
    }

    // Pull the engine-side fields. Each call routes through the
    // session-gated `Vault` accessor; the secret material stays inside.
    let device_id_arr: [u8; 32] = vault.device_pairing_device_id().map_err(store_into_ffi)?;
    let x25519_pairing_pub_arr: [u8; X25519_KEY_LEN] =
        vault.device_pairing_pubkey().map_err(store_into_ffi)?;
    let vault_id_arr: [u8; VAULT_ID_LEN] = vault.vault_id();
    // Signer = the active session's EVM wallet address (derived from the
    // same `DeviceKey`). Read engine-side — never crosses as a secret.
    let signer_addr = vault.evm_wallet().map_err(store_into_ffi)?.address();
    let signer_arr: [u8; SIGNER_LEN] = signer_addr.into_array();

    // Fresh CSPRNG nonce — the new device originates it (§0a Q-c). Use
    // the engine's `pangolin_crypto::rng::fill_random` shim (the
    // chokepoint for every secret-adjacent randomness in
    // pangolin-crypto).
    let mut freshness_nonce_arr = [0u8; FRESHNESS_NONCE_LEN];
    pangolin_crypto::rng::fill_random(&mut freshness_nonce_arr);

    let payload = PairingPayload {
        schema_version: PAIRING_PAYLOAD_SCHEMA_VERSION,
        vault_id: vault_id_arr,
        device_id: device_id_arr,
        x25519_pairing_pub: x25519_pairing_pub_arr,
        signer: signer_arr,
        freshness_nonce: freshness_nonce_arr,
    };
    Ok(FfiPairingPayload::from_payload(&payload))
}

// ---------------------------------------------------------------------------
// 2. pairing_local_payload — MANAGER (existing-device) builds its payload
// ---------------------------------------------------------------------------

/// **MANAGER (existing-device), step 2.** Build the manager's pairing
/// payload re-bound to the NEW device's freshness nonce — so both sides'
/// SAS derives over the SAME nonce (§0a Q-c reconciliation).
///
/// Session-gated (Active). `their_freshness_nonce` MUST be exactly 16
/// bytes — the SAME nonce carried in the new device's
/// [`FfiPairingPayload`]. The manager's payload carries A's
/// `(device_id, signer, x25519_pairing_pub, vault_id)` + B's nonce; the
/// SAS over `(A_pub, B_pub, nonce)` then matches on both screens.
///
/// **Why the nonce binding goes to the manager's payload.** A SAS over
/// two pubkeys + a single nonce is symmetric only if both sides agree
/// on which nonce to use. Per §0a Q-c the new device originates the
/// nonce; the manager re-emits the nonce in its own payload so the host
/// has BOTH payloads on each device, and both `derive_sas` calls
/// consume the SAME nonce. A mismatched nonce on the SAS-derive step
/// surfaces as `FfiError::Validation { kind: "argument" }` (engine-side
/// fail-closed).
///
/// # Errors
///
/// [`FfiError::Session`] for a placeholder / locked vault.
/// [`FfiError::Validation`] for a non-16-byte nonce.
#[allow(clippy::significant_drop_tightening, clippy::needless_pass_by_value)]
#[uniffi::export]
pub fn pairing_local_payload(
    handle: Arc<VaultHandle>,
    their_freshness_nonce: Vec<u8>,
) -> Result<FfiPairingPayload, FfiError> {
    let freshness_nonce_arr: [u8; FRESHNESS_NONCE_LEN] =
        fixed_bytes(&their_freshness_nonce, "freshness_nonce")?;

    let mut guard = handle.lock_vault();
    let vault = guard.as_mut()?;
    if vault.state() != pangolin_store::VaultState::Active {
        return Err(FfiError::Session {
            message: "vault is not unlocked".to_owned(),
        });
    }
    let device_id_arr: [u8; 32] = vault.device_pairing_device_id().map_err(store_into_ffi)?;
    let x25519_pairing_pub_arr: [u8; X25519_KEY_LEN] =
        vault.device_pairing_pubkey().map_err(store_into_ffi)?;
    let vault_id_arr: [u8; VAULT_ID_LEN] = vault.vault_id();
    let signer_addr = vault.evm_wallet().map_err(store_into_ffi)?.address();
    let signer_arr: [u8; SIGNER_LEN] = signer_addr.into_array();

    let payload = PairingPayload {
        schema_version: PAIRING_PAYLOAD_SCHEMA_VERSION,
        vault_id: vault_id_arr,
        device_id: device_id_arr,
        x25519_pairing_pub: x25519_pairing_pub_arr,
        signer: signer_arr,
        freshness_nonce: freshness_nonce_arr,
    };
    Ok(FfiPairingPayload::from_payload(&payload))
}

// ---------------------------------------------------------------------------
// 3. pairing_decode_{bytes,string} — pure decoders (no handle)
// ---------------------------------------------------------------------------

/// **Pure decode** (no handle). Decode a BYTE-form pairing payload into
/// an [`FfiPairingPayload`]. Length-strict + domain-checked + version-
/// gated.
///
/// # Errors
///
/// [`FfiError::Validation`] (`kind = "argument"`) for any decode failure
/// — `WrongLength` / `DomainMismatch` / `UnsupportedVersion`.
#[uniffi::export]
pub fn pairing_decode_bytes(bytes: Vec<u8>) -> Result<FfiPairingPayload, FfiError> {
    let payload = decode_payload_bytes(&bytes).map_err(transport_into_ffi)?;
    Ok(FfiPairingPayload::from_payload(&payload))
}

/// **Pure decode** (no handle). Decode the TEXT-form (base32 +
/// truncated-SHA-256 checksum) pairing payload into an
/// [`FfiPairingPayload`]. The host normalizes / strips whitespace
/// BEFORE calling.
///
/// # Errors
///
/// [`FfiError::Validation`] (`kind = "argument"`) for any decode failure
/// — `InvalidEncoding` / `WrongLength` / `ChecksumMismatch` /
/// `DomainMismatch` / `UnsupportedVersion`.
#[uniffi::export]
pub fn pairing_decode_string(s: String) -> Result<FfiPairingPayload, FfiError> {
    let payload = decode_payload_string(&s).map_err(transport_into_ffi)?;
    Ok(FfiPairingPayload::from_payload(&payload))
}

// ---------------------------------------------------------------------------
// 4. pairing_derive_sas — pure SAS derivation (no handle)
// ---------------------------------------------------------------------------

/// **Pure SAS derivation** (no handle). Derive the 6-digit decimal SAS
/// over `(payload_a.x25519_pairing_pub, payload_b.x25519_pairing_pub,
/// payload_a.freshness_nonce)`. Both payloads MUST carry the SAME
/// freshness nonce (the manager's payload is built with B's nonce, see
/// [`pairing_local_payload`]).
///
/// **L3 (canonical-symmetric).** The hash sorts the two pubkeys
/// lexicographically before hashing — both devices' invocations yield
/// the IDENTICAL code regardless of which payload is `a` / `b`.
///
/// **L2 (LOAD-BEARING).** A MITM that substituted one of the pubkeys
/// produces a DIFFERENT code; the human comparison surfaces it.
///
/// # Errors
///
/// [`FfiError::Validation`] (`kind = "argument"`) for malformed
/// payloads (bad byte lengths or version) OR for a mismatched
/// `freshness_nonce` across the two payloads (the SAS over different
/// nonces would compare apples to oranges — fail closed instead).
#[uniffi::export]
pub fn pairing_derive_sas(
    payload_a: FfiPairingPayload,
    payload_b: FfiPairingPayload,
) -> Result<String, FfiError> {
    let a = payload_a.to_payload()?;
    let b = payload_b.to_payload()?;
    if a.freshness_nonce != b.freshness_nonce {
        return Err(FfiError::Validation {
            kind: "argument".into(),
            message: "pairing_derive_sas: both payloads must carry the same freshness_nonce \
                 (the manager binds the new device's nonce into its own payload)"
                .into(),
        });
    }
    let sas = derive_sas(
        &a.x25519_pairing_pub,
        &b.x25519_pairing_pub,
        &a.freshness_nonce,
    );
    Ok(sas.as_str().to_owned())
}

// ---------------------------------------------------------------------------
// 4a. vault_bootstrap_chain — FIRST chain mutation (genesis of the SET)
// ---------------------------------------------------------------------------

/// **The FIRST chain-mutating call for a new vault.** Establishes the
/// authorized-device set on-chain so the calling device is the FIRST
/// authorized signer + the manager. The V2 contract REQUIRES this before
/// any [`vault_add_device`] / publishRevision call: a publish or
/// `addDevice` against an unbootstrapped vault REVERTS with
/// `VaultNotBootstrapped` (RevisionLogV2.sol Q-f — "a publish cannot
/// race an unestablished SET"). Repeated calls REVERT with
/// `VaultAlreadyBootstrapped` (one-shot flag, Q-f).
///
/// Host wiring: call EXACTLY ONCE per `.pvf`, AFTER `vault_unlock` and
/// BEFORE the first `vault_add_device` / publish. Idempotent at the
/// chain layer (the contract revert is the source of truth); the FFI
/// does not cache a "bootstrapped" flag.
///
/// L1 — ZERO secret material crosses. The gas-paying signer is sourced
/// engine-side from the unlocked vault (`Vault::evm_wallet`, identical
/// to [`vault_add_device`]); the master password is consumed + zeroized
/// for surface symmetry with the rest of the chain-mutating bindings
/// (the bootstrap tx itself doesn't need it — the EVM signer is the
/// existing live key).
///
/// L4 — vault MUST be Active (the EVM signer + the live vault_id are
/// only valid in an unlocked session).
///
/// L7 — testnet-only / D-011. Production builds hardcode
/// `ChainEnv::BaseSepolia` (see [`crate::chain_config::ffi_chain_env_and_id`]);
/// the dev/anvil path is `integration-tests`-gated and never reaches
/// shipped binaries.
///
/// # Errors
///
/// - [`FfiError::Session`] — the vault is Placeholder or Locked.
/// - [`FfiError::Chain`] — ANY chain-side failure: RPC, deployment-file
///   load, EIP-712 sign, broadcast, or `bootstrapVault` revert
///   (e.g. `VaultAlreadyBootstrapped` on a second call).
/// - [`FfiError::Store`] — engine-side wallet/signing internal failure.
#[allow(clippy::significant_drop_tightening, clippy::needless_pass_by_value)]
#[uniffi::export]
pub fn vault_bootstrap_chain(
    handle: Arc<VaultHandle>,
    master_password: Arc<SecretPassword>,
    config: FfiChainConfig,
) -> Result<(), FfiError> {
    // Bridge + zeroize the password (consumed for forward-compat parity
    // with `vault_add_device`; the bootstrap tx itself does not use it).
    let mut pw = zeroize::Zeroizing::new(master_password.bytes_for_bridge().to_vec());
    let secret = SecretBytes::new(std::mem::take(&mut *pw));

    // L4 session gate BEFORE any chain primitive.
    let mut guard = handle.lock_vault();
    let vault = guard.as_mut()?;
    if vault.state() != pangolin_store::VaultState::Active {
        return Err(FfiError::Session {
            message: "vault is not unlocked".to_owned(),
        });
    }
    let active_vault_id = vault.vault_id();
    let wallet_view = vault.evm_wallet().map_err(store_into_ffi)?;
    let signer_addr: Address = wallet_view.address();
    let signer = wallet_view.signer().clone();

    block_on_local(async {
        let (env, chain_id) = crate::chain_config::ffi_chain_env_and_id(&config.rpc_url)
            .await
            .map_err(chain_into_ffi)?;
        let contract = load_deployed_address(env, "RevisionLogV2").map_err(chain_into_ffi)?;
        // Genesis AddDevice @ nonce 0 — the V2 contract's bootstrap
        // shape (mirrors `bootstrap_vault_v2`'s sig requirements).
        let fields = DeviceAuthFields {
            kind: DeviceAuthKind::AddDevice,
            vault_id: active_vault_id,
            subject: signer_addr,
            nonce: 0,
            schema_version: REVISIONLOG_V2_SCHEMA_VERSION,
        };
        let signed_auth = build_signed_device_auth(&signer, fields, contract, chain_id)
            .map_err(chain_into_ffi)?;
        let wallet = pangolin_chain::EvmWallet::from_signer(signer.clone());
        bootstrap_vault_v2(&wallet, signer_addr, &signed_auth, env, &config.rpc_url)
            .await
            .map_err(chain_into_ffi)?;
        Ok::<(), FfiError>(())
    })??;

    drop(secret);
    Ok(())
}

// ---------------------------------------------------------------------------
// 5. vault_add_device — MANAGER role (the THIS-IS-THE-CONFIRMATION step)
// ---------------------------------------------------------------------------

/// **MANAGER, step 5 (the FINAL CONFIRMATION).** After the host has
/// surfaced the SAS to the human and the human has confirmed both
/// codes match, the manager calls this to:
///
/// 1. **Validate** the new device's payload — schema-version, vault_id
///    must equal the active vault's, fixed-length fields.
/// 2. **Read** the live on-chain `deviceNonce(vault_id)` (`async`,
///    driven through [`block_on_local`]; fail-closed on chain error).
/// 3. **Sign** the EIP-712 v2 `AddDevice` authorization with the
///    active session's EVM signer (`build_signed_device_auth`, signer
///    never crosses FFI).
/// 4. **Broadcast** `addDevice(vaultId, newSigner, nonce, schemaVersion,
///    sig)` (`add_device_v2`); await receipt.
/// 5. **Seal** the live VDK to the new device's X25519 pairing pubkey
///    (`Vault::seal_vdk_for_new_device` — STORE-side; the VDK never
///    leaves the engine).
/// 6. **Persist** the new device's directory entry (GAP A) so a future
///    rotation can resolve it as a known survivor.
/// 7. **Return** the sealed VDK envelope in both BYTE + TEXT forms for
///    the host to carry back to the new device.
///
/// Session-gated (Active — needs the live VDK + the EVM signer + the
/// directory write). The master password crosses IN behind the opaque
/// [`SecretPassword`] Object — currently UNUSED on this side (the
/// manager's signer is held in `Vault::active.evm_wallet` and the seal
/// uses `Vault::active.vdk`); accepted as a parameter for forward-
/// compatibility with a future re-confirmation-prompt flow. Nothing
/// secret crosses OUT.
///
/// **NOTE on the SAS gate (Q-a).** The engine cannot enforce the eyeball
/// comparison itself — that lives in the host UI. By the time
/// `vault_add_device` is called the human HAS confirmed; the FFI surface
/// treats this binding as the "I confirmed, proceed" step. The
/// seal-binding (the VDK is locked to the recipient `device_id`+pubkey)
/// is the belt-and-suspenders defense underneath.
///
/// # Errors
///
/// - [`FfiError::Session`] for a placeholder / locked vault (the L4 gate
///   BEFORE any chain primitive).
/// - [`FfiError::Validation`] (`kind = "argument"`) for a payload whose
///   `vault_id` does NOT match the active vault (cross-vault replay).
/// - [`FfiError::Chain`] for ANY chain-side failure (deployment-file
///   load, RPC, nonce-read, `addDevice` revert / receipt).
/// - [`FfiError::Store`] for a DB / signing-internal failure.
#[allow(clippy::significant_drop_tightening, clippy::needless_pass_by_value)]
#[uniffi::export]
pub fn vault_add_device(
    handle: Arc<VaultHandle>,
    master_password: Arc<SecretPassword>,
    config: FfiChainConfig,
    new_device_payload: FfiPairingPayload,
) -> Result<FfiSealedVdkEnvelope, FfiError> {
    // Bridge the password engine-side (unused for #106e-2 — see binding
    // doc — but consumed + zeroized for forward compatibility).
    let mut pw = zeroize::Zeroizing::new(master_password.bytes_for_bridge().to_vec());
    let secret = SecretBytes::new(std::mem::take(&mut *pw));

    // Decode the FFI payload into the engine-native shape + validate.
    let payload = new_device_payload.to_payload()?;
    if payload.schema_version != PAIRING_PAYLOAD_SCHEMA_VERSION {
        return Err(FfiError::Validation {
            kind: "argument".into(),
            message: format!(
                "unsupported pairing payload schema version {} (expected {PAIRING_PAYLOAD_SCHEMA_VERSION})",
                payload.schema_version
            ),
        });
    }

    // L4 session gate BEFORE any chain primitive.
    let mut guard = handle.lock_vault();
    let vault = guard.as_mut()?;
    if vault.state() != pangolin_store::VaultState::Active {
        return Err(FfiError::Session {
            message: "vault is not unlocked".to_owned(),
        });
    }
    // The new device's payload carries its OWN local vault_id (per
    // `pairing_begin_new_device`'s documented design — B adopts the
    // joining vault's id later in step 3 via `pairing_open_and_join` →
    // `Vault::install_paired_vdk`'s atomic re-key). The cryptographic
    // anti-attacker defense is the SAS comparison (mismatched code if a
    // MITM substituted a pubkey) plus the seal binding (the VDK seal is
    // bound to A's vault_id + B's device_id + B's pairing pubkey
    // engine-side below — an attacker who substituted their pubkey
    // would still be caught by the SAS). No vault_id comparison here:
    // user-error UX safety ("am I adding B to the right vault?") is the
    // host's job (e.g. a confirmation dialog before this call).
    let active_vault_id = vault.vault_id();

    // Pull the manager's signer out of the active session — never
    // crosses FFI (mirrors `vault_lock_with_drain` / `vault_pull_once`).
    let signer = vault.evm_wallet().map_err(store_into_ffi)?.signer().clone();

    // Drive the chain ops on a local current-thread runtime (the
    // `!Send` futures rule — same as the rotation_ffi / sync_status
    // bindings). `(env, chain_id)` are resolved via
    // [`crate::chain_config::ffi_chain_env_and_id`]: production builds
    // hardcode `BaseSepolia` + its pinned chain_id (testnet-only /
    // D-011, never crossed FFI); the `integration-tests` feature
    // (compiled OUT of shipped builds) opts into the `test_env` seam so
    // anvil-driven FFI E2Es can target `ChainEnv::Dev`.
    let new_signer_addr: Address = Address::from(payload.signer);
    // Note: `config.deployment_path` is unused on this binding (chain_id
    // + contract address resolve via the env path, NOT a host-supplied
    // file); it is accepted in the Record for forward-compatibility with
    // the other chain bindings (`vault_lock_with_drain` etc.) so the
    // host surface stays uniform.
    block_on_local(async {
        let (env, chain_id) = crate::chain_config::ffi_chain_env_and_id(&config.rpc_url)
            .await
            .map_err(chain_into_ffi)?;
        let contract = load_deployed_address(env, "RevisionLogV2").map_err(chain_into_ffi)?;
        let nonce = read_device_nonce_v2(env, &config.rpc_url, active_vault_id)
            .await
            .map_err(chain_into_ffi)?;
        let fields = DeviceAuthFields {
            kind: DeviceAuthKind::AddDevice,
            vault_id: active_vault_id,
            subject: new_signer_addr,
            nonce,
            schema_version: REVISIONLOG_V2_SCHEMA_VERSION,
        };
        let signed_auth = build_signed_device_auth(&signer, fields, contract, chain_id)
            .map_err(chain_into_ffi)?;
        // `EvmWallet` reconstructor: re-use the cloned signer so the
        // broadcast is signed under the same key the EIP-712 was. The
        // engine's `add_device_v2` wraps a `(&EvmWallet, ...)` — we
        // make a transient `EvmWallet` for the call only.
        let wallet = pangolin_chain::EvmWallet::from_signer(signer.clone());
        add_device_v2(&wallet, new_signer_addr, &signed_auth, env, &config.rpc_url)
            .await
            .map_err(chain_into_ffi)?;
        Ok::<(), FfiError>(())
    })??;

    // Seal the live VDK to the new device (store-side — VDK never
    // crosses out).
    let current_epoch = 0u64; // Clean device-add at the current vault epoch.
    let sealed: SealedVdkForDevice = vault
        .seal_vdk_for_new_device(
            &payload.x25519_pairing_pub,
            &payload.device_id,
            &active_vault_id,
            current_epoch,
        )
        .map_err(store_into_ffi)?;

    // Persist the directory entry (GAP A) so a future rotation can
    // resolve B as a known survivor.
    vault
        .record_device_directory_entry(
            payload.signer,
            payload.device_id,
            payload.x25519_pairing_pub,
        )
        .map_err(store_into_ffi)?;

    // Drop the (unused-but-consumed) password BEFORE returning the
    // (non-secret) envelope.
    drop(secret);
    Ok(envelope_build(sealed.as_bytes().to_vec()))
}

// ---------------------------------------------------------------------------
// 6. pairing_open_and_join — NEW device, step 6 (the FINAL step)
// ---------------------------------------------------------------------------

/// **NEW device, FINAL step.** Open the manager's sealed VDK envelope,
/// install the recovered VDK as this device's at-rest wrap under the
/// user-supplied master password, and adopt the joining vault's id.
///
/// The vault MUST be Active when this is called (the engine reads the
/// active session's `DeviceKey` to derive the X25519 pairing SECRET
/// store-internal — the secret never crosses out). After the install
/// step the vault is left Locked; the host calls
/// `vault_unlock(master_password)` to start a fresh session under the
/// newly-installed wrap.
///
/// Inputs (all length-validated):
/// - `sealed_vdk_bytes` — the raw sealed-VDK bytes from
///   [`FfiSealedVdkEnvelope::bytes`].
/// - `vault_id` — the EXISTING vault's 32-byte id (carried in the
///   pairing payload). The new device's `.pvf` adopts this as its
///   `meta.vault_id` so both `.pvf`s name the same logical vault.
/// - `epoch` — the vault's current epoch on a clean add (typically 0).
/// - `master_password` — the master password the user just chose for
///   this device. The recovered VDK is re-wrapped under it.
///
/// # Errors
///
/// - [`FfiError::Session`] for a placeholder / locked vault.
/// - [`FfiError::Validation`] (`kind = "argument"`) for a bad-length
///   input.
/// - [`FfiError::Validation`] (`kind = "authentication"`) if the
///   seal-open fails (wrong device / tampered ciphertext / context
///   mismatch — collapsed; no oracle on the cause).
/// - [`FfiError::Store`] on a DB / install failure.
#[allow(clippy::significant_drop_tightening, clippy::needless_pass_by_value)]
#[uniffi::export]
pub fn pairing_open_and_join(
    handle: Arc<VaultHandle>,
    sealed_vdk_bytes: Vec<u8>,
    vault_id: Vec<u8>,
    epoch: u64,
    master_password: Arc<SecretPassword>,
) -> Result<(), FfiError> {
    // Validate length of the vault_id; the sealed_vdk_bytes are
    // VARIABLE-length (the sealed-box wire form), so length-strict
    // checking is impossible — `SealedVdkForDevice::from_bytes` is a
    // wrapper that accepts any byte buffer + the open path performs the
    // authentication itself.
    let vault_id_arr: [u8; VAULT_ID_LEN] = fixed_bytes(&vault_id, "vault_id")?;
    // Reject an empty sealed-VDK buffer up-front (a sealed-box has a
    // minimum length of 48 bytes — ephemeral pubkey + Poly1305 tag; an
    // empty buffer is structurally invalid and would trigger an
    // undifferentiated open failure further down).
    if sealed_vdk_bytes.is_empty() {
        return Err(FfiError::Validation {
            kind: "argument".into(),
            message: "sealed_vdk_bytes must be non-empty".into(),
        });
    }
    let sealed = SealedVdkForDevice::from_bytes(sealed_vdk_bytes);

    // Bridge the password engine-side.
    let mut pw = zeroize::Zeroizing::new(master_password.bytes_for_bridge().to_vec());
    let secret = SecretBytes::new(std::mem::take(&mut *pw));

    let mut guard = handle.lock_vault();
    let vault = guard.as_mut()?;
    if vault.state() != pangolin_store::VaultState::Active {
        return Err(FfiError::Session {
            message: "vault is not unlocked".to_owned(),
        });
    }

    // Open the seal engine-side. The recovered VDK is held in a `VdkKey`
    // by value — it NEVER crosses the FFI as readable bytes.
    let recovered_vdk = vault
        .open_paired_vdk_seal(&sealed, &vault_id_arr, epoch)
        .map_err(store_into_ffi)?;

    // Install the recovered VDK as the new device's at-rest wrap under
    // `secret`, ADOPTING the joining vault's id. Leaves the vault
    // Locked on success; the host calls `vault_unlock` next.
    vault
        .install_paired_vdk(recovered_vdk, vault_id_arr, &secret)
        .map_err(store_into_ffi)?;
    drop(secret);
    Ok(())
}

// ---------------------------------------------------------------------------
// MVP-4-J: device removal + the authorized-set / manager reads
// ---------------------------------------------------------------------------

/// One device in the vault's LIVE on-chain authorized set (MVP-4-J).
///
/// Every field is non-secret: the 20-byte signer is the on-chain set key,
/// and the role markers are derived from public chain reads. `device_id`
/// is filled from the local survivor directory when known (peers added on
/// THIS device), else empty — peer device LABELS live in each peer's own
/// `.pvf` and are not available cross-device.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiAuthorizedDevice {
    /// Schema-version slot.
    pub schema_version: u16,
    /// 20-byte secp256k1 EVM signer (the on-chain authorized-set key + the
    /// value `vault_remove_device` takes).
    pub signer: Vec<u8>,
    /// `true` iff this signer is THIS device's own signer.
    pub is_current: bool,
    /// `true` iff this signer is the vault's current manager (the only
    /// device allowed to remove others).
    pub is_manager: bool,
    /// 32-byte stable device id if known from the local directory, else
    /// empty.
    pub device_id: Vec<u8>,
}

/// **MVP-4-J.** List the vault's LIVE on-chain authorized devices, joined
/// with the local survivor directory for any known device ids + role
/// markers (`is_current`, `is_manager`). The host renders this as the
/// removable-device list (vs the LOCAL-only `device_list`, which cannot
/// enumerate peers).
///
/// Reads the live set + manager FAIL-CLOSED (L3): a chain-read error
/// aborts; the host never sees a stale/guessed set.
///
/// # Errors
///
/// [`FfiError::Session`] for a locked vault; [`FfiError::Chain`] on a
/// chain-read failure.
#[allow(clippy::significant_drop_tightening)]
#[uniffi::export]
pub fn vault_list_authorized_devices(
    handle: Arc<VaultHandle>,
    config: FfiChainConfig,
) -> Result<Vec<FfiAuthorizedDevice>, FfiError> {
    let mut guard = handle.lock_vault();
    let vault = guard.as_mut()?;
    if vault.state() != pangolin_store::VaultState::Active {
        return Err(FfiError::Session {
            message: "vault is not unlocked".to_owned(),
        });
    }
    let vault_id = vault.vault_id();
    let my_addr: [u8; 20] = vault
        .evm_wallet()
        .map_err(store_into_ffi)?
        .address()
        .into_array();
    let directory = vault.device_directory().map_err(store_into_ffi)?;

    let (set, manager) = block_on_local(async {
        let (env, _chain_id) = crate::chain_config::ffi_chain_env_and_id(&config.rpc_url)
            .await
            .map_err(chain_into_ffi)?;
        let set = read_authorized_set_v2(env, &config.rpc_url, vault_id, 0)
            .await
            .map_err(chain_into_ffi)?;
        let manager = read_current_manager_v2(env, &config.rpc_url, vault_id)
            .await
            .map_err(chain_into_ffi)?;
        Ok::<_, FfiError>((set, manager))
    })??;

    let manager_arr: [u8; 20] = manager.into_array();
    let out = set
        .into_iter()
        .map(|addr| {
            let arr: [u8; 20] = addr.into_array();
            let device_id = directory
                .iter()
                .find(|d| d.signer == arr)
                .map(|d| d.device_id.to_vec())
                .unwrap_or_default();
            FfiAuthorizedDevice {
                schema_version: PAIRING_FFI_SCHEMA_VERSION,
                signer: arr.to_vec(),
                is_current: arr == my_addr,
                is_manager: arr == manager_arr,
                device_id,
            }
        })
        .collect();
    Ok(out)
}

/// **MVP-4-J. MANAGER-ONLY.** Remove a device from the vault: sign an
/// EIP-712 `RemoveDevice` authorization engine-side, broadcast the
/// on-chain `removeDevice`, then queue the local rotation-pending row so
/// the host can drive the mandatory VDK rotation
/// ([`vault_complete_rotation`]) that closes the forward-secrecy gap.
///
/// Mirrors [`vault_add_device`]'s spine (L4 gate → engine signer →
/// `block_on_local` → `read_device_nonce_v2` → `build_signed_device_auth`
/// → broadcast) but with `DeviceAuthKind::RemoveDevice`, no VDK seal, and
/// no directory write. Takes NO master password — the removal broadcast is
/// signed by the active session's signer; the password is needed only for
/// the SEPARATE [`vault_complete_rotation`] step the host calls next.
///
/// The signer of the authorization MUST be the current manager or the
/// contract reverts (`ErrNotDeviceManager`); the manager cannot remove
/// itself or the last device (`ErrWouldBrickVault`). The host pre-checks
/// these via [`vault_list_authorized_devices`] (whose rows carry the
/// `is_manager` / `is_current` markers) to fail fast, but the contract is
/// the source of truth.
///
/// # Errors
///
/// [`FfiError::Validation`] for a malformed `signer_to_remove`;
/// [`FfiError::Session`] for a locked vault; [`FfiError::Chain`] for an
/// RPC/tx failure (incl. `ErrNotDeviceManager` / `ErrWouldBrickVault` /
/// `ErrBadNonce`); [`FfiError::Store`] if the rotation-pending queue write
/// fails.
#[allow(clippy::significant_drop_tightening)]
#[uniffi::export]
pub fn vault_remove_device(
    handle: Arc<VaultHandle>,
    config: FfiChainConfig,
    signer_to_remove: Vec<u8>,
) -> Result<(), FfiError> {
    let remove_arr = fixed_bytes::<20>(&signer_to_remove, "signer_to_remove")?;

    let mut guard = handle.lock_vault();
    let vault = guard.as_mut()?;
    if vault.state() != pangolin_store::VaultState::Active {
        return Err(FfiError::Session {
            message: "vault is not unlocked".to_owned(),
        });
    }
    let active_vault_id = vault.vault_id();
    let signer = vault.evm_wallet().map_err(store_into_ffi)?.signer().clone();
    let observed_epoch = vault.current_vdk_epoch().map_err(store_into_ffi)?;
    let remove_addr: Address = Address::from(remove_arr);

    // Broadcast removeDevice, then read the POST-removal authorized set so
    // the rotation-pending trigger sees the removed signer is gone.
    let new_set: Vec<[u8; 20]> = block_on_local(async {
        let (env, chain_id) = crate::chain_config::ffi_chain_env_and_id(&config.rpc_url)
            .await
            .map_err(chain_into_ffi)?;
        let contract = load_deployed_address(env, "RevisionLogV2").map_err(chain_into_ffi)?;
        let nonce = read_device_nonce_v2(env, &config.rpc_url, active_vault_id)
            .await
            .map_err(chain_into_ffi)?;
        let fields = DeviceAuthFields {
            kind: DeviceAuthKind::RemoveDevice,
            vault_id: active_vault_id,
            subject: remove_addr,
            nonce,
            schema_version: REVISIONLOG_V2_SCHEMA_VERSION,
        };
        let signed_auth = build_signed_device_auth(&signer, fields, contract, chain_id)
            .map_err(chain_into_ffi)?;
        let wallet = pangolin_chain::EvmWallet::from_signer(signer.clone());
        remove_device_v2(&wallet, remove_addr, &signed_auth, env, &config.rpc_url)
            .await
            .map_err(chain_into_ffi)?;
        let set = read_authorized_set_v2(env, &config.rpc_url, active_vault_id, 0)
            .await
            .map_err(chain_into_ffi)?;
        Ok::<Vec<[u8; 20]>, FfiError>(set.into_iter().map(Address::into_array).collect())
    })??;

    // Queue the rotation-pending row (the gap MVP-4-J closes — nothing
    // else writes it). The removed signer is now absent from `new_set`, so
    // the trigger persists exactly one pending row for it. NEVER auto-
    // rotates (L3) — the host drives `vault_complete_rotation` next.
    vault
        .process_device_removed_trigger(&new_set, &[remove_arr], observed_epoch)
        .map_err(store_into_ffi)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// MVP-4-K: manager handoff / promotion (candidate-initiated, 48h, vetoable)
// ---------------------------------------------------------------------------

/// An in-flight manager promotion (MVP-4-K). All non-secret.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiPendingPromotion {
    /// Schema-version slot.
    pub schema_version: u16,
    /// 20-byte EVM signer of the candidate being promoted to manager.
    pub candidate: Vec<u8>,
    /// Unix-second timestamp the 48h delay elapses (when finalize becomes
    /// valid).
    pub ready_at: u64,
}

/// **MVP-4-K. CANDIDATE-INITIATED.** Propose THIS device as the vault's next
/// manager: self-sign a `Promote` authorization (the contract requires the
/// signature to recover to the candidate — the manager CANNOT do this) and
/// broadcast `proposePromotion`, starting the 48h delay. Returns the pending
/// promotion (candidate + `ready_at`) read back from chain.
///
/// Mirrors [`vault_remove_device`]'s spine but: `kind = Promote`, `subject =
/// THIS device's own signer` (self-proposal), broadcast `propose_promotion_v2`,
/// and NO store follow-up (promotion changes no key material — it is a pure
/// on-chain authority-pointer change; the candidate already holds its VDK).
/// Takes no master password (the session signer suffices).
///
/// # Errors
///
/// [`FfiError::Session`] for a locked vault; [`FfiError::Chain`] for an
/// RPC/tx failure (incl. `ErrPromotionPending` / `ErrNotSetMember` /
/// `ErrBadNonce`); [`FfiError::Internal`] if the broadcast did not register
/// a pending promotion (should not happen).
#[allow(clippy::significant_drop_tightening)]
#[uniffi::export]
pub fn vault_propose_promotion(
    handle: Arc<VaultHandle>,
    config: FfiChainConfig,
) -> Result<FfiPendingPromotion, FfiError> {
    let mut guard = handle.lock_vault();
    let vault = guard.as_mut()?;
    if vault.state() != pangolin_store::VaultState::Active {
        return Err(FfiError::Session {
            message: "vault is not unlocked".to_owned(),
        });
    }
    let vault_id = vault.vault_id();
    let wallet_obj = vault.evm_wallet().map_err(store_into_ffi)?;
    let signer = wallet_obj.signer().clone();
    let self_addr: Address = wallet_obj.address();

    let pending = block_on_local(async {
        let (env, chain_id) = crate::chain_config::ffi_chain_env_and_id(&config.rpc_url)
            .await
            .map_err(chain_into_ffi)?;
        let contract = load_deployed_address(env, "RevisionLogV2").map_err(chain_into_ffi)?;
        let nonce = read_device_nonce_v2(env, &config.rpc_url, vault_id)
            .await
            .map_err(chain_into_ffi)?;
        let fields = DeviceAuthFields {
            kind: DeviceAuthKind::Promote,
            vault_id,
            subject: self_addr,
            nonce,
            schema_version: REVISIONLOG_V2_SCHEMA_VERSION,
        };
        let signed_auth = build_signed_device_auth(&signer, fields, contract, chain_id)
            .map_err(chain_into_ffi)?;
        let wallet = pangolin_chain::EvmWallet::from_signer(signer.clone());
        propose_promotion_v2(&wallet, self_addr, &signed_auth, env, &config.rpc_url)
            .await
            .map_err(chain_into_ffi)?;
        read_pending_promotion_v2(env, &config.rpc_url, vault_id)
            .await
            .map_err(chain_into_ffi)
    })??;

    match pending {
        Some((candidate, ready_at)) => Ok(FfiPendingPromotion {
            schema_version: PAIRING_FFI_SCHEMA_VERSION,
            candidate: candidate.into_array().to_vec(),
            ready_at,
        }),
        None => Err(FfiError::Internal {
            message: "proposePromotion broadcast did not register a pending promotion".to_owned(),
        }),
    }
}

/// **MVP-4-K. PERMISSIONLESS.** Finalize a pending manager promotion after
/// its 48h delay has elapsed — rotates the on-chain manager pointer to the
/// candidate. Any device may submit it (the candidate, the old manager, or a
/// relayer). The tx is sent from THIS device's session wallet (gas).
///
/// # Errors
///
/// [`FfiError::Session`] for a locked vault; [`FfiError::Chain`] for an
/// RPC/tx failure (incl. `ErrNoPromotionPending` / `ErrPromotionDelayNotElapsed`).
#[allow(clippy::significant_drop_tightening)]
#[uniffi::export]
pub fn vault_finalize_promotion(
    handle: Arc<VaultHandle>,
    config: FfiChainConfig,
) -> Result<(), FfiError> {
    let mut guard = handle.lock_vault();
    let vault = guard.as_mut()?;
    if vault.state() != pangolin_store::VaultState::Active {
        return Err(FfiError::Session {
            message: "vault is not unlocked".to_owned(),
        });
    }
    let vault_id = vault.vault_id();
    let signer = vault.evm_wallet().map_err(store_into_ffi)?.signer().clone();
    block_on_local(async {
        let (env, _chain_id) = crate::chain_config::ffi_chain_env_and_id(&config.rpc_url)
            .await
            .map_err(chain_into_ffi)?;
        let wallet = pangolin_chain::EvmWallet::from_signer(signer.clone());
        finalize_promotion_v2(&wallet, vault_id, env, &config.rpc_url)
            .await
            .map_err(chain_into_ffi)?;
        Ok::<(), FfiError>(())
    })?
}

/// **MVP-4-K. MANAGER-ONLY.** Veto a pending manager promotion
/// (`cancelPromotion`). The contract gates this on `msg.sender ==
/// currentManager`, and the tx is sent from THIS device's session wallet —
/// so it only succeeds on the current manager's device. The host gates the
/// affordance behind `is_manager`; a non-manager attempt fails-closed
/// (`ErrNotAuthorizedToCancel`).
///
/// # Errors
///
/// [`FfiError::Session`] for a locked vault; [`FfiError::Chain`] for an
/// RPC/tx failure (incl. `ErrNotAuthorizedToCancel` / `ErrNoPromotionPending`).
#[allow(clippy::significant_drop_tightening)]
#[uniffi::export]
pub fn vault_cancel_promotion(
    handle: Arc<VaultHandle>,
    config: FfiChainConfig,
) -> Result<(), FfiError> {
    let mut guard = handle.lock_vault();
    let vault = guard.as_mut()?;
    if vault.state() != pangolin_store::VaultState::Active {
        return Err(FfiError::Session {
            message: "vault is not unlocked".to_owned(),
        });
    }
    let vault_id = vault.vault_id();
    let signer = vault.evm_wallet().map_err(store_into_ffi)?.signer().clone();
    block_on_local(async {
        let (env, _chain_id) = crate::chain_config::ffi_chain_env_and_id(&config.rpc_url)
            .await
            .map_err(chain_into_ffi)?;
        let wallet = pangolin_chain::EvmWallet::from_signer(signer.clone());
        cancel_promotion_v2(&wallet, vault_id, env, &config.rpc_url)
            .await
            .map_err(chain_into_ffi)?;
        Ok::<(), FfiError>(())
    })?
}

/// **MVP-4-K.** Read the in-flight manager promotion, if any. Drives the
/// pending banner + countdown + veto gating. Fail-closed (L3).
///
/// # Errors
///
/// [`FfiError::Session`] for a locked vault; [`FfiError::Chain`] on a
/// chain-read failure.
#[allow(clippy::significant_drop_tightening)]
#[uniffi::export]
pub fn vault_read_pending_promotion(
    handle: Arc<VaultHandle>,
    config: FfiChainConfig,
) -> Result<Option<FfiPendingPromotion>, FfiError> {
    let mut guard = handle.lock_vault();
    let vault = guard.as_mut()?;
    if vault.state() != pangolin_store::VaultState::Active {
        return Err(FfiError::Session {
            message: "vault is not unlocked".to_owned(),
        });
    }
    let vault_id = vault.vault_id();
    let pending = block_on_local(async {
        let (env, _chain_id) = crate::chain_config::ffi_chain_env_and_id(&config.rpc_url)
            .await
            .map_err(chain_into_ffi)?;
        read_pending_promotion_v2(env, &config.rpc_url, vault_id)
            .await
            .map_err(chain_into_ffi)
    })??;
    Ok(pending.map(|(candidate, ready_at)| FfiPendingPromotion {
        schema_version: PAIRING_FFI_SCHEMA_VERSION,
        candidate: candidate.into_array().to_vec(),
        ready_at,
    }))
}

// ---------------------------------------------------------------------------
// Tests — the LOAD-BEARING ones for the #106e-2 audit
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use pangolin_store::{PinIdentityProof, PressYPresenceProof, Vault};

    fn pwd_bytes() -> Vec<u8> {
        b"correct horse battery staple".to_vec()
    }

    fn unlocked_handle(dir: &tempfile::TempDir, name: &str) -> Arc<VaultHandle> {
        let path = dir.path().join(name);
        Vault::create(&path, &SecretBytes::new(pwd_bytes())).unwrap();
        let mut v = Vault::open(&path).unwrap();
        v.unlock(
            &PressYPresenceProof::confirmed(),
            &PinIdentityProof::new(SecretBytes::new(pwd_bytes())),
        )
        .unwrap();
        VaultHandle::from_vault(v)
    }

    fn bogus_config() -> FfiChainConfig {
        FfiChainConfig {
            schema_version: FFI_CHAIN_CONFIG_SCHEMA_VERSION,
            rpc_url: "http://127.0.0.1:1".into(),
            deployment_path: "/no/such/path/base-sepolia.json".into(),
            prefer_websocket: false,
        }
    }

    /// `pairing_begin_new_device` on an Active vault produces a
    /// well-formed payload (correct lengths, schema version, byte/text
    /// round-trip).
    #[test]
    fn begin_new_device_returns_well_formed_payload() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        let fp = pairing_begin_new_device(h).expect("begin payload");

        assert_eq!(fp.schema_version, PAIRING_FFI_SCHEMA_VERSION);
        assert_eq!(
            fp.payload_schema_version,
            u16::from(PAIRING_PAYLOAD_SCHEMA_VERSION)
        );
        assert_eq!(fp.bytes.len(), PAYLOAD_LEN, "bytes length pin");
        assert_eq!(fp.vault_id.len(), VAULT_ID_LEN);
        assert_eq!(fp.device_id.len(), 32);
        assert_eq!(fp.x25519_pairing_pub.len(), X25519_KEY_LEN);
        assert_eq!(fp.signer.len(), SIGNER_LEN);
        assert_eq!(fp.freshness_nonce.len(), FRESHNESS_NONCE_LEN);
        assert!(
            !fp.string_form.is_empty()
                && fp
                    .string_form
                    .bytes()
                    .all(|c| { c.is_ascii_lowercase() || (b'2'..=b'7').contains(&c) }),
            "string_form must be lowercase base32"
        );

        // The byte form decodes back through the pure pure FFI decoder
        // (proves the engine-side wire-form is round-trip-stable).
        let decoded = pairing_decode_bytes(fp.bytes.clone()).unwrap();
        assert_eq!(decoded.vault_id, fp.vault_id);
        assert_eq!(decoded.device_id, fp.device_id);
        assert_eq!(decoded.x25519_pairing_pub, fp.x25519_pairing_pub);
        assert_eq!(decoded.signer, fp.signer);
        assert_eq!(decoded.freshness_nonce, fp.freshness_nonce);

        // The text form decodes the same way.
        let decoded_t = pairing_decode_string(fp.string_form).unwrap();
        assert_eq!(decoded_t.bytes, decoded.bytes);
    }

    /// `pairing_begin_new_device` on a locked vault → `Session` (L4
    /// session gate).
    #[test]
    fn begin_new_device_rejects_locked() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        {
            let mut g = h.lock_vault();
            g.as_mut().unwrap().lock();
        }
        let err = pairing_begin_new_device(h).unwrap_err();
        assert!(matches!(err, FfiError::Session { .. }));
    }

    /// `pairing_begin_new_device` on a placeholder → `Session`.
    #[test]
    fn begin_new_device_rejects_placeholder() {
        let empty = VaultHandle::new_placeholder();
        let err = pairing_begin_new_device(empty).unwrap_err();
        assert!(matches!(err, FfiError::Session { .. }));
    }

    /// `pairing_local_payload` echoes the same shape as `begin_new_device`
    /// with the SUPPLIED nonce.
    #[test]
    fn local_payload_binds_supplied_nonce() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        let their_nonce = vec![0xAB; FRESHNESS_NONCE_LEN];
        let fp = pairing_local_payload(h, their_nonce.clone()).expect("local payload");
        assert_eq!(fp.freshness_nonce, their_nonce);
    }

    /// `pairing_local_payload` rejects a non-16-byte nonce.
    #[test]
    fn local_payload_rejects_bad_nonce_length() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        let err = pairing_local_payload(h, vec![0u8; 15]).unwrap_err();
        assert!(matches!(err, FfiError::Validation { ref kind, .. } if kind == "argument"));
    }

    /// `pairing_derive_sas` on two payloads sharing a nonce yields a
    /// 6-digit code; the code is identical regardless of (a, b) vs
    /// (b, a) — L3 canonical-symmetric round-trip through the FFI.
    #[test]
    fn derive_sas_canonical_symmetric_through_ffi() {
        let dir_a = tempfile::TempDir::new().unwrap();
        let dir_b = tempfile::TempDir::new().unwrap();
        let h_a = unlocked_handle(&dir_a, "a.pvf");
        let h_b = unlocked_handle(&dir_b, "b.pvf");
        let p_b = pairing_begin_new_device(h_b).unwrap();
        let p_a = pairing_local_payload(h_a, p_b.freshness_nonce.clone()).unwrap();

        let sas_ab = pairing_derive_sas(p_a.clone(), p_b.clone()).unwrap();
        let sas_ba = pairing_derive_sas(p_b, p_a).unwrap();
        assert_eq!(sas_ab.len(), 6, "SAS must be 6 digits");
        assert!(sas_ab.bytes().all(|c| c.is_ascii_digit()));
        assert_eq!(
            sas_ab, sas_ba,
            "L3: derive_sas must be canonical-symmetric through the FFI"
        );
    }

    /// `pairing_derive_sas` rejects mismatched-nonce payloads (the
    /// fail-closed property the spec calls out).
    #[test]
    fn derive_sas_rejects_mismatched_nonce() {
        let dir_a = tempfile::TempDir::new().unwrap();
        let dir_b = tempfile::TempDir::new().unwrap();
        let h_a = unlocked_handle(&dir_a, "a.pvf");
        let h_b = unlocked_handle(&dir_b, "b.pvf");
        let p_b = pairing_begin_new_device(h_b).unwrap();
        // A builds its payload with a DIFFERENT nonce — must reject.
        let other_nonce = vec![0xFE; FRESHNESS_NONCE_LEN];
        assert_ne!(other_nonce, p_b.freshness_nonce);
        let p_a = pairing_local_payload(h_a, other_nonce).unwrap();
        let err = pairing_derive_sas(p_a, p_b).unwrap_err();
        assert!(matches!(err, FfiError::Validation { ref kind, .. } if kind == "argument"));
    }

    /// **L2 LOAD-BEARING through the FFI.** A payload whose pairing
    /// pubkey was substituted by a MITM produces a DIFFERENT SAS — the
    /// human comparison fails. Round-tripped end-to-end through the FFI
    /// `derive_sas` surface, NOT just the crypto crate's direct
    /// derivation.
    #[test]
    fn derive_sas_defeats_pubkey_swap_mitm_through_ffi() {
        let dir_a = tempfile::TempDir::new().unwrap();
        let dir_b = tempfile::TempDir::new().unwrap();
        let dir_mallory = tempfile::TempDir::new().unwrap();
        let h_a = unlocked_handle(&dir_a, "a.pvf");
        let h_b = unlocked_handle(&dir_b, "b.pvf");
        let h_mallory = unlocked_handle(&dir_mallory, "m.pvf");

        let p_b = pairing_begin_new_device(h_b).unwrap();
        let p_a = pairing_local_payload(h_a, p_b.freshness_nonce.clone()).unwrap();
        let p_mallory = pairing_local_payload(h_mallory, p_b.freshness_nonce.clone()).unwrap();
        // Mallory swaps her pubkey in for B in A's view: A still sees
        // her own pubkey (p_a) but the "other side" is Mallory.
        let sas_honest = pairing_derive_sas(p_a.clone(), p_b).unwrap();
        let sas_mitm = pairing_derive_sas(p_a, p_mallory).unwrap();
        assert_ne!(
            sas_honest, sas_mitm,
            "L2: a pubkey-swap MITM must produce a DIFFERENT SAS code (anti-MITM property)"
        );
    }

    /// `pairing_decode_bytes` / `pairing_decode_string` route every
    /// transport error to `Validation { kind: "argument" }`. Mirrors the
    /// engine-side `From<PairingTransportError>` mapping.
    #[test]
    fn decode_errors_map_to_validation_argument() {
        // Length-too-short.
        let err = pairing_decode_bytes(vec![0u8; 5]).unwrap_err();
        assert!(matches!(err, FfiError::Validation { ref kind, .. } if kind == "argument"));
        // Empty string.
        let err = pairing_decode_string(String::new()).unwrap_err();
        assert!(matches!(err, FfiError::Validation { ref kind, .. } if kind == "argument"));
        // Invalid base32.
        let err = pairing_decode_string("uppercase".into()).unwrap_err();
        assert!(matches!(err, FfiError::Validation { ref kind, .. } if kind == "argument"));
    }

    /// `vault_add_device` ACCEPTS a payload whose `vault_id` is B's own
    /// (the new device's local `.pvf` id BEFORE it adopts A's id) — per
    /// `pairing_begin_new_device`'s documented design: B carries its own
    /// vault_id in the payload + adopts A's later in step 3 via
    /// `pairing_open_and_join`. The cryptographic anti-attacker defense
    /// is the SAS comparison + the engine-side seal binding to A's
    /// vault_id; the FFI does NOT compare the payload's vault_id against
    /// A's (user-error UX safety is a host-layer concern). This test
    /// asserts the binding proceeds PAST the pre-chain validation gates
    /// + into the chain step (which fails with `FfiError::Chain` against
    /// the `bogus_config()` rpc — a previous version returned a
    /// pre-chain `FfiError::Validation` for the same payload, so this
    /// test bites if a future refactor reintroduces the dropped check).
    #[test]
    fn vault_add_device_proceeds_past_dropped_cross_vault_check() {
        let dir_a = tempfile::TempDir::new().unwrap();
        let dir_b = tempfile::TempDir::new().unwrap();
        let h_a = unlocked_handle(&dir_a, "a.pvf");
        let h_b = unlocked_handle(&dir_b, "b.pvf");
        // B's payload carries B's own vault_id (NOT A's — the documented
        // design). Previously the binding rejected with Validation; now
        // it proceeds to the chain read, which fails on the bogus rpc.
        let p_b = pairing_begin_new_device(h_b).unwrap();
        let err = vault_add_device(h_a, SecretPassword::new(pwd_bytes()), bogus_config(), p_b)
            .unwrap_err();
        assert!(
            matches!(err, FfiError::Chain { .. }),
            "expected chain failure (binding proceeded past the dropped cross-vault gate), got {err:?}"
        );
    }

    /// `vault_bootstrap_chain` on a locked vault → `Session` (L4 gate
    /// BEFORE any chain primitive — mirrors `vault_add_device`'s gate).
    #[test]
    fn vault_bootstrap_chain_rejects_locked_before_chain() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        {
            let mut g = h.lock_vault();
            g.as_mut().unwrap().lock();
        }
        let err =
            vault_bootstrap_chain(h, SecretPassword::new(pwd_bytes()), bogus_config()).unwrap_err();
        assert!(matches!(err, FfiError::Session { .. }));
    }

    /// `vault_bootstrap_chain` on a placeholder handle → `Session`.
    #[test]
    fn vault_bootstrap_chain_rejects_placeholder() {
        let empty = VaultHandle::new_placeholder();
        let err = vault_bootstrap_chain(empty, SecretPassword::new(pwd_bytes()), bogus_config())
            .unwrap_err();
        assert!(matches!(err, FfiError::Session { .. }));
    }

    /// `vault_bootstrap_chain` on an unlocked vault PROCEEDS past the L4
    /// gate + fails at the chain step against a bogus RPC. Confirms the
    /// binding actually reaches the chain side (the L4 gate is not the
    /// only thing keeping it in `Session` territory).
    #[test]
    fn vault_bootstrap_chain_proceeds_to_chain_step_when_unlocked() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        let err =
            vault_bootstrap_chain(h, SecretPassword::new(pwd_bytes()), bogus_config()).unwrap_err();
        assert!(
            matches!(err, FfiError::Chain { .. }),
            "expected chain failure once the L4 gate is cleared, got {err:?}"
        );
    }

    /// `vault_add_device` on a locked vault → `Session` (L4 gate BEFORE
    /// chain).
    #[test]
    fn vault_add_device_rejects_locked_before_chain() {
        let dir_a = tempfile::TempDir::new().unwrap();
        let dir_b = tempfile::TempDir::new().unwrap();
        let h_a = unlocked_handle(&dir_a, "a.pvf");
        let h_b = unlocked_handle(&dir_b, "b.pvf");
        let p_b = pairing_begin_new_device(h_b).unwrap();
        {
            let mut g = h_a.lock_vault();
            g.as_mut().unwrap().lock();
        }
        let err = vault_add_device(h_a, SecretPassword::new(pwd_bytes()), bogus_config(), p_b)
            .unwrap_err();
        assert!(matches!(err, FfiError::Session { .. }));
    }

    /// `vault_add_device` on a placeholder → `Session`.
    #[test]
    fn vault_add_device_rejects_placeholder() {
        let dir = tempfile::TempDir::new().unwrap();
        let h_b = unlocked_handle(&dir, "b.pvf");
        let p_b = pairing_begin_new_device(h_b).unwrap();
        let empty = VaultHandle::new_placeholder();
        let err = vault_add_device(empty, SecretPassword::new(pwd_bytes()), bogus_config(), p_b)
            .unwrap_err();
        assert!(matches!(err, FfiError::Session { .. }));
    }

    /// `pairing_open_and_join` rejects bad-length inputs (empty sealed
    /// VDK, wrong-length vault_id).
    #[test]
    fn open_and_join_rejects_bad_lengths() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        // Empty sealed-VDK.
        let err = pairing_open_and_join(
            Arc::clone(&h),
            vec![],
            vec![0u8; VAULT_ID_LEN],
            0,
            SecretPassword::new(pwd_bytes()),
        )
        .unwrap_err();
        assert!(matches!(err, FfiError::Validation { ref kind, .. } if kind == "argument"));
        // Wrong-length vault_id.
        let err = pairing_open_and_join(
            h,
            vec![0u8; 48],
            vec![0u8; 31],
            0,
            SecretPassword::new(pwd_bytes()),
        )
        .unwrap_err();
        assert!(matches!(err, FfiError::Validation { ref kind, .. } if kind == "argument"));
    }

    /// `pairing_open_and_join` on a locked / placeholder vault → `Session`.
    #[test]
    fn open_and_join_rejects_locked_and_placeholder() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        {
            let mut g = h.lock_vault();
            g.as_mut().unwrap().lock();
        }
        let err = pairing_open_and_join(
            h,
            vec![0u8; 48],
            vec![0u8; VAULT_ID_LEN],
            0,
            SecretPassword::new(pwd_bytes()),
        )
        .unwrap_err();
        assert!(matches!(err, FfiError::Session { .. }));

        let empty = VaultHandle::new_placeholder();
        let err = pairing_open_and_join(
            empty,
            vec![0u8; 48],
            vec![0u8; VAULT_ID_LEN],
            0,
            SecretPassword::new(pwd_bytes()),
        )
        .unwrap_err();
        assert!(matches!(err, FfiError::Session { .. }));
    }

    /// **End-to-end through the FFI (NO chain) — the seal/open
    /// round-trip works.** This is the L1 byte-identity check at the
    /// FFI layer: a payload built by B + a seal built by A (calling
    /// `Vault::seal_vdk_for_new_device` directly, bypassing the chain
    /// step) + `pairing_open_and_join` on B recovers a vault B can
    /// unlock with B's chosen password and that has A's vault_id.
    ///
    /// The full chain path (`vault_add_device` with a real anvil) is
    /// exercised by the coupled E2E in `pangolin-core/tests/`.
    #[test]
    #[allow(clippy::significant_drop_tightening)]
    fn seal_open_round_trip_through_ffi() {
        let dir_a = tempfile::TempDir::new().unwrap();
        let dir_b = tempfile::TempDir::new().unwrap();

        // A's vault — Active, holds the live VDK.
        let h_a = unlocked_handle(&dir_a, "a.pvf");
        let vault_id_a = {
            let mut g = h_a.lock_vault();
            g.as_mut().unwrap().vault_id()
        };

        // B's vault — Active, brand-new (its own random vault_id).
        let h_b = unlocked_handle(&dir_b, "b.pvf");

        // B builds its pairing payload (fresh nonce, B's pairing pub).
        let p_b = pairing_begin_new_device(Arc::clone(&h_b)).expect("B payload");

        // A seals the VDK to B's pubkey (bypasses the chain step — this
        // is the unit test of the FFI plumbing, not the chain plumbing).
        let sealed_bytes = {
            let device_id_arr: [u8; 32] = (&p_b.device_id[..]).try_into().unwrap();
            let pub_arr: [u8; X25519_KEY_LEN] = (&p_b.x25519_pairing_pub[..]).try_into().unwrap();
            let mut g = h_a.lock_vault();
            let v = g.as_mut().unwrap();
            let sealed = v
                .seal_vdk_for_new_device(&pub_arr, &device_id_arr, &vault_id_a, 0)
                .expect("seal");
            sealed.as_bytes().to_vec()
        };

        // B's new master password — what B's user chooses.
        let b_pw = b"new-device pw for B".to_vec();
        // B opens the seal + installs the recovered VDK under B's
        // master password + adopts A's vault_id.
        pairing_open_and_join(
            Arc::clone(&h_b),
            sealed_bytes,
            vault_id_a.to_vec(),
            0,
            SecretPassword::new(b_pw.clone()),
        )
        .expect("open and join");

        // B's vault now carries A's vault_id, is Locked, and B unlocks
        // it with B's new master password — start a fresh session.
        {
            let mut g = h_b.lock_vault();
            let v = g.as_mut().unwrap();
            assert_eq!(v.vault_id(), vault_id_a, "B adopts A's vault_id (L3 join)");
            assert_eq!(v.state(), pangolin_store::VaultState::Locked);
            v.unlock(
                &PressYPresenceProof::confirmed(),
                &PinIdentityProof::new(SecretBytes::new(b_pw)),
            )
            .expect("B unlocks under its new master password");
            assert_eq!(v.state(), pangolin_store::VaultState::Active);
        }
    }

    // ---- MVP-4-J: device removal + authorized-set / manager reads ----

    /// `vault_remove_device` validates the signer length BEFORE touching
    /// the vault/chain → a non-20-byte signer is `Validation`.
    #[test]
    fn remove_device_rejects_bad_signer_length() {
        let empty = VaultHandle::new_placeholder();
        let err = vault_remove_device(empty, bogus_config(), vec![0x11; 10]).unwrap_err();
        match err {
            FfiError::Validation { kind, .. } => assert_eq!(kind, "argument"),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    /// `vault_remove_device` on a placeholder (no vault) → Session, before
    /// any chain primitive.
    #[test]
    fn remove_device_rejects_placeholder() {
        let empty = VaultHandle::new_placeholder();
        let err = vault_remove_device(empty, bogus_config(), vec![0x11; 20]).unwrap_err();
        assert!(matches!(err, FfiError::Session { .. }));
    }

    /// **§0a L3 fail-closed.** `vault_remove_device` against a bogus RPC
    /// (unreachable) maps to `Chain` — the broadcast never silently
    /// proceeds. An Active vault is required to reach the chain primitive.
    #[test]
    fn remove_device_fail_closed_on_bad_rpc_maps_to_chain() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        let err = vault_remove_device(h, bogus_config(), vec![0x11; 20]).unwrap_err();
        assert!(
            matches!(err, FfiError::Chain { .. }),
            "bad-rpc removal must fail-closed to Chain, got {err:?}"
        );
    }

    /// `vault_list_authorized_devices` on a placeholder → Session.
    #[test]
    fn list_authorized_devices_rejects_placeholder() {
        let empty = VaultHandle::new_placeholder();
        let err = vault_list_authorized_devices(empty, bogus_config()).unwrap_err();
        assert!(matches!(err, FfiError::Session { .. }));
    }

    /// **L3 fail-closed.** `vault_list_authorized_devices` against a bogus
    /// RPC maps to `Chain` (never a stale/guessed set).
    #[test]
    fn list_authorized_devices_fail_closed_on_bad_rpc() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        let err = vault_list_authorized_devices(h, bogus_config()).unwrap_err();
        assert!(matches!(err, FfiError::Chain { .. }));
    }

    // ---- MVP-4-K: promotion ----

    #[test]
    fn propose_promotion_rejects_placeholder() {
        let empty = VaultHandle::new_placeholder();
        let err = vault_propose_promotion(empty, bogus_config()).unwrap_err();
        assert!(matches!(err, FfiError::Session { .. }));
    }

    #[test]
    fn propose_promotion_fail_closed_on_bad_rpc() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        let err = vault_propose_promotion(h, bogus_config()).unwrap_err();
        assert!(matches!(err, FfiError::Chain { .. }));
    }

    #[test]
    fn finalize_promotion_rejects_placeholder() {
        let empty = VaultHandle::new_placeholder();
        let err = vault_finalize_promotion(empty, bogus_config()).unwrap_err();
        assert!(matches!(err, FfiError::Session { .. }));
    }

    #[test]
    fn finalize_promotion_fail_closed_on_bad_rpc() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        let err = vault_finalize_promotion(h, bogus_config()).unwrap_err();
        assert!(matches!(err, FfiError::Chain { .. }));
    }

    #[test]
    fn cancel_promotion_rejects_placeholder() {
        let empty = VaultHandle::new_placeholder();
        let err = vault_cancel_promotion(empty, bogus_config()).unwrap_err();
        assert!(matches!(err, FfiError::Session { .. }));
    }

    #[test]
    fn cancel_promotion_fail_closed_on_bad_rpc() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        let err = vault_cancel_promotion(h, bogus_config()).unwrap_err();
        assert!(matches!(err, FfiError::Chain { .. }));
    }

    #[test]
    fn read_pending_promotion_rejects_placeholder() {
        let empty = VaultHandle::new_placeholder();
        let err = vault_read_pending_promotion(empty, bogus_config()).unwrap_err();
        assert!(matches!(err, FfiError::Session { .. }));
    }

    #[test]
    fn read_pending_promotion_fail_closed_on_bad_rpc() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        let err = vault_read_pending_promotion(h, bogus_config()).unwrap_err();
        assert!(matches!(err, FfiError::Chain { .. }));
    }
}
