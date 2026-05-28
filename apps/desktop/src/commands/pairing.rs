// SPDX-License-Identifier: AGPL-3.0-or-later
//! Multi-device pairing Tauri commands (MVP-4-I).
//!
//! Thin wrappers over the already-built + audited pairing FFI
//! (`pangolin_ffi::pairing` + `pangolin_ffi::device`). This slice adds
//! NO new engine/crypto code — every command re-decodes its inputs from
//! the non-secret wire bytes and forwards to the FFI.
//!
//! Plan-LOCK: docs/issue-plans/mvp4-i-multidevice-pairing-ux.md.
//!
//! ## The handshake (see the plan §3.1)
//!
//! New device (B): `pairing_begin_new_device` → show payload → ingest A's
//! payload (`pairing_decode_*`) → `pairing_derive_sas` → (human confirms)
//! → ingest A's sealed envelope → `pairing_open_and_join` → `vault_unlock`.
//!
//! Manager (A): (`pairing_chain_bootstrap` if first time) → ingest B's
//! payload → `pairing_local_payload` → `pairing_derive_sas` → (human
//! confirms) → `pairing_add_device` → show sealed envelope for B.
//!
//! ## Statelessness (plan R-3)
//!
//! The in-flight `FfiPairingPayload` objects are opaque Rust values that
//! cannot serialize to JS, and they are NON-secret (pubkeys + EVM address
//! + random nonce — exactly what a QR exposes). So the frontend wizard
//! holds the serializable `bytes` / `string_form` / SAS, and each command
//! re-decodes from the wire bytes per call. The only Rust-held state is
//! the existing unlocked `VaultState`.
//!
//! ## L-invariants
//!
//! - **L1.** No NEW secret crosses the boundary. The payloads, the sealed
//!   VDK envelope, and the SAS are all non-secret. Master passwords cross
//!   via the SAME `SecretPassword::new(String)` direct-invoke path that
//!   `vault_unlock` already uses (plan R-4); the VDK never crosses (sealing
//!   + opening happen engine-side).
//! - **L2.** The SAS compare is a host-UI human gate; the FFI does not
//!   enforce it — calling `pairing_add_device` IS the "codes match" signal.
//! - **L3.** Fail-closed: chain / decode / session errors surface as typed
//!   `DesktopError`.
//! - **L4.** Handle-bearing commands are session-gated FFI-side (Active).
//! - **L7.** `DesktopError` carries non-secret category messages only.
//!
//! ## Chain calls + the runtime-within-runtime trap
//!
//! `vault_bootstrap_chain` + `vault_add_device` do on-chain I/O by driving
//! a `!Send` engine future on a fresh current-thread tokio runtime
//! (`chain_config::block_on_local`). Calling `block_on` from inside the
//! Tauri command's async context (itself a tokio task) panics with
//! "Cannot start a runtime from within a runtime". Both therefore run via
//! `tokio::task::spawn_blocking`, which executes on a dedicated blocking
//! thread with no ambient runtime. The other commands are sync, non-chain
//! FFI (no nested runtime) and run inline.

#![forbid(unsafe_code)]
// Heavily-documented pairing module (the handshake sequence + L1/L2/L4
// invariants warrant in-source docs). Doc-style pedantic lints are allowed
// at module level, matching crates/pangolin-ffi/src/pairing.rs; substantive
// lints stay enforced.
#![allow(
    clippy::doc_markdown,
    clippy::too_long_first_doc_paragraph,
    clippy::doc_lazy_continuation
)]

use serde::Serialize;
use tauri::State;

use pangolin_ffi::{FfiChainConfig, SecretPassword, FFI_CHAIN_CONFIG_SCHEMA_VERSION};

use crate::error::DesktopError;
use crate::state::VaultState;

/// Default Base Sepolia RPC endpoint (testnet-only — D-011 gates mainnet).
const DEFAULT_RPC_URL: &str = "https://sepolia.base.org";

// ---------------------------------------------------------------------------
// DTOs (snake_case Rust fields; the invoke.ts boundary maps to camelCase,
// mirroring the AccountSummaryDto pattern in commands/account.rs)
// ---------------------------------------------------------------------------

/// The non-secret pairing payload, in the shapes the frontend needs.
///
/// `bytes` feeds the QR render + is the canonical form passed back to the
/// SAS / local-payload / add-device commands. `string_form` is the
/// copy-paste display. The hex fields are render/convenience surfaces
/// (`vault_id` is what device B passes to `pairing_open_and_join`).
#[derive(Debug, Clone, Serialize)]
pub struct PairingPayloadDto {
    /// Length-strict payload byte-form. Host renders as a QR + passes back
    /// to the byte-taking commands.
    pub bytes: Vec<u8>,
    /// Copy-pasteable base32 + checksum text form.
    pub string_form: String,
    /// 64-char lowercase hex of the 32-byte vault id this payload joins.
    pub vault_id: String,
    /// 64-char lowercase hex of the 32-byte stable device id.
    pub device_id: String,
    /// 40-char lowercase hex of the 20-byte secp256k1 EVM signer address.
    pub signer: String,
}

impl From<pangolin_ffi::FfiPairingPayload> for PairingPayloadDto {
    fn from(p: pangolin_ffi::FfiPairingPayload) -> Self {
        Self {
            vault_id: hex_encode(&p.vault_id),
            device_id: hex_encode(&p.device_id),
            signer: hex_encode(&p.signer),
            bytes: p.bytes,
            string_form: p.string_form,
        }
    }
}

/// The non-secret sealed-VDK envelope the manager hands back to the new
/// device (QR + copy-paste forms).
#[derive(Debug, Clone, Serialize)]
pub struct SealedEnvelopeDto {
    /// Raw sealed-box bytes (sealed to B's pairing pubkey). Host renders
    /// as a QR.
    pub bytes: Vec<u8>,
    /// Copy-pasteable base32 + checksum text form.
    pub string_form: String,
}

impl From<pangolin_ffi::FfiSealedVdkEnvelope> for SealedEnvelopeDto {
    fn from(e: pangolin_ffi::FfiSealedVdkEnvelope) -> Self {
        Self {
            bytes: e.bytes,
            string_form: e.string_form,
        }
    }
}

/// One paired device, metadata-only (the read-only device list).
#[derive(Debug, Clone, Serialize)]
pub struct DeviceInfoDto {
    /// 64-char lowercase hex of the 32-byte device id.
    pub id: String,
    /// User-set label.
    pub label: String,
    /// `true` iff this is the device the app is running on.
    pub is_current: bool,
    /// Unix-second timestamp the device first registered.
    pub registered_at: i64,
    /// Lowercase hex of the 20-byte per-device EVM address (empty until
    /// the column is back-filled on first unlock).
    pub evm_address: String,
}

impl From<pangolin_ffi::DeviceInfo> for DeviceInfoDto {
    fn from(d: pangolin_ffi::DeviceInfo) -> Self {
        Self {
            id: hex_encode(&d.id.bytes),
            label: d.label,
            is_current: d.is_current,
            registered_at: d.registered_at,
            evm_address: hex_encode(&d.evm_address),
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Lowercase-hex encoder (stdlib-only; mirrors commands::account).
fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Decode a 64-char lowercase/uppercase-hex 32-byte vault id (the form
/// `PairingPayloadDto.vault_id` round-trips). Surfaces a typed
/// `Validation` error so the React side renders a toast.
fn vault_id_from_hex(hex: &str) -> Result<Vec<u8>, DesktopError> {
    if hex.len() != 64 {
        return Err(DesktopError::Validation {
            kind: "vault_id".into(),
            message: "vault id must be 64 hex characters".into(),
        });
    }
    let mut bytes = Vec::with_capacity(32);
    for chunk in hex.as_bytes().chunks_exact(2) {
        let hi = decode_nibble(chunk[0])?;
        let lo = decode_nibble(chunk[1])?;
        bytes.push((hi << 4) | lo);
    }
    Ok(bytes)
}

fn decode_nibble(b: u8) -> Result<u8, DesktopError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(DesktopError::Validation {
            kind: "vault_id".into(),
            message: "vault id contains a non-hex character".into(),
        }),
    }
}

/// Build the per-call chain config from explicit values (pure; testable).
///
/// `deployment_path` is REQUIRED — without the deployment file the chain
/// adapter cannot resolve the contract address / chain-id / bytecode hash,
/// so we fail-closed (L3) with an actionable message rather than guessing.
fn build_chain_config(
    rpc_url: String,
    deployment_path: Option<String>,
) -> Result<FfiChainConfig, DesktopError> {
    let deployment_path = deployment_path.ok_or_else(|| {
        DesktopError::Chain(
            "chain deployment file not configured — set PANGOLIN_DEPLOYMENT_PATH to the \
             base-sepolia.json deployment file before pairing"
                .into(),
        )
    })?;
    Ok(FfiChainConfig {
        schema_version: FFI_CHAIN_CONFIG_SCHEMA_VERSION,
        rpc_url,
        deployment_path,
        // Forward-compat toggle; the pull path ignores it today (see
        // FfiChainConfig docs). Pairing's addDevice/bootstrap broadcasts
        // are HTTP-JSON-RPC regardless.
        prefer_websocket: false,
    })
}

/// Resolve the chain config from the environment.
///
/// `PANGOLIN_RPC_URL` (default Base Sepolia public RPC) +
/// `PANGOLIN_DEPLOYMENT_PATH` (required). Testnet-only: the FFI hardcodes
/// `ChainEnv::BaseSepolia` (D-011 gates mainnet), so this only supplies
/// the RPC URL + deployment file path.
fn chain_config() -> Result<FfiChainConfig, DesktopError> {
    let rpc_url = std::env::var("PANGOLIN_RPC_URL").unwrap_or_else(|_| DEFAULT_RPC_URL.to_owned());
    let deployment_path = std::env::var("PANGOLIN_DEPLOYMENT_PATH")
        .ok()
        .filter(|s| !s.is_empty());
    build_chain_config(rpc_url, deployment_path)
}

// ---------------------------------------------------------------------------
// Pure / decode commands (no chain, no spawn_blocking)
// ---------------------------------------------------------------------------

/// **NEW device, step 1.** Generate this device's pairing payload (fresh
/// freshness nonce). The frontend shows `string_form` (copy) + a QR of
/// `bytes`, and moves it to the manager.
///
/// # Errors
/// `DesktopError::Session` for a locked / closed vault.
#[tauri::command]
pub async fn pairing_begin_new_device(
    state: State<'_, VaultState>,
) -> Result<PairingPayloadDto, DesktopError> {
    let handle = state.require_open()?;
    let payload =
        pangolin_ffi::pairing::pairing_begin_new_device(handle).map_err(DesktopError::from)?;
    Ok(payload.into())
}

/// Validate + decode a payload the user pasted (text form).
///
/// Used by both roles to validate a peer payload before advancing, and by
/// device B to learn the manager's `vault_id` (needed for
/// `pairing_open_and_join`). No handle / no session needed (pure decode).
///
/// # Errors
/// `DesktopError::Validation { kind = "argument" }` on a bad
/// checksum / version / encoding.
#[tauri::command]
pub async fn pairing_decode_string(text: String) -> Result<PairingPayloadDto, DesktopError> {
    let payload = pangolin_ffi::pairing::pairing_decode_string(text).map_err(DesktopError::from)?;
    Ok(payload.into())
}

/// Validate + decode a payload the user scanned (byte form, from a QR).
///
/// # Errors
/// `DesktopError::Validation { kind = "argument" }` on a bad
/// length / domain / version.
#[tauri::command]
pub async fn pairing_decode_bytes(bytes: Vec<u8>) -> Result<PairingPayloadDto, DesktopError> {
    let payload = pangolin_ffi::pairing::pairing_decode_bytes(bytes).map_err(DesktopError::from)?;
    Ok(payload.into())
}

/// **MANAGER, step 2.** Build the manager's mirror payload, re-bound to
/// the new device's freshness nonce so both sides' SAS derives over the
/// same nonce. `their_bytes` is device B's payload byte-form.
///
/// # Errors
/// `DesktopError::Validation` for a malformed peer payload;
/// `DesktopError::Session` for a locked vault.
#[tauri::command]
pub async fn pairing_local_payload(
    their_bytes: Vec<u8>,
    state: State<'_, VaultState>,
) -> Result<PairingPayloadDto, DesktopError> {
    let handle = state.require_open()?;
    let their =
        pangolin_ffi::pairing::pairing_decode_bytes(their_bytes).map_err(DesktopError::from)?;
    let mine = pangolin_ffi::pairing::pairing_local_payload(handle, their.freshness_nonce)
        .map_err(DesktopError::from)?;
    Ok(mine.into())
}

/// **Both roles.** Derive the 6-digit SAS over the two payloads. The
/// frontend displays it on both devices; the human compares (L2). Order
/// is canonical-symmetric, so passing (mine, theirs) on each side yields
/// the same code.
///
/// # Errors
/// `DesktopError::Validation` for malformed payloads or mismatched
/// freshness nonces.
#[tauri::command]
pub async fn pairing_derive_sas(
    a_bytes: Vec<u8>,
    b_bytes: Vec<u8>,
) -> Result<String, DesktopError> {
    let a = pangolin_ffi::pairing::pairing_decode_bytes(a_bytes).map_err(DesktopError::from)?;
    let b = pangolin_ffi::pairing::pairing_decode_bytes(b_bytes).map_err(DesktopError::from)?;
    pangolin_ffi::pairing::pairing_derive_sas(a, b).map_err(DesktopError::from)
}

/// **NEW device, FINAL step.** Open the manager's sealed envelope, install
/// the recovered VDK under a NEW master password, and adopt the joining
/// vault's id. The vault is left Locked; the frontend follows with
/// `vault_unlock(new_password)`.
///
/// `vault_id` is the manager's vault id (hex, from decoding A's payload);
/// `epoch` is 0 for a first pairing (the manager seals at epoch 0).
///
/// # Errors
/// `DesktopError::Validation` for a bad vault id; `DesktopError::Crypto` /
/// `Store` if the seal does not open (wrong recipient / tampered);
/// `DesktopError::Session` for a locked vault.
#[tauri::command]
pub async fn pairing_open_and_join(
    sealed_bytes: Vec<u8>,
    vault_id: String,
    epoch: u64,
    new_password: String,
    state: State<'_, VaultState>,
) -> Result<(), DesktopError> {
    let handle = state.require_open()?;
    let vault_id_bytes = vault_id_from_hex(&vault_id)?;
    let pw = SecretPassword::new(new_password.into_bytes());
    pangolin_ffi::pairing::pairing_open_and_join(handle, sealed_bytes, vault_id_bytes, epoch, pw)
        .map_err(DesktopError::from)
}

/// Read the read-only paired-device list.
///
/// # Errors
/// `DesktopError::Session` for a vault never unlocked; `DesktopError::Store`
/// on a storage failure.
#[tauri::command]
pub async fn pairing_device_list(
    state: State<'_, VaultState>,
) -> Result<Vec<DeviceInfoDto>, DesktopError> {
    let handle = state.require_open()?;
    let devices = pangolin_ffi::device::device_list(handle).map_err(DesktopError::from)?;
    Ok(devices.into_iter().map(DeviceInfoDto::from).collect())
}

// ---------------------------------------------------------------------------
// Chain commands (spawn_blocking — they drive a nested current-thread
// runtime via block_on_local, which would panic inline in the async ctx)
// ---------------------------------------------------------------------------

/// **MANAGER.** Bootstrap the vault's on-chain authorized-device set
/// (genesis `addDevice` @ nonce 0). MUST run once per vault before the
/// first `pairing_add_device`. Idempotent against re-bootstrap only at
/// the contract level (a second call reverts `VaultAlreadyBootstrapped`).
///
/// # Errors
/// `DesktopError::Chain` for an RPC / tx failure (incl. the
/// already-bootstrapped revert — the frontend treats that as "already
/// done"); `DesktopError::Session` for a locked vault.
#[tauri::command]
pub async fn pairing_chain_bootstrap(
    password: String,
    state: State<'_, VaultState>,
) -> Result<(), DesktopError> {
    let handle = state.require_open()?;
    let config = chain_config()?;
    let pw = SecretPassword::new(password.into_bytes());
    tokio::task::spawn_blocking(move || {
        pangolin_ffi::pairing::vault_bootstrap_chain(handle, pw, config)
    })
    .await
    .map_err(|e| DesktopError::Internal(format!("bootstrap task join failed: {e}")))?
    .map_err(DesktopError::from)
}

/// **MANAGER, FINAL CONFIRMATION.** After the human confirms the SAS
/// matches on both screens (L2), authorize device B on-chain
/// (`addDevice`), seal the VDK to B, persist the directory entry, and
/// return the sealed envelope for B to ingest. `their_bytes` is B's
/// payload byte-form.
///
/// # Errors
/// `DesktopError::Validation` for a malformed payload; `DesktopError::Chain`
/// for an RPC / tx / insufficient-gas failure; `DesktopError::Session` for
/// a locked vault.
#[tauri::command]
pub async fn pairing_add_device(
    their_bytes: Vec<u8>,
    password: String,
    state: State<'_, VaultState>,
) -> Result<SealedEnvelopeDto, DesktopError> {
    let handle = state.require_open()?;
    let their_payload =
        pangolin_ffi::pairing::pairing_decode_bytes(their_bytes).map_err(DesktopError::from)?;
    let config = chain_config()?;
    let pw = SecretPassword::new(password.into_bytes());
    let envelope = tokio::task::spawn_blocking(move || {
        pangolin_ffi::pairing::vault_add_device(handle, pw, config, their_payload)
    })
    .await
    .map_err(|e| DesktopError::Internal(format!("add-device task join failed: {e}")))?
    .map_err(DesktopError::from)?;
    Ok(envelope.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_encode_round_trip() {
        assert_eq!(hex_encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
        assert_eq!(hex_encode(&[]), "");
    }

    #[test]
    fn vault_id_from_hex_accepts_64_chars() {
        let id = vault_id_from_hex(&"ab".repeat(32)).expect("64 hex chars");
        assert_eq!(id.len(), 32);
        assert_eq!(id[0], 0xab);
    }

    #[test]
    fn vault_id_from_hex_rejects_wrong_length() {
        let err = vault_id_from_hex("deadbeef").expect_err("too short");
        match err {
            DesktopError::Validation { kind, .. } => assert_eq!(kind, "vault_id"),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn vault_id_from_hex_rejects_non_hex() {
        let err = vault_id_from_hex(&"z".repeat(64)).expect_err("non-hex");
        match err {
            DesktopError::Validation { kind, .. } => assert_eq!(kind, "vault_id"),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn vault_id_from_hex_accepts_uppercase() {
        let id = vault_id_from_hex(&"A".repeat(64)).expect("uppercase ok");
        assert_eq!(id[0], 0xaa);
    }

    #[test]
    fn build_chain_config_missing_deployment_path_is_chain_error() {
        let err = build_chain_config("https://sepolia.base.org".into(), None)
            .expect_err("missing deployment path");
        assert!(matches!(err, DesktopError::Chain(_)));
    }

    #[test]
    fn build_chain_config_populates_fields() {
        let cfg = build_chain_config(
            "https://rpc.example".into(),
            Some("/tmp/base-sepolia.json".into()),
        )
        .expect("config built");
        assert_eq!(cfg.rpc_url, "https://rpc.example");
        assert_eq!(cfg.deployment_path, "/tmp/base-sepolia.json");
        assert!(!cfg.prefer_websocket);
        assert_eq!(cfg.schema_version, FFI_CHAIN_CONFIG_SCHEMA_VERSION);
    }

    /// L1: the pairing payload DTO carries only non-secret fields (the
    /// same bytes a QR exposes). Round-trips an FFI payload → DTO.
    #[test]
    fn pairing_payload_dto_is_non_secret_projection() {
        let ffi = pangolin_ffi::FfiPairingPayload {
            schema_version: 1,
            bytes: vec![1, 2, 3],
            string_form: "abc".into(),
            payload_schema_version: 2,
            vault_id: vec![0xaa; 32],
            device_id: vec![0xbb; 32],
            x25519_pairing_pub: vec![0xcc; 32],
            signer: vec![0xdd; 20],
            freshness_nonce: vec![0xee; 16],
        };
        let dto: PairingPayloadDto = ffi.into();
        assert_eq!(dto.vault_id, "aa".repeat(32));
        assert_eq!(dto.device_id, "bb".repeat(32));
        assert_eq!(dto.signer, "dd".repeat(20));
        assert_eq!(dto.bytes, vec![1, 2, 3]);
        assert_eq!(dto.string_form, "abc");
    }

    #[test]
    fn sealed_envelope_dto_round_trip() {
        let ffi = pangolin_ffi::FfiSealedVdkEnvelope {
            schema_version: 1,
            bytes: vec![9, 8, 7],
            string_form: "zzz".into(),
        };
        let dto: SealedEnvelopeDto = ffi.into();
        assert_eq!(dto.bytes, vec![9, 8, 7]);
        assert_eq!(dto.string_form, "zzz");
    }
}
