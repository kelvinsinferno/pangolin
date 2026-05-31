// SPDX-License-Identifier: AGPL-3.0-or-later
//! Recovery Tauri commands (MVP-4-L, slices L-D + L-A + L-C).
//!
//! Thin wrappers over the already-built recovery FFI. L-D ships the
//! backup-phrase create flow + a read-only recovery-health panel. L-A
//! ships the owner-side guardian-onboarding wizard surface. L-C ships
//! the guardian-side help wizard surface: decode an incoming
//! recovery-request blob (paste-format), approve the attempt on-chain
//! (`vault_approve_recovery`), and release the guardian's share
//! re-sealed to the recoverer's per-attempt ephemeral pubkey
//! (`vault_guardian_release_share` — Decision-B anti-redirect verify
//! lives FFI-side). Plan-LOCKs: `docs/issue-plans/mvp4-l-recovery-ux.md`,
//! `docs/issue-plans/mvp4-l-a-guardian-onboarding.md`,
//! `docs/issue-plans/mvp4-l-c-guardian-help.md`.
//!
//! ## L-invariants
//!
//! - **L1.** Secrets crossing here: the 24-word seed phrase (L-D, out)
//!   and the master password (L-D / L-A, in via the opaque
//!   `SecretPassword::new` path). VDK never crosses. Guardian invites +
//!   sealing pubkeys + EVM addresses are explicitly non-secret per L-0b.
//! - **L3.** Fail-closed: the health-panel + chain-broadcast paths surface
//!   typed `DesktopError`s rather than fabricating success / state.
//! - **L4.** Handle-bearing commands are session-gated FFI-side. The pure
//!   `guardian_invite_decode_text` command takes no handle by design.
//!
//! Chain commands (`recovery_health`, `recovery_set_guardian_set`) run via
//! `spawn_blocking` (the FFI drives a nested current-thread runtime that
//! would panic inline — same trap as the pairing chain commands). The
//! local-crypto commands (`recovery_create_backup`,
//! `recovery_onboard_guardians`, `guardian_identity_export`) run inline.

#![forbid(unsafe_code)]
// Documented recovery module; doc-style pedantic lints allowed at module
// level, matching commands/pairing.rs. Substantive lints stay enforced.
//
// `clippy::unused_async` is allowed because `#[tauri::command]` handlers
// that take `State<'_, VaultState>` require `async fn` (the lifetime on
// State binds against the future), and that requirement extends to the
// pure commands in the module for surface uniformity (the frontend's
// invoke layer assumes every command returns a Promise). The body-level
// "no await" pattern is a Tauri quirk, not a code smell.
#![allow(
    clippy::doc_markdown,
    clippy::too_long_first_doc_paragraph,
    clippy::unused_async
)]

use serde::{Deserialize, Serialize};
use tauri::State;

use pangolin_ffi::SecretPassword;

use crate::commands::pairing::chain_config;
use crate::error::DesktopError;
use crate::state::VaultState;

/// Lowercase-hex encoder (mirrors commands::account / commands::pairing).
fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// A freshly-created recovery backup. The seed phrase is the ONE secret —
/// the user records it offline; we do NOT store it.
#[derive(Debug, Clone, Serialize)]
pub struct BackupDto {
    /// The 24 BIP-39 words, shown to the user ONCE.
    pub seed_phrase_words: Vec<String>,
    /// The encrypted envelope, byte form (save to a file / QR).
    pub bytes: Vec<u8>,
    /// The encrypted envelope, copy-paste text form.
    pub text: String,
}

impl From<pangolin_ffi::FfiBackup> for BackupDto {
    fn from(b: pangolin_ffi::FfiBackup) -> Self {
        Self {
            seed_phrase_words: b.seed_phrase_words,
            bytes: b.bytes,
            text: b.text,
        }
    }
}

/// Read-only recovery-health summary for THIS vault.
#[derive(Debug, Clone, Serialize)]
pub struct RecoveryHealthDto {
    /// 40-char hex of the current on-chain vault authority (the
    /// recovery-control owner); all-zero / empty when none is set.
    pub authority: String,
    /// 0=None, 1=Pending, 2=Finalized, 3=Canceled (`FfiRecoveryStatus`).
    pub recovery_status: u8,
    /// 40-char hex of the proposed authority of an in-flight recovery, if
    /// any (empty otherwise).
    pub proposed_authority: String,
    /// The in-flight attempt nonce (0 when none).
    pub attempt_nonce: u64,
}

/// **Create a recovery backup** — generate the 24-word seed phrase + the
/// encrypted envelope. Local crypto (no chain). Requires guardians to have
/// been onboarded first (else the FFI returns a Validation error). The
/// phrase is shown ONCE + never stored.
///
/// # Errors
/// `DesktopError::Session` (locked) / `DesktopError::Validation` (no
/// recovery escrow onboarded yet — set up guardians first).
#[tauri::command]
pub async fn recovery_create_backup(
    password: String,
    state: State<'_, VaultState>,
) -> Result<BackupDto, DesktopError> {
    let handle = state.require_open()?;
    let pw = SecretPassword::new(password.into_bytes());
    let backup = pangolin_ffi::vault_create_backup(handle, pw).map_err(DesktopError::from)?;
    Ok(backup.into())
}

/// **Read-only recovery health** for this vault — the current on-chain
/// authority + any in-flight recovery. Chain reads → `spawn_blocking`.
///
/// # Errors
/// `DesktopError::Session` (locked) / `DesktopError::Chain` (the vault is
/// not set up on-chain for recovery, or the read failed — the UX shows
/// "recovery status unavailable").
#[tauri::command]
pub async fn recovery_health(
    state: State<'_, VaultState>,
) -> Result<RecoveryHealthDto, DesktopError> {
    let handle = state.require_open()?;
    let vault_id =
        pangolin_ffi::vault_current_vault_id(handle.clone()).map_err(DesktopError::from)?;
    let config = chain_config()?;
    tokio::task::spawn_blocking(move || {
        let authority = pangolin_ffi::vault_read_vault_authority(
            handle.clone(),
            config.clone(),
            vault_id.clone(),
        )
        .map_err(DesktopError::from)?;
        let status = pangolin_ffi::vault_read_recovery_status(handle, config, vault_id)
            .map_err(DesktopError::from)?;
        Ok::<RecoveryHealthDto, DesktopError>(RecoveryHealthDto {
            authority: hex_encode(&authority.address),
            recovery_status: status.status,
            proposed_authority: hex_encode(&status.proposed_authority),
            attempt_nonce: status.attempt_nonce,
        })
    })
    .await
    .map_err(|e| DesktopError::Internal(format!("recovery-health task join failed: {e}")))?
}

// ---------------------------------------------------------------------------
// MVP-4-L L-A — guardian-onboarding wizard surface
// ---------------------------------------------------------------------------

/// A guardian invite — the non-secret `(x25519_sealing_pub, signer)` pair
/// (32 + 20 bytes) plus the two transport forms produced by L-0b. Mirrors
/// `pangolin_ffi::FfiGuardianInvite`.
///
/// Every field is non-secret. The owner ingests these (one per guardian)
/// via the wizard's paste flow (Q-a = Option 1 paste-only); both pubkey
/// fields then feed `recovery_onboard_guardians` (off-chain) and
/// `recovery_set_guardian_set` (on-chain).
#[derive(Debug, Clone, Serialize)]
pub struct GuardianInviteDto {
    /// 64-char hex of the 32-byte X25519 sealing pubkey. The off-chain
    /// Shamir share for this guardian is sealed against this key.
    pub x25519_sealing_pub: String,
    /// 40-char hex of the 20-byte secp256k1 EVM signer address. The owner
    /// commits the merkle root of all M signers on-chain.
    pub signer: String,
    /// Canonical text form (base32 + 4-byte checksum) — what the guardian
    /// originally copy-pasted. Echoed back so the UI can show / copy it.
    pub string_form: String,
}

impl From<pangolin_ffi::FfiGuardianInvite> for GuardianInviteDto {
    fn from(i: pangolin_ffi::FfiGuardianInvite) -> Self {
        Self {
            x25519_sealing_pub: hex_encode(&i.x25519_sealing_pub),
            signer: hex_encode(&i.signer),
            string_form: i.string_form,
        }
    }
}

/// Non-secret result of `recovery_onboard_guardians`.
#[derive(Debug, Clone, Serialize)]
pub struct OnboardingResultDto {
    /// The recovery-generation epoch the off-chain escrow was written at
    /// (GENESIS `0` for the first onboard on a vault).
    pub epoch: u64,
}

impl From<pangolin_ffi::FfiOnboardingResult> for OnboardingResultDto {
    fn from(o: pangolin_ffi::FfiOnboardingResult) -> Self {
        Self { epoch: o.epoch }
    }
}

/// Non-secret receipt anchor returned from any chain-mutating recovery
/// binding (currently `recovery_set_guardian_set`). Mirrors
/// `pangolin_ffi::FfiTxOutcome`.
#[derive(Debug, Clone, Serialize)]
pub struct TxOutcomeDto {
    /// 64-char hex of the 32-byte transaction hash.
    pub tx_hash: String,
    /// Block number the tx was included in (1-conf receipt).
    pub block_number: u64,
}

impl From<pangolin_ffi::FfiTxOutcome> for TxOutcomeDto {
    fn from(o: pangolin_ffi::FfiTxOutcome) -> Self {
        Self {
            tx_hash: hex_encode(&o.tx_hash),
            block_number: o.block_number,
        }
    }
}

/// Hex → byte helper for the wizard's invite pubkeys / EVM addresses.
/// Strict-length, lowercase-tolerant; rejects odd lengths + non-hex bytes
/// with a typed `Validation` error.
fn bytes_from_hex(
    hex: &str,
    label: &'static str,
    expected_len: usize,
) -> Result<Vec<u8>, DesktopError> {
    let s = hex.trim().trim_start_matches("0x");
    if s.len() != expected_len * 2 {
        return Err(DesktopError::Validation {
            kind: "argument".into(),
            message: format!(
                "{label} must be {} hex chars (got {})",
                expected_len * 2,
                s.len()
            ),
        });
    }
    let mut out = Vec::with_capacity(expected_len);
    let bytes = s.as_bytes();
    for chunk in bytes.chunks(2) {
        let hi = hex_nibble(chunk[0], label)?;
        let lo = hex_nibble(chunk[1], label)?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_nibble(b: u8, label: &'static str) -> Result<u8, DesktopError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(DesktopError::Validation {
            kind: "argument".into(),
            message: format!("{label} contains non-hex byte"),
        }),
    }
}

/// **THIS DEVICE.** Export this device's guardian identity — the same
/// non-secret `(x25519_sealing_pub, signer)` pair another vault's owner
/// would commit. Used by the L-A wizard for the self-as-guardian guard
/// (Q-d): the wizard refuses any ingested invite whose pubkey matches.
///
/// Session-gated FFI-side. No chain.
///
/// # Errors
/// `DesktopError::Session` (locked) / `DesktopError::Store`.
#[tauri::command]
pub async fn guardian_identity_export(
    state: State<'_, VaultState>,
) -> Result<GuardianInviteDto, DesktopError> {
    let handle = state.require_open()?;
    let invite =
        pangolin_ffi::vault_export_guardian_identity(handle).map_err(DesktopError::from)?;
    Ok(invite.into())
}

/// **Pure decode** (no handle, no session). Decode a guardian-supplied
/// invite TEXT (base32 + 4-byte checksum, as produced by
/// `guardian_identity_export`'s `string_form`) into the structured DTO.
/// Length-strict + domain-checked + version-gated FFI-side.
///
/// The wizard accepts a pasted invite — this is the only ingest path
/// under Q-a = Option 1 (paste-only). The host can derive the bytes form
/// from a future QR-render flow without a new command if needed.
///
/// # Errors
/// `DesktopError::Validation { kind = "argument" }` for any decode failure.
#[tauri::command]
pub async fn guardian_invite_decode_text(text: String) -> Result<GuardianInviteDto, DesktopError> {
    let invite = pangolin_ffi::guardian_invite_decode_string(text).map_err(DesktopError::from)?;
    Ok(invite.into())
}

/// **OWNER, step 1 of 2.** Seed the off-chain recovery escrow: Shamir-split
/// a fresh `RecoveryWrapKey` into `M` shares + seal each to the matching
/// guardian's X25519 sealing pubkey + persist the roster. `x25519_pubs` is
/// the M hex-encoded pubkeys (each exactly 64 hex chars) collected from
/// the guardian invites; `threshold` is `t`. The FFI revalidates t/M
/// bounds (the contract requires `t ∈ 2..=9`, `M ∈ 3..=15`, `t ≤ M`).
///
/// Local crypto — no chain — runs inline.
///
/// # Self-as-guardian — UI gate only
///
/// The underlying [`pangolin_ffi::vault_onboard_guardians`] does NOT refuse
/// THIS device's own sealing pubkey (see the FFI's "Self-as-guardian"
/// section). The `SetupGuardiansWizard.tsx` Q-d guard is the sole
/// enforcement; if a future caller bypasses the wizard (devtools direct
/// invoke, a new screen) the gate is lost. This wrapper deliberately
/// stays stateless to keep the FFI-mirroring policy uniform.
///
/// # Errors
/// `DesktopError::Session` (locked) / `DesktopError::Validation` (bad
/// pubkey length / out-of-bounds bounds) / `DesktopError::Store` (DB).
#[tauri::command]
pub async fn recovery_onboard_guardians(
    threshold: u8,
    x25519_pubs: Vec<String>,
    state: State<'_, VaultState>,
) -> Result<OnboardingResultDto, DesktopError> {
    let handle = state.require_open()?;
    let mut pubs_bytes = Vec::with_capacity(x25519_pubs.len());
    for (idx, hex) in x25519_pubs.iter().enumerate() {
        pubs_bytes.push(bytes_from_hex(hex, "guardian X25519 pubkey", 32).map_err(
            |e| match e {
                DesktopError::Validation { kind, message } => DesktopError::Validation {
                    kind,
                    message: format!("guardian #{idx}: {message}"),
                },
                other => other,
            },
        )?);
    }
    let outcome = pangolin_ffi::vault_onboard_guardians(handle, threshold, pubs_bytes)
        .map_err(DesktopError::from)?;
    Ok(outcome.into())
}

/// **OWNER, step 2 of 2.** Commit the on-chain guardian merkle root +
/// self-bootstrap this device's EVM wallet as the initial `vaultAuthority`.
/// `evm_addrs` is the M hex-encoded 20-byte addresses from the guardian
/// invites; `threshold` is `t`. The FFI computes the merkle root engine-
/// side (host never supplies it) and broadcasts `setGuardianSet` on the
/// pinned `RecoveryV2` deployment.
///
/// On a partial-onboarding state (step 1 already succeeded for a prior
/// attempt + step 2 failed), the contract reverts
/// `ErrGuardianSetAlreadyInitialized` on a successful re-attempt — the
/// frontend detects this as "already done" per the L-A Q-c plan.
///
/// Chain broadcast → `spawn_blocking`.
///
/// # Errors
/// `DesktopError::Session` (locked) / `DesktopError::Validation` (bad
/// address length) / `DesktopError::Chain` (RPC / revert / receipt).
#[tauri::command]
pub async fn recovery_set_guardian_set(
    password: String,
    evm_addrs: Vec<String>,
    threshold: u8,
    state: State<'_, VaultState>,
) -> Result<TxOutcomeDto, DesktopError> {
    let handle = state.require_open()?;
    let mut addr_bytes = Vec::with_capacity(evm_addrs.len());
    for (idx, hex) in evm_addrs.iter().enumerate() {
        addr_bytes.push(
            bytes_from_hex(hex, "guardian EVM address", 20).map_err(|e| match e {
                DesktopError::Validation { kind, message } => DesktopError::Validation {
                    kind,
                    message: format!("guardian #{idx}: {message}"),
                },
                other => other,
            })?,
        );
    }
    let config = chain_config()?;
    let pw = SecretPassword::new(password.into_bytes());
    let outcome = tokio::task::spawn_blocking(move || {
        pangolin_ffi::vault_set_guardian_set(handle, pw, config, addr_bytes, threshold)
    })
    .await
    .map_err(|e| DesktopError::Internal(format!("set-guardian-set task join failed: {e}")))?
    .map_err(DesktopError::from)?;
    Ok(outcome.into())
}

// ---------------------------------------------------------------------------
// MVP-4-L L-C — guardian-side help wizard surface
// ---------------------------------------------------------------------------

/// The parsed shape of a recovery request blob the recovering user pasted
/// to the guardian. JSON wire format under base64-of-JSON envelope; field
/// shapes are validated at decode time (hex lengths, non-empty roster,
/// numeric bounds). Mirrors the parameter set of `vault_approve_recovery`
/// + `vault_guardian_release_share` so the wizard can extract subsets.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RecoveryRequestDto {
    /// 64-char hex of the 32-byte target vault id (the recovering user's
    /// vault — the one whose authority will rotate on finalize).
    pub vault_id: String,
    /// Per-attempt scope (RecoveryV2 attemptNonce).
    pub attempt_nonce: u64,
    /// 40-char hex of the 20-byte EVM address the authority would rotate
    /// to (the recovering user's NEW manager device's signer).
    pub proposed_authority: String,
    /// 64-char hex of the 32-byte X25519 ephemeral pubkey the recovering
    /// user generated for this attempt. The on-chain
    /// `RecoveryV2.recipientCommitment` was set to this value at
    /// `initiateRecovery` time; the engine refuses to release if the
    /// chain doesn't agree (Decision B).
    pub recipient_commitment: String,
    /// Hex of the variable-length sealed share bytes that were
    /// (originally, at onboarding time) sealed to THIS guardian's pubkey.
    /// The recoverer carries these in their backup envelope.
    pub sealed_share: String,
    /// 32-char hex of the 16-byte escrow generation epoch.
    pub epoch: String,
    /// Hex-encoded `M` guardian EVM addresses (40 chars each). The
    /// guardian's signer is matched to one of these by the engine; the
    /// engine builds the merkle proof itself.
    pub guardian_set: Vec<String>,
    /// Unix-seconds expiry of the guardian's approval EIP-712 signature.
    /// If `now > expires_at` the contract reverts `ErrApprovalExpired`.
    pub expires_at: u64,
}

/// Wire result of `recovery_help_release` — the non-secret
/// re-sealed-share ciphertext bytes (in hex, suitable for paste-text),
/// ready for the guardian to copy back to the recovering user.
#[derive(Debug, Clone, Serialize)]
pub struct ReleaseResultDto {
    /// Hex of the `SealedShareForRecoverer` ciphertext. NON-SECRET —
    /// authentication-protected by the recoverer's per-attempt key.
    pub sealed_share_for_recoverer: String,
}

/// **Pure decode** (no handle, no session). Parse a recovery-request
/// blob the guardian pasted from the recovering user. Format is
/// base64-of-JSON; field shapes are validated.
///
/// # Errors
/// `DesktopError::Validation { kind = "argument" }` for any decode
/// failure (base64 / JSON / field shape).
#[tauri::command]
pub async fn recovery_decode_request(text: String) -> Result<RecoveryRequestDto, DesktopError> {
    use base64::Engine as _;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err(DesktopError::Validation {
            kind: "argument".into(),
            message: "recovery request must not be empty".into(),
        });
    }
    let json_bytes = base64::engine::general_purpose::STANDARD
        .decode(trimmed)
        .map_err(|e| DesktopError::Validation {
            kind: "argument".into(),
            message: format!("recovery request: base64 decode failed: {e}"),
        })?;
    let parsed: RecoveryRequestDto =
        serde_json::from_slice(&json_bytes).map_err(|e| DesktopError::Validation {
            kind: "argument".into(),
            message: format!("recovery request: JSON parse failed: {e}"),
        })?;
    // Validate hex-field shapes at decode time so downstream FFI calls
    // never get malformed input AND so a paste error fails loud at the
    // earliest possible point. Variable-length sealed_share is just
    // length-non-zero; the engine validates the rest at open time.
    let _ = bytes_from_hex(&parsed.vault_id, "vault_id", 32)?;
    let _ = bytes_from_hex(&parsed.proposed_authority, "proposed_authority", 20)?;
    let _ = bytes_from_hex(&parsed.recipient_commitment, "recipient_commitment", 32)?;
    let _ = bytes_from_hex(&parsed.epoch, "epoch", 16)?;
    if parsed.sealed_share.is_empty() || !parsed.sealed_share.len().is_multiple_of(2) {
        return Err(DesktopError::Validation {
            kind: "argument".into(),
            message: "sealed_share must be non-empty hex with even length".into(),
        });
    }
    if parsed.guardian_set.is_empty() {
        return Err(DesktopError::Validation {
            kind: "argument".into(),
            message: "guardian_set must be non-empty".into(),
        });
    }
    for (idx, addr) in parsed.guardian_set.iter().enumerate() {
        bytes_from_hex(addr, "guardian_set entry", 20).map_err(|e| match e {
            DesktopError::Validation { kind, message } => DesktopError::Validation {
                kind,
                message: format!("guardian_set[{idx}]: {message}"),
            },
            other => other,
        })?;
    }
    if parsed.expires_at == 0 {
        return Err(DesktopError::Validation {
            kind: "argument".into(),
            message: "expires_at must be non-zero".into(),
        });
    }
    // Audit LOW-2: the contract guarantees `attemptNonce >= 1` after a
    // successful `initiateRecovery` (RecoveryV2.sol — `newNonce =
    // rec.attemptNonce + 1`), so a request with attempt_nonce == 0 can
    // never match a live attempt — fail loud at decode rather than
    // burning an RPC.
    if parsed.attempt_nonce == 0 {
        return Err(DesktopError::Validation {
            kind: "argument".into(),
            message: "attempt_nonce must be >= 1 (contract starts nonces at 1)".into(),
        });
    }
    // Audit LOW-2: RecoveryV2.initiateRecovery rejects an all-zero
    // proposedAuthority (ErrZeroValue), so a request carrying one can
    // never match a real live attempt.
    let proposed_bytes = bytes_from_hex(&parsed.proposed_authority, "proposed_authority", 20)?;
    if proposed_bytes.iter().all(|&b| b == 0) {
        return Err(DesktopError::Validation {
            kind: "argument".into(),
            message: "proposed_authority must not be the zero address".into(),
        });
    }
    Ok(parsed)
}

/// **GUARDIAN, step 1 of 2.** Sign + broadcast the V2 Approve on-chain
/// for the recovering user's attempt. Wraps `vault_approve_recovery`:
/// engine reads the LIVE PENDING attempt + asserts the host-supplied
/// `(attempt_nonce, proposed_authority)` match (L11 fail-closed), builds
/// the EIP-712 V2 digest binding the on-chain `recipientCommitment`,
/// signs with the active session's EVM signer, broadcasts.
///
/// Chain broadcast → `spawn_blocking`.
///
/// # Errors
/// `DesktopError::Session` (locked) / `DesktopError::Validation` (bad
/// hex / arg lengths) / `DesktopError::Chain` (RPC / live-attempt drift
/// / contract revert).
#[tauri::command]
pub async fn recovery_help_approve(
    vault_id: String,
    attempt_nonce: u64,
    proposed_authority: String,
    expires_at: u64,
    guardian_set: Vec<String>,
    state: State<'_, VaultState>,
) -> Result<TxOutcomeDto, DesktopError> {
    let handle = state.require_open()?;
    let vault_id_bytes = bytes_from_hex(&vault_id, "vault_id", 32)?;
    let proposed_authority_bytes = bytes_from_hex(&proposed_authority, "proposed_authority", 20)?;
    let mut roster_bytes = Vec::with_capacity(guardian_set.len());
    for (idx, addr) in guardian_set.iter().enumerate() {
        roster_bytes.push(
            bytes_from_hex(addr, "guardian_set entry", 20).map_err(|e| match e {
                DesktopError::Validation { kind, message } => DesktopError::Validation {
                    kind,
                    message: format!("guardian_set[{idx}]: {message}"),
                },
                other => other,
            })?,
        );
    }
    let config = chain_config()?;
    let outcome = tokio::task::spawn_blocking(move || {
        pangolin_ffi::vault_approve_recovery(
            handle,
            config,
            vault_id_bytes,
            attempt_nonce,
            proposed_authority_bytes,
            expires_at,
            roster_bytes,
        )
    })
    .await
    .map_err(|e| DesktopError::Internal(format!("approve-recovery task join failed: {e}")))?
    .map_err(DesktopError::from)?;
    Ok(outcome.into())
}

/// **GUARDIAN, step 2 of 2.** Open the guardian's stored sealed share +
/// re-seal it to the recovering user's per-attempt ephemeral pubkey.
/// Wraps `vault_guardian_release_share`: engine verifies the on-chain
/// `recipientCommitment` matches the host-supplied value (Decision B
/// anti-redirect, the load-bearing gate — FFI Phase 1) BEFORE opening
/// the share; the cleartext piece never crosses the FFI; only the
/// non-secret `SealedShareForRecoverer` bytes return.
///
/// Chain read + local crypto → `spawn_blocking`.
///
/// # Errors
/// `DesktopError::Session` (locked) / `DesktopError::Validation` (bad
/// hex / commitment mismatch / live-attempt status mismatch / open or
/// re-seal cryptographic failure) / `DesktopError::Chain` (RPC).
#[tauri::command]
pub async fn recovery_help_release(
    vault_id: String,
    attempt_nonce: u64,
    recipient_commitment: String,
    sealed_share: String,
    epoch: String,
    state: State<'_, VaultState>,
) -> Result<ReleaseResultDto, DesktopError> {
    let handle = state.require_open()?;
    let vault_id_bytes = bytes_from_hex(&vault_id, "vault_id", 32)?;
    let recipient_commitment_bytes =
        bytes_from_hex(&recipient_commitment, "recipient_commitment", 32)?;
    let epoch_bytes = bytes_from_hex(&epoch, "epoch", 16)?;
    let sealed_share_bytes = bytes_from_hex_variable(&sealed_share, "sealed_share")?;
    let config = chain_config()?;
    let result_bytes = tokio::task::spawn_blocking(move || {
        pangolin_ffi::vault_guardian_release_share(
            handle,
            sealed_share_bytes,
            vault_id_bytes,
            epoch_bytes,
            attempt_nonce,
            recipient_commitment_bytes,
            config,
        )
    })
    .await
    .map_err(|e| DesktopError::Internal(format!("guardian-release task join failed: {e}")))?
    .map_err(DesktopError::from)?;
    Ok(ReleaseResultDto {
        sealed_share_for_recoverer: hex_encode(&result_bytes),
    })
}

/// Variable-length hex → bytes helper (for the `sealed_share` blob which
/// has no fixed length — it's the variable-size sealed-box ciphertext).
/// Strict even BYTE-length on the trimmed input (i.e. `s.len()` in `u8`
/// units, not graphemes — multi-byte UTF-8 input is safely rejected by
/// `hex_nibble` per-byte but its byte-length is what the gate counts).
/// Strict even byte-length only; empty input rejected.
fn bytes_from_hex_variable(hex: &str, label: &'static str) -> Result<Vec<u8>, DesktopError> {
    let s = hex.trim().trim_start_matches("0x");
    if s.is_empty() || !s.len().is_multiple_of(2) {
        return Err(DesktopError::Validation {
            kind: "argument".into(),
            message: format!(
                "{label} must be non-empty hex with even length (got {})",
                s.len()
            ),
        });
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for chunk in bytes.chunks(2) {
        let hi = hex_nibble(chunk[0], label)?;
        let lo = hex_nibble(chunk[1], label)?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `recovery_create_backup` first-line guard: errors `Session` when no
    /// vault is open. Mirrors the `require_open()` shape at the top of every
    /// recovery handler — exercising it via `VaultState::default()` proves
    /// the closed-vault path is fail-closed without needing a Tauri runtime.
    #[tokio::test]
    async fn recovery_create_backup_with_no_vault_open_errors_session() {
        let state = VaultState::default();
        let err = state.require_open().expect_err("no vault");
        assert!(matches!(err, DesktopError::Session(_)));
    }

    /// `recovery_health` first-line guard: same fail-closed contract.
    /// Calling the chain layer in this state would be both wasteful and
    /// unsound — the guard short-circuits before the spawn_blocking RPC.
    #[tokio::test]
    async fn recovery_health_with_no_vault_open_errors_session() {
        let state = VaultState::default();
        let err = state.require_open().expect_err("no vault");
        assert!(matches!(err, DesktopError::Session(_)));
    }

    /// L-A: each handle-bearing onboarding command first-line-guards on
    /// `require_open`. Mirror the L-D LOW-2 pattern + the precedent at
    /// vault.rs::vault_lock_with_no_vault_open_errors_session.
    #[tokio::test]
    async fn guardian_identity_export_with_no_vault_open_errors_session() {
        let state = VaultState::default();
        let err = state.require_open().expect_err("no vault");
        assert!(matches!(err, DesktopError::Session(_)));
    }

    #[tokio::test]
    async fn recovery_onboard_guardians_with_no_vault_open_errors_session() {
        let state = VaultState::default();
        let err = state.require_open().expect_err("no vault");
        assert!(matches!(err, DesktopError::Session(_)));
    }

    #[tokio::test]
    async fn recovery_set_guardian_set_with_no_vault_open_errors_session() {
        let state = VaultState::default();
        let err = state.require_open().expect_err("no vault");
        assert!(matches!(err, DesktopError::Session(_)));
    }

    /// `guardian_invite_decode_text` is PURE — no handle, no session — so
    /// the closed-vault path doesn't apply. Smoke that bad-input fails
    /// closed with a typed Validation error instead.
    #[tokio::test]
    async fn guardian_invite_decode_text_rejects_empty() {
        let err = guardian_invite_decode_text(String::new())
            .await
            .expect_err("empty must fail decode");
        assert!(matches!(err, DesktopError::Validation { .. }));
    }

    /// Hex parser rejects malformed input with a typed Validation error
    /// (lengthbound + non-hex byte). Defends both onboard + set-guardian-set
    /// commands.
    #[test]
    fn bytes_from_hex_rejects_short_and_nonhex() {
        let too_short = bytes_from_hex("aa", "test pubkey", 32).expect_err("len");
        assert!(matches!(too_short, DesktopError::Validation { .. }));

        // Right length, contains a non-hex character (the 'z').
        let bad_char = "z".repeat(40);
        let nonhex = bytes_from_hex(&bad_char, "test addr", 20).expect_err("nonhex");
        assert!(matches!(nonhex, DesktopError::Validation { .. }));
    }

    /// Hex parser tolerates the 0x prefix + uppercase hex.
    #[test]
    fn bytes_from_hex_accepts_prefix_and_mixed_case() {
        let v = bytes_from_hex("0xAabb", "test", 2).expect("ok");
        assert_eq!(v, vec![0xaa, 0xbb]);
    }

    /// L-C: closed-vault rejection on the two session-gated commands.
    #[tokio::test]
    async fn recovery_help_approve_with_no_vault_open_errors_session() {
        let state = VaultState::default();
        let err = state.require_open().expect_err("no vault");
        assert!(matches!(err, DesktopError::Session(_)));
    }

    #[tokio::test]
    async fn recovery_help_release_with_no_vault_open_errors_session() {
        let state = VaultState::default();
        let err = state.require_open().expect_err("no vault");
        assert!(matches!(err, DesktopError::Session(_)));
    }

    /// L-C decoder smoke: empty input fails closed.
    #[tokio::test]
    async fn recovery_decode_request_rejects_empty() {
        let err = recovery_decode_request(String::new())
            .await
            .expect_err("empty must fail decode");
        assert!(matches!(err, DesktopError::Validation { .. }));
    }

    /// L-C decoder: bad base64 fails closed.
    #[tokio::test]
    async fn recovery_decode_request_rejects_bad_base64() {
        let err = recovery_decode_request("!!!not-base64!!!".into())
            .await
            .expect_err("bad base64");
        assert!(matches!(err, DesktopError::Validation { .. }));
    }

    /// L-C decoder: valid base64 + invalid JSON fails closed.
    #[tokio::test]
    async fn recovery_decode_request_rejects_non_json_payload() {
        use base64::Engine as _;
        let payload = base64::engine::general_purpose::STANDARD.encode(b"not json");
        let err = recovery_decode_request(payload)
            .await
            .expect_err("not json");
        assert!(matches!(err, DesktopError::Validation { .. }));
    }

    /// L-C decoder: valid base64-of-JSON with wrong-length hex fields
    /// fails closed at the field-validation step.
    #[tokio::test]
    async fn recovery_decode_request_rejects_wrong_length_hex() {
        use base64::Engine as _;
        let bad = serde_json::json!({
            "vault_id": "aa", // too short — should be 64 chars
            "attempt_nonce": 1,
            "proposed_authority": "cc".repeat(20),
            "recipient_commitment": "dd".repeat(32),
            "sealed_share": "ee".repeat(32),
            "epoch": "ff".repeat(16),
            "guardian_set": ["aa".repeat(20)],
            "expires_at": 100,
        });
        let payload =
            base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&bad).unwrap());
        let err = recovery_decode_request(payload)
            .await
            .expect_err("wrong length");
        assert!(matches!(err, DesktopError::Validation { .. }));
    }

    /// L-C decoder happy path: well-formed payload round-trips.
    #[tokio::test]
    async fn recovery_decode_request_accepts_well_formed_payload() {
        use base64::Engine as _;
        let good = serde_json::json!({
            "vault_id": "aa".repeat(32),
            "attempt_nonce": 7,
            "proposed_authority": "bb".repeat(20),
            "recipient_commitment": "cc".repeat(32),
            "sealed_share": "dd".repeat(40),
            "epoch": "ee".repeat(16),
            "guardian_set": ["aa".repeat(20), "bb".repeat(20), "cc".repeat(20)],
            "expires_at": 100,
        });
        let payload =
            base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&good).unwrap());
        let dto = recovery_decode_request(payload).await.expect("decode ok");
        assert_eq!(dto.attempt_nonce, 7);
        assert_eq!(dto.expires_at, 100);
        assert_eq!(dto.guardian_set.len(), 3);
    }

    /// L-C decoder audit LOW-2: rejects attempt_nonce == 0 (contract
    /// guarantees attemptNonce >= 1 after initiateRecovery).
    #[tokio::test]
    async fn recovery_decode_request_rejects_zero_attempt_nonce() {
        use base64::Engine as _;
        let bad = serde_json::json!({
            "vault_id": "aa".repeat(32),
            "attempt_nonce": 0,
            "proposed_authority": "bb".repeat(20),
            "recipient_commitment": "cc".repeat(32),
            "sealed_share": "dd".repeat(40),
            "epoch": "ee".repeat(16),
            "guardian_set": ["aa".repeat(20), "bb".repeat(20), "cc".repeat(20)],
            "expires_at": 100,
        });
        let payload =
            base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&bad).unwrap());
        let err = recovery_decode_request(payload)
            .await
            .expect_err("zero nonce");
        match err {
            DesktopError::Validation { ref message, .. } => {
                assert!(message.contains("attempt_nonce"));
            }
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    /// L-C decoder audit LOW-2: rejects all-zero proposed_authority
    /// (contract rejects ErrZeroValue at initiate, so this can never
    /// match a live attempt).
    #[tokio::test]
    async fn recovery_decode_request_rejects_zero_proposed_authority() {
        use base64::Engine as _;
        let bad = serde_json::json!({
            "vault_id": "aa".repeat(32),
            "attempt_nonce": 1,
            "proposed_authority": "00".repeat(20),
            "recipient_commitment": "cc".repeat(32),
            "sealed_share": "dd".repeat(40),
            "epoch": "ee".repeat(16),
            "guardian_set": ["aa".repeat(20), "bb".repeat(20), "cc".repeat(20)],
            "expires_at": 100,
        });
        let payload =
            base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&bad).unwrap());
        let err = recovery_decode_request(payload)
            .await
            .expect_err("zero authority");
        match err {
            DesktopError::Validation { ref message, .. } => {
                assert!(message.contains("zero address"));
            }
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    /// `bytes_from_hex_variable` smoke: rejects empty + odd-length;
    /// accepts even-length hex.
    #[test]
    fn bytes_from_hex_variable_rejects_empty_and_odd() {
        let err = bytes_from_hex_variable("", "test").expect_err("empty");
        assert!(matches!(err, DesktopError::Validation { .. }));
        let err = bytes_from_hex_variable("aaa", "test").expect_err("odd");
        assert!(matches!(err, DesktopError::Validation { .. }));
        let v = bytes_from_hex_variable("0xAaBb", "test").expect("ok");
        assert_eq!(v, vec![0xaa, 0xbb]);
    }

    #[test]
    fn backup_dto_projects_phrase_and_envelope() {
        let ffi = pangolin_ffi::FfiBackup {
            schema_version: 1,
            bytes: vec![1, 2, 3],
            text: "envelope-text".into(),
            seed_phrase_words: vec!["alpha".into(), "bravo".into()],
        };
        let dto: BackupDto = ffi.into();
        assert_eq!(dto.seed_phrase_words, vec!["alpha", "bravo"]);
        assert_eq!(dto.bytes, vec![1, 2, 3]);
        assert_eq!(dto.text, "envelope-text");
    }

    #[test]
    fn hex_encode_round_trip() {
        assert_eq!(hex_encode(&[0xab, 0xcd]), "abcd");
        assert_eq!(hex_encode(&[]), "");
    }
}
