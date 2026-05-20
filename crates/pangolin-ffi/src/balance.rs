// SPDX-License-Identifier: AGPL-3.0-or-later
//! Gas-balance FFI shapes + entry points (MVP-2 issue 3.5, R-d).
//!
//! Wires [`pangolin_chain::BalanceMonitor`] across the FFI boundary so
//! the host can:
//!
//! 1. Start the background-poll task at session-open with
//!    [`balance_monitor_start`].
//! 2. Read the cached state via [`gas_balance_state`] (non-blocking
//!    sync call from the host thread).
//! 3. Stop the task at session-close with [`balance_monitor_stop`].
//!
//! Active-session policy lives HERE at the FFI boundary (L5 nuance):
//! the chain-crate balance helper is policy-agnostic, but locked-vault
//! callers crossing FFI get `FfiError::Session`.
//!
//! ## Surface vocabulary (L4 + §8.1.5)
//!
//! [`GasBalanceStateFfi`]'s variant names mirror
//! [`pangolin_chain::GasBalanceState`] verbatim — `Sufficient` /
//! `RequiresActiveAccount` / `TopUpInFlight` / `Unknown`. NEVER pricing
//! copy. Wei values cross as **hex strings** (`String`) to preserve
//! u128 fidelity through uniffi (u64 max is only ~18.4 ETH in wei,
//! which is small enough to overflow on a funded mainnet wallet).

use std::sync::Arc;

use alloy::primitives::Address;
use pangolin_chain::{BalanceMonitor, ChainEnv, GasBalanceState};

use crate::error::FfiError;
use crate::session::VaultHandle;

// ---------------------------------------------------------------------
// FFI-friendly mirror of GasBalanceState
// ---------------------------------------------------------------------

/// FFI-mirror of [`pangolin_chain::GasBalanceState`].
///
/// Variant names follow the §8.1.5 entitlement-state vocabulary
/// verbatim. Wei values cross as hex strings (`"0x..."`) so a 100 ETH
/// wallet (above u64 max wei) doesn't truncate.
///
/// **NEVER renamed** to a pricing-copy variant — the variant strings
/// are user-facing through host rendering and §8.1.5 forbids
/// `InsufficientFunds` / `LowBalance` / `OutOfGas` / `Upgrade` /
/// pricing copy.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum GasBalanceStateFfi {
    /// Wallet balance covers `MIN_BUFFER_REVISIONS = 3` future
    /// revisions at the currently-observed gas price.
    Sufficient {
        /// `"0x..."` hex string of the wallet balance in wei.
        balance_wei_hex: String,
        /// `"0x..."` hex string of the next-publish cost estimate in wei.
        estimate_wei_hex: String,
    },
    /// Wallet balance does NOT cover the 3-revision threshold; host
    /// renders the §8.1.5 `RequiresActiveAccount` flow.
    RequiresActiveAccount {
        balance_wei_hex: String,
        estimate_wei_hex: String,
    },
    /// A top-up flow is in flight; the next poll will observe the new
    /// balance.
    TopUpInFlight {
        /// Unix-second timestamp when the top-up was initiated.
        initiated_at_unix: u64,
    },
    /// State could not be determined (RPC failure, locked vault,
    /// monitor not yet polled, etc.).
    Unknown {
        /// Non-secret human description of the unknown cause.
        reason: String,
    },
}

impl From<GasBalanceState> for GasBalanceStateFfi {
    fn from(state: GasBalanceState) -> Self {
        match state {
            GasBalanceState::Sufficient {
                balance_wei,
                estimate_wei,
            } => Self::Sufficient {
                balance_wei_hex: format!("0x{balance_wei:x}"),
                estimate_wei_hex: format!("0x{estimate_wei:x}"),
            },
            GasBalanceState::RequiresActiveAccount {
                balance_wei,
                estimate_wei,
            } => Self::RequiresActiveAccount {
                balance_wei_hex: format!("0x{balance_wei:x}"),
                estimate_wei_hex: format!("0x{estimate_wei:x}"),
            },
            GasBalanceState::TopUpInFlight { initiated_at_unix } => {
                Self::TopUpInFlight { initiated_at_unix }
            }
            GasBalanceState::Unknown { reason } => Self::Unknown { reason },
        }
    }
}

// ---------------------------------------------------------------------
// MonitorHandle (FFI Object)
// ---------------------------------------------------------------------

/// Opaque handle to a running [`pangolin_chain::BalanceMonitor`].
///
/// The host obtains one via [`balance_monitor_start`], reads cached
/// state via [`gas_balance_state`], and disposes via
/// [`balance_monitor_stop`]. Cloning the `Arc` is cheap; the underlying
/// background task runs on the active tokio runtime.
#[derive(uniffi::Object)]
pub struct MonitorHandle {
    inner: BalanceMonitor,
}

impl std::fmt::Debug for MonitorHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MonitorHandle").finish()
    }
}

// ---------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------

fn store_into_ffi(err: pangolin_store::StoreError) -> FfiError {
    FfiError::from(pangolin_core::Error::from(err))
}

/// Active-session gate: borrow the vault `&mut`, error
/// `FfiError::Session` on locked / placeholder.
///
/// L5 FFI policy: balance reads require an active session at this
/// boundary (the chain-crate helper is policy-agnostic; the policy
/// lives here). `as_mut` errors on a placeholder; we also want to
/// reject a LOCKED-but-previously-unlocked vault. The `evm_wallet`
/// accessor handles that: locked vault → `StoreError::NotUnlocked`.
#[allow(clippy::significant_drop_tightening)]
fn require_unlocked(handle: &Arc<VaultHandle>) -> Result<(), FfiError> {
    let mut guard = handle.lock_vault();
    let vault = guard.as_mut()?;
    let _ = vault.evm_wallet().map_err(store_into_ffi)?;
    Ok(())
}

// ---------------------------------------------------------------------
// FFI entry points
// ---------------------------------------------------------------------

/// Start the background-poll balance monitor.
///
/// The host calls this once at session-open (or whenever it wants to
/// begin observing balance), stashes the returned handle, and reads
/// state via [`gas_balance_state`] until calling
/// [`balance_monitor_stop`] at teardown.
///
/// **Active-session gate** (L5 FFI policy): a locked vault errors
/// `FfiError::Session`. The chain-crate helper is policy-agnostic; the
/// policy lives at the FFI boundary.
///
/// # Arguments
///
/// - `handle` — the vault handle. Must be unlocked. Used to read the
///   cached `devices.evm_address` (sync), then released.
/// - `rpc_url` — RPC endpoint URL.
/// - `poll_interval_secs` — interval between background polls. Pass
///   `pangolin_chain::BALANCE_POLL_INTERVAL_SECS` (= 30) for the
///   default cadence.
///
/// # Errors
///
/// `FfiError::Session` for a locked / placeholder handle;
/// `FfiError::Store` if the device row's `evm_address` column is
/// missing (legacy pre-3.2 row); `FfiError::Validation` for an
/// out-of-range `poll_interval_secs` of `0`.
#[allow(clippy::significant_drop_tightening)]
#[uniffi::export]
pub fn balance_monitor_start(
    handle: Arc<VaultHandle>,
    rpc_url: String,
    poll_interval_secs: u64,
) -> Result<Arc<MonitorHandle>, FfiError> {
    if poll_interval_secs == 0 {
        return Err(FfiError::Validation {
            kind: "argument".into(),
            message: "poll_interval_secs must be > 0".into(),
        });
    }
    // Read the address with the vault guard held only briefly so the
    // monitor's tokio spawn doesn't keep the mutex.
    let address_bytes = {
        let mut guard = handle.lock_vault();
        let vault = guard.as_mut()?;
        // Active-session gate at the FFI boundary (L5): require a live
        // session before starting the monitor. Locked vault →
        // FfiError::Session.
        let _ = vault.evm_wallet().map_err(store_into_ffi)?;
        vault.evm_wallet_address().map_err(store_into_ffi)?
    };
    let address = Address::from(address_bytes);
    // 3.5 ships against Base Sepolia only (master plan §5 row 3.5).
    let env = ChainEnv::BaseSepolia;
    let poll_interval = core::time::Duration::from_secs(poll_interval_secs);
    let monitor = BalanceMonitor::start(rpc_url, address, env, poll_interval);
    Ok(Arc::new(MonitorHandle { inner: monitor }))
}

/// Stop a running balance monitor. Idempotent: a second stop is a
/// no-op.
#[uniffi::export]
pub async fn balance_monitor_stop(monitor: Arc<MonitorHandle>) -> Result<(), FfiError> {
    monitor.inner.stop().await;
    Ok(())
}

/// Read the cached gas-balance state.
///
/// **Active-session gate** (L5 FFI policy): a locked vault errors
/// `FfiError::Session`.
///
/// Returns a [`GasBalanceStateFfi`] that mirrors the chain crate's
/// `GasBalanceState`. The wei fields cross as hex strings so a 100 ETH
/// balance doesn't truncate.
///
/// # Errors
///
/// `FfiError::Session` for a locked / placeholder handle.
#[allow(clippy::significant_drop_tightening)]
#[uniffi::export]
pub fn gas_balance_state(
    handle: Arc<VaultHandle>,
    monitor: Arc<MonitorHandle>,
) -> Result<GasBalanceStateFfi, FfiError> {
    require_unlocked(&handle)?;
    let state = monitor.inner.current();
    Ok(GasBalanceStateFfi::from(state))
}

// ---------------------------------------------------------------------
// CLI-V1 (R-g) — vault_initiate_top_up stub
// ---------------------------------------------------------------------

/// FFI mirror of [`pangolin_funder_client::TopUpAttempt`].
///
/// CLI-V1 (R-g). Carries the client-generated attempt id (UUID
/// as a string), the funder's tx hashes, and the unix-second
/// submission timestamp.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiTopUpAttempt {
    /// Schema-version slot.
    pub schema_version: u16,
    /// Client-generated v4 UUID, as a string.
    pub attempt_id: String,
    /// Funder's `redeem` tx hash (`0x...` hex).
    pub redeem_tx_hash: String,
    /// ETH-transfer tx hash (`0x...` hex). `None` when the
    /// transfer leg failed (operator reconciliation required).
    pub eth_transfer_tx_hash: Option<String>,
    /// Wei transferred, as a `"0x..."` hex string. `"0x0"` when
    /// the transfer leg failed.
    pub eth_transferred_wei_hex: String,
    /// Unix-second timestamp when the POST was issued.
    pub submitted_at_unix: u64,
}

/// FFI mirror of [`pangolin_funder_client::Credit`] (MVP-3 issue
/// #100 R-c).
///
/// The Credit attestation the host obtains from the off-chain payment
/// service. Byte fields cross as hex strings (`0x`-prefixed accepted)
/// per the established convention; `nonce` / `schema_version` /
/// `expires_at` cross as integers. The [`FfiCredit`]→`Credit` reshape
/// is a single TOTAL function with strict hex-decode + length
/// validation (see [`ffi_credit_to_credit`]); malformed input → a
/// clear `FfiError::Validation`. The reshape is fail-safe: the Credit
/// signature binds the semantic fields and is verified downstream by
/// the funder + on-chain `ecrecover`, so any corruption → signature
/// mismatch → REJECTED, never a silent mis-bind.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiCredit {
    /// Schema-version slot (the FFI-wire transport version, distinct
    /// from the Credit's own `schema_version` event field below).
    pub schema_version: u16,
    /// Opaque user identifier — 32-byte hex string (`0x`-prefixed
    /// accepted).
    pub user_id_hex: String,
    /// Credits to add — `U256` as a hex string (`0x`-prefixed
    /// accepted).
    pub amount_hex: String,
    /// Nonce embedded in the attestation (strict-equality at submit).
    pub nonce: u64,
    /// Event-schema version of the Credit (the funder rejects values
    /// above `MAX_KNOWN_SCHEMA_VERSION`).
    pub credit_schema_version: u16,
    /// Unix timestamp after which the attestation expires.
    pub expires_at: u64,
    /// 65-byte `r || s || v` signature from `PAYMENT_AUTHORITY` — hex
    /// string (`0x`-prefixed accepted).
    pub signature_hex: String,
}

/// Schema-version slot value for [`FfiCredit`].
pub const FFI_CREDIT_SCHEMA_VERSION: u16 = 1;

/// Decode a hex string (optional `0x`/`0X` prefix) into exactly
/// `expected_len` bytes. TOTAL: any malformed input → a clear
/// `FfiError::Validation { kind: "credit" }`.
fn decode_hex_exact(field: &str, s: &str, expected_len: usize) -> Result<Vec<u8>, FfiError> {
    let stripped = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    let bytes = hex_decode(stripped).ok_or_else(|| FfiError::Validation {
        kind: "credit".into(),
        message: format!("credit field `{field}` is not valid hex"),
    })?;
    if bytes.len() != expected_len {
        return Err(FfiError::Validation {
            kind: "credit".into(),
            message: format!(
                "credit field `{field}` length mismatch: expected {expected_len} bytes, got {}",
                bytes.len()
            ),
        });
    }
    Ok(bytes)
}

/// Decode a lowercase/uppercase hex string into bytes. `None` on any
/// non-hex byte or an odd length.
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        out.push(u8::try_from(hi * 16 + lo).ok()?);
        i += 2;
    }
    Some(out)
}

/// TOTAL [`FfiCredit`]→[`pangolin_funder_client::Credit`] reshape with
/// strict hex-decode + length validation (R-c). Malformed → a clear
/// `FfiError::Validation { kind: "credit" }`.
fn ffi_credit_to_credit(c: &FfiCredit) -> Result<pangolin_funder_client::Credit, FfiError> {
    let user_id_vec = decode_hex_exact("user_id", &c.user_id_hex, 32)?;
    let user_id: [u8; 32] = user_id_vec
        .as_slice()
        .try_into()
        .expect("decode_hex_exact guarantees 32 bytes");
    let sig_vec = decode_hex_exact("signature", &c.signature_hex, 65)?;
    let signature: [u8; 65] = sig_vec
        .as_slice()
        .try_into()
        .expect("decode_hex_exact guarantees 65 bytes");
    let amount_stripped = c
        .amount_hex
        .strip_prefix("0x")
        .or_else(|| c.amount_hex.strip_prefix("0X"))
        .unwrap_or(&c.amount_hex);
    let amount = alloy::primitives::U256::from_str_radix(amount_stripped, 16).map_err(|e| {
        FfiError::Validation {
            kind: "credit".into(),
            message: format!("credit field `amount` is not a valid hex U256: {e}"),
        }
    })?;
    Ok(pangolin_funder_client::Credit {
        user_id,
        amount,
        nonce: c.nonce,
        schema_version: c.credit_schema_version,
        expires_at: c.expires_at,
        signature,
    })
}

/// Request a top-up from the funder service.
///
/// **MVP-3 issue #100 (R-c / R-d).** Reshapes the host-supplied
/// [`FfiCredit`] into a [`pangolin_funder_client::Credit`] (TOTAL,
/// strict-validating), reads the device's gas-paying signer
/// engine-side from the unlocked vault (`Vault::evm_wallet().signer()`
/// — cloned engine-side; **no secret material crosses FFI**, L1), and
/// drives [`pangolin_funder_client::initiate_top_up`] to completion on
/// a local current-thread runtime.
///
/// # Errors
///
/// `FfiError::Session` for a locked / placeholder handle (the L4
/// session gate, before any chain primitive);
/// `FfiError::Validation { kind: "credit" }` for a malformed
/// `FfiCredit`; `FfiError::Chain` for a funder / transport / signing
/// failure.
#[allow(clippy::significant_drop_tightening, clippy::needless_pass_by_value)]
#[uniffi::export]
pub fn vault_initiate_top_up(
    handle: Arc<VaultHandle>,
    funder_url: String,
    credit: FfiCredit,
) -> Result<FfiTopUpAttempt, FfiError> {
    // Reshape the Credit BEFORE acquiring the vault guard (no vault
    // state needed for validation; keeps the lock window short).
    let credit = ffi_credit_to_credit(&credit)?;
    // Active-session gate at the FFI boundary (L4) + read the gas
    // signer engine-side. L1: the signer is cloned from the unlocked
    // vault and never crosses FFI.
    let signer = {
        let mut guard = handle.lock_vault();
        let vault = guard.as_mut()?;
        vault.evm_wallet().map_err(store_into_ffi)?.signer().clone()
    };
    // `initiate_top_up`'s future IS `Send` (no `!Send` vault held
    // across the await), but the host calls this binding synchronously
    // from a worker thread, so we drive it on a local runtime for
    // posture parity with the other chain bindings.
    let attempt = crate::chain_config::block_on_local(async {
        pangolin_funder_client::initiate_top_up(&funder_url, credit, &signer)
            .await
            .map_err(|e| FfiError::Chain {
                message: e.to_string(),
            })
    })??;
    Ok(FfiTopUpAttempt {
        schema_version: 1,
        attempt_id: attempt.attempt_id.to_string(),
        redeem_tx_hash: format!(
            "0x{}",
            hex_encode_lower(attempt.funder_response.redeem_tx_hash.as_slice())
        ),
        eth_transfer_tx_hash: attempt
            .funder_response
            .eth_transfer_tx_hash
            .map(|h| format!("0x{}", hex_encode_lower(h.as_slice()))),
        eth_transferred_wei_hex: format!("0x{:x}", attempt.funder_response.eth_transferred_wei),
        submitted_at_unix: attempt.submitted_at_unix,
    })
}

/// Lowercase hex-encode helper (local — keeps the dep set tight,
/// mirrors the funder client's own `hex_encode`).
fn hex_encode_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::VaultHandle;
    use pangolin_core::{PinIdentityProof, PressYPresenceProof, Vault};
    use pangolin_crypto::secret::SecretBytes;
    use std::sync::Arc;

    fn pwd() -> SecretBytes {
        SecretBytes::new(b"correct horse battery staple".to_vec())
    }

    fn unlocked_handle(dir: &tempfile::TempDir, name: &str) -> Arc<VaultHandle> {
        let path = dir.path().join(name);
        Vault::create(&path, &pwd()).unwrap();
        let mut v = Vault::open(&path).unwrap();
        v.unlock(
            &PressYPresenceProof::confirmed(),
            &PinIdentityProof::new(pwd()),
        )
        .unwrap();
        VaultHandle::from_vault(v)
    }

    /// Locked vault → `FfiError::Session` from `gas_balance_state`.
    #[tokio::test]
    async fn ffi_gas_balance_state_requires_active_session() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        // Start a monitor while unlocked.
        let monitor = balance_monitor_start(Arc::clone(&h), "http://127.0.0.1:1".to_string(), 60)
            .expect("monitor start while unlocked");
        // Now lock the vault.
        {
            let mut guard = h.lock_vault();
            guard.as_mut().unwrap().lock();
        }
        // gas_balance_state must error.
        let err = gas_balance_state(Arc::clone(&h), Arc::clone(&monitor)).unwrap_err();
        assert!(
            matches!(err, FfiError::Session { .. }),
            "expected FfiError::Session, got {err:?}"
        );
        // Teardown.
        balance_monitor_stop(monitor).await.unwrap();
    }

    /// Full lifecycle: start, read, stop. The sync `gas_balance_state`
    /// accessor uses `tokio::sync::RwLock::blocking_read` internally;
    /// production FFI callers invoke it from the HOST's main thread
    /// (NOT from inside the runtime). The test harness simulates that
    /// via `spawn_blocking` on a multi-threaded runtime — calling
    /// `blocking_read` directly from a worker thread of a current-
    /// thread runtime panics with "Cannot block the current thread
    /// from within a runtime".
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ffi_balance_monitor_start_stop_lifecycle() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        let monitor = balance_monitor_start(Arc::clone(&h), "http://127.0.0.1:1".to_string(), 60)
            .expect("monitor start");
        let h_clone = Arc::clone(&h);
        let m_clone = Arc::clone(&monitor);
        let _state =
            tokio::task::spawn_blocking(move || gas_balance_state(h_clone, m_clone).unwrap())
                .await
                .unwrap();
        balance_monitor_stop(Arc::clone(&monitor)).await.unwrap();
        // Idempotent.
        balance_monitor_stop(monitor).await.unwrap();
    }

    /// An unlocked vault returns SOME state from `gas_balance_state`
    /// (likely `Unknown` since the bogus `rpc_url` errors).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ffi_gas_balance_state_returns_state_when_unlocked() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        let monitor = balance_monitor_start(Arc::clone(&h), "http://127.0.0.1:1".to_string(), 60)
            .expect("monitor start");
        let h_clone = Arc::clone(&h);
        let m_clone = Arc::clone(&monitor);
        let state =
            tokio::task::spawn_blocking(move || gas_balance_state(h_clone, m_clone).unwrap())
                .await
                .unwrap();
        // Any of the variants is valid for the initial / first-poll
        // window. We only assert it doesn't panic + we got a typed
        // shape.
        match state {
            GasBalanceStateFfi::Sufficient { .. }
            | GasBalanceStateFfi::RequiresActiveAccount { .. }
            | GasBalanceStateFfi::TopUpInFlight { .. }
            | GasBalanceStateFfi::Unknown { .. } => {}
        }
        balance_monitor_stop(monitor).await.unwrap();
    }

    /// Placeholder handle → `FfiError::Session` from
    /// `balance_monitor_start`.
    #[test]
    fn ffi_balance_monitor_start_rejects_placeholder_handle() {
        let empty = VaultHandle::new_placeholder();
        let err = balance_monitor_start(empty, "http://127.0.0.1:1".to_string(), 60).unwrap_err();
        assert!(
            matches!(err, FfiError::Session { .. }),
            "expected FfiError::Session, got {err:?}"
        );
    }

    /// Zero poll interval rejected as `Validation`.
    #[test]
    fn ffi_balance_monitor_start_rejects_zero_interval() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        let err = balance_monitor_start(h, "http://127.0.0.1:1".to_string(), 0).unwrap_err();
        assert!(
            matches!(&err, FfiError::Validation { kind, .. } if kind == "argument"),
            "expected FfiError::Validation, got {err:?}"
        );
    }

    // -----------------------------------------------------------------
    // MVP-3 #100: vault_initiate_top_up + FfiCredit reshape.
    // -----------------------------------------------------------------

    /// A well-formed [`FfiCredit`] (hex fields, `0x`-prefix optional).
    fn valid_ffi_credit() -> FfiCredit {
        FfiCredit {
            schema_version: FFI_CREDIT_SCHEMA_VERSION,
            user_id_hex: format!("0x{}", "aa".repeat(32)),
            amount_hex: "0x1e240".into(), // 123456
            nonce: 7,
            credit_schema_version: 1,
            expires_at: 2_000_000_000,
            signature_hex: "bb".repeat(65), // no 0x prefix → also accepted
        }
    }

    /// **MVP-3 #100 (R-c) — TOTAL reshape, happy path.** A well-formed
    /// `FfiCredit` reshapes field-for-field into a
    /// `pangolin_funder_client::Credit`, with `0x`-prefixed and
    /// bare-hex byte fields both accepted.
    #[test]
    fn ffi_credit_to_credit_round_trips_valid_fields() {
        let credit = ffi_credit_to_credit(&valid_ffi_credit()).expect("valid credit reshapes");
        assert_eq!(credit.user_id, [0xAAu8; 32]);
        assert_eq!(credit.amount, alloy::primitives::U256::from(123_456u64));
        assert_eq!(credit.nonce, 7);
        assert_eq!(credit.schema_version, 1);
        assert_eq!(credit.expires_at, 2_000_000_000);
        assert_eq!(credit.signature, [0xBBu8; 65]);
    }

    /// **MVP-3 #100 (R-c) — TOTAL reshape, malformed cases.** Each
    /// malformed byte field surfaces `FfiError::Validation { kind:
    /// "credit" }` — no panic, no silent mis-bind.
    #[test]
    fn ffi_credit_to_credit_rejects_malformed_fields() {
        // user_id wrong length.
        let mut c = valid_ffi_credit();
        c.user_id_hex = "0xaa".into();
        assert!(matches!(
            ffi_credit_to_credit(&c),
            Err(FfiError::Validation { ref kind, .. }) if kind == "credit"
        ));
        // signature non-hex.
        let mut c = valid_ffi_credit();
        c.signature_hex = "zz".repeat(65);
        assert!(matches!(
            ffi_credit_to_credit(&c),
            Err(FfiError::Validation { ref kind, .. }) if kind == "credit"
        ));
        // amount non-hex.
        let mut c = valid_ffi_credit();
        c.amount_hex = "0xnothex".into();
        assert!(matches!(
            ffi_credit_to_credit(&c),
            Err(FfiError::Validation { ref kind, .. }) if kind == "credit"
        ));
    }

    /// **MVP-3 #100 (R-f) — per-binding session gate (L4).** A
    /// malformed credit is rejected BEFORE the session gate (validation
    /// runs first, no vault state needed); a placeholder handle with a
    /// VALID credit errors `FfiError::Session` before any funder call.
    #[test]
    fn initiate_top_up_rejects_placeholder_before_funder_call() {
        let empty = VaultHandle::new_placeholder();
        let err =
            vault_initiate_top_up(empty, "http://127.0.0.1:1".to_string(), valid_ffi_credit())
                .unwrap_err();
        assert!(
            matches!(err, FfiError::Session { .. }),
            "expected FfiError::Session, got {err:?}"
        );
    }

    /// **MVP-3 #100 (R-c) — malformed credit rejected at the boundary
    /// even on an unlocked vault.**
    #[test]
    fn initiate_top_up_rejects_malformed_credit() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        let mut bad = valid_ffi_credit();
        bad.signature_hex = "0x00".into(); // wrong length
        let err = vault_initiate_top_up(h, "http://127.0.0.1:1".to_string(), bad).unwrap_err();
        assert!(
            matches!(&err, FfiError::Validation { kind, .. } if kind == "credit"),
            "expected FfiError::Validation(credit), got {err:?}"
        );
    }

    /// **MVP-3 #100 (R-d / R-f) — REAL-path stub-parity flip against a
    /// mock funder.** The binding sources the gas signer engine-side
    /// (no secret crosses FFI), reshapes the Credit, and POSTs to a
    /// wiremock funder; a 200 response decodes into a real
    /// `FfiTopUpAttempt` (NOT the old `Internal` stub). Runs on a
    /// multi-thread runtime so the binding's inner current-thread
    /// `block_on_local` is driven from a worker thread (the production
    /// host posture), exactly like `gas_balance_state`'s lifecycle test.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn initiate_top_up_real_path_against_mock_funder() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock = MockServer::start().await;
        let response_body = serde_json::json!({
            "redeem_tx_hash": "0x1111111111111111111111111111111111111111111111111111111111111111",
            "eth_transfer_tx_hash": "0x2222222222222222222222222222222222222222222222222222222222222222",
            "eth_transferred_wei": "0x16345785d8a0000"
        });
        Mock::given(method("POST"))
            .and(path("/funder/v1/top-up"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response_body))
            .mount(&mock)
            .await;
        let uri = mock.uri();

        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        let attempt =
            tokio::task::spawn_blocking(move || vault_initiate_top_up(h, uri, valid_ffi_credit()))
                .await
                .unwrap()
                .expect("top-up should succeed against mock funder");
        assert_eq!(attempt.schema_version, 1);
        assert_eq!(
            attempt.redeem_tx_hash,
            "0x1111111111111111111111111111111111111111111111111111111111111111"
        );
        assert_eq!(
            attempt.eth_transfer_tx_hash.as_deref(),
            Some("0x2222222222222222222222222222222222222222222222222222222222222222")
        );
        assert_eq!(attempt.eth_transferred_wei_hex, "0x16345785d8a0000");
        assert!(!attempt.attempt_id.is_empty());
    }

    /// **MVP-3 #100 (R-d) — skip-clean live `#[ignore]` test.** A real
    /// end-to-end top-up against the live funder backed by D-019,
    /// driven through the FFI binding. Skips cleanly when the env vars
    /// are absent (mirrors `pull_live.rs`). Requires a paid Credit
    /// attestation; the slot is reserved until one exists.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "live-funder FFI test; requires PANGOLIN_FUNDER_URL + a paid Credit"]
    async fn initiate_top_up_live_via_ffi() {
        let funder_url = match std::env::var("PANGOLIN_FUNDER_URL") {
            Ok(s) if !s.is_empty() => s,
            _ => {
                eprintln!("SKIP: PANGOLIN_FUNDER_URL not set");
                return;
            }
        };
        // A real Credit attestation would be read from
        // PANGOLIN_CREDIT_FILE here; until a paid Credit exists, skip.
        let credit_file = match std::env::var("PANGOLIN_CREDIT_FILE") {
            Ok(s) if !s.is_empty() => s,
            _ => {
                eprintln!("SKIP: PANGOLIN_CREDIT_FILE not set");
                return;
            }
        };
        let _ = (funder_url, credit_file);
        // Future: parse the credit file into an FfiCredit, build an
        // unlocked handle from a real vault, and assert the live
        // FfiTopUpAttempt shape. Reserved against D-019.
    }
}
