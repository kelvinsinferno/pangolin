// SPDX-License-Identifier: AGPL-3.0-or-later
//! Funder error taxonomy.
//!
//! `FunderError` is the unified error surface across handlers, signer,
//! ledger, and chain submission. axum's `IntoResponse` impl below
//! maps each variant to an HTTP status + JSON body. Per L12: the
//! body contains a short error-class string ONLY — no internal state,
//! no user identifiers, no signature bytes.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use thiserror::Error;

use pangolin_chain::ChainError;

use crate::ledger::LedgerError;

/// Errors surfaced by the funder service.
///
/// Each variant carries the minimum information needed to produce
/// the wire response + a short operator-facing log line. Internal
/// state (user identifiers, signature bytes, contract addresses
/// beyond what's in the health response) is NEVER part of any
/// `Display` form here.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum FunderError {
    /// Rate limit tripped (per-address or global). HTTP 429.
    #[error("rate limited (retry_after_seconds={retry_after_seconds})")]
    RateLimited {
        /// Seconds the caller should wait before retrying.
        retry_after_seconds: u64,
    },

    /// Request body failed deserialisation or structural validation.
    /// HTTP 400 with a generic `bad_request` class.
    #[error("bad request")]
    BadRequest,

    /// The Credit attestation's EIP-712 signature did not recover to
    /// the cached `PAYMENT_AUTHORITY`. HTTP 400.
    #[error("credit attestation signature invalid")]
    CreditSigInvalid,

    /// The Credit attestation's `expiresAt` is in the past per the
    /// funder's wall clock. HTTP 400.
    #[error("credit attestation expired")]
    CreditExpired,

    /// The Credit attestation's `schema_version` is greater than the
    /// funder + contract's `MAX_KNOWN_SCHEMA_VERSION`. HTTP 400.
    #[error("credit schema version unsupported")]
    CreditSchemaUnsupported,

    /// Device-binding signature mismatch — either the structural
    /// shape was bad, or the recovered signer did not equal the
    /// claimed `device_address`. HTTP 400 with the uniform
    /// `device_binding_invalid` class (R-g — no leak of which
    /// sub-check failed).
    #[error("device binding invalid")]
    DeviceBindingInvalid,

    /// Off-chain replay: the `attestation_hash` already exists in the
    /// payment ledger. HTTP 409.
    #[error("attestation already redeemed")]
    AlreadyRedeemed,

    /// Chain-submit failure. The wrapped class is a short tag for the
    /// operator log; the body returns 502 with a generic
    /// `chain_submit_failed` class.
    #[error("chain submit failed: {class}")]
    ChainSubmit {
        /// Short class tag — one of the `ChainError` variant names.
        class: &'static str,
    },

    /// The Credit attestation's `amount` exceeds the funder's per-tx
    /// ETH-transfer hard cap (L-DOS-eth-drain). HTTP 400. Per the
    /// L-payment-order doctrine: fail closed BEFORE the redemption tx
    /// so the user's on-chain balance is preserved. Wei values are
    /// rendered as hex strings in the response body to avoid surfacing
    /// `U256` decimal arithmetic in JSON.
    #[error("eth transfer cap exceeded")]
    EthTransferCapExceeded {
        /// Requested wei (from the Credit attestation amount).
        observed_wei: alloy::primitives::U256,
        /// Per-tx cap in wei.
        cap_wei: u128,
    },

    /// The redemption tx mined successfully but the ETH-transfer leg
    /// failed (RPC timeout, insufficient hot-wallet balance, transfer
    /// reverted). HTTP 500. The response body includes the redeem
    /// tx hash so the operator can manually reconcile per the
    /// funder runbook.
    #[error("eth transfer failed (class={class})")]
    EthTransferFailed {
        /// 32-byte hash of the successfully-mined redemption tx. The
        /// user's balance was debited; manual recovery via the
        /// funder runbook is required.
        redeem_tx_hash: alloy::primitives::B256,
        /// Short class tag — one of the `ChainError` variant names.
        class: &'static str,
    },

    /// Ledger write failed. HTTP 500.
    #[error("ledger operation failed")]
    Ledger,

    /// Keystore load / decryption failed. Surfaced only at startup;
    /// the server fails fast and exits.
    #[error("keystore load failed: {0}")]
    Keystore(String),

    /// Internal misconfiguration (e.g., env var missing). Surfaced
    /// only at startup; the server fails fast and exits.
    #[error("configuration error: {0}")]
    Configuration(String),

    /// Internal server error — used as a catch-all for I/O failures,
    /// channel-closed-errors, etc.
    #[error("internal server error")]
    Internal,
}

impl FunderError {
    /// Short error-class string for the JSON response body. Used by
    /// the handler in lieu of the variant name (which can leak
    /// implementation details).
    #[must_use]
    pub const fn class(&self) -> &'static str {
        match self {
            Self::RateLimited { .. } => "rate_limited",
            Self::BadRequest => "bad_request",
            Self::CreditSigInvalid => "credit_signature_invalid",
            Self::CreditExpired => "credit_expired",
            Self::CreditSchemaUnsupported => "credit_schema_unsupported",
            Self::DeviceBindingInvalid => "device_binding_invalid",
            Self::AlreadyRedeemed => "already_redeemed",
            Self::ChainSubmit { .. } => "chain_submit_failed",
            Self::EthTransferCapExceeded { .. } => "eth_transfer_cap_exceeded",
            Self::EthTransferFailed { .. } => "eth_transfer_failed",
            Self::Ledger => "ledger_error",
            Self::Keystore(_) | Self::Configuration(_) => "configuration_error",
            Self::Internal => "internal_error",
        }
    }

    /// HTTP status code for this variant.
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        match self {
            Self::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
            Self::BadRequest
            | Self::CreditSigInvalid
            | Self::CreditExpired
            | Self::CreditSchemaUnsupported
            | Self::DeviceBindingInvalid
            | Self::EthTransferCapExceeded { .. } => StatusCode::BAD_REQUEST,
            Self::AlreadyRedeemed => StatusCode::CONFLICT,
            Self::ChainSubmit { .. } => StatusCode::BAD_GATEWAY,
            Self::EthTransferFailed { .. }
            | Self::Ledger
            | Self::Keystore(_)
            | Self::Configuration(_)
            | Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl From<ChainError> for FunderError {
    fn from(e: ChainError) -> Self {
        // Map every ChainError variant onto a short class tag. The
        // funder's HTTP response carries the class only; the
        // operator log carries the full `ChainError::Display`.
        let class = match e {
            ChainError::WrongChain { .. } | ChainError::ChainIdMismatch { .. } => {
                "chain_id_mismatch"
            }
            ChainError::Deployment(_)
            | ChainError::DeploymentNotFound { .. }
            | ChainError::DeploymentParseError { .. }
            | ChainError::DeploymentAddressMismatch { .. }
            | ChainError::DeploymentMismatch { .. } => "deployment_misconfigured",
            ChainError::Rpc(_) | ChainError::RpcTransient { .. } => "rpc_transient",
            ChainError::Decode(_) => "decode_error",
            ChainError::Reverted { .. }
            | ChainError::RevertedOnChain { .. }
            | ChainError::RevertedPreBroadcast { .. } => "contract_reverted",
            ChainError::MissingEvent { .. } => "missing_event",
            ChainError::Wallet(_) => "wallet_error",
            ChainError::Keystore(_) => "keystore_error",
            ChainError::Io(_) => "io_error",
            ChainError::SignatureInvalid => "signature_invalid",
            ChainError::InsufficientFunds { .. } => "insufficient_funds",
            ChainError::GasCapExceeded { .. } => "gas_cap_exceeded",
            ChainError::NonceUnresolvable { .. } => "nonce_unresolvable",
            ChainError::ReceiptMismatch { .. } => "receipt_mismatch",
            _ => "chain_error_other",
        };
        Self::ChainSubmit { class }
    }
}

impl From<LedgerError> for FunderError {
    fn from(_: LedgerError) -> Self {
        // The handler converts `AlreadyExists` separately before
        // mapping into `FunderError`; any other ledger error here
        // is an internal failure.
        Self::Ledger
    }
}

/// JSON body shape for funder error responses.
#[derive(Debug, serde::Serialize)]
pub struct ErrorBody {
    /// Short error-class string. Stable across releases.
    pub error: &'static str,
    /// Present only on rate-limit responses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_seconds: Option<u64>,
    /// Present only on `eth_transfer_cap_exceeded` responses. Hex
    /// string (`0x...`) representation of the requested wei value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_wei: Option<String>,
    /// Present only on `eth_transfer_cap_exceeded` responses. Hex
    /// string representation of the configured cap (wei).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cap_wei: Option<String>,
    /// Present only on `eth_transfer_failed` responses. The 32-byte
    /// redeem tx hash the operator uses for manual recovery.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redeem_tx_hash: Option<String>,
    /// Present only on `eth_transfer_failed` responses. When the
    /// `eth_transfer_failed` class is set, this serialises as JSON
    /// `null` so the client always sees the key (matching the success
    /// response's `eth_transfer_tx_hash` field shape but with no
    /// value). Skipped entirely on other error classes.
    #[serde(skip_serializing_if = "EthTransferTxField::is_absent")]
    pub eth_transfer_tx_hash: EthTransferTxField,
}

/// Marker for the `eth_transfer_tx_hash` field in the
/// `eth_transfer_failed` error body. Serialises as JSON `null` when
/// `Present`, omitted when `Absent`.
#[derive(Debug, Default, Clone, Copy)]
pub enum EthTransferTxField {
    /// Field not in this response.
    #[default]
    Absent,
    /// Field present but value is `null` (the transfer failed; the
    /// redeem tx hash carries the recoverable identity).
    PresentNull,
}

impl EthTransferTxField {
    #[must_use]
    pub const fn is_absent(&self) -> bool {
        matches!(self, Self::Absent)
    }
}

impl serde::Serialize for EthTransferTxField {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        match self {
            // Absent variants are filtered by `is_absent` upstream.
            Self::Absent | Self::PresentNull => ser.serialize_none(),
        }
    }
}

impl IntoResponse for FunderError {
    fn into_response(self) -> Response {
        let status = self.status();
        let body = match &self {
            Self::RateLimited {
                retry_after_seconds,
            } => ErrorBody {
                error: self.class(),
                retry_after_seconds: Some(*retry_after_seconds),
                observed_wei: None,
                cap_wei: None,
                redeem_tx_hash: None,
                eth_transfer_tx_hash: EthTransferTxField::Absent,
            },
            Self::EthTransferCapExceeded {
                observed_wei,
                cap_wei,
            } => ErrorBody {
                error: self.class(),
                retry_after_seconds: None,
                observed_wei: Some(format!("0x{observed_wei:x}")),
                cap_wei: Some(format!("0x{cap_wei:x}")),
                redeem_tx_hash: None,
                eth_transfer_tx_hash: EthTransferTxField::Absent,
            },
            Self::EthTransferFailed { redeem_tx_hash, .. } => ErrorBody {
                error: self.class(),
                retry_after_seconds: None,
                observed_wei: None,
                cap_wei: None,
                redeem_tx_hash: Some(format!("{redeem_tx_hash:?}")),
                eth_transfer_tx_hash: EthTransferTxField::PresentNull,
            },
            _ => ErrorBody {
                error: self.class(),
                retry_after_seconds: None,
                observed_wei: None,
                cap_wei: None,
                redeem_tx_hash: None,
                eth_transfer_tx_hash: EthTransferTxField::Absent,
            },
        };
        let json = Json(body);
        // Add the standards-compliant `Retry-After` header for
        // 429 responses.
        if let Self::RateLimited {
            retry_after_seconds,
        } = self
        {
            let mut response = (status, json).into_response();
            if let Ok(val) = axum::http::HeaderValue::from_str(&retry_after_seconds.to_string()) {
                response
                    .headers_mut()
                    .insert(axum::http::header::RETRY_AFTER, val);
            }
            return response;
        }
        (status, json).into_response()
    }
}
