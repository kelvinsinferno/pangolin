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
            | Self::DeviceBindingInvalid => StatusCode::BAD_REQUEST,
            Self::AlreadyRedeemed => StatusCode::CONFLICT,
            Self::ChainSubmit { .. } => StatusCode::BAD_GATEWAY,
            Self::Ledger | Self::Keystore(_) | Self::Configuration(_) | Self::Internal => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
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
}

impl IntoResponse for FunderError {
    fn into_response(self) -> Response {
        let status = self.status();
        let body = ErrorBody {
            error: self.class(),
            retry_after_seconds: match &self {
                Self::RateLimited {
                    retry_after_seconds,
                } => Some(*retry_after_seconds),
                _ => None,
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
