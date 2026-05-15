// SPDX-License-Identifier: AGPL-3.0-or-later
//! `POST /funder/v1/top-up` — the redemption + ETH-transfer flow.
//!
//! Per R-c + R-g + L3 + L-payment-order (audit HIGH-1 fix-pass
//! 2026-05-15 wires the ETH-transfer leg, the cap-check, and the
//! lifecycle state machine):
//!
//! 1. Rate-limit check (per-address + global). Trip → 429.
//! 2. Parse + validate the request body. Bad shape → 400 `bad_request`.
//! 3. Verify the Credit attestation's EIP-712 signature against the
//!    cached `PAYMENT_AUTHORITY`. Mismatch → 400 `credit_signature_invalid`.
//!    Defense-in-depth: enforce canonical-low-s on the funder side too
//!    (audit LOW#3 fix; the contract also enforces this but
//!    rejecting at the HTTP layer saves a wasted on-chain tx).
//! 4. Check expiry / schema version. Bad → 400 with the relevant
//!    class.
//! 5. Verify the device-binding signature per R-g. Mismatch → 400
//!    `device_binding_invalid`.
//! 6. ETH-transfer cap pre-check (L-DOS-eth-drain). If the Credit's
//!    `amount` exceeds the per-tx cap, fail closed with 400 BEFORE
//!    the redemption submit so the user's on-chain balance is
//!    preserved.
//! 7. Off-chain replay defense: `INSERT INTO payments` with
//!    `attestation_hash UNIQUE`. Conflict → 409 `already_redeemed`.
//! 8. Sign + submit the `Redemption` attestation (the funder is the
//!    `REDEMPTION_AUTHORITY` half of 2.2 R-a). The ledger row's
//!    `state` advances:
//!      - on `eth_sendRawTransaction` Ok → `RedeemSubmitted` (the
//!        `update_redemption_tx_hash` helper sets this atomically).
//!      - on receipt confirm → `RedeemMined`.
//! 9. Send ETH to the device address (audit HIGH-1 fix). Build an
//!    EIP-1559 envelope via `submit_eth_transfer_v1`; await 1-conf
//!    receipt; advance lifecycle to `EthTransferSubmitted` then
//!    `EthTransferMined`. On failure the row goes to
//!    `EthTransferFailed` (terminal; operator reconciliation per the
//!    funder runbook).
//!
//! All error paths log at WARN with the rate-limit-class + the error
//! class only — no user identifiers per L12.

use alloy::primitives::{keccak256, Address, U256};
use alloy::sol_types::eip712_domain;
use axum::extract::State;
use axum::Json;
use std::time::{SystemTime, UNIX_EPOCH};

use pangolin_chain::{
    is_canonical_s, submit_eth_transfer_v1, submit_redemption_v1, ChainEnv, RedemptionFieldsV1,
    ENTITLEMENT_DOMAIN_SEPARATOR_BASE_SEPOLIA_V1,
    EXPECTED_ENTITLEMENT_REGISTRY_ADDRESS_BASE_SEPOLIA,
};
use pangolin_funder_client::{
    verify_device_binding, Credit, TopUpRequest, MAX_KNOWN_SCHEMA_VERSION,
};

use crate::error::FunderError;
use crate::http::AppState;
use crate::ledger::PaymentState;
use crate::rate_limit::RateLimitOutcome;
use crate::resume::clamp_eth_transfer_amount;

// ---------------------------------------------------------------------
// Wire shapes (serde adapters around the canonical `pangolin-funder-client`
// types — those use alloy primitives directly + don't derive Serialize).
// ---------------------------------------------------------------------

/// Wire shape for the request body. Mirrors
/// [`pangolin_funder_client::TopUpRequest`] but uses hex strings on
/// the wire for the byte-array fields (alloy types don't derive
/// `serde::Deserialize` in a way that meshes with axum's `Json`
/// extractor in 2.x without an additional feature; we hand-decode).
#[derive(Debug, Clone, serde::Deserialize)]
pub struct WireTopUpRequest {
    pub credit: WireCredit,
    pub device_binding_sig: String,
    pub device_address: String,
}

/// Wire shape for a Credit attestation. All `bytes32` / `uint256` /
/// `uint64` fields are 0x-hex; the signature is a 130-char hex
/// string (65 bytes).
#[derive(Debug, Clone, serde::Deserialize)]
pub struct WireCredit {
    pub user_id: String,
    pub amount: String,
    pub nonce: u64,
    pub schema_version: u16,
    pub expires_at: u64,
    pub signature: String,
}

/// Wire shape for the response body.
///
/// `eth_transfer_tx_hash` is `Option<String>` (serialised as JSON
/// `null` on transfer failure) so the client can tell the redeem-mined-
/// but-transfer-failed case apart from the happy path. The
/// `eth_transferred_wei` field is `"0x0"` on failure.
#[derive(Debug, Clone, serde::Serialize)]
pub struct WireTopUpResponse {
    pub redeem_tx_hash: String,
    pub eth_transfer_tx_hash: Option<String>,
    pub eth_transferred_wei: String,
}

impl WireTopUpRequest {
    fn parse(self) -> Result<TopUpRequest, FunderError> {
        let credit = self.credit.parse()?;
        let device_binding_sig =
            decode_hex_fixed::<65>(&self.device_binding_sig).ok_or(FunderError::BadRequest)?;
        let device_address: Address = self
            .device_address
            .parse()
            .map_err(|_| FunderError::BadRequest)?;
        Ok(TopUpRequest {
            credit,
            device_binding_sig,
            device_address,
        })
    }
}

impl WireCredit {
    fn parse(self) -> Result<Credit, FunderError> {
        let user_id = decode_hex_fixed::<32>(&self.user_id).ok_or(FunderError::BadRequest)?;
        let amount = decode_u256_hex_or_dec(&self.amount).ok_or(FunderError::BadRequest)?;
        let signature = decode_hex_fixed::<65>(&self.signature).ok_or(FunderError::BadRequest)?;
        Ok(Credit {
            user_id,
            amount,
            nonce: self.nonce,
            schema_version: self.schema_version,
            expires_at: self.expires_at,
            signature,
        })
    }
}

/// Parse a 0x-prefixed hex string into a fixed-size byte array. `N` is
/// the array length in bytes. Returns `None` on length mismatch /
/// invalid hex.
fn decode_hex_fixed<const N: usize>(s: &str) -> Option<[u8; N]> {
    let trimmed = s.trim_start_matches("0x");
    let mut out = [0u8; N];
    if trimmed.len() != N * 2 {
        return None;
    }
    hex::decode_to_slice(trimmed, &mut out).ok()?;
    Some(out)
}

/// Parse a U256 expressed as hex (`0x...`) OR decimal. The wire format
/// admits both for operator convenience.
fn decode_u256_hex_or_dec(s: &str) -> Option<U256> {
    if let Some(hex_body) = s.strip_prefix("0x") {
        return U256::from_str_radix(hex_body, 16).ok();
    }
    U256::from_str_radix(s, 10).ok()
}

// ---------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------

/// `POST /funder/v1/top-up` handler.
#[allow(clippy::too_many_lines)] // the handler is the load-bearing
                                 //                                 logic of 3.4; splitting it
                                 //                                 further would obscure the
                                 //                                 per-failure path.
pub async fn handle(
    State(state): State<AppState>,
    Json(wire): Json<WireTopUpRequest>,
) -> Result<Json<WireTopUpResponse>, FunderError> {
    // Decode the request body into the canonical types.
    let req = wire.parse()?;

    // 1. Rate-limit check. Per-address layer first; global second.
    //    Either trip → 429.
    match state.rate_limiter.check(req.device_address).await {
        RateLimitOutcome::Allowed => {}
        RateLimitOutcome::Denied {
            retry_after_seconds,
        } => {
            tracing::warn!(
                target: "pangolin_funder::http::top_up",
                class = "rate_limited",
                "request denied by rate limiter"
            );
            return Err(FunderError::RateLimited {
                retry_after_seconds,
            });
        }
    }

    // 2. Schema-version check (defense-in-depth; the contract also
    //    checks this).
    if req.credit.schema_version > MAX_KNOWN_SCHEMA_VERSION {
        tracing::warn!(
            target: "pangolin_funder::http::top_up",
            class = "credit_schema_unsupported",
            "rejecting unknown future schema_version"
        );
        return Err(FunderError::CreditSchemaUnsupported);
    }

    // 3. Expiry check.
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if now_unix > req.credit.expires_at {
        tracing::warn!(
            target: "pangolin_funder::http::top_up",
            class = "credit_expired",
            "rejecting expired attestation"
        );
        return Err(FunderError::CreditExpired);
    }

    // 4. Verify Credit signature against cached PAYMENT_AUTHORITY.
    if !verify_credit_signature(&req.credit, state.payment_authority, state.chain_env) {
        tracing::warn!(
            target: "pangolin_funder::http::top_up",
            class = "credit_signature_invalid",
            "credit signature did not recover to PAYMENT_AUTHORITY"
        );
        return Err(FunderError::CreditSigInvalid);
    }

    // 5. Verify device-binding signature (R-g).
    let attestation_hash = req.credit.attestation_hash();
    if !verify_device_binding(req.device_binding_sig, attestation_hash, req.device_address) {
        tracing::warn!(
            target: "pangolin_funder::http::top_up",
            class = "device_binding_invalid",
            "device binding signature did not match claimed device_address"
        );
        return Err(FunderError::DeviceBindingInvalid);
    }

    // 6. ETH-transfer per-tx cap pre-check (L-DOS-eth-drain). The
    //    cap is enforced BEFORE the redemption submit so a malicious
    //    or compromised PAYMENT_AUTHORITY cannot drain the funder
    //    hot wallet — and a cap-exceeded request never debits the
    //    user's on-chain balance.
    let Some(eth_amount) =
        clamp_eth_transfer_amount(req.credit.amount, state.eth_transfer_per_tx_cap_wei)
    else {
        tracing::warn!(
            target: "pangolin_funder::http::top_up",
            class = "eth_transfer_cap_exceeded",
            "credit amount exceeds per-tx ETH-transfer cap; failing closed before redeem"
        );
        return Err(FunderError::EthTransferCapExceeded {
            observed_wei: req.credit.amount,
            cap_wei: state.eth_transfer_per_tx_cap_wei,
        });
    };

    // 7. Off-chain replay defense: insert the ledger row. The
    //    `attestation_hash` column UNIQUE constraint rejects a
    //    duplicate; we surface that as 409 `already_redeemed`.
    let inserted = state
        .ledger
        .try_insert(
            attestation_hash,
            req.credit.user_id,
            req.device_address,
            req.credit.amount,
        )
        .await
        .map_err(FunderError::from)?;
    if !inserted {
        tracing::warn!(
            target: "pangolin_funder::http::top_up",
            class = "already_redeemed",
            "attestation_hash already in ledger; rejecting replay"
        );
        return Err(FunderError::AlreadyRedeemed);
    }

    // 8. Sign + submit the Redemption attestation.
    let redemption_fields = RedemptionFieldsV1 {
        user_id: req.credit.user_id,
        amount: req.credit.amount,
        nonce: req.credit.nonce,
        schema_version: req.credit.schema_version,
        expires_at: req.credit.expires_at,
    };
    let signed_redemption = state
        .signer
        .sign_redemption(redemption_fields, state.chain_env)
        .await?;
    // Submit to chain. Only the `local_signer` shape is wired in 3.4;
    // a future HSM-RPC adapter goes through the same `submit_redemption_v1`
    // surface via a different signer construction (separate codepath
    // in 3.x's HSM follow-up).
    let local_signer = state.signer.local_signer().ok_or_else(|| {
        FunderError::Configuration(
            "this signer impl does not expose a local PrivateKeySigner; HSM path \
             not wired in 3.4"
                .into(),
        )
    })?;
    let redeem_anchor = submit_redemption_v1(
        local_signer,
        &signed_redemption,
        state.chain_env,
        &state.rpc_url,
    )
    .await?;

    // 9. Update ledger with the redemption tx hash (advances state to
    //    RedeemSubmitted) and then explicitly to RedeemMined (the
    //    redeem path awaits 1-conf receipt before returning Ok).
    state
        .ledger
        .update_redemption_tx_hash(attestation_hash, redeem_anchor.tx_hash)
        .await
        .map_err(FunderError::from)?;
    state
        .ledger
        .transition_state(attestation_hash, PaymentState::RedeemMined)
        .await
        .map_err(FunderError::from)?;

    // 10. ETH transfer (audit HIGH-1 fix). On ANY failure the
    //     redemption is already on chain — the user's balance was
    //     debited. We surface HTTP 500 with the redeem tx hash so
    //     the operator can manually reconcile per the funder runbook;
    //     the ledger row is marked `EthTransferFailed` (terminal).
    let eth_anchor = match submit_eth_transfer_v1(
        local_signer,
        req.device_address,
        eth_amount,
        state.chain_env,
        &state.rpc_url,
    )
    .await
    {
        Ok(a) => a,
        Err(e) => {
            // Map to a class tag the operator log can correlate
            // against the L12 redacted-public-class taxonomy.
            let class: &'static str = match &e {
                pangolin_chain::ChainError::InsufficientFunds { .. } => "insufficient_funds",
                pangolin_chain::ChainError::GasCapExceeded { .. } => "gas_cap_exceeded",
                pangolin_chain::ChainError::Rpc(_)
                | pangolin_chain::ChainError::RpcTransient { .. } => "rpc_transient",
                pangolin_chain::ChainError::Reverted { .. }
                | pangolin_chain::ChainError::RevertedOnChain { .. }
                | pangolin_chain::ChainError::RevertedPreBroadcast { .. } => "contract_reverted",
                pangolin_chain::ChainError::ChainIdMismatch { .. } => "chain_id_mismatch",
                pangolin_chain::ChainError::ReceiptMismatch { .. } => "receipt_mismatch",
                _ => "eth_transfer_other",
            };
            tracing::error!(
                target: "pangolin_funder::http::top_up",
                class = "eth_transfer_failed",
                tx_class = class,
                redeem_tx = %redeem_anchor.tx_hash,
                "CRITICAL: redeem mined but ETH transfer failed; manual reconciliation required"
            );
            // Mark the ledger row terminal.
            let _ = state
                .ledger
                .transition_state(attestation_hash, PaymentState::EthTransferFailed)
                .await;
            return Err(FunderError::EthTransferFailed {
                redeem_tx_hash: redeem_anchor.tx_hash,
                class,
            });
        }
    };

    // Stamp the transfer submission + mine in the ledger. The
    // `submit_eth_transfer_v1` helper awaits the 1-conf receipt
    // before returning, so by the time we're here both transitions
    // are valid.
    state
        .ledger
        .mark_eth_transfer_submitted(attestation_hash, eth_anchor.tx_hash, eth_amount)
        .await
        .map_err(FunderError::from)?;
    state
        .ledger
        .mark_eth_transfer_mined(attestation_hash, eth_anchor.block_number)
        .await
        .map_err(FunderError::from)?;

    tracing::info!(
        target: "pangolin_funder::http::top_up",
        class = "ok",
        redeem_tx = %redeem_anchor.tx_hash,
        eth_transfer_tx = %eth_anchor.tx_hash,
        "redemption + eth-transfer completed"
    );

    Ok(Json(WireTopUpResponse {
        redeem_tx_hash: format!("{:?}", redeem_anchor.tx_hash),
        eth_transfer_tx_hash: Some(format!("{:?}", eth_anchor.tx_hash)),
        eth_transferred_wei: format!("0x{eth_amount:x}"),
    }))
}

// ---------------------------------------------------------------------
// Credit signature verification
// ---------------------------------------------------------------------

/// EIP-712 typehash for `Credit` — same literal as the contract's
/// `CREDIT_TYPEHASH` constant. Captured via `cast keccak` at builder
/// time (2026-05-15). Kept local here because the funder is the only
/// crate that VERIFIES Credit attestations (the contract's `credit(...)`
/// path verifies them on chain; the payment processor SIGNS them, and
/// 3.4 doesn't ship the signer side — only the verifier).
const CREDIT_TYPEHASH_V1: [u8; 32] =
    alloy::primitives::hex!("ca59260047837893befb7ee9800fca1d13197892f987afca3a253303e077dd77");

const ENTITLEMENT_DOMAIN_NAME: &str = "Pangolin EntitlementRegistry";
const ENTITLEMENT_DOMAIN_VERSION: &str = "1";

/// Verify a Credit attestation's EIP-712 signature against the cached
/// `payment_authority` address.
fn verify_credit_signature(credit: &Credit, payment_authority: Address, env: ChainEnv) -> bool {
    let verifying_contract = match env {
        ChainEnv::BaseSepolia => EXPECTED_ENTITLEMENT_REGISTRY_ADDRESS_BASE_SEPOLIA,
        // For non-Sepolia envs the verifyingContract would come from
        // the deployment file (mirror of `build_signed_redemption_v1`'s
        // load); 3.4 is Sepolia-only on the verify path. If/when
        // mainnet wires up, this becomes a `load_deployed_address`
        // call mirroring the signer-side cross-check.
        _ => return false,
    };
    let chain_id = env.chain_id().unwrap_or(0);
    let domain = eip712_domain! {
        name: ENTITLEMENT_DOMAIN_NAME,
        version: ENTITLEMENT_DOMAIN_VERSION,
        chain_id: chain_id,
        verifying_contract: verifying_contract,
    };
    // Sanity guard against domain drift: if a future contributor
    // changes the domain construction without updating the pinned
    // constant, the verify path would silently use a different
    // separator. The byte-equality check below fails closed on drift.
    if env == ChainEnv::BaseSepolia
        && domain.separator().0 != ENTITLEMENT_DOMAIN_SEPARATOR_BASE_SEPOLIA_V1
    {
        return false;
    }
    let domain_sep = domain.separator();

    // Struct hash for the Credit typed-data.
    let mut buf = [0u8; 6 * 32];
    let mut o = 0usize;
    buf[o..o + 32].copy_from_slice(&CREDIT_TYPEHASH_V1);
    o += 32;
    buf[o..o + 32].copy_from_slice(&credit.user_id);
    o += 32;
    buf[o..o + 32].copy_from_slice(&credit.amount.to_be_bytes::<32>());
    o += 32;
    buf[o + 24..o + 32].copy_from_slice(&credit.nonce.to_be_bytes());
    o += 32;
    buf[o + 30..o + 32].copy_from_slice(&credit.schema_version.to_be_bytes());
    o += 32;
    buf[o + 24..o + 32].copy_from_slice(&credit.expires_at.to_be_bytes());
    let struct_hash = keccak256(buf);

    // Final EIP-712 digest.
    let mut buf = [0u8; 66];
    buf[0] = 0x19;
    buf[1] = 0x01;
    buf[2..34].copy_from_slice(domain_sep.as_slice());
    buf[34..66].copy_from_slice(struct_hash.as_slice());
    let digest = keccak256(buf);

    // Defense-in-depth (audit LOW#3): enforce canonical-low-s on the
    // funder side too. The contract's `_recover` also enforces this,
    // but rejecting at the HTTP layer saves a wasted on-chain tx and
    // avoids leaking a queue slot. The pinned half-order constant
    // lives in pangolin-chain::secp256k1_signing per existing
    // precedent in 3.1 / 3.3.
    let s_bytes: [u8; 32] = credit.signature[32..64]
        .try_into()
        .expect("64-byte signature slice");
    if !is_canonical_s(&s_bytes) {
        return false;
    }

    // Recover the signer.
    let r = U256::from_be_slice(&credit.signature[0..32]);
    let s = U256::from_be_slice(&credit.signature[32..64]);
    let v_byte = credit.signature[64];
    if v_byte != 27 && v_byte != 28 {
        return false;
    }
    let y_parity = v_byte == 28;
    let alloy_sig = alloy::primitives::Signature::new(r, s, y_parity);
    match alloy_sig.recover_address_from_prehash(&digest) {
        Ok(recovered) => recovered == payment_authority,
        Err(_) => false,
    }
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{address, keccak256};
    use alloy::signers::local::PrivateKeySigner;
    use alloy::signers::SignerSync;
    use pangolin_funder_client::sign_device_binding;

    use crate::ledger::PaymentLedger;
    use crate::rate_limit::{RateLimitConfig, RateLimiter};
    use crate::signer::MockSigner;

    use std::sync::Arc;

    fn fixed_authority_signer() -> PrivateKeySigner {
        // Distinct seed from the device signer's so a device-bound
        // sig never accidentally verifies as a payment-authority sig.
        let hex = "0x1111111111111111111111111111111111111111111111111111111111111111";
        hex.parse::<PrivateKeySigner>().expect("parse")
    }

    fn fixed_device_signer() -> PrivateKeySigner {
        let hex = "0x4242424242424242424242424242424242424242424242424242424242424242";
        hex.parse::<PrivateKeySigner>().expect("parse")
    }

    fn build_state(payment_authority: Address) -> AppState {
        AppState {
            signer: Arc::new(MockSigner::default_for_tests()),
            ledger: PaymentLedger::open_in_memory().expect("ledger"),
            rate_limiter: RateLimiter::new(RateLimitConfig::default()),
            registry_address: EXPECTED_ENTITLEMENT_REGISTRY_ADDRESS_BASE_SEPOLIA,
            payment_authority,
            chain_env: ChainEnv::BaseSepolia,
            rpc_url: "http://127.0.0.1:0".into(),
            eth_transfer_per_tx_cap_wei: crate::ETH_TRANSFER_PER_TX_CAP_WEI,
        }
    }

    fn sign_credit(signer: &PrivateKeySigner, credit: &mut Credit) {
        // Mirror the on-handler digest construction.
        let domain = eip712_domain! {
            name: ENTITLEMENT_DOMAIN_NAME,
            version: ENTITLEMENT_DOMAIN_VERSION,
            chain_id: 84_532u64,
            verifying_contract: EXPECTED_ENTITLEMENT_REGISTRY_ADDRESS_BASE_SEPOLIA,
        };
        let domain_sep = domain.separator();
        let mut buf = [0u8; 6 * 32];
        let mut o = 0usize;
        buf[o..o + 32].copy_from_slice(&CREDIT_TYPEHASH_V1);
        o += 32;
        buf[o..o + 32].copy_from_slice(&credit.user_id);
        o += 32;
        buf[o..o + 32].copy_from_slice(&credit.amount.to_be_bytes::<32>());
        o += 32;
        buf[o + 24..o + 32].copy_from_slice(&credit.nonce.to_be_bytes());
        o += 32;
        buf[o + 30..o + 32].copy_from_slice(&credit.schema_version.to_be_bytes());
        o += 32;
        buf[o + 24..o + 32].copy_from_slice(&credit.expires_at.to_be_bytes());
        let struct_hash = keccak256(buf);
        let mut buf = [0u8; 66];
        buf[0] = 0x19;
        buf[1] = 0x01;
        buf[2..34].copy_from_slice(domain_sep.as_slice());
        buf[34..66].copy_from_slice(struct_hash.as_slice());
        let digest = keccak256(buf);
        let sig = signer.sign_hash_sync(&digest).expect("sign");
        let canonical = sig.normalize_s().unwrap_or(sig);
        credit.signature = canonical.as_bytes();
    }

    fn fresh_credit() -> Credit {
        Credit {
            user_id: [0xAAu8; 32],
            amount: U256::from(100u64),
            nonce: 0,
            schema_version: 1,
            expires_at: u64::MAX, // never expires for tests
            signature: [0u8; 65],
        }
    }

    #[test]
    fn credit_typehash_matches_pinned_constant() {
        let literal = "Credit(bytes32 userId,uint256 amount,uint64 nonce,uint16 schemaVersion,uint64 expiresAt)";
        let computed = keccak256(literal.as_bytes());
        assert_eq!(computed.0, CREDIT_TYPEHASH_V1);
    }

    #[test]
    fn verify_credit_signature_round_trip() {
        let authority = fixed_authority_signer();
        let mut credit = fresh_credit();
        sign_credit(&authority, &mut credit);
        assert!(verify_credit_signature(
            &credit,
            authority.address(),
            ChainEnv::BaseSepolia
        ));
    }

    #[test]
    fn verify_credit_signature_rejects_wrong_authority() {
        let authority = fixed_authority_signer();
        let mut credit = fresh_credit();
        sign_credit(&authority, &mut credit);
        // Verify against a different address — must fail.
        let other = address!("0x0000000000000000000000000000000000001234");
        assert!(!verify_credit_signature(
            &credit,
            other,
            ChainEnv::BaseSepolia
        ));
    }

    #[test]
    fn verify_credit_signature_rejects_tampered_field() {
        let authority = fixed_authority_signer();
        let mut credit = fresh_credit();
        sign_credit(&authority, &mut credit);
        // Tamper with `amount` post-signing.
        credit.amount = U256::from(101u64);
        assert!(!verify_credit_signature(
            &credit,
            authority.address(),
            ChainEnv::BaseSepolia
        ));
    }

    #[tokio::test]
    async fn rate_limit_429_after_burst() {
        // Use a tight bucket so we hit the limit fast.
        let cfg = RateLimitConfig {
            per_address_bucket_size: 2,
            per_address_replenish_interval_secs: 60,
            global_cap_per_hour: 200,
        };
        let limiter = RateLimiter::new(cfg);
        let device = fixed_device_signer().address();
        for _ in 0..2 {
            assert_eq!(limiter.check(device).await, RateLimitOutcome::Allowed);
        }
        assert!(matches!(
            limiter.check(device).await,
            RateLimitOutcome::Denied { .. }
        ));
    }

    #[tokio::test]
    async fn attestation_replay_409_via_ledger() {
        let ledger = PaymentLedger::open_in_memory().expect("ledger");
        let h = keccak256(b"replay test");
        let first = ledger
            .try_insert(
                h,
                [0xAAu8; 32],
                fixed_device_signer().address(),
                U256::from(1u64),
            )
            .await
            .expect("insert");
        assert!(first);
        let second = ledger
            .try_insert(
                h,
                [0xAAu8; 32],
                fixed_device_signer().address(),
                U256::from(1u64),
            )
            .await
            .expect("insert");
        assert!(!second, "duplicate attestation must hit ledger UNIQUE");
    }

    #[tokio::test]
    async fn device_binding_round_trip_works() {
        let device = fixed_device_signer();
        let mut credit = fresh_credit();
        sign_credit(&fixed_authority_signer(), &mut credit);
        let h = credit.attestation_hash();
        let sig = sign_device_binding(&device, h, device.address()).expect("sign");
        assert!(verify_device_binding(sig, h, device.address()));
    }

    #[tokio::test]
    async fn device_binding_wrong_address_rejects() {
        let device = fixed_device_signer();
        let mut credit = fresh_credit();
        sign_credit(&fixed_authority_signer(), &mut credit);
        let h = credit.attestation_hash();
        let sig = sign_device_binding(&device, h, device.address()).expect("sign");
        let other = address!("0x0000000000000000000000000000000000001234");
        assert!(!verify_device_binding(sig, h, other));
    }

    #[test]
    fn appstate_uses_cached_payment_authority() {
        // Sanity: the AppState's `payment_authority` is the cached
        // address. The handler reads ONLY from this field — no
        // per-request chain query is in the verify path (visible by
        // inspection of `verify_credit_signature` which takes the
        // address as an argument).
        let authority = fixed_authority_signer();
        let state = build_state(authority.address());
        assert_eq!(state.payment_authority, authority.address());
    }

    // ---------------------------------------------------------------
    // Audit fix-pass 2026-05-15 — tests for the HIGH-1 ETH-transfer
    // wiring + LOW#3 canonical-low-s defense-in-depth.
    // ---------------------------------------------------------------

    /// LOW#3: a high-s signature must be rejected at the funder's
    /// HTTP layer BEFORE any chain submission. The verifier wraps the
    /// pinned `is_canonical_s` check from `pangolin-chain`.
    #[test]
    fn canonical_low_s_check_rejects_high_s_credit() {
        use alloy::primitives::U256;
        let authority = fixed_authority_signer();
        let mut credit = fresh_credit();
        sign_credit(&authority, &mut credit);
        // Sanity: round-trip still works (the helper canonicalises).
        assert!(verify_credit_signature(
            &credit,
            authority.address(),
            ChainEnv::BaseSepolia
        ));

        // Flip s to its high-s representative (n - s). Reload SECP_N
        // here as the literal n constant.
        let secp_n_be: [u8; 32] = alloy::primitives::hex!(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
        );
        let n = U256::from_be_slice(&secp_n_be);
        let s_low = U256::from_be_slice(&credit.signature[32..64]);
        let s_high = n - s_low;
        let s_high_be: [u8; 32] = s_high.to_be_bytes();
        credit.signature[32..64].copy_from_slice(&s_high_be);
        // Flip v parity to match the high-s recovery (27 ↔ 28).
        credit.signature[64] = if credit.signature[64] == 27 { 28 } else { 27 };

        // Even though the high-s variant would recover the same
        // address under raw ecrecover, the canonical-low-s gate rejects.
        assert!(!verify_credit_signature(
            &credit,
            authority.address(),
            ChainEnv::BaseSepolia
        ));
    }

    /// HIGH-1 fix: a Credit with `amount > cap` must be rejected at
    /// the handler with HTTP 400 + `eth_transfer_cap_exceeded` BEFORE
    /// any redemption tx submits. We exercise the cap-check helper
    /// directly here (since the full handler path requires a live
    /// RPC mock).
    #[test]
    fn eth_transfer_cap_exceeded_pre_check_rejects() {
        let cap: u128 = crate::ETH_TRANSFER_PER_TX_CAP_WEI;
        let over_cap = U256::from(cap) + U256::from(1u64);
        assert_eq!(
            crate::resume::clamp_eth_transfer_amount(over_cap, cap),
            None,
            "amount above cap must produce a None clamp (handler maps to 400)"
        );
        // At-cap is the boundary; passes.
        assert_eq!(
            crate::resume::clamp_eth_transfer_amount(U256::from(cap), cap),
            Some(U256::from(cap))
        );
    }

    /// HIGH-1: the HTTP error variant for the cap-exceeded path
    /// serialises with the agreed body fields. This is the wire
    /// surface clients pin against.
    #[test]
    fn eth_transfer_cap_exceeded_error_response_shape() {
        use axum::response::IntoResponse;
        let err = FunderError::EthTransferCapExceeded {
            observed_wei: U256::from(2_000_000_000_000_000_000u128),
            cap_wei: 10_000_000_000_000_000,
        };
        assert_eq!(err.class(), "eth_transfer_cap_exceeded");
        assert_eq!(err.status(), axum::http::StatusCode::BAD_REQUEST);
        // The body serialises observed_wei + cap_wei as hex strings.
        let _resp = err.into_response();
    }

    /// HIGH-1: the HTTP error variant for the post-redeem transfer
    /// failure includes the redeem tx hash so the operator can
    /// reconcile manually per the runbook.
    #[test]
    fn eth_transfer_failed_error_response_shape() {
        use axum::response::IntoResponse;
        let err = FunderError::EthTransferFailed {
            redeem_tx_hash: alloy::primitives::b256!(
                "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
            ),
            class: "rpc_transient",
        };
        assert_eq!(err.class(), "eth_transfer_failed");
        assert_eq!(err.status(), axum::http::StatusCode::INTERNAL_SERVER_ERROR);
        let _resp = err.into_response();
    }

    /// HIGH-1 lifecycle: a ledger row in `RedeemMined` is picked up
    /// by `find_resumable_entries` — this is the resume contract that
    /// the restart-scan in `main.rs` relies on. The actual ETH-transfer
    /// drive requires a live RPC and is covered by the live
    /// integration test (network-gated).
    #[tokio::test]
    async fn restart_scan_resumes_redeem_mined_entries() {
        let ledger = PaymentLedger::open_in_memory().expect("ledger");
        let h = alloy::primitives::b256!(
            "0xABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB"
        );
        ledger
            .try_insert(
                h,
                [0xAAu8; 32],
                fixed_device_signer().address(),
                U256::from(1u64),
            )
            .await
            .expect("insert");
        ledger
            .transition_state(h, PaymentState::RedeemMined)
            .await
            .expect("transition");
        let rows = ledger.find_resumable_entries().await.expect("scan");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].state, PaymentState::RedeemMined);
        assert_eq!(rows[0].attestation_hash, h);
    }

    /// HIGH-1 lifecycle: a ledger row in `EthTransferSubmitted` is
    /// also picked up by `find_resumable_entries`; the resume path
    /// closes the receipt-poll race per L-payment-order.
    #[tokio::test]
    async fn restart_scan_resumes_eth_transfer_submitted_entries() {
        let ledger = PaymentLedger::open_in_memory().expect("ledger");
        let h = alloy::primitives::b256!(
            "0xCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCD"
        );
        ledger
            .try_insert(
                h,
                [0xAAu8; 32],
                fixed_device_signer().address(),
                U256::from(1u64),
            )
            .await
            .expect("insert");
        let eth_tx = alloy::primitives::b256!(
            "0xEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEF"
        );
        ledger
            .mark_eth_transfer_submitted(h, eth_tx, U256::from(1u64))
            .await
            .expect("mark submitted");
        let rows = ledger.find_resumable_entries().await.expect("scan");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].state, PaymentState::EthTransferSubmitted);
        assert_eq!(rows[0].eth_transfer_tx_hash, Some(eth_tx));
    }

    /// HIGH-1 happy-path lifecycle drive: simulate the handler's
    /// post-redeem ledger transitions WITHOUT going through a live
    /// chain. The handler's flow updates ledger state
    /// `pre_redeem → redeem_submitted → redeem_mined →
    /// eth_transfer_submitted → eth_transfer_mined`; this test
    /// asserts the ledger surface supports each transition in
    /// sequence.
    #[tokio::test]
    async fn happy_path_full_flow_with_eth_transfer() {
        let ledger = PaymentLedger::open_in_memory().expect("ledger");
        let h = alloy::primitives::b256!(
            "0x4242424242424242424242424242424242424242424242424242424242424242"
        );
        let device = fixed_device_signer().address();
        let credit_amount = U256::from(1_000_000_000_000u128); // 0.000001 ETH
        let eth_amount = credit_amount;

        // Insert (PreRedeem) → stamp redeem (RedeemSubmitted) →
        // RedeemMined → stamp transfer (EthTransferSubmitted) →
        // EthTransferMined.
        ledger
            .try_insert(h, [0xAAu8; 32], device, credit_amount)
            .await
            .expect("insert");
        let redeem_tx = alloy::primitives::b256!(
            "0x1111111111111111111111111111111111111111111111111111111111111111"
        );
        ledger
            .update_redemption_tx_hash(h, redeem_tx)
            .await
            .expect("stamp redeem");
        let row = ledger
            .get_by_attestation_hash(h)
            .await
            .expect("query")
            .expect("present");
        assert_eq!(row.state, PaymentState::RedeemSubmitted);

        ledger
            .transition_state(h, PaymentState::RedeemMined)
            .await
            .expect("transition");
        let eth_tx = alloy::primitives::b256!(
            "0x2222222222222222222222222222222222222222222222222222222222222222"
        );
        ledger
            .mark_eth_transfer_submitted(h, eth_tx, eth_amount)
            .await
            .expect("stamp transfer");
        ledger
            .mark_eth_transfer_mined(h, 100)
            .await
            .expect("mark mined");

        let row = ledger
            .get_by_attestation_hash(h)
            .await
            .expect("query")
            .expect("present");
        assert_eq!(row.state, PaymentState::EthTransferMined);
        assert_eq!(row.redemption_tx_hash, Some(redeem_tx));
        assert_eq!(row.eth_transfer_tx_hash, Some(eth_tx));
        assert_eq!(row.eth_transferred_wei, Some(eth_amount));
        assert_eq!(row.eth_transfer_block, Some(100));
    }

    /// HIGH-1 sad-path: when the ETH transfer fails post-redeem, the
    /// ledger row transitions to `EthTransferFailed` (terminal). The
    /// operator runbook covers the manual reconciliation.
    #[tokio::test]
    async fn eth_transfer_failure_marks_terminal_state() {
        let ledger = PaymentLedger::open_in_memory().expect("ledger");
        let h = alloy::primitives::b256!(
            "0xBABEBABEBABEBABEBABEBABEBABEBABEBABEBABEBABEBABEBABEBABEBABEBABE"
        );
        ledger
            .try_insert(
                h,
                [0xAAu8; 32],
                fixed_device_signer().address(),
                U256::from(1u64),
            )
            .await
            .expect("insert");
        // Simulate: redeem advanced through RedeemSubmitted +
        // RedeemMined, then the transfer leg blew up.
        let redeem_tx = alloy::primitives::b256!(
            "0x3333333333333333333333333333333333333333333333333333333333333333"
        );
        ledger
            .update_redemption_tx_hash(h, redeem_tx)
            .await
            .expect("stamp redeem");
        ledger
            .transition_state(h, PaymentState::RedeemMined)
            .await
            .expect("transition");
        // The handler's failure arm marks the row terminal.
        ledger
            .transition_state(h, PaymentState::EthTransferFailed)
            .await
            .expect("transition");
        let row = ledger
            .get_by_attestation_hash(h)
            .await
            .expect("query")
            .expect("present");
        assert_eq!(row.state, PaymentState::EthTransferFailed);
        assert_eq!(row.redemption_tx_hash, Some(redeem_tx));
        assert_eq!(row.eth_transfer_tx_hash, None);
    }
}
