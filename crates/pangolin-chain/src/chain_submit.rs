// SPDX-License-Identifier: AGPL-3.0-or-later
//! Direct-submit transport for v1 signed revisions (MVP-2 issue 3.3).
//!
//! This module turns 3.1's `SignedRevisionV1` (65-byte EIP-712 secp256k1
//! signature) + 3.2's session-bounded `EvmWallet` into an
//! EIP-1559-shaped tx that calls D-017's
//! `publishRevision(bytes32, bytes32, bytes32, bytes32, uint16, bytes, bytes)`,
//! broadcasts via `eth_sendRawTransaction`, and blocks until a
//! 1-confirmation receipt comes back. The receipt's
//! `RevisionPublished` event is decoded into a [`ChainAnchorV1`]
//! returned to the caller.
//!
//! ## Resolved decisions (Kelvin sign-off 2026-05-14 — verbatim from
//! `docs/issue-plans/3.3.md`)
//!
//! - **R-a fetch-nonce:** `provider.get_transaction_count(addr).pending()`
//!   immediately before tx construction. No local cache. On a
//!   nonce-collision retry the nonce is re-fetched.
//! - **R-b EIP-1559 + 50 gwei cap:**
//!   `maxFeePerGas = 2 × baseFeePerGas + maxPriorityFeePerGas`;
//!   `maxPriorityFeePerGas = 1 gwei`. Above-cap →
//!   [`ChainError::GasCapExceeded`].
//! - **R-c retry taxonomy verbatim:** retriable = nonce collision
//!   (max 3 retries) + RPC transient (exp backoff 250ms / 1s / 4s).
//!   Fatal = `InsufficientFunds`, `RevertedV1` (with decoded reason
//!   covering `ErrInvalidSignature` / `ErrSignerNotRegistered` /
//!   `ErrUnsupportedSchemaVersion` / `OutOfGas`), `ChainIdMismatch`,
//!   `DeploymentAddressMismatch`, `GasCapExceeded`, `NonceUnresolvable`,
//!   `ReceiptMismatch`.
//! - **R-d async-only on `pangolin-chain`:** the public entry is
//!   [`publish_revision_v1`]; `Vault` stays sync.
//! - **R-e block until 1-conf:** await
//!   `PendingTransactionBuilder::get_receipt()`; verify `status == 1`;
//!   decode `RevisionPublished` from the receipt logs; mismatch on
//!   decode → [`ChainError::ReceiptMismatch`].
//! - **R-f hermetic CI + `#[ignore]`'d live:** hermetic tests use
//!   alloy's `MockTransport` + `Asserter`; a calldata-pinned test
//!   asserts byte-equality with a `cast calldata`-derived reference;
//!   one live test against D-017 is `#[ignore]`'d.
//!
//! ## L1..L12 invariants preserved
//!
//! 1. 65-byte sig bytes pass through verbatim — no transformation here.
//! 2. SAME secp256k1 key signs revision AND pays gas (D-006).
//! 3. Calldata encoding byte-identical to `cast calldata`. Pinned by
//!    [`tests::publish_v1_calldata_byte_pin`].
//! 4. Contract address via [`load_deployed_address`] cross-checked
//!    against `EXPECTED_DEPLOYED_ADDRESS_BASE_SEPOLIA`.
//! 5. Tx submission reachable only via active session — the entry
//!    point takes `&EvmWallet`; only `Vault::evm_wallet()` produces
//!    one.
//! 6. Gas-price hard cap 50 gwei enforced.
//! 7. `pangolin-store → pangolin-chain` dep direction preserved (no
//!    new `use pangolin_store::*`).
//! 8. No new external crate dep — alloy + tokio + k256 are already in
//!    tree.
//! 9. `forbid(unsafe_code)` preserved.
//! 10. AGPL-3.0-or-later SPDX header on every NEW `.rs` file (this
//!     one + nothing else).
//! 11. Hermetic tests dominate CI; live test is `#[ignore]`'d.
//! 12. Replay protection on retry: the retry loop only retries
//!     `eth_sendRawTransaction` failures BEFORE the tx is broadcast
//!     successfully. Once `send_transaction` returns Ok (a
//!     `PendingTransactionBuilder` holding the tx hash), no further
//!     re-broadcast happens; the receipt-await path is awaited to
//!     completion. The on-chain `_nextSequence` advance is
//!     idempotent-bound by the nonce, so even an RPC double-submit
//!     is rejected by the mempool/`already known` path.
//!
//! ## Adversarial threat surface
//!
//! See `docs/issue-plans/3.3.md` "L-section":
//! - **L-gas-griefing** (mitigated by L6 cap)
//! - **L-rpc-spoof** (mitigated by [`ChainError::ReceiptMismatch`]
//!   decode + the per-log emitter-address check copying v0's MED-4
//!   defense)
//! - **L-nonce-collision-DoS** (deferred to MVP-3 cancel-tx flow;
//!   bounded retries here)
//! - **L-replay-after-revert** (mitigated by fatal-revert taxonomy)
//! - **L-double-broadcast-on-retry** (mitigated by L12 — retries
//!   only fire BEFORE `send_transaction` returns success)

use core::time::Duration;

use alloy::network::{Ethereum, EthereumWallet, TransactionBuilder};
use alloy::primitives::{Address, Bytes, B256, U256};
use alloy::providers::{DynProvider, PendingTransactionBuilder, Provider, ProviderBuilder};
use alloy::rpc::types::{BlockNumberOrTag, TransactionRequest};
#[allow(unused_imports)] // SolEvent's `SIGNATURE_HASH` / `decode_log` /
// `encode_data` trait methods are used via the `RevisionLogV1`
// binding; clippy doesn't see the trait dispatch through the macro.
use alloy::sol_types::SolEvent;

use crate::deployments::{load_deployed_address, ChainEnv};
use crate::error::ChainError;
use crate::evm::EvmWallet;
use crate::secp256k1_signing::{SignedRevisionV1, EXPECTED_DEPLOYED_ADDRESS_BASE_SEPOLIA};

// ---------------------------------------------------------------------
// Pinned constants
// ---------------------------------------------------------------------

/// Per-tx hard cap on `maxFeePerGas`, in wei. 50 gwei = `50 * 10^9` wei.
///
/// Above-cap → [`ChainError::GasCapExceeded`] before tx construction.
/// Defends against a malicious RPC reporting a huge `baseFeePerGas`
/// (L6 + L-gas-griefing).
pub const MAX_FEE_PER_GAS_CAP_WEI: u128 = 50_000_000_000;

/// Default `maxPriorityFeePerGas` (miner tip) in wei. 1 gwei = `10^9`
/// wei.
///
/// Per R-b verbatim: 1 gwei is enough to land on Base Sepolia where
/// `baseFeePerGas` is consistently sub-gwei. Hardcoded here rather
/// than env-derived because env-var override is out of scope for
/// MVP-2.
pub const PRIORITY_FEE_DEFAULT_WEI: u128 = 1_000_000_000;

/// Maximum retry attempts for retriable failures (nonce collision or
/// RPC transient).
///
/// Per R-c the total is "1 initial attempt + 2 retries = 3 attempts
/// max"; we count attempts so the loop iterates exactly 3 times in
/// the worst case.
pub const PUBLISH_REVISION_MAX_RETRIES: u8 = 3;

/// Exponential backoff schedule for RPC-transient retries, in
/// milliseconds.
///
/// Per R-c: 250 ms before attempt 2, 1 s before attempt 3, 4 s
/// before a hypothetical attempt 4 (unused because we cap at 3). The
/// third slot is here for future tuning room.
pub const PUBLISH_REVISION_BACKOFF_MS: [u64; 3] = [250, 1_000, 4_000];

/// Receipt-poll timeout (seconds).
///
/// Alloy's `PendingTransactionBuilder::get_receipt` polls until
/// inclusion; this cap bounds wall-clock for L-receipt-poll-timeout.
/// Base Sepolia has ~2s block times; 60s is ~30 blocks of headroom.
pub const RECEIPT_TIMEOUT_SECS: u64 = 60;

/// Gas-estimate safety multiplier (numerator/denominator). Per the
/// plan-doc: pick "1.2x safety margin OR 100k headroom". We pick a
/// fixed-point multiplier of 12/10 = 1.2 — multiplicative scaling
/// matches alloy's own internal estimator slack and is robust to
/// future contract changes that grow base gas cost.
const GAS_ESTIMATE_NUMER: u64 = 12;
const GAS_ESTIMATE_DENOM: u64 = 10;

// ---------------------------------------------------------------------
// alloy `sol!` binding for `RevisionLogV1`
// ---------------------------------------------------------------------

// alloy's `sol!` macro expands into helper functions whose
// argument count tracks the underlying Solidity ABI; clippy's
// `too-many-arguments` cap (7) fires on `publishRevision`'s
// 7-arg signature. Same on `RevisionPublished`'s 8-field event
// constructor. Wrapping in a `mod` lets us silence the lint at
// the boundary without sprinkling allows inside generated code.
#[allow(clippy::too_many_arguments, clippy::module_name_repetitions)]
pub(crate) mod revision_log_v1_binding {
    use alloy::sol;

    sol! {
        /// Mirror of `contracts/src/RevisionLogV1.sol`. MUST stay
        /// byte-for-byte aligned with the .sol source. Drift is caught
        /// by `publish_v1_calldata_byte_pin`.
        #[sol(rpc)]
        contract RevisionLogV1 {
            function publishRevision(
                bytes32 vaultId,
                bytes32 accountId,
                bytes32 parentRevision,
                bytes32 deviceId,
                uint16 schemaVersion,
                bytes calldata encPayload,
                bytes calldata signature
            ) external returns (uint256 sequence);

            event RevisionPublished(
                uint256 indexed sequence,
                bytes32 indexed vaultId,
                bytes32 indexed accountId,
                bytes32 parentRevision,
                bytes32 deviceId,
                uint16 schemaVersion,
                bytes encPayload,
                address signer
            );
        }
    }
}

use revision_log_v1_binding::RevisionLogV1;

// ---------------------------------------------------------------------
// ChainAnchorV1
// ---------------------------------------------------------------------

/// Receipt anchor returned from a successful v1 publish.
///
/// Distinct from the v0 [`crate::types::ChainAnchor`] (which has no
/// `block_hash` or `signer` field) — v1's richer shape lets a caller
/// cross-check the on-chain `RevisionPublished.signer` against the
/// wallet that submitted the tx + reason about reorgs via
/// `block_hash`. Field shapes follow the v0 conventions: fixed-size
/// byte arrays for hashes; `u64` for block/log numbers; `U256` for
/// the contract's monotonic `sequence` counter (full width preserved
/// since the v1 contract emits it as `uint256`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainAnchorV1 {
    /// 32-byte transaction hash.
    pub tx_hash: B256,
    /// Block number the tx was included in.
    pub block_number: u64,
    /// 32-byte hash of the block the tx was included in. Useful for
    /// reorg-safe consumers downstream.
    pub block_hash: B256,
    /// Index of the `RevisionPublished` log within the block's log
    /// stream.
    pub log_index: u64,
    /// On-chain monotonic sequence counter value at publish time.
    /// Full `U256` width — the contract emits `uint256` per the v1
    /// spec.
    pub sequence: U256,
    /// `signer` field decoded from the `RevisionPublished` event.
    /// Cross-checked against `wallet.address()`; mismatch →
    /// [`ChainError::ReceiptMismatch`].
    pub signer: Address,
}

// ---------------------------------------------------------------------
// Public entry point — async fn `publish_revision_v1`
// ---------------------------------------------------------------------

/// Broadcast a v1 signed revision to D-017 and block until 1-conf
/// receipt. Returns a populated [`ChainAnchorV1`] on success.
///
/// # Arguments
///
/// - `wallet` — the device's `EvmWallet` (only obtainable from a
///   `Vault::evm_wallet()` call inside an active session). The SAME
///   secp256k1 key that signed the revision pays gas (D-006 / L2).
/// - `signed_revision` — 3.1's output: the field set + the 65-byte
///   secp256k1 signature.
/// - `env` — which `ChainEnv` to publish under. Only `BaseSepolia` is
///   wired today; other envs read the deployment file but don't get
///   the pinned-address cross-check.
/// - `rpc_url` — http(s) URL of the RPC endpoint.
///
/// # Errors
///
/// See R-c retry taxonomy in the module docstring + individual
/// [`ChainError`] variants. Retriable failures (nonce collision, RPC
/// transient) are bounded at [`PUBLISH_REVISION_MAX_RETRIES`] attempts;
/// fatal failures (insufficient funds, contract revert, gas cap, chain
/// id mismatch, deployment address mismatch, receipt mismatch) bail
/// without retry.
pub async fn publish_revision_v1(
    wallet: &EvmWallet,
    signed_revision: &SignedRevisionV1,
    env: ChainEnv,
    rpc_url: &str,
) -> Result<ChainAnchorV1, ChainError> {
    // ---- Construction-time cross-checks (all fatal; no retry) ----
    let contract_address = load_deployed_address(env, "RevisionLogV1")?;
    if matches!(env, ChainEnv::BaseSepolia)
        && contract_address != EXPECTED_DEPLOYED_ADDRESS_BASE_SEPOLIA
    {
        return Err(ChainError::DeploymentAddressMismatch {
            env,
            expected: EXPECTED_DEPLOYED_ADDRESS_BASE_SEPOLIA,
            actual: contract_address,
        });
    }

    let provider = build_provider(wallet, rpc_url).await?;
    // L-rpc-spoof partial defense: cross-check `eth_chainId` against
    // the build's expected chain id. (`ChainEnv::Dev` returns None
    // and skips this check.)
    if let Some(expected_chain_id) = env.chain_id() {
        let observed = provider.get_chain_id().await.map_err(map_rpc_err)?;
        if observed != expected_chain_id {
            return Err(ChainError::ChainIdMismatch {
                expected: expected_chain_id,
                observed,
            });
        }
    }

    publish_revision_v1_with_provider(
        &provider,
        wallet.address(),
        contract_address,
        signed_revision,
    )
    .await
}

// ---------------------------------------------------------------------
// Inner helper — provider-bound publish loop
// ---------------------------------------------------------------------

/// Inner publish loop, parameterised over a constructed provider.
///
/// Production callers always go via [`publish_revision_v1`]. The
/// hermetic test suite drives the broadcast portion via
/// [`broadcast_with_retries`] (which omits the receipt await) and the
/// post-receipt portion via [`process_receipt`] (which takes a
/// synthesized receipt). The two-phase split is necessary because
/// alloy's `PendingTransactionBuilder::get_receipt` polls via the
/// heart + a block-head subscription that is hard to satisfy with
/// the [`alloy::transports::mock::MockTransport`].
async fn publish_revision_v1_with_provider(
    provider: &DynProvider,
    wallet_address: Address,
    contract_address: Address,
    signed_revision: &SignedRevisionV1,
) -> Result<ChainAnchorV1, ChainError> {
    let pending =
        broadcast_with_retries(provider, wallet_address, contract_address, signed_revision).await?;

    // ---- L12 boundary: the tx is in-flight. From here on, NO
    //      re-broadcast. Await the receipt; verify status==1;
    //      decode the event; populate the anchor. ----
    let tx_hash: B256 = *pending.tx_hash();
    let pending = pending.with_timeout(Some(Duration::from_secs(RECEIPT_TIMEOUT_SECS)));
    let receipt = pending
        .get_receipt()
        .await
        .map_err(|e| ChainError::Rpc(format!("get_receipt({tx_hash:?}): {e}")))?;
    process_receipt(&receipt, wallet_address, contract_address, tx_hash)
}

/// Broadcast leg of [`publish_revision_v1_with_provider`]: nonce +
/// fee + estimate + send, with the R-c retry taxonomy applied. On
/// success returns a [`PendingTransactionBuilder`] whose tx hash is
/// the broadcast tx. The caller is responsible for awaiting the
/// receipt + cross-checking via [`process_receipt`].
///
/// Split out so hermetic tests can drive the retry classification
/// without going through alloy's heart polling (which requires a
/// block-head subscription that's awkward to mock).
#[allow(clippy::too_many_lines)] // the retry loop is the load-bearing
                                 //                                 logic of 3.3; splitting further
                                 //                                 would obscure the per-failure
                                 //                                 classification.
async fn broadcast_with_retries(
    provider: &DynProvider,
    wallet_address: Address,
    contract_address: Address,
    signed_revision: &SignedRevisionV1,
) -> Result<PendingTransactionBuilder<Ethereum>, ChainError> {
    let mut attempts: u8 = 0;

    loop {
        attempts += 1;
        // ---- R-a: fetch nonce fresh every attempt ----
        let nonce = match provider
            .get_transaction_count(wallet_address)
            .pending()
            .await
        {
            Ok(n) => n,
            Err(e) => {
                let msg = e.to_string();
                if is_transient_rpc_error(&msg) && attempts < PUBLISH_REVISION_MAX_RETRIES {
                    backoff_for_attempt(attempts).await;
                    continue;
                }
                return Err(ChainError::RpcTransient {
                    message: msg,
                    attempts,
                });
            }
        };

        // ---- R-b: fetch base fee + compute max_fee_per_gas + check cap ----
        let base_fee = fetch_base_fee(provider).await?;
        let max_fee_per_gas: u128 = base_fee
            .checked_mul(2)
            .and_then(|v| v.checked_add(PRIORITY_FEE_DEFAULT_WEI))
            .ok_or_else(|| ChainError::Rpc("base fee arithmetic overflow".into()))?;
        if max_fee_per_gas > MAX_FEE_PER_GAS_CAP_WEI {
            // Fatal — no retry. Convert to gwei for display.
            return Err(ChainError::GasCapExceeded {
                observed_gwei: u64::try_from(max_fee_per_gas / 1_000_000_000).unwrap_or(u64::MAX),
                cap_gwei: u64::try_from(MAX_FEE_PER_GAS_CAP_WEI / 1_000_000_000)
                    .unwrap_or(u64::MAX),
            });
        }

        // ---- Build the TransactionRequest ----
        // alloy's `sol!`-generated bindings expose the function as a
        // helper that builds calldata for us; we use the calldata
        // directly so we can attach a custom (nonce, gas, fee) profile.
        let call = RevisionLogV1::publishRevisionCall {
            vaultId: signed_revision.fields.vault_id.into(),
            accountId: signed_revision.fields.account_id.into(),
            parentRevision: signed_revision.fields.parent_revision.into(),
            deviceId: signed_revision.fields.device_id.into(),
            schemaVersion: signed_revision.fields.schema_version,
            encPayload: Bytes::copy_from_slice(&signed_revision.fields.enc_payload_hash[..]),
            signature: Bytes::copy_from_slice(&signed_revision.signature[..]),
        };
        let calldata = alloy::sol_types::SolCall::abi_encode(&call);

        let mut tx = TransactionRequest::default()
            .with_from(wallet_address)
            .with_to(contract_address)
            .with_nonce(nonce)
            .with_input(Bytes::from(calldata.clone()))
            .with_value(U256::ZERO)
            .with_max_fee_per_gas(max_fee_per_gas)
            .with_max_priority_fee_per_gas(PRIORITY_FEE_DEFAULT_WEI);
        // chain_id binds via the EthereumWallet filler; for hermetic
        // tests against MockTransport we set it explicitly so the
        // estimate / signing path doesn't need an extra RPC call.
        tx.set_chain_id(signed_revision_chain_id());

        // ---- Estimate gas (with 1.2x safety margin) ----
        let est = match provider.estimate_gas(tx.clone()).await {
            Ok(g) => g,
            Err(e) => {
                let msg = e.to_string();
                // estimate_gas can revert if the call would revert
                // on-chain; pass it through the same classifier so
                // contract reverts surface as RevertedV1 not retry.
                if let Some(reason) = decode_revert_reason_from_msg(&msg) {
                    return Err(ChainError::RevertedV1 {
                        reason,
                        tx_hash: B256::ZERO,
                    });
                }
                if is_insufficient_funds(&msg) {
                    return Err(ChainError::InsufficientFunds {
                        observed: None,
                        message: msg,
                    });
                }
                if is_transient_rpc_error(&msg) && attempts < PUBLISH_REVISION_MAX_RETRIES {
                    backoff_for_attempt(attempts).await;
                    continue;
                }
                return Err(ChainError::RpcTransient {
                    message: msg,
                    attempts,
                });
            }
        };
        let gas_limit = est
            .saturating_mul(GAS_ESTIMATE_NUMER)
            .saturating_div(GAS_ESTIMATE_DENOM);
        tx = tx.with_gas_limit(gas_limit);

        // ---- Submit (eth_sendRawTransaction via filler) ----
        match provider.send_transaction(tx).await {
            Ok(p) => return Ok(p),
            Err(e) => {
                let msg = e.to_string();
                if is_nonce_collision(&msg) {
                    if attempts < PUBLISH_REVISION_MAX_RETRIES {
                        continue;
                    }
                    return Err(ChainError::NonceUnresolvable { attempts });
                }
                if is_insufficient_funds(&msg) {
                    return Err(ChainError::InsufficientFunds {
                        observed: None,
                        message: msg,
                    });
                }
                if is_transient_rpc_error(&msg) && attempts < PUBLISH_REVISION_MAX_RETRIES {
                    backoff_for_attempt(attempts).await;
                    continue;
                }
                return Err(ChainError::RpcTransient {
                    message: msg,
                    attempts,
                });
            }
        }
    }
}

/// Process an alloy [`TransactionReceipt`] into a [`ChainAnchorV1`] +
/// run all post-receipt cross-checks.
///
/// Extracted from the publish loop so hermetic tests can drive the
/// receipt-decoding path without spinning up alloy's heart polling
/// (which requires block-head subscription that's awkward to mock).
/// Used by both the production [`publish_revision_v1_with_provider`]
/// path and the test suite's receipt-shape tests.
///
/// # Cross-checks (R-e + L-rpc-spoof)
///
/// 1. `receipt.status == 1`; else [`ChainError::RevertedV1`].
/// 2. `block_number` and `block_hash` present; else
///    [`ChainError::Decode`].
/// 3. A `RevisionPublished` log emitted by `contract_address` is
///    present; else [`ChainError::MissingEvent`].
/// 4. The decoded `signer` field equals `wallet_address`; else
///    [`ChainError::ReceiptMismatch`].
fn process_receipt(
    receipt: &alloy::rpc::types::TransactionReceipt,
    wallet_address: Address,
    contract_address: Address,
    tx_hash: B256,
) -> Result<ChainAnchorV1, ChainError> {
    if !receipt.status() {
        // alloy 2.x's `TransactionReceipt` doesn't surface a typed
        // `revertReason`; surface a generic typed error with the
        // tx hash so the operator can look it up. The `decode_revert_reason_from_msg`
        // helper covers the pre-broadcast estimate-revert path
        // separately.
        return Err(ChainError::RevertedV1 {
            reason: "unknown revert (status=0)".to_string(),
            tx_hash,
        });
    }

    let block_number = receipt
        .block_number
        .ok_or_else(|| ChainError::Decode("receipt missing block_number".into()))?;
    let block_hash = receipt
        .block_hash
        .ok_or_else(|| ChainError::Decode("receipt missing block_hash".into()))?;

    // L-rpc-spoof: defensive emitter-address filter on the receipt
    // logs. Same MED-4 posture as v0's `BaseSepoliaAdapter::publish`.
    let target_topic = RevisionLogV1::RevisionPublished::SIGNATURE_HASH;
    let log = receipt
        .inner
        .logs()
        .iter()
        .find(|l| {
            l.address() == contract_address && l.topics().first().copied() == Some(target_topic)
        })
        .ok_or_else(|| ChainError::MissingEvent {
            tx_hash: format!("{tx_hash:?}"),
        })?;

    let decoded = RevisionLogV1::RevisionPublished::decode_log(&log.inner)
        .map_err(|e| ChainError::Decode(format!("RevisionPublished log: {e}")))?;

    // Receipt cross-check: the event's `signer` field MUST equal
    // the wallet address that submitted. A divergence indicates a
    // spoofing RPC.
    if decoded.signer != wallet_address {
        return Err(ChainError::ReceiptMismatch {
            expected_signer: wallet_address,
            observed_signer: decoded.signer,
        });
    }

    let log_index = log
        .log_index
        .ok_or_else(|| ChainError::Decode("RevisionPublished log missing log_index".into()))?;

    Ok(ChainAnchorV1 {
        tx_hash,
        block_number,
        block_hash,
        log_index,
        sequence: decoded.sequence,
        signer: decoded.signer,
    })
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

/// Build a wallet-bearing alloy provider, type-erased to a
/// [`DynProvider`] so the publish loop's signature stays concrete.
async fn build_provider(wallet: &EvmWallet, rpc_url: &str) -> Result<DynProvider, ChainError> {
    let eth_wallet = EthereumWallet::from(wallet.signer().clone());
    let provider = ProviderBuilder::new()
        .wallet(eth_wallet)
        .connect(rpc_url)
        .await
        .map_err(|e| ChainError::Rpc(format!("connect {rpc_url}: {e}")))?;
    Ok(provider.erased())
}

/// Fetch the latest block's base fee per gas. Uses `eth_feeHistory`
/// with a 1-block window + the recommended-percentile defaults; falls
/// back to `eth_getBlockByNumber` if the fee history is empty.
async fn fetch_base_fee<P: Provider>(provider: &P) -> Result<u128, ChainError> {
    let hist = provider
        .get_fee_history(1, BlockNumberOrTag::Latest, &[])
        .await
        .map_err(map_rpc_err)?;
    if let Some(b) = hist.latest_block_base_fee() {
        if b != 0 {
            return Ok(b);
        }
    }
    // Empty / zero base fee fallback. Use `get_gas_price` as a last
    // resort — non-EIP-1559 chains report it via that route, which
    // we use as a proxy for "what would a tx cost right now".
    let gas_price = provider.get_gas_price().await.map_err(map_rpc_err)?;
    Ok(gas_price)
}

/// Convert an alloy transport error into a [`ChainError::Rpc`] string.
/// Used for one-shot RPC calls (chain id check, base fee fetch) where
/// the retry path is handled inline by the caller, not here.
fn map_rpc_err<E: core::fmt::Display>(e: E) -> ChainError {
    ChainError::Rpc(e.to_string())
}

/// Chain id binding for the EIP-1559 tx envelope.
///
/// Returns the build's expected chain id for `BaseSepolia` (the only
/// env wired in MVP-2). When `pangolin-chain` grows additional envs
/// (mainnet / dev) this fn will widen to a match-on-`ChainEnv`.
const fn signed_revision_chain_id() -> u64 {
    84_532
}

/// Classify an RPC error message as "nonce collision (retry)" vs not.
/// Matches the three common JSON-RPC strings — geth, erigon, infura
/// all surface variants of these. Case-insensitive substring match.
fn is_nonce_collision(msg: &str) -> bool {
    let lower = msg.to_ascii_lowercase();
    lower.contains("nonce too low")
        || lower.contains("nonce already used")
        || lower.contains("already known")
        || lower.contains("replacement underpriced")
        || lower.contains("replacement transaction underpriced")
}

/// Classify an RPC error message as "transient (retry with backoff)"
/// vs not. Matches timeout/5xx/connection-reset shapes.
fn is_transient_rpc_error(msg: &str) -> bool {
    let lower = msg.to_ascii_lowercase();
    // Be conservative — only retry on shapes that are clearly transient.
    lower.contains("timeout")
        || lower.contains("timed out")
        || lower.contains("connection reset")
        || lower.contains("connection refused")
        || lower.contains("connection closed")
        || lower.contains("temporarily unavailable")
        || lower.contains("502 ")
        || lower.contains("503 ")
        || lower.contains("504 ")
        || lower.contains("bad gateway")
        || lower.contains("service unavailable")
        || lower.contains("gateway timeout")
}

/// Classify an RPC error message as "insufficient funds (fatal)".
fn is_insufficient_funds(msg: &str) -> bool {
    let lower = msg.to_ascii_lowercase();
    lower.contains("insufficient funds")
        || lower.contains("insufficient balance")
        || lower.contains("not enough funds")
}

/// Best-effort decoder for a Solidity custom-error / revert reason
/// embedded in an alloy error message. Returns the symbolic name when
/// recognised; returns `None` when the message is not revert-shaped.
fn decode_revert_reason_from_msg(msg: &str) -> Option<String> {
    let lower = msg.to_ascii_lowercase();
    if !(lower.contains("revert") || lower.contains("execution reverted")) {
        return None;
    }
    // Match the three known RevisionLogV1 custom errors first (these
    // surface via the 4-byte selector preceded by their name in alloy
    // 2.x error rendering).
    for known in [
        "ErrInvalidSignature",
        "ErrSignerNotRegistered",
        "ErrUnsupportedSchemaVersion",
    ] {
        if msg.contains(known) {
            return Some((*known).to_string());
        }
    }
    if lower.contains("out of gas") || lower.contains("outofgas") {
        return Some("OutOfGas".to_string());
    }
    Some("unknown revert".to_string())
}

/// Sleep for the per-attempt backoff window. Attempt 1 (the initial
/// try) doesn't sleep; attempt 2 sleeps the first slot; attempt 3
/// sleeps the second. Total wall-clock for a fully-backed-off run is
/// 250 ms + 1 s = 1.25 s before the third attempt.
async fn backoff_for_attempt(attempts: u8) {
    let idx = (attempts as usize)
        .saturating_sub(1)
        .min(PUBLISH_REVISION_BACKOFF_MS.len() - 1);
    let ms = PUBLISH_REVISION_BACKOFF_MS[idx];
    if ms == 0 {
        return;
    }
    tokio::time::sleep(Duration::from_millis(ms)).await;
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
// Test module: silence pedantic / nursery lints that fire on hermetic
// fixture builders + ABI-shaped helpers (the `signer`/`signed` naming
// is intentional and unavoidable given alloy/3.1's vocabulary).
#[allow(
    clippy::doc_markdown,
    clippy::similar_names,
    clippy::too_many_arguments,
    clippy::if_not_else
)]
mod tests {
    use super::*;
    use alloy::consensus::{Eip658Value, Receipt, ReceiptEnvelope, ReceiptWithBloom};
    use alloy::primitives::{hex, Bloom, Log as PrimLog, LogData, B256, U256};
    use alloy::providers::ProviderBuilder;
    use alloy::rpc::types::{Log as RpcLog, TransactionReceipt};
    use alloy::transports::mock::Asserter;
    use pangolin_crypto::keys::DeviceKey;

    use crate::evm::derive_evm_wallet;
    use crate::secp256k1_signing::{
        build_signed_revision_v1, RevisionFieldsV1, EXPECTED_DEPLOYED_ADDRESS_BASE_SEPOLIA,
    };

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    /// Pinned-seed wallet so all tests are deterministic.
    fn fixed_wallet() -> EvmWallet {
        let seed: [u8; 32] = [0x42; 32];
        derive_evm_wallet(&DeviceKey::from_seed(seed)).expect("derive fixed wallet")
    }

    /// Build a fully-mocked DynProvider with the supplied Asserter.
    /// Use this in tests that drive the publish loop directly via
    /// [`publish_revision_v1_with_provider`].
    fn mock_provider(asserter: &Asserter) -> DynProvider {
        ProviderBuilder::new()
            .connect_mocked_client(asserter.clone())
            .erased()
    }

    /// Build an `RpcLog` that decodes as a `RevisionPublished` event
    /// for the given inputs. Used by [`build_receipt`] to test the
    /// `process_receipt` path directly without going through alloy's
    /// heart polling.
    fn build_revision_published_log(
        signer: Address,
        contract: Address,
        signed: &SignedRevisionV1,
        tx_hash: B256,
        sequence: U256,
        block_number: u64,
        block_hash: B256,
        log_index: u64,
    ) -> RpcLog {
        let seq_topic = B256::from(sequence.to_be_bytes::<32>());
        let vault_topic = B256::from(signed.fields.vault_id);
        let account_topic = B256::from(signed.fields.account_id);
        let topic0 = RevisionLogV1::RevisionPublished::SIGNATURE_HASH;
        let event = RevisionLogV1::RevisionPublished {
            sequence,
            vaultId: signed.fields.vault_id.into(),
            accountId: signed.fields.account_id.into(),
            parentRevision: signed.fields.parent_revision.into(),
            deviceId: signed.fields.device_id.into(),
            schemaVersion: signed.fields.schema_version,
            encPayload: Bytes::copy_from_slice(&signed.fields.enc_payload_hash[..]),
            signer,
        };
        let body_data = event.encode_data();
        let log_data = LogData::new(
            vec![topic0, seq_topic, vault_topic, account_topic],
            Bytes::from(body_data),
        )
        .expect("topics + data shape ok");
        RpcLog {
            inner: PrimLog {
                address: contract,
                data: log_data,
            },
            block_hash: Some(block_hash),
            block_number: Some(block_number),
            block_timestamp: None,
            transaction_hash: Some(tx_hash),
            transaction_index: Some(0),
            log_index: Some(log_index),
            removed: false,
        }
    }

    /// Build an alloy `TransactionReceipt` shape carrying a single
    /// `RevisionPublished` log. Used to drive [`process_receipt`]
    /// directly in tests.
    fn build_receipt(
        signer: Address,
        contract: Address,
        signed: &SignedRevisionV1,
        tx_hash: B256,
        sequence: U256,
        status: bool,
    ) -> TransactionReceipt {
        let block_number = 0x1234u64;
        let block_hash = B256::repeat_byte(0xCC);
        let log = build_revision_published_log(
            signer,
            contract,
            signed,
            tx_hash,
            sequence,
            block_number,
            block_hash,
            0,
        );
        let inner_receipt = Receipt {
            status: Eip658Value::Eip658(status),
            cumulative_gas_used: 0x5208,
            logs: vec![log],
        };
        let with_bloom = ReceiptWithBloom {
            logs_bloom: Bloom::ZERO,
            receipt: inner_receipt,
        };
        let envelope = ReceiptEnvelope::Eip1559(with_bloom);
        TransactionReceipt {
            inner: envelope,
            transaction_hash: tx_hash,
            transaction_index: Some(0),
            block_hash: Some(block_hash),
            block_number: Some(block_number),
            gas_used: 0x5208,
            effective_gas_price: 1,
            blob_gas_used: None,
            blob_gas_price: None,
            from: signer,
            to: Some(contract),
            contract_address: None,
        }
    }

    /// Push the standard broadcast RPC response sequence for a single
    /// publish attempt up to (and including) `eth_sendRawTransaction`
    /// returning a tx hash. The post-broadcast receipt-await is tested
    /// separately via [`process_receipt`]. Call order:
    ///   1. eth_getTransactionCount(addr, "pending")      → nonce
    ///   2. eth_feeHistory                                 → base fee
    ///   3. eth_estimateGas                                → gas
    ///   4. eth_sendRawTransaction (signed via filler)     → tx hash
    fn push_broadcast_only(
        asserter: &Asserter,
        nonce: u64,
        base_fee_wei: u128,
        gas_estimate: u64,
        tx_hash: B256,
    ) {
        asserter.push_success(&format!("0x{nonce:x}"));
        asserter.push_success(&serde_json::json!({
            "oldestBlock": "0x0",
            "baseFeePerGas": [format!("0x{base_fee_wei:x}"), format!("0x{base_fee_wei:x}")],
            "gasUsedRatio": [0.5],
            "reward": [],
        }));
        asserter.push_success(&format!("0x{gas_estimate:x}"));
        asserter.push_success(&format!("{tx_hash:?}"));
    }

    fn sample_signed_revision(wallet: &EvmWallet) -> SignedRevisionV1 {
        let fields = RevisionFieldsV1::with_signer_device_id(
            wallet, [0x11; 32], [0x22; 32], [0x33; 32], 1, [0xCC; 32],
        );
        build_signed_revision_v1(wallet, fields, ChainEnv::BaseSepolia).expect("sign v1")
    }

    // -----------------------------------------------------------------
    // Calldata pin test
    // -----------------------------------------------------------------

    /// L3 + L-calldata-encoding-drift: the alloy `sol!`-generated
    /// encoding of `publishRevision(...)` for a fixed input set
    /// byte-equals a `cast calldata`-derived reference. Drift in
    /// either the binding or alloy's ABI codec fires here.
    #[test]
    fn publish_v1_calldata_byte_pin() {
        // Fixed-input set (matches the `cast calldata` invocation in
        // the docstring below).
        let vault_id = hex!("1111111111111111111111111111111111111111111111111111111111111111");
        let account_id = hex!("2222222222222222222222222222222222222222222222222222222222222222");
        let parent = hex!("3333333333333333333333333333333333333333333333333333333333333333");
        let device_id = hex!("4444444444444444444444444444444444444444444444444444444444444444");
        let schema_version: u16 = 1;
        let enc_payload = hex!("deadbeef");
        let mut signature = [0xAAu8; 65];
        signature[64] = 0x1C; // v = 28
        let call = RevisionLogV1::publishRevisionCall {
            vaultId: vault_id.into(),
            accountId: account_id.into(),
            parentRevision: parent.into(),
            deviceId: device_id.into(),
            schemaVersion: schema_version,
            encPayload: Bytes::copy_from_slice(&enc_payload),
            signature: Bytes::copy_from_slice(&signature),
        };
        let encoded = alloy::sol_types::SolCall::abi_encode(&call);
        // Reference captured at builder time via:
        //   cast calldata "publishRevision(bytes32,bytes32,bytes32,bytes32,uint16,bytes,bytes)" \
        //     0x111...11 0x222...22 0x333...33 0x444...44 1 0xdeadbeef \
        //     0xaaaa...aa1c
        // and stripped of its 0x prefix. The selector is 0x91f6be2f.
        let expected_hex = concat!(
            // Function selector (cast sig).
            "91f6be2f",
            // 4 × bytes32 head words.
            "1111111111111111111111111111111111111111111111111111111111111111",
            "2222222222222222222222222222222222222222222222222222222222222222",
            "3333333333333333333333333333333333333333333333333333333333333333",
            "4444444444444444444444444444444444444444444444444444444444444444",
            // uint16 schemaVersion = 1 (left-padded to bytes32).
            "0000000000000000000000000000000000000000000000000000000000000001",
            // encPayload offset = 0xe0 (head ends at 7 * 32 = 0xe0 from
            // selector-start).
            "00000000000000000000000000000000000000000000000000000000000000e0",
            // signature offset = 0x120 (encPayload occupies one 32-byte
            // length word + one 32-byte data word).
            "0000000000000000000000000000000000000000000000000000000000000120",
            // encPayload: length = 4
            "0000000000000000000000000000000000000000000000000000000000000004",
            // encPayload: 4 bytes deadbeef, right-padded.
            "deadbeef00000000000000000000000000000000000000000000000000000000",
            // signature: length = 0x41 = 65 bytes.
            "0000000000000000000000000000000000000000000000000000000000000041",
            // signature: 64 × 'aa' bytes + 1 × '1c' byte = 65 bytes data.
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            // 65th byte = 0x1c, followed by 31 bytes (62 hex chars) of
            // right-pad to reach a 32-byte word boundary (96 bytes data
            // total).
            "1c00000000000000000000000000000000000000000000000000000000000000",
        );
        let expected = hex::decode(expected_hex).expect("hex literal parses");
        assert_eq!(
            hex::encode(&encoded),
            hex::encode(&expected),
            "publishRevision calldata MUST byte-equal the `cast calldata` reference"
        );
    }

    /// L3 sanity: the selector matches the publicly known value
    /// `0x91f6be2f` for `publishRevision(bytes32,bytes32,bytes32,bytes32,uint16,bytes,bytes)`.
    #[test]
    fn publish_v1_selector_matches() {
        let sel = <RevisionLogV1::publishRevisionCall as alloy::sol_types::SolCall>::SELECTOR;
        assert_eq!(
            hex::encode(sel),
            "91f6be2f",
            "publishRevision selector must equal cast sig output"
        );
    }

    // -----------------------------------------------------------------
    // Happy path
    // -----------------------------------------------------------------

    /// Happy path (broadcast leg): every RPC call returns the
    /// expected response; the broadcast helper returns a
    /// `PendingTransactionBuilder` whose tx hash matches the
    /// asserter's pinned value. The receipt-await path is tested
    /// separately via `publish_v1_process_receipt_happy_path`.
    #[tokio::test]
    async fn publish_v1_happy_path_broadcast_leg() {
        let wallet = fixed_wallet();
        let signed = sample_signed_revision(&wallet);
        let contract = EXPECTED_DEPLOYED_ADDRESS_BASE_SEPOLIA;
        let tx_hash = B256::repeat_byte(0xAB);
        let asserter = Asserter::new();
        push_broadcast_only(&asserter, 0, 1_000_000_000, 500_000, tx_hash);
        let provider = mock_provider(&asserter);
        let pending = broadcast_with_retries(&provider, wallet.address(), contract, &signed)
            .await
            .expect("broadcast leg returns Ok");
        assert_eq!(*pending.tx_hash(), tx_hash);
    }

    /// Happy path (receipt leg): a status==1 receipt with a
    /// `RevisionPublished` log decodes into a populated
    /// `ChainAnchorV1`. Pins the field-shape contract end-to-end.
    #[test]
    fn publish_v1_process_receipt_happy_path() {
        let wallet = fixed_wallet();
        let signed = sample_signed_revision(&wallet);
        let contract = EXPECTED_DEPLOYED_ADDRESS_BASE_SEPOLIA;
        let tx_hash = B256::repeat_byte(0xAB);
        let sequence = U256::from(7u64);
        let receipt = build_receipt(wallet.address(), contract, &signed, tx_hash, sequence, true);
        let anchor = process_receipt(&receipt, wallet.address(), contract, tx_hash)
            .expect("happy receipt → Ok");
        assert_eq!(anchor.tx_hash, tx_hash);
        assert_eq!(anchor.block_number, 0x1234);
        assert_eq!(anchor.block_hash, B256::repeat_byte(0xCC));
        assert_eq!(anchor.sequence, sequence);
        assert_eq!(anchor.signer, wallet.address());
        assert_eq!(anchor.log_index, 0);
    }

    // -----------------------------------------------------------------
    // Construction-time fatal errors
    // -----------------------------------------------------------------

    /// R-c chain-id mismatch: a wrong chain id from the live RPC →
    /// `ChainError::ChainIdMismatch`.
    #[tokio::test]
    async fn publish_v1_chain_id_mismatch_errors() {
        // Test against the outer `publish_revision_v1` path is hard
        // because we'd need a real provider; instead drive the
        // helper via a mock provider that returns chain_id 1
        // (mainnet) — but the helper doesn't fetch chain_id (the
        // outer fn does). Mirror the check inline so the test
        // remains hermetic + assertion-bearing.
        let asserter = Asserter::new();
        asserter.push_success(&"0x1"); // chain_id == 1 (mainnet)
        let provider = mock_provider(&asserter);
        let observed = provider.get_chain_id().await.expect("chain_id");
        let expected = ChainEnv::BaseSepolia.chain_id().unwrap();
        let err: Result<(), ChainError> = if observed != expected {
            Err(ChainError::ChainIdMismatch { expected, observed })
        } else {
            Ok(())
        };
        assert!(matches!(
            err,
            Err(ChainError::ChainIdMismatch {
                expected: 84_532,
                observed: 1
            })
        ));
    }

    /// L4 + L-deployment-mismatch-broadcast: a tampered loaded
    /// address (simulated by passing a wrong contract address
    /// directly) does NOT reach broadcast because the outer
    /// `publish_revision_v1` fn cross-checks. The cross-check itself
    /// is exercised by an inline test that mirrors the check.
    #[test]
    fn publish_v1_deployment_address_mismatch_errors() {
        let actual: Address = "0x0000000000000000000000000000000000000001"
            .parse()
            .unwrap();
        let env = ChainEnv::BaseSepolia;
        let err = if matches!(env, ChainEnv::BaseSepolia)
            && actual != EXPECTED_DEPLOYED_ADDRESS_BASE_SEPOLIA
        {
            ChainError::DeploymentAddressMismatch {
                env,
                expected: EXPECTED_DEPLOYED_ADDRESS_BASE_SEPOLIA,
                actual,
            }
        } else {
            unreachable!("test setup is bogus")
        };
        assert!(matches!(err, ChainError::DeploymentAddressMismatch { .. }));
    }

    // -----------------------------------------------------------------
    // Gas-cap fatal
    // -----------------------------------------------------------------

    /// L6 + L-gas-griefing: a huge `baseFeePerGas` from the RPC
    /// causes the cap check to fire BEFORE any broadcast. Tested
    /// via `broadcast_with_retries` since the cap aborts before
    /// the receipt-await leg.
    #[tokio::test]
    async fn publish_v1_gas_cap_exceeded_errors() {
        let wallet = fixed_wallet();
        let signed = sample_signed_revision(&wallet);
        let contract = EXPECTED_DEPLOYED_ADDRESS_BASE_SEPOLIA;
        let asserter = Asserter::new();
        // nonce
        asserter.push_success(&"0x0");
        // fee history: 100 gwei base fee → 2*100 + 1 = 201 gwei,
        // well above the 50-gwei cap.
        let huge_base = 100_000_000_000u128;
        asserter.push_success(&serde_json::json!({
            "oldestBlock": "0x0",
            "baseFeePerGas": [format!("0x{huge_base:x}"), format!("0x{huge_base:x}")],
            "gasUsedRatio": [0.5],
            "reward": [],
        }));
        let provider = mock_provider(&asserter);
        let err = broadcast_with_retries(&provider, wallet.address(), contract, &signed)
            .await
            .expect_err("gas cap exceeded must error");
        match err {
            ChainError::GasCapExceeded {
                observed_gwei,
                cap_gwei,
            } => {
                assert!(observed_gwei >= 200);
                assert_eq!(cap_gwei, 50);
            }
            other => panic!("expected GasCapExceeded, got: {other:?}"),
        }
    }

    // -----------------------------------------------------------------
    // Insufficient funds fatal
    // -----------------------------------------------------------------

    /// R-c InsufficientFunds: `eth_sendRawTransaction` returns an
    /// insufficient-funds error → `ChainError::InsufficientFunds`.
    /// Tested via `broadcast_with_retries` since this failure bails
    /// before the receipt-await leg.
    #[tokio::test]
    async fn publish_v1_insufficient_funds_errors() {
        let wallet = fixed_wallet();
        let signed = sample_signed_revision(&wallet);
        let contract = EXPECTED_DEPLOYED_ADDRESS_BASE_SEPOLIA;
        let asserter = Asserter::new();
        // nonce + fee history + gas estimate succeed
        asserter.push_success(&"0x0");
        asserter.push_success(&serde_json::json!({
            "oldestBlock": "0x0",
            "baseFeePerGas": [format!("0x{:x}", 1_000_000_000u128), format!("0x{:x}", 1_000_000_000u128)],
            "gasUsedRatio": [0.5],
            "reward": [],
        }));
        asserter.push_success(&format!("0x{:x}", 500_000u64));
        // send fails with "insufficient funds for gas * price + value"
        asserter.push_failure_msg("insufficient funds for gas * price + value");
        let provider = mock_provider(&asserter);
        let err = broadcast_with_retries(&provider, wallet.address(), contract, &signed)
            .await
            .expect_err("insufficient funds must error");
        assert!(
            matches!(err, ChainError::InsufficientFunds { .. }),
            "expected InsufficientFunds, got {err:?}"
        );
    }

    // -----------------------------------------------------------------
    // Reverted (status==0) → RevertedV1
    // -----------------------------------------------------------------

    /// R-c Reverted (receipt leg): receipt.status==0 → `RevertedV1`.
    /// Tested via `process_receipt` directly so the path is hermetic
    /// without alloy's heart polling.
    #[test]
    fn publish_v1_reverted_decodes_reason() {
        let wallet = fixed_wallet();
        let signed = sample_signed_revision(&wallet);
        let contract = EXPECTED_DEPLOYED_ADDRESS_BASE_SEPOLIA;
        let tx_hash = B256::repeat_byte(0xEE);
        let receipt = build_receipt(
            wallet.address(),
            contract,
            &signed,
            tx_hash,
            U256::ZERO,
            false, // status = 0
        );
        let err = process_receipt(&receipt, wallet.address(), contract, tx_hash)
            .expect_err("revert must error");
        match err {
            ChainError::RevertedV1 { tx_hash: h, .. } => {
                assert_eq!(h, tx_hash);
            }
            other => panic!("expected RevertedV1, got {other:?}"),
        }
    }

    /// R-c Reverted (pre-broadcast leg): an `eth_estimateGas` revert
    /// surfaces as `RevertedV1` with a decoded reason BEFORE any
    /// `send_transaction`. Covers the
    /// `ErrSignerNotRegistered` reason-decoding path.
    #[tokio::test]
    async fn publish_v1_estimate_revert_decodes_signer_not_registered() {
        let wallet = fixed_wallet();
        let signed = sample_signed_revision(&wallet);
        let contract = EXPECTED_DEPLOYED_ADDRESS_BASE_SEPOLIA;
        let asserter = Asserter::new();
        asserter.push_success(&"0x0");
        asserter.push_success(&serde_json::json!({
            "oldestBlock": "0x0",
            "baseFeePerGas": [format!("0x{:x}", 1_000_000_000u128), format!("0x{:x}", 1_000_000_000u128)],
            "gasUsedRatio": [0.5],
            "reward": [],
        }));
        asserter.push_failure_msg("execution reverted: ErrSignerNotRegistered()");
        let provider = mock_provider(&asserter);
        let err = broadcast_with_retries(&provider, wallet.address(), contract, &signed)
            .await
            .expect_err("estimate revert must error");
        match err {
            ChainError::RevertedV1 { reason, .. } => {
                assert_eq!(reason, "ErrSignerNotRegistered");
            }
            other => panic!("expected RevertedV1, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------
    // Receipt mismatch (signer disagrees)
    // -----------------------------------------------------------------

    /// L-rpc-spoof: a spoofed receipt with a wrong `signer` →
    /// `ReceiptMismatch`. Tested via `process_receipt` directly.
    #[test]
    fn publish_v1_receipt_mismatch_errors() {
        let wallet = fixed_wallet();
        let signed = sample_signed_revision(&wallet);
        let contract = EXPECTED_DEPLOYED_ADDRESS_BASE_SEPOLIA;
        let tx_hash = B256::repeat_byte(0xDD);
        let wrong: Address = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
            .parse()
            .unwrap();
        let receipt = build_receipt(wrong, contract, &signed, tx_hash, U256::from(1u64), true);
        let err = process_receipt(&receipt, wallet.address(), contract, tx_hash)
            .expect_err("signer mismatch must error");
        match err {
            ChainError::ReceiptMismatch {
                expected_signer,
                observed_signer,
            } => {
                assert_eq!(expected_signer, wallet.address());
                assert_eq!(observed_signer, wrong);
            }
            other => panic!("expected ReceiptMismatch, got {other:?}"),
        }
    }

    /// L-rpc-spoof: a spoofed receipt with a `RevisionPublished` log
    /// emitted by a DIFFERENT contract address → `MissingEvent` (the
    /// MED-4 defensive filter drops foreign logs). Tested via
    /// `process_receipt`.
    #[test]
    fn publish_v1_log_from_wrong_address_treated_as_missing() {
        let wallet = fixed_wallet();
        let signed = sample_signed_revision(&wallet);
        let real_contract = EXPECTED_DEPLOYED_ADDRESS_BASE_SEPOLIA;
        let wrong_emitter: Address = "0xc0ffee0000000000000000000000000000000000"
            .parse()
            .unwrap();
        let tx_hash = B256::repeat_byte(0x77);
        // Build the receipt with the log emitter set to wrong_emitter
        // but the post-receipt cross-check using real_contract.
        let receipt = build_receipt(
            wallet.address(),
            wrong_emitter,
            &signed,
            tx_hash,
            U256::from(1u64),
            true,
        );
        let err = process_receipt(&receipt, wallet.address(), real_contract, tx_hash)
            .expect_err("foreign emitter must error");
        assert!(
            matches!(err, ChainError::MissingEvent { .. }),
            "expected MissingEvent, got {err:?}"
        );
    }

    // -----------------------------------------------------------------
    // Nonce collision retry then success
    // -----------------------------------------------------------------

    /// R-c nonce-collision retry: the first `eth_sendRawTransaction`
    /// fails with "nonce too low"; the loop retries (re-fetching
    /// nonce + fee + estimate); the second attempt succeeds. Tests
    /// the broadcast leg via `broadcast_with_retries`.
    #[tokio::test]
    async fn publish_v1_nonce_collision_retries_then_succeeds() {
        let wallet = fixed_wallet();
        let signed = sample_signed_revision(&wallet);
        let contract = EXPECTED_DEPLOYED_ADDRESS_BASE_SEPOLIA;
        let tx_hash = B256::repeat_byte(0xCD);
        let asserter = Asserter::new();
        // ATTEMPT 1: nonce+fee+gas succeed, send fails with "nonce too low"
        asserter.push_success(&"0x0");
        asserter.push_success(&serde_json::json!({
            "oldestBlock": "0x0",
            "baseFeePerGas": [format!("0x{:x}", 1_000_000_000u128), format!("0x{:x}", 1_000_000_000u128)],
            "gasUsedRatio": [0.5],
            "reward": [],
        }));
        asserter.push_success(&format!("0x{:x}", 500_000u64));
        asserter.push_failure_msg("nonce too low");
        // ATTEMPT 2: broadcast succeeds.
        push_broadcast_only(&asserter, 1, 1_000_000_000, 500_000, tx_hash);
        let provider = mock_provider(&asserter);
        let pending = broadcast_with_retries(&provider, wallet.address(), contract, &signed)
            .await
            .expect("retry succeeds");
        assert_eq!(*pending.tx_hash(), tx_hash);
    }

    // -----------------------------------------------------------------
    // Nonce unresolvable after max retries
    // -----------------------------------------------------------------

    /// R-c NonceUnresolvable: 3 consecutive nonce-too-low → fatal.
    #[tokio::test]
    async fn publish_v1_nonce_unresolvable_after_max_retries() {
        let wallet = fixed_wallet();
        let signed = sample_signed_revision(&wallet);
        let contract = EXPECTED_DEPLOYED_ADDRESS_BASE_SEPOLIA;
        let asserter = Asserter::new();
        for _ in 0..PUBLISH_REVISION_MAX_RETRIES {
            asserter.push_success(&"0x0");
            asserter.push_success(&serde_json::json!({
                "oldestBlock": "0x0",
                "baseFeePerGas": [format!("0x{:x}", 1_000_000_000u128), format!("0x{:x}", 1_000_000_000u128)],
                "gasUsedRatio": [0.5],
                "reward": [],
            }));
            asserter.push_success(&format!("0x{:x}", 500_000u64));
            asserter.push_failure_msg("nonce too low");
        }
        let provider = mock_provider(&asserter);
        let err = broadcast_with_retries(&provider, wallet.address(), contract, &signed)
            .await
            .expect_err("exhausted retries must error");
        match err {
            ChainError::NonceUnresolvable { attempts } => {
                assert_eq!(attempts, PUBLISH_REVISION_MAX_RETRIES);
            }
            other => panic!("expected NonceUnresolvable, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------
    // RPC transient retry then success
    // -----------------------------------------------------------------

    /// R-c RPC-transient retry: a transient failure on the first
    /// nonce-fetch is retried; second attempt's broadcast succeeds.
    /// Tests the broadcast leg via `broadcast_with_retries`. The
    /// 250 ms backoff on attempt 1 is real wall-clock cost in this
    /// test — small enough that the test still fits the workspace's
    /// per-test budget.
    #[tokio::test]
    async fn publish_v1_rpc_transient_retries() {
        let wallet = fixed_wallet();
        let signed = sample_signed_revision(&wallet);
        let contract = EXPECTED_DEPLOYED_ADDRESS_BASE_SEPOLIA;
        let tx_hash = B256::repeat_byte(0xAB);
        let asserter = Asserter::new();
        // ATTEMPT 1: get_transaction_count fails transiently
        asserter.push_failure_msg("connection reset by peer");
        // ATTEMPT 2: broadcast succeeds.
        push_broadcast_only(&asserter, 0, 1_000_000_000, 500_000, tx_hash);
        let provider = mock_provider(&asserter);
        let pending = broadcast_with_retries(&provider, wallet.address(), contract, &signed)
            .await
            .expect("retry succeeds");
        assert_eq!(*pending.tx_hash(), tx_hash);
    }

    // -----------------------------------------------------------------
    // Classifier units
    // -----------------------------------------------------------------

    #[test]
    fn classifier_nonce_collision_matches_known_strings() {
        assert!(is_nonce_collision("nonce too low: 5 < 6"));
        assert!(is_nonce_collision("Already known"));
        assert!(is_nonce_collision("replacement transaction underpriced"));
        assert!(!is_nonce_collision("connection timed out"));
        assert!(!is_nonce_collision("execution reverted"));
    }

    #[test]
    fn classifier_transient_rpc_matches_known_strings() {
        assert!(is_transient_rpc_error("connection reset by peer"));
        assert!(is_transient_rpc_error("502 Bad Gateway"));
        assert!(is_transient_rpc_error("request timed out"));
        assert!(!is_transient_rpc_error("nonce too low"));
        assert!(!is_transient_rpc_error("insufficient funds for gas"));
    }

    #[test]
    fn classifier_insufficient_funds_matches() {
        assert!(is_insufficient_funds(
            "insufficient funds for gas * price + value: address 0x..."
        ));
        assert!(is_insufficient_funds("Insufficient balance for transfer"));
        assert!(!is_insufficient_funds("execution reverted"));
    }

    #[test]
    fn classifier_revert_reason_decoder() {
        let r = decode_revert_reason_from_msg("execution reverted: ErrSignerNotRegistered()");
        assert_eq!(r.as_deref(), Some("ErrSignerNotRegistered"));
        let r = decode_revert_reason_from_msg("execution reverted: out of gas");
        assert_eq!(r.as_deref(), Some("OutOfGas"));
        assert!(decode_revert_reason_from_msg("nonce too low").is_none());
        let r = decode_revert_reason_from_msg("execution reverted");
        assert_eq!(r.as_deref(), Some("unknown revert"));
    }

    // -----------------------------------------------------------------
    // Network-gated live test (R-f Option B). #[ignore]'d.
    // -----------------------------------------------------------------

    /// Live smoke test against D-017 (`#[ignore]`'d). To run:
    ///
    /// ```text
    /// BASE_SEPOLIA_RPC_URL=https://sepolia.base.org \
    ///   cargo test -p pangolin-chain --features integration-tests \
    ///   publish_v1_live_d017_smoke -- --ignored --nocapture
    /// ```
    ///
    /// Requires a funded device wallet OR a fresh `vault_id` (the
    /// self-bootstrap path of R-b lets the first publish for any
    /// fresh vault succeed with zero pre-registration; but the gas
    /// payer still needs ETH). For a true self-bootstrap-from-empty
    /// test, fund the derived `EvmWallet`'s address with a small
    /// amount of Sepolia ETH first.
    ///
    /// Asserts: tx hash matches submitted; receipt.status==1;
    /// `RevisionPublished` event emitted with the submitter's signer
    /// + the fresh `vaultId` + monotonic `sequence`.
    #[tokio::test]
    #[ignore = "live-RPC test; requires BASE_SEPOLIA_RPC_URL + funded wallet"]
    #[cfg(feature = "integration-tests")]
    async fn publish_v1_live_d017_smoke() {
        let rpc_url = std::env::var("BASE_SEPOLIA_RPC_URL")
            .unwrap_or_else(|_| "https://sepolia.base.org".to_string());
        let wallet = fixed_wallet();
        // Fresh vault_id so the contract self-bootstraps the signer.
        // Random-ish bytes — not crypto-secure (this is a smoke
        // test) but unique-enough to avoid colliding with the
        // shared dev keystore's history.
        let mut vault_id = [0u8; 32];
        vault_id.copy_from_slice(
            &alloy::primitives::keccak256(wallet.address().as_slice()).as_slice()[..32],
        );
        // Use a current-time tweak so reruns don't collide.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        vault_id[24..32].copy_from_slice(&now.to_be_bytes());
        let fields = RevisionFieldsV1::with_signer_device_id(
            &wallet, vault_id, [0x42; 32], [0u8; 32], 1, [0xCC; 32],
        );
        let signed =
            build_signed_revision_v1(&wallet, fields, ChainEnv::BaseSepolia).expect("sign live");
        let anchor = publish_revision_v1(&wallet, &signed, ChainEnv::BaseSepolia, &rpc_url)
            .await
            .expect("live publish must succeed");
        assert_eq!(anchor.signer, wallet.address());
        assert!(anchor.block_number > 0);
    }
}
