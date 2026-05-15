// SPDX-License-Identifier: AGPL-3.0-or-later
//! Balance read + next-publish cost estimate + state machine (MVP-2 issue 3.5).
//!
//! Per Kelvin's R-a/R-c sign-off (2026-05-15 in `docs/issue-plans/3.5.md`):
//! the chain crate owns the balance-check + cost-estimate logic as free
//! async functions; the `GasBalanceState` enum + a pure
//! `compute_balance_state` function are the surface a host renders.
//! `Vault` exposes a separate SYNC `evm_wallet_address` accessor (see
//! `pangolin-store::Vault`); the caller orchestrates `Vault::evm_wallet_address`
//! (sync) → `query_evm_balance` (async) → `estimate_next_publish_cost`
//! (async) → `compute_balance_state` (sync, pure).
//!
//! ## L-section invariants (`docs/issue-plans/3.5.md`)
//!
//! - **L-rpc-spoof-balance defense** — every balance read sanity-checks
//!   `eth_chainId` against the build's `ChainEnv::chain_id()` BEFORE
//!   accepting the balance value. A spoofing RPC reporting fake high
//!   balance + wrong chain id is rejected with
//!   [`ChainError::ChainIdMismatch`]. (The chain-id match alone does
//!   NOT prove the balance is authoritative — the authoritative failure
//!   path is the on-chain `eth_sendRawTransaction` response per 3.3 —
//!   but it shrinks the spoof surface for the advisory state.)
//! - **L-state-leak-via-label** — the [`GasBalanceState`] variants carry
//!   wei values for hosts that EXPLICITLY want to render numeric
//!   detail; the **`Debug` impl** redacts wei to `"<wei>"` in release
//!   builds so log files cannot leak balance to an observer. Debug
//!   builds show the value (developer ergonomics).
//! - **L4 §8.1.5 vocabulary** — variant names are boolean-ish
//!   (`Sufficient` / `RequiresActiveAccount`) — NEVER "out of gas",
//!   "low balance", "insufficient funds", "upgrade", or any pricing
//!   copy. Pinned by [`tests::gas_balance_state_label_pinning`].
//! - **L1 + L7** — thin wrapper around `provider.get_balance`; NO new
//!   `pangolin-store` import; NO new external crate dep (alloy + tokio
//!   only).
//! - **L6** — balance is never persisted to disk; this module computes
//!   transient state from a fresh RPC read every time.

use alloy::primitives::{Address, U256};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::rpc::types::BlockNumberOrTag;

use crate::chain_submit::{MAX_FEE_PER_GAS_CAP_WEI, PRIORITY_FEE_DEFAULT_WEI};
use crate::deployments::ChainEnv;
use crate::error::ChainError;

// ---------------------------------------------------------------------
// Pinned constants (R-c verbatim)
// ---------------------------------------------------------------------

/// Expected gas a v1 `publishRevision` call consumes, in units.
///
/// The 3.3 gas-estimate observation shows real publish costs settle in
/// the 200k–400k gas band on Base Sepolia; we pick `500_000` as a safe
/// headroom-inclusive ceiling for the cost-estimate (the
/// `eth_estimateGas` path inside 3.3's broadcast loop still applies
/// its own 1.2x safety margin against the actual measured gas; this
/// `500_000` figure is the ESTIMATE-WORLD upper bound used to decide
/// whether the device's balance covers `MIN_BUFFER_REVISIONS = 3`
/// future publishes).
pub const EXPECTED_REVISION_GAS: u64 = 500_000;

/// Number of revisions the device should be able to publish before the
/// state surface trips to `RequiresActiveAccount`.
///
/// Per R-c sub-question: `3`. A user with `balance >= 3 *
/// estimate_next_publish_cost()` sees `Sufficient`; below that the
/// host can render the `RequiresActiveAccount` flow.
pub const MIN_BUFFER_REVISIONS: u32 = 3;

// ---------------------------------------------------------------------
// GasBalanceState enum (R-d shape)
// ---------------------------------------------------------------------

/// Client-side gas-balance state for the device's EVM wallet.
///
/// Variant names follow the §8.1.5 entitlement-state vocabulary
/// verbatim: NEVER `InsufficientFunds`, `LowBalance`, `OutOfGas`, or
/// any pricing copy. Pinned by [`tests::gas_balance_state_label_pinning`]
/// (L4).
///
/// ## `Debug` redaction (L-state-leak-via-label)
///
/// The `Debug` impl below redacts the `balance_wei` / `estimate_wei`
/// fields in release builds (so log files / `tracing::error!` calls
/// cannot expose precise wallet balance to a passive observer who has
/// the on-chain-observable device address). Debug builds keep the raw
/// values for developer ergonomics.
#[derive(Clone, PartialEq, Eq)]
pub enum GasBalanceState {
    /// The device wallet's balance covers at least
    /// `MIN_BUFFER_REVISIONS = 3` future revisions at the currently-
    /// observed gas price.
    Sufficient {
        /// Wallet balance at observation time, in wei.
        balance_wei: u128,
        /// `EXPECTED_REVISION_GAS × max_fee_per_gas × MIN_BUFFER_REVISIONS`
        /// — the cost ceiling under which `balance_wei` is considered
        /// sufficient.
        estimate_wei: u128,
    },
    /// The device wallet's balance does NOT cover the
    /// `MIN_BUFFER_REVISIONS = 3` next-publish ceiling. The host
    /// renders the user-facing "requires active account" flow (§8.1.5)
    /// — never pricing copy.
    RequiresActiveAccount {
        /// Wallet balance at observation time, in wei.
        balance_wei: u128,
        /// `EXPECTED_REVISION_GAS × max_fee_per_gas × MIN_BUFFER_REVISIONS`
        /// — the cost ceiling the balance falls under.
        estimate_wei: u128,
    },
    /// A top-up attempt is in flight. The monitor surfaces this state
    /// after [`crate::balance_monitor::BalanceMonitor::register_top_up`]
    /// is called and until the next poll cycle observes a new balance.
    TopUpInFlight {
        /// Unix timestamp (seconds) when the top-up was initiated.
        initiated_at_unix: u64,
    },
    /// State could not be determined — RPC failure, no balance read
    /// yet, locked vault at the FFI boundary, etc. Hosts render
    /// "checking" / "unknown" — never a pricing-copy fallback.
    Unknown {
        /// Non-secret human description of why the state is unknown
        /// (e.g. `"polling"`, `"rpc transient: <message>"`,
        /// `"chain id mismatch"`).
        reason: String,
    },
}

impl core::fmt::Debug for GasBalanceState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // L-state-leak-via-label: redact wei fields in release builds.
        // Debug builds (`cfg(debug_assertions)`) show the raw values so
        // developers can trace state transitions; release binaries log
        // only the variant name + `"<wei>"` placeholder.
        match self {
            Self::Sufficient {
                balance_wei,
                estimate_wei,
            } => {
                let mut s = f.debug_struct("Sufficient");
                #[cfg(debug_assertions)]
                {
                    s.field("balance_wei", balance_wei)
                        .field("estimate_wei", estimate_wei);
                }
                #[cfg(not(debug_assertions))]
                {
                    let _ = (balance_wei, estimate_wei);
                    s.field("balance_wei", &"<wei>")
                        .field("estimate_wei", &"<wei>");
                }
                s.finish()
            }
            Self::RequiresActiveAccount {
                balance_wei,
                estimate_wei,
            } => {
                let mut s = f.debug_struct("RequiresActiveAccount");
                #[cfg(debug_assertions)]
                {
                    s.field("balance_wei", balance_wei)
                        .field("estimate_wei", estimate_wei);
                }
                #[cfg(not(debug_assertions))]
                {
                    let _ = (balance_wei, estimate_wei);
                    s.field("balance_wei", &"<wei>")
                        .field("estimate_wei", &"<wei>");
                }
                s.finish()
            }
            Self::TopUpInFlight { initiated_at_unix } => f
                .debug_struct("TopUpInFlight")
                .field("initiated_at_unix", initiated_at_unix)
                .finish(),
            Self::Unknown { reason } => f.debug_struct("Unknown").field("reason", reason).finish(),
        }
    }
}

// ---------------------------------------------------------------------
// Public functions (R-a shape)
// ---------------------------------------------------------------------

/// Query the on-chain ETH balance of `address` against `rpc_url`.
///
/// Sanity-checks `eth_chainId` against `env.chain_id()` BEFORE accepting
/// the balance value — L-rpc-spoof-balance partial defense. A
/// `ChainEnv::Dev` env (whose `chain_id()` is `None`) skips the check,
/// matching the `chain_submit` posture.
///
/// # Errors
///
/// - [`ChainError::Rpc`] / [`ChainError::BalanceQueryFailed`] — RPC
///   transport failure (timeout, 5xx, parse error) on either the chain-id
///   probe or the balance fetch.
/// - [`ChainError::ChainIdMismatch`] — `eth_chainId` returned a value
///   that doesn't match `env.chain_id()`.
pub async fn query_evm_balance(
    rpc_url: &str,
    address: Address,
    env: ChainEnv,
) -> Result<U256, ChainError> {
    let provider = build_read_only_provider(rpc_url).await?;
    query_evm_balance_with_provider(&provider, address, env).await
}

/// Provider-bound variant of [`query_evm_balance`] for hermetic tests
/// that drive a mocked alloy provider AND for in-module callers that
/// already hold an alloy provider (`chain_submit::publish_revision_v1_with_config`'s
/// pre-publish balance gate). Production external callers go through
/// [`query_evm_balance`] which constructs the provider itself.
pub(crate) async fn query_evm_balance_with_provider(
    provider: &DynProvider,
    address: Address,
    env: ChainEnv,
) -> Result<U256, ChainError> {
    // L-rpc-spoof-balance: cross-check `eth_chainId` BEFORE accepting
    // the balance. `ChainEnv::Dev` returns None and skips the check
    // (mirrors `publish_revision_v1`'s posture in `chain_submit.rs`).
    if let Some(expected_chain_id) = env.chain_id() {
        let observed =
            provider
                .get_chain_id()
                .await
                .map_err(|e| ChainError::BalanceQueryFailed {
                    detail: format!("eth_chainId: {e}"),
                })?;
        if observed != expected_chain_id {
            return Err(ChainError::ChainIdMismatch {
                expected: expected_chain_id,
                observed,
            });
        }
    }
    provider
        .get_balance(address)
        .await
        .map_err(|e| ChainError::BalanceQueryFailed {
            detail: format!("eth_getBalance({address:?}): {e}"),
        })
}

/// Estimate the cost of the next revision publish, including the
/// `MIN_BUFFER_REVISIONS = 3` safety margin.
///
/// Per R-c (hybrid):
///
/// 1. Try `eth_feeHistory` for `baseFeePerGas`; compute
///    `max_fee_per_gas = 2 * baseFee + PRIORITY_FEE_DEFAULT_WEI`
///    (mirrors `chain_submit::publish_revision_v1`'s formula verbatim).
/// 2. If `eth_feeHistory` errors OR returns zero, fall back to the
///    conservative ceiling `MAX_FEE_PER_GAS_CAP_WEI`.
/// 3. Multiply by `EXPECTED_REVISION_GAS = 500_000` and
///    `MIN_BUFFER_REVISIONS = 3`.
///
/// The returned U256 is the threshold the device wallet must clear for
/// the state to be `Sufficient`. Overflow is saturated to `U256::MAX`
/// (vanishingly impractical with the pinned constants but guarded for
/// defense-in-depth).
///
/// # Errors
///
/// - [`ChainError::BalanceQueryFailed`] — the provider construction
///   itself failed. Note that an `eth_feeHistory` RPC error does NOT
///   error here; it triggers the fallback path with a WARN log.
pub async fn estimate_next_publish_cost(rpc_url: &str, env: ChainEnv) -> Result<U256, ChainError> {
    let provider = build_read_only_provider(rpc_url).await?;
    estimate_next_publish_cost_with_provider(&provider, env).await
}

/// Provider-bound variant for hermetic tests AND for in-module callers
/// that already hold an alloy provider (`chain_submit::publish_revision_v1_with_config`'s
/// pre-publish balance gate).
pub(crate) async fn estimate_next_publish_cost_with_provider(
    provider: &DynProvider,
    env: ChainEnv,
) -> Result<U256, ChainError> {
    // R-c hybrid: dynamic via `eth_feeHistory` when available, else
    // conservative ceiling. The clamp-to-cap mirrors the per-tx
    // gas-cap defended in `chain_submit::publish_revision_v1` (R-b);
    // if `eth_feeHistory` reports a spike above the cap, the actual
    // publish would refuse at `GasCapExceeded` anyway — for the
    // ESTIMATE we surface the realistic ceiling.
    let max_fee_per_gas_u128 = fetch_base_fee_with_fallback(provider, env).await.map_or(
        MAX_FEE_PER_GAS_CAP_WEI,
        |base_fee| {
            let computed = base_fee
                .saturating_mul(2)
                .saturating_add(PRIORITY_FEE_DEFAULT_WEI);
            core::cmp::min(computed, MAX_FEE_PER_GAS_CAP_WEI)
        },
    );
    let max_fee_u256 = U256::from(max_fee_per_gas_u128);
    let gas_u256 = U256::from(EXPECTED_REVISION_GAS);
    let buffer_u256 = U256::from(MIN_BUFFER_REVISIONS);
    let estimate = max_fee_u256
        .saturating_mul(gas_u256)
        .saturating_mul(buffer_u256);
    Ok(estimate)
}

/// Pure function: compute the state from a balance + estimate pair.
///
/// `balance >= estimate` → `Sufficient`; else `RequiresActiveAccount`.
/// Both variants carry the raw wei values so a host can render numeric
/// detail when it wants to (default UX shows label-only per L4).
///
/// The function ONLY returns `Sufficient` / `RequiresActiveAccount` —
/// the other two variants (`TopUpInFlight`, `Unknown`) are surfaced
/// by upstream paths (the monitor's `register_top_up` notification +
/// the RPC-failure error path respectively). Keeping this fn pure +
/// total over (balance, estimate) makes the state-transition table
/// easy to audit.
#[must_use]
pub fn compute_balance_state(balance_wei: U256, estimate_wei: U256) -> GasBalanceState {
    // Saturating-to-u128 conversion: the U256 → u128 narrowing here is
    // for host rendering only; the COMPARISON happens on the full U256
    // value above. A balance above u128::MAX (~3.4e20 ETH worth of wei
    // — physically impossible on any real network) renders as u128::MAX
    // in the host's UI but the > comparison was still authoritative.
    let balance_u128 = u128::try_from(balance_wei).unwrap_or(u128::MAX);
    let estimate_u128 = u128::try_from(estimate_wei).unwrap_or(u128::MAX);
    if balance_wei >= estimate_wei {
        GasBalanceState::Sufficient {
            balance_wei: balance_u128,
            estimate_wei: estimate_u128,
        }
    } else {
        GasBalanceState::RequiresActiveAccount {
            balance_wei: balance_u128,
            estimate_wei: estimate_u128,
        }
    }
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

/// Build a read-only alloy provider against `rpc_url`. No wallet
/// attached (every balance-check fn is read-only).
async fn build_read_only_provider(rpc_url: &str) -> Result<DynProvider, ChainError> {
    let provider = ProviderBuilder::new().connect(rpc_url).await.map_err(|e| {
        ChainError::BalanceQueryFailed {
            detail: format!("connect {rpc_url}: {e}"),
        }
    })?;
    Ok(provider.erased())
}

/// Fetch the latest block's `baseFeePerGas` via `eth_feeHistory`. Same
/// shape as `chain_submit::fetch_base_fee` but lives in this module so
/// the cross-module dep set stays tight (the `chain_submit` helper is
/// `pub(crate)` to its module; duplicating ~20 lines is preferable to
/// re-exporting an internal). On failure, returns the error so the
/// caller can decide whether to fall back.
async fn fetch_base_fee_with_fallback<P: Provider>(
    provider: &P,
    env: ChainEnv,
) -> Result<u128, ChainError> {
    // Same chain-id sanity check as `query_evm_balance` — defense-in-
    // depth, prevents an RPC spoof from feeding us a baseFee against
    // the wrong chain. Dev env skips.
    if let Some(expected_chain_id) = env.chain_id() {
        let observed =
            provider
                .get_chain_id()
                .await
                .map_err(|e| ChainError::BalanceQueryFailed {
                    detail: format!("eth_chainId: {e}"),
                })?;
        if observed != expected_chain_id {
            return Err(ChainError::ChainIdMismatch {
                expected: expected_chain_id,
                observed,
            });
        }
    }
    let hist = provider
        .get_fee_history(1, BlockNumberOrTag::Latest, &[])
        .await
        .map_err(|e| ChainError::BalanceQueryFailed {
            detail: format!("eth_feeHistory: {e}"),
        })?;
    if let Some(b) = hist.latest_block_base_fee() {
        if b != 0 {
            return Ok(b);
        }
    }
    // Empty / zero base fee → surface as error so the caller falls back
    // to the conservative ceiling. The chain_submit's helper used
    // `eth_gasPrice` here; the balance-check fall-through prefers the
    // hardcoded cap because we'd rather be PESSIMISTIC about the
    // estimate (under-stating the cost would render `Sufficient` for a
    // user who actually faces a spike).
    Err(ChainError::BalanceQueryFailed {
        detail: "eth_feeHistory returned empty/zero base fee".into(),
    })
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::doc_markdown)]
mod tests {
    use super::*;
    use alloy::primitives::address;
    use alloy::providers::ProviderBuilder;
    use alloy::transports::mock::Asserter;

    /// Build a fully-mocked DynProvider with the supplied Asserter.
    fn mock_provider(asserter: &Asserter) -> DynProvider {
        ProviderBuilder::new()
            .connect_mocked_client(asserter.clone())
            .erased()
    }

    fn sample_address() -> Address {
        address!("0x1234567890123456789012345678901234567890")
    }

    // ---- compute_balance_state pure tests ------------------------

    #[test]
    fn balance_state_sufficient_when_balance_above_threshold() {
        let estimate = U256::from(1_000_000u128);
        let balance = U256::from(3_000_001u128); // 3 * estimate + 1
        let state = compute_balance_state(balance, estimate);
        match state {
            GasBalanceState::Sufficient { .. } => {}
            other => panic!("expected Sufficient, got {other:?}"),
        }
    }

    #[test]
    fn balance_state_requires_active_account_when_below_threshold() {
        let estimate = U256::from(3_000_000u128);
        let balance = U256::from(2_999_999u128); // 3 * (estimate/3) - 1
        let state = compute_balance_state(balance, estimate);
        match state {
            GasBalanceState::RequiresActiveAccount { .. } => {}
            other => panic!("expected RequiresActiveAccount, got {other:?}"),
        }
    }

    #[test]
    fn balance_state_handles_zero_balance() {
        let state = compute_balance_state(U256::ZERO, U256::from(1u128));
        match state {
            GasBalanceState::RequiresActiveAccount {
                balance_wei,
                estimate_wei,
            } => {
                assert_eq!(balance_wei, 0);
                assert_eq!(estimate_wei, 1);
            }
            other => panic!("expected RequiresActiveAccount on zero, got {other:?}"),
        }
    }

    #[test]
    fn balance_state_handles_exact_threshold() {
        // balance == estimate → Sufficient (the comparison is >=).
        let state = compute_balance_state(U256::from(100u128), U256::from(100u128));
        assert!(matches!(state, GasBalanceState::Sufficient { .. }));
    }

    // ---- §8.1.5 vocabulary pinning (L4) --------------------------

    #[test]
    fn gas_balance_state_label_pinning() {
        // Stringify the Debug output of each variant and assert the
        // variant-name prefix matches §8.1.5 vocabulary verbatim. Drift
        // is caught here.
        let sufficient = format!(
            "{:?}",
            GasBalanceState::Sufficient {
                balance_wei: 0,
                estimate_wei: 0,
            }
        );
        assert!(
            sufficient.starts_with("Sufficient"),
            "variant must be 'Sufficient', got {sufficient}"
        );

        let requires = format!(
            "{:?}",
            GasBalanceState::RequiresActiveAccount {
                balance_wei: 0,
                estimate_wei: 0,
            }
        );
        assert!(
            requires.starts_with("RequiresActiveAccount"),
            "variant must be 'RequiresActiveAccount', got {requires}"
        );

        let in_flight = format!(
            "{:?}",
            GasBalanceState::TopUpInFlight {
                initiated_at_unix: 0
            }
        );
        assert!(
            in_flight.starts_with("TopUpInFlight"),
            "variant must be 'TopUpInFlight', got {in_flight}"
        );

        let unknown = format!(
            "{:?}",
            GasBalanceState::Unknown {
                reason: "polling".into()
            }
        );
        assert!(
            unknown.starts_with("Unknown"),
            "variant must be 'Unknown', got {unknown}"
        );

        // Vocabulary BAN list: assert these strings do NOT appear in
        // any variant's Debug form. Drift toward forbidden vocabulary
        // (a "LowBalance"/"OutOfGas"/"InsufficientFunds" rename) fires
        // here.
        for forbidden in [
            "LowBalance",
            "OutOfGas",
            "InsufficientFunds",
            "NotEnoughFunds",
            "Upgrade",
            "Pay",
            "Pricing",
        ] {
            for sample in [&sufficient, &requires, &in_flight, &unknown] {
                assert!(
                    !sample.contains(forbidden),
                    "variant Debug must NOT contain forbidden token {forbidden:?}; got {sample}"
                );
            }
        }
    }

    /// L-state-leak-via-label: in release builds the Debug impl must
    /// redact the wei values; in debug builds the raw values are shown.
    /// Tests run under `cfg(debug_assertions)`-aware paths, so we assert
    /// the variant CARRIES the field name + the redaction sentinel
    /// matches the build mode.
    #[test]
    fn debug_format_redacts_balance_in_release() {
        let state = GasBalanceState::Sufficient {
            balance_wei: 1_234_567_890_u128,
            estimate_wei: 9_876_543_210_u128,
        };
        let s = format!("{state:?}");
        #[cfg(debug_assertions)]
        {
            // Debug build: raw value is present.
            assert!(
                s.contains("1234567890"),
                "debug build must show raw wei value, got {s}"
            );
        }
        #[cfg(not(debug_assertions))]
        {
            // Release build: redaction sentinel is present + raw value
            // is absent.
            assert!(
                s.contains("<wei>"),
                "release build must redact wei to '<wei>', got {s}"
            );
            assert!(
                !s.contains("1234567890"),
                "release build must NOT leak raw wei, got {s}"
            );
        }
    }

    // ---- query_evm_balance hermetic tests ------------------------

    #[tokio::test]
    async fn balance_state_handles_rpc_failure() {
        // Push a transport error to the asserter so eth_chainId fails.
        let asserter = Asserter::new();
        asserter.push_failure_msg("connection refused");
        let provider = mock_provider(&asserter);
        let err =
            query_evm_balance_with_provider(&provider, sample_address(), ChainEnv::BaseSepolia)
                .await
                .expect_err("RPC failure must surface as BalanceQueryFailed");
        match err {
            ChainError::BalanceQueryFailed { detail } => {
                assert!(
                    detail.contains("connection refused")
                        || detail.to_ascii_lowercase().contains("rpc"),
                    "error detail should carry the upstream message, got {detail}"
                );
            }
            other => panic!("expected BalanceQueryFailed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn balance_check_rejects_wrong_chain_id() {
        // Asserter returns chain id 1 (mainnet); env expects 84_532 (Base Sepolia).
        let asserter = Asserter::new();
        asserter.push_success(&format!("0x{:x}", 1u64));
        let provider = mock_provider(&asserter);
        let err =
            query_evm_balance_with_provider(&provider, sample_address(), ChainEnv::BaseSepolia)
                .await
                .expect_err("wrong chain id must error");
        match err {
            ChainError::ChainIdMismatch { expected, observed } => {
                assert_eq!(expected, 84_532);
                assert_eq!(observed, 1);
            }
            other => panic!("expected ChainIdMismatch, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn balance_check_dev_env_skips_chain_id_check() {
        // ChainEnv::Dev → no chain-id check → balance fetch is the first call.
        let asserter = Asserter::new();
        // Balance = 0x42 wei.
        asserter.push_success(&format!("0x{:x}", 0x42u64));
        let provider = mock_provider(&asserter);
        let got = query_evm_balance_with_provider(&provider, sample_address(), ChainEnv::Dev)
            .await
            .expect("Dev env skips chain id check");
        assert_eq!(got, U256::from(0x42u64));
    }

    #[tokio::test]
    async fn balance_check_happy_path() {
        // chain_id then balance.
        let asserter = Asserter::new();
        asserter.push_success(&format!("0x{:x}", 84_532u64));
        asserter.push_success(&format!("0x{:x}", 1_000_000_000_000_000_000u128));
        let provider = mock_provider(&asserter);
        let got =
            query_evm_balance_with_provider(&provider, sample_address(), ChainEnv::BaseSepolia)
                .await
                .expect("happy-path balance fetch");
        assert_eq!(got, U256::from(1_000_000_000_000_000_000u128));
    }

    // ---- estimate_next_publish_cost hermetic tests ---------------

    #[tokio::test]
    async fn estimate_uses_base_fee_when_available() {
        // chain_id then fee_history.
        let asserter = Asserter::new();
        asserter.push_success(&format!("0x{:x}", 84_532u64));
        let base_fee: u128 = 1_000_000_000; // 1 gwei
        asserter.push_success(&serde_json::json!({
            "oldestBlock": "0x0",
            "baseFeePerGas": [format!("0x{base_fee:x}"), format!("0x{base_fee:x}")],
            "gasUsedRatio": [0.5],
            "reward": [],
        }));
        let provider = mock_provider(&asserter);
        let est = estimate_next_publish_cost_with_provider(&provider, ChainEnv::BaseSepolia)
            .await
            .expect("estimate");
        // Formula: (2 * base_fee + 1 gwei) * 500_000 * 3.
        // (2_000_000_000 + 1_000_000_000) * 500_000 * 3 = 4.5e15
        let expected_max_fee: u128 = 2 * base_fee + PRIORITY_FEE_DEFAULT_WEI;
        let expected = U256::from(expected_max_fee)
            * U256::from(EXPECTED_REVISION_GAS)
            * U256::from(MIN_BUFFER_REVISIONS);
        assert_eq!(est, expected);
    }

    #[tokio::test]
    #[allow(non_snake_case)]
    async fn estimate_falls_back_to_cap_when_feeHistory_fails() {
        // chain_id ok; fee_history errors.
        let asserter = Asserter::new();
        asserter.push_success(&format!("0x{:x}", 84_532u64));
        asserter.push_failure_msg("fee history unavailable");
        let provider = mock_provider(&asserter);
        let est = estimate_next_publish_cost_with_provider(&provider, ChainEnv::BaseSepolia)
            .await
            .expect("estimate falls back to cap");
        // Fallback: MAX_FEE_PER_GAS_CAP_WEI * 500_000 * 3.
        let expected = U256::from(MAX_FEE_PER_GAS_CAP_WEI)
            * U256::from(EXPECTED_REVISION_GAS)
            * U256::from(MIN_BUFFER_REVISIONS);
        assert_eq!(est, expected);
    }

    #[tokio::test]
    async fn estimate_clamps_to_cap_when_basefee_spikes() {
        // A base fee so high that 2*base_fee + 1gwei would exceed the cap.
        let asserter = Asserter::new();
        asserter.push_success(&format!("0x{:x}", 84_532u64));
        let huge_base_fee: u128 = MAX_FEE_PER_GAS_CAP_WEI; // 50 gwei — 2x exceeds cap.
        asserter.push_success(&serde_json::json!({
            "oldestBlock": "0x0",
            "baseFeePerGas": [
                format!("0x{huge_base_fee:x}"),
                format!("0x{huge_base_fee:x}")
            ],
            "gasUsedRatio": [0.5],
            "reward": [],
        }));
        let provider = mock_provider(&asserter);
        let est = estimate_next_publish_cost_with_provider(&provider, ChainEnv::BaseSepolia)
            .await
            .expect("estimate clamps to cap");
        // Clamped: MAX_FEE_PER_GAS_CAP_WEI * 500_000 * 3.
        let expected = U256::from(MAX_FEE_PER_GAS_CAP_WEI)
            * U256::from(EXPECTED_REVISION_GAS)
            * U256::from(MIN_BUFFER_REVISIONS);
        assert_eq!(est, expected);
    }

    /// L1 pinning: the constants we ship are exactly what the resolved
    /// decisions table says.
    #[test]
    fn balance_check_constants_are_pinned() {
        assert_eq!(EXPECTED_REVISION_GAS, 500_000);
        assert_eq!(MIN_BUFFER_REVISIONS, 3);
    }
}
