// SPDX-License-Identifier: AGPL-3.0-or-later
//! Shared chain-config FFI Record + the `!Send` runtime bridge (MVP-3
//! issue #100).
//!
//! ## `FfiChainConfig` (R-a)
//!
//! Per-call non-secret config the host supplies to the three chain-
//! mutating bindings (`vault_flush_publish_queue`,
//! `vault_lock_with_drain`, `vault_pull_once`). Bundling these into one
//! Record means future config knobs don't churn each binding's
//! signature. **Zero secret material crosses here** — the gas-paying
//! signer is read engine-side from the unlocked vault (L1); the host
//! supplies only the RPC URL + deployment path + a forward-compat
//! transport toggle.
//!
//! ## The `!Send` runtime bridge
//!
//! `pangolin_core::Vault` is `!Send` (it owns a `RefCell`-bearing
//! `rusqlite::Connection` + a `dyn Clock`). The flush / lock-with-drain
//! / pull engine methods hold `&mut Vault` across `.await`, so the
//! resulting future is `!Send` and cannot be exported as a `UniFFI`
//! `async fn` (which requires `Send` futures). Instead the bindings stay
//! synchronous (`pub fn`) and drive the engine future to completion on a
//! locally-built current-thread tokio runtime: the future never leaves
//! the calling thread, so `!Send` is fine. Hosts call the binding
//! blocking from a worker thread (the established posture for chain
//! calls, mirroring `balance_monitor_start`'s sync read).

#![forbid(unsafe_code)]

use crate::error::FfiError;

/// Per-call non-secret chain configuration (MVP-3 issue #100 R-a).
///
/// Crosses FFI by value. NO secret material — the gas-paying signer is
/// sourced engine-side from the unlocked vault (`Vault::evm_wallet()`),
/// never from this Record (L1).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiChainConfig {
    /// Schema-version slot.
    pub schema_version: u16,
    /// RPC endpoint URL (e.g. `"https://sepolia.base.org"`).
    pub rpc_url: String,
    /// Path to the canonical `contracts/deployments/base-sepolia.json`
    /// deployment file the adapter loads its contract address +
    /// chain-id + runtime-bytecode keccak from.
    pub deployment_path: String,
    /// **Accepted-but-not-forwarded (R-e amendment).** A forward-compat
    /// transport toggle the host can set today; `Vault::pull_once`
    /// currently hardcodes `SyncOptions::default()` and takes no
    /// options arg, so this field is a documented no-op on the pull
    /// path. Wiring it through `pull_once` is a deferred follow-up (the
    /// direct-WS-transport cycle); the slot lives here now so the host
    /// surface need not churn when it lands.
    pub prefer_websocket: bool,
}

/// Schema-version slot value for [`FfiChainConfig`].
pub const FFI_CHAIN_CONFIG_SCHEMA_VERSION: u16 = 1;

/// Build a single-threaded tokio runtime to drive a `!Send` engine
/// future to completion on the calling thread.
///
/// Returns `FfiError::Internal` if the runtime can't be built (an
/// `io::Error` from the OS thread/timer subsystem — a genuine
/// "should never happen" condition the host cannot meaningfully act
/// on, hence `Internal`).
pub(crate) fn build_local_runtime() -> Result<tokio::runtime::Runtime, FfiError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| FfiError::Internal {
            message: format!("failed to build local tokio runtime for chain call: {e}"),
        })
}

/// Drive a `!Send` future to completion on a fresh current-thread
/// runtime. The future never leaves the calling thread, so it is sound
/// for `Vault`'s `!Send` futures. ~Reused across the 3 chain-mutating
/// bindings.
pub(crate) fn block_on_local<F: core::future::Future>(fut: F) -> Result<F::Output, FfiError> {
    let rt = build_local_runtime()?;
    Ok(rt.block_on(fut))
}

/// Map a `pangolin_chain::ChainError` (surfaced by adapter
/// construction in the flush / lock-with-drain bindings) into the FFI
/// taxonomy.
///
/// Construction failures (deployment-file load, RPC connect,
/// chain-id / runtime-bytecode cross-check) are all chain-class; they
/// carry no secret material in their `Display`.
pub(crate) fn chain_into_ffi(err: pangolin_chain::ChainError) -> FfiError {
    FfiError::Chain {
        message: err.to_string(),
    }
}

/// Map a `pangolin_store::BatchFlushError` (surfaced by
/// `flush_publish_queue` / `lock_with_drain`) into the FFI taxonomy.
///
/// - `NoActiveSession` → `Session` (the L4 session-gate class).
/// - `Store(_)` → routed through the existing total
///   `StoreError`→`pangolin_core::Error`→`FfiError` mapping.
/// - `ChainError(_)` → `Chain`.
/// - `BalanceInsufficientForBatch { .. }` → `Chain` with a non-secret
///   message (wei values are on-chain-observable payload, not secrets;
///   the host renders the §8.1.5 `RequiresActiveAccount` flow off the
///   balance monitor, not off this error string).
pub(crate) fn batch_flush_into_ffi(err: pangolin_store::BatchFlushError) -> FfiError {
    match err {
        pangolin_store::BatchFlushError::NoActiveSession => FfiError::Session {
            message: "vault is not unlocked".to_owned(),
        },
        pangolin_store::BatchFlushError::Store(store_err) => {
            FfiError::from(pangolin_core::Error::from(store_err))
        }
        pangolin_store::BatchFlushError::ChainError(chain_err) => FfiError::Chain {
            message: chain_err.to_string(),
        },
        other @ pangolin_store::BatchFlushError::BalanceInsufficientForBatch { .. } => {
            FfiError::Chain {
                message: other.to_string(),
            }
        }
    }
}

/// Map a `pangolin_store::PullError` into the FFI taxonomy.
///
/// - `NoActiveSession` → `Session` (L4).
/// - `Chain(_)` → `Chain`.
/// - `Store(_)` → routed through the total `StoreError` mapping.
pub(crate) fn pull_into_ffi(err: pangolin_store::PullError) -> FfiError {
    match err {
        pangolin_store::PullError::NoActiveSession => FfiError::Session {
            message: "vault is not unlocked".to_owned(),
        },
        pangolin_store::PullError::Chain(chain_err) => FfiError::Chain {
            message: chain_err.to_string(),
        },
        pangolin_store::PullError::Store(store_err) => {
            FfiError::from(pangolin_core::Error::from(store_err))
        }
    }
}

/// Resolve the chain `(env, chain_id)` pair every FFI chain binding uses.
///
/// **Production (no `integration-tests` feature)**: hardcoded
/// [`pangolin_chain::ChainEnv::BaseSepolia`] + its pinned `chain_id`
/// (`84_532`). Defense-in-depth: dev/anvil mode is NEVER reachable
/// from a shipped binary; the host cannot opt into a different chain
/// even if compromised. This is the L1 "testnet-only / D-011" invariant.
///
/// **With `integration-tests`**: consults `PANGOLIN_CHAIN_ENV` via the
/// `pangolin_chain::test_env` seam so anvil-driven FFI E2Es can target
/// `ChainEnv::Dev` + the locally-deployed contracts. Compiled OUT of
/// production builds by the cfg gate; cannot leak.
#[cfg(feature = "integration-tests")]
pub(crate) async fn ffi_chain_env_and_id(
    rpc_url: &str,
) -> Result<(pangolin_chain::ChainEnv, u64), pangolin_chain::ChainError> {
    let env = pangolin_chain::test_env::target_chain_env();
    let chain_id = pangolin_chain::test_env::resolve_signing_chain_id(env, rpc_url).await?;
    Ok((env, chain_id))
}

#[cfg(not(feature = "integration-tests"))]
#[allow(clippy::unused_async)] // signature unified with the integration-tests path
pub(crate) async fn ffi_chain_env_and_id(
    _rpc_url: &str,
) -> Result<(pangolin_chain::ChainEnv, u64), pangolin_chain::ChainError> {
    let env = pangolin_chain::ChainEnv::BaseSepolia;
    let chain_id = env
        .chain_id()
        .expect("BaseSepolia has a pinned chain_id (84_532)");
    Ok((env, chain_id))
}
