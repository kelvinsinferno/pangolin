// SPDX-License-Identifier: AGPL-3.0-or-later
//! Sync-status FFI shapes + entry point (MVP-2 issue 5.4, R-h).
//!
//! Wires the [`pangolin_core::compute_next_status`] transition
//! function across the FFI boundary so the host UI can render the
//! indicator chip without the engine spawning any background task.
//! Per R-a Option C, the engine's FFI is a thin wrapper: lift the
//! `UniFFI` inputs into Rust types → call the bundling accessor
//! [`pangolin_core::Vault::sync_status_inputs`] → call the pure
//! transition function → bundle a [`FfiSyncStatusSnapshot`] for the
//! host. The host holds the orchestrator state (the prior
//! `SyncStatus`, the `consecutive_pull_failures` counter, the
//! tokio timer); the engine FFI is stateless.
//!
//! ## Surface vocabulary (L5 + §8.1.5)
//!
//! [`FfiSyncStatus`]'s variant names mirror
//! [`pangolin_core::SyncStatus`] verbatim — `Synced` / `Syncing` /
//! `Offline` / `ConflictsPending` / `BlockedOnBalance` /
//! `ActionRequired`. NEVER pricing copy. Wei values cross as
//! **hex strings** (mirroring the 3.5 `BalanceMonitor` FFI pattern
//! for the same u128 fidelity reason).

use std::sync::Arc;

use pangolin_chain::GasBalanceState;
use pangolin_core::{
    compute_next_status, BatchFlushErrorKind, ConflictSnapshot, LastFlushOutcome, LastPullOutcome,
    PullErrorKind, SyncStatus, SyncStatusInputs,
};
// SyncMode lives in `pangolin_store::vault` and is re-exported from
// `pangolin_store`. `pangolin_core` re-exports the higher-level types
// but not `SyncMode` itself (it's part of the 4.4 picker surface). The
// FFI crate already depends on `pangolin-store` directly so naming
// it here is in-policy.
use pangolin_store::SyncMode;

use crate::balance::GasBalanceStateFfi;
use crate::error::FfiError;
use crate::session::VaultHandle;

// ---------------------------------------------------------------------
// FfiSyncMode — UniFFI mirror of pangolin_core::SyncMode (4.4)
// ---------------------------------------------------------------------

/// FFI-mirror of [`pangolin_core::SyncMode`] — the 4.4 picker's
/// dispatch decision the host needs to render the
/// [`FfiSyncStatus::Syncing`] variant.
///
/// 4.4 did not ship an FFI mirror of `SyncMode` (the picker was
/// engine-only); 5.4 introduces it as an additive 1.1-surface
/// amendment.
///
/// MVP-2 issue 5.4 (R-h).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiSyncMode {
    /// In-process slow-mode chain sync via `Vault::sync_from_chain`
    /// (4.1 R-e).
    Slow,
    /// Host should render the D-007 "Spin up faster sync?" prompt;
    /// on accept the host spawns the `pangolin-indexer` subprocess.
    OfferFast,
    /// User pre-elected always-fast; the host spawns the indexer
    /// without a per-session prompt.
    AlwaysFast,
}

impl From<SyncMode> for FfiSyncMode {
    fn from(mode: SyncMode) -> Self {
        match mode {
            SyncMode::Slow => Self::Slow,
            SyncMode::OfferFast => Self::OfferFast,
            SyncMode::AlwaysFast => Self::AlwaysFast,
        }
    }
}

impl From<FfiSyncMode> for SyncMode {
    fn from(mode: FfiSyncMode) -> Self {
        match mode {
            FfiSyncMode::Slow => Self::Slow,
            FfiSyncMode::OfferFast => Self::OfferFast,
            FfiSyncMode::AlwaysFast => Self::AlwaysFast,
        }
    }
}

// ---------------------------------------------------------------------
// FfiSyncStatus + FfiSyncStatusSnapshot
// ---------------------------------------------------------------------

/// FFI-mirror of [`pangolin_core::SyncStatus`].
///
/// 6-variant single enum per R-b. Variant names follow §8.1.5
/// vocabulary discipline verbatim (L5). Wei values cross as hex
/// strings (`"0x..."`) — same posture as the 3.5
/// [`crate::balance::GasBalanceStateFfi`] FFI surface so a > u64
/// wei value never truncates.
///
/// MVP-2 issue 5.4 (R-h).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum FfiSyncStatus {
    /// Pull loop landed a successful cycle recently; conflict /
    /// balance state otherwise clean.
    Synced,
    /// A pull cycle is in flight or recently dispatched.
    Syncing {
        /// The 4.4 [`FfiSyncMode`] returned by the most recent
        /// picker run.
        mode: FfiSyncMode,
    },
    /// `OFFLINE_THRESHOLD_FAILURES` (= 3) consecutive
    /// `PullError::Chain(_)` failures observed.
    Offline {
        /// Number of consecutive chain failures.
        consecutive_failures: u32,
    },
    /// One or more accounts in the conflict surface (forked OR
    /// frozen). Host routes to the 5.3 conflict-resolution screen.
    ConflictsPending {
        /// Number of accounts in the conflict surface.
        count: u32,
    },
    /// The most recent flush returned
    /// `BatchFlushError::BalanceInsufficientForBatch`. Host
    /// renders the §8.1.5 `RequiresActiveAccount` flow.
    BlockedOnBalance {
        /// `"0x..."` hex string — sum of estimated batch cost
        /// across queued accounts, in wei.
        needed_wei_hex: String,
        /// `"0x..."` hex string — wallet balance at gate-check
        /// time, in wei.
        available_wei_hex: String,
    },
    /// Terminal / attention-required state.
    ActionRequired {
        /// Short non-secret label describing the cause.
        reason: String,
    },
}

impl From<SyncStatus> for FfiSyncStatus {
    fn from(status: SyncStatus) -> Self {
        match status {
            SyncStatus::Synced => Self::Synced,
            SyncStatus::Syncing { mode } => Self::Syncing { mode: mode.into() },
            SyncStatus::Offline {
                consecutive_failures,
            } => Self::Offline {
                consecutive_failures,
            },
            SyncStatus::ConflictsPending { count } => Self::ConflictsPending { count },
            SyncStatus::BlockedOnBalance {
                needed_wei,
                available_wei,
            } => Self::BlockedOnBalance {
                needed_wei_hex: format!("0x{needed_wei:x}"),
                available_wei_hex: format!("0x{available_wei:x}"),
            },
            SyncStatus::ActionRequired { reason } => Self::ActionRequired { reason },
        }
    }
}

/// One-stop FFI snapshot for the host UI's indicator chip.
///
/// Returned by [`vault_sync_status`]. Carries the freshly-computed
/// [`FfiSyncStatus`] plus the most commonly-rendered companion
/// fields so the host does not need a second round-trip.
///
/// MVP-2 issue 5.4 (R-h).
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiSyncStatusSnapshot {
    /// Schema-version slot.
    pub schema_version: u16,
    /// Freshly-computed status pill.
    pub status: FfiSyncStatus,
    /// Total number of accounts currently in the conflict surface
    /// (forked OR frozen).
    pub conflicts_count: u32,
    /// Dirty-marker count from the publish queue snapshot.
    pub publish_queue_dirty_count: u32,
    /// Unix-ms instant of the last successful pull, or `None`.
    pub last_pull_at_unix_ms: Option<i64>,
}

// ---------------------------------------------------------------------
// FfiSyncStatusInputs / FfiLastPullOutcome / FfiLastFlushOutcome
// ---------------------------------------------------------------------
//
// Host-supplied between-tick state. The host owns these fields per
// R-a Option C; the FFI lifts them into Rust types before invoking
// the bundling accessor + the pure transition function.

/// FFI-mirror of [`pangolin_core::PullErrorKind`].
///
/// MVP-2 issue 5.4 (R-h).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiPullErrorKind {
    /// `PullError::Chain(_)` — increments the offline counter.
    Chain,
    /// `PullError::Store(_)` — transitions to `ActionRequired`.
    Store,
}

impl From<FfiPullErrorKind> for PullErrorKind {
    fn from(kind: FfiPullErrorKind) -> Self {
        match kind {
            FfiPullErrorKind::Chain => Self::Chain,
            FfiPullErrorKind::Store => Self::Store,
        }
    }
}

/// FFI-mirror of [`pangolin_core::LastPullOutcome`].
///
/// MVP-2 issue 5.4 (R-h).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum FfiLastPullOutcome {
    /// Pull returned `Ok(PullReport)`.
    Success {
        /// The picker's mode for this cycle.
        mode: FfiSyncMode,
        /// Count of newly-frozen accounts surfaced this cycle.
        newly_frozen_count: u32,
        /// Count of newly-resolved accounts surfaced this cycle.
        newly_resolved_count: u32,
    },
    /// Pull returned an error.
    Failure {
        /// Type-erased variant kind.
        kind: FfiPullErrorKind,
    },
    /// Pull returned `PullError::NoActiveSession`.
    NoActiveSession,
}

impl From<FfiLastPullOutcome> for LastPullOutcome {
    fn from(outcome: FfiLastPullOutcome) -> Self {
        match outcome {
            FfiLastPullOutcome::Success {
                mode,
                newly_frozen_count,
                newly_resolved_count,
            } => Self::Success {
                mode: mode.into(),
                newly_frozen_count,
                newly_resolved_count,
            },
            FfiLastPullOutcome::Failure { kind } => Self::Failure(kind.into()),
            FfiLastPullOutcome::NoActiveSession => Self::NoActiveSession,
        }
    }
}

/// FFI-mirror of [`pangolin_core::BatchFlushErrorKind`].
///
/// MVP-2 issue 5.4 (R-h).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum FfiBatchFlushErrorKind {
    /// `BalanceInsufficient` — wei values as hex strings for u128
    /// fidelity (mirroring 3.5 `BalanceMonitor` FFI).
    BalanceInsufficient {
        /// `"0x..."` hex string of the needed wei sum.
        needed_wei_hex: String,
        /// `"0x..."` hex string of the available balance.
        available_wei_hex: String,
        /// Number of accounts queued at flush time.
        queued_count: u32,
    },
    /// Non-balance chain error.
    Chain,
    /// Store-side error.
    Store,
    /// `NoActiveSession`.
    NoActiveSession,
}

impl TryFrom<FfiBatchFlushErrorKind> for BatchFlushErrorKind {
    type Error = FfiError;
    fn try_from(kind: FfiBatchFlushErrorKind) -> Result<Self, Self::Error> {
        Ok(match kind {
            FfiBatchFlushErrorKind::BalanceInsufficient {
                needed_wei_hex,
                available_wei_hex,
                queued_count,
            } => Self::BalanceInsufficient {
                needed_wei: parse_wei_hex(&needed_wei_hex)?,
                available_wei: parse_wei_hex(&available_wei_hex)?,
                queued_count: queued_count as usize,
            },
            FfiBatchFlushErrorKind::Chain => Self::Chain,
            FfiBatchFlushErrorKind::Store => Self::Store,
            FfiBatchFlushErrorKind::NoActiveSession => Self::NoActiveSession,
        })
    }
}

/// FFI-mirror of [`pangolin_core::LastFlushOutcome`].
///
/// MVP-2 issue 5.4 (R-h).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum FfiLastFlushOutcome {
    /// Flush returned `Ok(_)`.
    Success,
    /// Flush returned an error.
    Failure {
        /// Type-erased variant kind.
        kind: FfiBatchFlushErrorKind,
    },
}

impl TryFrom<FfiLastFlushOutcome> for LastFlushOutcome {
    type Error = FfiError;
    fn try_from(outcome: FfiLastFlushOutcome) -> Result<Self, Self::Error> {
        Ok(match outcome {
            FfiLastFlushOutcome::Success => Self::Success,
            FfiLastFlushOutcome::Failure { kind } => Self::Failure(kind.try_into()?),
        })
    }
}

/// Bundled host-supplied between-tick state for
/// [`vault_sync_status`].
///
/// MVP-2 issue 5.4 (R-h).
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiSyncStatusInputs {
    /// Schema-version slot.
    pub schema_version: u16,
    /// Host-tracked outcome of the most recent `pull_once` cycle.
    pub last_pull_outcome: Option<FfiLastPullOutcome>,
    /// Host-tracked outcome of the most recent
    /// `flush_publish_queue` cycle.
    pub last_flush_outcome: Option<FfiLastFlushOutcome>,
    /// Host-tracked consecutive `PullError::Chain(_)` failure
    /// count.
    pub consecutive_pull_failures: u32,
    /// Host-supplied balance state from the 3.5 `BalanceMonitor`.
    pub balance_state: GasBalanceStateFfi,
    /// Current wall-clock instant in unix-ms.
    pub now_unix_ms: i64,
}

// ---------------------------------------------------------------------
// vault_sync_status FFI entry point
// ---------------------------------------------------------------------

fn store_into_ffi(err: pangolin_store::StoreError) -> FfiError {
    FfiError::from(pangolin_core::Error::from(err))
}

pub(crate) fn parse_wei_hex(s: &str) -> Result<u128, FfiError> {
    let stripped = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    u128::from_str_radix(stripped, 16).map_err(|e| FfiError::Validation {
        kind: "argument".into(),
        message: format!("invalid wei hex string {s:?}: {e}"),
    })
}

fn ffi_to_balance_state(state: GasBalanceStateFfi) -> Result<GasBalanceState, FfiError> {
    Ok(match state {
        GasBalanceStateFfi::Sufficient {
            balance_wei_hex,
            estimate_wei_hex,
        } => GasBalanceState::Sufficient {
            balance_wei: parse_wei_hex(&balance_wei_hex)?,
            estimate_wei: parse_wei_hex(&estimate_wei_hex)?,
        },
        GasBalanceStateFfi::RequiresActiveAccount {
            balance_wei_hex,
            estimate_wei_hex,
        } => GasBalanceState::RequiresActiveAccount {
            balance_wei: parse_wei_hex(&balance_wei_hex)?,
            estimate_wei: parse_wei_hex(&estimate_wei_hex)?,
        },
        GasBalanceStateFfi::TopUpInFlight { initiated_at_unix } => {
            GasBalanceState::TopUpInFlight { initiated_at_unix }
        }
        GasBalanceStateFfi::Unknown { reason } => GasBalanceState::Unknown { reason },
    })
}

/// **MVP-2 issue 5.4 (R-h).** Compute the freshly-derived
/// indicator-chip state for the host UI.
///
/// Thin wrapper: lifts FFI inputs into Rust types → calls
/// [`pangolin_core::Vault::sync_status_inputs`] (the engine
/// bundling accessor) → calls the pure
/// [`pangolin_core::compute_next_status`] transition function →
/// bundles a [`FfiSyncStatusSnapshot`] for the host.
///
/// The engine FFI does NOT hold orchestrator state — under R-a
/// Option C the host owns the tokio timer loop + the prior-status
/// memory + the consecutive-failure counter. This call is pure
/// over the inputs (apart from the engine's metadata-only SQL
/// reads inside `sync_status_inputs`).
///
/// **Active-session policy** (L5 FFI policy): a locked vault
/// errors `FfiError::Session`. The transition function would
/// emit a sane `ActionRequired { reason: "vault locked" }` for a
/// locked-vault tick, but at the FFI boundary we refuse the call
/// outright so the host's UI never accidentally renders the
/// terminal state on a fresh launch before unlock — consistent
/// with the 3.5 / 5.3 FFI policy.
///
/// # Arguments
///
/// - `handle` — the vault handle. Must be unlocked.
/// - `prev_status` — the host's prior-tick computed status. Used
///   as a hint (the transition function currently does not branch
///   on it but the API reserves the slot per R-h).
/// - `inputs` — bundled host-supplied between-tick state.
///
/// # Errors
///
/// `FfiError::Session` for a locked / placeholder handle;
/// `FfiError::Validation` for malformed `_wei_hex` strings on
/// `inputs.balance_state` or `last_flush_outcome`;
/// `FfiError::Store` on a storage failure inside the bundling
/// accessor.
#[allow(clippy::significant_drop_tightening)]
#[uniffi::export]
pub fn vault_sync_status(
    handle: Arc<VaultHandle>,
    prev_status: Option<FfiSyncStatus>,
    inputs: FfiSyncStatusInputs,
) -> Result<FfiSyncStatusSnapshot, FfiError> {
    // (1) Lift host-supplied inputs into Rust types. Do this
    //     BEFORE acquiring the vault guard so the lock window
    //     stays short.
    let last_pull_outcome: Option<LastPullOutcome> = inputs.last_pull_outcome.map(Into::into);
    let last_flush_outcome: Option<LastFlushOutcome> = match inputs.last_flush_outcome {
        Some(o) => Some(o.try_into()?),
        None => None,
    };
    let balance_state = ffi_to_balance_state(inputs.balance_state)?;
    // The transition function reads `prev_status` only as a hint;
    // a `None` from the caller (first call after unlock) defaults
    // to a sane bootstrap value.
    let prev: SyncStatus = match prev_status {
        Some(p) => ffi_to_sync_status(p)?,
        None => SyncStatus::Syncing {
            mode: SyncMode::Slow,
        },
    };

    // (2) Acquire the vault guard + active-session gate.
    let mut guard = handle.lock_vault();
    let vault = guard.as_mut()?;
    // Reject a Locked-but-previously-unlocked vault at the FFI
    // boundary (mirrors 3.5 `require_unlocked` pattern via a
    // metadata-only probe). The bundling accessor itself works on
    // a Locked vault (it's metadata-only), but the FFI policy is
    // to refuse the call so the host's UI never renders the
    // terminal state on a fresh launch before unlock.
    if !matches!(vault.state(), pangolin_core::VaultState::Active) {
        return Err(FfiError::Session {
            message: "vault is not unlocked".into(),
        });
    }

    // (3) Bundling accessor — pre-snapshot is taken from the
    //     current state (since the FFI surface doesn't carry one
    //     across calls; the host pulls per-tick); for the call
    //     here we use an empty `ConflictSnapshot` because the
    //     `conflict_delta` field is for callers that want the
    //     `removed_*` notification — the engine's `conflicts_count`
    //     is what the transition function consumes.
    //
    //     Per the canonical host loop in
    //     `docs/architecture/sync-orchestrator.md`, hosts that
    //     want the conflict-delta signal call
    //     `vault_list_conflicts` separately + diff client-side.
    let empty_prior = ConflictSnapshot::default();
    let core_inputs: SyncStatusInputs = vault
        .sync_status_inputs(
            &empty_prior,
            last_pull_outcome,
            last_flush_outcome,
            inputs.consecutive_pull_failures,
            balance_state,
            inputs.now_unix_ms,
        )
        .map_err(store_into_ffi)?;

    // (4) Pure transition function.
    let next: SyncStatus = compute_next_status(&prev, &core_inputs);

    // (5) Bundle the snapshot.
    Ok(FfiSyncStatusSnapshot {
        schema_version: pangolin_core::ACCOUNT_IDENTITY_SCHEMA_VERSION,
        status: next.into(),
        conflicts_count: core_inputs.conflicts_count,
        publish_queue_dirty_count: u32::try_from(core_inputs.publish_queue.dirty_count)
            .unwrap_or(u32::MAX),
        last_pull_at_unix_ms: core_inputs.last_pull_at_unix_ms,
    })
}

fn ffi_to_sync_status(s: FfiSyncStatus) -> Result<SyncStatus, FfiError> {
    Ok(match s {
        FfiSyncStatus::Synced => SyncStatus::Synced,
        FfiSyncStatus::Syncing { mode } => SyncStatus::Syncing { mode: mode.into() },
        FfiSyncStatus::Offline {
            consecutive_failures,
        } => SyncStatus::Offline {
            consecutive_failures,
        },
        FfiSyncStatus::ConflictsPending { count } => SyncStatus::ConflictsPending { count },
        FfiSyncStatus::BlockedOnBalance {
            needed_wei_hex,
            available_wei_hex,
        } => SyncStatus::BlockedOnBalance {
            needed_wei: parse_wei_hex(&needed_wei_hex)?,
            available_wei: parse_wei_hex(&available_wei_hex)?,
        },
        FfiSyncStatus::ActionRequired { reason } => SyncStatus::ActionRequired { reason },
    })
}

// ---------------------------------------------------------------------
// CLI-V1 (R-g): vault_pull_once + vault_last_pull_at_unix_ms
// ---------------------------------------------------------------------

/// FFI mirror of [`pangolin_store::PullReport`].
///
/// Per-cycle outcome carried back from
/// [`vault_pull_once`]. The mode field tracks the 4.4 picker's
/// dispatch decision; `newly_*` counters track the 5.3 conflict-
/// surface delta for the host's notification path.
///
/// CLI-V1 (R-g).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiPullReport {
    /// Schema-version slot.
    pub schema_version: u16,
    /// 4.4 picker's dispatch decision for this cycle.
    pub mode: FfiSyncMode,
    /// Unix-ms instant at which the dispatch completed.
    pub pulled_at_unix_ms: i64,
    /// Count of accounts whose `frozen_pending_resolve` flag
    /// transitioned from `false` to `true` this cycle.
    pub newly_frozen_count: u32,
    /// Count of accounts whose head set went from 1 → 2+ this
    /// cycle.
    pub newly_forked_count: u32,
    /// Count of accounts whose `frozen_pending_resolve` flag
    /// transitioned from `true` to `false` this cycle.
    pub newly_resolved_count: u32,
}

/// Run a single pull cycle.
///
/// **MVP-3 issue #100.** Drives the `!Send`
/// [`pangolin_store::Vault::pull_once`] future to completion on a
/// local current-thread runtime (the `Vault` is `!Send` — it holds an
/// `RefCell`-bearing `rusqlite::Connection` + a `dyn Clock` — so the
/// future never leaves the calling thread; see `chain_config.rs`
/// module doc). The pull path is read-only: it builds its own provider
/// internally and needs no adapter + no signer (zero secret crosses
/// FFI, trivially). `config.rpc_url` (the frozen `rpc_url` arg folded
/// into the R-a Record) supplies the endpoint; `ChainEnv` is hardcoded
/// `BaseSepolia` (L8, not crossed FFI).
///
/// `config.prefer_websocket` is **accepted-but-not-forwarded** (R-e
/// amendment): `Vault::pull_once` hardcodes `SyncOptions::default()`
/// and takes no options arg, so the toggle is a documented no-op on
/// this path; forwarding it is a deferred follow-up.
///
/// # Errors
///
/// `FfiError::Session` for a locked / placeholder handle (the L4
/// session gate, before any chain primitive); `FfiError::Chain` /
/// `FfiError::Store` for pull-cycle failures.
#[allow(clippy::significant_drop_tightening, clippy::needless_pass_by_value)]
#[uniffi::export]
pub fn vault_pull_once(
    handle: Arc<VaultHandle>,
    config: crate::chain_config::FfiChainConfig,
) -> Result<FfiPullReport, FfiError> {
    // Active-session gate at the FFI boundary (L4), BEFORE any chain
    // primitive.
    let mut guard = handle.lock_vault();
    let vault = guard.as_mut()?;
    let vault_id = vault.vault_id();
    // L8: ChainEnv is hardcoded BaseSepolia (not crossed FFI).
    let env = pangolin_chain::ChainEnv::BaseSepolia;
    let report = crate::chain_config::block_on_local(async {
        vault
            .pull_once(&config.rpc_url, env, &vault_id)
            .await
            .map_err(crate::chain_config::pull_into_ffi)
    })??;
    Ok(FfiPullReport {
        schema_version: 1,
        mode: FfiSyncMode::from(report.mode),
        pulled_at_unix_ms: report.pulled_at_unix_ms,
        newly_frozen_count: u32::try_from(report.newly_frozen_accounts.len()).unwrap_or(u32::MAX),
        newly_forked_count: u32::try_from(report.newly_forked_accounts.len()).unwrap_or(u32::MAX),
        newly_resolved_count: u32::try_from(report.newly_resolved_accounts.len())
            .unwrap_or(u32::MAX),
    })
}

/// Read the unix-ms instant of the most recent successful pull
/// cycle this session.
///
/// Returns `None` on a Locked vault OR if no pull cycle has run
/// yet on this session.
///
/// # Errors
///
/// None — the engine accessor returns `None` for both "locked"
/// and "no pull yet" because the host's UI treatment is
/// identical.
#[allow(clippy::significant_drop_tightening)]
#[uniffi::export]
pub fn vault_last_pull_at_unix_ms(handle: Arc<VaultHandle>) -> Result<Option<i64>, FfiError> {
    let mut guard = handle.lock_vault();
    let vault = guard.as_mut()?;
    Ok(vault.last_pull_at_unix_ms())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::balance::GasBalanceStateFfi;
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

    fn bootstrap_inputs() -> FfiSyncStatusInputs {
        FfiSyncStatusInputs {
            schema_version: 1,
            last_pull_outcome: None,
            last_flush_outcome: None,
            consecutive_pull_failures: 0,
            balance_state: GasBalanceStateFfi::Unknown {
                reason: "test-bootstrap".into(),
            },
            now_unix_ms: 1_700_000_000_000,
        }
    }

    /// **5.4 R-h baseline.** Clean vault, bootstrap inputs ⇒ the
    /// transition function returns `Syncing { Slow }` (the
    /// bootstrap default); the FFI rounds that through cleanly +
    /// the snapshot carries the expected zero counts.
    #[test]
    fn vault_sync_status_ffi_returns_synced_on_clean_vault() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        let snap = vault_sync_status(h, None, bootstrap_inputs()).expect("snapshot");
        // Bootstrap path: no prior pull, no Success outcome, no
        // failures → status is Syncing { Slow } (or Synced if a
        // last_pull stamp had been set; on a fresh vault, it's
        // Syncing — covers the spec's "Syncing… on first load").
        match snap.status {
            FfiSyncStatus::Syncing {
                mode: FfiSyncMode::Slow,
            } => {}
            other => panic!("expected Syncing(Slow) on bootstrap, got {other:?}"),
        }
        assert_eq!(snap.conflicts_count, 0);
        assert_eq!(snap.publish_queue_dirty_count, 0);
        assert!(snap.last_pull_at_unix_ms.is_none());
    }

    /// **5.4 R-h session-discipline.** Locked vault ⇒
    /// `FfiError::Session` — refuse the call at the boundary so
    /// the host's UI never accidentally renders the terminal
    /// state on a fresh launch before unlock.
    #[test]
    fn vault_sync_status_ffi_refuses_on_locked_vault_with_typed_error() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        {
            let mut g = h.lock_vault();
            g.as_mut().unwrap().lock();
        }
        let err = vault_sync_status(h, None, bootstrap_inputs()).unwrap_err();
        assert!(
            matches!(err, FfiError::Session { .. }),
            "expected FfiError::Session, got {err:?}"
        );
    }

    /// **5.4 R-h.** With a foreign-event-induced freeze on the
    /// vault, the snapshot's `conflicts_count` is populated AND
    /// the status pill is `ConflictsPending`.
    #[test]
    #[allow(clippy::significant_drop_tightening)]
    fn vault_sync_status_ffi_carries_conflicts_count_field() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        // Ingest a foreign chain event to surface a freeze.
        {
            let mut g = h.lock_vault();
            let vault = g.as_mut().unwrap();
            let device = pangolin_crypto::keys::DeviceKey::generate();
            let ev = pangolin_chain::RevisionEvent {
                vault_id: vault.vault_id(),
                account_id: [0xAAu8; 32],
                parent_revision: [0u8; 32],
                device_id: device.verifying_key().to_bytes(),
                schema_version: 0,
                sequence: 0,
                enc_payload: b"foreign".to_vec(),
                anchor: pangolin_chain::ChainAnchor {
                    tx_hash: [0xCC; 32],
                    block_number: 1,
                    log_index: 0,
                    sequence: 0,
                },
            };
            vault.ingest_chain_revision(&ev).expect("ingest");
        }
        let snap = vault_sync_status(h, None, bootstrap_inputs()).expect("snapshot");
        assert_eq!(snap.conflicts_count, 1);
        assert!(
            matches!(snap.status, FfiSyncStatus::ConflictsPending { count: 1 }),
            "expected ConflictsPending(1), got {:?}",
            snap.status
        );
    }

    // -----------------------------------------------------------------
    // Audit fix-pass: parse_wei_hex negative cases + FfiSyncMode round-trip
    // -----------------------------------------------------------------

    #[test]
    fn parse_wei_hex_round_trips_u128_max() {
        let max_hex = format!("0x{:x}", u128::MAX);
        let parsed = parse_wei_hex(&max_hex).expect("u128::MAX hex round-trips");
        assert_eq!(parsed, u128::MAX);
    }

    #[test]
    fn parse_wei_hex_accepts_uppercase_prefix() {
        let parsed = parse_wei_hex("0XFF").expect("0X prefix valid");
        assert_eq!(parsed, 0xFF);
    }

    #[test]
    fn parse_wei_hex_accepts_bare_hex() {
        let parsed = parse_wei_hex("ff").expect("bare hex valid");
        assert_eq!(parsed, 0xff);
    }

    #[test]
    fn parse_wei_hex_rejects_empty_string() {
        assert!(matches!(
            parse_wei_hex(""),
            Err(FfiError::Validation { kind, .. }) if kind == "argument"
        ));
    }

    #[test]
    fn parse_wei_hex_rejects_negative_sign() {
        assert!(matches!(
            parse_wei_hex("-1"),
            Err(FfiError::Validation { .. })
        ));
    }

    #[test]
    fn parse_wei_hex_rejects_non_hex_chars() {
        assert!(matches!(
            parse_wei_hex("0xZZ"),
            Err(FfiError::Validation { .. })
        ));
    }

    #[test]
    fn parse_wei_hex_rejects_whitespace() {
        assert!(matches!(
            parse_wei_hex(" 0x1"),
            Err(FfiError::Validation { .. })
        ));
    }

    // -----------------------------------------------------------------
    // MVP-3 #100: vault_pull_once REAL-path tests.
    // -----------------------------------------------------------------

    fn bogus_config() -> crate::chain_config::FfiChainConfig {
        crate::chain_config::FfiChainConfig {
            schema_version: 1,
            // The picker re-runs each cycle; on a fresh vault with no
            // checkpoint it returns OfferFast WITHOUT making an RPC
            // call (4.4 first-sync-only heuristic), so an unreachable
            // URL is never dialed.
            rpc_url: "http://127.0.0.1:1/should-not-be-called".into(),
            deployment_path: "/unused-on-pull-path/base-sepolia.json".into(),
            prefer_websocket: true,
        }
    }

    /// **MVP-3 #100 (R-f) — REAL-path stub-parity flip + the `!Send`
    /// runtime-bridge round-trip.** On a fresh unlocked vault the
    /// picker returns `OfferFast` without dialing the RPC, so
    /// `vault_pull_once` drives the `!Send` `Vault::pull_once` future
    /// to completion on the local current-thread runtime and returns a
    /// real `FfiPullReport` (NOT the old `Internal` stub). This
    /// exercises the whole synchronous-binding → `block_on_local` →
    /// `!Send` future → typed-Record round-trip.
    #[test]
    fn pull_once_real_path_round_trips_offer_fast_via_local_runtime() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        let report = vault_pull_once(h, bogus_config()).expect("pull cycle should succeed");
        assert_eq!(report.schema_version, 1);
        // Fresh-vault-no-checkpoint → picker returns OfferFast (signal-
        // only; engine never dispatches RPC).
        assert_eq!(report.mode, FfiSyncMode::OfferFast);
        assert_eq!(report.newly_frozen_count, 0);
        assert_eq!(report.newly_forked_count, 0);
        assert_eq!(report.newly_resolved_count, 0);
    }

    /// **MVP-3 #100 (R-f) — per-binding session gate (L4).** A locked
    /// vault errors `FfiError::Session` BEFORE any chain primitive.
    #[test]
    fn pull_once_rejects_locked_vault_before_chain() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        {
            let mut g = h.lock_vault();
            g.as_mut().unwrap().lock();
        }
        let err = vault_pull_once(h, bogus_config()).unwrap_err();
        assert!(
            matches!(err, FfiError::Session { .. }),
            "expected FfiError::Session (L4 gate before chain), got {err:?}"
        );
    }

    /// **MVP-3 #100 (R-f) — per-binding session gate (placeholder).**
    #[test]
    fn pull_once_rejects_placeholder() {
        let empty = VaultHandle::new_placeholder();
        let err = vault_pull_once(empty, bogus_config()).unwrap_err();
        assert!(
            matches!(err, FfiError::Session { .. }),
            "expected FfiError::Session, got {err:?}"
        );
    }

    #[test]
    fn ffi_sync_mode_round_trip_preserves_all_variants() {
        for original in [
            FfiSyncMode::Slow,
            FfiSyncMode::OfferFast,
            FfiSyncMode::AlwaysFast,
        ] {
            let store_form: SyncMode = original.into();
            let round_tripped: FfiSyncMode = store_form.into();
            assert_eq!(
                round_tripped, original,
                "FfiSyncMode round-trip must preserve variant {original:?}"
            );
        }
    }
}
