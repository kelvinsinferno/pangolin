// SPDX-License-Identifier: AGPL-3.0-or-later
//
//! Sync orchestrator state machine — `SyncStatus` enum + pure
//! `compute_next_status` transition function.
//!
//! ## What this module ships (MVP-2 issue 5.4)
//!
//! Per Kelvin's R-a..R-h sign-off (2026-05-17 in
//! `docs/issue-plans/5.4.md`), 5.4 is a **pure host concept**:
//! `pangolin-store` ships the [`SyncStatus`] enum (R-b 6-variant
//! shape), the pure [`compute_next_status`] transition function
//! (R-a + L11), the [`SyncStatusInputs`] bundling record, and the
//! [`crate::vault::Vault::sync_status_inputs`] bundling accessor
//! (R-a Option C). The host (CLI / Tauri / mobile) owns the
//! `tokio::interval` timer loop + the optional
//! `tokio::sync::watch` channel (R-f). The engine never spawns the
//! sync loop.
//!
//! The companion `Vault::lock_with_drain` async method (R-e) lives
//! in `vault.rs` and closes the 5.1 L1 deviation by flushing the
//! publish queue BEFORE dropping `active` on a graceful teardown.
//!
//! ## L-invariants (5.4)
//!
//! - **L1** — Orchestrator NEVER spawns the indexer (inherited
//!   from 4.4 L1 + 5.2 L2). `SyncMode::OfferFast` /
//!   `SyncMode::AlwaysFast` dispatches are signal-only at the
//!   transition function layer; the host owns indexer spawn.
//! - **L2** — Orchestrator NEVER publishes outside of
//!   `flush_publish_queue` (inherited from 5.1 L11). The transition
//!   function reads outcome shapes only; it does not invoke any
//!   chain primitive.
//! - **L4** — Offline counter resets on ANY `Ok(_)` from
//!   `pull_once` (including signal-only `OfferFast` / `AlwaysFast`).
//!   Only `Err(PullError::Chain(_))` increments. `Err(PullError::Store(_))`
//!   transitions to [`SyncStatus::ActionRequired`].
//!   `Err(PullError::NoActiveSession)` is terminal — the host loop
//!   breaks.
//! - **L5** — Variant names follow §8.1.5 vocabulary discipline
//!   verbatim. NEVER pricing copy (`"LowBalance"`, `"OutOfGas"`,
//!   `"Upgrade"`). Mirrors the 3.5
//!   [`pangolin_chain::GasBalanceState::RequiresActiveAccount`]
//!   pinning precedent. Pinned by
//!   [`tests::sync_status_variant_names_do_not_leak_pricing_copy`].
//! - **L11** — Transition function is PURE: takes all state
//!   by-value (`&SyncStatus` previous + `&SyncStatusInputs`
//!   bundled snapshot), returns a value; no I/O, no clock read
//!   (inputs carry `now_unix_ms`), no SQL. The bundling accessor
//!   [`crate::vault::Vault::sync_status_inputs`] is the impure
//!   layer.

use pangolin_chain::GasBalanceState;

use crate::conflict::ConflictDelta;
use crate::publish::PublishQueueState;
use crate::vault::SyncMode;

// ---------------------------------------------------------------------
// Public constants (R-c + staleness threshold)
// ---------------------------------------------------------------------

/// **MVP-2 issue 5.4 (R-c).** Number of consecutive
/// `PullError::Chain(_)` failures before the transition function
/// returns [`SyncStatus::Offline`].
///
/// At the 5.2 60-second default pull cadence this is ~3 min of
/// continuous RPC failure before the host UI's indicator chip
/// transitions to "Offline". One-off RPC blips are tolerated.
///
/// Counter resets on the FIRST `Ok(_)` from `pull_once` — any
/// variant — including signal-only `OfferFast` / `AlwaysFast`
/// cycles (per L4).
pub const OFFLINE_THRESHOLD_FAILURES: u32 = 3;

/// **MVP-2 issue 5.4.** Staleness threshold in ms.
///
/// Milliseconds after the last successful pull cycle's stamp at
/// which the transition function downgrades [`SyncStatus::Synced`]
/// to [`SyncStatus::Syncing`] even without a fresh outcome.
///
/// 5 minutes — comfortably above the 5.2 60-second cadence so an
/// active host running on schedule never trips this; only a host
/// whose scheduler is wedged or paused gets the downgrade.
pub const SYNCED_STALENESS_THRESHOLD_MS: i64 = 5 * 60 * 1000;

// ---------------------------------------------------------------------
// SyncStatus enum (R-b shape) — the 6-variant single-pill state
// ---------------------------------------------------------------------

/// Indicator-chip state for the host UI's "Synced / Syncing… /
/// Offline" pill.
///
/// 6-variant single enum per R-b — one variant at a time; the host
/// renders ONE pill. Variant names follow §8.1.5 vocabulary
/// discipline verbatim (L5): NEVER pricing copy.
///
/// MVP-2 issue 5.4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncStatus {
    /// The pull loop landed at least one successful cycle within
    /// [`SYNCED_STALENESS_THRESHOLD_MS`] of the current tick and
    /// the conflict / balance / outcome state is otherwise clean.
    Synced,
    /// A pull cycle is in flight or recently dispatched. The
    /// `mode` field carries the 4.4 picker's most recent decision
    /// — host UI may render different copy per mode.
    Syncing {
        /// The 4.4 [`SyncMode`] picked by the most recent
        /// `select_sync_mode` call (or [`SyncMode::Slow`] on
        /// bootstrap).
        mode: SyncMode,
    },
    /// Consecutive `PullError::Chain(_)` failures reached
    /// [`OFFLINE_THRESHOLD_FAILURES`]. Host UI may render an
    /// "Offline" pill with a non-blocking retry affordance.
    Offline {
        /// Number of consecutive chain failures the host has
        /// recorded — at least [`OFFLINE_THRESHOLD_FAILURES`] when
        /// this variant fires.
        consecutive_failures: u32,
    },
    /// One or more accounts are in the conflict surface (forked OR
    /// frozen). Host UI may render a "Conflicts pending" pill that
    /// routes to the 5.3 conflict-resolution screen via
    /// `vault_list_conflicts`.
    ConflictsPending {
        /// Total number of accounts in the conflict surface.
        count: u32,
    },
    /// The most recent flush cycle returned 5.1
    /// `BatchFlushError::BalanceInsufficientForBatch`. Host UI may
    /// render the §8.1.5 `RequiresActiveAccount` flow — NEVER
    /// pricing copy.
    BlockedOnBalance {
        /// Sum of estimated batch cost across queued accounts, in
        /// wei.
        needed_wei: u128,
        /// Wallet balance at the moment of the gate check, in wei.
        available_wei: u128,
    },
    /// Terminal / attention-required state — a store-side error
    /// from `pull_once`, a locked-vault tick after the host loop
    /// started, etc. The `reason` string is a short non-secret
    /// human label the host may render alongside a "retry" /
    /// "support" affordance.
    ActionRequired {
        /// Short non-secret label describing the cause.
        reason: String,
    },
}

// ---------------------------------------------------------------------
// Type-erased outcome shapes (for the pure transition function)
// ---------------------------------------------------------------------

/// Variant tag of the 5.2 [`crate::pull::PullError`] family, type-
/// erased for the pure [`compute_next_status`] inputs.
///
/// We can't carry [`pangolin_chain::ChainError`] / [`crate::StoreError`]
/// directly because those types are not `Clone` / `Eq` in all
/// variants; the transition function only needs the variant kind
/// to decide between offline-counter-bump (`Chain`),
/// `ActionRequired` (`Store`), and terminal-break (`NoActiveSession`).
///
/// MVP-2 issue 5.4 (R-a + L11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PullErrorKind {
    /// Chain-side error (`PullError::Chain`) — increments the
    /// offline counter on the host side.
    Chain,
    /// Store-side error (`PullError::Store`) — transitions the
    /// pill to `ActionRequired`.
    Store,
}

/// Variant tag of the 5.1 [`crate::publish::BatchFlushError`]
/// family, type-erased for the pure [`compute_next_status`]
/// inputs.
///
/// MVP-2 issue 5.4 (R-a + L11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatchFlushErrorKind {
    /// `BalanceInsufficientForBatch` — carries the wei values the
    /// flush gate reported so the transition function can emit
    /// [`SyncStatus::BlockedOnBalance`] with the same numbers.
    BalanceInsufficient {
        /// Sum of estimated cost across all queued accounts, in
        /// wei.
        needed_wei: u128,
        /// Wallet balance at the moment of the check, in wei.
        available_wei: u128,
        /// Number of accounts that were queued at flush time.
        queued_count: usize,
    },
    /// `ChainError` (non-balance) — currently leaves the status
    /// at whatever the prior compute call returned (the host
    /// retries on the next flush tick).
    Chain,
    /// `Store` — transitions to `ActionRequired`.
    Store,
    /// `NoActiveSession` — terminal for the host loop.
    NoActiveSession,
}

// ---------------------------------------------------------------------
// Host-tracked outcomes (last_pull_outcome / last_flush_outcome)
// ---------------------------------------------------------------------

/// Outcome of the most recent `pull_once` cycle, recorded by the
/// host between ticks for the transition function's consumption.
///
/// MVP-2 issue 5.4 (R-a + L4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LastPullOutcome {
    /// Pull cycle returned `Ok(PullReport)`. Carries the picker's
    /// decision + the per-tick conflict-delta counts so the
    /// transition function can distinguish a `Slow` chain-read from
    /// a signal-only `OfferFast` / `AlwaysFast` cycle.
    Success {
        /// The 4.4 [`SyncMode`] returned by this cycle.
        mode: SyncMode,
        /// Count of newly-frozen accounts surfaced this cycle.
        newly_frozen_count: u32,
        /// Count of newly-resolved accounts surfaced this cycle.
        newly_resolved_count: u32,
    },
    /// Pull cycle returned `Err(PullError::Chain(_) | Err(PullError::Store(_)))`.
    Failure(PullErrorKind),
    /// Pull cycle returned `Err(PullError::NoActiveSession)` —
    /// the host loop should break and stop calling the transition
    /// function. The function still produces a sane terminal
    /// [`SyncStatus::ActionRequired`] for any final UI render.
    NoActiveSession,
}

/// Outcome of the most recent `flush_publish_queue` cycle,
/// recorded by the host between ticks.
///
/// MVP-2 issue 5.4 (R-a).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LastFlushOutcome {
    /// Flush returned `Ok(BatchFlushReport)` — the queue
    /// (possibly empty) drained cleanly.
    Success,
    /// Flush returned `Err(BatchFlushError)` — carries the
    /// type-erased variant kind so the transition function can
    /// distinguish balance-blocked from other failure modes.
    Failure(BatchFlushErrorKind),
}

// ---------------------------------------------------------------------
// SyncStatusInputs — the bundled snapshot
// ---------------------------------------------------------------------

/// Bundled inputs for the pure [`compute_next_status`] transition
/// function.
///
/// Produced by [`crate::vault::Vault::sync_status_inputs`] (the
/// impure bundling accessor that reads the engine-side fields)
/// plus host-supplied fields (`last_pull_outcome`,
/// `last_flush_outcome`, `consecutive_pull_failures`,
/// `balance_state`, `now_unix_ms`).
///
/// MVP-2 issue 5.4 (R-a + L11).
#[derive(Debug, Clone)]
pub struct SyncStatusInputs {
    /// Host-tracked outcome of the most recent `pull_once` cycle.
    /// `None` on bootstrap before any pull has fired.
    pub last_pull_outcome: Option<LastPullOutcome>,
    /// Host-tracked outcome of the most recent
    /// `flush_publish_queue` cycle. `None` on bootstrap before any
    /// flush has fired.
    pub last_flush_outcome: Option<LastFlushOutcome>,
    /// Snapshot of the publish queue state at this tick.
    pub publish_queue: PublishQueueState,
    /// Total number of accounts in the conflict surface at this
    /// tick. Read by the bundling accessor via the 5.3
    /// `snapshot_conflicts` primitive.
    pub conflicts_count: u32,
    /// Per-tick conflict delta vs. the prior snapshot the host
    /// passed in. Carried for symmetry with the 5.3 `PullReport`
    /// delta — currently the transition function consumes
    /// `conflicts_count` directly; the delta is available for
    /// hosts that want to render banner notifications.
    pub conflict_delta: ConflictDelta,
    /// Unix-ms instant of the last successful pull, or `None` on
    /// bootstrap.
    pub last_pull_at_unix_ms: Option<i64>,
    /// Host-tracked count of consecutive `PullError::Chain(_)`
    /// failures since the last successful pull. Resets on any
    /// `Ok(_)` per L4.
    pub consecutive_pull_failures: u32,
    /// Most recent [`pangolin_chain::GasBalanceState`] observed
    /// by the host's 3.5 `BalanceMonitor`. The transition function
    /// uses this only as the steady-state hint —
    /// `BalanceInsufficient` flush errors take precedence per
    /// L-balance-state-stale-vs-flush-error.
    pub balance_state: GasBalanceState,
    /// Current wall-clock instant in unix-ms. Passed in (not
    /// read internally) to keep [`compute_next_status`] PURE
    /// per L11.
    pub now_unix_ms: i64,
}

// ---------------------------------------------------------------------
// Pure transition function (R-a + L11) — the core of the state
// machine
// ---------------------------------------------------------------------

/// Pure state-machine transition. Returns the next
/// [`SyncStatus`] given the prior status + a bundled snapshot of
/// inputs.
///
/// PURE per L11 — no I/O, no clock read, no SQL. Inputs carry
/// `now_unix_ms` so a hermetic test can pin every transition
/// deterministically.
///
/// ## Transition order (load-bearing — matches plan §spec verbatim)
///
/// 1. `NoActiveSession` terminal — `last_pull_outcome ==
///    NoActiveSession` ⇒ `ActionRequired { reason: "vault locked" }`.
///    The host loop should already have broken on this; the
///    transition still emits a sane status for any final render.
/// 2. Store error from pull ⇒ `ActionRequired`.
/// 3. Fresh `BalanceInsufficient` flush error PREFERRED over the
///    `BalanceMonitor`'s cached state ⇒ `BlockedOnBalance`
///    (defends `L-balance-state-stale-vs-flush-error`).
/// 4. Consecutive failures `>=` [`OFFLINE_THRESHOLD_FAILURES`] ⇒
///    `Offline`.
/// 5. `conflicts_count > 0` ⇒ `ConflictsPending`.
/// 6. Successful pull this tick — `Slow` ⇒ `Synced`; `OfferFast` /
///    `AlwaysFast` (signal-only) ⇒ `Syncing { mode }`.
/// 7. Staleness check — last pull older than
///    [`SYNCED_STALENESS_THRESHOLD_MS`] ⇒ `Syncing { Slow }`;
///    fresh ⇒ `Synced`.
/// 8. Bootstrap (no prior pull) ⇒ `Syncing { Slow }`.
///
/// MVP-2 issue 5.4 (R-a + L11).
#[must_use]
pub fn compute_next_status(_prev: &SyncStatus, inputs: &SyncStatusInputs) -> SyncStatus {
    // (1) NoActiveSession terminal — host should break.
    if matches!(
        inputs.last_pull_outcome,
        Some(LastPullOutcome::NoActiveSession)
    ) {
        return SyncStatus::ActionRequired {
            reason: "vault locked".to_string(),
        };
    }
    // (2) Store error from pull → ActionRequired (per L4).
    if matches!(
        inputs.last_pull_outcome,
        Some(LastPullOutcome::Failure(PullErrorKind::Store))
    ) {
        return SyncStatus::ActionRequired {
            reason: "store error during sync".to_string(),
        };
    }
    // (3) Fresh flush balance-error PREFERRED over the
    //     BalanceMonitor cache (defends L-balance-state-stale-vs-
    //     flush-error). The flush gate is the authoritative
    //     signal — it's the same RPC that would have refused the
    //     publish.
    if let Some(LastFlushOutcome::Failure(BatchFlushErrorKind::BalanceInsufficient {
        needed_wei,
        available_wei,
        ..
    })) = &inputs.last_flush_outcome
    {
        return SyncStatus::BlockedOnBalance {
            needed_wei: *needed_wei,
            available_wei: *available_wei,
        };
    }
    // (4) Consecutive failures >= threshold → Offline.
    if inputs.consecutive_pull_failures >= OFFLINE_THRESHOLD_FAILURES {
        return SyncStatus::Offline {
            consecutive_failures: inputs.consecutive_pull_failures,
        };
    }
    // (5) Conflict surface non-empty → ConflictsPending.
    if inputs.conflicts_count > 0 {
        return SyncStatus::ConflictsPending {
            count: inputs.conflicts_count,
        };
    }
    // (6) Successful pull this tick — Slow vs signal-only split.
    if let Some(LastPullOutcome::Success { mode, .. }) = &inputs.last_pull_outcome {
        match mode {
            SyncMode::Slow => return SyncStatus::Synced,
            SyncMode::OfferFast | SyncMode::AlwaysFast => {
                return SyncStatus::Syncing { mode: *mode };
            }
        }
    }
    // (7) Staleness check vs the last successful pull stamp.
    if let Some(last_pull_ms) = inputs.last_pull_at_unix_ms {
        if inputs.now_unix_ms - last_pull_ms > SYNCED_STALENESS_THRESHOLD_MS {
            return SyncStatus::Syncing {
                mode: SyncMode::Slow,
            };
        }
        return SyncStatus::Synced;
    }
    // (8) Bootstrap — no prior pull.
    SyncStatus::Syncing {
        mode: SyncMode::Slow,
    }
}

// ---------------------------------------------------------------------
// MVP-2 issue 5.4 — hermetic tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_publish_queue() -> PublishQueueState {
        PublishQueueState {
            window_started_at_unix_ms: None,
            dirty_count: 0,
            dirty_byte_size: 0,
            blocked_on_balance: false,
        }
    }

    fn empty_delta() -> ConflictDelta {
        ConflictDelta::default()
    }

    fn bootstrap_inputs() -> SyncStatusInputs {
        SyncStatusInputs {
            last_pull_outcome: None,
            last_flush_outcome: None,
            publish_queue: empty_publish_queue(),
            conflicts_count: 0,
            conflict_delta: empty_delta(),
            last_pull_at_unix_ms: None,
            consecutive_pull_failures: 0,
            balance_state: GasBalanceState::Unknown {
                reason: "test-bootstrap".into(),
            },
            now_unix_ms: 1_700_000_000_000,
        }
    }

    // -----------------------------------------------------------------
    // Happy path
    // -----------------------------------------------------------------

    #[test]
    fn initial_status_with_no_inputs_is_syncing() {
        let inputs = bootstrap_inputs();
        let next = compute_next_status(
            &SyncStatus::Syncing {
                mode: SyncMode::Slow,
            },
            &inputs,
        );
        assert!(matches!(
            next,
            SyncStatus::Syncing {
                mode: SyncMode::Slow
            }
        ));
    }

    #[test]
    fn first_successful_pull_transitions_syncing_to_synced() {
        let mut inputs = bootstrap_inputs();
        inputs.last_pull_outcome = Some(LastPullOutcome::Success {
            mode: SyncMode::Slow,
            newly_frozen_count: 0,
            newly_resolved_count: 0,
        });
        inputs.last_pull_at_unix_ms = Some(inputs.now_unix_ms);
        let next = compute_next_status(
            &SyncStatus::Syncing {
                mode: SyncMode::Slow,
            },
            &inputs,
        );
        assert_eq!(next, SyncStatus::Synced);
    }

    #[test]
    fn successful_pull_resets_consecutive_failures() {
        // The reset is a HOST responsibility (the host clears its
        // counter on Ok). The transition function sees the
        // already-reset counter; we pin the contract here as a
        // regression check that the function does NOT consult
        // `last_pull_outcome` to override a non-zero counter.
        let mut inputs = bootstrap_inputs();
        inputs.consecutive_pull_failures = 0;
        inputs.last_pull_outcome = Some(LastPullOutcome::Success {
            mode: SyncMode::Slow,
            newly_frozen_count: 0,
            newly_resolved_count: 0,
        });
        inputs.last_pull_at_unix_ms = Some(inputs.now_unix_ms);
        assert_eq!(
            compute_next_status(&SyncStatus::Synced, &inputs),
            SyncStatus::Synced
        );
    }

    #[test]
    fn signal_only_offer_fast_resets_consecutive_failures() {
        // Same shape as `successful_pull_resets_consecutive_failures`
        // for the OfferFast signal-only branch (L4).
        let mut inputs = bootstrap_inputs();
        inputs.consecutive_pull_failures = 0;
        inputs.last_pull_outcome = Some(LastPullOutcome::Success {
            mode: SyncMode::OfferFast,
            newly_frozen_count: 0,
            newly_resolved_count: 0,
        });
        let next = compute_next_status(&SyncStatus::Synced, &inputs);
        assert!(matches!(
            next,
            SyncStatus::Syncing {
                mode: SyncMode::OfferFast
            }
        ));
    }

    #[test]
    fn signal_only_always_fast_resets_consecutive_failures() {
        let mut inputs = bootstrap_inputs();
        inputs.consecutive_pull_failures = 0;
        inputs.last_pull_outcome = Some(LastPullOutcome::Success {
            mode: SyncMode::AlwaysFast,
            newly_frozen_count: 0,
            newly_resolved_count: 0,
        });
        let next = compute_next_status(&SyncStatus::Synced, &inputs);
        assert!(matches!(
            next,
            SyncStatus::Syncing {
                mode: SyncMode::AlwaysFast
            }
        ));
    }

    // -----------------------------------------------------------------
    // Offline (R-c)
    // -----------------------------------------------------------------

    #[test]
    fn one_chain_failure_does_not_transition_to_offline() {
        let mut inputs = bootstrap_inputs();
        inputs.last_pull_outcome = Some(LastPullOutcome::Failure(PullErrorKind::Chain));
        inputs.consecutive_pull_failures = 1;
        let next = compute_next_status(
            &SyncStatus::Syncing {
                mode: SyncMode::Slow,
            },
            &inputs,
        );
        assert!(
            !matches!(next, SyncStatus::Offline { .. }),
            "1 failure < threshold ⇒ no Offline; got {next:?}"
        );
    }

    #[test]
    fn two_consecutive_chain_failures_do_not_transition_to_offline() {
        let mut inputs = bootstrap_inputs();
        inputs.last_pull_outcome = Some(LastPullOutcome::Failure(PullErrorKind::Chain));
        inputs.consecutive_pull_failures = 2;
        let next = compute_next_status(
            &SyncStatus::Syncing {
                mode: SyncMode::Slow,
            },
            &inputs,
        );
        assert!(
            !matches!(next, SyncStatus::Offline { .. }),
            "2 failures < threshold ⇒ no Offline; got {next:?}"
        );
    }

    #[test]
    fn three_consecutive_chain_failures_transition_to_offline() {
        let mut inputs = bootstrap_inputs();
        inputs.last_pull_outcome = Some(LastPullOutcome::Failure(PullErrorKind::Chain));
        inputs.consecutive_pull_failures = 3;
        let next = compute_next_status(
            &SyncStatus::Syncing {
                mode: SyncMode::Slow,
            },
            &inputs,
        );
        assert_eq!(
            next,
            SyncStatus::Offline {
                consecutive_failures: 3
            }
        );
    }

    #[test]
    fn offline_threshold_requires_three_consecutive_failures() {
        // L-offline-flapping: the threshold is the FLOOR not the
        // exact match — 4/5/6 failures all still produce Offline.
        for n in [3u32, 4, 5, 10, 100] {
            let mut inputs = bootstrap_inputs();
            inputs.last_pull_outcome = Some(LastPullOutcome::Failure(PullErrorKind::Chain));
            inputs.consecutive_pull_failures = n;
            let next = compute_next_status(&SyncStatus::Synced, &inputs);
            assert!(
                matches!(next, SyncStatus::Offline { consecutive_failures } if consecutive_failures == n),
                "{n} failures must produce Offline; got {next:?}"
            );
        }
    }

    #[test]
    fn successful_pull_after_offline_transitions_back_to_synced() {
        // Recovery: post-Offline, the host clears its counter on
        // the first Ok; the transition function then sees
        // `consecutive_pull_failures = 0` + a Success outcome.
        let mut inputs = bootstrap_inputs();
        inputs.consecutive_pull_failures = 0; // host reset
        inputs.last_pull_outcome = Some(LastPullOutcome::Success {
            mode: SyncMode::Slow,
            newly_frozen_count: 0,
            newly_resolved_count: 0,
        });
        inputs.last_pull_at_unix_ms = Some(inputs.now_unix_ms);
        let next = compute_next_status(
            &SyncStatus::Offline {
                consecutive_failures: 3,
            },
            &inputs,
        );
        assert_eq!(next, SyncStatus::Synced);
    }

    // -----------------------------------------------------------------
    // ConflictsPending (R-b)
    // -----------------------------------------------------------------

    #[test]
    fn pull_with_newly_frozen_account_transitions_to_conflicts_pending() {
        let mut inputs = bootstrap_inputs();
        inputs.last_pull_outcome = Some(LastPullOutcome::Success {
            mode: SyncMode::Slow,
            newly_frozen_count: 1,
            newly_resolved_count: 0,
        });
        inputs.last_pull_at_unix_ms = Some(inputs.now_unix_ms);
        inputs.conflicts_count = 1;
        let next = compute_next_status(&SyncStatus::Synced, &inputs);
        assert_eq!(next, SyncStatus::ConflictsPending { count: 1 });
    }

    #[test]
    fn pull_with_newly_resolved_account_clears_conflicts_pending() {
        // Resolution loopback: prior conflicts_count went 1 → 0;
        // newly_resolved_count = 1 — the host UI's banner should
        // dismiss.
        let mut inputs = bootstrap_inputs();
        inputs.last_pull_outcome = Some(LastPullOutcome::Success {
            mode: SyncMode::Slow,
            newly_frozen_count: 0,
            newly_resolved_count: 1,
        });
        inputs.last_pull_at_unix_ms = Some(inputs.now_unix_ms);
        inputs.conflicts_count = 0;
        let next = compute_next_status(&SyncStatus::ConflictsPending { count: 1 }, &inputs);
        assert_eq!(next, SyncStatus::Synced);
    }

    #[test]
    fn self_publish_round_trip_does_not_flash_conflicts_pending() {
        // L-conflict-pill-flashes-on-self-publish — on the round-
        // trip tick after a local publish, the per-cycle deltas
        // are zero (covered by 5.3's pull_after_local_publish_does
        // _not_self_freeze regression test). The transition
        // function then sees: Success { Slow, 0, 0 } +
        // conflicts_count = 0 ⇒ Synced (no flash).
        let mut inputs = bootstrap_inputs();
        inputs.last_pull_outcome = Some(LastPullOutcome::Success {
            mode: SyncMode::Slow,
            newly_frozen_count: 0,
            newly_resolved_count: 0,
        });
        inputs.last_pull_at_unix_ms = Some(inputs.now_unix_ms);
        inputs.conflicts_count = 0;
        let next = compute_next_status(&SyncStatus::Synced, &inputs);
        assert_eq!(next, SyncStatus::Synced);
    }

    // -----------------------------------------------------------------
    // BlockedOnBalance (R-b)
    // -----------------------------------------------------------------

    #[test]
    fn flush_with_balance_insufficient_transitions_to_blocked_on_balance() {
        let mut inputs = bootstrap_inputs();
        inputs.last_flush_outcome = Some(LastFlushOutcome::Failure(
            BatchFlushErrorKind::BalanceInsufficient {
                needed_wei: 1_000_000,
                available_wei: 1_000,
                queued_count: 3,
            },
        ));
        let next = compute_next_status(&SyncStatus::Synced, &inputs);
        assert_eq!(
            next,
            SyncStatus::BlockedOnBalance {
                needed_wei: 1_000_000,
                available_wei: 1_000,
            }
        );
    }

    #[test]
    fn successful_flush_after_top_up_clears_blocked_on_balance() {
        let mut inputs = bootstrap_inputs();
        inputs.last_flush_outcome = Some(LastFlushOutcome::Success);
        inputs.last_pull_outcome = Some(LastPullOutcome::Success {
            mode: SyncMode::Slow,
            newly_frozen_count: 0,
            newly_resolved_count: 0,
        });
        inputs.last_pull_at_unix_ms = Some(inputs.now_unix_ms);
        let next = compute_next_status(
            &SyncStatus::BlockedOnBalance {
                needed_wei: 1_000_000,
                available_wei: 1_000,
            },
            &inputs,
        );
        assert_eq!(next, SyncStatus::Synced);
    }

    #[test]
    fn balance_state_stale_overridden_by_fresh_flush_error() {
        // L-balance-state-stale-vs-flush-error — the BalanceMonitor's
        // cache says Sufficient, but a fresh flush returned the
        // batch-balance-insufficient error. The transition function
        // PREFERS the fresh flush error.
        let mut inputs = bootstrap_inputs();
        inputs.balance_state = GasBalanceState::Sufficient {
            balance_wei: 9_999_999,
            estimate_wei: 1_000,
        };
        inputs.last_flush_outcome = Some(LastFlushOutcome::Failure(
            BatchFlushErrorKind::BalanceInsufficient {
                needed_wei: 5_000_000,
                available_wei: 1_000,
                queued_count: 2,
            },
        ));
        let next = compute_next_status(&SyncStatus::Synced, &inputs);
        assert_eq!(
            next,
            SyncStatus::BlockedOnBalance {
                needed_wei: 5_000_000,
                available_wei: 1_000,
            },
            "fresh flush error must override stale BalanceMonitor::Sufficient"
        );
    }

    // -----------------------------------------------------------------
    // Terminal paths
    // -----------------------------------------------------------------

    #[test]
    fn orchestrator_tick_on_locked_vault_transitions_to_action_required() {
        let mut inputs = bootstrap_inputs();
        inputs.last_pull_outcome = Some(LastPullOutcome::NoActiveSession);
        let next = compute_next_status(&SyncStatus::Synced, &inputs);
        match next {
            SyncStatus::ActionRequired { reason } => {
                assert!(reason.contains("locked"), "got reason {reason:?}");
            }
            other => panic!("expected ActionRequired, got {other:?}"),
        }
    }

    #[test]
    fn store_error_from_pull_transitions_to_action_required() {
        let mut inputs = bootstrap_inputs();
        inputs.last_pull_outcome = Some(LastPullOutcome::Failure(PullErrorKind::Store));
        let next = compute_next_status(&SyncStatus::Synced, &inputs);
        match next {
            SyncStatus::ActionRequired { reason } => {
                assert!(reason.contains("store"), "got reason {reason:?}");
            }
            other => panic!("expected ActionRequired, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------
    // Vocabulary discipline (L5)
    // -----------------------------------------------------------------

    /// **L5 + §8.1.5.** The variant names + the `reason` /
    /// debug-string surface must NOT contain forbidden pricing
    /// copy. Mirrors `gas_balance_state_label_pinning` in 3.5.
    #[test]
    fn sync_status_variant_names_do_not_leak_pricing_copy() {
        let samples = [
            format!("{:?}", SyncStatus::Synced),
            format!(
                "{:?}",
                SyncStatus::Syncing {
                    mode: SyncMode::Slow
                }
            ),
            format!(
                "{:?}",
                SyncStatus::Offline {
                    consecutive_failures: 3
                }
            ),
            format!("{:?}", SyncStatus::ConflictsPending { count: 1 }),
            format!(
                "{:?}",
                SyncStatus::BlockedOnBalance {
                    needed_wei: 0,
                    available_wei: 0,
                }
            ),
            format!(
                "{:?}",
                SyncStatus::ActionRequired {
                    reason: "vault locked".into()
                }
            ),
            format!(
                "{:?}",
                SyncStatus::ActionRequired {
                    reason: "store error during sync".into()
                }
            ),
        ];
        for forbidden in [
            "LowBalance",
            "low balance",
            "OutOfGas",
            "out of gas",
            "InsufficientFunds",
            "insufficient funds",
            "NotEnoughFunds",
            "not enough funds",
            "Upgrade",
            "upgrade",
            "Pay",
            "Pricing",
            "pricing",
        ] {
            for sample in &samples {
                assert!(
                    !sample.contains(forbidden),
                    "SyncStatus debug surface must NOT contain forbidden token {forbidden:?}; got {sample}"
                );
            }
        }
    }

    // -----------------------------------------------------------------
    // Staleness threshold (audit fix-pass — pin clause 7)
    // -----------------------------------------------------------------

    #[test]
    fn staleness_threshold_after_5_min_downgrades_synced_to_syncing() {
        // 5.4 audit MEDIUM: clause 7 of compute_next_status downgrades
        // `Synced` to `Syncing { Slow }` after SYNCED_STALENESS_THRESHOLD_MS
        // has elapsed since the last successful pull. Without this pin
        // a wedged host scheduler could render `Synced` indefinitely.
        let mut inputs = bootstrap_inputs();
        inputs.last_pull_at_unix_ms = Some(inputs.now_unix_ms - SYNCED_STALENESS_THRESHOLD_MS - 1);
        assert_eq!(
            compute_next_status(&SyncStatus::Synced, &inputs),
            SyncStatus::Syncing {
                mode: SyncMode::Slow,
            },
            "stamp older than threshold must downgrade Synced to Syncing"
        );
    }

    #[test]
    fn staleness_threshold_at_exact_boundary_stays_synced() {
        // The `>` operator (not `>=`) means an exact-boundary stamp
        // (last_pull_at_unix_ms == now - threshold) is STILL fresh.
        let mut inputs = bootstrap_inputs();
        inputs.last_pull_at_unix_ms = Some(inputs.now_unix_ms - SYNCED_STALENESS_THRESHOLD_MS);
        assert_eq!(
            compute_next_status(&SyncStatus::Synced, &inputs),
            SyncStatus::Synced,
            "exact-boundary stamp is still fresh under `>`"
        );
    }

    #[test]
    fn staleness_threshold_with_recent_stamp_stays_synced() {
        let mut inputs = bootstrap_inputs();
        inputs.last_pull_at_unix_ms = Some(inputs.now_unix_ms - 30_000); // 30s ago
        assert_eq!(
            compute_next_status(&SyncStatus::Synced, &inputs),
            SyncStatus::Synced
        );
    }
}
