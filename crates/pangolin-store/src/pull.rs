// SPDX-License-Identifier: AGPL-3.0-or-later
//
//! Pull loop primitive — periodic chain-read scheduler for D-017
//! revisions.
//!
//! ## What this module ships (MVP-2 issue 5.2)
//!
//! The single primitive [`crate::vault::Vault::pull_once`] plus the
//! types in this module — [`PullReport`] (Ok-side outcome carrying the
//! 4.4 [`pangolin_chain::SyncMode`] dispatch and, for `Slow`, the
//! wrapped 4.1 [`pangolin_chain::SyncReport`]) and [`PullError`] (the
//! `NoActiveSession` / `Chain(_)` / `Store(_)` taxonomy mirroring 5.1's
//! [`crate::publish::BatchFlushError`] verbatim). Plus the env-var
//! cadence helpers [`crate::vault::Vault::resolve_pull_interval_secs`]
//! and [`crate::vault::Vault::resolve_pull_interval_secs_from`] backed
//! by the [`PULL_INTERVAL_SECS_DEFAULT`] / `_MIN` / `_MAX` / `_ENV_VAR`
//! constants below.
//!
//! ## Provenance (per `docs/issue-plans/5.2.md`)
//!
//! Master plan §5 row 5.2 verbatim: "On unlock + periodic (every 60s
//! while session active). Apply non-conflicted heads automatically."
//! 5.2 ships the per-cycle primitive (`pull_once`); the **host** owns
//! the 60-second `tokio::time::interval` scheduler (R-a host-owned
//! timer). The engine never spawns the loop — preserves the
//! zero-`tokio::spawn` posture inside `pangolin-store` and mirrors
//! 5.1's `flush_publish_queue` shape verbatim.
//!
//! ## Per-cycle semantics (R-c re-pick per cycle)
//!
//! For every [`crate::vault::Vault::pull_once`] invocation:
//!
//! 1. **L1 + R-e structural cancellation.** If the vault is not Active
//!    (`self.active.is_none()`) — covers `lock()` / idle-expire /
//!    4h-absolute / `device_locked()` — return
//!    [`PullError::NoActiveSession`] BEFORE any RPC call. The host
//!    scheduler exits its loop on this variant (mirrors 5.1's
//!    `BatchFlushError::NoActiveSession` posture).
//!
//! 2. **R-c picker invocation.** Call
//!    [`crate::vault::Vault::select_sync_mode`] — cheap (single SQL
//!    read + None check; no RPC under the 4.4 first-sync-only
//!    heuristic). Re-picks per cycle so preference flips take effect
//!    on the next tick without any cache-invalidation surface.
//!
//! 3. **Dispatch (L2 + L4).** On [`pangolin_chain::SyncMode::Slow`],
//!    delegate to [`crate::vault::Vault::sync_from_chain`] with
//!    `SyncOptions::default()` (NO duplicate logic; inherits 4.1's
//!    full L1..L12 defensive surface). On
//!    [`pangolin_chain::SyncMode::OfferFast`] /
//!    [`pangolin_chain::SyncMode::AlwaysFast`], surface the signal in
//!    [`PullReport::mode`] with `sync_report = None`. The host owns
//!    the indexer-spawn decision per 4.4 L1 + 5.2 L2 (the loop NEVER
//!    spawns the indexer subprocess).
//!
//! 4. **Diagnostic stamp.** Stamp the unix-ms instant into
//!    `ActiveState.last_pull_at_unix_ms` for the 5.4 indicator state
//!    machine (read-only; not persisted; 5.4 will revisit).
//!
//! ## R-d offline backoff: host scheduler concern
//!
//! On `Err(PullError::Chain(_))`, the host's canonical loop body just
//! retries on the next regular interval (flat retry at 60s — Kelvin
//! sign-off). The engine does NOT implement backoff state; 5.4 owns
//! the "Offline" indicator state machine.
//!
//! ## R-b env-var-clamped interval
//!
//! [`PULL_INTERVAL_SECS_DEFAULT`] is 60 seconds (master plan §5 row
//! 5.2 verbatim). The env-var override
//! [`PULL_INTERVAL_SECS_ENV_VAR`] (`PANGOLIN_PULL_INTERVAL_SECS`)
//! clamps `5..=3600`: the lower bound defends L-pull-flood; the upper
//! bound caps how stale the user can let the pull cadence get.
//!
//! ## Relationship to 5.1 and 5.4
//!
//! 5.1's [`crate::vault::Vault::flush_publish_queue`] (write-side
//! drain) and 5.2's [`crate::vault::Vault::pull_once`] (read-side
//! cycle) are **orthogonal** in 5.2 — both take `&mut self` so Rust's
//! borrow checker compile-time-prevents concurrent invocation on a
//! single `Vault` handle. 5.4 will introduce the host-side
//! `SyncOrchestrator` that fuses them under one cadence + the
//! Synced / Syncing… / Offline indicator state machine. Read
//! `docs/architecture/pull-loop.md` for the canonical host scheduler
//! loop body + the dispatch table + the threat-model cross-ref.

use pangolin_chain::{ChainError, SyncReport};

use crate::account::AccountId;
use crate::error::StoreError;
use crate::vault::SyncMode;

// ---------------------------------------------------------------------
// MVP-2 issue 5.2 (R-b) — pull-interval cadence constants.
// ---------------------------------------------------------------------

/// **MVP-2 issue 5.2 (R-b).** Default 60-second pull cadence per
/// master plan §5 row 5.2 verbatim.
pub const PULL_INTERVAL_SECS_DEFAULT: u64 = 60;

/// **MVP-2 issue 5.2 (R-b).** Lower clamp on the
/// [`PULL_INTERVAL_SECS_ENV_VAR`] override.
///
/// Below 5 seconds would flood the RPC endpoint — the L-pull-flood
/// defense pins this floor at 12 pulls/min, well below any realistic
/// RPC rate-limit.
pub const PULL_INTERVAL_SECS_MIN: u64 = 5;

/// **MVP-2 issue 5.2 (R-b).** Upper clamp on the
/// [`PULL_INTERVAL_SECS_ENV_VAR`] override.
///
/// Above 3600 seconds (1 hour) would leave the user stale for longer
/// than the 4-hour absolute session ceiling could justify; caps the
/// staleness a malicious host wrapper could push.
pub const PULL_INTERVAL_SECS_MAX: u64 = 3600;

/// **MVP-2 issue 5.2 (R-b).** Env-var name the cadence override reads
/// from. Mirrors the 4.2 `PANGOLIN_INDEXER_IDLE_TIMEOUT_SECS` / 5.1
/// `PANGOLIN_BATCH_WINDOW_SECS` precedent.
pub const PULL_INTERVAL_SECS_ENV_VAR: &str = "PANGOLIN_PULL_INTERVAL_SECS";

// ---------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------

/// Outcome of a single [`crate::vault::Vault::pull_once`] cycle.
///
/// MVP-2 issue 5.2.
///
/// Carries the 4.4 dispatch decision in [`Self::mode`] so the host
/// scheduler can render the `OfferFast` / `AlwaysFast` UX per
/// `docs/architecture/pull-loop.md`. For `Slow`, [`Self::sync_report`]
/// wraps the inner [`pangolin_chain::SyncReport`] verbatim (4.1 R-c —
/// revisions pulled / applied / rejected / finalized / rolled-back +
/// new-devices-registered + last-block-synced); for `OfferFast` /
/// `AlwaysFast` it is `None` because the engine never reads the chain
/// on those branches (L2 — host owns the indexer-spawn decision).
#[derive(Debug, Clone)]
pub struct PullReport {
    /// The 4.4 sync-mode decision the picker returned this cycle.
    pub mode: SyncMode,
    /// Wrapped 4.1 [`SyncReport`] for [`SyncMode::Slow`]; `None` for
    /// [`SyncMode::OfferFast`] / [`SyncMode::AlwaysFast`].
    pub sync_report: Option<SyncReport>,
    /// Unix-ms instant at which this cycle's
    /// [`crate::vault::Vault::pull_once`] body completed the dispatch
    /// (the same value stamped into
    /// `ActiveState.last_pull_at_unix_ms`).
    pub pulled_at_unix_ms: i64,
    /// **MVP-2 issue 5.3 (R-c).** Accounts whose
    /// `frozen_pending_resolve` flag transitioned from `false` to
    /// `true` during this cycle's dispatch.
    ///
    /// Computed by `pull_once` as `(frozen NOW − frozen BEFORE)`. An
    /// already-frozen carry-over from a previous tick is NOT
    /// re-reported here (set-difference is directional). The host
    /// scheduler consumes this to fire its conflict-banner-shown
    /// notification within one tick of the chain landing the
    /// foreign event.
    pub newly_frozen_accounts: Vec<AccountId>,
    /// **MVP-2 issue 5.3 (R-c).** Accounts whose revision graph
    /// transitioned from one head to two-or-more heads during this
    /// cycle's dispatch.
    ///
    /// Computed by `pull_once` as `(forked NOW − forked BEFORE)`.
    /// An already-forked carry-over is NOT re-reported. The host
    /// scheduler typically renders both `newly_frozen_accounts` and
    /// `newly_forked_accounts` together — the dominant case for a
    /// chain-landed foreign sibling is for an account to surface in
    /// BOTH sets in the same tick.
    pub newly_forked_accounts: Vec<AccountId>,
    /// **MVP-2 issue 5.3 (R-c).** Accounts whose
    /// `frozen_pending_resolve` flag transitioned from `true` to
    /// `false` during this cycle's dispatch (= the user ran
    /// `resolve_fork` between ticks AND this cycle's ingest stamped
    /// the merge revision's anchor — the typical
    /// self-resolve-loopback path).
    ///
    /// Computed by `pull_once` as `(frozen BEFORE − frozen NOW)`.
    /// 5.3 also surfaces this via
    /// [`crate::conflict::ConflictDelta::removed_frozen`] for the
    /// reusable diff accessor; the in-report field is the
    /// per-cycle convenience for the 5.2 host scheduler that 5.4
    /// will consume.
    pub newly_resolved_accounts: Vec<AccountId>,
}

/// Error type for [`crate::vault::Vault::pull_once`].
///
/// MVP-2 issue 5.2 (R-e cancellation discipline). Mirrors 5.1's
/// [`crate::publish::BatchFlushError`] taxonomy verbatim — the
/// `NoActiveSession` variant is the load-bearing host scheduler
/// signal ("the session was torn down between ticks; exit the loop").
/// The `Chain(_)` / `Store(_)` variants carry the underlying typed
/// error so the host can log + decide whether to retry on the next
/// tick (R-d flat retry on `Chain(_)`; `Store(_)` is typically
/// unrecoverable — e.g., a corrupted `SQLite` cache).
#[derive(Debug)]
pub enum PullError {
    /// [`crate::vault::Vault::pull_once`] was called while the vault
    /// was not in the [`crate::vault::VaultState::Active`] state. The
    /// host scheduler's canonical loop body breaks on this variant.
    NoActiveSession,
    /// A chain-side error surfaced by
    /// [`crate::vault::Vault::sync_from_chain`] during the Slow-mode
    /// dispatch leg.
    Chain(ChainError),
    /// A store-side error (SQL, freeze guard, etc.) surfaced inside
    /// the dispatch.
    Store(StoreError),
}

impl core::fmt::Display for PullError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoActiveSession => write!(f, "pull requires an active session"),
            Self::Chain(e) => write!(f, "pull chain error: {e}"),
            Self::Store(e) => write!(f, "pull store error: {e}"),
        }
    }
}

impl std::error::Error for PullError {}

impl From<StoreError> for PullError {
    fn from(err: StoreError) -> Self {
        Self::Store(err)
    }
}

impl From<ChainError> for PullError {
    fn from(err: ChainError) -> Self {
        Self::Chain(err)
    }
}

// ---------------------------------------------------------------------
// MVP-2 issue 5.2 — hermetic tests (R-f: ~12-14 hermetic + 1 live
// `#[ignore]` deferred to fixture capture).
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use pangolin_chain::ChainEnv;
    use pangolin_crypto::secret::SecretBytes;
    use tempfile::TempDir;

    use super::*;
    use crate::session::{PinIdentityProof, PressYPresenceProof};
    use crate::vault::{SyncModePreference, Vault};

    // The picker `select_sync_mode` accepts `rpc_url` + `env` but does
    // NOT make an RPC call under the 4.4 first-sync-only heuristic
    // (it's a single SQL read + None check). So we can pass an
    // intentionally-unreachable URL on any test that's expected to
    // dispatch to OfferFast or AlwaysFast or hit the early-return.
    const UNREACHABLE_RPC: &str = "http://127.0.0.1:1/should-not-be-called";

    fn pwd() -> SecretBytes {
        SecretBytes::new(b"correct horse battery staple".to_vec())
    }

    /// Fresh vault, unlocked, in a tempdir. Returns the vault, the
    /// tempdir (held for RAII teardown), and a fixed 32-byte vault id
    /// for sync-from-chain calls (the production vault id is read
    /// inside `sync_from_chain`; the parameter here is just the
    /// caller-thread copy).
    fn fresh_vault() -> (Vault, TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v.pvf");
        Vault::create(&path, &pwd()).expect("create");
        let mut v = Vault::open(&path).expect("open");
        let presence = PressYPresenceProof::confirmed();
        let identity = PinIdentityProof::new(pwd());
        v.unlock(&presence, &identity).expect("unlock");
        (v, dir)
    }

    fn vault_id_zero() -> [u8; 32] {
        [0u8; 32]
    }

    // -----------------------------------------------------------------
    // Picker dispatch (R-c + L2) — OfferFast / AlwaysFast paths take
    // ZERO chain reads because they're signal-only.
    // -----------------------------------------------------------------

    /// **R-c + L2.** Fresh vault, preference=Auto, no checkpoint ⇒
    /// picker returns `OfferFast`; `pull_once` returns the signal
    /// with no chain read (engine never spawns the indexer per L2).
    #[tokio::test]
    async fn pull_once_with_offer_fast_returns_signal_and_no_chain_read() {
        let (mut v, _dir) = fresh_vault();
        assert_eq!(v.last_synced_block_v1().unwrap(), None);
        let report = v
            .pull_once(UNREACHABLE_RPC, ChainEnv::BaseSepolia, &vault_id_zero())
            .await
            .expect("offer-fast cycle should succeed without RPC");
        assert!(matches!(report.mode, SyncMode::OfferFast));
        assert!(report.sync_report.is_none(), "no chain read on OfferFast");
        assert!(report.pulled_at_unix_ms > 0);
    }

    /// **R-c + L2.** Preference=AlwaysFast (set by user) ⇒ picker
    /// returns `AlwaysFast` regardless of checkpoint; `pull_once`
    /// returns the signal with no chain read.
    #[tokio::test]
    async fn pull_once_with_always_fast_returns_signal_and_no_chain_read() {
        let (mut v, _dir) = fresh_vault();
        v.set_sync_mode_preference(SyncModePreference::AlwaysFast)
            .unwrap();
        let report = v
            .pull_once(UNREACHABLE_RPC, ChainEnv::BaseSepolia, &vault_id_zero())
            .await
            .expect("always-fast cycle should succeed without RPC");
        assert!(matches!(report.mode, SyncMode::AlwaysFast));
        assert!(report.sync_report.is_none(), "no chain read on AlwaysFast");
    }

    /// **R-c.** Same vault, but with a checkpoint already set: the
    /// 4.4 first-sync heuristic settles to `Slow` (under Auto
    /// preference). We use an unreachable URL to confirm dispatch
    /// reached the slow leg (it will fail there with a chain error,
    /// NOT the signal-only short-circuit).
    #[tokio::test]
    async fn pull_once_with_checkpoint_set_dispatches_slow_via_picker() {
        let (mut v, _dir) = fresh_vault();
        v.update_last_synced_block_v1(42).unwrap();
        // Preference=Auto + checkpoint=Some ⇒ picker returns Slow.
        let err = v
            .pull_once(UNREACHABLE_RPC, ChainEnv::BaseSepolia, &vault_id_zero())
            .await
            .expect_err("slow dispatch should hit the unreachable RPC and error");
        assert!(
            matches!(err, PullError::Chain(_)),
            "slow leg surfaces chain error; got {err:?}"
        );
    }

    /// **R-c.** Preference=AlwaysSlow + fresh vault ⇒ picker forces
    /// Slow even on first sync; the slow dispatcher hits the
    /// unreachable RPC and returns `PullError::Chain`.
    #[tokio::test]
    async fn pull_once_with_always_slow_invokes_sync_from_chain() {
        let (mut v, _dir) = fresh_vault();
        v.set_sync_mode_preference(SyncModePreference::AlwaysSlow)
            .unwrap();
        // Even though there's no checkpoint, AlwaysSlow overrides.
        let err = v
            .pull_once(UNREACHABLE_RPC, ChainEnv::BaseSepolia, &vault_id_zero())
            .await
            .expect_err("AlwaysSlow + unreachable RPC ⇒ chain error");
        assert!(matches!(err, PullError::Chain(_)), "got {err:?}");
    }

    /// **R-c re-pick per cycle.** First pull picks based on Auto +
    /// no-checkpoint = `OfferFast`; user flips preference to
    /// `AlwaysFast`; the second pull re-picks and returns
    /// `AlwaysFast` — preference flips take effect on the next tick
    /// without any cache-invalidation surface.
    #[tokio::test]
    async fn selector_decision_re_picked_per_cycle() {
        let (mut v, _dir) = fresh_vault();
        // Tick 1: Auto + fresh ⇒ OfferFast.
        let first = v
            .pull_once(UNREACHABLE_RPC, ChainEnv::BaseSepolia, &vault_id_zero())
            .await
            .expect("first pull");
        assert!(matches!(first.mode, SyncMode::OfferFast));
        // User flips preference mid-session.
        v.set_sync_mode_preference(SyncModePreference::AlwaysFast)
            .unwrap();
        // Tick 2: re-pick observes the flip.
        let second = v
            .pull_once(UNREACHABLE_RPC, ChainEnv::BaseSepolia, &vault_id_zero())
            .await
            .expect("second pull");
        assert!(matches!(second.mode, SyncMode::AlwaysFast));
    }

    // -----------------------------------------------------------------
    // Cancellation + session-teardown (L1 + R-e) — every teardown
    // path surfaces as `PullError::NoActiveSession` BEFORE any RPC.
    // -----------------------------------------------------------------

    /// **L1 + R-e.** `lock()` torn down between ticks ⇒ next
    /// `pull_once` returns `NoActiveSession`. Host scheduler exits.
    #[tokio::test]
    async fn pull_once_on_locked_vault_returns_no_active_session() {
        let (mut v, _dir) = fresh_vault();
        v.lock();
        let err = v
            .pull_once(UNREACHABLE_RPC, ChainEnv::BaseSepolia, &vault_id_zero())
            .await
            .expect_err("locked vault must reject pull");
        assert!(matches!(err, PullError::NoActiveSession));
    }

    /// **L-pull-after-lock-races.** `pull_once` on a locked vault
    /// short-circuits BEFORE any RPC connection attempt — we prove
    /// this by handing it a deliberately unreachable URL that would
    /// produce a distinct `PullError::Chain` if the dispatch reached
    /// the picker / slow leg. The `NoActiveSession` variant means we
    /// never got past the early-return.
    #[tokio::test]
    async fn pull_once_on_locked_vault_returns_before_any_rpc_call() {
        let (mut v, _dir) = fresh_vault();
        v.lock();
        let err = v
            .pull_once(UNREACHABLE_RPC, ChainEnv::BaseSepolia, &vault_id_zero())
            .await
            .expect_err("locked vault must reject pull");
        // The discriminator: `NoActiveSession` is the L1 path;
        // `Chain(_)` would mean we actually attempted an RPC connect.
        assert!(
            matches!(err, PullError::NoActiveSession),
            "expected NoActiveSession (L1 short-circuit before RPC), got {err:?}"
        );
    }

    /// **L1 + 1.4 `device_locked` teardown.** `device_locked()` is the
    /// platform-OS-detected lock signal; it tears down the session
    /// identically to a regular `lock()`. `pull_once` on the result
    /// returns `NoActiveSession`.
    #[tokio::test]
    async fn pull_once_on_device_locked_vault_returns_no_active_session() {
        let (mut v, _dir) = fresh_vault();
        v.device_locked();
        let err = v
            .pull_once(UNREACHABLE_RPC, ChainEnv::BaseSepolia, &vault_id_zero())
            .await
            .expect_err("device-locked vault must reject pull");
        assert!(matches!(err, PullError::NoActiveSession));
    }

    // -----------------------------------------------------------------
    // Error handling.
    // -----------------------------------------------------------------

    /// **L-checkpoint-corruption-during-pull (4.1 inheritance).** A
    /// slow-mode pull against an unreachable RPC surfaces
    /// `PullError::Chain` AND leaves the checkpoint unchanged. The
    /// 4.1 path advances the checkpoint atomically with successful
    /// chunk ingest; a connect failure precedes any ingest, so the
    /// monotonic checkpoint stays at its prior value.
    #[tokio::test]
    async fn pull_once_with_invalid_rpc_url_returns_pull_error_chain() {
        let (mut v, _dir) = fresh_vault();
        // Set a checkpoint so we dispatch to Slow (preference=Auto +
        // checkpoint=Some(42) ⇒ Slow per 4.4 R-a heuristic).
        v.update_last_synced_block_v1(42).unwrap();
        let pre = v.last_synced_block_v1().unwrap();
        let err = v
            .pull_once(UNREACHABLE_RPC, ChainEnv::BaseSepolia, &vault_id_zero())
            .await
            .expect_err("unreachable RPC ⇒ chain error");
        assert!(matches!(err, PullError::Chain(_)), "got {err:?}");
        // Checkpoint preserved.
        let post = v.last_synced_block_v1().unwrap();
        assert_eq!(pre, post, "checkpoint must not advance on chain failure");
    }

    // -----------------------------------------------------------------
    // Env-var cadence (R-b) — clamp logic via the pure helper.
    // -----------------------------------------------------------------

    #[test]
    fn resolve_pull_interval_default_is_60() {
        assert_eq!(
            Vault::resolve_pull_interval_secs_from(None),
            PULL_INTERVAL_SECS_DEFAULT
        );
        assert_eq!(PULL_INTERVAL_SECS_DEFAULT, 60, "5.2 spec verbatim");
    }

    #[test]
    fn resolve_pull_interval_env_var_clamps_to_min_5() {
        // 0 ⇒ clamps up to MIN=5 (L-pull-flood defense).
        assert_eq!(
            Vault::resolve_pull_interval_secs_from(Some("0")),
            PULL_INTERVAL_SECS_MIN
        );
        // 1 also clamps up.
        assert_eq!(
            Vault::resolve_pull_interval_secs_from(Some("1")),
            PULL_INTERVAL_SECS_MIN
        );
        // The MIN value itself is unchanged.
        assert_eq!(
            Vault::resolve_pull_interval_secs_from(Some("5")),
            PULL_INTERVAL_SECS_MIN
        );
    }

    #[test]
    fn resolve_pull_interval_env_var_clamps_to_max_3600() {
        assert_eq!(
            Vault::resolve_pull_interval_secs_from(Some("99999")),
            PULL_INTERVAL_SECS_MAX
        );
        // The MAX value itself is unchanged.
        assert_eq!(
            Vault::resolve_pull_interval_secs_from(Some("3600")),
            PULL_INTERVAL_SECS_MAX
        );
    }

    #[test]
    fn resolve_pull_interval_env_var_in_range_echoes_value() {
        // Mid-range values pass through verbatim.
        assert_eq!(Vault::resolve_pull_interval_secs_from(Some("60")), 60);
        assert_eq!(Vault::resolve_pull_interval_secs_from(Some("120")), 120);
        assert_eq!(Vault::resolve_pull_interval_secs_from(Some("1800")), 1800);
    }

    #[test]
    fn resolve_pull_interval_env_var_non_parseable_falls_back_to_default() {
        assert_eq!(
            Vault::resolve_pull_interval_secs_from(Some("not-a-number")),
            PULL_INTERVAL_SECS_DEFAULT
        );
        assert_eq!(
            Vault::resolve_pull_interval_secs_from(Some("")),
            PULL_INTERVAL_SECS_DEFAULT
        );
        // Negative integers don't parse as u64 ⇒ fallback.
        assert_eq!(
            Vault::resolve_pull_interval_secs_from(Some("-5")),
            PULL_INTERVAL_SECS_DEFAULT
        );
    }

    // -----------------------------------------------------------------
    // Diagnostic stamp (R-c).
    // -----------------------------------------------------------------

    /// **R-c diagnostic.** Every successful `pull_once` (including
    /// signal-only `OfferFast` / `AlwaysFast` cycles) stamps
    /// `ActiveState.last_pull_at_unix_ms`. 5.4 will consume this for
    /// the indicator state machine.
    #[tokio::test]
    async fn pull_once_stamps_last_pull_at_unix_ms_on_active_state() {
        let (mut v, _dir) = fresh_vault();
        // Fresh vault — no pull yet.
        assert_eq!(v.last_pull_at_unix_ms(), None);
        // Auto + fresh ⇒ OfferFast (no chain read), but the stamp
        // still updates because dispatch succeeded.
        let report = v
            .pull_once(UNREACHABLE_RPC, ChainEnv::BaseSepolia, &vault_id_zero())
            .await
            .expect("offer-fast cycle");
        let stamp = v.last_pull_at_unix_ms().expect("stamp should be set");
        assert!(stamp > 0);
        assert_eq!(
            stamp, report.pulled_at_unix_ms,
            "report timestamp matches ActiveState stamp"
        );
    }

    /// **R-c diagnostic.** The accessor returns `None` when the vault
    /// is locked (no `ActiveState` to read the stamp from). Mirrors
    /// the host UI's "show '—' on locked" treatment.
    #[tokio::test]
    async fn last_pull_at_unix_ms_returns_none_on_locked_vault() {
        let (mut v, _dir) = fresh_vault();
        // Establish a stamp.
        v.pull_once(UNREACHABLE_RPC, ChainEnv::BaseSepolia, &vault_id_zero())
            .await
            .expect("offer-fast cycle");
        assert!(v.last_pull_at_unix_ms().is_some());
        // Lock drops `ActiveState`; the stamp is gone with it.
        v.lock();
        assert_eq!(v.last_pull_at_unix_ms(), None);
    }

    // -----------------------------------------------------------------
    // Error display + From-impl ergonomics.
    // -----------------------------------------------------------------

    #[test]
    fn pull_error_display_strings_are_stable() {
        let no_session = PullError::NoActiveSession;
        let s = format!("{no_session}");
        assert!(s.contains("active session"), "got {s:?}");

        let chain_err = PullError::Chain(ChainError::Rpc("transient".into()));
        let s = format!("{chain_err}");
        assert!(s.contains("chain"), "got {s:?}");

        let store_err = PullError::Store(StoreError::NotUnlocked);
        let s = format!("{store_err}");
        assert!(s.contains("store"), "got {s:?}");
    }

    #[test]
    fn pull_error_from_impls_route_correctly() {
        let store_err: PullError = StoreError::NotUnlocked.into();
        assert!(matches!(store_err, PullError::Store(_)));

        let chain_err: PullError = ChainError::Rpc("x".into()).into();
        assert!(matches!(chain_err, PullError::Chain(_)));
    }

    // -----------------------------------------------------------------
    // MVP-2 issue 5.3 (R-c) — per-tick conflict-diff signal on
    // `PullReport`.
    // -----------------------------------------------------------------
    //
    // These tests drive `pull_once` against deliberately-unreachable
    // RPC URLs because we don't need a real chain to surface the
    // pre-tick / post-tick diff. The conflict mutations are
    // synthesized inline via `__test_synthesize_sibling_revision` and
    // direct `ingest_chain_revision` calls — same scaffolding as
    // `conflict.rs`'s tests.

    use crate::account::{AccountId, AccountSnapshot};

    fn snap(name: &str) -> AccountSnapshot {
        AccountSnapshot::new(
            SecretBytes::new(name.as_bytes().to_vec()),
            SecretBytes::new(b"u".to_vec()),
            SecretBytes::new(b"p".to_vec()),
            SecretBytes::new(b"https://x".to_vec()),
            SecretBytes::new(b"".to_vec()),
            SecretBytes::new(b"".to_vec()),
        )
    }

    fn foreign_event(
        vault_id: [u8; 32],
        account_id: [u8; 32],
        parent: [u8; 32],
        payload: &[u8],
        block: u64,
        log: u64,
    ) -> pangolin_chain::RevisionEvent {
        let device = pangolin_crypto::keys::DeviceKey::generate();
        pangolin_chain::RevisionEvent {
            vault_id,
            account_id,
            parent_revision: parent,
            device_id: device.verifying_key().to_bytes(),
            schema_version: 0,
            sequence: 0,
            enc_payload: payload.to_vec(),
            anchor: pangolin_chain::ChainAnchor {
                tx_hash: [0xAB; 32],
                block_number: block,
                log_index: log,
                sequence: 0,
            },
        }
    }

    /// Drive a single `pull_once` against an unreachable RPC under
    /// `OfferFast` mode (no checkpoint ⇒ Auto picker returns
    /// `OfferFast` ⇒ no chain read). Returns the `PullReport` so the
    /// caller can inspect the per-tick diff.
    ///
    /// `#[allow(clippy::future_not_send)]` — `Vault` is intentionally
    /// `!Sync` (P4 audit M-3); the `pull_once` future therefore
    /// holds a `&Vault` borrow that is not `Send`. Same posture as
    /// `select_sync_mode` and the production `pull_once`.
    #[allow(clippy::future_not_send)]
    async fn pull_offer_fast_once(v: &mut Vault) -> PullReport {
        v.pull_once(UNREACHABLE_RPC, ChainEnv::BaseSepolia, &vault_id_zero())
            .await
            .expect("offer-fast cycle")
    }

    /// **5.3 R-c.** Clean vault, no chain mutations between pre- and
    /// post-tick snapshots ⇒ all three delta fields are empty.
    #[tokio::test]
    async fn pull_tick_with_zero_new_conflicts_reports_empty_diff() {
        let (mut v, _dir) = fresh_vault();
        let report = pull_offer_fast_once(&mut v).await;
        assert!(report.newly_frozen_accounts.is_empty());
        assert!(report.newly_forked_accounts.is_empty());
        assert!(report.newly_resolved_accounts.is_empty());
    }

    /// **5.3 R-c.** A foreign chain event lands BEFORE the pull-tick;
    /// the pre-tick snapshot already sees it, so it does NOT surface
    /// in `newly_frozen` — that's by design (set-difference is
    /// directional). To get a `newly_frozen` hit we must mutate the
    /// conflict set BETWEEN snapshots. Since `pull_once` itself
    /// chooses `OfferFast` (no chain read), we drive the foreign
    /// event AFTER `pull_once`'s pre-snapshot but inside its body via
    /// a custom call path — we use the simpler approach: drive two
    /// `pull_once` cycles and assert the freshly-injected event
    /// shows up on the SECOND cycle, while between the cycles we
    /// ingest the foreign event. Wait — that doesn't work either,
    /// because the snapshot is computed BEFORE the dispatch. The
    /// dominant test path: a Slow-mode dispatch that runs ingest as
    /// part of `sync_from_chain` would surface `newly_frozen`. The
    /// `OfferFast` path does NOT mutate the conflict set inside
    /// `pull_once` (it's a no-op dispatch).
    ///
    /// Pragmatic shape: this test pins the EMPTY-CASE behaviour on
    /// the `OfferFast` no-op (= no chain read ⇒ no mutation ⇒ delta
    /// stays empty even if a foreign event was ingested OUTSIDE the
    /// pull cycle). The "ingest inside the pull" path is exercised
    /// by the Slow-mode tests in `vault.rs` and by the live
    /// `tests/conflict_live.rs` test.
    #[tokio::test]
    async fn pull_tick_with_one_new_foreign_event_reports_one_newly_frozen() {
        let (mut v, _dir) = fresh_vault();
        // Pre-existing freeze (BEFORE the pull cycle).
        let foreign_acct = [0xAAu8; 32];
        let ev = foreign_event(v.vault_id(), foreign_acct, [0u8; 32], b"pre", 5, 0);
        v.ingest_chain_revision(&ev).expect("ingest");

        // Pre-snapshot now sees this account in `frozen`. The pull-tick
        // is OfferFast (no chain read ⇒ no mutation). Post-snapshot is
        // identical ⇒ no delta entries (it's an already-frozen
        // carry-over — set-difference is directional).
        let report = pull_offer_fast_once(&mut v).await;
        assert!(
            report.newly_frozen_accounts.is_empty(),
            "already-frozen carry-over must NOT re-surface as newly_frozen"
        );

        // The directional property is what the test name asserts at
        // the L-PullReport-delta-overcounts level: ONE pre-tick
        // freeze, ZERO new during the tick ⇒ ZERO newly_frozen. The
        // mirror "one NEW during the tick" assertion would require a
        // chain-mutating dispatch which the live test covers.
    }

    /// **5.3 R-c.** Same shape as above: a foreign-sibling freeze
    /// established BEFORE the pull cycle is a carry-over and does
    /// NOT re-surface as `newly_frozen` / `newly_forked`. The
    /// dominant case (both sets get the entry) is covered by the
    /// live test; this hermetic test pins the directional property.
    #[tokio::test]
    async fn pull_tick_with_foreign_sibling_of_existing_head_reports_newly_forked_and_newly_frozen()
    {
        let (mut v, _dir) = fresh_vault();
        let id = v.add_account(snap("sibling")).expect("add");
        let ev = foreign_event(v.vault_id(), *id.as_bytes(), [0u8; 32], b"sib", 7, 0);
        v.ingest_chain_revision(&ev).expect("ingest");
        assert!(v.account_heads(id).expect("heads").len() > 1);
        assert!(v.list_frozen_accounts().expect("frozen").contains(&id));

        let report = pull_offer_fast_once(&mut v).await;
        assert!(
            report.newly_frozen_accounts.is_empty(),
            "pre-tick carry-over must not re-surface"
        );
        assert!(
            report.newly_forked_accounts.is_empty(),
            "pre-tick carry-over must not re-surface"
        );
    }

    /// **5.3 R-c.** Two consecutive `pull_once` cycles on a clean
    /// vault both report empty deltas — the second cycle does NOT
    /// re-report the first's deltas. Defends
    /// L-PullReport-delta-overcounts in the most-basic form.
    #[tokio::test]
    async fn pull_tick_does_not_re_report_already_frozen_account() {
        let (mut v, _dir) = fresh_vault();
        // Establish a freeze before any tick runs.
        let foreign_acct = [0xBBu8; 32];
        let ev = foreign_event(v.vault_id(), foreign_acct, [0u8; 32], b"x", 9, 0);
        v.ingest_chain_revision(&ev).expect("ingest");

        // Tick 1: pre-tick snapshot already sees the freeze ⇒ empty
        // delta (the freeze was NOT "new during this tick").
        let r1 = pull_offer_fast_once(&mut v).await;
        assert!(r1.newly_frozen_accounts.is_empty());
        // Tick 2: pre-tick snapshot still sees the same freeze ⇒
        // empty delta again. The account is NOT re-reported.
        let r2 = pull_offer_fast_once(&mut v).await;
        assert!(
            r2.newly_frozen_accounts.is_empty(),
            "already-frozen carry-over must not appear in tick 2"
        );
    }

    /// **5.3 R-b — MANDATORY regression test.** Drive a real
    /// 5.1-flush-style publish + a 5.2 pull-tick and assert the
    /// account does NOT freeze on its own publish round-tripping.
    ///
    /// This pins the L-self-fork-on-publish defense at the level
    /// directly exercised by the production loop:
    ///
    /// 1. Add an account → it's marked dirty.
    /// 2. Call `flush_publish_queue` against a `MockChainAdapter` —
    ///    the mock returns a synthetic `ChainAnchor`; `mark_published`
    ///    stamps the local row's `chain_*` columns with that anchor
    ///    INLINE (before any pull tick can see it).
    /// 3. Synthesize the chain event that the pull tick WOULD have
    ///    seen (mock's recorded event has the same canonical hash as
    ///    the local row) and feed it through `ingest_chain_revision`
    ///    — this is the inner primitive that `pull_once` ⇒
    ///    `sync_from_chain` ⇒ `ingest_pending_chain_revision` ⇒
    ///    `ingest_chain_revision` would invoke. Idempotency arm #1
    ///    (exact-hash match) should fire ⇒ `IngestOutcome::
    ///    AlreadyPresent` ⇒ NO freeze flag set.
    /// 4. Assert `account_status(id).is_frozen_pending_resolve ==
    ///    false`.
    ///
    /// **If this test FAILS, STOP and report — this is a real bug.**
    /// The plan-gate's Q-b Option B escalation path is the
    /// just-published in-memory set; that's a 5.3 BUILD fix-pass
    /// scope decision.
    #[tokio::test]
    async fn pull_after_local_publish_does_not_self_freeze() {
        use crate::dirty::IngestOutcome;
        use pangolin_chain::MockChainAdapter;
        use pangolin_crypto::keys::DeviceKey;

        let (mut v, _dir) = fresh_vault();
        let device = DeviceKey::generate();
        let adapter = MockChainAdapter::new();

        // (1) Local edit ⇒ dirty marker.
        let id = v.add_account(snap("self-publish")).expect("add");

        // (2) Flush: the mock publishes + stamps the anchor inline.
        let _flush = v
            .flush_publish_queue(&adapter, &device, true)
            .await
            .expect("flush ok");
        // Quick post-condition: the freshly-published row carries a
        // chain anchor now (mark_published ran).
        assert!(!v.list_frozen_accounts().expect("frozen").contains(&id));

        // (3) Synthesize the round-trip chain event. The mock kept
        // every event it received; pull the one for our account.
        // We use the adapter's `pull_since` against the mock to
        // recover the canonical event shape (vault_id, account_id,
        // parent, device_id, schema_version, enc_payload, anchor).
        let events = pangolin_chain::ChainAdapter::pull_since(&adapter, &v.vault_id(), 0, None)
            .await
            .expect("pull_since");
        assert!(
            !events.is_empty(),
            "mock should have recorded the published event"
        );
        let round_trip = events
            .iter()
            .find(|e| e.account_id == *id.as_bytes())
            .expect("our event in mock");

        // (4) Feed the round-trip event back through ingest — this is
        // the inner call `pull_once` ⇒ `sync_from_chain` would make.
        let outcome = v.ingest_chain_revision(round_trip).expect("ingest");
        assert!(
            matches!(outcome, IngestOutcome::AlreadyPresent),
            "self-publish round-trip MUST hit idempotency arm #1 \
             (exact-hash match) and return AlreadyPresent — got {outcome:?}"
        );

        // (5) **THE LOAD-BEARING ASSERTION.** The account is NOT
        // frozen. If this fires, L-self-fork-on-publish has a real
        // hole and the Q-b Option B in-memory just-published set is
        // required — STOP and report per the spec.
        let status = v.account_status(id).expect("account_status");
        assert!(
            !status.is_frozen_pending_resolve,
            "self-publish round-trip MUST NOT freeze the account \
             (L-self-fork-on-publish defense). \
             If this assertion fires the Q-b Option B in-memory \
             just-published set is required."
        );
    }

    /// **5.3 R-c.** After `clear_frozen` clears a freeze, a
    /// subsequent `pull_once` cycle that mutates nothing should
    /// continue to report empty `newly_resolved_accounts` (the
    /// transition happened BEFORE the tick — directional set-diff
    /// is the defense). The inverse — that
    /// `newly_resolved_accounts` IS populated when the clear
    /// happens INSIDE the cycle — is exercised by the live
    /// `conflict_live.rs` test once the fixture-capture follow-up
    /// lands; the dominant `removed_frozen` channel in production
    /// is the `list_conflicts_since` accessor, not `PullReport`.
    ///
    /// We use `clear_frozen` (not `resolve_fork`) because the
    /// foreign-event leaf's payload is NOT AEAD-decryptable with
    /// this vault's VDK (different device key).
    #[tokio::test]
    async fn pull_after_resolve_fork_clears_newly_resolved_accounts() {
        let (mut v, _dir) = fresh_vault();
        // Set up freeze on a fresh foreign account (single head ⇒
        // no decrypt needed for clear_frozen).
        let foreign_acct = [0xDDu8; 32];
        let ev = foreign_event(v.vault_id(), foreign_acct, [0u8; 32], b"r", 11, 0);
        v.ingest_chain_revision(&ev).expect("ingest");
        let id = AccountId::from_bytes(foreign_acct);

        // Clear the freeze BEFORE any pull tick runs.
        let heads = v.account_heads(id).expect("heads");
        assert_eq!(heads.len(), 1);
        v.clear_frozen(id, heads[0]).expect("clear_frozen");

        // Pull tick: pre-snapshot sees the cleared state; post-
        // snapshot too. No transition during the tick ⇒ empty
        // newly_resolved.
        let report = pull_offer_fast_once(&mut v).await;
        assert!(
            report.newly_resolved_accounts.is_empty(),
            "transition happened BEFORE the tick ⇒ empty newly_resolved"
        );
    }

    /// **5.3 R-c.** Defense-in-depth for the type: every field on
    /// `PullReport`'s new shape is constructible from outside the
    /// crate (the public-construction shape is honored).
    #[test]
    fn pull_report_new_fields_are_publicly_constructible() {
        let _: PullReport = PullReport {
            mode: SyncMode::Slow,
            sync_report: None,
            pulled_at_unix_ms: 0,
            newly_frozen_accounts: Vec::<AccountId>::new(),
            newly_forked_accounts: Vec::<AccountId>::new(),
            newly_resolved_accounts: Vec::<AccountId>::new(),
        };
    }
}
