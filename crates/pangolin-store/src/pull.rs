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
}
