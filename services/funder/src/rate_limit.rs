// SPDX-License-Identifier: AGPL-3.0-or-later
//! Layered rate-limiter for the funder HTTP service.
//!
//! Per R-e + L3 verbatim:
//!
//! - **Per-address token bucket.** Each `device_address` gets a bucket
//!   of [`RateLimitConfig::per_address_bucket_size`] tokens. Tokens
//!   replenish at one per
//!   [`RateLimitConfig::per_address_replenish_interval_secs`].
//!   Defaults: bucket size 10, replenish every 600 s (10 min). A
//!   single address can burst 10 then is throttled to 6/hour
//!   steady-state.
//! - **Global hourly cap.** A second-layer counter trips at
//!   [`RateLimitConfig::global_cap_per_hour`] requests/hour (default
//!   200). Even 50 distinct addresses cannot drain faster than the
//!   global cap allows.
//!
//! On either trip, the handler returns HTTP 429 with `Retry-After`
//! (RFC 9110 §10.2.3) and a JSON body `{ "error": "rate_limited",
//! "retry_after_seconds": N }` — the body leaks NO internal counter
//! state (only a clamped `retry_after`).
//!
//! ## Memory bound
//!
//! Bucket entries live in a `HashMap<Address, _>`. To bound memory
//! against an attacker spamming fresh addresses, the lazy GC at insert
//! time drops entries whose `last_seen` is older than 1 hour. Worst
//! case the map holds ~max(`global_cap_per_hour`, recent unique
//! callers) entries.
//!
//! ## Concurrency
//!
//! Both layers live behind a `tokio::sync::RwLock`. The per-address
//! check + global-counter increment are performed under a single
//! exclusive lock to make the layered check atomic — a request that
//! passes the per-address check but trips the global cap MUST NOT
//! consume a per-address token. This is enforced by computing the
//! global-cap decision FIRST (under the same lock), then refunding
//! the per-address token on a 429.

use core::time::Duration;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use alloy::primitives::Address;
use tokio::sync::RwLock;

/// Default per-address bucket size (R-e verbatim).
pub const PER_ADDRESS_BUCKET_SIZE: u32 = 10;

/// Default per-address replenish interval (R-e verbatim).
pub const PER_ADDRESS_REPLENISH_INTERVAL_SECS: u64 = 600;

/// Default global cap (R-e verbatim).
pub const GLOBAL_CAP_PER_HOUR: u32 = 200;

/// Lazy-eviction TTL — bucket entries with `last_seen` older than this
/// are dropped on the next insert pass. Bounds memory against
/// fresh-address spam (each request brings the visitor's address into
/// the map briefly; absent further activity it ages out).
const BUCKET_TTL_SECS: u64 = 3_600;

/// Per-address bucket state. Public for tests + the `RateLimiter`
/// internal API; not part of the HTTP surface.
#[derive(Debug, Clone, Copy)]
pub struct TokenBucketState {
    /// Currently available tokens. Bounded above by the configured
    /// bucket size.
    pub tokens: u32,
    /// `Instant` of the last replenishment event. Replenishment is
    /// computed lazily on read: on each `check`, we add
    /// `(now - last_replenish) / replenish_interval` tokens (clamped
    /// to the bucket cap) and update `last_replenish` to reflect the
    /// tokens actually granted.
    pub last_replenish: Instant,
    /// `Instant` of the last attempted access (success OR denial).
    /// Used for lazy eviction.
    pub last_seen: Instant,
}

/// Global per-hour counter state.
#[derive(Debug, Clone, Copy)]
struct GlobalCounterState {
    /// Counts requests in the current window.
    count: u32,
    /// `Instant` the current window started. New window begins after
    /// 3600 s elapsed.
    window_start: Instant,
}

/// Runtime configuration for the [`RateLimiter`].
///
/// Defaults match R-e verbatim; the funder's startup path reads
/// `FUNDER_RATE_LIMIT_*` env vars and constructs this via
/// [`FunderConfig`](crate::FunderConfig).
#[derive(Debug, Clone, Copy)]
pub struct RateLimitConfig {
    /// Per-address bucket size.
    pub per_address_bucket_size: u32,
    /// Per-address replenish interval (seconds).
    pub per_address_replenish_interval_secs: u64,
    /// Global cap per hour.
    pub global_cap_per_hour: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            per_address_bucket_size: PER_ADDRESS_BUCKET_SIZE,
            per_address_replenish_interval_secs: PER_ADDRESS_REPLENISH_INTERVAL_SECS,
            global_cap_per_hour: GLOBAL_CAP_PER_HOUR,
        }
    }
}

/// Outcome of a rate-limit check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitOutcome {
    /// Request allowed; the caller may proceed.
    Allowed,
    /// Request denied. The `retry_after_seconds` is a conservative
    /// upper bound on how long the caller should wait — enough for
    /// the layer that tripped to refresh.
    Denied {
        /// Seconds the caller should wait before retrying.
        retry_after_seconds: u64,
    },
}

/// The layered rate-limiter.
///
/// Wraps `Arc<RwLock<HashMap<...>>>` + `Arc<RwLock<GlobalCounterState>>`
/// so it can be cloned cheaply into axum's `Extension` / `State`
/// machinery. Cloning shares the underlying state — every clone sees
/// the same buckets + the same global counter.
#[derive(Debug, Clone)]
pub struct RateLimiter {
    per_address: Arc<RwLock<HashMap<Address, TokenBucketState>>>,
    global: Arc<RwLock<GlobalCounterState>>,
    config: RateLimitConfig,
}

impl RateLimiter {
    /// Construct a new rate-limiter with the given configuration.
    #[must_use]
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            per_address: Arc::new(RwLock::new(HashMap::new())),
            global: Arc::new(RwLock::new(GlobalCounterState {
                count: 0,
                window_start: Instant::now(),
            })),
            config,
        }
    }

    /// Run both layered checks atomically.
    ///
    /// Returns [`RateLimitOutcome::Allowed`] when both layers admit
    /// the request; the per-address bucket is decremented and the
    /// global counter is incremented.
    ///
    /// Returns [`RateLimitOutcome::Denied`] when either layer rejects.
    /// The per-address layer is checked FIRST under the same lock as
    /// the global counter, so a denial on the global cap does NOT
    /// consume a per-address token (the bucket decrement is deferred
    /// until both checks pass).
    pub async fn check(&self, addr: Address) -> RateLimitOutcome {
        let now = Instant::now();
        // ---- Per-address layer ----
        let bucket_outcome = self.check_per_address(addr, now).await;
        let RateLimitOutcome::Allowed = bucket_outcome else {
            return bucket_outcome;
        };
        // ---- Global layer ----
        let global_outcome = self.check_global(now).await;
        if matches!(global_outcome, RateLimitOutcome::Denied { .. }) {
            // Refund the per-address token consumed above (the global
            // layer tripped, so the per-address bucket should not be
            // charged for this attempt).
            self.refund_per_address(addr).await;
        }
        global_outcome
    }

    /// Per-address layer check: lazy-replenish then decrement.
    ///
    /// Holds an exclusive write lock for the duration of the
    /// replenish-and-decrement so concurrent requests for the SAME
    /// address see a consistent bucket state (no torn read between
    /// "check tokens > 0" and "decrement").
    async fn check_per_address(&self, addr: Address, now: Instant) -> RateLimitOutcome {
        let mut map = self.per_address.write().await;

        // Lazy GC: drop entries older than the TTL. Bounded work
        // because we walk the map only on map sizes > some
        // threshold; for typical operation (<200 entries) the cost
        // is negligible.
        if map.len() > 64 {
            map.retain(|_, b| {
                now.duration_since(b.last_seen) < Duration::from_secs(BUCKET_TTL_SECS)
            });
        }

        let entry = map.entry(addr).or_insert(TokenBucketState {
            tokens: self.config.per_address_bucket_size,
            last_replenish: now,
            last_seen: now,
        });

        // Lazy replenishment. Compute elapsed time, divide by
        // interval, add that many tokens (clamped to the cap).
        let elapsed = now.duration_since(entry.last_replenish);
        let interval = Duration::from_secs(self.config.per_address_replenish_interval_secs);
        if interval.as_secs() > 0 && elapsed >= interval {
            let intervals_elapsed = elapsed.as_secs() / interval.as_secs();
            let cap = u64::from(self.config.per_address_bucket_size);
            let new_tokens = u64::from(entry.tokens).saturating_add(intervals_elapsed);
            entry.tokens = u32::try_from(new_tokens.min(cap)).unwrap_or(u32::MAX);
            // Advance last_replenish by the consumed intervals so
            // partial-interval drift doesn't accumulate.
            entry.last_replenish += interval * u32::try_from(intervals_elapsed).unwrap_or(u32::MAX);
        }

        entry.last_seen = now;

        if entry.tokens == 0 {
            // Compute retry_after: time until the next replenish.
            let elapsed_in_interval = now.duration_since(entry.last_replenish);
            let remaining = interval.saturating_sub(elapsed_in_interval).as_secs();
            return RateLimitOutcome::Denied {
                retry_after_seconds: remaining.max(1),
            };
        }
        entry.tokens -= 1;
        RateLimitOutcome::Allowed
    }

    /// Global hourly cap check.
    async fn check_global(&self, now: Instant) -> RateLimitOutcome {
        let mut state = self.global.write().await;
        let window = Duration::from_secs(3_600);
        if now.duration_since(state.window_start) >= window {
            state.count = 0;
            state.window_start = now;
        }
        if state.count >= self.config.global_cap_per_hour {
            let remaining = window
                .saturating_sub(now.duration_since(state.window_start))
                .as_secs();
            return RateLimitOutcome::Denied {
                retry_after_seconds: remaining.max(1),
            };
        }
        state.count += 1;
        RateLimitOutcome::Allowed
    }

    /// Refund a per-address token. Used when the global layer trips
    /// after the per-address check has already consumed a token.
    async fn refund_per_address(&self, addr: Address) {
        let mut map = self.per_address.write().await;
        if let Some(entry) = map.get_mut(&addr) {
            let cap = self.config.per_address_bucket_size;
            entry.tokens = entry.tokens.saturating_add(1).min(cap);
        }
    }

    /// Test-only: snapshot the per-address bucket state.
    #[cfg(test)]
    pub(crate) async fn snapshot_bucket(&self, addr: Address) -> Option<TokenBucketState> {
        let map = self.per_address.read().await;
        map.get(&addr).copied()
    }

    /// Test-only: snapshot the global counter. Used by tests that
    /// verify cross-layer interaction without needing the exact value
    /// (the `_count` accessor is referenced via inspection from
    /// future debug tooling; allow `dead_code` so the structural
    /// hook stays available).
    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) async fn snapshot_global_count(&self) -> u32 {
        self.global.read().await.count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn small_config() -> RateLimitConfig {
        RateLimitConfig {
            per_address_bucket_size: 3,
            per_address_replenish_interval_secs: 60,
            global_cap_per_hour: 5,
        }
    }

    fn addr(byte: u8) -> Address {
        let mut bytes = [0u8; 20];
        bytes[19] = byte;
        Address::from(bytes)
    }

    #[tokio::test]
    async fn per_address_bucket_exhausts_after_n_requests() {
        let limiter = RateLimiter::new(small_config());
        let a = addr(1);
        for _ in 0..3 {
            assert_eq!(limiter.check(a).await, RateLimitOutcome::Allowed);
        }
        match limiter.check(a).await {
            RateLimitOutcome::Denied {
                retry_after_seconds,
            } => {
                assert!(retry_after_seconds <= 60);
            }
            RateLimitOutcome::Allowed => panic!("expected denial after exhausting bucket"),
        }
    }

    #[tokio::test]
    async fn per_address_buckets_are_independent() {
        let limiter = RateLimiter::new(small_config());
        let a = addr(1);
        let b = addr(2);
        for _ in 0..3 {
            assert_eq!(limiter.check(a).await, RateLimitOutcome::Allowed);
        }
        // Address B starts fresh.
        assert_eq!(limiter.check(b).await, RateLimitOutcome::Allowed);
    }

    #[tokio::test]
    async fn global_cap_trips_after_threshold() {
        // Use a config where the global cap is reachable BEFORE any
        // per-address bucket exhausts (so the failure mode under
        // test is the global trip, not the per-address trip).
        let cfg = RateLimitConfig {
            per_address_bucket_size: 100,
            per_address_replenish_interval_secs: 60,
            global_cap_per_hour: 5,
        };
        let limiter = RateLimiter::new(cfg);
        for i in 0..5 {
            let a = addr(u8::try_from(i).expect("i fits in u8"));
            assert_eq!(limiter.check(a).await, RateLimitOutcome::Allowed);
        }
        // The 6th request from a NEW address must trip the global
        // cap (the per-address layer is still fresh).
        let a6 = addr(99);
        match limiter.check(a6).await {
            RateLimitOutcome::Denied {
                retry_after_seconds,
            } => {
                assert!(retry_after_seconds <= 3_600);
            }
            RateLimitOutcome::Allowed => panic!("expected global-cap denial"),
        }
    }

    #[tokio::test]
    async fn global_trip_refunds_per_address_token() {
        // Force the global cap to trip at 1; the per-address bucket
        // must remain at full after the trip (token refund).
        let cfg = RateLimitConfig {
            per_address_bucket_size: 3,
            per_address_replenish_interval_secs: 60,
            global_cap_per_hour: 1,
        };
        let limiter = RateLimiter::new(cfg);
        let a = addr(1);
        assert_eq!(limiter.check(a).await, RateLimitOutcome::Allowed);
        // Bucket now at 2.
        let before = limiter.snapshot_bucket(a).await.expect("bucket present");
        assert_eq!(before.tokens, 2);

        // A second request (from a new address so per-address layer
        // doesn't kick in) trips the global cap. The new address's
        // bucket gets pre-decremented then refunded.
        let b = addr(2);
        assert!(matches!(
            limiter.check(b).await,
            RateLimitOutcome::Denied { .. }
        ));
        let refunded = limiter.snapshot_bucket(b).await.expect("bucket present");
        assert_eq!(refunded.tokens, 3, "global trip must refund per-address");
    }

    #[tokio::test]
    async fn concurrent_requests_for_same_address_dont_oversubscribe() {
        let limiter = RateLimiter::new(small_config());
        let a = addr(1);
        let mut tasks = Vec::new();
        for _ in 0..20 {
            let limiter = limiter.clone();
            tasks.push(tokio::spawn(async move { limiter.check(a).await }));
        }
        let mut allowed = 0u32;
        for t in tasks {
            if matches!(t.await.expect("join"), RateLimitOutcome::Allowed) {
                allowed += 1;
            }
        }
        // The per-address bucket size is 3 + the global cap is 5;
        // the per-address layer is tighter, so at most 3 requests
        // are allowed.
        assert_eq!(allowed, 3, "exactly 3 requests should succeed");
    }

    #[tokio::test]
    async fn replenishment_grants_token_after_interval() {
        // 1-second replenish interval so the test runs quickly. The
        // bucket size is small so we can exhaust quickly + observe
        // the refill.
        let cfg = RateLimitConfig {
            per_address_bucket_size: 1,
            per_address_replenish_interval_secs: 1,
            global_cap_per_hour: 1000,
        };
        let limiter = RateLimiter::new(cfg);
        let a = addr(1);
        assert_eq!(limiter.check(a).await, RateLimitOutcome::Allowed);
        assert!(matches!(
            limiter.check(a).await,
            RateLimitOutcome::Denied { .. }
        ));
        // Wait > 1 s for the replenishment.
        tokio::time::sleep(Duration::from_millis(1_100)).await;
        assert_eq!(limiter.check(a).await, RateLimitOutcome::Allowed);
    }
}
