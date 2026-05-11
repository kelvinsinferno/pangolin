//! Session policy engine — the Unified Session Authority spec
//! implemented inside `pangolin-store`.
//!
//! Per the master plan §0 cardinal principle 5:
//!
//! > "Session invariant is universal. Start = 2 proofs. Maintain = 1
//! > proof. Expired = 2 proofs again. High-risk actions require explicit
//! > presence even mid-session."
//!
//! This module defines:
//!
//! - The four-state [`SessionState`] machine (`Locked`,
//!   `PendingAuthorization`, `Active`, `Expired`).
//! - The [`PresenceProof`] / [`IdentityProof`] traits — interchangeable
//!   abstractions that slot in real proofs (NFC, platform passkey,
//!   biometric) in MVP-1 without API churn.
//! - `PoC` stand-in proof types ([`PinIdentityProof`],
//!   [`PressYPresenceProof`]) suitable for tests + CLI flows. These are
//!   placeholders for the MVP-1 hardware-backed proofs and explicitly
//!   carry the security-relevant disciplines (single-use replay
//!   resistance, zero-on-drop secret bytes, redacted `Debug`).
//! - The [`Clock`] trait — testable time injection so the idle-timer +
//!   absolute-max behaviors can be unit-tested deterministically without
//!   actually waiting 4 hours.
//! - Timing constants per Session spec §7 (15-min idle, 4-hour absolute,
//!   60-s presence freshness, 60-s prompt timeout).
//! - The [`SessionDuration`] enum — the configurable idle-timeout
//!   choices from Session spec §7.2 (`5/15/30/60/240 min` or "until
//!   device lock") plus its `meta`-table serialisation. The choice is
//!   persisted in the vault `meta` row; vaults that predate MVP-1
//!   issue 1.4 have no row → [`IDLE_TIMEOUT_DEFAULT`] applies.
//!
//! # Security-critical invariants
//!
//! - `PressYPresenceProof::verify` is single-use to prevent the simplest
//!   replay (a stale `Confirmed` value getting reused). The single-use
//!   discipline is enforced via interior `Cell<bool>` so the API stays
//!   `&self`; the second verify call returns
//!   [`AuthError::PresenceAlreadyConsumed`].
//! - `PinIdentityProof` carries the password bytes and zeroizes on drop.
//!   `Debug` is redacted; `Clone`/`Copy`/`PartialEq` are not derived.
//! - The `Clock` trait is `Send + Sync`-safe but the `SystemClock`
//!   reads `SystemTime::now()` on each call — no caching, so a clock
//!   that goes backwards re-reports a smaller time. `PoC` accepts the
//!   wall-clock skew tradeoff per the failure-modes table in the plan;
//!   MVP-1 may switch to `Instant` (monotonic).
//! - Touch-extending the idle deadline NEVER pushes `expires_at` past
//!   `session_started_at + ABSOLUTE_MAX_DEFAULT`. Computed at the
//!   touch site so a clock manipulation cannot stretch it.

use core::cell::Cell;
use core::fmt;
use core::time::Duration;
use std::time::SystemTime;

use pangolin_crypto::secret::SecretBytes;
use zeroize::ZeroizeOnDrop;

// ---------------------------------------------------------------------
// Timing constants — Session spec §7.1
// ---------------------------------------------------------------------

/// Default idle timeout. After this many seconds without any credential
/// op, the active session expires and the cache is zeroized. Spec §7.1.
pub const IDLE_TIMEOUT_DEFAULT: Duration = Duration::from_secs(15 * 60);

/// Absolute upper bound on a single session's lifetime. Even with
/// constant activity the session cannot live longer than this without
/// re-issuing both proofs. Spec §7.1.
pub const ABSOLUTE_MAX_DEFAULT: Duration = Duration::from_secs(4 * 3600);

/// Maximum age of a presence proof at the moment of `verify()`.
///
/// Spec §7.1 says 30–60 s; we adopt the upper bound. For `PoC` presence
/// proofs this is the delta between proof construction and the moment
/// the vault inspects it.
pub const PRESENCE_FRESHNESS: Duration = Duration::from_secs(60);

/// Hard timeout on a UI-mediated prompt for re-auth. Spec §8.5 / §7.7.
///
/// The host UI runs the wall-clock timer; the storage layer's
/// contribution is (a) this constant so callers don't pick a different
/// value, and (b) a stale presence proof landing at a reveal site —
/// because the host UI prompted, the user took >60 s, the proof's
/// `created_at` is now stale — surfaces as [`crate::error::StoreError::PromptTimedOut`]
/// rather than the generic authentication-failure variant.
pub const PROMPT_TIMEOUT: Duration = Duration::from_secs(60);

// ---------------------------------------------------------------------
// SessionDuration — the configurable idle timeout (Session spec §7.2)
// ---------------------------------------------------------------------

/// Sentinel `meta.session_idle_secs` value meaning "until device lock".
///
/// No idle timeout at all; only the absolute-max ceiling
/// ([`ABSOLUTE_MAX_DEFAULT`]) bounds the session, and a real device-lock
/// signal ([`crate::vault::Vault::device_locked`]) expires it
/// immediately. CLI builds have no OS-lock signal so this behaves like
/// "until process exit". Stored as `-1` because all real idle durations
/// are positive seconds.
pub const SESSION_IDLE_UNTIL_DEVICE_LOCK: i64 = -1;

/// User-selectable session idle duration. Session spec §7.2:
///
/// > "Users MAY choose: 5 min; 15 min (default); 30 min; 1 hour;
/// > 4 hours; until device lock."
///
/// Persisted in the vault `meta` row via [`Self::to_meta_secs`]; read
/// back via [`Self::from_meta_secs`]. A `meta` row absent the column ⇒
/// [`Self::Min15`] (the spec default) for vaults that predate MVP-1
/// issue 1.4. An out-of-set on-disk value (e.g. a tampered or
/// corrupted-but-decryptable row) is treated as the default rather than
/// bricking the vault — see [`Self::from_meta_secs`].
///
/// Picking [`Self::Hour4`] makes the idle deadline equal the
/// absolute-max ceiling: the session simply cannot be extended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionDuration {
    /// 5 minutes.
    Min5,
    /// 15 minutes — the Session spec §7.1 default.
    Min15,
    /// 30 minutes.
    Min30,
    /// 1 hour.
    Hour1,
    /// 4 hours — equals the absolute-max ceiling.
    Hour4,
    /// No idle timeout; only the absolute-max ceiling applies. On a real
    /// device-lock signal the session expires immediately.
    UntilDeviceLock,
}

impl SessionDuration {
    /// The Session spec §7.1 default.
    pub const DEFAULT: Self = Self::Min15;

    /// Idle window this choice implies, or `None` for
    /// [`Self::UntilDeviceLock`] (no idle window — only the absolute-max
    /// ceiling). The returned duration is what
    /// [`next_idle_deadline`] uses as the idle leg.
    #[must_use]
    pub const fn idle_window(self) -> Option<Duration> {
        match self {
            Self::Min5 => Some(Duration::from_secs(5 * 60)),
            Self::Min15 => Some(Duration::from_secs(15 * 60)),
            Self::Min30 => Some(Duration::from_secs(30 * 60)),
            Self::Hour1 => Some(Duration::from_secs(60 * 60)),
            Self::Hour4 => Some(Duration::from_secs(4 * 3600)),
            Self::UntilDeviceLock => None,
        }
    }

    /// `true` if `self` is a strictly longer idle window than `other`.
    /// [`Self::UntilDeviceLock`] is treated as the longest (it is bounded
    /// only by the 4 h absolute ceiling, but for the
    /// "lengthening-needs-presence" rule it counts as longest because it
    /// removes the idle timer entirely). Used by
    /// [`crate::vault::Vault::set_session_idle`]: lengthening the session
    /// is high-risk per §5.4 and requires a fresh presence proof;
    /// shortening it is always allowed.
    #[must_use]
    pub fn is_longer_than(self, other: Self) -> bool {
        let rank = |d: Self| -> u8 {
            match d {
                Self::Min5 => 0,
                Self::Min15 => 1,
                Self::Min30 => 2,
                Self::Hour1 => 3,
                Self::Hour4 => 4,
                Self::UntilDeviceLock => 5,
            }
        };
        rank(self) > rank(other)
    }

    /// Encode for the `meta.session_idle_secs` column. Positive seconds
    /// for the finite choices; [`SESSION_IDLE_UNTIL_DEVICE_LOCK`] (`-1`)
    /// for [`Self::UntilDeviceLock`].
    #[must_use]
    pub fn to_meta_secs(self) -> i64 {
        // Every finite variant's seconds fits in i64 (max 14400);
        // `try_from` can't fail but is the lint-clean way to widen.
        self.idle_window()
            .map_or(SESSION_IDLE_UNTIL_DEVICE_LOCK, |d| {
                i64::try_from(d.as_secs()).unwrap_or(i64::MAX)
            })
    }

    /// Decode from the `meta.session_idle_secs` column. `None` (column
    /// absent — pre-1.4 vault) ⇒ [`Self::DEFAULT`]. An out-of-set value
    /// ⇒ [`Self::DEFAULT`] too: a corrupt-but-decryptable meta field
    /// must not brick an otherwise-openable vault. `-1` ⇒
    /// [`Self::UntilDeviceLock`].
    #[must_use]
    pub fn from_meta_secs(raw: Option<i64>) -> Self {
        match raw {
            Some(SESSION_IDLE_UNTIL_DEVICE_LOCK) => Self::UntilDeviceLock,
            Some(300) => Self::Min5,
            Some(900) => Self::Min15,
            Some(1800) => Self::Min30,
            Some(3600) => Self::Hour1,
            Some(14400) => Self::Hour4,
            // None (absent column) or any out-of-set value ⇒ default.
            None | Some(_) => Self::DEFAULT,
        }
    }

    /// Validate a caller-supplied "raw seconds" value at the public-API
    /// boundary (the §7 set or the `-1` sentinel only). Returns the
    /// matching variant or a typed [`crate::error::StoreError::Validation`]
    /// with `kind = "session_duration"`. Used by 1.6's §18.7
    /// reject/migrate policy hook — 1.4 only adds the slot.
    ///
    /// # Errors
    ///
    /// [`crate::error::StoreError::Validation`] for any value outside the
    /// §7.2 set.
    pub fn try_from_meta_secs(raw: i64) -> crate::error::Result<Self> {
        match Self::from_meta_secs(Some(raw)) {
            // `from_meta_secs` maps unknowns to DEFAULT; re-check the
            // round-trip so an out-of-set value surfaces as an error
            // here (rather than silently becoming the default, which is
            // the *read*-path behaviour, not the *write*-path one).
            d if d.to_meta_secs() == raw => Ok(d),
            _ => Err(crate::error::StoreError::Validation {
                kind: "session_duration".into(),
                message: format!(
                    "session idle duration {raw}s is not one of {{300, 900, 1800, 3600, 14400, -1}}"
                ),
            }),
        }
    }
}

// ---------------------------------------------------------------------
// AuthError
// ---------------------------------------------------------------------

/// Failure modes surfaced by [`PresenceProof::verify`] and
/// [`IdentityProof::verify`].
///
/// Variants are intentionally non-distinguishing where they could
/// become an oracle — `Failed` collapses every "wrong proof" cause so
/// a caller cannot branch on it. Structural failures (proof empty,
/// presence already consumed, expired) are distinct so the host UI can
/// render a useful message but they do not depend on the secret
/// content.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// Generic authentication failure. Wrong PIN, malformed proof
    /// payload, etc. Modeled on the same indistinguishability discipline
    /// as `StoreError::AuthenticationFailed`.
    #[error("authentication failed")]
    Failed,
    /// The presence proof was already consumed by a prior `verify()`
    /// call. The single-use discipline prevents the simplest replay
    /// vector for `PoC` `PressYPresenceProof`.
    #[error("presence proof already consumed (single-use)")]
    PresenceAlreadyConsumed,
    /// The proof was constructed too long ago. For `PoC` this fires only
    /// if a presence proof's stored timestamp is older than
    /// [`PRESENCE_FRESHNESS`].
    #[error("proof not fresh")]
    NotFresh,
    /// The identity proof's payload is empty/unusable.
    #[error("identity proof empty")]
    Empty,
}

// ---------------------------------------------------------------------
// PresenceProof / IdentityProof traits
// ---------------------------------------------------------------------

/// Trait implemented by every presence-class proof.
///
/// `PoC`: `PressYPresenceProof` (the user pressed `y` on a CLI prompt or a
/// test confirmed it). MVP-1: NFC tap, phone-as-presence-bridge,
/// platform-authenticator presence assertion.
///
/// Production NFC/passkey implementations carry a nonce + timestamp in
/// their payload; their `verify()` checks both. The `PoC` proof stores a
/// `created_at: SystemTime` and `verify` rejects when
/// `now - created_at > PRESENCE_FRESHNESS`.
pub trait PresenceProof: fmt::Debug {
    /// Verify the proof. `PoC` implementations consume an internal one-shot
    /// flag so a second call returns
    /// [`AuthError::PresenceAlreadyConsumed`].
    ///
    /// # Errors
    ///
    /// [`AuthError::Failed`] for a generic verification failure;
    /// [`AuthError::PresenceAlreadyConsumed`] for a replay attempt;
    /// [`AuthError::NotFresh`] when the proof's freshness window has
    /// elapsed.
    fn verify(&self) -> Result<(), AuthError>;

    /// How long this proof remains "fresh" once produced. `PoC` PIN/PressY
    /// returns [`PRESENCE_FRESHNESS`]; real NFC/passkey may vary.
    #[must_use]
    fn freshness(&self) -> Duration;
}

/// Trait implemented by every identity-class proof.
///
/// `PoC`: `PinIdentityProof` carries a password byte string. MVP-1: PIN +
/// platform passkey fronted by Secure Enclave / TPM. The trait has two
/// methods because for `PoC` the identity proof's secret IS the KDF input;
/// real passkey implementations would derive a secret separately.
pub trait IdentityProof: fmt::Debug {
    /// Verify the proof's structural integrity. For `PoC` `PinIdentityProof`
    /// this is `Ok(())` for any non-empty PIN — the actual "wrong PIN"
    /// rejection happens later via the KDF + AEAD unwrap chain inside
    /// the vault, by design. (See module-level note: a wrong PIN must
    /// run the full Argon2id derivation before AEAD failure to preserve
    /// MEDIUM-1 indistinguishability.)
    ///
    /// # Errors
    ///
    /// [`AuthError::Empty`] when the underlying PIN payload is zero
    /// bytes; [`AuthError::Failed`] for any other structural failure.
    fn verify(&self) -> Result<(), AuthError>;

    /// Extract the secret bytes used as the KDF input. The returned
    /// `SecretBytes` is freshly allocated; callers consume it once and
    /// drop. The original proof retains its own copy until the proof
    /// itself is dropped.
    ///
    /// # Errors
    ///
    /// [`AuthError::Empty`] if the proof contains no usable secret.
    fn derive_secret(&self) -> Result<SecretBytes, AuthError>;

    /// Mirrors [`PresenceProof::freshness`]. `PoC` `PinIdentityProof`
    /// returns a long window (effectively no expiry) because PINs are
    /// retyped at unlock-time; MVP-1 platform-authenticator assertions
    /// would carry a real timestamp + freshness.
    #[must_use]
    fn freshness(&self) -> Duration;
}

// ---------------------------------------------------------------------
// `PoC` stand-in: PressYPresenceProof
// ---------------------------------------------------------------------

/// `PoC` presence proof: "the user pressed y at a confirmation prompt".
///
/// Construction is the moment-of-confirmation. Stores a `SystemTime`
/// timestamp so `verify()` can reject stale proofs ("user pressed y an
/// hour ago, then the host code waited around"). Consumed via internal
/// `Cell<bool>` so the same proof value cannot be re-used.
///
/// # Replay resistance
///
/// The first call to `verify()` toggles `consumed` from `false` to
/// `true`. A second call returns [`AuthError::PresenceAlreadyConsumed`].
/// Test code that wants two proofs must construct two separate values
/// (`PressYPresenceProof::confirmed()` twice) — exactly mirroring the
/// production discipline where two distinct hardware taps are required.
#[derive(Debug)]
pub struct PressYPresenceProof {
    /// Wall-clock time at which the proof was constructed. The freshness
    /// check `now - created_at > PRESENCE_FRESHNESS` rejects stale
    /// proofs. Non-secret.
    created_at: SystemTime,
    /// One-shot flag. `false` until first `verify()` call, `true`
    /// afterwards. Cell over `bool` because `verify(&self)` is the
    /// natural API and `&mut self` would force callers to pass &mut in
    /// situations where the proof is borrowed by reference.
    consumed: Cell<bool>,
}

impl PressYPresenceProof {
    /// Construct a fresh confirmation. Sets `created_at` to
    /// `SystemTime::now()`. The proof is good for [`PRESENCE_FRESHNESS`]
    /// after construction.
    #[must_use]
    pub fn confirmed() -> Self {
        Self {
            created_at: SystemTime::now(),
            consumed: Cell::new(false),
        }
    }

    /// Test-only constructor that pins `created_at` to a caller-supplied
    /// value, used by the unit tests to drive the freshness window
    /// deterministically.
    ///
    /// # Visibility (P4 audit I-6 / M-1)
    ///
    /// Gated behind `cfg(any(test, feature = "test-utilities"))` so
    /// production builds cannot link against it. The previous
    /// `#[doc(hidden)]`-only gate let a downstream caller forge a
    /// presence proof with an arbitrary timestamp — the `cfg` gate
    /// fixes that. The `feature = "test-utilities"` clause is
    /// forward-compat for future external integration testing; the
    /// feature is not declared in `Cargo.toml` yet because all
    /// in-process tests live inside this crate and `cfg(test)` alone
    /// suffices.
    #[cfg(any(test, feature = "test-utilities"))]
    #[doc(hidden)]
    #[must_use]
    pub fn __test_with_timestamp(created_at: SystemTime) -> Self {
        Self {
            created_at,
            consumed: Cell::new(false),
        }
    }
}

impl PresenceProof for PressYPresenceProof {
    fn verify(&self) -> Result<(), AuthError> {
        if self.consumed.get() {
            return Err(AuthError::PresenceAlreadyConsumed);
        }
        let now = SystemTime::now();
        let age = now
            .duration_since(self.created_at)
            .unwrap_or(Duration::ZERO);
        if age > PRESENCE_FRESHNESS {
            return Err(AuthError::NotFresh);
        }
        // Mark consumed only after all structural checks pass so a
        // failed-freshness verify doesn't burn the proof.
        self.consumed.set(true);
        Ok(())
    }

    fn freshness(&self) -> Duration {
        PRESENCE_FRESHNESS
    }
}

// ---------------------------------------------------------------------
// `PoC` stand-in: PinIdentityProof
// ---------------------------------------------------------------------

/// `PoC` identity proof: a password / PIN payload.
///
/// Owns a [`SecretBytes`] carrying the PIN (or password — the type
/// label "PIN" is the spec-aligned name; in `PoC` it's literally the
/// vault password). `verify()` does structural validation only —
/// non-empty — because the actual wrong-PIN rejection runs through the
/// KDF + AEAD unwrap chain at unlock time. This split is intentional:
/// any "is this PIN right?" verification done before kdf+AEAD would
/// open a side-channel oracle (a fast structural reject for "wrong
/// PIN" vs. a 1.5s Argon2id run for "right PIN") — see MEDIUM-1 in the
/// P2 audit.
///
/// `derive_secret` returns a fresh `SecretBytes` cloned from the
/// internal payload. The original is retained and zeroized on drop.
pub struct PinIdentityProof {
    /// PIN/password bytes. `ZeroizeOnDrop` via `SecretBytes`.
    pin: SecretBytes,
}

impl PinIdentityProof {
    /// Wrap a PIN payload.
    #[must_use]
    pub fn new(pin: SecretBytes) -> Self {
        Self { pin }
    }
}

impl IdentityProof for PinIdentityProof {
    fn verify(&self) -> Result<(), AuthError> {
        if self.pin.is_empty() {
            return Err(AuthError::Empty);
        }
        Ok(())
    }

    fn derive_secret(&self) -> Result<SecretBytes, AuthError> {
        if self.pin.is_empty() {
            return Err(AuthError::Empty);
        }
        // L-1 (P4 audit): clone the bytes into a fresh `SecretBytes`.
        // Both copies zeroize on drop (the original on `self` drop, the
        // returned one on the caller's drop). The bytes briefly exist
        // twice in memory; this is acceptable because the original is
        // the authoritative copy and is lifetime-bounded by the
        // caller's `&dyn IdentityProof` borrow. Avoiding the clone
        // would require either (a) consuming `self` in `derive_secret`
        // (which forces the proof's life to end at the unlock site,
        // breaking the trait's `&self` shape) or (b) handing out an
        // internal-`SecretBytes` reference (which leaks lifetime
        // through the trait object). Both are worse than the brief
        // double-allocation. PoC accepts the cost; documented for
        // audit traceability.
        Ok(SecretBytes::new(self.pin.expose().to_vec()))
    }

    fn freshness(&self) -> Duration {
        // PoC: identity proofs (PIN typed at unlock) are effectively
        // instantaneous from the user's perspective. Set to the
        // absolute-max bound so they're never rejected for staleness in
        // PoC. MVP-1 will tighten this for platform-authenticator
        // assertions.
        ABSOLUTE_MAX_DEFAULT
    }
}

impl fmt::Debug for PinIdentityProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PinIdentityProof")
            .field("pin", &"<redacted>")
            .field("len", &self.pin.len())
            .finish()
    }
}

// `PinIdentityProof`'s only field is a `SecretBytes` (which is
// `ZeroizeOnDrop`), so the marker propagates automatically. The marker
// impl makes the discipline self-documenting and lets test code
// `assert_impl_all!(PinIdentityProof: ZeroizeOnDrop)` if desired.
impl ZeroizeOnDrop for PinIdentityProof {}

// We intentionally do NOT derive Clone/Copy/PartialEq on PinIdentityProof
// — the secret-bearing types in this codebase deliberately reject those
// derivations to prevent accidental duplication or non-constant-time
// equality.

// ---------------------------------------------------------------------
// Clock — testable time injection
// ---------------------------------------------------------------------

/// Time source. Production uses [`SystemClock`]; tests use
/// [`TestClock`] to drive the idle-timer + absolute-max behavior
/// deterministically.
///
/// Implementations must be `'static` so the vault can hold a `Box<dyn
/// Clock>` without lifetime gymnastics. The trait is `Send` so a vault
/// owning a clock can be sent across threads (each individual `Vault`
/// is non-Sync by design — `&mut self` on every credential op).
pub trait Clock: Send + 'static {
    /// Wall-clock now. `PoC` reads `SystemTime::now()`; tests return a
    /// caller-controlled value.
    fn now(&self) -> SystemTime;
}

/// Production clock: reads `SystemTime::now()` on every call.
#[derive(Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

/// Test clock with caller-set time. Use [`TestClock::advance`] to walk
/// the clock forward without sleeping the test thread.
///
/// # Visibility
///
/// Gated behind `cfg(any(test, feature = "test-utilities"))` so
/// production builds cannot link against it (a vault driven by a
/// caller-controlled clock would be a security hazard). The
/// `test-utilities` feature is what the `pangolin-store` e2e suite
/// builds with; in-crate unit tests reach it via `cfg(test)`.
#[cfg(any(test, feature = "test-utilities"))]
#[derive(Debug)]
pub struct TestClock {
    inner: std::sync::Mutex<SystemTime>,
}

#[cfg(any(test, feature = "test-utilities"))]
impl TestClock {
    /// Construct with `now` as the initial reading.
    #[must_use]
    pub fn new(now: SystemTime) -> Self {
        Self {
            inner: std::sync::Mutex::new(now),
        }
    }

    /// Advance the clock by `delta`.
    pub fn advance(&self, delta: Duration) {
        let mut guard = self.inner.lock().unwrap();
        *guard += delta;
    }
}

#[cfg(any(test, feature = "test-utilities"))]
impl Clock for TestClock {
    fn now(&self) -> SystemTime {
        *self.inner.lock().unwrap()
    }
}

// ---------------------------------------------------------------------
// SessionState — the four-state machine
// ---------------------------------------------------------------------

/// The full session-policy state machine. Per spec §4.
///
/// State transitions:
///
/// ```text
///   Locked ──unlock(presence,identity)──▶ Active
///   Active ──idle > IDLE_TIMEOUT──▶ Expired (cache zeroized)
///   Active ──now > session_started + ABSOLUTE_MAX──▶ Expired
///   Active ──lock()──▶ Locked
///   Expired ──unlock(presence,identity)──▶ Active
/// ```
///
/// `PendingAuthorization` is a reserved variant for the host UI's
/// mid-action prompt state (one proof received, waiting for the other,
/// or a high-risk action awaiting an explicit presence proof). The
/// vault itself treats it as "not Active" (operations error
/// `SessionPending`) — host UIs drive the actual proof gathering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Vault is locked. No plaintext in memory. Next op needs the full
    /// 2-proof unlock.
    Locked,
    /// Awaiting one or both proofs. Cache is zeroized; this is a UX
    /// state, not a security state. The vault enters this when a
    /// caller wraps a re-auth flow around an op (`with_session`) and
    /// the original session has expired mid-action.
    PendingAuthorization,
    /// Both proofs satisfied; cache live; expires at `expires_at`.
    /// `last_proof_at` is the instant of the most recent activity-touch;
    /// `session_started_at` is the instant of the originating unlock —
    /// touch never extends `expires_at` past
    /// `session_started_at + ABSOLUTE_MAX_DEFAULT`.
    Active {
        /// Hard deadline. After this `SystemTime`, the next credential
        /// op fails `SessionExpired` and the cache is dropped.
        expires_at: SystemTime,
        /// Wall-clock instant of the most recent successful op (or the
        /// unlock instant if no op has run yet).
        last_proof_at: SystemTime,
        /// Wall-clock instant of the unlock that started this session.
        /// The absolute-max ceiling is computed from this value, not
        /// from `last_proof_at`.
        session_started_at: SystemTime,
    },
    /// Was Active; idle timer fired or absolute max hit. Cache zeroized
    /// at the moment of expiry. Next op needs full 2-proof unlock. The
    /// vault transitions through this state briefly before settling
    /// into `Locked` — `check_session_freshness` returns
    /// `SessionExpired` and locks atomically.
    Expired,
}

impl SessionState {
    /// `true` when the session permits credential ops.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self, Self::Active { .. })
    }
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

/// Compute the next `expires_at` after a touch, given the session's
/// configured idle window (`idle`).
///
/// Caps at `session_started_at + ABSOLUTE_MAX_DEFAULT`. This helper is
/// the single source of truth for the absolute-max ceiling — every code
/// path that extends a deadline routes through it. For
/// [`SessionDuration::UntilDeviceLock`] the result is purely the
/// absolute-max ceiling (no idle leg).
///
/// # P4 audit L-2: overflow-safe saturating arithmetic
///
/// Both addends are computed with `SystemTime::checked_add`; if either
/// overflows (which can only happen if `now` or `session_started_at`
/// is pathologically close to `SystemTime`'s representable range —
/// roughly the year 262,000 AD on most platforms, but a malicious or
/// buggy clock could synthesize one), we fall back to the
/// pre-addition `SystemTime` value. That fallback is intentionally
/// **not** session-extending: a saturated `idle_deadline` of `now`
/// produces immediate expiry on the next `check_session_freshness`
/// call, and a saturated `abs_max_deadline` of `session_started_at`
/// is in the past, so the `min` between the two still gives a
/// past-or-equal-to-now deadline. The fail-safe is "expire now"
/// rather than "extend forever".
#[must_use]
pub(crate) fn next_idle_deadline(
    now: SystemTime,
    session_started_at: SystemTime,
    idle: SessionDuration,
) -> SystemTime {
    // The absolute ceiling always applies. A saturated value here is
    // <= `now` (in the year-262k overflow case), so the `min` below
    // still produces a fail-safe deadline.
    let abs_max_deadline = session_started_at
        .checked_add(ABSOLUTE_MAX_DEFAULT)
        .unwrap_or(session_started_at);
    // Finite idle window ⇒ deadline = min(now + idle, abs ceiling), with
    // a saturating fallback on `now` (a year-262k overflow falls back to
    // `now` itself — the next freshness check expires; never silently
    // extend beyond representable time). "Until device lock" ⇒ no idle
    // leg; the deadline is purely the absolute-max ceiling (a device-lock
    // signal expires it out-of-band, `Vault::device_locked`).
    idle.idle_window().map_or(abs_max_deadline, |window| {
        now.checked_add(window).unwrap_or(now).min(abs_max_deadline)
    })
}

#[cfg(test)]
mod tests {
    use super::{
        next_idle_deadline, AuthError, Clock, IdentityProof, PinIdentityProof, PresenceProof,
        PressYPresenceProof, SessionDuration, SessionState, SystemClock, TestClock,
        ABSOLUTE_MAX_DEFAULT, IDLE_TIMEOUT_DEFAULT, PRESENCE_FRESHNESS,
        SESSION_IDLE_UNTIL_DEVICE_LOCK,
    };
    use core::time::Duration;
    use pangolin_crypto::secret::SecretBytes;
    use std::time::SystemTime;
    use zeroize::ZeroizeOnDrop;

    // -----------------------------------------------------------------
    // Constant sanity (locks the spec values)
    // -----------------------------------------------------------------

    #[test]
    fn timing_constants_match_spec() {
        assert_eq!(IDLE_TIMEOUT_DEFAULT, Duration::from_secs(15 * 60));
        assert_eq!(ABSOLUTE_MAX_DEFAULT, Duration::from_secs(4 * 3600));
        assert_eq!(PRESENCE_FRESHNESS, Duration::from_secs(60));
    }

    // -----------------------------------------------------------------
    // PressYPresenceProof
    // -----------------------------------------------------------------

    #[test]
    fn press_y_proof_verifies_once() {
        let p = PressYPresenceProof::confirmed();
        assert!(p.verify().is_ok());
        // Second verify must reject — single-use replay resistance.
        assert!(matches!(
            p.verify(),
            Err(AuthError::PresenceAlreadyConsumed)
        ));
    }

    #[test]
    fn press_y_proof_rejects_stale() {
        // Pin construction time to two minutes ago — past the 60s window.
        let stale = SystemTime::now() - Duration::from_secs(120);
        let p = PressYPresenceProof::__test_with_timestamp(stale);
        assert!(matches!(p.verify(), Err(AuthError::NotFresh)));
    }

    #[test]
    fn press_y_proof_failed_freshness_does_not_burn_proof() {
        let stale = SystemTime::now() - Duration::from_secs(120);
        let p = PressYPresenceProof::__test_with_timestamp(stale);
        // First call: NotFresh.
        assert!(matches!(p.verify(), Err(AuthError::NotFresh)));
        // Second call: STILL NotFresh, NOT PresenceAlreadyConsumed.
        // The single-use flag must only flip on a successful verify.
        assert!(matches!(p.verify(), Err(AuthError::NotFresh)));
    }

    // -----------------------------------------------------------------
    // PinIdentityProof
    // -----------------------------------------------------------------

    #[test]
    fn pin_proof_verifies_non_empty() {
        let p = PinIdentityProof::new(SecretBytes::new(b"correct horse".to_vec()));
        assert!(p.verify().is_ok());
        let secret = p.derive_secret().unwrap();
        assert_eq!(secret.expose(), b"correct horse");
    }

    #[test]
    fn pin_proof_rejects_empty() {
        let p = PinIdentityProof::new(SecretBytes::new(Vec::new()));
        assert!(matches!(p.verify(), Err(AuthError::Empty)));
        assert!(matches!(p.derive_secret(), Err(AuthError::Empty)));
    }

    #[test]
    fn pin_proof_debug_redacts() {
        let p = PinIdentityProof::new(SecretBytes::new(b"hunter2".to_vec()));
        let printed = format!("{p:?}");
        assert!(printed.contains("<redacted>"));
        assert!(!printed.contains("hunter2"));
    }

    /// The marker trait propagates through the field; this test exists
    /// so that a future refactor that accidentally removes
    /// `ZeroizeOnDrop` from the `pin` field type fails at compile time.
    const _: fn() = || {
        fn assert_zeroize<T: ZeroizeOnDrop>() {}
        assert_zeroize::<PinIdentityProof>();
    };

    // -----------------------------------------------------------------
    // SessionState
    // -----------------------------------------------------------------

    #[test]
    fn session_state_is_active_predicate() {
        assert!(!SessionState::Locked.is_active());
        assert!(!SessionState::PendingAuthorization.is_active());
        assert!(!SessionState::Expired.is_active());
        let now = SystemTime::now();
        assert!(SessionState::Active {
            expires_at: now + Duration::from_secs(60),
            last_proof_at: now,
            session_started_at: now,
        }
        .is_active());
    }

    // -----------------------------------------------------------------
    // next_idle_deadline — the absolute-max ceiling
    // -----------------------------------------------------------------

    #[test]
    fn touch_caps_at_absolute_max() {
        let started = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let idle = SessionDuration::DEFAULT;
        // Right at the start: deadline is now+IDLE.
        let deadline = next_idle_deadline(started, started, idle);
        assert_eq!(deadline, started + IDLE_TIMEOUT_DEFAULT);

        // 3 hours 50 min in: still under the 4-hour ceiling, deadline
        // would be 3h50m + 15m = 4h05m, but ceiling caps it at 4h.
        let almost_out = started + Duration::from_secs(3 * 3600 + 50 * 60);
        let deadline = next_idle_deadline(almost_out, started, idle);
        assert_eq!(deadline, started + ABSOLUTE_MAX_DEFAULT);

        // Right at the start + 14m: 14+15 = 29m < 4h, so no cap.
        let mid = started + Duration::from_secs(14 * 60);
        let deadline = next_idle_deadline(mid, started, idle);
        assert_eq!(deadline, mid + IDLE_TIMEOUT_DEFAULT);

        // A 30-min configured idle: deadline = now + 30m (under cap).
        let d30 = next_idle_deadline(started, started, SessionDuration::Min30);
        assert_eq!(d30, started + Duration::from_secs(30 * 60));

        // "Until device lock": the deadline is purely the absolute-max
        // ceiling regardless of how far into the session we are.
        let udl = SessionDuration::UntilDeviceLock;
        assert_eq!(
            next_idle_deadline(started, started, udl),
            started + ABSOLUTE_MAX_DEFAULT
        );
        assert_eq!(
            next_idle_deadline(started + Duration::from_secs(3600), started, udl),
            started + ABSOLUTE_MAX_DEFAULT
        );
    }

    // -----------------------------------------------------------------
    // SessionDuration — configurable idle (Session spec §7.2)
    // -----------------------------------------------------------------

    #[test]
    fn session_duration_meta_round_trip() {
        for d in [
            SessionDuration::Min5,
            SessionDuration::Min15,
            SessionDuration::Min30,
            SessionDuration::Hour1,
            SessionDuration::Hour4,
            SessionDuration::UntilDeviceLock,
        ] {
            assert_eq!(SessionDuration::from_meta_secs(Some(d.to_meta_secs())), d);
        }
        // Absent column ⇒ default (pre-1.4 vault).
        assert_eq!(
            SessionDuration::from_meta_secs(None),
            SessionDuration::Min15
        );
        // Out-of-set value ⇒ default (corrupt-but-decryptable, don't brick).
        assert_eq!(
            SessionDuration::from_meta_secs(Some(99_999)),
            SessionDuration::Min15
        );
        assert_eq!(SessionDuration::UntilDeviceLock.to_meta_secs(), -1);
        assert_eq!(SESSION_IDLE_UNTIL_DEVICE_LOCK, -1);
    }

    #[test]
    fn session_duration_try_from_meta_secs_rejects_out_of_set() {
        assert!(SessionDuration::try_from_meta_secs(900).is_ok());
        assert!(SessionDuration::try_from_meta_secs(-1).is_ok());
        let err = SessionDuration::try_from_meta_secs(42).unwrap_err();
        match err {
            crate::error::StoreError::Validation { kind, .. } => {
                assert_eq!(kind, "session_duration");
            }
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn session_duration_ordering_for_lengthening_rule() {
        assert!(SessionDuration::Hour4.is_longer_than(SessionDuration::Min5));
        assert!(SessionDuration::UntilDeviceLock.is_longer_than(SessionDuration::Hour4));
        assert!(!SessionDuration::Min5.is_longer_than(SessionDuration::Min15));
        assert!(!SessionDuration::Min15.is_longer_than(SessionDuration::Min15));
    }

    /// P4 audit L-2: a `now` close to `SystemTime`'s representable
    /// upper bound must NOT panic; instead the function returns a
    /// saturating fallback (`now` itself, which produces immediate
    /// expiry on the next freshness check). This protects the vault
    /// from a malicious or buggy clock that hands out `SystemTime`
    /// values near the upper representable range.
    ///
    /// The platform's representable upper bound is implementation-
    /// defined (Windows uses `i64`-encoded NT epoch for `SystemTime`;
    /// Unix uses `i64` seconds + nanos), so this test does a binary
    /// search for the largest representable `SystemTime` and uses
    /// that as `now`. The expected behavior is that
    /// `next_idle_deadline(near_max, near_max, SessionDuration::DEFAULT)` returns
    /// `<= near_max` (i.e., past-or-equal-to-now), proving the
    /// saturating fallback engaged.
    #[test]
    fn next_idle_deadline_saturates_on_overflow() {
        // Binary search for the largest `Duration` we can add to
        // `UNIX_EPOCH` without overflow. Bounds: [0, u64::MAX].
        // Cap the additive search at `u64::MAX / 2` seconds so the
        // `Duration::from_secs` call itself cannot overflow.
        let mut lo: u64 = 0;
        let mut hi: u64 = u64::MAX / 2;
        // Find a `hi` whose addition fails. If even `u64::MAX/2` does
        // not overflow on this platform, we cannot test saturation
        // (the platform's `SystemTime` range exceeds the
        // u64-second domain). Skip in that case.
        if SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_secs(hi))
            .is_some()
        {
            // Platform's representable range is unreachable in
            // u64-second arithmetic; the saturation guard is still
            // present in the function but unprovable from this test.
            // A normal-value sanity check is the most we can do.
            let normal = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
            let _ = next_idle_deadline(normal, normal, SessionDuration::DEFAULT);
            return;
        }
        // Binary search until lo+1 == hi: the boundary between
        // representable (lo) and non-representable (hi).
        while hi - lo > 1 {
            let mid = lo + (hi - lo) / 2;
            if SystemTime::UNIX_EPOCH
                .checked_add(Duration::from_secs(mid))
                .is_some()
            {
                lo = mid;
            } else {
                hi = mid;
            }
        }
        // `lo` is the largest representable second-offset; `lo + 1`
        // overflows. Pick `near_max = UNIX_EPOCH + lo` and confirm
        // adding even a 1-second duration overflows.
        let near_max = SystemTime::UNIX_EPOCH + Duration::from_secs(lo);
        assert!(
            near_max.checked_add(Duration::from_secs(1)).is_none(),
            "binary search did not converge to overflow boundary",
        );
        // The saturation guard must engage and produce <= near_max.
        let deadline = next_idle_deadline(near_max, near_max, SessionDuration::DEFAULT);
        assert!(
            deadline <= near_max,
            "saturating fallback must not extend past `now` on overflow",
        );
    }

    // -----------------------------------------------------------------
    // Clock impls
    // -----------------------------------------------------------------

    #[test]
    fn system_clock_returns_real_time() {
        let c = SystemClock;
        let a = c.now();
        let b = c.now();
        // Clock must be monotonic-or-equal across two reads.
        assert!(b >= a);
    }

    #[test]
    fn test_clock_advances_deterministically() {
        let start = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let c = TestClock::new(start);
        assert_eq!(c.now(), start);
        c.advance(Duration::from_secs(60));
        assert_eq!(c.now(), start + Duration::from_secs(60));
    }
}
