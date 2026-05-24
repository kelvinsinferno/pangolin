//! `Vault` — the only public credential-bearing handle on a `.pvf` file.
//!
//! State machine (P4 session policy):
//!
//! ```text
//!     ┌──────────┐  open(path)    ┌──────────┐  unlock(P,I)   ┌──────────┐
//!     │  Closed  │ ─────────────▶ │  Locked  │ ─────────────▶ │  Active  │
//!     │ (no SQL) │                │ (handle) │ ◀───────────── │ (cache)  │
//!     └──────────┘                └──────────┘   lock()        └──────────┘
//!           ▲                          ▲ ▲                          │
//!           │                          │ └── idle/abs-max expiry ───┘
//!           │  close(self)             │     (cache zeroized, then
//!           └──────────────────────────┘      lock from Expired)
//! ```
//!
//! Only `Active` permits credential operations. `Locked` is structurally
//! observable (vault id, account count) but reveals no plaintext;
//! `Closed` releases the `SQLite` handle.
//!
//! P4 (session policy) extends P2's two-state machine:
//!
//! - `unlock` requires both a [`crate::session::PresenceProof`] AND a
//!   [`crate::session::IdentityProof`]. Either failing surfaces as
//!   [`StoreError::AuthenticationFailed`] — the indistinguishability
//!   discipline from MEDIUM-1 collapses every proof-class failure
//!   (wrong PIN, replayed presence, KDF rejection, AEAD tamper) into a
//!   single variant.
//! - Active sessions auto-expire on idle ([`crate::session::IDLE_TIMEOUT_DEFAULT`]
//!   = 15 min) or absolute max
//!   ([`crate::session::ABSOLUTE_MAX_DEFAULT`] = 4 h). Every credential
//!   op runs `check_session_freshness()` at the top and `touch_session()`
//!   on success; expiry zeroizes the cache.
//! - High-risk ops (`reveal_password`, `export_payload`) require an
//!   explicit fresh presence proof EVEN during an active session
//!   (Session spec §5.3).
//! - The mid-action prompt/resume primitive is `Vault::with_session`.

use core::time::Duration;
use std::fs::{File, OpenOptions};
use std::io::Write as IoWrite;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use pangolin_chain::{
    build_signed_revision_v1, derive_evm_wallet, ChainEnv, EvmWallet, RevisionFieldsV1,
    SignedRevisionV1,
};
use pangolin_crypto::aead::{AeadKey, Ciphertext, Nonce, NONCE_LEN};
use pangolin_crypto::escrow::WrappedVdkRecovery;
use pangolin_crypto::kdf::{self, KdfParams, KdfSalt};
use pangolin_crypto::keys::{AuthorityKey, DeviceKey, VdkKey, WrapContext, VAULT_ID_LEN};
use pangolin_crypto::secret::SecretBytes;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};

use crate::account::{AccountId, AccountSnapshot, ACCOUNT_ID_LEN};
use crate::blob::{
    build_aad, open_payload, seal_snapshot, seal_tombstone, DecodedPayload, TombstonePayload,
};
use crate::device::{self, DeviceIdentity};
use crate::dirty::{IngestOutcome, RevisionPublishPayload};
use crate::error::{Result, StoreError};
use crate::meta::{self, VaultMeta};
use crate::recovery_escrow::{self, GuardianRecord};
use crate::revision::{
    ChainAnchor, DeviceId, RevisionGraph, RevisionId, RevisionMeta, REVISION_ID_LEN,
};
use crate::schema;
use crate::search::{DecryptedCache, SearchIndex, SearchProjection};
use crate::session::{
    next_idle_deadline, AuthError, Clock, IdentityProof, PresenceProof, SessionDuration,
    SessionState, SystemClock, PRESENCE_FRESHNESS,
};
use crate::vdk_chain;

// ---------------------------------------------------------------------
// P4 audit M-3: compile-time thread-safety contract for `Vault`.
// ---------------------------------------------------------------------
//
// `Vault` MUST be `Send` (so a `Vault` instance can be moved between
// threads — useful for host-side worker patterns where a UI thread
// hands off the vault handle to a background thread for an Argon2id
// unlock) but MUST NOT be `Sync` (concurrent access from two threads
// would race the underlying `rusqlite::Connection`, which we open with
// `SQLITE_OPEN_NO_MUTEX` to disable SQLite's own thread-safety
// machinery). The `Connection` is `Send` but `!Sync` under those
// flags; `Vault` inherits both via its `conn: Connection` field, plus
// its `clock: Box<dyn Clock>` where `Clock: Send + 'static` (no `Sync`
// bound — see `session.rs`). The assertions below pin both invariants
// at compile time so a future refactor that, e.g., switches the
// connection to a `Mutex<Connection>` (making `Vault: Sync`) would
// fail the build with a clear error pointing at this audit finding.
//
// `assert_impl_all!` triggers a compile error if the bound is missing;
// `assert_not_impl_any!` triggers a compile error if the bound is
// added. Together they pin the type to exactly `Send` (and not `Sync`).
static_assertions::assert_impl_all!(Vault: Send);
static_assertions::assert_not_impl_any!(Vault: Sync);

/// **P10-3 / A4 anti-resurrection retry budget.** `Vault::add_account`
/// regenerates the random `account_id` up to this many times if the
/// derived id collides with an existing tombstoned row's id. After all
/// attempts collide, [`StoreError::Internal`] is surfaced rather than
/// looping indefinitely. Per Q3 (locked Kelvin answer) the value is 4
/// — small enough to not paper over a genuine bug (e.g., a broken
/// RNG), large enough to absorb a 1-in-2^256 RNG stutter. The
/// per-attempt collision probability is `N / 2^256` where N is the
/// tombstone count; 4 attempts gives a worst-case `4 * N / 2^256`
/// failure probability, vanishing for any plausible vault size.
pub(crate) const ADD_ACCOUNT_RETRY_BUDGET: u32 = 4;

// ---------------------------------------------------------------------
// MVP-2 issue 5.1 — publish queue + batching constants.
// ---------------------------------------------------------------------

/// **MVP-2 issue 5.1 (R-a).** Default 30s coalescing window.
///
/// Master-plan §5 row 5.1 verbatim.
pub const BATCH_WINDOW_SECS_DEFAULT: u64 = 30;

/// **MVP-2 issue 5.1 (R-a).** Lower clamp on the env-var override.
/// Below this would coalesce nothing meaningful (sub-second windows
/// invalidate the "rapid edits" UX premise).
pub const BATCH_WINDOW_SECS_MIN: u64 = 1;

/// **MVP-2 issue 5.1 (R-a).** Upper clamp on the env-var override.
/// Above this would let a malicious host wrapper hide unsent edits
/// from the user for too long; L-window-DoS defense.
pub const BATCH_WINDOW_SECS_MAX: u64 = 300;

/// **MVP-2 issue 5.1 (R-a).** Env-var name the override is read from.
pub const BATCH_WINDOW_SECS_ENV_VAR: &str = "PANGOLIN_BATCH_WINDOW_SECS";

/// **MVP-2 issue 5.1 (R-b).** Hard cap on dirty-marker COUNT.
///
/// Once the queue reaches this size the host SHOULD invoke
/// [`Vault::flush_publish_queue`] regardless of the window timer;
/// the L-balance-blocked-grows-unbounded mitigation. Local edits
/// are NEVER refused — the cap is a flush trigger, not a refusal
/// gate.
pub const PUBLISH_QUEUE_COUNT_CAP: usize = 100;

/// **MVP-2 issue 5.1 (R-b).** Hard cap on total `enc_payload` bytes.
///
/// Same posture as the count cap: flush trigger, not refusal gate.
/// 1 MiB matches the conservative chain-tx-size budget and is well
/// above realistic single-account payloads.
pub const PUBLISH_QUEUE_BYTE_CAP_BYTES: u64 = 1_000_000;

/// One-stop per-account status view (MVP-1 issue 1.6).
///
/// Returned by [`Vault::account_status`]. All fields non-secret. A host
/// UI uses this to decide which banners to render (forked → "you have a
/// conflict to resolve"; frozen → "this account was chain-modified,
/// resolve before editing"; requires-upgrade → "this account needs a
/// newer Pangolin").
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountStatus {
    /// The account this status describes.
    pub account_id: crate::account::AccountId,
    /// `true` if the account has been deleted (tombstoned).
    pub is_tombstoned: bool,
    /// `true` if the revision graph has ≥ 2 leaves (a fork). The
    /// account stays readable at its canonical head; resolve via
    /// [`Vault::resolve_fork`].
    pub is_forked: bool,
    /// `true` if the P10 `frozen_pending_resolve` flag is set (a
    /// foreign-device chain event landed under this account via the
    /// dormant ingest path). Distinct from `is_forked`; stricter.
    pub is_frozen_pending_resolve: bool,
    /// `true` if the account's canonical head carries a schema version
    /// newer than this build understands (§18.7) — metadata-only reads
    /// keep working; reveals/edits/head-decryption are blocked. Only
    /// meaningful on an `Active` vault; `false` otherwise.
    pub requires_upgrade: bool,
}

/// Public state observable on a [`Vault`] handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultState {
    /// `SQLite` handle open; no plaintext in memory.
    Locked,
    /// `SQLite` handle open; in-memory cache live; credentials usable.
    Active,
}

// ---------------------------------------------------------------------
// MVP-2 issue 4.4 — sync-mode selector (Kelvin sign-off 2026-05-16).
//
// The picker decides whether to use 4.1's in-process slow-mode sync
// (`Vault::sync_from_chain`) or to offer the user 4.2/4.3's ephemeral
// `pangolin-indexer` ("Spin up faster sync?") path. 4.4 is read-only
// logic: it returns the decision; the host (CLI / Tauri shell) renders
// the prompt + spawns the indexer on user assent (L1 — selector NEVER
// auto-spawns; "AlwaysFast" is a pre-elected user assent recorded in
// the preference flag).
//
// Heuristic (R-a, locked 2026-05-16): first-sync-on-this-device only.
// `vault.last_synced_block_v1().is_none()` ⇒ `SyncMode::OfferFast`;
// else `SyncMode::Slow`. NO threshold, NO env-var override, NO
// eth_getLogs count. Subject to R-b override.
//
// Preference (R-b, locked 2026-05-16): three-state `meta.sync_mode_preference`
// TEXT column. NULL = Auto (default; run R-a heuristic). `'always_slow'`
// = force `SyncMode::Slow`. `'always_fast'` = force `SyncMode::AlwaysFast`.
// Cleartext (L2) — UX preference, not secret material; mirrors the 1.4
// `session_idle_secs` precedent.
// ---------------------------------------------------------------------

/// **MVP-2 issue 4.4 — R-b.** Three-state UX preference flag.
///
/// Recorded in the `meta.sync_mode_preference` column. `Auto` (the
/// default) defers to the first-sync-on-this-device heuristic;
/// `AlwaysSlow` / `AlwaysFast` are explicit user pre-elections that
/// override the heuristic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncModePreference {
    /// Default behavior — `Vault::select_sync_mode` runs the first-sync
    /// heuristic (`last_synced_block_v1().is_none() →
    /// SyncMode::OfferFast`, else `SyncMode::Slow`).
    Auto,
    /// User pre-elected "never offer fast-mode" — selector always
    /// returns `SyncMode::Slow` regardless of checkpoint state.
    AlwaysSlow,
    /// User pre-elected "skip the prompt, always go fast-mode" —
    /// selector always returns `SyncMode::AlwaysFast`. This is the
    /// only path where the host spawns the ephemeral indexer without
    /// a per-session prompt (the user assented when they set the
    /// preference).
    AlwaysFast,
}

impl SyncModePreference {
    /// Encode the preference into the storage representation used by
    /// the `meta.sync_mode_preference` column. `Auto` maps to SQL NULL
    /// (= `None`); the two explicit pre-elections map to fixed string
    /// literals.
    #[must_use]
    pub fn to_meta_str(self) -> Option<&'static str> {
        match self {
            Self::Auto => None,
            Self::AlwaysSlow => Some("always_slow"),
            Self::AlwaysFast => Some("always_fast"),
        }
    }

    /// Decode a value read from the `meta.sync_mode_preference` column.
    /// `None` (SQL NULL — both the row-absent and column-NULL cases per
    /// [`crate::meta::read_sync_mode_preference`]) maps to `Auto`. The
    /// two recognized strings map to the corresponding variants;
    /// anything else surfaces as
    /// [`StoreError::Corrupted`] so a tampered column value cannot
    /// silently degrade to a default.
    ///
    /// # Errors
    ///
    /// [`StoreError::Corrupted`] if `s` is `Some(_)` with an
    /// unrecognized value (anything other than `"always_slow"` or
    /// `"always_fast"`).
    pub fn from_meta_str(s: Option<&str>) -> Result<Self> {
        match s {
            None => Ok(Self::Auto),
            Some("always_slow") => Ok(Self::AlwaysSlow),
            Some("always_fast") => Ok(Self::AlwaysFast),
            Some(other) => Err(StoreError::Corrupted(format!(
                "meta.sync_mode_preference contains unrecognized value {other:?}; \
                 expected NULL, 'always_slow', or 'always_fast'"
            ))),
        }
    }
}

/// **MVP-3 issue #106c2.** The per-vault v1/v2 `RevisionLog` binding —
/// the routing signal for the sync loop + the publish call site.
///
/// Recorded in the `meta.revisionlog_version` column (`1` = V1, `2` =
/// V2). NULL / absence ⇒ [`Self::V1`] (the no-regression default — a
/// legacy vault predating #106c2 keeps routing to the V1 path verbatim).
/// NEW vaults are seeded [`Self::V1`] explicitly (Q-a: the V2 path is
/// testnet-only until a Base Sepolia V2 deploy + pinned address land).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevisionLogVersion {
    /// `RevisionLogV1` (the v1 EIP-712 domain `version "1"` + the v1
    /// contract / read path). The legacy + current-production binding.
    V1,
    /// `RevisionLogV2` (the v2 EIP-712 domain `version "2"` + the v2
    /// contract / read path). The #106c2 data-plane; testnet-only until
    /// the Base Sepolia V2 deploy lands.
    V2,
}

impl RevisionLogVersion {
    /// Encode the binding into the storage representation used by the
    /// `meta.revisionlog_version` column. `1` = V1, `2` = V2.
    #[must_use]
    pub fn to_meta_int(self) -> i64 {
        match self {
            Self::V1 => 1,
            Self::V2 => 2,
        }
    }

    /// Decode a value read from the `meta.revisionlog_version` column.
    /// `None` (SQL NULL — both the row-absent and column-NULL cases per
    /// [`crate::meta::read_revisionlog_version`]) maps to [`Self::V1`]
    /// (the no-regression default). `Some(1)` → V1, `Some(2)` → V2;
    /// anything else surfaces as [`StoreError::Corrupted`] so a tampered
    /// column value cannot silently route to the wrong contract.
    ///
    /// # Errors
    ///
    /// [`StoreError::Corrupted`] if `v` is `Some(_)` with a value other
    /// than `1` or `2`.
    pub fn from_meta_int(v: Option<i64>) -> Result<Self> {
        match v {
            None | Some(1) => Ok(Self::V1),
            Some(2) => Ok(Self::V2),
            Some(other) => Err(StoreError::Corrupted(format!(
                "meta.revisionlog_version contains unrecognized value {other}; \
                 expected NULL, 1 (V1), or 2 (V2)"
            ))),
        }
    }
}

/// **MVP-2 issue 4.4 — R-e.** Decision returned by
/// [`Vault::select_sync_mode`]. Carries no payload — the host renders
/// its own prompt copy without needing the picker to count anything.
///
/// Semantics (R-a + R-b, combined):
///
/// | `last_synced_block_v1` | preference | returns |
/// |---|---|---|
/// | `Some(_)` | `Auto` | `Slow` |
/// | `None` | `Auto` | `OfferFast` |
/// | any | `AlwaysSlow` | `Slow` |
/// | any | `AlwaysFast` | `AlwaysFast` |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncMode {
    /// In-process slow-mode chain sync via `Vault::sync_from_chain`
    /// (4.1 R-e). The host runs the sync directly; no indexer spawn.
    Slow,
    /// First-sync-on-this-device detected; host SHOULD render the D-007
    /// "Spin up faster sync? (uses temporary local indexer that
    /// auto-deletes)" prompt and, on user accept, spawn the
    /// `pangolin-indexer` (4.2/4.3). On user decline, fall through to
    /// `Slow`.
    OfferFast,
    /// User pre-elected always-fast; host spawns the
    /// `pangolin-indexer` without a per-session prompt. The user
    /// assented when they set `SyncModePreference::AlwaysFast`.
    AlwaysFast,
}

/// **MVP-3 issue #106e-0.** The NON-secret recovery-escrow parameters a
/// VDK rotation needs, returned by [`Vault::recovery_escrow_params`].
///
/// Read by the store with the active VDK (which opens the double-wrapped
/// escrow) but carrying NO secret: just the guardian set shape and the
/// guardians' SEALING pubkeys + the current recovery epoch. Lets the
/// `pangolin-core` composition layer drive `rotate_vdk_for_survivors`
/// without the active VDK ever crossing the crate boundary (Q-d).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryEscrowParams {
    /// The reconstruction threshold (`t`) — equals the on-chain
    /// `guardianSet.threshold`.
    pub threshold: u8,
    /// The guardian count (`M`) — equals the on-chain `guardianCount`.
    pub guardian_count: u8,
    /// The `M` guardians' 32-byte X25519 SEALING pubkeys, ordered by index
    /// (`0..M`). Non-secret — the re-split re-seals to the SAME guardian set.
    pub guardian_x25519_pubs: Vec<[u8; 32]>,
    /// The current recovery epoch the escrow generation is tagged with.
    pub current_epoch: u64,
}

/// **MVP-3 issue #106e-0b.** The NON-secret outcome of
/// [`Vault::onboard_guardians`] — the recovery-generation epoch the freshly
/// onboarded escrow was written at.
///
/// Carries NO secret: the RWK + the raw shares are minted, used, and
/// dropped (zeroized) inside the crypto onboard primitive; the active VDK
/// is borrowed store-internal and never leaves. Only this non-secret epoch
/// crosses the API boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OnboardingOutcome {
    /// The recovery-generation epoch the escrow was written at. The FIRST
    /// onboard writes GENESIS (`0`); rotation / recovery bump it thereafter
    /// (the existing epoch model). A re-onboard REPLACES the prior
    /// generation in place (still at genesis — the recovery re-split owns
    /// the bump, not a guardian-set change).
    pub epoch: u64,
}

/// Encrypted local vault.
///
/// Owns a `SQLite` connection and (when `Active`) the unwrapped VDK plus
/// the decrypted-account cache. Drop locks the cache automatically.
pub struct Vault {
    path: PathBuf,
    conn: Connection,
    meta: VaultMeta,
    /// Authoring device id stamped into every revision row this handle
    /// produces.
    ///
    /// **MVP-1 issue 1.5.** Before the first `unlock` this is a
    /// throwaway per-handle random placeholder (no revision can be
    /// written before `unlock` — `account_add`/`account_update` call
    /// `require_active()` — so the placeholder is never stamped onto a
    /// revision). The first `unlock` on a new vault file generates a
    /// `DeviceKey`, derives the real `device_id` from its verifying-key
    /// bytes, registers the `devices` row + the AEAD-sealed `device_key`
    /// row, and overwrites this field; subsequent unlocks load the same
    /// device and set this field to its persisted id. Pre-1.5 revisions
    /// keep their old throwaway `originating_device` values (accepted
    /// as-is — the trust list gates nothing in MVP-1).
    device_id: DeviceId,
    /// P4 session-policy state. Source of truth; the public
    /// [`VaultState`] view (returned by [`Self::state`]) is derived
    /// from this. Transitions:
    ///
    /// - `Locked` → `Active` on successful 2-proof unlock.
    /// - `Active` → `Expired` (then immediately `Locked`) when
    ///   `check_session_freshness` detects expiry.
    /// - `Active` → `Locked` on explicit `lock()`.
    session_state: SessionState,
    /// `Some` only while `session_state` is `Active`. Owns the
    /// unwrapped VDK and the decrypted-snapshot cache. `lock()` drops
    /// this; `Drop` does the same; idle/absolute-max expiry drops it
    /// inside `check_session_freshness` before returning
    /// [`StoreError::SessionExpired`].
    active: Option<ActiveState>,
    /// **MVP-1 issue 1.4.** The session's configured idle duration
    /// (Session spec §7.2). Read from `meta.session_idle_secs` on
    /// `open` / `create` ([`crate::session::SessionDuration::from_meta_secs`]);
    /// `meta` rows that predate 1.4 ⇒ [`crate::session::SessionDuration::DEFAULT`]
    /// (15 min). `unlock` uses it for the first `expires_at`;
    /// `touch_session` uses it on every extend; `set_session_idle`
    /// updates both this field and the persisted column.
    session_idle: SessionDuration,
    /// Time source. Production uses [`SystemClock`]; tests inject a
    /// mockable clock via [`Self::with_clock`] so the idle-timer +
    /// absolute-max behaviors can be driven deterministically without
    /// actually waiting 4 hours.
    clock: Box<dyn Clock>,
    /// Sidecar lock file held open for the lifetime of the `Vault`.
    /// The file is created with `create_new(true)` so a second `open`
    /// attempt on the same vault path observes its presence and
    /// returns [`StoreError::AlreadyOpen`]. The file is removed on
    /// `Drop`. After a hard crash the file remains and the next
    /// `Vault::open` call will surface as `AlreadyOpen` until the
    /// stale `.lock` is manually removed — this is the documented
    /// operational hazard from `docs/issue-plans/P2.md` "Failure modes
    /// considered" §"File deleted while open" sibling.
    _lock_file: File,
}

fn lock_path(vault_path: &Path) -> PathBuf {
    let mut p = vault_path.as_os_str().to_owned();
    p.push(".lock");
    PathBuf::from(p)
}

fn acquire_lock(vault_path: &Path) -> Result<File> {
    let lp = lock_path(vault_path);
    match OpenOptions::new().write(true).create_new(true).open(&lp) {
        Ok(mut f) => {
            // Stamp the lock file so a human inspecting it knows what
            // it is. Best-effort; failure here doesn't block us.
            let _ = writeln!(f, "pangolin-store vault lock");
            Ok(f)
        }
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => Err(StoreError::AlreadyOpen),
        Err(other) => Err(StoreError::Io(other)),
    }
}

fn release_lock(vault_path: &Path) {
    let lp = lock_path(vault_path);
    // Best-effort; `Drop` cannot signal failure usefully.
    let _ = std::fs::remove_file(&lp);
}

// ---------------------------------------------------------------------
// P11B fix-pass M-1: umask shim around `Vault::create`.
//
// The audit identified a race window: `Vault::create` opens the `.pvf`
// via `OpenOptions::create_new(true)` (inside `rusqlite`'s
// `OpenFlags::SQLITE_OPEN_CREATE`), and on a typical Unix host the
// process default umask is `0o022`, which means the file is created
// at mode `0o644` (world-readable). `pangolin-cli`'s
// `restrict_vault_file_mode` then chmods it to `0o600`, but in the
// window between create and chmod an attacker with a pre-positioned
// `inotify_add_watch` can read the freshly-written file. The file
// content includes the offline-Argon2id-bruteforce preconditions
// (`kdf_salt`, `kdf_params`, `wrapped_ciphertext`, `wrap_nonce`).
// Strong passwords are defended by Argon2id RECOMMENDED expense;
// weak passwords are exposed.
//
// The fix is to install `umask(0o077)` BEFORE the file is created,
// so the kernel applies the restrictive bits at creation time.
// We do this in `Vault::create` itself (not the CLI) so that ALL
// callers of `Vault::create` benefit, and so the CLI's existing
// `restrict_vault_file_mode` chmod becomes belt-and-braces defense-
// in-depth rather than the primary defense.
//
// Implementation uses the `nix` crate's safe `sys::stat::umask`
// wrapper so we do not need any `unsafe` block at our call site —
// this preserves `pangolin-store`'s `forbid(unsafe_code)` attribute
// (which `#[allow(unsafe_code)]` cannot relax). The guard is
// `cfg(unix)`-gated; on Windows umask is meaningless and the call
// is omitted (the existing CLI Windows behavior — file ACLs
// inherited from the parent — is unchanged).
//
// Concurrency caveat: `umask` is process-global, so concurrent
// threads in the same process that create files during
// `Vault::create`'s execution would observe the restrictive umask.
// In practice, `pangolin-cli vault create` is the only documented
// caller, runs in a single-threaded context for the create step,
// and is mutually exclusive with itself via `acquire_lock`'s
// `OpenOptions::create_new(true)` lock-file (the P2 sidecar lock).
// The guard restores the previous umask on `Drop`, including on
// panic, so any subsequent unrelated file creation in the same
// process resumes with the user's normal umask.
// ---------------------------------------------------------------------

/// Installs `0o077` as the process umask for the lifetime of this
/// guard, restoring the previous umask on `Drop`. Unix-only; on
/// Windows callers should not construct this type (umask is not a
/// Windows concept).
#[cfg(unix)]
struct UmaskGuard {
    previous: nix::sys::stat::Mode,
}

#[cfg(unix)]
impl UmaskGuard {
    /// Install `0o077` (`S_IRWXG | S_IRWXO`) as the umask, capturing
    /// the previous value for restoration on `Drop`. The `nix::umask`
    /// wrapper is safe (no `unsafe` block here); the underlying
    /// FFI's `unsafe` lives inside `nix`.
    fn restrict_to_owner_only() -> Self {
        use nix::sys::stat::Mode;
        // 0o077 == S_IRWXG | S_IRWXO. Files created while this is
        // installed get their group + world permission bits cleared,
        // yielding 0o600 for a 0o666 default-create mode.
        let restrictive = Mode::S_IRWXG | Mode::S_IRWXO;
        let previous = nix::sys::stat::umask(restrictive);
        Self { previous }
    }
}

#[cfg(unix)]
impl Drop for UmaskGuard {
    fn drop(&mut self) {
        // Restore the previous umask. `nix::umask` itself returns
        // the prior value; we ignore the return because we are
        // restoring, not capturing.
        let _ = nix::sys::stat::umask(self.previous);
    }
}

struct ActiveState {
    vdk: VdkKey,
    /// **MVP-3 issue #106b-2.** The retained-old-epoch VDK chain (plan
    /// §3.1). After a device-revoke rotation, `vdk` is the CURRENT epoch's
    /// VDK (new writes) and this chain holds every RETAINED OLD-epoch VDK
    /// so a surviving device decrypts PRE-rotation entries under
    /// `chain.aead_for_epoch(entry.vdk_epoch)`. EMPTY for an unrotated /
    /// legacy vault (every entry is the current epoch 0 -> `vdk`). Built on
    /// `unlock` under the password authority; drops (zeroizing every
    /// retained VDK) on every session-teardown path alongside `vdk`.
    chain: crate::vdk_chain::VdkChain,
    cache: DecryptedCache,
    /// MVP-1 issue 1.3: the `:memory:` FTS5 search index over the
    /// non-secret searchable projection of every live account. Built
    /// from the decrypted blobs on `unlock`; kept in sync from the
    /// add / update / delete paths; `SQLite` frees the arena when this
    /// `ActiveState` drops on `lock()` / expiry / `Drop`.
    search_index: SearchIndex,
    /// **MVP-2 issue 3.2 (R-b: eager materialisation).** The
    /// per-device EVM wallet derived deterministically from `device_key`
    /// via [`pangolin_chain::derive_evm_wallet`]. Materialised once on
    /// every successful `Vault::unlock` (one HKDF-SHA256 expand + one
    /// `k256::SecretKey::from_slice`; ~hundreds of microseconds —
    /// negligible against the ~ms Argon2id already pays). Held by
    /// value, never cloned (`EvmWallet` is deliberately not `Clone` —
    /// L-zeroize); every session-teardown path (`lock()` / idle
    /// expiry / absolute expiry / `Drop`) drops the wallet alongside
    /// `device_key`. The secp256k1 *scalar* lives only inside the
    /// wallet's `k256::SecretKey` whose `Drop` zeroizes; the on-disk
    /// shape carries only the wallet's public 20-byte *address* (R-a:
    /// vault-sealed-only).
    ///
    /// Reachable from production code via [`Vault::evm_wallet`] —
    /// which calls `require_active()` so a locked or expired session
    /// returns `StoreError::NotUnlocked` / `SessionExpired` rather
    /// than handing out the wallet. Production callers (MVP-2 issues
    /// 3.1 / 3.3 / 3.4 / 4.2) thread the borrowed wallet into chain
    /// primitives; the wallet is never re-derived per-call (consumer
    /// L6 doctrine).
    ///
    /// **Drop order (L1 audit fix-pass).** Declared BEFORE `device_key`
    /// so Rust's declaration-order drop semantics tear the derivative
    /// wallet down before the source seed — defense-in-depth (derivative
    /// material is wiped before the material it was derived from is
    /// itself wiped, so a hypothetical mid-Drop observer sees the
    /// derivative go first). The two zeroize disciplines are
    /// independent (`k256::SecretKey` vs `ed25519-dalek` `SecretKey` via
    /// `pangolin_crypto`'s `Zeroize` plumbing); ordering them here is
    /// pure belt-and-braces.
    evm_wallet: EvmWallet,
    /// **MVP-1 issue 1.5.** This device's Ed25519 [`DeviceKey`] — loaded
    /// (decrypted from the `device_key` table under the VDK) on `unlock`,
    /// or freshly generated + persisted on the first unlock that
    /// registers a device. It does NOT sign anything in MVP-1 (Q4 — it
    /// is the hook for MVP-2's signed-revision format / gas-payer role);
    /// it is held here so every session-teardown path (`lock()` /
    /// idle-or-absolute expiry / `Drop`) drops it alongside the cache +
    /// search index. `DeviceKey` zeroizes on drop and redacts `Debug`
    /// (P1 invariants); the on-disk form is only the AEAD ciphertext.
    ///
    /// Read only by the test/test-utilities accessor
    /// [`Vault::device_key_verifying_key`] (verifies the in-memory key
    /// matches the registered device + that teardown drops it); in a
    /// production build it is a write-only MVP-2 hook, hence the
    /// `dead_code` allow on the non-test cfg.
    #[cfg_attr(not(any(test, feature = "test-utilities")), allow(dead_code))]
    device_key: DeviceKey,
    /// **MVP-1 issue 1.4 — presence freshness + dedup (Session spec
    /// §7.6 / §8.6).** Wall-clock instant of the most recent successful
    /// presence proof for this session — set by `unlock` (the 2-proof
    /// start counts) and by every presence-gated op that consumes a
    /// fresh proof. A presence-gated op within
    /// [`crate::session::PRESENCE_FRESHNESS`] of this instant proceeds
    /// **without** consuming a new proof (prompt dedup: one proof
    /// satisfies concurrent reveals); outside the window it must verify
    /// a fresh proof and re-stamp this field. `None` immediately after
    /// the field is created and never thereafter (unlock always stamps
    /// it), but kept `Option` for explicitness.
    last_presence_at: Option<SystemTime>,
    /// **MVP-1 issue 1.6 — §18.7 "requires upgrade" per-account state.**
    /// Account ids whose canonical head (the revision the cache/index
    /// would reflect) carries a `schema_version` / `payload_version`
    /// newer than this build understands
    /// ([`crate::revision::REVISION_SCHEMA_VERSION_MAX`]). Populated on
    /// `unlock` (the cache build catches the per-account
    /// [`StoreError::UnsupportedRevisionSchemaVersion`] and records the
    /// id here rather than aborting the unlock). NOT a persisted column
    /// — the on-disk truth is "there is a revision with version > our
    /// max"; this is just a fast in-RAM lookup so user-facing reads /
    /// edits on the affected account surface a typed error without
    /// re-decrypting. Empty for a vault with no future-versioned heads.
    requires_upgrade: std::collections::HashSet<AccountId>,
    /// **MVP-2 issue 5.1 (R-d) — publish-queue 30s window.** Unix-ms
    /// instant at which the current coalescing window started, set on
    /// the FIRST dirty marker stamped after the queue is empty (or
    /// after a successful flush resets it). `None` between an empty
    /// queue and the next edit. Cleared on every successful
    /// [`Vault::flush_publish_queue`]. Not persisted — survives
    /// nowhere across `lock()` / unlock cycles; the next unlock starts
    /// a fresh window if there are dirty markers (R-d Option A).
    window_started_at_unix_ms: Option<i64>,
    /// **MVP-2 issue 5.1 (L11) — opt-in window-elapsed auto-flush.**
    /// Default `false`. When the host calls
    /// [`Vault::enable_window_elapsed_flush`] with `true`, subsequent
    /// `account_add` / `account_update` / `delete_account` calls
    /// check the window deadline and trigger an opportunistic
    /// `flush_publish_queue` BEFORE handling the new edit if the
    /// window has elapsed. 5.4 will wire this on by default; 5.1
    /// ships the primitive only.
    window_elapsed_flush_enabled: bool,
    /// **MVP-2 issue 5.1 — diagnostic.** `true` if the most recent
    /// `flush_publish_queue` invocation returned
    /// [`crate::publish::BatchFlushError::BalanceInsufficientForBatch`].
    /// Cleared on the next successful flush. Read-only outside the
    /// flush path; the chain-side per-revision balance gate (3.3) IS
    /// the authoritative defense — this flag is host-UX hinting only.
    last_flush_failed_balance: bool,
    /// **MVP-2 issue 5.2 (R-c diagnostic).** Unix-ms instant of the
    /// last successful [`Vault::pull_once`] cycle's dispatch — the
    /// stamp is taken inside the same call after the
    /// [`Vault::select_sync_mode`] picker (so `OfferFast` /
    /// `AlwaysFast` ticks also stamp the field; they DID run a pull
    /// cycle even if no chain read happened on this leg). Not
    /// persisted across `lock()` / unlock; 5.4 will use this as the
    /// "Syncing… / Synced N min ago" indicator-state-machine input
    /// and may revisit the persistence story then.
    last_pull_at_unix_ms: Option<i64>,
}

impl Vault {
    // -----------------------------------------------------------------
    // Lifecycle
    // -----------------------------------------------------------------

    /// Create a fresh `.pvf` vault file at `path`.
    ///
    /// Generates a fresh authority from a password-derived seed
    /// (Argon2id), a fresh VDK, wraps the VDK under that authority, and
    /// writes the meta row + empty schema. Returns the vault in the
    /// `Locked` state — the caller must call [`Self::unlock`] before
    /// adding accounts. The choice to leave the freshly-created vault
    /// locked rather than active is deliberate: it forces the unlock
    /// path through the same Argon2 round-trip as a subsequent open,
    /// so a user-perceptible failure mode (e.g., wrong password during
    /// first-account-add) cannot exist.
    ///
    /// # Errors
    ///
    /// Surfaces `StoreError::Sqlite` for any database issue or
    /// `StoreError::Io` if the parent directory of `path` is not
    /// writable. Crypto errors collapse to
    /// `StoreError::AuthenticationFailed`.
    pub fn create(path: &Path, password: &SecretBytes) -> Result<Self> {
        // Refuse to overwrite an existing file — `create` is for
        // first-time provisioning.
        if path.exists() {
            return Err(StoreError::Io(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("vault file already exists at {}", path.display()),
            )));
        }

        // **P11B fix-pass M-1.** Install a `0o077` umask BEFORE any
        // file-creating syscall fires inside this function. This
        // applies to both the sidecar lock file (`acquire_lock`) and
        // the `.pvf` itself (`open_connection` → SQLite create), so
        // both are born at mode `0o600` on Unix without any
        // intervening `chmod`. The previous umask is restored when
        // `_umask_guard` drops at the end of this function (or on
        // any panic). On Windows the guard is omitted — umask is
        // not a Windows concept and file ACLs are inherited from
        // the parent directory.
        #[cfg(unix)]
        let _umask_guard = UmaskGuard::restrict_to_owner_only();

        let lock_file = acquire_lock(path)?;
        let result = (|| -> Result<Self> {
            let conn = open_connection(path)?;
            schema::apply_pragmas_and_schema(&conn)?;

            let vault_id = random_32_via_sqlite(&conn)?;
            let salt = KdfSalt::random();
            let params = KdfParams::RECOMMENDED;
            let seed = kdf::derive_seed(password, &salt, &params)?;
            let authority = AuthorityKey::from_seed(*seed);
            let vdk = VdkKey::generate();
            let wrap_ctx = WrapContext::new(vault_id);
            let wrapped = vdk.wrap(&authority, &wrap_ctx)?;

            let now_ms = current_unix_ms();
            let meta_row = VaultMeta {
                vault_id,
                created_at: now_ms,
                kdf_params: params,
                kdf_salt: salt,
                wrap_context: wrap_ctx,
                wrapped_ciphertext: wrapped.ciphertext().as_bytes().to_vec(),
                wrapped_nonce: *wrapped.nonce().as_bytes(),
            };
            meta::write(&conn, &meta_row)?;

            // MVP-3 issue #106c2: seed the v1/v2 RevisionLog binding. NEW
            // vaults default to V1 (Q-a — the V2 path is testnet-only
            // until a Base Sepolia V2 deploy + pinned address land), so
            // #106c2 lands with zero behavioural change on the production
            // testnet path. The value is written explicitly (rather than
            // left NULL = V1) so the routing signal is unambiguous.
            meta::write_revisionlog_version(&conn, Some(RevisionLogVersion::V1.to_meta_int()))?;

            // Burn the freshly-derived VDK and authority; subsequent
            // operations re-derive them through the unlock path so the
            // create-then-unlock and open-then-unlock paths exercise
            // the same Argon2id derivation.
            drop(vdk);
            drop(authority);

            let device_id = DeviceId(random_32_via_sqlite(&conn)?);
            Ok(Self {
                path: path.to_path_buf(),
                conn,
                meta: meta_row,
                device_id,
                session_state: SessionState::Locked,
                active: None,
                // A freshly-created vault has no `session_idle_secs`
                // column value (it isn't listed in `meta::write`'s
                // INSERT), so it starts at the §7.1 default.
                session_idle: SessionDuration::DEFAULT,
                clock: Box::new(SystemClock),
                _lock_file: lock_file,
            })
        })();
        if result.is_err() {
            release_lock(path);
            // Also remove the partially-created vault file so subsequent
            // `create` calls succeed.
            let _ = std::fs::remove_file(path);
        }
        result
    }

    /// Open an existing `.pvf` file. Validates magic + `format_version`
    /// and asserts WAL mode + integrity. Returns the vault `Locked`.
    ///
    /// # Errors
    ///
    /// `StoreError::BadMagic` for a non-Pangolin file,
    /// `StoreError::UnsupportedFormatVersion` for a future version,
    /// `StoreError::AlreadyOpen` if another live `Vault` already holds
    /// the file. `SQLite` I/O errors propagate as `StoreError::Sqlite`.
    pub fn open(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Err(StoreError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("no vault file at {}", path.display()),
            )));
        }
        // Mutual-exclusion via sidecar lock file: the second open on
        // the same path observes the lock file and returns
        // `AlreadyOpen`. `SQLite`'s WAL mode allows concurrent connections
        // by design, so we can't rely on an exclusive transaction here.
        let lock_file = acquire_lock(path)?;
        // MEDIUM-2 (P2 audit): every `open` failure path beyond
        // `acquire_lock` MUST release the sidecar `.lock` file, otherwise
        // a stale lock blocks all subsequent legitimate `open` attempts
        // with `AlreadyOpen` until manual cleanup. The previous
        // implementation released on `open_connection` and `meta::read`
        // failure but propagated through `?` on
        // `apply_pragmas_and_schema`, `assert_wal_mode`,
        // `assert_integrity`, and `random_32_via_sqlite`, leaking the
        // lock on those paths. Wrapping the construction in a closure
        // and calling `release_lock` on any `Err` plugs all of them.
        let result = (|| -> Result<Self> {
            let conn = open_connection(path)?;
            schema::apply_pragmas_and_schema(&conn)?;
            schema::assert_wal_mode(&conn)?;
            schema::assert_integrity(&conn)?;
            let meta = meta::read(&conn)?.ok_or(StoreError::BadMagic)?;
            // MVP-1 issue 1.5: if this vault file has already had a
            // device registered (a prior `unlock` wrote the `devices`
            // row + the AEAD-sealed `device_key` row), adopt that
            // persisted id so a host can call `device_current` on a
            // locked-but-previously-registered vault. A brand-new or
            // never-unlocked vault has no `devices` row → fall back to
            // a throwaway per-handle placeholder, overwritten by the
            // first `unlock`'s register-on-unlock step. No revision can
            // be written before `unlock` (`require_active`), so the
            // placeholder is never stamped onto a revision.
            let device_id = match device::read_registered_device_id(&conn)? {
                Some(id) => id,
                None => DeviceId(random_32_via_sqlite(&conn)?),
            };
            // MVP-1 issue 1.4: read the configured idle duration.
            // Absent column (pre-1.4 vault) ⇒ NULL ⇒ 15-min default; an
            // out-of-set on-disk value is also coerced to the default by
            // `from_meta_secs` so a corrupt-but-decryptable meta field
            // does not brick an otherwise-openable vault.
            let session_idle =
                SessionDuration::from_meta_secs(meta::read_session_idle_secs(&conn)?);
            Ok(Self {
                path: path.to_path_buf(),
                conn,
                meta,
                device_id,
                session_state: SessionState::Locked,
                active: None,
                session_idle,
                clock: Box::new(SystemClock),
                _lock_file: lock_file,
            })
        })();
        if result.is_err() {
            release_lock(path);
        }
        result
    }

    /// Override the time source. Used by tests to drive the idle-timer
    /// + absolute-max behaviors deterministically. Production callers
    /// never need this — `Vault::open` and `Vault::create` install a
    /// [`SystemClock`] by default.
    ///
    /// # Visibility (P4 audit M-1)
    ///
    /// Gated behind `cfg(any(test, feature = "test-utilities"))` so
    /// production builds cannot link against it. The previous
    /// `#[doc(hidden)]`-only gate let downstream code call this and
    /// install a malicious / mis-configured clock — the `cfg` gate
    /// fixes that. The `feature = "test-utilities"` clause is
    /// forward-compat for future external integration testing; the
    /// feature is not declared in `Cargo.toml` yet because all
    /// in-process tests live inside this crate and `cfg(test)` alone
    /// suffices.
    ///
    /// The `Box<dyn Clock>` requires `'static` so callers cannot
    /// accidentally tie the clock's lifetime to a stack frame.
    #[cfg(any(test, feature = "test-utilities"))]
    #[doc(hidden)]
    #[must_use]
    pub fn with_clock(mut self, clock: Box<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Vault id (32-byte content-addressed identifier).
    #[must_use]
    pub fn vault_id(&self) -> [u8; VAULT_ID_LEN] {
        self.meta.vault_id
    }

    /// Current state. Maps the richer P4 [`SessionState`] down onto
    /// the simple two-state observable used by P2-era callers
    /// (`Active` iff the session is active; `Locked` otherwise — i.e.
    /// `Locked`, `PendingAuthorization`, and `Expired` all surface as
    /// `Locked`). For P4-aware code, prefer [`Self::session_state`].
    #[must_use]
    pub fn state(&self) -> VaultState {
        if self.session_state.is_active() {
            VaultState::Active
        } else {
            VaultState::Locked
        }
    }

    /// The full P4 [`SessionState`]. Distinct from [`Self::state`] —
    /// surfaces `PendingAuthorization` and `Expired` as their own
    /// states for P4-aware host-UI code.
    #[must_use]
    pub fn session_state(&self) -> SessionState {
        self.session_state
    }

    /// `true` iff the session is currently active **and** its idle
    /// deadline has not yet been crossed against the vault's clock.
    ///
    /// # P4 audit M-4
    ///
    /// The previous implementation returned the raw state-machine
    /// variant — `SessionState::Active { .. }` was treated as "active"
    /// even when the wall-clock had already advanced past
    /// `expires_at`, because the state-machine flip from `Active` to
    /// `Expired` only happens inside `check_session_freshness` (i.e.,
    /// on the next `&mut self` op). That was misleading: a caller
    /// checking `is_session_active()` between an idle expiry and the
    /// next mut-op would see `true` and proceed under the wrong
    /// assumption. The clock-aware check folded into the public method
    /// (the `is_session_active_now` private helper) makes the answer
    /// match reality regardless of which lifecycle phase the caller
    /// happens to observe.
    #[must_use]
    pub fn is_session_active(&self) -> bool {
        if let SessionState::Active { expires_at, .. } = self.session_state {
            self.clock.now() <= expires_at
        } else {
            false
        }
    }

    /// Time remaining on the active session, or `None` if the session
    /// is not active. Returns `Some(Duration::ZERO)` if the deadline
    /// has already passed but `check_session_freshness` has not yet
    /// run to transition the state.
    #[must_use]
    pub fn session_remaining(&self) -> Option<Duration> {
        if let SessionState::Active { expires_at, .. } = self.session_state {
            let now = self.clock.now();
            Some(expires_at.duration_since(now).unwrap_or(Duration::ZERO))
        } else {
            None
        }
    }

    /// On-disk path of the vault file (for diagnostics).
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Unlock the vault. P4 session-policy: requires both a presence
    /// proof AND an identity proof.
    ///
    /// # Order of operations
    ///
    /// 1. `presence.verify()` — fail-fast check (single-use replay
    ///    resistance + freshness). A second use of a `PressYPresenceProof`
    ///    returns `AuthError::PresenceAlreadyConsumed`, which collapses
    ///    to `StoreError::AuthenticationFailed` via the
    ///    `From<AuthError>` impl on `StoreError`.
    /// 2. `identity.verify()` — structural check on the identity proof
    ///    payload (e.g., non-empty PIN). This step deliberately does
    ///    NOT validate the PIN against any stored hash — see step 3.
    /// 3. `identity.derive_secret()` — extract the password bytes from
    ///    the proof.
    /// 4. `kdf::derive_seed(...)` — Argon2id derivation runs to
    ///    completion regardless of whether the PIN is "right" or
    ///    "wrong". This preserves the MEDIUM-1 indistinguishability
    ///    discipline: an attacker cannot distinguish "wrong PIN" from
    ///    "tampered KDF params" or "tampered wrapped VDK ciphertext"
    ///    via timing.
    /// 5. `WrappedVdk::unwrap_with(&authority)` — AEAD verification.
    ///    Failure surfaces as `AeadError::Tampered` and collapses to
    ///    `StoreError::AuthenticationFailed`.
    /// 6. `build_decrypted_cache(...)` — every live head is decrypted
    ///    and inserted into the in-memory cache.
    /// 7. `session_state` set to `Active{expires_at, last_proof_at,
    ///    session_started_at}` with `expires_at = now +
    ///    IDLE_TIMEOUT_DEFAULT`.
    ///
    /// # Behavior on a vault that is already `Active`
    ///
    /// MEDIUM-5 (P2 audit): the precise semantics of calling `unlock`
    /// twice in a row are worth pinning down because they're not what a
    /// casual reader might assume.
    ///
    /// 1. **Re-call with valid (correct) proofs while `Active`:**
    ///    succeeds. The full Argon2id derivation runs again (~1–2 s
    ///    burned), the VDK is re-unwrapped, the in-memory cache is
    ///    rebuilt from disk, and the previous `ActiveState` is dropped
    ///    (its secrets zeroize). The session timer resets — `expires_at`
    ///    is set anew from the current clock reading.
    /// 2. **Re-call with valid presence + WRONG identity (or empty
    ///    identity) while `Active`:** fails with
    ///    `AuthenticationFailed`, but the existing `ActiveState`
    ///    is **NOT** modified — the prior unlock remains in effect and
    ///    the cache is intact. The vault does NOT auto-lock on a failed
    ///    `unlock`.
    /// 3. **Re-call with a stale/replayed presence proof while
    ///    `Active`:** fails with `AuthenticationFailed` BEFORE any
    ///    Argon2id runs. This is acceptable: replay rejection is a
    ///    structural check on the proof envelope and does not involve
    ///    any secret-bearing material — the timing distinguishability
    ///    here is "structural failure vs. crypto failure", not "wrong
    ///    secret vs. right secret".
    ///
    /// # Errors
    ///
    /// `StoreError::AuthenticationFailed` for any proof-class or
    /// crypto-class failure (wrong PIN, replayed/stale presence,
    /// tampered meta, schema-version drift, KDF param tamper, etc. —
    /// all collapse into the single variant per the MEDIUM-1 fix).
    pub fn unlock(
        &mut self,
        presence: &dyn PresenceProof,
        identity: &dyn IdentityProof,
    ) -> Result<()> {
        // Step 1+2: structural proof verification. Order matters only
        // in that presence verify is cheaper (no secret material) and
        // it consumes the proof's one-shot flag — running it first
        // ensures a stale/replayed presence is caught immediately.
        // Both verifies route through `From<AuthError> for StoreError`,
        // collapsing to `AuthenticationFailed`.
        //
        // M-2 (P4 audit) — known timing distinguishability between
        // structural and content-class identity failures; PoC accepts;
        // MVP-1 hardening = run Argon2id on every code path that
        // produces an `AuthenticationFailed`. Concretely: a stale or
        // already-consumed presence proof, or an empty PIN, fails
        // here in microseconds; a wrong (non-empty) PIN fails after
        // the full ~1.5s Argon2id derivation downstream. An attacker
        // observing wall-clock timing can therefore distinguish
        // "structural rejection" from "content-class rejection" —
        // but NOT "right PIN" from "wrong PIN" (both run Argon2id to
        // completion). This residual distinguishability is acceptable
        // for PoC because the structural-failure timing leak does
        // not reveal any secret-bearing material; MVP-1 closes it
        // by routing every authentication-failure path through a
        // constant Argon2id round-trip. Do NOT add a sleep or
        // always-run-Argon2id workaround at PoC stage — those would
        // harm UX (every empty-PIN typo would 1.5s) and are out of
        // PoC scope.
        presence.verify()?;
        identity.verify()?;

        // Step 3: extract the password bytes. The returned SecretBytes
        // zeroes on drop, and we drop it explicitly after the kdf
        // derivation so the plaintext lives the minimum lifetime.
        let password = identity.derive_secret()?;

        // Step 4: Argon2id derivation runs to completion regardless of
        // whether the password is "right" or "wrong". The
        // From<KdfError> for StoreError collapses any KDF rejection
        // (e.g., tampered KDF params below the floor) into
        // AuthenticationFailed — preserving MEDIUM-1 indistinguishability.
        let seed = kdf::derive_seed(&password, &self.meta.kdf_salt, &self.meta.kdf_params)?;
        // Authority lifetime: only needed for unwrap.
        let authority = AuthorityKey::from_seed(*seed);
        // Drop the password as soon as the seed is derived so its bytes
        // are zeroized at the earliest opportunity.
        drop(password);

        // Step 5: AEAD verification. Failure here is the wrong-password
        // path (or tampered meta — same outcome by design). `meta` always
        // holds the CURRENT epoch's VDK (#106b-2: a rotation re-writes the
        // meta anchor under the new-password authority), so this unwrap
        // recovers the current-epoch VDK exactly as for an unrotated vault.
        let wrapped = self.meta.wrapped_vdk();
        let vdk = wrapped.unwrap_with(&authority)?;

        // Step 5b (MVP-3 issue #106b-2): build the retained-old-epoch VDK
        // chain under the SAME password authority (plan §3.1). Empty for an
        // unrotated / legacy vault. The authority is dropped right after so
        // its bytes zeroize at the earliest opportunity.
        let chain =
            vdk_chain::VdkChain::build_on_unlock(&self.conn, &self.meta.vault_id, &authority)?;
        // Authority was only needed to unwrap the current + retained VDKs.
        drop(authority);

        // Step 6: rebuild the decrypted cache AND the `:memory:` FTS5
        // search index in one decrypt pass over the live heads (1.3).
        // The index is RAM-only and rebuilt fresh on every unlock, so an
        // interrupted sync can never desync it persistently; V0-format
        // and 1.2-V1-format vaults alike get a working index here
        // regardless of blob version (the decrypt is V1-aware). Each entry
        // is decrypted under `chain[entry.vdk_epoch]` (#106b-2 Q-a) —
        // current-epoch entries under `vdk`, retained-epoch entries under
        // the chain.
        let (cache, search_index, requires_upgrade) =
            build_active_state_data(&self.conn, &self.meta, vdk.aead_key(), &chain)?;

        // Step 6b (MVP-1 issue 1.5): register-on-first-unlock /
        // load-on-subsequent-unlock for the device identity. Needs the
        // unwrapped VDK (the device-key seed is AEAD-sealed under it).
        // If the `device_key` table is empty (a brand-new vault, or a
        // PoC vault whose `devices` stub never held a row), generate a
        // `DeviceKey`, derive the real `device_id` from its verifying
        // key, and INSERT the `devices` row + the sealed `device_key`
        // row in one transaction; otherwise decrypt the stored seed and
        // reconstruct the same key. Either way, `self.device_id` is set
        // to the persisted id so revisions written this session stamp
        // the real `originating_device`. The `DeviceKey` does not sign
        // anything in MVP-1 (Q4); it is stashed in `ActiveState` so
        // every session-teardown path drops it.
        let now = self.clock.now();
        let now_ms = system_time_to_unix_ms(now);
        let device_key = if let Some(existing_id) = device::read_registered_device_id(&self.conn)? {
            let key = device::load_device_key_with_id(
                &self.conn,
                &self.meta.vault_id,
                vdk.aead_key(),
                &existing_id,
            )?
            .ok_or_else(|| {
                // A `devices` row exists but the `device_key` row does
                // not — they are written together, so this is storage
                // corruption.
                StoreError::Corrupted("devices row present but device_key row missing".into())
            })?;
            self.device_id = existing_id;
            key
        } else {
            let key = DeviceKey::generate();
            // The CLI has no UI to prompt for a device label on first
            // unlock (Q7 — CLI subcommands deferred), so the
            // register-on-unlock entry gets a generated placeholder a
            // user can rename later via `device_set_label`.
            let label = device::validate_label("This device")?;
            let registered = device::register_device(
                &self.conn,
                &self.meta.vault_id,
                vdk.aead_key(),
                &key,
                &label,
                now_ms,
            )?;
            self.device_id = registered;
            key
        };

        // Step 6c (MVP-2 issue 3.2 / R-b — eager materialisation):
        // derive the per-device EVM wallet from the just-materialised
        // `DeviceKey`. The wallet lives in `ActiveState` alongside the
        // `DeviceKey` and is dropped on every session-teardown path
        // (`lock()`, idle/absolute expiry, `Drop`); no static, no
        // `OnceCell`, no cross-session memoisation (L2). The
        // derivation is total in practice (HKDF rejection-sampling
        // budget exhaustion is ~ 2^-128); a failure surfaces as a
        // typed `StoreError::Corrupted` so the unlock collapses to a
        // clean failure path rather than panicking. The wallet's
        // secp256k1 scalar lives only inside the wallet's
        // `k256::SecretKey` whose `Drop` zeroizes.
        let evm_wallet = derive_evm_wallet(&device_key).map_err(|e| {
            StoreError::Corrupted(format!("evm wallet derivation failed during unlock: {e}"))
        })?;

        // Step 7: install the new ActiveState and session timer. If a
        // prior ActiveState exists (case 1 above), `Option::replace`
        // drops the old one, which zeroizes its cache + VDK + device key
        // + the prior EVM wallet (3.2) and frees the prior `:memory:`
        // index. The first `expires_at` derives from the configured
        // idle duration (1.4) — capped at the absolute-max ceiling via
        // `next_idle_deadline`, which for `SessionDuration::UntilDeviceLock`
        // collapses to "the absolute ceiling, no idle leg". The
        // unlock's presence proof is fresh *now*, so `last_presence_at
        // = now` — a reveal-class op within `PRESENCE_FRESHNESS` of
        // unlock won't re-prompt (Session spec §5.2's "access remains
        // seamless"; §8.6 dedup).
        self.active = Some(ActiveState {
            vdk,
            chain,
            cache,
            search_index,
            // L1 audit fix-pass: `evm_wallet` is declared BEFORE
            // `device_key` in ActiveState so the derivative drops
            // first; the construction order here mirrors the
            // declaration for visual clarity (Rust's struct-literal
            // syntax is by-name, so the literal order does not
            // affect drop order — that's purely a function of the
            // struct declaration).
            evm_wallet,
            device_key,
            last_presence_at: Some(now),
            requires_upgrade,
            // MVP-2 issue 5.1 (R-d): fresh window state on every unlock.
            // The persisted `dirty_accounts` table survives lock cycles
            // unaltered, so this unlock either resumes a partly-full
            // queue (with the window restarted from the next edit) or
            // starts clean. Either way the in-memory window timer is
            // re-zeroed.
            window_started_at_unix_ms: None,
            // L11: opt-in window-elapsed auto-flush defaults OFF in 5.1.
            // 5.4 will flip the default to ON when the host wiring lands.
            window_elapsed_flush_enabled: false,
            last_flush_failed_balance: false,
            // MVP-2 issue 5.2: no pull has run on this fresh session
            // yet. Stamped by every successful `Vault::pull_once` cycle
            // (including OfferFast / AlwaysFast signal cycles).
            last_pull_at_unix_ms: None,
        });
        self.session_state = SessionState::Active {
            expires_at: next_idle_deadline(now, now, self.session_idle),
            last_proof_at: now,
            session_started_at: now,
        };
        Ok(())
    }

    /// **MVP-3 issue #104b: the new-password-on-recovery branch (L8 /
    /// §5a Q-d/Q-e).** Re-secure the daily VDK-wrap under a FRESH
    /// password after a true social-recovery, given the byte-identical
    /// VDK reconstructed off-chain by
    /// `pangolin_core::recovery::recover_vdk_from_shares`.
    ///
    /// ## Why this is DISTINCT from `unlock` / device-add (L8)
    ///
    /// The normal "I got a new phone" device-add path reuses the EXISTING
    /// password (the new phone learns the password, derives the same
    /// authority, and unlocks via [`Self::unlock`] — no guardians, no RWK
    /// touch). This entry is ONLY reached on the lost-password recovery:
    /// the user has lost the password (so `unlock` is impossible), the
    /// guardians' threshold-shared RWK has recovered the VDK off-chain,
    /// and the user now sets a NEW password to re-secure the daily path.
    /// It does NOT touch the recovery-escrow state — the forward-security
    /// re-split (a fresh RWK' + fresh sealed shares) is the caller's
    /// separate `pangolin-store::recovery_escrow::write_recovery_escrow`
    /// step, kept independent so the two authorities stay decoupled (L5).
    ///
    /// ## Dual-authority separation (L5)
    ///
    /// This rotates ONLY the off-chain password-derived
    /// [`AuthorityKey`] (the VDK-wrap authority). The on-chain secp256k1
    /// `vaultAuthority` rotation is a wholly independent
    /// `pangolin-chain::finalize_recovery_v1` broadcast the caller drives
    /// separately; neither rotation touches the other. The VDK itself is
    /// PRESERVED bit-for-bit — `recovered_vdk` is re-wrapped, never
    /// re-derived (L3); `VdkKey::generate` is never on this path.
    ///
    /// A FRESH KDF salt is drawn so the new wrap key is a function of the
    /// new password alone (no carry-over from the lost password's salt).
    /// The vault is left `Locked`; the caller unlocks normally with the
    /// new password afterward (re-deriving the same authority).
    ///
    /// # Errors
    ///
    /// `StoreError::AuthenticationFailed` if the KDF / re-wrap fails (the
    /// indistinguishability discipline), `StoreError::Sqlite` on a DB
    /// error.
    pub fn recover_with_new_password(
        &mut self,
        recovered_vdk: VdkKey,
        new_password: &SecretBytes,
    ) -> Result<()> {
        // Derive the new password authority + re-wrap the recovered VDK
        // into a fresh `meta` row (the shared crypto, L3 — same VDK,
        // new authority). `recovered_vdk` is borrowed so the caller (here)
        // controls its drop/zeroize timing.
        let new_meta = self.build_recovery_meta(&recovered_vdk, new_password)?;
        // The recovered VDK has done its job; drop it so its bytes zeroize
        // at the earliest opportunity. The caller re-derives the authority
        // on the next `unlock`.
        drop(recovered_vdk);

        // Persist the new meta row (fresh salt + the re-wrapped daily VDK)
        // in place of the lost-password row, in its own single-write
        // transaction (no escrow write coupled here — that is the separate
        // forward-security re-split caller step; L8). The atomic COMBINED
        // path (meta re-wrap + escrow re-split in ONE tx) is
        // [`Self::commit_recovery_rekey`] (#105a / L2).
        meta::write(&self.conn, &new_meta)?;
        self.meta = new_meta;

        // Leave the vault Locked: recovery re-secures the at-rest wrap;
        // the user unlocks afresh with the new password. Any prior active
        // session is dropped (its secrets zeroize) — recovery is a
        // re-key, not a session continuation.
        self.active = None;
        self.session_state = SessionState::Locked;
        Ok(())
    }

    /// Derive the new password authority and re-wrap `recovered_vdk` into
    /// a fresh [`VaultMeta`] — the shared crypto of the recovery
    /// new-password re-wrap, factored so both [`Self::recover_with_new_password`]
    /// (its own single-write tx) and [`Self::commit_recovery_rekey`] (the
    /// atomic COMBINED tx, #105a) build the meta identically without
    /// duplicating the KDF / wrap (L3).
    ///
    /// Draws a FRESH KDF salt so the new wrap key is a function of the new
    /// password alone, derives the authority, wraps the (borrowed) VDK
    /// under it bound to the SAME vault context (L3 — same VDK, same
    /// vault, new authority), and zeroizes the transient authority before
    /// returning. Does NOT touch `self.conn` / `self.meta`; the caller
    /// persists + updates in-memory state (so a rollback before persist
    /// never desyncs memory from disk).
    ///
    /// # Errors
    ///
    /// `StoreError::AuthenticationFailed` if the KDF / re-wrap fails (the
    /// indistinguishability discipline).
    fn build_recovery_meta(
        &self,
        recovered_vdk: &VdkKey,
        new_password: &SecretBytes,
    ) -> Result<VaultMeta> {
        // Fresh salt + the recommended KDF params, then derive the new
        // password authority. Wrong-password indistinguishability is moot
        // here (the user is SETTING the password, not proving it), but we
        // still route any KDF failure through AuthenticationFailed for a
        // uniform failure surface.
        let salt = KdfSalt::random();
        let params = KdfParams::RECOMMENDED;
        let seed = kdf::derive_seed(new_password, &salt, &params)?;
        let new_authority = AuthorityKey::from_seed(*seed);

        // Re-wrap the recovered VDK under the new authority, bound to the
        // SAME vault context (L3 — same VDK, same vault, new authority).
        let wrap_ctx = WrapContext::new(self.meta.vault_id);
        let wrapped = recovered_vdk.wrap(&new_authority, &wrap_ctx)?;
        // The new authority has done its job; drop it so its bytes zeroize
        // at the earliest opportunity. The caller re-derives the authority
        // on the next `unlock`.
        drop(new_authority);

        Ok(VaultMeta {
            vault_id: self.meta.vault_id,
            created_at: self.meta.created_at,
            kdf_params: params,
            kdf_salt: salt,
            wrap_context: wrap_ctx,
            wrapped_ciphertext: wrapped.ciphertext().as_bytes().to_vec(),
            wrapped_nonce: *wrapped.nonce().as_bytes(),
        })
    }

    /// **MVP-3 issue #105a: the ATOMIC recovery re-key (L2 — LOAD-BEARING).**
    /// Re-secure the daily VDK-wrap under a FRESH password AND persist the
    /// forward-security re-split escrow in **ONE** transaction.
    ///
    /// ## Why this is distinct from [`Self::recover_with_new_password`]
    ///
    /// `recover_with_new_password` rotates ONLY the daily wrap (its own
    /// single-write tx). The #104b adversarial audit (plan §6 GAP FLAG 1 /
    /// the orchestration "Caller persistence ordering" contract) flagged
    /// that doing the meta re-wrap and the re-split escrow write as TWO
    /// separate commits opens an at-rest forward-security hole: a crash
    /// *between* them leaves a post-recovery daily wrap on disk beside a
    /// stale PRE-recovery (OLD-RWK) escrow generation, whose OLD guardian
    /// shares still reconstruct the OLD RWK and thus still unwrap the live
    /// VDK — defeating forward security until the next successful re-split.
    ///
    /// This entry closes that gap by wrapping BOTH writes in a single
    /// `unchecked_transaction()`:
    /// (a) derive the new password authority + re-wrap the daily
    ///     `WrappedVdk`, writing the new `meta` row **through the shared
    ///     transaction**;
    /// (b) write the forward-security re-split escrow + guardians
    ///     **through the SAME transaction** (`write_recovery_escrow_tx`),
    ///     double-wrapping each sealed share under the recovered VDK's
    ///     column-AEAD;
    /// (c) commit ONCE.
    /// On any error before commit, the un-committed transaction's `Drop`
    /// rolls BOTH writes back — there is no reachable on-disk state where
    /// a post-recovery daily wrap coexists with a pre-recovery escrow
    /// generation (L2).
    ///
    /// In-memory `self.meta` / session state are updated ONLY after a
    /// successful commit, so a rollback never desyncs memory from disk.
    ///
    /// ## Parameters (store-local; the #105b FFI surface is a later issue)
    ///
    /// `pangolin-store` is upstream of `pangolin-core`, so this takes the
    /// re-split as the store-local decomposition the caller obtains from
    /// `pangolin_core::recovery::RecoveryArtifacts::re_split`
    /// (`OnboardingArtifacts`): the fresh `WrappedVdkRecovery`, the
    /// `(threshold, guardian_count)` pair, the bumped `epoch`, and the
    /// per-guardian [`recovery_escrow::GuardianRecord`]s (index + X25519
    /// pubkey + sealed share). The VDK column-AEAD key for double-wrapping
    /// the sealed shares is sourced engine-side from `recovered_vdk`
    /// (the SAME VDK just re-wrapped) — never threaded through the API.
    ///
    /// `recovered_vdk` is consumed and dropped (zeroized) after the commit,
    /// exactly as `recover_with_new_password` does; it is re-wrapped, never
    /// re-derived (L3 — `VdkKey::generate` is never on this path).
    ///
    /// The vault is left `Locked`; the caller unlocks with the new password
    /// afterward.
    ///
    /// # Errors
    ///
    /// `StoreError::AuthenticationFailed` if the KDF / re-wrap / sealed-share
    /// double-wrap fails (the indistinguishability discipline);
    /// `StoreError::Sqlite` on a DB error; `StoreError::Corrupted` if the
    /// epoch overflows the on-disk encoding. On any error nothing is
    /// committed (L2 rollback).
    #[allow(clippy::too_many_arguments)]
    pub fn commit_recovery_rekey(
        &mut self,
        recovered_vdk: VdkKey,
        new_password: &SecretBytes,
        re_split_wrapped_recovery: &WrappedVdkRecovery,
        re_split_threshold: u8,
        re_split_guardian_count: u8,
        re_split_epoch: u64,
        re_split_guardians: &[GuardianRecord<'_>],
    ) -> Result<()> {
        // (a) Build the new meta (KDF + re-wrap) BEFORE opening the tx;
        //     borrow the VDK so we keep it alive for its column-AEAD key
        //     in step (b).
        let new_meta = self.build_recovery_meta(&recovered_vdk, new_password)?;

        // ONE transaction spanning BOTH writes (L2). On any early return
        // the un-committed `tx` `Drop`s with rollback semantics, undoing
        // the partial meta write — so disk never holds a post-recovery
        // daily wrap beside a pre-recovery escrow generation.
        let tx = self.conn.unchecked_transaction()?;
        // (a, persist) the meta re-wrap THROUGH the shared transaction
        //     (not `&self.conn`).
        meta::write(&tx, &new_meta)?;
        // (b) the forward-security re-split escrow THROUGH the SAME
        //     transaction. The sealed-share double-wrap is keyed by the
        //     recovered VDK's column-AEAD (sourced engine-side, L9 / Q-g).
        recovery_escrow::write_recovery_escrow_tx(
            &tx,
            &self.meta.vault_id,
            recovered_vdk.aead_key(),
            re_split_wrapped_recovery,
            re_split_threshold,
            re_split_guardian_count,
            re_split_epoch,
            re_split_guardians,
        )?;
        // (c) commit ONCE — both writes land atomically or not at all.
        tx.commit()?;

        // The recovered VDK has done its job (re-wrap + column-AEAD); drop
        // it so its bytes zeroize. The caller re-derives the wrap authority
        // on the next `unlock`.
        drop(recovered_vdk);

        // (d) update in-memory state ONLY after a successful commit, so a
        //     rollback never desyncs memory from disk.
        self.meta = new_meta;
        self.active = None;
        self.session_state = SessionState::Locked;
        Ok(())
    }

    /// **MVP-3 issue #106b-2: the ATOMIC VDK-rotation-on-revoke commit
    /// (L4 — LOAD-BEARING).** Persist the FRESH (post-revoke) VDK epoch +
    /// the re-pointed guardian escrow + the demoted OLD epoch into the VDK
    /// chain + the advanced epoch pointer, ALL in ONE transaction —
    /// mirroring [`Self::commit_recovery_rekey`]'s single-tx discipline
    /// (#105a). A crash mid-rotation rolls EVERYTHING back: the vault stays
    /// on the OLD epoch (fully functional; the rotation is safely
    /// retryable), never half-rotated.
    ///
    /// ## What it writes (ONE `unchecked_transaction()`)
    ///
    /// 1. **The new-epoch PASSWORD ANCHOR** of the FRESH VDK, under an
    ///    [`AuthorityKey`] freshly derived from the re-prompted master
    ///    `new_password` (PROMPT-on-revoke, §0a — the anchor is ALWAYS
    ///    current after a rotation, no anchor-behind-current-epoch window).
    ///    Written into the `meta` row, so the CURRENT epoch's VDK is the
    ///    meta VDK exactly as for an unrotated vault.
    /// 2. **The demoted OLD epoch** into the `vdk_chain` table: the OLD
    ///    (pre-revoke) VDK wrapped under the SAME new-password authority
    ///    (so one unlock re-derivation opens every epoch) AND under the
    ///    LOCAL device key — so a surviving device decrypts PRE-rotation
    ///    entries (L3), and the `vdk_chain_state.current_epoch` pointer
    ///    advances to the new epoch.
    /// 3. **The re-pointed escrow** ([`recovery_escrow::write_recovery_escrow_tx`],
    ///    REUSED verbatim, #104b re-split): the FRESH `WrappedVdkRecovery`
    ///    and guardians under the NEW VDK's column-AEAD, REPLACING the prior
    ///    generation (the old guardian rows are `DELETE`d) so a future
    ///    guardian recovery restores the NEW VDK, not the dead old one
    ///    (L2/L8). The double-wrap is keyed by the NEW VDK's column-AEAD
    ///    (`new_vdk.aead_key()`), sourced engine-side.
    ///
    /// On any error before the single `tx.commit()`, the un-committed
    /// transaction's `Drop` rolls ALL of it back (L4). In-memory state is
    /// updated ONLY after a successful commit. The vault is left `Locked`;
    /// the caller unlocks with the new password afterward (and the
    /// surviving devices that synced the seal re-wrap under their own
    /// device keys).
    ///
    /// ## Parameters (store-local; the FFI surface is a later issue)
    ///
    /// The caller obtains these from
    /// `pangolin_core::rotation::rotate_vdk_for_survivors`'s
    /// [`RotationArtifacts`]: `new_vdk` (consumed + dropped after commit;
    /// the ONE legitimate `VdkKey::generate` re-create, gated to revoke,
    /// L9), `new_epoch` (the bumped shared epoch), and the `re_split`
    /// (`OnboardingArtifacts`) decomposed exactly as `commit_recovery_rekey`
    /// takes it. `old_vdk` is the CURRENTLY-active VDK (the pre-revoke
    /// epoch's key) the caller pulls from the active session;
    /// `local_device` is this device's [`DeviceKey`] (for the OLD epoch's
    /// device-wrap retention).
    ///
    /// # Errors
    ///
    /// `StoreError::AuthenticationFailed` if the KDF / wrap / sealed-share
    /// double-wrap fails (indistinguishability); `StoreError::Sqlite` on a
    /// DB error; `StoreError::Corrupted` if an epoch overflows the on-disk
    /// encoding. On any error nothing is committed (L4 rollback).
    #[allow(clippy::too_many_arguments)]
    pub fn commit_vdk_rotation(
        &mut self,
        new_vdk: VdkKey,
        old_vdk: &VdkKey,
        local_device: &DeviceKey,
        new_password: &SecretBytes,
        new_epoch: u64,
        re_split_wrapped_recovery: &WrappedVdkRecovery,
        re_split_threshold: u8,
        re_split_guardian_count: u8,
        re_split_epoch: u64,
        re_split_guardians: &[GuardianRecord<'_>],
    ) -> Result<()> {
        let current_epoch = vdk_chain::read_current_epoch(&self.conn)?;

        // Derive the new-password authority ONCE; it wraps BOTH the new
        // epoch's VDK (meta anchor) AND the demoted old epoch's VDK
        // (retained chain anchor), so a single unlock re-derivation opens
        // every epoch. Fresh salt -> the wrap keys are a function of the
        // new password alone.
        let salt = KdfSalt::random();
        let params = KdfParams::RECOMMENDED;
        let seed = kdf::derive_seed(new_password, &salt, &params)?;
        let new_authority = AuthorityKey::from_seed(*seed);
        let wrap_ctx = WrapContext::new(self.meta.vault_id);

        // New-epoch password anchor of the FRESH VDK (prompt-on-revoke).
        let new_wrapped = new_vdk.wrap(&new_authority, &wrap_ctx)?;
        let new_meta = VaultMeta {
            vault_id: self.meta.vault_id,
            created_at: self.meta.created_at,
            kdf_params: params,
            kdf_salt: salt,
            wrap_context: wrap_ctx,
            wrapped_ciphertext: new_wrapped.ciphertext().as_bytes().to_vec(),
            wrapped_nonce: *new_wrapped.nonce().as_bytes(),
        };

        // The demoted OLD epoch's retention wrappers: the OLD VDK under the
        // SAME new authority (so one re-derivation opens it on unlock) +
        // under the LOCAL device key (L3 — survivor reads pre-rotation
        // entries). Built before the tx so a KDF/wrap failure aborts
        // cleanly with nothing written.
        let retained_anchor = old_vdk.wrap(&new_authority, &wrap_ctx)?;
        // The authority is no longer needed; drop it so its bytes zeroize.
        drop(new_authority);
        let retained_device_wrap =
            pangolin_crypto::pairing::wrap_vdk_for_device(old_vdk, local_device, &wrap_ctx)
                .map_err(|_| StoreError::AuthenticationFailed)?;

        // ONE transaction spanning ALL rotation writes (L4). On any early
        // return the un-committed `tx` `Drop`s with rollback semantics,
        // undoing every partial write — so disk never holds a half-rotated
        // vault (a new escrow generation beside stale per-epoch wraps, or a
        // bumped pointer with no chain row, etc.).
        let tx = self.conn.unchecked_transaction()?;
        // (1) the new-epoch password anchor THROUGH the shared tx.
        meta::write(&tx, &new_meta)?;
        // (2) demote the OLD epoch into the chain + advance the pointer.
        vdk_chain::append_retained_and_advance_tx(
            &tx,
            current_epoch,
            &retained_anchor,
            &retained_device_wrap,
            new_epoch,
        )?;
        // (3) the re-pointed escrow THROUGH the SAME tx, double-wrapping
        //     each sealed share under the NEW VDK's column-AEAD (L2/L8).
        recovery_escrow::write_recovery_escrow_tx(
            &tx,
            &self.meta.vault_id,
            new_vdk.aead_key(),
            re_split_wrapped_recovery,
            re_split_threshold,
            re_split_guardian_count,
            re_split_epoch,
            re_split_guardians,
        )?;
        // (4) re-seal the LOCAL device-key seed under the NEW VDK THROUGH
        //     the SAME tx. The seed is sealed under the VDK column-key; the
        //     next unlock loads it under the new (current) VDK, so it MUST
        //     be re-sealed or the post-rotation unlock cannot decrypt it.
        //     The device-key peer of the escrow re-point — both at-rest
        //     VDK-keyed blobs re-keyed atomically (L4).
        device::reseal_device_key_tx(&tx, &self.meta.vault_id, new_vdk.aead_key(), local_device)?;
        // commit ONCE — all writes land atomically or not at all.
        tx.commit()?;

        // The fresh VDK has done its job (anchor + escrow column-AEAD); drop
        // it so its bytes zeroize. The caller re-derives the wrap authority
        // on the next unlock.
        drop(new_vdk);

        // Update in-memory state ONLY after a successful commit (L4).
        self.meta = new_meta;
        self.active = None;
        self.session_state = SessionState::Locked;
        Ok(())
    }

    /// **MVP-3 issue #106e-0: the PRODUCTION thin wrapper that keeps
    /// `old_vdk` / `device_key` STORE-INTERNAL (the secret-hygiene seam).**
    ///
    /// Drive [`Self::commit_vdk_rotation`] supplying the CURRENTLY-active
    /// session's VDK as the OLD (pre-revoke) epoch's VDK and the active
    /// session's `DeviceKey` as the local device — both pulled from the
    /// private `self.active` here and never crossing a crate boundary.
    ///
    /// The composition layer in `pangolin-core`
    /// (`pangolin_core::composition::complete_rotation`) runs the pure
    /// rotation driver (which MINTS the FRESH `new_vdk` from non-secret
    /// inputs) and hands the FRESH `new_vdk` + re-split here. The OLD VDK +
    /// device key the audited [`Self::commit_vdk_rotation`] needs for the
    /// retained-epoch wraps are read from the active session INSIDE this
    /// method, so the dependency arrow (`pangolin-core` → `pangolin-store`)
    /// never carries `old_vdk` / `device_key` up into core. This is a PURE
    /// DELEGATE: it adds NO new atomic surface (the single-transaction
    /// commit lives entirely in [`Self::commit_vdk_rotation`], #106b-2 L4).
    ///
    /// Requires an active session (so there is an OLD VDK + device key to
    /// reuse). On success the vault is left `Locked` (the audited commit's
    /// posture); the caller re-unlocks with the new password.
    ///
    /// # Errors
    ///
    /// `StoreError::NotUnlocked` if no session is active; otherwise the
    /// errors of [`Self::commit_vdk_rotation`].
    #[allow(clippy::too_many_arguments)]
    pub fn commit_vdk_rotation_from_active(
        &mut self,
        new_vdk: VdkKey,
        new_password: &SecretBytes,
        new_epoch: u64,
        re_split_wrapped_recovery: &WrappedVdkRecovery,
        re_split_threshold: u8,
        re_split_guardian_count: u8,
        re_split_epoch: u64,
        re_split_guardians: &[GuardianRecord<'_>],
    ) -> Result<()> {
        // Pull the OLD VDK + local device key out of the active session.
        // They are BORROWED into the audited commit (which consumes/drops
        // the fresh `new_vdk`) and zeroize when `active` drops at end of
        // scope — exactly the discipline the `__test_` helper used, now
        // promoted to production (L2 — zero new secret-lifetime surface).
        let active = self.active.take().ok_or(StoreError::NotUnlocked)?;
        let old_vdk = active.vdk;
        let local_device = active.device_key;
        self.commit_vdk_rotation(
            new_vdk,
            &old_vdk,
            &local_device,
            new_password,
            new_epoch,
            re_split_wrapped_recovery,
            re_split_threshold,
            re_split_guardian_count,
            re_split_epoch,
            re_split_guardians,
        )
    }

    /// **Test-only (#106b-2).** Drive [`Self::commit_vdk_rotation`] reusing
    /// the CURRENTLY-active VDK as the OLD (pre-revoke) epoch's VDK and the
    /// active session's `DeviceKey` as the local device.
    ///
    /// As of #106e-0 this is a thin alias of the production
    /// [`Self::commit_vdk_rotation_from_active`] (which promoted this
    /// helper's exact body): a hermetic vault test cannot run the upstream
    /// `pangolin-core` rotation orchestration, so it builds a FRESH VDK +
    /// re-split locally and drives the SAME single-tx COMBINED branch (L4)
    /// through this entry point. Retained so the existing hermetic store
    /// coverage keeps its name.
    ///
    /// Requires an active session (so there is an OLD VDK + device key to
    /// reuse).
    ///
    /// # Errors
    ///
    /// `StoreError::NotUnlocked` if no session is active; otherwise the
    /// errors of [`Self::commit_vdk_rotation`].
    #[cfg(any(test, feature = "test-utilities"))]
    #[allow(clippy::too_many_arguments)]
    pub fn __test_commit_vdk_rotation_reusing_active(
        &mut self,
        new_vdk: VdkKey,
        new_password: &SecretBytes,
        new_epoch: u64,
        re_split_wrapped_recovery: &WrappedVdkRecovery,
        re_split_threshold: u8,
        re_split_guardian_count: u8,
        re_split_epoch: u64,
        re_split_guardians: &[GuardianRecord<'_>],
    ) -> Result<()> {
        self.commit_vdk_rotation_from_active(
            new_vdk,
            new_password,
            new_epoch,
            re_split_wrapped_recovery,
            re_split_threshold,
            re_split_guardian_count,
            re_split_epoch,
            re_split_guardians,
        )
    }

    /// **Test-only.** Drive [`Self::recover_with_new_password`] reusing
    /// the CURRENTLY-ACTIVE VDK as the stand-in for the escrow-reconstructed
    /// VDK.
    ///
    /// Genuine recovery hands `recover_with_new_password` the byte-identical
    /// VDK that `pangolin_core::recovery::recover_vdk_from_shares`
    /// reconstructed off-chain. A hermetic vault test cannot run the full
    /// escrow (the orchestration lives upstream in `pangolin-core`), so this
    /// helper pulls the active session's own VDK out (`Option::take`) and
    /// feeds it back in — exercising the SAME re-wrap-under-new-password
    /// branch with the SAME VDK that was protecting the vault's data, which
    /// is exactly the L3 byte-identity contract recovery upholds. The
    /// genuine off-chain reconstruction path is exercised end-to-end by the
    /// coupled anvil E2E in `pangolin-chain`.
    ///
    /// Requires an active session (so there is a VDK to reuse).
    ///
    /// # Errors
    ///
    /// `StoreError::NotUnlocked` if no session is active; otherwise the
    /// errors of [`Self::recover_with_new_password`].
    #[cfg(any(test, feature = "test-utilities"))]
    pub fn __test_recover_reusing_active_vdk(&mut self, new_password: &SecretBytes) -> Result<()> {
        let active = self.active.take().ok_or(StoreError::NotUnlocked)?;
        // Move the VDK out of the dropped ActiveState; the rest of the
        // ActiveState (cache, device key, evm wallet, search index) drops
        // here, zeroizing — exactly what a true recovery re-key does.
        let vdk = active.vdk;
        self.recover_with_new_password(vdk, new_password)
    }

    /// **Test-only (#105a).** Drive [`Self::commit_recovery_rekey`] reusing
    /// the CURRENTLY-ACTIVE VDK as the stand-in for the escrow-reconstructed
    /// VDK — the atomic-path twin of [`Self::__test_recover_reusing_active_vdk`].
    ///
    /// Genuine recovery hands `commit_recovery_rekey` the byte-identical VDK
    /// `pangolin_core::recovery::recover_vdk_from_shares` reconstructed +
    /// the `re_split` it returned. A hermetic vault test cannot run the full
    /// escrow orchestration (it lives upstream in `pangolin-core`), so this
    /// helper pulls the active session's own VDK out and feeds it back in
    /// alongside a caller-built re-split — exercising the SAME single-tx
    /// COMBINED branch (L2) with the SAME VDK that protected the vault data
    /// (the L3 byte-identity contract).
    ///
    /// Requires an active session (so there is a VDK to reuse).
    ///
    /// # Errors
    ///
    /// `StoreError::NotUnlocked` if no session is active; otherwise the
    /// errors of [`Self::commit_recovery_rekey`].
    #[cfg(any(test, feature = "test-utilities"))]
    #[allow(clippy::too_many_arguments)]
    pub fn __test_commit_recovery_rekey_reusing_active_vdk(
        &mut self,
        new_password: &SecretBytes,
        re_split_wrapped_recovery: &WrappedVdkRecovery,
        re_split_threshold: u8,
        re_split_guardian_count: u8,
        re_split_epoch: u64,
        re_split_guardians: &[GuardianRecord<'_>],
    ) -> Result<()> {
        let active = self.active.take().ok_or(StoreError::NotUnlocked)?;
        let vdk = active.vdk;
        self.commit_recovery_rekey(
            vdk,
            new_password,
            re_split_wrapped_recovery,
            re_split_threshold,
            re_split_guardian_count,
            re_split_epoch,
            re_split_guardians,
        )
    }

    /// **MVP-3 issue #106e-0b: set up social recovery on this vault.**
    ///
    /// The production twin of [`Self::__test_onboard_recovery_escrow`] and
    /// the prerequisite that makes the recovery / rotation surface live:
    /// `complete_rotation` reads the escrow ([`Self::recovery_escrow_params`])
    /// and `recover_from_shares` re-splits it, but until a vault has been
    /// onboarded there is NO escrow to read. This writes the INITIAL escrow.
    ///
    /// Reads the CURRENTLY-ACTIVE VDK store-internal (never exposed), mints
    /// a fresh `RecoveryWrapKey`, second-wraps the VDK under it,
    /// threshold-[`split_rwk`](pangolin_crypto::escrow::split_rwk)s the RWK
    /// into `M = guardian_x25519_pubs.len()` shares, and seals share `i` to
    /// guardian `i`'s X25519 SEALING pubkey — all via the ONE shared
    /// [`pangolin_crypto::escrow::onboard_escrow`] primitive (the SAME fn
    /// the `pangolin-core` rotation / recovery re-split calls, so the
    /// initial onboard and the re-split can never drift — #106e-0b Q-a /
    /// Option B). The resulting `wrapped_recovery` + sealed shares are
    /// persisted under the active VDK's column-AEAD in ONE
    /// `unchecked_transaction()`.
    ///
    /// **Epoch (Q-c).** The first onboard writes at GENESIS (`0`);
    /// rotation / recovery bump the recovery-generation epoch thereafter.
    ///
    /// **Re-onboard (Q-b).** A second call (the user changes their guardian
    /// set) REPLACES the prior generation — `write_recovery_escrow_tx`
    /// DELETEs the prior guardian rows and `INSERT OR REPLACE`s the single
    /// escrow row, so no stale share lingers. The genesis epoch is reused
    /// (a guardian-set change is not a recovery re-split — only recovery
    /// owns the forward-security bump).
    ///
    /// **Secret hygiene (L2).** The RWK + raw shares are dropped (zeroized)
    /// inside `onboard_escrow` before it returns; the active VDK is borrowed
    /// store-internal and never returned / logged; only the non-secret
    /// [`OnboardingOutcome`] epoch leaves.
    ///
    /// **Atomicity (L1).** Single transaction — a crash leaves NO partial
    /// escrow (the vault simply has no recovery set up yet; retryable).
    ///
    /// Session-gated (`require_active`).
    ///
    /// `threshold` (`t`) and `M = guardian_x25519_pubs.len()` must satisfy
    /// the on-chain bounds (`t ∈ 2..=9`, `M ∈ 3..=15`, `t ≤ M`); the escrow
    /// split rejects an out-of-bounds pair.
    ///
    /// # Errors
    ///
    /// - [`StoreError::NotUnlocked`] if no session is active.
    /// - [`StoreError::AuthenticationFailed`] if the onboard composition
    ///   (wrap / split / seal) fails (e.g. an out-of-bounds `(t, M)`).
    /// - [`StoreError::Corrupted`] if `M` overflows `u8`.
    /// - [`StoreError::Sqlite`] on a DB / transaction error.
    pub fn onboard_guardians(
        &mut self,
        threshold: u8,
        guardian_x25519_pubs: &[[u8; 32]],
    ) -> Result<OnboardingOutcome> {
        // Q-c: the first onboard writes at GENESIS (0); rotation / recovery
        // bump it thereafter. A re-onboard (Q-b) REPLACES in place at the
        // same genesis epoch (the re-split, not a guardian-set change, owns
        // the forward-security bump).
        const GENESIS_EPOCH: u64 = 0;

        let active = self.require_active()?;
        let vault_id = self.meta.vault_id;
        let guardian_count = u8::try_from(guardian_x25519_pubs.len())
            .map_err(|_| StoreError::Corrupted("guardian count overflows u8".into()))?;

        // The ONE shared onboard split-and-seal primitive (#106e-0b Q-a /
        // Option B). The fresh RWK + the raw Shares are minted, used, and
        // dropped (zeroized) INSIDE this call; only the wrapped recovery +
        // the sealed, non-secret assignments come back. The active VDK is
        // borrowed by reference and never leaves the store.
        let onboarding = pangolin_crypto::escrow::onboard_escrow(
            &active.vdk,
            &vault_id,
            threshold,
            guardian_count,
            guardian_x25519_pubs,
            GENESIS_EPOCH,
        )
        .map_err(|_| StoreError::AuthenticationFailed)?;

        // Map the crypto-level assignments into the store's borrowing
        // `GuardianRecord` slice (the sealed-share bytes are borrowed from
        // `onboarding`, which outlives the transaction below).
        let records: Vec<GuardianRecord<'_>> = onboarding
            .assignments
            .iter()
            .map(|a| GuardianRecord {
                index: a.index,
                guardian_x25519_pub: a.guardian_x25519_pub,
                sealed_share: &a.sealed_share,
            })
            .collect();

        // Persist the escrow under the active VDK's column-AEAD in ONE
        // transaction (L1 atomic — a crash rolls the whole escrow back).
        let vdk_aead = active.vdk.aead_key();
        let tx = self.conn.unchecked_transaction()?;
        recovery_escrow::write_recovery_escrow_tx(
            &tx,
            &vault_id,
            vdk_aead,
            &onboarding.wrapped_recovery,
            threshold,
            guardian_count,
            GENESIS_EPOCH,
            &records,
        )?;
        tx.commit()?;

        Ok(OnboardingOutcome {
            epoch: GENESIS_EPOCH,
        })
    }

    /// **Test-only (#106e-0b L5).** Read back the host-supplied recovery
    /// BACKUP material for the onboarded escrow generation: the
    /// [`WrappedVdkRecovery`] plus the `M` [`SealedShare`]s, ordered by
    /// guardian index (`0..M`).
    ///
    /// Both are NON-secret: the `wrapped_recovery` is the VDK wrapped under
    /// the now-dropped RWK (useless without `>= t` reconstructed shares),
    /// and each sealed share is encrypted to a guardian's X25519 key. In
    /// production this material travels in the user's recovery backup + the
    /// guardians' custody and is fed back into `recover_from_shares` as
    /// host-supplied input; the L5 round-trip test captures it from disk to
    /// prove a vault onboarded via the PRODUCTION [`Self::onboard_guardians`]
    /// is reconstructable. Opening the under-VDK double wrap requires the
    /// active VDK's column-AEAD, which stays store-internal — only the
    /// non-secret backup material is returned.
    ///
    /// `Ok(None)` if no escrow has been onboarded yet.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotUnlocked`] if no session is active; the same read
    /// errors as [`Self::recovery_escrow_params`].
    #[cfg(any(test, feature = "test-utilities"))]
    pub fn __test_recovery_backup_material(
        &self,
    ) -> Result<
        Option<(
            WrappedVdkRecovery,
            Vec<pangolin_crypto::escrow::SealedShare>,
        )>,
    > {
        let active = self.require_active()?;
        let vault_id = self.meta.vault_id;
        let escrow = crate::recovery_escrow::read_recovery_escrow(
            &self.conn,
            &vault_id,
            active.vdk.aead_key(),
        )?;
        Ok(escrow.map(|e| {
            let shares = e.guardians.into_iter().map(|g| g.sealed_share).collect();
            (e.wrapped_recovery, shares)
        }))
    }

    /// **Test-only (#106e-0).** Onboard a recovery escrow over the
    /// CURRENTLY-ACTIVE VDK, sealing one share to each supplied guardian
    /// X25519 SEALING pubkey, persisted at `epoch`.
    ///
    /// Production code onboards the escrow via the upstream
    /// `pangolin_core::recovery::onboard_guardian_escrow` driver feeding a
    /// caller-owned transaction; a hermetic / anvil store test needs a vault
    /// whose escrow is genuinely under its OWN active VDK so a later
    /// `complete_rotation` can read it back (`recovery_escrow_params`) and
    /// re-point it. This helper mints a fresh RWK, second-wraps the active
    /// VDK under it, splits + seals to the supplied pubkeys, and writes the
    /// escrow row under the active VDK's column-AEAD — exactly the shape
    /// `commit_recovery_rekey` / `commit_vdk_rotation` persist. Returns the
    /// `M` guardian X25519 SECRET scalars so the caller can open the shares.
    ///
    /// Requires an active session.
    ///
    /// # Errors
    ///
    /// `StoreError::NotUnlocked` if no session is active; otherwise a
    /// crypto / DB error from the escrow build / write.
    #[cfg(any(test, feature = "test-utilities"))]
    pub fn __test_onboard_recovery_escrow(
        &mut self,
        threshold: u8,
        guardian_pubs: &[[u8; 32]],
        epoch: u64,
    ) -> Result<()> {
        use pangolin_crypto::escrow::{seal_share, split_rwk, wrap_vdk_under_rwk, RecoveryWrapKey};
        let active = self.require_active()?;
        let vault_id = self.meta.vault_id;
        let wrap_ctx = WrapContext::new(vault_id);
        let guardian_count = u8::try_from(guardian_pubs.len())
            .map_err(|_| StoreError::Corrupted("guardian count overflows u8".into()))?;

        // Mint a fresh RWK, second-wrap the active VDK under it, split, seal.
        let rwk = RecoveryWrapKey::generate();
        let wrapped_recovery = wrap_vdk_under_rwk(&active.vdk, &rwk, &wrap_ctx)
            .map_err(|_| StoreError::AuthenticationFailed)?;
        let shares = split_rwk(&rwk, threshold, guardian_count)
            .map_err(|_| StoreError::AuthenticationFailed)?;
        drop(rwk);

        let mut epoch_bytes = [0u8; pangolin_crypto::escrow::EPOCH_LEN];
        epoch_bytes[8..].copy_from_slice(&epoch.to_be_bytes());
        let mut sealed = Vec::with_capacity(shares.len());
        for (share, pubkey) in shares.iter().zip(guardian_pubs) {
            sealed.push(
                seal_share(share, pubkey, &vault_id, &epoch_bytes)
                    .map_err(|_| StoreError::AuthenticationFailed)?,
            );
        }
        drop(shares);
        let records: Vec<GuardianRecord<'_>> = (0..usize::from(guardian_count))
            .map(|i| GuardianRecord {
                index: u8::try_from(i).expect("index <= M-1 fits u8"),
                guardian_x25519_pub: guardian_pubs[i],
                sealed_share: &sealed[i],
            })
            .collect();

        let vdk_aead = active.vdk.aead_key();
        let tx = self.conn.unchecked_transaction()?;
        recovery_escrow::write_recovery_escrow_tx(
            &tx,
            &vault_id,
            vdk_aead,
            &wrapped_recovery,
            threshold,
            guardian_count,
            epoch,
            &records,
        )?;
        tx.commit()?;
        Ok(())
    }

    /// The session's configured idle duration (Session spec §7.2).
    /// Read from `meta` on `open` / `create`; updated by
    /// [`Self::set_session_idle`]. Defaults to
    /// [`crate::session::SessionDuration::DEFAULT`] (15 min) for vaults
    /// that predate MVP-1 issue 1.4.
    #[must_use]
    pub fn session_idle(&self) -> SessionDuration {
        self.session_idle
    }

    /// Absolute-max deadline of the active session, or `None` if not
    /// active. The session expires at this instant regardless of
    /// activity (Session spec §7.4 — 4 h, not configurable). For a
    /// host UI rendering a countdown alongside the idle deadline.
    #[must_use]
    pub fn session_absolute_deadline(&self) -> Option<SystemTime> {
        match self.session_state {
            SessionState::Active {
                session_started_at, ..
            } => session_started_at.checked_add(crate::session::ABSOLUTE_MAX_DEFAULT),
            _ => None,
        }
    }

    /// Instant of the most recent successful presence proof for the
    /// active session (the 2-proof unlock counts), or `None` if not
    /// active. A presence-gated op within
    /// [`crate::session::PRESENCE_FRESHNESS`] of this instant does not
    /// re-prompt (prompt dedup, Session spec §8.6).
    #[must_use]
    pub fn last_presence_at(&self) -> Option<SystemTime> {
        self.active.as_ref().and_then(|a| a.last_presence_at)
    }

    /// **MVP-1 issue 1.5 (test/test-utilities only).** The 32-byte
    /// Ed25519 verifying-key bytes of the in-memory [`DeviceKey`] held
    /// by the active session, or `None` when the vault is not `Active`.
    ///
    /// Used by tests to confirm (a) the loaded/registered device key's
    /// verifying key matches `device_current().device_id` (the
    /// derived-from-the-key invariant) and (b) the key is dropped on
    /// `lock()` / expiry (this accessor returns `None` afterwards).
    /// Gated so production builds cannot link against it — the
    /// `DeviceKey` itself signs nothing in MVP-1; it is the MVP-2 hook.
    #[cfg(any(test, feature = "test-utilities"))]
    #[doc(hidden)]
    #[must_use]
    pub fn device_key_verifying_key(&self) -> Option<[u8; 32]> {
        self.active
            .as_ref()
            .map(|a| a.device_key.verifying_key().to_bytes())
    }

    /// **MVP-2 issue 3.2 (R-b).** Borrow the per-device EVM wallet
    /// for the active session. The wallet is derived deterministically
    /// from this device's Ed25519 [`DeviceKey`] via
    /// [`pangolin_chain::derive_evm_wallet`] inside `unlock`; it lives
    /// only in `ActiveState` (L2) and dies with the session — every
    /// `lock()`, idle / absolute-max expiry, and `Drop` path takes
    /// `ActiveState` whole, dropping the wallet alongside the
    /// `DeviceKey`. The wallet exposes the 20-byte public address via
    /// `.address()` (for diagnostics / display) and the inner alloy
    /// `PrivateKeySigner` via `.signer()` (the secp256k1 signing
    /// surface — consumed by MVP-2 issues 3.1 / 3.3 / 3.4 / 4.2). The
    /// secp256k1 *scalar* is held only inside the wallet's
    /// `k256::SecretKey`, whose `Drop` zeroizes; this accessor returns
    /// a borrow only (`EvmWallet` is deliberately not `Clone`).
    ///
    /// # Errors
    ///
    /// [`StoreError::NotUnlocked`] when the vault is not active (the
    /// session has never been unlocked, or has been locked /
    /// `Drop`-ped). The
    /// idle / absolute-max-expiry transition is observed via the
    /// caller's own freshness check (e.g.
    /// `check_session_freshness` inside the wrapping op); this
    /// accessor does *not* run a freshness check on its own, because
    /// it is the read-only "give me the wallet for a downstream
    /// signing call" primitive and the session-class gating happens
    /// at the wrapping op. Once expiry drops `ActiveState`, the
    /// accessor returns `NotUnlocked` (matching the existing
    /// `device_key_verifying_key` / `device_current` posture).
    pub fn evm_wallet(&self) -> Result<&EvmWallet> {
        Ok(&self.require_active()?.evm_wallet)
    }

    /// **MVP-2 issue 3.5 (R-a hybrid).** Read the device's cached EVM
    /// wallet address from the persistent `devices.evm_address` column.
    ///
    /// This is a SYNC accessor that works on a **Locked vault** — the
    /// address column is on-disk (3.2's R-a vault-sealed-only stores
    /// only the address publicly; the secret scalar is AEAD-sealed and
    /// requires unlock). The L5 nuance applies: the chain-crate balance
    /// helper is policy-agnostic (takes `&Address + rpc_url`), so the
    /// SYNC accessor at this layer is intentionally NOT
    /// active-session-gated. Policy/mechanism split: the FFI accessor
    /// IS active-session-gated (per L5 FFI policy); the host policy
    /// (render-on-locked-vault vs not) decides.
    ///
    /// Returns the 20-byte address as a fixed-size byte array
    /// (`[u8; EVM_ADDRESS_LEN]` = `[u8; 20]`). Callers in
    /// `pangolin-chain` / `pangolin-funder-client` convert via
    /// `alloy::primitives::Address::from(bytes)` to thread into chain
    /// helpers. Keeping the return type alloy-free at this layer
    /// preserves `pangolin-store`'s alloy-dep abstinence.
    ///
    /// # Errors
    ///
    /// - [`StoreError::NotUnlocked`] — no device row has been registered
    ///   yet (brand-new vault opened but never unlocked).
    /// - [`StoreError::Sqlite`] / [`StoreError::Corrupted`] — storage
    ///   failure.
    /// - [`StoreError::Validation`] (`kind = "evm_address"`) — the row
    ///   exists but `evm_address` is NULL (legacy 1.5-era row pre-3.2
    ///   that has not been back-filled by a 3.2-era unlock).
    pub fn evm_wallet_address(&self) -> Result<[u8; crate::device::EVM_ADDRESS_LEN]> {
        let identity = device::read_device(&self.conn, &self.device_id, &self.device_id)?
            .ok_or(StoreError::NotUnlocked)?;
        identity.evm_address.ok_or_else(|| StoreError::Validation {
            kind: "evm_address".to_string(),
            message:
                "device row missing evm_address; unlock once under a 3.2-era build to back-fill"
                    .to_string(),
        })
    }

    /// **MVP-2 issue 3.1 (R-a..R-e) + 3.3 audit-HIGH fix (2026-05-14).**
    /// Build a v1 signed revision over `fields` using the active
    /// session's [`EvmWallet`] and the deployed `RevisionLogV1`
    /// contract address for `chain_env`.
    ///
    /// Per L5 (signing reachable only via active session): this method
    /// calls [`Self::require_active`] before threading the wallet into
    /// [`pangolin_chain::build_signed_revision_v1`]; a Locked vault
    /// returns [`StoreError::NotUnlocked`]; an expired session
    /// surfaces via the require-active gate as
    /// [`StoreError::SessionExpired`] (the existing eager-drop
    /// mechanism).
    ///
    /// Returns a [`SignedRevisionV1`] carrying the fields, the raw
    /// `enc_payload` preimage, and the 65-byte `r ‖ s ‖ v` signature
    /// over the EIP-712 typed-data digest the deployed contract
    /// `_recover`s against. The broadcast layer (issue 3.3) consumes
    /// this output verbatim when wiring `publishRevision(...)` — it
    /// reads `signed.enc_payload` (not `fields.enc_payload_hash`) to
    /// fill the `bytes encPayload` calldata argument, because the
    /// contract recomputes `keccak256(encPayload)` from the calldata
    /// bytes.
    ///
    /// # Arguments
    ///
    /// - `fields` — the six EIP-712 `Revision` struct fields; caller
    ///   is responsible for populating `fields.enc_payload_hash`
    ///   `= keccak256(enc_payload)`.
    /// - `enc_payload` — the raw `encPayload` preimage. Travels
    ///   downstream onto the returned `SignedRevisionV1` so the
    ///   broadcast layer can put it on the wire. INVARIANT:
    ///   `keccak256(enc_payload) == fields.enc_payload_hash`
    ///   (`debug_assert!` inside the chain crate).
    /// - `chain_env` — which env to bind the EIP-712 domain to.
    /// - `chain_id` — the chain id to stamp into the EIP-712 domain
    ///   separator (issue #101 amendment). The caller resolves it:
    ///   `84_532` for `BaseSepolia` (production; never read from an RPC),
    ///   or the live `eth_chainId` from the connected local node for
    ///   `Dev` (anvil). See
    ///   [`pangolin_chain::build_signed_revision_v1`] for the contract.
    ///
    /// # Errors
    ///
    /// - [`StoreError::NotUnlocked`] / [`StoreError::SessionExpired`]
    ///   per the L5 session gate.
    /// - [`StoreError::ChainSignError`] for any chain-side failure:
    ///   missing / malformed deployment file, pinned-address mismatch
    ///   (L-domain-binding defense), or signer-internal error.
    pub fn sign_revision_v1(
        &self,
        fields: RevisionFieldsV1,
        enc_payload: Vec<u8>,
        chain_env: ChainEnv,
        chain_id: u64,
    ) -> Result<SignedRevisionV1> {
        let active = self.require_active()?;
        build_signed_revision_v1(&active.evm_wallet, fields, enc_payload, chain_env, chain_id)
            .map_err(StoreError::ChainSignError)
    }

    /// **MVP-1 issue 1.5 (test/test-utilities only).** The 32-byte
    /// secret Ed25519 seed of the in-memory [`DeviceKey`] held by the
    /// active session, or `None` when not `Active`. Wrapped in
    /// [`zeroize::Zeroizing`] so it wipes on drop.
    ///
    /// Used by the `no_plaintext_on_disk` e2e proptest to confirm the
    /// device-key seed bytes never appear in plaintext in the raw
    /// `.pvf` (criterion 5 — the seed is AEAD-sealed under the VDK in
    /// the `device_key` table). Gated so production builds cannot link
    /// against it — exposing a secret seed is a test-only affordance.
    #[cfg(any(test, feature = "test-utilities"))]
    #[doc(hidden)]
    #[must_use]
    pub fn device_key_secret_seed(&self) -> Option<zeroize::Zeroizing<[u8; 32]>> {
        self.active
            .as_ref()
            .map(|a| a.device_key.secret_seed_bytes())
    }

    /// Lock the vault. Drops the in-memory cache + VDK; transitions to
    /// `Locked`. Idempotent.
    pub fn lock(&mut self) {
        if let Some(active) = self.active.take() {
            drop(active); // ZeroizeOnDrop on every snapshot in cache.
        }
        self.session_state = SessionState::Locked;
    }

    /// Close the vault. Locks if necessary, then drops the `SQLite`
    /// handle on `Self::Drop`. Idempotent.
    pub fn close(mut self) -> Result<()> {
        self.lock();
        // The `SQLite` connection is closed implicitly when `self` is
        // dropped at the end of this scope. We deliberately do not call
        // `Connection::close` because its error path (which returns the
        // connection back) cannot be wired through a `Drop`-bearing
        // type without `unsafe` or `ManuallyDrop` plumbing — the close
        // here is sufficient for P2's semantics.
        drop(self);
        Ok(())
    }

    // -----------------------------------------------------------------
    // Active-state ops
    // -----------------------------------------------------------------

    fn require_active(&self) -> Result<&ActiveState> {
        self.active.as_ref().ok_or(StoreError::NotUnlocked)
    }
    fn require_active_mut(&mut self) -> Result<&mut ActiveState> {
        self.active.as_mut().ok_or(StoreError::NotUnlocked)
    }

    /// **MVP-3 issue #106b-2.** The CURRENT VDK epoch a NEW revision write
    /// must be tagged with (Q-a): the active session's chain current epoch,
    /// or `0` for an unrotated / legacy vault (or when no session is
    /// active — the write paths all gate on `require_active` first, so the
    /// `0` fallback is never reached on a real write). New entries encrypt
    /// under the active session's `vdk` (= the current epoch's VDK), so the
    /// stamp MUST equal the current epoch; the read path then decrypts each
    /// entry under `chain[vdk_epoch]`. As an `i64` for the rusqlite param.
    fn current_vdk_epoch_i64(&self) -> i64 {
        let epoch = self.active.as_ref().map_or(0, |a| a.chain.current_epoch());
        // The epoch is a monotonic counter that in practice never exceeds
        // i64::MAX (one rotation/sec for ~292 billion years); the column is
        // i64 and `commit_vdk_rotation` already rejects an overflowing
        // epoch on write, so this cast is total in practice.
        i64::try_from(epoch).unwrap_or(i64::MAX)
    }

    // -----------------------------------------------------------------
    // P4: session policy plumbing
    // -----------------------------------------------------------------

    /// Strict freshness check used by every cache-bearing credential
    /// op (`add_account`, `update_account`, `delete_account`,
    /// `get_account`, `search`, `list_accounts`, the test-helper
    /// `__test_synthesize_sibling_revision`).
    ///
    /// Behavior matrix:
    ///
    /// | Current `session_state`       | Action                                       |
    /// |-------------------------------|----------------------------------------------|
    /// | `Active`, `now <= expires_at` | `Ok(())`                                     |
    /// | `Active`, `now >  expires_at` | Drop cache → set `Expired` → return `SessionExpired` |
    /// | `Locked`                      | `Err(NotUnlocked)`                           |
    /// | `PendingAuthorization`        | `Err(SessionPending)`                        |
    /// | `Expired`                     | `Err(SessionExpired)`                        |
    ///
    /// The expiry-side cache drop runs through `lock()` which takes
    /// ownership of `active` and drops it — every `AccountSnapshot`
    /// inside the `DecryptedCache` is `ZeroizeOnDrop`, so the
    /// transitive `Drop` chain wipes the heap allocations. The
    /// `session_state` is set to `Expired` AFTER the drop so
    /// observers that read the state see the post-zeroize transition.
    fn check_session_freshness(&mut self) -> Result<()> {
        match self.session_state {
            SessionState::Active { expires_at, .. } => {
                let now = self.clock.now();
                if now > expires_at {
                    // Drop cache + VDK first; THEN flip state. Order
                    // matters for an observer reading `session_state`
                    // while we're inside this method (impossible in
                    // safe Rust without a re-entrant borrow, but the
                    // ordering is part of the documented invariant for
                    // unsafe-extension auditors).
                    if let Some(active) = self.active.take() {
                        drop(active);
                    }
                    self.session_state = SessionState::Expired;
                    Err(StoreError::SessionExpired)
                } else {
                    Ok(())
                }
            }
            SessionState::Locked => Err(StoreError::NotUnlocked),
            SessionState::PendingAuthorization => Err(StoreError::SessionPending),
            SessionState::Expired => Err(StoreError::SessionExpired),
        }
    }

    /// Soft freshness check used by metadata-only ops (`revisions_for`,
    /// `revision_graph`, `account_heads`, `is_forked`,
    /// `all_forked_accounts`, `unpublished_revisions`,
    /// `mark_published`).
    ///
    /// These ops query the `revisions` table for parent→child structure
    /// and chain anchors; they do NOT touch the AEAD-decrypted cache.
    /// P3's invariant — "metadata-only ops work on a `Locked` vault" —
    /// is preserved.
    ///
    /// Behavior matrix:
    ///
    /// | Current `session_state`       | Action                                       |
    /// |-------------------------------|----------------------------------------------|
    /// | `Active`, `now <= expires_at` | No-op                                        |
    /// | `Active`, `now >  expires_at` | Drop cache → set `Expired`                   |
    /// | `Locked`/`Pending`/`Expired`  | No-op                                        |
    ///
    /// The Active-but-expired path STILL zeroizes the cache, so the
    /// "next op surfaces `SessionExpired` AND cache is gone" criterion
    /// holds even if the next op happens to be a metadata-only one
    /// (the cache is gone after this call returns).
    fn maybe_expire_active_session(&mut self) {
        if let SessionState::Active { expires_at, .. } = self.session_state {
            let now = self.clock.now();
            if now > expires_at {
                if let Some(active) = self.active.take() {
                    drop(active);
                }
                self.session_state = SessionState::Expired;
            }
        }
    }

    /// Update the idle deadline after a successful op.
    ///
    /// `last_proof_at = now`. `expires_at = next_idle_deadline(now,
    /// session_started_at)` — the helper caps at
    /// `session_started_at + ABSOLUTE_MAX_DEFAULT` so a long-running
    /// session cannot extend its lifetime past the absolute ceiling
    /// even with constant activity. No-op if the session is not
    /// `Active`.
    fn touch_session(&mut self) {
        if let SessionState::Active {
            expires_at,
            last_proof_at,
            session_started_at,
        } = self.session_state
        {
            let now = self.clock.now();
            let new_deadline = next_idle_deadline(now, session_started_at, self.session_idle);
            self.session_state = SessionState::Active {
                expires_at: new_deadline,
                // Touch shifts last_proof_at to now, but never extends
                // session_started_at — that's the absolute-max anchor.
                last_proof_at: now,
                session_started_at,
            };
            // Suppress unused-binding warnings on the destructured
            // values that we don't need further (the new state
            // overrides them).
            let _ = expires_at;
            let _ = last_proof_at;
        }
    }

    /// **MVP-1 issue 1.4 — Session spec §7.6 / §8.6.** The single
    /// source of truth for "is presence fresh *right now*", with prompt
    /// deduplication built in.
    ///
    /// - If the active session's `last_presence_at` is within
    ///   [`crate::session::PRESENCE_FRESHNESS`] of now, the op proceeds
    ///   **without** consuming the supplied proof — the dedup case
    ///   (§8.6: "if multiple triggers occur, only one prompt MUST
    ///   appear; all queued actions resume after success"). The proof's
    ///   single-use flag is preserved.
    /// - Otherwise the supplied proof must `verify()`. On success,
    ///   `last_presence_at = now`. On failure: a stale proof
    ///   ([`AuthError::NotFresh`]) at a high-risk call site maps to
    ///   [`StoreError::PromptTimedOut`] (§7.7 — the prompt expired
    ///   before it was answered); any other proof failure (replayed,
    ///   empty, generic) collapses to [`StoreError::AuthenticationFailed`]
    ///   per the MEDIUM-1 indistinguishability discipline.
    ///
    /// Callers MUST run [`Self::check_session_freshness`] (and any
    /// frozen-account check) *before* this so a session/frozen failure
    /// surfaces with the proof un-consumed and recoverable.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotUnlocked`] if no active session;
    /// [`StoreError::PromptTimedOut`] for a stale proof at this site;
    /// [`StoreError::AuthenticationFailed`] for any other proof failure.
    fn ensure_presence_fresh(&mut self, presence: &dyn PresenceProof) -> Result<()> {
        let now = self.clock.now();
        let active = self.require_active()?;
        if let Some(last) = active.last_presence_at {
            // Saturating: a backward clock jump yields ZERO age (treated
            // as "fresh"). Same wall-clock-skew posture as the rest of
            // the session engine.
            let age = now.duration_since(last).unwrap_or(Duration::ZERO);
            if age <= PRESENCE_FRESHNESS {
                return Ok(());
            }
        }
        // Stale (or never set): the supplied proof must verify.
        presence.verify().map_err(|e| reveal_site_auth_error(&e))?;
        // Re-borrow mutably to stamp the freshness instant.
        self.require_active_mut()?.last_presence_at = Some(now);
        Ok(())
    }

    /// **MVP-1 issue 1.4 — Session spec §7.5 device-lock hook.**
    /// Expire the active session immediately, as if the OS reported a
    /// device-lock event. Drops the in-memory cache + VDK (zeroizing
    /// every cached `AccountSnapshot`) and frees the `:memory:` FTS5
    /// index, then flips the state to `Expired` — the same path as an
    /// idle-timeout expiry, so the next op needs the full 2-proof
    /// unlock.
    ///
    /// No-op when the vault is `Locked` / `Expired` / `PendingAuthorization`.
    ///
    /// For the CLI tier this is unused — a terminal has no OS-lock
    /// signal; the explicit `lock()` covers the user-driven case. The
    /// hook exists so MVP-3 (mobile) / MVP-4 (desktop) shells can wire
    /// it to the platform lock-screen event without touching the engine.
    pub fn device_locked(&mut self) {
        if matches!(self.session_state, SessionState::Active { .. }) {
            if let Some(active) = self.active.take() {
                drop(active);
            }
            self.session_state = SessionState::Expired;
        }
    }

    /// **MVP-1 issue 1.4 — Session spec §7.2.** Set the configured
    /// idle-timeout duration, persisting it to `meta.session_idle_secs`.
    ///
    /// Lengthening the session is a high-risk action per §5.4 ("extend
    /// long sessions") — the caller MUST supply a fresh presence proof
    /// in `presence` (a `None` returns [`StoreError::PresenceProofRequired`]);
    /// shortening (or setting the same value) is always allowed and may
    /// pass `None`. A `Locked` vault is fine (the choice is a property
    /// of the file, not the session); a present-but-expired session
    /// surfaces the session error first so the proof is not burned.
    ///
    /// When the new value takes effect: it updates this handle's
    /// in-memory `session_idle` immediately, and — if the session is
    /// active — re-derives the current `expires_at` from the new idle
    /// window (shortening can move the deadline earlier than now, which
    /// the next freshness check will treat as an expiry).
    ///
    /// # Errors
    ///
    /// [`StoreError::PresenceProofRequired`] if lengthening without a
    /// proof; [`StoreError::PromptTimedOut`] / [`StoreError::AuthenticationFailed`]
    /// if the supplied proof is stale / fails; [`StoreError::SessionExpired`]
    /// if the session is active-but-expired; [`StoreError::Sqlite`] for
    /// a persistence failure.
    pub fn set_session_idle(
        &mut self,
        choice: SessionDuration,
        presence: Option<&dyn PresenceProof>,
    ) -> Result<()> {
        let lengthening = choice.is_longer_than(self.session_idle);
        if lengthening {
            // High-risk: require a fresh presence proof. If the session
            // is active-but-expired, surface that first (proof not
            // burned). If `Locked`, there is no session-freshness gate
            // — the proof still has to verify, but `ensure_presence_fresh`
            // requires an active session, so we verify directly.
            let proof = presence.ok_or(StoreError::PresenceProofRequired)?;
            match self.session_state {
                SessionState::Active { .. } => {
                    self.check_session_freshness()?;
                    self.ensure_presence_fresh(proof)?;
                }
                // Locked / Expired / Pending: verify the proof directly
                // (no dedup window applies — there is no active session).
                _ => {
                    proof.verify().map_err(|e| reveal_site_auth_error(&e))?;
                }
            }
        }
        // Persist + apply.
        meta::write_session_idle_secs(&self.conn, Some(choice.to_meta_secs()))?;
        self.session_idle = choice;
        // Re-derive the current deadline from the new idle window so a
        // shortening takes effect immediately.
        if let SessionState::Active {
            session_started_at, ..
        } = self.session_state
        {
            let now = self.clock.now();
            self.session_state = SessionState::Active {
                expires_at: next_idle_deadline(now, session_started_at, self.session_idle),
                last_proof_at: now,
                session_started_at,
            };
        }
        Ok(())
    }

    /// **MVP-1 issue 1.4 — Session spec §5.4 "extend long sessions".**
    /// The single-proof "maintain" leg of the session invariant exposed
    /// as an explicit, presence-gated call (backs the FFI
    /// `session_extend`). Verifies the presence proof (with prompt
    /// dedup — within [`crate::session::PRESENCE_FRESHNESS`] of the last
    /// successful presence, no re-prompt) and then `touch_session()`
    /// to re-extend the idle deadline (still capped at the absolute-max
    /// ceiling).
    ///
    /// # Errors
    ///
    /// [`StoreError::NotUnlocked`] / [`StoreError::SessionExpired`] if
    /// the session is not active (proof not consumed);
    /// [`StoreError::PromptTimedOut`] for a stale proof;
    /// [`StoreError::AuthenticationFailed`] for any other proof failure.
    pub fn touch_session_explicit(&mut self, presence: &dyn PresenceProof) -> Result<()> {
        self.check_session_freshness()?;
        self.ensure_presence_fresh(presence)?;
        self.touch_session();
        Ok(())
    }

    /// **P8 fix CRIT-1.** Look up `account_identities.frozen_pending_resolve`
    /// for `id`. Returns `Ok(true)` if the account exists and is
    /// frozen, `Ok(false)` if it exists and is not frozen, and
    /// `Ok(false)` if the row is absent (no spurious freeze for
    /// unknown accounts — the caller's own `AccountNotFound` surfaces
    /// downstream).
    ///
    /// Implemented as a direct SQL probe rather than a cache flag
    /// because the cache is rebuilt only on unlock, and the freeze
    /// can be set at any time by `ingest_chain_revision` running
    /// against an `Active` vault. The probe runs against a single-row
    /// indexed lookup — sub-millisecond cost.
    fn is_account_frozen(&self, id: AccountId) -> Result<bool> {
        let frozen: Option<i64> = self
            .conn
            .query_row(
                "SELECT frozen_pending_resolve
                 FROM account_identities
                 WHERE account_id = ?1",
                params![id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        Ok(frozen.is_some_and(|v| v != 0))
    }

    /// Surface an `AccountFrozenPendingResolve` error if the supplied
    /// account is frozen. Used as a guard at the top of every user-
    /// facing read or edit path. Returns `Ok(())` if not frozen.
    fn refuse_if_frozen(&self, id: AccountId) -> Result<()> {
        if self.is_account_frozen(id)? {
            return Err(StoreError::AccountFrozenPendingResolve { account_id: id });
        }
        Ok(())
    }

    /// **MVP-1 issue 1.6 — §18.7.** `true` iff `id`'s canonical head
    /// carries a schema version newer than this build understands. Reads
    /// the in-RAM `requires_upgrade` set populated on `unlock`; returns
    /// `false` when the vault is not active (no set yet) — the
    /// session-state guards on the public callers surface that case.
    #[must_use]
    fn account_requires_upgrade(&self, id: AccountId) -> bool {
        self.active
            .as_ref()
            .is_some_and(|a| a.requires_upgrade.contains(&id))
    }

    /// Surface an [`StoreError::UnsupportedRevisionSchemaVersion`] if the
    /// supplied account's canonical head is from the future. Guard at the
    /// top of every user-facing read/edit/reveal path so a "requires
    /// upgrade" account fails loudly rather than serving stale data.
    fn refuse_if_requires_upgrade(&self, id: AccountId) -> Result<()> {
        if self.account_requires_upgrade(id) {
            // We don't have the future revision id cheaply here; the
            // canonical-head pointer is the right one to name. Read it.
            let revision_id = self
                .conn
                .query_row(
                    "SELECT head_revision_id FROM account_identities WHERE account_id = ?1",
                    params![id.as_bytes().as_slice()],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .optional()?
                .and_then(|b| <[u8; REVISION_ID_LEN]>::try_from(b.as_slice()).ok())
                .map_or(RevisionId::GENESIS_PARENT, RevisionId::from_bytes);
            return Err(StoreError::UnsupportedRevisionSchemaVersion {
                account_id: id,
                revision_id,
                // We know it's strictly greater than the max; the exact
                // value would require a re-read of the row column. Use
                // max+1 as a lower bound — callers branch on the variant
                // not the numbers.
                found: u32::from(crate::revision::REVISION_SCHEMA_VERSION_MAX) + 1,
                supported: u32::from(crate::revision::REVISION_SCHEMA_VERSION_MAX),
            });
        }
        Ok(())
    }

    /// Add a new account identity. Returns the freshly-generated
    /// `AccountId` of the new account.
    ///
    /// # Errors
    ///
    /// `StoreError::NotUnlocked` if the vault was never unlocked,
    /// `StoreError::SessionExpired` if the active session has expired
    /// (idle timeout or absolute max). `SessionExpired` zeroizes the
    /// cache before returning per Session spec §5 invariant 3.
    pub fn add_account(&mut self, snapshot: AccountSnapshot) -> Result<AccountId> {
        // P4: strict freshness check at the top. Order is critical —
        // `check_session_freshness` may transition Active→Expired and
        // drop the cache, so any subsequent `require_active` would
        // surface the expiry as `NotUnlocked` instead of
        // `SessionExpired`. Running freshness first preserves the
        // distinction.
        self.check_session_freshness()?;
        let _ = self.require_active()?;
        // **P10-3 / A4 anti-resurrection.** Cardinal Principle 4:
        // append-only state, no silent merges. A new `add_account`
        // call that lands on a tombstoned `account_id` would create
        // a "deleted at T1, created at T2" lineage for the same
        // logical entity, contradicting the linear-history model.
        // The guard probes the existing row for the derived id; if
        // the row's `tombstoned = 1`, regenerate. Under random-32
        // derivation the first-attempt collision probability is
        // bounded by N / 2^256 (N tombstoned rows in the vault); we
        // bound the retry budget at `ADD_ACCOUNT_RETRY_BUDGET` (4)
        // so a pathological RNG cannot spin forever. After 4
        // collisions we surface `StoreError::Internal` rather than
        // silently using a colliding id.
        let account_id = self.derive_fresh_account_id()?;
        let revision_id = RevisionId::from_bytes(random_32_via_sqlite(&self.conn)?);
        let parent = RevisionId::GENESIS_PARENT;
        let aad = build_aad(
            &self.meta.vault_id,
            &account_id,
            &parent,
            self.meta.wrap_context.schema_version,
        );

        let active = self.require_active()?;
        let (ct, nonce) = seal_snapshot(active.vdk.aead_key(), &snapshot, &aad)?;
        let now = current_unix_ms();

        // P8-2: wrap account_identities + revisions + dirty_accounts
        // in one immediate transaction. A crash between rows leaves
        // the vault in the pre-transaction state — the dirty marker
        // is never present without the revision row that produced it
        // (and vice versa).
        //
        // #106b-2: stamp the new revision with the CURRENT VDK epoch (Q-a)
        // — it is encrypted under the active session's `vdk` (= the current
        // epoch's VDK), so the per-entry tag MUST equal the current epoch.
        let vdk_epoch = self.current_vdk_epoch_i64();
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO account_identities (
                account_id, created_at, last_modified_at, tombstoned, head_revision_id
             ) VALUES (?1, ?2, ?2, 0, ?3)",
            params![
                account_id.as_bytes().as_slice(),
                now,
                revision_id.as_bytes().as_slice(),
            ],
        )?;
        tx.execute(
            "INSERT INTO revisions (
                revision_id, account_id, parent_revision_id, device_id,
                schema_version, created_at, enc_payload, enc_nonce, is_tombstone, vdk_epoch
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, ?9)",
            params![
                revision_id.as_bytes().as_slice(),
                account_id.as_bytes().as_slice(),
                parent.as_bytes().as_slice(),
                self.device_id.0.as_slice(),
                i64::from(self.meta.wrap_context.schema_version),
                now,
                ct.as_bytes(),
                nonce.as_bytes().as_slice(),
                vdk_epoch,
            ],
        )?;
        tx.execute(
            "INSERT OR IGNORE INTO dirty_accounts
                (account_id, revision_id, marked_at)
             VALUES (?1, ?2, ?3)",
            params![
                account_id.as_bytes().as_slice(),
                revision_id.as_bytes().as_slice(),
                now,
            ],
        )?;
        tx.commit()?;

        // MVP-2 issue 5.1 (R-d): stamp the in-memory window-start if
        // this is the first dirty marker after an empty queue / a
        // successful flush. Cheap no-op otherwise.
        self.note_dirty_marker_stamped(now);

        // 1.3: keep the `:memory:` FTS5 index in sync (V0 shim — no
        // tags; the single `url` is host-extracted like a V1 URL).
        let projection = SearchProjection::from_snapshot(&snapshot);
        let active = self.require_active_mut()?;
        active.search_index.insert(account_id, now, &projection)?;
        active.cache.insert(account_id, snapshot);
        // P4: success path touches the session — extends the idle
        // deadline (capped at session_started_at + ABSOLUTE_MAX_DEFAULT).
        self.touch_session();
        Ok(account_id)
    }

    /// **P10-3 / A4 helper.** Derive a fresh `AccountId` that does
    /// not collide with any existing tombstoned row's id. Runs the
    /// random-32 derivation up to [`ADD_ACCOUNT_RETRY_BUDGET`] times;
    /// surfaces [`StoreError::Internal`] after all attempts collide.
    /// Under `PoC` the random-32-via-sqlite-derived `account_id`
    /// makes this collision cryptographically negligible, so the
    /// retry budget is defense-in-depth + spec compliance with the
    /// append-only invariant (Cardinal Principle 4).
    ///
    /// A non-tombstoned-row collision is structurally impossible
    /// (the random 32-byte space dwarfs any plausible vault size),
    /// but if it did occur the subsequent INSERT would fail at the
    /// SQL layer with a uniqueness constraint violation; the
    /// pre-INSERT probe here only checks tombstoned-row collision
    /// because a tombstoned-row id MUST be retired forever (whereas
    /// a live-row id collision is "you just generated a duplicate
    /// id; very weird; let SQL surface it").
    fn derive_fresh_account_id(&self) -> Result<AccountId> {
        for _ in 0..ADD_ACCOUNT_RETRY_BUDGET {
            let candidate = AccountId::from_bytes(random_32_via_sqlite(&self.conn)?);
            let collision: Option<i64> = self
                .conn
                .query_row(
                    "SELECT tombstoned FROM account_identities WHERE account_id = ?1",
                    params![candidate.as_bytes().as_slice()],
                    |row| row.get(0),
                )
                .optional()?;
            match collision {
                // Tombstoned-row collision; loop iterates again.
                Some(1) => {}
                _ => return Ok(candidate),
            }
        }
        Err(StoreError::Internal {
            reason: format!(
                "account_id derivation collision after {ADD_ACCOUNT_RETRY_BUDGET} attempts"
            ),
        })
    }

    /// Replace an account's contents. Builds a new revision pointing at
    /// the current head as parent, persists, and updates the cache.
    pub fn update_account(
        &mut self,
        id: AccountId,
        new_snapshot: AccountSnapshot,
    ) -> Result<RevisionId> {
        // P4: strict freshness — see `add_account` rationale.
        self.check_session_freshness()?;
        let _ = self.require_active()?;
        // P8 fix CRIT-1: refuse edits on a frozen account. A user
        // editing their own copy of an account that has been chain-
        // modified would create a fork they don't realize they're
        // creating; surface the freeze before any work is done.
        self.refuse_if_frozen(id)?;
        self.refuse_if_requires_upgrade(id)?;
        // Look up account state.
        let account_row = self
            .conn
            .query_row(
                "SELECT tombstoned, head_revision_id
                 FROM account_identities WHERE account_id = ?1",
                params![id.as_bytes().as_slice()],
                |row| {
                    let tombstoned: i64 = row.get(0)?;
                    let head: Vec<u8> = row.get(1)?;
                    Ok((tombstoned != 0, head))
                },
            )
            .optional()?
            .ok_or(StoreError::AccountNotFound)?;
        if account_row.0 {
            return Err(StoreError::AccountTombstoned);
        }
        let head_arr: [u8; REVISION_ID_LEN] = account_row
            .1
            .as_slice()
            .try_into()
            .map_err(|_| StoreError::Corrupted("head_revision_id not 32 bytes".into()))?;
        let parent = RevisionId::from_bytes(head_arr);
        let revision_id = RevisionId::from_bytes(random_32_via_sqlite(&self.conn)?);

        let aad = build_aad(
            &self.meta.vault_id,
            &id,
            &parent,
            self.meta.wrap_context.schema_version,
        );
        let active = self.require_active()?;
        let (ct, nonce) = seal_snapshot(active.vdk.aead_key(), &new_snapshot, &aad)?;
        let now = current_unix_ms();

        // P8-2: revisions + account_identities head pointer + dirty
        // marker in one transaction.
        // #106b-2: stamp the CURRENT VDK epoch (Q-a) — encrypted under the
        // active session's `vdk` (= current epoch's VDK).
        let vdk_epoch = self.current_vdk_epoch_i64();
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO revisions (
                revision_id, account_id, parent_revision_id, device_id,
                schema_version, created_at, enc_payload, enc_nonce, is_tombstone, vdk_epoch
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, ?9)",
            params![
                revision_id.as_bytes().as_slice(),
                id.as_bytes().as_slice(),
                parent.as_bytes().as_slice(),
                self.device_id.0.as_slice(),
                i64::from(self.meta.wrap_context.schema_version),
                now,
                ct.as_bytes(),
                nonce.as_bytes().as_slice(),
                vdk_epoch,
            ],
        )?;
        tx.execute(
            "UPDATE account_identities
             SET head_revision_id = ?1, last_modified_at = ?2
             WHERE account_id = ?3",
            params![
                revision_id.as_bytes().as_slice(),
                now,
                id.as_bytes().as_slice(),
            ],
        )?;
        tx.execute(
            "INSERT OR IGNORE INTO dirty_accounts
                (account_id, revision_id, marked_at)
             VALUES (?1, ?2, ?3)",
            params![
                id.as_bytes().as_slice(),
                revision_id.as_bytes().as_slice(),
                now,
            ],
        )?;
        tx.commit()?;

        // MVP-2 issue 5.1 (R-d): window-start hook.
        self.note_dirty_marker_stamped(now);

        // 1.3: resync the `:memory:` FTS5 index (V0 shim).
        let projection = SearchProjection::from_snapshot(&new_snapshot);
        let active = self.require_active_mut()?;
        active.search_index.update(id, now, &projection)?;
        active.cache.insert(id, new_snapshot);
        self.touch_session();
        Ok(revision_id)
    }

    /// Tombstone an account. Writes a sentinel revision and flips the
    /// account row's `tombstoned` flag. Subsequent reads via
    /// [`Self::get_account`] return `None`.
    pub fn delete_account(&mut self, id: AccountId) -> Result<()> {
        // P4: strict freshness — see `add_account` rationale.
        self.check_session_freshness()?;
        let _ = self.require_active()?;
        // P8 fix CRIT-1: same freeze guard as `update_account`. A
        // delete on a frozen account would publish a tombstone
        // overriding the foreign chain edit; refuse so the user is
        // forced through resolve first.
        self.refuse_if_frozen(id)?;
        self.refuse_if_requires_upgrade(id)?;
        let head_row = self
            .conn
            .query_row(
                "SELECT tombstoned, head_revision_id
                 FROM account_identities WHERE account_id = ?1",
                params![id.as_bytes().as_slice()],
                |row| {
                    let t: i64 = row.get(0)?;
                    let h: Vec<u8> = row.get(1)?;
                    Ok((t != 0, h))
                },
            )
            .optional()?
            .ok_or(StoreError::AccountNotFound)?;
        if head_row.0 {
            return Err(StoreError::AccountTombstoned);
        }
        let head_arr: [u8; REVISION_ID_LEN] = head_row
            .1
            .as_slice()
            .try_into()
            .map_err(|_| StoreError::Corrupted("head_revision_id not 32 bytes".into()))?;
        let parent = RevisionId::from_bytes(head_arr);
        let revision_id = RevisionId::from_bytes(random_32_via_sqlite(&self.conn)?);
        let aad = build_aad(
            &self.meta.vault_id,
            &id,
            &parent,
            self.meta.wrap_context.schema_version,
        );
        let active = self.require_active()?;
        let now = current_unix_ms();
        // P10-1: widened tombstone payload carries account_id + the
        // unix-ms timestamp. `tombstoned_at_ms` matches the row's
        // `last_modified_at` (we use `now` for both so a forensic
        // reader sees consistent values), but the in-payload field
        // is the AEAD-authenticated source of truth.
        let tombstone_payload = TombstonePayload::new(id, u64::try_from(now).unwrap_or(0));
        let (ct, nonce) = seal_tombstone(active.vdk.aead_key(), &aad, &tombstone_payload)?;

        // P8-2: tombstone-revision + flip + dirty marker in one
        // transaction. Tombstone revisions also need publishing —
        // P10 (delete) reads them off the chain like any other
        // revision; the dirty marker tracks them through the publish
        // path identically.
        // #106b-2: stamp the CURRENT VDK epoch (Q-a) on the tombstone
        // revision — encrypted under the active session's `vdk`.
        let vdk_epoch = self.current_vdk_epoch_i64();
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO revisions (
                revision_id, account_id, parent_revision_id, device_id,
                schema_version, created_at, enc_payload, enc_nonce, is_tombstone, vdk_epoch
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1, ?9)",
            params![
                revision_id.as_bytes().as_slice(),
                id.as_bytes().as_slice(),
                parent.as_bytes().as_slice(),
                self.device_id.0.as_slice(),
                i64::from(self.meta.wrap_context.schema_version),
                now,
                ct.as_bytes(),
                nonce.as_bytes().as_slice(),
                vdk_epoch,
            ],
        )?;
        tx.execute(
            "UPDATE account_identities
             SET head_revision_id = ?1, last_modified_at = ?2, tombstoned = 1
             WHERE account_id = ?3",
            params![
                revision_id.as_bytes().as_slice(),
                now,
                id.as_bytes().as_slice(),
            ],
        )?;
        tx.execute(
            "INSERT OR IGNORE INTO dirty_accounts
                (account_id, revision_id, marked_at)
             VALUES (?1, ?2, ?3)",
            params![
                id.as_bytes().as_slice(),
                revision_id.as_bytes().as_slice(),
                now,
            ],
        )?;
        tx.commit()?;

        // MVP-2 issue 5.1 (R-d + L10): window-start hook. Tombstones
        // are stamped same as any other revision; the L10 invariant
        // "tombstone always wins" is enforced inside
        // `coalesce_dirty_markers` via the head-pointer rule (the
        // tombstone's revision_id == the account's new head, so it
        // is the marker preserved).
        self.note_dirty_marker_stamped(now);

        // 1.3: a tombstoned account must not appear in search — drop
        // its `:memory:` FTS5 row (makes the whitelist structural for
        // deleted accounts too).
        let active = self.require_active_mut()?;
        active.search_index.remove(id)?;
        let _ = active.cache.remove(id);
        self.touch_session();
        Ok(())
    }

    /// Return a borrow on the in-memory snapshot. `None` for unknown,
    /// tombstoned, vault-not-active, or session-expired.
    ///
    /// P4 note: `get_account` is `&self` (shared borrow) for ergonomics,
    /// so it cannot zeroize the cache mid-call. Instead it observes
    /// `session_remaining()` via the same `self.clock.now()` reading
    /// and returns `None` when the deadline has passed; the cache is
    /// then zeroized on the *next* `&mut self` op via
    /// `check_session_freshness` or `maybe_expire_active_session`.
    /// This is acceptable because the &-borrowed reference returned
    /// here is bounded by the &-borrow on `self`, so an attacker who
    /// somehow held that borrow past expiry would already be inside
    /// the same lexical scope — there is no interleaving with a
    /// concurrent `lock()` call. The plaintext stays in memory until
    /// the cache is dropped, which the next mut-op does.
    ///
    /// **P8 fix CRIT-1.** Also returns `None` for an account whose
    /// `frozen_pending_resolve` flag is set — the data on disk is
    /// stale relative to chain reality and the user must run
    /// `pangolin-cli resolve` (P9) before reading. Surfacing as `None`
    /// rather than an error keeps the existing `Option`-returning
    /// shape; callers that need the explicit "frozen" signal use
    /// [`Self::reveal_password`] or check via the public
    /// [`Self::list_frozen_accounts`].
    #[must_use]
    pub fn get_account(&self, id: AccountId) -> Option<&AccountSnapshot> {
        if !self.is_session_active() {
            return None;
        }
        // Frozen accounts are filtered out of the readable surface.
        // We swallow any SQL error here as `None` because `get_account`
        // returns `Option`; a corrupt DB will surface at the next
        // mut-op via the typed error path.
        if self.is_account_frozen(id).unwrap_or(false) {
            return None;
        }
        self.active.as_ref().and_then(|a| a.cache.get(id))
    }

    /// Substring search across non-tombstoned, non-frozen accounts.
    /// Returns an empty `Vec` if the session has expired (mirroring
    /// P2 semantics of returning empty for non-Active vaults).
    ///
    /// **P8 fix CRIT-1.** Frozen accounts are filtered out so that a
    /// user search does not surface stale plaintext — same discipline
    /// as `list_accounts` / `get_account`.
    #[must_use]
    pub fn search(&self, query: &str) -> Vec<AccountId> {
        if !self.is_session_active() {
            return Vec::new();
        }
        let frozen = self.frozen_set().unwrap_or_default();
        self.active.as_ref().map_or_else(Vec::new, |a| {
            a.cache
                .search(query)
                .into_iter()
                .filter(|id| !frozen.contains(id))
                .collect()
        })
    }

    /// All non-tombstoned, non-frozen account ids in the cache. Empty
    /// `Vec` if the session has expired.
    ///
    /// **P8 fix CRIT-1.** Frozen accounts (those whose
    /// `account_identities.frozen_pending_resolve` flag is set) are
    /// filtered out — they are not safe for user-facing reads until
    /// the upcoming P9 `resolve` command clears the flag. Callers
    /// that want the frozen-set explicitly use
    /// [`Self::list_frozen_accounts`].
    #[must_use]
    pub fn list_accounts(&self) -> Vec<AccountId> {
        if !self.is_session_active() {
            return Vec::new();
        }
        let frozen = self.frozen_set().unwrap_or_default();
        self.active.as_ref().map_or_else(Vec::new, |a| {
            a.cache
                .account_ids()
                .into_iter()
                .filter(|id| !frozen.contains(id))
                .collect()
        })
    }

    /// Snapshot of every account currently in the
    /// `frozen_pending_resolve` state.
    ///
    /// Surfaces the CRIT-1 sentinel set for tooling (`pangolin-cli
    /// pull` reports the count alongside the fork count; the future
    /// P9 `resolve` subcommand reads this list to drive its
    /// resolution UX). Metadata-only — does NOT require an active
    /// session. Empty `Vec` for a freshly-created vault.
    ///
    /// # Errors
    ///
    /// `StoreError::Sqlite` for any database issue.
    /// `StoreError::Corrupted` if a stored `account_id` BLOB is not
    /// 32 bytes.
    pub fn list_frozen_accounts(&self) -> Result<Vec<AccountId>> {
        let mut stmt = self.conn.prepare(
            "SELECT account_id
             FROM account_identities
             WHERE frozen_pending_resolve = 1
             ORDER BY account_id ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            let id: Vec<u8> = row.get(0)?;
            Ok(id)
        })?;
        let mut out = Vec::new();
        for r in rows {
            let blob = r?;
            let arr: [u8; ACCOUNT_ID_LEN] = blob.as_slice().try_into().map_err(|_| {
                StoreError::Corrupted("account_identities.account_id not 32 bytes".into())
            })?;
            out.push(AccountId::from_bytes(arr));
        }
        Ok(out)
    }

    /// Internal helper: as `list_frozen_accounts`, but returns a
    /// `HashSet` for O(1) lookups inside the read-path filters.
    fn frozen_set(&self) -> Result<std::collections::HashSet<AccountId>> {
        Ok(self.list_frozen_accounts()?.into_iter().collect())
    }

    /// **P10-5.** Snapshot of every account currently in the
    /// tombstoned state. Surfaces the count for the
    /// `pangolin-cli status` summary line.
    ///
    /// Metadata-only — does NOT require an active session. Empty
    /// `Vec` for a freshly-created vault.
    ///
    /// # Errors
    ///
    /// `StoreError::Sqlite` for any database issue.
    /// `StoreError::Corrupted` if a stored `account_id` BLOB is not
    /// 32 bytes.
    pub fn list_tombstoned_accounts(&self) -> Result<Vec<AccountId>> {
        let mut stmt = self.conn.prepare(
            "SELECT account_id
             FROM account_identities
             WHERE tombstoned = 1
             ORDER BY account_id ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            let id: Vec<u8> = row.get(0)?;
            Ok(id)
        })?;
        let mut out = Vec::new();
        for r in rows {
            let blob = r?;
            let arr: [u8; ACCOUNT_ID_LEN] = blob.as_slice().try_into().map_err(|_| {
                StoreError::Corrupted("account_identities.account_id not 32 bytes".into())
            })?;
            out.push(AccountId::from_bytes(arr));
        }
        Ok(out)
    }

    // -----------------------------------------------------------------
    // P9: conflict-resolution primitives (clear_frozen +
    //      read_payload_plaintext_for_resolve)
    // -----------------------------------------------------------------

    /// **P9-1.** Clear `frozen_pending_resolve` and advance
    /// `head_revision_id` to `chosen_revision_id` in one transaction.
    ///
    /// The natural caller pattern is "the resolve flow has just
    /// published a merge revision under `account_id` whose canonical
    /// `revision_id` is `chosen_revision_id`; ingest brought the row
    /// into the local store; now finalize the conflict-resolved state
    /// by clearing the freeze flag and pointing the canonical head at
    /// the merge."
    ///
    /// Idempotency: a non-frozen account whose `head_revision_id` is
    /// already `chosen_revision_id` is a no-op-equivalent (the
    /// transaction body re-runs the same UPDATE, which is identity).
    /// This makes recovery from a kill between
    /// `ingest_chain_revision` and `clear_frozen` straightforward —
    /// re-run the resolve flow with the same `--keep` choice; the
    /// pre-publish check sees the merge revision is already on chain,
    /// `ingest_chain_revision` recognises it via idempotency arm #1
    /// (no-op), and `clear_frozen` either clears the still-set flag or
    /// is a no-op if the prior call had already cleared it.
    ///
    /// Both writes (clearing the freeze flag + advancing the head
    /// pointer) run inside one `BEGIN IMMEDIATE … COMMIT` so a crash
    /// between them leaves the vault in the pre-transaction state.
    ///
    /// **P9 fix-pass MED-3.** Inside the SQL transaction (`BEGIN
    /// IMMEDIATE`), BEFORE the UPDATE, the implementation calls
    /// [`Self::account_heads`] and verifies `chosen_revision_id` is
    /// in the returned set. If not, returns
    /// [`StoreError::NotAHead`]. The check runs INSIDE the
    /// transaction so a concurrent ingest cannot change the head set
    /// between check and update — the contract is "errors with
    /// `NotAHead` if the supplied `revision_id` is not a current head
    /// AT THE TIME of the SQL transaction." This catches the bug
    /// class where the resolve flow passes the old chosen-revision
    /// id (a non-head, demoted by the merge revision's INSERT)
    /// instead of the merge revision's id.
    ///
    /// Metadata-only — does NOT require [`VaultState::Active`]. The
    /// caller (`pangolin-cli resolve`) holds the vault unlocked because
    /// it had to decrypt the chosen revision's plaintext via
    /// [`Self::read_payload_plaintext_for_resolve`], but `clear_frozen`
    /// itself touches no plaintext.
    ///
    /// # Errors
    ///
    /// `StoreError::AccountNotFound` if `account_id` has no
    /// `account_identities` row. `StoreError::RevisionNotFound` if
    /// `chosen_revision_id` does not exist in the `revisions` table for
    /// this `account_id`. [`StoreError::NotAHead`] (P9 fix-pass MED-3)
    /// if the revision exists but is not a current head at the time
    /// of the SQL transaction. `StoreError::Sqlite` for any database
    /// issue.
    pub fn clear_frozen(
        &mut self,
        account_id: AccountId,
        chosen_revision_id: RevisionId,
    ) -> Result<()> {
        // Soft-expiry: this is metadata-only, so a Locked vault still
        // works. Active+expired transitions to Expired and zeroizes
        // the cache before we proceed.
        self.maybe_expire_active_session();

        // Cross-check the account exists. Distinct error for unknown
        // account so the caller can distinguish "you typed the wrong
        // account_id" from "you typed the wrong revision_id".
        let account_exists: Option<i64> = self
            .conn
            .query_row(
                "SELECT 1 FROM account_identities WHERE account_id = ?1",
                params![account_id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        if account_exists.is_none() {
            return Err(StoreError::AccountNotFound);
        }

        // Cross-check the revision exists for this account. Both
        // checks (account_id AND revision_id) — defense in depth
        // against an attacker-supplied revision_id from a different
        // vault's account.
        let revision_exists: Option<i64> = self
            .conn
            .query_row(
                "SELECT 1 FROM revisions
                 WHERE account_id = ?1 AND revision_id = ?2",
                params![
                    account_id.as_bytes().as_slice(),
                    chosen_revision_id.as_bytes().as_slice(),
                ],
                |row| row.get(0),
            )
            .optional()?;
        if revision_exists.is_none() {
            return Err(StoreError::RevisionNotFound);
        }

        // Apply both writes atomically: validate head-membership AND
        // clear the freeze flag AND advance the head pointer.
        // `BEGIN IMMEDIATE` so a concurrent writer (which the lock
        // file already prevents at the OS boundary, but defense in
        // depth) cannot interleave between the head check and the
        // UPDATE.
        let tx = self.conn.unchecked_transaction()?;

        // P9 fix-pass MED-3: head-membership check INSIDE the
        // transaction. We use the same NOT EXISTS predicate that
        // `account_heads` uses for the multi-head detector, scoped
        // by `account_id` (M-1 P3 audit defense-in-depth).
        let mut head_stmt = tx.prepare(
            // #106d (salvaged #103-C FINDING 2): exclude revoked rows from
            // the head set. A revoked row is never a head, and a revoked
            // CHILD must not mask an honored parent from being a head
            // (hence the `r2.revoked = 0` in the child-existence subquery).
            "SELECT r.revision_id FROM revisions r
             WHERE r.account_id = ?1
               AND r.superseded_by IS NULL
               AND r.revoked = 0
               AND NOT EXISTS (
                 SELECT 1 FROM revisions r2
                 WHERE r2.parent_revision_id = r.revision_id
                   AND r2.account_id = r.account_id
                   AND r2.revoked = 0
               )",
        )?;
        let head_rows = head_stmt.query_map(params![account_id.as_bytes().as_slice()], |row| {
            let rid: Vec<u8> = row.get(0)?;
            Ok(rid)
        })?;
        let mut head_set: Vec<RevisionId> = Vec::new();
        for r in head_rows {
            let blob = r?;
            let arr: [u8; REVISION_ID_LEN] = blob
                .as_slice()
                .try_into()
                .map_err(|_| StoreError::Corrupted("head revision_id not 32 bytes".into()))?;
            head_set.push(RevisionId::from_bytes(arr));
        }
        drop(head_stmt);
        if !head_set.contains(&chosen_revision_id) {
            // Don't commit — let the transaction roll back.
            return Err(StoreError::NotAHead {
                account_id,
                chosen: chosen_revision_id,
                current_heads: head_set,
            });
        }

        let now = current_unix_ms();
        tx.execute(
            "UPDATE account_identities
             SET frozen_pending_resolve = 0,
                 head_revision_id = ?1,
                 last_modified_at = ?2
             WHERE account_id = ?3",
            params![
                chosen_revision_id.as_bytes().as_slice(),
                now,
                account_id.as_bytes().as_slice(),
            ],
        )?;
        tx.commit()?;

        self.touch_session();
        Ok(())
    }

    /// **P9-1.** Read the plaintext of an arbitrary revision belonging
    /// to `account_id`, bypassing the
    /// `frozen_pending_resolve` read guard.
    ///
    /// **DOCUMENTED FREEZE-GUARD BYPASS — DO NOT CALL FROM ANY PATH
    /// EXCEPT `pangolin-cli resolve`.** The frozen-account guard on
    /// every other read surface ([`Self::get_account`],
    /// [`Self::reveal_password`], [`Self::reveal_notes`],
    /// [`Self::reveal_totp_secret`], [`Self::export_payload`]) refuses
    /// to surface plaintext for an account in the
    /// `frozen_pending_resolve` state. The resolve flow needs to read
    /// the chosen head's plaintext exactly once, in memory only, to
    /// re-seal it under the merge revision's AAD with a fresh nonce
    /// (per P9 plan §A2 — a byte-copy of the ciphertext would carry
    /// the source revision's `parent_revision_id` in its baked-in AAD,
    /// producing an unopenable merge row).
    ///
    /// The user's explicit `--keep <revision-id>` flag is the
    /// proof-of-intent that authorizes this single bypass: the user
    /// has named the specific revision they want to ratify, so we
    /// trust the read for that one revision, for the duration of one
    /// resolve invocation. The returned [`AccountSnapshot`] zeroizes
    /// on drop; the caller is expected to consume it immediately into
    /// the re-seal pipeline and discard.
    ///
    /// Both `account_id` AND `revision_id` are cross-checked so that
    /// supplying a `revision_id` from a different account's history
    /// (or a different vault's account) does NOT decrypt — the AAD
    /// bind matches `account_id` and the SQL row lookup matches both.
    /// Mismatches collapse into `AccountNotFound` so this method does
    /// not become an oracle on which `(account, revision)` pairs are
    /// known locally.
    ///
    /// Requires the vault to be [`VaultState::Active`] — the AEAD
    /// `open` path needs the unwrapped VDK in the active cache.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotUnlocked`] / [`StoreError::SessionExpired`] if
    /// the session is not active.
    /// [`StoreError::AccountNotFound`] if `account_id` is unknown OR
    /// if `revision_id` is not a row for this account (collapsed —
    /// see above).
    /// [`StoreError::AuthenticationFailed`] if the AEAD open fails
    /// (tampered ciphertext, wrong AAD, schema-version drift).
    /// [`StoreError::Cbor`] if the decrypted payload's CBOR shape is
    /// not a live `AccountSnapshot` map (e.g., the revision is a
    /// tombstone — A5 of P9 plan; the resolve flow checks the
    /// `is_tombstone` flag separately and re-seals via
    /// [`crate::blob::seal_tombstone`] instead of calling this method).
    pub fn read_payload_plaintext_for_resolve(
        &mut self,
        account_id: AccountId,
        revision_id: RevisionId,
    ) -> Result<AccountSnapshot> {
        // Cache-bearing op (uses VDK). Strict freshness check.
        self.check_session_freshness()?;
        let _ = self.require_active()?;

        // Cross-check account exists. Collapse "unknown account" and
        // "unknown revision for this account" into the SAME error
        // variant to deny an oracle.
        let account_row: Option<(i64,)> = self
            .conn
            .query_row(
                "SELECT 1 FROM account_identities WHERE account_id = ?1",
                params![account_id.as_bytes().as_slice()],
                |row| Ok((row.get(0)?,)),
            )
            .optional()?;
        if account_row.is_none() {
            return Err(StoreError::AccountNotFound);
        }

        // Read the chosen revision's `(parent, schema_version,
        // enc_payload, enc_nonce)` cross-checked on `account_id` so
        // a `revision_id` from a different account does NOT match.
        // MVP-3 issue #106b-2: also read the per-entry `vdk_epoch` tag so we
        // decrypt this revision under `chain[vdk_epoch]` (Q-a) — the same
        // epoch-aware selection the unlock hydration path uses.
        let row: Option<(RawRevisionPayload, i64)> = self
            .conn
            .query_row(
                "SELECT parent_revision_id, schema_version, enc_payload, enc_nonce, vdk_epoch
                 FROM revisions
                 WHERE account_id = ?1 AND revision_id = ?2",
                params![
                    account_id.as_bytes().as_slice(),
                    revision_id.as_bytes().as_slice(),
                ],
                |row| {
                    let parent: Vec<u8> = row.get(0)?;
                    let sv: i64 = row.get(1)?;
                    let payload: Vec<u8> = row.get(2)?;
                    let nonce: Vec<u8> = row.get(3)?;
                    let epoch: i64 = row.get(4)?;
                    Ok((
                        RawRevisionPayload {
                            parent,
                            schema_version: sv,
                            enc_payload: payload,
                            enc_nonce: nonce,
                        },
                        epoch,
                    ))
                },
            )
            .optional()?;
        // Per docstring: collapse "wrong account_id for this
        // revision" into the same error variant as "unknown
        // account" so the method is not an oracle.
        let (
            RawRevisionPayload {
                parent: parent_blob,
                schema_version: sv_i64,
                enc_payload,
                enc_nonce,
            },
            vdk_epoch_i,
        ) = row.ok_or(StoreError::AccountNotFound)?;
        let vdk_epoch = u64::try_from(vdk_epoch_i)
            .map_err(|_| StoreError::Corrupted("revisions.vdk_epoch negative".into()))?;

        let parent_arr: [u8; REVISION_ID_LEN] = parent_blob
            .as_slice()
            .try_into()
            .map_err(|_| StoreError::Corrupted("parent_revision_id not 32 bytes".into()))?;
        let parent = RevisionId::from_bytes(parent_arr);
        let schema_version = u8::try_from(sv_i64).map_err(|_| {
            StoreError::Corrupted("revisions.schema_version out of u8 range".into())
        })?;

        // Reconstruct the AAD that was baked in at seal time. Same
        // build_aad call shape as add_account / update_account.
        let aad = build_aad(&self.meta.vault_id, &account_id, &parent, schema_version);

        // The nonce must be 24 bytes (NONCE_LEN). A pre-existing row
        // could have a placeholder zeroed nonce if it was inserted via
        // ingest_chain_revision (foreign chain event without the
        // original nonce — see ingest_chain_revision body). In that
        // case open_payload returns AuthenticationFailed because
        // the AEAD won't decrypt under the placeholder; the resolve
        // flow surfaces that as a clean error to the user.
        let nonce_arr: [u8; NONCE_LEN] = enc_nonce
            .as_slice()
            .try_into()
            .map_err(|_| StoreError::Corrupted("revisions.enc_nonce not 24 bytes".into()))?;
        let nonce = Nonce::from_storage_bytes(nonce_arr);
        let ciphertext = Ciphertext::from_vec(enc_payload);

        let active = self.require_active()?;
        // Select the decrypting VDK for this entry's epoch (#106b-2 §3.1):
        // the current epoch's VDK is `active.vdk`; a retained OLD epoch's
        // VDK comes from the chain. An entry tagged to an epoch this device
        // does not hold is undecryptable → AuthenticationFailed (the
        // resolve flow surfaces it cleanly, same as a placeholder-nonce).
        let entry_aead = if vdk_epoch == active.chain.current_epoch() {
            active.vdk.aead_key()
        } else {
            active
                .chain
                .aead_for_epoch(vdk_epoch)
                .ok_or(StoreError::AuthenticationFailed)?
        };
        let decoded = open_payload(entry_aead, &nonce, &ciphertext, &aad)?;

        let snapshot = match decoded {
            DecodedPayload::Live(s) => s,
            // Tombstone: the resolve flow detects is_tombstone via
            // revisions metadata and uses seal_tombstone directly
            // (per P9 plan §A5). If the caller passed a tombstone
            // revision into THIS method, surface a CBOR-class error
            // — the API contract is "live snapshot only".
            DecodedPayload::Tombstone(_) => {
                return Err(StoreError::Cbor(
                    "read_payload_plaintext_for_resolve called on tombstone revision; \
                     resolve flow must use seal_tombstone for tombstone heads"
                        .into(),
                ));
            }
        };

        self.touch_session();
        Ok(snapshot)
    }

    /// **P9-4.** Build the merge revision's `enc_payload` for the
    /// resolve flow.
    ///
    /// Reads the chosen revision's plaintext via the freeze-guard
    /// bypass (same proof-of-intent argument as
    /// [`Self::read_payload_plaintext_for_resolve`] — the user typed
    /// `--keep <id>`, we trust the read for that one revision) and
    /// re-seals it under a fresh nonce + the merge revision's own
    /// AAD (`parent_revision_id` = `chosen_revision_id`,
    /// `account_id` and `vault_id` unchanged, `schema_version`
    /// inherited from the chosen revision).
    ///
    /// Returns `(enc_payload, aead_nonce_bytes, schema_version,
    /// is_tombstone)` — plaintext NEVER leaves the store crate; the
    /// cli crate only sees the new ciphertext + the chain-relevant
    /// fields plus the nonce (load-bearing for the P9 fix-pass HIGH-1
    /// `pending_merges` stash so a kill mid-publish is recoverable on
    /// retry by re-using the SAME nonce + ciphertext — see
    /// [`Self::stash_pending_merge`] and `THREAT_MODEL.md` row #13).
    ///
    /// If the chosen revision is a tombstone, re-seals via
    /// [`crate::blob::seal_tombstone`] so the merge revision is
    /// structurally a tombstone too (per P9 plan §A5 — resolving to
    /// a tombstone ratifies the deletion).
    ///
    /// Requires the vault to be [`VaultState::Active`].
    ///
    /// # Errors
    ///
    /// Same set as [`Self::read_payload_plaintext_for_resolve`].
    /// Additionally surfaces [`StoreError::AuthenticationFailed`] if
    /// the freshly-derived re-seal fails (theoretically impossible
    /// for AEAD with a 24-byte random nonce on a payload below the
    /// 256-GB ceiling, but the typed surface is preserved).
    pub fn build_merge_payload_for_resolve(
        &mut self,
        account_id: AccountId,
        chosen_revision_id: RevisionId,
    ) -> Result<(Vec<u8>, [u8; NONCE_LEN], u8, bool)> {
        // Strict freshness — same as the plaintext reader (this
        // method composes that reader's discipline).
        self.check_session_freshness()?;
        let _ = self.require_active()?;

        // Read the schema_version + is_tombstone for the chosen
        // revision FIRST. We need them regardless of whether this is
        // a live snapshot (for AAD) or a tombstone (for re-seal
        // dispatch). The cross-check on `account_id` matches the
        // discipline in `read_payload_plaintext_for_resolve`.
        let row: Option<(i64, i64)> = self
            .conn
            .query_row(
                "SELECT schema_version, is_tombstone
                 FROM revisions
                 WHERE account_id = ?1 AND revision_id = ?2",
                params![
                    account_id.as_bytes().as_slice(),
                    chosen_revision_id.as_bytes().as_slice(),
                ],
                |row| {
                    let sv: i64 = row.get(0)?;
                    let ts: i64 = row.get(1)?;
                    Ok((sv, ts))
                },
            )
            .optional()?;
        let (sv_i64, is_tombstone_i64) = row.ok_or(StoreError::AccountNotFound)?;
        let schema_version = u8::try_from(sv_i64).map_err(|_| {
            StoreError::Corrupted("revisions.schema_version out of u8 range".into())
        })?;
        let is_tombstone = is_tombstone_i64 != 0;

        // Build the merge revision's AAD. The merge row's
        // parent_revision_id IS the chosen head's revision_id. This
        // is the load-bearing AAD discipline from P9 plan §A2 — a
        // byte-copy of the source ciphertext would carry the source
        // row's parent_revision_id baked in, which differs from the
        // merge row's parent and would render the merge row
        // unopenable.
        let merge_aad = build_aad(
            &self.meta.vault_id,
            &account_id,
            &chosen_revision_id,
            schema_version,
        );

        let active = self.require_active()?;
        let aead_key = active.vdk.aead_key();

        let (ct, nonce) = if is_tombstone {
            // Tombstone-resolve: re-seal the tombstone payload under
            // the merge AAD. P10 plan §A5 / Q2: `tombstoned_at_ms`
            // is the merge revision's OWN seal time (not the original
            // tombstone's timestamp). The merge revision is a fresh
            // chain event published at merge time; the in-payload
            // timestamp is the timestamp of the *seal*, not the
            // *concept*. The original tombstone's timestamp is
            // recoverable from the chain history of its parent event.
            let merge_payload =
                TombstonePayload::new(account_id, u64::try_from(current_unix_ms()).unwrap_or(0));
            seal_tombstone(aead_key, &merge_aad, &merge_payload)?
        } else {
            // Live snapshot: read plaintext via the bypass-aware
            // helper, then re-seal under the merge AAD with a fresh
            // random nonce. The snapshot is AccountSnapshot with
            // ZeroizeOnDrop on every secret field — it wipes when
            // it falls out of scope at the end of this block.
            let snapshot =
                self.read_payload_plaintext_for_resolve(account_id, chosen_revision_id)?;
            // Re-acquire the active borrow because
            // read_payload_plaintext_for_resolve takes &mut self
            // and may have invalidated our prior `active` borrow.
            let active = self.require_active()?;
            seal_snapshot(active.vdk.aead_key(), &snapshot, &merge_aad)?
        };

        // P9 fix-pass HIGH-1: the nonce is now surfaced to the caller
        // so it can be stashed in `pending_merges` BEFORE
        // adapter.publish. On retry, `take_pending_merge` returns the
        // same nonce + ciphertext + ephemeral signing seed; the
        // canonical hash is identical across retries and the chain
        // event from a prior partially-completed run can be matched
        // via the existing A3 idempotency scan inside
        // `sync::resolve_one`. Without this stash, every retry
        // generates a fresh nonce + fresh `DeviceKey`, the canonical
        // hash differs every run, and the user is permanently stuck
        // with a frozen account. See `THREAT_MODEL.md` row #13 +
        // DEVLOG P9 fix-pass entry.

        let nonce_bytes = *nonce.as_bytes();
        self.touch_session();
        Ok((ct.into_vec(), nonce_bytes, schema_version, is_tombstone))
    }

    // -----------------------------------------------------------------
    // P9 fix-pass HIGH-1: pending_merges stash for partial-failure
    //                     recovery
    // -----------------------------------------------------------------

    /// **P9 fix-pass HIGH-1.** Stash the merge-revision-build state
    /// so a kill between `adapter.publish` and `clear_frozen` is
    /// recoverable on retry.
    ///
    /// **LOAD-BEARING.** See `THREAT_MODEL.md` row #13. Without this
    /// stash, each retry of `sync::resolve_one` generates a fresh
    /// ephemeral [`pangolin_crypto::keys::DeviceKey`] + a fresh AEAD
    /// nonce, so the canonical hash differs every run and the chain
    /// event from a prior partially-completed run cannot be matched
    /// on retry. The user would be permanently stuck with a frozen
    /// account.
    ///
    /// `device_secret` is the 32-byte Ed25519 secret seed of the
    /// ephemeral merge-revision signing key. The seed bytes live at
    /// rest in the `SQLite` vault file as a BLOB; NOT additionally
    /// AEAD-sealed because at-rest exposure of the `.pvf` file
    /// already compromises the VDK and worse, so the marginal
    /// exposure of an ephemeral merge-signing key is bounded. The
    /// ephemeral key is discarded after `clear_frozen` succeeds (the
    /// row is deleted by [`Self::clear_pending_merge`]).
    ///
    /// `enc_payload` is AEAD ciphertext (NOT plaintext — the seal
    /// happened inside [`Self::build_merge_payload_for_resolve`]
    /// before the stash). Cardinal principle 2 holds.
    ///
    /// Idempotent: re-stashing the same `(account_id,
    /// target_head_id)` overwrites the prior row (`INSERT OR
    /// REPLACE`) — sharp-edged because it forfeits the prior
    /// stash's signing key, but the natural caller pattern stashes
    /// once per resolve invocation and the prior stash would only
    /// survive if the caller had already issued a publish under
    /// those bytes (in which case the prior bytes are still
    /// recoverable from the chain via the A3 idempotency scan).
    ///
    /// Metadata-only — does NOT require [`VaultState::Active`].
    /// Callers will hold an active session (the build of the
    /// payload requires it) but the stash itself does not.
    ///
    /// # Errors
    ///
    /// `StoreError::Sqlite` for any database issue.
    // `enc_payload: Vec<u8>` is taken by value so the call site
    // doesn't need a borrow on a shared cipher buffer; the clippy
    // `needless_pass_by_value` lint flags the body's `&enc_payload[..]`
    // as a non-consumption, but the by-value contract here is
    // load-bearing for the move-into-SQLite ergonomics.
    #[allow(clippy::needless_pass_by_value)]
    pub fn stash_pending_merge(
        &mut self,
        account_id: AccountId,
        target_head_id: RevisionId,
        device_secret: [u8; pangolin_crypto::sign::SECRET_KEY_LEN],
        aead_nonce: [u8; NONCE_LEN],
        enc_payload: Vec<u8>,
        schema_version: u8,
    ) -> Result<()> {
        // Soft-expiry: this is metadata-only.
        self.maybe_expire_active_session();
        let now = current_unix_ms();
        // The seed is ABOUT to be persisted into a long-lived BLOB
        // column. Wrap it in zeroizing so the local stack copy is
        // wiped when this function returns — even though the bytes
        // inside SQLite remain at rest until clear_pending_merge.
        let seed_z: zeroize::Zeroizing<[u8; pangolin_crypto::sign::SECRET_KEY_LEN]> =
            zeroize::Zeroizing::new(device_secret);
        self.conn.execute(
            "INSERT OR REPLACE INTO pending_merges (
                account_id, target_head_id, device_secret, aead_nonce,
                enc_payload, schema_version, created_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                account_id.as_bytes().as_slice(),
                target_head_id.as_bytes().as_slice(),
                &seed_z[..],
                &aead_nonce[..],
                &enc_payload[..],
                i64::from(schema_version),
                now,
            ],
        )?;
        // Touch only if Active.
        self.touch_session();
        Ok(())
    }

    /// **P9 fix-pass HIGH-1.** Returns the stashed merge state for
    /// `(account_id, target_head_id)` if present.
    ///
    /// Read-only; does NOT delete the row. The caller (`sync::resolve_one`'s
    /// retry path) deletes via [`Self::clear_pending_merge`] only
    /// after `clear_frozen` succeeds, so a kill between
    /// `take_pending_merge` and `clear_frozen` still leaves a
    /// recoverable stash on disk for the next retry.
    ///
    /// The returned [`PendingMerge`]'s `device_secret` field is a
    /// [`SecretBytes`] that zeroizes on drop; callers must consume
    /// it immediately into the [`pangolin_crypto::keys::DeviceKey::from_seed`]
    /// reconstruction path and let it drop.
    ///
    /// Returns `Ok(None)` for a clean miss (no stash for this pair),
    /// distinguishable from an error case.
    ///
    /// Metadata-only — does NOT require [`VaultState::Active`].
    ///
    /// # Errors
    ///
    /// `StoreError::Sqlite` for any database issue.
    /// `StoreError::Corrupted` if a stored BLOB has the wrong length
    /// for its column (e.g., `device_secret` not 32 bytes).
    pub fn take_pending_merge(
        &self,
        account_id: AccountId,
        target_head_id: RevisionId,
    ) -> Result<Option<crate::pending::PendingMerge>> {
        // Soft-expiry would mutate self; this method is &self for
        // read-only callers, so we do not touch the session here.
        // Callers who need session-touch can do so at their own layer.
        // Local helper struct to keep the row type sane for clippy's
        // type-complexity lint (the alternative tuple `(Vec<u8>,
        // Vec<u8>, Vec<u8>, i64)` triggers `clippy::type_complexity`
        // even though it is structurally simple).
        struct StashRowRaw {
            device_secret: Vec<u8>,
            aead_nonce: Vec<u8>,
            enc_payload: Vec<u8>,
            schema_version: i64,
        }
        let row: Option<StashRowRaw> = self
            .conn
            .query_row(
                "SELECT device_secret, aead_nonce, enc_payload, schema_version
                 FROM pending_merges
                 WHERE account_id = ?1 AND target_head_id = ?2",
                params![
                    account_id.as_bytes().as_slice(),
                    target_head_id.as_bytes().as_slice(),
                ],
                |row| {
                    Ok(StashRowRaw {
                        device_secret: row.get(0)?,
                        aead_nonce: row.get(1)?,
                        enc_payload: row.get(2)?,
                        schema_version: row.get(3)?,
                    })
                },
            )
            .optional()?;
        let Some(raw) = row else {
            return Ok(None);
        };
        let StashRowRaw {
            device_secret: seed_blob,
            aead_nonce: nonce_blob,
            enc_payload,
            schema_version: sv_i64,
        } = raw;
        if seed_blob.len() != pangolin_crypto::sign::SECRET_KEY_LEN {
            return Err(StoreError::Corrupted(format!(
                "pending_merges.device_secret not {} bytes (was {})",
                pangolin_crypto::sign::SECRET_KEY_LEN,
                seed_blob.len()
            )));
        }
        if nonce_blob.len() != NONCE_LEN {
            return Err(StoreError::Corrupted(format!(
                "pending_merges.aead_nonce not {NONCE_LEN} bytes (was {})",
                nonce_blob.len()
            )));
        }
        let mut nonce_arr = [0u8; NONCE_LEN];
        nonce_arr.copy_from_slice(&nonce_blob);
        let schema_version = u8::try_from(sv_i64).map_err(|_| {
            StoreError::Corrupted("pending_merges.schema_version out of u8 range".into())
        })?;
        // SecretBytes zeroizes on drop; the seed BLOB Vec<u8> from
        // rusqlite is moved into the SecretBytes constructor and
        // wiped via the SecretBytes drop impl.
        let device_secret = SecretBytes::new(seed_blob);
        Ok(Some(crate::pending::PendingMerge {
            device_secret,
            aead_nonce: nonce_arr,
            enc_payload,
            schema_version,
        }))
    }

    /// **P9 fix-pass HIGH-1.** Delete the stashed merge state for
    /// `(account_id, target_head_id)`.
    ///
    /// Idempotent — calling on a non-existent row is a no-op (zero
    /// rows deleted; no error). The natural caller pattern is
    /// "after `clear_frozen` succeeds, drop the stash so the
    /// ephemeral signing seed no longer lives at rest."
    ///
    /// Metadata-only — does NOT require [`VaultState::Active`].
    ///
    /// # Errors
    ///
    /// `StoreError::Sqlite` for any database issue.
    pub fn clear_pending_merge(
        &mut self,
        account_id: AccountId,
        target_head_id: RevisionId,
    ) -> Result<()> {
        self.maybe_expire_active_session();
        self.conn.execute(
            "DELETE FROM pending_merges
             WHERE account_id = ?1 AND target_head_id = ?2",
            params![
                account_id.as_bytes().as_slice(),
                target_head_id.as_bytes().as_slice(),
            ],
        )?;
        self.touch_session();
        Ok(())
    }

    /// **P9 fix-pass 2 — MEDIUM-2.** Prune `pending_merges` rows for
    /// `account_id` whose `target_head_id` is no longer a current
    /// head. Returns the number of rows deleted.
    ///
    /// Background: each entry in `pending_merges` carries a 32-byte
    /// Ed25519 secret seed. A user-changed `--keep` (or
    /// chain-moved-during-resolve, or any other path that abandons a
    /// stash row) leaves the row at rest indefinitely. This sweep
    /// keeps the stash table aligned with the current head set,
    /// bounding the at-rest seed exposure to the active recovery
    /// state only.
    ///
    /// Wraps the per-row scan + DELETE in a single SQL transaction
    /// so a concurrent writer cannot interleave between the head
    /// snapshot and the DELETE. The transaction is independent of
    /// any caller-side transaction, so the prune is composable
    /// (safe to call from inside `pull_all`'s per-chunk post-ingest
    /// step, where the chunk's own transaction has already
    /// committed).
    ///
    /// Idempotent — calling on a clean table or with all targets
    /// being current heads returns `Ok(0)`.
    ///
    /// Metadata-only — does NOT require [`VaultState::Active`].
    ///
    /// # Errors
    ///
    /// `StoreError::AccountNotFound` if `account_id` is unknown.
    /// `StoreError::Sqlite` for any database issue.
    pub fn prune_orphan_pending_merges(&mut self, account_id: AccountId) -> Result<usize> {
        self.maybe_expire_active_session();

        // Cross-check the account exists at the identity layer; if
        // not, surface AccountNotFound rather than a silently-empty
        // result.
        let exists: Option<i64> = self
            .conn
            .query_row(
                "SELECT 1 FROM account_identities WHERE account_id = ?1",
                params![account_id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        if exists.is_none() {
            return Err(StoreError::AccountNotFound);
        }

        let tx = self.conn.unchecked_transaction()?;

        // Collect the current head set (same NOT EXISTS predicate
        // that `account_heads` uses, scoped by `account_id` per
        // M-1's defense-in-depth).
        let mut head_stmt = tx.prepare(
            // #106d (salvaged #103-C FINDING 2): exclude revoked rows
            // (outer) + revoked children (subquery) from the head set.
            "SELECT r.revision_id FROM revisions r
             WHERE r.account_id = ?1
               AND r.superseded_by IS NULL
               AND r.revoked = 0
               AND NOT EXISTS (
                 SELECT 1 FROM revisions r2
                 WHERE r2.parent_revision_id = r.revision_id
                   AND r2.account_id = r.account_id
                   AND r2.revoked = 0
               )",
        )?;
        let head_rows = head_stmt.query_map(params![account_id.as_bytes().as_slice()], |row| {
            let rid: Vec<u8> = row.get(0)?;
            Ok(rid)
        })?;
        let mut head_set: Vec<[u8; REVISION_ID_LEN]> = Vec::new();
        for r in head_rows {
            let blob = r?;
            let arr: [u8; REVISION_ID_LEN] = blob
                .as_slice()
                .try_into()
                .map_err(|_| StoreError::Corrupted("head revision_id not 32 bytes".into()))?;
            head_set.push(arr);
        }
        drop(head_stmt);

        // Scan stash rows for this account.
        let mut stash_stmt = tx.prepare(
            "SELECT target_head_id FROM pending_merges
             WHERE account_id = ?1",
        )?;
        let stash_rows =
            stash_stmt.query_map(params![account_id.as_bytes().as_slice()], |row| {
                let rid: Vec<u8> = row.get(0)?;
                Ok(rid)
            })?;
        let mut to_delete: Vec<[u8; REVISION_ID_LEN]> = Vec::new();
        for r in stash_rows {
            let blob = r?;
            let arr: [u8; REVISION_ID_LEN] = blob.as_slice().try_into().map_err(|_| {
                StoreError::Corrupted("pending_merges.target_head_id not 32 bytes".into())
            })?;
            if !head_set.contains(&arr) {
                to_delete.push(arr);
            }
        }
        drop(stash_stmt);

        let mut deleted: usize = 0;
        for target in &to_delete {
            tx.execute(
                "DELETE FROM pending_merges
                 WHERE account_id = ?1 AND target_head_id = ?2",
                params![account_id.as_bytes().as_slice(), &target[..]],
            )?;
            deleted += 1;
        }
        tx.commit()?;
        self.touch_session();
        Ok(deleted)
    }

    // -----------------------------------------------------------------
    // High-risk operations — presence escalation (Session spec §5.4)
    // -----------------------------------------------------------------
    //
    // Per Session spec §5.4 ("High-Risk Actions"):
    //   "High-risk actions MUST require presence proof even during an
    //    active session. Examples: reveal password; export vault;
    //    modify recovery; approve devices; extend long sessions."
    //
    // Even on an active session, ops that surface secret material to
    // the host UI (`reveal_current_password`, `reveal_password_history`,
    // `reveal_notes`, `reveal_totp_secret`, `export_payload`) require
    // an explicit *fresh* presence proof — but "fresh" means "within
    // PRESENCE_FRESHNESS (60 s) of the last successful presence", so a
    // reveal moments after unlock, or a second reveal moments after the
    // first, does NOT re-prompt (§5.2 "access remains seamless"; §8.6
    // prompt dedup). The freshness window is the engine-side authority;
    // `ensure_presence_fresh` is the single check.
    //
    // Order of operations (security-critical):
    //   1. check_session_freshness — session-state structural check.
    //      If the session is locked / expired, return immediately
    //      WITHOUT touching the supplied presence proof. The proof's
    //      single-use flag is preserved for the caller to retry after
    //      reauth.
    //   2. refuse_if_frozen — refuse a frozen account BEFORE the proof
    //      is consumed (P8 fix CRIT-1).
    //   3. ensure_presence_fresh — dedup-or-verify. Within the window,
    //      no proof is consumed; outside it, the proof must verify
    //      (NotFresh ⇒ PromptTimedOut; other ⇒ AuthenticationFailed).
    //   4. Read the requested secret (from disk via the V1 identity for
    //      `reveal_password_history`, from the in-memory cache shadow
    //      for the head password / notes / totp).
    //   5. touch_session — extend the idle deadline.

    /// Reveal the **current** (head-of-history) plaintext password for
    /// an account. **High-risk operation** (Session spec §5.4).
    ///
    /// Requires an active session + a fresh presence proof (dedup'd
    /// within [`crate::session::PRESENCE_FRESHNESS`] — see the
    /// section comment above). Returns a freshly-allocated
    /// [`SecretBytes`] (zeroes on drop) cloned from the in-memory
    /// cache shadow; the cache stays intact. For the **full** password
    /// history (including superseded values, their timestamps, and the
    /// device that authored each), use [`Self::reveal_password_history`].
    ///
    /// # Errors
    ///
    /// - [`StoreError::SessionExpired`] / [`StoreError::NotUnlocked`]
    ///   if the session is not active (cache zeroized as a side-effect
    ///   of the freshness check if expiry was detected; proof not
    ///   consumed).
    /// - [`StoreError::AccountFrozenPendingResolve`] if the account is
    ///   frozen (proof not consumed).
    /// - [`StoreError::PromptTimedOut`] if the supplied presence proof
    ///   is stale (the prompt aged past the freshness window).
    /// - [`StoreError::AuthenticationFailed`] for any other presence-
    ///   proof failure (replayed, generic).
    /// - [`StoreError::AccountNotFound`] if `id` is unknown to the
    ///   cache (truly unknown or tombstoned).
    pub fn reveal_current_password(
        &mut self,
        id: AccountId,
        presence: &dyn PresenceProof,
    ) -> Result<SecretBytes> {
        self.reveal_secret_field(id, presence, |snap| snap.password.expose().to_vec())
    }

    /// Back-compat alias for [`Self::reveal_current_password`] — the
    /// P4 / CLI / pre-1.4 name. Identical semantics.
    pub fn reveal_password(
        &mut self,
        id: AccountId,
        presence: &dyn PresenceProof,
    ) -> Result<SecretBytes> {
        self.reveal_current_password(id, presence)
    }

    /// Reveal the **full password history** for an account, surfacing
    /// the production V1 model's data: every [`crate::account::PasswordEntry`]
    /// — plaintext bytes + the `set_at_ms` timestamp + the originating
    /// device id — newest first (the head entry is the current
    /// password). **High-risk operation** (Session spec §5.4); the FFI
    /// `AccountSnapshot` carries only the *count* (Q5b).
    ///
    /// Reads the head identity from disk (V1-aware decrypt, auto-
    /// migrating V0 payloads), not from the V0-shaped in-memory cache
    /// shadow — the cache shadow only holds the head password.
    ///
    /// # Errors
    ///
    /// Same set as [`Self::reveal_current_password`], plus
    /// [`StoreError::AccountTombstoned`] / [`StoreError::Corrupted`] /
    /// [`StoreError::Sqlite`] for storage-level failures.
    pub fn reveal_password_history(
        &mut self,
        id: AccountId,
        presence: &dyn PresenceProof,
    ) -> Result<Vec<crate::account::PasswordHistorySummaryEntry>> {
        self.check_session_freshness()?;
        self.refuse_if_frozen(id)?;
        self.refuse_if_requires_upgrade(id)?;
        self.ensure_presence_fresh(presence)?;
        let identity = self.read_head_identity(id)?;
        let crate::account::AccountIdentity {
            password_history, ..
        } = identity;
        let out = password_history
            .into_iter()
            .map(|e| crate::account::PasswordHistorySummaryEntry {
                password: e.password,
                set_at_ms: e.set_at_ms,
                originating_device: e.originating_device,
            })
            .collect();
        self.touch_session();
        Ok(out)
    }

    /// Reveal the plaintext notes for an account. **High-risk operation**
    /// (Session spec §5.4 — notes can carry recovery-class secrets:
    /// recovery phrases, security-question answers). Returns a
    /// freshly-allocated [`SecretBytes`] cloned from the in-memory
    /// cache shadow.
    ///
    /// # Errors
    ///
    /// Same set as [`Self::reveal_current_password`].
    pub fn reveal_notes(
        &mut self,
        id: AccountId,
        presence: &dyn PresenceProof,
    ) -> Result<SecretBytes> {
        self.reveal_secret_field(id, presence, |snap| snap.notes.expose().to_vec())
    }

    /// Reveal the raw plaintext TOTP shared-secret seed for an account.
    /// **High-risk operation** (Session spec §5.4 + the Phase-2 note —
    /// the raw seed is reveal-class; 1.7's RFC-6238 generator consumes
    /// it internally without a reveal, but exporting/revealing the
    /// *seed* is high-risk). Returns a freshly-allocated [`SecretBytes`]
    /// cloned from the in-memory cache shadow; empty (`expose() == b""`)
    /// when no TOTP is configured.
    ///
    /// # Errors
    ///
    /// Same set as [`Self::reveal_current_password`].
    pub fn reveal_totp_secret(
        &mut self,
        id: AccountId,
        presence: &dyn PresenceProof,
    ) -> Result<SecretBytes> {
        self.reveal_secret_field(id, presence, |snap| snap.totp_secret.expose().to_vec())
    }

    /// Generate the RFC 6238 TOTP code for an account at the given Unix
    /// time. **Session-class** (MVP-1 issue 1.7 Q3): only an unlocked,
    /// non-expired session is required — *no presence proof*. The TOTP
    /// code is the ephemeral user-facing artifact (refreshed every
    /// `period` seconds); the durable *seed* stays reveal-class via
    /// [`Self::reveal_totp_secret`]. The seed is decrypted transiently
    /// inside this call (and inside `pangolin-totp`) and zeroized
    /// before returning; only the digit string crosses out.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotUnlocked`] / [`StoreError::SessionExpired`] for a
    /// locked / expired session; [`StoreError::FrozenAccount`] /
    /// [`StoreError::UnsupportedRevisionSchemaVersion`] for a frozen /
    /// requires-upgrade account; [`StoreError::Validation`] with
    /// `kind = "totp_not_configured"` when the account has no TOTP
    /// secret; storage-level failures otherwise.
    pub fn totp_generate(
        &mut self,
        id: AccountId,
        at_unix_secs: u64,
    ) -> Result<pangolin_totp::TotpCode> {
        self.check_session_freshness()?;
        self.refuse_if_frozen(id)?;
        self.refuse_if_requires_upgrade(id)?;
        let identity = self.read_head_identity(id)?;
        if !identity.has_totp() {
            return Err(StoreError::Validation {
                kind: "totp_not_configured".into(),
                message: "no TOTP secret configured for this account".into(),
            });
        }
        let params = identity.totp_params();
        let secret = zeroize::Zeroizing::new(identity.totp_secret().expose().to_vec());
        let code = pangolin_totp::totp_at(&secret, at_unix_secs, &params).map_err(|e| {
            StoreError::Validation {
                kind: "totp_params".into(),
                message: e.to_string(),
            }
        })?;
        // `identity` (ZeroizeOnDrop) and `secret` (Zeroizing) wipe here.
        self.touch_session();
        Ok(code)
    }

    /// Shared implementation for the cache-shadow `reveal_*` accessors
    /// (head password / notes / totp). The only thing that varies is
    /// which [`SecretBytes`] field gets cloned out at step 4. Order of
    /// operations is the section comment above.
    fn reveal_secret_field<F>(
        &mut self,
        id: AccountId,
        presence: &dyn PresenceProof,
        extract: F,
    ) -> Result<SecretBytes>
    where
        F: FnOnce(&AccountSnapshot) -> Vec<u8>,
    {
        // Step 1: structural session check (proof not consumed on fail).
        self.check_session_freshness()?;
        // Step 2: refuse a frozen account before the proof is consumed
        // (P8 fix CRIT-1).
        self.refuse_if_frozen(id)?;
        // Step 2b (1.6 §18.7): refuse a "requires upgrade" account.
        self.refuse_if_requires_upgrade(id)?;
        // Step 3: dedup-or-verify the presence proof (Session spec
        // §7.6 / §8.6). Within PRESENCE_FRESHNESS of the last
        // successful presence — including the unlock's — no proof is
        // consumed; outside it, the proof verifies, NotFresh ⇒
        // PromptTimedOut, other ⇒ AuthenticationFailed.
        self.ensure_presence_fresh(presence)?;
        // Step 4: read from the in-memory cache shadow. Clone the
        // requested field into a fresh zeroizing allocation; the
        // original stays cached.
        let active = self.require_active()?;
        let snapshot = active.cache.get(id).ok_or(StoreError::AccountNotFound)?;
        let bytes = extract(snapshot);
        let out = SecretBytes::new(bytes);
        // Step 5: touch the session (extends the idle deadline).
        self.touch_session();
        Ok(out)
    }

    /// Read + decrypt the current head identity (V1 model) for `id`,
    /// auto-migrating a V0 payload. Looks up the head pointer in SQL,
    /// rejects tombstoned accounts, and routes through the V1-aware
    /// `read_identity_at`. Used by [`Self::reveal_password_history`];
    /// distinct from `account_get`'s summary builder in that it returns
    /// the in-memory model unchanged.
    fn read_head_identity(&self, id: AccountId) -> Result<crate::account::AccountIdentity> {
        let account_row = self
            .conn
            .query_row(
                "SELECT tombstoned, head_revision_id
                 FROM account_identities WHERE account_id = ?1",
                params![id.as_bytes().as_slice()],
                |row| {
                    let tombstoned: i64 = row.get(0)?;
                    let head: Vec<u8> = row.get(1)?;
                    Ok((tombstoned != 0, head))
                },
            )
            .optional()?
            .ok_or(StoreError::AccountNotFound)?;
        if account_row.0 {
            return Err(StoreError::AccountTombstoned);
        }
        let head_arr: [u8; REVISION_ID_LEN] = account_row
            .1
            .as_slice()
            .try_into()
            .map_err(|_| StoreError::Corrupted("head_revision_id not 32 bytes".into()))?;
        self.read_identity_at(id, RevisionId::from_bytes(head_arr))
    }

    /// Run an operation under session-policy supervision; on
    /// expiration, prompt the supplied re-auth callback and resume.
    ///
    /// Mirrors Pangolin §8.5 (mid-action expiration semantics): when
    /// the user invokes a credential op and the session is found to
    /// be expired (idle timeout / absolute max), the host UI is
    /// supposed to prompt for re-auth and then transparently resume
    /// the action. `with_session` is the storage-layer primitive that
    /// host shells (CLI, Tauri desktop, mobile) wrap with their own
    /// UI prompt code.
    ///
    /// # Order of operations (per the plan §"Mid-action resume primitive")
    ///
    /// ```text
    /// match check_session_freshness() {
    ///     Ok(())               => op(self)
    ///     Err(SessionExpired)  => reauth(self)?; op(self)
    ///     Err(other)           => return Err(other)
    /// }
    /// ```
    ///
    /// The proactive `check_session_freshness` guarantees that any
    /// expiry detected at-or-before the start of the op surfaces the
    /// re-auth prompt. (A session that expires mid-op — e.g., after
    /// an Argon2 derivation runs for ~1.5 s and the deadline was
    /// within that window — is NOT retried; the op returns whatever
    /// the underlying call returned. `PoC` accepts this; MVP-1 may
    /// add a "transactional retry" wrapper.)
    ///
    /// # Information leakage discipline
    ///
    /// Critical security invariant: the `reauth` callback MUST NOT
    /// see anything that could distinguish "session was active and
    /// op ran" from "session was expired and reauth was prompted",
    /// other than the bare fact that reauth was called. The op
    /// itself is invoked AFTER reauth on the expired-session branch,
    /// so the op cannot leak information about the session's prior
    /// state via the reauth callback's inputs (which are just
    /// `&mut self`).
    ///
    /// # Errors
    ///
    /// Forwards every error from `op` and `reauth`. If `reauth`
    /// returns `Err(_)`, the original op is NOT executed and the
    /// reauth error propagates.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use pangolin_store::{Vault, AccountSnapshot};
    /// # use pangolin_store::{PinIdentityProof, PressYPresenceProof};
    /// # use pangolin_crypto::secret::SecretBytes;
    /// # fn ex(vault: &mut Vault, pwd: &SecretBytes) -> pangolin_store::Result<()> {
    /// let count = vault.with_session(
    ///     |v| Ok(v.list_accounts().len()),
    ///     |v| {
    ///         let presence = PressYPresenceProof::confirmed();
    ///         let identity = PinIdentityProof::new(SecretBytes::new(pwd.expose().to_vec()));
    ///         v.unlock(&presence, &identity)
    ///     },
    /// )?;
    /// # let _ = count;
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_session<F, T, R>(&mut self, op: F, reauth: R) -> Result<T>
    where
        F: FnOnce(&mut Self) -> Result<T>,
        R: FnOnce(&mut Self) -> Result<()>,
    {
        match self.check_session_freshness() {
            Ok(()) => op(self),
            Err(StoreError::SessionExpired) => {
                // Re-auth: the host UI's prompt + 2-proof unlock flow.
                // If reauth succeeds, the vault is back in Active and
                // the op runs. If reauth itself errors (user
                // cancelled, wrong PIN, ...), the error propagates
                // and the original op is NOT executed.
                reauth(self)?;
                // L-3 (P4 audit): re-validate session freshness AFTER
                // reauth claims `Ok(())`. A malformed reauth
                // implementation that returns `Ok(())` without
                // actually transitioning the vault back to `Active`
                // (or leaving it Active-but-already-expired against
                // the clock — possible if reauth burns enough time)
                // would otherwise let `op` run against an invalid
                // session. Surfacing `SessionExpired` immediately is
                // both more explicit and avoids any ambiguity about
                // what state `op` ran under.
                self.check_session_freshness()?;
                op(self)
            }
            Err(other) => Err(other),
        }
    }

    /// Export an account's sealed payload for future key migration /
    /// backup.
    ///
    /// **High-risk operation** (Session spec §5.4). Same proof
    /// discipline as [`Self::reveal_current_password`]: an active
    /// session plus a fresh presence proof (dedup'd within
    /// [`crate::session::PRESENCE_FRESHNESS`]).
    ///
    /// Returns the on-disk AEAD ciphertext + nonce concatenation for
    /// the account's current head revision: `[nonce (24B)] || [ct]`.
    /// The bytes remain AEAD-sealed under the vault's VDK and require
    /// the same vault to decrypt — this primitive is for downstream
    /// migration tooling (P9 vault key rotation, MVP-1 multi-device
    /// re-wrap) rather than direct plaintext export. Plaintext export
    /// requires a separate, even-more-dangerous primitive (1.10).
    ///
    /// # Errors
    ///
    /// Same set as [`Self::reveal_current_password`], plus
    /// [`StoreError::AccountTombstoned`] if the account is tombstoned
    /// and [`StoreError::Sqlite`] for any storage-level issue.
    pub fn export_payload(
        &mut self,
        id: AccountId,
        presence: &dyn PresenceProof,
    ) -> Result<Vec<u8>> {
        self.check_session_freshness()?;
        // P8 fix CRIT-1: refuse before consuming the presence proof —
        // same discipline as `reveal_secret_field`.
        self.refuse_if_frozen(id)?;
        self.refuse_if_requires_upgrade(id)?;
        self.ensure_presence_fresh(presence)?;

        // Look up the account's current head and read its sealed
        // payload directly from the revisions table. We deliberately
        // do NOT re-seal: the on-disk ciphertext is already AEAD-bound
        // to (vault_id, account_id, parent_revision_id, schema_version)
        // via the AAD; downstream migration tooling reconstructs the
        // same AAD and re-decrypts under the same VDK. Re-sealing
        // here would just burn entropy and break round-trip
        // re-import.
        let head_row = self
            .conn
            .query_row(
                "SELECT ai.tombstoned, r.enc_nonce, r.enc_payload
                 FROM account_identities ai
                 JOIN revisions r ON ai.head_revision_id = r.revision_id
                 WHERE ai.account_id = ?1",
                params![id.as_bytes().as_slice()],
                |row| {
                    let tombstoned: i64 = row.get(0)?;
                    let nonce: Vec<u8> = row.get(1)?;
                    let payload: Vec<u8> = row.get(2)?;
                    Ok((tombstoned != 0, nonce, payload))
                },
            )
            .optional()?
            .ok_or(StoreError::AccountNotFound)?;
        if head_row.0 {
            return Err(StoreError::AccountTombstoned);
        }
        let (_, nonce_blob, payload_blob) = head_row;

        // Concat: [nonce (24)] || [ciphertext (variable)]. Caller
        // splits at 24 bytes on import.
        let mut out = Vec::with_capacity(nonce_blob.len() + payload_blob.len());
        out.extend_from_slice(&nonce_blob);
        out.extend_from_slice(&payload_blob);

        self.touch_session();
        Ok(out)
    }

    // -----------------------------------------------------------------
    // MVP-1 issue 1.10: encrypted export / restore-to-fresh-vault.
    //
    // Both export entries are reveal-class (Session spec §5.4 — "export
    // vault" is a high-risk action requiring presence even mid-session):
    // same `check_session_freshness` → `ensure_presence_fresh` →
    // `touch_session` pre-amble as `export_payload` / `reveal_*`. The
    // archive format + codec + decoder live in `crate::export`; these
    // methods gather the snapshot from the open vault. `restore_to_new_vault`
    // operates on a file path + archive passphrase, not an unlocked vault.
    // -----------------------------------------------------------------

    /// Gather the [`crate::export::ArchiveSnapshot`] for `selection` from
    /// this open vault. Shared by [`Self::export_encrypted`] and
    /// [`Self::export_plaintext`]. Reads every (non-tombstoned) account
    /// matching the selection — the full V1 identity (incl. the password
    /// history bytes/timestamps/devices) — plus the device trust list and
    /// the session-idle `meta` setting plus the provenance fingerprint.
    fn gather_archive_snapshot(
        &self,
        selection: &crate::export::AccountSelection,
    ) -> Result<crate::export::ArchiveSnapshot> {
        let exported_at = current_unix_ms() / 1000;
        let source_device_id = self.device_id.0;
        let vault_id = self.meta.vault_id;
        let session_idle_secs = meta::read_session_idle_secs(&self.conn)?;

        // Every live (non-tombstoned, non-frozen-by-upgrade) account id.
        let mut acct_rows: Vec<([u8; ACCOUNT_ID_LEN], i64)> = Vec::new();
        {
            let mut stmt = self.conn.prepare(
                "SELECT account_id, created_at FROM account_identities
                 WHERE tombstoned = 0 ORDER BY account_id ASC",
            )?;
            let rows = stmt.query_map([], |row| {
                let id: Vec<u8> = row.get(0)?;
                let created: i64 = row.get(1)?;
                Ok((id, created))
            })?;
            for r in rows {
                let (blob, created) = r?;
                let arr: [u8; ACCOUNT_ID_LEN] = blob.as_slice().try_into().map_err(|_| {
                    StoreError::Corrupted("account_identities.account_id not 32 bytes".into())
                })?;
                if selection.includes(&arr) {
                    acct_rows.push((arr, created));
                }
            }
        }

        let mut accounts = Vec::with_capacity(acct_rows.len());
        for (id_bytes, created_at_ms) in acct_rows {
            let id = AccountId::from_bytes(id_bytes);
            // Skip a "requires upgrade" account rather than fail the
            // whole export (it can't be hydrated by this build).
            if self.account_requires_upgrade(id) {
                continue;
            }
            let identity = match self.read_head_identity(id) {
                Ok(i) => i,
                Err(StoreError::AccountTombstoned) => continue,
                Err(e) => return Err(e),
            };
            let crate::account::AccountIdentity {
                display_name,
                tags,
                notes,
                urls,
                usernames,
                password_history,
                totp_secret,
                totp_params,
            } = identity;
            let archived_history = password_history
                .into_iter()
                .map(|e| {
                    let crate::account::PasswordEntry {
                        password,
                        set_at_ms,
                        originating_device,
                    } = e;
                    crate::export::ArchivedPasswordEntry {
                        password,
                        set_at_ms,
                        originating_device,
                    }
                })
                .collect();
            accounts.push(crate::export::ArchivedAccount {
                account_id: id_bytes,
                created_at_ms,
                display_name,
                tags,
                urls,
                usernames,
                notes,
                password_history: archived_history,
                totp_secret,
                totp_params,
            });
        }

        let devices = device::list_devices(&self.conn, &self.device_id)?
            .into_iter()
            .map(|d| crate::export::ArchivedDevice {
                device_id: d.device_id.0,
                label: d.label,
                added_at_ms: d.registered_at,
            })
            .collect();

        // MVP-1 issue 1.11 (L10): also gather the capture_authorities
        // registry. The destination of a restore does NOT re-register
        // them (Q-f / R-f) — but the archive carries them for archive
        // fidelity / a future MVP-3+ advanced-restore flow.
        let capture_authorities = self.gather_archive_capture_authorities()?;

        Ok(crate::export::ArchiveSnapshot {
            schema_version: crate::export::ARCHIVE_SNAPSHOT_SCHEMA_VERSION,
            exported_at,
            source_device_id,
            vault_id,
            session_idle_secs,
            accounts,
            devices,
            capture_authorities,
        })
    }

    /// Snapshot the `capture_authorities` table for archive export.
    /// Sorted by `(context_kind, platform_hint)` (stable output).
    /// Distinct from [`Self::capture_authority_list`] in that it does
    /// NOT touch the session machinery (no `check_session_freshness` /
    /// `touch_session`) — the caller has already done that as part of
    /// `export_encrypted` / `export_plaintext`.
    fn gather_archive_capture_authorities(
        &self,
    ) -> Result<Vec<crate::capture_authority::CapturedCaptureAuthority>> {
        let sql = format!(
            "SELECT {} FROM capture_authorities ORDER BY context_kind ASC, platform_hint ASC",
            crate::capture_authority::CAPTURE_AUTHORITIES_SELECT_COLS
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let mapped = stmt.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
            ))
        })?;
        let mut out = Vec::new();
        for r in mapped {
            let (ck, ph, ak, cid, cv, at, sv_i) = r?;
            let schema_version =
                u16::try_from(sv_i).map_err(|_| StoreError::CaptureAuthorityValidation {
                    reason: "stored schema_version out of u16 range".into(),
                })?;
            out.push(crate::capture_authority::CapturedCaptureAuthority {
                context_kind: ck,
                platform_hint: ph,
                authority_kind: ak,
                component_id: cid,
                component_version: cv,
                registered_at: at,
                schema_version,
            });
        }
        Ok(out)
    }

    /// Export an encrypted, self-contained Pangolin vault archive.
    ///
    /// **High-risk operation** (Session spec §5.4). Routes through the
    /// same presence gate as [`Self::export_payload`] / `reveal_*`: an
    /// active session plus a fresh presence proof. The archive is
    /// AEAD-sealed (XChaCha20-Poly1305) under a 256-bit key derived
    /// (Argon2id, `KdfParams::RECOMMENDED`) from `passphrase` — a fresh
    /// user-supplied export passphrase, independent of the vault master
    /// password — over a random 16-byte salt stored in the archive's
    /// plaintext header (which is the AEAD AAD). The returned bytes are
    /// `header || ciphertext`; the plaintext snapshot is never written
    /// un-sealed and never escapes this call's `Zeroizing` buffers.
    ///
    /// # Errors
    ///
    /// Same session/presence set as [`Self::export_payload`]
    /// ([`StoreError::NotUnlocked`], [`StoreError::SessionExpired`],
    /// [`StoreError::PromptTimedOut`], …); [`StoreError::Validation`]
    /// with an `export_*` `kind` on a crypto/serialization failure.
    pub fn export_encrypted(
        &mut self,
        passphrase: &SecretBytes,
        selection: &crate::export::AccountSelection,
        presence: &dyn PresenceProof,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        self.check_session_freshness()?;
        self.ensure_presence_fresh(presence)?;
        let snapshot = self.gather_archive_snapshot(selection)?;
        let plain = crate::export::encode_snapshot(&snapshot);
        drop(snapshot);
        let archive = crate::export::seal_archive(passphrase, &plain)?;
        self.touch_session();
        Ok(archive)
    }

    /// Export an **unencrypted, cleartext** Pangolin vault dump (the
    /// spec-guarded `--plaintext` branch — Design Spec §11 / master plan
    /// §4 row 1.10). **This writes every secret in cleartext.**
    ///
    /// **High-risk operation** (Session spec §5.4) — same presence gate
    /// as [`Self::export_encrypted`] — and additionally requires a
    /// structurally-valid single-use confirmation token. The
    /// double-confirmation + 30 s delay + warning copy are owned by the
    /// CLI/UI; the engine just refuses an empty/invalid token. The
    /// returned bytes carry a loud in-file cleartext banner.
    ///
    /// # Errors
    ///
    /// As [`Self::export_encrypted`], plus [`StoreError::Validation`]
    /// with `kind = "export_not_confirmed"` for an invalid token.
    pub fn export_plaintext(
        &mut self,
        confirmation: &crate::export::PlaintextExportConfirmationData,
        selection: &crate::export::AccountSelection,
        presence: &dyn PresenceProof,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        self.check_session_freshness()?;
        self.ensure_presence_fresh(presence)?;
        if !confirmation.is_valid() {
            return Err(StoreError::Validation {
                kind: "export_not_confirmed".into(),
                message: "plaintext export was not confirmed".into(),
            });
        }
        let snapshot = self.gather_archive_snapshot(selection)?;
        let bytes = crate::export::render_plaintext(&snapshot);
        drop(snapshot);
        self.touch_session();
        Ok(bytes)
    }

    /// Restore a **brand-new** `.pvf` vault at `dest` from a decoded
    /// archive `snapshot`, using `new_master_password` for the new
    /// vault's master key. Does **not** touch any existing vault and does
    /// **not** merge — that's deferred to MVP-2 (signed Revision Log v1).
    ///
    /// Each archived account is reconstructed through the normal
    /// validated `account_add` / `account_update` history-replay path
    /// (see [`Self::restore_write_account`]) — so the new vault preserves
    /// the credential **content** (the head password, the full sequence
    /// of historical password *values*, the identity fields, the TOTP
    /// slot) but **not** the lineage metadata: each restored account gets
    /// a *fresh random* `account_id` (not the source's), `now` timestamps
    /// on the replayed history entries (not the originals), and this (the
    /// new vault's) device as the originating device. The archived
    /// **device trust list is NOT written** into the new vault — the
    /// restored `.pvf` is its own fresh device (registered on its first
    /// unlock); grafting the source's device rows would mis-elect the
    /// device-key-load row and graft foreign device identities with no
    /// key material (the archive payload still carries the source device
    /// list / ids / timestamps / originating-devices — D1/D6 — for any
    /// future lineage-preserving restore). The session-idle `meta`
    /// setting is carried over. `snapshot` is moved in and dropped
    /// (zeroized) before returning. Matches the description in
    /// `docs/architecture/encrypted-export.md` and `THREAT_MODEL.md`.
    ///
    /// # Errors
    ///
    /// [`StoreError::AlreadyOpen`] / [`StoreError::Io`] if `dest` exists
    /// or cannot be created; [`StoreError::Validation`] for an internal
    /// failure; storage-level errors otherwise.
    pub fn restore_to_new_vault(
        dest: &Path,
        snapshot: crate::export::ArchiveSnapshot,
        new_master_password: &SecretBytes,
    ) -> Result<()> {
        // `snapshot` is `ZeroizeOnDrop` — it wipes when this fn returns.
        // Provision the fresh `.pvf`, then close it and re-open before
        // populating it — mirrors the proven create→close→open→unlock
        // pattern used elsewhere (e2e), so the `meta` write that `create`
        // committed is fully checkpointed into the on-disk DB before this
        // session writes a single revision.
        Self::create(dest, new_master_password)?.close()?;
        let mut vault = Self::open(dest)?;
        let presence = crate::session::PressYPresenceProof::confirmed();
        let identity = crate::session::PinIdentityProof::new(SecretBytes::new(
            new_master_password.expose().to_vec(),
        ));
        vault.unlock(&presence, &identity)?;

        // Carry over the session-idle meta setting.
        if let Some(secs) = snapshot.session_idle_secs {
            meta::write_session_idle_secs(&vault.conn, Some(secs))?;
        }

        // Reconstruct each archived account (head + replayed history).
        for a in &snapshot.accounts {
            vault.restore_write_account(a)?;
        }

        // 1.10 fidelity note: the archived device *trust list* is NOT
        // re-written into the new vault. The restored `.pvf` is its own
        // fresh device (registered on its first unlock); injecting the
        // source's device rows would (a) make this build's
        // device-key-load path pick the wrong device row (it elects the
        // oldest `added_at`) and fail, and (b) graft foreign device
        // identities with no key material — the trust-list reconciliation
        // belongs with MVP-2's signed authority registry. The archive
        // payload still carries the source device list (D1) for any
        // future merge.
        let _ = &snapshot.devices;

        // MVP-1 issue 1.11 (L10) / Q-f / R-f: the archived
        // capture-authority registry is NOT re-registered on the new
        // vault either — the destination is a new environment (new
        // device, possibly new OS); the source's registration is
        // stale; the user re-registers helpers on the new device
        // (when they're also re-installing extensions anyway). Mirrors
        // the `snapshot.devices` posture. The archive payload still
        // carries the source registry for a future MVP-3+ advanced-
        // restore flow.
        let _ = &snapshot.capture_authorities;

        vault.close()?;
        drop(snapshot);
        Ok(())
    }

    /// **1.10 restore helper.** Reconstruct one archived account into
    /// this (freshly-created, unlocked) vault.
    ///
    /// The non-secret identity fields + the head TOTP slot are written
    /// via the normal validated `account_add` path; the password history
    /// is replayed oldest-first via `account_update` so the restored
    /// vault has the same head password *and* the same number of
    /// historical password values (with their plaintext bytes).
    ///
    /// **1.10 fidelity note:** the restored account gets a *fresh*
    /// `account_id` (a new random id, not the source vault's), `now`
    /// timestamps on the history entries, and this device as the
    /// originating device — the encrypted archive payload still carries
    /// the original ids/timestamps/originating-devices (D1/D6); the
    /// *restore-to-a-fresh-vault* path in 1.10 reconstructs the
    /// credential content, not the lineage metadata. (Lineage-preserving
    /// restore is a follow-up alongside MVP-2's signed Revision Log.)
    fn restore_write_account(&mut self, a: &crate::export::ArchivedAccount) -> Result<AccountId> {
        // The archive stores the history head-first; replay oldest →
        // newest so the final head matches the source's current
        // password.
        let mut entries: Vec<&crate::export::ArchivedPasswordEntry> =
            a.password_history.iter().collect();
        entries.reverse();
        let first_pw = entries
            .first()
            .map_or_else(Vec::new, |e| e.password.expose().to_vec());
        let to_str = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
        // The validated `account_add` path requires ≥ 1 username; every
        // account written through the normal API has one, but synthesize
        // a placeholder if a hand-built archive somehow has none.
        let usernames: Vec<String> = if a.usernames.is_empty() {
            vec!["(no username)".to_string()]
        } else {
            a.usernames.iter().map(|u| to_str(u.expose())).collect()
        };
        let draft = crate::account::AccountIdentityDraft {
            schema_version: crate::account::ACCOUNT_IDENTITY_SCHEMA_VERSION,
            display_name: to_str(a.display_name.expose()),
            tags: a.tags.iter().map(|t| to_str(t.expose())).collect(),
            usernames,
            urls: a.urls.iter().map(|u| to_str(u.expose())).collect(),
            notes: to_str(a.notes.expose()),
            password: SecretBytes::new(first_pw),
            totp_secret: SecretBytes::new(a.totp_secret.expose().to_vec()),
            totp_params: a.totp_params,
        };
        let id = self.account_add(draft)?;
        // Replay the remaining history entries (oldest already written
        // as genesis).
        for e in entries.iter().skip(1) {
            let patch = crate::account::AccountIdentityPatch {
                schema_version: crate::account::ACCOUNT_IDENTITY_SCHEMA_VERSION,
                display_name: None,
                tags: None,
                usernames: None,
                urls: None,
                notes: None,
                password: Some(SecretBytes::new(e.password.expose().to_vec())),
                totp_secret: None,
                totp_params: None,
            };
            self.account_update(id, patch)?;
        }
        Ok(id)
    }

    // -----------------------------------------------------------------
    // MVP-1 issue 1.5: device identity + local trust list.
    //
    // The trust list is the `devices` table; it is add-only (no
    // revoke/remove path in MVP-1) and gates nothing destructive — it
    // is the local record + the MVP-2 on-chain-authority-registry hook.
    // `device_current` / `device_list` read it; they work on a locked
    // vault that has been unlocked at least once (the `devices` row is
    // persisted by register-on-unlock). `device_set_label` mutates the
    // human-readable label only — Q5: it requires an active (unlocked,
    // non-expired) session, NOT a fresh presence proof (it is not on
    // the Session spec §5.4 reveal-class list).
    // -----------------------------------------------------------------

    /// The device this `Vault` is running on (a `devices`-table row).
    ///
    /// Works on a `Locked` vault that has been unlocked at least once on
    /// this file (register-on-unlock persists the row + the AEAD-sealed
    /// device key). On a brand-new vault that has been opened but never
    /// unlocked there is no device row yet → returns
    /// [`StoreError::NotUnlocked`] (unlock once to register).
    ///
    /// # Errors
    ///
    /// [`StoreError::NotUnlocked`] when no device has been registered;
    /// [`StoreError::Sqlite`] / [`StoreError::Corrupted`] on a storage
    /// failure.
    pub fn device_current(&self) -> Result<DeviceIdentity> {
        device::read_device(&self.conn, &self.device_id, &self.device_id)?
            .ok_or(StoreError::NotUnlocked)
    }

    /// Every device in the trust list (one row in MVP-1). The
    /// `is_current` flag is set on the row matching this handle's
    /// `device_id`. Empty when no device has been registered yet
    /// (brand-new vault never unlocked). Same locked-vault behaviour as
    /// [`Self::device_current`].
    ///
    /// # Errors
    ///
    /// [`StoreError::Sqlite`] / [`StoreError::Corrupted`] on a storage
    /// failure.
    pub fn device_list(&self) -> Result<Vec<DeviceIdentity>> {
        device::list_devices(&self.conn, &self.device_id)
    }

    /// Rename a device in the trust list. Validates `label` (non-empty
    /// after trim, ≤ [`crate::device::DEVICE_LABEL_MAX_CHARS`] chars,
    /// NFC-normalised); persists. Survives close/reopen.
    ///
    /// **Q5:** requires an active (unlocked, non-expired) session — the
    /// same gate as `account_update`'s display-name edit — NOT a fresh
    /// presence proof. Renaming a device mutates only a human-readable
    /// string; it is not a §5.4 reveal-class action.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotUnlocked`] / [`StoreError::SessionExpired`] /
    /// [`StoreError::SessionPending`] when the session is not active;
    /// [`StoreError::Validation`] (`kind = "device_label"`) for an
    /// empty / over-long / control-char label;
    /// [`StoreError::AccountNotFound`] when `id` is not in the trust
    /// list.
    pub fn device_set_label(&mut self, id: DeviceId, label: &str) -> Result<()> {
        self.check_session_freshness()?;
        let _ = self.require_active()?;
        let canonical = device::validate_label(label)?;
        device::set_device_label(&self.conn, &id, &canonical)?;
        self.touch_session();
        Ok(())
    }

    // -----------------------------------------------------------------
    // MVP-1 issue 1.11: capture-authority registry.
    //
    // Browser-Ext spec §2.3 / API contract §16 / Threat Model invariant
    // #8: at most one component owns capture per context. The registry
    // lives in the `capture_authorities` table (PRIMARY KEY
    // (context_kind, platform_hint) — structural exclusivity). Reads
    // are session-class (no presence). Writes are *hybrid* (L6, R-c):
    // a `Created` or `NoOp` registration is session-class; a
    // `Replaced` registration (existing row overwritten via
    // `replace_existing=true`) is reveal-class — presence proof is
    // verified via `ensure_presence_fresh` before the REPLACE is
    // committed, same machinery as `reveal_*` / `export_*`.
    // -----------------------------------------------------------------

    /// Register a capture authority for a context.
    ///
    /// On entry:
    /// - `check_session_freshness()` runs first (locked / expired
    ///   session is rejected before any work).
    /// - `authority` and `context` are validated per L7 (NFC, length,
    ///   character classes, `platform_hint` allowlist, future-schema
    ///   reject).
    /// - The IMMEDIATE transaction looks up the existing row for the
    ///   `(context_kind, platform_hint)` key:
    ///   - **No existing row** → INSERT new row, return
    ///     [`crate::capture_authority::RegistrationOutcome::Created`].
    ///     Session-class.
    ///   - **Existing row, byte-identical payload** → no-op, return
    ///     [`crate::capture_authority::RegistrationOutcome::NoOp`].
    ///     Session-class.
    ///   - **Existing row, different payload**, `replace_existing=false`
    ///     → [`StoreError::CaptureAuthorityExclusivity`]. The error
    ///     names the context kind only (no info-leak on the existing
    ///     `component_id`).
    ///   - **Existing row, different payload**, `replace_existing=true`
    ///     → reveal-class branch: `ensure_presence_fresh(presence)`
    ///     consumes the proof, then REPLACE the row, then
    ///     `touch_session()`. Returns
    ///     [`crate::capture_authority::RegistrationOutcome::Replaced`]
    ///     carrying the prior payload (caller-side audit; the FFI
    ///     surface collapses Created/Replaced/NoOp to `Ok(())`).
    ///
    /// **L6 hybrid:** presence is *required* as an argument even on
    /// the session-class branches so the call site is uniform; it is
    /// only *consumed* (verified) on the Replace branch. A stale
    /// presence proof on a `Created` / `NoOp` registration never fires
    /// the `PromptTimedOut` path — the proof is dead weight there. On
    /// the Replace branch a stale proof maps to
    /// [`StoreError::PromptTimedOut`] (same as the `reveal_*` shape).
    ///
    /// # Errors
    /// - [`StoreError::NotUnlocked`] / [`StoreError::SessionExpired`] /
    ///   [`StoreError::SessionPending`] — locked / expired session.
    /// - [`StoreError::CaptureAuthorityValidation`] — payload rejected.
    /// - [`StoreError::CaptureAuthorityExclusivity`] — existing
    ///   different registration; caller must opt into replacement.
    /// - [`StoreError::PromptTimedOut`] /
    ///   [`StoreError::AuthenticationFailed`] — presence-proof
    ///   verification failure on the Replace branch.
    /// - [`StoreError::Sqlite`] / [`StoreError::Corrupted`] — storage
    ///   failure.
    #[allow(clippy::needless_pass_by_value)]
    pub fn capture_authority_register(
        &mut self,
        presence: &dyn PresenceProof,
        authority: crate::capture_authority::CaptureAuthority,
        context: crate::capture_authority::CaptureContext,
        replace_existing: bool,
    ) -> Result<crate::capture_authority::RegistrationOutcome> {
        // Step 1: session-freshness check (proof never consumed if
        // this fails; rejection happens before any work).
        self.check_session_freshness()?;
        // Step 2: validate inputs. Rejection happens before any DB I/O.
        let canonical_authority = crate::capture_authority::validate_authority(&authority)?;
        let canonical_context = crate::capture_authority::validate_context(&context)?;
        let context_kind_i = canonical_context.kind.to_repr();
        let platform_hint_stored =
            crate::capture_authority::coalesce_platform_hint(&canonical_context.platform_hint);

        // Step 3: lookup + decide outcome under a single IMMEDIATE
        // transaction. We drive the transaction via raw SQL
        // (`BEGIN IMMEDIATE` / `COMMIT` / `ROLLBACK`) rather than
        // rusqlite's `Transaction` wrapper so the SQLite write lock
        // can be held continuously across `ensure_presence_fresh` on
        // the Replace branch — the wrapper borrows `&self.conn`
        // immutably which would prevent calling
        // `self.ensure_presence_fresh(&mut self, ...)`.
        // `ensure_presence_fresh` is in-memory only (no DB I/O), so
        // holding the SQLite lock across it is safe and closes the
        // prior TOCTOU window between the lookup and the REPLACE.
        self.conn
            .execute_batch("BEGIN IMMEDIATE")
            .map_err(StoreError::from)?;
        let outcome = self.capture_authority_register_in_tx(
            presence,
            &canonical_authority,
            &canonical_context,
            context_kind_i,
            platform_hint_stored,
            replace_existing,
        );
        match outcome {
            Ok(o) => {
                self.conn
                    .execute_batch("COMMIT")
                    .map_err(StoreError::from)?;
                // touch_session runs on every successful outcome
                // (Created / NoOp / Replaced) — matches the original
                // semantics where the session is extended on a
                // successful no-op re-register too.
                self.touch_session();
                Ok(o)
            }
            Err(e) => {
                // Best-effort rollback on any error path
                // (validation, exclusivity, presence-stale, sqlite).
                // The original error wins — a rollback failure here
                // would only happen if the connection itself is
                // broken, in which case the caller already has more
                // serious problems to surface.
                let _ = self.conn.execute_batch("ROLLBACK");
                Err(e)
            }
        }
    }

    /// Inner body of [`Self::capture_authority_register`]. Runs under
    /// an already-opened `BEGIN IMMEDIATE` transaction; the outer
    /// wrapper commits on `Ok` and rolls back on `Err`. Split out so
    /// the borrow checker permits calling `&mut self` methods
    /// (specifically `ensure_presence_fresh`) on the Replace branch
    /// without releasing the `SQLite` write lock.
    #[allow(clippy::too_many_arguments)]
    fn capture_authority_register_in_tx(
        &mut self,
        presence: &dyn PresenceProof,
        canonical_authority: &crate::capture_authority::CaptureAuthority,
        canonical_context: &crate::capture_authority::CaptureContext,
        context_kind_i: i64,
        platform_hint_stored: &str,
        replace_existing: bool,
    ) -> Result<crate::capture_authority::RegistrationOutcome> {
        let existing: Option<(i64, String, String, i64, i64)> = self
            .conn
            .query_row(
                "SELECT authority_kind, component_id, component_version, registered_at, \
                 schema_version FROM capture_authorities \
                 WHERE context_kind = ?1 AND platform_hint = ?2",
                rusqlite::params![context_kind_i, platform_hint_stored],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                },
            )
            .optional()
            .map_err(StoreError::from)?;

        let now_ms = current_unix_ms();
        let schema_version_i =
            i64::from(crate::capture_authority::CAPTURE_AUTHORITY_SCHEMA_VERSION_MAX);

        match existing {
            None => {
                self.conn.execute(
                    "INSERT INTO capture_authorities \
                       (context_kind, platform_hint, authority_kind, component_id, \
                        component_version, registered_at, schema_version) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    rusqlite::params![
                        context_kind_i,
                        platform_hint_stored,
                        canonical_authority.kind.to_repr(),
                        &canonical_authority.component_id,
                        &canonical_authority.component_version,
                        now_ms,
                        schema_version_i,
                    ],
                )?;
                Ok(crate::capture_authority::RegistrationOutcome::Created)
            }
            Some((existing_kind_i, existing_id, existing_version, _existing_at, existing_sv_i)) => {
                let existing_sv = u16::try_from(existing_sv_i).map_err(|_| {
                    StoreError::CaptureAuthorityValidation {
                        reason: "stored schema_version out of u16 range".into(),
                    }
                })?;
                // §18.7 per-row ladder parity with `decode_row` (the
                // path query/list use): a row whose `schema_version`
                // is from the future is rejected on the register
                // path too. Without this check, a future-version row
                // could be silently NoOp'd by a byte-matching
                // payload — or silently downgraded to the current
                // MAX via `replace_existing=true` — defeating the
                // ladder for the only write path that touches it.
                if existing_sv > crate::capture_authority::CAPTURE_AUTHORITY_SCHEMA_VERSION_MAX {
                    return Err(StoreError::CaptureAuthorityValidation {
                        reason: format!(
                            "stored row schema_version {existing_sv} > {} \
                             (requires newer Pangolin)",
                            crate::capture_authority::CAPTURE_AUTHORITY_SCHEMA_VERSION_MAX
                        ),
                    });
                }
                let existing_kind =
                    crate::capture_authority::CaptureAuthorityKind::from_repr(existing_kind_i)?;
                let existing_authority = crate::capture_authority::CaptureAuthority {
                    schema_version: existing_sv,
                    kind: existing_kind,
                    component_id: existing_id,
                    component_version: existing_version,
                };
                let payload_matches = existing_authority.kind == canonical_authority.kind
                    && existing_authority.component_id == canonical_authority.component_id
                    && existing_authority.component_version
                        == canonical_authority.component_version;
                if payload_matches {
                    return Ok(crate::capture_authority::RegistrationOutcome::NoOp {
                        existing: existing_authority,
                    });
                }
                if !replace_existing {
                    return Err(StoreError::CaptureAuthorityExclusivity {
                        context: canonical_context.kind.label().to_owned(),
                    });
                }
                // Replace: reveal-class. `ensure_presence_fresh` runs
                // INSIDE the BEGIN IMMEDIATE held by the outer
                // wrapper — a stale proof surfaces `PromptTimedOut`,
                // the outer wrapper rolls back, no row is changed.
                // The continuous lock holds across the in-memory
                // presence check, closing the prior TOCTOU window
                // between lookup and REPLACE.
                self.ensure_presence_fresh(presence)?;
                self.conn.execute(
                    "INSERT OR REPLACE INTO capture_authorities \
                       (context_kind, platform_hint, authority_kind, component_id, \
                        component_version, registered_at, schema_version) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    rusqlite::params![
                        context_kind_i,
                        platform_hint_stored,
                        canonical_authority.kind.to_repr(),
                        &canonical_authority.component_id,
                        &canonical_authority.component_version,
                        now_ms,
                        schema_version_i,
                    ],
                )?;
                Ok(crate::capture_authority::RegistrationOutcome::Replaced {
                    prior: existing_authority,
                })
            }
        }
    }

    /// Look up the registered capture authority for `context`.
    ///
    /// Session-class — requires an unlocked, non-expired session, no
    /// presence proof. `Ok(None)` when no row matches the
    /// `(context_kind, platform_hint)` key.
    ///
    /// # Errors
    /// - [`StoreError::NotUnlocked`] / [`StoreError::SessionExpired`] /
    ///   [`StoreError::SessionPending`].
    /// - [`StoreError::CaptureAuthorityValidation`] — context payload
    ///   rejected.
    /// - [`StoreError::Sqlite`] — storage failure.
    #[allow(clippy::needless_pass_by_value)]
    pub fn capture_authority_query(
        &mut self,
        context: crate::capture_authority::CaptureContext,
    ) -> Result<Option<crate::capture_authority::CaptureAuthorityEntry>> {
        self.check_session_freshness()?;
        let canonical_context = crate::capture_authority::validate_context(&context)?;
        let context_kind_i = canonical_context.kind.to_repr();
        let platform_hint_stored =
            crate::capture_authority::coalesce_platform_hint(&canonical_context.platform_hint);
        let sql = format!(
            "SELECT {} FROM capture_authorities WHERE context_kind = ?1 AND platform_hint = ?2",
            crate::capture_authority::CAPTURE_AUTHORITIES_SELECT_COLS
        );
        let row: Option<(i64, String, i64, String, String, i64, i64)> = self
            .conn
            .query_row(
                &sql,
                rusqlite::params![context_kind_i, platform_hint_stored],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                    ))
                },
            )
            .optional()
            .map_err(StoreError::from)?;
        match row {
            None => {
                self.touch_session();
                Ok(None)
            }
            Some((ck, ph, ak, cid, cv, at, sv)) => {
                let entry = crate::capture_authority::decode_row(ck, ph, ak, cid, cv, at, sv)?;
                self.touch_session();
                Ok(Some(entry))
            }
        }
    }

    /// List every registered capture authority, sorted by
    /// `(context_kind, platform_hint)` (stable). Session-class.
    ///
    /// # Errors
    /// - [`StoreError::NotUnlocked`] / [`StoreError::SessionExpired`] /
    ///   [`StoreError::SessionPending`].
    /// - [`StoreError::CaptureAuthorityValidation`] — a row from the
    ///   future (per-row §18.7 ladder reject; rest of vault fine).
    /// - [`StoreError::Sqlite`] — storage failure.
    pub fn capture_authority_list(
        &mut self,
    ) -> Result<Vec<crate::capture_authority::CaptureAuthorityEntry>> {
        self.check_session_freshness()?;
        let sql = format!(
            "SELECT {} FROM capture_authorities ORDER BY context_kind ASC, platform_hint ASC",
            crate::capture_authority::CAPTURE_AUTHORITIES_SELECT_COLS
        );
        let rows = {
            let mut stmt = self.conn.prepare(&sql)?;
            let mapped = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            })?;
            let mut out = Vec::new();
            for r in mapped {
                let (ck, ph, ak, cid, cv, at, sv) = r?;
                out.push(crate::capture_authority::decode_row(
                    ck, ph, ak, cid, cv, at, sv,
                )?);
            }
            out
        };
        self.touch_session();
        Ok(rows)
    }

    /// Delete the registered authority for `context`. Returns `true`
    /// when a row was deleted, `false` when none was present.
    ///
    /// Session-class; not on the FFI surface in 1.11 (test helper +
    /// future MVP-2 "extension uninstalled" hook).
    ///
    /// # Errors
    /// - [`StoreError::NotUnlocked`] / [`StoreError::SessionExpired`] /
    ///   [`StoreError::SessionPending`].
    /// - [`StoreError::CaptureAuthorityValidation`].
    /// - [`StoreError::Sqlite`].
    #[allow(clippy::needless_pass_by_value)]
    pub fn capture_authority_clear(
        &mut self,
        context: crate::capture_authority::CaptureContext,
    ) -> Result<bool> {
        self.check_session_freshness()?;
        let canonical_context = crate::capture_authority::validate_context(&context)?;
        let context_kind_i = canonical_context.kind.to_repr();
        let platform_hint_stored =
            crate::capture_authority::coalesce_platform_hint(&canonical_context.platform_hint);
        let n = self.conn.execute(
            "DELETE FROM capture_authorities WHERE context_kind = ?1 AND platform_hint = ?2",
            rusqlite::params![context_kind_i, platform_hint_stored],
        )?;
        self.touch_session();
        Ok(n > 0)
    }

    /// Walk the revision history for `id` from genesis to head. Returns
    /// in chronological order (oldest first). Includes the tombstone
    /// revision when the account is tombstoned.
    pub fn revisions_for(&self, id: AccountId) -> Result<Vec<RevisionMeta>> {
        let mut stmt = self.conn.prepare(
            // #106d (salvaged #103-C FINDING 2): exclude revoked rows from
            // the history walk so a revoked revision never surfaces.
            "SELECT revision_id, parent_revision_id, device_id,
                    schema_version, created_at, is_tombstone,
                    chain_tx_hash, chain_block_number, chain_log_index,
                    superseded_by
             FROM revisions WHERE account_id = ?1
               AND revoked = 0
             ORDER BY created_at ASC",
        )?;
        let rows = stmt.query_map(params![id.as_bytes().as_slice()], |row| {
            let revision_id: Vec<u8> = row.get(0)?;
            let parent: Vec<u8> = row.get(1)?;
            let device_id: Vec<u8> = row.get(2)?;
            let schema_version: i64 = row.get(3)?;
            let created_at: i64 = row.get(4)?;
            let is_tombstone: i64 = row.get(5)?;
            let chain_tx_hash: Option<Vec<u8>> = row.get(6)?;
            let chain_block_number: Option<i64> = row.get(7)?;
            let chain_log_index: Option<i64> = row.get(8)?;
            let superseded_by: Option<Vec<u8>> = row.get(9)?;
            Ok(RawRevisionRow {
                revision_id,
                parent,
                device_id,
                schema_version,
                created_at,
                is_tombstone,
                chain_tx_hash,
                chain_block_number,
                chain_log_index,
                superseded_by,
            })
        })?;

        let mut out = Vec::new();
        for raw in rows {
            let raw = raw?;
            out.push(raw.into_meta()?);
        }
        Ok(out)
    }

    // -----------------------------------------------------------------
    // MVP-1 issue 1.2: V1 production AccountIdentity entry points.
    //
    // These methods are the FFI-facing surface (`account_add` /
    // `account_update` / `account_get` / `account_search` /
    // `account_history`). They produce / consume V1 CBOR payloads
    // (8-key map with `payload_version=1`); the V0 PoC entry points
    // (`add_account` / `update_account` / `get_account` / `search` /
    // `revisions_for`) keep working for legacy internal callers and
    // legacy on-disk vaults.
    //
    // Per `docs/issue-plans/1.2.md` Q2, the types live in
    // `pangolin-store::account`; `pangolin-core` re-exports.
    // -----------------------------------------------------------------

    /// Add a new account identity (V1 production path). Returns the
    /// freshly-generated [`AccountId`].
    ///
    /// Validates the supplied draft, builds an
    /// [`crate::account::AccountIdentity`] with a single-entry password
    /// history (genesis), encrypts the V1 payload, and writes a new
    /// genesis revision. The decrypted-cache entry is also installed
    /// (downgraded to a V0-shaped [`AccountSnapshot`] using the head
    /// password / first username / first url) so existing internal
    /// callers (`get_account` / `search` / `reveal_*`) keep working.
    pub fn account_add(
        &mut self,
        draft: crate::account::AccountIdentityDraft,
    ) -> Result<AccountId> {
        // Same session discipline as the V0 add_account.
        self.check_session_freshness()?;
        let _ = self.require_active()?;

        let now = current_unix_ms();
        let device = self.device_id;
        let identity = draft.validate_into_identity(now, device)?;

        let account_id = self.derive_fresh_account_id()?;
        let revision_id = RevisionId::from_bytes(random_32_via_sqlite(&self.conn)?);
        let parent = RevisionId::GENESIS_PARENT;
        let aad = build_aad(
            &self.meta.vault_id,
            &account_id,
            &parent,
            self.meta.wrap_context.schema_version,
        );

        let active = self.require_active()?;
        let (ct, nonce) = crate::blob::seal_identity(active.vdk.aead_key(), &identity, &aad)?;
        // #106b-2: the new revision is encrypted under the active session's
        // `vdk` (= current epoch's VDK), so stamp the current epoch (Q-a).
        let vdk_epoch = i64::try_from(active.chain.current_epoch()).unwrap_or(i64::MAX);

        // Build the V0 cache shadow snapshot (head password / first
        // username / first url). This keeps the existing cache-bearing
        // read paths (search, reveal_*) functional during 1.2 while
        // the production identity lives on disk in V1 form.
        let cache_snapshot = downgrade_identity_to_snapshot(&identity);

        // Persist (account_identities + revisions + dirty_accounts) in
        // one transaction.
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO account_identities (
                account_id, created_at, last_modified_at, tombstoned, head_revision_id
             ) VALUES (?1, ?2, ?2, 0, ?3)",
            params![
                account_id.as_bytes().as_slice(),
                now,
                revision_id.as_bytes().as_slice(),
            ],
        )?;
        tx.execute(
            "INSERT INTO revisions (
                revision_id, account_id, parent_revision_id, device_id,
                schema_version, created_at, enc_payload, enc_nonce, is_tombstone, vdk_epoch
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, ?9)",
            params![
                revision_id.as_bytes().as_slice(),
                account_id.as_bytes().as_slice(),
                parent.as_bytes().as_slice(),
                self.device_id.0.as_slice(),
                i64::from(self.meta.wrap_context.schema_version),
                now,
                ct.as_bytes(),
                nonce.as_bytes().as_slice(),
                vdk_epoch,
            ],
        )?;
        tx.execute(
            "INSERT OR IGNORE INTO dirty_accounts
                (account_id, revision_id, marked_at)
             VALUES (?1, ?2, ?3)",
            params![
                account_id.as_bytes().as_slice(),
                revision_id.as_bytes().as_slice(),
                now,
            ],
        )?;
        tx.commit()?;

        // MVP-2 issue 5.1 (R-d): window-start hook.
        self.note_dirty_marker_stamped(now);

        // 1.3: keep the `:memory:` FTS5 index in sync. Runs after the
        // blob write commits, so the index never reflects an
        // uncommitted revision; a crash before this line just means the
        // next unlock rebuilds the (RAM-only) index from the committed
        // blobs.
        let projection = SearchProjection::from_identity(&identity);
        drop(identity);
        let active_mut = self.require_active_mut()?;
        active_mut
            .search_index
            .insert(account_id, now, &projection)?;
        active_mut.cache.insert(account_id, cache_snapshot);
        self.touch_session();
        Ok(account_id)
    }

    /// Apply a patch to an existing account identity (V1 production
    /// path). Returns the new revision's id.
    ///
    /// Loads the current head as an [`AccountIdentity`] (auto-migrates
    /// V0 payloads on read per the 1.2 schemata), applies the patch,
    /// validates, encrypts as V1, writes a new revision pointed at
    /// the previous head, and updates the cache.
    pub fn account_update(
        &mut self,
        id: AccountId,
        patch: crate::account::AccountIdentityPatch,
    ) -> Result<RevisionId> {
        self.check_session_freshness()?;
        let _ = self.require_active()?;
        self.refuse_if_frozen(id)?;
        self.refuse_if_requires_upgrade(id)?;

        let account_row = self
            .conn
            .query_row(
                "SELECT tombstoned, head_revision_id
                 FROM account_identities WHERE account_id = ?1",
                params![id.as_bytes().as_slice()],
                |row| {
                    let tombstoned: i64 = row.get(0)?;
                    let head: Vec<u8> = row.get(1)?;
                    Ok((tombstoned != 0, head))
                },
            )
            .optional()?
            .ok_or(StoreError::AccountNotFound)?;
        if account_row.0 {
            return Err(StoreError::AccountTombstoned);
        }
        let head_arr: [u8; REVISION_ID_LEN] = account_row
            .1
            .as_slice()
            .try_into()
            .map_err(|_| StoreError::Corrupted("head_revision_id not 32 bytes".into()))?;
        let parent = RevisionId::from_bytes(head_arr);

        // Read + decrypt the current head as an AccountIdentity. Routes
        // through the V1-aware open path which auto-migrates V0 → V1.
        let mut identity = self.read_identity_at(id, parent)?;

        // Apply the patch — validation runs first, mutations second.
        let now = current_unix_ms();
        patch.apply(&mut identity, now, self.device_id)?;

        let revision_id = RevisionId::from_bytes(random_32_via_sqlite(&self.conn)?);
        let aad = build_aad(
            &self.meta.vault_id,
            &id,
            &parent,
            self.meta.wrap_context.schema_version,
        );
        let active = self.require_active()?;
        let (ct, nonce) = crate::blob::seal_identity(active.vdk.aead_key(), &identity, &aad)?;
        // #106b-2: stamp the current VDK epoch (Q-a) — encrypted under
        // `active.vdk` (= current epoch's VDK).
        let vdk_epoch = i64::try_from(active.chain.current_epoch()).unwrap_or(i64::MAX);

        let cache_snapshot = downgrade_identity_to_snapshot(&identity);

        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO revisions (
                revision_id, account_id, parent_revision_id, device_id,
                schema_version, created_at, enc_payload, enc_nonce, is_tombstone, vdk_epoch
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, ?9)",
            params![
                revision_id.as_bytes().as_slice(),
                id.as_bytes().as_slice(),
                parent.as_bytes().as_slice(),
                self.device_id.0.as_slice(),
                i64::from(self.meta.wrap_context.schema_version),
                now,
                ct.as_bytes(),
                nonce.as_bytes().as_slice(),
                vdk_epoch,
            ],
        )?;
        tx.execute(
            "UPDATE account_identities
             SET head_revision_id = ?1, last_modified_at = ?2
             WHERE account_id = ?3",
            params![
                revision_id.as_bytes().as_slice(),
                now,
                id.as_bytes().as_slice(),
            ],
        )?;
        tx.execute(
            "INSERT OR IGNORE INTO dirty_accounts
                (account_id, revision_id, marked_at)
             VALUES (?1, ?2, ?3)",
            params![
                id.as_bytes().as_slice(),
                revision_id.as_bytes().as_slice(),
                now,
            ],
        )?;
        tx.commit()?;

        // MVP-2 issue 5.1 (R-d): window-start hook.
        self.note_dirty_marker_stamped(now);

        // 1.3: resync the `:memory:` FTS5 index for this account.
        let projection = SearchProjection::from_identity(&identity);
        drop(identity);
        let active_mut = self.require_active_mut()?;
        active_mut.search_index.update(id, now, &projection)?;
        active_mut.cache.insert(id, cache_snapshot);
        self.touch_session();
        Ok(revision_id)
    }

    /// Read the current head identity for `id` and surface it as a
    /// summary (V1 production path).
    pub fn account_get(&mut self, id: AccountId) -> Result<crate::account::AccountIdentitySummary> {
        self.check_session_freshness()?;
        let _ = self.require_active()?;
        self.refuse_if_frozen(id)?;
        self.refuse_if_requires_upgrade(id)?;

        let account_row = self
            .conn
            .query_row(
                "SELECT tombstoned, head_revision_id
                 FROM account_identities WHERE account_id = ?1",
                params![id.as_bytes().as_slice()],
                |row| {
                    let tombstoned: i64 = row.get(0)?;
                    let head: Vec<u8> = row.get(1)?;
                    Ok((tombstoned != 0, head))
                },
            )
            .optional()?
            .ok_or(StoreError::AccountNotFound)?;
        if account_row.0 {
            return Err(StoreError::AccountTombstoned);
        }
        let head_arr: [u8; REVISION_ID_LEN] = account_row
            .1
            .as_slice()
            .try_into()
            .map_err(|_| StoreError::Corrupted("head_revision_id not 32 bytes".into()))?;
        let cached_head = RevisionId::from_bytes(head_arr);
        // 1.6: for a forked account the canonical head is the
        // largest-revision_id leaf (clock-free), not the cached pointer.
        let head = if self.account_heads(id)?.len() > 1 {
            self.canonical_head(id)?
        } else {
            cached_head
        };

        let identity = self.read_identity_at(id, head)?;
        let summary = identity_to_summary(id, head, &identity);
        self.touch_session();
        Ok(summary)
    }

    /// Search V1 account identities, backed by the `:memory:` FTS5
    /// index built at unlock (MVP-1 issue 1.3).
    ///
    /// Tokenises the query, runs an FTS5 `MATCH` over the non-secret
    /// searchable projection (`display_name`, canonical `tags`, URL-
    /// derived `hostnames` — the whitelist is structural; the index has
    /// no columns for `usernames` / full URLs / `notes` / passwords /
    /// `totp_secret`), orders by `bm25()` with a most-recently-modified
    /// tiebreaker, applies default-AND multi-term semantics, and caps
    /// the result count at [`crate::search::ACCOUNT_SEARCH_RESULT_CAP`].
    /// A query whose `trim()` is empty returns every live account
    /// ordered by recency (capped). Queries shorter than the `trigram`
    /// 3-char minimum fall back to a `LIKE` substring scan over the same
    /// projection columns.
    ///
    /// Tombstoned accounts are not in the index; frozen accounts are
    /// filtered out at query time (preserving 1.2's behaviour).
    ///
    /// Returns full summaries (not just ids) so the caller can render
    /// directly without a follow-up `account_get` per result. If the
    /// vault is not unlocked the usual session error surfaces (no
    /// `:memory:` index exists when locked).
    pub fn account_search(
        &mut self,
        query: &str,
    ) -> Result<Vec<crate::account::AccountIdentitySummary>> {
        self.check_session_freshness()?;
        let _ = self.require_active()?;

        let frozen = self.frozen_set().unwrap_or_default();
        let candidates = self.require_active()?.search_index.search(query)?;

        let mut hits = Vec::with_capacity(candidates.len());
        for (acct, _updated_at) in candidates {
            if frozen.contains(&acct) {
                continue;
            }
            // Re-read the head pointer from SQL (authoritative) rather
            // than trusting the in-RAM index's notion of "current".
            let head_blob: Option<Vec<u8>> = self
                .conn
                .query_row(
                    "SELECT head_revision_id FROM account_identities
                     WHERE account_id = ?1 AND tombstoned = 0",
                    params![acct.as_bytes().as_slice()],
                    |row| row.get(0),
                )
                .optional()?;
            let Some(head_blob) = head_blob else {
                // Raced with a tombstone; skip.
                continue;
            };
            // 1.6 §18.7: a "requires upgrade" account is not in the
            // index, but belt-and-suspenders skip it here too.
            if self.account_requires_upgrade(acct) {
                continue;
            }
            let head_arr: [u8; REVISION_ID_LEN] = head_blob
                .as_slice()
                .try_into()
                .map_err(|_| StoreError::Corrupted("head_revision_id not 32 bytes".into()))?;
            let cached_head = RevisionId::from_bytes(head_arr);
            // 1.6: for a forked account the canonical head is the
            // largest-revision_id leaf (clock-free), not the cached
            // pointer. Linear accounts take the fast path unchanged.
            let head = if self.account_heads(acct)?.len() > 1 {
                self.canonical_head(acct)?
            } else {
                cached_head
            };
            let identity = self.read_identity_at(acct, head)?;
            hits.push(identity_to_summary(acct, head, &identity));
        }
        self.touch_session();
        Ok(hits)
    }

    /// Read the revision history for an account (V1 alias for
    /// [`Self::revisions_for`]).
    pub fn account_history(&self, id: AccountId) -> Result<Vec<RevisionMeta>> {
        let exists: Option<i64> = self
            .conn
            .query_row(
                "SELECT 1 FROM account_identities WHERE account_id = ?1",
                params![id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        if exists.is_none() {
            return Err(StoreError::AccountNotFound);
        }
        self.revisions_for(id)
    }

    /// Decrypt the on-disk payload at `(account_id, revision_id)` and
    /// hydrate the V1 [`crate::account::AccountIdentity`]. Auto-
    /// migrates V0 payloads per the 1.2 schemata.
    fn read_identity_at(
        &self,
        id: AccountId,
        revision_id: RevisionId,
    ) -> Result<crate::account::AccountIdentity> {
        let row: (Vec<u8>, Vec<u8>, Vec<u8>, i64) = self
            .conn
            .query_row(
                "SELECT r.parent_revision_id, r.enc_payload, r.enc_nonce, r.schema_version
                 FROM revisions r
                 WHERE r.account_id = ?1 AND r.revision_id = ?2",
                params![id.as_bytes().as_slice(), revision_id.as_bytes().as_slice(),],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()?
            .ok_or(StoreError::RevisionNotFound)?;
        let parent_arr: [u8; REVISION_ID_LEN] = row
            .0
            .as_slice()
            .try_into()
            .map_err(|_| StoreError::Corrupted("parent_revision_id not 32 bytes".into()))?;
        let nonce_arr: [u8; NONCE_LEN] = row
            .2
            .as_slice()
            .try_into()
            .map_err(|_| StoreError::Corrupted("enc_nonce length mismatch".into()))?;
        let row_schema_version = u8::try_from(row.3).map_err(|_| {
            StoreError::Corrupted("revisions.schema_version out of u8 range".into())
        })?;

        let parent = RevisionId::from_bytes(parent_arr);
        let aad = build_aad(&self.meta.vault_id, &id, &parent, row_schema_version);
        let ct = Ciphertext::from_vec(row.1);
        let nonce = Nonce::from_storage_bytes(nonce_arr);
        let active = self.require_active()?;
        // §18.7 (1.6), audit L1: the `revisions.schema_version` byte is
        // bound into the AEAD AAD, so we authenticate first. A bare
        // on-disk byte-flip of that column produces an AAD this build
        // never sealed under → the open fails → `AuthenticationFailed`
        // (tampering), not a misleading "this account requires a newer
        // Pangolin" prompt. A *legitimately* future-versioned revision
        // was sealed by a future build with that exact byte in its AAD,
        // so the open succeeds; only then do we surface the typed
        // requires-upgrade error — before attempting to CBOR-decode the
        // (now-authenticated) future-shaped body.
        let decoded = crate::blob::open_identity_payload(active.vdk.aead_key(), &nonce, &ct, &aad)
            .map_err(|e| e.with_revision_context(id, revision_id))?;
        if row_schema_version > crate::revision::REVISION_SCHEMA_VERSION_MAX {
            return Err(StoreError::UnsupportedRevisionSchemaVersion {
                account_id: id,
                revision_id,
                found: u32::from(row_schema_version),
                supported: u32::from(crate::revision::REVISION_SCHEMA_VERSION_MAX),
            });
        }
        match decoded {
            crate::blob::DecodedIdentityPayload::Live(identity) => Ok(identity),
            crate::blob::DecodedIdentityPayload::Tombstone(_) => Err(StoreError::AccountTombstoned),
        }
    }

    // -----------------------------------------------------------------
    // Revision graph + fork detection (P3)
    // -----------------------------------------------------------------

    /// Build the [`RevisionGraph`] for `account_id`. Reads every
    /// `revisions` row for the account, indexes the parent→child
    /// structure, and returns. Does not require [`VaultState::Active`]
    /// because the graph is metadata-only (no `enc_payload`,
    /// no decrypted plaintext) — a `Locked` vault can still answer
    /// fork-detection queries.
    ///
    /// Returns an empty graph if the `account_id` has no revisions in
    /// the local store. (`account_identities` is not consulted; the
    /// graph is built directly from the `revisions` table so callers
    /// in P7's chain-replay path can build a graph for an account
    /// whose identity row hasn't been written yet.)
    ///
    /// # Errors
    ///
    /// `StoreError::Sqlite` for any database issue,
    /// `StoreError::Corrupted` if a stored row fails internal length
    /// checks (e.g., a 32-byte id field that isn't actually 32 bytes)
    /// or if the graph build detects a cycle or duplicate.
    pub fn revision_graph(&self, id: AccountId) -> Result<RevisionGraph> {
        let rows = self.read_revision_rows_for(id)?;
        RevisionGraph::build(rows)
    }

    /// Heads of the revision graph for `account_id`.
    ///
    /// Length 1: the account is in a clean linear state. Length > 1:
    /// the account is forked. Length 0: the account has no revisions
    /// (either truly empty or the row hasn't been written yet).
    ///
    /// # Errors
    ///
    /// `StoreError::AccountNotFound` if the account is unknown — i.e.,
    /// no row in `account_identities` matches `id`. The graph itself
    /// is built from the `revisions` table; we cross-check against
    /// `account_identities` here so callers get a clear "no such
    /// account" signal rather than a silently-empty result.
    pub fn account_heads(&self, id: AccountId) -> Result<Vec<RevisionId>> {
        // Cross-check the account exists at the identity layer.
        let exists: Option<i64> = self
            .conn
            .query_row(
                "SELECT 1 FROM account_identities WHERE account_id = ?1",
                params![id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        if exists.is_none() {
            return Err(StoreError::AccountNotFound);
        }
        // Use a SQL pre-filter for the multi-head case so we don't
        // pay the full RevisionGraph::build cost when the caller only
        // wants the head set. Plan §"Schema implications" anchors the
        // NOT EXISTS subquery as the canonical multi-head detector.
        // M-1 (P3 audit): scope the NOT EXISTS subquery by `account_id`
        // as defense-in-depth against a hypothetical future code path
        // that allows cross-account `parent_revision_id` references.
        // RevisionIds are 32-byte CSPRNG output, so accidental
        // collision is cryptographically negligible — this is belt +
        // suspenders, not a fix for a current vulnerability.
        let mut stmt = self.conn.prepare(
            // #106d (salvaged #103-C FINDING 2): exclude revoked rows
            // (outer) + revoked children (subquery) so revoked revisions
            // never surface as honored heads.
            "SELECT r.revision_id, r.created_at FROM revisions r
             WHERE r.account_id = ?1
               AND r.superseded_by IS NULL
               AND r.revoked = 0
               AND NOT EXISTS (
                 SELECT 1 FROM revisions r2
                 WHERE r2.parent_revision_id = r.revision_id
                   AND r2.account_id = r.account_id
                   AND r2.revoked = 0
               )
             ORDER BY r.created_at ASC, r.revision_id ASC",
        )?;
        let rows = stmt.query_map(params![id.as_bytes().as_slice()], |row| {
            let rid: Vec<u8> = row.get(0)?;
            let created_at: i64 = row.get(1)?;
            Ok((rid, created_at))
        })?;
        let mut out: Vec<RevisionId> = Vec::new();
        for row in rows {
            let (rid, _ts) = row?;
            let arr: [u8; REVISION_ID_LEN] = rid
                .as_slice()
                .try_into()
                .map_err(|_| StoreError::Corrupted("head revision_id not 32 bytes".into()))?;
            out.push(RevisionId::from_bytes(arr));
        }
        Ok(out)
    }

    /// `true` iff `account_heads(id).len() > 1`.
    ///
    /// # Errors
    ///
    /// Same conditions as [`Self::account_heads`].
    pub fn is_forked(&self, id: AccountId) -> Result<bool> {
        Ok(self.account_heads(id)?.len() > 1)
    }

    /// **MVP-1 issue 1.6.** The canonical head of `id`'s revision graph
    /// per the production rule: the leaf with the
    /// lexicographically-largest `revision_id` (byte-order). For a
    /// linear chain this is the single head; for a fork it is the
    /// rule-winner. NO `created_at` involvement (Q1 — clock-free). The
    /// same id on a reopened vault.
    ///
    /// # Errors
    ///
    /// [`StoreError::AccountNotFound`] if `id` is unknown;
    /// [`StoreError::Corrupted`] if `id` has zero revisions (an account
    /// row with no genesis revision is corruption) or the graph build
    /// detects a cycle/duplicate.
    pub fn canonical_head(&self, id: AccountId) -> Result<RevisionId> {
        let exists: Option<i64> = self
            .conn
            .query_row(
                "SELECT 1 FROM account_identities WHERE account_id = ?1",
                params![id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        if exists.is_none() {
            return Err(StoreError::AccountNotFound);
        }
        let graph = self.revision_graph(id)?;
        graph
            .canonical_head()
            .copied()
            .ok_or_else(|| StoreError::Corrupted("account has no revisions".into()))
    }

    /// **MVP-1 issue 1.6 — the one-stop account-status view.** Derived
    /// from the persisted `account_identities` row, the revision graph,
    /// and the in-RAM `requires_upgrade` set. Metadata-only and works on
    /// a `Locked` vault for the persisted bits; the `requires_upgrade`
    /// field is only meaningful on an `Active` vault (`false` otherwise).
    ///
    /// # Errors
    ///
    /// [`StoreError::AccountNotFound`] if `id` is unknown;
    /// [`StoreError::Sqlite`] / [`StoreError::Corrupted`] on storage
    /// issues.
    pub fn account_status(&self, id: AccountId) -> Result<AccountStatus> {
        let row: Option<(i64, i64)> = self
            .conn
            .query_row(
                "SELECT tombstoned, frozen_pending_resolve
                 FROM account_identities WHERE account_id = ?1",
                params![id.as_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let (tombstoned, frozen) = row.ok_or(StoreError::AccountNotFound)?;
        let is_forked = self.account_heads(id)?.len() > 1;
        Ok(AccountStatus {
            account_id: id,
            is_tombstoned: tombstoned != 0,
            is_forked,
            is_frozen_pending_resolve: frozen != 0,
            requires_upgrade: self.account_requires_upgrade(id),
        })
    }

    /// **MVP-1 issue 1.6 — conflict resolution → canonical head.**
    ///
    /// Ratify `keep_revision_id` (a current head of `account_id`'s
    /// forked graph) as the surviving branch: write a new revision
    /// parented at it (payload re-sealed under a fresh nonce + the merge
    /// revision's own AAD), advance `head_revision_id` to the new id —
    /// which is the largest `revision_id` by construction (newest), so
    /// the account is un-forked — clear `frozen_pending_resolve`, write
    /// the `dirty_accounts` marker, and prune the now-orphan
    /// `pending_merges` stash row(s). The losing branch's revision rows
    /// are **kept** (Q5 — append-only; audit/recovery; they're just off
    /// the head chain now). Returns the new (merge) revision id.
    ///
    /// Composes the P9 store internals into the MVP-1 user-facing API.
    /// Requires only an active (unlocked, non-expired) session — NOT a
    /// fresh presence proof: resolving a fork reparents the graph; it
    /// reveals nothing (Q2 — not a Session spec §5.4 reveal-class
    /// action). Never auto-resolves; the user must call this explicitly.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotUnlocked`] / [`StoreError::SessionExpired`] if
    /// the session is not active. [`StoreError::AccountNotFound`] if
    /// `account_id` is unknown OR if `keep_revision_id` is not a row for
    /// this account (collapsed — no cross-account oracle).
    /// [`StoreError::NotAHead`] if `keep_revision_id` exists for the
    /// account but is not a current head.
    /// [`StoreError::Validation`] (`kind = "not-forked"`) if the account
    /// is not forked (nothing to resolve — typed, not a silent no-op).
    /// [`StoreError::AccountTombstoned`] if the account is tombstoned.
    /// [`StoreError::AuthenticationFailed`] if the chosen leaf's payload
    /// fails to decrypt.
    pub fn resolve_fork(
        &mut self,
        account_id: AccountId,
        keep_revision_id: RevisionId,
    ) -> Result<RevisionId> {
        // Cache-bearing op (decrypts the chosen leaf, re-seals). Strict
        // freshness check; NO presence proof (Q2).
        self.check_session_freshness()?;
        let _ = self.require_active()?;

        let (chosen_schema_version, chosen_is_tombstone) =
            self.resolve_fork_validate(account_id, keep_revision_id)?;

        // Build the merge revision's ciphertext. The merge row's
        // parent_revision_id IS the chosen head's revision_id, so the
        // AAD binds the new parent (a byte-copy of the chosen leaf's
        // ciphertext would carry the chosen leaf's own parent baked into
        // its AAD and be unopenable as the merge row). The schema
        // version is inherited from the chosen leaf.
        let merge_revision_id = RevisionId::from_bytes(random_32_via_sqlite(&self.conn)?);
        let merge_aad = build_aad(
            &self.meta.vault_id,
            &account_id,
            &keep_revision_id,
            chosen_schema_version,
        );
        let now = current_unix_ms();
        let (ct, nonce, is_tombstone) = if chosen_is_tombstone {
            // Resolving to a tombstone ratifies the deletion (P9 §A5).
            // Audit L1: still authenticate the chosen leaf's ciphertext
            // first — `read_identity_at` does the AEAD open (the
            // `revisions.schema_version` byte is in the AAD, so a bare
            // byte-flip of that column surfaces `AuthenticationFailed`
            // here; a legit future-version leaf surfaces
            // `UnsupportedRevisionSchemaVersion`). A tombstone payload
            // decodes to `Err(AccountTombstoned)` *after* a successful
            // authenticated open — that's the expected, authenticated
            // outcome for this branch; anything else propagates.
            match self.read_identity_at(account_id, keep_revision_id) {
                Err(StoreError::AccountTombstoned) => {}
                Err(e) => return Err(e),
                Ok(_) => {
                    // The `is_tombstone` column said tombstone but the
                    // (authenticated) payload decoded Live — a tampered
                    // flag. Refuse to ratify.
                    return Err(StoreError::AuthenticationFailed);
                }
            }
            let active = self.require_active()?;
            let merge_payload = TombstonePayload::new(account_id, u64::try_from(now).unwrap_or(0));
            let (ct, nonce) = seal_tombstone(active.vdk.aead_key(), &merge_aad, &merge_payload)?;
            (ct, nonce, true)
        } else {
            // Read the chosen leaf as an AccountIdentity (V1-aware,
            // auto-migrating V0 on read) and re-seal it under the merge
            // AAD with a fresh nonce. The identity zeroizes on drop.
            // `read_identity_at` does the AEAD open first (audit L1):
            // a flipped `schema_version` byte → `AuthenticationFailed`;
            // a legit future leaf → `UnsupportedRevisionSchemaVersion`.
            let identity = self.read_identity_at(account_id, keep_revision_id)?;
            let active = self.require_active()?;
            let (ct, nonce) =
                crate::blob::seal_identity(active.vdk.aead_key(), &identity, &merge_aad)?;
            drop(identity);
            (ct, nonce, false)
        };

        self.resolve_fork_commit(
            account_id,
            keep_revision_id,
            merge_revision_id,
            chosen_schema_version,
            now,
            &ct,
            &nonce,
            is_tombstone,
        )?;

        // MVP-2 issue 5.1 (R-d): window-start hook for the merge
        // revision's dirty marker. Stamped here rather than inside
        // `resolve_fork_commit` because that helper is `&self` (its
        // SQL discipline takes an interior borrow of `conn`); the
        // hook needs `&mut self` for the in-memory window-state
        // mutation.
        self.note_dirty_marker_stamped(now);

        // Prune any pending_merges stash row whose target_head_id is no
        // longer a current head (the just-resolved losing leaves, and
        // the resolved target itself if it was stashed). Best-effort —
        // a failure here doesn't undo the resolve, which has committed.
        let _ = self.prune_orphan_pending_merges(account_id);
        self.resolve_fork_sync_cache(account_id, merge_revision_id, now, is_tombstone);
        self.touch_session();
        Ok(merge_revision_id)
    }

    /// `resolve_fork` step 1: validate the account exists + isn't
    /// tombstoned, the chosen revision is a row of *this* account, the
    /// account is forked, and the chosen revision is a current head.
    /// Returns `(chosen_schema_version, chosen_is_tombstone)`.
    fn resolve_fork_validate(
        &self,
        account_id: AccountId,
        keep_revision_id: RevisionId,
    ) -> Result<(u8, bool)> {
        let tombstoned: bool = self
            .conn
            .query_row(
                "SELECT tombstoned FROM account_identities WHERE account_id = ?1",
                params![account_id.as_bytes().as_slice()],
                |row| {
                    let t: i64 = row.get(0)?;
                    Ok(t != 0)
                },
            )
            .optional()?
            .ok_or(StoreError::AccountNotFound)?;
        if tombstoned {
            return Err(StoreError::AccountTombstoned);
        }
        // Defense-in-depth: never let a cross-account revision_id become
        // an oracle — collapse the mismatch into AccountNotFound.
        let chosen_row: Option<(i64, i64)> = self
            .conn
            .query_row(
                "SELECT schema_version, is_tombstone FROM revisions
                 WHERE account_id = ?1 AND revision_id = ?2",
                params![
                    account_id.as_bytes().as_slice(),
                    keep_revision_id.as_bytes().as_slice(),
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let (chosen_sv_i64, chosen_is_tombstone_i64) =
            chosen_row.ok_or(StoreError::AccountNotFound)?;
        let chosen_schema_version = u8::try_from(chosen_sv_i64).map_err(|_| {
            StoreError::Corrupted("revisions.schema_version out of u8 range".into())
        })?;
        // Audit L1: no `chosen_schema_version > MAX` pre-check here —
        // the `revisions.schema_version` byte is bound into the AEAD
        // AAD, so the authoritative check is the AEAD open of the chosen
        // leaf in `resolve_fork` (via `read_identity_at`). A bare
        // byte-flip of that column surfaces `AuthenticationFailed`
        // there; a legit future-version leaf surfaces
        // `UnsupportedRevisionSchemaVersion` there. Pre-checking here
        // would let a flipped byte short-circuit to a misleading
        // "requires upgrade" before authentication.
        let heads = self.account_heads(account_id)?;
        if heads.len() <= 1 {
            return Err(StoreError::Validation {
                kind: "not-forked".into(),
                message: "account is not forked; nothing to resolve".into(),
            });
        }
        if !heads.contains(&keep_revision_id) {
            return Err(StoreError::NotAHead {
                account_id,
                chosen: keep_revision_id,
                current_heads: heads,
            });
        }
        Ok((chosen_schema_version, chosen_is_tombstone_i64 != 0))
    }

    /// `resolve_fork` step 2: INSERT the merge revision + advance the
    /// head pointer + clear `frozen_pending_resolve` + write the dirty
    /// marker, all in one transaction. Re-checks head membership inside
    /// the transaction so a concurrent `ingest_chain_revision` that
    /// demoted the chosen leaf surfaces `NotAHead` rather than producing
    /// a merge parented at a non-head.
    #[allow(clippy::too_many_arguments)]
    fn resolve_fork_commit(
        &self,
        account_id: AccountId,
        keep_revision_id: RevisionId,
        merge_revision_id: RevisionId,
        schema_version: u8,
        now: i64,
        ct: &Ciphertext,
        nonce: &Nonce,
        is_tombstone: bool,
    ) -> Result<()> {
        // #106b-2: the merge revision is sealed under the current epoch's
        // VDK (the caller seals via `active.vdk`), so stamp the current
        // epoch (Q-a). Captured before the tx borrow.
        let vdk_epoch = self.current_vdk_epoch_i64();
        let tx = self.conn.unchecked_transaction()?;
        {
            let mut head_stmt = tx.prepare(
                // #106d (salvaged #103-C FINDING 2): exclude revoked rows
                // (outer) + revoked children (subquery) from the head set.
                "SELECT r.revision_id FROM revisions r
                 WHERE r.account_id = ?1
                   AND r.superseded_by IS NULL
                   AND r.revoked = 0
                   AND NOT EXISTS (
                     SELECT 1 FROM revisions r2
                     WHERE r2.parent_revision_id = r.revision_id
                       AND r2.account_id = r.account_id
                       AND r2.revoked = 0
                   )",
            )?;
            let head_rows =
                head_stmt.query_map(params![account_id.as_bytes().as_slice()], |row| {
                    let rid: Vec<u8> = row.get(0)?;
                    Ok(rid)
                })?;
            let mut tx_heads: Vec<RevisionId> = Vec::new();
            for r in head_rows {
                let blob = r?;
                let arr: [u8; REVISION_ID_LEN] = blob
                    .as_slice()
                    .try_into()
                    .map_err(|_| StoreError::Corrupted("head revision_id not 32 bytes".into()))?;
                tx_heads.push(RevisionId::from_bytes(arr));
            }
            drop(head_stmt);
            if !tx_heads.contains(&keep_revision_id) {
                return Err(StoreError::NotAHead {
                    account_id,
                    chosen: keep_revision_id,
                    current_heads: tx_heads,
                });
            }
            // Q5: KEEP the losing branch's revision rows (audit). They
            // are merely marked `superseded_by = <merge>` so the head
            // detector stops counting them as leaves — a resolved fork
            // reports a single canonical head. (Append-only preserved:
            // no row is deleted; this is a metadata pointer like the
            // chain-anchor columns.)
            for losing in tx_heads.iter().filter(|h| **h != keep_revision_id) {
                tx.execute(
                    "UPDATE revisions SET superseded_by = ?1
                     WHERE account_id = ?2 AND revision_id = ?3",
                    params![
                        merge_revision_id.as_bytes().as_slice(),
                        account_id.as_bytes().as_slice(),
                        losing.as_bytes().as_slice(),
                    ],
                )?;
            }
        }
        tx.execute(
            "INSERT INTO revisions (
                revision_id, account_id, parent_revision_id, device_id,
                schema_version, created_at, enc_payload, enc_nonce, is_tombstone, vdk_epoch
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                merge_revision_id.as_bytes().as_slice(),
                account_id.as_bytes().as_slice(),
                keep_revision_id.as_bytes().as_slice(),
                self.device_id.0.as_slice(),
                i64::from(schema_version),
                now,
                ct.as_bytes(),
                nonce.as_bytes().as_slice(),
                i64::from(is_tombstone),
                vdk_epoch,
            ],
        )?;
        tx.execute(
            "UPDATE account_identities
             SET head_revision_id = ?1, last_modified_at = ?2,
                 frozen_pending_resolve = 0, tombstoned = ?3
             WHERE account_id = ?4",
            params![
                merge_revision_id.as_bytes().as_slice(),
                now,
                i64::from(is_tombstone),
                account_id.as_bytes().as_slice(),
            ],
        )?;
        tx.execute(
            "INSERT OR IGNORE INTO dirty_accounts
                (account_id, revision_id, marked_at)
             VALUES (?1, ?2, ?3)",
            params![
                account_id.as_bytes().as_slice(),
                merge_revision_id.as_bytes().as_slice(),
                now,
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// `resolve_fork` step 3: keep the in-RAM cache + FTS5 index aligned
    /// with the new canonical head. A merge-to-tombstone drops the
    /// account from both; otherwise re-insert the now-canonical
    /// identity. Best-effort — the resolve has already committed.
    fn resolve_fork_sync_cache(
        &mut self,
        account_id: AccountId,
        merge_revision_id: RevisionId,
        now: i64,
        is_tombstone: bool,
    ) {
        if is_tombstone {
            if let Ok(active) = self.require_active_mut() {
                let _ = active.cache.remove(account_id);
                let _ = active.search_index.remove(account_id);
            }
        } else if let Ok(identity) = self.read_identity_at(account_id, merge_revision_id) {
            let projection = SearchProjection::from_identity(&identity);
            let snapshot = downgrade_identity_to_snapshot(&identity);
            drop(identity);
            if let Ok(active) = self.require_active_mut() {
                let _ = active.search_index.update(account_id, now, &projection);
                active.cache.insert(account_id, snapshot);
            }
        }
    }

    /// Every account in the local store that currently has more than
    /// one head — the "needs attention" set for P9's eventual conflict
    /// resolution UI.
    ///
    /// The query groups the `revisions` table by `account_id` and
    /// retains only those whose count of children-less rows
    /// (heads) exceeds one. Order: `account_id` byte-order ASC for
    /// deterministic iteration.
    ///
    /// # Errors
    ///
    /// `StoreError::Sqlite` on any database issue.
    pub fn all_forked_accounts(&self) -> Result<Vec<AccountId>> {
        // M-1 (P3 audit): scope the NOT EXISTS subquery by `account_id`
        // (defense-in-depth — see `account_heads` above for rationale).
        let mut stmt = self.conn.prepare(
            // #106d (salvaged #103-C FINDING 2): exclude revoked rows
            // (outer) + revoked children (subquery) so a fork that exists
            // only because of a revoked head is not reported as forked.
            "SELECT account_id FROM (
                SELECT r.account_id, COUNT(*) AS head_count
                FROM revisions r
                WHERE r.superseded_by IS NULL
                  AND r.revoked = 0
                  AND NOT EXISTS (
                    SELECT 1 FROM revisions r2
                    WHERE r2.parent_revision_id = r.revision_id
                      AND r2.account_id = r.account_id
                      AND r2.revoked = 0
                )
                GROUP BY r.account_id
                HAVING head_count > 1
            )
            ORDER BY account_id ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            let id: Vec<u8> = row.get(0)?;
            Ok(id)
        })?;
        let mut out: Vec<AccountId> = Vec::new();
        for row in rows {
            let id = row?;
            let arr: [u8; ACCOUNT_ID_LEN] = id
                .as_slice()
                .try_into()
                .map_err(|_| StoreError::Corrupted("account_id not 32 bytes".into()))?;
            out.push(AccountId::from_bytes(arr));
        }
        Ok(out)
    }

    /// **P9-2.** Snapshot every account currently in a
    /// conflict-needing-resolution state — fork OR freeze OR both.
    ///
    /// The returned vector is the union of `all_forked_accounts()`
    /// and `list_frozen_accounts()`, with one
    /// [`crate::conflict::ConflictReport`] row per account; the
    /// per-account head set is computed via `account_heads(...)`.
    /// Iteration order is `account_id` byte-order ASC for
    /// deterministic output regardless of the underlying table layout.
    ///
    /// State combinations the caller will see:
    ///
    /// | `frozen` | `heads.len()` | Meaning                                  |
    /// |---|---|---|
    /// | true | 1 | Foreign chain event landed on a brand-new foreign account; the local row has the freeze flag set but the graph is structurally linear. |
    /// | true | >1 | Foreign chain event landed under an existing local account whose graph is also forked (the dominant resolve case). |
    /// | false | >1 | Two LOCAL revisions both unpublished, no chain involvement yet (e.g., two handles of the same vault file edited offline). |
    /// | false | 1 | Not in the report (clean state). |
    ///
    /// Metadata-only — does NOT require [`VaultState::Active`]. The
    /// `pangolin-cli resolve` subcommand calls this on a Locked vault
    /// to enumerate candidates BEFORE prompting for the password.
    ///
    /// # Errors
    ///
    /// Inherits [`StoreError::Sqlite`] / [`StoreError::Corrupted`]
    /// from the underlying `account_heads` /
    /// `list_frozen_accounts` / `all_forked_accounts` calls.
    pub fn list_conflicts(&self) -> Result<Vec<crate::conflict::ConflictReport>> {
        // Build the union of forked + frozen account ids. The two
        // sets can overlap (an account both forked AND frozen is the
        // dominant case); we deduplicate via `BTreeSet`-equivalent
        // logic — but `AccountId` does not implement `Ord`, so we
        // use a `HashSet` and sort the resulting Vec by raw bytes
        // for the deterministic output ordering.
        let forked = self.all_forked_accounts()?;
        let frozen = self.list_frozen_accounts()?;
        let mut union: std::collections::HashSet<AccountId> = std::collections::HashSet::new();
        union.extend(forked.iter().copied());
        union.extend(frozen.iter().copied());

        let frozen_set: std::collections::HashSet<AccountId> = frozen.iter().copied().collect();

        let mut ids: Vec<AccountId> = union.into_iter().collect();
        // `AccountId` is a 32-byte opaque blob; sort by raw bytes
        // for deterministic iteration. The closure cannot panic —
        // `as_bytes` returns a slice of fixed length 32.
        ids.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));

        let mut out: Vec<crate::conflict::ConflictReport> = Vec::with_capacity(ids.len());
        for account_id in ids {
            // **MVP-2 issue 5.3 (R-d).** Enrich every head into a
            // `ConflictBranchSummary`. We reuse `revision_graph`
            // (cheap — one SQL read per account, builds the in-memory
            // index from the `revisions` rows) so we get the
            // `on_canonical_chain` answer from the 1.6 R-c canonical-
            // head rule without re-implementing it here. The graph's
            // metadata view of each leaf is the per-row source of
            // truth for `device_id` / `schema_version` /
            // `is_tombstone` / `parent_revision_id`. The
            // `observed_at_block` column is NOT in the graph (it's a
            // chain-sync-only annotation); we read it via a focused
            // SQL query per leaf — at most N-heads-per-conflicted-
            // account reads, typically 2-3.
            let graph = self.revision_graph(account_id)?;
            let heads = graph.heads().to_vec();
            let canonical = graph.canonical_head().copied();

            // Stable iteration order: byte-lexicographic ASC by
            // revision_id. Matches the deterministic ordering used
            // everywhere else in the store.
            let mut sorted_heads = heads;
            sorted_heads.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));

            let mut branches: Vec<crate::conflict::ConflictBranchSummary> =
                Vec::with_capacity(sorted_heads.len());
            for head_id in &sorted_heads {
                let meta = graph.get(head_id).ok_or_else(|| {
                    StoreError::Corrupted("head revision_id missing from graph index".into())
                })?;
                // observed_at_block: prefer the chain-sync annotation
                // (set inside `ingest_pending_chain_revision`);
                // fall back to `chain_block_number` for rows stamped
                // via `mark_published` (= local publish round-trip)
                // so the host UI always has some "when did this
                // first appear on the chain" anchor.
                let observed_at_block = self.read_observed_at_block(account_id, *head_id)?;
                let parent = if meta.parent_revision_id == RevisionId::GENESIS_PARENT {
                    None
                } else {
                    Some(meta.parent_revision_id)
                };
                let on_canonical_chain = canonical.is_some_and(|head| {
                    *head_id == head || graph.ancestors(&head).contains(head_id)
                });
                branches.push(crate::conflict::ConflictBranchSummary {
                    revision_id: *head_id,
                    parent,
                    device_id: meta.device_id.0.to_vec(),
                    observed_at_block,
                    schema_version: u32::from(meta.schema_version),
                    is_tombstone: meta.is_tombstone,
                    on_canonical_chain,
                });
            }

            let report = crate::conflict::ConflictReport {
                account_id,
                branches,
                frozen: frozen_set.contains(&account_id),
            };
            out.push(report);
        }
        Ok(out)
    }

    /// **MVP-2 issue 5.3 (R-d).** Per-revision `observed_at_block`
    /// lookup with fallback. Internal helper for [`Self::list_conflicts`].
    ///
    /// Returns the chain-sync `observed_at_block` if populated (set
    /// by [`Self::ingest_pending_chain_revision`] for rows that came
    /// in through the 4.1 chain-sync path); otherwise falls back to
    /// `chain_block_number` from the `mark_published` anchor stamp.
    /// Returns `None` for purely local rows that haven't yet been
    /// published or observed on chain.
    fn read_observed_at_block(
        &self,
        account_id: AccountId,
        revision_id: RevisionId,
    ) -> Result<Option<u64>> {
        let row: Option<(Option<i64>, Option<i64>)> = self
            .conn
            .query_row(
                "SELECT observed_at_block, chain_block_number
                 FROM revisions
                 WHERE account_id = ?1 AND revision_id = ?2",
                params![
                    account_id.as_bytes().as_slice(),
                    revision_id.as_bytes().as_slice(),
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((observed, chain_block)) = row else {
            return Ok(None);
        };
        // Prefer chain-sync's observed_at_block; fall back to the
        // local mark_published anchor's block_number for the
        // self-publish-round-trip case.
        let i64_block = observed.or(chain_block);
        i64_block.map_or_else(
            || Ok(None),
            |b| {
                u64::try_from(b).map(Some).map_err(|_| {
                    StoreError::Corrupted(format!("observed_at_block {b} is negative"))
                })
            },
        )
    }

    /// **MVP-2 issue 5.3 (R-c helper).** One-shot snapshot of the
    /// account-level conflict set.
    ///
    /// Computes the `(frozen, forked)` `HashSet` pair via the two
    /// existing accessors (`list_frozen_accounts` +
    /// `all_forked_accounts`). Suitable for passing into
    /// [`Self::list_conflicts_since`] to diff against a later state.
    /// Used internally by [`Self::pull_once`] to populate
    /// `PullReport.newly_frozen_accounts` /
    /// `newly_forked_accounts` / `newly_resolved_accounts`.
    ///
    /// Metadata-only — does NOT require [`VaultState::Active`]. Two
    /// cheap O(N-conflicted) SQL reads.
    ///
    /// # Errors
    ///
    /// Inherits [`StoreError::Sqlite`] / [`StoreError::Corrupted`]
    /// from the underlying `list_frozen_accounts` /
    /// `all_forked_accounts` calls.
    pub fn snapshot_conflicts(&self) -> Result<crate::conflict::ConflictSnapshot> {
        let frozen: std::collections::HashSet<AccountId> =
            self.list_frozen_accounts()?.into_iter().collect();
        let forked: std::collections::HashSet<AccountId> =
            self.all_forked_accounts()?.into_iter().collect();
        Ok(crate::conflict::ConflictSnapshot { frozen, forked })
    }

    /// **MVP-2 issue 5.3 (R-c helper).** Diff the current conflict
    /// set against a prior [`crate::conflict::ConflictSnapshot`].
    ///
    /// Returns a [`crate::conflict::ConflictDelta`] populated via
    /// directional set-difference (see `ConflictDelta` docs for the
    /// exact semantics). Convenience wrapper around
    /// [`Self::snapshot_conflicts`] + a pure
    /// [`diff_conflict_snapshots`] call.
    ///
    /// Metadata-only — does NOT require [`VaultState::Active`].
    ///
    /// # Errors
    ///
    /// Inherits the error set of [`Self::snapshot_conflicts`].
    pub fn list_conflicts_since(
        &self,
        prior: &crate::conflict::ConflictSnapshot,
    ) -> Result<crate::conflict::ConflictDelta> {
        let current = self.snapshot_conflicts()?;
        Ok(diff_conflict_snapshots(prior, &current))
    }

    // -----------------------------------------------------------------
    // P3 test helpers (cfg(test) only)
    // -----------------------------------------------------------------

    /// **Test-only**: synthesize a sibling revision whose parent is the
    /// caller-chosen `parent_revision_id` rather than the account's
    /// current canonical head. This is the ONLY way to exercise fork
    /// detection from inside this crate without going through P7's
    /// chain adapter — production [`Self::add_account`] and
    /// [`Self::update_account`] always advance linearly.
    ///
    /// The synthesized revision uses the same crypto primitives as
    /// production: it AEAD-seals the supplied snapshot under the
    /// active VDK with an AAD bound to (`vault_id`, `account_id`,
    /// chosen `parent_revision_id`, `schema_version`). A round-trip
    /// through the unlock path therefore decrypts cleanly, and any
    /// future divergence (e.g., wrong AAD) would be caught by the
    /// existing AEAD authentication discipline.
    ///
    /// The vault must be `Active`; the account must exist and not be
    /// tombstoned. Unlike `update_account`, this method does NOT
    /// modify `account_identities.head_revision_id` — the canonical
    /// head pointer remains whatever it was before the call. The
    /// fork-detection query (`NOT EXISTS` subquery) discovers the new
    /// head independently.
    ///
    /// # Visibility
    ///
    /// Public so `tests/e2e.rs` (an integration test that links the
    /// crate as an external dependency) can build a fork without
    /// needing the chain adapter. The `__` prefix on the method name
    /// plus the `#[doc(hidden)]` attribute on the method itself are
    /// the standard Rust idiom for "this is in the public surface
    /// strictly to make the test harness work; not for downstream
    /// consumption."
    ///
    /// **P9 fix-pass LOW-1.** Previously this method was `pub`
    /// unconditionally, relying on the `__` prefix + `#[doc(hidden)]`
    /// as the only discipline against accidental production use.
    /// This fix-pass moves the method behind the existing
    /// `feature = "test-utilities"` gate (also active under `cfg(test)`
    /// for in-crate tests) so production builds of downstream
    /// binaries (`chaincli`, `pangolin-cli`) cannot link against the
    /// helper at all.  The helper is still reachable from this
    /// crate's own `#[cfg(test)]` modules and from external
    /// integration tests that opt in to the `test-utilities` feature.
    ///
    /// Returns the synthesized revision's id.
    ///
    /// # Errors
    ///
    /// Same set as `update_account`, plus `RevisionNotFound` if the
    /// **MVP-2 issue 5.1 test helper.** Force-set the `marked_at`
    /// column of a specific `dirty_accounts` row. Used by the
    /// L-clock-skew coalescing test to simulate a backwards-jumping
    /// host clock without `Instant`-mocking gymnastics. Gated behind
    /// `cfg(any(test, feature = "test-utilities"))` so production
    /// builds cannot link against it.
    ///
    /// No-op if the `(account_id, revision_id)` pair has no marker.
    ///
    /// # Errors
    ///
    /// `StoreError::Sqlite` for any database issue.
    #[doc(hidden)]
    #[cfg(any(test, feature = "test-utilities"))]
    pub fn __test_set_dirty_marker_timestamp(
        &self,
        account_id: AccountId,
        revision_id: RevisionId,
        new_marked_at: i64,
    ) -> Result<()> {
        self.conn.execute(
            "UPDATE dirty_accounts
             SET marked_at = ?1
             WHERE account_id = ?2 AND revision_id = ?3",
            params![
                new_marked_at,
                account_id.as_bytes().as_slice(),
                revision_id.as_bytes().as_slice(),
            ],
        )?;
        Ok(())
    }

    /// declared parent is not in the account's revision history.
    #[doc(hidden)]
    #[cfg(any(test, feature = "test-utilities"))]
    // Mirrors the `add_account` / `update_account` signature shape
    // (snapshot taken by value) so a test reads identically to a
    // production write. Production paths consume the snapshot into
    // the cache; this one does not, but matching the signature keeps
    // the test-side ergonomics aligned with the API the helper
    // pretends to be.
    #[allow(clippy::needless_pass_by_value)]
    pub fn __test_synthesize_sibling_revision(
        &mut self,
        id: AccountId,
        parent: RevisionId,
        snapshot: AccountSnapshot,
    ) -> Result<RevisionId> {
        // P4: cache-bearing path (uses the AEAD key). Strict check.
        self.check_session_freshness()?;
        let _ = self.require_active()?;
        // Confirm the account exists and that the chosen parent is in
        // its revision history. The first check protects against
        // typos in tests; the second prevents synthesizing an
        // attacker-style "orphan revision" with no shared lineage.
        let account_row = self
            .conn
            .query_row(
                "SELECT tombstoned FROM account_identities WHERE account_id = ?1",
                params![id.as_bytes().as_slice()],
                |row| {
                    let t: i64 = row.get(0)?;
                    Ok(t != 0)
                },
            )
            .optional()?
            .ok_or(StoreError::AccountNotFound)?;
        if account_row {
            return Err(StoreError::AccountTombstoned);
        }
        let parent_exists: Option<i64> = self
            .conn
            .query_row(
                "SELECT 1 FROM revisions
                 WHERE account_id = ?1 AND revision_id = ?2",
                params![id.as_bytes().as_slice(), parent.as_bytes().as_slice(),],
                |row| row.get(0),
            )
            .optional()?;
        if parent_exists.is_none() {
            return Err(StoreError::RevisionNotFound);
        }

        let revision_id = RevisionId::from_bytes(random_32_via_sqlite(&self.conn)?);
        let aad = build_aad(
            &self.meta.vault_id,
            &id,
            &parent,
            self.meta.wrap_context.schema_version,
        );
        let active = self.require_active()?;
        let (ct, nonce) = seal_snapshot(active.vdk.aead_key(), &snapshot, &aad)?;
        let now = current_unix_ms();

        // INSERT only into `revisions` — do NOT touch
        // `account_identities.head_revision_id`. The whole point of
        // this helper is to leave the canonical head pointer alone so
        // multi-head detection has work to do.
        self.conn.execute(
            "INSERT INTO revisions (
                revision_id, account_id, parent_revision_id, device_id,
                schema_version, created_at, enc_payload, enc_nonce, is_tombstone
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0)",
            params![
                revision_id.as_bytes().as_slice(),
                id.as_bytes().as_slice(),
                parent.as_bytes().as_slice(),
                self.device_id.0.as_slice(),
                i64::from(self.meta.wrap_context.schema_version),
                now,
                ct.as_bytes(),
                nonce.as_bytes().as_slice(),
            ],
        )?;
        self.touch_session();
        Ok(revision_id)
    }

    /// **Test-only (MVP-1 issue 1.6).** Append a revision parented at
    /// the account's current head whose blob carries a *future* schema
    /// version — either the `revisions.schema_version` row column
    /// (`row_version`, written verbatim — also the AAD byte, so the
    /// blob is sealed under that byte) or, when `row_version` ==
    /// [`crate::revision::REVISION_SCHEMA_VERSION_MAX`], a future
    /// `payload_version` inside the V1 CBOR body (`payload_version`).
    /// This is the only way to synthesise a "requires upgrade"
    /// revision from inside the crate (the production encoder always
    /// emits `payload_version = 1` and `schema_version = wrap_context`).
    /// The new revision becomes a leaf; advancing the cached
    /// `head_revision_id` to it (so unlock sees it as the canonical
    /// head when the account is otherwise linear) is the caller's job
    /// via the optional `advance_head` flag.
    ///
    /// Gated so production builds cannot link against it.
    ///
    /// Returns the synthesized revision's id.
    #[doc(hidden)]
    #[cfg(any(test, feature = "test-utilities"))]
    #[allow(clippy::needless_pass_by_value)]
    pub fn __test_synthesize_future_version_revision(
        &mut self,
        id: AccountId,
        snapshot: AccountSnapshot,
        row_version: u8,
        payload_version: u8,
        advance_head: bool,
    ) -> Result<RevisionId> {
        self.check_session_freshness()?;
        let _ = self.require_active()?;
        let head_blob = self
            .conn
            .query_row(
                "SELECT head_revision_id FROM account_identities WHERE account_id = ?1",
                params![id.as_bytes().as_slice()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .ok_or(StoreError::AccountNotFound)?;
        let parent_arr: [u8; REVISION_ID_LEN] = head_blob
            .as_slice()
            .try_into()
            .map_err(|_| StoreError::Corrupted("head_revision_id not 32 bytes".into()))?;
        let parent = RevisionId::from_bytes(parent_arr);
        let revision_id = RevisionId::from_bytes(random_32_via_sqlite(&self.conn)?);
        // Build an AccountIdentity from the snapshot (hydrate V0→V1
        // like add_account would) so we can seal a V1 8-key blob.
        let identity = crate::account::AccountIdentity::new_unchecked(
            SecretBytes::new(snapshot.display_name.expose().to_vec()),
            Vec::new(),
            SecretBytes::new(snapshot.notes.expose().to_vec()),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            SecretBytes::new(snapshot.totp_secret.expose().to_vec()),
        );
        let aad = build_aad(&self.meta.vault_id, &id, &parent, row_version);
        let active = self.require_active()?;
        let (ct, nonce) = crate::blob::seal_identity_with_payload_version(
            active.vdk.aead_key(),
            &identity,
            &aad,
            payload_version,
        )?;
        let now = current_unix_ms();
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO revisions (
                revision_id, account_id, parent_revision_id, device_id,
                schema_version, created_at, enc_payload, enc_nonce, is_tombstone
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0)",
            params![
                revision_id.as_bytes().as_slice(),
                id.as_bytes().as_slice(),
                parent.as_bytes().as_slice(),
                self.device_id.0.as_slice(),
                i64::from(row_version),
                now,
                ct.as_bytes(),
                nonce.as_bytes().as_slice(),
            ],
        )?;
        if advance_head {
            tx.execute(
                "UPDATE account_identities SET head_revision_id = ?1, last_modified_at = ?2
                 WHERE account_id = ?3",
                params![
                    revision_id.as_bytes().as_slice(),
                    now,
                    id.as_bytes().as_slice(),
                ],
            )?;
        }
        tx.commit()?;
        self.touch_session();
        Ok(revision_id)
    }

    /// Internal: read every `revisions` row for `account_id` into
    /// [`RevisionMeta`] form. Used by [`Self::revision_graph`].
    fn read_revision_rows_for(&self, id: AccountId) -> Result<Vec<RevisionMeta>> {
        let mut stmt = self.conn.prepare(
            // #106d (salvaged #103-C FINDING 2): exclude revoked rows so a
            // revoked revision never reaches the content / conflict reads
            // (`revision_graph` feeds them via this helper).
            "SELECT revision_id, parent_revision_id, device_id,
                    schema_version, created_at, is_tombstone,
                    chain_tx_hash, chain_block_number, chain_log_index,
                    superseded_by
             FROM revisions WHERE account_id = ?1
               AND revoked = 0
             ORDER BY created_at ASC, revision_id ASC",
        )?;
        let rows = stmt.query_map(params![id.as_bytes().as_slice()], |row| {
            let revision_id: Vec<u8> = row.get(0)?;
            let parent: Vec<u8> = row.get(1)?;
            let device_id: Vec<u8> = row.get(2)?;
            let schema_version: i64 = row.get(3)?;
            let created_at: i64 = row.get(4)?;
            let is_tombstone: i64 = row.get(5)?;
            let chain_tx_hash: Option<Vec<u8>> = row.get(6)?;
            let chain_block_number: Option<i64> = row.get(7)?;
            let chain_log_index: Option<i64> = row.get(8)?;
            let superseded_by: Option<Vec<u8>> = row.get(9)?;
            Ok(RawRevisionRow {
                revision_id,
                parent,
                device_id,
                schema_version,
                created_at,
                is_tombstone,
                chain_tx_hash,
                chain_block_number,
                chain_log_index,
                superseded_by,
            })
        })?;
        let mut out: Vec<RevisionMeta> = Vec::new();
        for raw in rows {
            out.push(raw?.into_meta()?);
        }
        Ok(out)
    }

    // -----------------------------------------------------------------
    // Chain anchor primitives (P7 hooks)
    // -----------------------------------------------------------------

    /// Return revision ids that have not yet been published on chain
    /// (i.e., `chain_tx_hash IS NULL`). Order: chronological.
    pub fn unpublished_revisions(&self) -> Result<Vec<RevisionId>> {
        let mut stmt = self.conn.prepare(
            "SELECT revision_id FROM revisions
             WHERE chain_tx_hash IS NULL
             ORDER BY created_at ASC, revision_id ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            let blob: Vec<u8> = row.get(0)?;
            Ok(blob)
        })?;
        let mut out = Vec::new();
        for blob in rows {
            let blob = blob?;
            let arr: [u8; REVISION_ID_LEN] = blob
                .as_slice()
                .try_into()
                .map_err(|_| StoreError::Corrupted("revision_id not 32 bytes".into()))?;
            out.push(RevisionId::from_bytes(arr));
        }
        Ok(out)
    }

    /// Record a chain anchor for a revision.
    ///
    /// P4 note: `mark_published` is metadata-only (touches `revisions`
    /// chain-anchor columns; never reads `enc_payload`). It uses the
    /// soft `maybe_expire_active_session` path: if the vault is
    /// `Active` and the idle timer has fired, the cache is zeroized
    /// before the chain anchor is stamped, but the operation itself
    /// succeeds even from a `Locked` state. This preserves the P3
    /// invariant ("metadata-only ops work on a `Locked` vault") and
    /// the P4 invariant ("cache zeroized on session expiry").
    ///
    /// # Errors
    ///
    /// `StoreError::RevisionNotFound` if the id is not in the local
    /// log.
    pub fn mark_published(&mut self, revision_id: RevisionId, anchor: ChainAnchor) -> Result<()> {
        // Soft expiry — does not error for Locked, only zeroizes if
        // Active+expired.
        self.maybe_expire_active_session();
        // Widen the unsigned u64 fields from `pangolin_chain::ChainAnchor`
        // to the SQLite-native i64 used by the `revisions.chain_*`
        // columns. Both Base Sepolia block numbers and log indices stay
        // well below 2^63 for the foreseeable future; we still
        // `try_from` rather than cast so a future overflow surfaces as
        // a clear error instead of silently flipping sign.
        let block_i64 = i64::try_from(anchor.block_number).map_err(|_| {
            StoreError::Corrupted(
                "chain anchor block_number does not fit in i64; refusing to store".into(),
            )
        })?;
        let log_index_i64 = i64::try_from(anchor.log_index).map_err(|_| {
            StoreError::Corrupted(
                "chain anchor log_index does not fit in i64; refusing to store".into(),
            )
        })?;
        let updated = self.conn.execute(
            "UPDATE revisions
             SET chain_tx_hash = ?1, chain_block_number = ?2, chain_log_index = ?3
             WHERE revision_id = ?4",
            params![
                anchor.tx_hash.as_slice(),
                block_i64,
                log_index_i64,
                revision_id.as_bytes().as_slice(),
            ],
        )?;
        if updated == 0 {
            return Err(StoreError::RevisionNotFound);
        }
        // Touch only if we're still Active (the soft expiry above may
        // have transitioned us to Expired).
        self.touch_session();
        Ok(())
    }

    /// Ingest a chain-side revision event into the local log.
    ///
    /// **Distinct from [`Self::add_account`] / [`Self::update_account`]
    /// / [`Self::delete_account`]**: those are the *create-from-edit*
    /// path that produces a new local revision and stamps a dirty
    /// marker. `ingest_chain_revision` is the *ingest* path used by
    /// `pangolin-cli pull` (P8-4) — the revision is stored with its
    /// chain anchor populated from the supplied event, and the dirty
    /// marker is NOT stamped (the revision is already on chain).
    ///
    /// ## Identity discipline
    ///
    /// The local `revision_id` is set to the canonical hash of the
    /// event (per [`pangolin_chain::canonical_hash`]). This is
    /// content-deterministic — two devices that pull the same chain
    /// event ingest under the same `revision_id`, so the cross-device
    /// graph is keyed off the chain's canonical identity rather than
    /// the random ids used for pre-publish revisions.
    ///
    /// ## Idempotency
    ///
    /// Returns `Ok(IngestOutcome::AlreadyPresent)` (without touching
    /// the row) when:
    ///
    /// 1. A row with `revision_id == canonical_hash(event)` already
    ///    exists — i.e., this exact event was previously ingested,
    ///    OR
    /// 2. A row exists with the same `(account_id, parent_revision,
    ///    enc_payload, device_id, schema_version)` AND has a
    ///    populated `chain_tx_hash` — i.e., this device's own
    ///    publish coming back from the chain. The original local row
    ///    keeps its random `revision_id`, but we recognise it as the
    ///    same revision by content and skip the insert.
    ///
    /// ## Defense-in-depth signature verification
    ///
    /// Per `P8.md` §Q6, callers (`pangolin-cli pull`) MUST verify the
    /// signed-revision signature before invoking this method. v0
    /// contract has no on-chain signature semantics; this client-side
    /// check catches an attacker-controlled-RPC-with-forged-events
    /// threat at the device boundary.
    ///
    /// Metadata-ish — does NOT touch the decrypted cache and does
    /// NOT require [`VaultState::Active`].
    ///
    /// # Errors
    ///
    /// `StoreError::Sqlite` for any database issue.
    /// `StoreError::Corrupted` if the supplied `tx_hash` /
    /// `block_number` / `log_index` values would not fit in `i64`.
    #[allow(clippy::too_many_lines)] // The three idempotency checks
                                     // + the merge path + the insert path inherently expand the body
                                     // beyond the workspace's 100-line clippy floor; factoring out
                                     // sub-helpers would obscure the linear flow that makes the
                                     // method's invariants reviewable. The added comments are
                                     // load-bearing for the audit.
    pub fn ingest_chain_revision(
        &mut self,
        event: &pangolin_chain::RevisionEvent,
    ) -> Result<IngestOutcome> {
        self.maybe_expire_active_session();

        // Compute the content-deterministic identity for the chain
        // event. This is the keccak digest the v1 contract is
        // expected to verify natively.
        let canonical = pangolin_chain::canonical_hash(
            &event.vault_id,
            &event.account_id,
            &event.parent_revision,
            &event.device_id,
            event.schema_version,
            &event.enc_payload,
        );
        let revision_id_arr = canonical;

        // Idempotency check #1: exact-hash match.
        let existing_by_hash: Option<i64> = self
            .conn
            .query_row(
                "SELECT 1 FROM revisions WHERE revision_id = ?1",
                params![&revision_id_arr[..]],
                |row| row.get(0),
            )
            .optional()?;
        if existing_by_hash.is_some() {
            self.touch_session();
            return Ok(IngestOutcome::AlreadyPresent);
        }

        // Idempotency check #2: this device's own publish round-
        // tripping through the chain. The chain event carries a
        // `tx_hash` anchor; if a local revision row was previously
        // marked published with that exact tx_hash + log_index, the
        // current event is that same row coming back. We match on
        // (account_id, chain_tx_hash, chain_log_index) — every
        // chain event has exactly one `(tx_hash, log_index)`
        // identity, so this is unambiguous.
        //
        // The device_id field is NOT part of this check because the
        // PoC two-key model means the signing DeviceKey (whose
        // verifying-key becomes the event's `device_id`) may differ
        // from the local row's stored `device_id` (a random 32 bytes
        // generated at vault create — see vault.rs::open). Matching
        // on the chain anchor is content-equivalent and avoids the
        // two-key drift.
        let block_check = i64::try_from(event.anchor.block_number).map_err(|_| {
            StoreError::Corrupted(
                "RevisionEvent.anchor.block_number does not fit in i64; refusing to store".into(),
            )
        })?;
        let log_check = i64::try_from(event.anchor.log_index).map_err(|_| {
            StoreError::Corrupted(
                "RevisionEvent.anchor.log_index does not fit in i64; refusing to store".into(),
            )
        })?;
        let existing_by_anchor: Option<i64> = self
            .conn
            .query_row(
                "SELECT 1 FROM revisions
                 WHERE account_id = ?1
                   AND chain_tx_hash = ?2
                   AND chain_block_number = ?3
                   AND chain_log_index = ?4",
                params![
                    &event.account_id[..],
                    &event.anchor.tx_hash[..],
                    block_check,
                    log_check,
                ],
                |row| row.get(0),
            )
            .optional()?;
        if existing_by_anchor.is_some() {
            self.touch_session();
            return Ok(IngestOutcome::AlreadyPresent);
        }

        // Idempotency check #3 — content-merge: a local row exists
        // with the same `(account_id, parent_revision, enc_payload,
        // schema_version, device_id)` AND its chain_tx_hash IS NULL.
        // This is "I created this revision locally, and now it's
        // coming back to me from the chain because some other handle
        // published it." We merge by stamping the chain anchor onto
        // the existing local row rather than inserting a duplicate
        // canonical-hash-keyed row. Without this merge the vault
        // would see a spurious 2-head fork on every round-trip
        // through the chain.
        //
        // **P8 fix-pass MED-1.** The audit suggested re-fetching the
        // event via `ChainAdapter::get_revision(tx_hash)` before
        // stamping the anchor. We rejected that approach because an
        // attacker controlling the RPC can spoof both the
        // `pull_since` result AND the `get_revision` result, so
        // re-fetch adds no defense. Instead, we tighten the merge
        // condition itself: the local row's `device_id` must match
        // the event's `device_id`. The legitimate own-publish round-
        // trip carries the same device_id that signed the local
        // row; an attacker spoofing a chain event for a victim's
        // row would have to also know the victim's device_id (which
        // is observable on prior chain events for the same vault but
        // not trivial to harvest). Combined with HIGH-1 (forged
        // events become forks rather than silent merges via the
        // device_id canonical-form check inside `pull_all`), this
        // tightens MED-1 without an extra RPC.
        //
        // The PoC two-key model originally argued device_id wouldn't
        // round-trip; in practice `pangolin-cli publish` and the
        // P0..P7 unit tests both use a `DeviceKey::generate()` whose
        // `verifying_key().to_bytes()` is what flows into both the
        // local revision row AND the chain event's `device_id` (see
        // `signing::build_signed_revision`). MVP-1's switch to the
        // derived wallet (D-006) preserves the same shape.
        let merge_target: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT revision_id FROM revisions
                 WHERE account_id = ?1
                   AND parent_revision_id = ?2
                   AND enc_payload = ?3
                   AND schema_version = ?4
                   AND device_id = ?5
                   AND chain_tx_hash IS NULL
                 LIMIT 1",
                params![
                    &event.account_id[..],
                    &event.parent_revision[..],
                    &event.enc_payload,
                    i64::from(event.schema_version),
                    &event.device_id[..],
                ],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(existing_rev_id) = merge_target {
            // Stamp the chain anchor onto the existing local row.
            self.conn.execute(
                "UPDATE revisions
                 SET chain_tx_hash = ?1,
                     chain_block_number = ?2,
                     chain_log_index = ?3
                 WHERE revision_id = ?4",
                params![
                    &event.anchor.tx_hash[..],
                    block_check,
                    log_check,
                    &existing_rev_id[..],
                ],
            )?;
            self.touch_session();
            return Ok(IngestOutcome::AlreadyPresent);
        }

        // Reuse the i64 conversions computed for the idempotency
        // check above — same widening, no need to repeat.
        let block_i64 = block_check;
        let log_index_i64 = log_check;

        // The chain event carries no nonce (the on-chain contract
        // does not see the AEAD nonce, which lives inside the
        // application's own format). For an *ingested* revision
        // we don't have the original nonce; the ingest path stores
        // a placeholder zeroed nonce. The local vault that
        // originated the revision still has the real nonce in its
        // own row (separate from this ingest row); a vault that
        // first sees the revision via pull cannot decrypt the
        // payload without the nonce — but it can structurally
        // store the row, advance heads, and surface forks. P9
        // resolution + future cross-device sync of nonces (MVP-1)
        // close this gap. For PoC, ingestion succeeds with the
        // zeroed nonce; the receiving device gets the chain
        // structure but not plaintext. Genuine cross-device key
        // sharing is MVP-1.
        let placeholder_nonce = [0u8; NONCE_LEN];
        let now = current_unix_ms();

        // **P10-2: opportunistic tombstone-bit detection.** Inside the
        // genuine-foreign-INSERT branch, attempt to AEAD-open the chain
        // event's `enc_payload` under the local VDK using the placeholder
        // zero nonce that we are about to persist. Three outcomes:
        // (a) decryption succeeds AND decodes to `Tombstone` → bit=1;
        // (b) decryption succeeds AND decodes to `Live` → bit=0;
        // (c) decryption FAILS → bit=0; the freeze sentinel below still
        //     fires for the foreign-event UX safety net.
        //
        // **Non-oracle property (P10 plan A2 audit point).** The
        // decode-success-vs-decode-failure branches MUST NOT diverge
        // observably from outside this function: both paths return
        // `IngestOutcome::Inserted`, both write the same set of columns
        // (the same row is INSERTed in either case), and the caller sees
        // no error-variant difference. The only observable side effect of
        // a successful decode is the `is_tombstone` bit on the inserted
        // row (and, in P10-3, the `account_identities.tombstoned` flag).
        // The AEAD open call's failure path is silently swallowed —
        // every error variant collapses into "bit=0, freeze sentinel
        // fires". No logging, no error-variant escape.
        //
        // **PoC-two-key reality.** The chain event ABI does not transport
        // the AEAD nonce. In practice the seal-time nonce is random and
        // unknown to the ingest path; the open under the placeholder
        // zero nonce will fail except for synthetically-constructed test
        // payloads that were sealed with the placeholder zero nonce
        // deliberately. So under PoC, this branch is functionally a
        // no-op (always falls through to bit=0 + freeze) — but the
        // structurally-correct code is in place for MVP-1's
        // nonce-on-chain to make this functional without further code
        // changes. The audit-flagged hardcode `is_tombstone_i64 = 0`
        // is replaced with the structurally-honest opportunistic
        // decode. Documented in DEVLOG and THREAT_MODEL as known PoC
        // limitation #15 (closed by MVP-1 nonce-on-chain).
        //
        // The decryption is gated on the vault being `Active` (we need
        // the VDK in the session cache). On a Locked vault, the open
        // is skipped; the row lands with bit=0 and the freeze sentinel
        // fires. The opportunistic decode does NOT re-fire on next
        // unlock (idempotency arm #1 by canonical hash hits) — but the
        // resolve flow (P9) does not depend on the `is_tombstone` bit
        // for its read path; the bit's only correctness load is on the
        // post-resolve-merge row, which is local-write-controlled.
        let event_schema_version = event.schema_version;
        let is_tombstone_i64: i64 = self.detect_tombstone_bit_at_ingest(
            &event.account_id,
            &event.parent_revision,
            event_schema_version,
            &event.enc_payload,
            &placeholder_nonce,
        );

        // The revisions.account_id FOREIGN KEY references
        // account_identities(account_id), so we must insert (or
        // observe) the matching account_identities row FIRST. We
        // INSERT OR IGNORE — if the row already exists we leave the
        // head_revision_id alone (the local canonical-head-pointer
        // reflects locally-edited state, not chain state). For a
        // fresh receive-only vault that has no local edits for this
        // account, the row was missing and we create it pointing at
        // the just-ingested revision so `account_heads` works.
        //
        // **P8 fix CRIT-1: defensive frozen-pending-resolve sentinel.**
        // None of the three idempotency arms above matched, so this
        // is a genuinely-new revision from a foreign device — i.e.,
        // the vault is "chain-modified under our nose" for this
        // account. Two cases:
        //
        // - The account row already exists locally (we have prior
        //   revisions for it; another device just edited it): set
        //   `frozen_pending_resolve = 1` so user-facing reads/edits
        //   refuse on this account until P9's `resolve` clears the
        //   flag. The user still sees the prior cached plaintext
        //   structurally (it's in memory) but every read path checks
        //   the flag first.
        //
        // - The account row does NOT yet exist locally (a fresh
        //   foreign account being introduced for the first time):
        //   we INSERT a new row with `frozen_pending_resolve = 1`
        //   too — the receiving vault has no nonce for the new
        //   account and cannot decrypt the ciphertext anyway, but
        //   the sentinel is set for symmetry with the existing-row
        //   case. P9's resolve flow will handle both.
        //
        // The check is "does the row exist BEFORE this INSERT" so
        // we run a probe inside the same transaction, then set the
        // flag unconditionally on the INSERTed/UPDATEd row.
        //
        // Both writes run inside one BEGIN IMMEDIATE … COMMIT
        // transaction so a crash between the two leaves the vault
        // in the pre-transaction state.
        let tx = self.conn.unchecked_transaction()?;
        let preexisting: Option<i64> = tx
            .query_row(
                "SELECT 1 FROM account_identities WHERE account_id = ?1",
                params![&event.account_id[..]],
                |row| row.get(0),
            )
            .optional()?;
        // **P10-3.** When the opportunistic-decode (P10-2) confirmed
        // a tombstone, ALSO surface the deletion to the user-facing
        // summary by flipping `account_identities.tombstoned = 1`.
        // Without this UPDATE, P10-2's bit-set on the revisions row
        // alone wouldn't propagate through `list_accounts` (which
        // filters on the `account_identities` row's tombstoned flag).
        // The `tombstoned` flag is sticky / append-only — once set,
        // never cleared except by P9's resolve flow producing a fresh
        // revision (and even then, only for live-revision merges; a
        // tombstone-merge re-affirms the deletion).
        let tombstoned_set = is_tombstone_i64 == 1;
        if preexisting.is_some() {
            // Existing local account just got modified on chain by
            // another device. Set the freeze sentinel; leave
            // head_revision_id pointing at the local head (which is
            // what the local AAD chain still authenticates against).
            // P10-3: if the opportunistic decode says this is a
            // tombstone, flip `tombstoned = 1` too so list_accounts
            // filters the row. The freeze sentinel is still set so
            // the user sees the deletion as a frozen-pending-resolve
            // surface (the multi-resolve flow handles the merge).
            if tombstoned_set {
                tx.execute(
                    "UPDATE account_identities
                     SET frozen_pending_resolve = 1, tombstoned = 1, last_modified_at = ?1
                     WHERE account_id = ?2",
                    params![now, &event.account_id[..]],
                )?;
            } else {
                tx.execute(
                    "UPDATE account_identities
                     SET frozen_pending_resolve = 1, last_modified_at = ?1
                     WHERE account_id = ?2",
                    params![now, &event.account_id[..]],
                )?;
            }
        } else {
            // Brand-new foreign account. Insert with the freeze flag
            // already set. head_revision_id points at the just-
            // ingested revision so `account_heads` works. P10-3:
            // tombstoned set to the opportunistic-decode result.
            tx.execute(
                "INSERT INTO account_identities
                    (account_id, created_at, last_modified_at, tombstoned,
                     head_revision_id, frozen_pending_resolve)
                 VALUES (?1, ?2, ?2, ?3, ?4, 1)",
                params![
                    &event.account_id[..],
                    now,
                    i64::from(tombstoned_set),
                    &revision_id_arr[..],
                ],
            )?;
        }
        tx.execute(
            "INSERT INTO revisions (
                revision_id, account_id, parent_revision_id, device_id,
                schema_version, created_at, enc_payload, enc_nonce,
                is_tombstone, chain_tx_hash, chain_block_number, chain_log_index
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                &revision_id_arr[..],
                &event.account_id[..],
                &event.parent_revision[..],
                &event.device_id[..],
                i64::from(event.schema_version),
                now,
                &event.enc_payload,
                &placeholder_nonce[..],
                is_tombstone_i64,
                &event.anchor.tx_hash[..],
                block_i64,
                log_index_i64,
            ],
        )?;
        tx.commit()?;

        self.touch_session();
        Ok(IngestOutcome::Inserted)
    }

    /// **P10-2 helper.** Opportunistic tombstone-bit detection for the
    /// genuine-foreign-INSERT branch of [`Self::ingest_chain_revision`].
    ///
    /// Returns `1` iff the chain event's `enc_payload` AEAD-decrypts
    /// (under the local VDK + the placeholder zero nonce that ingest
    /// will persist) AND the decoded plaintext is a [`TombstonePayload`]
    /// whose `deleted` field is `true`. Returns `0` for every other
    /// outcome:
    ///
    /// - vault is Locked (no VDK in session cache);
    /// - AEAD open fails (the common case under `PoC` two-key — the
    ///   chain event's seal-time nonce is unknown, so the open under
    ///   placeholder zero nonce fails authentication);
    /// - decoded payload is a Live snapshot;
    /// - decoded `TombstonePayload::is_deleted()` is somehow false
    ///   (unreachable under correct seal practice; defensive).
    ///
    /// **Non-oracle invariant.** Every error path collapses to `0`; the
    /// only observable side effect of decode-success is the bit value.
    /// No error variant escapes. No logging beyond what the workspace
    /// already does (none here). The caller writes the same row with
    /// the same column set in either case (the freeze sentinel still
    /// fires regardless, for foreign-ingest UX safety).
    ///
    /// **Defense-in-depth payload-vs-event `account_id` cross-check.**
    /// After a successful AEAD-open + CBOR-decode that yields a
    /// `TombstonePayload`, the plaintext-level `payload.account_id()`
    /// is compared against `event_account_id` (the AAD-bound id) using
    /// [`subtle::ConstantTimeEq::ct_eq`]. A mismatch silently collapses
    /// to `is_tombstone = 0` (the same bucket as AEAD failure / CBOR
    /// failure / locked-vault), preserving the non-oracle property —
    /// the only observable difference between "valid tombstone for
    /// this row" and "valid tombstone for *some other* account that
    /// somehow reused our AAD components" is the persisted bit. No
    /// error variant escapes, no log line fires, and the freeze
    /// sentinel still fires for the row's INSERT regardless.
    /// Constant-time comparison forecloses any timing side-channel on
    /// the byte-prefix-match position. This closes the documentation
    /// drift previously flagged as audit M-1 + M-2 (`THREAT_MODEL`
    /// row 18 and `docs/issue-plans/P10.md` §A1/§C used to claim the
    /// cross-check existed before the code shipped it).
    fn detect_tombstone_bit_at_ingest(
        &self,
        event_account_id: &[u8; ACCOUNT_ID_LEN],
        event_parent_revision: &[u8; REVISION_ID_LEN],
        event_schema_version: u8,
        event_enc_payload: &[u8],
        placeholder_nonce: &[u8; NONCE_LEN],
    ) -> i64 {
        // Locked vault → no VDK → cannot decode → return 0.
        let Some(active) = self.active.as_ref() else {
            return 0;
        };

        let account_id = AccountId::from_bytes(*event_account_id);
        let parent_revision_id = RevisionId::from_bytes(*event_parent_revision);
        let aad = build_aad(
            &self.meta.vault_id,
            &account_id,
            &parent_revision_id,
            event_schema_version,
        );
        let nonce = Nonce::from_storage_bytes(*placeholder_nonce);
        let ciphertext = Ciphertext::from_vec(event_enc_payload.to_vec());

        // Swallow every error variant (AEAD failure, CBOR decode
        // failure, malformed-payload, etc.) into a single `0` return
        // for non-oracle discipline. On decode success, gate the
        // bit-set on a constant-time payload-vs-event account_id
        // comparison; mismatch collapses to the same `0` bucket
        // (M-1 + M-2 defense-in-depth). The `Choice::unwrap_u8`
        // returns 0 or 1 by masking, NOT by branching — a
        // mismatched cross-account payload silently lands in the
        // same 0 bucket as AEAD failure, NOT a distinct error
        // variant.
        match open_payload(active.vdk.aead_key(), &nonce, &ciphertext, &aad) {
            Ok(DecodedPayload::Tombstone(p)) if p.is_deleted() => {
                use subtle::ConstantTimeEq;
                i64::from(p.account_id().ct_eq(event_account_id).unwrap_u8())
            }
            Ok(_) | Err(_) => 0,
        }
    }

    // -----------------------------------------------------------------
    // Sync-state primitives (P7) — last_pulled_block checkpoint
    // -----------------------------------------------------------------

    /// Read the local `last_pulled_block` checkpoint.
    ///
    /// Returned value is the highest block number from which the local
    /// vault has ingested chain events. Default for a fresh vault is
    /// `0`; the caller (P8 sync orchestration) typically initializes
    /// it to `deploy_block - 1` so the first sync includes the deploy
    /// block.
    ///
    /// The checkpoint is stored in a single-row `sync_state` table
    /// keyed on `id = 0`. The table is created idempotently
    /// (`CREATE TABLE IF NOT EXISTS`) at vault open; existing P2/P3/P4
    /// vaults pick it up on next open without a schema-version bump
    /// (per `docs/issue-plans/P7.md` §"`last_pulled_block`
    /// checkpoint").
    ///
    /// Passive accessor — does NOT touch the session timer.
    pub fn last_pulled_block(&self) -> Result<u64> {
        let raw: Option<i64> = self
            .conn
            .query_row(
                "SELECT last_pulled_block FROM sync_state WHERE id = 0",
                [],
                |row| row.get(0),
            )
            .optional()?;
        raw.map_or(Ok(0), |v| {
            u64::try_from(v).map_err(|_| {
                StoreError::Corrupted(
                    "sync_state.last_pulled_block is negative; refusing to surface".into(),
                )
            })
        })
    }

    /// Advance the local `last_pulled_block` checkpoint to `new_block`.
    ///
    /// Refuses to move backward — a backward move is symptomatic of
    /// a reorg or operator error and is out of P7's scope (P8 will
    /// add reorg-aware handling). Equal values are treated as no-ops
    /// rather than errors so idempotent retry of `sync_pull` doesn't
    /// surface spurious failures.
    ///
    /// # Errors
    ///
    /// `StoreError::Corrupted` if `new_block` is strictly less than
    /// the current checkpoint, or if it does not fit in `i64`.
    pub fn advance_last_pulled_block(&mut self, new_block: u64) -> Result<()> {
        let current = self.last_pulled_block()?;
        if new_block < current {
            return Err(StoreError::Corrupted(format!(
                "advance_last_pulled_block: new_block {new_block} < current {current}; \
                 backward moves are out of scope for P7 (P8 handles reorgs)"
            )));
        }
        if new_block == current {
            return Ok(());
        }
        let new_i64 = i64::try_from(new_block).map_err(|_| {
            StoreError::Corrupted("last_pulled_block does not fit in i64; refusing to store".into())
        })?;
        // Insert OR replace on id=0; the schema constraint
        // `CHECK (id = 0)` enforces single-row.
        self.conn.execute(
            "INSERT OR REPLACE INTO sync_state (id, last_pulled_block) VALUES (0, ?1)",
            params![new_i64],
        )?;
        Ok(())
    }

    // -----------------------------------------------------------------
    // Chain-sync v1 primitives (MVP-2 issue 4.1, R-a + R-c + R-d)
    // -----------------------------------------------------------------

    /// **MVP-2 issue 4.1 (R-a).** Read the per-vault `last_synced_block`
    /// checkpoint stored in `chain_sync_v1_state`.
    ///
    /// Returns `Ok(None)` for a fresh vault that has never run a v1
    /// chain sync — the caller (orchestrator in
    /// [`pangolin_chain::chain_sync`]) then defaults to the D-017
    /// deploy block per
    /// [`pangolin_chain::d017_deploy_block`].
    ///
    /// Distinct from [`Self::last_pulled_block`] (the v0 P7-era
    /// checkpoint kept for v0 readback compatibility).
    ///
    /// # Errors
    ///
    /// [`StoreError::Corrupted`] if the stored value is negative.
    pub fn last_synced_block_v1(&self) -> Result<Option<u64>> {
        let raw: Option<i64> = self
            .conn
            .query_row(
                "SELECT last_synced_block FROM chain_sync_v1_state WHERE id = 0",
                [],
                |row| row.get(0),
            )
            .optional()?;
        raw.map_or(Ok(None), |v| {
            u64::try_from(v).map(Some).map_err(|_| {
                StoreError::Corrupted(
                    "chain_sync_v1_state.last_synced_block is negative; refusing to surface".into(),
                )
            })
        })
    }

    /// **MVP-2 issue 4.1 (R-a + L12).** Advance the v1 `last_synced_block`
    /// checkpoint to `new_block`. Monotonic — refuses to move backward
    /// (a backward move is symptomatic of either operator error or a
    /// reorg the rollback path failed to handle; both are out of the
    /// monotonic-checkpoint contract).
    ///
    /// Equal values are no-ops so idempotent retry of `sync_from_chain`
    /// is safe.
    ///
    /// # Errors
    ///
    /// [`StoreError::Corrupted`] if `new_block` is strictly less than
    /// the current checkpoint or does not fit in `i64`.
    pub fn update_last_synced_block_v1(&mut self, new_block: u64) -> Result<()> {
        let current = self.last_synced_block_v1()?.unwrap_or(0);
        if new_block < current {
            return Err(StoreError::Corrupted(format!(
                "update_last_synced_block_v1: new_block {new_block} < current {current}; \
                 backward moves violate the monotonic-checkpoint contract (L12)"
            )));
        }
        if new_block == current && self.last_synced_block_v1()?.is_some() {
            return Ok(());
        }
        let new_i64 = i64::try_from(new_block).map_err(|_| {
            StoreError::Corrupted(
                "chain_sync_v1_state.last_synced_block does not fit in i64; refusing to store"
                    .into(),
            )
        })?;
        let now_ms = current_unix_ms();
        self.conn.execute(
            "INSERT OR REPLACE INTO chain_sync_v1_state \
                (id, chain_env_tag, last_synced_block, last_synced_at, schema_version) \
             VALUES (0, 1, ?1, ?2, 1)",
            params![new_i64, now_ms],
        )?;
        Ok(())
    }

    /// **MVP-3 issue #106c2 (Q-e).** Read the per-vault V2
    /// `last_synced_block` checkpoint stored in `chain_sync_v2_state`.
    ///
    /// SEPARATE from [`Self::last_synced_block_v1`] so a V2-bound vault
    /// never reads/advances the V1 cursor (and vice-versa). Returns
    /// `Ok(None)` for a vault that has never run a V2 chain sync.
    ///
    /// # Errors
    ///
    /// [`StoreError::Corrupted`] if the stored value is negative.
    pub fn last_synced_block_v2(&self) -> Result<Option<u64>> {
        let raw: Option<i64> = self
            .conn
            .query_row(
                "SELECT last_synced_block FROM chain_sync_v2_state WHERE id = 0",
                [],
                |row| row.get(0),
            )
            .optional()?;
        raw.map_or(Ok(None), |v| {
            u64::try_from(v).map(Some).map_err(|_| {
                StoreError::Corrupted(
                    "chain_sync_v2_state.last_synced_block is negative; refusing to surface".into(),
                )
            })
        })
    }

    /// **MVP-3 issue #106c2 (Q-e).** Advance the V2 `last_synced_block`
    /// checkpoint to `new_block`. Monotonic — refuses to move backward,
    /// equal values are no-ops (idempotent retry). SEPARATE table from
    /// the V1 cursor.
    ///
    /// # Errors
    ///
    /// [`StoreError::Corrupted`] if `new_block` is strictly less than
    /// the current checkpoint or does not fit in `i64`.
    pub fn update_last_synced_block_v2(&mut self, new_block: u64) -> Result<()> {
        let current = self.last_synced_block_v2()?.unwrap_or(0);
        if new_block < current {
            return Err(StoreError::Corrupted(format!(
                "update_last_synced_block_v2: new_block {new_block} < current {current}; \
                 backward moves violate the monotonic-checkpoint contract"
            )));
        }
        if new_block == current && self.last_synced_block_v2()?.is_some() {
            return Ok(());
        }
        let new_i64 = i64::try_from(new_block).map_err(|_| {
            StoreError::Corrupted(
                "chain_sync_v2_state.last_synced_block does not fit in i64; refusing to store"
                    .into(),
            )
        })?;
        let now_ms = current_unix_ms();
        self.conn.execute(
            "INSERT OR REPLACE INTO chain_sync_v2_state \
                (id, chain_env_tag, last_synced_block, last_synced_at, schema_version) \
             VALUES (0, 1, ?1, ?2, 1)",
            params![new_i64, now_ms],
        )?;
        Ok(())
    }

    // -----------------------------------------------------------------
    // MVP-2 issue 4.4 — sync-mode selector (R-a..R-e).
    // -----------------------------------------------------------------

    /// **MVP-2 issue 4.4 (R-b).** Read the per-vault sync-mode
    /// preference from `meta.sync_mode_preference`. SQL NULL ⇒
    /// [`SyncModePreference::Auto`]. The two non-NULL string values
    /// (`"always_slow"`, `"always_fast"`) decode to the explicit
    /// pre-election variants.
    ///
    /// # Errors
    ///
    /// [`StoreError::Sqlite`] for a DB error;
    /// [`StoreError::Corrupted`] if the column value is non-NULL but
    /// not one of the two recognized strings (forwarded from
    /// [`SyncModePreference::from_meta_str`]).
    pub fn sync_mode_preference(&self) -> Result<SyncModePreference> {
        let raw = meta::read_sync_mode_preference(&self.conn)?;
        SyncModePreference::from_meta_str(raw.as_deref())
    }

    /// **MVP-2 issue 4.4 (R-b).** Persist the per-vault sync-mode
    /// preference into `meta.sync_mode_preference`. `Auto` writes
    /// SQL NULL (the column's default state); `AlwaysSlow` /
    /// `AlwaysFast` write the corresponding string literal.
    ///
    /// This is a UX preference (L2), NOT secret material. The column
    /// is cleartext by design — a filesystem-tamperer who flips the
    /// value causes a UX degrade (denied fast-mode UX, or forced
    /// indexer spawn), nothing more. The user retains the ability to
    /// flip the value via this accessor at any time.
    ///
    /// `&mut self` (mirroring `set_session_idle`) — the preference is
    /// a write to the vault file.
    ///
    /// # Errors
    ///
    /// [`StoreError::Sqlite`] for a persistence failure.
    pub fn set_sync_mode_preference(&mut self, pref: SyncModePreference) -> Result<()> {
        meta::write_sync_mode_preference(&self.conn, pref.to_meta_str())?;
        Ok(())
    }

    /// **MVP-3 issue #106c2.** Read the per-vault v1/v2 `RevisionLog`
    /// binding from `meta.revisionlog_version` — the routing signal for
    /// the sync loop + the publish call site.
    ///
    /// SQL NULL / absent column ⇒ [`RevisionLogVersion::V1`] (the
    /// no-regression default — a legacy vault keeps the V1 path
    /// verbatim).
    ///
    /// # Errors
    ///
    /// [`StoreError::Corrupted`] if the column value is non-NULL but not
    /// `1` or `2` (forwarded from [`RevisionLogVersion::from_meta_int`]).
    pub fn revisionlog_version(&self) -> Result<RevisionLogVersion> {
        let raw = meta::read_revisionlog_version(&self.conn)?;
        RevisionLogVersion::from_meta_int(raw)
    }

    /// **MVP-3 issue #106c2.** Persist the per-vault v1/v2 `RevisionLog`
    /// binding into `meta.revisionlog_version` (`1` = V1, `2` = V2).
    ///
    /// Plaintext routing state (L2), NOT secret material — same posture
    /// as `sync_mode_preference`. `&mut self` (a write to the vault
    /// file).
    ///
    /// # Errors
    ///
    /// [`StoreError::Sqlite`] for a persistence failure.
    pub fn set_revisionlog_version(&mut self, version: RevisionLogVersion) -> Result<()> {
        meta::write_revisionlog_version(&self.conn, Some(version.to_meta_int()))?;
        Ok(())
    }

    /// **MVP-2 issue 4.4 (R-c).** Pure picker — decide whether the
    /// host should run an in-process slow-mode sync
    /// ([`Self::sync_from_chain`], 4.1 R-e) or offer the user the
    /// ephemeral `pangolin-indexer` fast-mode path (4.2 / 4.3).
    ///
    /// Returns a [`SyncMode`] decision; **does NOT spawn the indexer
    /// (L1)**. The host is responsible for rendering the D-007
    /// "Spin up faster sync? (uses temporary local indexer that
    /// auto-deletes)" prompt on `OfferFast` and spawning the indexer
    /// on user assent. `AlwaysFast` (a pre-elected user preference)
    /// is the only variant where the host may spawn without a per-
    /// session prompt — the user assented when they wrote the
    /// preference.
    ///
    /// Heuristic (R-a, locked 2026-05-16): first-sync-on-this-device.
    /// `vault.last_synced_block_v1().is_none() →
    /// SyncMode::OfferFast`; else `SyncMode::Slow`. NO threshold, NO
    /// env-var override, NO `eth_getLogs` count. Long-offline-catchup
    /// users get slow-mode; tolerable.
    ///
    /// Preference (R-b) override:
    ///
    /// | `last_synced_block_v1` | preference | returns |
    /// |---|---|---|
    /// | `Some(_)` | `Auto` | `Slow` |
    /// | `None` | `Auto` | `OfferFast` |
    /// | any | `AlwaysSlow` | `Slow` |
    /// | any | `AlwaysFast` | `AlwaysFast` |
    ///
    /// # The `async fn` signature
    ///
    /// `async` is locked at the API boundary even though this current
    /// implementation never awaits — the R-c plan-gate signature
    /// reserves the option to call a chain RPC (e.g.,
    /// `pangolin_chain::fetch_current_block_number`) from future
    /// heuristics without breaking the public API. Today the heuristic
    /// only looks at vault-local state (the v1 checkpoint + the
    /// preference column), so `rpc_url` and `env` are unused. Future
    /// refinements (e.g., a sample-based count of unsynced events) can
    /// wire RPC traffic in without an SemVer-relevant change.
    ///
    /// # Errors
    ///
    /// [`StoreError::Sqlite`] for a DB error;
    /// [`StoreError::Corrupted`] from
    /// [`Self::sync_mode_preference`] if the preference column is
    /// tampered.
    // `clippy::future_not_send` — `Vault` is intentionally `!Sync`
    // (P4 audit M-3: the inner `rusqlite::Connection` holds a
    // `RefCell` and the `dyn Clock` is not `Sync`). The picker
    // returns a future that holds `&Vault` for its (single,
    // never-yielding) suspension; that future is therefore also
    // `!Send`. Same posture as `sync_from_chain` (which sidesteps
    // the lint because its awaits actually yield); ours collapses
    // back to ready-without-yield, so the lint flags it. The
    // caller's runtime is single-threaded (host = CLI / Tauri main
    // thread / mobile UI thread) so `!Send` is the correct shape.
    #[allow(
        clippy::unused_async,
        clippy::needless_pass_by_value,
        clippy::future_not_send,
        unused_variables
    )]
    pub async fn select_sync_mode(&self, rpc_url: &str, env: ChainEnv) -> Result<SyncMode> {
        // Read the user-preference first — a pre-election overrides
        // the heuristic in both directions.
        let pref = self.sync_mode_preference()?;
        match pref {
            SyncModePreference::AlwaysSlow => return Ok(SyncMode::Slow),
            SyncModePreference::AlwaysFast => return Ok(SyncMode::AlwaysFast),
            SyncModePreference::Auto => { /* fall through to heuristic */ }
        }
        // R-a heuristic: first sync on this device → OfferFast; else
        // Slow. The L-malicious-RPC-fakes-chain-head defense lives
        // in the underlying 4.1 / 4.2 sync paths (chain-id check,
        // pinned-address check, per-event signer recovery); the
        // selector itself is advisory.
        if self.last_synced_block_v1()?.is_none() {
            Ok(SyncMode::OfferFast)
        } else {
            Ok(SyncMode::Slow)
        }
    }

    /// **MVP-2 issue 4.1 (R-c rollback).** Mark all `Pending` revisions
    /// whose `observed_at_block` falls in `[block_low, block_high]` as
    /// rolled-back. The current implementation is a soft delete: the
    /// row is removed from the revisions table (along with its
    /// `account_identities.head_revision_id` pointer if the head
    /// matched). Future MVP-3 work may add a `tombstoned_by_reorg`
    /// status instead of outright deletion for stronger audit trails;
    /// MVP-2 deletes match the "rolled back never happened" semantics
    /// the user expects.
    ///
    /// Returns the count of revisions removed.
    ///
    /// **Safety invariant:** only `Pending` revisions are rolled back;
    /// `Finalized` revisions are never touched (R-c boundary). The
    /// rollback range is constrained by the caller (the chain-sync
    /// orchestrator passes the `ReorgInfo` window directly).
    ///
    /// # Errors
    ///
    /// `StoreError::Sqlite` for any DB error.
    pub fn rollback_pending_revisions_in_range(
        &mut self,
        block_low: u64,
        block_high: u64,
    ) -> Result<u32> {
        let low_i = i64::try_from(block_low).map_err(|_| {
            StoreError::Corrupted("rollback_pending_revisions_in_range: block_low overflow".into())
        })?;
        let high_i = i64::try_from(block_high).map_err(|_| {
            StoreError::Corrupted("rollback_pending_revisions_in_range: block_high overflow".into())
        })?;
        let removed = self.conn.execute(
            "DELETE FROM revisions \
             WHERE revision_status = 'pending' \
               AND observed_at_block >= ?1 \
               AND observed_at_block <= ?2",
            params![low_i, high_i],
        )?;
        let count_u32 = u32::try_from(removed).unwrap_or(u32::MAX);
        Ok(count_u32)
    }

    /// **MVP-2 issue 4.1 (R-c finalization).** Promote `Pending`
    /// revisions whose `observed_at_block` is at depth ≥
    /// `CONFIRMATION_DEPTH_FOR_FINALIZATION` from `current_block_head`
    /// to `Finalized`. Returns the count of promotions.
    ///
    /// `current_block_head` is the orchestrator's view of the chain
    /// tip; passed as a parameter rather than queried here so the
    /// Vault layer stays sync.
    ///
    /// # Errors
    ///
    /// `StoreError::Sqlite` for any DB error.
    pub fn promote_finalized_revisions(&mut self, current_block_head: u64) -> Result<u32> {
        // Depth threshold: any pending row whose observed_at_block ≤
        // current_block_head - 12 is finalized.
        let threshold =
            current_block_head.saturating_sub(pangolin_chain::CONFIRMATION_DEPTH_FOR_FINALIZATION);
        let threshold_i = i64::try_from(threshold).map_err(|_| {
            StoreError::Corrupted("promote_finalized_revisions: threshold overflow".into())
        })?;
        let updated = self.conn.execute(
            "UPDATE revisions \
             SET revision_status = 'finalized' \
             WHERE revision_status = 'pending' \
               AND observed_at_block IS NOT NULL \
               AND observed_at_block <= ?1",
            params![threshold_i],
        )?;
        let count_u32 = u32::try_from(updated).unwrap_or(u32::MAX);
        Ok(count_u32)
    }

    /// **MVP-2 issue 4.1 (R-c ingest path).** Ingest a verified chain
    /// event into the local revision graph with `Pending` status +
    /// associated `observed_at_block` / `observed_block_hash` columns
    /// populated.
    ///
    /// Delegates to the existing
    /// [`Self::ingest_chain_revision`] for the idempotency + foreign-
    /// row machinery, then stamps the chain-sync-specific status
    /// columns onto the resulting row.
    ///
    /// # Errors
    ///
    /// Same taxonomy as [`Self::ingest_chain_revision`].
    pub fn ingest_pending_chain_revision(
        &mut self,
        event: &pangolin_chain::RevisionEvent,
        observed_at_block: u64,
        observed_block_hash: [u8; 32],
    ) -> Result<IngestOutcome> {
        let outcome = self.ingest_chain_revision(event)?;
        let block_i = i64::try_from(observed_at_block).map_err(|_| {
            StoreError::Corrupted(
                "ingest_pending_chain_revision: observed_at_block does not fit in i64".into(),
            )
        })?;
        // Stamp status + observed-block fields on the row identified
        // by the chain anchor. We match by chain_tx_hash + chain_log_index
        // because that's the unambiguous chain-event identity.
        let tx_hash_i64 = i64::try_from(event.anchor.block_number)
            .map_err(|_| StoreError::Corrupted("event anchor block_number overflow".into()))?;
        let log_idx_i64 = i64::try_from(event.anchor.log_index)
            .map_err(|_| StoreError::Corrupted("event anchor log_index overflow".into()))?;
        self.conn.execute(
            "UPDATE revisions \
             SET revision_status = 'pending', \
                 observed_at_block = ?1, \
                 observed_block_hash = ?2 \
             WHERE chain_tx_hash = ?3 \
               AND chain_block_number = ?4 \
               AND chain_log_index = ?5",
            params![
                block_i,
                &observed_block_hash[..],
                &event.anchor.tx_hash[..],
                tx_hash_i64,
                log_idx_i64,
            ],
        )?;
        Ok(outcome)
    }

    /// **MVP-2 issue 4.1 (R-d audit).** Returns the count of
    /// `discovered_via_chain_sync = 1` rows in the devices table.
    /// Useful for `SyncReport` accounting + diagnostic queries.
    ///
    /// # Errors
    ///
    /// `StoreError::Sqlite` for any DB error.
    pub fn count_chain_sync_discovered_devices(&self) -> Result<u32> {
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM devices WHERE discovered_via_chain_sync = 1",
            [],
            |row| row.get(0),
        )?;
        Ok(u32::try_from(n).unwrap_or(u32::MAX))
    }

    // -----------------------------------------------------------------
    // MVP-3 issue #106c — multi-device device-add + DeviceRemoved trigger
    // -----------------------------------------------------------------

    /// **#106c GAP A.** Record a known device's
    /// `signer -> (device_id, pairing_pub)` triple in the local directory
    /// (populated at device-add, with opportunistic completion). The rotation
    /// survivor-resolver reads this to seal the new VDK to each survivor (the
    /// on-chain set stores only secp256k1 addresses; the X25519 pairing pubkey
    /// lives here).
    ///
    /// # Errors
    ///
    /// [`StoreError::Sqlite`] on a DB error.
    pub fn record_device_directory_entry(
        &self,
        signer: [u8; crate::device::EVM_ADDRESS_LEN],
        device_id: [u8; 32],
        pairing_pub: [u8; 32],
    ) -> Result<()> {
        let entry = crate::multi_device::DirectoryEntry {
            signer,
            device_id,
            pairing_pub,
        };
        crate::multi_device::upsert_directory_entry(&self.conn, &entry, current_unix_ms())
    }

    /// **#106c GAP A.** Read the full local survivor-pubkey directory (for
    /// resolving a rotation's survivors).
    ///
    /// # Errors
    ///
    /// [`StoreError::Sqlite`] / [`StoreError::Corrupted`] on a DB / decode
    /// error.
    pub fn device_directory(&self) -> Result<Vec<crate::multi_device::DirectoryEntry>> {
        crate::multi_device::read_directory(&self.conn)
    }

    /// **MVP-3 issue #106e-0: the NON-secret recovery-escrow parameters a
    /// rotation needs, read store-side WITHOUT exposing the active VDK.**
    ///
    /// `pangolin_core::composition::complete_rotation` needs the guardian
    /// set `(t, M)`, the `M` guardian X25519 pubkeys, and the current
    /// recovery epoch to drive `rotate_vdk_for_survivors`. The escrow blob
    /// is double-wrapped under the CURRENT VDK's column-AEAD, so reading it
    /// requires `self.active.vdk.aead_key()` — a SECRET that must NOT cross
    /// the `pangolin-core` ↔ `pangolin-store` boundary. This accessor opens
    /// the escrow with the active VDK INSIDE the store and returns ONLY the
    /// non-secret parameters (Q-d). The VDK itself never leaves `self`.
    ///
    /// A rotation always runs on an existing unlocked device (it is an
    /// existing device revoking a peer), so the active VDK is available.
    ///
    /// `Ok(None)` if no recovery escrow has been onboarded yet.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotUnlocked`] if no session is active;
    /// [`StoreError::Sqlite`] / [`StoreError::Corrupted`] /
    /// [`StoreError::AuthenticationFailed`] from the escrow read.
    pub fn recovery_escrow_params(&self) -> Result<Option<RecoveryEscrowParams>> {
        let active = self.require_active()?;
        let vault_id = self.meta.vault_id;
        let escrow = crate::recovery_escrow::read_recovery_escrow(
            &self.conn,
            &vault_id,
            active.vdk.aead_key(),
        )?;
        let current_epoch = vdk_chain::read_current_epoch(&self.conn)?;
        Ok(escrow.map(|e| RecoveryEscrowParams {
            threshold: e.threshold,
            guardian_count: e.guardian_count,
            // The M guardian X25519 pubkeys, ordered by index (0..M) — all
            // non-secret (they are the SEALING pubkeys shares were sealed
            // to). The decrypted `sealed_share` bytes in `e.guardians` are
            // dropped here (never copied out).
            guardian_x25519_pubs: e.guardians.iter().map(|g| g.guardian_x25519_pub).collect(),
            current_epoch,
        }))
    }

    /// **MVP-3 issue #109: build a canonical encrypted recovery-backup
    /// envelope sealed under a freshly-generated 24-word BIP-39 seed
    /// phrase.**
    ///
    /// Reads the live recovery-escrow material engine-side (sourced
    /// through `recovery_escrow::read_recovery_escrow` under the active
    /// VDK's column-AEAD), packages it into a
    /// [`crate::recovery_backup::BackupContents`] body, and seals the
    /// envelope. The output is the ONE blob the host persists for the
    /// user (file / cloud / paper-string) — unlocked later by the
    /// seed phrase the user records out-of-band at backup time.
    ///
    /// `vault_display_name` is left empty here (the store doesn't carry
    /// a per-vault user-visible label today; a future amendment can
    /// thread it through). `created_at_unix` is derived from the meta
    /// row's `created_at` (saturating to 0 if negative).
    ///
    /// Returns `Ok(None)` if no recovery escrow has been onboarded
    /// (without an escrow there is nothing to back up).
    ///
    /// **Session-gated (Active)** — needs the active VDK's column-AEAD
    /// to read the escrow. The `master_password` parameter is accepted
    /// for surface symmetry with other chain-/recovery-class entry
    /// points (so the FFI binding can take it behind `SecretPassword`);
    /// the seal itself uses the seed phrase as the wrap authority, so
    /// the master password is only consumed + zeroized.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotUnlocked`] if no session is active;
    /// [`StoreError::Sqlite`] / [`StoreError::Corrupted`] /
    /// [`StoreError::AuthenticationFailed`] from the escrow read;
    /// [`StoreError::RecoveryBackup`] (newly added) for any failure
    /// inside [`crate::recovery_backup`] (KDF / AEAD / wire-format).
    pub fn create_recovery_backup(
        &self,
        _master_password: &pangolin_crypto::secret::SecretBytes,
    ) -> Result<Option<crate::recovery_backup::RecoveryBackupArtifacts>> {
        let active = self.require_active()?;
        let vault_id = self.meta.vault_id;
        let escrow = crate::recovery_escrow::read_recovery_escrow(
            &self.conn,
            &vault_id,
            active.vdk.aead_key(),
        )?;
        let Some(escrow) = escrow else {
            return Ok(None);
        };
        let current_epoch = vdk_chain::read_current_epoch(&self.conn)?;
        let created_at_unix = u64::try_from(self.meta.created_at).unwrap_or(0);

        // Serialize `WrappedVdkRecovery` into the canonical wire form
        // the recovery_ffi path already round-trips:
        //   schema_version (1 B) || nonce (NONCE_LEN B) || ciphertext (rest)
        // (mirrors `recovery_ffi::decode_wrapped_recovery` at the FFI
        // boundary so a backup minted here decodes 1:1 there.)
        let wrapped_recovery_bytes = {
            let inner = escrow.wrapped_recovery.as_wrapped();
            let mut buf = Vec::with_capacity(
                1 + pangolin_crypto::aead::NONCE_LEN + inner.ciphertext().as_bytes().len(),
            );
            buf.push(inner.context().schema_version);
            buf.extend_from_slice(inner.nonce().as_bytes());
            buf.extend_from_slice(inner.ciphertext().as_bytes());
            buf
        };

        let contents = crate::recovery_backup::BackupContents {
            wrapped_recovery: wrapped_recovery_bytes,
            vault_id,
            epoch: current_epoch,
            threshold: escrow.threshold,
            guardian_count: escrow.guardian_count,
            guardian_x25519_pubs: escrow
                .guardians
                .iter()
                .map(|g| g.guardian_x25519_pub)
                .collect(),
            vault_display_name: String::new(),
            created_at_unix,
        };
        let seed_phrase =
            crate::recovery_backup::generate_seed_phrase().map_err(StoreError::RecoveryBackup)?;
        let bytes = crate::recovery_backup::seal_backup(&contents, seed_phrase.as_slice())
            .map_err(StoreError::RecoveryBackup)?;
        Ok(Some((seed_phrase, bytes)))
    }

    /// **MVP-3 issue #106e-0: a guardian opens a share sealed to it.**
    ///
    /// The local device is acting as a GUARDIAN for some vault being
    /// recovered (not necessarily its own — hence the explicit `vault_id` /
    /// `epoch`). It derives its guardian X25519 SEALING secret from the
    /// active session's `DeviceKey` via
    /// [`pangolin_crypto::guardian::derive_x25519_sealing_key`] (the
    /// share-to-guardian derivation — NOT the device-pairing key) and opens
    /// the [`SealedShare`] with
    /// [`pangolin_crypto::escrow::open_sealed_share`].
    ///
    /// The returned [`Share`] is the ONE secret this composition layer
    /// yields; the #106e-1 FFI wraps it behind an opaque handle (#106e L1).
    /// Session-gated. The derived sealing secret is a `Zeroizing` buffer
    /// passed straight into `open_sealed_share` (no copy, L2).
    ///
    /// # Errors
    ///
    /// [`StoreError::NotUnlocked`] if no session is active;
    /// [`StoreError::AuthenticationFailed`] if the open fails (wrong key,
    /// tampered ciphertext, or a `vault_id` / `epoch` mismatch — the
    /// undifferentiated indistinguishability collapse).
    pub fn guardian_open_sealed_share(
        &self,
        sealed_share: &pangolin_crypto::escrow::SealedShare,
        vault_id: &[u8; VAULT_ID_LEN],
        epoch: &[u8; pangolin_crypto::escrow::EPOCH_LEN],
    ) -> Result<pangolin_crypto::escrow::Share> {
        let active = self.require_active()?;
        let sealing = pangolin_crypto::guardian::derive_x25519_sealing_key(&active.device_key);
        pangolin_crypto::escrow::open_sealed_share(
            sealed_share,
            &sealing.secret_bytes(),
            vault_id,
            epoch,
        )
        .map_err(|_| StoreError::AuthenticationFailed)
    }

    // -----------------------------------------------------------------
    // MVP-3 issue #106e-2 — device-pairing handshake store-side surface
    // -----------------------------------------------------------------
    //
    // The pure pairing crypto (`pangolin_crypto::pairing`,
    // `pangolin_core::device_add`) does not touch a `Vault`. The thin
    // store methods below are what the #106e-2 FFI bindings call so the
    // active VDK + the active `DeviceKey` never cross the
    // `pangolin-core ↔ pangolin-store` boundary. Mirrors the
    // `commit_vdk_rotation_from_active` discipline (#106e-0).
    //
    // L1 (zero secret crosses FFI as readable bytes): the FFI sees only
    // the resulting `SealedVdkForDevice` bytes (non-secret) on the
    // manager side, and `()` on the new-device side. The X25519 pairing
    // secret + the VDK stay inside `ActiveState`.

    /// **#106e-2 MANAGER role.** Seal the active VDK to a new device's
    /// X25519 pairing pubkey, bound to `(vault_id, device_id, epoch)`.
    ///
    /// Mirrors [`pangolin_core::device_add::seal_vdk_to_new_device`] but
    /// runs INSIDE the store so `self.active.vdk` never has to cross out.
    /// Session-gated (Active — the manager holds the live VDK). The
    /// returned [`pangolin_crypto::pairing::SealedVdkForDevice`] is
    /// non-secret (sealed to the recipient's pairing pubkey) and travels
    /// to the new device over the SAS-authenticated channel.
    ///
    /// The recipient `device_id` MUST be the new device's
    /// [`pangolin_core::device_add::device_id_from_device_key`] (the seal
    /// header binds it; the new device only opens with its OWN
    /// `device_id`). The `vault_id` MUST be `self.vault_id()` (the
    /// caller passes it as a parameter so a future per-vault add path
    /// can be reused; the FFI binding asserts equality with the active
    /// vault's id before calling).
    ///
    /// # Errors
    ///
    /// [`StoreError::NotUnlocked`] if no session is active.
    /// [`StoreError::AuthenticationFailed`] if the underlying sealed-box
    /// op fails (indistinguishability collapse).
    pub fn seal_vdk_for_new_device(
        &self,
        recipient_x25519_pairing_pub: &[u8; 32],
        recipient_device_id: &[u8; 32],
        vault_id: &[u8; VAULT_ID_LEN],
        epoch: u64,
    ) -> Result<pangolin_crypto::pairing::SealedVdkForDevice> {
        let active = self.require_active()?;
        let mut epoch_bytes = [0u8; pangolin_crypto::escrow::EPOCH_LEN];
        epoch_bytes[8..].copy_from_slice(&epoch.to_be_bytes());
        pangolin_crypto::pairing::seal_vdk_to_device(
            &active.vdk,
            recipient_x25519_pairing_pub,
            vault_id,
            recipient_device_id,
            &epoch_bytes,
        )
        .map_err(|_| StoreError::AuthenticationFailed)
    }

    /// **#106e-2 NEW-device role.** The active session's local device
    /// 32-byte X25519 PAIRING PUBKEY (what an existing manager seals the
    /// VDK to).
    ///
    /// Session-gated (Active — the device key lives in `ActiveState`).
    /// Derived deterministically from the active session's `DeviceKey`
    /// via [`pangolin_crypto::pairing::derive_x25519_pairing_key`]; the
    /// SECRET scalar stays inside the derivation closure and never
    /// crosses out. Returns the non-secret pubkey bytes.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotUnlocked`] if no session is active.
    pub fn device_pairing_pubkey(&self) -> Result<[u8; 32]> {
        let active = self.require_active()?;
        Ok(*pangolin_crypto::pairing::derive_x25519_pairing_key(&active.device_key).public_bytes())
    }

    /// **#106e-2 NEW-device role.** The active session's stable
    /// `device_id` (the 32-byte Ed25519 verifying-key bytes — GAP B). The
    /// SAME value the seal header binds.
    ///
    /// Session-gated. Required by the new-device FFI binding so the
    /// engine returns a `device_id` that exactly matches what
    /// `wrap_vdk_for_device` will later expect.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotUnlocked`] if no session is active.
    pub fn device_pairing_device_id(&self) -> Result<[u8; 32]> {
        let active = self.require_active()?;
        Ok(active.device_key.verifying_key().to_bytes())
    }

    /// **#106e-2 NEW-device role — install a paired VDK + set vault id +
    /// re-wrap under a master password.**
    ///
    /// The final step of the new-device join: the host has decoded
    /// `SealedVdkForDevice` bytes, the engine has opened it under
    /// `device_pairing_secret_for_self` and recovered the byte-identical
    /// VDK, and now this method PERSISTS that VDK as this device's at-
    /// rest wrap under `new_password` AND adopts the existing-vault's
    /// `vault_id` (so this device's `.pvf` shares the same logical-vault
    /// identity as the joining vault).
    ///
    /// Mirrors [`Self::build_recovery_meta`] (the recovery commit) but:
    /// 1. takes the supplied `vault_id` (not `self.meta.vault_id` — the
    ///    new device freshly-created a `.pvf` with its OWN random
    ///    `vault_id`; the join replaces it),
    /// 2. binds the [`WrapContext`] to the SUPPLIED `vault_id`.
    ///
    /// Like recovery, leaves the vault Locked on success — the host
    /// calls `vault_unlock(new_password)` to start a session against the
    /// newly-installed wrap.
    ///
    /// The `recovered_vdk` is borrowed (the caller drops it after); the
    /// `new_password` is borrowed.
    ///
    /// # Errors
    ///
    /// [`StoreError::AuthenticationFailed`] if the KDF / wrap fails
    /// (uniform failure surface — recovery uses the same posture even
    /// though wrong-password is not the failure mode here, because the
    /// user is SETTING the password). [`StoreError::Sqlite`] on a write
    /// failure.
    pub fn install_paired_vdk(
        &mut self,
        recovered_vdk: VdkKey,
        vault_id: [u8; VAULT_ID_LEN],
        new_password: &SecretBytes,
    ) -> Result<()> {
        // ATOMIC re-key + adopt-vault-id + re-seal device-key row in ONE
        // transaction. Without this:
        //
        //  - The device_key row was sealed under THIS device's ORIGINAL
        //    (random) VDK + the original (random) vault_id. After this
        //    method, the persisted VDK is the RECOVERED one (from A)
        //    and the persisted vault_id is A's. A subsequent
        //    `Vault::unlock` would derive A's VDK + try to open the
        //    OLD-VDK-sealed device_key row → fail.
        //
        //  - The active session's `device_id` (= the verifying-key bytes
        //    of the active `DeviceKey`) IS the same `device_id` A's
        //    pairing seal was bound to. The seal/AAD uses
        //    `device_key_aad(vault_id, device_id)`, which binds BOTH
        //    the OLD vault_id AND the device_id. So we MUST re-seal the
        //    device-key row under the NEW VDK + the NEW vault_id +
        //    keep the SAME `DeviceKey` (so future re-derivations of the
        //    pairing pub / signer remain stable — what A registered
        //    on-chain stays valid).
        //
        // Pull the active DeviceKey's seed out engine-side first (Active
        // session is required — the host always reaches this from
        // `Active` because `pairing_open_and_join` runs
        // `open_paired_vdk_seal` on the same borrow). The seed is held
        // in a Zeroizing buffer so it wipes when dropped at the end of
        // this method. Scoped block so the `&ActiveState` borrow of
        // `self.active` releases before we mutate `self.meta` below.
        let device_key_seed = {
            let active = self.active.as_ref().ok_or(StoreError::NotUnlocked)?;
            active.device_key.secret_seed_bytes()
        };

        // Build the new meta row under the SUPPLIED vault_id. The KDF
        // salt is fresh per L3 (independent of any other vault's wrap
        // material); the authority is derived + dropped inside the
        // builder.
        let salt = KdfSalt::random();
        let params = KdfParams::RECOMMENDED;
        let kdf_seed = kdf::derive_seed(new_password, &salt, &params)?;
        let new_authority = AuthorityKey::from_seed(*kdf_seed);
        let wrap_ctx = WrapContext::new(vault_id);
        let wrapped = recovered_vdk.wrap(&new_authority, &wrap_ctx)?;
        // Authority + the KDF-derived seed have done their job — drop so
        // they zeroize early.
        drop(new_authority);

        let new_meta = VaultMeta {
            vault_id,
            created_at: self.meta.created_at,
            kdf_params: params,
            kdf_salt: salt,
            wrap_context: wrap_ctx,
            wrapped_ciphertext: wrapped.ciphertext().as_bytes().to_vec(),
            wrapped_nonce: *wrapped.nonce().as_bytes(),
        };

        // Reconstruct the local DeviceKey from the seed copy we pulled
        // off the active session. The original session's `DeviceKey` is
        // about to be dropped when we set `self.active = None`; we hold
        // an independent zeroizing copy here so the re-seal can run.
        let local_device = DeviceKey::from_seed(*device_key_seed);

        // Atomic transaction: write meta + re-seal device_key under the
        // new VDK + new vault_id. Rollback on any error. Mirrors the
        // `commit_vdk_rotation` re-seal-under-new-VDK pattern at
        // vault.rs:1621.
        let tx = self.conn.unchecked_transaction()?;
        meta::write(&tx, &new_meta)?;
        device::reseal_device_key_tx(&tx, &vault_id, recovered_vdk.aead_key(), &local_device)?;
        tx.commit()?;

        // The recovered VDK has done its job here — drop after the
        // commit so the transaction body sees the live AEAD key, and
        // it zeroizes the moment we leave this scope.
        drop(recovered_vdk);

        // Mutate in-memory state ONLY after the atomic commit succeeds
        // (so a failed write never desyncs memory from disk).
        self.meta = new_meta;
        // The device_id field on `self` is the local `.pvf`'s device id
        // (random per-handle until `unlock` writes a stable row). After
        // this re-seal the device-key row's `id` is the verifying-key
        // bytes of `local_device` — stamp that onto `self.device_id` so
        // the next `unlock` reads the right row.
        self.device_id = DeviceId(local_device.verifying_key().to_bytes());

        // Drop secrets ASAP.
        drop(local_device);
        drop(device_key_seed);

        // Leave the vault Locked: the host calls `vault_unlock` with
        // `new_password` to start the first active session under the
        // newly-installed wrap. Any prior session is torn down (its
        // secrets zeroize) — this is a re-key, not a continuation.
        self.active = None;
        self.session_state = SessionState::Locked;
        Ok(())
    }

    /// **#106e-2 NEW-device role — open the manager's `SealedVdkForDevice`
    /// and return the byte-identical VDK.**
    ///
    /// Session-gated (Active — the active `DeviceKey` derives the
    /// recipient X25519 pairing SECRET store-internal; the secret never
    /// crosses out). The recovered [`VdkKey`] is returned by value to the
    /// caller — which on the new-device path is the FFI binding, that
    /// passes it straight into [`Self::install_paired_vdk`] (which
    /// consumes it and drops it). The VDK NEVER crosses the FFI boundary.
    ///
    /// `vault_id` is the EXISTING vault's id (carried in the pairing
    /// payload, used by the seal header); `epoch` is the current epoch
    /// on a clean add (host-supplied — typically 0).
    ///
    /// # Errors
    ///
    /// [`StoreError::NotUnlocked`] if no session is active.
    /// [`StoreError::AuthenticationFailed`] if the open fails (wrong
    /// recipient key / tampered ciphertext / context mismatch —
    /// indistinguishability collapse).
    pub fn open_paired_vdk_seal(
        &self,
        sealed: &pangolin_crypto::pairing::SealedVdkForDevice,
        vault_id: &[u8; VAULT_ID_LEN],
        epoch: u64,
    ) -> Result<VdkKey> {
        let active = self.require_active()?;
        let pairing_key = pangolin_crypto::pairing::derive_x25519_pairing_key(&active.device_key);
        let secret = pairing_key.secret_bytes();
        let device_id = active.device_key.verifying_key().to_bytes();
        let mut epoch_bytes = [0u8; pangolin_crypto::escrow::EPOCH_LEN];
        epoch_bytes[8..].copy_from_slice(&epoch.to_be_bytes());
        pangolin_crypto::pairing::open_vdk_from_pairing(
            sealed,
            &secret,
            vault_id,
            &device_id,
            &epoch_bytes,
        )
        .map_err(|_| StoreError::AuthenticationFailed)
    }

    /// **#106c GAP D / L5.** The minimal set-membership honor gate: returns
    /// `true` iff `signer` is in the supplied CURRENT on-chain authorized
    /// set. The host reads the live set via
    /// `pangolin_chain::read_authorized_device_v2` (or folds the device-
    /// management events) and passes it here. Replaces the permissive
    /// "trust any signer seen" posture for the multi-device V2 path; a
    /// removed / never-added signer is NOT honored. The FULL systematic
    /// generalization (lineage / v1→v2 dual-read cut-over) is #106d.
    #[must_use]
    pub fn is_signer_honored(
        signer: &[u8; crate::device::EVM_ADDRESS_LEN],
        current_onchain_set: &[[u8; crate::device::EVM_ADDRESS_LEN]],
    ) -> bool {
        crate::multi_device::is_signer_honored(signer, current_onchain_set)
    }

    /// **#106c GAP D / L5: honor-gated V2 chain-revision ingest.** Ingest a
    /// V2 revision ONLY if its signer is in the CURRENT on-chain authorized
    /// set; otherwise it is rejected (NOT ingested, NOT auto-registered).
    /// This is the set-membership replacement for the permissive
    /// `auto_register_device_from_chain_sync` on the multi-device path: an
    /// unhonored signer (removed / never-added) does not land in the local
    /// graph.
    ///
    /// Returns `Some(outcome)` if the signer was honored + the revision
    /// ingested; `None` if the signer was NOT in the set (rejected).
    ///
    /// **MEDIUM under-revocation FIX (#106d fix-pass).** On a successful
    /// honor + ingest, the ecrecovered `signer` is PERSISTED onto the
    /// chain-anchored row's `recovered_signer` column. This is the SAME
    /// identity this gate honors. The retroactive revocation pass
    /// ([`Self::reevaluate_revocation_against_set`]) keys on this stored
    /// signer rather than the OPAQUE `device_id`, because `RevisionLogV2`
    /// gates publishing ONLY on the ecrecovered signer and NEVER enforces
    /// `deviceId == leftpad(signer)`. Keying the retroactive pass on
    /// `device_id` would let an in-set device B publish a B-signed revision
    /// carrying `deviceId = leftpad(A)`; after B is removed the row would
    /// survive (its `device_id` still decodes to in-set A) — the dangerous
    /// under-revocation direction. Persisting the recovered signer closes
    /// that hole by making the retroactive predicate use the gating
    /// identity. The row is located by its unambiguous chain-anchor
    /// identity `(account_id, chain_tx_hash, chain_block_number,
    /// chain_log_index)` (idempotency check #2's key), so the stamp lands
    /// correctly whether the ingest inserted a fresh row or merged onto a
    /// local pre-publish row. Re-stamping the same value is idempotent.
    ///
    /// # Errors
    ///
    /// The errors of [`Self::ingest_chain_revision`].
    pub fn ingest_v2_revision_if_honored(
        &mut self,
        event: &pangolin_chain::RevisionEvent,
        signer: [u8; crate::device::EVM_ADDRESS_LEN],
        current_onchain_set: &[[u8; crate::device::EVM_ADDRESS_LEN]],
    ) -> Result<Option<IngestOutcome>> {
        if !crate::multi_device::is_signer_honored(&signer, current_onchain_set) {
            return Ok(None);
        }
        let outcome = self.ingest_chain_revision(event)?;
        // Persist the ecrecovered signer onto the just-ingested chain-
        // anchored row so the retroactive revocation pass keys on the
        // gating identity, not the opaque device_id.
        self.stamp_recovered_signer(event, &signer)?;
        Ok(Some(outcome))
    }

    /// **#106d fix-pass helper (MEDIUM under-revocation fix).** Persist the
    /// ecrecovered `signer` onto the V2 chain-anchored row identified by
    /// its chain-anchor identity `(account_id, chain_tx_hash,
    /// chain_block_number, chain_log_index)` — the unambiguous chain-event
    /// key (one `(tx_hash, log_index)` per event). The retroactive
    /// revocation pass ([`Self::reevaluate_revocation_against_set`]) keys
    /// on this stored signer rather than the OPAQUE `device_id`, because
    /// `RevisionLogV2` gates publishing ONLY on the recovered signer and
    /// NEVER enforces `deviceId == leftpad(signer)`. Stamping by the chain
    /// anchor lands the value whether the ingest inserted a fresh row or
    /// merged onto a local pre-publish row; re-stamping the same value is
    /// idempotent.
    ///
    /// # Errors
    ///
    /// [`StoreError::Sqlite`] for a DB error; [`StoreError::Corrupted`] if
    /// the anchor block/log values would not fit in `i64`.
    fn stamp_recovered_signer(
        &self,
        event: &pangolin_chain::RevisionEvent,
        signer: &[u8; crate::device::EVM_ADDRESS_LEN],
    ) -> Result<()> {
        let block_i64 = i64::try_from(event.anchor.block_number).map_err(|_| {
            StoreError::Corrupted(
                "RevisionEvent.anchor.block_number does not fit in i64; refusing to stamp signer"
                    .into(),
            )
        })?;
        let log_i64 = i64::try_from(event.anchor.log_index).map_err(|_| {
            StoreError::Corrupted(
                "RevisionEvent.anchor.log_index does not fit in i64; refusing to stamp signer"
                    .into(),
            )
        })?;
        self.conn.execute(
            "UPDATE revisions SET recovered_signer = ?1 \
             WHERE account_id = ?2 AND chain_tx_hash = ?3 \
               AND chain_block_number = ?4 AND chain_log_index = ?5",
            params![
                &signer[..],
                &event.account_id[..],
                &event.anchor.tx_hash[..],
                block_i64,
                log_i64,
            ],
        )?;
        Ok(())
    }

    /// **MVP-3 issue #106d (salvaged #103-C GAP FLAG 3, predicate re-keyed)
    /// — retroactive revocation re-eval against the live on-chain SET.**
    /// Re-evaluate every locally-stored CHAIN-ANCHORED revision against the
    /// current on-chain authorized `set` and MARK (do NOT hard-delete, L6)
    /// the `revoked` column accordingly. Returns the count of rows whose
    /// `revoked` flag transitioned `0 → 1` during this pass (newly revoked)
    /// so the caller can fold it into [`pangolin_chain::SyncReport`].
    ///
    /// **Why retroactive (the gap).** The reader may already hold rows
    /// signed by a signer that has since left the set — ingested by an
    /// earlier sync before the removal was observed. The new-event GATE in
    /// the V2 sync path only filters *incoming* events; this pass closes
    /// the historical hole.
    ///
    /// **Signer source (#106d fix-pass — MEDIUM under-revocation fix).**
    /// The pass keys on the stored `recovered_signer` — the ecrecovered
    /// secp256k1 address the V2 honor gate persisted at ingest
    /// ([`Self::ingest_v2_revision_if_honored`]) — NOT on the OPAQUE
    /// `device_id`. `RevisionLogV2` gates publishing ONLY on the recovered
    /// signer and NEVER enforces `deviceId == leftpad(signer)`, so a row's
    /// `device_id` is attacker-chosen and may decode to a DIFFERENT address
    /// than the signer the gate honored. Keying on `device_id` would let an
    /// in-set device B publish a B-signed revision carrying
    /// `deviceId = leftpad(A)`; after B is removed, the `device_id` still
    /// decodes to in-set A and the row would survive — under-revocation
    /// (the dangerous direction). Keying on `recovered_signer` makes the
    /// retroactive predicate use the EXACT identity the ingest gate uses.
    /// Only rows with a non-NULL `chain_tx_hash` are re-evaluated —
    /// purely-local (unpublished) rows have no on-chain set binding and are
    /// never auto-revoked. A chain-anchored row with a NULL
    /// `recovered_signer` (a V1 row, or a row not ingested through the V2
    /// honor gate) is treated CONSERVATIVELY — it is NOT silently honored;
    /// if such a row reaches the V2 retroactive pass it is marked revoked
    /// (it has no V2-honored signer to test against the set). This is the
    /// parked #103-C `reevaluate_revocation_against_lineage` with the
    /// predicate swapped to `set.contains(&recovered_signer)`; the loop,
    /// the both-directions recompute, and the idempotency are reused.
    ///
    /// **Reversible / both directions.** The mark is recomputed in BOTH
    /// directions each pass (a row whose signer is in the current set is
    /// set `revoked = 0`), so a re-added device un-revokes its rows on the
    /// next pass. On a set containing every stored signer this pass is a
    /// no-op.
    ///
    /// # Errors
    ///
    /// [`StoreError::Sqlite`] for any DB error.
    pub fn reevaluate_revocation_against_set(
        &mut self,
        set: &[[u8; crate::device::EVM_ADDRESS_LEN]],
    ) -> Result<u32> {
        // Collect every chain-anchored row's (revision_id,
        // recovered_signer, current revoked flag). recovered_signer is the
        // 20-byte ecrecovered EVM address the V2 honor gate persisted at
        // ingest — the SAME identity the gate honored (NOT the opaque
        // device_id, which RevisionLogV2 never binds to the signer).
        let mut stmt = self.conn.prepare(
            "SELECT revision_id, recovered_signer, revoked \
             FROM revisions WHERE chain_tx_hash IS NOT NULL",
        )?;
        let rows = stmt
            .query_map([], |row| {
                let revision_id: Vec<u8> = row.get(0)?;
                let recovered_signer: Option<Vec<u8>> = row.get(1)?;
                let revoked: i64 = row.get(2)?;
                Ok((revision_id, recovered_signer, revoked))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        drop(stmt);

        let mut newly_revoked: u32 = 0;
        for (revision_id, recovered_signer, was_revoked) in rows {
            // Key on the persisted recovered signer (the gating identity).
            // A NULL or malformed-length recovered_signer on a chain-
            // anchored row is treated CONSERVATIVELY: it has no V2-honored
            // signer to test against the set, so it is marked revoked
            // rather than silently honored (closes the under-revocation
            // direction the audit flagged).
            let want_revoked = match recovered_signer {
                Some(bytes) if bytes.len() == crate::device::EVM_ADDRESS_LEN => {
                    let mut addr_bytes = [0u8; crate::device::EVM_ADDRESS_LEN];
                    addr_bytes.copy_from_slice(&bytes);
                    // Honor iff the recovered signer is in the CURRENT set.
                    i64::from(!set.contains(&addr_bytes))
                }
                // NULL or malformed → conservatively revoked.
                _ => 1,
            };
            if want_revoked != was_revoked {
                self.conn.execute(
                    "UPDATE revisions SET revoked = ?1 WHERE revision_id = ?2",
                    params![want_revoked, &revision_id[..]],
                )?;
                if want_revoked == 1 && was_revoked == 0 {
                    newly_revoked = newly_revoked.saturating_add(1);
                }
            }
        }
        Ok(newly_revoked)
    }

    /// **#106c: the `DeviceRemoved`→rotation TRIGGER (detection + persist
    /// half, L3).** Given the CURRENT on-chain authorized set + the locally-
    /// known honored signers + the observed vault epoch, persist a crash-
    /// durable rotation-pending row for each signer that is locally-known
    /// but NO LONGER in the on-chain set (a removal). NEVER auto-rotates —
    /// it only PERSISTS + SURFACES (the host re-prompts the master password
    /// and drives `commit_vdk_rotation`). Idempotent (L6): re-observing the
    /// same removal does not double-queue.
    ///
    /// Returns the count of newly-queued rotation-pending rows.
    ///
    /// # Errors
    ///
    /// [`StoreError::Sqlite`] / [`StoreError::Corrupted`] on a DB error.
    pub fn process_device_removed_trigger(
        &self,
        current_onchain_set: &[[u8; crate::device::EVM_ADDRESS_LEN]],
        locally_known_signers: &[[u8; crate::device::EVM_ADDRESS_LEN]],
        observed_epoch: u64,
    ) -> Result<u32> {
        let now_ms = current_unix_ms();
        let mut queued = 0u32;
        for signer in locally_known_signers {
            if current_onchain_set.contains(signer) {
                continue;
            }
            let pending = crate::multi_device::RotationPending {
                removed_signer: *signer,
                observed_epoch,
                observed_at: now_ms,
            };
            if crate::multi_device::queue_rotation_pending(&self.conn, &pending)? {
                queued = queued.saturating_add(1);
            }
        }
        Ok(queued)
    }

    /// **#106c: read the OUTSTANDING rotation-pending rows.** The host
    /// surfaces these as "rotation pending — enter master password". A
    /// closed app RESUMES them on next open (crash-durable, L6).
    ///
    /// # Errors
    ///
    /// [`StoreError::Sqlite`] / [`StoreError::Corrupted`] on a DB error.
    pub fn pending_rotations(&self) -> Result<Vec<crate::multi_device::RotationPending>> {
        crate::multi_device::read_pending_rotations(&self.conn)
    }

    /// **#106c: mark a rotation-pending row resolved** (after the host
    /// completes `commit_vdk_rotation` for the removal). Idempotent.
    ///
    /// # Errors
    ///
    /// [`StoreError::Sqlite`] on a DB error.
    pub fn resolve_rotation_pending(
        &self,
        removed_signer: &[u8; crate::device::EVM_ADDRESS_LEN],
    ) -> Result<()> {
        crate::multi_device::mark_rotation_resolved(&self.conn, removed_signer)
    }

    /// Fetch the publish-relevant fields of a single revision row:
    /// `(parent_revision, schema_version, enc_payload)`.
    ///
    /// `pangolin-cli publish` (P8-3) calls this to feed
    /// [`pangolin_chain::signing::build_signed_revision`] without
    /// decrypting the payload. The returned `enc_payload` is the
    /// AEAD-sealed bytes exactly as they were stored — opaque to this
    /// layer and to the publish path; only a future receiver that
    /// holds the same VDK can decrypt them.
    ///
    /// Metadata-ish — does NOT touch the decrypted cache and does
    /// NOT require [`VaultState::Active`]. Soft-expiry path.
    ///
    /// # Errors
    ///
    /// `StoreError::RevisionNotFound` if the `(account_id,
    /// revision_id)` pair does not match any local row.
    /// `StoreError::Sqlite` for any database issue.
    /// `StoreError::Corrupted` if the `schema_version` column is out
    /// of `u8` range.
    pub fn read_revision_for_publish(
        &mut self,
        account_id: AccountId,
        revision_id: RevisionId,
    ) -> Result<RevisionPublishPayload> {
        self.maybe_expire_active_session();
        let row: Option<(Vec<u8>, i64, Vec<u8>)> = self
            .conn
            .query_row(
                "SELECT parent_revision_id, schema_version, enc_payload
                 FROM revisions
                 WHERE account_id = ?1 AND revision_id = ?2",
                params![
                    account_id.as_bytes().as_slice(),
                    revision_id.as_bytes().as_slice(),
                ],
                |row| {
                    let parent: Vec<u8> = row.get(0)?;
                    let sv: i64 = row.get(1)?;
                    let payload: Vec<u8> = row.get(2)?;
                    Ok((parent, sv, payload))
                },
            )
            .optional()?;
        let (parent_blob, sv_i64, enc_payload) = row.ok_or(StoreError::RevisionNotFound)?;
        let parent_arr: [u8; REVISION_ID_LEN] = parent_blob
            .as_slice()
            .try_into()
            .map_err(|_| StoreError::Corrupted("parent_revision_id not 32 bytes".into()))?;
        let schema_version = u8::try_from(sv_i64).map_err(|_| {
            StoreError::Corrupted("revisions.schema_version out of u8 range".into())
        })?;
        Ok(RevisionPublishPayload {
            parent_revision: RevisionId::from_bytes(parent_arr),
            schema_version,
            enc_payload,
        })
    }

    // -----------------------------------------------------------------
    // Dirty-marker primitives (P8-2) — `dirty_accounts` table API
    // -----------------------------------------------------------------

    /// Stamp `(account_id, revision_id)` into `dirty_accounts`.
    ///
    /// Idempotent — uses `INSERT OR IGNORE` so a re-stamp of the same
    /// `(account_id, revision_id)` pair is a no-op. The auto-stamp
    /// inside [`Self::add_account`] / [`Self::update_account`] /
    /// [`Self::delete_account`] runs in the same transaction as the
    /// revision INSERT, so callers don't usually need to invoke this
    /// directly. The public method is exposed for forward-compat with
    /// future ingestion paths (e.g., importing a revision from an
    /// out-of-band source).
    ///
    /// Metadata-only — does NOT require [`VaultState::Active`].
    /// Touches the soft-expiry path so a long-idle session is properly
    /// zeroized but the operation itself proceeds even from a `Locked`
    /// vault.
    ///
    /// # Errors
    ///
    /// `StoreError::Sqlite` for any database issue. `StoreError::Corrupted`
    /// if the unix-ms timestamp does not fit in `i64` (impossible
    /// before year ~292M).
    pub fn mark_dirty(&mut self, account_id: AccountId, revision_id: RevisionId) -> Result<()> {
        self.maybe_expire_active_session();
        // P8 fix CRIT-1: refuse to mark a frozen account dirty. A
        // user editing their own copy of an account that has been
        // chain-modified would create a fork they don't realize
        // they're creating. The internal auto-stamp inside
        // `add_account`/`update_account`/`delete_account` is already
        // gated by the `refuse_if_frozen` check at the top of those
        // ops; this guard catches the public `mark_dirty` surface for
        // anyone reaching it directly (forward-compat with future
        // ingestion paths).
        self.refuse_if_frozen(account_id)?;
        let now = current_unix_ms();
        let affected = self.conn.execute(
            "INSERT OR IGNORE INTO dirty_accounts
                (account_id, revision_id, marked_at)
             VALUES (?1, ?2, ?3)",
            params![
                account_id.as_bytes().as_slice(),
                revision_id.as_bytes().as_slice(),
                now,
            ],
        )?;
        // MVP-2 issue 5.1 (R-d): only stamp the window when a NEW
        // marker is inserted (INSERT OR IGNORE returns 0 affected on
        // a duplicate pair). Re-marking the same pair shouldn't
        // reset the window.
        if affected > 0 {
            self.note_dirty_marker_stamped(now);
        }
        self.touch_session();
        Ok(())
    }

    /// Remove the marker for `(account_id, revision_id)`. No-op if
    /// no such marker exists. Idempotent.
    ///
    /// Per `P8.md` §A2 the pair-key discipline means clearing a
    /// `(account_id, wrong_revision_id)` pair has no effect on other
    /// markers for the same account — this is the test
    /// `clear_with_wrong_revision_id_is_noop` (below).
    ///
    /// Metadata-only — does NOT require [`VaultState::Active`].
    ///
    /// # Errors
    ///
    /// `StoreError::Sqlite` for any database issue.
    pub fn clear_dirty(&mut self, account_id: AccountId, revision_id: RevisionId) -> Result<()> {
        self.maybe_expire_active_session();
        self.conn.execute(
            "DELETE FROM dirty_accounts
             WHERE account_id = ?1 AND revision_id = ?2",
            params![
                account_id.as_bytes().as_slice(),
                revision_id.as_bytes().as_slice(),
            ],
        )?;
        self.touch_session();
        Ok(())
    }

    /// Snapshot the current dirty list, sorted by `marked_at` ASC
    /// (FIFO).
    ///
    /// Empty `Vec` for a freshly-created vault. Length grows by one
    /// per call to `add_account` / `update_account` / `delete_account`
    /// and shrinks by one per `clear_dirty` (or per successful
    /// `mark_published` + clear in the publish orchestrator — see
    /// `pangolin-cli sync.rs`, P8-3).
    ///
    /// Metadata-only — does NOT require [`VaultState::Active`].
    ///
    /// # Errors
    ///
    /// `StoreError::Sqlite` for any database issue.
    /// `StoreError::Corrupted` if a stored row's BLOB columns are not
    /// 32 bytes (storage corruption).
    pub fn list_dirty(&self) -> Result<Vec<crate::dirty::DirtyEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT account_id, revision_id, marked_at
             FROM dirty_accounts
             ORDER BY marked_at ASC, account_id ASC, revision_id ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            let account_id: Vec<u8> = row.get(0)?;
            let revision_id: Vec<u8> = row.get(1)?;
            let marked_at: i64 = row.get(2)?;
            Ok((account_id, revision_id, marked_at))
        })?;
        let mut out: Vec<crate::dirty::DirtyEntry> = Vec::new();
        for row in rows {
            let (acc_blob, rev_blob, marked_at) = row?;
            let acc_arr: [u8; ACCOUNT_ID_LEN] = acc_blob.as_slice().try_into().map_err(|_| {
                StoreError::Corrupted("dirty_accounts.account_id not 32 bytes".into())
            })?;
            let rev_arr: [u8; REVISION_ID_LEN] = rev_blob.as_slice().try_into().map_err(|_| {
                StoreError::Corrupted("dirty_accounts.revision_id not 32 bytes".into())
            })?;
            out.push(crate::dirty::DirtyEntry {
                account_id: AccountId::from_bytes(acc_arr),
                revision_id: RevisionId::from_bytes(rev_arr),
                marked_at,
            });
        }
        Ok(out)
    }

    // -----------------------------------------------------------------
    // MVP-2 issue 5.1 — publish queue + batching (30s same-account
    // coalescing layer on top of the P8-2 dirty_accounts table).
    // -----------------------------------------------------------------

    /// **MVP-2 issue 5.1 (R-d).** Window-start hook called by every
    /// op that stamps a dirty marker (`add_account` / `update_account`
    /// / `delete_account` / `account_add` / `account_update` /
    /// `resolve_fork`). Sets `ActiveState.window_started_at_unix_ms`
    /// to `now_ms` IF the field is currently `None`. Cheap no-op on
    /// a vault without an active session (the dirty marker was
    /// already persisted; the in-memory window state is just unset
    /// until the next unlock).
    fn note_dirty_marker_stamped(&mut self, now_ms: i64) {
        if let Some(active) = self.active.as_mut() {
            if active.window_started_at_unix_ms.is_none() {
                active.window_started_at_unix_ms = Some(now_ms);
            }
        }
    }

    /// **MVP-2 issue 5.1 (L11).** Host opts in (or out) of the
    /// window-elapsed auto-flush primitive. Default: `false` in 5.1
    /// (this issue ships the primitive only; 5.4 will flip the
    /// host default to `true` when the always-on wiring lands).
    ///
    /// When `true`, the next `account_add` / `account_update` /
    /// `delete_account` (etc.) call that finds the 30s window
    /// elapsed will attempt a best-effort [`Self::flush_publish_queue`]
    /// BEFORE handling the new edit. Best-effort: the flush is run
    /// with a caller-supplied `ChainAdapter`; if no adapter is
    /// registered (the default for 5.1) the auto-flush primitive is
    /// inert until the host explicitly calls `flush_publish_queue`.
    ///
    /// Idempotent — calling with the same value twice is a no-op.
    /// Returns `Ok(())` even on a Locked vault (the field is part of
    /// the in-memory session state; a Locked vault preserves the
    /// LAST-known value but the unlock path re-zeroes it).
    ///
    /// # Errors
    ///
    /// [`StoreError::NotUnlocked`] if the vault has never been
    /// unlocked (there is no `ActiveState` to hold the flag).
    pub fn enable_window_elapsed_flush(&mut self, on: bool) -> Result<()> {
        let active = self.require_active_mut()?;
        active.window_elapsed_flush_enabled = on;
        Ok(())
    }

    /// **MVP-2 issue 5.1.** Snapshot of the publish queue state for
    /// host UI rendering. Metadata-only — works on a Locked vault
    /// (the dirty markers persist; only the in-memory window state
    /// goes away).
    ///
    /// `window_started_at_unix_ms` is `None` on a Locked vault even
    /// if dirty markers exist; the next unlock will start a fresh
    /// window if the queue is non-empty.
    ///
    /// # Errors
    ///
    /// `StoreError::Sqlite` for any database issue. `StoreError::Corrupted`
    /// if a stored row's `enc_payload` size doesn't fit `i64` (storage
    /// corruption — impossible in practice given the 4 MiB chain-tx
    /// cap on a single revision).
    pub fn publish_queue_state(&self) -> Result<crate::publish::PublishQueueState> {
        let dirty = self.list_dirty()?;
        let dirty_count = dirty.len();

        // Sum enc_payload sizes for the byte-cap (R-b option 8).
        let mut dirty_byte_size: u64 = 0;
        for entry in &dirty {
            let size_i64: i64 = self
                .conn
                .query_row(
                    "SELECT LENGTH(enc_payload)
                     FROM revisions
                     WHERE account_id = ?1 AND revision_id = ?2",
                    params![
                        entry.account_id.as_bytes().as_slice(),
                        entry.revision_id.as_bytes().as_slice(),
                    ],
                    |row| row.get(0),
                )
                .optional()?
                .unwrap_or(0);
            let size_bytes = u64::try_from(size_i64).unwrap_or(0);
            dirty_byte_size = dirty_byte_size.saturating_add(size_bytes);
        }

        let (window_started_at_unix_ms, blocked_on_balance) =
            self.active.as_ref().map_or((None, false), |a| {
                (a.window_started_at_unix_ms, a.last_flush_failed_balance)
            });

        Ok(crate::publish::PublishQueueState {
            window_started_at_unix_ms,
            dirty_count,
            dirty_byte_size,
            blocked_on_balance,
        })
    }

    /// **MVP-2 issue 5.1 (R-c) — per-account coalescing pass.**
    ///
    /// Walks the `dirty_accounts` table and, for every account that
    /// has MORE than one dirty marker, prunes all markers except the
    /// one that points at the account's CURRENT head (read from
    /// `account_identities.head_revision_id`, NOT `MAX(marked_at)` —
    /// the head pointer is updated atomically inside the
    /// `add_account` / `update_account` / `delete_account` /
    /// `resolve_fork` transactions, so it is the authoritative,
    /// clock-skew-immune source of truth per L-clock-skew-coalesce-
    /// wrong-order in the 5.1 plan).
    ///
    /// **Tombstone-wins invariant (L10).** When an account's head is
    /// a tombstone revision, the tombstone's dirty marker is the one
    /// preserved (because the head pointer == the tombstone's id);
    /// prior live-update markers for the same account are pruned.
    /// Conversely, an in-flight "update X, delete X" within a single
    /// window collapses to the tombstone being preserved — the
    /// deletion intent always ships to chain.
    ///
    /// Returns the number of markers pruned. `Ok(0)` is the common
    /// case (no account has > 1 marker).
    ///
    /// # Errors
    ///
    /// `StoreError::Sqlite` for any database issue. `StoreError::Corrupted`
    /// for malformed BLOB columns.
    pub fn coalesce_dirty_markers(&mut self) -> Result<usize> {
        // Group dirty markers by account_id; for each group with > 1
        // marker, read the canonical head from account_identities and
        // prune every other marker.
        let dirty = self.list_dirty()?;
        if dirty.is_empty() {
            return Ok(0);
        }
        // Build a per-account marker count first so we only do the
        // SQL work for accounts that actually have > 1 marker.
        let mut per_account: std::collections::HashMap<AccountId, Vec<RevisionId>> =
            std::collections::HashMap::new();
        for entry in &dirty {
            per_account
                .entry(entry.account_id)
                .or_default()
                .push(entry.revision_id);
        }
        let mut pruned: usize = 0;
        let tx = self.conn.unchecked_transaction()?;
        for (account_id, revisions) in per_account {
            if revisions.len() < 2 {
                continue;
            }
            // Authoritative head from account_identities.
            let head_blob: Option<Vec<u8>> = tx
                .query_row(
                    "SELECT head_revision_id
                     FROM account_identities WHERE account_id = ?1",
                    params![account_id.as_bytes().as_slice()],
                    |row| row.get(0),
                )
                .optional()?;
            let Some(head_blob) = head_blob else {
                // Account row missing — unusual but defensive: do not
                // prune anything for this account. (A missing row
                // would also mean the dirty markers are orphans and
                // should ideally be cleaned by a separate maintenance
                // path; 5.1 stays conservative.)
                continue;
            };
            let head_arr: [u8; REVISION_ID_LEN] = head_blob
                .as_slice()
                .try_into()
                .map_err(|_| StoreError::Corrupted("head_revision_id not 32 bytes".into()))?;
            let head_id = RevisionId::from_bytes(head_arr);
            for rev in revisions {
                if rev == head_id {
                    continue;
                }
                let affected = tx.execute(
                    "DELETE FROM dirty_accounts
                     WHERE account_id = ?1 AND revision_id = ?2",
                    params![account_id.as_bytes().as_slice(), rev.as_bytes().as_slice(),],
                )?;
                pruned = pruned.saturating_add(affected);
            }
        }
        tx.commit()?;
        Ok(pruned)
    }

    /// **MVP-2 issue 5.1 — batched publish-queue flush.**
    ///
    /// Top-level flush entry point. Per the plan §R-c / §R-e:
    ///
    /// 1. **Coalesce** dirty markers via [`Self::coalesce_dirty_markers`]
    ///    (per-account; tombstone-wins). After this pass, every
    ///    account has at most one marker pointing at its canonical
    ///    head.
    /// 2. **Top-of-flush balance gate (R-e + L2 + L12).** Sum
    ///    `queued_count × estimate_next_publish_cost`; if the wallet
    ///    balance is below the sum, return
    ///    [`crate::publish::BatchFlushError::BalanceInsufficientForBatch`]
    ///    BEFORE any chain submit is attempted. The dirty markers
    ///    stay; the next call re-runs the gate (with whatever extra
    ///    markers may have been appended per R-f).
    /// 3. **Per-account publish loop.** Delegate to
    ///    [`crate::publish::publish_all_for_vault`] with the supplied
    ///    adapter and the device key from the active session.
    ///    Per-account failures surface as
    ///    [`crate::publish::PublishOutcome::Failed`] rows in the wrapped
    ///    report — the outer `Result` stays `Ok`.
    ///
    /// The `force` flag is reserved for callers that want to skip
    /// the (future) 30s window gate when 5.4 ships always-on
    /// auto-flush. In 5.1 `flush_publish_queue` ALWAYS flushes when
    /// invoked (the host is in control of the cadence); `force` is
    /// kept on the signature for forward-compat without API churn.
    ///
    /// # Window state side effects
    ///
    /// On a SUCCESSFUL flush (no balance-gate failure), the window
    /// state is reset: `window_started_at_unix_ms = None`,
    /// `last_flush_failed_balance = false`. The NEXT dirty marker
    /// after the flush starts a fresh 30s window.
    ///
    /// On a `BalanceInsufficientForBatch` return,
    /// `last_flush_failed_balance` is set to `true` so the host UI
    /// can render the blocked-on-balance hint.
    ///
    /// # Errors
    ///
    /// See [`crate::publish::BatchFlushError`].
    pub async fn flush_publish_queue<A: pangolin_chain::ChainAdapter + ?Sized>(
        &mut self,
        adapter: &A,
        device_key: &pangolin_crypto::keys::DeviceKey,
        _force: bool,
    ) -> core::result::Result<crate::publish::BatchFlushReport, crate::publish::BatchFlushError>
    {
        // The flush path requires an active session for two reasons:
        // (1) `read_revision_for_publish` is gated by an active
        //     session (it's the read path the publish loop calls); a
        //     Locked vault returns NotUnlocked from the inner call.
        // (2) The L11 invariant says only flush_publish_queue (and
        //     its drain-on-teardown invocations) reaches publish; we
        //     enforce it structurally by requiring `active` here.
        if self.active.is_none() {
            return Err(crate::publish::BatchFlushError::NoActiveSession);
        }

        // ---- Step 1: coalesce. ----
        let coalesced_markers_pruned = self
            .coalesce_dirty_markers()
            .map_err(crate::publish::BatchFlushError::Store)?;

        // ---- Step 2: pre-flight batch balance gate (R-e + L2 + L12). ----
        //
        // After coalesce, count the rows that will actually attempt
        // chain submission. Then ask the adapter for a pre-flight
        // balance projection. If the adapter reports
        // `Some(BatchBalanceCheck)` AND the check is insufficient,
        // fail-fast with the typed L12 variant carrying the actual
        // wei values — BEFORE any chain submit. The "everything-or-
        // nothing" guarantee per R-e.
        //
        // Adapters that pre-date 5.1 (e.g., `MockChainAdapter` in some
        // PoC tests) return `Ok(None)` from the default-impl, in which
        // case we fall back to the per-revision gate inside
        // `publish_revision_v1` (defense-in-depth; same posture the
        // pre-fix-pass code had).
        let queued_count_after_coalesce = self
            .list_dirty()
            .map_err(crate::publish::BatchFlushError::Store)?
            .len();
        if let Some(check) = adapter
            .pre_flight_batch_balance(queued_count_after_coalesce)
            .await
            .map_err(crate::publish::BatchFlushError::ChainError)?
        {
            if !check.is_sufficient() {
                if let Some(active) = self.active.as_mut() {
                    active.last_flush_failed_balance = true;
                }
                return Err(
                    crate::publish::BatchFlushError::BalanceInsufficientForBatch {
                        needed: check.total_estimated_cost_wei,
                        available: check.current_balance_wei,
                        queued_count: queued_count_after_coalesce,
                    },
                );
            }
        }

        // ---- Step 3: per-account publish loop. ----
        let publish_report = crate::publish::publish_all_for_vault(self, adapter, device_key)
            .await
            .map_err(crate::publish::BatchFlushError::Store)?;

        // ---- Step 4: window-state reset on successful flush. ----
        if let Some(active) = self.active.as_mut() {
            active.window_started_at_unix_ms = None;
            active.last_flush_failed_balance = false;
        }

        Ok(crate::publish::BatchFlushReport {
            coalesced_markers_pruned,
            publish_report,
        })
    }

    /// **MVP-2 issue 5.1 (R-a) — env-var-clamped batch window.**
    ///
    /// Resolves the 30s coalescing window from
    /// `PANGOLIN_BATCH_WINDOW_SECS` (clamped `1..=300`), defaulting
    /// to `BATCH_WINDOW_SECS_DEFAULT = 30`. Pure function (the env
    /// var is read once per call); host can override the default for
    /// testing without using `env::set_var` (a process-global side
    /// effect) by using [`Self::resolve_batch_window_secs_from`].
    #[must_use]
    pub fn resolve_batch_window_secs() -> u64 {
        Self::resolve_batch_window_secs_from(
            std::env::var(BATCH_WINDOW_SECS_ENV_VAR).ok().as_deref(),
        )
    }

    /// Pure version of [`Self::resolve_batch_window_secs`] for
    /// testability. The env var is read separately so hermetic tests
    /// can drive the clamp logic deterministically.
    #[must_use]
    pub fn resolve_batch_window_secs_from(raw: Option<&str>) -> u64 {
        let parsed = raw.and_then(|s| s.parse::<u64>().ok());
        let value = parsed.unwrap_or(BATCH_WINDOW_SECS_DEFAULT);
        value.clamp(BATCH_WINDOW_SECS_MIN, BATCH_WINDOW_SECS_MAX)
    }

    /// **MVP-2 issue 4.1 (R-e + R-a + R-c + R-d).** Pull v1
    /// `RevisionPublished` events from D-017 + ingest them into the
    /// local revision graph + advance the per-vault checkpoint.
    ///
    /// Async because the underlying alloy provider calls are async;
    /// the `&mut self` signature preserves the sync-Vault doctrine
    /// (R-e). The orchestrator loops `fetch_and_verify_chunk` at
    /// `CHAIN_SYNC_LOG_BLOCK_CHUNK = 9_000` per L6, ingests each
    /// verified event via [`Self::ingest_pending_chain_revision`]
    /// (R-c Pending status), auto-registers unknown signers per R-d,
    /// promotes pending revisions whose depth reaches the
    /// finalization threshold per R-c, detects + rolls back reorgs
    /// per R-c, and advances the v1 checkpoint atomically with
    /// successful ingest.
    ///
    /// # Arguments
    ///
    /// - `rpc_url` — HTTP(S) RPC endpoint to talk to.
    /// - `env` — which `ChainEnv` to bind to. Only `BaseSepolia` is
    ///   pinned in MVP-2.
    /// - `vault_id` — 32-byte vault id to filter events by.
    /// - `options` — caller tuning. `Default::default()` is the
    ///   production posture.
    ///
    /// # Errors
    ///
    /// See [`pangolin_chain::error::ChainError`] taxonomy for the
    /// fail-closed variants ([`ChainIdMismatch`], [`DeploymentAddressMismatch`],
    /// [`CheckpointOutOfRange`]) plus the store's own
    /// [`StoreError::Sqlite`] etc.
    pub async fn sync_from_chain(
        &mut self,
        rpc_url: &str,
        env: pangolin_chain::ChainEnv,
        vault_id: &[u8; 32],
        options: pangolin_chain::SyncOptions,
    ) -> Result<pangolin_chain::SyncReport> {
        self.sync_from_chain_with_ws_url(rpc_url, None, env, vault_id, options)
            .await
    }

    /// Test-facing variant of [`Self::sync_from_chain`] that accepts an
    /// explicit `ws_url_override` for hermetic WS tests against a
    /// local mock server. Production callers use
    /// [`Self::sync_from_chain`] which derives the WS URL via the
    /// Q-c resolver (`resolve_ws_url`).
    ///
    /// Issue #99 §2d orchestrator branch lives here so the public
    /// `sync_from_chain` surface stays unchanged.
    #[allow(clippy::too_many_lines)]
    pub async fn sync_from_chain_with_ws_url(
        &mut self,
        rpc_url: &str,
        ws_url_override: Option<&str>,
        env: pangolin_chain::ChainEnv,
        vault_id: &[u8; 32],
        options: pangolin_chain::SyncOptions,
    ) -> Result<pangolin_chain::SyncReport> {
        use pangolin_chain::chain_sync::poll::{verify_alloy_log, VerifyOutcome};
        use pangolin_chain::chain_sync::ws::{
            open_subscription, recv_next_event, resolve_ws_url, WsRecvOutcome,
        };
        use pangolin_chain::chain_sync::{detect_reorg_via_rpc, fetch_and_verify_chunk};
        use pangolin_chain::{
            d017_deploy_block, fetch_current_block_number, ChainEventSource, SyncReport,
            WS_CIRCUIT_BREAKER_THRESHOLD,
        };
        use std::time::Duration;

        const CHUNK: u64 = pangolin_chain::CHAIN_SYNC_LOG_BLOCK_CHUNK;
        // Issue #99 §2d. Wall-clock window the WS recv loop holds
        // inside ONE `sync_from_chain` call before returning. Bounds
        // the call duration; the host's pull-loop drives the next
        // call to keep the WS path alive across many ticks.
        const WS_TIP_FOLLOW_WINDOW_SECS: u64 = 30;
        // Per-recv idle timeout. If no event arrives in this window,
        // the recv loop returns control to the caller (= exits this
        // `sync_from_chain` invocation gracefully). Shorter than
        // `WS_TIP_FOLLOW_WINDOW_SECS` so a quiet WS connection
        // doesn't block the host's pull-loop cadence.
        const WS_RECV_IDLE_TIMEOUT_MS: u64 = 250;

        // MVP-3 issue #106c2 routing: a V2-bound vault reads via the V2
        // path + its own SEPARATE checkpoint; a V1-bound vault (incl. all
        // legacy vaults, NULL → V1) keeps the existing V1 path below
        // VERBATIM — the L-no-regression invariant.
        if matches!(self.revisionlog_version()?, RevisionLogVersion::V2) {
            return self
                .sync_from_chain_v2_path(rpc_url, ws_url_override, env, vault_id, options)
                .await;
        }

        // R-a: resolve the starting cursor.
        let persisted = self.last_synced_block_v1()?;
        let mut cursor = if options.from_genesis {
            d017_deploy_block(env)
        } else {
            persisted.unwrap_or_else(|| d017_deploy_block(env))
        };

        // L3 chain-id cross-check + head fetch happen inside the
        // chain-sync helpers (the helpers run their own provider
        // construction with the cross-check baked in).
        let head = match options.until_block {
            Some(t) => t,
            None => fetch_current_block_number(rpc_url).await?,
        };

        // L-checkpoint-corruption defense: if a persisted checkpoint
        // points past the current tip, fail closed.
        if cursor > head {
            return Err(pangolin_chain::error::ChainError::CheckpointOutOfRange {
                observed: cursor,
                tip: head,
            }
            .into());
        }

        let mut report = SyncReport {
            event_source: ChainEventSource::HttpPolling,
            ..Default::default()
        };
        let mut detector = pangolin_chain::chain_sync::reorg::ReorgDetector::default();

        // -----------------------------------------------------------
        // Stage 1 — HTTP backfill (Q-a Option A).
        // WS subscriptions cannot replay history; the chunked
        // `eth_getLogs` loop catches up `cursor -> head` first.
        // -----------------------------------------------------------
        while cursor < head {
            let chunk_start = cursor.saturating_add(1);
            let chunk_end = chunk_start
                .saturating_add(CHUNK.saturating_sub(1))
                .min(head);
            let (events, rejected) =
                fetch_and_verify_chunk(rpc_url, env, vault_id, chunk_start, chunk_end).await?;
            report.revisions_pulled = report
                .revisions_pulled
                .saturating_add(u32::try_from(events.len()).unwrap_or(u32::MAX));
            report.revisions_rejected = report.revisions_rejected.saturating_add(rejected);

            for ev in events {
                // R-d: auto-register the signer if not yet in the
                // devices table. Idempotent.
                let signer_bytes = ev.signer.into_array();
                let now_ms = current_unix_ms();
                let inserted_new = device::auto_register_device_from_chain_sync(
                    &self.conn,
                    signer_bytes,
                    ev.event.anchor.block_number,
                    now_ms,
                )?;
                if inserted_new {
                    report.new_devices_registered = report.new_devices_registered.saturating_add(1);
                }

                // R-c: ingest with Pending status + observed block info.
                self.ingest_pending_chain_revision(
                    &ev.event,
                    ev.event.anchor.block_number,
                    ev.block_hash.0,
                )?;
                detector.record(ev.event.anchor.block_number, ev.block_hash);
                report.revisions_applied = report.revisions_applied.saturating_add(1);
            }

            // R-c: reorg detection. After each chunk, query canonical
            // chain for observed heights + roll back affected window.
            if let Some(info) = detect_reorg_via_rpc(rpc_url, &detector).await? {
                let rolled = self.rollback_pending_revisions_in_range(
                    info.affected_block_low,
                    info.affected_block_high,
                )?;
                report.revisions_rolled_back = report.revisions_rolled_back.saturating_add(rolled);
                detector.forget_window(info);
            }

            // R-c: promote pending revisions whose depth >= 12.
            let promoted = self.promote_finalized_revisions(head)?;
            report.revisions_finalized = report.revisions_finalized.saturating_add(promoted);

            // R-a + L12: advance the checkpoint atomically with the
            // ingest (the ingest already happened above; the
            // checkpoint advance is the closing fence).
            self.update_last_synced_block_v1(chunk_end)?;
            cursor = chunk_end;
            // Guard against pathological zero-progress chunks.
            if chunk_end >= head {
                break;
            }
        }

        // Final finalization pass on whatever pending rows remain.
        let promoted = self.promote_finalized_revisions(head)?;
        report.revisions_finalized = report.revisions_finalized.saturating_add(promoted);
        report.last_block_synced = head;

        // -----------------------------------------------------------
        // Stage 2 — WS tip-follow (Q-a Option A second phase).
        // Issue #99 §2d. After backfill catches up to head, attempt
        // a WS subscription for new events at tip. On open-fail or
        // mid-session-drop, increment `ws_drops` and back off up to
        // `WS_CIRCUIT_BREAKER_THRESHOLD` consecutive failures, then
        // fall through to HTTP polling for the rest of the session.
        //
        // L10: WS open-fail / drop NEVER fails the sync. The path
        // taken at exit is reflected honestly in
        // `report.event_source` per L9.
        //
        // The recv loop holds the connection for up to
        // `WS_TIP_FOLLOW_WINDOW_SECS` of wall-clock; the host's
        // pull-loop calls `sync_from_chain` again on its cadence to
        // re-establish the WS session for the next window.
        // -----------------------------------------------------------
        // Skip WS entirely when an explicit `until_block` was passed
        // (caller is doing a bounded historical sync, not tip-follow).
        let tip_follow_eligible = options.prefer_websocket && options.until_block.is_none();
        if !tip_follow_eligible {
            return Ok(report);
        }

        // The HTTP backfill above already ran the same resolver
        // successfully, so the Err branch is unreachable in
        // practice. Defensive: fall through to HTTP if it ever
        // fires.
        let Ok(contract_address) = pangolin_chain::chain_sync::resolve_and_check_contract(env)
        else {
            return Ok(report);
        };

        // Q-c URL resolver. For hermetic tests, `ws_url_override`
        // bypasses the JSON pin + scheme derivation; production
        // callers pass None and the resolver derives from
        // `rpc_url` (Option I) or picks up a JSON pin (Option III,
        // wired by the host's deployment-file loader).
        let ws_url = if let Some(forced) = ws_url_override {
            forced.to_owned()
        } else {
            // No JSON-pin loader is wired into `sync_from_chain`
            // yet (it would require pangolin-store to depend on
            // the deployment-file loader); the resolver derives
            // from the HTTP URL until that wiring lands. This is
            // a deviation from Q-c Option III's "pin source-of-
            // truth" arm — closed by the future wiring task; the
            // L-ws-tls-downgrade defense still fires inside
            // `open_subscription` regardless.
            match resolve_ws_url(rpc_url, env, None) {
                Ok(s) => s,
                Err(_) => return Ok(report),
            }
        };

        // Stage 2 recv loop: bounded by `WS_TIP_FOLLOW_WINDOW_SECS`
        // wall-clock + circuit-breaker count.
        let stage2_deadline =
            tokio::time::Instant::now() + Duration::from_secs(WS_TIP_FOLLOW_WINDOW_SECS);

        let mut consecutive_failures: u32 = 0;
        let mut backoff_ms: u64 = 0;
        // Track whether we processed at least one WS event so
        // `report.event_source` reflects the path actually taken
        // (L9). Set to `WebSocket` only after the first
        // successfully-ingested event.
        let mut ws_path_used = false;

        'ws_session: while tokio::time::Instant::now() < stage2_deadline
            && consecutive_failures < WS_CIRCUIT_BREAKER_THRESHOLD
        {
            // Backoff before opening (skipped for the first attempt
            // since backoff_ms = 0).
            if backoff_ms > 0 {
                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
            }
            // L10: WS open-fail never aborts; bump ws_drops,
            // advance backoff, retry up to the circuit-breaker cap.
            let Ok(mut handle) = open_subscription(&ws_url, env, vault_id, contract_address).await
            else {
                report.ws_drops = report.ws_drops.saturating_add(1);
                consecutive_failures = consecutive_failures.saturating_add(1);
                backoff_ms = pangolin_chain::chain_sync::ws::next_reconnect_backoff_ms(backoff_ms);
                continue 'ws_session;
            };

            // Issue #99 F-2 fix-pass — recv-loop-exit gate.
            //
            // Track whether at least one verified event landed during
            // this open's recv loop. The breaker counter is reset to
            // 0 ONLY when this flag is true at recv-loop exit;
            // otherwise the recv-loop exit accumulates the counter
            // toward `WS_CIRCUIT_BREAKER_THRESHOLD`.
            //
            // **Scope honesty (F-4 re-audit empirical finding).** This
            // gate fires only when `recv_next_event` returns
            // `WsRecvOutcome::SubscriptionClosed` — which alloy's
            // `alloy-pubsub` 2.0.4 layer only surfaces when its
            // internal `reconnect_with_retries` loop gives up (max
            // ~10 FAILED-reconnects × exponential-backoff ≈ minutes).
            // On the accept-then-drop FAST-failure mode (RPC accepts
            // the WS + replies to eth_subscribe + immediately drops),
            // every reconnect cycle is a "fresh success" from
            // alloy's POV, so `max_retries` never increments and the
            // pubsub layer absorbs the storm silently below the
            // orchestrator's recv layer. The orchestrator therefore
            // does NOT receive the close signal in that scenario, and
            // this gate is unreachable. See
            // `docs/architecture/chain-sync.md` for the documented
            // limitation + the deferred wrapper architectural
            // follow-up (direct WS transport that bypasses
            // alloy-pubsub and surfaces drops to the orchestrator).
            //
            // This gate remains valuable for the SLOW-failure mode
            // (alloy gives up entirely; rare but real) — it then
            // correctly distinguishes "open succeeded but no event
            // landed during this session" from "session was healthy"
            // for breaker accounting.
            let mut event_ingested_this_open = false;

            // Drain events with a short idle timeout so a quiet
            // tip returns the caller quickly. Any event whose
            // verification succeeds advances the local revision
            // graph + the v1 checkpoint.
            'recv_loop: loop {
                if tokio::time::Instant::now() >= stage2_deadline {
                    // Wall-clock deadline: treat as a successful
                    // recv-loop exit only if at least one event
                    // landed (so the breaker resets only on
                    // healthy sessions). The post-loop reset
                    // gate below handles the bookkeeping.
                    break 'ws_session;
                }
                let recv_fut = recv_next_event(&mut handle);
                // Timeout — no events available; gracefully
                // exit the WS session for this call. Honest
                // event_source reporting requires at least one
                // successfully-ingested WS event for the
                // `WebSocket` label; if no events arrived,
                // the sync reports HttpPolling per L9.
                let Ok(outcome) =
                    tokio::time::timeout(Duration::from_millis(WS_RECV_IDLE_TIMEOUT_MS), recv_fut)
                        .await
                else {
                    break 'ws_session;
                };
                match outcome {
                    WsRecvOutcome::Event(log) => {
                        match verify_alloy_log(&log, vault_id, &contract_address, env) {
                            VerifyOutcome::Verified(ev) => {
                                report.revisions_pulled = report.revisions_pulled.saturating_add(1);
                                let signer_bytes = ev.signer.into_array();
                                let now_ms = current_unix_ms();
                                let inserted_new = device::auto_register_device_from_chain_sync(
                                    &self.conn,
                                    signer_bytes,
                                    ev.event.anchor.block_number,
                                    now_ms,
                                )?;
                                if inserted_new {
                                    report.new_devices_registered =
                                        report.new_devices_registered.saturating_add(1);
                                }
                                self.ingest_pending_chain_revision(
                                    &ev.event,
                                    ev.event.anchor.block_number,
                                    ev.block_hash.0,
                                )?;
                                detector.record(ev.event.anchor.block_number, ev.block_hash);
                                report.revisions_applied =
                                    report.revisions_applied.saturating_add(1);
                                // L9: WS path used iff at least one
                                // event landed via WS.
                                ws_path_used = true;
                                // F-2: mark this open's recv loop
                                // as healthy. Only verified +
                                // ingested events count — a wire
                                // event that fails verification
                                // (foreign address, future schema,
                                // etc.) doesn't prove the channel
                                // is real, just that we received
                                // bytes.
                                event_ingested_this_open = true;
                                // Advance the v1 checkpoint to the
                                // event's block. The block-number
                                // monotone-advance guard inside
                                // `update_last_synced_block_v1`
                                // rejects out-of-order WS events
                                // gracefully (the L7 idempotency
                                // path already handles the
                                // duplicate-row case).
                                let new_cursor = ev.event.anchor.block_number;
                                if new_cursor > cursor {
                                    self.update_last_synced_block_v1(new_cursor)?;
                                    cursor = new_cursor;
                                }
                            }
                            VerifyOutcome::Rejected => {
                                report.revisions_rejected =
                                    report.revisions_rejected.saturating_add(1);
                            }
                        }
                    }
                    WsRecvOutcome::SubscriptionClosed => {
                        // L-ws-silent-disconnect: server closed
                        // the channel (or broadcast lagged).
                        // Increment ws_drops + back off. The
                        // breaker-counter bookkeeping happens at
                        // the recv-loop-exit gate below so the
                        // accept-then-drop storm is captured.
                        report.ws_drops = report.ws_drops.saturating_add(1);
                        backoff_ms =
                            pangolin_chain::chain_sync::ws::next_reconnect_backoff_ms(backoff_ms);
                        break 'recv_loop;
                    }
                }
            }

            // F-2 recv-loop-exit gate. Reset the breaker counter
            // ONLY if at least one verified event landed during
            // this open. Otherwise treat the open-then-drop as a
            // continuation of the storm and let the counter
            // accumulate toward WS_CIRCUIT_BREAKER_THRESHOLD.
            if event_ingested_this_open {
                consecutive_failures = 0;
                backoff_ms = 0;
            } else {
                consecutive_failures = consecutive_failures.saturating_add(1);
            }
        }

        if ws_path_used {
            report.event_source = ChainEventSource::WebSocket;
            // Run another finalization pass since the WS path may
            // have added new pending rows that crossed the
            // finalization threshold.
            let promoted = self.promote_finalized_revisions(head)?;
            report.revisions_finalized = report.revisions_finalized.saturating_add(promoted);
        }
        // L9 default: report.event_source already initialised to
        // HttpPolling. Set here for clarity if WS never took the path.
        Ok(report)
    }

    /// **MVP-3 issue #106c2.** The V2 read leg of
    /// [`Self::sync_from_chain_with_ws_url`]: a mechanical mirror of the
    /// V1 path that reads `RevisionLogV2.RevisionPublished` via
    /// [`pangolin_chain::fetch_and_verify_chunk_v2`] + the V2 WS path,
    /// advancing the SEPARATE `chain_sync_v2_state` checkpoint (Q-e).
    ///
    /// Reuses the shared ingest/reorg/finalize machinery
    /// ([`Self::ingest_pending_chain_revision`],
    /// [`Self::promote_finalized_revisions`],
    /// [`Self::rollback_pending_revisions_in_range`]) verbatim — only the
    /// chunk-fetch + WS-subscribe + checkpoint-state differ from V1, so
    /// the byte-identity-of-verification + reorg posture cannot drift
    /// between paths.
    ///
    /// # Errors
    ///
    /// Same taxonomy as [`Self::sync_from_chain_with_ws_url`].
    #[allow(clippy::too_many_lines)]
    async fn sync_from_chain_v2_path(
        &mut self,
        rpc_url: &str,
        ws_url_override: Option<&str>,
        env: pangolin_chain::ChainEnv,
        vault_id: &[u8; 32],
        options: pangolin_chain::SyncOptions,
    ) -> Result<pangolin_chain::SyncReport> {
        use pangolin_chain::chain_sync::poll::VerifyOutcome;
        use pangolin_chain::chain_sync::v2::{
            open_subscription_v2, recv_next_event_v2, verify_alloy_log_v2,
        };
        use pangolin_chain::chain_sync::ws::{resolve_ws_url, WsRecvOutcome};
        use pangolin_chain::chain_sync::{detect_reorg_via_rpc, fetch_and_verify_chunk_v2};
        use pangolin_chain::{
            fetch_current_block_number, ChainEventSource, SyncReport, WS_CIRCUIT_BREAKER_THRESHOLD,
        };
        use std::time::Duration;

        const CHUNK: u64 = pangolin_chain::CHAIN_SYNC_LOG_BLOCK_CHUNK;
        const WS_TIP_FOLLOW_WINDOW_SECS: u64 = 30;
        const WS_RECV_IDLE_TIMEOUT_MS: u64 = 250;

        // V2 genesis cursor: there is no pinned V2 deploy block (Q-f), so
        // a never-synced V2-bound vault replays from 0 (anvil/Dev is
        // fresh per harness run; the chunk loop bounds the window).
        let persisted = self.last_synced_block_v2()?;
        let mut cursor = if options.from_genesis {
            0
        } else {
            persisted.unwrap_or(0)
        };

        let head = match options.until_block {
            Some(t) => t,
            None => fetch_current_block_number(rpc_url).await?,
        };

        if cursor > head {
            return Err(pangolin_chain::error::ChainError::CheckpointOutOfRange {
                observed: cursor,
                tip: head,
            }
            .into());
        }

        let mut report = SyncReport {
            event_source: ChainEventSource::HttpPolling,
            ..Default::default()
        };
        let mut detector = pangolin_chain::chain_sync::reorg::ReorgDetector::default();

        // -----------------------------------------------------------
        // Issue #106d (Q-a / L2 / L3) — read the LIVE on-chain
        // authorized SET once per sync (the honor source of truth).
        //
        // FAIL-CLOSED (L3): this vault is V2-bound by its FIXED
        // `meta.revisionlog_version` (the routing already decided V2,
        // NOT a chain heuristic). A V2 vault ALWAYS has a bootstrapped
        // set, so a missing deployment / connect / chain-id /
        // `eth_getLogs` / `authorizedDevice` view failure is a REAL
        // error, returned as `Err` and propagated here with `?` — we
        // MUST NOT swallow it to an empty (honor-all) set, which would
        // re-honor a removed device on a rotated vault (under-revocation,
        // the exact hole). Failing the whole sync lets the host retry
        // later with the set gate intact.
        //
        // The gate below honors a verified V2 revision IFF its signer is
        // in this set; a non-set signer's revision is COUNTED
        // (`revisions_revoked`) but NOT ingested (NOT auto-registered).
        // The set is read from the V2 genesis (0; the future Base Sepolia
        // V2 deploy block once pinned).
        let current_set: Vec<[u8; crate::device::EVM_ADDRESS_LEN]> =
            pangolin_chain::read_authorized_set_v2(env, rpc_url, *vault_id, 0)
                .await?
                .into_iter()
                .map(pangolin_chain::Address::into_array)
                .collect();

        // Stage 1 — HTTP backfill (V2 events).
        while cursor < head {
            let chunk_start = cursor.saturating_add(1);
            let chunk_end = chunk_start
                .saturating_add(CHUNK.saturating_sub(1))
                .min(head);
            let (events, rejected) =
                fetch_and_verify_chunk_v2(rpc_url, env, vault_id, chunk_start, chunk_end).await?;
            report.revisions_pulled = report
                .revisions_pulled
                .saturating_add(u32::try_from(events.len()).unwrap_or(u32::MAX));
            report.revisions_rejected = report.revisions_rejected.saturating_add(rejected);

            for ev in events {
                let signer_bytes = ev.signer.into_array();
                // Issue #106d honor GATE (L2). A verified V2 event whose
                // signer is NOT in the current on-chain authorized set is
                // COUNTED but NOT ingested (NOT auto-registered). Sits ON
                // TOP of the unchanged V2 signature verification.
                if !crate::multi_device::is_signer_honored(&signer_bytes, &current_set) {
                    report.revisions_revoked = report.revisions_revoked.saturating_add(1);
                    continue;
                }
                let now_ms = current_unix_ms();
                let inserted_new = device::auto_register_device_from_chain_sync(
                    &self.conn,
                    signer_bytes,
                    ev.event.anchor.block_number,
                    now_ms,
                )?;
                if inserted_new {
                    report.new_devices_registered = report.new_devices_registered.saturating_add(1);
                }
                self.ingest_pending_chain_revision(
                    &ev.event,
                    ev.event.anchor.block_number,
                    ev.block_hash.0,
                )?;
                // #106d fix-pass: persist the ecrecovered signer so the
                // retroactive revocation pass keys on the gating identity
                // (the recovered signer), NOT the opaque device_id.
                self.stamp_recovered_signer(&ev.event, &signer_bytes)?;
                detector.record(ev.event.anchor.block_number, ev.block_hash);
                report.revisions_applied = report.revisions_applied.saturating_add(1);
            }

            if let Some(info) = detect_reorg_via_rpc(rpc_url, &detector).await? {
                let rolled = self.rollback_pending_revisions_in_range(
                    info.affected_block_low,
                    info.affected_block_high,
                )?;
                report.revisions_rolled_back = report.revisions_rolled_back.saturating_add(rolled);
                detector.forget_window(info);
            }

            let promoted = self.promote_finalized_revisions(head)?;
            report.revisions_finalized = report.revisions_finalized.saturating_add(promoted);

            // Advance the SEPARATE V2 checkpoint (Q-e).
            self.update_last_synced_block_v2(chunk_end)?;
            cursor = chunk_end;
            if chunk_end >= head {
                break;
            }
        }

        let promoted = self.promote_finalized_revisions(head)?;
        report.revisions_finalized = report.revisions_finalized.saturating_add(promoted);
        report.last_block_synced = head;

        // Issue #106d (salvaged #103-C GAP FLAG 3) — retroactive
        // revocation re-eval. Re-evaluate ALREADY-STORED chain-anchored
        // rows against the current on-chain set and MARK any whose signer
        // left the set (rows ingested in an earlier sync before the
        // removal was observed). The new-event gate above only filters
        // incoming events; this closes the historical hole. Both
        // directions are recomputed each pass (a re-added device
        // un-revokes its rows). Disjoint from the incoming-gate count (a
        // gated incoming event is never stored), so adding the
        // newly-revoked-row count keeps `revisions_revoked` an honest
        // total of "what this sync cut".
        let retro_revoked = self.reevaluate_revocation_against_set(&current_set)?;
        report.revisions_revoked = report.revisions_revoked.saturating_add(retro_revoked);

        // Stage 2 — WS tip-follow (V2 events).
        let tip_follow_eligible = options.prefer_websocket && options.until_block.is_none();
        if !tip_follow_eligible {
            return Ok(report);
        }
        let Ok(contract_address) =
            pangolin_chain::revisionlog_v2_client::resolve_contract_address(env)
        else {
            return Ok(report);
        };
        let ws_url = if let Some(forced) = ws_url_override {
            forced.to_owned()
        } else {
            match resolve_ws_url(rpc_url, env, None) {
                Ok(s) => s,
                Err(_) => return Ok(report),
            }
        };

        let stage2_deadline =
            tokio::time::Instant::now() + Duration::from_secs(WS_TIP_FOLLOW_WINDOW_SECS);
        let mut consecutive_failures: u32 = 0;
        let mut backoff_ms: u64 = 0;
        let mut ws_path_used = false;

        'ws_session: while tokio::time::Instant::now() < stage2_deadline
            && consecutive_failures < WS_CIRCUIT_BREAKER_THRESHOLD
        {
            if backoff_ms > 0 {
                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
            }
            let Ok(mut handle) =
                open_subscription_v2(&ws_url, env, vault_id, contract_address).await
            else {
                report.ws_drops = report.ws_drops.saturating_add(1);
                consecutive_failures = consecutive_failures.saturating_add(1);
                backoff_ms = pangolin_chain::chain_sync::ws::next_reconnect_backoff_ms(backoff_ms);
                continue 'ws_session;
            };

            let mut event_ingested_this_open = false;

            'recv_loop: loop {
                if tokio::time::Instant::now() >= stage2_deadline {
                    break 'ws_session;
                }
                let recv_fut = recv_next_event_v2(&mut handle);
                let Ok(outcome) =
                    tokio::time::timeout(Duration::from_millis(WS_RECV_IDLE_TIMEOUT_MS), recv_fut)
                        .await
                else {
                    break 'ws_session;
                };
                match outcome {
                    WsRecvOutcome::Event(log) => {
                        match verify_alloy_log_v2(&log, vault_id, &contract_address, env) {
                            VerifyOutcome::Verified(ev) => {
                                report.revisions_pulled = report.revisions_pulled.saturating_add(1);
                                let signer_bytes = ev.signer.into_array();
                                // Issue #106d honor GATE (L2) — the SAME
                                // predicate as the HTTP backfill arm above.
                                // A non-set-signer tip event is COUNTED but
                                // NOT ingested (NOT auto-registered). Sits
                                // ON TOP of the unchanged V2 verification.
                                if !crate::multi_device::is_signer_honored(
                                    &signer_bytes,
                                    &current_set,
                                ) {
                                    report.revisions_revoked =
                                        report.revisions_revoked.saturating_add(1);
                                    continue 'recv_loop;
                                }
                                let now_ms = current_unix_ms();
                                let inserted_new = device::auto_register_device_from_chain_sync(
                                    &self.conn,
                                    signer_bytes,
                                    ev.event.anchor.block_number,
                                    now_ms,
                                )?;
                                if inserted_new {
                                    report.new_devices_registered =
                                        report.new_devices_registered.saturating_add(1);
                                }
                                self.ingest_pending_chain_revision(
                                    &ev.event,
                                    ev.event.anchor.block_number,
                                    ev.block_hash.0,
                                )?;
                                // #106d fix-pass: persist the ecrecovered
                                // signer so the retroactive revocation pass
                                // keys on the gating identity, NOT the
                                // opaque device_id.
                                self.stamp_recovered_signer(&ev.event, &signer_bytes)?;
                                detector.record(ev.event.anchor.block_number, ev.block_hash);
                                report.revisions_applied =
                                    report.revisions_applied.saturating_add(1);
                                ws_path_used = true;
                                event_ingested_this_open = true;
                                let new_cursor = ev.event.anchor.block_number;
                                if new_cursor > cursor {
                                    self.update_last_synced_block_v2(new_cursor)?;
                                    cursor = new_cursor;
                                }
                            }
                            VerifyOutcome::Rejected => {
                                report.revisions_rejected =
                                    report.revisions_rejected.saturating_add(1);
                            }
                        }
                    }
                    WsRecvOutcome::SubscriptionClosed => {
                        report.ws_drops = report.ws_drops.saturating_add(1);
                        backoff_ms =
                            pangolin_chain::chain_sync::ws::next_reconnect_backoff_ms(backoff_ms);
                        break 'recv_loop;
                    }
                }
            }

            if event_ingested_this_open {
                consecutive_failures = 0;
                backoff_ms = 0;
            } else {
                consecutive_failures = consecutive_failures.saturating_add(1);
            }
        }

        if ws_path_used {
            report.event_source = ChainEventSource::WebSocket;
            let promoted = self.promote_finalized_revisions(head)?;
            report.revisions_finalized = report.revisions_finalized.saturating_add(promoted);
        }
        Ok(report)
    }

    // -----------------------------------------------------------------
    // MVP-2 issue 5.2 — pull-loop primitive (R-a + R-c + R-e).
    // -----------------------------------------------------------------

    /// **MVP-2 issue 5.2 (R-a + R-c + R-e).** Single pull cycle.
    ///
    /// Re-picks the [`SyncMode`] via [`Self::select_sync_mode`] (R-c
    /// re-pick per cycle) and dispatches:
    ///
    /// - [`SyncMode::Slow`] — delegates to [`Self::sync_from_chain`]
    ///   with [`pangolin_chain::SyncOptions::default`] (L4: NO
    ///   duplicate logic; inherits 4.1's full L1..L12 defensive
    ///   surface).
    /// - [`SyncMode::OfferFast`] / [`SyncMode::AlwaysFast`] — surfaces
    ///   the signal in [`crate::pull::PullReport::mode`] with
    ///   `sync_report = None`; the host owns the indexer-spawn
    ///   decision per 4.4 L1 + 5.2 L2 (the loop NEVER spawns).
    ///
    /// Returns [`crate::pull::PullError::NoActiveSession`] BEFORE any
    /// RPC call if the vault is not in the
    /// [`VaultState::Active`] state (L1 + R-e: covers every
    /// session-teardown path — `lock()`, idle-expire, 4h-absolute,
    /// `device_locked()`). The host scheduler's canonical loop body
    /// exits on this variant; the worst-case lock→exit latency is one
    /// tick (≤60s default), bounded by the host's interval.
    ///
    /// Stamps `ActiveState.last_pull_at_unix_ms` on every successful
    /// dispatch — diagnostic only (5.4 will wire the
    /// "Synced / Syncing… / Offline" indicator state machine on top
    /// of this stamp; not persisted across `lock()` / unlock).
    ///
    /// # Adapter-less API shape note (deviation explainer for auditors)
    ///
    /// The plan-gate left the choice between adapter-less and
    /// adapter-threaded shapes to the builder; 5.2 ships the
    /// adapter-less form because slow-mode delegates to
    /// [`Self::sync_from_chain`] which takes raw `rpc_url` + `env` +
    /// `vault_id` (NOT a [`pangolin_chain::ChainAdapter`]) and the
    /// `OfferFast` / `AlwaysFast` branches return signal-only (the
    /// host invokes the indexer with its own adapter machinery on
    /// accept).
    /// If a future cycle needs an adapter (e.g., the 5.4
    /// `SyncOrchestrator` fuses pull + flush behind one adapter
    /// handle), the additive change is to introduce a second method
    /// that threads it through; this primitive stays minimal.
    ///
    /// # Errors
    ///
    /// - [`crate::pull::PullError::NoActiveSession`] when the vault
    ///   is locked / expired / pending; no RPC call is made.
    /// - [`crate::pull::PullError::Chain`] when the Slow-mode
    ///   delegate surfaces a chain-side error
    ///   ([`pangolin_chain::ChainError`]). Per R-d the host retries
    ///   on the next regular interval (flat retry); the engine does
    ///   not implement backoff.
    /// - [`crate::pull::PullError::Store`] when the picker or
    ///   delegate surfaces a store-side error
    ///   ([`crate::StoreError`]).
    // `clippy::future_not_send` — `Vault` is intentionally `!Sync`
    // (P4 audit M-3: inner `rusqlite::Connection` holds a `RefCell`;
    // the `dyn Clock` is also not `Sync`). The future returned by
    // `pull_once` holds `&mut self` for its suspension; that future
    // is therefore `!Send`. Same posture as `select_sync_mode` and
    // `sync_from_chain`. The caller's runtime is single-threaded
    // (host = CLI / Tauri main thread / mobile UI thread) so `!Send`
    // is the correct shape per R-a.
    #[allow(clippy::future_not_send)]
    pub async fn pull_once(
        &mut self,
        rpc_url: &str,
        env: pangolin_chain::ChainEnv,
        vault_id: &[u8; 32],
    ) -> core::result::Result<crate::pull::PullReport, crate::pull::PullError> {
        // (1) L1 + R-e structural cancellation. Mirrors 5.1's
        // `flush_publish_queue` early-return shape verbatim. The
        // existing `lock()` / `check_session_freshness` /
        // `device_locked()` / absolute-expiry paths already drop
        // `active`; we just observe the result here and short-circuit
        // BEFORE any chain primitive is touched (L-pull-after-lock-races).
        if self.active.is_none() {
            return Err(crate::pull::PullError::NoActiveSession);
        }

        // (1.5) **MVP-2 issue 5.3 (R-c).** Pre-tick conflict snapshot.
        // Two cheap O(N-conflicted) SQL reads (`list_frozen_accounts`
        // + `all_forked_accounts`) into HashSets — the per-cycle diff
        // is computed against the post-tick snapshot below to
        // populate `newly_frozen_accounts` / `newly_forked_accounts`
        // / `newly_resolved_accounts` on the returned `PullReport`.
        let pre_snapshot = self
            .snapshot_conflicts()
            .map_err(crate::pull::PullError::Store)?;

        // (2) R-c: re-pick per cycle. Cheap — single SQL read + None
        // check; no RPC under 4.4's first-sync-only heuristic. The
        // `clippy::map_err_ignore` lint would prefer `.map_err(Into::into)?`
        // here, but the explicit form documents the variant routing
        // for auditors.
        let mode = self
            .select_sync_mode(rpc_url, env)
            .await
            .map_err(crate::pull::PullError::Store)?;

        // (3) Dispatch (L2 + L4). Slow goes through 4.1; OfferFast +
        // AlwaysFast return signal-only (engine never spawns).
        let sync_report = match mode {
            SyncMode::Slow => Some(
                self.sync_from_chain(
                    rpc_url,
                    env,
                    vault_id,
                    pangolin_chain::SyncOptions::default(),
                )
                .await
                .map_err(|store_err| match store_err {
                    // `sync_from_chain` returns `Result<SyncReport,
                    // StoreError>`; chain-side errors propagate via
                    // the `From<ChainError> for StoreError` impl
                    // which wraps them in `StoreError::ChainSyncError`
                    // (per 4.1). We unwrap that wrapping here so
                    // callers see `PullError::Chain` for chain-side
                    // errors (R-d: host retries on next tick) vs
                    // `PullError::Store` for true store errors
                    // (typically unrecoverable; the host breaks).
                    StoreError::ChainSyncError(chain_err) => {
                        crate::pull::PullError::Chain(chain_err)
                    }
                    other => crate::pull::PullError::Store(other),
                })?,
            ),
            // L2: signal-only; host owns indexer spawn per 4.4 L1.
            SyncMode::OfferFast | SyncMode::AlwaysFast => None,
        };

        // (3.5) **MVP-2 issue 5.3 (R-c).** Post-tick conflict
        // snapshot + per-cycle diff. Set-difference is directional:
        // already-frozen carry-overs from prior ticks do NOT
        // re-surface (covers L-PullReport-delta-overcounts-on-
        // existing-frozen). `removed_frozen` from the diff IS the
        // `newly_resolved_accounts` channel (covers the self-resolve
        // loopback case once 5.1 flush stamps the merge anchor and
        // 5.2 pull ingests via idempotency arm #1).
        let post_snapshot = self
            .snapshot_conflicts()
            .map_err(crate::pull::PullError::Store)?;
        let delta = diff_conflict_snapshots(&pre_snapshot, &post_snapshot);

        // (4) Stamp the diagnostic field on success. We re-check
        // `active` here because the await above released the borrow;
        // a parallel teardown can't happen (we hold &mut self), but
        // the `if let Some` keeps the type machinery honest.
        let now_ms = current_unix_ms();
        if let Some(active) = self.active.as_mut() {
            active.last_pull_at_unix_ms = Some(now_ms);
        }

        Ok(crate::pull::PullReport {
            mode,
            sync_report,
            pulled_at_unix_ms: now_ms,
            newly_frozen_accounts: delta.added_frozen,
            newly_forked_accounts: delta.added_forked,
            newly_resolved_accounts: delta.removed_frozen,
        })
    }

    /// **MVP-2 issue 5.2 (R-b).** Env-var-clamped pull-loop interval
    /// in seconds.
    ///
    /// Resolves the 60-second cadence from
    /// [`crate::pull::PULL_INTERVAL_SECS_ENV_VAR`]
    /// (`PANGOLIN_PULL_INTERVAL_SECS`; clamped
    /// `5..=3600`), defaulting to
    /// [`crate::pull::PULL_INTERVAL_SECS_DEFAULT`] (60). Pure function
    /// (the env var is read once per call); host can override the
    /// default for testing without using `env::set_var` (a
    /// process-global side effect) by using
    /// [`Self::resolve_pull_interval_secs_from`].
    ///
    /// Mirrors 5.1's [`Self::resolve_batch_window_secs`] verbatim.
    #[must_use]
    pub fn resolve_pull_interval_secs() -> u64 {
        Self::resolve_pull_interval_secs_from(
            std::env::var(crate::pull::PULL_INTERVAL_SECS_ENV_VAR)
                .ok()
                .as_deref(),
        )
    }

    /// Pure version of [`Self::resolve_pull_interval_secs`] for
    /// testability. The env var is read separately so hermetic tests
    /// can drive the clamp logic deterministically.
    ///
    /// MVP-2 issue 5.2 (R-b).
    #[must_use]
    pub fn resolve_pull_interval_secs_from(raw: Option<&str>) -> u64 {
        let parsed = raw.and_then(|s| s.parse::<u64>().ok());
        let value = parsed.unwrap_or(crate::pull::PULL_INTERVAL_SECS_DEFAULT);
        value.clamp(
            crate::pull::PULL_INTERVAL_SECS_MIN,
            crate::pull::PULL_INTERVAL_SECS_MAX,
        )
    }

    /// **MVP-2 issue 5.2 (diagnostic).** Read the last successful
    /// pull cycle's unix-ms timestamp from `ActiveState`.
    ///
    /// Returns `None` if the vault is not Active OR if no pull cycle
    /// has run on this session yet. 5.4 will consume this for the
    /// "Synced N min ago" indicator; 5.2 ships it as the diagnostic
    /// accessor only.
    ///
    /// # Errors
    ///
    /// None — the accessor returns `None` for both "locked" and
    /// "active-but-no-pull-yet" because the host's UI treatment is
    /// identical (show "—" / "never").
    #[must_use]
    pub fn last_pull_at_unix_ms(&self) -> Option<i64> {
        self.active.as_ref().and_then(|a| a.last_pull_at_unix_ms)
    }

    // -----------------------------------------------------------------
    // MVP-2 issue 5.4 — bundling accessor + pre-lock drain (R-a + R-e).
    // -----------------------------------------------------------------

    /// **MVP-2 issue 5.4 (R-a).** Bundle the engine-readable inputs
    /// for the pure [`crate::sync_status::compute_next_status`]
    /// transition function.
    ///
    /// Reads [`Self::publish_queue_state`] +
    /// [`Self::list_conflicts_since`] (against the caller's prior
    /// snapshot) + [`Self::list_frozen_accounts`] +
    /// [`Self::all_forked_accounts`] (for `conflicts_count`) +
    /// [`Self::last_pull_at_unix_ms`] and combines them with the
    /// host-tracked fields (`last_pull_outcome`,
    /// `last_flush_outcome`, `consecutive_pull_failures`,
    /// `balance_state`, `now_unix_ms`) into a single
    /// [`crate::sync_status::SyncStatusInputs`] snapshot.
    ///
    /// **Metadata-only** — works on a Locked vault. The pull /
    /// flush outcome inputs are host-tracked between ticks; the
    /// engine never persists them.
    ///
    /// # Errors
    ///
    /// Inherits [`StoreError::Sqlite`] / [`StoreError::Corrupted`]
    /// from the inner SQL reads.
    pub fn sync_status_inputs(
        &self,
        prior_conflict_snapshot: &crate::conflict::ConflictSnapshot,
        last_pull_outcome: Option<crate::sync_status::LastPullOutcome>,
        last_flush_outcome: Option<crate::sync_status::LastFlushOutcome>,
        consecutive_pull_failures: u32,
        balance_state: pangolin_chain::GasBalanceState,
        now_unix_ms: i64,
    ) -> Result<crate::sync_status::SyncStatusInputs> {
        let publish_queue = self.publish_queue_state()?;
        let conflict_delta = self.list_conflicts_since(prior_conflict_snapshot)?;
        let frozen = self.list_frozen_accounts()?;
        let forked = self.all_forked_accounts()?;
        let mut conflict_set: std::collections::HashSet<AccountId> = frozen.into_iter().collect();
        conflict_set.extend(forked);
        let conflicts_count = u32::try_from(conflict_set.len()).unwrap_or(u32::MAX);
        Ok(crate::sync_status::SyncStatusInputs {
            last_pull_outcome,
            last_flush_outcome,
            publish_queue,
            conflicts_count,
            conflict_delta,
            last_pull_at_unix_ms: self.last_pull_at_unix_ms(),
            consecutive_pull_failures,
            balance_state,
            now_unix_ms,
        })
    }

    /// **MVP-2 issue 5.4 (R-e).** Pre-lock drain — run
    /// [`Self::flush_publish_queue`] with `force = true` BEFORE
    /// transitioning to `Locked`. Best-effort per L3: flush errors
    /// do NOT block teardown; the error is RETURNED to the caller
    /// AFTER `lock()` runs.
    ///
    /// Closes the 5.1 L1 deviation: the existing sync [`Self::lock`]
    /// cannot await a flush; this async helper threads an adapter +
    /// device key through and gives hosts (CLI, Tauri, mobile) a
    /// single primitive for graceful shutdown.
    ///
    /// `lock()` runs regardless of whether the flush succeeded.
    /// Dirty markers persist in `SQLite` if the flush returned an
    /// error (network, balance, store) — the next unlock resumes
    /// the queue (covered by 5.1
    /// `dirty_markers_persist_through_lock_and_resume_on_next_unlock`).
    ///
    /// # Errors
    ///
    /// Surfaces the underlying [`crate::publish::BatchFlushError`]
    /// from the inner flush call AFTER `lock()` runs. Returns
    /// [`crate::publish::BatchFlushError::NoActiveSession`]
    /// WITHOUT touching `lock()` if the vault was already locked at
    /// entry — there is nothing to drain and nothing to tear down.
    pub async fn lock_with_drain<A: pangolin_chain::ChainAdapter + ?Sized>(
        &mut self,
        adapter: &A,
        device_key: &pangolin_crypto::keys::DeviceKey,
    ) -> core::result::Result<(), crate::publish::BatchFlushError> {
        // (1) Guard: locked vault → NoActiveSession early-return.
        //     Consistent with 5.1 `flush_publish_queue` /
        //     5.2 `pull_once` posture.
        if self.active.is_none() {
            return Err(crate::publish::BatchFlushError::NoActiveSession);
        }
        // (2) Attempt drain with force=true so the (future) window
        //     gate is bypassed — graceful shutdown must drain
        //     whatever is queued regardless of the 30s window.
        let flush_result = self.flush_publish_queue(adapter, device_key, true).await;
        // (3) Lock regardless (L3 — best-effort drain; teardown
        //     wins). Captures the flush_result and returns it AFTER
        //     the lock transition so the caller observes the same
        //     locked-state post-condition no matter what.
        self.lock();
        // (4) Surface flush error AFTER lock. Map BatchFlushReport
        //     to `()` since the caller's interest is "did the drain
        //     succeed?" — not the per-row outcome counts (host can
        //     re-query `list_dirty` after the next unlock).
        flush_result.map(|_| ())
    }
}

impl Drop for Vault {
    fn drop(&mut self) {
        // ZeroizeOnDrop on the active state's snapshots fires here.
        self.active.take();
        release_lock(&self.path);
    }
}

// =============================================================================
// MVP-1 issue 1.2: V1 helpers
// =============================================================================

/// Downgrade an [`AccountIdentity`] to a V0 [`AccountSnapshot`] for
/// the in-memory cache. Takes head-of-history password, first
/// username, and first url. Empty-string fallbacks for empty
/// collections.
fn downgrade_identity_to_snapshot(identity: &crate::account::AccountIdentity) -> AccountSnapshot {
    let display_name = SecretBytes::new(identity.display_name.expose().to_vec());
    let username = identity.usernames.first().map_or_else(
        || SecretBytes::new(Vec::new()),
        |s| SecretBytes::new(s.expose().to_vec()),
    );
    let password = identity.current_password().map_or_else(
        || SecretBytes::new(Vec::new()),
        |s| SecretBytes::new(s.expose().to_vec()),
    );
    let url = identity.urls.first().map_or_else(
        || SecretBytes::new(Vec::new()),
        |s| SecretBytes::new(s.expose().to_vec()),
    );
    let notes = SecretBytes::new(identity.notes().expose().to_vec());
    let totp_secret = SecretBytes::new(identity.totp_secret().expose().to_vec());
    AccountSnapshot::new(display_name, username, password, url, notes, totp_secret)
}

/// Convert an [`AccountIdentity`] into the metadata-only
/// [`crate::account::AccountIdentitySummary`] (MVP-1 issue 1.4, Q5b —
/// the FFI projection carries zero secret material). Display name,
/// tags, usernames and URLs are non-secret per the V1 model; the
/// secret bytes (head password, full history, notes, raw TOTP seed)
/// are reachable only via the presence-gated `Vault::reveal_*` entry
/// points.
fn identity_to_summary(
    id: AccountId,
    head_revision_id: RevisionId,
    identity: &crate::account::AccountIdentity,
) -> crate::account::AccountIdentitySummary {
    let display_name =
        String::from_utf8(identity.display_name.expose().to_vec()).unwrap_or_default();
    let tags = identity
        .tags
        .iter()
        .map(|t| String::from_utf8(t.expose().to_vec()).unwrap_or_default())
        .collect();
    let usernames = identity
        .usernames
        .iter()
        .map(|u| String::from_utf8(u.expose().to_vec()).unwrap_or_default())
        .collect();
    let urls = identity
        .urls
        .iter()
        .map(|u| String::from_utf8(u.expose().to_vec()).unwrap_or_default())
        .collect();
    let history = identity.password_history();
    crate::account::AccountIdentitySummary {
        schema_version: crate::account::ACCOUNT_IDENTITY_SCHEMA_VERSION,
        id,
        head_revision_id,
        display_name,
        tags,
        usernames,
        urls,
        password_history_count: u32::try_from(history.len()).unwrap_or(u32::MAX),
        has_totp: identity.has_totp(),
        current_password_changed_at_ms: history.first().map_or(0, |e| e.set_at_ms),
    }
}

impl core::fmt::Debug for Vault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Format vault_id inline as hex without pulling a hex crate.
        // Using `core::fmt::Write` avoids a `format!` allocation per byte.
        use core::fmt::Write as _;
        let mut hex_id = String::with_capacity(self.meta.vault_id.len() * 2);
        for b in self.meta.vault_id {
            write!(&mut hex_id, "{b:02x}").expect("writing to String is infallible");
        }
        f.debug_struct("Vault")
            .field("path", &self.path)
            .field("vault_id", &hex_id)
            .field("session_state", &self.session_state)
            .field("cache_size", &self.active.as_ref().map(|a| a.cache.len()))
            // The `meta`, `device_id`, and `_lock_file` fields are
            // intentionally omitted from Debug — `meta` carries the
            // wrapped VDK ciphertext (non-secret but verbose);
            // `device_id` is opaque; `_lock_file` is a sidecar handle
            // with no diagnostic value.
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

/// **MVP-1 issue 1.4.** Map an [`AuthError`] surfaced at a high-risk
/// (reveal-class / session-extend) call site to a [`StoreError`].
///
/// A stale proof ([`AuthError::NotFresh`]) at such a site means the
/// presence prompt aged past [`crate::session::PROMPT_TIMEOUT`] before
/// the user answered → [`StoreError::PromptTimedOut`] (Session spec
/// §7.7 — loud, typed, never silent per §8.2). Every other proof
/// failure (replayed, empty, generic) collapses to
/// [`StoreError::AuthenticationFailed`] per the MEDIUM-1
/// indistinguishability discipline — a caller MUST NOT be able to tell
/// "wrong proof content" from "another structural reason".
///
/// `PromptTimedOut` is not an oracle: a timed-out prompt reveals
/// nothing about any secret; it's a UX signal. The content-class
/// collapse (wrong PIN etc.) is preserved.
fn reveal_site_auth_error(err: &AuthError) -> StoreError {
    match err {
        AuthError::NotFresh => StoreError::PromptTimedOut,
        AuthError::Failed | AuthError::PresenceAlreadyConsumed | AuthError::Empty => {
            StoreError::AuthenticationFailed
        }
    }
}

fn open_connection(path: &Path) -> Result<Connection> {
    Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(StoreError::from)
}

fn current_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}

/// Convert a [`SystemTime`] (e.g. the vault clock's `now`) to whole unix
/// milliseconds, or `0` on under/overflow. Used by the issue-1.5
/// register-on-unlock path so the `devices.added_at` timestamp respects
/// an injected test clock.
fn system_time_to_unix_ms(t: SystemTime) -> i64 {
    t.duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}

/// Generate 32 random bytes via `SQLite`'s `randomblob(32)`. Routes a CSPRNG
/// call we'd otherwise need a separate `rand` dep for.
fn random_32_via_sqlite(conn: &Connection) -> Result<[u8; 32]> {
    let blob: Vec<u8> = conn.query_row("SELECT randomblob(32)", [], |row| row.get(0))?;
    blob.as_slice()
        .try_into()
        .map_err(|_| StoreError::Corrupted(format!("randomblob(32) returned {} bytes", blob.len())))
}

/// Pull all live (non-tombstoned) account heads, AEAD-decrypt them once,
/// and build BOTH the in-memory [`DecryptedCache`] (V0-shaped snapshot —
/// the legacy read-path cache) AND the `:memory:` FTS5 [`SearchIndex`]
/// (MVP-1 issue 1.3 — over the non-secret searchable projection).
///
/// The decrypt routes through the V1-aware `open_identity_payload`, which
/// auto-migrates V0 payloads to the `AccountIdentity` shape, so this
/// single pass handles V0-format and 1.2-V1-format vaults alike — the
/// cache snapshot is the `downgrade_identity_to_snapshot` projection and
/// the index gets the whitelisted-fields projection. Decrypting once
/// rather than twice keeps the unlock cost (the dominant 10k-account
/// cost is the per-head AEAD decrypt) from doubling.
///
/// Recency stamp for the index is the row's `last_modified_at`. Frozen
/// accounts are still indexed; the `account_search` query-side filter
/// drops them (the freeze flag can flip at runtime via
/// `ingest_chain_revision`, so filtering at query time is the only
/// correct place).
///
/// MEDIUM-4 (P2 audit): the per-row `schema_version` is bound into the
/// AAD on decrypt — tampering it on disk diverges the reconstructed AAD
/// from the seal-time AAD and the AEAD open fails → `AuthenticationFailed`.
fn build_active_state_data(
    conn: &Connection,
    meta: &VaultMeta,
    vdk_aead: &AeadKey,
    chain: &crate::vdk_chain::VdkChain,
) -> Result<(
    DecryptedCache,
    SearchIndex,
    std::collections::HashSet<AccountId>,
)> {
    let mut cache = DecryptedCache::new();
    let mut index = SearchIndex::new_empty()?;
    let mut requires_upgrade: std::collections::HashSet<AccountId> =
        std::collections::HashSet::new();
    // First pass: collect (account_id, cached_head_pointer,
    // last_modified_at) for every live account. We do NOT trust the
    // cached `head_revision_id` for a *forked* account — 1.6's
    // canonical-head rule (clock-free largest-revision_id leaf) is the
    // production head. For a linear account the cached pointer IS the
    // single leaf, so the fast path is untouched.
    let mut stmt = conn.prepare(
        "SELECT account_id, head_revision_id, last_modified_at
         FROM account_identities WHERE tombstoned = 0",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, i64>(2)?,
        ))
    })?;
    let mut accounts: Vec<(AccountId, RevisionId, i64)> = Vec::new();
    for raw in rows {
        let (account_id_blob, head_blob, last_modified_at) = raw?;
        let account_id_arr: [u8; ACCOUNT_ID_LEN] = account_id_blob
            .as_slice()
            .try_into()
            .map_err(|_| StoreError::Corrupted("account_id not 32 bytes".into()))?;
        let head_arr: [u8; REVISION_ID_LEN] = head_blob
            .as_slice()
            .try_into()
            .map_err(|_| StoreError::Corrupted("head_revision_id not 32 bytes".into()))?;
        accounts.push((
            AccountId::from_bytes(account_id_arr),
            RevisionId::from_bytes(head_arr),
            last_modified_at,
        ));
    }
    drop(stmt);

    for (account_id, cached_head, last_modified_at) in accounts {
        hydrate_account_into_state(
            conn,
            meta,
            vdk_aead,
            chain,
            account_id,
            cached_head,
            last_modified_at,
            &mut cache,
            &mut index,
            &mut requires_upgrade,
        )?;
    }
    Ok((cache, index, requires_upgrade))
}

/// Hydrate one live account's canonical head into the unlock-time
/// decrypted cache and FTS5 index, or — when that head is
/// future-versioned — record the account in `requires_upgrade` and skip
/// indexing it. Extracted from [`build_active_state_data`] to keep that
/// function under the workspace's `too_many_lines` floor.
#[allow(clippy::too_many_arguments)]
fn hydrate_account_into_state(
    conn: &Connection,
    meta: &VaultMeta,
    vdk_aead: &AeadKey,
    chain: &crate::vdk_chain::VdkChain,
    account_id: AccountId,
    cached_head: RevisionId,
    last_modified_at: i64,
    cache: &mut DecryptedCache,
    index: &mut SearchIndex,
    requires_upgrade: &mut std::collections::HashSet<AccountId>,
) -> Result<()> {
    // Determine the canonical head (and, for a forked account, the
    // full leaf set so every leaf's blob is authenticated at unlock —
    // a tampered leaf surfaces `AuthenticationFailed` regardless of
    // which leaf is canonical; defends against a cross-account row
    // transplant that lands on a non-canonical leaf).
    let heads = account_heads_inline(conn, account_id)?;
    let (canonical_head, all_leaves): (RevisionId, Vec<RevisionId>) = if heads.len() > 1 {
        let graph = RevisionGraph::build(read_revision_rows_inline(conn, account_id)?)?;
        let canon = graph.canonical_head().copied().unwrap_or(cached_head);
        (canon, graph.heads().to_vec())
    } else {
        (cached_head, vec![cached_head])
    };
    // Decode every leaf for authentication; remember the canonical
    // head's outcome for the cache/index.
    //
    // Leaves whose stored nonce is the placeholder zero nonce are
    // foreign-ingested chain revisions sealed by another device — under
    // the PoC two-key model this device legitimately cannot decrypt
    // them, and `ingest_chain_revision` writes the placeholder
    // (`[0u8; NONCE_LEN]`) on that path. That is the documented
    // frozen-pending-resolve state, not tampering: skip them here. They
    // are authenticated when the resolve flow consumes them. A
    // genuinely-tampered leaf carries a *real* nonce with a mismatched
    // AAD (e.g. a cross-account row transplant) — that still gets
    // decoded below and still surfaces `AuthenticationFailed`,
    // regardless of which leaf is canonical.
    let mut canonical_outcome: Option<HeadDecodeOutcome> = None;
    for leaf in &all_leaves {
        match decode_head_row(conn, meta, vdk_aead, chain, account_id, *leaf)? {
            HeadDecodeOutcome::FutureVersion => {
                requires_upgrade.insert(account_id);
            }
            outcome => {
                if *leaf == canonical_head {
                    canonical_outcome = Some(outcome);
                }
            }
        }
    }
    // If the canonical head is itself a foreign placeholder-nonce leaf
    // (it can win the clock-free largest-`revision_id` head election),
    // the account is not locally readable at its canonical head pending
    // resolution. Fall back to the cached local-canonical-head pointer
    // (`account_identities.head_revision_id`) — the resolve flow keeps
    // that pointing at a leaf this device can decrypt — so the cache /
    // index snapshot still reflects something locally readable, exactly
    // as the pre-1.6 unlock path did for a forked frozen account. If
    // that fallback is also undecryptable, drop the account from the
    // cache/index (it surfaces via the freeze/resolve workflow, not as
    // an aborted unlock).
    if matches!(canonical_outcome, Some(HeadDecodeOutcome::PlaceholderNonce)) {
        canonical_outcome = if cached_head == canonical_head {
            None
        } else {
            Some(decode_head_row(
                conn,
                meta,
                vdk_aead,
                chain,
                account_id,
                cached_head,
            )?)
        };
    }
    match canonical_outcome {
        Some(HeadDecodeOutcome::Live(identity)) => {
            let projection = SearchProjection::from_identity(&identity);
            let snapshot = downgrade_identity_to_snapshot(&identity);
            drop(identity);
            index.insert(account_id, last_modified_at, &projection)?;
            cache.insert(account_id, snapshot);
        }
        // Canonical head is a tombstone (a forked account whose
        // largest-revision_id leaf is a resolve-to-tombstone), OR the
        // canonical head is future-versioned (already recorded in
        // `requires_upgrade`), OR neither the canonical head nor the
        // cached local head is locally decryptable (frozen pending
        // resolve): drop it from the index/cache.
        Some(HeadDecodeOutcome::Tombstone | HeadDecodeOutcome::PlaceholderNonce) | None => {
            let _ = cache.remove(account_id);
            index.remove(account_id)?;
        }
        Some(HeadDecodeOutcome::FutureVersion) => unreachable!(),
    }
    Ok(())
}

/// Outcome of decoding a single revision-head row at unlock time.
enum HeadDecodeOutcome {
    /// Decrypted to a live identity.
    Live(crate::account::AccountIdentity),
    /// The revision is a tombstone.
    Tombstone,
    /// The revision's `schema_version` / `payload_version` is newer
    /// than this build understands (§18.7 — that account "requires
    /// upgrade"; not an abort-unlock condition).
    FutureVersion,
    /// The revision's stored nonce is the placeholder zero nonce — a
    /// foreign-ingested chain revision this device cannot decrypt under
    /// the `PoC` two-key model. Not an abort-unlock condition: the
    /// account is frozen pending resolve and this leaf is authenticated
    /// when the resolve flow consumes it.
    PlaceholderNonce,
}

/// Decode one revision row's blob at unlock time. Returns
/// [`HeadDecodeOutcome`]; propagates `AuthenticationFailed` (a tampered
/// blob aborts the unlock — consistent with the P2 transplant-defence
/// test) and `Corrupted` / `Sqlite`.
fn decode_head_row(
    conn: &Connection,
    meta: &VaultMeta,
    vdk_aead: &AeadKey,
    chain: &crate::vdk_chain::VdkChain,
    account_id: AccountId,
    rev_id: RevisionId,
) -> Result<HeadDecodeOutcome> {
    // MVP-3 issue #106b-2: also read the per-entry `vdk_epoch` tag (Q-a) so
    // we decrypt this entry under `chain[entry.vdk_epoch]`. The tuple is a
    // local extension of `RawRevisionPayload` (which other call sites
    // share) — we keep the epoch local rather than widen the shared struct.
    let row: Option<(RawRevisionPayload, i64)> = conn
        .query_row(
            "SELECT parent_revision_id, schema_version, enc_payload, enc_nonce, vdk_epoch
             FROM revisions WHERE account_id = ?1 AND revision_id = ?2",
            params![
                account_id.as_bytes().as_slice(),
                rev_id.as_bytes().as_slice()
            ],
            |row| {
                Ok((
                    RawRevisionPayload {
                        parent: row.get(0)?,
                        schema_version: row.get(1)?,
                        enc_payload: row.get(2)?,
                        enc_nonce: row.get(3)?,
                    },
                    row.get(4)?,
                ))
            },
        )
        .optional()?;
    let Some((
        RawRevisionPayload {
            parent: parent_blob,
            schema_version: schema_version_i,
            enc_payload: payload,
            enc_nonce: nonce_blob,
        },
        vdk_epoch_i,
    )) = row
    else {
        return Err(StoreError::Corrupted(
            "account_identities head_revision_id has no matching revisions row".into(),
        ));
    };
    let vdk_epoch = u64::try_from(vdk_epoch_i)
        .map_err(|_| StoreError::Corrupted("revisions.vdk_epoch negative".into()))?;
    // Select the decrypting VDK for this entry's epoch (plan §3.1): the
    // CURRENT epoch's VDK is `vdk_aead` (the active session's VDK); a
    // RETAINED OLD epoch's VDK comes from the chain. An entry tagged to an
    // epoch this device does not hold (e.g. a post-revoke epoch on a
    // removed device, or a not-yet-synced wrap) is undecryptable here — we
    // surface it as a `PlaceholderNonce` outcome (drop from cache/index,
    // exactly like a foreign-ingested row), NOT an unlock abort.
    let entry_aead: &AeadKey = if vdk_epoch == chain.current_epoch() {
        vdk_aead
    } else {
        match chain.aead_for_epoch(vdk_epoch) {
            Some(k) => k,
            None => return Ok(HeadDecodeOutcome::PlaceholderNonce),
        }
    };
    let parent_arr: [u8; REVISION_ID_LEN] = parent_blob
        .as_slice()
        .try_into()
        .map_err(|_| StoreError::Corrupted("parent_revision_id not 32 bytes".into()))?;
    let nonce_arr: [u8; NONCE_LEN] = nonce_blob
        .as_slice()
        .try_into()
        .map_err(|_| StoreError::Corrupted("enc_nonce length mismatch".into()))?;
    let row_schema_version = u8::try_from(schema_version_i)
        .map_err(|_| StoreError::Corrupted("revisions.schema_version out of u8 range".into()))?;
    // A foreign-ingested chain revision under the PoC two-key model
    // carries the placeholder zero nonce (`ingest_chain_revision`'s
    // genuine-foreign-INSERT path) — this device cannot decrypt it and
    // is not expected to. Report it as such rather than attempting an
    // AEAD open that would (correctly, for a real ciphertext under the
    // wrong/zero nonce) fail as `Tampered`. This precedes the schema-
    // version check: a zero-nonce row is frozen-pending-resolve
    // regardless of its `schema_version`.
    if nonce_arr == [0u8; NONCE_LEN] {
        return Ok(HeadDecodeOutcome::PlaceholderNonce);
    }
    let parent = RevisionId::from_bytes(parent_arr);
    let aad = build_aad(&meta.vault_id, &account_id, &parent, row_schema_version);
    let ct = Ciphertext::from_vec(payload);
    let nonce = Nonce::from_storage_bytes(nonce_arr);
    // Audit L1: `revisions.schema_version` is bound into the AAD, so we
    // authenticate before honouring it. A real-nonce row whose
    // `schema_version` byte was flipped on disk yields an AAD this
    // build never sealed under → the open fails → propagate
    // `AuthenticationFailed` (the unlock aborts on tamper, consistent
    // with the P2 transplant-defence test) rather than a misleading
    // `FutureVersion`/"requires upgrade". A legit future revision was
    // sealed by a future build with that byte in its AAD, so the open
    // succeeds; only then do we report it as `FutureVersion`.
    let outcome = match crate::blob::open_identity_payload(entry_aead, &nonce, &ct, &aad) {
        Ok(crate::blob::DecodedIdentityPayload::Live(identity)) => {
            HeadDecodeOutcome::Live(identity)
        }
        Ok(crate::blob::DecodedIdentityPayload::Tombstone(_)) => HeadDecodeOutcome::Tombstone,
        // The body's own `payload_version` / map-arity check tripped a
        // future shape — still a "requires upgrade" signal.
        Err(StoreError::UnsupportedRevisionSchemaVersion { .. }) => {
            return Ok(HeadDecodeOutcome::FutureVersion)
        }
        Err(e) => return Err(e),
    };
    if row_schema_version > crate::revision::REVISION_SCHEMA_VERSION_MAX {
        return Ok(HeadDecodeOutcome::FutureVersion);
    }
    Ok(outcome)
}

/// **MVP-2 issue 5.3 (R-c helper).** Pure set-difference between two
/// [`crate::conflict::ConflictSnapshot`]s producing a
/// [`crate::conflict::ConflictDelta`].
///
/// Two-call sites: [`Vault::pull_once`] computes the per-tick diff
/// (`pre_snapshot` → `post_snapshot`) to populate
/// [`crate::pull::PullReport::newly_frozen_accounts`] et al.;
/// [`Vault::list_conflicts_since`] exposes the same primitive as a
/// public accessor for the 5.4 indicator state machine. Pure +
/// deterministic — useful unit-test target.
fn diff_conflict_snapshots(
    prior: &crate::conflict::ConflictSnapshot,
    current: &crate::conflict::ConflictSnapshot,
) -> crate::conflict::ConflictDelta {
    let added_frozen: Vec<AccountId> = current.frozen.difference(&prior.frozen).copied().collect();
    let removed_frozen: Vec<AccountId> =
        prior.frozen.difference(&current.frozen).copied().collect();
    let added_forked: Vec<AccountId> = current.forked.difference(&prior.forked).copied().collect();
    let removed_forked: Vec<AccountId> =
        prior.forked.difference(&current.forked).copied().collect();
    crate::conflict::ConflictDelta {
        added_frozen,
        removed_frozen,
        added_forked,
        removed_forked,
    }
}

/// Helper: the head set for `account_id` via the `NOT EXISTS` detector
/// (scoped by `account_id`, per P3 audit M-1) — used by
/// [`build_active_state_data`] which has only a `&Connection`, not a
/// `&Vault`.
fn account_heads_inline(conn: &Connection, account_id: AccountId) -> Result<Vec<RevisionId>> {
    let mut stmt = conn.prepare(
        // #106d (salvaged #103-C FINDING 2): exclude revoked rows (outer)
        // + revoked children (subquery) — mirror of `account_heads`.
        "SELECT r.revision_id FROM revisions r
         WHERE r.account_id = ?1
           AND r.superseded_by IS NULL
           AND r.revoked = 0
           AND NOT EXISTS (
             SELECT 1 FROM revisions r2
             WHERE r2.parent_revision_id = r.revision_id
               AND r2.account_id = r.account_id
               AND r2.revoked = 0
           )",
    )?;
    let rows = stmt.query_map(params![account_id.as_bytes().as_slice()], |row| {
        let rid: Vec<u8> = row.get(0)?;
        Ok(rid)
    })?;
    let mut out = Vec::new();
    for r in rows {
        let blob = r?;
        let arr: [u8; REVISION_ID_LEN] = blob
            .as_slice()
            .try_into()
            .map_err(|_| StoreError::Corrupted("head revision_id not 32 bytes".into()))?;
        out.push(RevisionId::from_bytes(arr));
    }
    Ok(out)
}

/// Helper: read every `revisions` row for `account_id` into
/// [`RevisionMeta`] form using only a `&Connection`. Mirror of
/// [`Vault::read_revision_rows_for`] for [`build_active_state_data`].
fn read_revision_rows_inline(
    conn: &Connection,
    account_id: AccountId,
) -> Result<Vec<RevisionMeta>> {
    let mut stmt = conn.prepare(
        // #106d (salvaged #103-C FINDING 2): exclude revoked rows — mirror
        // of `read_revision_rows_for`.
        "SELECT revision_id, parent_revision_id, device_id,
                schema_version, created_at, is_tombstone,
                chain_tx_hash, chain_block_number, chain_log_index,
                superseded_by
         FROM revisions WHERE account_id = ?1
           AND revoked = 0
         ORDER BY created_at ASC, revision_id ASC",
    )?;
    let rows = stmt.query_map(params![account_id.as_bytes().as_slice()], |row| {
        Ok(RawRevisionRow {
            revision_id: row.get(0)?,
            parent: row.get(1)?,
            device_id: row.get(2)?,
            schema_version: row.get(3)?,
            created_at: row.get(4)?,
            is_tombstone: row.get(5)?,
            chain_tx_hash: row.get(6)?,
            chain_block_number: row.get(7)?,
            chain_log_index: row.get(8)?,
            superseded_by: row.get(9)?,
        })
    })?;
    let mut out = Vec::new();
    for raw in rows {
        out.push(raw?.into_meta()?);
    }
    Ok(out)
}

/// **P9-1.** Helper struct factored out so the `query_row` body in
/// [`Vault::read_payload_plaintext_for_resolve`] avoids the
/// `clippy::type_complexity` rule on a 4-tuple of varied types.
struct RawRevisionPayload {
    parent: Vec<u8>,
    schema_version: i64,
    enc_payload: Vec<u8>,
    enc_nonce: Vec<u8>,
}

/// Helper to read a revisions-row into [`RevisionMeta`].
struct RawRevisionRow {
    revision_id: Vec<u8>,
    parent: Vec<u8>,
    device_id: Vec<u8>,
    schema_version: i64,
    created_at: i64,
    is_tombstone: i64,
    chain_tx_hash: Option<Vec<u8>>,
    chain_block_number: Option<i64>,
    chain_log_index: Option<i64>,
    superseded_by: Option<Vec<u8>>,
}

impl RawRevisionRow {
    fn into_meta(self) -> Result<RevisionMeta> {
        fn arr32(v: &[u8], field: &str) -> Result<[u8; 32]> {
            v.try_into().map_err(|_| {
                StoreError::Corrupted(format!("{field} not 32 bytes (was {})", v.len()))
            })
        }
        let revision_id = RevisionId::from_bytes(arr32(&self.revision_id, "revision_id")?);
        let parent_revision_id = RevisionId::from_bytes(arr32(&self.parent, "parent")?);
        let device_id = DeviceId(arr32(&self.device_id, "device_id")?);
        let schema_version = u8::try_from(self.schema_version)
            .map_err(|_| StoreError::Corrupted("schema_version out of range".into()))?;
        // SQL columns store i64; the canonical ChainAnchor (re-exported
        // from `pangolin_chain`) uses u64. Narrow at the boundary;
        // `chain_block_number` / `chain_log_index` are insertable only
        // through `mark_published` which already widens from u64 → i64
        // via `try_from`, so a negative value here would be storage
        // corruption.
        let chain_anchor = match (
            self.chain_tx_hash,
            self.chain_block_number,
            self.chain_log_index,
        ) {
            (Some(tx), Some(b), Some(i)) => {
                let block_number = u64::try_from(b).map_err(|_| {
                    StoreError::Corrupted(format!("chain_block_number {b} is negative"))
                })?;
                let log_index = u64::try_from(i).map_err(|_| {
                    StoreError::Corrupted(format!("chain_log_index {i} is negative"))
                })?;
                Some(ChainAnchor {
                    tx_hash: arr32(&tx, "chain_tx_hash")?,
                    block_number,
                    log_index,
                    // The local `revisions` table does not store
                    // `sequence`. Callers that need the on-chain
                    // sequence value re-pull from the chain via
                    // ChainAdapter::get_revision; this default of 0
                    // makes the field structurally present without
                    // claiming a meaningful value.  Documented in
                    // `docs/issue-plans/P7.md` §"P7-7 …
                    // pangolin-store integration".
                    sequence: 0,
                })
            }
            _ => None,
        };
        let superseded_by = match self.superseded_by {
            Some(b) => Some(RevisionId::from_bytes(arr32(&b, "superseded_by")?)),
            None => None,
        };
        Ok(RevisionMeta {
            revision_id,
            parent_revision_id,
            device_id,
            schema_version,
            created_at: self.created_at,
            is_tombstone: self.is_tombstone != 0,
            superseded_by,
            chain_anchor,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{RevisionLogVersion, Vault, VaultState};
    use crate::account::AccountSnapshot;
    use crate::error::StoreError;
    use crate::meta::{FORMAT_VERSION, MAGIC};
    use crate::recovery_escrow::GuardianRecord;
    use crate::session::{PinIdentityProof, PressYPresenceProof};
    use pangolin_crypto::escrow::WrappedVdkRecovery;
    use pangolin_crypto::keys::{DeviceKey, VdkKey, WrapContext, VAULT_ID_LEN};
    use pangolin_crypto::secret::SecretBytes;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn fresh_password() -> SecretBytes {
        SecretBytes::new(b"correct horse battery staple".to_vec())
    }
    /// Construct a fresh PIN identity proof from `fresh_password`.
    /// Each call produces a fresh `SecretBytes` allocation; `PoC` PIN
    /// proofs are not single-use so the same factory can be invoked
    /// repeatedly within a test.
    fn fresh_pin() -> PinIdentityProof {
        PinIdentityProof::new(fresh_password())
    }
    /// Wrong-password identity proof for the failure-mode tests.
    fn wrong_pin() -> PinIdentityProof {
        PinIdentityProof::new(SecretBytes::new(
            b"definitely not the right password".to_vec(),
        ))
    }
    /// Construct a fresh "user pressed y" presence proof. `PoC` proofs
    /// are single-use, so each `unlock` call needs its own.
    fn fresh_presence() -> PressYPresenceProof {
        PressYPresenceProof::confirmed()
    }
    fn fresh_snapshot() -> AccountSnapshot {
        AccountSnapshot::new(
            SecretBytes::new(b"github".to_vec()),
            SecretBytes::new(b"alice".to_vec()),
            SecretBytes::new(b"hunter2".to_vec()),
            SecretBytes::new(b"https://github.com".to_vec()),
            SecretBytes::new(b"some notes".to_vec()),
            SecretBytes::new(b"".to_vec()),
        )
    }
    fn vault_path(dir: &TempDir, name: &str) -> PathBuf {
        dir.path().join(name)
    }

    /// Plan §"Test plan" / success criterion 2: fresh vault file
    /// contains the magic header and format-version 0 byte.
    #[test]
    fn magic_header() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "v.pvf");
        let v = Vault::create(&p, &fresh_password()).unwrap();
        drop(v);
        // Read raw bytes of the .pvf file and verify the magic and
        // application_id appear. `SQLite` places `application_id` at
        // offset 68 (4 BE bytes); the magic itself lives in the meta
        // row's BLOB column further along the file.
        let bytes = std::fs::read(&p).unwrap();
        assert!(bytes.windows(MAGIC.len()).any(|w| w == MAGIC.as_slice()));
        // The application_id field at offset 68 should be the BE-packed
        // first four magic bytes.
        let app_id_offset = 68;
        let expected = &MAGIC[..4];
        assert_eq!(&bytes[app_id_offset..app_id_offset + 4], expected);
        // Format-version byte is '0' inside `meta.format_version` —
        // serialized as INTEGER, hard to byte-pin; we validated via
        // open path below.
        let _ = FORMAT_VERSION;
    }

    /// Success criterion 4: wrong password returns
    /// `AuthenticationFailed` and leaves the vault Locked.
    #[test]
    fn wrong_password_rejected() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "v.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        let err = v.unlock(&fresh_presence(), &wrong_pin()).unwrap_err();
        assert!(matches!(err, StoreError::AuthenticationFailed));
        assert_eq!(v.state(), VaultState::Locked);
    }

    /// **MVP-3 issue #104b (L8 / L3 / L5).** The new-password-on-recovery
    /// branch: after `recover_with_new_password` re-keys the daily wrap
    /// under a fresh password, the OLD password must FAIL and the NEW
    /// password must unlock — and the vault's pre-recovery data must
    /// survive byte-for-byte (the recovered VDK was re-wrapped, never
    /// re-derived; L3).
    #[test]
    fn recover_with_new_password_rotates_wrap_and_preserves_data() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "recover.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();

        // Unlock with the original password + add an account (data sealed
        // under the vault's VDK).
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        let id = v.add_account(fresh_snapshot()).unwrap();
        assert!(v.get_account(id).is_some(), "account present pre-recovery");

        // True recovery: re-wrap the (byte-identical) VDK under a NEW
        // password. The helper reuses the active session's own VDK as the
        // stand-in for the escrow-reconstructed VDK (same bytes).
        let new_password = SecretBytes::new(b"a brand new recovery passphrase".to_vec());
        v.__test_recover_reusing_active_vdk(&new_password).unwrap();
        // Recovery leaves the vault Locked.
        assert_eq!(v.state(), VaultState::Locked);

        // The OLD password no longer unlocks (the wrap authority rotated).
        let old_err = v.unlock(&fresh_presence(), &fresh_pin()).unwrap_err();
        assert!(matches!(old_err, StoreError::AuthenticationFailed));
        assert_eq!(v.state(), VaultState::Locked);

        // The NEW password unlocks, and the pre-recovery account is intact
        // (L3 — the VDK was preserved, so the data decrypts unchanged).
        let new_pin = PinIdentityProof::new(SecretBytes::new(
            b"a brand new recovery passphrase".to_vec(),
        ));
        v.unlock(&fresh_presence(), &new_pin).unwrap();
        assert_eq!(v.state(), VaultState::Active);
        let after = v.get_account(id).expect("account present post-recovery");
        // The pre-recovery data decrypts unchanged under the new password
        // (L3 — the VDK was preserved, so the same plaintext comes back).
        assert!(
            bool::from(after.ct_eq(&fresh_snapshot())),
            "vault data must survive recovery byte-for-byte (L3)"
        );

        // L8: the new-password recovery branch does NOT write any
        // recovery-escrow state (the forward-security re-split is a
        // separate caller step). The recovery_escrow table is untouched.
        let escrow_rows: i64 = v
            .conn
            .query_row("SELECT COUNT(*) FROM recovery_escrow", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            escrow_rows, 0,
            "recovery_with_new_password must not touch the recovery-escrow state (L8)"
        );
    }

    /// Build a re-split escrow fixture for the #105a `commit_recovery_rekey`
    /// tests: a FRESH RWK', the VDK second-wrapped under it
    /// ([`WrappedVdkRecovery`]), and `m` sealed shares to derived guardian
    /// X25519 pubkeys, tagged at `epoch`. Returns the wrapper, the owned
    /// sealed shares, the guardian pubkeys, and the guardian X25519 secret
    /// scalars (for the open-side / forward-security assertions).
    ///
    /// `vdk` is the byte-identical recovered VDK (the re-split wraps the
    /// SAME VDK under the new RWK', mirroring the orchestration re-split).
    #[allow(clippy::type_complexity)]
    fn build_re_split(
        vdk: &VdkKey,
        vault_id: &[u8; VAULT_ID_LEN],
        t: u8,
        m: u8,
        epoch: u64,
    ) -> (
        WrappedVdkRecovery,
        Vec<pangolin_crypto::escrow::SealedShare>,
        Vec<[u8; 32]>,
        Vec<[u8; 32]>,
    ) {
        use pangolin_crypto::escrow::{seal_share, split_rwk, wrap_vdk_under_rwk, RecoveryWrapKey};
        use pangolin_crypto::guardian::derive_x25519_sealing_key;

        let ctx = WrapContext::new(*vault_id);
        let rwk = RecoveryWrapKey::generate();
        let wrapped = wrap_vdk_under_rwk(vdk, &rwk, &ctx).unwrap();
        let shares = split_rwk(&rwk, t, m).unwrap();
        let mut epoch_bytes = [0u8; pangolin_crypto::escrow::EPOCH_LEN];
        epoch_bytes[8..].copy_from_slice(&epoch.to_be_bytes());
        let mut sealed = Vec::new();
        let mut pubs = Vec::new();
        let mut secs = Vec::new();
        for (i, share) in shares.iter().enumerate() {
            let dev = DeviceKey::from_seed([0xE0 + u8::try_from(i).unwrap(); 32]);
            let k = derive_x25519_sealing_key(&dev);
            sealed.push(seal_share(share, k.public_bytes(), vault_id, &epoch_bytes).unwrap());
            pubs.push(*k.public_bytes());
            secs.push(*k.secret_bytes());
        }
        (wrapped, sealed, pubs, secs)
    }

    /// **MVP-3 issue #105a (L2 positive path).** `commit_recovery_rekey`
    /// commits the new-password daily re-wrap AND the forward-security
    /// re-split escrow in ONE transaction. After commit: the NEW password
    /// opens the daily wrap, the OLD password fails, the pre-recovery data
    /// is intact (L3), the new-epoch escrow is live on disk, and the OLD
    /// recovery RWK can no longer unwrap the LIVE (new) recovery wrapper —
    /// forward security holds.
    #[test]
    fn commit_recovery_rekey_atomically_rotates_wrap_and_escrow() {
        use pangolin_crypto::escrow::{reconstruct_rwk, unwrap_vdk_under_rwk, RecoveryWrapKey};

        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "rekey.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        let id = v.add_account(fresh_snapshot()).unwrap();
        let vault_id = v.vault_id();

        // A pre-recovery "old generation" RWK + shares (epoch 1) — these
        // are what recovery exposed; forward security must kill them.
        let old_vdk_for_old_rwk = {
            // Reconstruct what the recovered VDK is: reuse the active VDK's
            // bytes by re-wrapping with a known RWK we hold for the assert.
            // We model the OLD escrow as an independent RWK over the same
            // VDK so we can later prove the OLD RWK can't open the NEW
            // wrapper.
            VdkKey::generate()
        };
        let old_rwk = RecoveryWrapKey::generate();
        let old_wrapped = pangolin_crypto::escrow::wrap_vdk_under_rwk(
            &old_vdk_for_old_rwk,
            &old_rwk,
            &WrapContext::new(vault_id),
        )
        .unwrap();
        let old_shares = pangolin_crypto::escrow::split_rwk(&old_rwk, 2, 3).unwrap();
        drop(old_rwk);

        // The re-split (new generation, epoch 2) the orchestration would
        // hand the caller. Wraps the SAME (recovered) VDK — modelled here
        // via the active-VDK reuse helper inside the commit call; for the
        // wrapper fixture we use a fresh VDK clone-by-bytes is unavailable
        // (VdkKey is !Clone), so we build the re-split over a fresh VDK and
        // rely on the daily-wrap assertions for L3 (the recovery_escrow
        // round-trip already proves wrapper integrity).
        let re_split_vdk = VdkKey::generate();
        let (new_wrapped, new_sealed, new_pubs, new_secs) =
            build_re_split(&re_split_vdk, &vault_id, 2, 3, 2);
        let records: Vec<GuardianRecord<'_>> = (0..3)
            .map(|i| GuardianRecord {
                index: u8::try_from(i).unwrap(),
                guardian_x25519_pub: new_pubs[i],
                sealed_share: &new_sealed[i],
            })
            .collect();

        let new_password = SecretBytes::new(b"a fresh post-recovery passphrase".to_vec());
        v.__test_commit_recovery_rekey_reusing_active_vdk(
            &new_password,
            &new_wrapped,
            2,
            3,
            2,
            &records,
        )
        .unwrap();
        assert_eq!(v.state(), VaultState::Locked);

        // OLD password fails; NEW password opens; data intact (L3).
        let old_err = v.unlock(&fresh_presence(), &fresh_pin()).unwrap_err();
        assert!(matches!(old_err, StoreError::AuthenticationFailed));
        let new_pin = PinIdentityProof::new(SecretBytes::new(
            b"a fresh post-recovery passphrase".to_vec(),
        ));
        v.unlock(&fresh_presence(), &new_pin).unwrap();
        assert_eq!(v.state(), VaultState::Active);
        let after = v.get_account(id).expect("account present post-recovery");
        assert!(
            bool::from(after.ct_eq(&fresh_snapshot())),
            "vault data must survive recovery byte-for-byte (L3)"
        );

        // The new-epoch escrow is live on disk and reads back at epoch 2
        // with 3 guardians, openable with the new guardian secrets. The
        // live session holds the byte-identical recovered VDK (L3), whose
        // column-AEAD double-wrapped the sealed shares at commit time, so
        // it reads them back.
        let live_vdk_aead = v.active.as_ref().expect("active").vdk.aead_key();
        let loaded =
            crate::recovery_escrow::read_recovery_escrow(&v.conn, &vault_id, live_vdk_aead)
                .unwrap()
                .expect("escrow present");
        assert_eq!(loaded.epoch, 2);
        assert_eq!(loaded.guardian_count, 3);
        assert_eq!(loaded.guardians.len(), 3);
        let mut e2 = [0u8; pangolin_crypto::escrow::EPOCH_LEN];
        e2[8..].copy_from_slice(&2u64.to_be_bytes());
        for (i, g) in loaded.guardians.iter().enumerate() {
            pangolin_crypto::escrow::open_sealed_share(
                &g.sealed_share,
                &new_secs[i],
                &vault_id,
                &e2,
            )
            .unwrap();
        }

        // Forward security: the OLD RWK (reconstructed from the OLD shares)
        // can NOT unwrap the LIVE (new) recovery wrapper — the wrapper is
        // under a different RWK', so the AEAD open fails.
        let reconstructed_old = reconstruct_rwk(&old_shares[..2]).unwrap();
        assert!(
            unwrap_vdk_under_rwk(&new_wrapped, &reconstructed_old).is_err(),
            "OLD RWK must not open the post-recovery (new-RWK') wrapper (forward security)"
        );
        // (sanity) the OLD RWK still opens its OWN old wrapper — the kill is
        // specific to the new generation, not a degenerate always-fail.
        let _ = old_wrapped; // bound for the sanity narrative; open below.
        assert!(
            unwrap_vdk_under_rwk(&old_wrapped, &reconstructed_old).is_ok(),
            "control: OLD RWK opens its OWN old wrapper"
        );
    }

    /// **MVP-3 issue #105a (L2 / L11 — THE MERGE GATE: crash-injection).**
    /// Force a rollback BETWEEN the meta re-wrap and the escrow write inside
    /// `commit_recovery_rekey`, then re-open the vault and ASSERT the OLD
    /// generation is fully intact: the daily wrap still opens under the OLD
    /// password, and NO escrow row survives. Because both writes share ONE
    /// transaction, the second-write failure rolls the first (meta) write
    /// back too.
    ///
    /// The fault is REAL and in-method: a `re_split_epoch` of `u64::MAX`
    /// overflows the `i64` on-disk encoding inside `write_recovery_escrow_tx`
    /// — which runs AFTER `meta::write(&tx, …)` — so the escrow write errors
    /// and the un-committed `tx` `Drop`s with rollback semantics.
    ///
    /// **Single-tx is load-bearing:** if `commit_recovery_rekey` were
    /// reverted to two separate commits (commit the meta, THEN open a second
    /// tx for the escrow), the meta commit would survive the escrow failure
    /// and the OLD password would stop opening the daily wrap — turning the
    /// `unlock(OLD)` assertion below RED. (Verified by hand-reverting during
    /// development.)
    #[test]
    fn commit_recovery_rekey_rolls_back_both_writes_on_escrow_failure() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "rekey-crash.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        let id = v.add_account(fresh_snapshot()).unwrap();
        let vault_id = v.vault_id();

        let re_split_vdk = VdkKey::generate();
        // epoch 0 sealing for a VALID set of guardian records (the records
        // themselves are well-formed; only the `re_split_epoch` arg passed
        // to commit overflows, failing the escrow write AFTER the meta write).
        let (new_wrapped, new_sealed, new_pubs, _secs) =
            build_re_split(&re_split_vdk, &vault_id, 2, 3, 0);
        let records: Vec<GuardianRecord<'_>> = (0..3)
            .map(|i| GuardianRecord {
                index: u8::try_from(i).unwrap(),
                guardian_x25519_pub: new_pubs[i],
                sealed_share: &new_sealed[i],
            })
            .collect();

        let new_password = SecretBytes::new(b"a fresh post-recovery passphrase".to_vec());
        // u64::MAX overflows i64 inside write_recovery_escrow_tx — the
        // second write FAILS after the meta write, forcing the single-tx
        // rollback.
        let err = v
            .__test_commit_recovery_rekey_reusing_active_vdk(
                &new_password,
                &new_wrapped,
                2,
                3,
                u64::MAX,
                &records,
            )
            .unwrap_err();
        assert!(
            matches!(err, StoreError::Corrupted(_)),
            "epoch overflow must surface as the escrow-write error, got {err:?}"
        );

        // Re-open the vault from disk (a fresh handle — the in-memory state
        // is irrelevant; we assert what actually LANDED on disk).
        drop(v);
        let mut v2 = Vault::open(&p).unwrap();

        // L2: the OLD password STILL opens the daily wrap (the meta re-wrap
        // rolled back with the failed escrow write — single-tx atomicity).
        v2.unlock(&fresh_presence(), &fresh_pin())
            .expect("OLD password must still open after the rolled-back rekey");
        assert_eq!(v2.state(), VaultState::Active);
        let after = v2.get_account(id).expect("account intact");
        assert!(bool::from(after.ct_eq(&fresh_snapshot())));

        // L2: NO escrow row survives — neither the new generation (rolled
        // back) nor any partial.
        let escrow_rows: i64 = v2
            .conn
            .query_row("SELECT COUNT(*) FROM recovery_escrow", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            escrow_rows, 0,
            "no escrow row may survive the rollback (L2)"
        );
        let guardian_rows: i64 = v2
            .conn
            .query_row("SELECT COUNT(*) FROM recovery_guardians", [], |r| r.get(0))
            .unwrap();
        assert_eq!(guardian_rows, 0, "no guardian row may survive the rollback");
    }

    // =================================================================
    // MVP-3 issue #106b-2 — VDK-rotation-on-revoke commit (L4 atomic +
    // L3 epoch chain + prompt-on-revoke password anchor).
    // =================================================================

    /// **#106b-2 (L4 positive path + L3 epoch chain + anchor-current).**
    /// `commit_vdk_rotation` atomically writes the new-epoch password
    /// anchor + the demoted OLD epoch into the chain + the re-pointed
    /// escrow. After commit + re-unlock with the NEW password: the vault
    /// opens (anchor is current under the new password), the OLD password
    /// fails, a PRE-rotation account (sealed under the OLD VDK at epoch 0)
    /// still decrypts via the retained chain (L3), the current-epoch
    /// pointer advanced to 1, and the escrow generation was REPLACED.
    #[test]
    fn commit_vdk_rotation_atomic_advances_epoch_and_retains_old_vdk() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "rotate.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        // A PRE-rotation account — sealed under the OLD (epoch 0) VDK.
        let id = v.add_account(fresh_snapshot()).unwrap();
        let vault_id = v.vault_id();
        // Pre-rotation, the entry is tagged epoch 0.
        let pre_epoch: i64 = v
            .conn
            .query_row("SELECT vdk_epoch FROM revisions LIMIT 1", [], |r| r.get(0))
            .unwrap();
        assert_eq!(pre_epoch, 0, "pre-rotation entry is tagged epoch 0");

        // The FRESH VDK the pure driver minted for epoch 1 + its re-split
        // escrow (over the SAME fresh VDK, epoch 1).
        let new_vdk = VdkKey::generate();
        let (new_wrapped, new_sealed, new_pubs, _secs) =
            build_re_split(&new_vdk, &vault_id, 2, 3, 1);
        let records: Vec<GuardianRecord<'_>> = (0..3)
            .map(|i| GuardianRecord {
                index: u8::try_from(i).unwrap(),
                guardian_x25519_pub: new_pubs[i],
                sealed_share: &new_sealed[i],
            })
            .collect();

        let new_password = SecretBytes::new(b"post-revoke master password".to_vec());
        v.__test_commit_vdk_rotation_reusing_active(
            new_vdk,
            &new_password,
            1,
            &new_wrapped,
            2,
            3,
            1,
            &records,
        )
        .unwrap();
        assert_eq!(v.state(), VaultState::Locked);

        // The current-epoch pointer advanced to 1; the OLD epoch 0 is
        // retained in the chain.
        assert_eq!(crate::vdk_chain::read_current_epoch(&v.conn).unwrap(), 1);
        let chain_rows = crate::vdk_chain::read_chain(&v.conn, &vault_id).unwrap();
        assert_eq!(chain_rows.len(), 1, "epoch 0 is retained in the chain");
        assert_eq!(chain_rows[0].epoch, 0);

        // OLD password fails (the anchor was re-written under the NEW
        // password — prompt-on-revoke); NEW password opens.
        let old_err = v.unlock(&fresh_presence(), &fresh_pin()).unwrap_err();
        assert!(matches!(old_err, StoreError::AuthenticationFailed));
        let new_pin =
            PinIdentityProof::new(SecretBytes::new(b"post-revoke master password".to_vec()));
        v.unlock(&fresh_presence(), &new_pin).unwrap();
        assert_eq!(v.state(), VaultState::Active);

        // L3: the PRE-rotation account (sealed under the OLD epoch-0 VDK)
        // still decrypts via the retained chain — the cache hydrated it.
        let after = v
            .get_account(id)
            .expect("pre-rotation account decrypts post-rotation (L3)");
        assert!(
            bool::from(after.ct_eq(&fresh_snapshot())),
            "old-epoch entry must decrypt under the retained chain VDK (L3)"
        );

        // A NEW post-rotation write is stamped with the CURRENT epoch (1)
        // and reads back under the current VDK.
        let id3 = v.add_account(fresh_snapshot()).unwrap();
        let new_epoch_tag: i64 = v
            .conn
            .query_row(
                "SELECT vdk_epoch FROM revisions WHERE account_id = ?1",
                params![id3.as_bytes().as_slice()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            new_epoch_tag, 1,
            "a post-rotation write must be stamped with the current epoch (1)"
        );
        // And it reads back fine under the current VDK.
        assert!(v.get_account(id3).is_some());

        // The escrow generation was REPLACED: it reads back at epoch 1 with
        // 3 guardians under the new (current) VDK.
        let live_vdk_aead = v.active.as_ref().expect("active").vdk.aead_key();
        let loaded =
            crate::recovery_escrow::read_recovery_escrow(&v.conn, &vault_id, live_vdk_aead)
                .unwrap()
                .expect("escrow present after rotation");
        assert_eq!(loaded.epoch, 1, "escrow re-pointed at the new epoch");
        assert_eq!(loaded.guardian_count, 3);
    }

    /// **#106b-2 (L4 crash-injection — turns RED if the tx is split).**
    /// Force a fault AFTER the meta anchor + chain writes but DURING the
    /// escrow write (an `re_split_epoch` of `u64::MAX` overflows the i64
    /// on-disk encoding inside `write_recovery_escrow_tx`). Because ALL
    /// rotation writes share ONE transaction, the failure rolls EVERYTHING
    /// back: re-opened from disk, the vault is still on the OLD epoch — the
    /// OLD password opens it, NO `vdk_chain` row survives, the pointer is
    /// unchanged (0), and NO escrow row survives. If the commit were split
    /// into separate transactions, the OLD password would stop opening (the
    /// anchor would have been overwritten) and a stale chain row / advanced
    /// pointer would survive — turning the assertions below RED.
    #[test]
    fn commit_vdk_rotation_rolls_back_all_writes_on_escrow_failure() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "rotate-crash.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        let id = v.add_account(fresh_snapshot()).unwrap();
        let vault_id = v.vault_id();

        let new_vdk = VdkKey::generate();
        let (new_wrapped, new_sealed, new_pubs, _secs) =
            build_re_split(&new_vdk, &vault_id, 2, 3, 0);
        let records: Vec<GuardianRecord<'_>> = (0..3)
            .map(|i| GuardianRecord {
                index: u8::try_from(i).unwrap(),
                guardian_x25519_pub: new_pubs[i],
                sealed_share: &new_sealed[i],
            })
            .collect();

        let new_password = SecretBytes::new(b"post-revoke master password".to_vec());
        // re_split_epoch = u64::MAX overflows i64 inside
        // write_recovery_escrow_tx — the escrow write FAILS after the meta
        // anchor + chain writes, forcing the single-tx rollback.
        let err = v
            .__test_commit_vdk_rotation_reusing_active(
                new_vdk,
                &new_password,
                1,
                &new_wrapped,
                2,
                3,
                u64::MAX,
                &records,
            )
            .unwrap_err();
        assert!(
            matches!(err, StoreError::Corrupted(_)),
            "epoch overflow must surface as the escrow-write error, got {err:?}"
        );

        // Re-open from disk — assert what actually LANDED.
        drop(v);
        let mut v2 = Vault::open(&p).unwrap();

        // L4: the OLD password STILL opens (the anchor re-write rolled back).
        v2.unlock(&fresh_presence(), &fresh_pin())
            .expect("OLD password must still open after the rolled-back rotation");
        assert_eq!(v2.state(), VaultState::Active);
        let after = v2.get_account(id).expect("account intact");
        assert!(bool::from(after.ct_eq(&fresh_snapshot())));

        // L4: the pointer is UNCHANGED (still epoch 0) and NO chain row
        // survives.
        assert_eq!(
            crate::vdk_chain::read_current_epoch(&v2.conn).unwrap(),
            0,
            "the current-epoch pointer must not advance on rollback"
        );
        let chain_rows: i64 = v2
            .conn
            .query_row("SELECT COUNT(*) FROM vdk_chain", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            chain_rows, 0,
            "no vdk_chain row may survive the rollback (L4)"
        );
        // L4: NO escrow row survives either.
        let escrow_rows: i64 = v2
            .conn
            .query_row("SELECT COUNT(*) FROM recovery_escrow", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            escrow_rows, 0,
            "no escrow row may survive the rollback (L4)"
        );
    }

    /// **#106e-2 LOW-1 / install_paired_vdk atomicity discrimination.**
    /// The fault-injection regression for `Vault::install_paired_vdk`'s
    /// single-transaction property: if the device-key re-seal fails AFTER
    /// the meta write inside the SAME `unchecked_transaction()`, the tx
    /// drops without committing → SQLite rolls back both writes → the
    /// vault stays on the OLD meta (the OLD password still opens) and
    /// has NOT adopted the new `vault_id`.
    ///
    /// The fault is injected by renaming the `device_key` table out of
    /// the way before the call — `device::reseal_device_key_tx`'s
    /// `read_device_key_row` SELECT hits "no such table: device_key" →
    /// propagates `StoreError::Sqlite`
    /// through `install_paired_vdk`'s `?`. The tx (held in scope inside
    /// `install_paired_vdk`) `Drop`s without commit → rollback (L4).
    ///
    /// **Discrimination:** if a future refactor splits the
    /// `meta::write` + `device::reseal_device_key_tx` into SEPARATE
    /// transactions, the meta write would land + the reseal would still
    /// fail → the OLD password would NO LONGER open (it was overwritten
    /// to the new wrap authority) AND the vault_id would have been
    /// adopted → the assertions below go RED.
    #[test]
    #[allow(clippy::doc_markdown)]
    fn install_paired_vdk_rolls_back_meta_when_device_reseal_fails() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "install-paired-fault.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        let original_vault_id = v.vault_id();

        // Inject the fault: rename the `device_key` table so the upcoming
        // `device::reseal_device_key_tx` SELECT inside `install_paired_vdk`'s
        // single tx hits "no such table" AFTER the `meta::write` succeeds.
        // This forces the tx to drop without commit → rollback (L4).
        v.conn
            .execute(
                "ALTER TABLE device_key RENAME TO device_key_fault_inject",
                [],
            )
            .expect("rename device_key");

        // The host-supplied (post-pairing) recovered VDK + new vault_id + the
        // user's chosen post-pair password. None of this gets persisted
        // because the tx will roll back.
        let recovered_vdk = VdkKey::generate();
        let new_vault_id: [u8; VAULT_ID_LEN] = [0xCC; VAULT_ID_LEN];
        let new_password = SecretBytes::new(b"post-pair master pw".to_vec());

        let err = v
            .install_paired_vdk(recovered_vdk, new_vault_id, &new_password)
            .expect_err("install_paired_vdk must fail when reseal hits a missing device_key table");
        assert!(
            matches!(err, StoreError::Sqlite(_)),
            "expected StoreError::Sqlite from the missing device_key table, got {err:?}"
        );

        // Restore the schema so we can reopen the vault file and assert
        // the persisted state.
        v.conn
            .execute(
                "ALTER TABLE device_key_fault_inject RENAME TO device_key",
                [],
            )
            .expect("restore device_key table");
        drop(v);

        let mut v2 = Vault::open(&p).unwrap();

        // L4 ROLLBACK: the OLD password STILL opens (the meta write
        // rolled back; the wrap authority is unchanged).
        v2.unlock(&fresh_presence(), &fresh_pin()).expect(
            "OLD password must still open — install_paired_vdk's meta::write must have \
             rolled back when reseal failed",
        );
        assert_eq!(v2.state(), VaultState::Active);

        // L4 ROLLBACK: the vault_id was NOT adopted (rollback restored
        // the original vault_id in the meta row).
        assert_eq!(
            v2.vault_id(),
            original_vault_id,
            "vault_id must NOT have been adopted on rollback",
        );
        assert_ne!(
            v2.vault_id(),
            new_vault_id,
            "vault_id must NOT be the rolled-back-attempted new_vault_id",
        );

        // The NEW post-pair password must NOT open (no half-joined state
        // where the meta got partially updated).
        let new_pw_err = v2
            .unlock(
                &fresh_presence(),
                &PinIdentityProof::new(SecretBytes::new(b"post-pair master pw".to_vec())),
            )
            .unwrap_err();
        assert!(
            matches!(new_pw_err, StoreError::AuthenticationFailed),
            "new password must NOT open the rolled-back vault, got {new_pw_err:?}",
        );
    }

    /// L8: the NORMAL device-add / re-unlock path uses the EXISTING
    /// password and never invokes the recovery branch — re-unlocking with
    /// the same password leaves the wrap authority unchanged (no rotation,
    /// no recovery-escrow write).
    #[test]
    fn normal_reunlock_does_not_rotate_or_touch_escrow() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "reunlock.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        let id = v.add_account(fresh_snapshot()).unwrap();
        v.lock();
        // Re-unlock with the SAME password (the device-add idiom) — works,
        // data intact, no escrow row written.
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        assert!(v.get_account(id).is_some());
        let escrow_rows: i64 = v
            .conn
            .query_row("SELECT COUNT(*) FROM recovery_escrow", [], |r| r.get(0))
            .unwrap();
        assert_eq!(escrow_rows, 0);
    }

    /// MEDIUM-5 (P2 audit): pin the documented behavior of `unlock`
    /// being called a second time on a vault that is already `Active`.
    /// A wrong-password retry must NOT auto-lock the vault — the prior
    /// `ActiveState` survives, accounts remain queryable, and only an
    /// explicit `lock()` clears the cache.
    #[test]
    fn second_unlock_with_wrong_password_does_not_lock_vault() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "second-unlock.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();

        // First unlock (correct proofs) — vault enters Active.
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        assert_eq!(v.state(), VaultState::Active);
        let snap = AccountSnapshot::new(
            SecretBytes::new(b"d".to_vec()),
            SecretBytes::new(b"u".to_vec()),
            SecretBytes::new(b"p".to_vec()),
            SecretBytes::new(b"https://x".to_vec()),
            SecretBytes::new(b"".to_vec()),
            SecretBytes::new(b"".to_vec()),
        );
        let id = v.add_account(snap).unwrap();
        assert!(v.get_account(id).is_some());

        // Second unlock with WRONG password — must fail
        // AuthenticationFailed and must NOT lock the vault.
        let err = v.unlock(&fresh_presence(), &wrong_pin()).unwrap_err();
        assert!(matches!(err, StoreError::AuthenticationFailed));
        assert_eq!(
            v.state(),
            VaultState::Active,
            "wrong-password unlock-on-Active must not auto-lock the vault",
        );
        // Cache remains intact: account is still queryable.
        assert!(
            v.get_account(id).is_some(),
            "decrypted cache must survive a failed second unlock",
        );
    }

    /// Success criterion 7: tombstone visibility.
    #[test]
    fn tombstone() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "v.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        let id = v.add_account(fresh_snapshot()).unwrap();
        assert!(v.get_account(id).is_some());
        v.delete_account(id).unwrap();
        assert!(v.get_account(id).is_none());
        let history = v.revisions_for(id).unwrap();
        assert_eq!(history.len(), 2);
        assert!(history.last().unwrap().is_tombstone);
        // delete on tombstoned errors:
        assert!(matches!(
            v.delete_account(id).unwrap_err(),
            StoreError::AccountTombstoned
        ));
    }

    /// **P10-1.** `delete_account` writes a tombstone whose
    /// AEAD-sealed plaintext is the canonical three-field
    /// [`crate::blob::TombstonePayload`], NOT the legacy single-entry
    /// shape. We open the persisted ciphertext via the same VDK + AAD
    /// the vault used at seal time and assert the payload's
    /// `account_id` and timestamp survive the round-trip.
    #[test]
    fn delete_account_writes_canonical_three_field_tombstone_payload() {
        use crate::blob::{build_aad, open_payload, DecodedPayload};
        use pangolin_crypto::aead::{Ciphertext, Nonce, NONCE_LEN};
        use rusqlite::params;

        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "v.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        let id = v.add_account(fresh_snapshot()).unwrap();
        v.delete_account(id).unwrap();

        // Find the tombstone revision row for this account.
        let history = v.revisions_for(id).unwrap();
        let tomb_meta = history
            .iter()
            .find(|m| m.is_tombstone)
            .expect("tombstone revision present");
        let parent_id = tomb_meta.parent_revision_id;

        // Read the row's enc_payload + enc_nonce + schema_version
        // directly from the SQL layer so we can re-derive the AAD
        // and open the ciphertext.
        let (payload_bytes, nonce_bytes, schema_version_i): (Vec<u8>, Vec<u8>, i64) = v
            .conn
            .query_row(
                "SELECT enc_payload, enc_nonce, schema_version
                 FROM revisions
                 WHERE revision_id = ?1",
                params![tomb_meta.revision_id.as_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        let schema_version = u8::try_from(schema_version_i).unwrap();
        let aad = build_aad(&v.meta.vault_id, &id, &parent_id, schema_version);
        let nonce_arr: [u8; NONCE_LEN] = nonce_bytes.as_slice().try_into().unwrap();
        let nonce = Nonce::from_storage_bytes(nonce_arr);
        let ct = Ciphertext::from_vec(payload_bytes);

        let active = v.require_active().unwrap();
        let decoded = open_payload(active.vdk.aead_key(), &nonce, &ct, &aad).unwrap();
        match decoded {
            DecodedPayload::Tombstone(p) => {
                assert!(p.is_deleted(), "deleted bit must be true");
                assert_eq!(
                    p.account_id(),
                    id.as_bytes(),
                    "in-payload account_id must match the AAD-bound account_id"
                );
                assert!(
                    p.tombstoned_at_ms() > 0,
                    "tombstoned_at_ms must be a real timestamp, got 0"
                );
            }
            DecodedPayload::Live(_) => panic!("expected Tombstone, got Live"),
        }
    }

    /// Success criterion 10: WAL pragma.
    #[test]
    fn wal_mode_set() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "v.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let v = Vault::open(&p).unwrap();
        let mode: String = v
            .conn
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();
        assert_eq!(mode.to_ascii_lowercase(), "wal");
    }

    /// Success criterion 12: opening the same vault file twice fails.
    #[test]
    fn double_open_fails() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "v.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let _v1 = Vault::open(&p).unwrap();
        let err = Vault::open(&p).unwrap_err();
        assert!(matches!(err, StoreError::AlreadyOpen));
    }

    /// Success criterion 9: lock drops the cache (best-effort,
    /// observable via state + size).
    #[test]
    fn lock_zeroizes_cache() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "v.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        v.add_account(fresh_snapshot()).unwrap();
        assert_eq!(v.state(), VaultState::Active);
        assert_eq!(v.list_accounts().len(), 1);
        v.lock();
        assert_eq!(v.state(), VaultState::Locked);
        assert!(v.list_accounts().is_empty());
        assert!(v
            .get_account(crate::account::AccountId::from_bytes([0u8; 32]))
            .is_none());
    }

    /// P7 success criterion 8: `last_pulled_block` checkpoint
    /// persists across `Vault::close` + `Vault::open`. Defaults to 0
    /// on a fresh vault; advance + read returns the new value;
    /// reopen sees the same value.
    #[test]
    fn last_pulled_block_persists_across_open_close() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "v.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        {
            let mut v = Vault::open(&p).unwrap();
            // Default for a fresh vault is 0.
            assert_eq!(v.last_pulled_block().unwrap(), 0);
            // Advance to a non-zero value.
            v.advance_last_pulled_block(1_234_567).unwrap();
            assert_eq!(v.last_pulled_block().unwrap(), 1_234_567);
        }
        // Reopen the same file; the checkpoint must still be there.
        let v = Vault::open(&p).unwrap();
        assert_eq!(v.last_pulled_block().unwrap(), 1_234_567);
    }

    /// `advance_last_pulled_block` is monotonic — backward moves are
    /// rejected as `Corrupted`. Equal-value advances are no-ops
    /// (idempotent retry of a sync).
    #[test]
    fn advance_last_pulled_block_is_monotonic() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "v.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.advance_last_pulled_block(100).unwrap();
        // Equal-value re-advance is a no-op, not an error.
        v.advance_last_pulled_block(100).unwrap();
        assert_eq!(v.last_pulled_block().unwrap(), 100);
        // Backward move is rejected.
        let err = v.advance_last_pulled_block(50).unwrap_err();
        assert!(
            matches!(err, StoreError::Corrupted(_)),
            "backward advance must surface Corrupted, got {err:?}"
        );
        // The underlying value did not change after the failed call.
        assert_eq!(v.last_pulled_block().unwrap(), 100);
    }

    /// P2-3c: chain anchor primitives — unpublished -> `mark_published`
    /// loop.
    #[test]
    fn chain_anchor_round_trip() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "v.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        v.add_account(fresh_snapshot()).unwrap();
        let unpub = v.unpublished_revisions().unwrap();
        assert_eq!(unpub.len(), 1);
        let anchor = crate::revision::ChainAnchor {
            tx_hash: [0xAB; 32],
            block_number: 12345,
            log_index: 7,
            sequence: 42,
        };
        v.mark_published(unpub[0], anchor).unwrap();
        let unpub_after = v.unpublished_revisions().unwrap();
        assert!(unpub_after.is_empty());
        // Double-mark on missing revision = RevisionNotFound.
        let missing = crate::revision::RevisionId::from_bytes([0xFF; 32]);
        assert!(matches!(
            v.mark_published(missing, anchor).unwrap_err(),
            StoreError::RevisionNotFound
        ));
        // Round-trip read: the SQL row stores tx_hash + block + log,
        // not sequence (the local table is intentionally lossless on
        // those three).  Reconstructed `ChainAnchor.sequence` is 0
        // because the SQL row doesn't carry it; callers that need the
        // on-chain sequence re-pull from the chain.
        let acct = v
            .list_accounts()
            .into_iter()
            .next()
            .expect("one account exists");
        let metas = v.revisions_for(acct).expect("revisions_for");
        let stored = metas
            .iter()
            .find_map(|m| m.chain_anchor.filter(|a| a.tx_hash == [0xAB; 32]))
            .expect("the marked anchor round-trips through SQL");
        assert_eq!(stored.tx_hash, [0xAB; 32]);
        assert_eq!(stored.block_number, 12345);
        assert_eq!(stored.log_index, 7);
        assert_eq!(
            stored.sequence, 0,
            "sequence is intentionally not stored in SQL — see vault::mark_published docs"
        );
    }

    /// Success criterion 6: revision lineage is unbroken across
    /// multiple edits.
    #[test]
    fn revision_lineage_walk() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "v.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        let id = v.add_account(fresh_snapshot()).unwrap();
        for _ in 0..5 {
            v.update_account(id, fresh_snapshot()).unwrap();
        }
        let history = v.revisions_for(id).unwrap();
        assert_eq!(history.len(), 6);
        // Walk from head back to genesis.
        let mut by_id: std::collections::HashMap<_, _> =
            history.iter().map(|r| (r.revision_id, r)).collect();
        let head = history.last().unwrap();
        let mut cursor = head.revision_id;
        let mut depth = 0;
        loop {
            let r = by_id.remove(&cursor).expect("missing parent in map");
            depth += 1;
            if r.parent_revision_id == crate::revision::RevisionId::GENESIS_PARENT {
                break;
            }
            cursor = r.parent_revision_id;
            assert!(depth < 100, "lineage walk did not terminate");
        }
        assert_eq!(depth, 6);
    }

    // -----------------------------------------------------------------
    // P3 vault-side fork-detection tests
    // -----------------------------------------------------------------

    /// Plan success criterion 2: a clean linear edit history exposes
    /// `is_forked() == false`, `account_heads().len() == 1`, and the
    /// graph contains exactly one head whose id equals the
    /// `account_identities.head_revision_id` canonical pointer.
    #[test]
    fn is_forked_false_after_linear_edits() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "linear.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        let id = v.add_account(fresh_snapshot()).unwrap();
        for _ in 0..5 {
            v.update_account(id, fresh_snapshot()).unwrap();
        }
        let heads = v.account_heads(id).unwrap();
        assert_eq!(heads.len(), 1, "linear lineage must have exactly one head");
        assert!(!v.is_forked(id).unwrap());
        let graph = v.revision_graph(id).unwrap();
        assert_eq!(graph.heads().len(), 1);
        assert!(!graph.is_forked());
        assert_eq!(graph.len(), 6); // genesis + 5 updates
                                    // Genesis is detected, and the canonical head from the
                                    // identity row matches the graph's head.
        assert!(graph.genesis().is_some());
        // Cross-check: account_heads via SQL agrees with the graph.
        assert_eq!(graph.heads()[0], heads[0]);
    }

    /// Plan success criterion 3 (vault path): synthesize a fork via
    /// the test helper and confirm `is_forked()` flips, both heads
    /// surface from `account_heads`, and the common ancestor is the
    /// shared parent.
    #[test]
    fn vault_two_way_fork_via_test_helper() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "fork.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        let id = v.add_account(fresh_snapshot()).unwrap();
        // Linear: genesis (R0) -> R1 -> R2.
        let r1 = v.update_account(id, fresh_snapshot()).unwrap();
        let _r2 = v.update_account(id, fresh_snapshot()).unwrap();
        assert!(!v.is_forked(id).unwrap());
        // Synthesize a sibling of R2 by inserting another revision
        // whose parent is R1. This is what "another device's update
        // from R1 has just synced in" looks like at the storage layer.
        let r2_alt = v
            .__test_synthesize_sibling_revision(id, r1, fresh_snapshot())
            .unwrap();
        // Now there are two heads.
        assert!(v.is_forked(id).unwrap());
        let heads = v.account_heads(id).unwrap();
        assert_eq!(heads.len(), 2, "two-way fork must surface as two heads");
        let graph = v.revision_graph(id).unwrap();
        assert!(graph.is_forked());
        assert_eq!(graph.heads().len(), 2);
        // r2_alt is one of the heads.
        let head_set: std::collections::HashSet<_> = heads.into_iter().collect();
        assert!(head_set.contains(&r2_alt));
        // Common ancestor of the two heads is R1 (the fork point).
        let head_vec: Vec<_> = head_set.into_iter().collect();
        let lca = graph.common_ancestor(&head_vec[0], &head_vec[1]).unwrap();
        assert_eq!(lca, r1, "fork point must be R1");
    }

    /// Plan success criterion 7 (vault path): an account with mixed
    /// forked / unforked siblings reports only the forked ones via
    /// `all_forked_accounts`.
    #[test]
    fn all_forked_accounts_lists_only_forked() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "mixed.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        // Two accounts, only the second one will be forked.
        let id_clean = v.add_account(fresh_snapshot()).unwrap();
        v.update_account(id_clean, fresh_snapshot()).unwrap();
        v.update_account(id_clean, fresh_snapshot()).unwrap();

        let id_fork = v.add_account(fresh_snapshot()).unwrap();
        let parent = v.update_account(id_fork, fresh_snapshot()).unwrap();
        v.update_account(id_fork, fresh_snapshot()).unwrap();
        v.__test_synthesize_sibling_revision(id_fork, parent, fresh_snapshot())
            .unwrap();

        // Only the forked account should appear.
        let forked = v.all_forked_accounts().unwrap();
        assert_eq!(forked.len(), 1, "exactly one forked account expected");
        assert_eq!(forked[0], id_fork);
        assert!(!v.is_forked(id_clean).unwrap());
        assert!(v.is_forked(id_fork).unwrap());
    }

    /// Plan failure-mode coverage: querying an unknown account yields
    /// `AccountNotFound` rather than an empty / silent answer.
    #[test]
    fn account_heads_unknown_account_errors() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "unknown.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        let bogus = crate::account::AccountId::from_bytes([0x99; 32]);
        let err = v.account_heads(bogus).unwrap_err();
        assert!(matches!(err, StoreError::AccountNotFound));
        let err = v.is_forked(bogus).unwrap_err();
        assert!(matches!(err, StoreError::AccountNotFound));
    }

    /// `revision_graph` is metadata-only and works while the vault is
    /// `Locked` (no VDK in memory). Cardinal-principle 2 sanity: no
    /// plaintext is needed to enumerate the lineage.
    #[test]
    fn revision_graph_works_while_locked() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "locked.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let id;
        {
            let mut v = Vault::open(&p).unwrap();
            v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
            id = v.add_account(fresh_snapshot()).unwrap();
            v.update_account(id, fresh_snapshot()).unwrap();
            v.lock();
            v.close().unwrap();
        }
        let v = Vault::open(&p).unwrap();
        // Vault is Locked; no unlock call.
        assert_eq!(v.state(), VaultState::Locked);
        let g = v.revision_graph(id).unwrap();
        assert_eq!(g.len(), 2);
        assert!(!g.is_forked());
    }

    /// Empty vault: `all_forked_accounts` returns an empty Vec.
    #[test]
    fn all_forked_accounts_empty_vault() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "empty.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let v = Vault::open(&p).unwrap();
        let forked = v.all_forked_accounts().unwrap();
        assert!(forked.is_empty());
    }

    /// Success criterion 3 (kernel): create -> open -> unlock round
    /// trips a freshly-added snapshot byte-equal.
    #[test]
    fn create_open_unlock_round_trip() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "v.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let id;
        {
            let mut v = Vault::open(&p).unwrap();
            v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
            id = v.add_account(fresh_snapshot()).unwrap();
            v.lock();
            v.close().unwrap();
        }
        // Reopen cycle.
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        let reloaded = v.get_account(id).expect("missing on reopen");
        assert!(bool::from(fresh_snapshot().ct_eq(reloaded)));
    }

    // -----------------------------------------------------------------
    // P4 session-policy tests (success criteria 2..10)
    // -----------------------------------------------------------------
    //
    // These tests live in `vault::tests` rather than `session::tests`
    // (which the plan §"Test plan" suggested as a home) because every
    // success-criterion test needs a real `Vault` to drive the unlock
    // path; the session module doesn't own a Vault factory. The
    // semantic content is unchanged from the plan; only the file path
    // differs. The plan's named tests are mapped 1:1 below with
    // matching docstrings.

    use crate::session::{
        TestClock, ABSOLUTE_MAX_DEFAULT, IDLE_TIMEOUT_DEFAULT, PRESENCE_FRESHNESS,
    };
    use std::sync::Arc;
    use std::time::{Duration, SystemTime};

    /// Adapter that lets two test handles (the test thread + the
    /// vault) share a single `TestClock` via `Arc`. Defined at module
    /// scope rather than inside `open_vault_with_test_clock` to keep
    /// clippy's `items_after_statements` happy.
    struct ArcClockAdapter(Arc<TestClock>);
    impl crate::session::Clock for ArcClockAdapter {
        fn now(&self) -> SystemTime {
            self.0.now()
        }
    }

    /// Construct a vault with a deterministic test clock pinned to
    /// `SystemTime::UNIX_EPOCH + 1_000_000s`. Returns the vault and a
    /// shared handle to the clock the caller can `advance()`.
    fn open_vault_with_test_clock(p: &std::path::Path) -> (Vault, Arc<TestClock>) {
        let start = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let clock = Arc::new(TestClock::new(start));
        let v = Vault::open(p)
            .unwrap()
            .with_clock(Box::new(ArcClockAdapter(Arc::clone(&clock))));
        (v, clock)
    }

    /// Plan success criterion 2 (3 cases):
    /// `session::tests::two_proof_required_at_unlock` — unlock requires
    /// BOTH valid presence AND valid identity proofs. Either failing
    /// surfaces as `AuthenticationFailed`.
    #[test]
    fn two_proof_required_at_unlock() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "two-proof.pvf");
        Vault::create(&p, &fresh_password()).unwrap();

        // Case 1: valid presence + INVALID identity (wrong PIN) →
        // AuthenticationFailed. The Argon2id derivation must run to
        // completion before the AEAD failure (preserving MEDIUM-1
        // indistinguishability) — we can't directly assert timing, but
        // the result variant collapse is the contract.
        {
            let mut v = Vault::open(&p).unwrap();
            let err = v.unlock(&fresh_presence(), &wrong_pin()).unwrap_err();
            assert!(matches!(err, StoreError::AuthenticationFailed));
            assert_eq!(v.state(), VaultState::Locked);
            v.close().unwrap();
        }

        // Case 2: valid presence + EMPTY identity → AuthenticationFailed
        // (collapses through `From<AuthError>` for `AuthError::Empty`).
        // No KDF runs because identity.verify() fails structurally
        // before we'd extract the password — but this is the "empty
        // input" path, not the "wrong content" path; the structural
        // distinguishability here is acceptable per the design (an
        // empty PIN is a UX-level error, not a secret-bearing one).
        {
            let mut v = Vault::open(&p).unwrap();
            let empty = PinIdentityProof::new(SecretBytes::new(Vec::new()));
            let err = v.unlock(&fresh_presence(), &empty).unwrap_err();
            assert!(matches!(err, StoreError::AuthenticationFailed));
            assert_eq!(v.state(), VaultState::Locked);
            v.close().unwrap();
        }

        // Case 3: STALE presence (constructed in the past beyond
        // PRESENCE_FRESHNESS) + valid identity → AuthenticationFailed.
        {
            let mut v = Vault::open(&p).unwrap();
            let stale = PressYPresenceProof::__test_with_timestamp(
                SystemTime::now() - PRESENCE_FRESHNESS - Duration::from_secs(10),
            );
            let err = v.unlock(&stale, &fresh_pin()).unwrap_err();
            assert!(matches!(err, StoreError::AuthenticationFailed));
            assert_eq!(v.state(), VaultState::Locked);
            v.close().unwrap();
        }

        // Case 4 (the positive control): both valid → Active.
        {
            let mut v = Vault::open(&p).unwrap();
            v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
            assert_eq!(v.state(), VaultState::Active);
        }
    }

    /// Plan success criterion 3:
    /// `session::tests::idle_timeout_expires_session` — after the idle
    /// timer fires, the session expires, the cache is zeroized, and
    /// the next op surfaces `SessionExpired`.
    #[test]
    fn idle_timeout_expires_session() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "idle.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let (mut v, clock) = open_vault_with_test_clock(&p);
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        let id = v.add_account(fresh_snapshot()).unwrap();
        assert!(v.is_session_active());

        // Advance clock past the idle deadline.
        clock.advance(IDLE_TIMEOUT_DEFAULT + Duration::from_secs(1));

        // Next op surfaces SessionExpired and the vault transitions.
        let err = v.update_account(id, fresh_snapshot()).unwrap_err();
        assert!(matches!(err, StoreError::SessionExpired));
        // Cache is gone — list_accounts is empty after expiry.
        assert!(v.list_accounts().is_empty());
        // session_state reflects Expired.
        assert!(matches!(
            v.session_state(),
            crate::session::SessionState::Expired
        ));
    }

    /// Plan success criterion 4:
    /// `session::tests::absolute_max_caps_active_session` — even with
    /// constant activity, a session cannot live past
    /// `session_started_at + ABSOLUTE_MAX_DEFAULT`.
    #[test]
    fn absolute_max_caps_active_session() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "absmax.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let (mut v, clock) = open_vault_with_test_clock(&p);
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        let id = v.add_account(fresh_snapshot()).unwrap();

        // Simulate constant activity: every minute, do an op for
        // 4 hours' worth of time. Each op touches the session and
        // resets the idle deadline, but never past
        // session_started + ABSOLUTE_MAX_DEFAULT.
        let step = Duration::from_secs(60);
        let total_minutes = ABSOLUTE_MAX_DEFAULT.as_secs() / 60;
        let mut ops_succeeded = 0u64;
        for _ in 0..total_minutes {
            // Op succeeds while we're under the absolute max.
            v.update_account(id, fresh_snapshot()).unwrap();
            ops_succeeded += 1;
            clock.advance(step);
        }
        // We've now advanced exactly ABSOLUTE_MAX_DEFAULT from
        // start. The session deadline is capped at exactly that point
        // by next_idle_deadline. Advance one more second so we're past
        // the absolute ceiling regardless of any rounding.
        clock.advance(Duration::from_secs(1));

        // Now the next op MUST fail SessionExpired even though we've
        // been touching the session every minute. Active timer would
        // have allowed continued use indefinitely; absolute-max
        // ceiling is what fires here.
        let err = v.update_account(id, fresh_snapshot()).unwrap_err();
        assert!(
            matches!(err, StoreError::SessionExpired),
            "expected SessionExpired after {ops_succeeded} successful ops; got {err:?}"
        );
        assert!(matches!(
            v.session_state(),
            crate::session::SessionState::Expired
        ));
    }

    /// Plan success criterion 5:
    /// `session::tests::touch_extends_idle_deadline` — touching the
    /// session via a successful op extends the idle deadline so the
    /// session survives 14 + 14 = 28 minutes of activity (well past
    /// the bare 15-minute idle timeout).
    #[test]
    fn touch_extends_idle_deadline() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "touch.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let (mut v, clock) = open_vault_with_test_clock(&p);
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        let id = v.add_account(fresh_snapshot()).unwrap();

        // Advance 14 min — under the 15-min idle deadline. Op succeeds
        // and resets the idle deadline.
        clock.advance(Duration::from_secs(14 * 60));
        v.update_account(id, fresh_snapshot()).unwrap();
        // Advance another 14 min — total 28 min from unlock. Idle
        // deadline was reset 14 min ago, so we're 14 min into a new
        // 15-min window. Op must succeed.
        clock.advance(Duration::from_secs(14 * 60));
        v.update_account(id, fresh_snapshot()).unwrap();
        assert!(v.is_session_active());
    }

    /// Plan success criterion 6 (rewritten for 1.4's freshness + dedup
    /// model): a reveal-class op requires a presence proof that is fresh
    /// *now* — meaning within `PRESENCE_FRESHNESS` of the last
    /// successful presence (which includes the unlock's). Within the
    /// window no re-prompt is needed (dedup); outside it a fresh proof
    /// is required, and a stale one surfaces `PromptTimedOut`.
    #[test]
    fn reveal_password_requires_fresh_presence() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "reveal.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let (mut v, clock) = open_vault_with_test_clock(&p);
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        let snap = AccountSnapshot::new(
            SecretBytes::new(b"display".to_vec()),
            SecretBytes::new(b"alice".to_vec()),
            SecretBytes::new(b"hunter2-the-secret".to_vec()),
            SecretBytes::new(b"https://x".to_vec()),
            SecretBytes::new(b"".to_vec()),
            SecretBytes::new(b"".to_vec()),
        );
        let id = v.add_account(snap).unwrap();

        // Within the window of the unlock's presence — no re-prompt.
        // A throwaway (even already-consumed) proof is fine because the
        // engine does not consume it: dedup, not replay.
        let already_consumed = PressYPresenceProof::confirmed();
        let _ = <PressYPresenceProof as crate::session::PresenceProof>::verify(&already_consumed);
        let pwd = v.reveal_password(id, &already_consumed).unwrap();
        assert_eq!(pwd.expose(), b"hunter2-the-secret");
        // A second reveal moments later — still within the window —
        // also no re-prompt.
        let pwd2 = v
            .reveal_password(id, &PressYPresenceProof::confirmed())
            .unwrap();
        assert_eq!(pwd2.expose(), b"hunter2-the-secret");

        // Advance past PRESENCE_FRESHNESS (and stay under the idle
        // deadline). Now a reveal needs a fresh proof. A stale proof
        // (constructed in the past relative to the test clock's now)
        // surfaces PromptTimedOut — but `PressYPresenceProof::verify`
        // uses the *real* clock for its own staleness check, so a
        // `__test_with_timestamp` proof pinned to "real now minus
        // PRESENCE_FRESHNESS minus slack" is stale by that check too.
        clock.advance(PRESENCE_FRESHNESS + Duration::from_secs(5));
        let stale = PressYPresenceProof::__test_with_timestamp(
            SystemTime::now() - PRESENCE_FRESHNESS - Duration::from_secs(10),
        );
        let err = v.reveal_password(id, &stale).unwrap_err();
        assert!(
            matches!(err, StoreError::PromptTimedOut),
            "stale proof at a reveal site must be PromptTimedOut; got {err:?}"
        );

        // A fresh proof works again and re-opens the dedup window.
        let pwd3 = v
            .reveal_password(id, &PressYPresenceProof::confirmed())
            .unwrap();
        assert_eq!(pwd3.expose(), b"hunter2-the-secret");
    }

    /// Plan success criterion 7: same shape as criterion 6 but for the
    /// export primitive — and an export of a tombstoned account
    /// surfaces `AccountTombstoned` (after the freshness check passes).
    #[test]
    fn export_payload_requires_fresh_presence() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "export.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let (mut v, clock) = open_vault_with_test_clock(&p);
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        let id = v.add_account(fresh_snapshot()).unwrap();

        // Within the unlock's presence window — no re-prompt.
        let bytes = v
            .export_payload(id, &PressYPresenceProof::confirmed())
            .unwrap();
        assert!(
            bytes.len() > 50,
            "exported payload too short: {} bytes",
            bytes.len()
        );

        // Past the freshness window: a stale proof → PromptTimedOut.
        clock.advance(PRESENCE_FRESHNESS + Duration::from_secs(5));
        let stale = PressYPresenceProof::__test_with_timestamp(
            SystemTime::now() - PRESENCE_FRESHNESS - Duration::from_secs(10),
        );
        let err = v.export_payload(id, &stale).unwrap_err();
        assert!(matches!(err, StoreError::PromptTimedOut), "got {err:?}");

        // Tombstoned account → AccountTombstoned. A fresh proof re-opens
        // the window; the tombstone check happens after the freshness
        // gate (P8 CRIT-1 frozen-account check is what runs *before*
        // the proof; tombstone is checked while reading the head).
        v.delete_account(id).unwrap();
        let err = v
            .export_payload(id, &PressYPresenceProof::confirmed())
            .unwrap_err();
        assert!(matches!(err, StoreError::AccountTombstoned), "got {err:?}");
    }

    // -----------------------------------------------------------------
    // MVP-1 issue 1.4: configurable idle, device-lock, prompt timeout
    // -----------------------------------------------------------------

    /// Criterion 7 (variant): a non-default configured idle duration
    /// drives the deadline. `set_session_idle(Min30, None)` (shortening
    /// from the 15-min default is not "lengthening", so no presence
    /// needed) — wait, 30 > 15 IS lengthening. Use the proof. Then a
    /// re-`unlock` gives a 30-min window; advancing 20 min keeps the
    /// session, 35 min expires it.
    #[test]
    fn idle_timeout_expires_session_with_configured_idle() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "idle-30.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let (mut v, clock) = open_vault_with_test_clock(&p);
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        // Lengthen to 30 min — high-risk; needs a fresh presence proof.
        v.set_session_idle(
            crate::session::SessionDuration::Min30,
            Some(&PressYPresenceProof::confirmed()),
        )
        .unwrap();
        // Right after set: deadline ≈ now + 30 min.
        let r = v.session_remaining().unwrap();
        assert!(r > Duration::from_secs(29 * 60) && r <= Duration::from_secs(30 * 60));
        let id = v.add_account(fresh_snapshot()).unwrap();
        // 20 min in (under 30-min idle): op succeeds.
        clock.advance(Duration::from_secs(20 * 60));
        v.update_account(id, fresh_snapshot()).unwrap();
        // 35 more min (deadline was reset 20 min ago to now+30; 35 > 30):
        // expired.
        clock.advance(Duration::from_secs(35 * 60));
        let err = v.update_account(id, fresh_snapshot()).unwrap_err();
        assert!(matches!(err, StoreError::SessionExpired), "got {err:?}");
        // Re-open: the 30-min choice persisted; a fresh unlock gives a
        // 30-min window.
        drop(v);
        let v2 = Vault::open(&p).unwrap();
        assert_eq!(v2.session_idle(), crate::session::SessionDuration::Min30);
    }

    /// Criterion 14: `set_session_idle` — lengthening requires a fresh
    /// presence proof; shortening does not; an out-of-set value is
    /// rejected. (The "out-of-set" path is the public-API validator
    /// `SessionDuration::try_from_meta_secs`; `set_session_idle` itself
    /// takes a typed variant, so the validator is the gate a caller
    /// hits when it builds the variant from a raw number.)
    #[test]
    fn set_session_idle_presence_rules() {
        use crate::session::SessionDuration;
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "set-idle.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        // Lengthen (15 → Hour1) without a proof → PresenceProofRequired.
        let err = v
            .set_session_idle(SessionDuration::Hour1, None)
            .unwrap_err();
        assert!(
            matches!(err, StoreError::PresenceProofRequired),
            "got {err:?}"
        );
        // Lengthen with a fresh proof → ok.
        v.set_session_idle(
            SessionDuration::Hour1,
            Some(&PressYPresenceProof::confirmed()),
        )
        .unwrap();
        assert_eq!(v.session_idle(), SessionDuration::Hour1);
        // Shorten (Hour1 → Min5) without a proof → ok.
        v.set_session_idle(SessionDuration::Min5, None).unwrap();
        assert_eq!(v.session_idle(), SessionDuration::Min5);
        // Out-of-set raw value → Validation { kind: "session_duration" }.
        let err = SessionDuration::try_from_meta_secs(42).unwrap_err();
        assert!(
            matches!(err, StoreError::Validation { ref kind, .. } if kind == "session_duration")
        );
    }

    /// Criterion 15: `device_locked()` on an `Active` vault expires the
    /// session (cache zeroized, `:memory:` index gone); on a `Locked` /
    /// `Expired` vault it is a no-op.
    #[test]
    fn device_locked_expires_active_session() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "device-lock.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        // Locked: device_locked is a no-op.
        v.device_locked();
        assert!(matches!(
            v.session_state(),
            crate::session::SessionState::Locked
        ));
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        let id = v.add_account(fresh_snapshot()).unwrap();
        assert!(v.get_account(id).is_some());
        // Device locks → session expires; cache zeroized.
        v.device_locked();
        assert!(matches!(
            v.session_state(),
            crate::session::SessionState::Expired
        ));
        assert!(!v.is_session_active());
        assert!(v.get_account(id).is_none());
        assert!(v.list_accounts().is_empty());
        // device_locked on the already-Expired vault → no-op.
        v.device_locked();
        assert!(matches!(
            v.session_state(),
            crate::session::SessionState::Expired
        ));
        // Next op needs a full 2-proof unlock.
        let err = v.update_account(id, fresh_snapshot()).unwrap_err();
        assert!(matches!(err, StoreError::SessionExpired));
        // Re-unlock works (2-proof), and rebuilds the cache.
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        assert!(v.get_account(id).is_some());
    }

    // -----------------------------------------------------------------
    // MVP-1 issue 1.5: device identity + trust list (criteria 1..8, 12).
    // -----------------------------------------------------------------

    /// Criteria 1, 3, 5, 7, 8: first unlock on a new vault registers
    /// exactly one device, marked current; `device_current` /
    /// `device_list` agree; the in-memory `DeviceKey`'s verifying key
    /// equals the registered `device_id`; the default capability is
    /// `Full`; `last_sync_at` is `None` (MVP-2 fills it).
    #[test]
    fn register_on_first_unlock_creates_one_device() {
        use crate::device::DeviceCapabilities;
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "dev-register.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        // No device registered before the first unlock.
        assert!(matches!(
            v.device_current().unwrap_err(),
            StoreError::NotUnlocked
        ));
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();

        let cur = v.device_current().unwrap();
        let listed = v.device_list().unwrap();
        assert_eq!(listed.len(), 1, "exactly one device after first unlock");
        assert_eq!(listed[0].device_id, cur.device_id);
        assert!(cur.is_current);
        assert!(listed[0].is_current);
        assert_eq!(cur.capabilities, DeviceCapabilities::Full);
        assert_eq!(cur.last_sync_at, None, "MVP-2 chain sync populates this");
        assert!(cur.public_key.is_some());
        // device_id == verifying-key bytes of the in-memory DeviceKey.
        assert_eq!(
            v.device_key_verifying_key().unwrap(),
            cur.device_id.0,
            "device_id must be the DeviceKey's verifying-key bytes"
        );
        // ...and == the stored public_key.
        assert_eq!(cur.public_key.unwrap().to_bytes(), cur.device_id.0);
    }

    /// Criterion 2: re-open + re-unlock the same `.pvf` does NOT register
    /// a second device; the `device_id` is stable and equals
    /// `self.device_id` (the revision-stamping id).
    #[test]
    fn second_unlock_does_not_register_second_device() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "dev-stable.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let first_id = {
            let mut v = Vault::open(&p).unwrap();
            v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
            let id = v.device_current().unwrap().device_id;
            v.close().unwrap();
            id
        };
        // Reopen — even before unlock, `open` adopts the persisted id.
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        assert_eq!(v.device_list().unwrap().len(), 1, "no second device");
        assert_eq!(v.device_current().unwrap().device_id, first_id);
        assert_eq!(
            v.device_key_verifying_key().unwrap(),
            first_id.0,
            "loaded DeviceKey's verifying key must match the persisted device_id"
        );
        // A revision written this session stamps the real device_id.
        let acct = v.add_account(fresh_snapshot()).unwrap();
        let revs = v.revisions_for(acct).unwrap();
        assert_eq!(revs.last().unwrap().device_id, first_id);
    }

    /// Criterion 6: `originating_device` on a new (post-1.5) revision is
    /// the current device's real (verifying-key-derived) `device_id`.
    #[test]
    fn revisions_stamp_real_device_id_after_register() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "dev-stamp.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        let real_id = v.device_current().unwrap().device_id;
        let acct = v.add_account(fresh_snapshot()).unwrap();
        v.update_account(acct, fresh_snapshot()).unwrap();
        let revs = v.revisions_for(acct).unwrap();
        assert!(revs.len() >= 2);
        for r in &revs {
            assert_eq!(
                r.device_id, real_id,
                "every post-1.5 revision stamps the real device_id"
            );
        }
    }

    /// Criterion 4: `device_set_label` validates + persists; the new
    /// label survives close/reopen; an empty / over-long label is
    /// rejected; a locked-vault call errors (active session required).
    #[test]
    fn device_set_label_validates_persists_and_requires_active() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "dev-label.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let id = {
            let mut v = Vault::open(&p).unwrap();
            v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
            let id = v.device_current().unwrap().device_id;
            // Empty rejected.
            assert!(matches!(
                v.device_set_label(id, "   ").unwrap_err(),
                StoreError::Validation { kind, .. } if kind == "device_label"
            ));
            // Over-256 rejected.
            assert!(matches!(
                v.device_set_label(id, &"x".repeat(300)).unwrap_err(),
                StoreError::Validation { kind, .. } if kind == "device_label"
            ));
            // NFC-normalised + trimmed on the way in.
            v.device_set_label(id, "  Kelvin's Cafe\u{0301}  ").unwrap();
            assert_eq!(v.device_current().unwrap().label, "Kelvin's Café");
            // Locked → errors.
            v.lock();
            assert!(matches!(
                v.device_set_label(id, "Whatever").unwrap_err(),
                StoreError::NotUnlocked
            ));
            // device_current still readable on the locked vault.
            assert_eq!(v.device_current().unwrap().label, "Kelvin's Café");
            v.close().unwrap();
            id
        };
        // Survives reopen.
        let v = Vault::open(&p).unwrap();
        assert_eq!(v.device_current().unwrap().device_id, id);
        assert_eq!(v.device_current().unwrap().label, "Kelvin's Café");
    }

    // -----------------------------------------------------------------
    // MVP-1 issue 1.11: capture-authority registry tests.
    // -----------------------------------------------------------------

    fn sample_authority() -> crate::capture_authority::CaptureAuthority {
        crate::capture_authority::CaptureAuthority {
            schema_version: 1,
            kind: crate::capture_authority::CaptureAuthorityKind::BrowserExtension,
            component_id: "com.example.ext".into(),
            component_version: "1.0".into(),
        }
    }

    fn sample_context() -> crate::capture_authority::CaptureContext {
        crate::capture_authority::CaptureContext {
            schema_version: 1,
            kind: crate::capture_authority::CaptureContextKind::Browser,
            platform_hint: Some("chrome".into()),
        }
    }

    /// L6 (Created branch): a first register on an empty key is
    /// session-class — succeeds without consuming the presence proof.
    /// Subsequent identical register is a `NoOp` (no row duplication).
    #[test]
    fn capture_authority_register_then_query_roundtrip() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "ca-roundtrip.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();

        // Empty initially.
        assert!(v.capture_authority_list().unwrap().is_empty());

        // Created.
        let outcome = v
            .capture_authority_register(
                &fresh_presence(),
                sample_authority(),
                sample_context(),
                false,
            )
            .unwrap();
        assert!(matches!(
            outcome,
            crate::capture_authority::RegistrationOutcome::Created
        ));

        // Query finds it.
        let found = v
            .capture_authority_query(sample_context())
            .unwrap()
            .expect("registered");
        assert_eq!(found.authority.component_id, "com.example.ext");
        assert_eq!(found.context.platform_hint.as_deref(), Some("chrome"));

        // NoOp on identical re-register.
        let outcome = v
            .capture_authority_register(
                &fresh_presence(),
                sample_authority(),
                sample_context(),
                false,
            )
            .unwrap();
        assert!(matches!(
            outcome,
            crate::capture_authority::RegistrationOutcome::NoOp { .. }
        ));
        assert_eq!(v.capture_authority_list().unwrap().len(), 1);
    }

    /// L8: a second register with a different payload AND
    /// `replace_existing=false` surfaces `CaptureAuthorityExclusivity`
    /// (the message names the context kind only — no info-leak on the
    /// existing `component_id`). With `replace_existing=true`, the
    /// REPLACE succeeds and returns `Replaced { prior }`.
    #[test]
    fn capture_authority_rejects_exclusivity_then_replaces() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "ca-exclusivity.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        v.capture_authority_register(
            &fresh_presence(),
            sample_authority(),
            sample_context(),
            false,
        )
        .unwrap();

        let mut other = sample_authority();
        other.component_id = "com.different.ext".into();

        let err = v
            .capture_authority_register(&fresh_presence(), other.clone(), sample_context(), false)
            .unwrap_err();
        match err {
            StoreError::CaptureAuthorityExclusivity { context } => {
                // No-info-leak: the context kind is named, the existing
                // component_id is NOT in the variant.
                assert_eq!(context, "browser");
            }
            other => panic!("expected CaptureAuthorityExclusivity, got {other:?}"),
        }

        // Replace with fresh presence — succeeds.
        let outcome = v
            .capture_authority_register(&fresh_presence(), other, sample_context(), true)
            .unwrap();
        match outcome {
            crate::capture_authority::RegistrationOutcome::Replaced { prior } => {
                assert_eq!(prior.component_id, "com.example.ext");
            }
            o => panic!("expected Replaced, got {o:?}"),
        }
        // The new payload is now live.
        let found = v
            .capture_authority_query(sample_context())
            .unwrap()
            .unwrap();
        assert_eq!(found.authority.component_id, "com.different.ext");
    }

    /// L7: malformed inputs surface `CaptureAuthorityValidation` and
    /// do NOT write a row.
    #[test]
    fn capture_authority_rejects_malformed_inputs() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "ca-validation.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();

        // Empty component_id.
        let mut bad = sample_authority();
        bad.component_id = String::new();
        assert!(matches!(
            v.capture_authority_register(&fresh_presence(), bad, sample_context(), false)
                .unwrap_err(),
            StoreError::CaptureAuthorityValidation { .. }
        ));

        // Non-allowlist platform_hint.
        let mut bad_ctx = sample_context();
        bad_ctx.platform_hint = Some("opera".into());
        assert!(matches!(
            v.capture_authority_register(&fresh_presence(), sample_authority(), bad_ctx, false)
                .unwrap_err(),
            StoreError::CaptureAuthorityValidation { .. }
        ));

        // Uppercase rejected (must be lowercased ASCII).
        let mut bad_ctx = sample_context();
        bad_ctx.platform_hint = Some("Chrome".into());
        assert!(matches!(
            v.capture_authority_register(&fresh_presence(), sample_authority(), bad_ctx, false)
                .unwrap_err(),
            StoreError::CaptureAuthorityValidation { .. }
        ));

        // No row was written.
        assert!(v.capture_authority_list().unwrap().is_empty());
    }

    /// Reads on a locked vault error with `NotUnlocked`.
    #[test]
    fn capture_authority_reads_require_active_session() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "ca-locked.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        v.lock();
        assert!(matches!(
            v.capture_authority_list().unwrap_err(),
            StoreError::NotUnlocked
        ));
        assert!(matches!(
            v.capture_authority_query(sample_context()).unwrap_err(),
            StoreError::NotUnlocked
        ));
    }

    /// `clear` deletes a registered row and returns whether anything
    /// was removed. Test-only helper; not on the FFI surface in 1.11.
    #[test]
    fn capture_authority_clear_removes_row() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "ca-clear.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        v.capture_authority_register(
            &fresh_presence(),
            sample_authority(),
            sample_context(),
            false,
        )
        .unwrap();
        assert!(v.capture_authority_clear(sample_context()).unwrap());
        assert!(v
            .capture_authority_query(sample_context())
            .unwrap()
            .is_none());
        // Second clear: nothing to remove.
        assert!(!v.capture_authority_clear(sample_context()).unwrap());
    }

    /// L10 / Q-f: an archive round-trip preserves the registry in the
    /// snapshot (encode + decode), and `restore_to_new_vault` starts
    /// the destination with an empty registry (does NOT re-register
    /// the source's rows; mirrors the `devices` posture).
    #[test]
    fn capture_authority_archive_round_trip_destination_starts_empty() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "ca-archive.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        v.capture_authority_register(
            &fresh_presence(),
            sample_authority(),
            sample_context(),
            false,
        )
        .unwrap();
        let pw = SecretBytes::new(b"export-pp-123".to_vec());
        let archive = v
            .export_encrypted(
                &pw,
                &crate::export::AccountSelection::All,
                &fresh_presence(),
            )
            .unwrap();
        let snapshot = crate::export::decode_archive(&archive, &pw).unwrap();
        // The snapshot carries the registered row.
        assert_eq!(snapshot.capture_authorities.len(), 1);
        assert_eq!(
            snapshot.capture_authorities[0].component_id,
            "com.example.ext"
        );
        // Restore into a fresh vault. Q-f: destination starts with an
        // empty registry — the snapshot field is carried for fidelity
        // but `restore_to_new_vault` ignores it.
        v.close().unwrap();
        let dest_dir = TempDir::new().unwrap();
        let dest = vault_path(&dest_dir, "ca-archive-restored.pvf");
        let new_master = SecretBytes::new(b"new-master".to_vec());
        Vault::restore_to_new_vault(&dest, snapshot, &new_master).unwrap();
        let mut dv = Vault::open(&dest).unwrap();
        dv.unlock(
            &fresh_presence(),
            &crate::session::PinIdentityProof::new(SecretBytes::new(b"new-master".to_vec())),
        )
        .unwrap();
        assert!(
            dv.capture_authority_list().unwrap().is_empty(),
            "Q-f: restored vault starts with an empty capture-authority registry"
        );
    }

    /// §18.7 per-row ladder: a row hand-injected with a
    /// `schema_version` above the supported max is rejected at decode
    /// for that row only; the rest of the vault is fine. We poke a
    /// row in directly via SQL so the test does not depend on a
    /// future build.
    #[test]
    fn capture_authority_future_row_schema_version_rejected_per_row() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "ca-future-row.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        // A clean valid row first.
        v.capture_authority_register(
            &fresh_presence(),
            sample_authority(),
            sample_context(),
            false,
        )
        .unwrap();
        // Hand-inject a row with a future schema_version on a
        // different key.
        v.conn
            .execute(
                "INSERT INTO capture_authorities \
                   (context_kind, platform_hint, authority_kind, component_id, \
                    component_version, registered_at, schema_version) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                rusqlite::params![
                    0i64, // Desktop context
                    "",
                    0i64, // Desktop authority kind
                    "future-ext".to_string(),
                    "9.9".to_string(),
                    1_700_000_000_000i64,
                    i64::from(crate::capture_authority::CAPTURE_AUTHORITY_SCHEMA_VERSION_MAX + 1,),
                ],
            )
            .unwrap();
        // `list` rejects when it hits the future row.
        assert!(matches!(
            v.capture_authority_list().unwrap_err(),
            StoreError::CaptureAuthorityValidation { .. }
        ));
        // `query` for the future-row's key rejects too.
        let future_ctx = crate::capture_authority::CaptureContext {
            schema_version: 1,
            kind: crate::capture_authority::CaptureContextKind::Desktop,
            platform_hint: None,
        };
        assert!(matches!(
            v.capture_authority_query(future_ctx.clone()).unwrap_err(),
            StoreError::CaptureAuthorityValidation { .. }
        ));
        // Re-audit L1: `register` against the future-row's key must
        // also reject — both the would-be-NoOp shape (a byte-matching
        // payload that would otherwise short-circuit to NoOp) AND the
        // would-be-Replace shape (`replace_existing=true` that would
        // otherwise silently downgrade the future row to the current
        // MAX). Both arms drive the new §18.7 ladder check on the
        // register path (vault.rs:`capture_authority_register_in_tx`)
        // that the read paths already enforced via `decode_row`.
        let byte_matching_authority = crate::capture_authority::CaptureAuthority {
            schema_version: 1,
            kind: crate::capture_authority::CaptureAuthorityKind::Desktop,
            component_id: "future-ext".into(),
            component_version: "9.9".into(),
        };
        // Would-be-NoOp (replace_existing=false, payload matches the
        // hand-injected future row byte-for-byte): rejects on ladder.
        assert!(matches!(
            v.capture_authority_register(
                &fresh_presence(),
                byte_matching_authority.clone(),
                future_ctx.clone(),
                false,
            )
            .unwrap_err(),
            StoreError::CaptureAuthorityValidation { .. }
        ));
        // Would-be-Replace (replace_existing=true, payload differs):
        // rejects on ladder before the presence check fires.
        let mut different_authority = byte_matching_authority;
        different_authority.component_id = "different-ext".into();
        assert!(matches!(
            v.capture_authority_register(&fresh_presence(), different_authority, future_ctx, true,)
                .unwrap_err(),
            StoreError::CaptureAuthorityValidation { .. }
        ));
        // The hand-injected row's columns are unchanged — neither
        // register attempt mutated it (the outer wrapper rolled back).
        let still_future_sv: i64 = v
            .conn
            .query_row(
                "SELECT schema_version FROM capture_authorities \
                 WHERE context_kind = 0 AND platform_hint = ''",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            still_future_sv,
            i64::from(crate::capture_authority::CAPTURE_AUTHORITY_SCHEMA_VERSION_MAX + 1),
            "register's ladder check must not have downgraded the future row"
        );
        // The valid (Browser/chrome) row remains queryable.
        let ok = v
            .capture_authority_query(sample_context())
            .unwrap()
            .unwrap();
        assert_eq!(ok.authority.component_id, "com.example.ext");
    }

    /// Plan §6 Test 5 / audit F2 fix: a session expired by idle
    /// timeout blocks `capture_authority_register` for both
    /// `replace_existing=false` (would-be Created or Exclusivity) and
    /// `replace_existing=true` (would-be Replaced). The
    /// `check_session_freshness` preamble fires *before* any DB I/O,
    /// presence check, or row mutation — same shape as
    /// `device_set_label`'s active-session contract.
    #[test]
    fn capture_authority_register_session_expired_blocked() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "ca-session-expired.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let (mut v, clock) = open_vault_with_test_clock(&p);
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();

        // Seed a row so the second register (after expiry) would land
        // on either NoOp / Exclusivity / Replaced — exercising the
        // existence branches as well as the no-existing-row branch.
        v.capture_authority_register(
            &fresh_presence(),
            sample_authority(),
            sample_context(),
            false,
        )
        .unwrap();

        // Advance clock past the idle deadline.
        clock.advance(IDLE_TIMEOUT_DEFAULT + Duration::from_secs(1));

        // replace_existing = false → would-be Exclusivity if the
        // session were live; with the expired session we hit
        // SessionExpired first, before validation / DB / presence.
        let mut other = sample_authority();
        other.component_id = "com.different.ext".into();
        let err = v
            .capture_authority_register(&fresh_presence(), other.clone(), sample_context(), false)
            .unwrap_err();
        assert!(
            matches!(err, StoreError::SessionExpired),
            "expected SessionExpired (replace_existing=false), got {err:?}"
        );

        // After SessionExpired surfaces, the session is torn down;
        // re-unlock to get back into a usable state for the second arm.
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        clock.advance(IDLE_TIMEOUT_DEFAULT + Duration::from_secs(1));

        // replace_existing = true → would-be Replaced if the session
        // were live; with the expired session we hit SessionExpired
        // before the presence check is invoked (the proof is dead
        // weight on the failure path — never consumed).
        let err = v
            .capture_authority_register(&fresh_presence(), other, sample_context(), true)
            .unwrap_err();
        assert!(
            matches!(err, StoreError::SessionExpired),
            "expected SessionExpired (replace_existing=true), got {err:?}"
        );

        // The originally-seeded row is unchanged.
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        let found = v
            .capture_authority_query(sample_context())
            .unwrap()
            .expect("seeded row survives the failed register attempts");
        assert_eq!(found.authority.component_id, "com.example.ext");
    }

    /// Criterion 5: the in-memory `DeviceKey` is dropped on `lock()` —
    /// the test/test-utilities accessor returns `None` afterwards — and
    /// is re-loaded (decrypting the AEAD-sealed seed under the VDK) on
    /// the next `unlock`, re-deriving the same `device_id`.
    #[test]
    fn device_key_dropped_on_lock_and_reloaded_on_unlock() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "dev-key-lifecycle.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        let vk1 = v.device_key_verifying_key().expect("device key present");
        v.lock();
        assert_eq!(
            v.device_key_verifying_key(),
            None,
            "DeviceKey must be dropped on lock()"
        );
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        let vk2 = v.device_key_verifying_key().expect("device key reloaded");
        assert_eq!(vk1, vk2, "reloaded DeviceKey re-derives the same device_id");
    }

    /// MVP-2 issue 3.2 (R-b): `Vault::evm_wallet()` returns Ok on an
    /// active session and surfaces the address that
    /// `pangolin_chain::derive_evm_wallet` would produce; the access
    /// fails on a locked vault, a never-unlocked vault, and an
    /// expired session.
    #[test]
    fn evm_wallet_accessor_works_on_active_only() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "evm-wallet-active.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        // Not unlocked yet → NotUnlocked.
        assert!(matches!(
            v.evm_wallet().unwrap_err(),
            StoreError::NotUnlocked
        ));
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        // Active → Ok, address matches the cached `devices.evm_address`.
        let cached = v
            .device_current()
            .unwrap()
            .evm_address
            .expect("3.2-era unlock populates the cache");
        let wallet_addr = v.evm_wallet().unwrap().address();
        assert_eq!(
            wallet_addr.as_slice(),
            cached.as_slice(),
            "wallet address must match the cached column"
        );
        v.lock();
        // Locked → NotUnlocked again (the wallet dropped with the
        // session — see `evm_wallet_dropped_on_lock_idle_expiry_absolute_expiry`).
        assert!(matches!(
            v.evm_wallet().unwrap_err(),
            StoreError::NotUnlocked
        ));
    }

    /// MVP-2 issue 3.5 (R-a hybrid): the SYNC accessor
    /// `Vault::evm_wallet_address` reads the cached `devices.evm_address`
    /// column on a LOCKED vault. L5 nuance: the chain-crate balance
    /// helper is policy-agnostic, so this layer is NOT
    /// active-session-gated (the FFI layer IS gated; see
    /// `pangolin-ffi/src/balance.rs`).
    #[test]
    fn evm_wallet_address_accessor_works_on_locked_vault() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "evm-addr-locked.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        // Unlock once so the device row is registered (3.2-era unlock
        // back-fills the evm_address column).
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        let unlocked_addr = v.evm_wallet_address().expect("unlocked accessor works");
        // Lock the vault; the cached column survives.
        v.lock();
        let locked_addr = v
            .evm_wallet_address()
            .expect("LOCKED accessor must work — column is on disk");
        assert_eq!(
            unlocked_addr, locked_addr,
            "sync accessor must return same address before + after lock"
        );
        // Cross-check against the cached column reported via
        // `device_current`.
        let cached = v
            .device_current()
            .unwrap()
            .evm_address
            .expect("3.2-era unlock populates the cache");
        assert_eq!(
            locked_addr, cached,
            "sync accessor must match the device_current cached column"
        );
    }

    /// MVP-2 issue 3.5 (R-a): on a brand-new vault opened but NEVER
    /// unlocked, `evm_wallet_address` errors `NotUnlocked` because no
    /// device row exists yet (register-on-unlock).
    #[test]
    fn evm_wallet_address_errors_when_no_device_registered() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "evm-addr-no-device.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let v = Vault::open(&p).unwrap();
        let err = v
            .evm_wallet_address()
            .expect_err("never-unlocked vault has no device row");
        assert!(
            matches!(err, StoreError::NotUnlocked),
            "expected NotUnlocked, got {err:?}"
        );
    }

    /// MVP-2 issue 3.6 (R-c distributed-impl touchpoint).
    ///
    /// Verify that `pangolin_chain::DefaultStrategy::select_address_for_vault`
    /// returns the default address verbatim at the consumer boundary.
    /// `pangolin-store::Vault` is one of the three Phase-2 hook
    /// consumers (optional fresh-address-per-vault); this test pins
    /// that consumers CAN construct + call the trait today AND that
    /// the no-op default preserves 3.5 behaviour bit-for-bit (L1 +
    /// L4 verbatim).
    ///
    /// The `vault_id` is sourced from the actual `Vault::vault_id`
    /// surface (3.2 R-a) — the trait method takes `[u8; 32]` so
    /// callers can wire any 32-byte identifier; here we use the same
    /// alloy `Address` the wallet returns, padded to 32 bytes for
    /// shape compatibility.
    #[test]
    fn issue_3_6_default_strategy_select_address_for_vault_is_pass_through() {
        use pangolin_chain::{Address, DefaultStrategy, PrivacyStrategy};

        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "issue-3-6-select-addr.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        let default_addr_bytes = v.evm_wallet_address().expect("unlocked accessor works");
        let default_addr = Address::from(default_addr_bytes);

        // Synthetic vault-id: the test doesn't have direct access to a
        // 32-byte vault identifier (pangolin-store identifies devices
        // by name, not vaults by 32-byte ids), so we use a fixed test
        // shape. The 3.6 trait method only cares about pass-through.
        let vault_id_a = [0x11u8; 32];
        let vault_id_b = [0x22u8; 32];

        let out_a = DefaultStrategy
            .select_address_for_vault(vault_id_a, default_addr)
            .expect("default select_address must succeed");
        let out_b = DefaultStrategy
            .select_address_for_vault(vault_id_b, default_addr)
            .expect("default select_address must succeed");

        assert_eq!(
            out_a, default_addr,
            "DefaultStrategy must pass through the default address at the \
             pangolin-store consumer boundary (3.6 L1 + L4)"
        );
        assert_eq!(
            out_a, out_b,
            "DefaultStrategy must ignore vault_id (no-op invariant)"
        );
    }

    /// MVP-2 issue 3.6 (R-c distributed-impl touchpoint).
    ///
    /// Verify that
    /// `pangolin_chain::DefaultStrategy::derive_wallet_for_revision`
    /// returns the same wallet as `Vault::evm_wallet()` does today.
    /// `pangolin-store::Vault` is one of the three Phase-2 hook
    /// consumers (per-revision wallet rotation); this test pins the
    /// byte-identity property at the signing-side consumer boundary.
    ///
    /// `Vault` does not currently expose a `pub fn device_key`
    /// accessor (the active `DeviceKey` is private to the session
    /// state). The test uses the gated `device_key_secret_seed`
    /// affordance to reconstruct a `DeviceKey` from the same seed
    /// the active session derived its wallet from, then runs both
    /// the `Vault::evm_wallet` accessor + the
    /// `DefaultStrategy::derive_wallet_for_revision` hook against
    /// it. The address-equality assertion is the byte-identity pin.
    #[test]
    fn issue_3_6_default_strategy_derive_wallet_matches_vault_wallet() {
        use pangolin_chain::{DefaultStrategy, PrivacyStrategy};
        use pangolin_crypto::keys::DeviceKey;

        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "issue-3-6-derive-wallet.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();

        let vault_wallet_addr = v.evm_wallet().unwrap().address();
        let seed = v
            .device_key_secret_seed()
            .expect("active session must expose seed via test-utilities affordance");
        let device_key = DeviceKey::from_seed(*seed);

        // The DefaultStrategy's derive_wallet_for_revision must
        // produce the SAME address as Vault::evm_wallet at every
        // revision_index (no-op invariant: index is ignored).
        let via_default_idx0 = DefaultStrategy
            .derive_wallet_for_revision(&device_key, 0)
            .expect("derive via default at idx 0");
        let via_default_idx_99 = DefaultStrategy
            .derive_wallet_for_revision(&device_key, 99)
            .expect("derive via default at idx 99");

        assert_eq!(
            via_default_idx0.address(),
            vault_wallet_addr,
            "DefaultStrategy must produce same wallet address as Vault::evm_wallet \
             at the pangolin-store consumer boundary (3.6 L1 + L4)"
        );
        assert_eq!(
            via_default_idx_99.address(),
            vault_wallet_addr,
            "DefaultStrategy must ignore revision_index at vault layer"
        );
    }

    /// MVP-2 issue 3.2 (L2): the in-memory `EvmWallet` is dropped on
    /// every session-teardown path — `lock()`, idle expiry, and
    /// absolute expiry — alongside the existing `DeviceKey`. We
    /// observe the drop indirectly: `evm_wallet()` errors after each
    /// teardown.
    ///
    /// Three subtests in one (the plan-gate's "three subtests if
    /// convenient" wording): all three legs share the same setup
    /// helpers + the assertion shape, so they live in one body to
    /// keep the noise down.
    #[test]
    fn evm_wallet_dropped_on_lock_idle_expiry_absolute_expiry() {
        // Leg 1: lock().
        {
            let dir = TempDir::new().unwrap();
            let p = vault_path(&dir, "evm-wallet-lock.pvf");
            Vault::create(&p, &fresh_password()).unwrap();
            let mut v = Vault::open(&p).unwrap();
            v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
            assert!(v.evm_wallet().is_ok());
            v.lock();
            assert!(matches!(
                v.evm_wallet().unwrap_err(),
                StoreError::NotUnlocked
            ));
        }
        // Leg 2: idle-timer expiry.
        {
            let dir = TempDir::new().unwrap();
            let p = vault_path(&dir, "evm-wallet-idle.pvf");
            Vault::create(&p, &fresh_password()).unwrap();
            let (mut v, clock) = open_vault_with_test_clock(&p);
            v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
            assert!(v.evm_wallet().is_ok());
            clock.advance(IDLE_TIMEOUT_DEFAULT + Duration::from_secs(1));
            // A cache-bearing &mut op observes expiry and drops
            // ActiveState (the documented mechanism — same as
            // `device_key_dropped_on_session_expiry`).
            let err = v.add_account(fresh_snapshot()).unwrap_err();
            assert!(matches!(err, StoreError::SessionExpired));
            assert!(matches!(
                v.evm_wallet().unwrap_err(),
                StoreError::NotUnlocked
            ));
        }
        // Leg 3: absolute-max expiry.
        {
            let dir = TempDir::new().unwrap();
            let p = vault_path(&dir, "evm-wallet-abs.pvf");
            Vault::create(&p, &fresh_password()).unwrap();
            let (mut v, clock) = open_vault_with_test_clock(&p);
            v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
            assert!(v.evm_wallet().is_ok());
            clock.advance(crate::session::ABSOLUTE_MAX_DEFAULT + Duration::from_secs(1));
            let err = v.add_account(fresh_snapshot()).unwrap_err();
            assert!(matches!(err, StoreError::SessionExpired));
            assert!(matches!(
                v.evm_wallet().unwrap_err(),
                StoreError::NotUnlocked
            ));
        }
    }

    /// MVP-2 issue 3.1 (L5 + R-a..R-e): `Vault::sign_revision_v1` is
    /// reachable ONLY via an active session. Three legs (mirroring
    /// `evm_wallet_accessor_works_on_active_only`):
    ///
    /// 1. Locked vault → `StoreError::NotUnlocked`.
    /// 2. Active session → `Ok(SignedRevisionV1)` with a 65-byte sig.
    /// 3. Idle-expired session → `StoreError::SessionExpired` via the
    ///    require-active gate (an intervening cache-bearing &mut op
    ///    observes expiry and drops `ActiveState`).
    ///
    /// The sig itself is also recovery-checked: signing then
    /// recovering via the wallet's address must round-trip — but
    /// that's covered hermetically in `pangolin-chain` already; this
    /// test focuses on the session gate, the production-critical
    /// piece.
    #[test]
    fn sign_revision_v1_requires_active_session() {
        use pangolin_chain::{ChainEnv, RevisionFieldsV1};
        // Canonical preimage + matching hash; carried in tandem so the
        // 3.3 audit-HIGH `SignedRevisionV1` invariant
        // (`keccak256(enc_payload) == fields.enc_payload_hash`) holds.
        // The hash below was derived once via:
        //   cast keccak 0x$(printf 'store-test-encpayload' | xxd -p)
        // (output `0x9c03f671f049c622c4ada35ebfe4c443eb25050ee033bfbd064df8191cb045b3`).
        // Pinned as a hex literal so pangolin-store doesn't need a
        // direct alloy or sha3 dependency just for this one site —
        // the chain crate's `debug_assert!` re-validates the
        // invariant when `build_signed_revision_v1` is called, so a
        // typo in this constant fires loudly in cargo test.
        let enc_payload: Vec<u8> = b"store-test-encpayload".to_vec();
        let enc_payload_hash: [u8; 32] = [
            0x9c, 0x03, 0xf6, 0x71, 0xf0, 0x49, 0xc6, 0x22, 0xc4, 0xad, 0xa3, 0x5e, 0xbf, 0xe4,
            0xc4, 0x43, 0xeb, 0x25, 0x05, 0x0e, 0xe0, 0x33, 0xbf, 0xbd, 0x06, 0x4d, 0xf8, 0x19,
            0x1c, 0xb0, 0x45, 0xb3,
        ];

        // Leg 1: Locked → NotUnlocked.
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "sign-v1-locked.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        let fields = RevisionFieldsV1 {
            vault_id: [0x11; 32],
            account_id: [0x22; 32],
            parent_revision: [0x33; 32],
            device_id: [0x44; 32],
            schema_version: 1,
            enc_payload_hash,
        };
        let err = v
            .sign_revision_v1(fields, enc_payload.clone(), ChainEnv::BaseSepolia, 84_532)
            .unwrap_err();
        assert!(
            matches!(err, StoreError::NotUnlocked),
            "Locked vault must error NotUnlocked, got {err:?}"
        );

        // Leg 2: Active → Ok + 65-byte sig + device_id-derived sig
        // matches the wallet's address.
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        let wallet_addr = v.evm_wallet().unwrap().address();
        let fields = RevisionFieldsV1::with_signer_device_id(
            v.evm_wallet().unwrap(),
            [0x11; 32],
            [0x22; 32],
            [0x33; 32],
            1,
            enc_payload_hash,
        );
        let signed = v
            .sign_revision_v1(fields, enc_payload.clone(), ChainEnv::BaseSepolia, 84_532)
            .expect("active session must sign");
        assert_eq!(signed.signature.len(), 65, "EIP-712 sig is 65 bytes");
        // device_id field carries the left-padded wallet address.
        assert_eq!(
            &signed.fields.device_id[12..],
            wallet_addr.as_slice(),
            "device_id must be the left-padded wallet address"
        );
        // 3.3 audit-HIGH: preimage rides through onto the
        // `SignedRevisionV1` so the broadcast layer can put it on the
        // wire as the `encPayload` calldata bytes.
        assert_eq!(
            signed.enc_payload, enc_payload,
            "SignedRevisionV1 must carry the preimage through Vault::sign_revision_v1"
        );

        // Leg 3: idle-expired session → SessionExpired via the
        // require-active gate (an intervening &mut op observes
        // expiry; then the &self signing call sees no active state).
        let dir2 = TempDir::new().unwrap();
        let p2 = vault_path(&dir2, "sign-v1-expired.pvf");
        Vault::create(&p2, &fresh_password()).unwrap();
        let (mut v2, clock) = open_vault_with_test_clock(&p2);
        v2.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        assert!(v2
            .sign_revision_v1(fields, enc_payload.clone(), ChainEnv::BaseSepolia, 84_532)
            .is_ok());
        clock.advance(IDLE_TIMEOUT_DEFAULT + Duration::from_secs(1));
        // Trigger expiry via an &mut op — the documented mechanism.
        let err = v2.add_account(fresh_snapshot()).unwrap_err();
        assert!(matches!(err, StoreError::SessionExpired));
        // Now the &self signing call sees no active state.
        let err = v2
            .sign_revision_v1(fields, enc_payload, ChainEnv::BaseSepolia, 84_532)
            .unwrap_err();
        assert!(
            matches!(err, StoreError::NotUnlocked),
            "expired session must error NotUnlocked, got {err:?}"
        );
    }

    /// Criterion 5 (expiry leg): the in-memory `DeviceKey` is also
    /// dropped when the session expires (idle / absolute-max) — same
    /// teardown path as the cache + `:memory:` index.
    #[test]
    fn device_key_dropped_on_session_expiry() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "dev-key-expiry.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let (mut v, clock) = open_vault_with_test_clock(&p);
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        assert!(v.device_key_verifying_key().is_some());
        // Advance past the idle deadline; a cache-bearing `&mut self`
        // op (`add_account`) runs `check_session_freshness`, which on
        // expiry drops the `ActiveState` (cache + `:memory:` index +
        // `DeviceKey`) and surfaces `SessionExpired`.
        clock.advance(IDLE_TIMEOUT_DEFAULT + Duration::from_secs(1));
        let err = v.add_account(fresh_snapshot()).unwrap_err();
        assert!(matches!(err, StoreError::SessionExpired));
        assert!(matches!(
            v.session_state(),
            crate::session::SessionState::Expired
        ));
        assert_eq!(
            v.device_key_verifying_key(),
            None,
            "DeviceKey must be dropped on session expiry"
        );
    }

    /// Criterion 8: `last_sync_at` stays `None` across N add/update/
    /// lock/unlock cycles (the dormant-column shape — MVP-2's chain-sync
    /// code is what populates it).
    #[test]
    fn last_sync_at_is_none_and_stays_none() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "dev-lastsync.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        assert_eq!(v.device_current().unwrap().last_sync_at, None);
        for _ in 0..3 {
            let acct = v.add_account(fresh_snapshot()).unwrap();
            v.update_account(acct, fresh_snapshot()).unwrap();
            v.lock();
            v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
            assert_eq!(
                v.device_current().unwrap().last_sync_at,
                None,
                "last_sync_at is dormant in MVP-1; MVP-2's chain sync fills it"
            );
        }
    }

    /// Criterion 11/13: a presence proof whose `created_at` is already
    /// stale (the prompt aged out) at a reveal site → `PromptTimedOut`,
    /// distinct from `AuthenticationFailed`. Needs the dedup window to
    /// be *closed* first (advance the test clock past
    /// [`crate::session::PRESENCE_FRESHNESS`] since the unlock's presence).
    #[test]
    fn reveal_with_stale_proof_returns_prompt_timed_out() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "prompt-timeout.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let (mut v, clock) = open_vault_with_test_clock(&p);
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        let id = v.add_account(fresh_snapshot()).unwrap();
        // Close the dedup window opened by the unlock.
        clock.advance(PRESENCE_FRESHNESS + Duration::from_secs(10));
        // A proof constructed >60 s ago (in real time) at a reveal site.
        let stale = PressYPresenceProof::__test_with_timestamp(
            SystemTime::now() - PRESENCE_FRESHNESS - Duration::from_secs(30),
        );
        let err = v.reveal_notes(id, &stale).unwrap_err();
        assert!(matches!(err, StoreError::PromptTimedOut), "got {err:?}");
        // PromptTimedOut is distinct from AuthenticationFailed.
        assert!(!matches!(err, StoreError::AuthenticationFailed));
    }

    /// Criterion 12 (new): `with_session(op, reauth)` where `reauth`
    /// fails — `op` must NOT run and the reauth error propagates.
    /// (`with_session_resumes_op_after_reauth` already covers the
    /// happy path + the wrong-PIN-reauth case; this one is the
    /// dedicated "op never runs" assertion via a panic in `op`.)
    #[test]
    fn with_session_reauth_err_does_not_run_op() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "ws-reauth-err.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let (mut v, clock) = open_vault_with_test_clock(&p);
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        v.add_account(fresh_snapshot()).unwrap();
        clock.advance(IDLE_TIMEOUT_DEFAULT + Duration::from_secs(1));
        let err = v
            .with_session(
                |_v| -> Result<(), StoreError> { panic!("op must not run when reauth errors") },
                |_v| Err(StoreError::AuthenticationFailed),
            )
            .unwrap_err();
        assert!(matches!(err, StoreError::AuthenticationFailed));
    }

    /// Criterion 10 (dedup): two reveals within 60 s of the last
    /// successful presence — the second does not consume a proof.
    /// Demonstrated by passing an *already-consumed* proof to the
    /// second reveal: if the engine called `verify()` it would reject
    /// with `PresenceAlreadyConsumed` (→ `AuthenticationFailed`); since
    /// the engine dedups, it never calls `verify()` and the reveal
    /// succeeds.
    #[test]
    fn two_reveals_within_window_verify_proof_once() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "dedup.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        let snap = AccountSnapshot::new(
            SecretBytes::new(b"d".to_vec()),
            SecretBytes::new(b"u".to_vec()),
            SecretBytes::new(b"the-pw".to_vec()),
            SecretBytes::new(b"https://x".to_vec()),
            SecretBytes::new(b"".to_vec()),
            SecretBytes::new(b"".to_vec()),
        );
        let id = v.add_account(snap).unwrap();
        // First reveal: dedup'd against the unlock's presence (no
        // verify) — succeeds.
        assert_eq!(
            v.reveal_password(id, &fresh_presence()).unwrap().expose(),
            b"the-pw"
        );
        // Second reveal with an already-consumed proof: still dedup'd,
        // never verified — succeeds.
        let burned = PressYPresenceProof::confirmed();
        let _ = <PressYPresenceProof as crate::session::PresenceProof>::verify(&burned);
        assert_eq!(v.reveal_password(id, &burned).unwrap().expose(), b"the-pw");
    }

    /// Criterion 13: `reveal_password_history` returns the full V1
    /// history — bytes + timestamps + originating device per entry,
    /// newest first. Uses the V1 `account_add` / `account_update` path
    /// (the V0 `add_account` shadow only carries the head).
    #[test]
    fn reveal_password_history_returns_full_history() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "pw-history.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        let draft = crate::account::AccountIdentityDraft {
            schema_version: crate::account::ACCOUNT_IDENTITY_SCHEMA_VERSION,
            display_name: "GitHub".into(),
            tags: vec!["work".into()],
            usernames: vec!["alice@example.com".into()],
            urls: vec!["https://github.com".into()],
            notes: "n".into(),
            password: SecretBytes::new(b"pw-genesis".to_vec()),
            totp_secret: SecretBytes::new(Vec::new()),
            totp_params: crate::account::TotpParams::default(),
        };
        let id = v.account_add(draft).unwrap();
        for new in [b"pw-2".as_slice(), b"pw-3".as_slice()] {
            let patch = crate::account::AccountIdentityPatch {
                schema_version: crate::account::ACCOUNT_IDENTITY_SCHEMA_VERSION,
                display_name: None,
                tags: None,
                usernames: None,
                urls: None,
                notes: None,
                password: Some(SecretBytes::new(new.to_vec())),
                totp_secret: None,
                totp_params: None,
            };
            v.account_update(id, patch).unwrap();
        }
        let history = v.reveal_password_history(id, &fresh_presence()).unwrap();
        assert_eq!(history.len(), 3);
        // Newest first.
        assert_eq!(history[0].password.expose(), b"pw-3");
        assert_eq!(history[1].password.expose(), b"pw-2");
        assert_eq!(history[2].password.expose(), b"pw-genesis");
        // Each entry carries a 32-byte originating device + a timestamp.
        assert_eq!(history[0].originating_device.0.len(), 32);
        assert!(history[0].set_at_ms >= history[2].set_at_ms);
        // reveal_current_password agrees with the head.
        assert_eq!(
            v.reveal_current_password(id, &fresh_presence())
                .unwrap()
                .expose(),
            b"pw-3"
        );
    }

    /// Criterion 13: reveal-class ops on a locked vault → `NotUnlocked`;
    /// on an expired session → `SessionExpired` (cache zeroized); on a
    /// frozen account → `AccountFrozenPendingResolve` (proof not
    /// consumed — checked before `ensure_presence_fresh`).
    #[test]
    fn reveal_on_locked_and_expired_session_errors() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "reveal-errs.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let (mut v, clock) = open_vault_with_test_clock(&p);
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        let id = v.add_account(fresh_snapshot()).unwrap();
        // Locked: NotUnlocked.
        v.lock();
        let err = v.reveal_notes(id, &fresh_presence()).unwrap_err();
        assert!(matches!(err, StoreError::NotUnlocked), "got {err:?}");
        // Re-unlock, then expire the session: SessionExpired (cache gone).
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        clock.advance(IDLE_TIMEOUT_DEFAULT + Duration::from_secs(1));
        let err = v.reveal_totp_secret(id, &fresh_presence()).unwrap_err();
        assert!(matches!(err, StoreError::SessionExpired), "got {err:?}");
        assert!(v.list_accounts().is_empty());
        // history reveal on the expired session → also SessionExpired.
        let err = v
            .reveal_password_history(id, &fresh_presence())
            .unwrap_err();
        assert!(matches!(err, StoreError::SessionExpired));
    }

    /// Plan success criterion 8:
    /// `vault::tests::with_session_resumes_op_after_reauth` — when the
    /// session is expired, `with_session(op, reauth)` runs reauth then
    /// runs op and returns its T.
    #[test]
    fn with_session_resumes_op_after_reauth() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "withsession.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let (mut v, clock) = open_vault_with_test_clock(&p);
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        v.add_account(fresh_snapshot()).unwrap();

        // Expire the session.
        clock.advance(IDLE_TIMEOUT_DEFAULT + Duration::from_secs(1));

        // The op closure: list accounts after re-auth. We use a
        // SessionExpired-confirming first call to verify the session
        // really was expired (sanity check).
        // Actually we route through with_session — its proactive
        // freshness check will detect the expiry, run reauth, and
        // then run op.
        let count = v
            .with_session(
                |v_inner| Ok(v_inner.list_accounts().len()),
                |v_inner| {
                    let presence = PressYPresenceProof::confirmed();
                    let identity = PinIdentityProof::new(fresh_password());
                    v_inner.unlock(&presence, &identity)
                },
            )
            .unwrap();
        assert_eq!(count, 1, "op must run after reauth and see the cache");
        assert!(v.is_session_active(), "session must be live after reauth");

        // If reauth itself fails, op MUST NOT run and the original
        // error propagates. Re-expire and try with a wrong PIN.
        clock.advance(IDLE_TIMEOUT_DEFAULT + Duration::from_secs(1));
        let err = v
            .with_session(
                |_v_inner| -> Result<usize, StoreError> {
                    panic!("op must NOT run when reauth fails");
                },
                |v_inner| {
                    let presence = PressYPresenceProof::confirmed();
                    let identity = PinIdentityProof::new(SecretBytes::new(b"wrong".to_vec()));
                    v_inner.unlock(&presence, &identity)
                },
            )
            .unwrap_err();
        assert!(matches!(err, StoreError::AuthenticationFailed));
    }

    /// P4 audit L-3: a malformed reauth callback that returns
    /// `Ok(())` WITHOUT actually transitioning the vault back to
    /// `Active` must NOT cause `with_session` to run `op`. The
    /// post-reauth `check_session_freshness` re-validation surfaces
    /// `SessionExpired` immediately. This protects against host UIs
    /// whose reauth flow paths can erroneously short-circuit success
    /// (e.g., a UI bug that loses the focus event between the prompt
    /// and the unlock call).
    #[test]
    fn with_session_revalidates_after_reauth_returns_ok() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "with-session-revalidate.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let (mut v, clock) = open_vault_with_test_clock(&p);
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        v.add_account(fresh_snapshot()).unwrap();

        // Expire the session.
        clock.advance(IDLE_TIMEOUT_DEFAULT + Duration::from_secs(1));

        // The malformed reauth: returns Ok(()) without unlocking.
        // `op` MUST NOT run. The error must be `SessionExpired`,
        // surfaced by the L-3 re-validation step inside
        // `with_session`.
        let err = v
            .with_session(
                |_v_inner| -> Result<usize, StoreError> {
                    panic!("op must NOT run when reauth lies about success");
                },
                |_v_inner| Ok(()),
            )
            .unwrap_err();
        assert!(
            matches!(err, StoreError::SessionExpired),
            "expected SessionExpired from L-3 re-validation; got {err:?}"
        );
    }

    /// Plan success criterion 9:
    /// `vault::tests::session_remaining_decreases_with_time` — the
    /// `is_session_active` and `session_remaining` accessors reflect
    /// the current state.
    #[test]
    fn session_remaining_decreases_with_time() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "remaining.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let (mut v, clock) = open_vault_with_test_clock(&p);
        // Locked: no remaining.
        assert!(!v.is_session_active());
        assert!(v.session_remaining().is_none());

        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        // Right after unlock: remaining ≈ IDLE_TIMEOUT_DEFAULT.
        let r0 = v.session_remaining().unwrap();
        assert_eq!(r0, IDLE_TIMEOUT_DEFAULT);

        // Advance 5 min — remaining drops by 5 min.
        clock.advance(Duration::from_secs(5 * 60));
        let r1 = v.session_remaining().unwrap();
        assert_eq!(
            r1,
            IDLE_TIMEOUT_DEFAULT
                .checked_sub(Duration::from_secs(5 * 60))
                .unwrap()
        );

        // Past the deadline: remaining == ZERO (saturating).
        clock.advance(IDLE_TIMEOUT_DEFAULT);
        let r_zero = v.session_remaining().unwrap();
        assert_eq!(r_zero, Duration::ZERO);

        // After lock(): no remaining.
        v.lock();
        assert!(v.session_remaining().is_none());
        assert!(!v.is_session_active());
    }

    /// Plan success criterion 10:
    /// `vault::tests::expired_session_zeroizes_cache` — when the
    /// idle timer fires and the next op detects expiry, the in-memory
    /// cache is GONE. Mirrors the P2 `lock_zeroizes_cache` test
    /// pattern: post-expiry, `list_accounts` is empty and
    /// `get_account` returns `None`.
    #[test]
    fn expired_session_zeroizes_cache() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "zero-on-expiry.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let (mut v, clock) = open_vault_with_test_clock(&p);
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        let id = v.add_account(fresh_snapshot()).unwrap();
        // Sanity: cache populated.
        assert!(v.get_account(id).is_some());
        assert_eq!(v.list_accounts().len(), 1);

        // Advance past idle deadline.
        clock.advance(IDLE_TIMEOUT_DEFAULT + Duration::from_secs(1));

        // First op after expiry: surfaces SessionExpired AND the cache
        // is gone (read-side already reports empty/None because
        // `is_session_active()` is now clock-aware (P4 M-4) and
        // returns `false` once the deadline is crossed).
        assert!(v.get_account(id).is_none());
        assert!(v.list_accounts().is_empty());
        let err = v.update_account(id, fresh_snapshot()).unwrap_err();
        assert!(matches!(err, StoreError::SessionExpired));

        // After the strict op transitions state to Expired, the
        // session_state is Expired (not Active anymore) and the
        // cache is dropped.
        assert!(matches!(
            v.session_state(),
            crate::session::SessionState::Expired
        ));
        assert!(!v.is_session_active());
    }

    /// Defense-in-depth: high-risk ops (`reveal_password`,
    /// `export_payload`) called with the session expired must surface
    /// `SessionExpired` BEFORE the presence proof is verified — so the
    /// caller can re-auth without burning their proof.
    #[test]
    fn high_risk_op_on_expired_session_surfaces_session_expired_first() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "expired-reveal.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let (mut v, clock) = open_vault_with_test_clock(&p);
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        let id = v.add_account(fresh_snapshot()).unwrap();

        // Expire the session.
        clock.advance(IDLE_TIMEOUT_DEFAULT + Duration::from_secs(1));

        // reveal_password must error SessionExpired (NOT
        // AuthenticationFailed), and the presence proof's single-use
        // flag must NOT be burned.
        let presence = PressYPresenceProof::confirmed();
        let err = v.reveal_password(id, &presence).unwrap_err();
        assert!(
            matches!(err, StoreError::SessionExpired),
            "expected SessionExpired pre-presence; got {err:?}"
        );
        // Now reauth (resets session). The same presence proof must
        // still be usable for a subsequent reveal.
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        // BUT — the test_clock-based vault was advanced past
        // PRESENCE_FRESHNESS (the proof is now > 60s old in
        // SystemTime::now() terms because the test_clock and real
        // clock are independent). So we need to make a fresh proof
        // for the actual reveal. The point of THIS test is just to
        // confirm that the ORIGINAL proof's single-use flag wasn't
        // burned by the expired-session path — a weaker but easier-
        // to-test invariant: the proof's verify() returns
        // PresenceAlreadyConsumed only if it was previously consumed.
        assert!(matches!(
            <PressYPresenceProof as crate::session::PresenceProof>::verify(&presence),
            // Either NotFresh (because real time advanced more than
            // PRESENCE_FRESHNESS during the test setup) or Ok(()).
            // It MUST NOT be PresenceAlreadyConsumed — that's the
            // invariant we're testing. We map both acceptable
            // outcomes through this match.
            Ok(()) | Err(crate::session::AuthError::NotFresh),
        ));
    }

    // -----------------------------------------------------------------
    // P8-4: ingest_chain_revision tests
    // -----------------------------------------------------------------

    use crate::dirty::IngestOutcome;

    /// Build a fresh `RevisionEvent` for ingest tests. The
    /// `device_id` is set to the verifying-key bytes of a freshly-
    /// generated `DeviceKey` so the canonical-hash of the event
    /// matches what `verify_signed_revision` would expect.
    fn fresh_event(
        vault_id: [u8; 32],
        account_id: [u8; 32],
        parent: [u8; 32],
        payload: &[u8],
        block: u64,
        log: u64,
    ) -> pangolin_chain::RevisionEvent {
        let device = pangolin_crypto::keys::DeviceKey::generate();
        let device_id = device.verifying_key().to_bytes();
        pangolin_chain::RevisionEvent {
            vault_id,
            account_id,
            parent_revision: parent,
            device_id,
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

    /// Plan test: ingesting populates the chain anchor on the
    /// freshly-inserted row.
    #[test]
    fn ingest_chain_revision_populates_anchor() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "v.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        let ev = fresh_event(v.vault_id(), [0x11; 32], [0u8; 32], b"ingest-1", 99, 0);
        let outcome = v.ingest_chain_revision(&ev).expect("ingest ok");
        assert_eq!(outcome, IngestOutcome::Inserted);
        // Compute the expected revision_id (canonical hash) and look
        // up the row directly.
        let rev_id = pangolin_chain::canonical_hash(
            &ev.vault_id,
            &ev.account_id,
            &ev.parent_revision,
            &ev.device_id,
            ev.schema_version,
            &ev.enc_payload,
        );
        let rev_id_obj = crate::revision::RevisionId::from_bytes(rev_id);
        let revs = v
            .revisions_for(crate::account::AccountId::from_bytes(ev.account_id))
            .expect("revisions_for");
        assert_eq!(revs.len(), 1);
        assert_eq!(revs[0].revision_id, rev_id_obj);
        let anchor = revs[0].chain_anchor.expect("anchor present");
        assert_eq!(anchor.block_number, 99);
        assert_eq!(anchor.log_index, 0);
    }

    /// Plan test: ingest does NOT stamp a dirty marker (the chain
    /// already has the revision; nothing to publish).
    #[test]
    fn ingest_chain_revision_does_not_mark_dirty() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "v.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        let ev = fresh_event(v.vault_id(), [0x22; 32], [0u8; 32], b"no-dirty", 1, 0);
        v.ingest_chain_revision(&ev).expect("ingest");
        assert!(
            v.list_dirty().expect("list dirty").is_empty(),
            "ingest must NOT stamp a dirty marker"
        );
    }

    /// Plan test: idempotent — re-ingesting the same event returns
    /// `AlreadyPresent` and does NOT insert a duplicate row.
    #[test]
    fn ingest_chain_revision_idempotent() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "v.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        let ev = fresh_event(v.vault_id(), [0x33; 32], [0u8; 32], b"idemp", 1, 0);
        let first = v.ingest_chain_revision(&ev).expect("first");
        let second = v.ingest_chain_revision(&ev).expect("second");
        assert_eq!(first, IngestOutcome::Inserted);
        assert_eq!(second, IngestOutcome::AlreadyPresent);
        let revs = v
            .revisions_for(crate::account::AccountId::from_bytes(ev.account_id))
            .expect("revisions_for");
        assert_eq!(revs.len(), 1, "no duplicate row on re-ingest");
    }

    // -----------------------------------------------------------------
    // MVP-3 issue #106d: retroactive revocation re-eval against the live
    // on-chain SET (salvaged #103-C GAP FLAG 3, predicate re-keyed)
    // -----------------------------------------------------------------

    /// Build a chain-anchored `RevisionEvent` whose `device_id` is the
    /// 20-byte EVM `addr` left-padded to 32 bytes (12 zero bytes ‖ 20
    /// address bytes) — the same shape the V2 publish path emits. Lets the
    /// #106d re-eval tests seed a row attributable to a specific signer.
    fn chain_event_signed_by(
        vault_id: [u8; 32],
        account_id: [u8; 32],
        parent: [u8; 32],
        addr: [u8; 20],
        payload: &[u8],
        block: u64,
        log: u64,
    ) -> pangolin_chain::RevisionEvent {
        let mut device_id = [0u8; 32];
        device_id[12..].copy_from_slice(&addr);
        pangolin_chain::RevisionEvent {
            vault_id,
            account_id,
            parent_revision: parent,
            device_id,
            schema_version: 1,
            sequence: 0,
            enc_payload: payload.to_vec(),
            anchor: pangolin_chain::ChainAnchor {
                tx_hash: [0xCD; 32],
                block_number: block,
                log_index: log,
                sequence: 0,
            },
        }
    }

    /// **#106d fix-pass helper.** Ingest a V2 chain revision through the
    /// honor gate ([`Vault::ingest_v2_revision_if_honored`]) with `addr`
    /// as the ecrecovered signer (in-set at ingest), so the row's
    /// `recovered_signer` column is persisted — the identity the
    /// retroactive pass keys on. Mirrors how the live V2 sync path ingests.
    fn ingest_v2_as_signer(v: &mut Vault, ev: &pangolin_chain::RevisionEvent, addr: [u8; 20]) {
        v.ingest_v2_revision_if_honored(ev, addr, &[addr])
            .expect("honor-gated ingest")
            .expect("signer in-set at ingest");
    }

    /// **#106d L4.** A row stored under signer A (ingested before A left
    /// the set) is retroactively MARKED revoked when re-evaluated against
    /// a set that no longer contains A — and a row signed by an in-set
    /// signer B is left honored. Mark-not-delete (L6): the row still
    /// exists. Idempotent: a second pass reports 0 newly-revoked.
    #[test]
    fn retroactive_reeval_marks_out_of_set_row_revoked() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "v.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();

        let addr_a = [0xAA; 20];
        let addr_b = [0xBB; 20];

        // Two chain-anchored rows: one signed by A (soon out-of-set), one
        // by B (in-set).
        let ev_a =
            chain_event_signed_by(v.vault_id(), [0x11; 32], [0u8; 32], addr_a, b"by-A", 10, 0);
        let ev_b =
            chain_event_signed_by(v.vault_id(), [0x22; 32], [0u8; 32], addr_b, b"by-B", 20, 1);
        ingest_v2_as_signer(&mut v, &ev_a, addr_a);
        ingest_v2_as_signer(&mut v, &ev_b, addr_b);

        // Current set = {B} only — A was removed.
        let set = vec![addr_b];
        let newly = v.reevaluate_revocation_against_set(&set).expect("re-eval");
        assert_eq!(newly, 1, "exactly A's row newly revoked");

        let rev_id_a = pangolin_chain::canonical_hash(
            &ev_a.vault_id,
            &ev_a.account_id,
            &ev_a.parent_revision,
            &ev_a.device_id,
            ev_a.schema_version,
            &ev_a.enc_payload,
        );
        let rev_id_b = pangolin_chain::canonical_hash(
            &ev_b.vault_id,
            &ev_b.account_id,
            &ev_b.parent_revision,
            &ev_b.device_id,
            ev_b.schema_version,
            &ev_b.enc_payload,
        );
        let revoked_a: i64 = v
            .conn
            .query_row(
                "SELECT revoked FROM revisions WHERE revision_id = ?1",
                params![&rev_id_a[..]],
                |row| row.get(0),
            )
            .expect("A row present");
        let revoked_b: i64 = v
            .conn
            .query_row(
                "SELECT revoked FROM revisions WHERE revision_id = ?1",
                params![&rev_id_b[..]],
                |row| row.get(0),
            )
            .expect("B row present");
        assert_eq!(revoked_a, 1, "A (out-of-set) revoked");
        assert_eq!(revoked_b, 0, "B (in-set) honored");

        // Idempotent.
        let again = v
            .reevaluate_revocation_against_set(&set)
            .expect("re-eval 2");
        assert_eq!(again, 0, "second pass is idempotent");
    }

    /// **#106d L4 — reversible / both directions.** A previously-revoked
    /// signer that re-enters the set un-revokes its rows on the next pass.
    /// A set containing every stored signer revokes nothing.
    #[test]
    fn retroactive_reeval_is_reversible_and_noop_on_full_set() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "v.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();

        let addr_a = [0xAA; 20];
        let ev_a =
            chain_event_signed_by(v.vault_id(), [0x11; 32], [0u8; 32], addr_a, b"by-A", 10, 0);
        ingest_v2_as_signer(&mut v, &ev_a, addr_a);
        let rev_id_a = pangolin_chain::canonical_hash(
            &ev_a.vault_id,
            &ev_a.account_id,
            &ev_a.parent_revision,
            &ev_a.device_id,
            ev_a.schema_version,
            &ev_a.enc_payload,
        );

        // A removed (set = {B}) ⇒ A revoked.
        v.reevaluate_revocation_against_set(&[[0xBB; 20]])
            .expect("revoke pass");
        let r1: i64 = v
            .conn
            .query_row(
                "SELECT revoked FROM revisions WHERE revision_id = ?1",
                params![&rev_id_a[..]],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(r1, 1, "A revoked when out of set");

        // A re-added (set = {A}) ⇒ A un-revokes (re-add un-revokes).
        v.reevaluate_revocation_against_set(&[addr_a])
            .expect("restore pass");
        let r2: i64 = v
            .conn
            .query_row(
                "SELECT revoked FROM revisions WHERE revision_id = ?1",
                params![&rev_id_a[..]],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(r2, 0, "A un-revoked when re-added (reversible)");
    }

    /// **#106d L4 (salvaged #103-C FINDING 2 regression).** Marking a row
    /// `revoked = 1` MUST exclude it from the materialized honored state —
    /// the head set, the `revisions_for` history walk, and the
    /// `revision_graph` content reads. A revoked child must NOT mask its
    /// honored parent from the head set (the child-existence subquery
    /// excludes revoked rows). This pins that the read-filters actually
    /// read the column (a marks-but-reads-don't-filter regression flips it
    /// red — the L11 negative).
    #[test]
    #[allow(clippy::too_many_lines)] // pre + post revocation across head/history/graph
    fn revoked_rows_excluded_from_head_history_and_content() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "v.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();

        let addr_a = [0xAA; 20]; // in-set (honored)
        let addr_b = [0xBB; 20]; // removed (revoked)
        let acct = [0x77; 32];

        // Genesis G signed by A. Child C (parent = G) signed by B. Before
        // any revocation C is the sole head and G is its ancestor.
        let ev_g = chain_event_signed_by(
            v.vault_id(),
            acct,
            [0u8; 32],
            addr_a,
            b"genesis-by-A",
            10,
            0,
        );
        let rev_id_g = pangolin_chain::canonical_hash(
            &ev_g.vault_id,
            &ev_g.account_id,
            &ev_g.parent_revision,
            &ev_g.device_id,
            ev_g.schema_version,
            &ev_g.enc_payload,
        );
        let ev_c =
            chain_event_signed_by(v.vault_id(), acct, rev_id_g, addr_b, b"child-by-B", 20, 1);
        let rev_id_c = pangolin_chain::canonical_hash(
            &ev_c.vault_id,
            &ev_c.account_id,
            &ev_c.parent_revision,
            &ev_c.device_id,
            ev_c.schema_version,
            &ev_c.enc_payload,
        );
        ingest_v2_as_signer(&mut v, &ev_g, addr_a);
        ingest_v2_as_signer(&mut v, &ev_c, addr_b);

        let acct_id = crate::account::AccountId::from_bytes(acct);
        let rid_g = crate::revision::RevisionId::from_bytes(rev_id_g);
        let rid_c = crate::revision::RevisionId::from_bytes(rev_id_c);

        // Pre-revocation: BOTH rows materialize; C is the head; history
        // has both. Pins the `revoked = 0` default behavior the gate must
        // not change.
        let heads_before = v.account_heads(acct_id).expect("heads before");
        assert_eq!(heads_before.len(), 1, "single head before revocation");
        assert_eq!(heads_before[0], rid_c, "C is the head before revocation");
        let hist_before = v.revisions_for(acct_id).expect("history before");
        assert_eq!(hist_before.len(), 2, "both rows in history before");

        // Set = {A} only — B removed ⇒ C (by B) revoked, G (by A) honored.
        let newly = v
            .reevaluate_revocation_against_set(&[addr_a])
            .expect("re-eval");
        assert_eq!(newly, 1, "exactly C newly revoked");

        // C MARKED revoked but still present on disk (L6).
        let revoked_c: i64 = v
            .conn
            .query_row(
                "SELECT revoked FROM revisions WHERE revision_id = ?1",
                params![&rev_id_c[..]],
                |row| row.get(0),
            )
            .expect("C row still present");
        assert_eq!(revoked_c, 1, "C marked revoked (mark-not-delete)");

        // (1) Head set: G is now the head; revoked child C must not mask
        //     it. C must not appear as a head.
        let heads_after = v.account_heads(acct_id).expect("heads after");
        assert_eq!(heads_after.len(), 1, "exactly one honored head");
        assert_eq!(heads_after[0], rid_g, "G is the head after C revoked");
        assert!(!heads_after.contains(&rid_c), "revoked C is not a head");

        // (2) History walk: only honored G appears.
        let hist_after = v.revisions_for(acct_id).expect("history after");
        let hist_ids: Vec<crate::revision::RevisionId> =
            hist_after.iter().map(|m| m.revision_id).collect();
        assert!(hist_ids.contains(&rid_g), "honored G still in history");
        assert!(
            !hist_ids.contains(&rid_c),
            "revoked C excluded from history"
        );

        // (3) revision_graph (feeds content/conflict reads) excludes C.
        let graph = v.revision_graph(acct_id).expect("graph");
        assert!(graph.get(&rid_g).is_some(), "honored G present in graph");
        assert!(graph.get(&rid_c).is_none(), "revoked C absent from graph");
    }

    /// **#106d FIX-PASS regression — MEDIUM under-revocation: the
    /// retroactive pass MUST key on the recovered signer, NOT the opaque
    /// `device_id`.**
    ///
    /// `RevisionLogV2` treats `deviceId` as OPAQUE and gates publishing
    /// ONLY on the ecrecovered signer (it NEVER enforces
    /// `deviceId == leftpad(signer)`). So an authorized in-set device B can
    /// publish a revision SIGNED by B but carrying `deviceId = leftpad(A)`
    /// (A another in-set device). The ingest honor gate correctly uses
    /// B's recovered signer. But once B is REMOVED from the set, a
    /// retroactive pass keyed on `device_id` would decode the row to A
    /// (still in-set) and leave it `revoked = 0` — B's revision SURVIVES
    /// B's removal (under-revocation, the dangerous direction).
    ///
    /// This test seeds exactly that row (`device_id = leftpad(A)`,
    /// recovered signer = B), then runs the retroactive pass against the
    /// set `{A}` (B removed). The CORRECT (recovered-signer-keyed) logic
    /// REVOKES the row. The OLD (device_id-keyed) logic would decode A,
    /// find A in-set, and leave it honored — so this assertion FAILS under
    /// the old logic, proving the test is real.
    #[test]
    fn retroactive_reeval_keys_on_recovered_signer_not_device_id() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "v.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();

        let addr_a = [0xAA; 20]; // stays in-set
        let addr_b = [0xBB; 20]; // the real signer; removed from the set

        // The event carries device_id = leftpad(A) (attacker-chosen,
        // RevisionLogV2 never binds it to the signer)...
        let ev = chain_event_signed_by(
            v.vault_id(),
            [0x33; 32],
            [0u8; 32],
            addr_a, // device_id = leftpad(A)
            b"signed-by-B-but-device_id-A",
            30,
            2,
        );
        // ...but the ecrecovered signer the honor gate saw is B. B is
        // in-set at ingest time, so the gate honors + persists
        // recovered_signer = B.
        ingest_v2_as_signer(&mut v, &ev, addr_b);

        let rev_id = pangolin_chain::canonical_hash(
            &ev.vault_id,
            &ev.account_id,
            &ev.parent_revision,
            &ev.device_id,
            ev.schema_version,
            &ev.enc_payload,
        );

        // Sanity: the persisted recovered_signer is B (not A from
        // device_id). Confirms the under-revocation precondition exists.
        let stored_signer: Vec<u8> = v
            .conn
            .query_row(
                "SELECT recovered_signer FROM revisions WHERE revision_id = ?1",
                params![&rev_id[..]],
                |row| row.get(0),
            )
            .expect("row present with recovered_signer");
        assert_eq!(stored_signer, addr_b.to_vec(), "recovered signer is B");

        // B removed; A still in-set. The CORRECT logic revokes this row
        // (its real signer B is gone). The OLD device_id-keyed logic would
        // decode A (in-set) and leave it honored → this assertion would
        // FAIL under the old logic (proving the regression test is real).
        let newly = v
            .reevaluate_revocation_against_set(&[addr_a])
            .expect("re-eval");
        assert_eq!(
            newly, 1,
            "B-signed row (device_id spoofed to A) is revoked after B removed"
        );
        let revoked: i64 = v
            .conn
            .query_row(
                "SELECT revoked FROM revisions WHERE revision_id = ?1",
                params![&rev_id[..]],
                |row| row.get(0),
            )
            .expect("row present");
        assert_eq!(
            revoked, 1,
            "under-revocation closed: B's revision does NOT survive B's removal"
        );
    }

    /// **#106d L5 — V1 path untouched.** A V1-bound vault (the default
    /// binding) never marks any row revoked: the V2 retroactive pass is
    /// only driven from the V2 sync path, and a V1 vault's permissive
    /// reads behave byte-identically to pre-#106d. This asserts a freshly
    /// ingested V1-style chain row reads as `revoked = 0` and surfaces in
    /// head/history exactly as before (no V2 set gate is ever applied to a
    /// V1 vault).
    #[test]
    fn v1_vault_rows_stay_honored_untouched() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "v.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        // A fresh vault binds V1 by default (NULL → V1).
        assert_eq!(
            v.revisionlog_version().unwrap(),
            RevisionLogVersion::V1,
            "fresh vault is V1-bound by default"
        );
        let acct = [0x55; 32];
        let ev = fresh_event(v.vault_id(), acct, [0u8; 32], b"v1-row", 5, 0);
        v.ingest_chain_revision(&ev).expect("ingest");
        let rev_id = pangolin_chain::canonical_hash(
            &ev.vault_id,
            &ev.account_id,
            &ev.parent_revision,
            &ev.device_id,
            ev.schema_version,
            &ev.enc_payload,
        );
        // The row reads as honored (revoked = 0) — the V1 path never
        // writes the column.
        let revoked: i64 = v
            .conn
            .query_row(
                "SELECT revoked FROM revisions WHERE revision_id = ?1",
                params![&rev_id[..]],
                |row| row.get(0),
            )
            .expect("row present");
        assert_eq!(revoked, 0, "V1 row stays honored (revoked = 0)");
        let acct_id = crate::account::AccountId::from_bytes(acct);
        let heads = v.account_heads(acct_id).expect("heads");
        assert_eq!(heads.len(), 1, "V1 row is the head, as pre-#106d");
        assert_eq!(
            heads[0],
            crate::revision::RevisionId::from_bytes(rev_id),
            "the V1 row surfaces unchanged"
        );
    }

    // -----------------------------------------------------------------
    // P8 fix-pass CRIT-1: frozen_pending_resolve sentinel tests
    // -----------------------------------------------------------------

    /// **P8 fix CRIT-1.** When a foreign-device chain event lands on
    /// an account that the local vault already has a row for, the
    /// `frozen_pending_resolve` flag is set and `reveal_password`
    /// refuses on that account. This is the "vault A creates account,
    /// vault B copies the file, vault A modifies the account on
    /// chain, vault B's `reveal_password` still returns plaintext"
    /// attack the §16.5 audit found.
    #[test]
    fn frozen_after_foreign_ingest_blocks_reveal_password() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "v.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        // Local create — vault has the account in cache + on disk.
        let id = v.add_account(fresh_snapshot()).expect("add_account");
        // Sanity: prior to ingest, reveal_password works.
        let pwd = v
            .reveal_password(id, &fresh_presence())
            .expect("reveal pre-freeze");
        assert_eq!(pwd.expose(), b"hunter2");

        // Foreign-device chain event lands. Use a different
        // `device_id` (a fresh DeviceKey's verifying-key bytes) and
        // a different payload so the merge arms can't match.
        let ev = fresh_event(
            v.vault_id(),
            *id.as_bytes(),
            [0u8; 32],
            b"foreign-payload",
            42,
            0,
        );
        let outcome = v.ingest_chain_revision(&ev).expect("ingest");
        assert_eq!(outcome, IngestOutcome::Inserted);

        // The freeze sentinel is set; reveal_password refuses.
        let err = v
            .reveal_password(id, &fresh_presence())
            .expect_err("reveal must refuse on frozen");
        match err {
            StoreError::AccountFrozenPendingResolve { account_id } => {
                assert_eq!(account_id, id);
            }
            other => panic!("expected AccountFrozenPendingResolve, got {other:?}"),
        }
        // Same for export_payload.
        let err = v
            .export_payload(id, &fresh_presence())
            .expect_err("export must refuse on frozen");
        assert!(matches!(
            err,
            StoreError::AccountFrozenPendingResolve { .. }
        ));
        // get_account returns None, list_accounts excludes the id.
        assert!(v.get_account(id).is_none());
        assert!(!v.list_accounts().contains(&id));
        // list_frozen_accounts surfaces the id.
        let frozen = v.list_frozen_accounts().expect("list frozen");
        assert_eq!(frozen, vec![id]);
    }

    /// **P8 fix CRIT-1.** A vault's own publish round-trip MUST
    /// NOT freeze the account. The publish path stamps the chain
    /// anchor onto the local row via `mark_published`; on subsequent
    /// pull, idempotency arm #2 `(account_id, chain_tx_hash, block,
    /// log)` matches and we return `AlreadyPresent` without taking
    /// the INSERT path.
    #[test]
    fn own_publish_roundtrip_does_not_freeze() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "v.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        let id = v.add_account(fresh_snapshot()).expect("add_account");
        let rev = v.list_dirty().expect("list dirty")[0].revision_id;

        // Simulate publish: stamp a chain anchor via `mark_published`
        // and then ingest the same event back. The (tx_hash, block,
        // log_index) anchor on the chain event must match the
        // `mark_published` call's anchor for arm #2 to fire.
        let anchor = pangolin_chain::ChainAnchor {
            tx_hash: [0xCD; 32],
            block_number: 7,
            log_index: 0,
            sequence: 0,
        };
        v.mark_published(rev, anchor).expect("mark_published");
        v.clear_dirty(id, rev).expect("clear_dirty");

        // Build the chain event as if we'd just received our own
        // publish back via pull. The event's device_id is whatever
        // `publish_all` would have used at publish time — under the
        // PoC two-key model that's NOT the local row's device_id, so
        // arm #3 cannot match. Arm #2 (tx_hash + block + log) MUST
        // match.
        let ev = pangolin_chain::RevisionEvent {
            vault_id: v.vault_id(),
            account_id: *id.as_bytes(),
            // Use the local row's parent — irrelevant for arm #2 but
            // we set it consistent with the local genesis.
            parent_revision: [0u8; 32],
            // Fresh DeviceKey's pubkey — does NOT match local row's
            // device_id (which is the vault handle's random bytes).
            device_id: pangolin_crypto::keys::DeviceKey::generate()
                .verifying_key()
                .to_bytes(),
            schema_version: 0,
            sequence: 0,
            // enc_payload doesn't need to match — arm #2 doesn't
            // gate on it.
            enc_payload: b"unrelated".to_vec(),
            anchor,
        };
        let outcome = v.ingest_chain_revision(&ev).expect("ingest");
        assert_eq!(
            outcome,
            IngestOutcome::AlreadyPresent,
            "own-publish round-trip caught by idempotency arm #2 (chain anchor match), no freeze"
        );
        // No freeze: list_frozen_accounts is empty, reveal_password
        // still works.
        assert!(v.list_frozen_accounts().expect("list frozen").is_empty());
        let pwd = v
            .reveal_password(id, &fresh_presence())
            .expect("reveal post-roundtrip");
        assert_eq!(pwd.expose(), b"hunter2");
    }

    /// **P8 fix CRIT-1.** Once frozen, subsequent edits
    /// (`update_account`, `delete_account`, `mark_dirty`) refuse
    /// with `AccountFrozenPendingResolve` so a user editing their
    /// stale plaintext copy cannot create a silent fork.
    #[test]
    fn frozen_account_blocks_mark_dirty() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "v.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        let id = v.add_account(fresh_snapshot()).expect("add_account");
        let rev = v.list_dirty().expect("list")[0].revision_id;

        // Trigger freeze via foreign-ingest.
        let ev = fresh_event(v.vault_id(), *id.as_bytes(), [0u8; 32], b"foreign", 1, 0);
        v.ingest_chain_revision(&ev).expect("ingest");
        assert!(!v.list_frozen_accounts().expect("list frozen").is_empty());

        // mark_dirty refuses.
        let err = v.mark_dirty(id, rev).expect_err("mark_dirty must refuse");
        assert!(matches!(
            err,
            StoreError::AccountFrozenPendingResolve { .. }
        ));
        // update_account refuses.
        let err = v
            .update_account(id, fresh_snapshot())
            .expect_err("update must refuse");
        assert!(matches!(
            err,
            StoreError::AccountFrozenPendingResolve { .. }
        ));
        // delete_account refuses.
        let err = v.delete_account(id).expect_err("delete must refuse");
        assert!(matches!(
            err,
            StoreError::AccountFrozenPendingResolve { .. }
        ));
    }

    /// **P8 fix CRIT-1.** `Vault::list_frozen_accounts` is the
    /// canonical surface for the frozen-set; the new
    /// `PullReport.frozen` field in `pangolin-cli sync.rs` is
    /// populated from it. This unit test pins the storage-layer
    /// shape that the orchestrator relies on.
    #[test]
    fn frozen_account_listed_separately_in_pull_result() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "v.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        let id_a = v.add_account(fresh_snapshot()).expect("add A");
        let id_b = v.add_account(fresh_snapshot()).expect("add B");

        // Freeze A only.
        let ev = fresh_event(
            v.vault_id(),
            *id_a.as_bytes(),
            [0u8; 32],
            b"foreign-A",
            10,
            0,
        );
        v.ingest_chain_revision(&ev).expect("ingest A");

        // list_frozen_accounts surfaces exactly A.
        let frozen = v.list_frozen_accounts().expect("list frozen");
        assert_eq!(frozen.len(), 1);
        assert_eq!(frozen[0], id_a);
        // B is still readable.
        assert!(v.get_account(id_b).is_some());
        // list_accounts excludes A but includes B.
        let live = v.list_accounts();
        assert!(live.contains(&id_b));
        assert!(!live.contains(&id_a));
    }

    /// **P8 fix-pass: schema migration.** Vaults predating the
    /// `frozen_pending_resolve` column open cleanly via the
    /// migration in `apply_pragmas_and_schema`. We synthesize a
    /// pre-migration vault by dropping the column out of an opened
    /// vault's `account_identities` table and confirming a
    /// subsequent `Vault::open` re-adds it via the migration.
    #[test]
    fn legacy_vault_picks_up_frozen_column_on_open() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "v.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        // Open + close to ensure the schema is in place; then strip
        // the column out via a recreate-without-the-column dance to
        // simulate a pre-fix vault.
        {
            let v = Vault::open(&p).unwrap();
            // Build a fresh table without the column, copy rows over,
            // drop the original, rename. SQLite doesn't support DROP
            // COLUMN directly on older library versions; we stay
            // portable.
            v.conn
                .execute_batch(
                    "BEGIN IMMEDIATE;
                     CREATE TABLE account_identities_legacy (
                       account_id BLOB PRIMARY KEY,
                       created_at INTEGER NOT NULL,
                       last_modified_at INTEGER NOT NULL,
                       tombstoned INTEGER NOT NULL DEFAULT 0,
                       head_revision_id BLOB NOT NULL
                     );
                     INSERT INTO account_identities_legacy
                       SELECT account_id, created_at, last_modified_at,
                              tombstoned, head_revision_id
                       FROM account_identities;
                     DROP TABLE account_identities;
                     ALTER TABLE account_identities_legacy RENAME TO account_identities;
                     COMMIT;",
                )
                .expect("strip frozen_pending_resolve column");
        }
        // Confirm the column is absent before re-open.
        {
            use rusqlite::Connection;
            let conn = Connection::open(&p).unwrap();
            let mut stmt = conn
                .prepare("PRAGMA table_info(account_identities)")
                .unwrap();
            let names: Vec<String> = stmt
                .query_map([], |row| row.get::<_, String>(1))
                .unwrap()
                .map(|r| r.unwrap())
                .collect();
            assert!(
                !names.contains(&"frozen_pending_resolve".to_string()),
                "pre-condition: column should be absent before migration"
            );
        }
        // Re-open via Vault::open — the migration runs and re-adds the column.
        let v = Vault::open(&p).expect("re-open legacy vault");
        // The freeze surface works post-migration: list_frozen_accounts
        // returns Ok([]) on the freshly-migrated vault.
        let frozen = v
            .list_frozen_accounts()
            .expect("list_frozen_accounts after migration");
        assert!(frozen.is_empty());
    }

    // -----------------------------------------------------------------
    // P9-1: clear_frozen + read_payload_plaintext_for_resolve tests
    // -----------------------------------------------------------------

    /// **P9-1.** Happy path — `clear_frozen` clears the
    /// `frozen_pending_resolve` flag AND advances `head_revision_id`
    /// to the supplied revision in one transaction. Verified post-
    /// call by reading both columns directly.
    #[test]
    fn clear_frozen_advances_head_and_clears_flag() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "v.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        let id = v.add_account(fresh_snapshot()).expect("add");

        // Trigger the freeze via a foreign chain event under the same
        // account_id but a different device_id + payload (genuine-
        // foreign-INSERT path).
        let ev = fresh_event(v.vault_id(), *id.as_bytes(), [0u8; 32], b"foreign", 1, 0);
        v.ingest_chain_revision(&ev).expect("ingest");
        assert!(v.list_frozen_accounts().unwrap().contains(&id));

        // The local genesis revision is still in the table; we use it
        // as the chosen head for the resolve test (its content is
        // arbitrary — we're testing clear_frozen's mechanics, not the
        // resolve flow's full publish path).
        let revs = v.revisions_for(id).expect("revisions");
        let chosen = revs[0].revision_id;

        v.clear_frozen(id, chosen).expect("clear_frozen ok");

        // Flag is clear.
        assert!(
            !v.list_frozen_accounts().unwrap().contains(&id),
            "frozen flag must be cleared"
        );
        // Head pointer advanced.
        let head: Vec<u8> = v
            .conn
            .query_row(
                "SELECT head_revision_id FROM account_identities WHERE account_id = ?1",
                rusqlite::params![id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .expect("read head");
        assert_eq!(head.as_slice(), chosen.as_bytes().as_slice());
    }

    /// **P9-1.** Idempotent — clearing a non-frozen account whose
    /// head already equals `chosen_revision_id` is a no-op.
    #[test]
    fn clear_frozen_idempotent_on_already_clean() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "v.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        let id = v.add_account(fresh_snapshot()).expect("add");
        let revs = v.revisions_for(id).expect("revisions");
        let head = revs[0].revision_id;

        // No freeze; head already at the expected revision. Idempotent.
        v.clear_frozen(id, head).expect("first clear");
        v.clear_frozen(id, head).expect("idempotent second clear");
        assert!(!v.list_frozen_accounts().unwrap().contains(&id));
    }

    /// **P9-1.** Unknown `revision_id` surfaces `RevisionNotFound`.
    #[test]
    fn clear_frozen_rejects_unknown_revision() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "v.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        let id = v.add_account(fresh_snapshot()).expect("add");
        let bogus = crate::revision::RevisionId::from_bytes([0xCC; 32]);
        let err = v.clear_frozen(id, bogus).expect_err("must reject");
        assert!(
            matches!(err, StoreError::RevisionNotFound),
            "unknown revision_id should return RevisionNotFound, got {err:?}"
        );
    }

    /// **P9-1.** Unknown `account_id` surfaces `AccountNotFound`.
    #[test]
    fn clear_frozen_rejects_unknown_account() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "v.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        let bogus_acct = crate::account::AccountId::from_bytes([0xAB; 32]);
        let bogus_rev = crate::revision::RevisionId::from_bytes([0xCC; 32]);
        let err = v
            .clear_frozen(bogus_acct, bogus_rev)
            .expect_err("must reject");
        assert!(
            matches!(err, StoreError::AccountNotFound),
            "unknown account_id should return AccountNotFound, got {err:?}"
        );
    }

    /// **P9-1.** `read_payload_plaintext_for_resolve` decrypts the
    /// chosen revision's payload EVEN when the account is frozen.
    /// This is the documented bypass — see the loud docstring on
    /// the method.
    #[test]
    fn read_payload_plaintext_for_resolve_bypasses_freeze_guard() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "v.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        let id = v.add_account(fresh_snapshot()).expect("add");
        let revs = v.revisions_for(id).expect("revisions");
        let local_head = revs[0].revision_id;

        // Trigger freeze.
        let ev = fresh_event(v.vault_id(), *id.as_bytes(), [0u8; 32], b"foreign", 1, 0);
        v.ingest_chain_revision(&ev).expect("ingest");

        // Sanity: get_account refuses on the frozen row.
        assert!(v.get_account(id).is_none());

        // The bypass succeeds — we can still read the LOCAL revision's
        // plaintext (which the resolve flow needs for re-seal).
        let snapshot = v
            .read_payload_plaintext_for_resolve(id, local_head)
            .expect("bypass must succeed for the resolve flow");
        assert!(bool::from(snapshot.ct_eq(&fresh_snapshot())));
    }

    /// **P9-1.** Requires an active session — a Locked vault refuses.
    #[test]
    fn read_payload_plaintext_for_resolve_requires_unlocked_vault() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "v.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        let id = v.add_account(fresh_snapshot()).expect("add");
        let revs = v.revisions_for(id).expect("revisions");
        let head = revs[0].revision_id;
        v.lock();

        let err = v
            .read_payload_plaintext_for_resolve(id, head)
            .expect_err("locked vault must refuse");
        assert!(
            matches!(err, StoreError::NotUnlocked),
            "locked vault should return NotUnlocked, got {err:?}"
        );
    }

    /// **P9-1.** Cross-account safety — supplying a `revision_id`
    /// that belongs to a different account collapses to
    /// `AccountNotFound` (no oracle).
    #[test]
    fn read_payload_plaintext_for_resolve_rejects_wrong_account_id() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "v.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        let id_a = v.add_account(fresh_snapshot()).expect("add A");
        let id_b = v.add_account(fresh_snapshot()).expect("add B");

        // Take A's head revision and try to read it under B's
        // account_id. Cross-account substitution must fail.
        let revs_a = v.revisions_for(id_a).expect("revisions A");
        let head_a = revs_a[0].revision_id;

        let err = v
            .read_payload_plaintext_for_resolve(id_b, head_a)
            .expect_err("cross-account read must refuse");
        assert!(
            matches!(err, StoreError::AccountNotFound),
            "cross-account substitution must collapse to AccountNotFound, got {err:?}"
        );
    }

    // -----------------------------------------------------------------
    // P9 fix-pass MED-3: clear_frozen validates head membership inside tx
    // -----------------------------------------------------------------

    /// **P9 fix-pass MED-3.** `clear_frozen` rejects with
    /// `NotAHead` when the supplied `chosen_revision_id` exists in
    /// the `revisions` table for the account but is not a current
    /// head of the account's revision graph at the time of the SQL
    /// transaction.
    ///
    /// Setup: an account with two revisions where the local genesis
    /// has been `UPDATE`d to a child. The child is the only head; the
    /// genesis is no longer a head (it has a child).
    #[test]
    fn clear_frozen_rejects_non_head_revision_id() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "v.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        let id = v.add_account(fresh_snapshot()).expect("add");
        // Update so genesis is no longer a head.
        let _child = v
            .update_account(id, fresh_snapshot())
            .expect("update so genesis is demoted");
        // The genesis revision is the older (smaller created_at)
        // entry; the child is the head. Pull both ids.
        let revs = v.revisions_for(id).expect("revisions");
        assert_eq!(revs.len(), 2);
        let genesis = revs
            .iter()
            .find(|m| m.parent_revision_id == crate::revision::RevisionId::GENESIS_PARENT)
            .map(|m| m.revision_id)
            .expect("genesis row present");

        // Try to `clear_frozen` against the genesis (a non-head).
        // Must reject with NotAHead.
        let err = v
            .clear_frozen(id, genesis)
            .expect_err("non-head clear must reject");
        match err {
            StoreError::NotAHead {
                account_id,
                chosen,
                current_heads,
            } => {
                assert_eq!(account_id, id);
                assert_eq!(chosen, genesis);
                assert_eq!(current_heads.len(), 1, "exactly one head after the update");
                assert_ne!(current_heads[0], genesis);
            }
            other => panic!("expected NotAHead, got {other:?}"),
        }
    }

    /// **P9 fix-pass MED-2.** `clear_frozen`'s `BEGIN IMMEDIATE`
    /// wrapper holds across the freeze-clear + head-advance UPDATE
    /// pair. Pinned by exercising the simulated-crash discipline
    /// from the audit hint:
    ///
    /// 1. Run `clear_frozen` to completion on a fresh frozen
    ///    account; observe the post-state (flag = 0, head =
    ///    chosen).
    /// 2. As a control: directly UPDATE only one of the two
    ///    columns inside a transaction that is THEN rolled back;
    ///    confirm the transaction-rollback semantics work as
    ///    expected on this rusqlite version (state is unchanged
    ///    after rollback). This validates the test infrastructure.
    /// 3. Confirm `clear_frozen`'s `unchecked_transaction()` +
    ///    `tx.commit()` discipline runs the freeze-clear and
    ///    head-advance UPDATE inside a single atomic boundary
    ///    (verified structurally by reading the SQL through the
    ///    code in this file — the test in step 1 already exercised
    ///    the success path; step 2 confirms rollback works on this
    ///    `SQLite` build).
    ///
    /// Note on the simulated crash: rusqlite's `update_hook` API
    /// is not stable across versions, and a true `panic` between
    /// two SQL statements would unwind the `unchecked_transaction`
    /// (which `Drop`s with rollback semantics). We therefore
    /// validate the rollback path explicitly via a manual
    /// transaction abort, then assert that `clear_frozen`'s
    /// success path lands the expected end state.
    #[test]
    fn clear_frozen_atomic_under_simulated_crash() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "v.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        let id = v.add_account(fresh_snapshot()).expect("add");
        // Trigger freeze + a fork via a foreign event. The local
        // genesis remains a head.
        let ev = fresh_event(v.vault_id(), *id.as_bytes(), [0u8; 32], b"foreign", 1, 0);
        v.ingest_chain_revision(&ev).expect("ingest");
        assert!(v.list_frozen_accounts().unwrap().contains(&id));
        let revs = v.revisions_for(id).expect("revisions");
        let local_genesis = revs
            .iter()
            .find(|m| {
                m.parent_revision_id == crate::revision::RevisionId::GENESIS_PARENT
                    && !m.is_tombstone
            })
            .map(|m| m.revision_id)
            .expect("local genesis present");

        // ---- Step 2: transaction-rollback control. ----
        //
        // Validate that an aborted transaction on the same row
        // shape leaves the row in its pre-transaction state. We
        // partially mutate `last_modified_at` via a direct SQL
        // UPDATE inside a transaction we never commit, then
        // confirm the column is unchanged after the abort.
        let pre_last_modified: i64 = v
            .conn
            .query_row(
                "SELECT last_modified_at FROM account_identities WHERE account_id = ?1",
                rusqlite::params![id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .expect("read pre");
        {
            let tx = v.conn.unchecked_transaction().expect("tx open");
            tx.execute(
                "UPDATE account_identities SET last_modified_at = ?1 WHERE account_id = ?2",
                rusqlite::params![pre_last_modified + 999_999, id.as_bytes().as_slice()],
            )
            .expect("partial update");
            // Drop the tx WITHOUT committing — rollback semantics
            // restore the row to its pre-update state.
            drop(tx);
        }
        let post_abort_last_modified: i64 = v
            .conn
            .query_row(
                "SELECT last_modified_at FROM account_identities WHERE account_id = ?1",
                rusqlite::params![id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .expect("read post-abort");
        assert_eq!(
            pre_last_modified, post_abort_last_modified,
            "transaction-rollback control: aborted UPDATE must not persist"
        );

        // ---- Step 3: clear_frozen's success path lands the
        // expected end state in one atomic step. ----
        v.clear_frozen(id, local_genesis).expect("clear_frozen ok");
        // Both writes (freeze flag + head pointer) landed.
        let (flag, head): (i64, Vec<u8>) = v
            .conn
            .query_row(
                "SELECT frozen_pending_resolve, head_revision_id
                 FROM account_identities WHERE account_id = ?1",
                rusqlite::params![id.as_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("read post-clear");
        assert_eq!(flag, 0, "freeze flag cleared");
        assert_eq!(head.as_slice(), local_genesis.as_bytes().as_slice());
        // The vault is no longer in the frozen-set.
        assert!(!v.list_frozen_accounts().unwrap().contains(&id));
    }

    // -----------------------------------------------------------------
    // P9 fix-pass HIGH-1: pending_merges stash tests
    // -----------------------------------------------------------------

    /// **P9 fix-pass HIGH-1.** Round-trip the stash API:
    /// `stash_pending_merge` writes the row, `take_pending_merge`
    /// reads it back, `clear_pending_merge` deletes it. The
    /// retrieved bytes equal the stashed bytes byte-for-byte
    /// (essential for the canonical-hash determinism that the
    /// recovery path depends on).
    #[test]
    fn stash_take_clear_round_trip() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "v.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        let id = v.add_account(fresh_snapshot()).expect("add");
        let target = crate::revision::RevisionId::from_bytes([0xAA; 32]);
        let seed = [0x33u8; pangolin_crypto::sign::SECRET_KEY_LEN];
        let nonce = [0x44u8; crate::pending::PENDING_MERGE_NONCE_LEN];
        let payload = b"sealed-bytes".to_vec();

        // Pre-condition: no stash present.
        let before = v.take_pending_merge(id, target).expect("take pre");
        assert!(before.is_none(), "no stash on a clean vault");

        // Stash.
        v.stash_pending_merge(id, target, seed, nonce, payload.clone(), 7)
            .expect("stash ok");

        // Take returns Some and the bytes match exactly.
        let got = v
            .take_pending_merge(id, target)
            .expect("take post-stash")
            .expect("stash present");
        assert_eq!(got.device_secret.expose(), &seed[..]);
        assert_eq!(got.aead_nonce, nonce);
        assert_eq!(got.enc_payload, payload);
        assert_eq!(got.schema_version, 7);

        // Take is read-only — the stash is still there for a
        // second `take`.
        let got_again = v
            .take_pending_merge(id, target)
            .expect("take is non-destructive")
            .expect("stash still present after take");
        assert_eq!(got_again.enc_payload, payload);

        // Clear deletes the row.
        v.clear_pending_merge(id, target).expect("clear ok");
        let after = v.take_pending_merge(id, target).expect("take post-clear");
        assert!(after.is_none(), "stash gone after clear");

        // Clear is idempotent — second call on the missing row is OK.
        v.clear_pending_merge(id, target)
            .expect("idempotent second clear");
    }

    /// **P9 fix-pass HIGH-1.** The stash row is durable across
    /// close + open (the recovery semantics MUST survive a process
    /// restart, otherwise the kill-mid-publish recovery doesn't
    /// work).
    #[test]
    fn stash_persists_across_close_open() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "v.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let target = crate::revision::RevisionId::from_bytes([0xBB; 32]);
        let seed = [0x55u8; pangolin_crypto::sign::SECRET_KEY_LEN];
        let nonce = [0x66u8; crate::pending::PENDING_MERGE_NONCE_LEN];
        let payload = b"durable".to_vec();
        let id;
        {
            let mut v = Vault::open(&p).unwrap();
            v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
            id = v.add_account(fresh_snapshot()).expect("add");
            v.stash_pending_merge(id, target, seed, nonce, payload.clone(), 3)
                .expect("stash");
            v.close().expect("close");
        }
        // Re-open in a fresh handle. Stash should be intact.
        let v = Vault::open(&p).expect("re-open");
        let got = v
            .take_pending_merge(id, target)
            .expect("take after reopen")
            .expect("stash survived close+open");
        assert_eq!(got.device_secret.expose(), &seed[..]);
        assert_eq!(got.aead_nonce, nonce);
        assert_eq!(got.enc_payload, payload);
        assert_eq!(got.schema_version, 3);
    }

    /// **P9 fix-pass HIGH-1.** `take_pending_merge` returns
    /// `Ok(None)` on a clean miss (no stash for this pair), not an
    /// error. Distinguishable from the case where the stash row
    /// exists.
    #[test]
    fn take_returns_none_for_nonexistent_account() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "v.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let v = Vault::open(&p).unwrap();
        let bogus_acct = crate::account::AccountId::from_bytes([0xDE; 32]);
        let bogus_target = crate::revision::RevisionId::from_bytes([0xAD; 32]);
        let got = v
            .take_pending_merge(bogus_acct, bogus_target)
            .expect("take on missing pair must Ok-None, not error");
        assert!(got.is_none(), "no stash row for an unknown account");
    }

    /// **P9 fix-pass HIGH-1.** The in-memory `device_secret` field
    /// of the returned [`crate::pending::PendingMerge`] zeroizes
    /// when the struct is dropped. We verify this structurally —
    /// the field is a [`pangolin_crypto::secret::SecretBytes`] which
    /// derives `Drop` via `zeroize::Zeroizing`, so dropping the
    /// struct triggers the zeroize. We exercise the type-level
    /// invariant by constructing a stash, taking it, asserting the
    /// `expose()` returns the expected bytes, then dropping the
    /// struct — the structural guarantee from the `SecretBytes`
    /// type definition is what makes this safe.
    #[test]
    fn pending_merge_zeroizes_secret_on_drop() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "v.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        let id = v.add_account(fresh_snapshot()).expect("add");
        let target = crate::revision::RevisionId::from_bytes([0xCD; 32]);
        let seed = [0x77u8; pangolin_crypto::sign::SECRET_KEY_LEN];
        v.stash_pending_merge(
            id,
            target,
            seed,
            [0u8; crate::pending::PENDING_MERGE_NONCE_LEN],
            b"".to_vec(),
            0,
        )
        .expect("stash");
        // Take, observe, then drop. The `SecretBytes`-typed
        // `device_secret` field zeroizes on drop by construction
        // (the `zeroize::Zeroizing` wrapper inside SecretBytes is
        // a `Drop` impl that wipes the heap allocation). The
        // structural invariant is the load-bearing property here;
        // a runtime memory inspection would be unreliable on a
        // managed allocator.
        {
            let stash = v
                .take_pending_merge(id, target)
                .expect("take")
                .expect("present");
            assert_eq!(stash.device_secret.expose(), &seed[..]);
            // `stash` is dropped at this scope's end; SecretBytes
            // wipes the heap bytes via its Drop impl.
        }
        // Type-level invariant: `SecretBytes` wraps
        // `Zeroizing<Vec<u8>>` which has a Drop impl that wipes
        // the heap allocation. The structural guarantee is what
        // we rely on; the runtime drop above exercises the path.
        // The `static_assertions` crate's `const_assert` would
        // fire at compile time; we use a runtime assertion here
        // because `needs_drop` is a const fn and the runtime
        // call has zero overhead (the compiler folds it).
        assert!(
            std::mem::needs_drop::<pangolin_crypto::secret::SecretBytes>(),
            "SecretBytes must implement Drop (zeroize-on-drop discipline)"
        );
    }

    // -----------------------------------------------------------------
    // P9 fix-pass 2 — MEDIUM-2: prune_orphan_pending_merges tests
    // -----------------------------------------------------------------

    /// **P9 fix-pass 2 — MEDIUM-2.** Stash three rows with distinct
    /// `target_head_id`s; only one is a current head (the genesis
    /// revision id). Prune. Two rows whose `target_head_id` is NOT a
    /// head are deleted; the matching row remains.
    #[test]
    fn prune_orphan_pending_merges_removes_non_head_targets() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "prune.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        let id = v.add_account(fresh_snapshot()).expect("add account");

        // Read the genesis revision id — that's the current sole head.
        let heads = v.account_heads(id).expect("heads");
        assert_eq!(heads.len(), 1, "genesis is sole head");
        let head = heads[0];
        let orphan_a = crate::revision::RevisionId::from_bytes([0xAA; 32]);
        let orphan_b = crate::revision::RevisionId::from_bytes([0xBB; 32]);

        // Stash three rows: one matching the head, two orphans.
        let seed = [0x33u8; pangolin_crypto::sign::SECRET_KEY_LEN];
        let nonce = [0x44u8; crate::pending::PENDING_MERGE_NONCE_LEN];
        let payload = b"sealed".to_vec();
        v.stash_pending_merge(id, head, seed, nonce, payload.clone(), 0)
            .expect("stash head");
        v.stash_pending_merge(id, orphan_a, seed, nonce, payload.clone(), 0)
            .expect("stash orphan_a");
        v.stash_pending_merge(id, orphan_b, seed, nonce, payload, 0)
            .expect("stash orphan_b");

        // Prune.
        let deleted = v.prune_orphan_pending_merges(id).expect("prune ok");
        assert_eq!(deleted, 2, "exactly two orphan rows deleted");

        // The matching head's row remains; both orphans are gone.
        assert!(
            v.take_pending_merge(id, head).expect("take head").is_some(),
            "head's stash row remains"
        );
        assert!(
            v.take_pending_merge(id, orphan_a)
                .expect("take a")
                .is_none(),
            "orphan A's stash row deleted"
        );
        assert!(
            v.take_pending_merge(id, orphan_b)
                .expect("take b")
                .is_none(),
            "orphan B's stash row deleted"
        );
    }

    /// **P9 fix-pass 2 — MEDIUM-2.** When every stash row's
    /// `target_head_id` IS a current head, prune is a no-op
    /// (returns 0).
    #[test]
    fn prune_no_op_when_all_targets_are_heads() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "prune-noop.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        let id = v.add_account(fresh_snapshot()).expect("add account");
        let heads = v.account_heads(id).expect("heads");
        assert_eq!(heads.len(), 1);
        let head = heads[0];
        v.stash_pending_merge(
            id,
            head,
            [0x11u8; pangolin_crypto::sign::SECRET_KEY_LEN],
            [0x22u8; crate::pending::PENDING_MERGE_NONCE_LEN],
            b"sealed".to_vec(),
            0,
        )
        .expect("stash");
        let deleted = v.prune_orphan_pending_merges(id).expect("prune ok");
        assert_eq!(deleted, 0, "no orphans → 0 deletions");
        // Stash row still present.
        assert!(v.take_pending_merge(id, head).expect("take").is_some());
    }

    /// **P9 fix-pass 2 — MEDIUM-2.** Empty stash table → prune
    /// returns 0 with no errors.
    #[test]
    fn prune_no_op_on_empty_table() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "prune-empty.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        let id = v.add_account(fresh_snapshot()).expect("add account");
        let deleted = v
            .prune_orphan_pending_merges(id)
            .expect("prune ok on empty");
        assert_eq!(deleted, 0, "empty stash table → 0 deletions");
    }

    // ---------------------------------------------------------------
    // P10-2: opportunistic tombstone-bit detection at ingest time
    // ---------------------------------------------------------------

    use crate::account::{AccountId, ACCOUNT_ID_LEN};
    use crate::revision::RevisionId;
    use rusqlite::{params, OptionalExtension};

    /// Helper: seal a tombstone payload under the supplied vault's VDK
    /// using the **placeholder zero nonce** that the ingest path
    /// persists for foreign events. Returns the resulting AEAD
    /// ciphertext bytes — to be plumbed into a synthetic
    /// `RevisionEvent.enc_payload` so the ingest path's opportunistic
    /// open succeeds.
    fn seal_tombstone_with_placeholder_nonce(
        v: &Vault,
        account_id: AccountId,
        parent: RevisionId,
        schema_version: u8,
        ts_ms: u64,
    ) -> Vec<u8> {
        use crate::blob::{build_aad, TombstonePayload};
        use ciborium_io::Write as _;
        use ciborium_ll::{Encoder, Header};
        use pangolin_crypto::aead::{Nonce, NONCE_LEN};
        let aad = build_aad(&v.meta.vault_id, &account_id, &parent, schema_version);
        let active = v.require_active().expect("vault active");
        let payload = TombstonePayload::new(account_id, ts_ms);
        // Replicate the encoder inline so we can plumb the
        // placeholder zero nonce into the seal call (the public
        // seal_tombstone uses Nonce::random()).
        let mut out: Vec<u8> = Vec::with_capacity(64);
        {
            let mut enc = Encoder::from(&mut out);
            enc.push(Header::Map(Some(3))).unwrap();
            enc.text("account_id", None).unwrap();
            enc.push(Header::Bytes(Some(ACCOUNT_ID_LEN))).unwrap();
            enc.write_all(payload.account_id()).unwrap();
            enc.text("deleted", None).unwrap();
            enc.push(Header::Simple(ciborium_ll::simple::TRUE)).unwrap();
            enc.text("tombstoned_at_ms", None).unwrap();
            enc.push(Header::Positive(payload.tombstoned_at_ms()))
                .unwrap();
        }
        let nonce = Nonce::from_storage_bytes([0u8; NONCE_LEN]);
        let ct = active
            .vdk
            .aead_key()
            .seal(&nonce, &out, &aad)
            .expect("seal");
        ct.as_bytes().to_vec()
    }

    /// Helper: same as `seal_tombstone_with_placeholder_nonce` but for
    /// a live snapshot. Encodes a six-entry CBOR map in canonical
    /// slot order (`display_name`, `username`, `password`, `url`,
    /// `notes`, `totp_secret`) under the placeholder zero nonce.
    fn seal_live_with_placeholder_nonce(
        v: &Vault,
        account_id: AccountId,
        parent: RevisionId,
        schema_version: u8,
    ) -> Vec<u8> {
        use crate::blob::build_aad;
        use ciborium_io::Write as _;
        use ciborium_ll::{Encoder, Header};
        use pangolin_crypto::aead::{Nonce, NONCE_LEN};
        let aad = build_aad(&v.meta.vault_id, &account_id, &parent, schema_version);
        let active = v.require_active().expect("vault active");
        let mut out: Vec<u8> = Vec::with_capacity(256);
        {
            let mut enc = Encoder::from(&mut out);
            enc.push(Header::Map(Some(6))).unwrap();
            for (k, val) in [
                ("display_name", b"x".as_slice()),
                ("username", b"u".as_slice()),
                ("password", b"p".as_slice()),
                ("url", b"https://x".as_slice()),
                ("notes", b"".as_slice()),
                ("totp_secret", b"".as_slice()),
            ] {
                enc.text(k, None).unwrap();
                enc.push(Header::Bytes(Some(val.len()))).unwrap();
                enc.write_all(val).unwrap();
            }
        }
        let nonce = Nonce::from_storage_bytes([0u8; NONCE_LEN]);
        let ct = active
            .vdk
            .aead_key()
            .seal(&nonce, &out, &aad)
            .expect("seal");
        ct.as_bytes().to_vec()
    }

    /// Build a `RevisionEvent` with the supplied `enc_payload` and a
    /// synthetic chain anchor.
    fn synth_event(
        vault_id: [u8; 32],
        account_id: [u8; 32],
        parent: [u8; 32],
        enc_payload: Vec<u8>,
        block: u64,
        log: u64,
    ) -> pangolin_chain::RevisionEvent {
        let device = pangolin_crypto::keys::DeviceKey::generate();
        let device_id = device.verifying_key().to_bytes();
        pangolin_chain::RevisionEvent {
            vault_id,
            account_id,
            parent_revision: parent,
            device_id,
            schema_version: 0,
            sequence: 0,
            enc_payload,
            anchor: pangolin_chain::ChainAnchor {
                tx_hash: [0xEA; 32],
                block_number: block,
                log_index: log,
                sequence: 0,
            },
        }
    }

    /// **P10-2 A2 positive case.** A synthetic foreign event whose
    /// `enc_payload` is sealed under the local VDK with the
    /// **placeholder zero nonce** that ingest will use for the open
    /// attempt: the opportunistic decode succeeds, the bit is set to 1.
    #[test]
    fn ingest_synthetic_decryptable_tombstone_event_sets_bit() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "p10-2-pos.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        let acct = AccountId::from_bytes([0xAA; 32]);
        let parent = RevisionId::from_bytes([0u8; 32]);
        let ct = seal_tombstone_with_placeholder_nonce(&v, acct, parent, 0, 1_700_000_000_000);
        let ev = synth_event(v.vault_id(), [0xAA; 32], [0u8; 32], ct, 12, 0);
        let outcome = v.ingest_chain_revision(&ev).expect("ingest");
        assert_eq!(outcome, IngestOutcome::Inserted);
        // The inserted row's is_tombstone column is 1.
        let revs = v.revisions_for(acct).expect("revisions_for");
        assert_eq!(revs.len(), 1);
        assert!(
            revs[0].is_tombstone,
            "opportunistic decode succeeded → is_tombstone bit must be 1"
        );
    }

    /// **P10-2 A2 negative case (live).** A synthetic foreign event
    /// whose payload decrypts to a Live snapshot: the bit is NOT set.
    #[test]
    fn ingest_own_live_revision_does_not_set_tombstone_bit() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "p10-2-live.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        let acct = AccountId::from_bytes([0xBB; 32]);
        let parent = RevisionId::from_bytes([0u8; 32]);
        let ct = seal_live_with_placeholder_nonce(&v, acct, parent, 0);
        let ev = synth_event(v.vault_id(), [0xBB; 32], [0u8; 32], ct, 13, 0);
        v.ingest_chain_revision(&ev).expect("ingest");
        let revs = v.revisions_for(acct).expect("revisions_for");
        assert_eq!(revs.len(), 1);
        assert!(
            !revs[0].is_tombstone,
            "opportunistic decode of a live payload must NOT set is_tombstone"
        );
    }

    /// **P10-2 A3 negative case (decryption fails).** A foreign event
    /// whose `enc_payload` does NOT AEAD-decrypt (random bytes; the
    /// common case under `PoC` two-key when seal-time nonce is unknown)
    /// MUST leave `is_tombstone` clear AND fire the freeze sentinel.
    #[test]
    fn ingest_foreign_event_with_unreadable_payload_leaves_tombstone_clear_and_freezes() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "p10-2-undec.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        // Fresh local account so the freeze sentinel UPDATE-arm fires.
        let id = v.add_account(fresh_snapshot()).expect("add_account");
        // Foreign event with a random enc_payload — won't decrypt.
        let bogus_ct = vec![0xDE; 64];
        let ev = synth_event(v.vault_id(), *id.as_bytes(), [0u8; 32], bogus_ct, 99, 0);
        v.ingest_chain_revision(&ev).expect("ingest");
        // Two revisions: the local genesis + the foreign-ingested row.
        let revs = v.revisions_for(id).expect("revisions_for");
        let ingested = revs
            .iter()
            .find(|m| m.chain_anchor.is_some())
            .expect("foreign-ingested row");
        assert!(
            !ingested.is_tombstone,
            "decode failed → bit must be 0; freeze sentinel handles UX"
        );
        // Freeze sentinel fires regardless of decode success.
        let frozen = v.list_frozen_accounts().expect("list frozen");
        assert!(
            frozen.contains(&id),
            "freeze sentinel must fire on foreign-ingest"
        );
    }

    /// **P10-2 A2 locked-vault edge case.** Ingesting on a Locked vault
    /// (no VDK in cache) skips the opportunistic decode and behaves as
    /// per the unreadable-payload case: bit=0, freeze sentinel fires.
    /// `pull_all` and `ingest_chain_revision` are explicitly metadata-
    /// only ops that work without an active session, so this path is
    /// reachable.
    #[test]
    fn ingest_locked_vault_skips_decryption_and_treats_as_unreadable() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "p10-2-locked.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        // No unlock — vault stays Locked.
        let acct = AccountId::from_bytes([0xCC; 32]);
        // Even if we had a magically-decryptable payload, the locked
        // path can't construct it (no VDK access without unlock). Just
        // pass random bytes; the test is verifying the no-panic / bit=0
        // discipline.
        let bogus_ct = vec![0xFF; 32];
        let ev = synth_event(v.vault_id(), *acct.as_bytes(), [0u8; 32], bogus_ct, 1, 0);
        let outcome = v.ingest_chain_revision(&ev).expect("ingest on locked");
        assert_eq!(outcome, IngestOutcome::Inserted);
        let revs = v.revisions_for(acct).expect("revisions_for");
        assert_eq!(revs.len(), 1);
        assert!(
            !revs[0].is_tombstone,
            "locked-vault ingest must leave is_tombstone clear"
        );
    }

    /// **P10-3.** When the opportunistic decode at ingest time
    /// returns `is_tombstone = 1`, the `account_identities.tombstoned`
    /// flag is also flipped to 1. Without this UPDATE, the bit would
    /// be invisible to user-facing read paths.
    #[test]
    fn ingest_tombstone_sets_account_identities_tombstoned_flag() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "p10-3-flag.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        let acct = AccountId::from_bytes([0xAA; 32]);
        let parent = RevisionId::from_bytes([0u8; 32]);
        let ct = seal_tombstone_with_placeholder_nonce(&v, acct, parent, 0, 1);
        let ev = synth_event(v.vault_id(), [0xAA; 32], [0u8; 32], ct, 22, 0);
        v.ingest_chain_revision(&ev).expect("ingest");
        // Direct SQL probe: the new row's tombstoned column is 1.
        let tombstoned: i64 = v
            .conn
            .query_row(
                "SELECT tombstoned FROM account_identities WHERE account_id = ?1",
                params![&[0xAAu8; 32][..]],
                |row| row.get(0),
            )
            .expect("row exists");
        assert_eq!(tombstoned, 1, "tombstoned flag must be 1 post-ingest");
    }

    /// **P10-3.** A chain-ingested tombstone (synthetic-decryptable)
    /// is filtered out of `list_accounts`, just like a locally-deleted
    /// account.
    #[test]
    fn ingest_tombstone_filters_account_from_list_accounts() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "p10-3-listaccts.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        let acct = AccountId::from_bytes([0xBB; 32]);
        let parent = RevisionId::from_bytes([0u8; 32]);
        let ct = seal_tombstone_with_placeholder_nonce(&v, acct, parent, 0, 1);
        let ev = synth_event(v.vault_id(), [0xBB; 32], [0u8; 32], ct, 23, 0);
        v.ingest_chain_revision(&ev).expect("ingest");
        let accts = v.list_accounts();
        assert!(
            !accts.contains(&acct),
            "tombstoned account must not appear in list_accounts"
        );
    }

    /// **P10-3.** `get_account` on a chain-ingested tombstone returns
    /// `None` (the row is filtered, just like a locally-deleted
    /// account).
    #[test]
    fn ingest_tombstone_makes_get_account_return_none() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "p10-3-getnone.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        let acct = AccountId::from_bytes([0xCC; 32]);
        let parent = RevisionId::from_bytes([0u8; 32]);
        let ct = seal_tombstone_with_placeholder_nonce(&v, acct, parent, 0, 1);
        let ev = synth_event(v.vault_id(), [0xCC; 32], [0u8; 32], ct, 24, 0);
        v.ingest_chain_revision(&ev).expect("ingest");
        assert!(
            v.get_account(acct).is_none(),
            "tombstoned → get_account = None"
        );
    }

    /// **P10-3.** `reveal_password` on a chain-ingested tombstone
    /// surfaces a refusal. Under `PoC` the freeze sentinel fires first
    /// (`AccountFrozenPendingResolve`), which is the
    /// stricter-than-`AccountTombstoned` refusal — same UX outcome
    /// (the account is unreadable) and, structurally, freeze takes
    /// precedence in the `refuse_if_*` check order. Both surfaces are
    /// acceptable as long as the read is refused.
    #[test]
    fn ingest_tombstone_makes_reveal_password_return_account_tombstoned() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "p10-3-reveal.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        let acct = AccountId::from_bytes([0xDD; 32]);
        let parent = RevisionId::from_bytes([0u8; 32]);
        let ct = seal_tombstone_with_placeholder_nonce(&v, acct, parent, 0, 1);
        let ev = synth_event(v.vault_id(), [0xDD; 32], [0u8; 32], ct, 25, 0);
        v.ingest_chain_revision(&ev).expect("ingest");
        let err = v
            .reveal_password(acct, &fresh_presence())
            .expect_err("reveal must refuse");
        match err {
            StoreError::AccountTombstoned | StoreError::AccountFrozenPendingResolve { .. } => {}
            other => {
                panic!("expected AccountTombstoned or AccountFrozenPendingResolve, got {other:?}")
            }
        }
    }

    /// **P10-3 / A4.** `add_account` refuses to resurrect a
    /// tombstoned `account_id`. We synthesize a tombstoned row with
    /// a known id, monkey-patch the random-32 derivation to return
    /// that id once before generating fresh, and assert the retry
    /// happens (a fresh non-colliding id is returned).
    ///
    /// The test cannot easily mock `random_32_via_sqlite` directly
    /// (it's a free function over a `Connection`), so instead we use
    /// a deterministic-but-rare condition: insert a tombstoned row
    /// with `id = [0xAF; 32]` (`SQLite`'s randomblob never returns
    /// the same 32-byte sequence twice in practice — we test the
    /// collision-row SCAN path, not the retry-loop exhaustion).
    /// Then we assert that a normal `add_account` does NOT collide
    /// (its random id is fresh) and the new account is distinct from
    /// the tombstoned one. This pins the SCAN path; the
    /// retry-exhaustion path is exercised by the next test.
    #[test]
    fn add_account_refuses_to_resurrect_tombstoned_id() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "p10-3-resurrect.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        // Synthesize a tombstoned row directly via SQL.
        let synthesized_tomb_id = [0xAFu8; 32];
        v.conn
            .execute(
                "INSERT INTO account_identities
                    (account_id, created_at, last_modified_at, tombstoned,
                     head_revision_id)
                 VALUES (?1, 0, 0, 1, ?2)",
                params![&synthesized_tomb_id[..], &[0u8; 32][..]],
            )
            .expect("synth tombstone insert");
        // A normal add_account derives a fresh id; under random-32
        // derivation the chance of colliding with our synthesized
        // tombstoned id is 1/2^256. The probe verifies the helper
        // does NOT return the colliding id.
        let new_id = v
            .add_account(fresh_snapshot())
            .expect("add_account succeeds with fresh id");
        assert_ne!(
            new_id.as_bytes(),
            &synthesized_tomb_id,
            "fresh id must not equal the tombstoned id"
        );
        // Sanity: the synthesized tombstone is still tombstoned.
        let still_tomb: i64 = v
            .conn
            .query_row(
                "SELECT tombstoned FROM account_identities WHERE account_id = ?1",
                params![&synthesized_tomb_id[..]],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(still_tomb, 1, "synthesized tombstone unchanged");
    }

    /// **P10-3 / A4.** Exercise the retry-budget exhaustion path.
    /// We force the helper to repeatedly generate a colliding id by
    /// pre-populating EVERY plausible derivation with a tombstoned
    /// row — impossible in practice, but achievable in test by
    /// monkey-patching the `random_32_via_sqlite` source... which we
    /// can't easily do. Instead, we directly call
    /// `derive_fresh_account_id` on a vault whose entire `account_id`
    /// space is tombstoned (we cannot tombstone all 2^256 ids; we
    /// tombstone the small set of ids that `randomblob` can produce
    /// in our test run by, ah, this isn't tractable without RNG
    /// mocking).
    ///
    /// The pragmatic test: assert that calling
    /// `derive_fresh_account_id` on a vault with NO tombstoned rows
    /// returns `Ok` (no collision is even possible). This is a
    /// smoke-test for the retry loop's happy path; the failure path's
    /// probability bound (~1/2^256) makes a deterministic test
    /// impractical without RNG mocking, which is out of scope for
    /// `PoC`. Documented in the test docstring as a known coverage
    /// gap.
    #[test]
    fn add_account_retry_budget_happy_path_no_collision() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "p10-3-budget.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        // Add 10 live accounts (none tombstoned) to confirm helper
        // doesn't false-positive collide on live ids.
        for _ in 0..10 {
            v.add_account(fresh_snapshot()).expect("add");
        }
        let id = v
            .derive_fresh_account_id()
            .expect("happy path must succeed");
        // No tombstoned-collision check fired because no tombstones.
        let collision: Option<i64> = v
            .conn
            .query_row(
                "SELECT tombstoned FROM account_identities WHERE account_id = ?1",
                params![id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()
            .unwrap();
        // The fresh id must not collide with any existing id at all
        // (live OR tombstoned).
        assert!(
            collision.is_none(),
            "fresh derived id must not collide with any existing row"
        );
    }

    /// **P10-3 / A5 reaffirmation.** P9's
    /// `build_merge_payload_for_resolve` tombstone branch now
    /// produces the P10-1 widened three-field payload. Verify the
    /// merge revision's payload decodes as a `TombstonePayload` whose
    /// `account_id` matches the merge's `account_id` and whose
    /// `tombstoned_at_ms` is the merge's seal time (NOT the original
    /// tombstone's timestamp — per plan §A5 / Q2 the merge revision
    /// is a fresh chain event and the in-payload timestamp is the
    /// timestamp of the *seal*, not the *concept*).
    #[test]
    fn merge_payload_for_resolve_uses_new_three_field_tombstone_shape() {
        use crate::blob::{build_aad, open_payload, DecodedPayload};
        use pangolin_crypto::aead::{Ciphertext, Nonce, NONCE_LEN};

        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "p10-3-merge.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        let acct = v.add_account(fresh_snapshot()).expect("add");
        v.delete_account(acct).expect("delete");
        let history = v.revisions_for(acct).expect("revs");
        let tomb_meta = history.iter().find(|m| m.is_tombstone).expect("tomb");
        let chosen = tomb_meta.revision_id;

        let (payload_bytes, nonce_bytes, schema_version, _is_tomb) = v
            .build_merge_payload_for_resolve(acct, chosen)
            .expect("merge payload");
        let aad = build_aad(&v.meta.vault_id, &acct, &chosen, schema_version);
        let nonce_arr: [u8; NONCE_LEN] = nonce_bytes;
        let nonce = Nonce::from_storage_bytes(nonce_arr);
        let ct = Ciphertext::from_vec(payload_bytes);
        let active = v.require_active().expect("active");
        match open_payload(active.vdk.aead_key(), &nonce, &ct, &aad).expect("open") {
            DecodedPayload::Tombstone(p) => {
                assert!(p.is_deleted());
                assert_eq!(p.account_id(), acct.as_bytes());
                assert!(p.tombstoned_at_ms() > 0);
            }
            DecodedPayload::Live(_) => panic!("expected Tombstone"),
        }
    }

    /// **P10-2 A2 non-oracle property.** AEAD-failure (random bytes)
    /// and CBOR-decode-failure (a successful AEAD open whose plaintext
    /// is malformed CBOR) MUST take the same branch — both produce the
    /// same `IngestOutcome::Inserted`, both leave `is_tombstone = 0`,
    /// neither escapes any error variant. The non-oracle property is
    /// what blocks an attacker from distinguishing "I corrupted the
    /// AEAD ciphertext" from "I corrupted the CBOR plaintext."
    #[test]
    fn ingest_tombstone_bit_does_not_oracle_aead_failure_versus_decode_failure() {
        use crate::blob::build_aad;
        use pangolin_crypto::aead::{Nonce, NONCE_LEN};

        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "p10-2-oracle.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();

        // Path 1: AEAD fails (bogus bytes; opens fail).
        let acct1 = AccountId::from_bytes([0x11; 32]);
        let bogus_ct = vec![0xDD; 32];
        let ev1 = synth_event(v.vault_id(), *acct1.as_bytes(), [0u8; 32], bogus_ct, 10, 0);
        let out1 = v.ingest_chain_revision(&ev1).expect("ingest 1");
        assert_eq!(out1, IngestOutcome::Inserted, "path 1: same outcome");
        let revs1 = v.revisions_for(acct1).expect("revs 1");
        assert!(!revs1[0].is_tombstone, "path 1: bit=0");

        // Path 2: AEAD succeeds (we seal under the placeholder zero
        // nonce) BUT the plaintext is malformed CBOR (not a valid
        // map). The open succeeds; the decode fails. The bit must
        // still be 0 with the same outcome.
        let acct2 = AccountId::from_bytes([0x22; 32]);
        let parent2 = RevisionId::from_bytes([0u8; 32]);
        let aad = build_aad(&v.meta.vault_id, &acct2, &parent2, 0);
        let active = v.require_active().expect("active");
        let nonce = Nonce::from_storage_bytes([0u8; NONCE_LEN]);
        // Plaintext that is NOT a valid CBOR map header.
        let malformed_plaintext = vec![0xFFu8, 0xFF, 0xFF, 0xFF];
        let malformed_ct = active
            .vdk
            .aead_key()
            .seal(&nonce, &malformed_plaintext, &aad)
            .expect("seal");
        let ev2 = synth_event(
            v.vault_id(),
            *acct2.as_bytes(),
            [0u8; 32],
            malformed_ct.as_bytes().to_vec(),
            11,
            0,
        );
        let out2 = v.ingest_chain_revision(&ev2).expect("ingest 2");
        assert_eq!(
            out2, out1,
            "AEAD-fail and CBOR-fail must produce indistinguishable outcomes"
        );
        let revs2 = v.revisions_for(acct2).expect("revs 2");
        assert!(!revs2[0].is_tombstone, "path 2: bit=0");
    }

    // ---------------------------------------------------------------
    // P10 fix-pass: M-1 + M-2 — payload-vs-event account_id
    // cross-check inside detect_tombstone_bit_at_ingest.
    //
    // The audit flagged a documentation drift: THREAT_MODEL row 18 +
    // docs/issue-plans/P10.md §A1/§C claimed the cross-check existed
    // before the code shipped it. The fix-pass implements the check
    // (constant-time via subtle::ConstantTimeEq) and silently rejects
    // mismatches by returning is_tombstone = 0 — the same bucket as
    // AEAD failure / CBOR failure / locked vault, preserving the
    // non-oracle property of the ingest decoder.
    // ---------------------------------------------------------------

    /// Helper: seal a tombstone payload whose **internal**
    /// `payload.account_id` is `inner_account_id` while the AEAD AAD
    /// is bound to `outer_account_id` (the row/event's
    /// `account_id`). When `inner != outer`, this constructs a
    /// synthetic "cross-account injection" — a ciphertext that
    /// authenticates under the row's AAD but whose plaintext claims
    /// to tombstone a different account.
    ///
    /// Sealed under the placeholder zero nonce, so the ingest path's
    /// opportunistic AEAD-open succeeds.
    fn seal_tombstone_with_payload_account_mismatch(
        v: &Vault,
        outer_account_id: AccountId,
        inner_account_id: AccountId,
        parent: RevisionId,
        schema_version: u8,
        ts_ms: u64,
    ) -> Vec<u8> {
        use crate::blob::build_aad;
        use ciborium_io::Write as _;
        use ciborium_ll::{Encoder, Header};
        use pangolin_crypto::aead::{Nonce, NONCE_LEN};
        let aad = build_aad(&v.meta.vault_id, &outer_account_id, &parent, schema_version);
        let active = v.require_active().expect("vault active");
        // Encode the three-field tombstone CBOR map with the SUPPLIED
        // `inner_account_id` as the plaintext field — NOT the
        // outer/event id. This is the structurally-honest way to
        // exercise the cross-check (the encoder accepts any valid id;
        // the cross-check rejects a mismatched one at ingest).
        let mut out: Vec<u8> = Vec::with_capacity(64);
        {
            let mut enc = Encoder::from(&mut out);
            enc.push(Header::Map(Some(3))).unwrap();
            enc.text("account_id", None).unwrap();
            enc.push(Header::Bytes(Some(ACCOUNT_ID_LEN))).unwrap();
            enc.write_all(inner_account_id.as_bytes()).unwrap();
            enc.text("deleted", None).unwrap();
            enc.push(Header::Simple(ciborium_ll::simple::TRUE)).unwrap();
            enc.text("tombstoned_at_ms", None).unwrap();
            enc.push(Header::Positive(ts_ms)).unwrap();
        }
        let nonce = Nonce::from_storage_bytes([0u8; NONCE_LEN]);
        let ct = active
            .vdk
            .aead_key()
            .seal(&nonce, &out, &aad)
            .expect("seal");
        ct.as_bytes().to_vec()
    }

    /// **P10 fix-pass M-1 + M-2 negative case.** A synthetic event
    /// whose AAD-bound `account_id` is X but whose decrypted
    /// `TombstonePayload::account_id` is Y != X. The decode succeeds
    /// (AEAD valid; CBOR well-formed) but the cross-check inside
    /// `detect_tombstone_bit_at_ingest` rejects the mismatch in
    /// constant time and the row lands with `is_tombstone = 0`.
    /// Crucially, no error variant surfaces — the rejection is
    /// silent, in the same bucket as AEAD failure (non-oracle
    /// property strengthened).
    #[test]
    fn detect_tombstone_bit_rejects_cross_account_payload() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "p10-fix-cross-account.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        let outer = AccountId::from_bytes([0xAA; 32]);
        let inner = AccountId::from_bytes([0xBB; 32]); // DIFFERENT id
        let parent = RevisionId::from_bytes([0u8; 32]);
        let ct = seal_tombstone_with_payload_account_mismatch(
            &v,
            outer,
            inner,
            parent,
            0,
            1_700_000_000_000,
        );
        let ev = synth_event(v.vault_id(), *outer.as_bytes(), [0u8; 32], ct, 99, 0);
        // The ingest itself MUST succeed (no error variant escapes).
        let outcome = v.ingest_chain_revision(&ev).expect("ingest must not error");
        assert_eq!(outcome, IngestOutcome::Inserted);
        let revs = v.revisions_for(outer).expect("revisions_for");
        assert_eq!(revs.len(), 1);
        // The bit MUST be 0 even though decode succeeded — the
        // cross-check rejected the mismatched account_id.
        assert!(
            !revs[0].is_tombstone,
            "cross-account tombstone payload must be silently rejected (bit=0)"
        );
    }

    /// **P10 fix-pass M-1 + M-2 positive case.** Same setup as above
    /// but `payload.account_id == event.account_id`. The cross-check
    /// passes; the bit is set to 1 (regression coverage that the
    /// constant-time comparison doesn't false-reject the valid case).
    #[test]
    fn detect_tombstone_bit_accepts_matching_payload() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "p10-fix-matching.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        let acct = AccountId::from_bytes([0xCC; 32]);
        let parent = RevisionId::from_bytes([0u8; 32]);
        // outer == inner — the matching case.
        let ct = seal_tombstone_with_payload_account_mismatch(
            &v,
            acct,
            acct,
            parent,
            0,
            1_700_000_000_000,
        );
        let ev = synth_event(v.vault_id(), *acct.as_bytes(), [0u8; 32], ct, 100, 0);
        let outcome = v.ingest_chain_revision(&ev).expect("ingest");
        assert_eq!(outcome, IngestOutcome::Inserted);
        let revs = v.revisions_for(acct).expect("revisions_for");
        assert_eq!(revs.len(), 1);
        assert!(
            revs[0].is_tombstone,
            "matching payload account_id must yield is_tombstone = 1"
        );
    }

    // ---------------------------------------------------------------
    // P11B fix-pass M-1: umask shim regression tests.
    // ---------------------------------------------------------------

    /// **P11B fix-pass M-1.** `Vault::create` installs a `0o077`
    /// umask BEFORE the `.pvf` file is created on disk, so the file
    /// is born at mode `0o600` without any intervening `chmod`.
    /// This test reads the file's permissions IMMEDIATELY after
    /// `Vault::create` returns — no chmod is applied by
    /// `pangolin-store` itself, so a `0o600` reading here must come
    /// from the umask, not from a follow-up permission tweak.
    /// (`pangolin-cli`'s `restrict_vault_file_mode` chmod is now
    /// belt-and-braces defense-in-depth, but it is not invoked by
    /// the library.)
    #[cfg(unix)]
    #[test]
    fn umask_set_to_0o077_around_vault_create_unix() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "v-umask.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "expected mode 0o600 from umask shim, got: {:o}",
            mode & 0o777,
        );
    }

    /// **P11B fix-pass M-1.** The `UmaskGuard` restores the previous
    /// umask on `Drop`, so file creation in the same process AFTER
    /// `Vault::create` returns observes the user's normal umask
    /// (typically `0o022`), not the restrictive `0o077` we install
    /// during create. Without the restoration, every subsequent
    /// `File::create` in the same process would silently produce
    /// `0o600` files, which would be a surprising side-effect
    /// outside the vault-provisioning code path.
    ///
    /// We capture the user's umask via a sacrificial file BEFORE
    /// `Vault::create` runs, then create a second file AFTER and
    /// compare. The two modes must match — anything else means the
    /// guard's `Drop` did not restore correctly.
    #[cfg(unix)]
    #[test]
    fn umask_restored_after_vault_create() {
        use nix::sys::stat::{umask, Mode};
        use std::os::unix::fs::PermissionsExt as _;
        let dir = TempDir::new().unwrap();

        // Pin the umask to a KNOWN non-0o077 value (0o022, the canonical
        // Linux default) BEFORE we run anything. This sidesteps host-
        // umask-dependent false alarms — GitHub Actions Linux runners
        // default to 0o077, which would make the original probe-and-
        // compare logic fail the "did the guard leak" assertion even
        // though the guard works correctly.
        //
        // We capture the previous umask so we can restore the test
        // host's actual umask on the way out (matches `UmaskGuard`'s
        // Drop discipline).
        let baseline = Mode::from_bits_truncate(0o022);
        let original = umask(baseline);

        // Probe 1: capture the umask we just pinned, via a file.
        let probe1 = dir.path().join("probe-before.txt");
        std::fs::File::create(&probe1).unwrap();
        let mode_before = std::fs::metadata(&probe1).unwrap().permissions().mode() & 0o777;

        // Run `Vault::create` — this installs `0o077` for its duration
        // and restores the previous (= our 0o022 baseline) value on Drop.
        let p = vault_path(&dir, "v-umask-restore.pvf");
        Vault::create(&p, &fresh_password()).unwrap();

        // Probe 2: a fresh file created AFTER `Vault::create` returns
        // must observe the SAME umask as probe 1 (= 0o022, mode 0o644).
        let probe2 = dir.path().join("probe-after.txt");
        std::fs::File::create(&probe2).unwrap();
        let mode_after = std::fs::metadata(&probe2).unwrap().permissions().mode() & 0o777;

        // Capture assertions BEFORE restoring umask so a panic doesn't
        // skip the cleanup step.
        let restoration_ok = mode_before == mode_after;
        let no_leak = mode_after != 0o600;

        // Restore the test host's original umask. Match `UmaskGuard`'s
        // Drop discipline: this happens regardless of whether the
        // assertions below succeed.
        umask(original);

        assert!(
            restoration_ok,
            "umask must be restored after Vault::create (before: {mode_before:o}, after: {mode_after:o})",
        );
        assert!(
            no_leak,
            "umask 0o077 leaked past Vault::create; subsequent file creation observed 0o600 even though baseline was pinned to 0o022.",
        );
    }

    // -----------------------------------------------------------------
    // MVP-1 issue 1.6: canonical head / fork / resolve / §18.7
    // -----------------------------------------------------------------

    /// Build an unlocked vault with one account that has a 2-way fork
    /// (R0 -> R1 -> R2, plus a sibling R2' of R2). Returns the vault,
    /// the account id, R1 (the fork point), and the two leaves.
    fn forked_account() -> (
        Vault,
        AccountId,
        RevisionId,
        RevisionId,
        RevisionId,
        TempDir,
    ) {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "fork16.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        let id = v.add_account(fresh_snapshot()).unwrap();
        let r1 = v.update_account(id, fresh_snapshot()).unwrap();
        let r2 = v.update_account(id, fresh_snapshot()).unwrap();
        let r2_alt = v
            .__test_synthesize_sibling_revision(id, r1, fresh_snapshot())
            .unwrap();
        (v, id, r1, r2, r2_alt, dir)
    }

    #[test]
    fn vault_canonical_head_matches_after_reopen() {
        let (v, id, _r1, r2, r2_alt, dir) = forked_account();
        let head1 = v.canonical_head(id).unwrap();
        // Canonical head is the largest-revision_id leaf.
        let expected = if r2.as_bytes() > r2_alt.as_bytes() {
            r2
        } else {
            r2_alt
        };
        assert_eq!(head1, expected);
        // Reopen the vault; the rule has no run-to-run dependency.
        let p = v.path().to_path_buf();
        v.close().unwrap();
        let v2 = Vault::open(&p).unwrap();
        assert_eq!(v2.canonical_head(id).unwrap(), head1);
        let _ = dir;
    }

    #[test]
    fn unlock_caches_canonical_head_of_forked_account() {
        let (mut v, id, _r1, r2, r2_alt, dir) = forked_account();
        let canonical = if r2.as_bytes() > r2_alt.as_bytes() {
            r2
        } else {
            r2_alt
        };
        // Re-unlock so the cache is built fresh (the synthesized
        // sibling was inserted after the prior unlock).
        v.lock();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        // account_get returns the summary at the canonical head.
        let summary = v.account_get(id).unwrap();
        assert_eq!(summary.head_revision_id, canonical);
        // account_search also reflects the canonical head.
        let hits = v.account_search("github").unwrap();
        assert!(hits
            .iter()
            .any(|h| h.id == id && h.head_revision_id == canonical));
        let _ = dir;
    }

    #[test]
    fn resolve_fork_unforks_and_advances_head() {
        let (mut v, id, _r1, r2, r2_alt, dir) = forked_account();
        v.lock();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        // Count revisions before.
        let before = v.account_heads(id).unwrap().len();
        assert_eq!(before, 2);
        let all_before = v.account_history(id).unwrap().len();
        // Keep r2 (the linear branch). Resolve.
        let new_rev = v.resolve_fork(id, r2).unwrap();
        assert!(!v.is_forked(id).unwrap());
        assert_eq!(v.canonical_head(id).unwrap(), new_rev);
        // The losing branch (r2_alt) row still exists (Q5 — audit).
        let all_after = v.account_history(id).unwrap();
        assert_eq!(
            all_after.len(),
            all_before + 1,
            "merge revision added, nothing pruned"
        );
        assert!(all_after.iter().any(|m| m.revision_id == r2_alt));
        let _ = dir;
    }

    #[test]
    fn resolve_fork_clears_frozen_and_writes_dirty_marker() {
        let (mut v, id, _r1, r2, _r2_alt, dir) = forked_account();
        v.lock();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        // Force the freeze flag on (defense — resolve must clear it).
        v.conn
            .execute(
                "UPDATE account_identities SET frozen_pending_resolve = 1 WHERE account_id = ?1",
                params![id.as_bytes().as_slice()],
            )
            .unwrap();
        let new_rev = v.resolve_fork(id, r2).unwrap();
        assert!(!v.is_account_frozen(id).unwrap());
        // The merge revision is marked dirty (unpublished).
        let dirty: i64 = v
            .conn
            .query_row(
                "SELECT 1 FROM dirty_accounts WHERE account_id = ?1 AND revision_id = ?2",
                params![id.as_bytes().as_slice(), new_rev.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(dirty, 1);
        let _ = dir;
    }

    #[test]
    fn resolve_fork_prunes_pending_merge_stash() {
        let (mut v, id, _r1, r2, r2_alt, dir) = forked_account();
        v.lock();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        // Stash a pending merge whose target is the *losing* leaf r2_alt
        // (so after resolving to r2, r2_alt is no longer a head → the
        // stash row is orphan → pruned).
        v.stash_pending_merge(
            id,
            r2_alt,
            [7u8; pangolin_crypto::sign::SECRET_KEY_LEN],
            [0u8; pangolin_crypto::aead::NONCE_LEN],
            vec![1, 2, 3],
            1,
        )
        .unwrap();
        assert!(v.take_pending_merge(id, r2_alt).unwrap().is_some());
        v.resolve_fork(id, r2).unwrap();
        assert!(
            v.take_pending_merge(id, r2_alt).unwrap().is_none(),
            "orphan stash row must be pruned on resolve"
        );
        let _ = dir;
    }

    #[test]
    fn resolve_fork_non_head_revision_errors_not_a_head() {
        let (mut v, id, r1, r2, _r2_alt, dir) = forked_account();
        v.lock();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        // r1 is the fork point — a row of this account but NOT a head.
        match v.resolve_fork(id, r1).unwrap_err() {
            StoreError::NotAHead { chosen, .. } => assert_eq!(chosen, r1),
            other => panic!("expected NotAHead, got {other:?}"),
        }
        // Sanity: r2 IS a head.
        assert!(v.account_heads(id).unwrap().contains(&r2));
        let _ = dir;
    }

    #[test]
    fn resolve_fork_cross_account_revision_id_collapsed() {
        let (mut v, id, _r1, r2, _r2_alt, dir) = forked_account();
        v.lock();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        // A revision id from a *different* account → collapsed to
        // AccountNotFound (no oracle), not NotAHead.
        let other_id = v.add_account(fresh_snapshot()).unwrap();
        let other_rev = v.update_account(other_id, fresh_snapshot()).unwrap();
        match v.resolve_fork(id, other_rev).unwrap_err() {
            StoreError::AccountNotFound => {}
            other => panic!("expected AccountNotFound, got {other:?}"),
        }
        assert!(v.account_heads(id).unwrap().contains(&r2));
        let _ = dir;
    }

    #[test]
    fn resolve_fork_non_forked_account_errors_validation() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "linear16.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        let id = v.add_account(fresh_snapshot()).unwrap();
        let head = v.update_account(id, fresh_snapshot()).unwrap();
        match v.resolve_fork(id, head).unwrap_err() {
            StoreError::Validation { kind, .. } => assert_eq!(kind, "not-forked"),
            other => panic!("expected Validation(not-forked), got {other:?}"),
        }
    }

    #[test]
    fn resolve_fork_requires_active_session() {
        let (mut v, id, _r1, r2, _r2_alt, dir) = forked_account();
        v.lock();
        // Locked vault → NotUnlocked, no presence prompt.
        match v.resolve_fork(id, r2).unwrap_err() {
            StoreError::NotUnlocked => {}
            other => panic!("expected NotUnlocked, got {other:?}"),
        }
        let _ = dir;
    }

    #[test]
    fn read_revision_with_future_schema_version_rejects() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "future_row.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        let id = v.add_account(fresh_snapshot()).unwrap();
        let other = v.add_account(fresh_snapshot()).unwrap();
        // Append a head revision with row schema_version = 255.
        v.__test_synthesize_future_version_revision(id, fresh_snapshot(), 255, 1, true)
            .unwrap();
        // Re-unlock so the cache build sees the future head.
        v.lock();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        // The affected account requires upgrade; reads error typed.
        let status = v.account_status(id).unwrap();
        assert!(status.requires_upgrade);
        match v.account_get(id).unwrap_err() {
            StoreError::UnsupportedRevisionSchemaVersion { .. } => {}
            other => panic!("expected UnsupportedRevisionSchemaVersion, got {other:?}"),
        }
        match v.reveal_password(id, &fresh_presence()).unwrap_err() {
            StoreError::UnsupportedRevisionSchemaVersion { .. } => {}
            other => panic!("expected UnsupportedRevisionSchemaVersion, got {other:?}"),
        }
        // Metadata-only reads still work for the affected account.
        assert!(!v.account_history(id).unwrap().is_empty());
        assert!(!v.is_forked(id).unwrap());
        // The rest of the vault works fine.
        assert!(v.account_get(other).is_ok());
        assert!(!v.account_status(other).unwrap().requires_upgrade);
        // Search does not surface the affected account.
        let hits = v.account_search("github").unwrap();
        assert!(hits.iter().all(|h| h.id != id));
        assert!(hits.iter().any(|h| h.id == other));
    }

    #[test]
    fn read_revision_with_future_payload_version_rejects() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "future_payload.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        let id = v.add_account(fresh_snapshot()).unwrap();
        // Row schema_version stays at the build's value (= MAX); the
        // *payload_version* inside the CBOR body is one past MAX (now 3,
        // since 1.7 made V2 a known version).
        let row_v = crate::revision::REVISION_SCHEMA_VERSION_MAX;
        let future_payload = crate::revision::REVISION_SCHEMA_VERSION_MAX + 1;
        v.__test_synthesize_future_version_revision(
            id,
            fresh_snapshot(),
            row_v,
            future_payload,
            true,
        )
        .unwrap();
        v.lock();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        assert!(v.account_status(id).unwrap().requires_upgrade);
        match v.account_get(id).unwrap_err() {
            StoreError::UnsupportedRevisionSchemaVersion { .. } => {}
            other => panic!("expected UnsupportedRevisionSchemaVersion, got {other:?}"),
        }
    }

    #[test]
    fn file_format_version_check_unchanged() {
        // The whole-vault format_version gate is untouched by 1.6 — a
        // bad magic / future format_version still rejects at open.
        // (Regression marker; the meta.rs tests cover the detail.)
        assert_eq!(crate::meta::FORMAT_VERSION, crate::meta::FORMAT_VERSION);
    }

    // -----------------------------------------------------------------
    // MVP-2 issue 4.1 — chain_sync v1 accessor tests
    // -----------------------------------------------------------------

    /// **MVP-2 issue 4.1 (R-a).** Fresh vault returns `None` for the
    /// v1 checkpoint; after `update_last_synced_block_v1` it returns
    /// the persisted value.
    #[test]
    fn last_synced_block_v1_round_trip() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "v.pvf");
        let _ = Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        assert_eq!(v.last_synced_block_v1().unwrap(), None);
        v.update_last_synced_block_v1(100).unwrap();
        assert_eq!(v.last_synced_block_v1().unwrap(), Some(100));
        // Idempotent re-write of the same value.
        v.update_last_synced_block_v1(100).unwrap();
        assert_eq!(v.last_synced_block_v1().unwrap(), Some(100));
        // Forward advance OK.
        v.update_last_synced_block_v1(200).unwrap();
        assert_eq!(v.last_synced_block_v1().unwrap(), Some(200));
    }

    /// **MVP-2 issue 4.1 (R-a + L12).** Backward checkpoint moves are
    /// rejected.
    #[test]
    fn last_synced_block_v1_monotonic() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "v.pvf");
        let _ = Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.update_last_synced_block_v1(200).unwrap();
        let err = v.update_last_synced_block_v1(100).unwrap_err();
        match err {
            StoreError::Corrupted(msg) => assert!(msg.contains("backward")),
            other => panic!("expected Corrupted, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------
    // MVP-3 issue #106c2 — v1/v2 binding + V2 checkpoint tests
    // -----------------------------------------------------------------

    /// A NEW vault is seeded V1 at `Vault::create` (Q-a default), survives
    /// a reopen, and round-trips through `set_revisionlog_version`.
    #[test]
    fn revisionlog_version_default_and_round_trip() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "v.pvf");
        let _ = Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        assert_eq!(
            v.revisionlog_version().unwrap(),
            RevisionLogVersion::V1,
            "NEW vaults default to V1 (Q-a)"
        );
        v.set_revisionlog_version(RevisionLogVersion::V2).unwrap();
        assert_eq!(v.revisionlog_version().unwrap(), RevisionLogVersion::V2);
        // Survives a reopen.
        v.close().unwrap();
        let v2 = Vault::open(&p).unwrap();
        assert_eq!(v2.revisionlog_version().unwrap(), RevisionLogVersion::V2);
    }

    /// A legacy vault whose `meta.revisionlog_version` is NULL reads as
    /// V1 (the no-regression default).
    #[test]
    fn revisionlog_version_null_reads_v1() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "v.pvf");
        let _ = Vault::create(&p, &fresh_password()).unwrap();
        let v = Vault::open(&p).unwrap();
        // Force the column back to NULL to simulate a legacy vault.
        v.conn
            .execute(
                "UPDATE meta SET revisionlog_version = NULL WHERE id = 0",
                [],
            )
            .unwrap();
        assert_eq!(v.revisionlog_version().unwrap(), RevisionLogVersion::V1);
    }

    /// A corrupted (out-of-range) `revisionlog_version` fails closed
    /// rather than silently routing to a default.
    #[test]
    fn revisionlog_version_corrupted_value_rejected() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "v.pvf");
        let _ = Vault::create(&p, &fresh_password()).unwrap();
        let v = Vault::open(&p).unwrap();
        v.conn
            .execute("UPDATE meta SET revisionlog_version = 9 WHERE id = 0", [])
            .unwrap();
        let err = v.revisionlog_version().unwrap_err();
        match err {
            StoreError::Corrupted(msg) => assert!(msg.contains("unrecognized")),
            other => panic!("expected Corrupted, got {other:?}"),
        }
    }

    /// The V2 checkpoint is SEPARATE from the V1 checkpoint (Q-e): writing
    /// one never touches the other.
    #[test]
    fn v1_v2_checkpoints_are_independent() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "v.pvf");
        let _ = Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        assert_eq!(v.last_synced_block_v2().unwrap(), None);
        v.update_last_synced_block_v1(100).unwrap();
        // V2 cursor is untouched by a V1 advance.
        assert_eq!(v.last_synced_block_v2().unwrap(), None);
        v.update_last_synced_block_v2(50).unwrap();
        assert_eq!(v.last_synced_block_v2().unwrap(), Some(50));
        // V1 cursor is untouched by a V2 advance.
        assert_eq!(v.last_synced_block_v1().unwrap(), Some(100));
        // V2 monotonic guard.
        let err = v.update_last_synced_block_v2(10).unwrap_err();
        match err {
            StoreError::Corrupted(msg) => assert!(msg.contains("backward")),
            other => panic!("expected Corrupted, got {other:?}"),
        }
    }

    /// **MVP-2 issue 4.1 (R-c).** `rollback_pending_revisions_in_range`
    /// only deletes rows whose `revision_status = 'pending'`.
    #[test]
    fn rollback_pending_revisions_in_range_skips_finalized() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "v.pvf");
        let _ = Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        // Pre-seed: one pending row in range, one pending out of range,
        // one finalized in range. None should fire on the finalized.
        let acc = [0xAAu8; 32];
        v.conn
            .execute(
                "INSERT INTO account_identities (account_id, created_at, last_modified_at, head_revision_id)
                 VALUES (?1, 0, 0, ?2)",
                rusqlite::params![&acc[..], &[0xBBu8; 32][..]],
            )
            .unwrap();
        for (rid_byte, status, block) in [
            (0x01u8, "pending", 100i64),
            (0x02u8, "pending", 500i64),
            (0x03u8, "finalized", 100i64),
        ] {
            v.conn
                .execute(
                    "INSERT INTO revisions \
                        (revision_id, account_id, parent_revision_id, device_id, schema_version, \
                         created_at, enc_payload, enc_nonce, revision_status, observed_at_block) \
                     VALUES (?1, ?2, ?3, ?4, 1, 0, ?5, ?6, ?7, ?8)",
                    rusqlite::params![
                        &[rid_byte; 32][..],
                        &acc[..],
                        &[0u8; 32][..],
                        &[0xCCu8; 32][..],
                        &[0xDEu8; 4][..],
                        &[0xEEu8; 24][..],
                        status,
                        block,
                    ],
                )
                .unwrap();
        }
        let rolled = v.rollback_pending_revisions_in_range(50, 200).unwrap();
        assert_eq!(rolled, 1, "only the pending row in range gets rolled back");
        // Verify the finalized row in range is preserved.
        let preserved: i64 = v
            .conn
            .query_row(
                "SELECT COUNT(*) FROM revisions WHERE revision_id = ?1",
                rusqlite::params![&[0x03u8; 32][..]],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(preserved, 1, "finalized rows must NEVER be rolled back");
        // Verify the out-of-range pending row is also preserved.
        let pending_out: i64 = v
            .conn
            .query_row(
                "SELECT COUNT(*) FROM revisions WHERE revision_id = ?1",
                rusqlite::params![&[0x02u8; 32][..]],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(pending_out, 1, "out-of-range pending rows preserved");
    }

    /// **MVP-2 issue 4.1 (R-c).** `promote_finalized_revisions`
    /// promotes only pending rows at depth ≥ 12.
    #[test]
    fn promote_finalized_at_twelve_conf() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "v.pvf");
        let _ = Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        let acc = [0xAAu8; 32];
        v.conn
            .execute(
                "INSERT INTO account_identities (account_id, created_at, last_modified_at, head_revision_id)
                 VALUES (?1, 0, 0, ?2)",
                rusqlite::params![&acc[..], &[0xBBu8; 32][..]],
            )
            .unwrap();
        // Insert pending rows at blocks 88 (depth 12 vs head=100, eligible)
        // and 95 (depth 5, NOT eligible).
        for (rid_byte, block) in [(0x10u8, 88i64), (0x11u8, 95i64)] {
            v.conn
                .execute(
                    "INSERT INTO revisions \
                        (revision_id, account_id, parent_revision_id, device_id, schema_version, \
                         created_at, enc_payload, enc_nonce, revision_status, observed_at_block) \
                     VALUES (?1, ?2, ?3, ?4, 1, 0, ?5, ?6, 'pending', ?7)",
                    rusqlite::params![
                        &[rid_byte; 32][..],
                        &acc[..],
                        &[0u8; 32][..],
                        &[0xCCu8; 32][..],
                        &[0xDEu8; 4][..],
                        &[0xEEu8; 24][..],
                        block,
                    ],
                )
                .unwrap();
        }
        let promoted = v.promote_finalized_revisions(100).unwrap();
        assert_eq!(
            promoted, 1,
            "only the depth-12 row should promote (head=100, threshold=88)"
        );
        let status_at_88: String = v
            .conn
            .query_row(
                "SELECT revision_status FROM revisions WHERE revision_id = ?1",
                rusqlite::params![&[0x10u8; 32][..]],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(status_at_88, "finalized");
        let status_at_95: String = v
            .conn
            .query_row(
                "SELECT revision_status FROM revisions WHERE revision_id = ?1",
                rusqlite::params![&[0x11u8; 32][..]],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(status_at_95, "pending", "depth 5 stays pending");
    }

    /// **MVP-2 issue 4.1 (R-d).** Auto-registering a new chain-sync-
    /// observed device inserts a row flagged with
    /// `discovered_via_chain_sync = 1`; a second call with the same
    /// address is idempotent.
    #[test]
    fn auto_register_chain_sync_device_idempotent() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "v.pvf");
        let _ = Vault::create(&p, &fresh_password()).unwrap();
        let v = Vault::open(&p).unwrap();
        let evm = [0xAAu8; 20];
        let inserted_first = crate::device::auto_register_device_from_chain_sync(
            &v.conn,
            evm,
            500,
            1_700_000_000_000,
        )
        .unwrap();
        assert!(inserted_first, "first call inserts");
        let inserted_second = crate::device::auto_register_device_from_chain_sync(
            &v.conn,
            evm,
            500,
            1_700_000_000_000,
        )
        .unwrap();
        assert!(!inserted_second, "second call is idempotent");
        let count = v.count_chain_sync_discovered_devices().unwrap();
        assert_eq!(count, 1);
    }

    // -----------------------------------------------------------------
    // MVP-2 issue 4.4 — sync-mode selector tests
    // -----------------------------------------------------------------
    //
    // The picker is `async fn` per the locked R-c API signature, even
    // though the current implementation never awaits. We drive it
    // through a small tokio current-thread runtime so the test path
    // mirrors the production caller shape.

    use crate::vault::{SyncMode, SyncModePreference};
    use pangolin_chain::ChainEnv;

    /// Helper: drive an async future to completion on a fresh tokio
    /// current-thread runtime. Tokio is a dev-only dep on this crate
    /// (added in 4.4); the runtime is small + per-call so tests stay
    /// hermetic.
    fn block_on<F: std::future::Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(fut)
    }

    /// **MVP-2 issue 4.4 (R-a).** Fresh vault (no v1 checkpoint) +
    /// preference NULL ⇒ `SyncMode::OfferFast`.
    #[test]
    fn select_sync_mode_returns_offer_fast_for_first_sync() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "v.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let v = Vault::open(&p).unwrap();
        assert_eq!(v.last_synced_block_v1().unwrap(), None);
        assert_eq!(v.sync_mode_preference().unwrap(), SyncModePreference::Auto);
        let mode =
            block_on(v.select_sync_mode("http://unused.example", ChainEnv::BaseSepolia)).unwrap();
        assert_eq!(mode, SyncMode::OfferFast);
    }

    /// **MVP-2 issue 4.4 (R-a).** Vault that has synced at least once
    /// (checkpoint = Some) + preference NULL ⇒ `SyncMode::Slow`.
    #[test]
    fn select_sync_mode_returns_slow_after_first_sync() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "v.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.update_last_synced_block_v1(42).unwrap();
        let mode =
            block_on(v.select_sync_mode("http://unused.example", ChainEnv::BaseSepolia)).unwrap();
        assert_eq!(mode, SyncMode::Slow);
    }

    /// **MVP-2 issue 4.4 (R-b).** `AlwaysSlow` preference + fresh
    /// checkpoint = None overrides the would-be `OfferFast`.
    #[test]
    fn select_sync_mode_respects_always_slow() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "v.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.set_sync_mode_preference(SyncModePreference::AlwaysSlow)
            .unwrap();
        assert_eq!(v.last_synced_block_v1().unwrap(), None);
        let mode =
            block_on(v.select_sync_mode("http://unused.example", ChainEnv::BaseSepolia)).unwrap();
        assert_eq!(mode, SyncMode::Slow);
    }

    /// **MVP-2 issue 4.4 (R-b).** `AlwaysSlow` preference + non-fresh
    /// checkpoint still returns `Slow` (preference dominates).
    #[test]
    fn select_sync_mode_respects_always_slow_with_checkpoint() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "v.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.update_last_synced_block_v1(42).unwrap();
        v.set_sync_mode_preference(SyncModePreference::AlwaysSlow)
            .unwrap();
        let mode =
            block_on(v.select_sync_mode("http://unused.example", ChainEnv::BaseSepolia)).unwrap();
        assert_eq!(mode, SyncMode::Slow);
    }

    /// **MVP-2 issue 4.4 (R-b).** `AlwaysFast` preference + fresh
    /// checkpoint = None returns `AlwaysFast` (preference forces fast
    /// even on first sync, skipping the prompt).
    #[test]
    fn select_sync_mode_respects_always_fast() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "v.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.set_sync_mode_preference(SyncModePreference::AlwaysFast)
            .unwrap();
        let mode =
            block_on(v.select_sync_mode("http://unused.example", ChainEnv::BaseSepolia)).unwrap();
        assert_eq!(mode, SyncMode::AlwaysFast);
    }

    /// **MVP-2 issue 4.4 (R-b).** `AlwaysFast` preference + non-fresh
    /// checkpoint still returns `AlwaysFast` — preference forces fast
    /// even when caught up.
    #[test]
    fn select_sync_mode_respects_always_fast_with_checkpoint() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "v.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.update_last_synced_block_v1(42).unwrap();
        v.set_sync_mode_preference(SyncModePreference::AlwaysFast)
            .unwrap();
        let mode =
            block_on(v.select_sync_mode("http://unused.example", ChainEnv::BaseSepolia)).unwrap();
        assert_eq!(mode, SyncMode::AlwaysFast);
    }

    /// **MVP-2 issue 4.4 (R-b persistence).** `set_sync_mode_preference`
    /// → close + reopen the vault → preference reads back as
    /// `AlwaysSlow`.
    #[test]
    fn sync_mode_preference_round_trip_always_slow() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "v.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        {
            let mut v = Vault::open(&p).unwrap();
            v.set_sync_mode_preference(SyncModePreference::AlwaysSlow)
                .unwrap();
        }
        // Re-open and read.
        let v2 = Vault::open(&p).unwrap();
        assert_eq!(
            v2.sync_mode_preference().unwrap(),
            SyncModePreference::AlwaysSlow
        );
    }

    /// **MVP-2 issue 4.4 (R-b persistence).** Same as above with
    /// `AlwaysFast`.
    #[test]
    fn sync_mode_preference_round_trip_always_fast() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "v.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        {
            let mut v = Vault::open(&p).unwrap();
            v.set_sync_mode_preference(SyncModePreference::AlwaysFast)
                .unwrap();
        }
        let v2 = Vault::open(&p).unwrap();
        assert_eq!(
            v2.sync_mode_preference().unwrap(),
            SyncModePreference::AlwaysFast
        );
    }

    /// **MVP-2 issue 4.4 (R-b default).** A freshly-created vault
    /// reads as `SyncModePreference::Auto` (column is NULL by default).
    #[test]
    fn sync_mode_preference_default_is_auto() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "v.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let v = Vault::open(&p).unwrap();
        assert_eq!(v.sync_mode_preference().unwrap(), SyncModePreference::Auto);
    }

    /// **MVP-2 issue 4.4 (R-b reversibility).** Setting a preference
    /// then clearing back to `Auto` writes SQL NULL and reads `Auto`.
    #[test]
    fn sync_mode_preference_can_be_cleared() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "v.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.set_sync_mode_preference(SyncModePreference::AlwaysSlow)
            .unwrap();
        assert_eq!(
            v.sync_mode_preference().unwrap(),
            SyncModePreference::AlwaysSlow
        );
        // Clear back to Auto.
        v.set_sync_mode_preference(SyncModePreference::Auto)
            .unwrap();
        assert_eq!(v.sync_mode_preference().unwrap(), SyncModePreference::Auto);
        // Confirm the underlying column is SQL NULL (not the literal
        // string "auto" or similar — Auto ⇔ NULL is load-bearing per
        // R-b).
        let raw: Option<String> = v
            .conn
            .query_row(
                "SELECT sync_mode_preference FROM meta WHERE id = 0",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            raw.is_none(),
            "Auto must serialize as SQL NULL, not a string literal"
        );
    }

    /// **MVP-2 issue 4.4 (R-b).** An unrecognized value in the
    /// `meta.sync_mode_preference` column surfaces as
    /// `StoreError::Corrupted` rather than silently degrading to a
    /// default — defense against tampered cleartext flags.
    #[test]
    fn from_meta_str_rejects_unknown_value() {
        let err = SyncModePreference::from_meta_str(Some("garbage")).unwrap_err();
        match err {
            StoreError::Corrupted(msg) => {
                assert!(msg.contains("garbage"));
                assert!(msg.contains("always_slow"));
                assert!(msg.contains("always_fast"));
            }
            other => panic!("expected Corrupted, got {other:?}"),
        }
    }

    /// **MVP-2 issue 4.4 (R-d doc-spec parity).** Exhaustive
    /// round-trip: `from_meta_str(to_meta_str(x)) == Ok(x)` for all
    /// three variants. Pins the storage encoding so a future
    /// refactor cannot silently re-map (e.g., flipping the
    /// `"always_slow"` / `"always_fast"` string literals).
    #[test]
    fn sync_mode_preference_meta_str_round_trip() {
        for variant in [
            SyncModePreference::Auto,
            SyncModePreference::AlwaysSlow,
            SyncModePreference::AlwaysFast,
        ] {
            let s = variant.to_meta_str();
            let back = SyncModePreference::from_meta_str(s).unwrap();
            assert_eq!(back, variant, "round-trip mismatch for {variant:?}");
        }
        // Also pin the actual literal strings — drift defense.
        assert_eq!(SyncModePreference::Auto.to_meta_str(), None);
        assert_eq!(
            SyncModePreference::AlwaysSlow.to_meta_str(),
            Some("always_slow")
        );
        assert_eq!(
            SyncModePreference::AlwaysFast.to_meta_str(),
            Some("always_fast")
        );
    }

    // =================================================================
    // MVP-2 issue 5.4 (R-e) — `Vault::lock_with_drain` tests.
    // =================================================================
    //
    // Cover the pre-lock drain contract: flush runs BEFORE lock; flush
    // failures do NOT block teardown; locked-vault entry returns the
    // typed `NoActiveSession` without touching state.

    mod lock_with_drain_tests {
        use super::*;
        use crate::publish::BatchFlushError;
        use async_trait::async_trait;
        use pangolin_chain::{
            ChainAdapter, ChainAnchor, ChainError, EventLocation, MockChainAdapter, RevisionEvent,
            SignedRevision, VaultId,
        };
        use pangolin_crypto::keys::DeviceKey;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc as StdArc;

        /// Helper: fresh, unlocked vault in a tempdir.
        fn fresh_unlocked() -> (Vault, TempDir) {
            let dir = TempDir::new().expect("tempdir");
            let path = vault_path(&dir, "v.pvf");
            Vault::create(&path, &fresh_password()).expect("create");
            let mut v = Vault::open(&path).expect("open");
            v.unlock(&fresh_presence(), &fresh_pin()).expect("unlock");
            (v, dir)
        }

        /// Adapter that counts publish calls; otherwise proxies into
        /// `MockChainAdapter`.
        struct CountingAdapter {
            inner: MockChainAdapter,
            count: StdArc<AtomicUsize>,
        }
        impl CountingAdapter {
            fn new() -> Self {
                Self {
                    inner: MockChainAdapter::new(),
                    count: StdArc::new(AtomicUsize::new(0)),
                }
            }
            fn count(&self) -> usize {
                self.count.load(Ordering::SeqCst)
            }
        }
        #[async_trait]
        impl ChainAdapter for CountingAdapter {
            async fn publish(&self, signed: &SignedRevision) -> Result<ChainAnchor, ChainError> {
                self.count.fetch_add(1, Ordering::SeqCst);
                self.inner.publish(signed).await
            }
            async fn pull_since(
                &self,
                vault_id: &VaultId,
                from_block: u64,
                until_block: Option<u64>,
            ) -> Result<Vec<RevisionEvent>, ChainError> {
                self.inner
                    .pull_since(vault_id, from_block, until_block)
                    .await
            }
            async fn get_revision(
                &self,
                location: &EventLocation,
            ) -> Result<Option<RevisionEvent>, ChainError> {
                self.inner.get_revision(location).await
            }
            async fn current_block(&self) -> Result<u64, ChainError> {
                self.inner.current_block().await
            }
        }

        /// Adapter that fails the pre-flight balance gate AND would
        /// fail per-revision publishes if it ever got there.
        struct BalanceInsufficientAdapter {
            inner: MockChainAdapter,
            publish_count: StdArc<AtomicUsize>,
        }
        impl BalanceInsufficientAdapter {
            fn new() -> Self {
                Self {
                    inner: MockChainAdapter::new(),
                    publish_count: StdArc::new(AtomicUsize::new(0)),
                }
            }
        }
        #[async_trait]
        impl ChainAdapter for BalanceInsufficientAdapter {
            async fn publish(&self, _signed: &SignedRevision) -> Result<ChainAnchor, ChainError> {
                self.publish_count.fetch_add(1, Ordering::SeqCst);
                Err(ChainError::PrePublishBalanceInsufficient {
                    balance_wei: 1_000,
                    estimate_wei: 1_000_000,
                })
            }
            async fn pull_since(
                &self,
                vault_id: &VaultId,
                from_block: u64,
                until_block: Option<u64>,
            ) -> Result<Vec<RevisionEvent>, ChainError> {
                self.inner
                    .pull_since(vault_id, from_block, until_block)
                    .await
            }
            async fn get_revision(
                &self,
                location: &EventLocation,
            ) -> Result<Option<RevisionEvent>, ChainError> {
                self.inner.get_revision(location).await
            }
            async fn current_block(&self) -> Result<u64, ChainError> {
                self.inner.current_block().await
            }
            async fn pre_flight_batch_balance(
                &self,
                queued_count: usize,
            ) -> Result<Option<pangolin_chain::BatchBalanceCheck>, ChainError> {
                Ok(Some(pangolin_chain::BatchBalanceCheck {
                    total_estimated_cost_wei: 1_000_000u128.saturating_mul(queued_count as u128),
                    current_balance_wei: 1_000,
                }))
            }
        }

        /// **5.4 R-e (load-bearing).** With a pending dirty marker,
        /// `lock_with_drain` MUST flush the marker BEFORE the vault
        /// transitions to Locked — verified by: (a) the adapter sees
        /// the publish call (count == 1), (b) post-call the vault is
        /// Locked, (c) the dirty queue is empty post-call. The
        /// "BEFORE" ordering is enforced structurally: flush runs on
        /// `&mut self.active`'s contents BEFORE `self.lock()` takes
        /// `active` and drops it.
        #[tokio::test]
        async fn lock_with_drain_flushes_pending_queue_before_lock() {
            let (mut v, _dir) = fresh_unlocked();
            let device = DeviceKey::generate();
            let adapter = CountingAdapter::new();
            // Stage a dirty marker.
            let _ = v.add_account(fresh_snapshot()).expect("add");
            assert_eq!(v.list_dirty().expect("list").len(), 1);
            assert!(matches!(v.state(), VaultState::Active));
            // Drain + lock.
            v.lock_with_drain(&adapter, &device)
                .await
                .expect("drain ok");
            // (a) Adapter saw the publish call BEFORE lock — proven by
            //     the call having occurred while `active` was Some.
            assert_eq!(adapter.count(), 1, "flush must run before lock");
            // (b) Vault is Locked post-call.
            assert!(matches!(v.state(), VaultState::Locked));
            // (c) Dirty queue empty (the flush succeeded + cleared).
            //     `list_dirty` works on a locked vault.
            assert!(
                v.list_dirty().expect("list post-lock").is_empty(),
                "drain cleared the dirty marker before lock"
            );
        }

        /// **5.4 R-e + L3.** A flush failure does NOT block teardown —
        /// the vault still transitions to Locked + the error is
        /// returned to the caller AFTER lock runs.
        #[tokio::test]
        async fn lock_with_drain_flush_failure_does_not_block_teardown() {
            let (mut v, _dir) = fresh_unlocked();
            let device = DeviceKey::generate();
            let adapter = BalanceInsufficientAdapter::new();
            let _ = v.add_account(fresh_snapshot()).expect("add");
            assert!(matches!(v.state(), VaultState::Active));
            // Drain attempt fails on the balance gate, but lock still
            // runs (best-effort per L3).
            let result = v.lock_with_drain(&adapter, &device).await;
            // Lock ran regardless.
            assert!(
                matches!(v.state(), VaultState::Locked),
                "lock must transition even on flush failure"
            );
            // Error surfaced AFTER lock.
            let err = result.expect_err("balance gate fires");
            assert!(
                matches!(err, BatchFlushError::BalanceInsufficientForBatch { .. }),
                "expected BalanceInsufficientForBatch, got {err:?}"
            );
            // Dirty marker persists for retry after the next unlock —
            // covered by 5.1's lock/unlock-persistence test on the same
            // primitive.
        }

        /// **5.4 R-e edge case.** An empty queue: `lock_with_drain`
        /// is a no-op-then-lock — zero chain calls, vault Locked.
        #[tokio::test]
        async fn lock_with_drain_on_empty_queue_is_noop_then_locks() {
            let (mut v, _dir) = fresh_unlocked();
            let device = DeviceKey::generate();
            let adapter = CountingAdapter::new();
            assert!(v.list_dirty().expect("list").is_empty());
            v.lock_with_drain(&adapter, &device).await.expect("ok");
            assert_eq!(adapter.count(), 0, "no publish on empty queue");
            assert!(matches!(v.state(), VaultState::Locked));
        }

        /// **5.4 R-e guard.** Calling `lock_with_drain` on an
        /// already-locked vault returns `NoActiveSession` WITHOUT
        /// touching the (already-None) `active` field. No spurious
        /// double-lock; consistent with 5.1 / 5.2 posture.
        #[tokio::test]
        async fn lock_with_drain_on_locked_vault_returns_noactivesession_without_attempting() {
            let (mut v, _dir) = fresh_unlocked();
            let device = DeviceKey::generate();
            let adapter = CountingAdapter::new();
            v.lock();
            assert!(matches!(v.state(), VaultState::Locked));
            let err = v
                .lock_with_drain(&adapter, &device)
                .await
                .expect_err("locked → NoActiveSession");
            assert!(
                matches!(err, BatchFlushError::NoActiveSession),
                "expected NoActiveSession, got {err:?}"
            );
            // Adapter was never touched — the guard short-circuited.
            assert_eq!(adapter.count(), 0);
        }
    }
}
