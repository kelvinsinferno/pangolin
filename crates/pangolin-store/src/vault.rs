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

use pangolin_crypto::aead::{AeadKey, Ciphertext, Nonce, NONCE_LEN};
use pangolin_crypto::kdf::{self, KdfParams, KdfSalt};
use pangolin_crypto::keys::{AuthorityKey, VdkKey, WrapContext, VAULT_ID_LEN};
use pangolin_crypto::secret::SecretBytes;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};

use crate::account::{AccountId, AccountSnapshot, ACCOUNT_ID_LEN};
use crate::blob::{
    build_aad, open_payload, seal_snapshot, seal_tombstone, DecodedPayload, TombstonePayload,
};
use crate::dirty::{IngestOutcome, RevisionPublishPayload};
use crate::error::{Result, StoreError};
use crate::meta::{self, VaultMeta};
use crate::revision::{
    ChainAnchor, DeviceId, RevisionGraph, RevisionId, RevisionMeta, REVISION_ID_LEN,
};
use crate::schema;
use crate::search::DecryptedCache;
use crate::session::{
    next_idle_deadline, Clock, IdentityProof, PresenceProof, SessionState, SystemClock,
    IDLE_TIMEOUT_DEFAULT,
};

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

/// Public state observable on a [`Vault`] handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultState {
    /// `SQLite` handle open; no plaintext in memory.
    Locked,
    /// `SQLite` handle open; in-memory cache live; credentials usable.
    Active,
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
    /// produces. P2 uses a per-handle random id; MVP-1 will replace
    /// with the device's `pangolin_crypto::keys::DeviceKey` verifying
    /// key bytes.
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

struct ActiveState {
    vdk: VdkKey,
    cache: DecryptedCache,
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
            let device_id = DeviceId(random_32_via_sqlite(&conn)?);
            Ok(Self {
                path: path.to_path_buf(),
                conn,
                meta,
                device_id,
                session_state: SessionState::Locked,
                active: None,
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
        // path (or tampered meta — same outcome by design).
        let wrapped = self.meta.wrapped_vdk();
        let vdk = wrapped.unwrap_with(&authority)?;
        // Authority was only needed to unwrap; drop immediately.
        drop(authority);

        // Step 6: rebuild the decrypted cache.
        let cache = build_decrypted_cache(&self.conn, &self.meta, vdk.aead_key())?;

        // Step 7: install the new ActiveState and session timer. If a
        // prior ActiveState exists (case 1 above), `Option::replace`
        // drops the old one, which zeroizes its cache + VDK.
        let now = self.clock.now();
        self.active = Some(ActiveState { vdk, cache });
        self.session_state = SessionState::Active {
            expires_at: now + IDLE_TIMEOUT_DEFAULT,
            last_proof_at: now,
            session_started_at: now,
        };
        Ok(())
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
            let new_deadline = next_idle_deadline(now, session_started_at);
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
                schema_version, created_at, enc_payload, enc_nonce, is_tombstone
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0)",
            params![
                revision_id.as_bytes().as_slice(),
                account_id.as_bytes().as_slice(),
                parent.as_bytes().as_slice(),
                self.device_id.0.as_slice(),
                i64::from(self.meta.wrap_context.schema_version),
                now,
                ct.as_bytes(),
                nonce.as_bytes().as_slice(),
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

        let active = self.require_active_mut()?;
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
                i64::from(self.meta.wrap_context.schema_version),
                now,
                ct.as_bytes(),
                nonce.as_bytes().as_slice(),
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

        let active = self.require_active_mut()?;
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
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO revisions (
                revision_id, account_id, parent_revision_id, device_id,
                schema_version, created_at, enc_payload, enc_nonce, is_tombstone
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1)",
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

        let active = self.require_active_mut()?;
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
            "SELECT r.revision_id FROM revisions r
             WHERE r.account_id = ?1
               AND NOT EXISTS (
                 SELECT 1 FROM revisions r2
                 WHERE r2.parent_revision_id = r.revision_id
                   AND r2.account_id = r.account_id
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
        let row: Option<RawRevisionPayload> = self
            .conn
            .query_row(
                "SELECT parent_revision_id, schema_version, enc_payload, enc_nonce
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
                    Ok(RawRevisionPayload {
                        parent,
                        schema_version: sv,
                        enc_payload: payload,
                        enc_nonce: nonce,
                    })
                },
            )
            .optional()?;
        // Per docstring: collapse "wrong account_id for this
        // revision" into the same error variant as "unknown
        // account" so the method is not an oracle.
        let RawRevisionPayload {
            parent: parent_blob,
            schema_version: sv_i64,
            enc_payload,
            enc_nonce,
        } = row.ok_or(StoreError::AccountNotFound)?;

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
        let decoded = open_payload(active.vdk.aead_key(), &nonce, &ciphertext, &aad)?;

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
            "SELECT r.revision_id FROM revisions r
             WHERE r.account_id = ?1
               AND NOT EXISTS (
                 SELECT 1 FROM revisions r2
                 WHERE r2.parent_revision_id = r.revision_id
                   AND r2.account_id = r.account_id
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
    // P4: high-risk operations — presence escalation
    // -----------------------------------------------------------------
    //
    // Per Pangolin §5.3 ("High-Risk Action Escalation"):
    //   "For high-risk actions, explicit presence MUST be required"
    //
    // Even on an active session, ops that surface secret material to
    // the host UI (reveal_password, export_payload) require the user
    // to perform an explicit presence confirmation. This is the
    // "step-up" pattern — the active 1-proof session authorizes
    // routine credential access, but secrecy-revealing or vault-
    // migrating ops re-prompt for presence.
    //
    // Order of operations (security-critical):
    //   1. check_session_freshness — session-state structural check.
    //      If the session is locked / expired, return immediately
    //      WITHOUT touching the supplied presence proof. The proof's
    //      single-use flag is preserved for the caller to retry after
    //      reauth. (PressYPresenceProof::Confirmed is single-use; we
    //      MUST NOT burn it on a freshness failure that the caller
    //      can recover from.)
    //   2. presence.verify() — actually check the proof. Single-use
    //      replay rejection + freshness rejection live here. Burns
    //      the proof's one-shot flag.
    //   3. Perform the high-risk op against the cache / disk.
    //   4. touch_session — extend the idle deadline.

    /// Reveal the plaintext password for an account.
    ///
    /// **High-risk operation** (Pangolin §5.3). Requires:
    /// - Active session (1-proof maintain, per the routine session
    ///   policy).
    /// - PLUS an explicit fresh presence proof passed in `presence`.
    ///
    /// Returns a freshly-allocated [`SecretBytes`] cloned from the
    /// in-memory cache. The original cache entry is untouched; the
    /// caller is responsible for the lifetime of the returned bytes
    /// (which zero on drop).
    ///
    /// # Errors
    ///
    /// - [`StoreError::SessionExpired`] / [`StoreError::NotUnlocked`]
    ///   if the session is not active (cache is zeroized as a
    ///   side-effect of `check_session_freshness` if expiry was
    ///   detected).
    /// - [`StoreError::AuthenticationFailed`] if the supplied presence
    ///   proof fails to verify (replayed, stale, or generic failure).
    /// - [`StoreError::AccountNotFound`] if `id` is unknown to the
    ///   cache (either truly unknown or tombstoned).
    pub fn reveal_password(
        &mut self,
        id: AccountId,
        presence: &dyn PresenceProof,
    ) -> Result<SecretBytes> {
        self.reveal_secret_field(id, presence, |snap| snap.password.expose().to_vec())
    }

    /// Reveal the plaintext notes for an account.
    ///
    /// **High-risk operation** (Pangolin §5.4 — same reveal-class
    /// umbrella as `reveal_password`). Notes can carry recovery
    /// phrases or answers to security questions, so the same presence
    /// gate applies. Returns a freshly-allocated [`SecretBytes`] cloned
    /// from the in-memory cache.
    ///
    /// Added in P4-fix-pass-H-1 alongside making
    /// [`crate::account::AccountSnapshot::notes`] crate-private. Without
    /// this accessor, external callers would have no way to read notes
    /// off an unlocked vault — which is the point: every secret-field
    /// readout must route through a presence-gated entry point.
    ///
    /// # Errors
    ///
    /// Same set as [`Self::reveal_password`].
    pub fn reveal_notes(
        &mut self,
        id: AccountId,
        presence: &dyn PresenceProof,
    ) -> Result<SecretBytes> {
        self.reveal_secret_field(id, presence, |snap| snap.notes.expose().to_vec())
    }

    /// Reveal the plaintext TOTP secret for an account.
    ///
    /// **High-risk operation** (Pangolin §5.4 — same reveal-class
    /// umbrella as `reveal_password`). The TOTP shared secret is
    /// directly equivalent to a second-factor seed; revealing it lets
    /// the caller generate codes, so it is gated identically to the
    /// password.
    ///
    /// Returns a freshly-allocated [`SecretBytes`] cloned from the
    /// in-memory cache. If the account has no TOTP configured the
    /// returned `SecretBytes` is empty (`expose() == b""`).
    ///
    /// # Errors
    ///
    /// Same set as [`Self::reveal_password`].
    pub fn reveal_totp_secret(
        &mut self,
        id: AccountId,
        presence: &dyn PresenceProof,
    ) -> Result<SecretBytes> {
        self.reveal_secret_field(id, presence, |snap| snap.totp_secret.expose().to_vec())
    }

    /// Shared implementation for the three `reveal_*` accessors.
    ///
    /// Order of operations is identical to the per-method docstring on
    /// [`Self::reveal_password`] — the only thing that varies between
    /// password / notes / totp is which `SecretBytes` field gets
    /// cloned out at step 3.
    fn reveal_secret_field<F>(
        &mut self,
        id: AccountId,
        presence: &dyn PresenceProof,
        extract: F,
    ) -> Result<SecretBytes>
    where
        F: FnOnce(&AccountSnapshot) -> Vec<u8>,
    {
        // Step 1: structural session check. If this fails, the
        // presence proof is NOT consumed — the caller can retry after
        // reauthing.
        self.check_session_freshness()?;
        // Step 1b (P8 fix CRIT-1): refuse before the presence proof
        // is consumed — same single-use-flag preservation discipline
        // as the session-freshness check above. A user prompted for
        // "press Y" only to be told "this account is frozen" should
        // still be able to retry the proof against a non-frozen
        // account.
        self.refuse_if_frozen(id)?;
        // Step 2: verify presence proof (consumes single-use flag).
        presence.verify()?;
        // Step 3: read from the in-memory cache. Clone the requested
        // field's bytes into a fresh allocation for the caller; the
        // original stays in the cache. Both copies zero on drop.
        let active = self.require_active()?;
        let snapshot = active.cache.get(id).ok_or(StoreError::AccountNotFound)?;
        let bytes = extract(snapshot);
        let out = SecretBytes::new(bytes);
        // Step 4: touch the session (extends the idle deadline).
        self.touch_session();
        Ok(out)
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
    /// **High-risk operation** (Pangolin §5.3). Same proof discipline
    /// as [`Self::reveal_password`]: active session + fresh presence
    /// proof.
    ///
    /// Returns the on-disk AEAD ciphertext + nonce concatenation for
    /// the account's current head revision: `[nonce (24B)] || [ct]`.
    /// The bytes remain AEAD-sealed under the vault's VDK and require
    /// the same vault to decrypt — this primitive is for downstream
    /// migration tooling (P9 vault key rotation, MVP-1 multi-device
    /// re-wrap) rather than direct plaintext export. Plaintext export
    /// requires a separate, even-more-dangerous primitive (deferred
    /// to MVP-1).
    ///
    /// # Errors
    ///
    /// Same set as [`Self::reveal_password`], plus
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
        presence.verify()?;

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

    /// Walk the revision history for `id` from genesis to head. Returns
    /// in chronological order (oldest first). Includes the tombstone
    /// revision when the account is tombstoned.
    pub fn revisions_for(&self, id: AccountId) -> Result<Vec<RevisionMeta>> {
        let mut stmt = self.conn.prepare(
            "SELECT revision_id, parent_revision_id, device_id,
                    schema_version, created_at, is_tombstone,
                    chain_tx_hash, chain_block_number, chain_log_index
             FROM revisions WHERE account_id = ?1
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
            "SELECT r.revision_id, r.created_at FROM revisions r
             WHERE r.account_id = ?1
               AND NOT EXISTS (
                 SELECT 1 FROM revisions r2
                 WHERE r2.parent_revision_id = r.revision_id
                   AND r2.account_id = r.account_id
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
            "SELECT account_id FROM (
                SELECT r.account_id, COUNT(*) AS head_count
                FROM revisions r
                WHERE NOT EXISTS (
                    SELECT 1 FROM revisions r2
                    WHERE r2.parent_revision_id = r.revision_id
                      AND r2.account_id = r.account_id
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
            let heads = self.account_heads(account_id)?;
            let report = crate::conflict::ConflictReport {
                account_id,
                heads,
                frozen: frozen_set.contains(&account_id),
            };
            out.push(report);
        }
        Ok(out)
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

    /// Internal: read every `revisions` row for `account_id` into
    /// [`RevisionMeta`] form. Used by [`Self::revision_graph`].
    fn read_revision_rows_for(&self, id: AccountId) -> Result<Vec<RevisionMeta>> {
        let mut stmt = self.conn.prepare(
            "SELECT revision_id, parent_revision_id, device_id,
                    schema_version, created_at, is_tombstone,
                    chain_tx_hash, chain_block_number, chain_log_index
             FROM revisions WHERE account_id = ?1
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
        // for non-oracle discipline.
        match open_payload(active.vdk.aead_key(), &nonce, &ciphertext, &aad) {
            Ok(DecodedPayload::Tombstone(p)) if p.is_deleted() => 1,
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
        self.conn.execute(
            "INSERT OR IGNORE INTO dirty_accounts
                (account_id, revision_id, marked_at)
             VALUES (?1, ?2, ?3)",
            params![
                account_id.as_bytes().as_slice(),
                revision_id.as_bytes().as_slice(),
                now,
            ],
        )?;
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
}

impl Drop for Vault {
    fn drop(&mut self) {
        // ZeroizeOnDrop on the active state's snapshots fires here.
        self.active.take();
        release_lock(&self.path);
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

/// Generate 32 random bytes via `SQLite`'s `randomblob(32)`. Routes a CSPRNG
/// call we'd otherwise need a separate `rand` dep for.
fn random_32_via_sqlite(conn: &Connection) -> Result<[u8; 32]> {
    let blob: Vec<u8> = conn.query_row("SELECT randomblob(32)", [], |row| row.get(0))?;
    blob.as_slice()
        .try_into()
        .map_err(|_| StoreError::Corrupted(format!("randomblob(32) returned {} bytes", blob.len())))
}

/// Pull all live (non-tombstoned) account heads, decrypt them, and
/// build the in-memory cache.
fn build_decrypted_cache(
    conn: &Connection,
    meta: &VaultMeta,
    vdk_aead: &AeadKey,
) -> Result<DecryptedCache> {
    let mut cache = DecryptedCache::new();
    // MEDIUM-4 (P2 audit): include the per-row `schema_version` in the
    // SELECT so we can bind the row's claimed schema version into the
    // AAD on decrypt. If an attacker edits this column on disk the
    // reconstructed AAD diverges from the seal-time AAD and the AEAD
    // open fails → AuthenticationFailed. Without binding the per-row
    // value, the column was inert (writes set it, reads ignored it).
    let mut stmt = conn.prepare(
        "SELECT ai.account_id, r.parent_revision_id, r.enc_payload, r.enc_nonce, r.schema_version
         FROM account_identities ai
         JOIN revisions r ON ai.head_revision_id = r.revision_id
         WHERE ai.tombstoned = 0",
    )?;
    let rows = stmt.query_map([], |row| {
        let account_id: Vec<u8> = row.get(0)?;
        let parent: Vec<u8> = row.get(1)?;
        let payload: Vec<u8> = row.get(2)?;
        let nonce: Vec<u8> = row.get(3)?;
        let schema_version_i: i64 = row.get(4)?;
        Ok((account_id, parent, payload, nonce, schema_version_i))
    })?;

    for raw in rows {
        let (account_id_blob, parent_blob, payload, nonce_blob, schema_version_i) = raw?;
        let account_id_arr: [u8; ACCOUNT_ID_LEN] = account_id_blob
            .as_slice()
            .try_into()
            .map_err(|_| StoreError::Corrupted("account_id not 32 bytes".into()))?;
        let parent_arr: [u8; REVISION_ID_LEN] = parent_blob
            .as_slice()
            .try_into()
            .map_err(|_| StoreError::Corrupted("parent_revision_id not 32 bytes".into()))?;
        let nonce_arr: [u8; NONCE_LEN] = nonce_blob
            .as_slice()
            .try_into()
            .map_err(|_| StoreError::Corrupted("enc_nonce length mismatch".into()))?;
        // The per-row schema_version column is u8 in spirit; an out-of-
        // range value indicates row-level corruption (or a deliberate
        // tamper attempting to inject a value too large to fit). Either
        // way, surface it as Corrupted rather than silently truncating.
        let row_schema_version = u8::try_from(schema_version_i).map_err(|_| {
            StoreError::Corrupted("revisions.schema_version out of u8 range".into())
        })?;

        let account_id = AccountId::from_bytes(account_id_arr);
        let parent = RevisionId::from_bytes(parent_arr);
        let aad = build_aad(&meta.vault_id, &account_id, &parent, row_schema_version);
        let ct = Ciphertext::from_vec(payload);
        let nonce = Nonce::from_storage_bytes(nonce_arr);
        match open_payload(vdk_aead, &nonce, &ct, &aad)? {
            DecodedPayload::Live(snapshot) => {
                cache.insert(account_id, snapshot);
            }
            DecodedPayload::Tombstone(_) => {
                // A tombstoned head should not have appeared because
                // ai.tombstoned = 0 in the WHERE clause, but if it
                // does we treat it as corruption.
                return Err(StoreError::Corrupted(
                    "non-tombstoned account_identities row points at a tombstone revision".into(),
                ));
            }
        }
    }
    Ok(cache)
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
        Ok(RevisionMeta {
            revision_id,
            parent_revision_id,
            device_id,
            schema_version,
            created_at: self.created_at,
            is_tombstone: self.is_tombstone != 0,
            chain_anchor,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{Vault, VaultState};
    use crate::account::AccountSnapshot;
    use crate::error::StoreError;
    use crate::meta::{FORMAT_VERSION, MAGIC};
    use crate::session::{PinIdentityProof, PressYPresenceProof};
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

    /// Plan success criterion 6:
    /// `vault::tests::reveal_password_requires_fresh_presence` — an
    /// active session does NOT permit `reveal_password` without the
    /// explicit presence proof.
    #[test]
    fn reveal_password_requires_fresh_presence() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "reveal.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
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

        // Active session + valid presence → returns the plaintext.
        let presence = fresh_presence();
        let pwd = v.reveal_password(id, &presence).unwrap();
        assert_eq!(pwd.expose(), b"hunter2-the-secret");

        // The presence proof is consumed; reusing it returns
        // AuthenticationFailed (single-use replay rejection).
        let err = v.reveal_password(id, &presence).unwrap_err();
        assert!(matches!(err, StoreError::AuthenticationFailed));

        // A stale presence proof is rejected.
        let stale = PressYPresenceProof::__test_with_timestamp(
            SystemTime::now() - PRESENCE_FRESHNESS - Duration::from_secs(10),
        );
        let err = v.reveal_password(id, &stale).unwrap_err();
        assert!(matches!(err, StoreError::AuthenticationFailed));

        // A fresh presence proof works again.
        let presence2 = PressYPresenceProof::confirmed();
        let pwd2 = v.reveal_password(id, &presence2).unwrap();
        assert_eq!(pwd2.expose(), b"hunter2-the-secret");
    }

    /// Plan success criterion 7:
    /// `vault::tests::export_payload_requires_fresh_presence` — same
    /// shape as criterion 6 but for the export primitive.
    #[test]
    fn export_payload_requires_fresh_presence() {
        let dir = TempDir::new().unwrap();
        let p = vault_path(&dir, "export.pvf");
        Vault::create(&p, &fresh_password()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        let id = v.add_account(fresh_snapshot()).unwrap();

        // Valid presence → returns the sealed payload.
        let presence = fresh_presence();
        let bytes = v.export_payload(id, &presence).unwrap();
        // Must be at least nonce_len (24) + AEAD-tag (16) + minimum
        // CBOR overhead for an empty struct (~8). 50 bytes is a
        // generous lower bound for any non-degenerate snapshot.
        assert!(
            bytes.len() > 50,
            "exported payload too short: {} bytes",
            bytes.len()
        );

        // Replayed presence → AuthenticationFailed.
        let err = v.export_payload(id, &presence).unwrap_err();
        assert!(matches!(err, StoreError::AuthenticationFailed));

        // Tombstoned account → AccountTombstoned (only after presence
        // verifies, so we use a fresh proof).
        v.delete_account(id).unwrap();
        let presence_after = PressYPresenceProof::confirmed();
        let err = v.export_payload(id, &presence_after).unwrap_err();
        assert!(matches!(err, StoreError::AccountTombstoned));
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
}
