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
use crate::blob::{build_aad, open_payload, seal_snapshot, seal_tombstone, DecodedPayload};
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
        let account_id = AccountId::from_bytes(random_32_via_sqlite(&self.conn)?);
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
        let (ct, nonce) = seal_tombstone(active.vdk.aead_key(), &aad)?;
        let now = current_unix_ms();

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
    #[must_use]
    pub fn get_account(&self, id: AccountId) -> Option<&AccountSnapshot> {
        if !self.is_session_active() {
            return None;
        }
        self.active.as_ref().and_then(|a| a.cache.get(id))
    }

    /// Substring search across non-tombstoned accounts. Returns an
    /// empty `Vec` if the session has expired (mirroring P2 semantics
    /// of returning empty for non-Active vaults).
    #[must_use]
    pub fn search(&self, query: &str) -> Vec<AccountId> {
        if !self.is_session_active() {
            return Vec::new();
        }
        self.active
            .as_ref()
            .map_or_else(Vec::new, |a| a.cache.search(query))
    }

    /// All non-tombstoned account ids in the cache. Empty `Vec` if
    /// the session has expired.
    #[must_use]
    pub fn list_accounts(&self) -> Vec<AccountId> {
        if !self.is_session_active() {
            return Vec::new();
        }
        self.active
            .as_ref()
            .map_or_else(Vec::new, |a| a.cache.account_ids())
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
    /// consumption." A future iteration that introduces a
    /// `cargo`-feature-gated test-utilities surface (`feature =
    /// "test-utilities"`) can move this method behind that gate
    /// without breaking any consumer that respects the prefix
    /// convention.
    ///
    /// Returns the synthesized revision's id.
    ///
    /// # Errors
    ///
    /// Same set as `update_account`, plus `RevisionNotFound` if the
    /// declared parent is not in the account's revision history.
    #[doc(hidden)]
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
        let is_tombstone_i64: i64 = 0; // Per Q's: P10 owns tombstone semantics.

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
        // Both writes run inside one BEGIN IMMEDIATE … COMMIT
        // transaction so a crash between the two leaves the vault
        // in the pre-transaction state.
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT OR IGNORE INTO account_identities
                (account_id, created_at, last_modified_at, tombstoned, head_revision_id)
             VALUES (?1, ?2, ?2, 0, ?3)",
            params![&event.account_id[..], now, &revision_id_arr[..]],
        )?;
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
            DecodedPayload::Tombstone => {
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
}
