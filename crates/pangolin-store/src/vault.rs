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
    /// # Visibility
    ///
    /// Public so the integration test in `tests/e2e.rs` can install a
    /// long-window test clock if needed. The `Box<dyn Clock>` requires
    /// `'static` so callers cannot accidentally tie the clock's
    /// lifetime to a stack frame.
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

    /// `true` iff the session is currently active.
    /// Convenience for the common case in P4-aware callers.
    #[must_use]
    pub fn is_session_active(&self) -> bool {
        self.session_state.is_active()
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

        // Use a single immediate transaction for the two-row write.
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
        if !self.is_session_active_now() {
            return None;
        }
        self.active.as_ref().and_then(|a| a.cache.get(id))
    }

    /// Substring search across non-tombstoned accounts. Returns an
    /// empty `Vec` if the session has expired (mirroring P2 semantics
    /// of returning empty for non-Active vaults).
    #[must_use]
    pub fn search(&self, query: &str) -> Vec<AccountId> {
        if !self.is_session_active_now() {
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
        if !self.is_session_active_now() {
            return Vec::new();
        }
        self.active
            .as_ref()
            .map_or_else(Vec::new, |a| a.cache.account_ids())
    }

    /// `&self`-friendly check: is the session active AND its deadline
    /// not yet past? Used by the `&self` cache-bearing readers
    /// (`get_account`, `search`, `list_accounts`) which cannot mutate
    /// state to flip Active→Expired but DO need to gate their reads.
    fn is_session_active_now(&self) -> bool {
        if let SessionState::Active { expires_at, .. } = self.session_state {
            self.clock.now() <= expires_at
        } else {
            false
        }
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
        let updated = self.conn.execute(
            "UPDATE revisions
             SET chain_tx_hash = ?1, chain_block_number = ?2, chain_log_index = ?3
             WHERE revision_id = ?4",
            params![
                anchor.tx_hash.as_slice(),
                anchor.block_number,
                anchor.log_index,
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
        let chain_anchor = match (
            self.chain_tx_hash,
            self.chain_block_number,
            self.chain_log_index,
        ) {
            (Some(tx), Some(b), Some(i)) => Some(ChainAnchor {
                tx_hash: arr32(&tx, "chain_tx_hash")?,
                block_number: b,
                log_index: i,
            }),
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
}
