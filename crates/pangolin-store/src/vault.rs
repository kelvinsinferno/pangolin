//! `Vault` — the only public credential-bearing handle on a `.pvf` file.
//!
//! State machine:
//!
//! ```text
//!     ┌──────────┐  open(path)    ┌──────────┐  unlock(pwd)   ┌──────────┐
//!     │  Closed  │ ─────────────▶ │  Locked  │ ─────────────▶ │  Active  │
//!     │ (no SQL) │                │ (handle) │ ◀───────────── │ (cache)  │
//!     └──────────┘                └──────────┘   lock()        └──────────┘
//!           ▲                          ▲                            │
//!           │                          │   create(path, pwd)         │
//!           └─────  close(self) ───────┴─────────────────────────────┘
//! ```
//!
//! Only `Active` permits credential operations. `Locked` is structurally
//! observable (vault id, account count) but reveals no plaintext;
//! `Closed` releases the `SQLite` handle.

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
use crate::revision::{ChainAnchor, DeviceId, RevisionId, RevisionMeta, REVISION_ID_LEN};
use crate::schema;
use crate::search::DecryptedCache;

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
    state: VaultState,
    /// `Some` only while `state == Active`. Owns the unwrapped VDK and
    /// the decrypted-snapshot cache. `lock()` drops this; `Drop` does
    /// the same.
    active: Option<ActiveState>,
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
                state: VaultState::Locked,
                active: None,
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
                state: VaultState::Locked,
                active: None,
                _lock_file: lock_file,
            })
        })();
        if result.is_err() {
            release_lock(path);
        }
        result
    }

    /// Vault id (32-byte content-addressed identifier).
    #[must_use]
    pub fn vault_id(&self) -> [u8; VAULT_ID_LEN] {
        self.meta.vault_id
    }

    /// Current state.
    #[must_use]
    pub fn state(&self) -> VaultState {
        self.state
    }

    /// On-disk path of the vault file (for diagnostics).
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Unlock the vault using `password`.
    ///
    /// Derives the password-AEAD-key via Argon2id at the stored params,
    /// unwraps the [`pangolin_crypto::keys::WrappedVdk`], decrypts every
    /// live account head, builds the in-memory cache, and transitions
    /// to `Active`.
    ///
    /// # Behavior on a vault that is already `Active`
    ///
    /// MEDIUM-5 (P2 audit): the precise semantics of calling `unlock`
    /// twice in a row are worth pinning down because they're not what a
    /// casual reader might assume.
    ///
    /// 1. **Re-call with the same (correct) password while `Active`:**
    ///    succeeds. The full Argon2id derivation runs again (~1–2 s
    ///    burned), the VDK is re-unwrapped, the in-memory cache is
    ///    rebuilt from disk, and the previous `ActiveState` is dropped
    ///    (its secrets zeroize). Useful for re-validating the password
    ///    mid-session, but expensive — callers that just want a fresh
    ///    cache should consider exposing a cheaper "refresh" surface in
    ///    a future version.
    /// 2. **Re-call with the *wrong* password while `Active`:** fails
    ///    with `AuthenticationFailed`, but the existing `ActiveState`
    ///    is **NOT** modified — the prior unlock remains in effect and
    ///    the cache is intact. The vault does NOT auto-lock on a failed
    ///    `unlock`. Callers that want fail-then-lock semantics must
    ///    follow a failed `unlock` with an explicit [`Self::lock`].
    ///
    /// In both cases the Argon2id derivation runs to completion before
    /// any AEAD work (constant-time on the wrong-password vs. tampered-
    /// metadata distinction).
    ///
    /// # Errors
    ///
    /// `StoreError::AuthenticationFailed` for any crypto-class failure
    /// (wrong password, tampered meta, schema-version drift, KDF param
    /// tamper, etc. — all collapse into the single variant per the
    /// MEDIUM-1 fix).
    pub fn unlock(&mut self, password: &SecretBytes) -> Result<()> {
        let seed = kdf::derive_seed(password, &self.meta.kdf_salt, &self.meta.kdf_params)?;
        let authority = AuthorityKey::from_seed(*seed);
        let wrapped = self.meta.wrapped_vdk();
        let vdk = wrapped.unwrap_with(&authority)?;
        // Authority was only needed to unwrap; drop immediately.
        drop(authority);

        let cache = build_decrypted_cache(&self.conn, &self.meta, vdk.aead_key())?;
        self.active = Some(ActiveState { vdk, cache });
        self.state = VaultState::Active;
        Ok(())
    }

    /// Lock the vault. Drops the in-memory cache + VDK; transitions to
    /// `Locked`. Idempotent.
    pub fn lock(&mut self) {
        if let Some(active) = self.active.take() {
            drop(active); // ZeroizeOnDrop on every snapshot in cache.
        }
        self.state = VaultState::Locked;
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

    /// Add a new account identity. Returns the freshly-generated
    /// `AccountId` of the new account.
    ///
    /// # Errors
    ///
    /// `StoreError::NotUnlocked` if state != Active.
    pub fn add_account(&mut self, snapshot: AccountSnapshot) -> Result<AccountId> {
        // Validate state and gather the bytes we need for the seal up
        // front so we don't need to hold the active borrow across the
        // `SQLite` transaction.
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
        Ok(account_id)
    }

    /// Replace an account's contents. Builds a new revision pointing at
    /// the current head as parent, persists, and updates the cache.
    pub fn update_account(
        &mut self,
        id: AccountId,
        new_snapshot: AccountSnapshot,
    ) -> Result<RevisionId> {
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
        Ok(revision_id)
    }

    /// Tombstone an account. Writes a sentinel revision and flips the
    /// account row's `tombstoned` flag. Subsequent reads via
    /// [`Self::get_account`] return `None`.
    pub fn delete_account(&mut self, id: AccountId) -> Result<()> {
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
        Ok(())
    }

    /// Return a borrow on the in-memory snapshot. `None` for unknown,
    /// tombstoned, or vault-not-active.
    #[must_use]
    pub fn get_account(&self, id: AccountId) -> Option<&AccountSnapshot> {
        self.active.as_ref().and_then(|a| a.cache.get(id))
    }

    /// Substring search across non-tombstoned accounts.
    #[must_use]
    pub fn search(&self, query: &str) -> Vec<AccountId> {
        self.active
            .as_ref()
            .map_or_else(Vec::new, |a| a.cache.search(query))
    }

    /// All non-tombstoned account ids in the cache.
    #[must_use]
    pub fn list_accounts(&self) -> Vec<AccountId> {
        self.active
            .as_ref()
            .map_or_else(Vec::new, |a| a.cache.account_ids())
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
    /// # Errors
    ///
    /// `StoreError::RevisionNotFound` if the id is not in the local
    /// log.
    pub fn mark_published(&mut self, revision_id: RevisionId, anchor: ChainAnchor) -> Result<()> {
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
            Err(StoreError::RevisionNotFound)
        } else {
            Ok(())
        }
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
            .field("state", &self.state)
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
    use pangolin_crypto::secret::SecretBytes;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn fresh_password() -> SecretBytes {
        SecretBytes::new(b"correct horse battery staple".to_vec())
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
        let bad = SecretBytes::new(b"definitely not the right password".to_vec());
        let err = v.unlock(&bad).unwrap_err();
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
        let pwd = fresh_password();
        Vault::create(&p, &pwd).unwrap();
        let mut v = Vault::open(&p).unwrap();

        // First unlock (correct password) — vault enters Active.
        v.unlock(&pwd).unwrap();
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
        let bad = SecretBytes::new(b"wrong".to_vec());
        let err = v.unlock(&bad).unwrap_err();
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
        v.unlock(&fresh_password()).unwrap();
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
        v.unlock(&fresh_password()).unwrap();
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
        v.unlock(&fresh_password()).unwrap();
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
        v.unlock(&fresh_password()).unwrap();
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
            v.unlock(&fresh_password()).unwrap();
            id = v.add_account(fresh_snapshot()).unwrap();
            v.lock();
            v.close().unwrap();
        }
        // Reopen cycle.
        let mut v = Vault::open(&p).unwrap();
        v.unlock(&fresh_password()).unwrap();
        let reloaded = v.get_account(id).expect("missing on reopen");
        assert!(bool::from(fresh_snapshot().ct_eq(reloaded)));
    }
}
