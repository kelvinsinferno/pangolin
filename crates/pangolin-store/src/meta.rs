//! Read/write the single-row `meta` table.
//!
//! The meta row carries the bytes a fresh client needs in order to
//! attempt the password-derived unlock: magic header, format version,
//! vault id, KDF parameter triple, KDF salt, and the persisted
//! `WrappedVdk` (ciphertext + nonce + schema version). All of those
//! values are non-secret — the secret material is the user password,
//! which never touches disk.

use pangolin_crypto::aead::{Ciphertext, Nonce, NONCE_LEN};
use pangolin_crypto::kdf::{KdfParams, KdfSalt, SALT_LEN};
use pangolin_crypto::keys::{WrapContext, WrappedVdk, VAULT_ID_LEN};
use rusqlite::{params, Connection, OptionalExtension};

use crate::error::{Result, StoreError};

/// Magic header bytes. The same 8 bytes are written as `meta.magic` and
/// repeated as the `SQLite` `application_id` pragma so that a `strings(1)`
/// scan of a `.pvf` file finds them.
pub const MAGIC: [u8; 8] = *b"PNGLNVT0";

/// Format version produced by *this* build of the crate.
///
/// Per master plan §18.7 schema-versioning policy, future versions MUST
/// accept all old `format_version`s read-only and produce a clean error
/// on unknown future versions; [`StoreError::UnsupportedFormatVersion`]
/// is the latter. Until P2 ships v1, "this build" supports only `0`.
pub const FORMAT_VERSION: u32 = 0;

/// In-memory view of the meta row.
///
/// Held briefly between `open` and `unlock`. None of these fields is
/// secret — the user password and the unwrapped VDK live entirely in
/// memory and are never represented here.
#[derive(Debug)]
pub struct VaultMeta {
    pub vault_id: [u8; VAULT_ID_LEN],
    pub created_at: i64,
    pub kdf_params: KdfParams,
    pub kdf_salt: KdfSalt,
    pub wrap_context: WrapContext,
    pub wrapped_ciphertext: Vec<u8>,
    pub wrapped_nonce: [u8; NONCE_LEN],
}

impl VaultMeta {
    /// Reconstruct a [`WrappedVdk`] from the persisted parts. The
    /// returned value authenticates only when paired with the
    /// password-derived authority via
    /// [`pangolin_crypto::keys::WrappedVdk::unwrap_with`].
    pub fn wrapped_vdk(&self) -> WrappedVdk {
        WrappedVdk::from_parts(
            Ciphertext::from_vec(self.wrapped_ciphertext.clone()),
            Nonce::from_storage_bytes(self.wrapped_nonce),
            self.wrap_context,
        )
    }
}

/// Persist the meta row at `id = 0` with `INSERT OR REPLACE`.
pub fn write(conn: &Connection, meta: &VaultMeta) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO meta (
            id, magic, format_version, vault_id, created_at,
            kdf_memory_kib, kdf_time_cost, kdf_parallelism, kdf_salt,
            schema_version, wrapped_ct, wrapped_nonce
        ) VALUES (
            0, ?1, ?2, ?3, ?4,
            ?5, ?6, ?7, ?8,
            ?9, ?10, ?11
        )",
        params![
            MAGIC.as_slice(),
            i64::from(FORMAT_VERSION),
            meta.vault_id.as_slice(),
            meta.created_at,
            i64::from(meta.kdf_params.memory_kib),
            i64::from(meta.kdf_params.time_cost),
            i64::from(meta.kdf_params.parallelism),
            meta.kdf_salt.as_bytes().as_slice(),
            i64::from(meta.wrap_context.schema_version),
            meta.wrapped_ciphertext.as_slice(),
            meta.wrapped_nonce.as_slice(),
        ],
    )?;
    // Mirror the magic into SQLite's `application_id` so a `file(1)` /
    // `strings` scan finds it without needing to know the table layout.
    // application_id is a 32-bit signed int in SQLite — pack the first
    // four bytes of MAGIC so the on-disk header byte order is stable.
    let app_id = i32::from_be_bytes([MAGIC[0], MAGIC[1], MAGIC[2], MAGIC[3]]);
    conn.pragma_update(None, "application_id", app_id)?;
    Ok(())
}

/// Read the `meta.session_idle_secs` column (MVP-1 issue 1.4 — the
/// configurable idle-timeout choice from Session spec §7.2).
///
/// Returns `Ok(None)` when the row is absent (fresh database not yet
/// written) **or** the column is NULL (a vault that predates 1.4, or one
/// that never explicitly set the choice). Both map to the 15-min
/// default at the call site via
/// [`crate::session::SessionDuration::from_meta_secs`]. A present value
/// is returned verbatim; the caller validates it against the §7.2 set.
pub fn read_session_idle_secs(conn: &Connection) -> Result<Option<i64>> {
    let raw: Option<Option<i64>> = conn
        .query_row(
            "SELECT session_idle_secs FROM meta WHERE id = 0",
            [],
            |row| row.get(0),
        )
        .optional()?;
    // Outer Option = "row present?"; inner Option = "column non-NULL?".
    Ok(raw.flatten())
}

/// Persist (or clear, with `None`) the `meta.session_idle_secs` column.
/// `Some(secs)` writes the raw seconds value (the caller is expected to
/// have validated it against the §7.2 set / the `-1` sentinel);
/// `None` writes SQL `NULL`, which the read path interprets as the
/// 15-min default. UPDATE-only (the meta row exists by construction
/// after `Vault::create`).
pub fn write_session_idle_secs(conn: &Connection, secs: Option<i64>) -> Result<()> {
    conn.execute(
        "UPDATE meta SET session_idle_secs = ?1 WHERE id = 0",
        params![secs],
    )?;
    Ok(())
}

/// Read the `meta.sync_mode_preference` column (MVP-2 issue 4.4 — the
/// three-state sync-mode preference flag).
///
/// Returns `Ok(None)` when the row is absent (fresh database not yet
/// written) **or** the column is NULL (a vault that predates 4.4, or
/// one that never explicitly set the preference). Both map to
/// `SyncModePreference::Auto` at the call site via
/// [`crate::vault::SyncModePreference::from_meta_str`]. A present value
/// is returned verbatim; the caller validates it against the
/// `'always_slow'` / `'always_fast'` set.
///
/// Mirrors `read_session_idle_secs` byte-for-byte in shape.
pub fn read_sync_mode_preference(conn: &Connection) -> Result<Option<String>> {
    let raw: Option<Option<String>> = conn
        .query_row(
            "SELECT sync_mode_preference FROM meta WHERE id = 0",
            [],
            |row| row.get(0),
        )
        .optional()?;
    // Outer Option = "row present?"; inner Option = "column non-NULL?".
    Ok(raw.flatten())
}

/// Persist (or clear, with `None`) the `meta.sync_mode_preference`
/// column. `Some(pref)` writes the literal string (the caller is
/// expected to have validated it against the `'always_slow'` /
/// `'always_fast'` set via
/// [`crate::vault::SyncModePreference::to_meta_str`]); `None` writes
/// SQL `NULL`, which the read path interprets as
/// `SyncModePreference::Auto`. UPDATE-only (the meta row exists by
/// construction after `Vault::create`).
pub fn write_sync_mode_preference(conn: &Connection, pref: Option<&str>) -> Result<()> {
    conn.execute(
        "UPDATE meta SET sync_mode_preference = ?1 WHERE id = 0",
        params![pref],
    )?;
    Ok(())
}

/// Read the meta row. Returns `Ok(None)` when the row has not yet been
/// written (fresh database).
pub fn read(conn: &Connection) -> Result<Option<VaultMeta>> {
    conn.query_row(
        "SELECT magic, format_version, vault_id, created_at,
                kdf_memory_kib, kdf_time_cost, kdf_parallelism, kdf_salt,
                schema_version, wrapped_ct, wrapped_nonce
         FROM meta WHERE id = 0",
        [],
        |row| {
            let magic_blob: Vec<u8> = row.get(0)?;
            let format_version_i: i64 = row.get(1)?;
            let vault_id_blob: Vec<u8> = row.get(2)?;
            let created_at: i64 = row.get(3)?;
            let memory_kib_i: i64 = row.get(4)?;
            let time_cost_i: i64 = row.get(5)?;
            let parallelism_i: i64 = row.get(6)?;
            let kdf_salt_blob: Vec<u8> = row.get(7)?;
            let schema_version_i: i64 = row.get(8)?;
            let wrapped_ct: Vec<u8> = row.get(9)?;
            let wrapped_nonce_blob: Vec<u8> = row.get(10)?;
            Ok(RawMeta {
                magic_blob,
                format_version_i,
                vault_id_blob,
                created_at,
                memory_kib_i,
                time_cost_i,
                parallelism_i,
                kdf_salt_blob,
                schema_version_i,
                wrapped_ct,
                wrapped_nonce_blob,
            })
        },
    )
    .optional()
    .map_err(StoreError::from)?
    .map(RawMeta::into_validated)
    .transpose()
}

/// Intermediate row representation. Validated into [`VaultMeta`] inside
/// [`RawMeta::into_validated`] so all the byte-length / range checks live
/// in one place.
struct RawMeta {
    magic_blob: Vec<u8>,
    format_version_i: i64,
    vault_id_blob: Vec<u8>,
    created_at: i64,
    memory_kib_i: i64,
    time_cost_i: i64,
    parallelism_i: i64,
    kdf_salt_blob: Vec<u8>,
    schema_version_i: i64,
    wrapped_ct: Vec<u8>,
    wrapped_nonce_blob: Vec<u8>,
}

impl RawMeta {
    fn into_validated(self) -> Result<VaultMeta> {
        if self.magic_blob.as_slice() != MAGIC.as_slice() {
            return Err(StoreError::BadMagic);
        }
        let format_version = u32::try_from(self.format_version_i)
            .map_err(|_| StoreError::Corrupted("format_version negative".into()))?;
        if format_version != FORMAT_VERSION {
            return Err(StoreError::UnsupportedFormatVersion(
                format_version,
                FORMAT_VERSION,
            ));
        }
        let vault_id: [u8; VAULT_ID_LEN] =
            self.vault_id_blob.as_slice().try_into().map_err(|_| {
                StoreError::Corrupted(format!(
                    "vault_id length {} (expected {VAULT_ID_LEN})",
                    self.vault_id_blob.len()
                ))
            })?;
        let memory_kib = u32::try_from(self.memory_kib_i)
            .map_err(|_| StoreError::Corrupted("kdf memory_kib out of range".into()))?;
        let time_cost = u32::try_from(self.time_cost_i)
            .map_err(|_| StoreError::Corrupted("kdf time_cost out of range".into()))?;
        let parallelism = u32::try_from(self.parallelism_i)
            .map_err(|_| StoreError::Corrupted("kdf parallelism out of range".into()))?;
        let kdf_salt_arr: [u8; SALT_LEN] =
            self.kdf_salt_blob.as_slice().try_into().map_err(|_| {
                StoreError::Corrupted(format!(
                    "kdf_salt length {} (expected {SALT_LEN})",
                    self.kdf_salt_blob.len()
                ))
            })?;
        let schema_version = u8::try_from(self.schema_version_i)
            .map_err(|_| StoreError::Corrupted("schema_version out of range".into()))?;
        let wrapped_nonce: [u8; NONCE_LEN] =
            self.wrapped_nonce_blob.as_slice().try_into().map_err(|_| {
                StoreError::Corrupted(format!(
                    "wrapped_nonce length {} (expected {NONCE_LEN})",
                    self.wrapped_nonce_blob.len()
                ))
            })?;
        Ok(VaultMeta {
            vault_id,
            created_at: self.created_at,
            kdf_params: KdfParams {
                memory_kib,
                time_cost,
                parallelism,
            },
            kdf_salt: KdfSalt::from_bytes(kdf_salt_arr),
            wrap_context: WrapContext {
                vault_id,
                schema_version,
            },
            wrapped_ciphertext: self.wrapped_ct,
            wrapped_nonce,
        })
    }
}
