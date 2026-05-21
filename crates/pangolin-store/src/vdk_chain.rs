// SPDX-License-Identifier: AGPL-3.0-or-later
//! Epoch-keyed VDK-chain persistence (MVP-3 issue #106b-2).
//!
//! When a device is revoked, [`rotate_vdk_for_survivors`] mints a FRESH
//! VDK for a new **VDK epoch**. Because on-chain `encPayload` history is
//! IMMUTABLE, "rotate the VDK" can NOT re-encrypt past entries — instead
//! the client keeps a CHAIN of epoch-keyed VDKs and decrypts each entry
//! under `chain[entry.vdk_epoch]` (plan §3.1, the load-bearing model).
//!
//! This module persists that chain:
//!
//! - the single-row [`vdk_chain_state`] table holds the **current VDK
//!   epoch** pointer (the shared monotonic per-vault epoch, Q-f; the new
//!   writes use the VDK of this epoch);
//! - the [`vdk_chain`] table holds, per NON-current epoch, the
//!   password-anchor [`WrappedVdk`] of that epoch's VDK + the LOCAL
//!   device's per-device wrap [`DeviceWrappedVdk`], so a survivor can
//!   decrypt OLD-epoch entries after a rotation.
//!
//! ## The current epoch's VDK lives in `meta`, not here (additive / legacy)
//!
//! Epoch 0 — and after a rotation the CURRENT epoch — is the VDK in the
//! [`crate::meta`] row (`meta.wrapped_vdk`, the password anchor) + the
//! guardian escrow ([`crate::recovery_escrow`]). A legacy vault that never
//! rotated has NO `vdk_chain` rows and a `vdk_chain_state` row that is
//! absent → it defaults to "single epoch 0, the meta VDK" — exactly the
//! pre-#106b-2 behaviour. The `vdk_chain` table only ever holds the
//! RETAINED OLD epochs (read-only, for decrypting pre-rotation entries on a
//! surviving device); the current epoch is never duplicated into it.
//!
//! ## At-rest discipline (mirrors `recovery_escrow` Q-g / L9)
//!
//! The password-anchor + device-wrap blobs are non-secret at rest (the VDK
//! inside is AEAD-sealed under the password authority / the device key) →
//! plain BLOBs, the `meta.wrapped_ct` idiom. Each retained epoch's VDK is
//! recoverable ONLY by the password authority (anchor) or the local device
//! (device wrap), so a `.pvf` thief without the password / device seed
//! learns nothing.

use std::collections::HashMap;

use pangolin_crypto::aead::{AeadKey, Ciphertext, Nonce, NONCE_LEN};
use pangolin_crypto::keys::{AuthorityKey, VdkKey, WrapContext, WrappedVdk, VAULT_ID_LEN};
use pangolin_crypto::pairing::DeviceWrappedVdk;
use rusqlite::{params, Connection, OptionalExtension, Transaction};

use crate::error::{Result, StoreError};

/// The unlocked RETAINED-epoch VDK chain — the in-memory selector the
/// read path uses to decrypt PRE-rotation entries under
/// `chain[entry.vdk_epoch]` (plan §3.1).
///
/// Holds only the RETAINED OLD-epoch VDKs (read-only). The CURRENT
/// epoch's VDK is NOT held here — it lives in the active session's `vdk`
/// field (the one all new writes encrypt under), so the read path is:
/// `if entry.vdk_epoch == current_epoch { active.vdk } else {
/// chain.aead_for_epoch(entry.vdk_epoch) }`. Built on `unlock` from the
/// [`vdk_chain`] rows (each retained VDK unwrapped under the password
/// authority — the same authority that just opened the current VDK). Lives
/// in the active session and drops (zeroizing every retained VDK) on lock /
/// expiry / `Drop`.
///
/// For an unrotated / legacy vault the chain is EMPTY and `current_epoch`
/// is 0, so the read path always uses `active.vdk` — identical to the
/// pre-#106b-2 single-VDK behaviour.
pub struct VdkChain {
    /// epoch -> that RETAINED (non-current) epoch's VDK.
    retained: HashMap<u64, VdkKey>,
    /// The current (newest) epoch — the one new writes are tagged with and
    /// the one whose VDK lives in `ActiveState.vdk`, not here.
    current_epoch: u64,
}

impl core::fmt::Debug for VdkChain {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The VDKs are secret; report only the epoch shape.
        f.debug_struct("VdkChain")
            .field("current_epoch", &self.current_epoch)
            .field("retained_epochs", &{
                let mut e: Vec<u64> = self.retained.keys().copied().collect();
                e.sort_unstable();
                e
            })
            .finish()
    }
}

impl VdkChain {
    /// The current (newest) epoch — what new writes are tagged with.
    #[must_use]
    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    /// The column-AEAD key for the VDK of a RETAINED `epoch`, or `None` if
    /// this device does not hold that epoch's VDK. NEVER returns the
    /// current epoch's VDK — that lives in `ActiveState.vdk`; the caller
    /// checks `epoch == current_epoch` first.
    #[must_use]
    pub fn aead_for_epoch(&self, epoch: u64) -> Option<&AeadKey> {
        self.retained.get(&epoch).map(VdkKey::aead_key)
    }

    /// Number of RETAINED VDKs in the chain (0 for an unrotated vault).
    #[must_use]
    pub fn retained_len(&self) -> usize {
        self.retained.len()
    }

    /// Build the chain on `unlock`: the persisted `current_epoch` pointer
    /// plus every RETAINED epoch's VDK unwrapped under `authority` (the
    /// same password authority that opened the current VDK on the unlock
    /// path). The current epoch's VDK is NOT loaded here (it stays in the
    /// active session's `vdk`).
    ///
    /// # Errors
    ///
    /// [`StoreError::AuthenticationFailed`] if a retained epoch's password
    /// anchor fails to unwrap under `authority` (tamper / wrong authority);
    /// [`StoreError::Sqlite`] / [`StoreError::Corrupted`] from the chain
    /// read.
    pub fn build_on_unlock(
        conn: &Connection,
        vault_id: &[u8; VAULT_ID_LEN],
        authority: &AuthorityKey,
    ) -> Result<Self> {
        let current_epoch = read_current_epoch(conn)?;
        let mut retained = HashMap::new();
        for stored in read_chain(conn, vault_id)? {
            // The current epoch's VDK is never in `vdk_chain` (it is the
            // meta VDK); guard defensively anyway.
            if stored.epoch == current_epoch {
                continue;
            }
            let vdk = stored
                .password_anchor
                .unwrap_with(authority)
                .map_err(|_| StoreError::AuthenticationFailed)?;
            retained.insert(stored.epoch, vdk);
        }
        Ok(Self {
            retained,
            current_epoch,
        })
    }
}

/// Schema-version slot for the VDK-chain records (master plan §18.7).
/// Mirrors [`crate::recovery_escrow::RECOVERY_ESCROW_SCHEMA_VERSION`].
pub const VDK_CHAIN_SCHEMA_VERSION: u16 = 1;

/// One retained NON-current epoch's VDK as loaded back from disk: its
/// password-anchor wrapper + the local device's per-device wrap.
#[derive(Debug)]
pub struct StoredEpochVdk {
    /// The epoch this VDK is keyed by (`< current_epoch`).
    pub epoch: u64,
    /// The epoch's VDK wrapped under the password authority (the anchor),
    /// recoverable on unlock by re-deriving the authority from the
    /// password. Decrypts OLD-epoch entries.
    pub password_anchor: WrappedVdk,
    /// The epoch's VDK wrapped under the LOCAL device's key (biometric
    /// fast-unlock at-rest form), recoverable by this device alone.
    pub device_wrapped: DeviceWrappedVdk,
}

/// Read the persisted **current VDK epoch** pointer.
///
/// `Ok(0)` when the single-row `vdk_chain_state` table has no row — a
/// legacy / never-rotated vault is "single epoch 0" by construction.
///
/// # Errors
///
/// [`StoreError::Sqlite`] on a DB error; [`StoreError::Corrupted`] on a
/// negative on-disk epoch.
pub fn read_current_epoch(conn: &Connection) -> Result<u64> {
    let raw: Option<i64> = conn
        .query_row(
            "SELECT current_epoch FROM vdk_chain_state WHERE id = 0",
            [],
            |r| r.get(0),
        )
        .optional()?;
    raw.map_or_else(
        || Ok(0),
        |e| {
            u64::try_from(e)
                .map_err(|_| StoreError::Corrupted("vdk_chain_state.epoch negative".into()))
        },
    )
}

/// Load every RETAINED (non-current) epoch's VDK wrappers, ordered by
/// epoch ascending.
///
/// `Ok(vec![])` for a legacy / never-rotated vault (no rows). A row whose
/// `schema_version` exceeds this build's is rejected.
///
/// # Errors
///
/// [`StoreError::Sqlite`] on a DB error; [`StoreError::Corrupted`] on a
/// malformed column; [`StoreError::UnsupportedFormatVersion`] on a future
/// `schema_version`.
pub fn read_chain(conn: &Connection, vault_id: &[u8; VAULT_ID_LEN]) -> Result<Vec<StoredEpochVdk>> {
    let mut stmt = conn.prepare(
        "SELECT epoch, anchor_ct, anchor_nonce, anchor_wrap_schema,
                device_ct, device_nonce, device_wrap_schema, schema_version
         FROM vdk_chain ORDER BY epoch ASC",
    )?;
    let raw_rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, Vec<u8>>(1)?,
            r.get::<_, Vec<u8>>(2)?,
            r.get::<_, i64>(3)?,
            r.get::<_, Vec<u8>>(4)?,
            r.get::<_, Vec<u8>>(5)?,
            r.get::<_, i64>(6)?,
            r.get::<_, i64>(7)?,
        ))
    })?;
    let mut out = Vec::new();
    for raw in raw_rows {
        out.push(decode_chain_row(raw?, vault_id)?);
    }
    Ok(out)
}

/// Raw `vdk_chain` row tuple as read from `SQLite`.
type RawChainRow = (i64, Vec<u8>, Vec<u8>, i64, Vec<u8>, Vec<u8>, i64, i64);

fn decode_chain_row(raw: RawChainRow, vault_id: &[u8; VAULT_ID_LEN]) -> Result<StoredEpochVdk> {
    let (
        epoch_i,
        anchor_ct,
        anchor_nonce,
        anchor_schema_i,
        device_ct,
        device_nonce,
        device_schema_i,
        schema_i,
    ) = raw;
    let schema = u16::try_from(schema_i)
        .map_err(|_| StoreError::Corrupted("vdk_chain.schema_version out of u16".into()))?;
    if schema > VDK_CHAIN_SCHEMA_VERSION {
        return Err(StoreError::UnsupportedFormatVersion(
            u32::from(schema),
            u32::from(VDK_CHAIN_SCHEMA_VERSION),
        ));
    }
    let epoch = u64::try_from(epoch_i)
        .map_err(|_| StoreError::Corrupted("vdk_chain.epoch negative".into()))?;
    let password_anchor = WrappedVdk::from_parts(
        Ciphertext::from_vec(anchor_ct),
        decode_nonce(&anchor_nonce, "vdk_chain.anchor_nonce")?,
        WrapContext {
            vault_id: *vault_id,
            schema_version: decode_schema_u8(anchor_schema_i, "vdk_chain.anchor_wrap_schema")?,
        },
    );
    let device_wrapped = DeviceWrappedVdk::from_wrapped(WrappedVdk::from_parts(
        Ciphertext::from_vec(device_ct),
        decode_nonce(&device_nonce, "vdk_chain.device_nonce")?,
        WrapContext {
            vault_id: *vault_id,
            schema_version: decode_schema_u8(device_schema_i, "vdk_chain.device_wrap_schema")?,
        },
    ));
    Ok(StoredEpochVdk {
        epoch,
        password_anchor,
        device_wrapped,
    })
}

fn decode_nonce(blob: &[u8], what: &str) -> Result<Nonce> {
    let arr: [u8; NONCE_LEN] = blob
        .try_into()
        .map_err(|_| StoreError::Corrupted(format!("{what} length")))?;
    Ok(Nonce::from_storage_bytes(arr))
}

fn decode_schema_u8(v: i64, what: &str) -> Result<u8> {
    u8::try_from(v).map_err(|_| StoreError::Corrupted(format!("{what} out of u8")))
}

/// Append one RETAINED epoch's VDK wrappers (the epoch being demoted from
/// CURRENT to retained-old on a rotation) through a caller-owned
/// transaction, and advance the `current_epoch` pointer.
///
/// This is the atomic-composition primitive `Vault::commit_vdk_rotation`
/// uses: it runs the SAME writes as a standalone commit but on a
/// **borrowed** [`Transaction`] the caller will commit (or roll back)
/// itself, so the chain append + the escrow re-point + the new-epoch
/// password anchor land in ONE atomic boundary (#105a discipline).
///
/// `retained_epoch` is the epoch that WAS current before this rotation
/// (its VDK is the one the caller just demoted); `password_anchor` /
/// `device_wrapped` are that VDK's wrappers. `new_current_epoch` is the
/// epoch the freshly-minted VDK is keyed by — written into the pointer.
///
/// # Errors
///
/// [`StoreError::Sqlite`] on a DB error; [`StoreError::Corrupted`] if an
/// epoch overflows the on-disk encoding.
pub fn append_retained_and_advance_tx(
    tx: &Transaction<'_>,
    retained_epoch: u64,
    password_anchor: &WrappedVdk,
    device_wrapped: &DeviceWrappedVdk,
    new_current_epoch: u64,
) -> Result<()> {
    let retained_i = i64::try_from(retained_epoch)
        .map_err(|_| StoreError::Corrupted("vdk_chain.epoch overflows i64".into()))?;
    let new_current_i = i64::try_from(new_current_epoch)
        .map_err(|_| StoreError::Corrupted("vdk_chain_state.epoch overflows i64".into()))?;

    let anchor = password_anchor;
    let dev = device_wrapped.as_wrapped();
    tx.execute(
        "INSERT OR REPLACE INTO vdk_chain
            (epoch, anchor_ct, anchor_nonce, anchor_wrap_schema,
             device_ct, device_nonce, device_wrap_schema, schema_version)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            retained_i,
            anchor.ciphertext().as_bytes(),
            anchor.nonce().as_bytes().as_slice(),
            i64::from(anchor.context().schema_version),
            dev.ciphertext().as_bytes(),
            dev.nonce().as_bytes().as_slice(),
            i64::from(dev.context().schema_version),
            i64::from(VDK_CHAIN_SCHEMA_VERSION),
        ],
    )?;
    tx.execute(
        "INSERT OR REPLACE INTO vdk_chain_state (id, current_epoch, schema_version)
         VALUES (0, ?1, ?2)",
        params![new_current_i, i64::from(VDK_CHAIN_SCHEMA_VERSION)],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pangolin_crypto::keys::{AuthorityKey, DeviceKey, VdkKey};
    use pangolin_crypto::pairing::{unwrap_vdk_for_device, wrap_vdk_for_device};

    const VAULT_A: [u8; VAULT_ID_LEN] = [0xAA; VAULT_ID_LEN];

    fn fresh_conn() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        crate::schema::apply_pragmas_and_schema(&conn).unwrap();
        conn
    }

    /// A fresh / never-rotated vault: current epoch defaults to 0 and the
    /// chain is empty (the single-epoch-0 default).
    #[test]
    fn fresh_vault_defaults_to_epoch_zero_empty_chain() {
        let conn = fresh_conn();
        assert_eq!(read_current_epoch(&conn).unwrap(), 0);
        assert!(read_chain(&conn, &VAULT_A).unwrap().is_empty());
    }

    /// Append a retained epoch + advance the pointer in one tx, read it
    /// back: the pointer advances, the retained epoch's VDK opens under
    /// both its password anchor AND its device wrap, byte-identical.
    #[test]
    fn append_retained_round_trips() {
        let conn = fresh_conn();
        let old_vdk = VdkKey::generate();
        let auth = AuthorityKey::generate();
        let dev = DeviceKey::generate();
        let ctx = WrapContext::new(VAULT_A);
        let anchor = old_vdk.wrap(&auth, &ctx).unwrap();
        let dwrapped = wrap_vdk_for_device(&old_vdk, &dev, &ctx).unwrap();

        let tx = conn.unchecked_transaction().unwrap();
        append_retained_and_advance_tx(&tx, 0, &anchor, &dwrapped, 1).unwrap();
        tx.commit().unwrap();

        assert_eq!(read_current_epoch(&conn).unwrap(), 1);
        let chain = read_chain(&conn, &VAULT_A).unwrap();
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].epoch, 0);
        // Opens under the password anchor.
        let via_anchor = chain[0].password_anchor.unwrap_with(&auth).unwrap();
        assert!(bool::from(old_vdk.ct_eq(&via_anchor)));
        // Opens under the local device wrap.
        let via_dev = unwrap_vdk_for_device(&chain[0].device_wrapped, &dev).unwrap();
        assert!(bool::from(old_vdk.ct_eq(&via_dev)));
    }

    /// Multi-rotation: epochs 0 then 1 are demoted as the pointer advances
    /// 0→1→2; both retained epochs are readable and ordered.
    #[test]
    fn multi_rotation_retains_each_epoch() {
        let conn = fresh_conn();
        let auth = AuthorityKey::generate();
        let dev = DeviceKey::generate();
        let ctx = WrapContext::new(VAULT_A);

        let v0 = VdkKey::generate();
        let v1 = VdkKey::generate();
        let tx = conn.unchecked_transaction().unwrap();
        append_retained_and_advance_tx(
            &tx,
            0,
            &v0.wrap(&auth, &ctx).unwrap(),
            &wrap_vdk_for_device(&v0, &dev, &ctx).unwrap(),
            1,
        )
        .unwrap();
        tx.commit().unwrap();
        let tx = conn.unchecked_transaction().unwrap();
        append_retained_and_advance_tx(
            &tx,
            1,
            &v1.wrap(&auth, &ctx).unwrap(),
            &wrap_vdk_for_device(&v1, &dev, &ctx).unwrap(),
            2,
        )
        .unwrap();
        tx.commit().unwrap();

        assert_eq!(read_current_epoch(&conn).unwrap(), 2);
        let chain = read_chain(&conn, &VAULT_A).unwrap();
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0].epoch, 0);
        assert_eq!(chain[1].epoch, 1);
        assert!(bool::from(
            v0.ct_eq(&chain[0].password_anchor.unwrap_with(&auth).unwrap())
        ));
        assert!(bool::from(
            v1.ct_eq(&chain[1].password_anchor.unwrap_with(&auth).unwrap())
        ));
    }

    /// A rollback (tx dropped without commit) leaves the chain + pointer
    /// untouched (atomicity primitive).
    #[test]
    fn rollback_leaves_chain_untouched() {
        let conn = fresh_conn();
        let v0 = VdkKey::generate();
        let auth = AuthorityKey::generate();
        let dev = DeviceKey::generate();
        let ctx = WrapContext::new(VAULT_A);
        {
            let tx = conn.unchecked_transaction().unwrap();
            append_retained_and_advance_tx(
                &tx,
                0,
                &v0.wrap(&auth, &ctx).unwrap(),
                &wrap_vdk_for_device(&v0, &dev, &ctx).unwrap(),
                1,
            )
            .unwrap();
            // tx dropped here WITHOUT commit -> rollback.
        }
        assert_eq!(
            read_current_epoch(&conn).unwrap(),
            0,
            "pointer must not advance on rollback"
        );
        assert!(read_chain(&conn, &VAULT_A).unwrap().is_empty());
    }
}
