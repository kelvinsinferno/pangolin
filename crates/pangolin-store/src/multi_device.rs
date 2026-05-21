// SPDX-License-Identifier: AGPL-3.0-or-later
//! Multi-device store glue (#106c).
//!
//! The GAP A survivor-pubkey directory, the crash-durable rotation-pending
//! state, the GAP C remote-survivor seal-consumption path, and the GAP D
//! set-membership honor gate.
//!
//! These are free functions over a `rusqlite::Connection` (the same posture
//! as [`crate::device`] / [`crate::recovery_escrow`]), wired into the
//! `Vault` engine. None of them hold the master password (L3) — the
//! detection + persistence is engine-side; the password-gated rotation
//! COMPLETION is host-driven (`pangolin-core` stays pure, the Argon2id KDF
//! stays in `Vault::commit_vdk_rotation`).

use pangolin_crypto::escrow::{EPOCH_LEN, X25519_KEY_LEN};
use pangolin_crypto::keys::{DeviceKey, VdkKey, WrapContext, VAULT_ID_LEN};
use pangolin_crypto::pairing::{
    open_vdk_from_pairing, wrap_vdk_for_device, DeviceWrappedVdk, PairingError, SealedVdkForDevice,
    DEVICE_ID_LEN,
};
use rusqlite::{params, Connection, OptionalExtension};

use crate::device::EVM_ADDRESS_LEN;
use crate::error::{Result, StoreError};

/// Schema-version slot for the #106c multi-device records.
pub const MULTI_DEVICE_SCHEMA_VERSION: u16 = 1;

// ---------------------------------------------------------------------
// GAP A — the local signer → (device_id, x25519_pairing_pub) directory
// ---------------------------------------------------------------------

/// One resolved directory entry.
///
/// A known device's secp256k1 `signer` (the on-chain set key) → its stable
/// 32-byte `device_id` (GAP B) + its X25519 pairing pubkey (what rotation
/// seals the new VDK to). All non-secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectoryEntry {
    /// 20-byte secp256k1 signer (the on-chain authorized-set key).
    pub signer: [u8; EVM_ADDRESS_LEN],
    /// Stable 32-byte device identifier (GAP B).
    pub device_id: [u8; DEVICE_ID_LEN],
    /// 32-byte X25519 pairing pubkey.
    pub pairing_pub: [u8; X25519_KEY_LEN],
}

/// Upsert a directory entry (GAP A).
///
/// Populated at device-add when the existing device learns the new device's
/// full triple, and opportunistically as survivors come online. Idempotent:
/// re-upserting the same signer overwrites the row (the pairing pubkey is a
/// pure function of the device key, so a re-presented triple is identical).
///
/// `now_ms` is the wall-clock observation time (audit only).
///
/// # Errors
///
/// [`StoreError::Sqlite`] on a DB error.
pub fn upsert_directory_entry(
    conn: &Connection,
    entry: &DirectoryEntry,
    now_ms: i64,
) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO device_directory
            (signer, device_id, pairing_pub, discovered_at, schema_version)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            entry.signer.as_slice(),
            entry.device_id.as_slice(),
            entry.pairing_pub.as_slice(),
            now_ms,
            i64::from(MULTI_DEVICE_SCHEMA_VERSION),
        ],
    )?;
    Ok(())
}

/// Look up a directory entry by its secp256k1 signer.
///
/// `Ok(None)` when the signer's pairing pubkey is not yet known locally (the
/// opportunistic-completion gap — that survivor is re-keyed when it next
/// comes online).
///
/// # Errors
///
/// [`StoreError::Sqlite`] on a DB error; [`StoreError::Corrupted`] on a
/// malformed-length blob.
pub fn lookup_directory_entry(
    conn: &Connection,
    signer: &[u8; EVM_ADDRESS_LEN],
) -> Result<Option<DirectoryEntry>> {
    let row: Option<(Vec<u8>, Vec<u8>)> = conn
        .query_row(
            "SELECT device_id, pairing_pub FROM device_directory WHERE signer = ?1",
            params![signer.as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    match row {
        None => Ok(None),
        Some((dev, pair)) => {
            let device_id: [u8; DEVICE_ID_LEN] = dev.as_slice().try_into().map_err(|_| {
                StoreError::Corrupted("device_directory.device_id not 32 bytes".into())
            })?;
            let pairing_pub: [u8; X25519_KEY_LEN] = pair.as_slice().try_into().map_err(|_| {
                StoreError::Corrupted("device_directory.pairing_pub not 32 bytes".into())
            })?;
            Ok(Some(DirectoryEntry {
                signer: *signer,
                device_id,
                pairing_pub,
            }))
        }
    }
}

/// Read the full directory (all known `signer → (device_id, pairing_pub)`
/// entries). Used by the rotation-survivor resolver (GAP A + #106c
/// `pangolin_core::device_add::resolve_survivors`).
///
/// # Errors
///
/// [`StoreError::Sqlite`] on a DB error; [`StoreError::Corrupted`] on a
/// malformed-length blob.
pub fn read_directory(conn: &Connection) -> Result<Vec<DirectoryEntry>> {
    let mut stmt = conn
        .prepare("SELECT signer, device_id, pairing_pub FROM device_directory ORDER BY signer")?;
    let rows = stmt.query_map([], |r| {
        let signer: Vec<u8> = r.get(0)?;
        let device_id: Vec<u8> = r.get(1)?;
        let pairing_pub: Vec<u8> = r.get(2)?;
        Ok((signer, device_id, pairing_pub))
    })?;
    let mut out = Vec::new();
    for r in rows {
        let (signer, device_id, pairing_pub) = r?;
        let signer: [u8; EVM_ADDRESS_LEN] = signer
            .as_slice()
            .try_into()
            .map_err(|_| StoreError::Corrupted("device_directory.signer not 20 bytes".into()))?;
        let device_id: [u8; DEVICE_ID_LEN] = device_id
            .as_slice()
            .try_into()
            .map_err(|_| StoreError::Corrupted("device_directory.device_id not 32 bytes".into()))?;
        let pairing_pub: [u8; X25519_KEY_LEN] =
            pairing_pub.as_slice().try_into().map_err(|_| {
                StoreError::Corrupted("device_directory.pairing_pub not 32 bytes".into())
            })?;
        out.push(DirectoryEntry {
            signer,
            device_id,
            pairing_pub,
        });
    }
    drop(stmt);
    Ok(out)
}

// ---------------------------------------------------------------------
// Rotation-pending state (crash-durable, resumable, idempotent — L6)
// ---------------------------------------------------------------------

/// One outstanding rotation-pending row: a device was removed from the
/// on-chain set + the local VDK gap has NOT yet been closed by a rotation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RotationPending {
    /// The 20-byte secp256k1 signer that was removed on-chain.
    pub removed_signer: [u8; EVM_ADDRESS_LEN],
    /// The vault epoch observed at detection time.
    pub observed_epoch: u64,
    /// Wall-clock unix-ms observation time.
    pub observed_at: i64,
}

/// Persist a rotation-pending row (L3: PERSIST + SURFACE only — NEVER
/// rotates).
///
/// Idempotent (L6): re-observing the same `removed_signer` is a no-op
/// (`INSERT OR IGNORE` on the PK), so a closed app re-reading the chain does
/// not double-queue. A closed app RESUMES the pending state on next open via
/// [`read_pending_rotations`].
///
/// # Errors
///
/// [`StoreError::Sqlite`] on a DB error; [`StoreError::Corrupted`] on an
/// epoch overflow.
pub fn queue_rotation_pending(conn: &Connection, pending: &RotationPending) -> Result<bool> {
    let epoch_i = i64::try_from(pending.observed_epoch)
        .map_err(|_| StoreError::Corrupted("rotation_pending.observed_epoch overflow".into()))?;
    let inserted = conn.execute(
        "INSERT OR IGNORE INTO rotation_pending
            (removed_signer, observed_epoch, observed_at, resolved, schema_version)
         VALUES (?1, ?2, ?3, 0, ?4)",
        params![
            pending.removed_signer.as_slice(),
            epoch_i,
            pending.observed_at,
            i64::from(MULTI_DEVICE_SCHEMA_VERSION),
        ],
    )?;
    Ok(inserted > 0)
}

/// Read all OUTSTANDING (unresolved) rotation-pending rows.
///
/// The host surfaces these as "rotation pending — enter master password". A
/// legacy vault with the table absent — impossible after
/// `apply_pragmas_and_schema` — would read an empty list (clean default).
///
/// # Errors
///
/// [`StoreError::Sqlite`] on a DB error; [`StoreError::Corrupted`] on a
/// malformed row.
pub fn read_pending_rotations(conn: &Connection) -> Result<Vec<RotationPending>> {
    let mut stmt = conn.prepare(
        "SELECT removed_signer, observed_epoch, observed_at FROM rotation_pending
         WHERE resolved = 0 ORDER BY observed_at ASC, removed_signer ASC",
    )?;
    let rows = stmt.query_map([], |r| {
        let signer: Vec<u8> = r.get(0)?;
        let epoch: i64 = r.get(1)?;
        let at: i64 = r.get(2)?;
        Ok((signer, epoch, at))
    })?;
    let mut out = Vec::new();
    for r in rows {
        let (signer, epoch, at) = r?;
        let removed_signer: [u8; EVM_ADDRESS_LEN] = signer.as_slice().try_into().map_err(|_| {
            StoreError::Corrupted("rotation_pending.removed_signer not 20 bytes".into())
        })?;
        let observed_epoch = u64::try_from(epoch).map_err(|_| {
            StoreError::Corrupted("rotation_pending.observed_epoch out of range".into())
        })?;
        out.push(RotationPending {
            removed_signer,
            observed_epoch,
            observed_at: at,
        });
    }
    drop(stmt);
    Ok(out)
}

/// Mark a rotation-pending row resolved.
///
/// Called after the host completes `commit_vdk_rotation` for the removal.
/// Idempotent — a missing row is a no-op. The row is retained (marked
/// `resolved = 1`) rather than deleted so re-observing the SAME removal on a
/// later sync does not re-queue it.
///
/// # Errors
///
/// [`StoreError::Sqlite`] on a DB error.
pub fn mark_rotation_resolved(
    conn: &Connection,
    removed_signer: &[u8; EVM_ADDRESS_LEN],
) -> Result<()> {
    conn.execute(
        "UPDATE rotation_pending SET resolved = 1 WHERE removed_signer = ?1",
        params![removed_signer.as_slice()],
    )?;
    Ok(())
}

// ---------------------------------------------------------------------
// GAP C — remote-survivor seal consumption
// ---------------------------------------------------------------------

/// **GAP C: a remote survivor consumes its rotation seal.**
///
/// Open the `SealedVdkForDevice` minted to THIS device's X25519 pairing
/// pubkey by a rotation (`pangolin_core::rotation::rotate_vdk_for_survivors`),
/// verify the bound `vault_id ‖ device_id ‖ epoch`, and re-wrap the recovered
/// new-epoch VDK under THIS device's own [`DeviceKey`] — producing the
/// at-rest [`DeviceWrappedVdk`] (biometric fast-unlock form) for the new
/// epoch.
///
/// This is the symmetric peer of the device-add open/wrap
/// (`pangolin_core::device_add::open_vdk_for_new_device` +
/// `wrap_vdk_for_device`): the local device driving a revoke wraps the new
/// VDK inside `commit_vdk_rotation`; a REMOTE survivor that only synced the
/// SEAL re-wraps it here on its next sync. The recovered VDK is byte-
/// identical to the one the rotation minted (the seal hands it over, never
/// re-derives it — L4). The recipient `device_id` MUST be this device's
/// (GAP B); `epoch` is the new (post-rotation) epoch.
///
/// Returns both the recovered new-epoch VDK (so the caller can also drive
/// the full `commit_vdk_rotation` chain persistence with it) and the per-
/// device wrap. The VDK never crosses un-sealed; this fn carries it only
/// inside the returned [`VdkKey`], which the caller consumes + drops.
///
/// # Errors
///
/// [`StoreError::AuthenticationFailed`] if the seal open fails (wrong
/// recipient key, tampered ciphertext, or wrong `vault_id`/`device_id`/
/// `epoch`) or the re-wrap fails — collapsed to one variant
/// (indistinguishability, matching the crate's discipline).
pub fn consume_survivor_seal(
    sealed: &SealedVdkForDevice,
    local_device: &DeviceKey,
    vault_id: &[u8; VAULT_ID_LEN],
    device_id: &[u8; DEVICE_ID_LEN],
    new_epoch: u64,
) -> Result<(VdkKey, DeviceWrappedVdk)> {
    let secret = derive_pairing_secret(local_device);
    let mut epoch_bytes = [0u8; EPOCH_LEN];
    epoch_bytes[8..].copy_from_slice(&new_epoch.to_be_bytes());

    let vdk = open_vdk_from_pairing(sealed, &secret, vault_id, device_id, &epoch_bytes)
        .map_err(map_pairing_err)?;
    let ctx = WrapContext::new(*vault_id);
    let wrapped = wrap_vdk_for_device(&vdk, local_device, &ctx).map_err(map_pairing_err)?;
    Ok((vdk, wrapped))
}

/// Derive the local device's X25519 pairing SECRET scalar for opening a
/// survivor seal. Crate-private: the secret never escapes this module's
/// open path. Mirrors `consume_survivor_seal`'s recipient role.
fn derive_pairing_secret(device: &DeviceKey) -> [u8; X25519_KEY_LEN] {
    let pairing = pangolin_crypto::pairing::derive_x25519_pairing_key(device);
    *pairing.secret_bytes()
}

/// Collapse a [`PairingError`] into the store's indistinguishable
/// [`StoreError::AuthenticationFailed`] (no oracle on the cause).
fn map_pairing_err(_e: PairingError) -> StoreError {
    StoreError::AuthenticationFailed
}

// ---------------------------------------------------------------------
// GAP D — the minimal set-membership honor gate
// ---------------------------------------------------------------------

/// **GAP D / L5: the minimal set-membership honor gate.**
///
/// A revision is honored iff its signer ∈ the supplied CURRENT on-chain
/// authorized set (the #106a honor rule). Replaces the permissive
/// `auto_register_device_from_chain_sync` "trust any signer seen" posture: a
/// removed / never-added / former-manager signer is NOT honored.
///
/// `current_onchain_set` is the live `authorizedDevice` set the engine read
/// for the vault (via `pangolin_chain::read_authorized_device_v2` /
/// folding the device-management events). This is the MINIMUM the #106c E2E
/// needs; the FULL systematic generalization (lineage / retroactive
/// re-eval) is #106d.
#[must_use]
pub fn is_signer_honored(
    signer: &[u8; EVM_ADDRESS_LEN],
    current_onchain_set: &[[u8; EVM_ADDRESS_LEN]],
) -> bool {
    current_onchain_set.contains(signer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pangolin_crypto::pairing::derive_x25519_pairing_key;

    fn fresh_conn() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        crate::schema::apply_pragmas_and_schema(&conn).unwrap();
        conn
    }

    fn signer(b: u8) -> [u8; EVM_ADDRESS_LEN] {
        [b; EVM_ADDRESS_LEN]
    }

    /// GAP A: a directory entry persists, looks up, and round-trips through
    /// `read_directory`; re-upsert is idempotent.
    #[test]
    fn directory_upsert_lookup_round_trips() {
        let conn = fresh_conn();
        let dk = DeviceKey::from_seed([0x11; 32]);
        let entry = DirectoryEntry {
            signer: signer(0xA1),
            device_id: dk.verifying_key().to_bytes(),
            pairing_pub: *derive_x25519_pairing_key(&dk).public_bytes(),
        };
        upsert_directory_entry(&conn, &entry, 1_700_000_000_000).unwrap();
        let got = lookup_directory_entry(&conn, &entry.signer)
            .unwrap()
            .unwrap();
        assert_eq!(got, entry);
        // Idempotent re-upsert.
        upsert_directory_entry(&conn, &entry, 1_700_000_001_000).unwrap();
        let all = read_directory(&conn).unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0], entry);
        // Unknown signer reads None.
        assert!(lookup_directory_entry(&conn, &signer(0xFF))
            .unwrap()
            .is_none());
    }

    /// The rotation-pending row persists, resumes after a close/reopen, is
    /// idempotent on re-observe (L6), and clears on resolve.
    #[test]
    fn rotation_pending_persist_resume_resolve() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("rp.sqlite");
        let pending = RotationPending {
            removed_signer: signer(0xB2),
            observed_epoch: 3,
            observed_at: 1_700_000_000_000,
        };
        {
            let conn = Connection::open(&path).unwrap();
            crate::schema::apply_pragmas_and_schema(&conn).unwrap();
            assert!(queue_rotation_pending(&conn, &pending).unwrap());
            // Idempotent re-observe (L6).
            assert!(!queue_rotation_pending(&conn, &pending).unwrap());
        }
        // Closed app RESUMES the pending state.
        let conn = Connection::open(&path).unwrap();
        crate::schema::apply_pragmas_and_schema(&conn).unwrap();
        let outstanding = read_pending_rotations(&conn).unwrap();
        assert_eq!(outstanding.len(), 1);
        assert_eq!(outstanding[0], pending);

        // Resolve clears it from the outstanding list; re-observe stays a
        // no-op (the resolved row's PK still collides).
        mark_rotation_resolved(&conn, &pending.removed_signer).unwrap();
        assert!(read_pending_rotations(&conn).unwrap().is_empty());
        assert!(!queue_rotation_pending(&conn, &pending).unwrap());
    }

    /// GAP D / L5: the honor gate honors an in-set signer and rejects a
    /// removed / never-added one.
    #[test]
    fn honor_gate_set_membership() {
        let a = signer(0xA1);
        let b = signer(0xB2);
        let set = [a];
        assert!(is_signer_honored(&a, &set), "in-set signer honored");
        assert!(
            !is_signer_honored(&b, &set),
            "out-of-set signer rejected (L5)"
        );
        // Empty set honors nobody.
        assert!(!is_signer_honored(&a, &[]));
    }

    /// GAP C: a remote survivor opens a rotation seal minted to its pairing
    /// pubkey and re-wraps under its own device key (the recovered VDK is
    /// byte-identical; the wrap unwraps back to it).
    #[test]
    fn consume_survivor_seal_round_trips() {
        use pangolin_crypto::pairing::{seal_vdk_to_device, unwrap_vdk_for_device};

        let vault_id = [0xAA; VAULT_ID_LEN];
        let new_epoch = 5u64;
        let survivor_dk = DeviceKey::from_seed([0x5A; 32]);
        let pairing = derive_x25519_pairing_key(&survivor_dk);
        let device_id = survivor_dk.verifying_key().to_bytes();

        // A rotation seals the new VDK to the survivor's pairing pubkey.
        let new_vdk = VdkKey::generate();
        let mut epoch_bytes = [0u8; EPOCH_LEN];
        epoch_bytes[8..].copy_from_slice(&new_epoch.to_be_bytes());
        let sealed = seal_vdk_to_device(
            &new_vdk,
            pairing.public_bytes(),
            &vault_id,
            &device_id,
            &epoch_bytes,
        )
        .unwrap();

        // The remote survivor consumes it.
        let (recovered, wrapped) =
            consume_survivor_seal(&sealed, &survivor_dk, &vault_id, &device_id, new_epoch).unwrap();
        assert!(
            bool::from(new_vdk.ct_eq(&recovered)),
            "recovered new-epoch VDK must be byte-identical (L4)"
        );
        // The per-device wrap unwraps back to the same VDK.
        let unwrapped = unwrap_vdk_for_device(&wrapped, &survivor_dk).unwrap();
        assert!(bool::from(recovered.ct_eq(&unwrapped)));

        // A different device cannot consume the seal.
        let other = DeviceKey::from_seed([0x6B; 32]);
        let res = consume_survivor_seal(
            &sealed,
            &other,
            &vault_id,
            &other.verifying_key().to_bytes(),
            new_epoch,
        );
        assert!(matches!(res, Err(StoreError::AuthenticationFailed)));
    }

    /// Additive-migration: a legacy vault opening with the #106c tables
    /// absent picks them up cleanly (empty directory + no pending).
    #[test]
    fn legacy_vault_opens_with_empty_multi_device_state() {
        let conn = Connection::open_in_memory().unwrap();
        // Apply the schema (idempotent migrations create the tables).
        crate::schema::apply_pragmas_and_schema(&conn).unwrap();
        assert!(read_directory(&conn).unwrap().is_empty());
        assert!(read_pending_rotations(&conn).unwrap().is_empty());
    }
}
