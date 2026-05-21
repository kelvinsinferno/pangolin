// SPDX-License-Identifier: AGPL-3.0-or-later
//! Recovery-escrow persistence (MVP-3 issue #104b).
//!
//! Persists the local social-recovery escrow state produced by
//! `pangolin_core::recovery::orchestration`:
//!
//! - the [`WrappedVdkRecovery`] (the VDK second-wrapped under the RWK) —
//!   ciphertext + nonce + wrap context;
//! - the guardian-set parameters (`t`, `M`);
//! - the monotonic recovery `epoch` (GAP FLAG 2 — the big-endian counter
//!   baked into each sealed share's domain header);
//! - per-guardian: the guardian's X25519 public key + the locally-retained
//!   copy of their [`SealedShare`].
//!
//! ## At-rest discipline (plan §5a Q-g / L9)
//!
//! The recovery wrapper, the guardian X25519 pubkeys, `t`/`M`, and the
//! epoch are **non-secret at rest** (the wrapper is AEAD ciphertext keyed
//! by the threshold-shared RWK; the pubkeys are public) → they live as
//! plain BLOBs in the single-row `recovery_escrow` table, exactly like
//! `meta.wrapped_ct`.
//!
//! The locally-retained **sealed-share copies** are *also* non-secret (a
//! sealed share is encrypted to a guardian's X25519 key), but per Q-g they
//! are **additionally double-wrapped under the VDK column-AEAD** — the same
//! discipline `device_key` uses for the device seed. This hides the
//! guardian↔share map from an at-rest `.pvf` thief who lacks the VDK, and
//! makes the `no_plaintext_on_disk`-style assertion hold for the
//! `recovery_guardians.enc_sealed_share` column. The AEAD AAD binds the
//! `vault_id`, the `epoch`, and the `guardian_index` (anti-transplant:
//! a sealed-share row cannot be moved to a different vault / epoch / slot).

use pangolin_crypto::aead::{AeadKey, Ciphertext, Nonce, NONCE_LEN};
use pangolin_crypto::escrow::{SealedShare, WrappedVdkRecovery, EPOCH_LEN, X25519_KEY_LEN};
use pangolin_crypto::keys::{WrapContext, WrappedVdk, VAULT_ID_LEN};
use rusqlite::{params, Connection, OptionalExtension};

use crate::error::{Result, StoreError};

/// Schema-version slot for the recovery-escrow records (master plan
/// §18.7). Mirrors [`crate::device::DEVICE_IDENTITY_SCHEMA_VERSION`].
pub const RECOVERY_ESCROW_SCHEMA_VERSION: u16 = 1;

/// 8-byte AAD domain separator for double-wrapping a sealed share under
/// the VDK column-AEAD.
///
/// Distinct from the device-key domain (`pgdvk0\0\0`), the revision-payload
/// domain, and the VDK-wrap domain so a recovery sealed-share blob can
/// never be replayed as any other under-VDK row. Versioned trailing-zero
/// padding.
pub const RECOVERY_SHARE_AAD_DOMAIN: [u8; 8] = *b"pgresh0\0";

/// Length of the AAD blob bound when sealing a guardian's sealed-share
/// copy under the VDK: `domain (8) || vault_id (32) || epoch (16) ||
/// guardian_index (1)`.
const RECOVERY_SHARE_AAD_LEN: usize =
    RECOVERY_SHARE_AAD_DOMAIN.len() + VAULT_ID_LEN + EPOCH_LEN + 1;

/// A guardian's persisted recovery-escrow assignment as loaded back from
/// disk: the join index, the X25519 pubkey, and the (decrypted) sealed
/// share.
#[derive(Debug)]
pub struct StoredGuardian {
    /// The guardian's ordinal position in the set (`0..M`) — the L2 join
    /// to the on-chain merkle-committed secp256k1 address at the same
    /// index.
    pub index: u8,
    /// The guardian's 32-byte X25519 public key.
    pub guardian_x25519_pub: [u8; X25519_KEY_LEN],
    /// The guardian's sealed share (decrypted from its under-VDK double
    /// wrap).
    pub sealed_share: SealedShare,
}

/// The full recovery-escrow state as loaded back from disk.
#[derive(Debug)]
pub struct StoredRecoveryEscrow {
    /// The VDK second-wrapped under the RWK.
    pub wrapped_recovery: WrappedVdkRecovery,
    /// The reconstruction threshold (`t`) — equals the on-chain
    /// `guardianSet.threshold` (L2).
    pub threshold: u8,
    /// The guardian count (`M`) — equals the on-chain `guardianCount` (L2).
    pub guardian_count: u8,
    /// The monotonic recovery epoch (the `u64` counter).
    pub epoch: u64,
    /// Per-guardian assignments, ordered by `index` (`0..M`).
    pub guardians: Vec<StoredGuardian>,
}

/// Build the AAD blob bound when sealing / opening a guardian's
/// sealed-share copy under the VDK column-AEAD.
fn recovery_share_aad(
    vault_id: &[u8; VAULT_ID_LEN],
    epoch: u64,
    guardian_index: u8,
) -> [u8; RECOVERY_SHARE_AAD_LEN] {
    let mut out = [0u8; RECOVERY_SHARE_AAD_LEN];
    let mut cursor = 0;
    out[cursor..cursor + RECOVERY_SHARE_AAD_DOMAIN.len()]
        .copy_from_slice(&RECOVERY_SHARE_AAD_DOMAIN);
    cursor += RECOVERY_SHARE_AAD_DOMAIN.len();
    out[cursor..cursor + VAULT_ID_LEN].copy_from_slice(vault_id);
    cursor += VAULT_ID_LEN;
    // The 16-byte escrow-epoch encoding: 8 reserved zero bytes + big-endian
    // u64 (the same shape `RecoveryEpoch::to_escrow_bytes` produces).
    out[cursor + 8..cursor + EPOCH_LEN].copy_from_slice(&epoch.to_be_bytes());
    cursor += EPOCH_LEN;
    out[cursor] = guardian_index;
    out
}

/// One guardian's pieces, as the orchestration layer hands them to the
/// store.
///
/// Mirrors `pangolin_core::recovery::GuardianAssignment` but uses only the
/// store's local types (no `pangolin-core` dep — store is upstream of
/// core).
#[derive(Debug)]
pub struct GuardianRecord<'a> {
    /// The guardian's ordinal position (`0..M`).
    pub index: u8,
    /// The guardian's 32-byte X25519 public key.
    pub guardian_x25519_pub: [u8; X25519_KEY_LEN],
    /// A borrow of the guardian's sealed share.
    pub sealed_share: &'a SealedShare,
}

/// Persist (or replace) the full recovery-escrow state in one transaction.
///
/// The single-row `recovery_escrow` table holds the wrapper + `t`/`M` +
/// epoch as plain BLOBs (non-secret, L9). Each guardian's sealed-share
/// copy is double-wrapped under `vdk_aead` (Q-g) before insertion into
/// `recovery_guardians`; the AAD binds `vault_id` + `epoch` + `index`.
///
/// `INSERT OR REPLACE` semantics: writing a fresh generation (e.g. the
/// forward-security re-split) overwrites the prior single row and DELETEs
/// the prior guardian rows first, so a stale share from the old epoch can
/// never linger on disk (L6 at-rest hygiene).
///
/// # Errors
///
/// [`StoreError::Sqlite`] on a DB error; [`StoreError`] from the AEAD seal
/// (collapsed to an internal/auth error) if double-wrapping fails.
// The recovery-escrow row is a flat record (wrapper + t/M + epoch + the
// keying material); bundling it into a struct would only move the same
// fields behind one indirection without improving the call site, so the
// faithful persistence signature keeps the columns as explicit arguments.
#[allow(clippy::too_many_arguments)]
pub fn write_recovery_escrow(
    conn: &Connection,
    vault_id: &[u8; VAULT_ID_LEN],
    vdk_aead: &AeadKey,
    wrapped_recovery: &WrappedVdkRecovery,
    threshold: u8,
    guardian_count: u8,
    epoch: u64,
    guardians: &[GuardianRecord<'_>],
) -> Result<()> {
    let inner = wrapped_recovery.as_wrapped();
    let wrapped_ct = inner.ciphertext().as_bytes().to_vec();
    let wrapped_nonce = inner.nonce().as_bytes().to_vec();
    let wrap_schema_version = i64::from(inner.context().schema_version);
    let epoch_i = i64::try_from(epoch)
        .map_err(|_| StoreError::Corrupted("recovery_escrow.epoch overflows i64".into()))?;

    let tx = conn.unchecked_transaction()?;
    tx.execute(
        "INSERT OR REPLACE INTO recovery_escrow
            (id, wrapped_ct, wrapped_nonce, wrap_schema_version,
             threshold, guardian_count, epoch, schema_version)
         VALUES (0, ?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            wrapped_ct.as_slice(),
            wrapped_nonce.as_slice(),
            wrap_schema_version,
            i64::from(threshold),
            i64::from(guardian_count),
            epoch_i,
            i64::from(RECOVERY_ESCROW_SCHEMA_VERSION),
        ],
    )?;
    // Clear any prior generation's guardian rows BEFORE inserting the new
    // ones (so a shrinking M / a re-split never leaves orphan rows).
    tx.execute("DELETE FROM recovery_guardians", [])?;

    for g in guardians {
        let nonce = Nonce::random();
        let aad = recovery_share_aad(vault_id, epoch, g.index);
        let enc = vdk_aead.seal(&nonce, g.sealed_share.as_bytes(), &aad)?;
        tx.execute(
            "INSERT OR REPLACE INTO recovery_guardians
                (guardian_index, guardian_x25519_pub, enc_sealed_share, enc_nonce, schema_version)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                i64::from(g.index),
                g.guardian_x25519_pub.as_slice(),
                enc.as_bytes(),
                nonce.as_bytes().as_slice(),
                i64::from(RECOVERY_ESCROW_SCHEMA_VERSION),
            ],
        )?;
    }
    tx.commit()?;
    Ok(())
}

/// Load the recovery-escrow state, decrypting each guardian's sealed-share
/// copy from its under-VDK double wrap.
///
/// `Ok(None)` when no escrow has been onboarded yet (the single row is
/// absent — a vault that never set up guardians, or a legacy vault
/// predating #104b). A double-wrap AEAD failure (tampered blob, wrong VDK,
/// transplanted row) collapses to [`StoreError::AuthenticationFailed`] per
/// the crate's indistinguishability discipline.
///
/// # Errors
///
/// [`StoreError::Sqlite`] on a DB error; [`StoreError::Corrupted`] on a
/// malformed column; [`StoreError::AuthenticationFailed`] on a double-wrap
/// open failure; [`StoreError::UnsupportedFormatVersion`] if a stored
/// `schema_version` exceeds this build's.
pub fn read_recovery_escrow(
    conn: &Connection,
    vault_id: &[u8; VAULT_ID_LEN],
    vdk_aead: &AeadKey,
) -> Result<Option<StoredRecoveryEscrow>> {
    let Some(meta) = read_escrow_meta_row(conn)? else {
        return Ok(None);
    };
    if meta.schema_version > RECOVERY_ESCROW_SCHEMA_VERSION {
        return Err(StoreError::UnsupportedFormatVersion(
            u32::from(meta.schema_version),
            u32::from(RECOVERY_ESCROW_SCHEMA_VERSION),
        ));
    }
    let wrapped_nonce: [u8; NONCE_LEN] = meta
        .wrapped_nonce
        .as_slice()
        .try_into()
        .map_err(|_| StoreError::Corrupted("recovery_escrow.wrapped_nonce length".into()))?;
    let wrapped_recovery = WrappedVdkRecovery::from_wrapped(WrappedVdk::from_parts(
        Ciphertext::from_vec(meta.wrapped_ct),
        Nonce::from_storage_bytes(wrapped_nonce),
        WrapContext {
            vault_id: *vault_id,
            schema_version: meta.wrap_schema_version,
        },
    ));

    // Load + decrypt each guardian row, ordered by index.
    let mut stmt = conn.prepare(
        "SELECT guardian_index, guardian_x25519_pub, enc_sealed_share, enc_nonce, schema_version
         FROM recovery_guardians ORDER BY guardian_index ASC",
    )?;
    let raw_rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, Vec<u8>>(1)?,
            r.get::<_, Vec<u8>>(2)?,
            r.get::<_, Vec<u8>>(3)?,
            r.get::<_, i64>(4)?,
        ))
    })?;
    let mut guardians = Vec::new();
    for raw in raw_rows {
        guardians.push(decode_guardian_row(raw?, vault_id, meta.epoch, vdk_aead)?);
    }
    drop(stmt);

    Ok(Some(StoredRecoveryEscrow {
        wrapped_recovery,
        threshold: meta.threshold,
        guardian_count: meta.guardian_count,
        epoch: meta.epoch,
        guardians,
    }))
}

/// Validated single-row `recovery_escrow` metadata (named fields so the
/// read path is not a complex tuple).
struct EscrowMetaRow {
    wrapped_ct: Vec<u8>,
    wrapped_nonce: Vec<u8>,
    wrap_schema_version: u8,
    threshold: u8,
    guardian_count: u8,
    epoch: u64,
    schema_version: u16,
}

/// Raw single-row `recovery_escrow` tuple as read from `SQLite`:
/// `(wrapped_ct, wrapped_nonce, wrap_schema_version, threshold,
/// guardian_count, epoch, schema_version)`.
type RawEscrowMetaTuple = (Vec<u8>, Vec<u8>, i64, i64, i64, i64, i64);

/// Read + validate the single `recovery_escrow` row. `Ok(None)` if absent.
fn read_escrow_meta_row(conn: &Connection) -> Result<Option<EscrowMetaRow>> {
    let row: Option<RawEscrowMetaTuple> = conn
        .query_row(
            "SELECT wrapped_ct, wrapped_nonce, wrap_schema_version,
                    threshold, guardian_count, epoch, schema_version
             FROM recovery_escrow WHERE id = 0",
            [],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                ))
            },
        )
        .optional()
        .map_err(StoreError::from)?;
    let Some((
        wrapped_ct,
        wrapped_nonce,
        wrap_schema_i,
        threshold_i,
        guardian_count_i,
        epoch_i,
        schema_i,
    )) = row
    else {
        return Ok(None);
    };
    Ok(Some(EscrowMetaRow {
        wrapped_ct,
        wrapped_nonce,
        wrap_schema_version: u8::try_from(wrap_schema_i).map_err(|_| {
            StoreError::Corrupted("recovery_escrow.wrap_schema_version out of u8".into())
        })?,
        threshold: u8::try_from(threshold_i)
            .map_err(|_| StoreError::Corrupted("recovery_escrow.threshold out of u8".into()))?,
        guardian_count: u8::try_from(guardian_count_i).map_err(|_| {
            StoreError::Corrupted("recovery_escrow.guardian_count out of u8".into())
        })?,
        epoch: u64::try_from(epoch_i)
            .map_err(|_| StoreError::Corrupted("recovery_escrow.epoch negative".into()))?,
        schema_version: u16::try_from(schema_i).map_err(|_| {
            StoreError::Corrupted("recovery_escrow.schema_version out of u16".into())
        })?,
    }))
}

/// Raw `recovery_guardians` row tuple as read from `SQLite`.
type RawGuardianRow = (i64, Vec<u8>, Vec<u8>, Vec<u8>, i64);

/// Decode + decrypt one `recovery_guardians` row into a [`StoredGuardian`].
fn decode_guardian_row(
    raw: RawGuardianRow,
    vault_id: &[u8; VAULT_ID_LEN],
    epoch: u64,
    vdk_aead: &AeadKey,
) -> Result<StoredGuardian> {
    let (index_i, pub_blob, enc_share, enc_nonce_blob, g_schema_i) = raw;
    let g_schema = u16::try_from(g_schema_i).map_err(|_| {
        StoreError::Corrupted("recovery_guardians.schema_version out of u16".into())
    })?;
    if g_schema > RECOVERY_ESCROW_SCHEMA_VERSION {
        return Err(StoreError::UnsupportedFormatVersion(
            u32::from(g_schema),
            u32::from(RECOVERY_ESCROW_SCHEMA_VERSION),
        ));
    }
    let index = u8::try_from(index_i)
        .map_err(|_| StoreError::Corrupted("recovery_guardians.guardian_index out of u8".into()))?;
    let guardian_x25519_pub: [u8; X25519_KEY_LEN] =
        pub_blob.as_slice().try_into().map_err(|_| {
            StoreError::Corrupted("recovery_guardians.guardian_x25519_pub length".into())
        })?;
    let nonce_arr: [u8; NONCE_LEN] = enc_nonce_blob
        .as_slice()
        .try_into()
        .map_err(|_| StoreError::Corrupted("recovery_guardians.enc_nonce length".into()))?;
    let aad = recovery_share_aad(vault_id, epoch, index);
    let plaintext = vdk_aead.open(
        &Nonce::from_storage_bytes(nonce_arr),
        &Ciphertext::from_vec(enc_share),
        &aad,
    )?;
    Ok(StoredGuardian {
        index,
        guardian_x25519_pub,
        sealed_share: SealedShare::from_bytes(plaintext),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pangolin_crypto::escrow::{seal_share, split_rwk, wrap_vdk_under_rwk, RecoveryWrapKey};
    use pangolin_crypto::guardian::derive_x25519_sealing_key;
    use pangolin_crypto::keys::{DeviceKey, VdkKey, WrapContext};

    const VAULT_A: [u8; VAULT_ID_LEN] = [0xAA; VAULT_ID_LEN];

    fn fresh_conn() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        crate::schema::apply_pragmas_and_schema(&conn).unwrap();
        conn
    }

    /// Build a full onboarding fixture (wrapper + M sealed shares to
    /// derived guardian keys), returning the pieces a store write needs +
    /// the guardian secret scalars (for the open-side assertions).
    #[allow(clippy::type_complexity)]
    fn fixture(
        t: u8,
        m: u8,
        epoch: u64,
    ) -> (
        WrappedVdkRecovery,
        Vec<SealedShare>,
        Vec<[u8; X25519_KEY_LEN]>,
        Vec<[u8; X25519_KEY_LEN]>,
        VdkKey,
    ) {
        let vdk = VdkKey::generate();
        let ctx = WrapContext::new(VAULT_A);
        let rwk = RecoveryWrapKey::generate();
        let wrapped = wrap_vdk_under_rwk(&vdk, &rwk, &ctx).unwrap();
        let shares = split_rwk(&rwk, t, m).unwrap();
        // Epoch -> escrow bytes (8 reserved + big-endian u64).
        let mut epoch_bytes = [0u8; EPOCH_LEN];
        epoch_bytes[8..].copy_from_slice(&epoch.to_be_bytes());
        let mut secrets = Vec::new();
        let mut pubs = Vec::new();
        let mut sealed = Vec::new();
        for (i, share) in shares.iter().enumerate() {
            let dev = DeviceKey::from_seed([0xD0 + u8::try_from(i).unwrap(); 32]);
            let k = derive_x25519_sealing_key(&dev);
            sealed.push(seal_share(share, k.public_bytes(), &VAULT_A, &epoch_bytes).unwrap());
            pubs.push(*k.public_bytes());
            secrets.push(*k.secret_bytes());
        }
        (wrapped, sealed, pubs, secrets, vdk)
    }

    /// Round-trip: write the escrow + guardians, read it back, and confirm
    /// the wrapper, t/M/epoch, and every guardian's pubkey + sealed share
    /// survive verbatim (the sealed share opens with the guardian's key).
    #[test]
    fn write_then_read_round_trips() {
        let conn = fresh_conn();
        let vdk_aead = AeadKey::generate();
        let (wrapped, sealed, pubs, secrets, _vdk) = fixture(3, 5, 1);

        let records: Vec<GuardianRecord<'_>> = (0..5)
            .map(|i| GuardianRecord {
                index: u8::try_from(i).unwrap(),
                guardian_x25519_pub: pubs[i],
                sealed_share: &sealed[i],
            })
            .collect();
        write_recovery_escrow(&conn, &VAULT_A, &vdk_aead, &wrapped, 3, 5, 1, &records).unwrap();

        let loaded = read_recovery_escrow(&conn, &VAULT_A, &vdk_aead)
            .unwrap()
            .expect("escrow present");
        assert_eq!(loaded.threshold, 3);
        assert_eq!(loaded.guardian_count, 5);
        assert_eq!(loaded.epoch, 1);
        assert_eq!(loaded.guardians.len(), 5);

        let mut epoch_bytes = [0u8; EPOCH_LEN];
        epoch_bytes[8..].copy_from_slice(&1u64.to_be_bytes());
        for (i, g) in loaded.guardians.iter().enumerate() {
            assert_eq!(usize::from(g.index), i);
            assert_eq!(g.guardian_x25519_pub, pubs[i]);
            // The decrypted sealed share opens with the guardian's secret.
            let opened = pangolin_crypto::escrow::open_sealed_share(
                &g.sealed_share,
                &secrets[i],
                &VAULT_A,
                &epoch_bytes,
            )
            .unwrap();
            // And the bytes equal the original sealed share's plaintext.
            let opened_orig = pangolin_crypto::escrow::open_sealed_share(
                &sealed[i],
                &secrets[i],
                &VAULT_A,
                &epoch_bytes,
            )
            .unwrap();
            assert_eq!(opened.as_bytes(), opened_orig.as_bytes());
        }
    }

    /// L9: the sealed-share copies are double-wrapped under the VDK — the
    /// raw `enc_sealed_share` column bytes do NOT equal the plaintext
    /// sealed-share bytes (the AEAD layer is real, not a passthrough), and
    /// a wrong VDK fails to open.
    #[test]
    fn sealed_shares_are_double_wrapped_under_vdk() {
        let conn = fresh_conn();
        let vdk_aead = AeadKey::generate();
        let (wrapped, sealed, pubs, _secrets, _vdk) = fixture(2, 3, 0);
        let records: Vec<GuardianRecord<'_>> = (0..3)
            .map(|i| GuardianRecord {
                index: u8::try_from(i).unwrap(),
                guardian_x25519_pub: pubs[i],
                sealed_share: &sealed[i],
            })
            .collect();
        write_recovery_escrow(&conn, &VAULT_A, &vdk_aead, &wrapped, 2, 3, 0, &records).unwrap();

        // The on-disk enc_sealed_share bytes are NOT the plaintext sealed
        // share (double-wrap is real).
        let disk: Vec<u8> = conn
            .query_row(
                "SELECT enc_sealed_share FROM recovery_guardians WHERE guardian_index = 0",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_ne!(
            disk.as_slice(),
            sealed[0].as_bytes(),
            "sealed-share column must be VDK-double-wrapped, not plaintext"
        );

        // A wrong VDK cannot open the escrow.
        let wrong_vdk = AeadKey::generate();
        assert!(matches!(
            read_recovery_escrow(&conn, &VAULT_A, &wrong_vdk).unwrap_err(),
            StoreError::AuthenticationFailed
        ));
    }

    /// Anti-transplant: the sealed-share AAD binds the `vault_id`, so reading
    /// under a different `vault_id` fails (the AAD won't match).
    #[test]
    fn wrong_vault_id_fails_to_open() {
        let conn = fresh_conn();
        let vdk_aead = AeadKey::generate();
        let (wrapped, sealed, pubs, _secrets, _vdk) = fixture(2, 3, 0);
        let records: Vec<GuardianRecord<'_>> = (0..3)
            .map(|i| GuardianRecord {
                index: u8::try_from(i).unwrap(),
                guardian_x25519_pub: pubs[i],
                sealed_share: &sealed[i],
            })
            .collect();
        write_recovery_escrow(&conn, &VAULT_A, &vdk_aead, &wrapped, 2, 3, 0, &records).unwrap();

        let other_vault = [0xBBu8; VAULT_ID_LEN];
        assert!(matches!(
            read_recovery_escrow(&conn, &other_vault, &vdk_aead).unwrap_err(),
            StoreError::AuthenticationFailed
        ));
    }

    /// A fresh vault (no onboarding yet) reads `None`, not an error.
    #[test]
    fn absent_escrow_reads_none() {
        let conn = fresh_conn();
        let vdk_aead = AeadKey::generate();
        assert!(read_recovery_escrow(&conn, &VAULT_A, &vdk_aead)
            .unwrap()
            .is_none());
    }

    /// Re-split hygiene (L6): writing a new generation REPLACES the prior
    /// row + DELETEs the prior guardian rows, so a shrunk set never leaves
    /// orphans and a stale epoch's shares never linger.
    #[test]
    fn rewrite_replaces_prior_generation() {
        let conn = fresh_conn();
        let vdk_aead = AeadKey::generate();

        // First generation: 5 guardians at epoch 1.
        let (w1, s1, p1, _sec1, _v1) = fixture(3, 5, 1);
        let r1: Vec<GuardianRecord<'_>> = (0..5)
            .map(|i| GuardianRecord {
                index: u8::try_from(i).unwrap(),
                guardian_x25519_pub: p1[i],
                sealed_share: &s1[i],
            })
            .collect();
        write_recovery_escrow(&conn, &VAULT_A, &vdk_aead, &w1, 3, 5, 1, &r1).unwrap();

        // Second generation: 3 guardians at epoch 2 (re-split shrink).
        let (w2, s2, p2, sec2, _v2) = fixture(2, 3, 2);
        let r2: Vec<GuardianRecord<'_>> = (0..3)
            .map(|i| GuardianRecord {
                index: u8::try_from(i).unwrap(),
                guardian_x25519_pub: p2[i],
                sealed_share: &s2[i],
            })
            .collect();
        write_recovery_escrow(&conn, &VAULT_A, &vdk_aead, &w2, 2, 3, 2, &r2).unwrap();

        let loaded = read_recovery_escrow(&conn, &VAULT_A, &vdk_aead)
            .unwrap()
            .unwrap();
        assert_eq!(loaded.epoch, 2);
        assert_eq!(loaded.guardian_count, 3);
        // Exactly 3 guardian rows — no orphans from the 5-guardian gen.
        assert_eq!(loaded.guardians.len(), 3);
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM recovery_guardians", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 3, "prior generation's guardian rows must be gone");
        // The new shares open at epoch 2.
        let mut e2 = [0u8; EPOCH_LEN];
        e2[8..].copy_from_slice(&2u64.to_be_bytes());
        for (i, g) in loaded.guardians.iter().enumerate() {
            pangolin_crypto::escrow::open_sealed_share(&g.sealed_share, &sec2[i], &VAULT_A, &e2)
                .unwrap();
        }
    }
}
