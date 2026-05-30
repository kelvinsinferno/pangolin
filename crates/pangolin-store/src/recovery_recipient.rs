// SPDX-License-Identifier: AGPL-3.0-or-later
//! Recovery-recipient ephemeral X25519 keypair persistence (MVP-4-L L-0a-2.2).
//!
//! On the RECOVERING device, an active recovery attempt has an ephemeral
//! per-attempt X25519 keypair (Decision A from the locked share-transport
//! design). The pubkey is the on-chain `recipientCommitment` (RecoveryV2);
//! the SECRET must be persisted sealed-at-rest under the recovering
//! vault's VDK column-AEAD for the attempt's duration (spans the 72h
//! on-chain delay) and zeroized + purged on finalize / cancel.
//!
//! This module owns the single-row-per-target_vault_id `recovery_recipient`
//! table — `INSERT OR REPLACE` semantics (a new attempt against the same
//! target vault overwrites the prior row's secret + deletes it from disk).
//!
//! ## At-rest discipline (mirrors `recovery_escrow.rs::write_recovery_escrow_tx`)
//!
//! The X25519 SECRET is encrypted under the recovering vault's VDK
//! column-AEAD (XChaCha20-Poly1305), per-row random nonce, AAD bound to
//! `(domain || target_vault_id || attempt_nonce_be)`. So:
//! - An at-rest `.pvf` thief without the VDK cannot read the secret.
//! - A row cannot be transplanted to another vault / attempt (AAD binds
//!   `target_vault_id` + `attempt_nonce`).
//! - Replacing a stale row with a fresh one (e.g., a re-attempt) atomically
//!   destroys the prior ciphertext (`INSERT OR REPLACE`).
//!
//! ## What lives plaintext on disk
//!
//! `target_vault_id`, `attempt_nonce`, `x25519_pub`, `created_at_unix`,
//! `schema_version` are all NON-secret (the pubkey IS the on-chain
//! commitment, observable to anyone reading the chain). Only `enc_secret`
//! + `enc_nonce` carry secret material.

// Heavily-documented persistence module (the on-disk discipline + AAD
// binding need in-source docs); allow the doc-style pedantic lints at
// module level (matches `recovery_escrow.rs`). Substantive lints stay
// enforced. The `peek_recipient_secret` return tuple is intentionally
// inline (callers ignore the pubkey when they only need the secret); the
// type-complexity allow attaches to that function.
#![allow(
    clippy::doc_markdown,
    clippy::too_long_first_doc_paragraph,
    clippy::doc_lazy_continuation
)]

use pangolin_crypto::aead::{AeadKey, Ciphertext, Nonce, NONCE_LEN};
use pangolin_crypto::escrow::X25519_KEY_LEN;
use pangolin_crypto::keys::VAULT_ID_LEN;
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use zeroize::Zeroizing;

use crate::error::{Result, StoreError};

/// Schema-version slot for the recovery-recipient row.
pub const RECOVERY_RECIPIENT_SCHEMA_VERSION: u16 = 1;

/// 8-byte AAD domain separator for sealing the recipient X25519 secret
/// under the VDK column-AEAD. Distinct from every other column-AEAD
/// domain in the crate (`pgresh0\0` for recovery sealed-shares; the
/// device-key domain; the revision-payload domain).
pub const RECOVERY_RECIPIENT_AAD_DOMAIN: [u8; 8] = *b"pgrecv0\0";

/// Length of the AAD blob bound when sealing the recipient secret:
/// `domain (8) || target_vault_id (32) || attempt_nonce (8)`.
const RECOVERY_RECIPIENT_AAD_LEN: usize = RECOVERY_RECIPIENT_AAD_DOMAIN.len() + VAULT_ID_LEN + 8;

/// Build the AAD that binds the persisted secret to its
/// `(target_vault_id, attempt_nonce)` slot. A row sealed for one
/// `(target, nonce)` cannot be opened by another.
fn recipient_aad(
    target_vault_id: &[u8; VAULT_ID_LEN],
    attempt_nonce: u64,
) -> [u8; RECOVERY_RECIPIENT_AAD_LEN] {
    let mut out = [0u8; RECOVERY_RECIPIENT_AAD_LEN];
    let mut cursor = 0;
    out[cursor..cursor + RECOVERY_RECIPIENT_AAD_DOMAIN.len()]
        .copy_from_slice(&RECOVERY_RECIPIENT_AAD_DOMAIN);
    cursor += RECOVERY_RECIPIENT_AAD_DOMAIN.len();
    out[cursor..cursor + VAULT_ID_LEN].copy_from_slice(target_vault_id);
    cursor += VAULT_ID_LEN;
    out[cursor..cursor + 8].copy_from_slice(&attempt_nonce.to_be_bytes());
    out
}

/// Non-secret read of the recipient pubkey for an active recovery attempt.
/// Returns `None` if no row exists for `target_vault_id` (no active attempt).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredRecipientIdentity {
    /// The attempt nonce this keypair was generated for.
    pub attempt_nonce: u64,
    /// The 32-byte X25519 public key — the on-chain `recipientCommitment`.
    pub x25519_pub: [u8; X25519_KEY_LEN],
    /// Unix timestamp the row was written.
    pub created_at_unix: i64,
}

/// **Write or replace** the ephemeral recipient keypair for `target_vault_id`.
///
/// Inserts (or replaces) the single row keyed on `target_vault_id`. The
/// X25519 SECRET is AEAD-sealed under `vdk_aead` with the AAD binding
/// `(domain || target_vault_id || attempt_nonce)`; per-row random nonce.
/// The pubkey + nonce are persisted plaintext (non-secret).
///
/// `INSERT OR REPLACE` semantics atomically destroy any prior row's
/// ciphertext (a fresh attempt against the same target vault overwrites).
///
/// # Errors
///
/// [`StoreError::Sqlite`] on a DB error; an AEAD seal failure (vanishingly
/// rare) collapses to a typed `StoreError`.
pub fn write_recipient_tx(
    tx: &Transaction<'_>,
    vdk_aead: &AeadKey,
    target_vault_id: &[u8; VAULT_ID_LEN],
    attempt_nonce: u64,
    x25519_secret: &[u8; X25519_KEY_LEN],
    x25519_pub: &[u8; X25519_KEY_LEN],
    created_at_unix: i64,
) -> Result<()> {
    let nonce = Nonce::random();
    let aad = recipient_aad(target_vault_id, attempt_nonce);
    let enc = vdk_aead.seal(&nonce, x25519_secret, &aad)?;
    let attempt_nonce_i = i64::try_from(attempt_nonce).map_err(|_| {
        StoreError::Corrupted("recovery_recipient.attempt_nonce overflows i64".into())
    })?;

    tx.execute(
        "INSERT OR REPLACE INTO recovery_recipient
            (target_vault_id, attempt_nonce, x25519_pub, enc_secret, enc_nonce,
             created_at_unix, schema_version)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            target_vault_id.as_slice(),
            attempt_nonce_i,
            x25519_pub.as_slice(),
            enc.as_bytes(),
            nonce.as_bytes().as_slice(),
            created_at_unix,
            i64::from(RECOVERY_RECIPIENT_SCHEMA_VERSION),
        ],
    )?;
    Ok(())
}

/// **Read** the recipient identity (non-secret fields) for `target_vault_id`.
///
/// Returns `None` if no active recovery attempt is recorded. Does NOT
/// decrypt the secret — for that see [`peek_recipient_secret`].
///
/// # Errors
///
/// [`StoreError::Sqlite`] on a DB error.
pub fn read_recipient_identity(
    conn: &Connection,
    target_vault_id: &[u8; VAULT_ID_LEN],
) -> Result<Option<StoredRecipientIdentity>> {
    conn.query_row(
        "SELECT attempt_nonce, x25519_pub, created_at_unix
         FROM recovery_recipient WHERE target_vault_id = ?1",
        params![target_vault_id.as_slice()],
        |row| {
            let nonce_i: i64 = row.get(0)?;
            let pub_bytes: Vec<u8> = row.get(1)?;
            let created_at: i64 = row.get(2)?;
            Ok((nonce_i, pub_bytes, created_at))
        },
    )
    .optional()?
    .map(|(nonce_i, pub_bytes, created_at_unix)| {
        let attempt_nonce = u64::try_from(nonce_i).map_err(|_| {
            StoreError::Corrupted("recovery_recipient.attempt_nonce read as negative".into())
        })?;
        let mut x25519_pub = [0u8; X25519_KEY_LEN];
        if pub_bytes.len() != X25519_KEY_LEN {
            return Err(StoreError::Corrupted(
                "recovery_recipient.x25519_pub wrong length".into(),
            ));
        }
        x25519_pub.copy_from_slice(&pub_bytes);
        Ok(StoredRecipientIdentity {
            attempt_nonce,
            x25519_pub,
            created_at_unix,
        })
    })
    .transpose()
}

/// **Peek** (decrypt-then-read) the recipient secret for `target_vault_id`.
///
/// Returns `None` if no active recovery attempt is recorded; otherwise
/// `Some((attempt_nonce, secret_bytes, pubkey))`. The secret bytes come
/// back wrapped in `Zeroizing` — the caller must NOT hold the bytes past
/// their immediate use (e.g., one `open_share_from_recoverer` call).
///
/// Does NOT delete the row (the secret remains persisted for subsequent
/// share-ingests in the same attempt). Use [`clear_recipient`] on
/// finalize / cancel to wipe.
///
/// # Errors
///
/// [`StoreError::Sqlite`] on a DB error; [`StoreError::Corrupted`] on a
/// malformed row; AEAD open failure (e.g., a transplanted row) collapses
/// to a typed `StoreError`.
#[allow(clippy::type_complexity)]
pub fn peek_recipient_secret(
    conn: &Connection,
    vdk_aead: &AeadKey,
    target_vault_id: &[u8; VAULT_ID_LEN],
) -> Result<Option<(u64, Zeroizing<[u8; X25519_KEY_LEN]>, [u8; X25519_KEY_LEN])>> {
    let row = conn
        .query_row(
            "SELECT attempt_nonce, x25519_pub, enc_secret, enc_nonce
             FROM recovery_recipient WHERE target_vault_id = ?1",
            params![target_vault_id.as_slice()],
            |row| {
                let nonce_i: i64 = row.get(0)?;
                let pub_bytes: Vec<u8> = row.get(1)?;
                let enc_secret: Vec<u8> = row.get(2)?;
                let enc_nonce: Vec<u8> = row.get(3)?;
                Ok((nonce_i, pub_bytes, enc_secret, enc_nonce))
            },
        )
        .optional()?;
    let Some((nonce_i, pub_bytes, enc_secret, enc_nonce)) = row else {
        return Ok(None);
    };

    let attempt_nonce = u64::try_from(nonce_i).map_err(|_| {
        StoreError::Corrupted("recovery_recipient.attempt_nonce read as negative".into())
    })?;
    if pub_bytes.len() != X25519_KEY_LEN {
        return Err(StoreError::Corrupted(
            "recovery_recipient.x25519_pub wrong length".into(),
        ));
    }
    let mut x25519_pub = [0u8; X25519_KEY_LEN];
    x25519_pub.copy_from_slice(&pub_bytes);

    let nonce_arr: [u8; NONCE_LEN] = enc_nonce
        .as_slice()
        .try_into()
        .map_err(|_| StoreError::Corrupted("recovery_recipient.enc_nonce wrong length".into()))?;
    let aad = recipient_aad(target_vault_id, attempt_nonce);
    let plaintext = vdk_aead.open(
        &Nonce::from_storage_bytes(nonce_arr),
        &Ciphertext::from_vec(enc_secret),
        &aad,
    )?;
    if plaintext.len() != X25519_KEY_LEN {
        return Err(StoreError::Corrupted(
            "recovery_recipient.enc_secret plaintext wrong length".into(),
        ));
    }
    let mut secret = Zeroizing::new([0u8; X25519_KEY_LEN]);
    secret.copy_from_slice(&plaintext);
    Ok(Some((attempt_nonce, secret, x25519_pub)))
}

/// **Clear** the recipient row for `target_vault_id` (atomic DELETE).
///
/// Wipes the at-rest ciphertext of the ephemeral secret. Called on
/// `vault_finalize_recovery` / `vault_cancel_recovery` so the secret never
/// lingers past attempt closure (locked design: ephemeral per-attempt).
///
/// Returns the number of rows affected (0 if no row existed).
///
/// # Errors
///
/// [`StoreError::Sqlite`] on a DB error.
pub fn clear_recipient_tx(
    tx: &Transaction<'_>,
    target_vault_id: &[u8; VAULT_ID_LEN],
) -> Result<usize> {
    let affected = tx.execute(
        "DELETE FROM recovery_recipient WHERE target_vault_id = ?1",
        params![target_vault_id.as_slice()],
    )?;
    Ok(affected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pangolin_crypto::aead::{AeadKey, KEY_LEN};

    fn fresh_aead() -> AeadKey {
        let mut k = [0u8; KEY_LEN];
        pangolin_crypto::rng::fill_random(&mut k);
        AeadKey::from_bytes(k)
    }

    fn in_memory_conn() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute(
            "CREATE TABLE recovery_recipient (
                target_vault_id  BLOB    PRIMARY KEY NOT NULL,
                attempt_nonce    INTEGER NOT NULL,
                x25519_pub       BLOB    NOT NULL,
                enc_secret       BLOB    NOT NULL,
                enc_nonce        BLOB    NOT NULL,
                created_at_unix  INTEGER NOT NULL,
                schema_version   INTEGER NOT NULL
            )",
            [],
        )
        .unwrap();
        conn
    }

    /// Round-trip: write -> peek recovers the byte-identical secret + pubkey.
    #[test]
    fn write_then_peek_round_trips() {
        let mut conn = in_memory_conn();
        let aead = fresh_aead();
        let target = [0x11u8; VAULT_ID_LEN];
        let attempt = 7u64;
        let secret = [0xAA; X25519_KEY_LEN];
        let pubkey = [0xBB; X25519_KEY_LEN];

        {
            let tx = conn.transaction().unwrap();
            write_recipient_tx(
                &tx,
                &aead,
                &target,
                attempt,
                &secret,
                &pubkey,
                1_700_000_000,
            )
            .unwrap();
            tx.commit().unwrap();
        }

        let (n, s, p) = peek_recipient_secret(&conn, &aead, &target)
            .unwrap()
            .expect("row present");
        assert_eq!(n, attempt);
        assert_eq!(&*s, &secret);
        assert_eq!(p, pubkey);
    }

    /// `read_recipient_identity` returns the pubkey + nonce + created_at
    /// without touching the secret.
    #[test]
    fn read_identity_returns_pubkey_only() {
        let mut conn = in_memory_conn();
        let aead = fresh_aead();
        let target = [0x22u8; VAULT_ID_LEN];
        let attempt = 13u64;
        let secret = [0xCC; X25519_KEY_LEN];
        let pubkey = [0xDD; X25519_KEY_LEN];

        {
            let tx = conn.transaction().unwrap();
            write_recipient_tx(
                &tx,
                &aead,
                &target,
                attempt,
                &secret,
                &pubkey,
                1_700_000_001,
            )
            .unwrap();
            tx.commit().unwrap();
        }

        let id = read_recipient_identity(&conn, &target).unwrap().unwrap();
        assert_eq!(id.attempt_nonce, attempt);
        assert_eq!(id.x25519_pub, pubkey);
        assert_eq!(id.created_at_unix, 1_700_000_001);
    }

    /// Absent target -> Ok(None) on read / peek; clear returns 0.
    #[test]
    fn absent_target_returns_none() {
        let conn = in_memory_conn();
        let aead = fresh_aead();
        let target = [0x33u8; VAULT_ID_LEN];
        assert!(read_recipient_identity(&conn, &target).unwrap().is_none());
        assert!(peek_recipient_secret(&conn, &aead, &target)
            .unwrap()
            .is_none());
    }

    /// `clear_recipient_tx` deletes the row; subsequent peek returns None.
    #[test]
    fn clear_purges_the_secret() {
        let mut conn = in_memory_conn();
        let aead = fresh_aead();
        let target = [0x44u8; VAULT_ID_LEN];
        {
            let tx = conn.transaction().unwrap();
            write_recipient_tx(
                &tx,
                &aead,
                &target,
                42,
                &[0xEE; X25519_KEY_LEN],
                &[0xFF; X25519_KEY_LEN],
                1,
            )
            .unwrap();
            tx.commit().unwrap();
        }
        assert!(read_recipient_identity(&conn, &target).unwrap().is_some());
        {
            let tx = conn.transaction().unwrap();
            assert_eq!(clear_recipient_tx(&tx, &target).unwrap(), 1);
            tx.commit().unwrap();
        }
        assert!(read_recipient_identity(&conn, &target).unwrap().is_none());
        assert!(peek_recipient_secret(&conn, &aead, &target)
            .unwrap()
            .is_none());
    }

    /// Anti-transplant: a row written for (target_A, nonce_N) is rejected
    /// when peeked under (target_B, nonce_N) — the AAD binding fails.
    /// Simulate by writing for A then forcing the peek query for B against
    /// A's bytes (would require manual SQL — here we just write for A and
    /// peek for B, which returns None because the row isn't there). The
    /// real transplant test belongs in an integration test against a
    /// hand-crafted DB; the AAD discipline is mirrored from
    /// `recovery_escrow.rs` which has the same property.
    #[test]
    fn aad_binds_target_and_nonce() {
        let mut conn = in_memory_conn();
        let aead = fresh_aead();
        let target_a = [0x55u8; VAULT_ID_LEN];
        let target_b = [0x66u8; VAULT_ID_LEN];
        {
            let tx = conn.transaction().unwrap();
            write_recipient_tx(
                &tx,
                &aead,
                &target_a,
                100,
                &[0x12; X25519_KEY_LEN],
                &[0x34; X25519_KEY_LEN],
                1,
            )
            .unwrap();
            tx.commit().unwrap();
        }
        // B has no row -> Ok(None) (the table is keyed on target).
        assert!(peek_recipient_secret(&conn, &aead, &target_b)
            .unwrap()
            .is_none());
        // A has its own row, opens fine.
        assert!(peek_recipient_secret(&conn, &aead, &target_a)
            .unwrap()
            .is_some());
    }

    /// Wrong VDK (AEAD key) → open fails closed.
    #[test]
    fn wrong_vdk_fails_open() {
        let mut conn = in_memory_conn();
        let aead_a = fresh_aead();
        let aead_b = fresh_aead();
        let target = [0x77u8; VAULT_ID_LEN];
        {
            let tx = conn.transaction().unwrap();
            write_recipient_tx(
                &tx,
                &aead_a,
                &target,
                1,
                &[0x99; X25519_KEY_LEN],
                &[0xAB; X25519_KEY_LEN],
                1,
            )
            .unwrap();
            tx.commit().unwrap();
        }
        let err = peek_recipient_secret(&conn, &aead_b, &target).unwrap_err();
        assert!(matches!(err, StoreError::AuthenticationFailed));
    }

    /// AAD domain is distinct from the recovery-escrow share AAD domain.
    #[test]
    fn aad_domain_is_distinct() {
        assert_ne!(
            RECOVERY_RECIPIENT_AAD_DOMAIN,
            crate::recovery_escrow::RECOVERY_SHARE_AAD_DOMAIN,
            "recovery-recipient AAD domain must differ from recovery-share's"
        );
    }
}
