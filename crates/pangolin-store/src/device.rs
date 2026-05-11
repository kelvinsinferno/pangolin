// SPDX-License-Identifier: AGPL-3.0-or-later
//! Device identity + local trust list (MVP-1 issue 1.5).
//!
//! Every `.pvf` knows which device it runs on. On the first successful
//! unlock on a new vault file the vault registers a device: it generates
//! a fresh Ed25519 [`pangolin_crypto::keys::DeviceKey`], derives a stable
//! [`DeviceId`] from that key's verifying-key bytes, inserts a `devices`
//! row, and stores the device key's *secret* seed AEAD-sealed under the
//! VDK in the single-row `device_key` table. Subsequent unlocks re-load
//! that device — they do **not** register a second one.
//!
//! The trust list is the set of `devices` rows. In MVP-1 (zero chain
//! code) it is **add-only** — there is no revoke/remove path; the
//! `revoked_at` column the P2 stub already carries is the MVP-2/3 hook.
//! It gates nothing destructive: it is the local record + the hook the
//! MVP-2 on-chain authority registry will canonicalise. `originating_device`
//! on every post-1.5 revision is the open handle's real `device_id`;
//! pre-1.5 revisions keep their throwaway-random value (accepted as-is).
//!
//! The `DeviceKey` does **not** sign anything in MVP-1. It is generated
//! and stored as the hook for MVP-2's signed-revision format / gas-payer
//! role; the serialisation of the device-key seed (seed → BLOB → seed)
//! lives entirely here in `pangolin-store` — `pangolin-crypto` gains no
//! serde path (HIGH-1).

use pangolin_crypto::aead::{AeadKey, Ciphertext, Nonce, NONCE_LEN};
use pangolin_crypto::keys::DeviceKey;
use pangolin_crypto::secret::SecretBytes;
use pangolin_crypto::sign::{VerifyingKey, SECRET_KEY_LEN};
use rusqlite::{params, Connection, OptionalExtension};

use crate::error::{Result, StoreError};
use crate::revision::{DeviceId, DEVICE_ID_LEN};

/// Schema-version slot for the device-identity records / on-disk
/// `device_key` blob.
///
/// Master plan §18.7 — the policy text is locked by issue 1.6. Mirrors
/// [`crate::account::ACCOUNT_IDENTITY_SCHEMA_VERSION`].
pub const DEVICE_IDENTITY_SCHEMA_VERSION: u16 = 1;

/// Maximum length of a device label in characters (post-NFC, post-trim).
///
/// Matches [`crate::account::limits::DISPLAY_NAME_MAX_CHARS`].
pub const DEVICE_LABEL_MAX_CHARS: usize = 256;

/// 8-byte AAD domain separator for sealing the device-key seed under the
/// VDK.
///
/// Distinct from the revision-payload domain (`pgrev0\0\0`) and the
/// VDK-wrap domain so a device-key blob cannot be replayed as a revision
/// blob or a wrapped-VDK blob. Versioned trailing-zero padding.
pub const DEVICE_KEY_AAD_DOMAIN: [u8; 8] = *b"pgdvk0\0\0";

/// Length of the AAD blob bound when sealing the device-key seed:
/// `DEVICE_KEY_AAD_DOMAIN (8) || vault_id (32) || device_id (32)`.
const DEVICE_KEY_AAD_LEN: usize = DEVICE_KEY_AAD_DOMAIN.len() + 32 + DEVICE_ID_LEN;

/// Raw `device_key` row tuple: `(enc_seed, enc_nonce, schema_version)`.
type DeviceKeyRow = (Vec<u8>, Vec<u8>, i64);

/// Device capability flags.
///
/// MVP-1 has one device class — `Full`. Stored as an `INTEGER`
/// (`0 = Full`) so MVP-2/3 can add variants (read-only seats,
/// browser-extension-as-a-limited-device, …) without a schema change.
/// An unknown stored value coerces to `Full` — the same forward-compat-
/// tolerant doctrine as [`crate::session::SessionDuration::from_meta_secs`]
/// (a corrupt-but-readable column does not brick an otherwise-openable
/// vault).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(i64)]
pub enum DeviceCapabilities {
    /// The MVP-1 device class — full read/write/publish.
    #[default]
    Full = 0,
}

impl DeviceCapabilities {
    /// The stored integer for this capability set.
    #[must_use]
    pub fn to_repr(self) -> i64 {
        self as i64
    }

    /// Decode a stored integer. `0` is `Full`; any other value coerces
    /// to `Full` too (forward-compat: an MVP-1 build opening an MVP-2/3
    /// vault that stamped a richer capability sees the device as `Full`,
    /// the safe-and-permissive default for the single-device CLI).
    #[must_use]
    pub fn from_repr(_value: i64) -> Self {
        // Only one variant exists in MVP-1; MVP-2/3 add `match` arms
        // here and a real fallback. For now every stored value maps to
        // `Full` (deliberate forward-compat coercion).
        Self::Full
    }
}

/// In-memory view of a `devices` row.
///
/// All fields are non-secret — the device id, the user-set label, the
/// timestamps, the capability flags, the *public* verifying key. The
/// secret is the seed in the `device_key` table, which has its own
/// redacting wrapper via [`DeviceKey`]'s `Debug`.
#[derive(Debug, Clone)]
pub struct DeviceIdentity {
    /// Stable device id — the 32-byte Ed25519 verifying-key bytes of
    /// this device's [`DeviceKey`].
    pub device_id: DeviceId,
    /// Human-readable label (user-set). Non-empty after trim,
    /// ≤ [`DEVICE_LABEL_MAX_CHARS`] chars, NFC-normalised.
    pub label: String,
    /// Wall-clock unix-ms timestamp the device first registered. (The
    /// SQL column is named `added_at`; the view renames it `registered_at`.)
    pub registered_at: i64,
    /// **Dormant in MVP-1** — always `None`. MVP-2's chain-sync code
    /// populates it (the last time this device published-or-pulled
    /// through the contract). Same doctrine as the `chain_anchor_*`
    /// columns on revisions: the schema carries the shape; the field is
    /// dormant until the feature that fills it lands.
    pub last_sync_at: Option<i64>,
    /// Capability flags. `Full` in MVP-1.
    pub capabilities: DeviceCapabilities,
    /// The device's Ed25519 verifying key bytes (non-secret) — stored so
    /// MVP-2 can signature-verify this device's revisions without
    /// re-deriving. `None` only for legacy P2 rows (which 1.5 never
    /// creates) — every 1.5-registered device row writes it.
    pub public_key: Option<VerifyingKey>,
    /// `true` iff this row matches the open handle's `device_id` (filled
    /// by the read path).
    pub is_current: bool,
}

/// Build the AAD blob bound when sealing / opening the device-key seed.
fn device_key_aad(vault_id: &[u8; 32], device_id: &DeviceId) -> [u8; DEVICE_KEY_AAD_LEN] {
    let mut out = [0u8; DEVICE_KEY_AAD_LEN];
    let mut cursor = 0;
    out[cursor..cursor + DEVICE_KEY_AAD_DOMAIN.len()].copy_from_slice(&DEVICE_KEY_AAD_DOMAIN);
    cursor += DEVICE_KEY_AAD_DOMAIN.len();
    out[cursor..cursor + 32].copy_from_slice(vault_id);
    cursor += 32;
    out[cursor..cursor + DEVICE_ID_LEN].copy_from_slice(&device_id.0);
    out
}

/// Validate + canonicalise a device label.
///
/// Same discipline as [`crate::account::validate::display_name`]:
/// NFC-normalise first, then trim, then the non-empty / length /
/// control-char checks against the post-NFC string. Errors surface as
/// [`StoreError::Validation`] with `kind = "device_label"`.
pub fn validate_label(input: &str) -> Result<String> {
    use unicode_normalization::UnicodeNormalization;
    let normalised: String = input.nfc().collect();
    let trimmed = normalised.trim();
    if trimmed.is_empty() {
        return Err(StoreError::Validation {
            kind: "device_label".into(),
            message: "device label must not be empty".into(),
        });
    }
    if trimmed.chars().count() > DEVICE_LABEL_MAX_CHARS {
        return Err(StoreError::Validation {
            kind: "device_label".into(),
            message: format!("device label exceeds {DEVICE_LABEL_MAX_CHARS} chars"),
        });
    }
    if trimmed
        .chars()
        .any(|c| c.is_control() && c != '\t' && c != '\n' && c != '\r')
    {
        return Err(StoreError::Validation {
            kind: "device_label".into(),
            message: "device label contains disallowed control chars".into(),
        });
    }
    Ok(trimmed.to_owned())
}

/// Derive the stable [`DeviceId`] from a device key's verifying key.
///
/// The id is the 32-byte canonical Ed25519 public encoding — exactly
/// what [`crate::revision::DeviceId`]'s doc-comment promised it would
/// become ("the verifying-key bytes of the device's signing keypair").
#[must_use]
pub fn device_id_from_key(key: &DeviceKey) -> DeviceId {
    DeviceId(key.verifying_key().to_bytes())
}

/// Read the single-row `device_key` table. `Ok(None)` when the row is
/// absent (no device registered yet on this vault file).
fn read_device_key_row(conn: &Connection) -> Result<Option<DeviceKeyRow>> {
    conn.query_row(
        "SELECT enc_seed, enc_nonce, schema_version FROM device_key WHERE id = 0",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )
    .optional()
    .map_err(StoreError::from)
}

/// Read the `device_id` of this vault file's registered device.
///
/// That is the (single, in MVP-1) `devices`-table row. `Ok(None)` when
/// no device has been registered yet — a brand-new vault never
/// unlocked, or an older-build vault whose `devices` stub is empty.
/// MVP-1's register-on-unlock writes the `devices` row and the
/// `device_key` row in one transaction, so the presence of either
/// implies the other.
pub fn read_registered_device_id(conn: &Connection) -> Result<Option<DeviceId>> {
    let blob: Option<Vec<u8>> = conn
        .query_row(
            "SELECT device_id FROM devices ORDER BY added_at ASC, device_id ASC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(StoreError::from)?;
    match blob {
        None => Ok(None),
        Some(bytes) => {
            let arr: [u8; DEVICE_ID_LEN] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| StoreError::Corrupted("devices.device_id not 32 bytes".into()))?;
            Ok(Some(DeviceId(arr)))
        }
    }
}

/// Load the device key from a previously-registered vault file.
///
/// Decrypts the AEAD-sealed seed under the VDK and reconstructs the
/// [`DeviceKey`]. `Ok(None)` when the `device_key` row is absent (no
/// device registered yet). `device_id` is the value already read from
/// the `devices` table — the AEAD AAD binds it (anti-transplant), so it
/// must be rebuilt before the open. AEAD failure (tampered blob, wrong
/// VDK, transplanted from another vault) collapses to
/// [`StoreError::AuthenticationFailed`] per the crate's
/// indistinguishability discipline.
pub fn load_device_key_with_id(
    conn: &Connection,
    vault_id: &[u8; 32],
    vdk_aead: &AeadKey,
    device_id: &DeviceId,
) -> Result<Option<DeviceKey>> {
    let Some((enc_seed, enc_nonce, schema_version_i)) = read_device_key_row(conn)? else {
        return Ok(None);
    };
    let schema_version = u16::try_from(schema_version_i)
        .map_err(|_| StoreError::Corrupted("device_key.schema_version out of u16 range".into()))?;
    if schema_version > DEVICE_IDENTITY_SCHEMA_VERSION {
        return Err(StoreError::UnsupportedFormatVersion(
            u32::from(schema_version),
            u32::from(DEVICE_IDENTITY_SCHEMA_VERSION),
        ));
    }
    let nonce_arr: [u8; NONCE_LEN] = enc_nonce
        .as_slice()
        .try_into()
        .map_err(|_| StoreError::Corrupted("device_key.enc_nonce length mismatch".into()))?;
    let nonce = Nonce::from_storage_bytes(nonce_arr);
    let ct = Ciphertext::from_vec(enc_seed);
    let aad = device_key_aad(vault_id, device_id);
    let plaintext = vdk_aead.open(&nonce, &ct, &aad)?;
    if plaintext.len() != SECRET_KEY_LEN {
        // The seed must be exactly 32 bytes — anything else means the
        // blob was forged with a different schema. Treat as tamper and
        // don't reveal the length.
        let _wiped = SecretBytes::new(plaintext);
        return Err(StoreError::AuthenticationFailed);
    }
    let mut seed = [0u8; SECRET_KEY_LEN];
    seed.copy_from_slice(&plaintext);
    let _wiped = SecretBytes::new(plaintext);
    let key = DeviceKey::from_seed(seed);
    // Defense in depth: the recovered key's verifying key must match the
    // device_id the AAD bound (it does, since the AEAD authenticated the
    // AAD — but the explicit check guards a future refactor that loosens
    // the AAD).
    if device_id_from_key(&key) != *device_id {
        return Err(StoreError::AuthenticationFailed);
    }
    Ok(Some(key))
}

/// Register a brand-new device on the first unlock of a vault file.
///
/// Seals the device key's secret seed under the VDK and inserts the
/// `device_key` row + the `devices` row, all in one transaction.
/// `now_ms` is the registration timestamp; `label` must already be
/// validated (see [`validate_label`]).
pub fn register_device(
    conn: &Connection,
    vault_id: &[u8; 32],
    vdk_aead: &AeadKey,
    key: &DeviceKey,
    label: &str,
    now_ms: i64,
) -> Result<DeviceId> {
    let device_id = device_id_from_key(key);
    let seed = key.secret_seed_bytes();
    let nonce = Nonce::random();
    let aad = device_key_aad(vault_id, &device_id);
    let ct = vdk_aead.seal(&nonce, &*seed, &aad)?;
    let public_key = key.verifying_key().to_bytes();

    let tx = conn.unchecked_transaction()?;
    tx.execute(
        "INSERT OR REPLACE INTO device_key (id, enc_seed, enc_nonce, schema_version)
         VALUES (0, ?1, ?2, ?3)",
        params![
            ct.as_bytes(),
            nonce.as_bytes().as_slice(),
            i64::from(DEVICE_IDENTITY_SCHEMA_VERSION),
        ],
    )?;
    tx.execute(
        "INSERT OR REPLACE INTO devices
            (device_id, label, added_at, revoked_at, capabilities, last_sync_at, public_key,
             schema_version)
         VALUES (?1, ?2, ?3, NULL, ?4, NULL, ?5, ?6)",
        params![
            device_id.0.as_slice(),
            label,
            now_ms,
            DeviceCapabilities::Full.to_repr(),
            public_key.as_slice(),
            i64::from(DEVICE_IDENTITY_SCHEMA_VERSION),
        ],
    )?;
    tx.commit()?;
    Ok(device_id)
}

/// Raw `devices` row, as read out of `SQLite`. Validated into a
/// [`DeviceIdentity`] by [`DeviceRow::into_identity`].
struct DeviceRow {
    device_id_blob: Vec<u8>,
    label: String,
    added_at: i64,
    capabilities_i: i64,
    last_sync_at: Option<i64>,
    public_key_blob: Option<Vec<u8>>,
}

/// SELECT column list for the `devices` rows. Order matches
/// [`DeviceRow::from_sqlite_row`].
const DEVICES_SELECT_COLS: &str =
    "device_id, label, added_at, capabilities, last_sync_at, public_key";

impl DeviceRow {
    fn from_sqlite_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            device_id_blob: row.get(0)?,
            label: row.get(1)?,
            added_at: row.get(2)?,
            capabilities_i: row.get(3)?,
            last_sync_at: row.get(4)?,
            public_key_blob: row.get(5)?,
        })
    }

    fn into_identity(self, current: &DeviceId) -> Result<DeviceIdentity> {
        let device_arr: [u8; DEVICE_ID_LEN] = self
            .device_id_blob
            .as_slice()
            .try_into()
            .map_err(|_| StoreError::Corrupted("devices.device_id not 32 bytes".into()))?;
        let device_id = DeviceId(device_arr);
        let public_key = match self.public_key_blob {
            None => None,
            Some(bytes) => {
                let arr: [u8; 32] = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| StoreError::Corrupted("devices.public_key not 32 bytes".into()))?;
                // A non-canonical / off-curve public key on disk is
                // storage corruption — but it is non-secret metadata,
                // not load-bearing in MVP-1, so keep it `None` rather
                // than brick the vault.
                VerifyingKey::from_bytes(arr).ok()
            }
        };
        Ok(DeviceIdentity {
            device_id,
            label: self.label,
            registered_at: self.added_at,
            last_sync_at: self.last_sync_at,
            capabilities: DeviceCapabilities::from_repr(self.capabilities_i),
            public_key,
            is_current: device_id == *current,
        })
    }
}

/// Read every row in the `devices` table (the trust list).
///
/// `is_current` is set on the row matching `current_device_id`. In
/// MVP-1 every row has `revoked_at IS NULL` (add-only), so no filter is
/// needed; ordered by `added_at` for stable output.
pub fn list_devices(
    conn: &Connection,
    current_device_id: &DeviceId,
) -> Result<Vec<DeviceIdentity>> {
    let sql =
        format!("SELECT {DEVICES_SELECT_COLS} FROM devices ORDER BY added_at ASC, device_id ASC");
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map([], DeviceRow::from_sqlite_row)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?.into_identity(current_device_id)?);
    }
    drop(stmt);
    Ok(out)
}

/// Read the `devices` row for `device_id`.
///
/// `Ok(None)` when there is no matching row (e.g. `device_current`
/// called on a vault that has never been unlocked, so no device is
/// registered yet).
pub fn read_device(
    conn: &Connection,
    device_id: &DeviceId,
    current_device_id: &DeviceId,
) -> Result<Option<DeviceIdentity>> {
    let sql = format!("SELECT {DEVICES_SELECT_COLS} FROM devices WHERE device_id = ?1");
    let row = conn
        .query_row(
            &sql,
            params![device_id.0.as_slice()],
            DeviceRow::from_sqlite_row,
        )
        .optional()
        .map_err(StoreError::from)?;
    match row {
        None => Ok(None),
        Some(r) => Ok(Some(r.into_identity(current_device_id)?)),
    }
}

/// Update the `label` column for `device_id`. Returns
/// [`StoreError::AccountNotFound`] (re-used as "no such device row") if
/// the id is not in the trust list. `label` must already be validated.
pub fn set_device_label(conn: &Connection, device_id: &DeviceId, label: &str) -> Result<()> {
    let n = conn.execute(
        "UPDATE devices SET label = ?1 WHERE device_id = ?2",
        params![label, device_id.0.as_slice()],
    )?;
    if n == 0 {
        return Err(StoreError::AccountNotFound);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        device_id_from_key, list_devices, load_device_key_with_id, read_device, register_device,
        set_device_label, validate_label, DeviceCapabilities, DEVICE_IDENTITY_SCHEMA_VERSION,
    };
    use crate::error::StoreError;
    use crate::revision::DeviceId;
    use pangolin_crypto::aead::AeadKey;
    use pangolin_crypto::keys::DeviceKey;
    use rusqlite::Connection;

    fn fresh_conn() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        crate::schema::apply_pragmas_and_schema(&conn).unwrap();
        conn
    }

    #[test]
    fn capabilities_round_trip_default_full() {
        assert_eq!(DeviceCapabilities::default(), DeviceCapabilities::Full);
        assert_eq!(DeviceCapabilities::Full.to_repr(), 0);
        assert_eq!(DeviceCapabilities::from_repr(0), DeviceCapabilities::Full);
        // Unknown stored value coerces to Full (forward-compat).
        assert_eq!(DeviceCapabilities::from_repr(99), DeviceCapabilities::Full);
        assert_eq!(DeviceCapabilities::from_repr(-1), DeviceCapabilities::Full);
    }

    #[test]
    fn validate_label_rejects_empty_and_overlong() {
        assert!(matches!(
            validate_label("   ").unwrap_err(),
            StoreError::Validation { kind, .. } if kind == "device_label"
        ));
        let long = "x".repeat(300);
        assert!(matches!(
            validate_label(&long).unwrap_err(),
            StoreError::Validation { kind, .. } if kind == "device_label"
        ));
        // NFC-normalised + trimmed.
        assert_eq!(validate_label("  Cafe\u{0301}  ").unwrap(), "Café");
    }

    #[test]
    fn register_then_load_round_trips() {
        let conn = fresh_conn();
        let vault_id = [0xAAu8; 32];
        let vdk = AeadKey::generate();
        let key = DeviceKey::generate();
        let expected_id = device_id_from_key(&key);
        let registered =
            register_device(&conn, &vault_id, &vdk, &key, "Device 1", 1_700_000_000_000).unwrap();
        assert_eq!(registered, expected_id);

        // device_key row decrypts back to the same key.
        let loaded = load_device_key_with_id(&conn, &vault_id, &vdk, &registered)
            .unwrap()
            .expect("device_key row present");
        assert_eq!(device_id_from_key(&loaded), expected_id);
        assert!(bool::from(loaded.ct_eq(&key)));

        // devices row is queryable and marked current.
        let listed = list_devices(&conn, &registered).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].device_id, expected_id);
        assert_eq!(listed[0].label, "Device 1");
        assert_eq!(listed[0].registered_at, 1_700_000_000_000);
        assert_eq!(listed[0].last_sync_at, None, "MVP-2 chain sync fills this");
        assert_eq!(listed[0].capabilities, DeviceCapabilities::Full);
        assert!(listed[0].is_current);
        assert!(listed[0].public_key.is_some());

        let one = read_device(&conn, &registered, &registered)
            .unwrap()
            .unwrap();
        assert_eq!(one.device_id, expected_id);
        assert!(one.is_current);
        assert_eq!(DEVICE_IDENTITY_SCHEMA_VERSION, 1);
    }

    #[test]
    fn wrong_vdk_or_vault_id_fails_to_load() {
        let conn = fresh_conn();
        let vault_id = [0xAAu8; 32];
        let vdk = AeadKey::generate();
        let key = DeviceKey::generate();
        let id = register_device(&conn, &vault_id, &vdk, &key, "D", 1).unwrap();

        let other_vdk = AeadKey::generate();
        assert!(matches!(
            load_device_key_with_id(&conn, &vault_id, &other_vdk, &id).unwrap_err(),
            StoreError::AuthenticationFailed
        ));
        let other_vault = [0xBBu8; 32];
        assert!(matches!(
            load_device_key_with_id(&conn, &other_vault, &vdk, &id).unwrap_err(),
            StoreError::AuthenticationFailed
        ));
    }

    #[test]
    fn set_label_persists_and_unknown_id_errors() {
        let conn = fresh_conn();
        let vault_id = [0x11u8; 32];
        let vdk = AeadKey::generate();
        let key = DeviceKey::generate();
        let id = register_device(&conn, &vault_id, &vdk, &key, "Old", 1).unwrap();
        set_device_label(&conn, &id, "New name").unwrap();
        assert_eq!(
            read_device(&conn, &id, &id).unwrap().unwrap().label,
            "New name"
        );
        let bogus = DeviceId([0x99u8; 32]);
        assert!(matches!(
            set_device_label(&conn, &bogus, "X").unwrap_err(),
            StoreError::AccountNotFound
        ));
    }

    #[test]
    fn no_device_registered_reads_none() {
        let conn = fresh_conn();
        let id = DeviceId([0u8; 32]);
        assert!(read_device(&conn, &id, &id).unwrap().is_none());
        assert!(list_devices(&conn, &id).unwrap().is_empty());
        let vdk = AeadKey::generate();
        assert!(load_device_key_with_id(&conn, &[0u8; 32], &vdk, &id)
            .unwrap()
            .is_none());
    }
}
