// SPDX-License-Identifier: AGPL-3.0-or-later
//! Device-identity FFI shapes + entry points (MVP-1 issue 1.5).
//!
//! `device_current` / `device_list` / `device_set_label` expose the
//! local trust list — the `devices` table the `pangolin-store` engine
//! maintains (one row per device that has ever opened+unlocked this
//! `.pvf`; the row is created on first unlock — register-on-unlock).
//! The trust list is add-only in MVP-1 (no revoke path) and gates
//! nothing destructive: it is the local record + the MVP-2 on-chain-
//! authority-registry hook. `device_set_label` requires an active
//! (unlocked, non-expired) session only — NOT a fresh presence proof
//! (Q5: a label rename is not a Session spec §5.4 reveal-class action).
//!
//! These are an **additive 1.1-surface amendment** — the 1.1 freeze
//! declared the `DeviceId` record but no `Device` / `DeviceInfo` shape
//! and no `device_*` entries; nothing external binds the 1.1 surface
//! yet, so it is safe (identical posture to 1.2's `AccountDraft`
//! widening and 1.4's `reveal_*` entries). `docs/architecture/ffi-surface.md`
//! is updated to add `DeviceInfo`, `DeviceCapabilities`, and the three
//! `device_*` entries.

use std::sync::Arc;

use crate::error::FfiError;
use crate::identity::DeviceId;
use crate::session::{UnixTimestamp, VaultHandle};

/// Device capability flags.
///
/// MVP-1 has one device class — `Full` (can do everything). The enum is
/// designed to grow (read-only seats, browser-extension-as-a-limited-
/// device, …) in MVP-2/3; the `pangolin-store` side stores it as a small
/// integer (`0 = Full`) so adding variants is a value addition, not a
/// schema change. Carries no `schema_version` slot — it is a closed
/// enum, not a user-data record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum DeviceCapabilities {
    /// The MVP-1 device class — full read/write/publish.
    Full,
}

impl From<pangolin_core::DeviceCapabilities> for DeviceCapabilities {
    fn from(value: pangolin_core::DeviceCapabilities) -> Self {
        match value {
            pangolin_core::DeviceCapabilities::Full => Self::Full,
        }
    }
}

/// One device in the trust list.
///
/// Carries only non-secret material — the device id, the user-set
/// label, the timestamps, the capability flags, the *public* verifying
/// key. The device's *secret* key never crosses FFI in MVP-1; it signs
/// nothing — it is the MVP-2 hook.
#[derive(Debug, Clone, uniffi::Record)]
pub struct DeviceInfo {
    /// Schema-version slot. 1.5 returns `1`; 1.6 locks the §18.7 policy.
    pub schema_version: u16,
    /// The device's stable id — the 32-byte Ed25519 verifying-key bytes.
    pub id: DeviceId,
    /// Human-readable label (user-set). Non-empty, NFC-normalised,
    /// ≤ 256 chars.
    pub label: String,
    /// Wall-clock unix-second timestamp the device first registered.
    pub registered_at: UnixTimestamp,
    /// **Dormant in MVP-1 — always `None`.** MVP-2's chain-sync code
    /// fills it (the last time this device published-or-pulled through
    /// the contract). A host UI renders "never synced" / hides it.
    pub last_sync_at: Option<UnixTimestamp>,
    /// Capability flags. `Full` in MVP-1.
    pub capabilities: DeviceCapabilities,
    /// `true` iff this is the device this `Vault` is running on.
    pub is_current: bool,
    /// The device's 32-byte Ed25519 verifying-key bytes (non-secret) —
    /// lets a host render a fingerprint and is what MVP-2 registers on
    /// chain. Equal to `id.bytes` for every 1.5-registered device;
    /// empty only for a legacy P2 stub row (which 1.5 never creates).
    pub public_key: Vec<u8>,
    /// **MVP-2 issue 3.2 (R-c — address-only FFI).** The device's per-
    /// device EVM wallet *address* (20 bytes; the public Ethereum
    /// address derived deterministically from this device's Ed25519
    /// `DeviceKey` via `pangolin_chain::derive_evm_address`). Non-
    /// secret — the address is on-chain-observable per D-006's known
    /// mitigation. NO signing handle ever crosses FFI in 3.2 — every
    /// future chain-write (3.3 direct-submit, 3.4 funder client, 4.2
    /// indexer reads) signs inside the Rust core; this field is render-
    /// only (a host UI shows "your gas wallet: 0x...").
    ///
    /// Empty `Vec` (`.len() == 0`) for a legacy 1.5-era row that has
    /// not yet been back-filled. The first 3.2-era `Vault::unlock`
    /// back-fills the column from the recovered `DeviceKey`, so this
    /// vector is empty in practice only between (a) opening a 1.5-era
    /// vault for the first time under a 3.2-era build and (b) the
    /// first `unlock` on it — i.e. in MVP-1 hosts that call
    /// `device_current` on a locked-but-previously-registered vault
    /// before unlocking it once under 3.2. Hosts render "not yet
    /// derived; unlock once to populate".
    ///
    /// Appended at end-of-record per the additive-FFI-surface
    /// discipline (1.1-frozen-but-amend posture; nothing external
    /// binds the 1.1 surface yet — see issue 3.2 R-c).
    pub evm_address: Vec<u8>,
}

/// Convert a core [`pangolin_core::DeviceIdentity`] to the FFI shape.
fn device_identity_to_ffi(identity: pangolin_core::DeviceIdentity) -> DeviceInfo {
    let public_key = identity
        .public_key
        .map(|vk| vk.to_bytes().to_vec())
        .unwrap_or_default();
    // MVP-2 issue 3.2 (R-c): the 20-byte EVM address (cached on
    // disk in `devices.evm_address`). Empty `Vec` for a legacy
    // 1.5-era row whose column is still NULL pre-back-fill; once
    // unlocked under a 3.2-era build, the first unlock writes the
    // column and subsequent reads return `len() == 20`.
    let evm_address = identity.evm_address.map(|a| a.to_vec()).unwrap_or_default();
    DeviceInfo {
        schema_version: pangolin_core::DEVICE_IDENTITY_SCHEMA_VERSION,
        id: DeviceId {
            schema_version: pangolin_core::DEVICE_IDENTITY_SCHEMA_VERSION,
            bytes: identity.device_id.0.to_vec(),
        },
        label: identity.label,
        // ms → s, integer-truncated (matches the PasswordHistoryEntry /
        // AccountSnapshot timestamp-conversion discipline; audit L-4).
        registered_at: identity.registered_at / 1000,
        last_sync_at: identity.last_sync_at.map(|ms| ms / 1000),
        capabilities: identity.capabilities.into(),
        is_current: identity.is_current,
        public_key,
        evm_address,
    }
}

/// Wire-form length of a [`DeviceId`]. Must be 32 bytes.
const DEVICE_ID_BYTES: usize = 32;

/// Convert an FFI [`DeviceId`] to a `pangolin_core::DeviceId`.
fn device_id_from_ffi(id: &DeviceId) -> Result<pangolin_core::DeviceId, FfiError> {
    let arr: [u8; DEVICE_ID_BYTES] =
        id.bytes
            .as_slice()
            .try_into()
            .map_err(|_| FfiError::Validation {
                kind: "argument".into(),
                message: format!(
                    "DeviceId.bytes must be {DEVICE_ID_BYTES} bytes (got {})",
                    id.bytes.len()
                ),
            })?;
    Ok(pangolin_core::DeviceId(arr))
}

fn store_into_ffi(err: pangolin_store::StoreError) -> FfiError {
    FfiError::from(pangolin_core::Error::from(err))
}

/// Read the trust list — every device that has ever opened+unlocked this
/// `.pvf` (one row in MVP-1). Works on a `Locked` vault that has been
/// unlocked at least once on this file.
///
/// # Errors
///
/// `FfiError::Session` if the handle has no vault installed;
/// `FfiError::Store` on a storage failure.
#[allow(clippy::significant_drop_tightening)]
#[uniffi::export]
pub fn device_list(handle: Arc<VaultHandle>) -> Result<Vec<DeviceInfo>, FfiError> {
    let mut guard = handle.lock_vault();
    let vault = guard.as_mut()?;
    let devices = vault.device_list().map_err(store_into_ffi)?;
    Ok(devices.into_iter().map(device_identity_to_ffi).collect())
}

/// Read the device this `Vault` is running on.
///
/// Works on a `Locked` vault that has been unlocked at least once. On a
/// brand-new vault opened but never unlocked there is no device row yet
/// → `FfiError::Session` ("vault is not unlocked" — unlock once to
/// register the device).
///
/// # Errors
///
/// `FfiError::Session` if the handle has no vault installed or no device
/// has been registered yet; `FfiError::Store` on a storage failure.
#[allow(clippy::significant_drop_tightening)]
#[uniffi::export]
pub fn device_current(handle: Arc<VaultHandle>) -> Result<DeviceInfo, FfiError> {
    let mut guard = handle.lock_vault();
    let vault = guard.as_mut()?;
    let identity = vault.device_current().map_err(store_into_ffi)?;
    Ok(device_identity_to_ffi(identity))
}

/// Rename a device in the trust list. Validates `label` (non-empty,
/// ≤ 256 chars, NFC-normalised); persists; survives close/reopen.
///
/// **Q5:** requires an active (unlocked, non-expired) session only —
/// NOT a fresh presence proof. A locked-vault or expired-session call
/// errors.
///
/// # Errors
///
/// `FfiError::Session` for a locked / expired session or a missing
/// handle; `FfiError::Validation` (`kind = "device_label"`) for an
/// empty / over-long / control-char label; `FfiError::Store` if the id
/// is not in the trust list.
#[allow(clippy::significant_drop_tightening)]
#[uniffi::export]
pub fn device_set_label(
    handle: Arc<VaultHandle>,
    id: DeviceId,
    label: String,
) -> Result<(), FfiError> {
    let mut guard = handle.lock_vault();
    let vault = guard.as_mut()?;
    let store_id = device_id_from_ffi(&id)?;
    vault
        .device_set_label(store_id, &label)
        .map_err(store_into_ffi)
}

#[cfg(test)]
mod tests {
    use super::{device_current, device_list, device_set_label, DeviceCapabilities};
    use crate::identity::DeviceId as FfiDeviceId;
    use crate::session::VaultHandle;
    use pangolin_core::{PinIdentityProof, PressYPresenceProof, Vault};
    use pangolin_crypto::secret::SecretBytes;
    use std::sync::Arc;

    fn pwd() -> SecretBytes {
        SecretBytes::new(b"correct horse battery staple".to_vec())
    }

    /// Build an unlocked vault handle the 1.2/1.4 test pattern way.
    fn unlocked_handle(dir: &tempfile::TempDir, name: &str) -> Arc<VaultHandle> {
        let path = dir.path().join(name);
        Vault::create(&path, &pwd()).unwrap();
        let mut v = Vault::open(&path).unwrap();
        v.unlock(
            &PressYPresenceProof::confirmed(),
            &PinIdentityProof::new(pwd()),
        )
        .unwrap();
        VaultHandle::from_vault(v)
    }

    #[test]
    fn device_current_list_set_label_end_to_end() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");

        let listed = device_list(Arc::clone(&h)).unwrap();
        assert_eq!(listed.len(), 1, "exactly one device after first unlock");
        let only = &listed[0];
        assert_eq!(only.schema_version, 1);
        assert_eq!(only.last_sync_at, None, "MVP-2 chain sync fills this");
        assert_eq!(only.capabilities, DeviceCapabilities::Full);
        assert!(only.is_current);
        assert_eq!(only.id.bytes.len(), 32);
        assert_eq!(only.public_key, only.id.bytes);
        // MVP-2 issue 3.2 (R-c): the FFI carries the 20-byte EVM
        // wallet address for a 3.2-era registered device.
        assert_eq!(
            only.evm_address.len(),
            20,
            "DeviceInfo.evm_address must be 20 bytes for a registered device"
        );

        let cur = device_current(Arc::clone(&h)).unwrap();
        assert_eq!(cur.id.bytes, only.id.bytes);
        assert!(cur.is_current);

        // Rename works (active session) and persists.
        device_set_label(Arc::clone(&h), cur.id.clone(), "Kelvin's MacBook".into()).unwrap();
        let after = device_current(Arc::clone(&h)).unwrap();
        assert_eq!(after.label, "Kelvin's MacBook");

        // Empty label rejected.
        assert!(matches!(
            device_set_label(Arc::clone(&h), cur.id, "   ".into()).unwrap_err(),
            crate::error::FfiError::Validation { kind, .. } if kind == "device_label"
        ));
    }

    /// MVP-2 issue 3.2: `device_current()` returns `DeviceInfo` whose
    /// `evm_address` is the 20-byte EVM wallet address for a
    /// registered device, and equals the address that
    /// `pangolin_chain::derive_evm_address` produces from the same
    /// device's `DeviceKey` (determinism). The FFI surface does NOT
    /// expose any signing handle — only the public address (R-c).
    #[test]
    fn ffi_device_current_returns_evm_address() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "evm-ffi.pvf");
        let cur = device_current(Arc::clone(&h)).unwrap();
        assert_eq!(
            cur.evm_address.len(),
            20,
            "DeviceInfo.evm_address must be 20 bytes for a registered device"
        );
        // Determinism: every byte is non-deterministic per device,
        // but the field IS non-empty + IS exactly 20 bytes. (We
        // do not have host-side access to the seed to re-derive
        // the exact bytes here; the determinism property is
        // exercised in `pangolin-store::device::tests` and the
        // `evm_address_determinism_across_unlock_cycles` e2e
        // proptest.)
        let listed = device_list(Arc::clone(&h)).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(
            listed[0].evm_address, cur.evm_address,
            "list and current must agree on the EVM address"
        );
    }

    #[test]
    fn device_calls_on_empty_or_locked_handle_error() {
        // Empty handle (no vault installed).
        let empty = VaultHandle::new_placeholder();
        assert!(matches!(
            device_current(Arc::clone(&empty)).unwrap_err(),
            crate::error::FfiError::Session { .. }
        ));
        assert!(matches!(
            device_list(Arc::clone(&empty)).unwrap_err(),
            crate::error::FfiError::Session { .. }
        ));
        let bogus = FfiDeviceId {
            schema_version: 1,
            bytes: vec![0u8; 32],
        };
        assert!(matches!(
            device_set_label(empty, bogus, "X".into()).unwrap_err(),
            crate::error::FfiError::Session { .. }
        ));

        // Locked vault: device_set_label errors (active session
        // required); device_current / device_list still work (the row
        // is persisted).
        let dir = tempfile::TempDir::new().unwrap();
        let h = unlocked_handle(&dir, "v.pvf");
        let id = device_current(Arc::clone(&h)).unwrap().id;
        {
            let mut guard = h.lock_vault();
            guard.as_mut().unwrap().lock();
        }
        assert!(matches!(
            device_set_label(Arc::clone(&h), id, "X".into()).unwrap_err(),
            crate::error::FfiError::Session { .. }
        ));
        // Reads still work on the locked-but-previously-registered vault.
        assert_eq!(device_list(Arc::clone(&h)).unwrap().len(), 1);
        assert!(device_current(h).is_ok());
    }
}
