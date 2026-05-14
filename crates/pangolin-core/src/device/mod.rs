// SPDX-License-Identifier: AGPL-3.0-or-later
//! Device identity + local trust list — landed by MVP-1 issue 1.5.
//!
//! Per the standing posture (issue 1.4 Q1 = no physical relocation) the
//! production [`DeviceIdentity`] model physically lives in
//! `pangolin-store::device` and `pangolin-core` re-exports it. The
//! re-exports below let downstream callers (e.g. `pangolin-ffi`) refer
//! to the model under the `pangolin_core::device::*` namespace, in
//! addition to the crate-root re-exports surfaced by `crate::lib`.
//!
//! MVP-1 boundaries (see `docs/issue-plans/1.5.md`): the trust list is
//! add-only (register-on-unlock; no revoke path — that needs authority
//! rotation, which is MVP-3); the per-device `DeviceKey` is generated +
//! stored encrypted but signs nothing in MVP-1 (the MVP-2 signed-
//! revision / gas-payer hook); `last_sync_at` is a dormant column
//! (MVP-2's chain sync fills it). It gates nothing operationally — it is
//! the local record + the MVP-2 on-chain-authority-registry hook.

pub use pangolin_store::{
    DeviceCapabilities, DeviceId, DeviceIdentity, DEVICE_IDENTITY_SCHEMA_VERSION, EVM_ADDRESS_LEN,
};
