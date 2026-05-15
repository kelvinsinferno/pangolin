// SPDX-License-Identifier: AGPL-3.0-or-later
//! [`DefaultStrategy`] — the verbatim no-op [`PrivacyStrategy`] impl.
//!
//! L1 + L4 verbatim: this impl MUST preserve 3.5 behaviour bit-for-bit
//! on every hook. The byte-identity regression tests in
//! `crates/pangolin-chain/src/privacy/tests.rs` are the mechanical
//! lock; CI re-runs them every PR. A future builder that "improves"
//! any of the three hooks below MUST coordinate a fresh fixture
//! capture + a DEVLOG entry explaining the drift.
//!
//! Layout discipline (audit-friendly):
//!
//! - `derive_wallet_for_revision` IGNORES the index; calls
//!   [`super::default_wallet_for`] which is the existing
//!   [`crate::evm::derive_evm_wallet`] (3.2 surface).
//! - `transform_funder_response` is the identity function on the
//!   response shape.
//! - `select_address_for_vault` IGNORES the vault id; returns the
//!   supplied `default_address` verbatim.
//!
//! Each hook body is one line by design. If a future maintainer feels
//! the urge to add logic here, they are shipping a Phase-2 mode and
//! MUST do it in a NEW strategy impl — not by widening
//! [`DefaultStrategy`].

use alloy::primitives::Address;

use super::{default_wallet_for, EvmWallet, FunderResponseShape, PrivacyError, PrivacyStrategy};
use pangolin_crypto::keys::DeviceKey;

/// Verbatim no-op privacy strategy. Selecting this is the 3.5
/// behavior bit-for-bit (L1).
///
/// Constructed via the trivial `DefaultStrategy` unit-struct
/// constructor. The type is zero-sized; every callsite can construct
/// a fresh instance for free (no lifetime / ownership concerns).
#[derive(Clone, Copy, Debug, Default)]
pub struct DefaultStrategy;

impl PrivacyStrategy for DefaultStrategy {
    fn derive_wallet_for_revision(
        &self,
        device_key: &DeviceKey,
        _revision_index: u64,
    ) -> Result<EvmWallet, PrivacyError> {
        // L1 + L4: ignore the index; return the single device wallet
        // (3.5 behaviour). Any deviation from this one line fires the
        // byte-identity test.
        default_wallet_for(device_key)
    }

    fn transform_funder_response(
        &self,
        funder_response: FunderResponseShape,
    ) -> Result<FunderResponseShape, PrivacyError> {
        // L1 + L4: identity function on the response shape (3.5
        // behaviour — no pre-mixing).
        Ok(funder_response)
    }

    fn select_address_for_vault(
        &self,
        _vault_id: [u8; 32],
        default_address: Address,
    ) -> Result<Address, PrivacyError> {
        // L1 + L4: ignore the vault_id; return the supplied default
        // address (3.5 behaviour — one device address per device).
        Ok(default_address)
    }
}
