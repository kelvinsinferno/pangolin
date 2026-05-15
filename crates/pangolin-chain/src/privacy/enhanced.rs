// SPDX-License-Identifier: AGPL-3.0-or-later
//! [`EnhancedPrivacyStrategy`] — the fail-loudly [`PrivacyStrategy`]
//! stub.
//!
//! L7 verbatim: every hook returns
//! [`PrivacyError::NotYetImplemented`] BEFORE doing any work. Silent
//! fallback to [`super::DefaultStrategy`] is REJECTED — a user / host
//! that explicitly opts in MUST get an unambiguous "not yet" signal,
//! not a quiet degrade to the observable-on-chain default.
//!
//! The three test bodies in `crates/pangolin-chain/src/privacy/tests.rs`
//! assert each hook returns the expected typed variant; CI re-runs
//! them every PR.
//!
//! A future Phase-2 implementer who wants to ship real logic REPLACES
//! this stub (or, more likely, adds a parallel strategy impl + flips
//! the [`super::PrivacyMode::EnhancedPrivacy`] → strategy adapter to
//! the new impl). Until then, the explicit "not yet" error is the
//! user-facing fail-closed signal.

use alloy::primitives::Address;

use super::{EvmWallet, FunderResponseShape, PrivacyError, PrivacyMode, PrivacyStrategy};
use pangolin_crypto::keys::DeviceKey;

/// Fail-loudly stub privacy strategy. Selecting this in 3.6 means
/// "I want Phase-2 behaviour but it does not exist yet" — every hook
/// fires [`PrivacyError::NotYetImplemented`].
///
/// Constructed via the trivial unit-struct constructor. The type is
/// zero-sized; constructing one is free.
#[derive(Clone, Copy, Debug, Default)]
pub struct EnhancedPrivacyStrategy;

impl PrivacyStrategy for EnhancedPrivacyStrategy {
    fn derive_wallet_for_revision(
        &self,
        _device_key: &DeviceKey,
        _revision_index: u64,
    ) -> Result<EvmWallet, PrivacyError> {
        // L7: fail loudly, BEFORE doing any work.
        Err(PrivacyError::NotYetImplemented {
            mode: PrivacyMode::EnhancedPrivacy,
            hook: "derive_wallet_for_revision",
        })
    }

    fn transform_funder_response(
        &self,
        _funder_response: FunderResponseShape,
    ) -> Result<FunderResponseShape, PrivacyError> {
        // L7: fail loudly, BEFORE doing any work.
        Err(PrivacyError::NotYetImplemented {
            mode: PrivacyMode::EnhancedPrivacy,
            hook: "transform_funder_response",
        })
    }

    fn select_address_for_vault(
        &self,
        _vault_id: [u8; 32],
        _default_address: Address,
    ) -> Result<Address, PrivacyError> {
        // L7: fail loudly, BEFORE doing any work.
        Err(PrivacyError::NotYetImplemented {
            mode: PrivacyMode::EnhancedPrivacy,
            hook: "select_address_for_vault",
        })
    }
}
