// SPDX-License-Identifier: AGPL-3.0-or-later
//! Privacy Phase-2 hook scaffolding (MVP-2 issue 3.6, scaffolding-only).
//!
//! See `docs/issue-plans/3.6.md` for the full design + L1..L7
//! invariants and `docs/architecture/privacy.md` for the architecture
//! overview. Whitepaper §8.3 is the spec reference; master plan §5 row
//! 3.6 + D-006 capture the on-chain-observability mitigation the hooks
//! are scaffolded for.
//!
//! ## L3 CRITICAL: stable APIs
//!
//! Hook method signatures on [`PrivacyStrategy`] and the variants of
//! [`PrivacyMode`] are **stable APIs** Phase-2 implementations will pin
//! against. DO NOT rename methods or change argument shapes without
//! coordinating with the Phase-2 implementation (MVP-3 / MVP-4
//! territory). A rename here is a BREAKING change to Phase-2 work.
//!
//! ## R-a..R-d in one paragraph (the binding contract)
//!
//! - **R-a** — both [`PrivacyMode`] enum + [`PrivacyStrategy`] trait
//!   ship. [`DefaultStrategy`] is a verbatim no-op preserving 3.5
//!   behaviour bit-for-bit; [`EnhancedPrivacyStrategy`] is a
//!   fail-loudly stub returning [`PrivacyError::NotYetImplemented`]
//!   from every hook.
//! - **R-b** — three hooks per the master plan §5 row 3.6 three modes:
//!   per-revision wallet rotation
//!   ([`PrivacyStrategy::derive_wallet_for_revision`]), `CoinJoin` pre-
//!   mixing of funder top-ups
//!   ([`PrivacyStrategy::transform_funder_response`] — placeholder, no
//!   concrete mixer wired), and optional fresh-address-per-vault
//!   ([`PrivacyStrategy::select_address_for_vault`]).
//! - **R-c** — central declarations live here; consumer crates
//!   (`pangolin-funder-client`, `pangolin-store`, and `pangolin-chain`
//!   itself for signing + balance paths) import the trait at their hook
//!   points. No new workspace crate.
//! - **R-d** — three test classes in [`tests`]: compile-time trait
//!   shape; byte-identity assertions vs the 3.5 baseline (captured at
//!   builder time as compile-time hex constants); fail-loudly = every
//!   `EnhancedPrivacyStrategy` hook returns
//!   `Err(PrivacyError::NotYetImplemented)`.
//!
//! ## L1 + L4 (the load-bearing invariants)
//!
//! [`DefaultStrategy`] MUST preserve 3.5 behaviour bit-for-bit.
//! Signatures, calldata, balance-state outputs MUST be byte-identical
//! to the pre-3.6 baseline (`main` at `3227d38`). The fixture-based
//! byte-identity regression test
//! (`tests::default_strategy_revision_signature_matches_pre_3_6_baseline`)
//! is the mechanical lock; CI re-runs it every PR. A drift fails the
//! build.
//!
//! ## L7 (fail-loudly)
//!
//! [`EnhancedPrivacyStrategy`] MUST fail loudly when instantiated. No
//! Phase-2 implementation exists in 3.6; the "enabled" path returns
//! [`PrivacyError::NotYetImplemented`] BEFORE doing any work. Silent
//! fallback to [`PrivacyMode::Default`] is REJECTED — a user / host
//! that explicitly opts in MUST get an unambiguous "not yet" signal,
//! not a quiet degrade to the observable-on-chain default.

use alloy::primitives::{Address, B256, U256};

use crate::error::ChainError;
use crate::evm::{derive_evm_wallet, EvmWallet};
use pangolin_crypto::keys::DeviceKey;

/// User-facing privacy mode selection (R-a enum).
///
/// The enum is the **host-facing knob**; the [`PrivacyStrategy`] trait
/// is the **internal implementation surface** consumers consume. A
/// future Phase-2 adapter will map this enum into a concrete
/// `Box<dyn PrivacyStrategy>` at the host boundary.
///
/// Variant names are stable APIs (L3): renaming them is a BREAKING
/// change to Phase-2 work. The order is locked too — `Default` first,
/// `EnhancedPrivacy` second.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PrivacyMode {
    /// Current MVP-2 behaviour: single device wallet, no rotation, no
    /// mixing, no per-vault address derivation. The
    /// [`DefaultStrategy`] impl is a verbatim no-op preserving 3.5
    /// behaviour bit-for-bit (L1 + L4).
    Default,
    /// Phase-2 mode (deferred to MVP-3 / MVP-4): per-revision wallet
    /// rotation, `CoinJoin` pre-mixing of funder top-ups, optional
    /// fresh-address-per-vault. **Currently fail-loudly stubbed** —
    /// see [`EnhancedPrivacyStrategy`] and L7 verbatim. Instantiating
    /// a strategy in this mode + calling any hook returns
    /// [`PrivacyError::NotYetImplemented`].
    EnhancedPrivacy,
}

/// Errors specific to the privacy hook layer.
///
/// Decoupled from [`crate::ChainError`] because the privacy hook
/// surface is its own concern (the Phase-2 impl may want to surface
/// per-mode failure modes — mixer offline, rotation cap reached, etc.
/// — without bloating `ChainError`). The
/// [`PrivacyError::WalletDerivationFailed`] variant carries the
/// underlying [`ChainError`] for the
/// [`PrivacyStrategy::derive_wallet_for_revision`] hook's failure
/// path so callers can introspect when the privacy layer's own
/// wrapping of [`derive_evm_wallet`] surfaces a derivation error.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PrivacyError {
    /// **L7 verbatim.** A hook on the [`EnhancedPrivacyStrategy`] stub
    /// was called. No Phase-2 implementation exists in 3.6; the
    /// "enabled" path returns this error BEFORE doing any work. The
    /// `mode` field is always [`PrivacyMode::EnhancedPrivacy`] for
    /// this variant; the `hook` field carries the static name of the
    /// trait method that errored (one of
    /// `"derive_wallet_for_revision"`,
    /// `"transform_funder_response"`,
    /// `"select_address_for_vault"`).
    ///
    /// See `docs/issue-plans/3.6.md` for the Phase-2 implementation
    /// roadmap.
    #[error(
        "privacy mode {mode:?} is scaffolding-only in MVP-2; hook \
         '{hook}' returns not-yet-implemented. See \
         docs/issue-plans/3.6.md for the Phase-2 implementation \
         roadmap."
    )]
    NotYetImplemented {
        /// Which mode the caller had selected when the hook fired.
        /// Always [`PrivacyMode::EnhancedPrivacy`] in 3.6 — the
        /// [`DefaultStrategy`] never returns this variant.
        mode: PrivacyMode,
        /// Static name of the trait method that errored. One of:
        /// `"derive_wallet_for_revision"`,
        /// `"transform_funder_response"`,
        /// `"select_address_for_vault"`.
        hook: &'static str,
    },

    /// The underlying [`derive_evm_wallet`] call inside the
    /// [`PrivacyStrategy::derive_wallet_for_revision`] hook surfaced
    /// a [`ChainError`]. The privacy layer cannot itself produce a
    /// secp256k1 wallet without that primitive succeeding; the wrap is
    /// the boundary at which `ChainError` becomes a `PrivacyError`.
    ///
    /// Carries the chain-side error description as a string (the
    /// underlying [`ChainError::Wallet`] is the only practical
    /// variant that flows here today, but we string-wrap so any
    /// future variant on [`derive_evm_wallet`]'s `Result` is
    /// surfaceable without a cyclical typed wrap). No secret material
    /// crosses the boundary — [`ChainError`]'s `Display` is
    /// secret-free per its module docs.
    #[error("wallet derivation failed inside privacy hook: {detail}")]
    WalletDerivationFailed {
        /// Upstream chain-layer error description (non-secret).
        detail: String,
    },
}

impl PrivacyError {
    /// Lift a [`ChainError`] into a [`PrivacyError::WalletDerivationFailed`]
    /// at the trait-impl boundary. Helper kept local because the
    /// conversion is a one-line `.to_string()`; an explicit `From<...>`
    /// impl would push the `PrivacyError` into every
    /// `derive_evm_wallet` callsite via `?`, which is the wrong
    /// direction — privacy errors should never bubble through
    /// non-privacy paths.
    fn from_wallet_chain_error(e: &ChainError) -> Self {
        Self::WalletDerivationFailed {
            detail: e.to_string(),
        }
    }
}

/// Placeholder shape for the funder response the
/// [`PrivacyStrategy::transform_funder_response`] hook accepts +
/// returns.
///
/// The actual `pangolin_funder_client::TopUpResponse` type lives in
/// `pangolin-funder-client`, which depends transitively on alloy but
/// does **NOT** depend on `pangolin-chain` (per the L1-style invariant
/// in that crate's `lib.rs`). To avoid a circular dep
/// (`pangolin-funder-client → pangolin-chain → pangolin-funder-client`)
/// the trait surface here uses this LOCAL marker shape that holds the
/// same two load-bearing fields the funder response carries:
/// `tx_hash` (the redeem tx) and `eth_transferred_wei`.
///
/// Phase-2 will likely promote this to a richer type — possibly a
/// trait, possibly a struct shared via a new dep edge — depending on
/// how the concrete `CoinJoin` client wants to consume / produce
/// funder responses. The shape is intentionally minimal in 3.6 so the
/// architectural-locking property is preserved without baking a wrong
/// guess into the trait surface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FunderResponseShape {
    /// The redeem tx hash returned by the funder
    /// (`pangolin_funder_client::TopUpResponse::redeem_tx_hash` in the
    /// real surface).
    pub tx_hash: B256,
    /// ETH transferred (wei) — `U256::ZERO` if the eth-transfer leg
    /// failed (matches the funder-client semantic).
    pub eth_transferred_wei: U256,
}

/// The Phase-2 hook interface (R-a + R-b trait).
///
/// Three hooks per R-b — one per master plan §5 row 3.6 mode:
///
/// - [`PrivacyStrategy::derive_wallet_for_revision`] — per-revision
///   wallet rotation (Phase-2 derives a fresh wallet keyed by the
///   revision index; default returns the single device wallet).
/// - [`PrivacyStrategy::transform_funder_response`] — `CoinJoin` pre-
///   mixing of funder top-ups (Phase-2 intercepts the funder's
///   response to route the ETH through a non-custodial `CoinJoin`
///   tool BEFORE it lands at the device wallet; default passes
///   through).
/// - [`PrivacyStrategy::select_address_for_vault`] — optional fresh-
///   address-per-vault (Phase-2 derives a vault-keyed address;
///   default returns the supplied default address).
///
/// L3 CRITICAL: signatures here are stable APIs. Phase-2 work will pin
/// against them.
pub trait PrivacyStrategy: Send + Sync {
    /// Per-revision wallet rotation hook.
    ///
    /// Phase-2 implementation will derive a fresh EVM wallet keyed by
    /// `revision_index` (a sequence number under R-b; the exact key
    /// scheme is Phase-2's choice). The [`DefaultStrategy`] ignores
    /// the index and returns the result of calling
    /// [`derive_evm_wallet`] on the supplied `device_key` — i.e. the
    /// single device wallet 3.5 ships.
    ///
    /// # Errors
    ///
    /// - [`PrivacyError::WalletDerivationFailed`] if the underlying
    ///   [`derive_evm_wallet`] surface returns a [`ChainError`]
    ///   (vanishingly rare per its docs — only on HKDF rejection-
    ///   sampling exhaustion).
    /// - [`PrivacyError::NotYetImplemented`] from
    ///   [`EnhancedPrivacyStrategy`] (L7 verbatim).
    ///
    /// L3: do not rename. Phase-2 will pin against
    /// `derive_wallet_for_revision`.
    fn derive_wallet_for_revision(
        &self,
        device_key: &DeviceKey,
        revision_index: u64,
    ) -> Result<EvmWallet, PrivacyError>;

    /// `CoinJoin` pre-mixing of funder top-ups hook.
    ///
    /// Phase-2 implementation will route the funder's response
    /// through a non-custodial `CoinJoin` tool BEFORE the ETH lands
    /// at the device wallet. The [`DefaultStrategy`] passes the
    /// response through unchanged (3.5 behaviour).
    ///
    /// Note: 3.6 does NOT wire a concrete `CoinJoin` client — the
    /// chosen mixer + its trust posture is a Phase-2 decision with
    /// its own audit gate. This hook is the architectural-locking
    /// surface; the implementation is deferred.
    ///
    /// # Errors
    ///
    /// - [`PrivacyError::NotYetImplemented`] from
    ///   [`EnhancedPrivacyStrategy`] (L7 verbatim).
    ///
    /// L3: do not rename. Phase-2 will pin against
    /// `transform_funder_response`.
    fn transform_funder_response(
        &self,
        funder_response: FunderResponseShape,
    ) -> Result<FunderResponseShape, PrivacyError>;

    /// Optional fresh-address-per-vault hook.
    ///
    /// Phase-2 implementation will derive a per-vault EVM address
    /// keyed by `vault_id` so two distinct vaults on the same device
    /// publish under distinct on-chain identities (defeating the
    /// trivial "watch this device's chain activity to learn which
    /// vaults it owns" correlation). The [`DefaultStrategy`] ignores
    /// `vault_id` and returns `default_address` — i.e. the single
    /// device address 3.2 ships.
    ///
    /// # Errors
    ///
    /// - [`PrivacyError::NotYetImplemented`] from
    ///   [`EnhancedPrivacyStrategy`] (L7 verbatim).
    ///
    /// L3: do not rename. Phase-2 will pin against
    /// `select_address_for_vault`.
    fn select_address_for_vault(
        &self,
        vault_id: [u8; 32],
        default_address: Address,
    ) -> Result<Address, PrivacyError>;
}

pub mod default;
pub mod enhanced;

pub use default::DefaultStrategy;
pub use enhanced::EnhancedPrivacyStrategy;

#[cfg(test)]
mod tests;

/// Internal helper for [`default::DefaultStrategy`] to wrap a
/// [`ChainError`] from [`derive_evm_wallet`] into a
/// [`PrivacyError::WalletDerivationFailed`]. Kept here at the
/// `pub(crate)` boundary so the no-op impl can stay a thin shim.
pub(crate) fn wrap_wallet_error(e: &ChainError) -> PrivacyError {
    PrivacyError::from_wallet_chain_error(e)
}

/// Internal helper that yields a fresh single-device wallet via the
/// existing 3.2 derivation primitive. Wraps [`derive_evm_wallet`] so
/// the no-op impl can be one line.
pub(crate) fn default_wallet_for(device_key: &DeviceKey) -> Result<EvmWallet, PrivacyError> {
    derive_evm_wallet(device_key).map_err(|e| wrap_wallet_error(&e))
}
