//! `EVM` chain adapter for Pangolin.
//!
//! This crate is the **library-quality** chain integration that the rest of
//! the Pangolin core consumes — `pangolin-store` for `mark_published` /
//! `unpublished_revisions` plumbing, `pangolin-cli` for direct user-facing
//! publish/pull commands, and the eventual `pangolin-indexer` (D-007) when
//! that lands.
//!
//! Per master plan §3.7 (P7) and decision D-006:
//! - Direct submit (no relay).
//! - One device → one Ed25519 keypair signs the revision payload AND
//!   pays gas. Because Ethereum does not natively verify Ed25519, the
//!   gas wallet is a **derived** secp256k1 wallet — see [`evm`] module
//!   for the deterministic Ed25519→secp256k1 derivation. Same Pangolin
//!   `DeviceKey` always produces the same EVM address.
//! - Signature over a domain-separated keccak-hash of the canonical
//!   revision fields. v0 contract ignores the signature (per P5-1 audit
//!   threat #2); v1 will verify (MVP-2 issue 2.1). The discipline lives
//!   on the client side now so MVP-2 doesn't need a client-side
//!   migration.
//!
//! ## Modules
//!
//! - [`adapter`] — the `ChainAdapter` async trait.
//! - [`types`] — `ChainAnchor`, `SignedRevision`, `RevisionEvent`,
//!   `EventLocation`, `VaultId`.
//! - [`error`] — `ChainError` taxonomy.
//! - [`signing`] — `build_signed_revision(...)`: Ed25519 over the
//!   domain-separated canonical hash.
//! - [`evm`] — Ed25519 → secp256k1 wallet derivation.
//! - [`base_sepolia`] — the production `BaseSepoliaAdapter`
//!   (alloy-backed, three constructors).
//! - [`mock`] — `MockChainAdapter` for in-memory tests
//!   (`cfg(any(test, feature = "test-utilities"))`).
//!
//! ## Re-exports of pangolin-store types
//!
//! `pangolin-store::ChainAnchor` is the same type as
//! `pangolin_chain::types::ChainAnchor` — `pangolin-chain` is the
//! canonical owner per success criterion 6 of `docs/issue-plans/P7.md`.
//! `pangolin-store` re-exports it from here so existing consumers
//! (revision rows, `Vault::mark_published`) keep their public surface
//! unchanged.

#![cfg_attr(not(any(test, feature = "test-utilities")), forbid(unsafe_code))]
#![cfg_attr(any(test, feature = "test-utilities"), deny(unsafe_code))]

pub mod adapter;
pub mod base_sepolia;
pub mod error;
pub mod evm;
pub mod signing;
pub mod types;

#[cfg(any(test, feature = "test-utilities"))]
pub mod mock;

pub use adapter::ChainAdapter;
pub use error::ChainError;
pub use evm::{derive_evm_address, derive_evm_wallet, EvmWallet};
pub use signing::{
    build_signed_revision, canonical_hash, verify_signed_revision, SignatureInvalid,
};
pub use types::{ChainAnchor, EventLocation, RevisionEvent, SignedRevision, VaultId};

/// Returns the crate name. Useful for diagnostics and version reporting.
#[must_use]
pub fn name() -> &'static str {
    "pangolin-chain"
}

#[cfg(test)]
mod tests {
    use super::name;

    #[test]
    fn crate_name_is_set() {
        assert_eq!(name(), "pangolin-chain");
    }
}
