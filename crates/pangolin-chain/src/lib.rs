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
//!   threat #2); v1 (MVP-2 issue 2.1) will verify. We sign on the client
//!   today so the **canonical-hash construction** (keccak256 of fixed-
//!   width fields, with payload reduced to its keccak digest) transfers
//!   into v1 unchanged — that's the part of the discipline that
//!   survives every plausible v1 path. The **signature primitive
//!   itself** may not transfer (see HIGH-2 caveat below); v1's choice
//!   of primitive may force a client-side rework even though the hash
//!   stays the same.
//!
//! ## v1 forward-prep — what actually transfers (P7 audit HIGH-2)
//!
//! The original P7 framing claimed P5-1's signed-revision discipline
//! is "forward-prep so MVP-2 doesn't need a client-side migration".
//! That overstated the case. There are two plausible v1 paths and
//! only the *canonical-hash* part is path-independent:
//!
//! - **Path A — Solidity Ed25519 verifier on chain.** Cost is roughly
//!   500k gas per verification (the lower-bound figure for current
//!   pure-Solidity Ed25519 implementations; see e.g. the
//!   `ed25519-solidity` reference and analogous gas reports). On
//!   Base mainnet (an L2) at typical 2026 fees that's
//!   ~$0.01–0.02/verify; on Ethereum L1 at non-trivial gas prices
//!   that'd be ~$25–50/verify, which is not viable for per-revision
//!   verification. Path A is therefore L2-only in practice.
//!
//!   Under Path A: every byte of `signing.rs`'s API surface
//!   (`SignedRevision`, the Ed25519 `signature` field, `device_id`
//!   semantics as Ed25519 verifying-key bytes, `build_signed_revision`,
//!   `verify_signed_revision`) survives unchanged. The contract
//!   verifies the same digest the client builds today.
//!
//! - **Path B — v1 switches to secp256k1 signatures.** Likely on L1
//!   mainnet for cost reasons (`ecrecover` is a 3 000-gas precompile,
//!   ~150x cheaper than the cheapest Solidity Ed25519). Under Path B:
//!   `device_id` semantics change from "Ed25519 verifying-key bytes"
//!   to "secp256k1 EVM-address" (or to a separately-registered key
//!   per-vault), the `signature` field changes type, and the
//!   canonical-hash construction may need re-keying so the digest
//!   binds the secp256k1 identity rather than the Ed25519 one.
//!
//!   Under Path B: the current `signing.rs` API surface is
//!   Path-A-shaped. Path B would require a new
//!   `secp256k1_signing.rs` (or a refactor to a generic `Signer`
//!   trait that abstracts over both primitives), and stored
//!   `SignedRevision` records on disk would need a re-sign before
//!   they could be re-broadcast under v1's verifier.
//!
//! What survives in **both** paths: the canonical-hash structure
//! (keccak256 of fixed-width fields, payload-keccak fed in as a
//! 32-byte digest, versioned domain separator). What survives in
//! **only Path A**: the Ed25519 signature semantics and the current
//! `signing.rs` API. The honest claim is: "the canonical-hash
//! construction transfers; the signature primitive may not".
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
pub mod chain_submit;
pub mod deployments;
pub mod error;
pub mod evm;
pub mod secp256k1_signing;
pub mod signing;
pub mod types;

#[cfg(any(test, feature = "test-utilities"))]
pub mod mock;

pub use adapter::ChainAdapter;
pub use base_sepolia::{BaseSepoliaAdapter, BASE_SEPOLIA_CHAIN_ID};
pub use chain_submit::{
    publish_revision_v1, ChainAnchorV1, MAX_FEE_PER_GAS_CAP_WEI, PRIORITY_FEE_DEFAULT_WEI,
    PUBLISH_REVISION_BACKOFF_MS, PUBLISH_REVISION_MAX_RETRIES, RECEIPT_TIMEOUT_SECS,
};
pub use deployments::{load_deployed_address, ChainEnv};
pub use error::ChainError;
pub use evm::{derive_evm_address, derive_evm_wallet, EvmWallet};
pub use secp256k1_signing::{
    build_signed_revision_v1, RevisionFieldsV1, SignedRevisionV1, DOMAIN_SEPARATOR_BASE_SEPOLIA_V1,
    EXPECTED_DEPLOYED_ADDRESS_BASE_SEPOLIA, REVISION_TYPEHASH_V1, SIGNED_REVISION_DOMAIN_V1,
};
pub use signing::{
    build_signed_revision, canonical_hash, verify_signed_revision, SignatureInvalid,
};
pub use types::{ChainAnchor, EventLocation, RevisionEvent, SignedRevision, VaultId};

#[cfg(any(test, feature = "test-utilities"))]
pub use mock::MockChainAdapter;

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
