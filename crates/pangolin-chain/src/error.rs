//! Error taxonomy for the chain adapter.
//!
//! Every variant is hand-classified into one of four families:
//!
//! 1. **Configuration** — the adapter was constructed with a deployment
//!    file, RPC URL, or device key that doesn't match the chain we
//!    expect. Fail-closed: refuse to talk to a foreign contract.
//! 2. **RPC transport** — the network call itself failed (timeout, 5xx,
//!    JSON shape mismatch). Not a security failure; surface for retry.
//! 3. **Decode** — alloy returned a structurally-bad response. Could be
//!    a misbehaving RPC; could be a bug in our typed binding. Either
//!    way, refuse to silently accept attacker-controlled bytes.
//! 4. **Wallet / Signing** — the device key can't be turned into a
//!    valid secp256k1 scalar (vanishingly rare; happens when the HKDF
//!    output is exactly the curve order, which the derivation handles
//!    by re-deriving with a counter, but if even that fails we error).
//!
//! ## `Debug`/`Display` discipline
//!
//! Audit MEDIUM (P7 plan §"Security-critical?"): no variant carries
//! secret material in its `Display` or `Debug` form. The `Rpc` variant
//! wraps an `alloy::transports::TransportError` whose `Display`
//! includes the URL but never the request body or wallet address; we
//! propagate that as-is. The `Wallet` family carries only a fixed
//! string description.

use thiserror::Error;

/// Errors returned by [`crate::ChainAdapter`] methods and constructor
/// helpers.
///
/// `non_exhaustive` so future variants can be added without breaking
/// downstream `match` arms. Pattern-matching consumers should always
/// include a `_ =>` fallback per Rust API guidelines.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ChainError {
    /// The deployment file's `chain_id` did not match the chain the RPC
    /// reports. Fail-closed: the adapter refuses to broadcast a
    /// transaction to the wrong chain.
    #[error("chain_id mismatch: deployment expects {expected}, RPC reports {observed}")]
    WrongChain {
        /// `chain_id` from `contracts/deployments/base-sepolia.json`.
        expected: u64,
        /// `chain_id` returned by `eth_chainId`.
        observed: u64,
    },

    /// Construction-time error: the deployment file at the given path
    /// could not be loaded (missing, malformed JSON, missing fields,
    /// missing ABI file). The wrapped string is the detailed message
    /// from the upstream loader; it never carries secret material.
    #[error("deployment file load failed: {0}")]
    Deployment(String),

    /// RPC call failed at the transport layer. The wrapped error is the
    /// alloy transport error, whose `Display` is itself
    /// secret-material-free (URL + status code + parse error, no
    /// request body).
    #[error("RPC transport error: {0}")]
    Rpc(String),

    /// alloy returned a response that did not decode as the expected
    /// shape (e.g., the `RevisionPublished` log topics don't match,
    /// the `sequence` field doesn't fit in `u64`). Could be a
    /// misbehaving RPC — refuse to silently accept.
    #[error("response decoding failed: {0}")]
    Decode(String),

    /// The transaction broadcast succeeded but the receipt's status
    /// flag was 0 (the tx reverted on-chain). Out-of-gas, contract
    /// `require()` failure, etc.
    #[error("transaction reverted: tx={tx_hash}")]
    Reverted {
        /// 0x-prefixed 32-byte tx hash so the operator can look it up
        /// on the explorer.
        tx_hash: String,
    },

    /// A `RevisionPublished` log was expected on the receipt but none
    /// was found at the contract address. Indicates either a contract
    /// bug or a wrong contract address.
    #[error("expected RevisionPublished log not present in receipt: tx={tx_hash}")]
    MissingEvent {
        /// 0x-prefixed 32-byte tx hash.
        tx_hash: String,
    },

    /// The device key's Ed25519 → secp256k1 derivation failed —
    /// vanishingly rare (the HKDF output landed at the curve order or
    /// zero scalar; the derivation iterates a counter to retry, and
    /// only fails if the counter exhausts the iteration budget).
    #[error("EVM wallet derivation failed: {0}")]
    Wallet(&'static str),

    /// Foundry-keystore decryption failed (wrong password, malformed
    /// keystore file, etc.). Wraps the alloy-signer-local error
    /// message verbatim.
    #[error("keystore decryption failed: {0}")]
    Keystore(String),

    /// Construction-time IO error (e.g., the keystore file isn't
    /// readable). Carries only the `io::ErrorKind` description; the
    /// path is logged at the call site by the adapter.
    #[error("io error: {0}")]
    Io(String),

    /// The runtime bytecode at the deployment file's recorded
    /// contract address does not match the file's recorded
    /// `deployed_runtime_keccak256`. Surfaces from the constructor's
    /// `eth_getCode` cross-check (P7 audit MED-2). Same fail-closed
    /// posture as `WrongChain`: a CREATE2 collision, a tampered
    /// deployment file, or a wrong contract address would all trigger
    /// this; refuse to proceed in any of those cases.
    ///
    /// Both fields are 0x-prefixed 32-byte hex strings so the operator
    /// can paste them into `cast` / a search tool without further
    /// formatting.
    #[error(
        "runtime bytecode keccak mismatch: live RPC reports {found}, \
         deployment file expects {expected}"
    )]
    DeploymentMismatch {
        /// `deployed_runtime_keccak256` from the deployment file.
        expected: String,
        /// keccak256 of the live `eth_getCode` response at the
        /// deployment's contract address, observed at construction
        /// time.
        found: String,
    },

    /// A `SignedRevision` failed signature verification at the
    /// adapter boundary.
    ///
    /// Surfaces from:
    ///
    /// - `MockChainAdapter::publish` (P7 audit MED-4) — the mock
    ///   verifies signatures eagerly so a regression in
    ///   `build_signed_revision` that produces invalid signatures
    ///   fires loudly in tests.
    /// - `BaseSepoliaAdapter::pull_since` / `get_revision` when a
    ///   future v1 contract enforces signatures and returns logs
    ///   bearing them; v0 does not, so this variant is dormant in
    ///   production today.
    ///
    /// Carries no payload by design — the underlying Ed25519
    /// strict-mode verifier collapses every failure cause into a
    /// single sentinel so a timing attacker cannot tell wrong-key
    /// from wrong-message from non-canonical-encoding.
    #[error("signed revision did not verify")]
    SignatureInvalid,
}
