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

use alloy::primitives::{Address, B256, U256};
use thiserror::Error;

use crate::deployments::ChainEnv;

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

    /// **MVP-2 issue 3.1 (R-c).** A deployment file expected to exist
    /// at `contracts/deployments/<env>.json` is missing, OR the file
    /// is present but does not list the requested `<contract_name>`
    /// under `.contracts.<contract_name>.address`.
    ///
    /// Fail-closed posture: the v1 EIP-712 signing path refuses to
    /// produce a signature against an unknown `verifyingContract`.
    /// Distinct from [`Self::DeploymentParseError`] so callers can
    /// distinguish "deployment never recorded" from "deployment file
    /// present but malformed".
    #[error("deployment file or contract entry not found: env={env:?}, contract={contract_name}")]
    DeploymentNotFound {
        /// Which env was looked up.
        env: ChainEnv,
        /// Which contract name was requested.
        contract_name: String,
    },

    /// **MVP-2 issue 3.1 (R-c).** The deployment file at
    /// `contracts/deployments/<env>.json` is present but its JSON
    /// content is malformed, OR the recorded address string does not
    /// parse as a hex `Address`. The wrapped `source` is the upstream
    /// error message; never carries secret material (deployment files
    /// are public artifacts).
    #[error("deployment file parse error: env={env:?}, source={detail}")]
    DeploymentParseError {
        /// Which env was looked up.
        env: ChainEnv,
        /// Upstream error description.
        detail: String,
    },

    /// **MVP-2 issue 3.1 (L-domain-binding defense).** The runtime
    /// address loaded via [`crate::deployments::load_deployed_address`]
    /// disagrees with the pinned-at-source `EXPECTED_DEPLOYED_ADDRESS_*`
    /// constant inside the signing primitive. Either the JSON file was
    /// tampered (deployment redirected to an attacker's contract) or
    /// the binary was built against a stale pinned constant after a
    /// legitimate redeploy. Either way the signer refuses to produce a
    /// signature that would bind to the wrong `verifyingContract` —
    /// see L-domain-binding in `docs/issue-plans/3.1.md` for the
    /// worst-case adversary leverage this defends against (permanent
    /// self-bootstrap-capture of the wrong device).
    #[error(
        "deployment address mismatch: env={env:?}, expected={expected}, actual={actual}; \
         pinned constant and on-disk deployment must agree"
    )]
    DeploymentAddressMismatch {
        /// Which env was looked up.
        env: ChainEnv,
        /// The address pinned in source (the
        /// `EXPECTED_DEPLOYED_ADDRESS_*` constant).
        expected: Address,
        /// The address loaded from the on-disk deployment file.
        actual: Address,
    },

    /// **MVP-2 issue 3.3 (R-c retry taxonomy).** The RPC's reported
    /// `eth_chainId` did not match the chain id this build is bound to
    /// (e.g., Base Sepolia `84_532`). Distinct from
    /// [`Self::WrongChain`] which the v0 adapter raises against the
    /// JSON file's recorded `chain_id`; this variant fires from the
    /// v1 direct-submit transport's pre-broadcast cross-check against
    /// [`crate::deployments::ChainEnv::chain_id()`].
    #[error("chain id mismatch (v1 transport): expected {expected}, observed {observed}")]
    ChainIdMismatch {
        /// Chain id this build expects (from `ChainEnv::chain_id`).
        expected: u64,
        /// Chain id reported by the connected RPC.
        observed: u64,
    },

    /// **MVP-2 issue 3.3 (R-c retry taxonomy).** The device wallet has
    /// insufficient ETH to pay for the transaction. Fatal — never
    /// retried — so the operator knows to top up the wallet before
    /// re-attempting. Carries the wallet's currently-observed balance
    /// (best effort; may be `None` if the RPC's error message did not
    /// surface a balance number).
    #[error("insufficient funds in device wallet: {message}")]
    InsufficientFunds {
        /// Best-effort balance observed at the time of the failed
        /// submission, in wei. `None` if the RPC error did not
        /// surface a numeric balance.
        observed: Option<U256>,
        /// Upstream RPC error message verbatim (no secret material —
        /// it includes the wallet's public address + the requested gas
        /// cost only).
        message: String,
    },

    /// **MVP-2 issue 3.3 (R-c retry taxonomy + 3.3 audit-LOW#2
    /// split).** The tx mined but the receipt's `status` flag was 0
    /// (the contract reverted on-chain). The decoded revert reason is
    /// a best-effort English string; the `tx_hash` is always populated
    /// so the operator can look up the reverting tx on an explorer.
    ///
    /// Distinct from [`Self::RevertedPreBroadcast`] (estimate-gas
    /// revert before the tx ever broadcast) — that path has no
    /// `tx_hash`. The audit-LOW#2 fix (2026-05-14) split a single
    /// `RevertedV1 { reason, tx_hash: B256 }` variant in two so the
    /// pre-broadcast path no longer carries a `tx=0x000...0` in its
    /// operator-facing message.
    ///
    /// Distinct from the v0 [`Self::Reverted`] variant — this one
    /// carries a typed `tx_hash` (B256) and a decoded `reason`,
    /// where v0's variant stringifies the tx hash and has no reason
    /// field. Both variants exist because v0's adapter is the legacy
    /// path; the v1 transport produces this richer form.
    #[error("revision tx reverted on-chain: reason={reason}, tx={tx_hash}")]
    RevertedOnChain {
        /// Decoded revert reason (best effort). Examples:
        /// `"ErrInvalidSignature"`, `"ErrSignerNotRegistered"`,
        /// `"ErrUnsupportedSchemaVersion"`, `"OutOfGas"`,
        /// `"unknown revert"`.
        reason: String,
        /// 32-byte tx hash so the operator can look it up on Base
        /// Sepolia's explorer.
        tx_hash: B256,
    },

    /// **MVP-2 issue 3.3 (R-c retry taxonomy + 3.3 audit-LOW#2
    /// split).** The `eth_estimateGas` simulation reverted BEFORE the
    /// tx was broadcast. The decoded revert reason is a best-effort
    /// English string; no `tx_hash` is reported because nothing was
    /// ever sent to the mempool.
    ///
    /// Pre-MVP-2 the broadcast layer collapsed both pre- and post-
    /// broadcast reverts into a single `RevertedV1 { reason, tx_hash:
    /// B256 }` variant; the pre-broadcast path carried `tx_hash =
    /// B256::ZERO`, which surfaced as a confusing `tx=0x000...0` in
    /// the operator-facing error message. The audit-LOW#2 fix splits
    /// the variants so the no-tx case is typed as such.
    #[error("revision tx reverted pre-broadcast (estimate-gas): reason={reason}")]
    RevertedPreBroadcast {
        /// Decoded revert reason (best effort). Same alphabet as
        /// [`Self::RevertedOnChain::reason`].
        reason: String,
    },

    /// **MVP-2 issue 3.3 (R-b gas-cap defense; L6).** The computed
    /// `maxFeePerGas` exceeded the build's per-tx hard cap (50 gwei).
    /// Fatal — never retried. Defends against a malicious RPC that
    /// reports a huge `baseFeePerGas` (L-gas-griefing).
    #[error(
        "gas-cap exceeded: computed max_fee_per_gas {observed_gwei} gwei exceeds \
         hard cap {cap_gwei} gwei"
    )]
    GasCapExceeded {
        /// Computed `maxFeePerGas`, converted to gwei for display.
        observed_gwei: u64,
        /// Per-tx hard cap, in gwei (50 for MVP-2).
        cap_gwei: u64,
    },

    /// **MVP-2 issue 3.3 (R-c retry taxonomy).** Nonce-collision
    /// retries were exhausted (3 attempts). Fatal — surface to the
    /// operator so they can manually replace via `cast` or a wallet
    /// UI.
    #[error("nonce unresolvable after {attempts} retries")]
    NonceUnresolvable {
        /// Number of attempts made before giving up (always 3 for
        /// MVP-2).
        attempts: u8,
    },

    /// **MVP-2 issue 3.3 (L-rpc-spoof defense).** The decoded
    /// `RevisionPublished` event's `signer` field disagreed with the
    /// wallet's EVM address — the malicious-RPC defense kicked in.
    /// Fatal — never retried.
    #[error(
        "receipt mismatch: RevisionPublished log signer={observed_signer} \
         disagrees with submitter wallet={expected_signer}"
    )]
    ReceiptMismatch {
        /// Wallet address that submitted the tx.
        expected_signer: Address,
        /// Signer address decoded from the on-receipt
        /// `RevisionPublished` log.
        observed_signer: Address,
    },

    /// **MVP-2 issue 3.3 (R-c retry taxonomy).** The RPC transport
    /// failed repeatedly (timeout, 5xx, connection reset). Exhausted
    /// retries with exponential backoff. Surfaces the upstream error
    /// message and the attempt count.
    #[error("RPC transport transient error (exhausted {attempts} retries): {message}")]
    RpcTransient {
        /// Upstream alloy transport error description. Named
        /// `message` (not `source`) because `thiserror` reserves the
        /// `source` field name for `std::error::Error::source()` —
        /// alloy's transport error is already string-formatted by
        /// the call site, so there is no chained source to expose.
        message: String,
        /// Number of attempts made before giving up.
        attempts: u8,
    },
}
