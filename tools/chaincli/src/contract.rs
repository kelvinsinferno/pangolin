//! Compile-time-typed binding for the deployed `RevisionLogV0` contract.
//!
//! Uses `alloy::sol!` to derive the call/event types from a literal
//! Solidity declaration that mirrors `contracts/src/RevisionLogV0.sol`.
//!
//! Why a sol-macro rather than a `JsonAbi`-driven dynamic dispatch:
//!   - Compile-time field-name safety. A typo in a field access becomes
//!     a build error, not a runtime panic.
//!   - The audit surface is the literal Solidity-shaped declaration
//!     here; an auditor can read it side-by-side with the `.sol`
//!     source. The `JsonAbi` we still load in `client.rs` is used by
//!     `commands/status.rs` to verify the deployed ABI matches what
//!     this binding compiles against (no version skew).

use alloy::sol;

sol! {
    /// Mirror of `contracts/src/RevisionLogV0.sol`. Audited 2026-05-05.
    /// MUST stay byte-for-byte aligned with the .sol source — see
    /// `commands/status.rs` which cross-checks the function selectors
    /// against the deployed `contracts/abi/RevisionLogV0.json`.
    #[sol(rpc)]
    contract RevisionLogV0 {
        function nextSequence() external view returns (uint256);

        function publishRevision(
            bytes32 vaultId,
            bytes32 accountId,
            bytes32 parentRevision,
            bytes32 deviceId,
            uint8 schemaVersion,
            bytes calldata encPayload
        ) external returns (uint256 sequence);

        event RevisionPublished(
            bytes32 indexed vaultId,
            bytes32 indexed accountId,
            bytes32 indexed parentRevision,
            bytes32 deviceId,
            uint8 schemaVersion,
            uint256 sequence,
            bytes encPayload
        );
    }
}
