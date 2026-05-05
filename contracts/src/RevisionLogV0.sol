// SPDX-License-Identifier: Apache-2.0
// @dev Exact-pinned pragma (NOT `^0.8.24`): per docs/issue-plans/P5-1.md
//      "Solidity compiler regression" failure-mode mitigation, the
//      contract must build with the exact compiler version it was
//      audited against. A future contributor MUST NOT relax this to a
//      caret range. (Audit fix L-3.)
pragma solidity 0.8.24;

/// @title RevisionLogV0
/// @notice Append-only log of encrypted vault revisions. v0 of the contract
///         performs **zero verification** of payload contents or caller
///         identity. Its sole purpose is to provide durable, ordered,
///         tamper-evident storage of encrypted-revision events that clients
///         can read via `eth_getLogs`.
///
/// @dev Cardinal contract design rules (master plan §0 cardinal principles
///      3 + 4, whitepaper §D1, master plan §2 locked decision):
///        - **No admin keys.** No owner. No role. No multisig.
///        - **No upgrades.** No proxy. No `selfdestruct`. Deploy v2 if v0
///          turns out to be broken.
///        - **No pause / freeze.** Liveness is monotonic.
///        - **Append-only.** The only state is a monotonically increasing
///          sequence counter; every published revision is emitted as event
///          data. The chain is the log; events ARE the storage.
///
/// @dev Cross-chain portability (DECISIONS.md D-005):
///        - Compiled with `evm_version = "shanghai"` so the bytecode runs
///          unchanged on Base, Arbitrum, OP, Polygon and any other EVM
///          chain at Shanghai-or-later. No Base-specific opcodes.
///
/// @dev Future versions:
///        - v1 (MVP-2 issue 2.1) will add signature verification + a
///          "signer must be a registered device key for vaultId" check.
///        - This file is frozen for v0; revisions to v1 will be a
///          new contract in a new file (`RevisionLogV1.sol`).
contract RevisionLogV0 {
    // -----------------------------------------------------------------
    // Events
    // -----------------------------------------------------------------

    /// @notice Emitted on every successful `publishRevision` call.
    ///
    /// @dev Three indexed topics is Solidity's per-event maximum
    ///      (the event signature consumes the fourth topic slot). We
    ///      pick `vaultId`, `accountId`, `parentRevision` because those
    ///      are the filter dimensions clients need:
    ///        - vaultId: "all revisions in this vault"
    ///        - vaultId + accountId: "all revisions for this account"
    ///        - parentRevision: "the child(ren) of this specific parent"
    ///
    /// @dev `deviceId`, `schemaVersion`, `sequence`, and `encPayload` are
    ///      unindexed event data. Filtering on them is rare and can
    ///      happen client-side after `eth_getLogs` decoding.
    event RevisionPublished(
        bytes32 indexed vaultId,
        bytes32 indexed accountId,
        bytes32 indexed parentRevision,
        bytes32 deviceId,
        uint8 schemaVersion,
        uint256 sequence,
        bytes encPayload
    );

    // -----------------------------------------------------------------
    // Storage
    // -----------------------------------------------------------------

    /// @notice Monotonically increasing global sequence number.
    ///
    /// @dev Storage slot 0. The ONLY storage slot this contract uses;
    ///      every other slot is and must remain zero. `invariant_*`
    ///      tests assert this property under fuzzed call sequences.
    ///
    /// @dev `nextSequence` provides a total ordering across all vaults.
    ///      Per-vault head pointers are NOT stored on-chain — clients
    ///      compute the head per `(vaultId, accountId)` from the event
    ///      stream by following the `parentRevision` chain.
    uint256 public nextSequence;

    // -----------------------------------------------------------------
    // External API (the entire public surface)
    // -----------------------------------------------------------------

    /// @notice Publish a new encrypted revision to the log.
    ///
    /// @param vaultId         Application-defined vault identifier
    ///                        (32 bytes; opaque to the contract).
    /// @param accountId       Application-defined per-account identifier
    ///                        within `vaultId` (opaque).
    /// @param parentRevision  The revision id this one descends from
    ///                        (or `bytes32(0)` for a vault genesis).
    ///                        Opaque to the contract; clients compute
    ///                        and verify the chain off-chain.
    /// @param deviceId        Application-defined device identifier
    ///                        for the publishing device (opaque).
    /// @param schemaVersion   Application-defined payload-schema tag
    ///                        so clients can branch on payload format
    ///                        without decrypting first.
    /// @param encPayload      Opaque ciphertext + AEAD metadata. The
    ///                        contract performs **no validation**: not
    ///                        length, not format, not signatures.
    ///                        Garbage inputs cost the publisher gas;
    ///                        no contract-level harm.
    ///
    /// @return sequence       The global sequence number assigned to
    ///                        this revision. Equals `nextSequence` at
    ///                        the time of the call (pre-increment).
    ///
    /// @dev v0 has no `payable` modifier: calls with `value > 0` revert
    ///      automatically. There is no `receive()` or `fallback()`.
    ///      This contract cannot accept ETH through normal means.
    ///
    /// @dev `unchecked` increment: overflow at 2^256 calls is not a
    ///      real-world failure mode and the wraparound check would
    ///      cost gas on every publish.
    function publishRevision(
        bytes32 vaultId,
        bytes32 accountId,
        bytes32 parentRevision,
        bytes32 deviceId,
        uint8 schemaVersion,
        bytes calldata encPayload
    ) external returns (uint256 sequence) {
        sequence = nextSequence;
        unchecked {
            nextSequence = sequence + 1;
        }
        emit RevisionPublished(
            vaultId, accountId, parentRevision, deviceId, schemaVersion, sequence, encPayload
        );
    }
}
