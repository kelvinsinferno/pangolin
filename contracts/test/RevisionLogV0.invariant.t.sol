// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {RevisionLogV0} from "../src/RevisionLogV0.sol";

/// @notice Handler the Foundry invariant runner uses to drive the
///         contract under random call sequences.
///
/// @dev Tracks how many times `publishRevision` succeeded, so the
///      "event count == sequence" invariant can compare without
///      having to parse logs.
contract RevisionLogV0Handler is Test {
    RevisionLogV0 public immutable REV_LOG;
    uint256 public publishCount;
    uint256 public lastSequence;
    bool public lastSequenceSet;

    constructor(RevisionLogV0 log_) {
        REV_LOG = log_;
    }

    /// @notice Fuzz-target. The runner picks random arg values; we
    ///         forward them to `publishRevision` and record the result.
    ///
    /// @dev We bound `payloadLen` to keep gas-per-run reasonable; the
    ///      contract itself imposes no length cap and the unit tests
    ///      cover the 4 KB case explicitly.
    function publishRevision(
        bytes32 vaultId,
        bytes32 accountId,
        bytes32 parentRevision,
        bytes32 deviceId,
        uint8 schemaVersion,
        bytes calldata encPayload
    ) external {
        // Bound payload to <= 1024 bytes to keep fuzz runs fast.
        if (encPayload.length > 1024) {
            return;
        }
        uint256 seq = REV_LOG.publishRevision(
            vaultId, accountId, parentRevision, deviceId, schemaVersion, encPayload
        );
        // Local invariant (not strictly tested below, but a useful
        // sanity check during fuzzing): `publishRevision` should
        // always return the pre-increment sequence value.
        if (lastSequenceSet) {
            require(seq == lastSequence + 1, "handler: sequence not pre-increment");
        }
        lastSequence = seq;
        lastSequenceSet = true;
        unchecked {
            publishCount += 1;
        }
    }
}

/// @title RevisionLogV0 invariant tests
/// @notice Maps 1:1 to the invariant table in docs/issue-plans/P5-1.md.
///         Configured to run with `--invariant-runs 10000` in CI.
contract RevisionLogV0InvariantTest is Test {
    RevisionLogV0 internal revLog;
    RevisionLogV0Handler internal handler;

    uint256 internal lastSeenNextSequence;

    function setUp() public {
        revLog = new RevisionLogV0();
        handler = new RevisionLogV0Handler(revLog);

        // Restrict the invariant runner to call ONLY the handler. This
        // ensures every `publishRevision` goes through our counting
        // path, and the runner doesn't try to call the public
        // `nextSequence()` getter as a state-mutator.
        targetContract(address(handler));
    }

    /// @dev Maps to plan invariant: invariant_sequenceMonotonic.
    /// @dev `nextSequence` may only ever go up. Forge runs this after
    ///      every fuzzed handler call sequence; we track the last
    ///      observed value across runs in a contract-storage variable
    ///      so a regression would be caught even between runs.
    function invariant_sequenceMonotonic() public {
        uint256 current = revLog.nextSequence();
        assertGe(current, lastSeenNextSequence, "nextSequence must be monotonic");
        lastSeenNextSequence = current;
    }

    /// @dev Maps to plan invariant: invariant_eventCountEqualsSequence.
    /// @dev The number of successful `publishRevision` calls (counted
    ///      in the handler) must equal `nextSequence`. There must be
    ///      no path that bumps the sequence without emitting an
    ///      event, and no path that emits without bumping.
    function invariant_eventCountEqualsSequence() public view {
        assertEq(
            revLog.nextSequence(),
            handler.publishCount(),
            "nextSequence must equal successful publish count"
        );
    }

    /// @dev Maps to plan invariant: invariant_noStorageMutationBesidesSequence.
    /// @dev Probe the first 32 storage slots and assert that all slots
    ///      other than slot 0 (where `nextSequence` lives) remain zero.
    ///      v0 has only one declared storage variable; if a future
    ///      change accidentally introduces another, this catches it.
    function invariant_noStorageMutationBesidesSequence() public view {
        for (uint256 slot = 1; slot < 32; slot++) {
            bytes32 v = vm.load(address(revLog), bytes32(slot));
            assertEq(v, bytes32(0), "non-zero storage outside slot 0");
        }
    }
}
