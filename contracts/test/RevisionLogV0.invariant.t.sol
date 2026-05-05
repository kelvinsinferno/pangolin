// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.24;

import {Test, Vm} from "forge-std/Test.sol";
import {RevisionLogV0} from "../src/RevisionLogV0.sol";

/// @notice Handler the Foundry invariant runner uses to drive the
///         contract under random call sequences.
///
/// @dev Tracks how many times `publishRevision` succeeded, so the
///      "event count == sequence" invariant can compare without
///      having to parse logs. Also captures every emitted log's
///      topic0 so `invariant_onlyRevisionPublishedEventEmitted`
///      can assert event-surface immutability across the run.
///
/// @dev Audit fix M-2: this handler uses `vm.assume(...)` instead of
///      an early-`return` for out-of-bounds inputs so the run count
///      stays clean under `fail_on_revert = true`.
contract RevisionLogV0Handler is Test {
    RevisionLogV0 public immutable REV_LOG;
    uint256 public publishCount;
    uint256 public lastSequence;
    bool public lastSequenceSet;

    /// @dev Event topic0 hashes captured across every handler call.
    ///      An invariant inspects this array to assert that the
    ///      contract has only ever emitted `RevisionPublished`.
    bytes32[] internal capturedTopic0;

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
        // Bound payload to <= 1024 bytes to keep fuzz runs fast. Under
        // `fail_on_revert = true` we use `vm.assume` (audit fix M-2):
        // the runner discards the call without it counting as a revert
        // or polluting the run statistics.
        vm.assume(encPayload.length <= 1024);

        // Start recording emitted events for this call. We then read
        // them back via `vm.getRecordedLogs()` to capture topic0s for
        // `invariant_onlyRevisionPublishedEventEmitted`.
        vm.recordLogs();
        uint256 seq = REV_LOG.publishRevision(
            vaultId, accountId, parentRevision, deviceId, schemaVersion, encPayload
        );
        Vm.Log[] memory entries = vm.getRecordedLogs();
        for (uint256 i = 0; i < entries.length; i++) {
            // Only inspect logs emitted by the contract under test;
            // ignore any helper/test-runner logs that may sit in the
            // same recording buffer.
            if (entries[i].emitter == address(REV_LOG)) {
                require(entries[i].topics.length > 0, "handler: log without topic0");
                capturedTopic0.push(entries[i].topics[0]);
            }
        }

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

    function capturedTopic0Length() external view returns (uint256) {
        return capturedTopic0.length;
    }

    function capturedTopic0At(uint256 i) external view returns (bytes32) {
        return capturedTopic0[i];
    }
}

/// @title RevisionLogV0 invariant tests
/// @notice Maps 1:1 to the invariant table in docs/issue-plans/P5-1.md.
///         Configured to run with `--invariant-runs 10000` in CI.
contract RevisionLogV0InvariantTest is Test {
    RevisionLogV0 internal revLog;
    RevisionLogV0Handler internal handler;

    uint256 internal lastSeenNextSequence;

    /// @dev Pre-computed `keccak256("RevisionPublished(bytes32,bytes32,bytes32,bytes32,uint8,uint256,bytes)")`.
    ///      Verified offline via `cast keccak`. If the contract's event
    ///      signature ever changes, this constant must be updated and
    ///      the change reviewed — that is the whole point of pinning
    ///      it as a test-side constant. Audit gap-6.
    bytes32 internal constant REVISION_PUBLISHED_TOPIC0 =
        0x6562412104cd03f86bf4f5184aa68e9d47cdb237b31b1de9d2fe1904eddcae8f;

    function setUp() public {
        revLog = new RevisionLogV0();
        handler = new RevisionLogV0Handler(revLog);

        // Restrict the invariant runner to call ONLY the handler. This
        // ensures every `publishRevision` goes through our counting
        // path, and the runner doesn't try to call the public
        // `nextSequence()` getter as a state-mutator.
        targetContract(address(handler));

        // Audit fix M-1: seed multiple distinct sender addresses so
        // the runner exercises the no-caller-restriction property of
        // v0 across many `msg.sender` values rather than the default
        // single fuzzed sender. v0 has no caller check, so the choice
        // of sender does not matter for correctness, but rotating
        // senders broadens fuzz coverage of the handler call path.
        targetSender(address(0xA11CE));
        targetSender(address(0xB0B));
        targetSender(address(0xCAFE));
        targetSender(address(0xDEADBEEF));
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
    ///
    /// @dev Audit fix M-1: in addition to the linear slots 1..31, we
    ///      probe a deterministic sample of *hashed* slots — the
    ///      address scheme Solidity uses for `mapping(K => V)` storage.
    ///      v0 has no mappings, but v1 will, and this future-proofs
    ///      the invariant: a mapping slot accidentally introduced
    ///      under v0 (e.g., by a forgotten test edit) would be caught
    ///      here. We use a small fixed sample to keep the test fast.
    function invariant_noStorageMutationBesidesSequence() public view {
        // Linear slots 1..31.
        for (uint256 slot = 1; slot < 32; slot++) {
            bytes32 v = vm.load(address(revLog), bytes32(slot));
            assertEq(v, bytes32(0), "non-zero storage outside slot 0");
        }

        // Hashed slots: keccak256(abi.encode(key, slotIndex)) for a
        // deterministic, small (12-element) sample of (key, slot)
        // combos. The keys are arbitrary but include zero-key,
        // common test-fuzz constants, and a couple of high-entropy
        // values so a misuse is more likely to land here.
        bytes32[3] memory keys =
            [bytes32(0), keccak256("vault-1"), keccak256(abi.encode(address(0xBEEF), uint256(1)))];
        uint256[4] memory slotIndices = [uint256(0), uint256(1), uint256(2), uint256(7)];
        for (uint256 ki = 0; ki < keys.length; ki++) {
            for (uint256 si = 0; si < slotIndices.length; si++) {
                bytes32 hashedSlot = keccak256(abi.encode(keys[ki], slotIndices[si]));
                bytes32 v = vm.load(address(revLog), hashedSlot);
                assertEq(v, bytes32(0), "non-zero storage at hashed mapping-style slot");
            }
        }
    }

    /// @dev Audit gap-6: assert that across the entire fuzzed run,
    ///      the contract has only ever emitted `RevisionPublished`.
    ///      Catches a regression where someone adds a second event
    ///      type (which would silently change the on-chain interface
    ///      that clients filter against).
    function invariant_onlyRevisionPublishedEventEmitted() public view {
        uint256 n = handler.capturedTopic0Length();
        for (uint256 i = 0; i < n; i++) {
            assertEq(
                handler.capturedTopic0At(i),
                REVISION_PUBLISHED_TOPIC0,
                "unexpected event topic0 (only RevisionPublished is allowed)"
            );
        }
    }
}
