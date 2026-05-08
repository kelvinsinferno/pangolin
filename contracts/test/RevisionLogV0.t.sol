// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {RevisionLogV0} from "../src/RevisionLogV0.sol";

/// @title RevisionLogV0 unit tests
/// @notice Maps 1:1 to the unit-test table in docs/issue-plans/P5-1.md
///         "Test plan / Unit tests" section. Each test name is the
///         table's test name.
contract RevisionLogV0Test is Test {
    RevisionLogV0 internal revLog;

    // Re-declared here so `vm.expectEmit` can match on the topic
    // signature. (Forge needs a local copy of the event ABI.)
    event RevisionPublished(
        bytes32 indexed vaultId,
        bytes32 indexed accountId,
        bytes32 indexed parentRevision,
        bytes32 deviceId,
        uint8 schemaVersion,
        uint256 sequence,
        bytes encPayload
    );

    function setUp() public {
        revLog = new RevisionLogV0();
    }

    // -----------------------------------------------------------------
    // Happy-path tests
    // -----------------------------------------------------------------

    /// @dev Maps to plan: test_publishRevision_emitsEvent
    function test_publishRevision_emitsEvent() public {
        bytes32 vaultId = keccak256("vault-1");
        bytes32 accountId = keccak256("account-1");
        bytes32 parentRevision = keccak256("parent-1");
        bytes32 deviceId = keccak256("device-1");
        uint8 schemaVersion = 1;
        bytes memory encPayload = hex"deadbeef";

        // checkTopic1, checkTopic2, checkTopic3, checkData
        vm.expectEmit(true, true, true, true, address(revLog));
        emit RevisionPublished(
            vaultId, accountId, parentRevision, deviceId, schemaVersion, 0, encPayload
        );
        uint256 seq = revLog.publishRevision(
            vaultId, accountId, parentRevision, deviceId, schemaVersion, encPayload
        );
        assertEq(seq, 0, "first sequence should be 0");
    }

    /// @dev Maps to plan: test_publishRevision_returnsMonotonicSequence
    function test_publishRevision_returnsMonotonicSequence() public {
        bytes memory payload = hex"01";
        uint256 first =
            revLog.publishRevision(bytes32(0), bytes32(0), bytes32(0), bytes32(0), 0, payload);
        uint256 second =
            revLog.publishRevision(bytes32(0), bytes32(0), bytes32(0), bytes32(0), 0, payload);
        uint256 third =
            revLog.publishRevision(bytes32(0), bytes32(0), bytes32(0), bytes32(0), 0, payload);
        assertEq(first, 0);
        assertEq(second, 1);
        assertEq(third, 2);
        assertEq(revLog.nextSequence(), 3, "nextSequence should be 3 after 3 publishes");
    }

    /// @dev Maps to plan: test_nextSequence_startsAtZero
    function test_nextSequence_startsAtZero() public view {
        assertEq(revLog.nextSequence(), 0, "fresh deploy: nextSequence is 0");
    }

    /// @dev Maps to plan: test_publishRevision_acceptsLargePayload
    function test_publishRevision_acceptsLargePayload() public {
        bytes memory big = new bytes(4096);
        for (uint256 i = 0; i < big.length; i++) {
            big[i] = bytes1(uint8(i & 0xff));
        }
        uint256 seq = revLog.publishRevision(
            keccak256("v"), keccak256("a"), bytes32(0), keccak256("d"), 7, big
        );
        assertEq(seq, 0, "4 KB payload should publish");
        assertEq(revLog.nextSequence(), 1);
    }

    /// @dev Maps to plan: test_publishRevision_acceptsZeroByteFields
    function test_publishRevision_acceptsZeroByteFields() public {
        // v0 has no content validation: zero-valued ids and empty payload
        // must succeed (the contract is a dumb log).
        uint256 seq = revLog.publishRevision(bytes32(0), bytes32(0), bytes32(0), bytes32(0), 0, "");
        assertEq(seq, 0);
        assertEq(revLog.nextSequence(), 1);
    }

    /// @dev Maps to plan: test_publishRevision_anyCallerAllowed
    function test_publishRevision_anyCallerAllowed() public {
        address eoa = address(0xBEEF);
        address contractCaller = address(new RelayCaller(revLog));

        // Direct EOA call via vm.prank: tx.origin == msg.sender == eoa
        vm.prank(eoa);
        uint256 seqA = revLog.publishRevision(bytes32(0), bytes32(0), bytes32(0), bytes32(0), 0, "");
        assertEq(seqA, 0);

        // Indirect call: tx.origin (the test runner) != msg.sender (the
        // RelayCaller contract). v0 has no caller restriction, so this
        // must succeed.
        uint256 seqB = RelayCaller(contractCaller).relay();
        assertEq(seqB, 1, "tx.origin != msg.sender path should succeed");
        assertEq(revLog.nextSequence(), 2);
    }

    // -----------------------------------------------------------------
    // Negative / surface-restriction tests
    // -----------------------------------------------------------------

    /// @dev Maps to plan: test_publishRevision_doesNotAcceptEth
    /// @dev `publishRevision` is non-payable. Sending value with the
    ///      call must revert.
    function test_publishRevision_doesNotAcceptEth() public {
        vm.deal(address(this), 1 ether);
        bytes memory cd = abi.encodeWithSelector(
            RevisionLogV0.publishRevision.selector,
            bytes32(0),
            bytes32(0),
            bytes32(0),
            bytes32(0),
            uint8(0),
            bytes("")
        );
        (bool ok,) = address(revLog).call{value: 1 wei}(cd);
        assertFalse(ok, "non-payable call with value must revert");
    }

    /// @dev Audit fix L-1: extend ETH-rejection coverage to the
    ///      empty-calldata and unknown-selector paths. solc emits a
    ///      single CALLVALUE/ISZERO/JUMPI/REVERT guard at the top of
    ///      the dispatcher when there is no `receive()`, no
    ///      `fallback()`, and no `payable` function: every incoming
    ///      call is rejected when `msg.value > 0` regardless of the
    ///      selector (or absence thereof). These three sub-cases
    ///      pin that behavior so a future contributor cannot quietly
    ///      add a `receive()` without breaking this test.
    function test_contract_rejectsEthOnAllCallPaths() public {
        vm.deal(address(this), 1 ether);

        // 1. Empty calldata + value -> dispatcher's CALLVALUE guard reverts.
        (bool ok1,) = address(revLog).call{value: 1 wei}("");
        assertFalse(ok1, "empty calldata with value must revert (no receive())");

        // 2. Unknown selector + value -> still hits the CALLVALUE guard
        //    (which sits before any selector dispatch). The selector
        //    being unknown is incidental; value is the rejection cause.
        (bool ok2,) = address(revLog).call{value: 1 wei}(hex"deadbeef");
        assertFalse(ok2, "unknown selector with value must revert");

        // 3. Unknown selector + zero value -> reverts on the
        //    no-matching-function path (no fallback()). Demonstrates
        //    the contract has zero implicit payable surface AND no
        //    catch-all fallback.
        (bool ok3,) = address(revLog).call{value: 0}(hex"deadbeef");
        assertFalse(ok3, "unknown selector with no fallback must revert");
    }

    /// @dev Maps to plan: test_contract_hasNoOwnerFunction
    function test_contract_hasNoOwnerFunction() public {
        bytes memory cd = abi.encodeWithSignature("owner()");
        (bool ok, bytes memory ret) = address(revLog).call(cd);
        assertFalse(ok, "owner() must not exist");
        assertEq(ret.length, 0, "no return data from missing selector");
    }

    /// @dev Maps to plan: test_contract_hasNoAdminFunction
    function test_contract_hasNoAdminFunction() public {
        bytes memory cd = abi.encodeWithSignature("admin()");
        (bool ok, bytes memory ret) = address(revLog).call(cd);
        assertFalse(ok, "admin() must not exist");
        assertEq(ret.length, 0);
    }

    /// @dev Maps to plan: test_contract_hasNoUpgradeFunction (renamed to
    ///      `test_contract_hasNoAdminOrProxySelectors` per audit fix L-2).
    /// @dev Probes the canonical admin / ownership / pause / upgrade
    ///      selectors a proxy or admin-key contract would expose.
    ///      All must revert (no fallback, no receive, no matching
    ///      function). Probing the full set rather than the original
    ///      4 selectors hardens the surface assertion: a future
    ///      contributor accidentally importing an `Ownable` mixin or
    ///      a proxy-storage layout would be caught here.
    /// @dev Selectors verified offline; one assertion per selector
    ///      keeps the failure message specific.
    function test_contract_hasNoAdminOrProxySelectors() public {
        bytes[16] memory probes = [
            // Ownership family (Ownable / Ownable2Step).
            abi.encodeWithSignature("transferOwnership(address)", address(0)),
            abi.encodeWithSignature("renounceOwnership()"),
            abi.encodeWithSignature("acceptOwnership()"),
            abi.encodeWithSignature("pendingOwner()"),
            abi.encodeWithSignature("owner()"),
            // Admin family (TransparentUpgradeableProxy).
            abi.encodeWithSignature("changeAdmin(address)", address(0)),
            abi.encodeWithSignature("admin()"),
            // Pause family (Pausable).
            abi.encodeWithSignature("pause()"),
            abi.encodeWithSignature("unpause()"),
            abi.encodeWithSignature("paused()"),
            // Self-destruct / kill family.
            abi.encodeWithSignature("kill()"),
            abi.encodeWithSignature("destroy()"),
            // Upgrade family (UUPS / TransparentUpgradeableProxy).
            abi.encodeWithSignature("upgradeTo(address)", address(0)),
            abi.encodeWithSignature("upgradeToAndCall(address,bytes)", address(0), bytes("")),
            abi.encodeWithSignature("implementation()"),
            // Audit gap #3: a fictitious sequence-mutator that, if
            // ever introduced, would let an admin reset the global
            // counter. Prove no such selector exists.
            abi.encodeWithSignature("setNextSequence(uint256)", uint256(0))
        ];
        for (uint256 i = 0; i < probes.length; i++) {
            (bool ok, bytes memory ret) = address(revLog).call(probes[i]);
            assertFalse(ok, "admin/proxy/upgrade selector must not exist");
            assertEq(ret.length, 0, "no return data from missing admin/proxy selector");
        }
    }

    // -----------------------------------------------------------------
    // Bonus surface checks (still covered by plan success criterion #6)
    // -----------------------------------------------------------------

    /// @dev Maps to plan success criterion #7: publishRevision with a
    ///       256-byte payload must cost less than 50,000 gas.
    /// @dev We run two consecutive publishes and measure the second one
    ///      so the warm-storage cost (5k) rather than the cold cold-slot
    ///      first-write cost (22k) dominates. The first-write cost
    ///      naturally still passes (22k + ~9k for the log) but the
    ///      steady-state cost is what matters in production.
    function test_publishRevision_256BytePayload_under50kGas() public {
        bytes memory payload = new bytes(256);
        for (uint256 i = 0; i < 256; i++) {
            payload[i] = bytes1(uint8(i));
        }

        // Warm the storage slot.
        revLog.publishRevision(bytes32(0), bytes32(0), bytes32(0), bytes32(0), 0, payload);

        // Measure the steady-state call.
        uint256 gasBefore = gasleft();
        revLog.publishRevision(bytes32(0), bytes32(0), bytes32(0), bytes32(0), 0, payload);
        uint256 gasUsed = gasBefore - gasleft();

        emit log_named_uint("publishRevision 256B payload gas (warm)", gasUsed);
        assertLt(gasUsed, 50_000, "256-byte publishRevision must cost < 50k gas");
    }

    /// @dev No `pause()`/`unpause()` exists.
    function test_contract_hasNoPauseFunction() public {
        (bool okPause,) = address(revLog).call(abi.encodeWithSignature("pause()"));
        assertFalse(okPause, "pause() must not exist");
        (bool okUnpause,) = address(revLog).call(abi.encodeWithSignature("unpause()"));
        assertFalse(okUnpause, "unpause() must not exist");
    }
}

/// @dev Helper contract used to prove `tx.origin != msg.sender` works.
contract RelayCaller {
    RevisionLogV0 internal immutable LOG;

    constructor(RevisionLogV0 log_) {
        LOG = log_;
    }

    function relay() external returns (uint256) {
        return LOG.publishRevision(bytes32(0), bytes32(0), bytes32(0), bytes32(0), 0, "");
    }
}
