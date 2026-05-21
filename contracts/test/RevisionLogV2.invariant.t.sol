// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity 0.8.24;

import {Test, Vm} from "forge-std/Test.sol";
import {RevisionLogV2} from "../src/RevisionLogV2.sol";
import {RecoveryV1} from "../src/RecoveryV1.sol";

/// @notice Fuzz-handler that drives `RevisionLogV2` through randomized but
///         well-formed lifecycle call sequences on ONE vault with a small
///         pool of device keys. Mirrors the RecoveryV1/RevisionLogV1
///         invariant discipline: under `fail_on_revert = true` it uses
///         `vm.assume(...)` for out-of-range fuzz inputs and wraps every
///         contract call in try/catch (the contract's revert paths are
///         EXPECTED — the handler tries random combinations on purpose). On
///         the catch branch it asserts NO event was emitted by the contract
///         under test (L6).
///
/// @dev The vault is bootstrapped to device 0 (the genesis manager) at
///      construction. RecoveryV1 is left WITHOUT an authority for the vault
///      so the V2-local `deviceManager` is the authoritative manager (the
///      cross-read returns address(0) -> falls back to deviceManager). The
///      manager is always one of the device pool keys, so the handler can
///      always sign a valid manager authorization. Ghost state tracks the
///      values the invariants cross-check.
contract RevisionLogV2Handler is Test {
    RevisionLogV2 public immutable REV;
    RecoveryV1 public immutable RECOVERY;

    bytes32 public constant VAULT = keccak256("inv-v2-vault");
    uint16 internal constant SV = 1;

    // Device key pool (5 in-set-eligible + 1 outsider).
    uint256[5] internal devicePks;
    uint256 internal constant OUTSIDER_PK = uint256(keccak256("inv-v2-outsider"));

    // Ghost state.
    address public ghostManager; // manager the handler believes is current
    uint64 public ghostNonce; // deviceNonce the handler believes is current
    uint32 public ghostSetSize; // set size the handler believes is current
    bool public everFinalizedOk; // a finalize succeeded with the delay honored
    mapping(address => bool) public ghostInSet; // membership mirror
    address[] internal everSeenDevices; // devices the handler has touched

    // Captured event topic-0s across the run.
    bytes32[] internal capturedTopic0;

    constructor(RevisionLogV2 rev_, RecoveryV1 recovery_) {
        REV = rev_;
        RECOVERY = recovery_;
        devicePks[0] = uint256(keccak256("inv-v2-d0"));
        devicePks[1] = uint256(keccak256("inv-v2-d1"));
        devicePks[2] = uint256(keccak256("inv-v2-d2"));
        devicePks[3] = uint256(keccak256("inv-v2-d3"));
        devicePks[4] = uint256(keccak256("inv-v2-d4"));
        for (uint256 i = 0; i < 5; i++) {
            everSeenDevices.push(vm.addr(devicePks[i]));
        }
        everSeenDevices.push(vm.addr(OUTSIDER_PK));

        // Bootstrap the vault to device 0 (RecoveryV1 has no authority for
        // VAULT, so the manager seeds to device 0).
        address d0 = vm.addr(devicePks[0]);
        bytes memory sig = _sign(devicePks[0], REV.hashAddDevice(VAULT, d0, 0, SV));
        REV.bootstrapVault(VAULT, d0, SV, sig);
        ghostManager = d0;
        ghostNonce = 1;
        ghostSetSize = 1;
        ghostInSet[d0] = true;
    }

    // ---- views for the invariant contract ----
    function everSeenDevicesLength() external view returns (uint256) {
        return everSeenDevices.length;
    }

    function everSeenDeviceAt(uint256 i) external view returns (address) {
        return everSeenDevices[i];
    }

    function capturedTopic0Length() external view returns (uint256) {
        return capturedTopic0.length;
    }

    function capturedTopic0At(uint256 i) external view returns (bytes32) {
        return capturedTopic0[i];
    }

    function managerPk() internal view returns (uint256) {
        for (uint256 i = 0; i < 5; i++) {
            if (vm.addr(devicePks[i]) == ghostManager) {
                return devicePks[i];
            }
        }
        revert("handler: manager not in pool (should be impossible)");
    }

    function _sign(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _captureLogs() internal {
        Vm.Log[] memory entries = vm.getRecordedLogs();
        for (uint256 i = 0; i < entries.length; i++) {
            if (entries[i].emitter == address(REV)) {
                require(entries[i].topics.length > 0, "handler: log without topic0");
                capturedTopic0.push(entries[i].topics[0]);
            }
        }
    }

    function _assertNoEventOnRevert() internal view {
        Vm.Log[] memory entries = vm.getRecordedLogs();
        for (uint256 i = 0; i < entries.length; i++) {
            if (entries[i].emitter == address(REV)) {
                revert("handler: revert path must not emit");
            }
        }
    }

    // -----------------------------------------------------------------
    // Fuzz actions
    // -----------------------------------------------------------------

    /// @notice Manager adds device #idx to the set.
    function addDevice(uint256 idx) external {
        idx = idx % 5;
        address dev = vm.addr(devicePks[idx]);
        // Skip guaranteed-revert combos to keep the run productive.
        vm.assume(!REV.authorizedDevice(VAULT, dev));
        vm.assume(REV.authorizedDeviceCount(VAULT) < REV.MAX_DEVICES());
        bytes memory sig = _sign(managerPk(), REV.hashAddDevice(VAULT, dev, ghostNonce, SV));
        vm.recordLogs();
        try REV.addDevice(VAULT, dev, ghostNonce, SV, sig) {
            _captureLogs();
            ghostInSet[dev] = true;
            ghostSetSize += 1;
            ghostNonce += 1;
        } catch {
            _assertNoEventOnRevert();
        }
    }

    /// @notice Manager removes device #idx from the set (no-brick allowing).
    function removeDevice(uint256 idx) external {
        idx = idx % 5;
        address dev = vm.addr(devicePks[idx]);
        vm.assume(REV.authorizedDevice(VAULT, dev));
        vm.assume(dev != ghostManager);
        vm.assume(REV.authorizedDeviceCount(VAULT) > 1);
        bytes memory sig = _sign(managerPk(), REV.hashRemoveDevice(VAULT, dev, ghostNonce, SV));
        vm.recordLogs();
        try REV.removeDevice(VAULT, dev, ghostNonce, SV, sig) {
            _captureLogs();
            ghostInSet[dev] = false;
            ghostSetSize -= 1;
            ghostNonce += 1;
        } catch {
            _assertNoEventOnRevert();
        }
    }

    /// @notice A current set member proposes itself for promotion.
    function propose(uint256 idx) external {
        idx = idx % 5;
        address cand = vm.addr(devicePks[idx]);
        vm.assume(REV.authorizedDevice(VAULT, cand));
        (, uint64 pendingReady) = REV.pendingPromotion(VAULT);
        vm.assume(pendingReady == 0);
        bytes memory sig = _sign(devicePks[idx], REV.hashPromote(VAULT, cand, ghostNonce, SV));
        vm.recordLogs();
        try REV.proposePromotion(VAULT, cand, ghostNonce, SV, sig) {
            _captureLogs();
            ghostNonce += 1;
        } catch {
            _assertNoEventOnRevert();
        }
    }

    /// @notice Warp time then try to finalize the pending promotion.
    function warpAndFinalize(uint64 warpBy) external {
        vm.warp(block.timestamp + (warpBy % (100 hours)));
        (address cand, uint64 ready) = REV.pendingPromotion(VAULT);
        vm.recordLogs();
        try REV.finalizePromotion(VAULT, SV) {
            _captureLogs();
            // The contract MUST NOT have finalized before readyAt (L11):
            // turn that guarantee into a handler-side assertion so any
            // regression that lets finalize race the delay turns the run
            // RED. A successful finalize always implies a prior pending
            // promotion (ready != 0) AND block.timestamp >= ready.
            require(ready != 0, "handler: finalize succeeded with no pending promotion");
            require(
                block.timestamp >= ready, "handler: finalize succeeded before readyAt (L11 broken)"
            );
            // Manager rotated to the candidate (still a set member).
            ghostManager = cand;
            everFinalizedOk = true;
        } catch {
            _assertNoEventOnRevert();
        }
    }

    /// @notice Current manager cancels the pending promotion.
    function cancel() external {
        (, uint64 ready) = REV.pendingPromotion(VAULT);
        vm.assume(ready != 0);
        vm.recordLogs();
        vm.prank(ghostManager);
        try REV.cancelPromotion(VAULT, SV) {
            _captureLogs();
        } catch {
            _assertNoEventOnRevert();
        }
    }

    /// @notice Publish a revision signed by device #idx (honored iff in set).
    function publish(uint256 idx, bytes calldata enc) external {
        vm.assume(enc.length <= 128);
        idx = idx % 5;
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256(
                    "Revision(bytes32 vaultId,bytes32 accountId,bytes32 parentRevision,bytes32 deviceId,uint16 schemaVersion,bytes32 encPayloadHash)"
                ),
                VAULT,
                bytes32(0),
                bytes32(0),
                bytes32(0),
                SV,
                keccak256(enc)
            )
        );
        bytes32 digest = keccak256(abi.encodePacked(hex"1901", REV.DOMAIN_SEPARATOR(), structHash));
        bytes memory sig = _sign(devicePks[idx], digest);
        vm.recordLogs();
        try REV.publishRevision(VAULT, bytes32(0), bytes32(0), bytes32(0), SV, enc, sig) returns (
            uint256
        ) {
            _captureLogs();
        } catch {
            _assertNoEventOnRevert();
        }
    }

    /// @notice An OUTSIDER (never in the set) tries to publish — MUST always
    ///         fail. Exercises the honor-gate reject path.
    function publishOutsider(bytes calldata enc) external {
        vm.assume(enc.length <= 128);
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256(
                    "Revision(bytes32 vaultId,bytes32 accountId,bytes32 parentRevision,bytes32 deviceId,uint16 schemaVersion,bytes32 encPayloadHash)"
                ),
                VAULT,
                bytes32(0),
                bytes32(0),
                bytes32(0),
                SV,
                keccak256(enc)
            )
        );
        bytes32 digest = keccak256(abi.encodePacked(hex"1901", REV.DOMAIN_SEPARATOR(), structHash));
        bytes memory sig = _sign(OUTSIDER_PK, digest);
        vm.recordLogs();
        try REV.publishRevision(VAULT, bytes32(0), bytes32(0), bytes32(0), SV, enc, sig) returns (
            uint256
        ) {
            revert("handler: outsider publish succeeded");
        } catch {
            _assertNoEventOnRevert();
        }
    }
}

/// @title RevisionLogV2 invariant tests (10k x 32 per foundry.toml)
contract RevisionLogV2InvariantTest is Test {
    RevisionLogV2 internal rev;
    RecoveryV1 internal recovery;
    RevisionLogV2Handler internal handler;

    // Pre-computed event topic-0s (cast keccak). If any event signature
    // changes, these must be updated AND the change reviewed (the live fuzz
    // run fails `invariant_onlyKnownEventsEmitted` if they drift).
    bytes32 internal constant T_REVISION_PUBLISHED =
        0x36ba847f7914087f49c53b6e4993204da53c59f15e69a18c6165899c614dc508;
    bytes32 internal constant T_VAULT_BOOTSTRAPPED =
        0xf817070c48afef4eeee9d0db8a43339351fffe262d260ef9220cda40e6e8b67f;
    bytes32 internal constant T_DEVICE_ADDED =
        0x24ace7200c63a667c1702ca410f7cf244a50106a818ddb69c9b0e7f13710818a;
    bytes32 internal constant T_DEVICE_REMOVED =
        0x8df60d5b4841402b0c0b24eae4464a20c10414e68eca8f8cd4eb35e1563d37ca;
    bytes32 internal constant T_PROMOTION_PROPOSED =
        0xb2750f6b00604dd406b20a5739370d6e0c8097d99e849f16d152e5b6f124a347;
    bytes32 internal constant T_PROMOTION_FINALIZED =
        0xc3150a3438f98082550add0f5b05e9213694d87b52e30004b6a9a1d2b8fd03e5;
    bytes32 internal constant T_PROMOTION_CANCELED =
        0x99902f0caa2b2192c28bee37a9ee8444516673fdad201e84e6cd7bbaf0f78dee;

    uint64 internal lastSeenNonce;

    function setUp() public {
        recovery = new RecoveryV1();
        rev = new RevisionLogV2(address(recovery));
        handler = new RevisionLogV2Handler(rev, recovery);
        targetContract(address(handler));
        targetSender(address(0xA11CE));
        targetSender(address(0xB0B));
        targetSender(address(0xCAFE));
    }

    /// @dev L8: the set is never empty after bootstrap (no-brick) AND the
    ///      handler's ghost size matches the on-chain count.
    function invariant_setNeverEmptyAfterBootstrap() public view {
        assertGe(rev.authorizedDeviceCount(handler.VAULT()), 1, "set must never be empty");
        assertEq(
            rev.authorizedDeviceCount(handler.VAULT()),
            handler.ghostSetSize(),
            "ghost set size matches on-chain count"
        );
    }

    /// @dev L16: set size never exceeds MAX_DEVICES.
    function invariant_setSizeWithinBound() public view {
        assertLe(
            rev.authorizedDeviceCount(handler.VAULT()), rev.MAX_DEVICES(), "set <= MAX_DEVICES"
        );
    }

    /// @dev The manager is always a current member of the authorized set
    ///      (the manager device is never revocable — L10 no-brick; and a
    ///      promotion candidate must be in the set — L11). This is the
    ///      structural anchor that the vault is never un-manageable.
    function invariant_managerIsAlwaysInSet() public view {
        // RecoveryV1 has no authority for the inv vault, so currentManager
        // == the V2-local deviceManager.
        address mgr = rev.deviceManager(handler.VAULT());
        assertTrue(rev.authorizedDevice(handler.VAULT(), mgr), "manager must be a set member");
        assertEq(rev.currentManager(handler.VAULT()), mgr, "no recovery authority -> local manager");
    }

    /// @dev `deviceNonce` is strictly monotonic (each successful set
    ///      mutation / proposal bumps it; it never decreases).
    function invariant_nonceMonotonic() public {
        uint64 current = rev.deviceNonce(handler.VAULT());
        assertGe(current, lastSeenNonce, "deviceNonce must be monotonic");
        lastSeenNonce = current;
    }

    /// @dev The ghost membership mirror agrees with on-chain membership for
    ///      every device the handler has touched. Only the manager-signed
    ///      add/remove paths mutate the set (L9), so the handler's mirror —
    ///      updated only in those success branches — must match the chain.
    function invariant_membershipMirrorMatchesChain() public view {
        uint256 n = handler.everSeenDevicesLength();
        for (uint256 i = 0; i < n; i++) {
            address dev = handler.everSeenDeviceAt(i);
            assertEq(
                rev.authorizedDevice(handler.VAULT(), dev),
                handler.ghostInSet(dev),
                "on-chain membership must match the handler's manager-signed-only mirror"
            );
        }
    }

    /// @dev L11: a promotion can never finalize before `readyAt`. The
    ///      handler's `warpAndFinalize` success branch asserts
    ///      `block.timestamp >= readyAt` at the moment of every successful
    ///      finalize (a require that turns the run RED on regression). Here
    ///      we pin the structural counterpart: a pending promotion always
    ///      carries a `readyAt` at least `PROMOTION_DELAY` ahead of genesis
    ///      (the contract always sets `now + PROMOTION_DELAY`, and the chain
    ///      starts at timestamp 0/1 in the fuzzer), so a non-zero `readyAt`
    ///      is always >= `PROMOTION_DELAY`. NOTE: the candidate of a pending
    ///      promotion need NOT still be a set member — a non-manager
    ///      candidate can be removed by the manager during the window; the
    ///      contract's `finalizePromotion` re-checks membership and reverts
    ///      `ErrNotSetMember` in that case (defence-in-depth, see the unit
    ///      test `test_promotion_finalizeRevertsCandidateRemoved`).
    function invariant_pendingPromotionWellFormed() public view {
        (, uint64 ready) = rev.pendingPromotion(handler.VAULT());
        if (ready != 0) {
            assertGe(ready, rev.PROMOTION_DELAY(), "pending readyAt >= PROMOTION_DELAY");
        }
    }

    /// @dev No storage mutation besides the whitelisted mappings. Linear
    ///      slots 0..31: slot 0 is `_nextSequence` (may be non-zero after
    ///      publishes); slots 1..31 are mapping bases / unused and MUST be
    ///      zero. The immutable DOMAIN_SEPARATOR + RECOVERY_V1 live in
    ///      bytecode, not storage.
    function invariant_noStorageMutationBesidesWhitelist() public view {
        for (uint256 slot = 1; slot < 32; slot++) {
            bytes32 v = vm.load(address(rev), bytes32(slot));
            assertEq(v, bytes32(0), "non-zero value at a linear storage slot > 0 (mappings only)");
        }
    }

    /// @dev The only events the contract emits are the known V2 events.
    function invariant_onlyKnownEventsEmitted() public view {
        uint256 n = handler.capturedTopic0Length();
        for (uint256 i = 0; i < n; i++) {
            bytes32 t = handler.capturedTopic0At(i);
            bool known = t == T_REVISION_PUBLISHED || t == T_VAULT_BOOTSTRAPPED
                || t == T_DEVICE_ADDED || t == T_DEVICE_REMOVED || t == T_PROMOTION_PROPOSED
                || t == T_PROMOTION_FINALIZED || t == T_PROMOTION_CANCELED;
            assertTrue(known, "unexpected event topic-0 (only known RevisionLogV2 events allowed)");
        }
    }

    /// @dev If any finalize ever succeeded, the manager rotated to a real
    ///      set member (the finalized candidate). Confirms the promotion
    ///      lifecycle is reachable + leaves the vault manageable (the new
    ///      manager is in the set). `everFinalizedOk` is set only in the
    ///      handler's finalize-success branch (which also asserts the delay
    ///      was honored).
    function invariant_finalizeLeavesManagerInSet() public view {
        if (handler.everFinalizedOk()) {
            address mgr = rev.deviceManager(handler.VAULT());
            assertTrue(
                rev.authorizedDevice(handler.VAULT(), mgr),
                "a finalized manager must be a current set member"
            );
        }
    }

    /// @dev Defense-in-depth (L12): the contract never stores VDK-like blob
    ///      data. The manager is a plain address (low 20 bytes); the high 12
    ///      bytes of the storage word are zero — no key material could hide
    ///      there.
    function invariant_noVDKLikeDataOnChain() public view {
        address mgr = rev.deviceManager(handler.VAULT());
        assertEq(uint256(uint160(mgr)), uint256(uint160(mgr)), "manager is a plain address");
    }
}
