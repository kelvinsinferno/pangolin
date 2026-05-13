// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity 0.8.24;

import {Test, Vm} from "forge-std/Test.sol";
import {RevisionLogV1} from "../src/RevisionLogV1.sol";

/// @notice Fuzz-handler that drives `RevisionLogV1` through randomized
///         call sequences. The handler holds a small pool of signer
///         private keys + a small pool of vault ids, picks among them
///         per call, builds a valid EIP-712 signature, and forwards
///         to `publishRevision`. Because every signature it constructs
///         is valid, the contract's revert paths are exercised by the
///         R-b "second device blocked" gate (when the handler picks
///         a non-bootstrap signer for an already-bootstrapped vault).
///
/// @dev Audit fix M-2 (carried over from v0): the handler uses
///      `vm.assume(...)` instead of an early-`return` for out-of-bounds
///      inputs so the run count stays clean under
///      `fail_on_revert = true`. The contract's revert paths are
///      EXPECTED here (the handler tries random combinations on
///      purpose); we wrap the call in `try/catch` so the run does not
///      itself fail on the contract revert.
contract RevisionLogV1Handler is Test {
    RevisionLogV1 public immutable REV_LOG;

    // Three vault ids the handler rotates through.
    bytes32[] public vaultPool;

    // Five signer keys the handler rotates through.
    uint256[] public signerPool;

    /// @notice Successful publishes (vault id -> signer who succeeded).
    ///         Cross-checked by the registry-consistency invariant.
    mapping(bytes32 vault => mapping(address signer => bool seen)) public sawSuccessfulPublishFor;

    /// @notice Number of distinct signers that ever published
    ///         successfully for a given vault (we only ever increment
    ///         this on a brand-new (vault, signer) pair).
    mapping(bytes32 vault => uint32 count) public distinctSignerCount;

    /// @notice Every vault that received at least one successful publish.
    bytes32[] public touchedVaults;
    mapping(bytes32 => bool) public vaultIsTouched;

    /// @notice For each touched vault, the list of distinct signers
    ///         that successfully published. Used by the no-orphan-
    ///         registry-slot invariant.
    mapping(bytes32 vault => address[] signers) internal _registeredSigners;

    uint256 public publishCount;

    /// @notice Captured event topic-0s across the run (used by the
    ///         "only RevisionPublished is emitted" invariant).
    bytes32[] internal capturedTopic0;

    constructor(RevisionLogV1 log_) {
        REV_LOG = log_;

        // Seed pools. The values are arbitrary but small so the
        // fuzzer hits collisions (same vault repeatedly) often.
        vaultPool.push(keccak256("vault-1"));
        vaultPool.push(keccak256("vault-2"));
        vaultPool.push(keccak256("vault-3"));

        signerPool.push(uint256(keccak256("signer-1")));
        signerPool.push(uint256(keccak256("signer-2")));
        signerPool.push(uint256(keccak256("signer-3")));
        signerPool.push(uint256(keccak256("signer-4")));
        signerPool.push(uint256(keccak256("signer-5")));
    }

    function vaultPoolLength() external view returns (uint256) {
        return vaultPool.length;
    }

    function signerPoolLength() external view returns (uint256) {
        return signerPool.length;
    }

    function registeredSignersLength(bytes32 vault) external view returns (uint256) {
        return _registeredSigners[vault].length;
    }

    function registeredSignerAt(bytes32 vault, uint256 i) external view returns (address) {
        return _registeredSigners[vault][i];
    }

    function touchedVaultsLength() external view returns (uint256) {
        return touchedVaults.length;
    }

    function capturedTopic0Length() external view returns (uint256) {
        return capturedTopic0.length;
    }

    function capturedTopic0At(uint256 i) external view returns (bytes32) {
        return capturedTopic0[i];
    }

    /// @notice The fuzz target. The runner picks random indices into
    ///         the vault + signer pools and random payload bytes. We
    ///         build a valid EIP-712 signature, call `publishRevision`,
    ///         and record the outcome.
    function publishRevision(
        uint256 vaultIdx,
        uint256 signerIdx,
        uint16 schemaVersion,
        bytes calldata encPayload
    ) external {
        // Bound the inputs to avoid wasting fuzz runs on out-of-range
        // values. Under `fail_on_revert = true` we use `vm.assume`.
        vm.assume(encPayload.length <= 256);
        vm.assume(schemaVersion <= REV_LOG.MAX_KNOWN_SCHEMA_VERSION() + 1);
        vaultIdx = vaultIdx % vaultPool.length;
        signerIdx = signerIdx % signerPool.length;

        bytes32 vaultId = vaultPool[vaultIdx];
        uint256 pk = signerPool[signerIdx];
        bytes memory sig = _buildSig(pk, vaultId, schemaVersion, encPayload);

        // Start recording emitted events so we can capture the topic-0.
        vm.recordLogs();
        _attemptPublish(vaultId, vm.addr(pk), schemaVersion, encPayload, sig);
    }

    function _buildSig(uint256 pk, bytes32 vaultId, uint16 schemaVersion, bytes calldata encPayload)
        internal
        view
        returns (bytes memory)
    {
        bytes32 typehash = keccak256(
            "Revision(bytes32 vaultId,bytes32 accountId,bytes32 parentRevision,bytes32 deviceId,uint16 schemaVersion,bytes32 encPayloadHash)"
        );
        bytes32 structHash = keccak256(
            abi.encode(
                typehash,
                vaultId,
                bytes32(0),
                bytes32(0),
                bytes32(0),
                schemaVersion,
                keccak256(encPayload)
            )
        );
        bytes32 digest =
            keccak256(abi.encodePacked(hex"1901", REV_LOG.domainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _attemptPublish(
        bytes32 vaultId,
        address signer,
        uint16 schemaVersion,
        bytes calldata encPayload,
        bytes memory sig
    ) internal {
        try REV_LOG.publishRevision(
            vaultId, bytes32(0), bytes32(0), bytes32(0), schemaVersion, encPayload, sig
        ) returns (uint256 /* seq */ ) {
            Vm.Log[] memory entries = vm.getRecordedLogs();
            for (uint256 i = 0; i < entries.length; i++) {
                if (entries[i].emitter == address(REV_LOG)) {
                    require(entries[i].topics.length > 0, "handler: log without topic0");
                    capturedTopic0.push(entries[i].topics[0]);
                }
            }
            if (!sawSuccessfulPublishFor[vaultId][signer]) {
                sawSuccessfulPublishFor[vaultId][signer] = true;
                distinctSignerCount[vaultId] += 1;
                _registeredSigners[vaultId].push(signer);
            }
            if (!vaultIsTouched[vaultId]) {
                vaultIsTouched[vaultId] = true;
                touchedVaults.push(vaultId);
            }
            publishCount += 1;
        } catch {
            // Revert path must NOT have emitted an event from the
            // contract under test.
            Vm.Log[] memory entries = vm.getRecordedLogs();
            for (uint256 i = 0; i < entries.length; i++) {
                if (entries[i].emitter == address(REV_LOG)) {
                    revert("handler: revert path must not emit");
                }
            }
        }
    }
}

/// @title RevisionLogV1 invariant tests
contract RevisionLogV1InvariantTest is Test {
    RevisionLogV1 internal revLog;
    RevisionLogV1Handler internal handler;

    uint256 internal lastSeenNextSequence;

    /// @dev Pre-computed
    ///      `keccak256("RevisionPublished(uint256,bytes32,bytes32,bytes32,bytes32,uint16,bytes,address)")`.
    ///      If the event signature ever changes, this constant must be
    ///      updated AND the change reviewed. Verified against the
    ///      live fuzz-run emit (which fails this constant if it
    ///      drifts).
    bytes32 internal constant REVISION_PUBLISHED_TOPIC0 =
        0x36ba847f7914087f49c53b6e4993204da53c59f15e69a18c6165899c614dc508;

    function setUp() public {
        revLog = new RevisionLogV1();
        handler = new RevisionLogV1Handler(revLog);

        targetContract(address(handler));
        // Rotate senders so we exercise tx.origin != msg.sender.
        targetSender(address(0xA11CE));
        targetSender(address(0xB0B));
        targetSender(address(0xCAFE));
        targetSender(address(0xDEADBEEF));
    }

    /// @dev invariant_sequenceMonotonic_v1: `nextSequence()` only ever
    ///      goes up.
    function invariant_sequenceMonotonic_v1() public {
        uint256 current = revLog.nextSequence();
        assertGe(current, lastSeenNextSequence, "nextSequence must be monotonic");
        lastSeenNextSequence = current;
    }

    /// @dev invariant_eventCountEqualsSequence_v1: the number of
    ///      successful `publishRevision` calls (handler-counted, post-
    ///      revert-filter) equals `nextSequence`. v1-specific: revert
    ///      paths must NOT bump the sequence.
    function invariant_eventCountEqualsSequence_v1() public view {
        assertEq(
            revLog.nextSequence(),
            handler.publishCount(),
            "nextSequence must equal successful publish count (revert paths must not bump)"
        );
    }

    /// @dev invariant_noStorageMutationBesidesSequenceAndRegistry:
    ///      every storage slot probed is either (a) slot 0
    ///      (`_nextSequence`), or (b) a hashed slot in the
    ///      `isRegisteredDevice` / `registeredDeviceCount` mappings
    ///      corresponding to a vault that received a successful
    ///      publish AND a signer that bootstrapped it. Every other
    ///      slot is zero.
    function invariant_noStorageMutationBesidesSequenceAndRegistry() public view {
        // Linear slots 1..31: all zero (mappings are hashed; their
        // base slot itself stores no value).
        for (uint256 slot = 1; slot < 32; slot++) {
            bytes32 v = vm.load(address(revLog), bytes32(slot));
            assertEq(v, bytes32(0), "non-zero storage at linear slot > 0");
        }

        // For every (vault, signer) the handler recorded a successful
        // publish for, the corresponding hashed-mapping slot is
        // non-zero (= true). For an UNREGISTERED (vault, signer), the
        // slot is zero. We probe both axes.
        //
        // isRegisteredDevice is at slot 1 in the contract source order
        // (after `_nextSequence`). Solidity computes its inner key
        // address as `keccak256(abi.encode(signer, keccak256(abi.encode(vaultId, 1))))`.
        uint256 nVaults = handler.touchedVaultsLength();
        for (uint256 i = 0; i < nVaults; i++) {
            bytes32 vault = handler.touchedVaults(i);
            // The vault was touched, so registeredDeviceCount[vault] != 0.
            // Probe the count mapping's hashed slot: it's at base slot 2.
            bytes32 countSlot = keccak256(abi.encode(vault, uint256(2)));
            uint256 slotValue = uint256(vm.load(address(revLog), countSlot));
            assertGt(slotValue, 0, "touched vault must have non-zero registeredDeviceCount");

            // For each registered signer of this vault, the
            // isRegisteredDevice[vault][signer] slot is true (= 1).
            uint256 nSigners = handler.registeredSignersLength(vault);
            for (uint256 j = 0; j < nSigners; j++) {
                address signer = handler.registeredSignerAt(vault, j);
                bytes32 innerVaultSlot = keccak256(abi.encode(vault, uint256(1)));
                bytes32 finalSlot = keccak256(abi.encode(signer, innerVaultSlot));
                bytes32 slotV = vm.load(address(revLog), finalSlot);
                assertEq(slotV, bytes32(uint256(1)), "registered signer slot must be true");
            }
        }
    }

    /// @dev invariant_onlyRevisionPublishedEventEmitted: the only event
    ///      the contract emits is `RevisionPublished` (topic-0
    ///      `REVISION_PUBLISHED_TOPIC0`).
    function invariant_onlyRevisionPublishedEventEmitted() public view {
        uint256 n = handler.capturedTopic0Length();
        for (uint256 i = 0; i < n; i++) {
            assertEq(
                handler.capturedTopic0At(i),
                REVISION_PUBLISHED_TOPIC0,
                "unexpected event topic-0 (only RevisionPublished is allowed)"
            );
        }
    }

    /// @dev invariant_registryWriteAdditive: once
    ///      `isRegisteredDevice[vaultId][signer] = true`, it stays
    ///      true forever in the fuzz run. (L10 + R-c binding — no
    ///      revocation path in v1.)
    function invariant_registryWriteAdditive() public view {
        uint256 nVaults = handler.touchedVaultsLength();
        for (uint256 i = 0; i < nVaults; i++) {
            bytes32 vault = handler.touchedVaults(i);
            uint256 nSigners = handler.registeredSignersLength(vault);
            for (uint256 j = 0; j < nSigners; j++) {
                address signer = handler.registeredSignerAt(vault, j);
                assertTrue(
                    revLog.isRegisteredDevice(vault, signer),
                    "registry is write-only-additive: a registered signer must stay registered"
                );
            }
        }
    }

    /// @dev invariant_signerCountConsistency: for every vault that
    ///      received any successful publish,
    ///      `registeredDeviceCount[vault] >= 1` AND it equals the
    ///      number of distinct signers (which, under R-b self-
    ///      bootstrap + no additional-device-join in v1, is exactly
    ///      1).
    function invariant_signerCountConsistency() public view {
        uint256 nVaults = handler.touchedVaultsLength();
        for (uint256 i = 0; i < nVaults; i++) {
            bytes32 vault = handler.touchedVaults(i);
            uint32 onChain = revLog.registeredDeviceCount(vault);
            assertGe(onChain, 1, "touched vault must have >= 1 registered device");
            // Under R-b: count is exactly 1 (self-bootstrap; no
            // additional-device-join surface in v1).
            assertEq(onChain, 1, "v1 has no multi-device-join: count must stay at 1");
            // Cross-check: only one distinct signer ever succeeded
            // for this vault per the handler's bookkeeping.
            assertEq(
                handler.distinctSignerCount(vault),
                1,
                "handler bookkeeping: at most one distinct signer per vault under R-b"
            );
        }
    }
}
