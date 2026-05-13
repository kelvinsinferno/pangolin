// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity 0.8.24;

import {Test, Vm} from "forge-std/Test.sol";
import {RevisionLogV1} from "../src/RevisionLogV1.sol";

/// @title RevisionLogV1 unit tests
/// @notice Maps 1:1 to docs/issue-plans/2.1.md "Test plan / Unit tests"
///         table, adapted to the resolved-decisions (R-a Path B ecrecover
///         + EIP-712 + R-b self-bootstrap + R-d schemaVersion=1).
contract RevisionLogV1Test is Test {
    RevisionLogV1 internal revLog;

    // Re-declared so `vm.expectEmit` can match on the topic signature.
    event RevisionPublished(
        uint256 indexed sequence,
        bytes32 indexed vaultId,
        bytes32 indexed accountId,
        bytes32 parentRevision,
        bytes32 deviceId,
        uint16 schemaVersion,
        bytes encPayload,
        address signer
    );

    // Re-declared so `vm.expectRevert` can use the typed error selector.
    error ErrInvalidSignature();
    error ErrSignerNotRegistered();
    error ErrUnsupportedSchemaVersion();

    // EIP-712 typehashes — mirror the ones in the contract.
    bytes32 internal constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    bytes32 internal constant REVISION_TYPEHASH = keccak256(
        "Revision(bytes32 vaultId,bytes32 accountId,bytes32 parentRevision,bytes32 deviceId,uint16 schemaVersion,bytes32 encPayloadHash)"
    );

    // Fixed test signer private keys (NOT for production — these are
    // public values picked for deterministic test output).
    uint256 internal constant DEVICE_A_PK =
        0xA0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0;
    uint256 internal constant DEVICE_B_PK =
        0xB0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0;

    function setUp() public {
        revLog = new RevisionLogV1();
    }

    // -----------------------------------------------------------------
    // Local digest helpers (mirror the contract's _hashRevision)
    // -----------------------------------------------------------------

    function _computeDigest(
        bytes32 vaultId,
        bytes32 accountId,
        bytes32 parentRevision,
        bytes32 deviceId,
        uint16 schemaVersion,
        bytes memory encPayload
    ) internal view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                REVISION_TYPEHASH,
                vaultId,
                accountId,
                parentRevision,
                deviceId,
                schemaVersion,
                keccak256(encPayload)
            )
        );
        return keccak256(abi.encodePacked(hex"1901", revLog.domainSeparator(), structHash));
    }

    function _sign(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    // -----------------------------------------------------------------
    // Happy-path tests
    // -----------------------------------------------------------------

    /// @dev test_publishRevision_v1_happyPath: a fresh vault, first
    ///      publish, signer auto-registered, sequence 0, event emitted
    ///      with every field correct.
    function test_publishRevision_v1_happyPath() public {
        bytes32 vaultId = keccak256("vault-1");
        bytes32 accountId = keccak256("account-1");
        bytes32 parentRevision = keccak256("parent-1");
        bytes32 deviceId = keccak256("device-1");
        uint16 schemaVersion = 1;
        bytes memory encPayload = hex"deadbeef";

        address signer = vm.addr(DEVICE_A_PK);
        bytes32 digest =
            _computeDigest(vaultId, accountId, parentRevision, deviceId, schemaVersion, encPayload);
        bytes memory sig = _sign(DEVICE_A_PK, digest);

        vm.expectEmit(true, true, true, true, address(revLog));
        emit RevisionPublished(
            0, vaultId, accountId, parentRevision, deviceId, schemaVersion, encPayload, signer
        );
        uint256 seq = revLog.publishRevision(
            vaultId, accountId, parentRevision, deviceId, schemaVersion, encPayload, sig
        );
        assertEq(seq, 0, "first sequence should be 0");
        assertEq(revLog.nextSequence(), 1);
        assertTrue(
            revLog.isRegisteredDevice(vaultId, signer),
            "self-bootstrap must register the first signer"
        );
        assertEq(revLog.registeredDeviceCount(vaultId), 1);
    }

    /// @dev test_publishRevision_v1_returnsMonotonicSequence: five
    ///      publishes across two vaults; sequence is global 0..4.
    function test_publishRevision_v1_returnsMonotonicSequence() public {
        bytes32 vaultX = keccak256("vault-X");
        bytes32 vaultY = keccak256("vault-Y");
        bytes32 acc = keccak256("acc");
        bytes32 parent = bytes32(0);
        bytes32 dev = keccak256("dev");
        bytes memory payload = hex"01";

        // Both vaults use DEVICE_A (independent self-bootstrap per vault).
        uint256[5] memory seqs;
        bytes32[5] memory vaults = [vaultX, vaultY, vaultX, vaultY, vaultX];
        for (uint256 i = 0; i < 5; i++) {
            bytes32 digest = _computeDigest(vaults[i], acc, parent, dev, 1, payload);
            bytes memory sig = _sign(DEVICE_A_PK, digest);
            seqs[i] = revLog.publishRevision(vaults[i], acc, parent, dev, 1, payload, sig);
        }
        assertEq(seqs[0], 0);
        assertEq(seqs[1], 1);
        assertEq(seqs[2], 2);
        assertEq(seqs[3], 3);
        assertEq(seqs[4], 4);
        assertEq(revLog.nextSequence(), 5);
    }

    /// @dev test_publishRevision_v1_selfBootstrapsFirstSigner — vault X
    ///      has device A registered; device B cannot publish for vault X.
    function test_publishRevision_v1_selfBootstrapRejectsSecondDevice() public {
        bytes32 vaultId = keccak256("vault-bootstrap");
        bytes32 accountId = keccak256("acc");
        bytes memory payload = hex"01";

        // Device A bootstraps the vault.
        {
            bytes32 digest = _computeDigest(vaultId, accountId, bytes32(0), bytes32(0), 1, payload);
            bytes memory sig = _sign(DEVICE_A_PK, digest);
            revLog.publishRevision(vaultId, accountId, bytes32(0), bytes32(0), 1, payload, sig);
        }
        assertTrue(revLog.isRegisteredDevice(vaultId, vm.addr(DEVICE_A_PK)));

        // Device B tries to publish for the same vault — must revert.
        {
            bytes32 digest = _computeDigest(vaultId, accountId, bytes32(0), bytes32(0), 1, payload);
            bytes memory sig = _sign(DEVICE_B_PK, digest);
            vm.expectRevert(ErrSignerNotRegistered.selector);
            revLog.publishRevision(vaultId, accountId, bytes32(0), bytes32(0), 1, payload, sig);
        }
        // Registry unchanged: B is NOT registered.
        assertFalse(revLog.isRegisteredDevice(vaultId, vm.addr(DEVICE_B_PK)));
        assertEq(revLog.registeredDeviceCount(vaultId), 1);
    }

    /// @dev test_publishRevision_v1_multiVaultIsolation — device A is
    ///      the bootstrap signer for vault X; can also bootstrap for
    ///      vault Y; the two registries are independent.
    function test_publishRevision_v1_multiVaultIsolation() public {
        bytes32 vaultX = keccak256("vault-X");
        bytes32 vaultY = keccak256("vault-Y");
        bytes memory payload = hex"01";
        address signerA = vm.addr(DEVICE_A_PK);

        // Bootstrap vault X with device A.
        bytes32 d1 = _computeDigest(vaultX, bytes32(0), bytes32(0), bytes32(0), 1, payload);
        revLog.publishRevision(
            vaultX, bytes32(0), bytes32(0), bytes32(0), 1, payload, _sign(DEVICE_A_PK, d1)
        );

        // Bootstrap vault Y with the same device A (independent registry).
        bytes32 d2 = _computeDigest(vaultY, bytes32(0), bytes32(0), bytes32(0), 1, payload);
        revLog.publishRevision(
            vaultY, bytes32(0), bytes32(0), bytes32(0), 1, payload, _sign(DEVICE_A_PK, d2)
        );

        assertTrue(revLog.isRegisteredDevice(vaultX, signerA));
        assertTrue(revLog.isRegisteredDevice(vaultY, signerA));
        // Negative axis: device B not registered for either.
        assertFalse(revLog.isRegisteredDevice(vaultX, vm.addr(DEVICE_B_PK)));
        assertFalse(revLog.isRegisteredDevice(vaultY, vm.addr(DEVICE_B_PK)));
        assertEq(revLog.registeredDeviceCount(vaultX), 1);
        assertEq(revLog.registeredDeviceCount(vaultY), 1);
    }

    /// @dev test_publishRevision_v1_noBumpOnRevert — an
    ///      ErrInvalidSignature revert must NOT bump the sequence
    ///      counter. The next successful publish gets the un-burned
    ///      sequence. (L6 binding.)
    function test_publishRevision_v1_noBumpOnRevert() public {
        bytes32 vaultId = keccak256("vault-no-bump");
        bytes memory payload = hex"01";
        bytes32 digest = _computeDigest(vaultId, bytes32(0), bytes32(0), bytes32(0), 1, payload);
        bytes memory sig = _sign(DEVICE_A_PK, digest);

        // Tamper the signature so ecrecover yields a different signer.
        bytes memory badSig = abi.encodePacked(sig);
        badSig[0] ^= bytes1(uint8(0x01));

        // First call reverts.
        vm.expectRevert();
        revLog.publishRevision(vaultId, bytes32(0), bytes32(0), bytes32(0), 1, payload, badSig);
        assertEq(revLog.nextSequence(), 0, "sequence must not bump on revert");

        // Second call (with correct sig) gets sequence 0.
        uint256 seq =
            revLog.publishRevision(vaultId, bytes32(0), bytes32(0), bytes32(0), 1, payload, sig);
        assertEq(seq, 0, "the un-burned sequence is assigned to the next success");
    }

    /// @dev test_publishRevision_v1_rejectsUnsupportedSchemaVersion —
    ///      `schemaVersion = MAX_KNOWN + 1` reverts.
    function test_publishRevision_v1_rejectsUnsupportedSchemaVersion() public {
        bytes32 vaultId = keccak256("vault");
        bytes memory payload = hex"01";
        bytes32 digest = _computeDigest(vaultId, bytes32(0), bytes32(0), bytes32(0), 2, payload);
        bytes memory sig = _sign(DEVICE_A_PK, digest);

        vm.expectRevert(ErrUnsupportedSchemaVersion.selector);
        revLog.publishRevision(vaultId, bytes32(0), bytes32(0), bytes32(0), 2, payload, sig);
    }

    /// @dev test_publishRevision_v1_rejectsInvalidSignature — a flipped
    ///      byte in the signature recovers to a different (random)
    ///      signer; for a fresh vault that signer self-bootstraps as
    ///      whoever they happen to be, which makes the test about
    ///      "did the contract behave per spec given a malformed sig" —
    ///      see the malformed-length variant for the pure
    ///      ErrInvalidSignature path.
    function test_publishRevision_v1_rejectsMalformedSignatureLength() public {
        bytes32 vaultId = keccak256("vault");
        bytes memory payload = hex"01";

        // 64-byte sig (one byte short): the contract's _recover() returns
        // address(0) immediately, ErrInvalidSignature.
        bytes memory shortSig = new bytes(64);
        vm.expectRevert(ErrInvalidSignature.selector);
        revLog.publishRevision(vaultId, bytes32(0), bytes32(0), bytes32(0), 1, payload, shortSig);
    }

    /// @dev test_publishRevision_v1_rejectsBadV — `v` outside {27, 28}.
    function test_publishRevision_v1_rejectsBadV() public {
        bytes32 vaultId = keccak256("vault");
        bytes memory payload = hex"01";
        bytes32 digest = _computeDigest(vaultId, bytes32(0), bytes32(0), bytes32(0), 1, payload);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(DEVICE_A_PK, digest);
        // Force `v` to 26 (invalid).
        bytes memory badV = abi.encodePacked(r, s, uint8(26));
        // Suppress unused-variable warning by referencing v.
        v;

        vm.expectRevert(ErrInvalidSignature.selector);
        revLog.publishRevision(vaultId, bytes32(0), bytes32(0), bytes32(0), 1, payload, badV);
    }

    /// @dev test_publishRevision_v1_rejectsHighS — s in the upper half
    ///      of the curve order is rejected (EIP-2 low-s discipline).
    function test_publishRevision_v1_rejectsHighS() public {
        bytes32 vaultId = keccak256("vault");
        bytes memory payload = hex"01";
        bytes32 digest = _computeDigest(vaultId, bytes32(0), bytes32(0), bytes32(0), 1, payload);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(DEVICE_A_PK, digest);
        // secp256k1 group order n
        uint256 N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
        bytes32 highS = bytes32(N - uint256(s));
        // Flip v so the (r, n-s, v^1) signature also recovers to the
        // same signer — except it should be rejected outright.
        uint8 flippedV = v == 27 ? 28 : 27;
        bytes memory mall = abi.encodePacked(r, highS, flippedV);
        vm.expectRevert(ErrInvalidSignature.selector);
        revLog.publishRevision(vaultId, bytes32(0), bytes32(0), bytes32(0), 1, payload, mall);
    }

    /// @dev test_publishRevision_v1_rejectsTamperedPayload — signature
    ///      is over keccak(encPayload); flipping a payload byte produces
    ///      a digest mismatch -> recovered signer is wrong -> for a
    ///      fresh vault this self-bootstraps the wrong-signer, but for
    ///      an already-bootstrapped vault it reverts with
    ///      ErrSignerNotRegistered.
    function test_publishRevision_v1_rejectsTamperedPayload() public {
        bytes32 vaultId = keccak256("vault");
        bytes memory payload = hex"01";

        // Bootstrap with DEVICE_A on the correct payload.
        bytes32 digest = _computeDigest(vaultId, bytes32(0), bytes32(0), bytes32(0), 1, payload);
        bytes memory sig = _sign(DEVICE_A_PK, digest);
        revLog.publishRevision(vaultId, bytes32(0), bytes32(0), bytes32(0), 1, payload, sig);

        // Re-use the signature over the OLD payload but submit a
        // different payload. The recovered signer recovers to a
        // pseudo-random address that is not registered for this
        // vault -> ErrSignerNotRegistered.
        bytes memory tampered = hex"02";
        vm.expectRevert(ErrSignerNotRegistered.selector);
        revLog.publishRevision(vaultId, bytes32(0), bytes32(0), bytes32(0), 1, tampered, sig);
    }

    /// @dev test_publishRevision_v1_rejectsCrossVaultReplay — a
    ///      signature for (vault X) cannot publish for (vault Y).
    function test_publishRevision_v1_rejectsCrossVaultReplay() public {
        bytes32 vaultX = keccak256("vault-X");
        bytes32 vaultY = keccak256("vault-Y");
        bytes memory payload = hex"01";

        // Bootstrap vault X with DEVICE_A.
        bytes32 dx = _computeDigest(vaultX, bytes32(0), bytes32(0), bytes32(0), 1, payload);
        bytes memory sigX = _sign(DEVICE_A_PK, dx);
        revLog.publishRevision(vaultX, bytes32(0), bytes32(0), bytes32(0), 1, payload, sigX);
        // Bootstrap vault Y with DEVICE_B so vaultY has a non-empty
        // registry that does not contain whoever sigX-recovers-to-
        // against-vaultY.
        bytes32 dy = _computeDigest(vaultY, bytes32(0), bytes32(0), bytes32(0), 1, payload);
        bytes memory sigY = _sign(DEVICE_B_PK, dy);
        revLog.publishRevision(vaultY, bytes32(0), bytes32(0), bytes32(0), 1, payload, sigY);

        // Try sigX (made for vaultX) against vaultY: it recovers to
        // some random signer that is not DEVICE_B; not registered.
        vm.expectRevert(ErrSignerNotRegistered.selector);
        revLog.publishRevision(vaultY, bytes32(0), bytes32(0), bytes32(0), 1, payload, sigX);
    }

    /// @dev test_publishRevision_v1_rejectsCrossChainReplay — a
    ///      signature computed under a different chainId does not
    ///      verify (domain separator binds chainId).
    function test_publishRevision_v1_rejectsCrossChainReplay() public {
        // Sign under chain id 999.
        vm.chainId(999);
        // Note: the contract's _DOMAIN_SEPARATOR was set in the
        // constructor under the ORIGINAL chain id (`block.chainid`
        // at construction). Switching chain id post-construction
        // does NOT update it — which is the whole point of EIP-712
        // domain binding. We sign a digest that uses the FAKE
        // chain id and submit it.
        bytes32 fakeDomainSep = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes("Pangolin RevisionLog")),
                keccak256(bytes("1")),
                uint256(999),
                address(revLog)
            )
        );
        // Make sure the fake domain separator actually differs from the
        // real one — otherwise the test would be a tautology under a
        // testchain whose initial chainid happens to be 999. Foundry's
        // default chainid is 31337 so this is fine.
        assertTrue(fakeDomainSep != revLog.domainSeparator(), "fake/real separators must differ");

        bytes32 vaultId = keccak256("vault");
        bytes memory payload = hex"01";
        bytes32 structHash = keccak256(
            abi.encode(
                REVISION_TYPEHASH,
                vaultId,
                bytes32(0),
                bytes32(0),
                bytes32(0),
                uint16(1),
                keccak256(payload)
            )
        );
        bytes32 fakeDigest = keccak256(abi.encodePacked(hex"1901", fakeDomainSep, structHash));
        bytes memory sig = _sign(DEVICE_A_PK, fakeDigest);

        // The contract will recompute the digest under its REAL
        // domain separator; ecrecover yields a different address;
        // for a fresh vault that "different address" self-
        // bootstraps. That is the EIP-712 cross-chain replay
        // story: the signer who signed under chainid 999 does NOT
        // become a registered device on the real chain — only
        // whoever the recompute happens to recover to does. So we
        // assert that DEVICE_A is NOT registered after the call.
        revLog.publishRevision(vaultId, bytes32(0), bytes32(0), bytes32(0), 1, payload, sig);
        assertFalse(
            revLog.isRegisteredDevice(vaultId, vm.addr(DEVICE_A_PK)),
            "cross-chain signature must not register DEVICE_A"
        );
    }

    /// @dev test_publishRevision_v1_acceptsLargePayload — 64 KiB
    ///      payload works (digest hashes to 32 B before EIP-712).
    function test_publishRevision_v1_acceptsLargePayload() public {
        bytes memory big = new bytes(65536);
        for (uint256 i = 0; i < big.length; i++) {
            big[i] = bytes1(uint8(i & 0xff));
        }
        bytes32 vaultId = keccak256("v");
        bytes32 digest = _computeDigest(vaultId, bytes32(0), bytes32(0), bytes32(0), 1, big);
        bytes memory sig = _sign(DEVICE_A_PK, digest);
        uint256 seq =
            revLog.publishRevision(vaultId, bytes32(0), bytes32(0), bytes32(0), 1, big, sig);
        assertEq(seq, 0);
    }

    /// @dev test_publishRevision_v1_acceptsEmptyPayload — encPayload = ""
    ///      is valid; the digest is over keccak256("").
    function test_publishRevision_v1_acceptsEmptyPayload() public {
        bytes32 vaultId = keccak256("v");
        bytes memory empty = "";
        bytes32 digest = _computeDigest(vaultId, bytes32(0), bytes32(0), bytes32(0), 1, empty);
        bytes memory sig = _sign(DEVICE_A_PK, digest);
        uint256 seq =
            revLog.publishRevision(vaultId, bytes32(0), bytes32(0), bytes32(0), 1, empty, sig);
        assertEq(seq, 0);
    }

    /// @dev test_publishRevision_v1_anyCallerAllowed — tx.origin !=
    ///      msg.sender works; the signature, not msg.sender, is what
    ///      authenticates.
    function test_publishRevision_v1_anyCallerAllowed() public {
        bytes32 vaultId = keccak256("v");
        bytes memory payload = hex"01";
        bytes32 digest = _computeDigest(vaultId, bytes32(0), bytes32(0), bytes32(0), 1, payload);
        bytes memory sig = _sign(DEVICE_A_PK, digest);

        RelayCallerV1 relay = new RelayCallerV1(revLog);
        uint256 seq = relay.relay(vaultId, payload, sig);
        assertEq(seq, 0);
        // DEVICE_A is registered, even though msg.sender was the relay.
        assertTrue(revLog.isRegisteredDevice(vaultId, vm.addr(DEVICE_A_PK)));
    }

    /// @dev test_publishRevision_v1_replayingIdenticalBytesIsAllowed —
    ///      the contract is a log, not an authority; same bytes can be
    ///      republished and get a fresh sequence. Documents threat #1
    ///      residual.
    function test_publishRevision_v1_replayingIdenticalBytesIsAllowed() public {
        bytes32 vaultId = keccak256("v");
        bytes memory payload = hex"01";
        bytes32 digest = _computeDigest(vaultId, bytes32(0), bytes32(0), bytes32(0), 1, payload);
        bytes memory sig = _sign(DEVICE_A_PK, digest);
        uint256 s1 =
            revLog.publishRevision(vaultId, bytes32(0), bytes32(0), bytes32(0), 1, payload, sig);
        uint256 s2 =
            revLog.publishRevision(vaultId, bytes32(0), bytes32(0), bytes32(0), 1, payload, sig);
        assertEq(s1, 0);
        assertEq(s2, 1);
    }

    // -----------------------------------------------------------------
    // ETH-rejection + surface tests (mirrors v0's audit-fix L-1)
    // -----------------------------------------------------------------

    /// @dev test_publishRevision_v1_doesNotAcceptEth.
    function test_publishRevision_v1_doesNotAcceptEth() public {
        vm.deal(address(this), 1 ether);
        bytes memory cd = abi.encodeWithSelector(
            RevisionLogV1.publishRevision.selector,
            bytes32(0),
            bytes32(0),
            bytes32(0),
            bytes32(0),
            uint16(0),
            bytes(""),
            bytes("")
        );
        (bool ok,) = address(revLog).call{value: 1 wei}(cd);
        assertFalse(ok, "non-payable call with value must revert");
    }

    /// @dev test_contract_rejectsEthOnAllCallPaths_v1.
    function test_contract_rejectsEthOnAllCallPaths_v1() public {
        vm.deal(address(this), 1 ether);
        (bool ok1,) = address(revLog).call{value: 1 wei}("");
        assertFalse(ok1, "empty calldata with value must revert (no receive())");
        (bool ok2,) = address(revLog).call{value: 1 wei}(hex"deadbeef");
        assertFalse(ok2, "unknown selector with value must revert");
        (bool ok3,) = address(revLog).call{value: 0}(hex"deadbeef");
        assertFalse(ok3, "unknown selector with no fallback must revert");
    }

    /// @dev test_contract_hasNoAdminOrProxySelectors_v1 — mirror of v0's
    ///      probe, extended for v1-specific concerns (no removal /
    ///      reset / setMax / setRegistry surface).
    function test_contract_hasNoAdminOrProxySelectors_v1() public {
        bytes[24] memory probes = [
            // Ownership / admin / proxy family (mirror of v0).
            abi.encodeWithSignature("transferOwnership(address)", address(0)),
            abi.encodeWithSignature("renounceOwnership()"),
            abi.encodeWithSignature("acceptOwnership()"),
            abi.encodeWithSignature("pendingOwner()"),
            abi.encodeWithSignature("owner()"),
            abi.encodeWithSignature("changeAdmin(address)", address(0)),
            abi.encodeWithSignature("admin()"),
            abi.encodeWithSignature("pause()"),
            abi.encodeWithSignature("unpause()"),
            abi.encodeWithSignature("paused()"),
            abi.encodeWithSignature("kill()"),
            abi.encodeWithSignature("destroy()"),
            abi.encodeWithSignature("terminate()"),
            abi.encodeWithSignature("upgradeTo(address)", address(0)),
            abi.encodeWithSignature("upgradeToAndCall(address,bytes)", address(0), bytes("")),
            abi.encodeWithSignature("implementation()"),
            abi.encodeWithSignature("proxiableUUID()"),
            abi.encodeWithSignature("setNextSequence(uint256)", uint256(0)),
            // v1-specific removal/reset/admin probes.
            abi.encodeWithSignature("revokeDevice(bytes32,address)", bytes32(0), address(0)),
            abi.encodeWithSignature("removeDevice(bytes32,address)", bytes32(0), address(0)),
            abi.encodeWithSignature("unregisterDevice(bytes32,address)", bytes32(0), address(0)),
            abi.encodeWithSignature("setMaxSchemaVersion(uint16)", uint16(0)),
            abi.encodeWithSignature("setRegistry(bytes32,address,bool)", bytes32(0), address(0), false),
            abi.encodeWithSignature("resetVault(bytes32)", bytes32(0))
        ];
        for (uint256 i = 0; i < probes.length; i++) {
            (bool ok, bytes memory ret) = address(revLog).call(probes[i]);
            assertFalse(ok, "admin/proxy/removal selector must not exist");
            assertEq(ret.length, 0, "no return data from missing admin/proxy selector");
        }
    }

    /// @dev MAX_KNOWN_SCHEMA_VERSION constant is 1 per R-d
    ///      Implementation impact (2).
    function test_constants_maxKnownSchemaVersion_is_1() public view {
        assertEq(revLog.MAX_KNOWN_SCHEMA_VERSION(), 1);
    }

    /// @dev nextSequence() starts at zero.
    function test_nextSequence_startsAtZero() public view {
        assertEq(revLog.nextSequence(), 0);
    }

    /// @dev domainSeparator() is non-zero and binds chain id +
    ///      contract address.
    function test_domainSeparator_binds_contract_address() public {
        bytes32 expected = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes("Pangolin RevisionLog")),
                keccak256(bytes("1")),
                block.chainid,
                address(revLog)
            )
        );
        assertEq(revLog.domainSeparator(), expected);
        // A second deployment has a DIFFERENT separator (different
        // contract address).
        RevisionLogV1 other = new RevisionLogV1();
        assertTrue(other.domainSeparator() != revLog.domainSeparator());
    }

    /// @dev hashRevision() returns the same digest the contract verifies.
    function test_hashRevision_matchesInternalDigest() public view {
        bytes32 vaultId = keccak256("v");
        bytes memory payload = hex"01";
        bytes32 viaView =
            revLog.hashRevision(vaultId, bytes32(0), bytes32(0), bytes32(0), 1, payload);
        bytes32 viaLocal = _computeDigest(vaultId, bytes32(0), bytes32(0), bytes32(0), 1, payload);
        assertEq(viaView, viaLocal, "hashRevision view must match the verified digest");
    }

    /// @dev Gas sanity (R-a Path B target: << 80k for warm storage).
    function test_publishRevision_v1_gasUnder150k() public {
        bytes32 vaultId = keccak256("gas");
        bytes memory payload = new bytes(256);
        for (uint256 i = 0; i < 256; i++) {
            payload[i] = bytes1(uint8(i));
        }

        // Warm: first publish self-bootstraps (cold reg writes); we
        // measure the second one.
        bytes32 d1 = _computeDigest(vaultId, bytes32(0), bytes32(0), bytes32(0), 1, payload);
        revLog.publishRevision(
            vaultId, bytes32(0), bytes32(0), bytes32(0), 1, payload, _sign(DEVICE_A_PK, d1)
        );

        bytes32 d2 =
            _computeDigest(vaultId, bytes32(0), bytes32(0), bytes32(uint256(1)), 1, payload);
        bytes memory sig = _sign(DEVICE_A_PK, d2);
        uint256 gasBefore = gasleft();
        revLog.publishRevision(
            vaultId, bytes32(0), bytes32(0), bytes32(uint256(1)), 1, payload, sig
        );
        uint256 gasUsed = gasBefore - gasleft();

        emit log_named_uint("publishRevision_v1 256B payload gas (warm)", gasUsed);
        assertLt(gasUsed, 150_000, "256-byte v1 publishRevision must cost < 150k gas");
    }
}

/// @dev Helper contract for tx.origin != msg.sender coverage.
contract RelayCallerV1 {
    RevisionLogV1 internal immutable LOG;

    constructor(RevisionLogV1 log_) {
        LOG = log_;
    }

    function relay(bytes32 vaultId, bytes calldata payload, bytes calldata sig)
        external
        returns (uint256)
    {
        return LOG.publishRevision(vaultId, bytes32(0), bytes32(0), bytes32(0), 1, payload, sig);
    }
}
