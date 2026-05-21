// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {RevisionLogV2} from "../src/RevisionLogV2.sol";
import {RecoveryV1} from "../src/RecoveryV1.sol";

/// @title RevisionLogV2 unit tests
/// @notice Maps to docs/issue-plans/106a-revisionlogv2-contract.md "Test
///         posture": full lifecycle + every revert path; publish honored
///         iff in the SET; add/remove manager-signed + nonce-replay
///         rejected; no-brick (remove last/manager reverts); promotion
///         propose/cancel/finalize lifecycle with vm.warp(48h) +
///         finalize-before-delay reverts + non-candidate finalize reverts;
///         bootstrap once-only; MAX_DEVICES cap; cross-read of RecoveryV1
///         authority; byte-pinned EIP-712 domain v2 + typehashes;
///         no-admin selector probe; non-payable.
contract RevisionLogV2Test is Test {
    RevisionLogV2 internal revLog;
    RecoveryV1 internal recovery;

    // Re-declared so vm.expectEmit / vm.expectRevert can match.
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
    event VaultBootstrapped(
        bytes32 indexed vaultId, address firstSigner, address manager, uint16 schemaVersion
    );
    event DeviceAdded(
        bytes32 indexed vaultId, address signer, address manager, uint64 nonce, uint16 schemaVersion
    );
    event DeviceRemoved(
        bytes32 indexed vaultId, address signer, address manager, uint64 nonce, uint16 schemaVersion
    );
    event PromotionProposed(
        bytes32 indexed vaultId, address candidate, uint64 readyAt, uint16 schemaVersion
    );
    event PromotionFinalized(
        bytes32 indexed vaultId, address oldManager, address newManager, uint16 schemaVersion
    );
    event PromotionCanceled(bytes32 indexed vaultId, address candidate, uint16 schemaVersion);

    error ErrInvalidSignature();
    error ErrSignerNotAuthorized();
    error ErrNotDeviceManager();
    error ErrAlreadyAuthorized();
    error ErrNotAuthorized();
    error ErrVaultAlreadyBootstrapped();
    error ErrVaultNotBootstrapped();
    error ErrWouldBrickVault();
    error ErrNotSetMember();
    error ErrPromotionPending();
    error ErrNoPromotionPending();
    error ErrPromotionDelayNotElapsed();
    error ErrNotAuthorizedToCancel();
    error ErrBadNonce();
    error ErrSetSizeExceeded();
    error ErrUnsupportedSchemaVersion();
    error ErrZeroValue();

    // EIP-712 typehashes — mirror the contract.
    bytes32 internal constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    bytes32 internal constant REVISION_TYPEHASH = keccak256(
        "Revision(bytes32 vaultId,bytes32 accountId,bytes32 parentRevision,bytes32 deviceId,uint16 schemaVersion,bytes32 encPayloadHash)"
    );
    bytes32 internal constant ADD_DEVICE_TYPEHASH =
        keccak256("AddDevice(bytes32 vaultId,address newSigner,uint64 nonce,uint16 schemaVersion)");
    bytes32 internal constant REMOVE_DEVICE_TYPEHASH =
        keccak256("RemoveDevice(bytes32 vaultId,address signer,uint64 nonce,uint16 schemaVersion)");
    bytes32 internal constant PROMOTE_TYPEHASH =
        keccak256("Promote(bytes32 vaultId,address candidate,uint64 nonce,uint16 schemaVersion)");

    // Device private keys.
    uint256 internal constant A_PK = uint256(keccak256("device-A"));
    uint256 internal constant B_PK = uint256(keccak256("device-B"));
    uint256 internal constant C_PK = uint256(keccak256("device-C"));
    uint256 internal constant OUT_PK = uint256(keccak256("outsider"));

    address internal a;
    address internal b;
    address internal c;
    address internal outsider;

    bytes32 internal constant VAULT = keccak256("v2-vault-1");

    function setUp() public {
        recovery = new RecoveryV1();
        revLog = new RevisionLogV2(address(recovery));
        a = vm.addr(A_PK);
        b = vm.addr(B_PK);
        c = vm.addr(C_PK);
        outsider = vm.addr(OUT_PK);
    }

    // -----------------------------------------------------------------
    // Local digest + sign helpers
    // -----------------------------------------------------------------

    function _sign(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _revDigest(bytes32 vaultId, uint16 sv, bytes memory enc)
        internal
        view
        returns (bytes32)
    {
        bytes32 structHash = keccak256(
            abi.encode(
                REVISION_TYPEHASH, vaultId, bytes32(0), bytes32(0), bytes32(0), sv, keccak256(enc)
            )
        );
        return keccak256(abi.encodePacked(hex"1901", revLog.DOMAIN_SEPARATOR(), structHash));
    }

    function _publishSig(uint256 pk, bytes32 vaultId, bytes memory enc)
        internal
        view
        returns (bytes memory)
    {
        return _sign(pk, _revDigest(vaultId, 1, enc));
    }

    function _addSig(uint256 pk, bytes32 vaultId, address newSigner, uint64 nonce)
        internal
        view
        returns (bytes memory)
    {
        return _sign(pk, revLog.hashAddDevice(vaultId, newSigner, nonce, 1));
    }

    function _removeSig(uint256 pk, bytes32 vaultId, address signer, uint64 nonce)
        internal
        view
        returns (bytes memory)
    {
        return _sign(pk, revLog.hashRemoveDevice(vaultId, signer, nonce, 1));
    }

    function _promoteSig(uint256 pk, bytes32 vaultId, address candidate, uint64 nonce)
        internal
        view
        returns (bytes memory)
    {
        return _sign(pk, revLog.hashPromote(vaultId, candidate, nonce, 1));
    }

    /// @dev Bootstrap VAULT with device A as the genesis signer + manager
    ///      (RecoveryV1 has no authority for VAULT, so manager seeds to A).
    function _bootstrapA() internal {
        bytes memory sig = _addSig(A_PK, VAULT, a, 0);
        revLog.bootstrapVault(VAULT, a, 1, sig);
    }

    /// @dev Bootstrap A, then add B (manager A signs, nonce 1).
    function _bootstrapAandAddB() internal {
        _bootstrapA();
        bytes memory sig = _addSig(A_PK, VAULT, b, 1);
        revLog.addDevice(VAULT, b, 1, 1, sig);
    }

    // -----------------------------------------------------------------
    // Byte-pinned EIP-712 domain v2 + typehash parity
    // -----------------------------------------------------------------

    function test_domainSeparator_isVersion2_bytePinned() public view {
        bytes32 expected = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes("Pangolin RevisionLog")),
                keccak256(bytes("2")),
                block.chainid,
                address(revLog)
            )
        );
        assertEq(revLog.DOMAIN_SEPARATOR(), expected, "domain v2 separator byte-pinned");
    }

    /// @dev A V1-domain (version "1") signature can NEVER verify against V2:
    ///      the domain separator differs, so the recovered signer differs.
    function test_v1DomainSignature_doesNotReplayAgainstV2() public {
        _bootstrapA();
        bytes32 v1Domain = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes("Pangolin RevisionLog")),
                keccak256(bytes("1")), // version 1
                block.chainid,
                address(revLog)
            )
        );
        assertTrue(v1Domain != revLog.DOMAIN_SEPARATOR(), "v1/v2 separators differ");
        bytes memory enc = bytes("payload");
        bytes32 structHash = keccak256(
            abi.encode(
                REVISION_TYPEHASH,
                VAULT,
                bytes32(0),
                bytes32(0),
                bytes32(0),
                uint16(1),
                keccak256(enc)
            )
        );
        bytes32 v1Digest = keccak256(abi.encodePacked(hex"1901", v1Domain, structHash));
        bytes memory sig = _sign(A_PK, v1Digest);
        // Recovered signer != A under the real (v2) domain -> not in set.
        vm.expectRevert(ErrSignerNotAuthorized.selector);
        revLog.publishRevision(VAULT, bytes32(0), bytes32(0), bytes32(0), 1, enc, sig);
    }

    function test_hashOracles_matchLocalDigests() public view {
        // AddDevice
        bytes32 addView = revLog.hashAddDevice(VAULT, b, 3, 1);
        bytes32 addLocal = keccak256(
            abi.encodePacked(
                hex"1901",
                revLog.DOMAIN_SEPARATOR(),
                keccak256(abi.encode(ADD_DEVICE_TYPEHASH, VAULT, b, uint64(3), uint16(1)))
            )
        );
        assertEq(addView, addLocal, "hashAddDevice parity");
        // RemoveDevice
        bytes32 remView = revLog.hashRemoveDevice(VAULT, b, 3, 1);
        bytes32 remLocal = keccak256(
            abi.encodePacked(
                hex"1901",
                revLog.DOMAIN_SEPARATOR(),
                keccak256(abi.encode(REMOVE_DEVICE_TYPEHASH, VAULT, b, uint64(3), uint16(1)))
            )
        );
        assertEq(remView, remLocal, "hashRemoveDevice parity");
        // Promote
        bytes32 proView = revLog.hashPromote(VAULT, c, 5, 1);
        bytes32 proLocal = keccak256(
            abi.encodePacked(
                hex"1901",
                revLog.DOMAIN_SEPARATOR(),
                keccak256(abi.encode(PROMOTE_TYPEHASH, VAULT, c, uint64(5), uint16(1)))
            )
        );
        assertEq(proView, proLocal, "hashPromote parity");
        // Revision oracle
        bytes memory enc = bytes("xyz");
        assertEq(
            revLog.hashRevision(VAULT, bytes32(0), bytes32(0), bytes32(0), 1, enc),
            _revDigest(VAULT, 1, enc),
            "hashRevision parity"
        );
    }

    function test_constants() public view {
        assertEq(revLog.MAX_KNOWN_SCHEMA_VERSION(), 1);
        assertEq(revLog.MAX_DEVICES(), 32);
        assertEq(revLog.PROMOTION_DELAY(), 48 hours);
        assertEq(revLog.RECOVERY_V1(), address(recovery));
    }

    // -----------------------------------------------------------------
    // bootstrapVault
    // -----------------------------------------------------------------

    function test_bootstrap_happyPath_seedsManagerToFirstSigner() public {
        bytes memory sig = _addSig(A_PK, VAULT, a, 0);
        vm.expectEmit(true, false, false, true, address(revLog));
        emit VaultBootstrapped(VAULT, a, a, 1);
        revLog.bootstrapVault(VAULT, a, 1, sig);
        assertTrue(revLog.authorizedDevice(VAULT, a), "A authorized");
        assertEq(revLog.authorizedDeviceCount(VAULT), 1);
        assertEq(revLog.deviceManager(VAULT), a, "manager seeded to A");
        assertEq(revLog.deviceNonce(VAULT), 1, "nonce bumped to 1");
        assertTrue(revLog.bootstrapped(VAULT));
    }

    /// @dev When RecoveryV1 has an authority for the vault, the manager
    ///      seeds to THAT authority (Q-h cross-read), not the first signer.
    function test_bootstrap_seedsManagerFromRecoveryAuthority() public {
        // Establish a guardian set on RecoveryV1 so vaultAuthority(VAULT)
        // becomes a non-zero address (the caller).
        bytes32 root = keccak256("some-root");
        vm.prank(c); // c becomes the recovery authority
        recovery.setGuardianSet(VAULT, root, 2, 3, 1);
        assertEq(recovery.vaultAuthority(VAULT), c);

        bytes memory sig = _addSig(A_PK, VAULT, a, 0);
        revLog.bootstrapVault(VAULT, a, 1, sig);
        // Manager seeds to the recovery authority c, not the first signer a.
        assertEq(revLog.deviceManager(VAULT), c, "manager seeded from RecoveryV1 authority");
        // But the SET still contains the genesis device A (the honor rule
        // is on the SET, not the manager).
        assertTrue(revLog.authorizedDevice(VAULT, a));
        // currentManager view reflects the live authority.
        assertEq(revLog.currentManager(VAULT), c);
    }

    function test_bootstrap_revertsOnceOnly() public {
        _bootstrapA();
        bytes memory sig = _addSig(A_PK, VAULT, a, 0);
        vm.expectRevert(ErrVaultAlreadyBootstrapped.selector);
        revLog.bootstrapVault(VAULT, a, 1, sig);
    }

    function test_bootstrap_revertsZeroFirstSigner() public {
        bytes memory sig = new bytes(65);
        vm.expectRevert(ErrZeroValue.selector);
        revLog.bootstrapVault(VAULT, address(0), 1, sig);
    }

    function test_bootstrap_revertsBadSchema() public {
        bytes memory sig = new bytes(65);
        vm.expectRevert(ErrUnsupportedSchemaVersion.selector);
        revLog.bootstrapVault(VAULT, a, 2, sig);
    }

    function test_bootstrap_revertsSignerMismatch() public {
        // Sign with B but claim firstSigner is A -> recovered != firstSigner.
        bytes memory sig = _addSig(B_PK, VAULT, a, 0);
        vm.expectRevert(ErrInvalidSignature.selector);
        revLog.bootstrapVault(VAULT, a, 1, sig);
    }

    function test_bootstrap_revertsBadSigLength() public {
        bytes memory sig = new bytes(64);
        vm.expectRevert(ErrInvalidSignature.selector);
        revLog.bootstrapVault(VAULT, a, 1, sig);
    }

    // -----------------------------------------------------------------
    // publishRevision (honor gate)
    // -----------------------------------------------------------------

    function test_publish_happyPath_honoredInSet() public {
        _bootstrapA();
        bytes memory enc = bytes("rev-1");
        bytes memory sig = _publishSig(A_PK, VAULT, enc);
        vm.expectEmit(true, true, true, true, address(revLog));
        emit RevisionPublished(0, VAULT, bytes32(0), bytes32(0), bytes32(0), 1, enc, a);
        uint256 seq = revLog.publishRevision(VAULT, bytes32(0), bytes32(0), bytes32(0), 1, enc, sig);
        assertEq(seq, 0);
        assertEq(revLog.nextSequence(), 1);
    }

    function test_publish_revertsNotBootstrapped() public {
        bytes memory enc = bytes("x");
        bytes memory sig = _publishSig(A_PK, VAULT, enc);
        vm.expectRevert(ErrVaultNotBootstrapped.selector);
        revLog.publishRevision(VAULT, bytes32(0), bytes32(0), bytes32(0), 1, enc, sig);
    }

    function test_publish_revertsSignerNotInSet() public {
        _bootstrapA();
        bytes memory enc = bytes("x");
        // B is not in the set.
        bytes memory sig = _publishSig(B_PK, VAULT, enc);
        vm.expectRevert(ErrSignerNotAuthorized.selector);
        revLog.publishRevision(VAULT, bytes32(0), bytes32(0), bytes32(0), 1, enc, sig);
    }

    function test_publish_secondDeviceHonoredAfterAdd() public {
        _bootstrapAandAddB();
        bytes memory enc = bytes("from-B");
        bytes memory sig = _publishSig(B_PK, VAULT, enc);
        uint256 seq = revLog.publishRevision(VAULT, bytes32(0), bytes32(0), bytes32(0), 1, enc, sig);
        assertEq(seq, 0, "B's publish honored after add");
    }

    function test_publish_revertsTamperedPayload() public {
        _bootstrapA();
        bytes memory enc = bytes("original");
        bytes memory sig = _publishSig(A_PK, VAULT, enc);
        // Submit a DIFFERENT payload than what was signed.
        vm.expectRevert(ErrSignerNotAuthorized.selector);
        revLog.publishRevision(VAULT, bytes32(0), bytes32(0), bytes32(0), 1, bytes("tampered"), sig);
    }

    function test_publish_revertsBadSchema() public {
        _bootstrapA();
        bytes memory sig = new bytes(65);
        vm.expectRevert(ErrUnsupportedSchemaVersion.selector);
        revLog.publishRevision(VAULT, bytes32(0), bytes32(0), bytes32(0), 2, bytes("x"), sig);
    }

    function test_publish_revertsCrossVaultReplay() public {
        _bootstrapA();
        bytes32 other = keccak256("v2-vault-other");
        bytes memory enc = bytes("x");
        // Sign for `other` but submit against VAULT.
        bytes memory sig = _publishSig(A_PK, other, enc);
        vm.expectRevert(ErrSignerNotAuthorized.selector);
        revLog.publishRevision(VAULT, bytes32(0), bytes32(0), bytes32(0), 1, enc, sig);
    }

    // -----------------------------------------------------------------
    // addDevice
    // -----------------------------------------------------------------

    function test_addDevice_happyPath() public {
        _bootstrapA();
        bytes memory sig = _addSig(A_PK, VAULT, b, 1);
        vm.expectEmit(true, false, false, true, address(revLog));
        emit DeviceAdded(VAULT, b, a, 1, 1);
        revLog.addDevice(VAULT, b, 1, 1, sig);
        assertTrue(revLog.authorizedDevice(VAULT, b));
        assertEq(revLog.authorizedDeviceCount(VAULT), 2);
        assertEq(revLog.deviceNonce(VAULT), 2, "nonce incremented");
    }

    function test_addDevice_revertsWrongManager() public {
        _bootstrapA();
        // B (not the manager) signs the add.
        bytes memory sig = _addSig(B_PK, VAULT, c, 1);
        vm.expectRevert(ErrNotDeviceManager.selector);
        revLog.addDevice(VAULT, c, 1, 1, sig);
    }

    function test_addDevice_revertsBadNonce() public {
        _bootstrapA();
        // Current nonce is 1; sign + submit with nonce 5.
        bytes memory sig = _addSig(A_PK, VAULT, b, 5);
        vm.expectRevert(ErrBadNonce.selector);
        revLog.addDevice(VAULT, b, 5, 1, sig);
    }

    function test_addDevice_revertsReplay() public {
        _bootstrapA();
        bytes memory sig = _addSig(A_PK, VAULT, b, 1);
        revLog.addDevice(VAULT, b, 1, 1, sig);
        // Replaying the same (nonce=1) sig now fails: nonce advanced to 2.
        vm.expectRevert(ErrBadNonce.selector);
        revLog.addDevice(VAULT, c, 1, 1, sig);
    }

    function test_addDevice_revertsDuplicate() public {
        _bootstrapAandAddB();
        // Try to add B again (nonce now 2).
        bytes memory sig = _addSig(A_PK, VAULT, b, 2);
        vm.expectRevert(ErrAlreadyAuthorized.selector);
        revLog.addDevice(VAULT, b, 2, 1, sig);
    }

    function test_addDevice_revertsZeroSigner() public {
        _bootstrapA();
        bytes memory sig = new bytes(65);
        vm.expectRevert(ErrZeroValue.selector);
        revLog.addDevice(VAULT, address(0), 1, 1, sig);
    }

    function test_addDevice_revertsNotBootstrapped() public {
        bytes memory sig = new bytes(65);
        vm.expectRevert(ErrVaultNotBootstrapped.selector);
        revLog.addDevice(VAULT, b, 0, 1, sig);
    }

    function test_addDevice_revertsBadSchema() public {
        _bootstrapA();
        bytes memory sig = new bytes(65);
        vm.expectRevert(ErrUnsupportedSchemaVersion.selector);
        revLog.addDevice(VAULT, b, 1, 2, sig);
    }

    /// @dev MAX_DEVICES cap (Q-i / L16): adding the 33rd device reverts.
    function test_addDevice_revertsSetSizeExceeded() public {
        _bootstrapA(); // count = 1
        uint64 nonce = 1;
        // Add devices 2..32 (31 adds -> count 32).
        for (uint256 i = 0; i < 31; i++) {
            address dev = vm.addr(uint256(keccak256(abi.encode("cap-dev", i))));
            bytes memory sig = _addSig(A_PK, VAULT, dev, nonce);
            revLog.addDevice(VAULT, dev, nonce, 1, sig);
            nonce++;
        }
        assertEq(revLog.authorizedDeviceCount(VAULT), 32);
        // The 33rd add reverts.
        address one = vm.addr(uint256(keccak256("cap-overflow")));
        bytes memory sigOver = _addSig(A_PK, VAULT, one, nonce);
        vm.expectRevert(ErrSetSizeExceeded.selector);
        revLog.addDevice(VAULT, one, nonce, 1, sigOver);
    }

    // -----------------------------------------------------------------
    // removeDevice (+ no-brick)
    // -----------------------------------------------------------------

    function test_removeDevice_happyPath() public {
        _bootstrapAandAddB(); // A manager, B secondary, nonce = 2
        bytes memory sig = _removeSig(A_PK, VAULT, b, 2);
        vm.expectEmit(true, false, false, true, address(revLog));
        emit DeviceRemoved(VAULT, b, a, 2, 1);
        revLog.removeDevice(VAULT, b, 2, 1, sig);
        assertFalse(revLog.authorizedDevice(VAULT, b));
        assertEq(revLog.authorizedDeviceCount(VAULT), 1);
        assertEq(revLog.deviceNonce(VAULT), 3);
    }

    function test_removeDevice_revokedSignerCannotPublish() public {
        _bootstrapAandAddB();
        bytes memory sig = _removeSig(A_PK, VAULT, b, 2);
        revLog.removeDevice(VAULT, b, 2, 1, sig);
        // B is now revoked: publish reverts.
        bytes memory enc = bytes("after-revoke");
        bytes memory pubSig = _publishSig(B_PK, VAULT, enc);
        vm.expectRevert(ErrSignerNotAuthorized.selector);
        revLog.publishRevision(VAULT, bytes32(0), bytes32(0), bytes32(0), 1, enc, pubSig);
    }

    /// @dev No-brick (L10): removing the manager reverts.
    function test_removeDevice_revertsRemoveManager() public {
        _bootstrapAandAddB(); // A is manager + in set
        bytes memory sig = _removeSig(A_PK, VAULT, a, 2);
        vm.expectRevert(ErrWouldBrickVault.selector);
        revLog.removeDevice(VAULT, a, 2, 1, sig);
    }

    /// @dev No-brick (L10): removing the last device reverts (the lone
    ///      device is also the manager, so it hits the manager guard).
    function test_removeDevice_revertsRemoveLast() public {
        _bootstrapA(); // count = 1, A is manager + only device
        bytes memory sig = _removeSig(A_PK, VAULT, a, 1);
        vm.expectRevert(ErrWouldBrickVault.selector);
        revLog.removeDevice(VAULT, a, 1, 1, sig);
    }

    function test_removeDevice_revertsWrongManager() public {
        _bootstrapAandAddB();
        // B signs to remove itself (B is not the manager).
        bytes memory sig = _removeSig(B_PK, VAULT, b, 2);
        vm.expectRevert(ErrNotDeviceManager.selector);
        revLog.removeDevice(VAULT, b, 2, 1, sig);
    }

    function test_removeDevice_revertsNotInSet() public {
        _bootstrapA();
        // c is not in the set.
        bytes memory sig = _removeSig(A_PK, VAULT, c, 1);
        vm.expectRevert(ErrNotAuthorized.selector);
        revLog.removeDevice(VAULT, c, 1, 1, sig);
    }

    function test_removeDevice_revertsBadNonce() public {
        _bootstrapAandAddB();
        bytes memory sig = _removeSig(A_PK, VAULT, b, 9);
        vm.expectRevert(ErrBadNonce.selector);
        revLog.removeDevice(VAULT, b, 9, 1, sig);
    }

    // -----------------------------------------------------------------
    // promotion lifecycle
    // -----------------------------------------------------------------

    function test_promotion_happyPath() public {
        _bootstrapAandAddB(); // A manager, B secondary, nonce = 2
        // B proposes itself.
        bytes memory sig = _promoteSig(B_PK, VAULT, b, 2);
        uint64 expectedReady = uint64(block.timestamp) + 48 hours;
        vm.expectEmit(true, false, false, true, address(revLog));
        emit PromotionProposed(VAULT, b, expectedReady, 1);
        revLog.proposePromotion(VAULT, b, 2, 1, sig);
        (address cand, uint64 readyAt) = revLog.pendingPromotion(VAULT);
        assertEq(cand, b);
        assertEq(readyAt, expectedReady);
        assertEq(revLog.deviceNonce(VAULT), 3, "propose bumps nonce");

        // Finalize before delay reverts.
        vm.expectRevert(ErrPromotionDelayNotElapsed.selector);
        revLog.finalizePromotion(VAULT, 1);

        // Warp past the delay + finalize.
        vm.warp(uint256(expectedReady));
        vm.expectEmit(true, false, false, true, address(revLog));
        emit PromotionFinalized(VAULT, a, b, 1);
        revLog.finalizePromotion(VAULT, 1);
        assertEq(revLog.deviceManager(VAULT), b, "manager rotated to B");
        (address cand2, uint64 readyAt2) = revLog.pendingPromotion(VAULT);
        assertEq(cand2, address(0), "pending cleared");
        assertEq(readyAt2, 0);
    }

    function test_promotion_oldManagerCannotMutateAfterFinalize() public {
        _bootstrapAandAddB();
        bytes memory sig = _promoteSig(B_PK, VAULT, b, 2);
        revLog.proposePromotion(VAULT, b, 2, 1, sig);
        vm.warp(block.timestamp + 48 hours);
        revLog.finalizePromotion(VAULT, 1); // B is now manager, nonce = 3

        // Old manager A tries to add a device -> not the manager anymore.
        bytes memory addSig = _addSig(A_PK, VAULT, c, 3);
        vm.expectRevert(ErrNotDeviceManager.selector);
        revLog.addDevice(VAULT, c, 3, 1, addSig);

        // New manager B can.
        bytes memory addSigB = _addSig(B_PK, VAULT, c, 3);
        revLog.addDevice(VAULT, c, 3, 1, addSigB);
        assertTrue(revLog.authorizedDevice(VAULT, c));
    }

    function test_promotion_managerCancelsWithinWindow() public {
        _bootstrapAandAddB();
        bytes memory sig = _promoteSig(B_PK, VAULT, b, 2);
        revLog.proposePromotion(VAULT, b, 2, 1, sig);
        // Manager A cancels (msg.sender == manager).
        vm.prank(a);
        vm.expectEmit(true, false, false, true, address(revLog));
        emit PromotionCanceled(VAULT, b, 1);
        revLog.cancelPromotion(VAULT, 1);
        (address cand, uint64 readyAt) = revLog.pendingPromotion(VAULT);
        assertEq(cand, address(0));
        assertEq(readyAt, 0);
        // After cancel, finalize reverts (nothing pending).
        vm.warp(block.timestamp + 48 hours);
        vm.expectRevert(ErrNoPromotionPending.selector);
        revLog.finalizePromotion(VAULT, 1);
    }

    function test_promotion_cancelRevertsNonManager() public {
        _bootstrapAandAddB();
        bytes memory sig = _promoteSig(B_PK, VAULT, b, 2);
        revLog.proposePromotion(VAULT, b, 2, 1, sig);
        vm.prank(c); // not the manager
        vm.expectRevert(ErrNotAuthorizedToCancel.selector);
        revLog.cancelPromotion(VAULT, 1);
    }

    function test_promotion_proposeRevertsNonMember() public {
        _bootstrapA();
        // outsider is not in the set; sign as outsider for itself.
        bytes memory sig = _promoteSig(OUT_PK, VAULT, outsider, 1);
        vm.expectRevert(ErrNotSetMember.selector);
        revLog.proposePromotion(VAULT, outsider, 1, 1, sig);
    }

    function test_promotion_proposeRevertsAlreadyPending() public {
        _bootstrapAandAddB();
        bytes memory sig = _promoteSig(B_PK, VAULT, b, 2);
        revLog.proposePromotion(VAULT, b, 2, 1, sig);
        // A second propose (A, nonce now 3) reverts pending.
        bytes memory sigA = _promoteSig(A_PK, VAULT, a, 3);
        vm.expectRevert(ErrPromotionPending.selector);
        revLog.proposePromotion(VAULT, a, 3, 1, sigA);
    }

    function test_promotion_proposeRevertsSelfSigMismatch() public {
        _bootstrapAandAddB();
        // A signs a Promote for candidate B (recovered A != candidate B).
        bytes memory sig = _promoteSig(A_PK, VAULT, b, 2);
        vm.expectRevert(ErrInvalidSignature.selector);
        revLog.proposePromotion(VAULT, b, 2, 1, sig);
    }

    function test_promotion_proposeRevertsBadNonce() public {
        _bootstrapAandAddB();
        bytes memory sig = _promoteSig(B_PK, VAULT, b, 7);
        vm.expectRevert(ErrBadNonce.selector);
        revLog.proposePromotion(VAULT, b, 7, 1, sig);
    }

    function test_promotion_finalizeRevertsNoPending() public {
        _bootstrapA();
        vm.expectRevert(ErrNoPromotionPending.selector);
        revLog.finalizePromotion(VAULT, 1);
    }

    /// @dev If the candidate is removed during the window, finalize reverts
    ///      (defence-in-depth: a removed candidate cannot become manager).
    function test_promotion_finalizeRevertsCandidateRemoved() public {
        _bootstrapAandAddB(); // nonce 2
        // C added so the set has 3 (so B can be removed without bricking).
        bytes memory addC = _addSig(A_PK, VAULT, c, 2);
        revLog.addDevice(VAULT, c, 2, 1, addC); // nonce 3
        // B proposes itself (nonce 3).
        bytes memory pro = _promoteSig(B_PK, VAULT, b, 3);
        revLog.proposePromotion(VAULT, b, 3, 1, pro); // nonce 4
        // Manager A removes B (B is not the manager) during the window.
        bytes memory rem = _removeSig(A_PK, VAULT, b, 4);
        revLog.removeDevice(VAULT, b, 4, 1, rem);
        // Warp + finalize -> candidate no longer in set.
        vm.warp(block.timestamp + 48 hours);
        vm.expectRevert(ErrNotSetMember.selector);
        revLog.finalizePromotion(VAULT, 1);
    }

    function test_promotion_finalizeAtExactBoundary_succeeds() public {
        _bootstrapAandAddB();
        bytes memory sig = _promoteSig(B_PK, VAULT, b, 2);
        revLog.proposePromotion(VAULT, b, 2, 1, sig);
        (, uint64 readyAt) = revLog.pendingPromotion(VAULT);
        vm.warp(uint256(readyAt)); // exactly readyAt (>= boundary)
        revLog.finalizePromotion(VAULT, 1);
        assertEq(revLog.deviceManager(VAULT), b);
    }

    function test_promotion_finalizeIsPermissionless() public {
        _bootstrapAandAddB();
        bytes memory sig = _promoteSig(B_PK, VAULT, b, 2);
        revLog.proposePromotion(VAULT, b, 2, 1, sig);
        vm.warp(block.timestamp + 48 hours);
        vm.prank(address(0xDEAD)); // arbitrary caller
        revLog.finalizePromotion(VAULT, 1);
        assertEq(revLog.deviceManager(VAULT), b);
    }

    // -----------------------------------------------------------------
    // Full lifecycle (prompt-mandated single test)
    // -----------------------------------------------------------------

    /// @dev bootstrap A -> addDevice(B) -> publish-as-B succeeds ->
    ///      removeDevice(B) -> publish-as-B reverts (revoked) ->
    ///      proposePromotion(C) [C added first] -> finalize before 48h
    ///      reverts -> warp(48h) -> finalize succeeds -> C is manager ->
    ///      old manager A can no longer mutate.
    function test_fullLifecycle() public {
        // bootstrap A (manager + device), nonce -> 1
        _bootstrapA();
        assertEq(revLog.deviceManager(VAULT), a);

        // addDevice(B), nonce 1 -> 2
        bytes memory addB = _addSig(A_PK, VAULT, b, 1);
        revLog.addDevice(VAULT, b, 1, 1, addB);

        // publish as B succeeds
        bytes memory encB = bytes("B-rev");
        revLog.publishRevision(
            VAULT, bytes32(0), bytes32(0), bytes32(0), 1, encB, _publishSig(B_PK, VAULT, encB)
        );

        // addDevice(C) so we can remove B and still promote C, nonce 2 -> 3
        bytes memory addC = _addSig(A_PK, VAULT, c, 2);
        revLog.addDevice(VAULT, c, 2, 1, addC);

        // removeDevice(B), nonce 3 -> 4
        bytes memory remB = _removeSig(A_PK, VAULT, b, 3);
        revLog.removeDevice(VAULT, b, 3, 1, remB);

        // publish as B now reverts (revoked)
        bytes memory encB2 = bytes("B-after-revoke");
        bytes memory pubB2 = _publishSig(B_PK, VAULT, encB2);
        vm.expectRevert(ErrSignerNotAuthorized.selector);
        revLog.publishRevision(VAULT, bytes32(0), bytes32(0), bytes32(0), 1, encB2, pubB2);

        // proposePromotion(C), nonce 4 -> 5
        bytes memory proC = _promoteSig(C_PK, VAULT, c, 4);
        revLog.proposePromotion(VAULT, c, 4, 1, proC);

        // finalize before 48h reverts
        vm.expectRevert(ErrPromotionDelayNotElapsed.selector);
        revLog.finalizePromotion(VAULT, 1);

        // warp 48h + finalize -> C manager
        vm.warp(block.timestamp + 48 hours);
        revLog.finalizePromotion(VAULT, 1);
        assertEq(revLog.deviceManager(VAULT), c, "C promoted to manager");

        // old manager A can no longer mutate (add D fails)
        address d = vm.addr(uint256(keccak256("device-D")));
        bytes memory addDByA = _addSig(A_PK, VAULT, d, 5);
        vm.expectRevert(ErrNotDeviceManager.selector);
        revLog.addDevice(VAULT, d, 5, 1, addDByA);

        // new manager C can add D
        bytes memory addDByC = _addSig(C_PK, VAULT, d, 5);
        revLog.addDevice(VAULT, d, 5, 1, addDByC);
        assertTrue(revLog.authorizedDevice(VAULT, d));
    }

    // -----------------------------------------------------------------
    // Cross-read of RecoveryV1 authority (live re-align, Q-k)
    // -----------------------------------------------------------------

    /// @dev When RecoveryV1 finalizes a recovery that rotates vaultAuthority,
    ///      the V2 manager-auth check live-reads the NEW authority — the new
    ///      authority manages devices, the old V2-local manager does not.
    function test_crossRead_recoveryRotationRealignsManager() public {
        // Bootstrap A as the genesis device (manager seeds to A since
        // RecoveryV1 has no authority yet).
        _bootstrapA();
        assertEq(revLog.currentManager(VAULT), a);

        // Now establish a guardian set on RecoveryV1 -> vaultAuthority = c.
        bytes32 root = keccak256("root-x");
        vm.prank(c);
        recovery.setGuardianSet(VAULT, root, 2, 3, 1);
        assertEq(recovery.vaultAuthority(VAULT), c);

        // The live-read now reconciles the manager to c: A can no longer
        // add devices, but c (the recovery authority) can.
        assertEq(revLog.currentManager(VAULT), c, "manager re-aligned to recovery authority");
        bytes memory addByA = _addSig(A_PK, VAULT, b, 1);
        vm.expectRevert(ErrNotDeviceManager.selector);
        revLog.addDevice(VAULT, b, 1, 1, addByA);

        bytes memory addByC = _addSig(C_PK, VAULT, b, 1);
        revLog.addDevice(VAULT, b, 1, 1, addByC);
        assertTrue(revLog.authorizedDevice(VAULT, b));
    }

    // -----------------------------------------------------------------
    // No-admin surface + non-payable + zero RecoveryV1 ctor guard
    // -----------------------------------------------------------------

    function test_constructor_revertsZeroRecoveryV1() public {
        vm.expectRevert(ErrZeroValue.selector);
        new RevisionLogV2(address(0));
    }

    function test_contract_hasNoAdminSelectors() public {
        bytes[18] memory probes = [
            abi.encodeWithSignature("setManager(bytes32,address)", bytes32(0), address(0)),
            abi.encodeWithSignature("forceAddDevice(bytes32,address)", bytes32(0), address(0)),
            abi.encodeWithSignature("forceRemoveDevice(bytes32,address)", bytes32(0), address(0)),
            abi.encodeWithSignature("adminPromote(bytes32,address)", bytes32(0), address(0)),
            abi.encodeWithSignature("pause()"),
            abi.encodeWithSignature("unpause()"),
            abi.encodeWithSignature("paused()"),
            abi.encodeWithSignature("transferOwnership(address)", address(0)),
            abi.encodeWithSignature("renounceOwnership()"),
            abi.encodeWithSignature("owner()"),
            abi.encodeWithSignature("admin()"),
            abi.encodeWithSignature("kill()"),
            abi.encodeWithSignature("destroy()"),
            abi.encodeWithSignature("upgradeTo(address)", address(0)),
            abi.encodeWithSignature("implementation()"),
            abi.encodeWithSignature("setDomainSeparator(bytes32)", bytes32(0)),
            abi.encodeWithSignature("resetVault(bytes32)", bytes32(0)),
            abi.encodeWithSignature("setRecoveryV1(address)", address(0))
        ];
        for (uint256 i = 0; i < probes.length; i++) {
            (bool ok, bytes memory ret) = address(revLog).call(probes[i]);
            assertFalse(ok, "admin/proxy selector must not exist");
            assertEq(ret.length, 0, "no return data from missing admin selector");
        }
    }

    function test_contract_rejectsEth() public {
        vm.deal(address(this), 1 ether);
        (bool ok1,) = address(revLog).call{value: 1 wei}("");
        assertFalse(ok1, "empty calldata with value must revert (no receive())");
        (bool ok2,) = address(revLog).call{value: 1 wei}(hex"deadbeef");
        assertFalse(ok2, "unknown selector with value must revert");
        (bool ok3,) = address(revLog).call{value: 0}(hex"deadbeef");
        assertFalse(ok3, "unknown selector with no fallback must revert");
    }

    /// @dev Two vaults are isolated: bootstrap of one does not affect the
    ///      other.
    function test_multiVaultIsolation() public {
        _bootstrapA();
        bytes32 vaultB = keccak256("v2-vault-2");
        bytes memory sig = _addSig(B_PK, vaultB, b, 0);
        revLog.bootstrapVault(vaultB, b, 1, sig);
        assertEq(revLog.deviceManager(VAULT), a);
        assertEq(revLog.deviceManager(vaultB), b);
        assertTrue(revLog.authorizedDevice(VAULT, a));
        assertFalse(revLog.authorizedDevice(VAULT, b));
        assertTrue(revLog.authorizedDevice(vaultB, b));
        assertFalse(revLog.authorizedDevice(vaultB, a));
    }
}
