// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {RecoveryV2} from "../src/RecoveryV2.sol";

/// @title RecoveryV2 unit tests
/// @notice Port of RecoveryV1.t.sol with the V2 commitment field threaded
///         through every call / destructure / digest, plus four new
///         V2-specific cases at the end (zero-commitment rejected,
///         commitment stored + emitted, Approve digest covers the
///         commitment, V1-shape approval rejected by typehash mismatch).
contract RecoveryV2Test is Test {
    RecoveryV2 internal rec;

    // Re-declared so vm.expectEmit can match.
    event GuardianSetInitialized(
        bytes32 indexed vaultId,
        bytes32 root,
        uint8 threshold,
        uint8 guardianCount,
        address initialAuthority,
        uint16 schemaVersion
    );
    event RecoveryInitiated(
        bytes32 indexed vaultId,
        uint64 indexed attemptNonce,
        address proposedAuthority,
        uint64 initiatedAt,
        bytes32 recipientCommitment,
        uint16 schemaVersion
    );
    event RecoveryApproved(
        bytes32 indexed vaultId,
        uint64 indexed attemptNonce,
        address guardian,
        uint8 approvals,
        uint16 schemaVersion
    );
    event RecoveryCanceled(
        bytes32 indexed vaultId, uint64 indexed attemptNonce, uint16 schemaVersion
    );
    event RecoveryFinalized(
        bytes32 indexed vaultId,
        uint64 indexed attemptNonce,
        address oldAuthority,
        address newAuthority,
        uint16 schemaVersion
    );

    error ErrGuardianSetAlreadyInitialized();
    error ErrThresholdOutOfBounds();
    error ErrGuardianCountOutOfBounds();
    error ErrZeroValue();
    error ErrGuardianSetNotInitialized();
    error ErrRecoveryAlreadyPending();
    error ErrNoActiveRecovery();
    error ErrInvalidSignature();
    error ErrInvalidMerkleProof();
    error ErrDuplicateApproval();
    error ErrDelayNotElapsed();
    error ErrThresholdNotMet();
    error ErrNotAuthorizedToCancel();
    error ErrApprovalExpired();
    error ErrUnsupportedSchemaVersion();

    bytes32 internal constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    /// V2 typehash — six fields, includes `recipientCommitment` between
    /// `expiresAt` and `schemaVersion`. Drift = CI red.
    bytes32 internal constant APPROVE_TYPEHASH_V2 = keccak256(
        "Approve(bytes32 vaultId,address proposedAuthority,uint64 attemptNonce,uint64 expiresAt,bytes32 recipientCommitment,uint16 schemaVersion)"
    );
    /// V1 typehash kept for the rejects-V1-shape-approval test only.
    bytes32 internal constant APPROVE_TYPEHASH_V1 = keccak256(
        "Approve(bytes32 vaultId,address proposedAuthority,uint64 attemptNonce,uint64 expiresAt,uint16 schemaVersion)"
    );

    uint256 internal constant G0_PK = uint256(keccak256("guardian-0"));
    uint256 internal constant G1_PK = uint256(keccak256("guardian-1"));
    uint256 internal constant G2_PK = uint256(keccak256("guardian-2"));
    uint256 internal constant G3_PK = uint256(keccak256("guardian-3"));
    uint256 internal constant OUTSIDER_PK = uint256(keccak256("outsider"));

    address internal g0;
    address internal g1;
    address internal g2;
    address internal g3;
    address internal outsider;

    bytes32 internal constant VAULT = keccak256("vault-recovery-v2-1");
    address internal constant AUTHORITY = address(0xA17F0);
    address internal constant NEW_AUTH = address(0xBEEF);

    /// Non-zero recipient commitment for tests (mimics a 32-byte X25519
    /// pubkey). The exact bytes are not crypto-significant; only the
    /// non-zero property + roundtrip pinning matters here.
    bytes32 internal constant COMMITMENT =
        bytes32(uint256(0xC011117EDB000000_DEADBEEFCAFE0123_456789ABCDEFABCD_EFAABBCCDDEEFF11));
    bytes32 internal constant COMMITMENT_2 =
        bytes32(uint256(0xC011117EDB111111_FFFFFFFFFFFF1010_1010101010101010_2020202020202020));

    bytes32[4] internal leaves;
    bytes32 internal root;

    function setUp() public {
        rec = new RecoveryV2();
        g0 = vm.addr(G0_PK);
        g1 = vm.addr(G1_PK);
        g2 = vm.addr(G2_PK);
        g3 = vm.addr(G3_PK);
        outsider = vm.addr(OUTSIDER_PK);

        leaves[0] = keccak256(abi.encode(g0));
        leaves[1] = keccak256(abi.encode(g1));
        leaves[2] = keccak256(abi.encode(g2));
        leaves[3] = keccak256(abi.encode(g3));
        root = _buildRoot4(leaves);
    }

    // -----------------------------------------------------------------
    // Merkle helpers
    // -----------------------------------------------------------------

    function _hashPair(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return a <= b ? keccak256(abi.encodePacked(a, b)) : keccak256(abi.encodePacked(b, a));
    }

    function _buildRoot4(bytes32[4] memory ls) internal pure returns (bytes32) {
        bytes32 n01 = _hashPair(ls[0], ls[1]);
        bytes32 n23 = _hashPair(ls[2], ls[3]);
        return _hashPair(n01, n23);
    }

    function _proof4(bytes32[4] memory ls, uint256 idx) internal pure returns (bytes32[] memory) {
        bytes32[] memory p = new bytes32[](2);
        bytes32 n01 = _hashPair(ls[0], ls[1]);
        bytes32 n23 = _hashPair(ls[2], ls[3]);
        if (idx == 0) {
            p[0] = ls[1];
            p[1] = n23;
        } else if (idx == 1) {
            p[0] = ls[0];
            p[1] = n23;
        } else if (idx == 2) {
            p[0] = ls[3];
            p[1] = n01;
        } else {
            p[0] = ls[2];
            p[1] = n01;
        }
        return p;
    }

    function _sign(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    /// V2 helper: signs over the V2 6-field digest (commitment included).
    function _approveSig(
        uint256 pk,
        address proposed,
        uint64 nonce,
        uint64 expiresAt,
        bytes32 commitment
    ) internal view returns (bytes memory) {
        return _sign(pk, rec.hashApprove(VAULT, proposed, nonce, expiresAt, commitment, 1));
    }

    function _bootstrap() internal {
        vm.prank(AUTHORITY);
        rec.setGuardianSet(VAULT, root, 3, 4, 1);
    }

    function _initiate() internal returns (uint64 nonce) {
        _bootstrap();
        rec.initiateRecovery(VAULT, NEW_AUTH, COMMITMENT, 1);
        (,, nonce,,,) = rec.recovery(VAULT);
    }

    function _approveBy(uint256 pk, uint256 idx, uint64 nonce, uint64 expiresAt) internal {
        bytes memory sig = _approveSig(pk, NEW_AUTH, nonce, expiresAt, COMMITMENT);
        rec.approveRecovery(VAULT, vm.addr(pk), _proof4(leaves, idx), expiresAt, 1, sig);
    }

    // -----------------------------------------------------------------
    // Happy-path lifecycle
    // -----------------------------------------------------------------

    function test_fullLifecycle_happyPath() public {
        vm.expectEmit(true, false, false, true, address(rec));
        emit GuardianSetInitialized(VAULT, root, 3, 4, AUTHORITY, 1);
        vm.prank(AUTHORITY);
        rec.setGuardianSet(VAULT, root, 3, 4, 1);
        assertEq(rec.vaultAuthority(VAULT), AUTHORITY);

        uint64 t0 = uint64(block.timestamp);
        vm.expectEmit(true, true, false, true, address(rec));
        emit RecoveryInitiated(VAULT, 1, NEW_AUTH, t0, COMMITMENT, 1);
        rec.initiateRecovery(VAULT, NEW_AUTH, COMMITMENT, 1);
        (
            address proposed,
            uint64 initiatedAt,
            uint64 nonce,
            uint8 approvals,
            RecoveryV2.Status st,
            bytes32 storedCommit
        ) = rec.recovery(VAULT);
        assertEq(proposed, NEW_AUTH);
        assertEq(initiatedAt, t0);
        assertEq(nonce, 1);
        assertEq(approvals, 0);
        assertEq(uint8(st), uint8(RecoveryV2.Status.Pending));
        assertEq(storedCommit, COMMITMENT, "commitment stored on initiate");

        uint64 exp = t0 + 1000;
        _approveBy(G0_PK, 0, 1, exp);
        _approveBy(G1_PK, 1, 1, exp);
        vm.expectEmit(true, true, false, true, address(rec));
        emit RecoveryApproved(VAULT, 1, g2, 3, 1);
        _approveBy(G2_PK, 2, 1, exp);
        (,,, approvals,,) = rec.recovery(VAULT);
        assertEq(approvals, 3);

        vm.warp(block.timestamp + 72 hours + 1);
        vm.expectEmit(true, true, false, true, address(rec));
        emit RecoveryFinalized(VAULT, 1, AUTHORITY, NEW_AUTH, 1);
        rec.finalizeRecovery(VAULT, 1);
        assertEq(rec.vaultAuthority(VAULT), NEW_AUTH);
        (,,,, st,) = rec.recovery(VAULT);
        assertEq(uint8(st), uint8(RecoveryV2.Status.Finalized));
    }

    function test_secondAttemptAfterFinalize_freshNonceAndApprovals() public {
        uint64 n1 = _initiate();
        uint64 exp = uint64(block.timestamp) + 1000;
        _approveBy(G0_PK, 0, n1, exp);
        _approveBy(G1_PK, 1, n1, exp);
        _approveBy(G2_PK, 2, n1, exp);
        vm.warp(block.timestamp + 72 hours + 1);
        rec.finalizeRecovery(VAULT, 1);
        assertEq(rec.vaultAuthority(VAULT), NEW_AUTH);

        rec.initiateRecovery(VAULT, address(0xCAFE), COMMITMENT_2, 1);
        (,, uint64 n2, uint8 approvals, RecoveryV2.Status st, bytes32 c) = rec.recovery(VAULT);
        assertEq(n2, 2);
        assertEq(approvals, 0);
        assertEq(uint8(st), uint8(RecoveryV2.Status.Pending));
        assertEq(c, COMMITMENT_2, "second attempt's commitment overwrites first");
    }

    function test_cancelThenReinitiate() public {
        _initiate();
        vm.prank(AUTHORITY);
        rec.cancelRecovery(VAULT, 1);
        (,,,, RecoveryV2.Status st,) = rec.recovery(VAULT);
        assertEq(uint8(st), uint8(RecoveryV2.Status.Canceled));
        rec.initiateRecovery(VAULT, NEW_AUTH, COMMITMENT, 1);
        (,, uint64 n,, RecoveryV2.Status st2,) = rec.recovery(VAULT);
        assertEq(n, 2);
        assertEq(uint8(st2), uint8(RecoveryV2.Status.Pending));
    }

    // -----------------------------------------------------------------
    // setGuardianSet revert paths (verbatim from V1; no V2 surface change)
    // -----------------------------------------------------------------

    function test_setGuardianSet_revertsDoubleInit() public {
        _bootstrap();
        vm.prank(AUTHORITY);
        vm.expectRevert(ErrGuardianSetAlreadyInitialized.selector);
        rec.setGuardianSet(VAULT, root, 3, 4, 1);
    }

    function test_setGuardianSet_revertsZeroRoot() public {
        vm.expectRevert(ErrZeroValue.selector);
        rec.setGuardianSet(VAULT, bytes32(0), 3, 4, 1);
    }

    function test_setGuardianSet_revertsThresholdTooLow() public {
        vm.expectRevert(ErrThresholdOutOfBounds.selector);
        rec.setGuardianSet(VAULT, root, 1, 4, 1);
    }

    function test_setGuardianSet_revertsThresholdTooHigh() public {
        vm.expectRevert(ErrThresholdOutOfBounds.selector);
        rec.setGuardianSet(VAULT, root, 10, 12, 1);
    }

    function test_setGuardianSet_revertsThresholdGtCount() public {
        vm.expectRevert(ErrThresholdOutOfBounds.selector);
        rec.setGuardianSet(VAULT, root, 5, 4, 1);
    }

    function test_setGuardianSet_revertsCountTooLow() public {
        vm.expectRevert(ErrGuardianCountOutOfBounds.selector);
        rec.setGuardianSet(VAULT, root, 2, 2, 1);
    }

    function test_setGuardianSet_revertsCountTooHigh() public {
        vm.expectRevert(ErrGuardianCountOutOfBounds.selector);
        rec.setGuardianSet(VAULT, root, 3, 16, 1);
    }

    function test_setGuardianSet_revertsUnsupportedSchema() public {
        vm.expectRevert(ErrUnsupportedSchemaVersion.selector);
        rec.setGuardianSet(VAULT, root, 3, 4, 2);
    }

    function test_setGuardianSet_boundaryValues_accepted() public {
        rec.setGuardianSet(keccak256("v-min"), root, 2, 3, 1);
        rec.setGuardianSet(keccak256("v-max"), root, 9, 15, 1);
        rec.setGuardianSet(keccak256("v-eq"), root, 4, 4, 1);
    }

    // -----------------------------------------------------------------
    // initiateRecovery revert paths (commitment threaded through)
    // -----------------------------------------------------------------

    function test_initiate_revertsNoGuardianSet() public {
        vm.expectRevert(ErrGuardianSetNotInitialized.selector);
        rec.initiateRecovery(VAULT, NEW_AUTH, COMMITMENT, 1);
    }

    function test_initiate_revertsZeroProposed() public {
        _bootstrap();
        vm.expectRevert(ErrZeroValue.selector);
        rec.initiateRecovery(VAULT, address(0), COMMITMENT, 1);
    }

    function test_initiate_revertsAlreadyPending() public {
        _initiate();
        vm.expectRevert(ErrRecoveryAlreadyPending.selector);
        rec.initiateRecovery(VAULT, NEW_AUTH, COMMITMENT, 1);
    }

    function test_initiate_revertsUnsupportedSchema() public {
        _bootstrap();
        vm.expectRevert(ErrUnsupportedSchemaVersion.selector);
        rec.initiateRecovery(VAULT, NEW_AUTH, COMMITMENT, 2);
    }

    // -----------------------------------------------------------------
    // approveRecovery revert paths
    // -----------------------------------------------------------------

    function test_approve_revertsNoActiveRecovery() public {
        _bootstrap();
        uint64 exp = uint64(block.timestamp) + 1000;
        bytes memory sig = _approveSig(G0_PK, NEW_AUTH, 1, exp, COMMITMENT);
        vm.expectRevert(ErrNoActiveRecovery.selector);
        rec.approveRecovery(VAULT, g0, _proof4(leaves, 0), exp, 1, sig);
    }

    function test_approve_revertsExpired() public {
        uint64 n = _initiate();
        uint64 exp = uint64(block.timestamp);
        vm.warp(block.timestamp + 1);
        bytes memory sig = _approveSig(G0_PK, NEW_AUTH, n, exp, COMMITMENT);
        vm.expectRevert(ErrApprovalExpired.selector);
        rec.approveRecovery(VAULT, g0, _proof4(leaves, 0), exp, 1, sig);
    }

    function test_approve_revertsNonGuardianMerkle() public {
        uint64 n = _initiate();
        uint64 exp = uint64(block.timestamp) + 1000;
        bytes memory sig = _approveSig(OUTSIDER_PK, NEW_AUTH, n, exp, COMMITMENT);
        vm.expectRevert(ErrInvalidMerkleProof.selector);
        rec.approveRecovery(VAULT, outsider, _proof4(leaves, 0), exp, 1, sig);
    }

    function test_approve_revertsWrongLeafForRealGuardian() public {
        uint64 n = _initiate();
        uint64 exp = uint64(block.timestamp) + 1000;
        bytes memory sig = _approveSig(G0_PK, NEW_AUTH, n, exp, COMMITMENT);
        vm.expectRevert(ErrInvalidMerkleProof.selector);
        rec.approveRecovery(VAULT, g0, _proof4(leaves, 1), exp, 1, sig);
    }

    function test_approve_revertsSignerLeafMismatch() public {
        uint64 n = _initiate();
        uint64 exp = uint64(block.timestamp) + 1000;
        bytes memory sig = _approveSig(G0_PK, NEW_AUTH, n, exp, COMMITMENT);
        vm.expectRevert(ErrInvalidSignature.selector);
        rec.approveRecovery(VAULT, g1, _proof4(leaves, 1), exp, 1, sig);
    }

    function test_approve_revertsDuplicate() public {
        uint64 n = _initiate();
        uint64 exp = uint64(block.timestamp) + 1000;
        _approveBy(G0_PK, 0, n, exp);
        bytes memory sig = _approveSig(G0_PK, NEW_AUTH, n, exp, COMMITMENT);
        vm.expectRevert(ErrDuplicateApproval.selector);
        rec.approveRecovery(VAULT, g0, _proof4(leaves, 0), exp, 1, sig);
    }

    function test_approve_revertsBadSigLength() public {
        _initiate();
        uint64 exp = uint64(block.timestamp) + 1000;
        bytes memory shortSig = new bytes(64);
        vm.expectRevert(ErrInvalidSignature.selector);
        rec.approveRecovery(VAULT, g0, _proof4(leaves, 0), exp, 1, shortSig);
    }

    function test_approve_revertsBadV() public {
        uint64 n = _initiate();
        uint64 exp = uint64(block.timestamp) + 1000;
        (, bytes32 r, bytes32 s) =
            vm.sign(G0_PK, rec.hashApprove(VAULT, NEW_AUTH, n, exp, COMMITMENT, 1));
        bytes memory badV = abi.encodePacked(r, s, uint8(26));
        vm.expectRevert(ErrInvalidSignature.selector);
        rec.approveRecovery(VAULT, g0, _proof4(leaves, 0), exp, 1, badV);
    }

    function test_approve_revertsHighS() public {
        uint64 n = _initiate();
        uint64 exp = uint64(block.timestamp) + 1000;
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(G0_PK, rec.hashApprove(VAULT, NEW_AUTH, n, exp, COMMITMENT, 1));
        uint256 N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
        bytes32 highS = bytes32(N - uint256(s));
        uint8 flippedV = v == 27 ? 28 : 27;
        bytes memory mall = abi.encodePacked(r, highS, flippedV);
        vm.expectRevert(ErrInvalidSignature.selector);
        rec.approveRecovery(VAULT, g0, _proof4(leaves, 0), exp, 1, mall);
    }

    function test_approve_revertsZeroRZeroS() public {
        _initiate();
        uint64 exp = uint64(block.timestamp) + 1000;
        bytes memory sig = abi.encodePacked(bytes32(0), bytes32(0), uint8(27));
        vm.expectRevert(ErrInvalidSignature.selector);
        rec.approveRecovery(VAULT, g0, _proof4(leaves, 0), exp, 1, sig);
    }

    function test_approve_revertsUnsupportedSchema() public {
        _initiate();
        uint64 exp = uint64(block.timestamp) + 1000;
        bytes memory sig = new bytes(65);
        vm.expectRevert(ErrUnsupportedSchemaVersion.selector);
        rec.approveRecovery(VAULT, g0, _proof4(leaves, 0), exp, 2, sig);
    }

    function test_approve_revertsStaleAttemptNonce() public {
        uint64 n1 = _initiate();
        uint64 exp = uint64(block.timestamp) + 100000;
        bytes memory sig = _approveSig(G0_PK, NEW_AUTH, n1, exp, COMMITMENT);
        vm.prank(AUTHORITY);
        rec.cancelRecovery(VAULT, 1);
        rec.initiateRecovery(VAULT, NEW_AUTH, COMMITMENT, 1);
        vm.expectRevert(ErrInvalidSignature.selector);
        rec.approveRecovery(VAULT, g0, _proof4(leaves, 0), exp, 1, sig);
    }

    // -----------------------------------------------------------------
    // finalizeRecovery revert paths (no V2 surface change)
    // -----------------------------------------------------------------

    function test_finalize_revertsNoActiveRecovery() public {
        _bootstrap();
        vm.expectRevert(ErrNoActiveRecovery.selector);
        rec.finalizeRecovery(VAULT, 1);
    }

    function test_finalize_revertsBelowThreshold() public {
        uint64 n = _initiate();
        uint64 exp = uint64(block.timestamp) + 1000;
        _approveBy(G0_PK, 0, n, exp);
        _approveBy(G1_PK, 1, n, exp);
        vm.warp(block.timestamp + 72 hours + 1);
        vm.expectRevert(ErrThresholdNotMet.selector);
        rec.finalizeRecovery(VAULT, 1);
    }

    function test_finalize_revertsBeforeDelay() public {
        uint64 n = _initiate();
        uint64 exp = uint64(block.timestamp) + 1000000;
        _approveBy(G0_PK, 0, n, exp);
        _approveBy(G1_PK, 1, n, exp);
        _approveBy(G2_PK, 2, n, exp);
        vm.warp(block.timestamp + 72 hours - 1);
        vm.expectRevert(ErrDelayNotElapsed.selector);
        rec.finalizeRecovery(VAULT, 1);
    }

    function test_finalize_atExactDelayBoundary_succeeds() public {
        uint64 t0 = uint64(block.timestamp);
        uint64 n = _initiate();
        uint64 exp = t0 + 1000000;
        _approveBy(G0_PK, 0, n, exp);
        _approveBy(G1_PK, 1, n, exp);
        _approveBy(G2_PK, 2, n, exp);
        vm.warp(uint256(t0) + 72 hours);
        rec.finalizeRecovery(VAULT, 1);
        assertEq(rec.vaultAuthority(VAULT), NEW_AUTH);
    }

    function test_finalize_revertsUnsupportedSchema() public {
        _initiate();
        vm.expectRevert(ErrUnsupportedSchemaVersion.selector);
        rec.finalizeRecovery(VAULT, 2);
    }

    function test_cancelThenFinalize_blocked() public {
        uint64 n = _initiate();
        uint64 exp = uint64(block.timestamp) + 1000000;
        _approveBy(G0_PK, 0, n, exp);
        _approveBy(G1_PK, 1, n, exp);
        _approveBy(G2_PK, 2, n, exp);
        vm.prank(AUTHORITY);
        rec.cancelRecovery(VAULT, 1);
        vm.warp(block.timestamp + 72 hours + 1);
        vm.expectRevert(ErrNoActiveRecovery.selector);
        rec.finalizeRecovery(VAULT, 1);
        assertEq(rec.vaultAuthority(VAULT), AUTHORITY);
    }

    // -----------------------------------------------------------------
    // cancelRecovery revert paths
    // -----------------------------------------------------------------

    function test_cancel_revertsWrongAuthority() public {
        _initiate();
        vm.prank(address(0xBAD));
        vm.expectRevert(ErrNotAuthorizedToCancel.selector);
        rec.cancelRecovery(VAULT, 1);
    }

    function test_cancel_revertsNoActiveRecovery() public {
        _bootstrap();
        vm.prank(AUTHORITY);
        vm.expectRevert(ErrNoActiveRecovery.selector);
        rec.cancelRecovery(VAULT, 1);
    }

    function test_cancel_revertsUnsupportedSchema() public {
        _initiate();
        vm.prank(AUTHORITY);
        vm.expectRevert(ErrUnsupportedSchemaVersion.selector);
        rec.cancelRecovery(VAULT, 2);
    }

    function test_cancel_authorityFollowsRotation() public {
        uint64 n = _initiate();
        uint64 exp = uint64(block.timestamp) + 1000000;
        _approveBy(G0_PK, 0, n, exp);
        _approveBy(G1_PK, 1, n, exp);
        _approveBy(G2_PK, 2, n, exp);
        vm.warp(block.timestamp + 72 hours + 1);
        rec.finalizeRecovery(VAULT, 1);

        rec.initiateRecovery(VAULT, address(0xCAFE), COMMITMENT, 1);
        vm.prank(AUTHORITY);
        vm.expectRevert(ErrNotAuthorizedToCancel.selector);
        rec.cancelRecovery(VAULT, 1);
        vm.prank(NEW_AUTH);
        rec.cancelRecovery(VAULT, 1);
        (,,,, RecoveryV2.Status st,) = rec.recovery(VAULT);
        assertEq(uint8(st), uint8(RecoveryV2.Status.Canceled));
    }

    // -----------------------------------------------------------------
    // Cross-chain / wrong-binding replay rejection
    // -----------------------------------------------------------------

    function test_approve_rejectsCrossChainReplay() public {
        uint64 n = _initiate();
        uint64 exp = uint64(block.timestamp) + 1000;
        bytes32 fakeDomain = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes("Pangolin Recovery")),
                keccak256(bytes("1")),
                uint256(999),
                address(rec)
            )
        );
        assertTrue(fakeDomain != rec.DOMAIN_SEPARATOR());
        bytes32 structHash = keccak256(
            abi.encode(APPROVE_TYPEHASH_V2, VAULT, NEW_AUTH, n, exp, COMMITMENT, uint16(1))
        );
        bytes32 fakeDigest = keccak256(abi.encodePacked(hex"1901", fakeDomain, structHash));
        bytes memory sig = _sign(G0_PK, fakeDigest);
        vm.expectRevert(ErrInvalidSignature.selector);
        rec.approveRecovery(VAULT, g0, _proof4(leaves, 0), exp, 1, sig);
    }

    function test_approve_rejectsWrongProposedAuthorityBinding() public {
        uint64 n = _initiate();
        uint64 exp = uint64(block.timestamp) + 1000;
        bytes memory sig = _approveSig(G0_PK, address(0xDEAD), n, exp, COMMITMENT);
        vm.expectRevert(ErrInvalidSignature.selector);
        rec.approveRecovery(VAULT, g0, _proof4(leaves, 0), exp, 1, sig);
    }

    // -----------------------------------------------------------------
    // Digest-oracle parity
    // -----------------------------------------------------------------

    function test_hashApprove_matchesLocalDigest() public view {
        uint64 exp = 12345;
        bytes32 viaView = rec.hashApprove(VAULT, NEW_AUTH, 7, exp, COMMITMENT, 1);
        bytes32 structHash = keccak256(
            abi.encode(APPROVE_TYPEHASH_V2, VAULT, NEW_AUTH, uint64(7), exp, COMMITMENT, uint16(1))
        );
        bytes32 viaLocal =
            keccak256(abi.encodePacked(hex"1901", rec.DOMAIN_SEPARATOR(), structHash));
        assertEq(viaView, viaLocal);
    }

    function test_hashCancel_and_hashInitiate_areViewOnly() public view {
        assertTrue(rec.hashCancel(VAULT, 1, 1) != bytes32(0));
        assertTrue(rec.hashInitiate(VAULT, NEW_AUTH, 1, COMMITMENT, 1) != bytes32(0));
    }

    function test_domainSeparator_bindsContractAddress() public {
        bytes32 expected = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes("Pangolin Recovery")),
                keccak256(bytes("1")),
                block.chainid,
                address(rec)
            )
        );
        assertEq(rec.DOMAIN_SEPARATOR(), expected);
        RecoveryV2 other = new RecoveryV2();
        assertTrue(other.DOMAIN_SEPARATOR() != rec.DOMAIN_SEPARATOR());
    }

    // -----------------------------------------------------------------
    // Merkle verification correctness
    // -----------------------------------------------------------------

    function test_merkle_allFourLeavesVerify() public {
        uint64 n = _initiate();
        uint64 exp = uint64(block.timestamp) + 1000;
        _approveBy(G0_PK, 0, n, exp);
        _approveBy(G1_PK, 1, n, exp);
        _approveBy(G2_PK, 2, n, exp);
        _approveBy(G3_PK, 3, n, exp);
        (,,, uint8 approvals,,) = rec.recovery(VAULT);
        assertEq(approvals, 4);
    }

    function test_merkle_forgedProofRejected() public {
        uint64 n = _initiate();
        uint64 exp = uint64(block.timestamp) + 1000;
        bytes32[] memory forged = new bytes32[](2);
        forged[0] = keccak256("forged-a");
        forged[1] = keccak256("forged-b");
        bytes memory sig = _approveSig(G0_PK, NEW_AUTH, n, exp, COMMITMENT);
        vm.expectRevert(ErrInvalidMerkleProof.selector);
        rec.approveRecovery(VAULT, g0, forged, exp, 1, sig);
    }

    // -----------------------------------------------------------------
    // No-admin surface + non-payable + constants
    // -----------------------------------------------------------------

    function test_contract_hasNoAdminSelectors() public {
        bytes[20] memory probes = [
            abi.encodeWithSignature("forceFinalize(bytes32)", bytes32(0)),
            abi.encodeWithSignature("adminCancel(bytes32)", bytes32(0)),
            abi.encodeWithSignature("setAuthority(bytes32,address)", bytes32(0), address(0)),
            abi.encodeWithSignature("setThreshold(bytes32,uint8)", bytes32(0), uint8(0)),
            abi.encodeWithSignature("pauseRecovery()"),
            abi.encodeWithSignature("removeGuardian(bytes32,address)", bytes32(0), address(0)),
            abi.encodeWithSignature("updateGuardianSet(bytes32,bytes32)", bytes32(0), bytes32(0)),
            abi.encodeWithSignature("transferOwnership(address)", address(0)),
            abi.encodeWithSignature("renounceOwnership()"),
            abi.encodeWithSignature("owner()"),
            abi.encodeWithSignature("admin()"),
            abi.encodeWithSignature("pause()"),
            abi.encodeWithSignature("unpause()"),
            abi.encodeWithSignature("paused()"),
            abi.encodeWithSignature("kill()"),
            abi.encodeWithSignature("destroy()"),
            abi.encodeWithSignature("upgradeTo(address)", address(0)),
            abi.encodeWithSignature("implementation()"),
            abi.encodeWithSignature("setMinDelay(uint64)", uint64(0)),
            abi.encodeWithSignature("resetRecovery(bytes32)", bytes32(0))
        ];
        for (uint256 i = 0; i < probes.length; i++) {
            (bool ok, bytes memory ret) = address(rec).call(probes[i]);
            assertFalse(ok);
            assertEq(ret.length, 0);
        }
    }

    function test_contract_rejectsEth() public {
        vm.deal(address(this), 1 ether);
        (bool ok1,) = address(rec).call{value: 1 wei}("");
        assertFalse(ok1);
        (bool ok2,) = address(rec).call{value: 1 wei}(hex"deadbeef");
        assertFalse(ok2);
        (bool ok3,) = address(rec).call{value: 0}(hex"deadbeef");
        assertFalse(ok3);
        bytes memory cd = abi.encodeWithSelector(
            RecoveryV2.initiateRecovery.selector, VAULT, NEW_AUTH, COMMITMENT, uint16(1)
        );
        (bool ok4,) = address(rec).call{value: 1 wei}(cd);
        assertFalse(ok4);
    }

    function test_constants() public view {
        assertEq(rec.MAX_KNOWN_SCHEMA_VERSION(), 1);
        assertEq(rec.MIN_DELAY(), 72 hours);
        assertEq(rec.MIN_THRESHOLD(), 2);
        assertEq(rec.MAX_THRESHOLD(), 9);
        assertEq(rec.MIN_GUARDIANS(), 3);
        assertEq(rec.MAX_GUARDIANS(), 15);
    }

    function test_initiateAndFinalize_arePermissionless() public {
        _bootstrap();
        vm.prank(address(0x1234));
        rec.initiateRecovery(VAULT, NEW_AUTH, COMMITMENT, 1);
        (,, uint64 n,,,) = rec.recovery(VAULT);
        uint64 exp = uint64(block.timestamp) + 1000000;
        _approveBy(G0_PK, 0, n, exp);
        _approveBy(G1_PK, 1, n, exp);
        _approveBy(G2_PK, 2, n, exp);
        vm.warp(block.timestamp + 72 hours + 1);
        vm.prank(address(0x5678));
        rec.finalizeRecovery(VAULT, 1);
        assertEq(rec.vaultAuthority(VAULT), NEW_AUTH);
    }

    function test_multiVaultIsolation() public {
        bytes32 vaultB = keccak256("vault-B");
        _bootstrap();
        vm.prank(address(0x9999));
        rec.setGuardianSet(vaultB, root, 2, 3, 1);
        assertEq(rec.vaultAuthority(VAULT), AUTHORITY);
        assertEq(rec.vaultAuthority(vaultB), address(0x9999));
        rec.initiateRecovery(VAULT, NEW_AUTH, COMMITMENT, 1);
        (,,,, RecoveryV2.Status stB,) = rec.recovery(vaultB);
        assertEq(uint8(stB), uint8(RecoveryV2.Status.None));
    }

    // -----------------------------------------------------------------
    // V2-SPECIFIC NEW CASES (the anti-redirect binding)
    // -----------------------------------------------------------------

    /// V2: a zero recipient commitment is rejected at initiate (would
    /// defeat the anti-redirect binding by accepting any recipient).
    function test_initiate_revertsZeroRecipientCommitment() public {
        _bootstrap();
        vm.expectRevert(ErrZeroValue.selector);
        rec.initiateRecovery(VAULT, NEW_AUTH, bytes32(0), 1);
    }

    /// V2: the recipient commitment is stored on the struct AND emitted
    /// in `RecoveryInitiated`. The two views (struct read + event) must
    /// agree.
    function test_initiate_storesAndEmitsRecipientCommitment() public {
        _bootstrap();
        uint64 t0 = uint64(block.timestamp);
        vm.expectEmit(true, true, false, true, address(rec));
        emit RecoveryInitiated(VAULT, 1, NEW_AUTH, t0, COMMITMENT, 1);
        rec.initiateRecovery(VAULT, NEW_AUTH, COMMITMENT, 1);
        (,,,,, bytes32 stored) = rec.recovery(VAULT);
        assertEq(stored, COMMITMENT, "stored commitment matches initiate arg");
    }

    /// V2: the on-chain Approve digest changes if the commitment changes
    /// — concretely, a guardian sig over COMMITMENT_2 cannot validate
    /// against a live attempt that stored COMMITMENT.
    function test_approve_rejectsCommitmentMismatch() public {
        uint64 n = _initiate(); // stores COMMITMENT
        uint64 exp = uint64(block.timestamp) + 1000;
        // Guardian signs the digest with a DIFFERENT commitment. The
        // on-chain _hashApprove rebuilds with the stored COMMITMENT; the
        // recovered signer doesn't match g0 -> ErrInvalidSignature.
        bytes memory sig = _approveSig(G0_PK, NEW_AUTH, n, exp, COMMITMENT_2);
        vm.expectRevert(ErrInvalidSignature.selector);
        rec.approveRecovery(VAULT, g0, _proof4(leaves, 0), exp, 1, sig);
    }

    /// V2: a guardian's V1-shape signature (5-field typehash, no
    /// commitment) cannot validate against a V2 attempt — the typehash
    /// itself differs, the digest differs, ecrecover yields a different
    /// signer.
    function test_approve_rejectsV1ShapeApproval_typehashMismatch() public {
        uint64 n = _initiate();
        uint64 exp = uint64(block.timestamp) + 1000;
        // Build the V1-shape digest (the typehash V1 used + 5 fields).
        bytes32 v1StructHash =
            keccak256(abi.encode(APPROVE_TYPEHASH_V1, VAULT, NEW_AUTH, n, exp, uint16(1)));
        bytes32 v1Digest =
            keccak256(abi.encodePacked(hex"1901", rec.DOMAIN_SEPARATOR(), v1StructHash));
        // Confirm the V1 digest is NOT the V2 digest.
        bytes32 v2Digest = rec.hashApprove(VAULT, NEW_AUTH, n, exp, COMMITMENT, 1);
        assertTrue(v1Digest != v2Digest, "V1 and V2 digests are distinct");
        // A guardian sig over the V1 digest fails against V2 verify.
        bytes memory sig = _sign(G0_PK, v1Digest);
        vm.expectRevert(ErrInvalidSignature.selector);
        rec.approveRecovery(VAULT, g0, _proof4(leaves, 0), exp, 1, sig);
    }
}
