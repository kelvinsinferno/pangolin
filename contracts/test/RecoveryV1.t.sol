// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {RecoveryV1} from "../src/RecoveryV1.sol";

/// @title RecoveryV1 unit tests
/// @notice Maps to docs/issue-plans/102-recovery-v1-contract.md "Test
///         posture" + the #102 prompt test list: full happy-path
///         lifecycle, every revert path, replay rejection, no-admin
///         probe, non-payable, _recover discipline, digest-oracle
///         parity, merkle-proof correctness. Uses `vm.warp` to cross
///         the 72h MIN_DELAY hermetically (contract-only; the anvil
///         Rust<->contract path is the deferred client cycle).
contract RecoveryV1Test is Test {
    RecoveryV1 internal rec;

    // Re-declared so vm.expectEmit / vm.expectRevert can match.
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
    bytes32 internal constant APPROVE_TYPEHASH = keccak256(
        "Approve(bytes32 vaultId,address proposedAuthority,uint64 attemptNonce,uint64 expiresAt,uint16 schemaVersion)"
    );

    // Five guardian private keys (4 used + 1 spare non-guardian).
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

    // Test vault + actors.
    bytes32 internal constant VAULT = keccak256("vault-recovery-1");
    address internal constant AUTHORITY = address(0xA17F0); // the bootstrapping device
    address internal constant NEW_AUTH = address(0xBEEF);

    // The 4-guardian merkle tree (sorted-pair keccak, 4 leaves = perfect).
    bytes32[4] internal leaves;
    bytes32 internal root;

    function setUp() public {
        rec = new RecoveryV1();
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
    // Merkle helpers (sorted-pair keccak, mirror the contract)
    // -----------------------------------------------------------------

    function _hashPair(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return a <= b ? keccak256(abi.encodePacked(a, b)) : keccak256(abi.encodePacked(b, a));
    }

    /// @dev 4-leaf perfect tree: root = H(H(l0,l1), H(l2,l3)).
    function _buildRoot4(bytes32[4] memory ls) internal pure returns (bytes32) {
        bytes32 n01 = _hashPair(ls[0], ls[1]);
        bytes32 n23 = _hashPair(ls[2], ls[3]);
        return _hashPair(n01, n23);
    }

    /// @dev Proof for leaf index `idx` in the 4-leaf tree: [sibling-leaf,
    ///      sibling-internal-node].
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

    function _approveSig(uint256 pk, address proposed, uint64 nonce, uint64 expiresAt)
        internal
        view
        returns (bytes memory)
    {
        return _sign(pk, rec.hashApprove(VAULT, proposed, nonce, expiresAt, 1));
    }

    /// @dev Standard setup: 3-of-4 guardian set bootstrapped by AUTHORITY.
    function _bootstrap() internal {
        vm.prank(AUTHORITY);
        rec.setGuardianSet(VAULT, root, 3, 4, 1);
    }

    /// @dev Bootstrap + initiate a fresh attempt to NEW_AUTH.
    function _initiate() internal returns (uint64 nonce) {
        _bootstrap();
        rec.initiateRecovery(VAULT, NEW_AUTH, 1);
        (,, nonce,,) = rec.recovery(VAULT);
    }

    function _approveBy(uint256 pk, uint256 idx, uint64 nonce, uint64 expiresAt) internal {
        bytes memory sig = _approveSig(pk, NEW_AUTH, nonce, expiresAt);
        rec.approveRecovery(VAULT, vm.addr(pk), _proof4(leaves, idx), expiresAt, 1, sig);
    }

    // -----------------------------------------------------------------
    // Happy-path lifecycle
    // -----------------------------------------------------------------

    /// @dev Full lifecycle: setGuardianSet -> initiate -> approve x3 ->
    ///      warp past 72h -> finalize -> assert authority rotated +
    ///      events.
    function test_fullLifecycle_happyPath() public {
        // setGuardianSet
        vm.expectEmit(true, false, false, true, address(rec));
        emit GuardianSetInitialized(VAULT, root, 3, 4, AUTHORITY, 1);
        vm.prank(AUTHORITY);
        rec.setGuardianSet(VAULT, root, 3, 4, 1);
        assertEq(rec.vaultAuthority(VAULT), AUTHORITY, "authority self-bootstrapped to caller");

        // initiate
        uint64 t0 = uint64(block.timestamp);
        vm.expectEmit(true, true, false, true, address(rec));
        emit RecoveryInitiated(VAULT, 1, NEW_AUTH, t0, 1);
        rec.initiateRecovery(VAULT, NEW_AUTH, 1);
        (address proposed, uint64 initiatedAt, uint64 nonce, uint8 approvals, RecoveryV1.Status st)
        = rec.recovery(VAULT);
        assertEq(proposed, NEW_AUTH);
        assertEq(initiatedAt, t0);
        assertEq(nonce, 1);
        assertEq(approvals, 0);
        assertEq(uint8(st), uint8(RecoveryV1.Status.Pending));

        // approve x3 (g0, g1, g2)
        uint64 exp = t0 + 1000;
        _approveBy(G0_PK, 0, 1, exp);
        _approveBy(G1_PK, 1, 1, exp);
        vm.expectEmit(true, true, false, true, address(rec));
        emit RecoveryApproved(VAULT, 1, g2, 3, 1);
        _approveBy(G2_PK, 2, 1, exp);
        (,,, approvals,) = rec.recovery(VAULT);
        assertEq(approvals, 3, "3 approvals counted");

        // warp past delay + finalize
        vm.warp(block.timestamp + 72 hours + 1);
        vm.expectEmit(true, true, false, true, address(rec));
        emit RecoveryFinalized(VAULT, 1, AUTHORITY, NEW_AUTH, 1);
        rec.finalizeRecovery(VAULT, 1);
        assertEq(rec.vaultAuthority(VAULT), NEW_AUTH, "authority rotated on finalize");
        (,,,, st) = rec.recovery(VAULT);
        assertEq(uint8(st), uint8(RecoveryV1.Status.Finalized));
    }

    /// @dev A second recovery attempt after a finalize re-initiates with
    ///      a bumped nonce + fresh approval set, and the NEW authority is
    ///      the one who can cancel.
    function test_secondAttemptAfterFinalize_freshNonceAndApprovals() public {
        uint64 n1 = _initiate();
        uint64 exp = uint64(block.timestamp) + 1000;
        _approveBy(G0_PK, 0, n1, exp);
        _approveBy(G1_PK, 1, n1, exp);
        _approveBy(G2_PK, 2, n1, exp);
        vm.warp(block.timestamp + 72 hours + 1);
        rec.finalizeRecovery(VAULT, 1);
        assertEq(rec.vaultAuthority(VAULT), NEW_AUTH);

        // Re-initiate: nonce bumps to 2, approvals reset.
        rec.initiateRecovery(VAULT, address(0xCAFE), 1);
        (,, uint64 n2, uint8 approvals, RecoveryV1.Status st) = rec.recovery(VAULT);
        assertEq(n2, 2, "attempt nonce bumped");
        assertEq(approvals, 0, "fresh approval count");
        assertEq(uint8(st), uint8(RecoveryV1.Status.Pending));
    }

    /// @dev cancel -> CANCELED, then a fresh initiate works.
    function test_cancelThenReinitiate() public {
        _initiate();
        vm.prank(AUTHORITY);
        rec.cancelRecovery(VAULT, 1);
        (,,,, RecoveryV1.Status st) = rec.recovery(VAULT);
        assertEq(uint8(st), uint8(RecoveryV1.Status.Canceled));
        // re-initiate allowed (not Pending anymore)
        rec.initiateRecovery(VAULT, NEW_AUTH, 1);
        (,, uint64 n,, RecoveryV1.Status st2) = rec.recovery(VAULT);
        assertEq(n, 2);
        assertEq(uint8(st2), uint8(RecoveryV1.Status.Pending));
    }

    // -----------------------------------------------------------------
    // setGuardianSet revert paths
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
        rec.setGuardianSet(VAULT, root, 1, 4, 1); // threshold 1 < MIN 2
    }

    function test_setGuardianSet_revertsThresholdTooHigh() public {
        vm.expectRevert(ErrThresholdOutOfBounds.selector);
        rec.setGuardianSet(VAULT, root, 10, 12, 1); // threshold 10 > MAX 9
    }

    function test_setGuardianSet_revertsThresholdGtCount() public {
        vm.expectRevert(ErrThresholdOutOfBounds.selector);
        rec.setGuardianSet(VAULT, root, 5, 4, 1); // threshold > count
    }

    function test_setGuardianSet_revertsCountTooLow() public {
        vm.expectRevert(ErrGuardianCountOutOfBounds.selector);
        rec.setGuardianSet(VAULT, root, 2, 2, 1); // count 2 < MIN 3
    }

    function test_setGuardianSet_revertsCountTooHigh() public {
        vm.expectRevert(ErrGuardianCountOutOfBounds.selector);
        rec.setGuardianSet(VAULT, root, 3, 16, 1); // count 16 > MAX 15
    }

    function test_setGuardianSet_revertsUnsupportedSchema() public {
        vm.expectRevert(ErrUnsupportedSchemaVersion.selector);
        rec.setGuardianSet(VAULT, root, 3, 4, 2);
    }

    function test_setGuardianSet_boundaryValues_accepted() public {
        // Min config: 2-of-3.
        rec.setGuardianSet(keccak256("v-min"), root, 2, 3, 1);
        // Max config: 9-of-15.
        rec.setGuardianSet(keccak256("v-max"), root, 9, 15, 1);
        // threshold == count edge.
        rec.setGuardianSet(keccak256("v-eq"), root, 4, 4, 1);
    }

    // -----------------------------------------------------------------
    // initiateRecovery revert paths
    // -----------------------------------------------------------------

    function test_initiate_revertsNoGuardianSet() public {
        vm.expectRevert(ErrGuardianSetNotInitialized.selector);
        rec.initiateRecovery(VAULT, NEW_AUTH, 1);
    }

    function test_initiate_revertsZeroProposed() public {
        _bootstrap();
        vm.expectRevert(ErrZeroValue.selector);
        rec.initiateRecovery(VAULT, address(0), 1);
    }

    function test_initiate_revertsAlreadyPending() public {
        _initiate();
        vm.expectRevert(ErrRecoveryAlreadyPending.selector);
        rec.initiateRecovery(VAULT, NEW_AUTH, 1);
    }

    function test_initiate_revertsUnsupportedSchema() public {
        _bootstrap();
        vm.expectRevert(ErrUnsupportedSchemaVersion.selector);
        rec.initiateRecovery(VAULT, NEW_AUTH, 2);
    }

    // -----------------------------------------------------------------
    // approveRecovery revert paths
    // -----------------------------------------------------------------

    function test_approve_revertsNoActiveRecovery() public {
        _bootstrap();
        uint64 exp = uint64(block.timestamp) + 1000;
        bytes memory sig = _approveSig(G0_PK, NEW_AUTH, 1, exp);
        vm.expectRevert(ErrNoActiveRecovery.selector);
        rec.approveRecovery(VAULT, g0, _proof4(leaves, 0), exp, 1, sig);
    }

    function test_approve_revertsExpired() public {
        uint64 n = _initiate();
        uint64 exp = uint64(block.timestamp); // expires now
        vm.warp(block.timestamp + 1); // now > expiresAt
        bytes memory sig = _approveSig(G0_PK, NEW_AUTH, n, exp);
        vm.expectRevert(ErrApprovalExpired.selector);
        rec.approveRecovery(VAULT, g0, _proof4(leaves, 0), exp, 1, sig);
    }

    function test_approve_revertsNonGuardianMerkle() public {
        uint64 n = _initiate();
        uint64 exp = uint64(block.timestamp) + 1000;
        // Outsider signs correctly but is not in the tree; pass g0's
        // proof for the outsider address -> merkle check fails (the leaf
        // keccak(outsider) is not provable by g0's proof).
        bytes memory sig = _approveSig(OUTSIDER_PK, NEW_AUTH, n, exp);
        vm.expectRevert(ErrInvalidMerkleProof.selector);
        rec.approveRecovery(VAULT, outsider, _proof4(leaves, 0), exp, 1, sig);
    }

    function test_approve_revertsWrongLeafForRealGuardian() public {
        uint64 n = _initiate();
        uint64 exp = uint64(block.timestamp) + 1000;
        // g0 is a real guardian, but we give g1's proof for g0's leaf.
        bytes memory sig = _approveSig(G0_PK, NEW_AUTH, n, exp);
        vm.expectRevert(ErrInvalidMerkleProof.selector);
        rec.approveRecovery(VAULT, g0, _proof4(leaves, 1), exp, 1, sig);
    }

    function test_approve_revertsSignerLeafMismatch() public {
        uint64 n = _initiate();
        uint64 exp = uint64(block.timestamp) + 1000;
        // Valid merkle proof for g1, but signature is from g0. The
        // claimed guardian (g1) passes merkle, but recovered signer (g0)
        // != g1 -> ErrInvalidSignature.
        bytes memory sig = _approveSig(G0_PK, NEW_AUTH, n, exp);
        vm.expectRevert(ErrInvalidSignature.selector);
        rec.approveRecovery(VAULT, g1, _proof4(leaves, 1), exp, 1, sig);
    }

    function test_approve_revertsDuplicate() public {
        uint64 n = _initiate();
        uint64 exp = uint64(block.timestamp) + 1000;
        _approveBy(G0_PK, 0, n, exp);
        bytes memory sig = _approveSig(G0_PK, NEW_AUTH, n, exp);
        vm.expectRevert(ErrDuplicateApproval.selector);
        rec.approveRecovery(VAULT, g0, _proof4(leaves, 0), exp, 1, sig);
    }

    function test_approve_revertsBadSigLength() public {
        uint64 n = _initiate();
        uint64 exp = uint64(block.timestamp) + 1000;
        // A valid merkle proof for g0 but a 64-byte sig -> _recover
        // returns address(0) -> ErrInvalidSignature.
        n;
        bytes memory shortSig = new bytes(64);
        vm.expectRevert(ErrInvalidSignature.selector);
        rec.approveRecovery(VAULT, g0, _proof4(leaves, 0), exp, 1, shortSig);
    }

    function test_approve_revertsBadV() public {
        uint64 n = _initiate();
        uint64 exp = uint64(block.timestamp) + 1000;
        (, bytes32 r, bytes32 s) = vm.sign(G0_PK, rec.hashApprove(VAULT, NEW_AUTH, n, exp, 1));
        bytes memory badV = abi.encodePacked(r, s, uint8(26));
        vm.expectRevert(ErrInvalidSignature.selector);
        rec.approveRecovery(VAULT, g0, _proof4(leaves, 0), exp, 1, badV);
    }

    function test_approve_revertsHighS() public {
        uint64 n = _initiate();
        uint64 exp = uint64(block.timestamp) + 1000;
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(G0_PK, rec.hashApprove(VAULT, NEW_AUTH, n, exp, 1));
        uint256 N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
        bytes32 highS = bytes32(N - uint256(s));
        uint8 flippedV = v == 27 ? 28 : 27;
        bytes memory mall = abi.encodePacked(r, highS, flippedV);
        vm.expectRevert(ErrInvalidSignature.selector);
        rec.approveRecovery(VAULT, g0, _proof4(leaves, 0), exp, 1, mall);
    }

    function test_approve_revertsZeroRZeroS() public {
        uint64 n = _initiate();
        uint64 exp = uint64(block.timestamp) + 1000;
        n;
        bytes memory sig = abi.encodePacked(bytes32(0), bytes32(0), uint8(27));
        vm.expectRevert(ErrInvalidSignature.selector);
        rec.approveRecovery(VAULT, g0, _proof4(leaves, 0), exp, 1, sig);
    }

    function test_approve_revertsUnsupportedSchema() public {
        uint64 n = _initiate();
        uint64 exp = uint64(block.timestamp) + 1000;
        n;
        bytes memory sig = new bytes(65);
        vm.expectRevert(ErrUnsupportedSchemaVersion.selector);
        rec.approveRecovery(VAULT, g0, _proof4(leaves, 0), exp, 2, sig);
    }

    /// @dev An approval signed for attempt N cannot be replayed into a
    ///      fresh attempt N+1 (L11): the digest binds attemptNonce, so a
    ///      sig over nonce=1 fails when the live attempt is nonce=2.
    function test_approve_revertsStaleAttemptNonce() public {
        uint64 n1 = _initiate();
        uint64 exp = uint64(block.timestamp) + 100000;
        // Sign for attempt n1.
        bytes memory sig = _approveSig(G0_PK, NEW_AUTH, n1, exp);
        // Cancel + re-initiate -> attempt nonce becomes 2.
        vm.prank(AUTHORITY);
        rec.cancelRecovery(VAULT, 1);
        rec.initiateRecovery(VAULT, NEW_AUTH, 1);
        // The old sig (over nonce=1) recovers a signer != g0 against the
        // live nonce=2 digest -> signer/leaf mismatch -> ErrInvalidSignature.
        vm.expectRevert(ErrInvalidSignature.selector);
        rec.approveRecovery(VAULT, g0, _proof4(leaves, 0), exp, 1, sig);
    }

    // -----------------------------------------------------------------
    // finalizeRecovery revert paths
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
        _approveBy(G1_PK, 1, n, exp); // only 2-of-3
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
        // Warp to JUST short of the delay.
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
        // Exactly initiatedAt + MIN_DELAY (>= boundary).
        vm.warp(uint256(t0) + 72 hours);
        rec.finalizeRecovery(VAULT, 1);
        assertEq(rec.vaultAuthority(VAULT), NEW_AUTH);
    }

    function test_finalize_revertsUnsupportedSchema() public {
        _initiate();
        vm.expectRevert(ErrUnsupportedSchemaVersion.selector);
        rec.finalizeRecovery(VAULT, 2);
    }

    /// @dev cancel-then-finalize is blocked: a canceled attempt is
    ///      terminal, finalize reverts ErrNoActiveRecovery.
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
        // Authority did NOT rotate.
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

    /// @dev After a finalize rotates authority, the OLD authority can no
    ///      longer cancel a new attempt; only the NEW authority can.
    function test_cancel_authorityFollowsRotation() public {
        uint64 n = _initiate();
        uint64 exp = uint64(block.timestamp) + 1000000;
        _approveBy(G0_PK, 0, n, exp);
        _approveBy(G1_PK, 1, n, exp);
        _approveBy(G2_PK, 2, n, exp);
        vm.warp(block.timestamp + 72 hours + 1);
        rec.finalizeRecovery(VAULT, 1); // authority -> NEW_AUTH

        rec.initiateRecovery(VAULT, address(0xCAFE), 1);
        // Old authority can't cancel.
        vm.prank(AUTHORITY);
        vm.expectRevert(ErrNotAuthorizedToCancel.selector);
        rec.cancelRecovery(VAULT, 1);
        // New authority can.
        vm.prank(NEW_AUTH);
        rec.cancelRecovery(VAULT, 1);
        (,,,, RecoveryV1.Status st) = rec.recovery(VAULT);
        assertEq(uint8(st), uint8(RecoveryV1.Status.Canceled));
    }

    // -----------------------------------------------------------------
    // Cross-chain replay
    // -----------------------------------------------------------------

    /// @dev A signature computed under a different chainId does not
    ///      verify: the domain separator was baked at construction under
    ///      the original chainId, so a sig over a fake-chain digest
    ///      recovers a different address -> signer/leaf mismatch.
    function test_approve_rejectsCrossChainReplay() public {
        uint64 n = _initiate();
        uint64 exp = uint64(block.timestamp) + 1000;
        // Build a fake domain separator under chainId 999 and sign that.
        bytes32 fakeDomain = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes("Pangolin Recovery")),
                keccak256(bytes("1")),
                uint256(999),
                address(rec)
            )
        );
        assertTrue(fakeDomain != rec.DOMAIN_SEPARATOR(), "fake/real separators differ");
        bytes32 structHash =
            keccak256(abi.encode(APPROVE_TYPEHASH, VAULT, NEW_AUTH, n, exp, uint16(1)));
        bytes32 fakeDigest = keccak256(abi.encodePacked(hex"1901", fakeDomain, structHash));
        bytes memory sig = _sign(G0_PK, fakeDigest);
        // The contract recomputes under the REAL domain; recovered signer
        // != g0 -> ErrInvalidSignature.
        vm.expectRevert(ErrInvalidSignature.selector);
        rec.approveRecovery(VAULT, g0, _proof4(leaves, 0), exp, 1, sig);
    }

    /// @dev A sig bound to a different proposedAuthority cannot be used
    ///      against the live attempt (R-c attempt binding).
    function test_approve_rejectsWrongProposedAuthorityBinding() public {
        uint64 n = _initiate();
        uint64 exp = uint64(block.timestamp) + 1000;
        // Sign over a DIFFERENT proposed authority than the live attempt.
        bytes memory sig = _approveSig(G0_PK, address(0xDEAD), n, exp);
        vm.expectRevert(ErrInvalidSignature.selector);
        rec.approveRecovery(VAULT, g0, _proof4(leaves, 0), exp, 1, sig);
    }

    // -----------------------------------------------------------------
    // Digest-oracle parity
    // -----------------------------------------------------------------

    function test_hashApprove_matchesLocalDigest() public view {
        uint64 exp = 12345;
        bytes32 viaView = rec.hashApprove(VAULT, NEW_AUTH, 7, exp, 1);
        bytes32 structHash =
            keccak256(abi.encode(APPROVE_TYPEHASH, VAULT, NEW_AUTH, uint64(7), exp, uint16(1)));
        bytes32 viaLocal =
            keccak256(abi.encodePacked(hex"1901", rec.DOMAIN_SEPARATOR(), structHash));
        assertEq(viaView, viaLocal);
    }

    function test_hashCancel_and_hashInitiate_areViewOnly() public view {
        // Just assert they return non-zero deterministic digests (they
        // are forward-compat oracles not consumed by v1).
        assertTrue(rec.hashCancel(VAULT, 1, 1) != bytes32(0));
        assertTrue(rec.hashInitiate(VAULT, NEW_AUTH, 1, 1) != bytes32(0));
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
        RecoveryV1 other = new RecoveryV1();
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
        // g3 (4th leaf) also verifies — proves all proof shapes work.
        _approveBy(G3_PK, 3, n, exp);
        (,,, uint8 approvals,) = rec.recovery(VAULT);
        assertEq(approvals, 4);
    }

    function test_merkle_forgedProofRejected() public {
        uint64 n = _initiate();
        uint64 exp = uint64(block.timestamp) + 1000;
        // Random forged proof for g0.
        bytes32[] memory forged = new bytes32[](2);
        forged[0] = keccak256("forged-a");
        forged[1] = keccak256("forged-b");
        bytes memory sig = _approveSig(G0_PK, NEW_AUTH, n, exp);
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
            assertFalse(ok, "admin/proxy selector must not exist");
            assertEq(ret.length, 0, "no return data from missing admin selector");
        }
    }

    function test_contract_rejectsEth() public {
        vm.deal(address(this), 1 ether);
        (bool ok1,) = address(rec).call{value: 1 wei}("");
        assertFalse(ok1, "empty calldata with value must revert (no receive())");
        (bool ok2,) = address(rec).call{value: 1 wei}(hex"deadbeef");
        assertFalse(ok2, "unknown selector with value must revert");
        (bool ok3,) = address(rec).call{value: 0}(hex"deadbeef");
        assertFalse(ok3, "unknown selector with no fallback must revert");
        // A real function with value attached also reverts (non-payable).
        bytes memory cd =
            abi.encodeWithSelector(RecoveryV1.initiateRecovery.selector, VAULT, NEW_AUTH, uint16(1));
        (bool ok4,) = address(rec).call{value: 1 wei}(cd);
        assertFalse(ok4, "non-payable function with value must revert");
    }

    function test_constants() public view {
        assertEq(rec.MAX_KNOWN_SCHEMA_VERSION(), 1);
        assertEq(rec.MIN_DELAY(), 72 hours);
        assertEq(rec.MIN_THRESHOLD(), 2);
        assertEq(rec.MAX_THRESHOLD(), 9);
        assertEq(rec.MIN_GUARDIANS(), 3);
        assertEq(rec.MAX_GUARDIANS(), 15);
    }

    /// @dev Any caller may initiate/finalize (permissionless); the
    ///      security is the quorum + delay, not msg.sender gating.
    function test_initiateAndFinalize_arePermissionless() public {
        _bootstrap();
        vm.prank(address(0x1234)); // arbitrary caller
        rec.initiateRecovery(VAULT, NEW_AUTH, 1);
        (,, uint64 n,,) = rec.recovery(VAULT);
        uint64 exp = uint64(block.timestamp) + 1000000;
        _approveBy(G0_PK, 0, n, exp);
        _approveBy(G1_PK, 1, n, exp);
        _approveBy(G2_PK, 2, n, exp);
        vm.warp(block.timestamp + 72 hours + 1);
        vm.prank(address(0x5678)); // different arbitrary caller
        rec.finalizeRecovery(VAULT, 1);
        assertEq(rec.vaultAuthority(VAULT), NEW_AUTH);
    }

    /// @dev Two vaults are isolated: a guardian set / recovery in one
    ///      does not affect the other.
    function test_multiVaultIsolation() public {
        bytes32 vaultB = keccak256("vault-B");
        _bootstrap(); // VAULT, authority = AUTHORITY
        vm.prank(address(0x9999));
        rec.setGuardianSet(vaultB, root, 2, 3, 1);
        assertEq(rec.vaultAuthority(VAULT), AUTHORITY);
        assertEq(rec.vaultAuthority(vaultB), address(0x9999));
        // Recovery on VAULT does not touch vaultB.
        rec.initiateRecovery(VAULT, NEW_AUTH, 1);
        (,,,, RecoveryV1.Status stB) = rec.recovery(vaultB);
        assertEq(uint8(stB), uint8(RecoveryV1.Status.None));
    }
}
