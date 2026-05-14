// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity 0.8.24;

import {Test, Vm} from "forge-std/Test.sol";
import {EntitlementRegistry} from "../src/EntitlementRegistry.sol";

/// @title EntitlementRegistry unit tests
/// @notice Maps 1:1 to docs/issue-plans/2.2.md §5 "Test plan" table.
///         Adapted to the resolved R-a..R-e decisions: split-signer
///         (PAYMENT_AUTHORITY for credit, REDEMPTION_AUTHORITY for
///         redeem), opaque bytes32 userId, funder-push direction with
///         strict-equality nonce, constructor-immutable authorities,
///         expiresAt anti-stale-signature.
contract EntitlementRegistryTest is Test {
    EntitlementRegistry internal reg;

    // Re-declared so `vm.expectEmit` can match on the topic signature.
    event Credited(
        bytes32 indexed userId,
        uint256 amount,
        uint256 newBalance,
        uint64 nonce,
        uint16 schemaVersion
    );
    event Redeemed(
        bytes32 indexed userId,
        uint256 amount,
        uint256 newBalance,
        uint64 nonce,
        uint16 schemaVersion
    );

    // Re-declared so `vm.expectRevert` can use the typed error selector.
    error ErrInvalidSignature();
    error ErrUnauthorizedSigner();
    error ErrInsufficientBalance();
    error ErrNonceTooLow();
    error ErrUnsupportedSchemaVersion();
    error ErrAttestationExpired();
    error ErrZeroAuthority();

    // EIP-712 typehashes — mirror the ones in the contract.
    bytes32 internal constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    bytes32 internal constant CREDIT_TYPEHASH = keccak256(
        "Credit(bytes32 userId,uint256 amount,uint64 nonce,uint16 schemaVersion,uint64 expiresAt)"
    );
    bytes32 internal constant REDEMPTION_TYPEHASH = keccak256(
        "Redemption(bytes32 userId,uint256 amount,uint64 nonce,uint16 schemaVersion,uint64 expiresAt)"
    );

    // Fixed test signer private keys (NOT for production — public
    // constants picked for deterministic test output). Two distinct
    // keys per R-a split-signer model.
    uint256 internal constant PAYMENT_AUTHORITY_PK =
        0xC0FFEE00C0FFEE00C0FFEE00C0FFEE00C0FFEE00C0FFEE00C0FFEE00C0FFEE00;
    uint256 internal constant REDEMPTION_AUTHORITY_PK =
        0xDECAFBADDECAFBADDECAFBADDECAFBADDECAFBADDECAFBADDECAFBADDECAFBAD;
    uint256 internal constant RANDO_PK =
        0xABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD;

    address internal paymentAuthority;
    address internal redemptionAuthority;

    function setUp() public {
        paymentAuthority = vm.addr(PAYMENT_AUTHORITY_PK);
        redemptionAuthority = vm.addr(REDEMPTION_AUTHORITY_PK);
        reg = new EntitlementRegistry(paymentAuthority, redemptionAuthority);
    }

    // -----------------------------------------------------------------
    // Local digest helpers (mirror the contract's _hashCredit /
    // _hashRedemption)
    // -----------------------------------------------------------------

    function _computeCreditDigest(
        bytes32 userId,
        uint256 amount,
        uint64 attestationNonce,
        uint16 schemaVersion,
        uint64 expiresAt
    ) internal view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(CREDIT_TYPEHASH, userId, amount, attestationNonce, schemaVersion, expiresAt)
        );
        return keccak256(abi.encodePacked(hex"1901", reg.DOMAIN_SEPARATOR(), structHash));
    }

    function _computeRedemptionDigest(
        bytes32 userId,
        uint256 amount,
        uint64 attestationNonce,
        uint16 schemaVersion,
        uint64 expiresAt
    ) internal view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                REDEMPTION_TYPEHASH, userId, amount, attestationNonce, schemaVersion, expiresAt
            )
        );
        return keccak256(abi.encodePacked(hex"1901", reg.DOMAIN_SEPARATOR(), structHash));
    }

    function _sign(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    /// @dev Convenience: build a valid credit signature with the given
    ///      parameters and an `expiresAt` 1 hour in the future.
    function _validCreditSig(bytes32 userId, uint256 amount, uint64 attestationNonce)
        internal
        view
        returns (bytes memory sig, uint64 expiresAt)
    {
        expiresAt = uint64(block.timestamp + 3600);
        bytes32 digest = _computeCreditDigest(userId, amount, attestationNonce, 1, expiresAt);
        sig = _sign(PAYMENT_AUTHORITY_PK, digest);
    }

    function _validRedemptionSig(bytes32 userId, uint256 amount, uint64 attestationNonce)
        internal
        view
        returns (bytes memory sig, uint64 expiresAt)
    {
        expiresAt = uint64(block.timestamp + 300);
        bytes32 digest = _computeRedemptionDigest(userId, amount, attestationNonce, 1, expiresAt);
        sig = _sign(REDEMPTION_AUTHORITY_PK, digest);
    }

    // =================================================================
    // 1. test_constructor_setsImmutables
    // =================================================================

    function test_constructor_setsImmutables() public view {
        assertEq(reg.PAYMENT_AUTHORITY(), paymentAuthority, "PAYMENT_AUTHORITY mismatch");
        assertEq(reg.REDEMPTION_AUTHORITY(), redemptionAuthority, "REDEMPTION_AUTHORITY mismatch");
        bytes32 expected = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes("Pangolin EntitlementRegistry")),
                keccak256(bytes("1")),
                block.chainid,
                address(reg)
            )
        );
        assertEq(reg.DOMAIN_SEPARATOR(), expected, "DOMAIN_SEPARATOR mismatch");
    }

    function test_constructor_rejectsZeroPaymentAuthority() public {
        vm.expectRevert(ErrZeroAuthority.selector);
        new EntitlementRegistry(address(0), redemptionAuthority);
    }

    function test_constructor_rejectsZeroRedemptionAuthority() public {
        vm.expectRevert(ErrZeroAuthority.selector);
        new EntitlementRegistry(paymentAuthority, address(0));
    }

    // =================================================================
    // 2. test_constants_maxKnownSchemaVersion_is_1
    // =================================================================

    function test_constants_maxKnownSchemaVersion_is_1() public view {
        assertEq(reg.MAX_KNOWN_SCHEMA_VERSION(), 1);
    }

    // =================================================================
    // 3. test_credit_happyPath
    // =================================================================

    function test_credit_happyPath() public {
        bytes32 userId = keccak256("user-1");
        uint256 amount = 5_000;
        uint64 nonce0 = 0;
        (bytes memory sig, uint64 expiresAt) = _validCreditSig(userId, amount, nonce0);

        vm.expectEmit(true, true, true, true, address(reg));
        emit Credited(userId, amount, amount, nonce0, 1);
        uint256 newBalance = reg.credit(userId, amount, nonce0, 1, expiresAt, sig);
        assertEq(newBalance, amount, "newBalance return mismatch");
        assertEq(reg.balance(userId), amount, "balance not updated");
        assertEq(reg.nonce(userId), 1, "nonce not bumped");
    }

    // =================================================================
    // 4. test_credit_repeatBumpsBalance
    // =================================================================

    function test_credit_repeatBumpsBalance() public {
        bytes32 userId = keccak256("user-1");
        uint256 amount1 = 5_000;
        uint256 amount2 = 7_000;
        (bytes memory sig1, uint64 exp1) = _validCreditSig(userId, amount1, 0);
        reg.credit(userId, amount1, 0, 1, exp1, sig1);

        (bytes memory sig2, uint64 exp2) = _validCreditSig(userId, amount2, 1);
        reg.credit(userId, amount2, 1, 1, exp2, sig2);

        assertEq(reg.balance(userId), amount1 + amount2, "balance not summed");
        assertEq(reg.nonce(userId), 2, "nonce not bumped twice");
    }

    // =================================================================
    // 5. test_credit_rejectsWrongAuthority
    // =================================================================

    function test_credit_rejectsWrongAuthority() public {
        bytes32 userId = keccak256("user-1");
        uint256 amount = 5_000;
        uint64 expiresAt = uint64(block.timestamp + 3600);
        bytes32 digest = _computeCreditDigest(userId, amount, 0, 1, expiresAt);
        // Sign with REDEMPTION_AUTHORITY (wrong authority for Credit).
        bytes memory sig = _sign(REDEMPTION_AUTHORITY_PK, digest);

        vm.expectRevert(ErrUnauthorizedSigner.selector);
        reg.credit(userId, amount, 0, 1, expiresAt, sig);
    }

    // =================================================================
    // 6. test_credit_rejectsExpired
    // =================================================================

    function test_credit_rejectsExpired() public {
        bytes32 userId = keccak256("user-1");
        uint256 amount = 5_000;
        // Move time forward, then sign with an `expiresAt` in the past.
        vm.warp(10_000);
        uint64 expiresAt = uint64(block.timestamp - 1);
        bytes32 digest = _computeCreditDigest(userId, amount, 0, 1, expiresAt);
        bytes memory sig = _sign(PAYMENT_AUTHORITY_PK, digest);

        vm.expectRevert(ErrAttestationExpired.selector);
        reg.credit(userId, amount, 0, 1, expiresAt, sig);
    }

    // =================================================================
    // 7. test_credit_rejectsBadSignature
    // =================================================================

    function test_credit_rejectsBadSignature() public {
        bytes32 userId = keccak256("user-1");
        uint64 expiresAt = uint64(block.timestamp + 3600);
        // 64-byte sig: contract's _recover() returns address(0) immediately.
        bytes memory shortSig = new bytes(64);
        vm.expectRevert(ErrInvalidSignature.selector);
        reg.credit(userId, 5_000, 0, 1, expiresAt, shortSig);
    }

    // =================================================================
    // 8. test_credit_rejectsLowNonce
    // =================================================================

    function test_credit_rejectsLowNonce() public {
        bytes32 userId = keccak256("user-1");
        // First credit lands at nonce 0; nonce[userId] is now 1.
        (bytes memory sig0, uint64 exp0) = _validCreditSig(userId, 5_000, 0);
        reg.credit(userId, 5_000, 0, 1, exp0, sig0);
        assertEq(reg.nonce(userId), 1);

        // Sign a NEW attestation that re-uses nonce = 0; strict equality
        // says 0 != 1 so the contract rejects.
        (bytes memory sig0b, uint64 exp0b) = _validCreditSig(userId, 3_000, 0);
        vm.expectRevert(ErrNonceTooLow.selector);
        reg.credit(userId, 3_000, 0, 1, exp0b, sig0b);
    }

    // =================================================================
    // 9. test_credit_rejectsReplay
    // =================================================================

    function test_credit_rejectsReplay() public {
        bytes32 userId = keccak256("user-1");
        (bytes memory sig, uint64 exp) = _validCreditSig(userId, 5_000, 0);
        reg.credit(userId, 5_000, 0, 1, exp, sig);
        // Identical bytes resubmitted → nonce now 1, attestation nonce 0 → revert.
        vm.expectRevert(ErrNonceTooLow.selector);
        reg.credit(userId, 5_000, 0, 1, exp, sig);
    }

    // =================================================================
    // 10. test_credit_rejectsUnsupportedSchemaVersion
    // =================================================================

    function test_credit_rejectsUnsupportedSchemaVersion() public {
        bytes32 userId = keccak256("user-1");
        uint64 expiresAt = uint64(block.timestamp + 3600);
        bytes32 digest = _computeCreditDigest(userId, 5_000, 0, 2, expiresAt);
        bytes memory sig = _sign(PAYMENT_AUTHORITY_PK, digest);
        vm.expectRevert(ErrUnsupportedSchemaVersion.selector);
        reg.credit(userId, 5_000, 0, 2, expiresAt, sig);
    }

    // =================================================================
    // 11. test_credit_rejectsZeroR_ZeroS
    // =================================================================

    function test_credit_rejectsZeroR_ZeroS() public {
        bytes32 userId = keccak256("user-1");
        uint64 expiresAt = uint64(block.timestamp + 3600);
        // r=0, s=0, v=27. ecrecover returns address(0). Contract must
        // surface ErrInvalidSignature, NOT silently accept address(0).
        bytes memory sig = abi.encodePacked(bytes32(0), bytes32(0), uint8(27));
        assertEq(sig.length, 65, "signature must be 65 bytes");
        vm.expectRevert(ErrInvalidSignature.selector);
        reg.credit(userId, 5_000, 0, 1, expiresAt, sig);
    }

    // =================================================================
    // 12. test_credit_rejectsCrossDeploymentReplay
    // =================================================================

    function test_credit_rejectsCrossDeploymentReplay() public {
        // Deploy a SECOND registry with the same authority keys but
        // a different address → different DOMAIN_SEPARATOR.
        EntitlementRegistry other = new EntitlementRegistry(paymentAuthority, redemptionAuthority);
        assertTrue(other.DOMAIN_SEPARATOR() != reg.DOMAIN_SEPARATOR(), "domain seps must differ");

        // Sign a Credit for `reg`, submit to `other`.
        bytes32 userId = keccak256("user-1");
        uint256 amount = 5_000;
        uint64 expiresAt = uint64(block.timestamp + 3600);
        bytes32 digestForReg = _computeCreditDigest(userId, amount, 0, 1, expiresAt);
        bytes memory sig = _sign(PAYMENT_AUTHORITY_PK, digestForReg);

        // `other` recomputes the digest under ITS domain separator;
        // ecrecover yields a different (pseudo-random) address; not
        // equal to PAYMENT_AUTHORITY → ErrUnauthorizedSigner.
        vm.expectRevert(ErrUnauthorizedSigner.selector);
        other.credit(userId, amount, 0, 1, expiresAt, sig);
    }

    // =================================================================
    // 13. test_credit_rejectsCrossChainReplay
    // =================================================================

    function test_credit_rejectsCrossChainReplay() public {
        // Compute a digest under a FAKE chain id (999).
        vm.chainId(999);
        bytes32 fakeDomainSep = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes("Pangolin EntitlementRegistry")),
                keccak256(bytes("1")),
                uint256(999),
                address(reg)
            )
        );
        assertTrue(
            fakeDomainSep != reg.DOMAIN_SEPARATOR(),
            "fake/real separators must differ -- pick a different fake chainid if not"
        );

        bytes32 userId = keccak256("user-1");
        uint256 amount = 5_000;
        uint64 expiresAt = uint64(block.timestamp + 3600);
        bytes32 structHash =
            keccak256(abi.encode(CREDIT_TYPEHASH, userId, amount, uint64(0), uint16(1), expiresAt));
        bytes32 fakeDigest = keccak256(abi.encodePacked(hex"1901", fakeDomainSep, structHash));
        bytes memory sig = _sign(PAYMENT_AUTHORITY_PK, fakeDigest);

        // Submit to the live contract. Its real DOMAIN_SEPARATOR
        // produces a different digest → ecrecover yields a pseudo-
        // random address → not equal to PAYMENT_AUTHORITY → revert.
        vm.expectRevert(ErrUnauthorizedSigner.selector);
        reg.credit(userId, amount, 0, 1, expiresAt, sig);
    }

    // =================================================================
    // 14. test_credit_rejectsAsRedemption
    // =================================================================

    function test_credit_rejectsAsRedemption() public {
        // Sign a Credit struct under PAYMENT_AUTHORITY; submit to redeem.
        bytes32 userId = keccak256("user-1");
        uint256 amount = 5_000;
        uint64 expiresAt = uint64(block.timestamp + 3600);
        bytes32 creditDigest = _computeCreditDigest(userId, amount, 0, 1, expiresAt);
        bytes memory sig = _sign(PAYMENT_AUTHORITY_PK, creditDigest);

        // The contract's redeem recomputes the digest with
        // REDEMPTION_TYPEHASH; ecrecover yields a pseudo-random
        // address; not REDEMPTION_AUTHORITY → ErrUnauthorizedSigner.
        // We must pre-credit so the InsufficientBalance check doesn't
        // intercept — actually, the authority check fires BEFORE the
        // balance check, so no pre-credit needed.
        vm.expectRevert(ErrUnauthorizedSigner.selector);
        reg.redeem(userId, amount, 0, 1, expiresAt, sig);
    }

    // =================================================================
    // 15. test_redeem_happyPath
    // =================================================================

    function test_redeem_happyPath() public {
        bytes32 userId = keccak256("user-1");
        // Pre-credit a balance so there's something to redeem.
        (bytes memory creditSig, uint64 creditExp) = _validCreditSig(userId, 10_000, 0);
        reg.credit(userId, 10_000, 0, 1, creditExp, creditSig);

        // Redeem 3,000. After credit the nonce is 1.
        uint256 amount = 3_000;
        (bytes memory redeemSig, uint64 redeemExp) = _validRedemptionSig(userId, amount, 1);

        vm.expectEmit(true, true, true, true, address(reg));
        emit Redeemed(userId, amount, 7_000, 1, 1);
        uint256 newBalance = reg.redeem(userId, amount, 1, 1, redeemExp, redeemSig);
        assertEq(newBalance, 7_000, "newBalance return mismatch");
        assertEq(reg.balance(userId), 7_000, "balance not decremented");
        assertEq(reg.nonce(userId), 2, "nonce not bumped");
    }

    // =================================================================
    // 16. test_redeem_rejectsInsufficientBalance
    // =================================================================

    function test_redeem_rejectsInsufficientBalance() public {
        bytes32 userId = keccak256("user-1");
        // No prior credit: balance is 0; redeeming any positive amount must revert.
        (bytes memory sig, uint64 exp) = _validRedemptionSig(userId, 5_000, 0);
        vm.expectRevert(ErrInsufficientBalance.selector);
        reg.redeem(userId, 5_000, 0, 1, exp, sig);
        // State unchanged.
        assertEq(reg.balance(userId), 0);
        assertEq(reg.nonce(userId), 0);
    }

    // =================================================================
    // 17. test_redeem_rejectsWrongAuthority
    // =================================================================

    function test_redeem_rejectsWrongAuthority() public {
        bytes32 userId = keccak256("user-1");
        (bytes memory creditSig, uint64 creditExp) = _validCreditSig(userId, 10_000, 0);
        reg.credit(userId, 10_000, 0, 1, creditExp, creditSig);

        // Sign Redemption struct with PAYMENT_AUTHORITY (wrong).
        uint64 expiresAt = uint64(block.timestamp + 300);
        bytes32 digest = _computeRedemptionDigest(userId, 5_000, 1, 1, expiresAt);
        bytes memory sig = _sign(PAYMENT_AUTHORITY_PK, digest);

        vm.expectRevert(ErrUnauthorizedSigner.selector);
        reg.redeem(userId, 5_000, 1, 1, expiresAt, sig);
    }

    // =================================================================
    // 18. test_redeem_rejectsLowNonce
    // =================================================================

    function test_redeem_rejectsLowNonce() public {
        bytes32 userId = keccak256("user-1");
        (bytes memory creditSig, uint64 creditExp) = _validCreditSig(userId, 10_000, 0);
        reg.credit(userId, 10_000, 0, 1, creditExp, creditSig);
        // nonce is 1 now.

        (bytes memory redeemSig, uint64 redeemExp) = _validRedemptionSig(userId, 3_000, 1);
        reg.redeem(userId, 3_000, 1, 1, redeemExp, redeemSig);
        // nonce is 2 now.

        // Replay the same redeem signature: nonce != 1 → revert.
        vm.expectRevert(ErrNonceTooLow.selector);
        reg.redeem(userId, 3_000, 1, 1, redeemExp, redeemSig);
    }

    // =================================================================
    // 19. test_redeem_rejectsAsCredit
    // =================================================================

    function test_redeem_rejectsAsCredit() public {
        // Sign a Redemption struct under REDEMPTION_AUTHORITY; submit to credit.
        bytes32 userId = keccak256("user-1");
        uint256 amount = 5_000;
        uint64 expiresAt = uint64(block.timestamp + 300);
        bytes32 redeemDigest = _computeRedemptionDigest(userId, amount, 0, 1, expiresAt);
        bytes memory sig = _sign(REDEMPTION_AUTHORITY_PK, redeemDigest);

        // The credit path recomputes under CREDIT_TYPEHASH → digest
        // differs → ecrecover yields a pseudo-random address → not
        // PAYMENT_AUTHORITY → ErrUnauthorizedSigner.
        vm.expectRevert(ErrUnauthorizedSigner.selector);
        reg.credit(userId, amount, 0, 1, expiresAt, sig);
    }

    // =================================================================
    // 20. test_redeem_rejectsExpired
    // =================================================================

    function test_redeem_rejectsExpired() public {
        bytes32 userId = keccak256("user-1");
        (bytes memory creditSig, uint64 creditExp) = _validCreditSig(userId, 10_000, 0);
        reg.credit(userId, 10_000, 0, 1, creditExp, creditSig);

        vm.warp(20_000);
        uint64 expiresAt = uint64(block.timestamp - 1);
        bytes32 digest = _computeRedemptionDigest(userId, 5_000, 1, 1, expiresAt);
        bytes memory sig = _sign(REDEMPTION_AUTHORITY_PK, digest);

        vm.expectRevert(ErrAttestationExpired.selector);
        reg.redeem(userId, 5_000, 1, 1, expiresAt, sig);
    }

    // =================================================================
    // 21. test_noBumpOnRevert
    // =================================================================

    function test_noBumpOnRevert() public {
        bytes32 userId = keccak256("user-1");
        (bytes memory creditSig, uint64 creditExp) = _validCreditSig(userId, 10_000, 0);
        reg.credit(userId, 10_000, 0, 1, creditExp, creditSig);
        uint256 balBefore = reg.balance(userId);
        uint64 nonceBefore = reg.nonce(userId);

        // Try a redeem with insufficient balance → revert; state unchanged.
        (bytes memory bigSig, uint64 bigExp) =
            _validRedemptionSig(userId, balBefore + 1, nonceBefore);
        vm.expectRevert(ErrInsufficientBalance.selector);
        reg.redeem(userId, balBefore + 1, nonceBefore, 1, bigExp, bigSig);
        assertEq(reg.balance(userId), balBefore, "balance bumped on revert");
        assertEq(reg.nonce(userId), nonceBefore, "nonce bumped on revert");

        // Confirm the un-burned nonce still lands the next attestation.
        (bytes memory okSig, uint64 okExp) = _validRedemptionSig(userId, 3_000, nonceBefore);
        reg.redeem(userId, 3_000, nonceBefore, 1, okExp, okSig);
        assertEq(reg.balance(userId), balBefore - 3_000);
        assertEq(reg.nonce(userId), nonceBefore + 1);
    }

    // =================================================================
    // 22. test_eventEmissionOnlyOnSuccess
    // =================================================================

    function test_eventEmissionOnlyOnSuccess() public {
        bytes32 userId = keccak256("user-1");
        // Set up a failing credit call (wrong authority) and verify no event.
        uint64 expiresAt = uint64(block.timestamp + 3600);
        bytes32 digest = _computeCreditDigest(userId, 5_000, 0, 1, expiresAt);
        bytes memory badSig = _sign(REDEMPTION_AUTHORITY_PK, digest);

        vm.recordLogs();
        vm.expectRevert(ErrUnauthorizedSigner.selector);
        reg.credit(userId, 5_000, 0, 1, expiresAt, badSig);
        Vm.Log[] memory entries = vm.getRecordedLogs();
        for (uint256 i = 0; i < entries.length; i++) {
            if (entries[i].emitter == address(reg)) {
                fail();
            }
        }
    }

    // =================================================================
    // 23. test_multiUserIsolation
    // =================================================================

    function test_multiUserIsolation() public {
        bytes32 userA = keccak256("user-A");
        bytes32 userB = keccak256("user-B");
        (bytes memory sigA, uint64 expA) = _validCreditSig(userA, 7_000, 0);
        reg.credit(userA, 7_000, 0, 1, expA, sigA);
        (bytes memory sigB, uint64 expB) = _validCreditSig(userB, 12_000, 0);
        reg.credit(userB, 12_000, 0, 1, expB, sigB);

        assertEq(reg.balance(userA), 7_000);
        assertEq(reg.balance(userB), 12_000);
        assertEq(reg.nonce(userA), 1);
        assertEq(reg.nonce(userB), 1);

        // Redeem some from A; B unaffected.
        (bytes memory rSigA, uint64 rExpA) = _validRedemptionSig(userA, 2_000, 1);
        reg.redeem(userA, 2_000, 1, 1, rExpA, rSigA);
        assertEq(reg.balance(userA), 5_000);
        assertEq(reg.balance(userB), 12_000, "userB balance leaked");
        assertEq(reg.nonce(userA), 2);
        assertEq(reg.nonce(userB), 1, "userB nonce leaked");
    }

    // =================================================================
    // 24. test_hashCredit_matchesInternalDigest
    // =================================================================

    function test_hashCredit_matchesInternalDigest() public view {
        bytes32 userId = keccak256("u");
        uint64 expiresAt = uint64(block.timestamp + 100);
        bytes32 viaView = reg.hashCredit(userId, 5_000, 0, 1, expiresAt);
        bytes32 viaLocal = _computeCreditDigest(userId, 5_000, 0, 1, expiresAt);
        assertEq(viaView, viaLocal, "hashCredit view must match local digest");
    }

    // =================================================================
    // 25. test_hashRedemption_matchesInternalDigest
    // =================================================================

    function test_hashRedemption_matchesInternalDigest() public view {
        bytes32 userId = keccak256("u");
        uint64 expiresAt = uint64(block.timestamp + 100);
        bytes32 viaView = reg.hashRedemption(userId, 5_000, 0, 1, expiresAt);
        bytes32 viaLocal = _computeRedemptionDigest(userId, 5_000, 0, 1, expiresAt);
        assertEq(viaView, viaLocal, "hashRedemption view must match local digest");
    }

    // =================================================================
    // 26. test_contract_hasNoAdminOrProxySelectors
    // =================================================================

    /// @dev Probe a long list of admin/proxy/rotation selectors. NONE
    ///      of these may exist on the contract. Mirror of v0/v1's
    ///      selector audit plus registry-specific rotation/setter
    ///      additions.
    function test_contract_hasNoAdminOrProxySelectors() public {
        bytes[27] memory probes = [
            // Ownership / admin / proxy family (mirror of v0/v1).
            abi.encodeWithSignature("owner()"),
            abi.encodeWithSignature("admin()"),
            abi.encodeWithSignature("transferOwnership(address)", address(0)),
            abi.encodeWithSignature("renounceOwnership()"),
            abi.encodeWithSignature("acceptOwnership()"),
            abi.encodeWithSignature("pendingOwner()"),
            abi.encodeWithSignature("pause()"),
            abi.encodeWithSignature("unpause()"),
            abi.encodeWithSignature("paused()"),
            abi.encodeWithSignature("kill()"),
            abi.encodeWithSignature("destroy()"),
            abi.encodeWithSignature("terminate()"),
            abi.encodeWithSignature("withdraw()"),
            abi.encodeWithSignature("upgradeTo(address)", address(0)),
            abi.encodeWithSignature("upgradeToAndCall(address,bytes)", address(0), bytes("")),
            abi.encodeWithSignature("implementation()"),
            abi.encodeWithSignature("proxiableUUID()"),
            // Registry-specific rotation / setter probes (R-d binding).
            abi.encodeWithSignature("setPaymentAuthority(address)", address(0)),
            abi.encodeWithSignature("setRedemptionAuthority(address)", address(0)),
            abi.encodeWithSignature("setSigner(address)", address(0)),
            abi.encodeWithSignature("rotateKeys(address,address)", address(0), address(0)),
            abi.encodeWithSignature("updateAuthority(address)", address(0)),
            abi.encodeWithSignature("setBalance(bytes32,uint256)", bytes32(0), uint256(0)),
            abi.encodeWithSignature("setNonce(bytes32,uint64)", bytes32(0), uint64(0)),
            abi.encodeWithSignature("reset()"),
            abi.encodeWithSignature("revokeUser(bytes32)", bytes32(0)),
            abi.encodeWithSignature("pauseUser(bytes32)", bytes32(0))
        ];
        for (uint256 i = 0; i < probes.length; i++) {
            (bool ok, bytes memory ret) = address(reg).call(probes[i]);
            assertFalse(ok, "admin/proxy/rotation selector must not exist");
            assertEq(ret.length, 0, "no return data from missing selector");
        }
    }

    // =================================================================
    // 27. test_contract_rejectsEthOnAllCallPaths
    // =================================================================

    function test_contract_rejectsEthOnAllCallPaths() public {
        vm.deal(address(this), 1 ether);
        // 1. Empty calldata + ETH: no receive() / fallback() → revert.
        (bool ok1,) = address(reg).call{value: 1 wei}("");
        assertFalse(ok1, "empty calldata with value must revert (no receive())");
        // 2. Unknown selector + ETH: revert.
        (bool ok2,) = address(reg).call{value: 1 wei}(hex"deadbeef");
        assertFalse(ok2, "unknown selector with value must revert");
        // 3. Unknown selector, no value: still revert (no fallback).
        (bool ok3,) = address(reg).call{value: 0}(hex"deadbeef");
        assertFalse(ok3, "unknown selector with no fallback must revert");
        // 4. credit() with value: non-payable, revert.
        bytes32 userId = keccak256("u");
        (bytes memory sig, uint64 exp) = _validCreditSig(userId, 5_000, 0);
        bytes memory cd = abi.encodeWithSelector(
            EntitlementRegistry.credit.selector,
            userId,
            uint256(5_000),
            uint64(0),
            uint16(1),
            exp,
            sig
        );
        (bool ok4,) = address(reg).call{value: 1 wei}(cd);
        assertFalse(ok4, "credit with value must revert (non-payable)");
        // 5. redeem() with value: non-payable, revert.
        (bytes memory rSig, uint64 rExp) = _validRedemptionSig(userId, 1_000, 0);
        bytes memory cd2 = abi.encodeWithSelector(
            EntitlementRegistry.redeem.selector,
            userId,
            uint256(1_000),
            uint64(0),
            uint16(1),
            rExp,
            rSig
        );
        (bool ok5,) = address(reg).call{value: 1 wei}(cd2);
        assertFalse(ok5, "redeem with value must revert (non-payable)");
    }

    // =================================================================
    // Additional ecrecover-discipline coverage (mirrors v1 explicit
    // pins of L-1/L-2 audit fixes — bad v + high s).
    // =================================================================

    function test_credit_rejectsBadV() public {
        bytes32 userId = keccak256("u");
        uint64 expiresAt = uint64(block.timestamp + 3600);
        bytes32 digest = _computeCreditDigest(userId, 5_000, 0, 1, expiresAt);
        (, bytes32 r, bytes32 s) = vm.sign(PAYMENT_AUTHORITY_PK, digest);
        bytes memory badV = abi.encodePacked(r, s, uint8(26));
        vm.expectRevert(ErrInvalidSignature.selector);
        reg.credit(userId, 5_000, 0, 1, expiresAt, badV);
    }

    function test_credit_rejectsHighS() public {
        bytes32 userId = keccak256("u");
        uint64 expiresAt = uint64(block.timestamp + 3600);
        bytes32 digest = _computeCreditDigest(userId, 5_000, 0, 1, expiresAt);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PAYMENT_AUTHORITY_PK, digest);
        uint256 N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
        bytes32 highS = bytes32(N - uint256(s));
        uint8 flippedV = v == 27 ? 28 : 27;
        bytes memory mall = abi.encodePacked(r, highS, flippedV);
        vm.expectRevert(ErrInvalidSignature.selector);
        reg.credit(userId, 5_000, 0, 1, expiresAt, mall);
    }

    // -----------------------------------------------------------------
    // Gas sanity (informational — no plan target, but useful in report)
    // -----------------------------------------------------------------

    function test_credit_gasUnder150k() public {
        bytes32 userId = keccak256("u-gas");
        // Warm the slots.
        (bytes memory s0, uint64 e0) = _validCreditSig(userId, 1, 0);
        reg.credit(userId, 1, 0, 1, e0, s0);

        (bytes memory s1, uint64 e1) = _validCreditSig(userId, 1_000, 1);
        uint256 g0 = gasleft();
        reg.credit(userId, 1_000, 1, 1, e1, s1);
        uint256 gasUsed = g0 - gasleft();
        emit log_named_uint("credit (warm) gas", gasUsed);
        assertLt(gasUsed, 150_000, "warm credit must cost < 150k gas");
    }

    function test_redeem_gasUnder150k() public {
        bytes32 userId = keccak256("u-gas");
        (bytes memory s0, uint64 e0) = _validCreditSig(userId, 10_000, 0);
        reg.credit(userId, 10_000, 0, 1, e0, s0);
        // Warm the slots.
        (bytes memory r0, uint64 re0) = _validRedemptionSig(userId, 1, 1);
        reg.redeem(userId, 1, 1, 1, re0, r0);

        (bytes memory r1, uint64 re1) = _validRedemptionSig(userId, 100, 2);
        uint256 g0 = gasleft();
        reg.redeem(userId, 100, 2, 1, re1, r1);
        uint256 gasUsed = g0 - gasleft();
        emit log_named_uint("redeem (warm) gas", gasUsed);
        assertLt(gasUsed, 150_000, "warm redeem must cost < 150k gas");
    }
}
