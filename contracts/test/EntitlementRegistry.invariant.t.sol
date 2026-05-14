// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity 0.8.24;

import {Test, Vm} from "forge-std/Test.sol";
import {EntitlementRegistry} from "../src/EntitlementRegistry.sol";

/// @notice Fuzz-handler that drives `EntitlementRegistry` through
///         randomized credit + redeem sequences. The handler holds the
///         two authority private keys (so it can sign valid
///         attestations) and a small pool of user ids. Every call
///         constructs a properly-signed attestation, so the contract's
///         revert paths fire only on edge cases (insufficient balance,
///         expired attestation, etc.) — which the handler tries on
///         purpose.
///
/// @dev Audit fix M-2 (carried over from v0/v1): the handler uses
///      `vm.assume(...)` instead of an early-`return` for out-of-bounds
///      inputs so the run count stays clean under
///      `fail_on_revert = true`. Every contract call is wrapped in
///      `try/catch` so expected reverts (insufficient balance, low
///      nonce, expired) don't poison the run.
contract EntitlementRegistryHandler is Test {
    EntitlementRegistry public immutable REG;

    uint256 public immutable PAYMENT_AUTHORITY_PK;
    uint256 public immutable REDEMPTION_AUTHORITY_PK;
    uint256 public immutable RANDO_PK;

    // EIP-712 typehashes — mirror the ones in the contract.
    bytes32 internal constant CREDIT_TYPEHASH = keccak256(
        "Credit(bytes32 userId,uint256 amount,uint64 nonce,uint16 schemaVersion,uint64 expiresAt)"
    );
    bytes32 internal constant REDEMPTION_TYPEHASH = keccak256(
        "Redemption(bytes32 userId,uint256 amount,uint64 nonce,uint16 schemaVersion,uint64 expiresAt)"
    );

    // Five user ids the handler rotates through (small enough for
    // collisions to be common in fuzz runs).
    bytes32[] public userPool;

    // -----------------------------------------------------------------
    // Bookkeeping the invariants read.
    // -----------------------------------------------------------------

    /// @notice Expected balance per user — handler-computed mirror of
    ///         `REG.balance(userId)`. Asserted by
    ///         `invariant_balanceMatchesEventSum`.
    mapping(bytes32 user => uint256) public expectedBalance;

    /// @notice Expected nonce per user — handler-computed mirror of
    ///         `REG.nonce(userId)`. Used by `invariant_nonceMonotonic`
    ///         (also asserted to never decrease at this handler level).
    mapping(bytes32 user => uint64) public expectedNonce;

    /// @notice High-water-mark per user; only ever increases.
    mapping(bytes32 user => uint64) public maxSeenNonce;

    uint256 public successfulCreditCount;
    uint256 public successfulRedeemCount;

    /// @notice Every user id the fuzzer ever touched (successfully or
    ///         not). Used by the storage-mutation probe.
    bytes32[] public touchedUsers;
    mapping(bytes32 => bool) public userIsTouched;

    /// @notice Captured event topic-0s across the run. Used by
    ///         `invariant_eventCountConsistency` and
    ///         `invariant_onlyAuthorizedSignersWroteAnything`.
    bytes32[] public capturedTopic0;

    /// @notice Per-call: the (event, signer) pair the handler signed
    ///         under. Asserted by
    ///         `invariant_onlyAuthorizedSignersWroteAnything`.
    address[] public successfulCreditSigners;
    address[] public successfulRedeemSigners;

    constructor(EntitlementRegistry reg_, uint256 payPk, uint256 redeemPk, uint256 randoPk) {
        REG = reg_;
        PAYMENT_AUTHORITY_PK = payPk;
        REDEMPTION_AUTHORITY_PK = redeemPk;
        RANDO_PK = randoPk;

        userPool.push(keccak256("user-1"));
        userPool.push(keccak256("user-2"));
        userPool.push(keccak256("user-3"));
        userPool.push(keccak256("user-4"));
        userPool.push(keccak256("user-5"));
    }

    function userPoolLength() external view returns (uint256) {
        return userPool.length;
    }

    function touchedUsersLength() external view returns (uint256) {
        return touchedUsers.length;
    }

    function capturedTopic0Length() external view returns (uint256) {
        return capturedTopic0.length;
    }

    function successfulCreditSignersLength() external view returns (uint256) {
        return successfulCreditSigners.length;
    }

    function successfulRedeemSignersLength() external view returns (uint256) {
        return successfulRedeemSigners.length;
    }

    // -----------------------------------------------------------------
    // Internal digest builders.
    // -----------------------------------------------------------------

    function _creditDigest(
        bytes32 userId,
        uint256 amount,
        uint64 attestationNonce,
        uint16 schemaVersion,
        uint64 expiresAt
    ) internal view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(CREDIT_TYPEHASH, userId, amount, attestationNonce, schemaVersion, expiresAt)
        );
        return keccak256(abi.encodePacked(hex"1901", REG.DOMAIN_SEPARATOR(), structHash));
    }

    function _redemptionDigest(
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
        return keccak256(abi.encodePacked(hex"1901", REG.DOMAIN_SEPARATOR(), structHash));
    }

    function _sign(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _markTouched(bytes32 user) internal {
        if (!userIsTouched[user]) {
            userIsTouched[user] = true;
            touchedUsers.push(user);
        }
    }

    function _captureLogs() internal {
        Vm.Log[] memory entries = vm.getRecordedLogs();
        for (uint256 i = 0; i < entries.length; i++) {
            if (entries[i].emitter == address(REG)) {
                require(entries[i].topics.length > 0, "handler: log without topic0");
                capturedTopic0.push(entries[i].topics[0]);
            }
        }
    }

    function _ensureNoLogsFromReg() internal view {
        Vm.Log[] memory entries = vm.getRecordedLogs();
        for (uint256 i = 0; i < entries.length; i++) {
            if (entries[i].emitter == address(REG)) {
                revert("handler: revert path must not emit");
            }
        }
    }

    // -----------------------------------------------------------------
    // Fuzz targets.
    // -----------------------------------------------------------------

    /// @notice Attempt a credit with the correct payment authority key.
    function creditValid(
        uint256 userIdx,
        uint128 amount,
        uint8 schemaVersionRaw,
        uint64 expiresInSeconds
    ) external {
        // Bound inputs.
        vm.assume(amount > 0);
        // Cap individual credits so 2^256 overflow is impossible across
        // a 10k×32 run.
        vm.assume(amount <= type(uint128).max);
        vm.assume(expiresInSeconds <= 86_400);
        userIdx = userIdx % userPool.length;
        uint16 schemaVersion = uint16(schemaVersionRaw % 3); // 0, 1, or 2 (2 triggers ErrUnsupportedSchemaVersion)

        bytes32 userId = userPool[userIdx];
        _markTouched(userId);

        uint64 attestationNonce = expectedNonce[userId];
        uint64 expiresAt = uint64(block.timestamp + uint256(expiresInSeconds) + 1);
        bytes32 digest =
            _creditDigest(userId, uint256(amount), attestationNonce, schemaVersion, expiresAt);
        bytes memory sig = _sign(PAYMENT_AUTHORITY_PK, digest);

        vm.recordLogs();
        try REG.credit(userId, uint256(amount), attestationNonce, schemaVersion, expiresAt, sig)
        returns (uint256) {
            _captureLogs();
            expectedBalance[userId] += uint256(amount);
            expectedNonce[userId] = attestationNonce + 1;
            if (attestationNonce + 1 > maxSeenNonce[userId]) {
                maxSeenNonce[userId] = attestationNonce + 1;
            }
            successfulCreditCount += 1;
            successfulCreditSigners.push(vm.addr(PAYMENT_AUTHORITY_PK));
        } catch {
            _ensureNoLogsFromReg();
        }
    }

    /// @notice Attempt a credit with the WRONG authority key. Always
    ///         reverts; never updates expected state.
    function creditWrongAuth(uint256 userIdx, uint128 amount) external {
        vm.assume(amount > 0);
        vm.assume(amount <= type(uint128).max);
        userIdx = userIdx % userPool.length;
        bytes32 userId = userPool[userIdx];
        _markTouched(userId);

        uint64 attestationNonce = expectedNonce[userId];
        uint64 expiresAt = uint64(block.timestamp + 3600);
        bytes32 digest = _creditDigest(userId, uint256(amount), attestationNonce, 1, expiresAt);
        // Sign with the REDEMPTION authority (wrong for credit).
        bytes memory sig = _sign(REDEMPTION_AUTHORITY_PK, digest);

        vm.recordLogs();
        try REG.credit(userId, uint256(amount), attestationNonce, 1, expiresAt, sig) returns (
            uint256
        ) {
            revert("handler: credit with wrong authority must revert");
        } catch {
            _ensureNoLogsFromReg();
        }
    }

    /// @notice Attempt a redeem with the correct redemption authority key.
    function redeemValid(
        uint256 userIdx,
        uint128 amount,
        uint8 schemaVersionRaw,
        uint64 expiresInSeconds
    ) external {
        vm.assume(amount > 0);
        vm.assume(amount <= type(uint128).max);
        vm.assume(expiresInSeconds <= 86_400);
        userIdx = userIdx % userPool.length;
        uint16 schemaVersion = uint16(schemaVersionRaw % 3);

        bytes32 userId = userPool[userIdx];
        _markTouched(userId);

        uint64 attestationNonce = expectedNonce[userId];
        uint64 expiresAt = uint64(block.timestamp + uint256(expiresInSeconds) + 1);
        bytes32 digest =
            _redemptionDigest(userId, uint256(amount), attestationNonce, schemaVersion, expiresAt);
        bytes memory sig = _sign(REDEMPTION_AUTHORITY_PK, digest);

        vm.recordLogs();
        try REG.redeem(userId, uint256(amount), attestationNonce, schemaVersion, expiresAt, sig)
        returns (uint256) {
            _captureLogs();
            expectedBalance[userId] -= uint256(amount);
            expectedNonce[userId] = attestationNonce + 1;
            if (attestationNonce + 1 > maxSeenNonce[userId]) {
                maxSeenNonce[userId] = attestationNonce + 1;
            }
            successfulRedeemCount += 1;
            successfulRedeemSigners.push(vm.addr(REDEMPTION_AUTHORITY_PK));
        } catch {
            _ensureNoLogsFromReg();
        }
    }

    /// @notice Attempt a redeem with the WRONG authority key. Always reverts.
    function redeemWrongAuth(uint256 userIdx, uint128 amount) external {
        vm.assume(amount > 0);
        vm.assume(amount <= type(uint128).max);
        userIdx = userIdx % userPool.length;
        bytes32 userId = userPool[userIdx];
        _markTouched(userId);

        uint64 attestationNonce = expectedNonce[userId];
        uint64 expiresAt = uint64(block.timestamp + 300);
        bytes32 digest = _redemptionDigest(userId, uint256(amount), attestationNonce, 1, expiresAt);
        // Sign with the PAYMENT authority (wrong for redeem).
        bytes memory sig = _sign(PAYMENT_AUTHORITY_PK, digest);

        vm.recordLogs();
        try REG.redeem(userId, uint256(amount), attestationNonce, 1, expiresAt, sig) returns (
            uint256
        ) {
            revert("handler: redeem with wrong authority must revert");
        } catch {
            _ensureNoLogsFromReg();
        }
    }

    /// @notice Attempt a credit with a tampered nonce (wrong slot).
    function creditWrongNonce(uint256 userIdx, uint128 amount, uint64 nonceDelta) external {
        vm.assume(amount > 0);
        vm.assume(nonceDelta > 0);
        vm.assume(amount <= type(uint128).max);
        vm.assume(nonceDelta < 1_000_000);
        userIdx = userIdx % userPool.length;
        bytes32 userId = userPool[userIdx];
        _markTouched(userId);

        uint64 attestationNonce = expectedNonce[userId] + nonceDelta;
        uint64 expiresAt = uint64(block.timestamp + 3600);
        bytes32 digest = _creditDigest(userId, uint256(amount), attestationNonce, 1, expiresAt);
        bytes memory sig = _sign(PAYMENT_AUTHORITY_PK, digest);

        vm.recordLogs();
        try REG.credit(userId, uint256(amount), attestationNonce, 1, expiresAt, sig) returns (
            uint256
        ) {
            revert("handler: credit with wrong nonce must revert");
        } catch {
            _ensureNoLogsFromReg();
        }
    }
}

/// @title EntitlementRegistry invariant tests
///
/// @dev Implements the 5 invariants in docs/issue-plans/2.2.md §5:
///        - balanceMatchesEventSum (via handler bookkeeping)
///        - nonceMonotonic
///        - eventCountConsistency
///        - noStorageMutationBesidesBalanceAndNonce
///        - onlyAuthorizedSignersWroteAnything
contract EntitlementRegistryInvariantsTest is Test {
    EntitlementRegistry internal reg;
    EntitlementRegistryHandler internal handler;

    uint256 internal constant PAYMENT_AUTHORITY_PK =
        0xC0FFEE00C0FFEE00C0FFEE00C0FFEE00C0FFEE00C0FFEE00C0FFEE00C0FFEE00;
    uint256 internal constant REDEMPTION_AUTHORITY_PK =
        0xDECAFBADDECAFBADDECAFBADDECAFBADDECAFBADDECAFBADDECAFBADDECAFBAD;
    uint256 internal constant RANDO_PK =
        0xABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD;

    /// @dev Pre-computed
    ///      `keccak256("Credited(bytes32,uint256,uint256,uint64,uint16)")`.
    ///      Drift-protection — if the event signature ever changes,
    ///      this constant must be updated AND the change reviewed.
    bytes32 internal constant CREDITED_TOPIC0 =
        keccak256("Credited(bytes32,uint256,uint256,uint64,uint16)");

    /// @dev Pre-computed
    ///      `keccak256("Redeemed(bytes32,uint256,uint256,uint64,uint16)")`.
    bytes32 internal constant REDEEMED_TOPIC0 =
        keccak256("Redeemed(bytes32,uint256,uint256,uint64,uint16)");

    uint64 internal constant SLOT_BALANCE = 0;
    uint64 internal constant SLOT_NONCE = 1;

    function setUp() public {
        address payAuth = vm.addr(PAYMENT_AUTHORITY_PK);
        address redeemAuth = vm.addr(REDEMPTION_AUTHORITY_PK);
        reg = new EntitlementRegistry(payAuth, redeemAuth);
        handler = new EntitlementRegistryHandler(
            reg, PAYMENT_AUTHORITY_PK, REDEMPTION_AUTHORITY_PK, RANDO_PK
        );

        targetContract(address(handler));
        // Rotate senders so we exercise tx.origin != msg.sender.
        targetSender(address(0xA11CE));
        targetSender(address(0xB0B));
        targetSender(address(0xCAFE));
        targetSender(address(0xDEADBEEF));
    }

    /// @dev Invariant 1: balanceMatchesEventSum. For every user the
    ///      handler has interacted with, the on-chain balance equals
    ///      the handler's running mirror.
    function invariant_balanceMatchesEventSum() public view {
        uint256 n = handler.touchedUsersLength();
        for (uint256 i = 0; i < n; i++) {
            bytes32 user = handler.touchedUsers(i);
            assertEq(
                reg.balance(user),
                handler.expectedBalance(user),
                "balance must equal handler-mirrored sum of credits - redeems"
            );
        }
    }

    /// @dev Invariant 2: nonceMonotonic. For every touched user, the
    ///      contract's nonce equals the handler's expected nonce AND
    ///      the maxSeenNonce — i.e., the nonce never decreased.
    function invariant_nonceMonotonic() public view {
        uint256 n = handler.touchedUsersLength();
        for (uint256 i = 0; i < n; i++) {
            bytes32 user = handler.touchedUsers(i);
            uint64 onChain = reg.nonce(user);
            uint64 expected = handler.expectedNonce(user);
            uint64 highWater = handler.maxSeenNonce(user);
            assertEq(onChain, expected, "nonce must equal handler-mirrored expected");
            assertEq(onChain, highWater, "nonce must equal high-water (monotonic)");
        }
    }

    /// @dev Invariant 3: eventCountConsistency. The total number of
    ///      events emitted by the contract equals the total number of
    ///      successful credit + redeem operations.
    function invariant_eventCountConsistency() public view {
        uint256 captured = handler.capturedTopic0Length();
        uint256 successful = handler.successfulCreditCount() + handler.successfulRedeemCount();
        assertEq(captured, successful, "captured event count must equal successful tx count");
        // Topic-0 of every captured event must be Credited or Redeemed.
        for (uint256 i = 0; i < captured; i++) {
            bytes32 t = handler.capturedTopic0(i);
            assertTrue(
                t == CREDITED_TOPIC0 || t == REDEEMED_TOPIC0,
                "unexpected event topic-0 (only Credited/Redeemed allowed)"
            );
        }
    }

    /// @dev Invariant 4: noStorageMutationBesidesBalanceAndNonce. The
    ///      only storage slots that may be non-zero are:
    ///        - the hashed slots of the `balance` mapping (base slot
    ///          SLOT_BALANCE) for touched users
    ///        - the hashed slots of the `nonce` mapping (base slot
    ///          SLOT_NONCE) for touched users
    ///      Every linear slot from 0..31 stays zero (mappings hash
    ///      their entries; the base slot itself stores no value).
    ///      Immutables are NOT in storage (they're inlined into
    ///      bytecode) so they don't count.
    function invariant_noStorageMutationBesidesBalanceAndNonce() public view {
        // Probe linear slots 0..31. Mappings' base slot is itself zero;
        // only the hashed entries hold data.
        for (uint256 slot = 0; slot < 32; slot++) {
            bytes32 v = vm.load(address(reg), bytes32(slot));
            assertEq(v, bytes32(0), "non-zero storage at linear slot");
        }

        // For every touched user, the balance + nonce hashed slots
        // should agree with the on-chain getters (sanity check that
        // the slot layout matches the assumed `SLOT_BALANCE = 0` /
        // `SLOT_NONCE = 1`).
        uint256 n = handler.touchedUsersLength();
        for (uint256 i = 0; i < n; i++) {
            bytes32 user = handler.touchedUsers(i);

            bytes32 balSlot = keccak256(abi.encode(user, uint256(SLOT_BALANCE)));
            bytes32 noncePackedSlot = keccak256(abi.encode(user, uint256(SLOT_NONCE)));

            uint256 storedBal = uint256(vm.load(address(reg), balSlot));
            uint256 storedNoncePacked = uint256(vm.load(address(reg), noncePackedSlot));
            // nonce is uint64; it occupies the low 8 bytes of the slot;
            // the rest of the slot is zero (Solidity zero-extends).
            uint64 storedNonce = uint64(storedNoncePacked);
            uint256 highBits = storedNoncePacked >> 64;
            assertEq(highBits, 0, "high bits of nonce slot must be zero");

            assertEq(storedBal, reg.balance(user), "balance slot drift");
            assertEq(storedNonce, reg.nonce(user), "nonce slot drift");
        }
    }

    /// @dev Invariant 5: onlyAuthorizedSignersWroteAnything. For every
    ///      successful credit recorded by the handler, the signer was
    ///      PAYMENT_AUTHORITY. For every successful redeem, the signer
    ///      was REDEMPTION_AUTHORITY. The handler builds these lists
    ///      itself; the invariant cross-checks them against the
    ///      authorities the contract exposes.
    function invariant_onlyAuthorizedSignersWroteAnything() public view {
        address payAuth = reg.PAYMENT_AUTHORITY();
        address redeemAuth = reg.REDEMPTION_AUTHORITY();

        uint256 nc = handler.successfulCreditSignersLength();
        for (uint256 i = 0; i < nc; i++) {
            assertEq(
                handler.successfulCreditSigners(i),
                payAuth,
                "successful credit signer must be PAYMENT_AUTHORITY"
            );
        }
        uint256 nr = handler.successfulRedeemSignersLength();
        for (uint256 j = 0; j < nr; j++) {
            assertEq(
                handler.successfulRedeemSigners(j),
                redeemAuth,
                "successful redeem signer must be REDEMPTION_AUTHORITY"
            );
        }
    }
}
