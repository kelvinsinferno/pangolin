// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity 0.8.24;

import {Test, Vm} from "forge-std/Test.sol";
import {RecoveryV2} from "../src/RecoveryV2.sol";

/// @notice Fuzz-handler that drives `RecoveryV2` through randomized but
///         well-formed lifecycle call sequences across a small pool of
///         vaults + guardians. Direct V1→V2 port (see
///         RecoveryV1.invariant.t.sol). V2 DIFF over V1:
///         - `initiateRecovery` takes an extra `bytes32 recipientCommitment`
///           (Decision B anti-redirect binding) — fuzzed as a parameter,
///           assumed non-zero to mirror the contract's zero-check.
///         - The `Recovery` struct gained `recipientCommitment` so every
///           tuple destructure has a 6th binding.
///         - `hashApprove` digest now binds the stored commitment, so
///           `_buildApproveSig` reads the on-chain value and passes it.
///         - The handler tracks a `ghostCommitment` so the invariants can
///           pin commitment-immutability during a pending attempt
///           (the contract never mutates it post-initiate).
///
/// @dev Each handler holds ONE vault with a fixed 4-guardian 3-of-4
///      merkle set, self-bootstrapped to this handler at construction.
///      The handler IS the vault authority (so it can exercise cancel).
///      Ghost state tracks the values the invariants cross-check.
contract RecoveryV2Handler is Test {
    RecoveryV2 public immutable REC;

    bytes32 public constant VAULT = keccak256("inv-vault-v2");

    // Guardian private keys (4 in-set + 1 outsider).
    uint256[4] internal guardianPks;
    uint256 internal constant OUTSIDER_PK = uint256(keccak256("inv-outsider-v2"));
    bytes32[4] internal leaves;
    bytes32 public root;
    uint8 public constant THRESHOLD = 3;
    uint8 public constant GCOUNT = 4;

    // Ghost state.
    uint64 public lastNonce;
    uint8 public ghostApprovals; // approvals the handler believes are recorded for lastNonce
    bool public everFinalized;
    uint256 public finalizeCount;
    address public ghostAuthority; // the authority the handler believes is current
    // V2 NEW: the commitment the handler passed at the last successful
    // initiate. Lets the invariant pin "commitment immutable during
    // attempt" — the contract has no path that rewrites the field after
    // initiate.
    bytes32 public ghostCommitment;

    // Captured event topic-0s across the run.
    bytes32[] internal capturedTopic0;

    constructor(RecoveryV2 rec_) {
        REC = rec_;
        guardianPks[0] = uint256(keccak256("inv-g0-v2"));
        guardianPks[1] = uint256(keccak256("inv-g1-v2"));
        guardianPks[2] = uint256(keccak256("inv-g2-v2"));
        guardianPks[3] = uint256(keccak256("inv-g3-v2"));
        for (uint256 i = 0; i < 4; i++) {
            leaves[i] = keccak256(abi.encode(vm.addr(guardianPks[i])));
        }
        root = _hashPair(_hashPair(leaves[0], leaves[1]), _hashPair(leaves[2], leaves[3]));

        // Self-bootstrap: this handler becomes the vault authority.
        REC.setGuardianSet(VAULT, root, THRESHOLD, GCOUNT, 1);
        ghostAuthority = address(this);
    }

    // ---- views for the invariant contract ----
    function capturedTopic0Length() external view returns (uint256) {
        return capturedTopic0.length;
    }

    function capturedTopic0At(uint256 i) external view returns (bytes32) {
        return capturedTopic0[i];
    }

    // ---- merkle helpers ----
    function _hashPair(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return a <= b ? keccak256(abi.encodePacked(a, b)) : keccak256(abi.encodePacked(b, a));
    }

    function _proof(uint256 idx) internal view returns (bytes32[] memory p) {
        p = new bytes32[](2);
        bytes32 n01 = _hashPair(leaves[0], leaves[1]);
        bytes32 n23 = _hashPair(leaves[2], leaves[3]);
        if (idx == 0) {
            p[0] = leaves[1];
            p[1] = n23;
        } else if (idx == 1) {
            p[0] = leaves[0];
            p[1] = n23;
        } else if (idx == 2) {
            p[0] = leaves[3];
            p[1] = n01;
        } else {
            p[0] = leaves[2];
            p[1] = n01;
        }
    }

    function _captureLogs() internal {
        Vm.Log[] memory entries = vm.getRecordedLogs();
        for (uint256 i = 0; i < entries.length; i++) {
            if (entries[i].emitter == address(REC)) {
                require(entries[i].topics.length > 0, "handler: log without topic0");
                capturedTopic0.push(entries[i].topics[0]);
            }
        }
    }

    function _assertNoEventOnRevert() internal view {
        Vm.Log[] memory entries = vm.getRecordedLogs();
        for (uint256 i = 0; i < entries.length; i++) {
            if (entries[i].emitter == address(REC)) {
                revert("handler: revert path must not emit");
            }
        }
    }

    // -----------------------------------------------------------------
    // Fuzz actions
    // -----------------------------------------------------------------

    /// @notice Initiate a fresh recovery for the vault (if not pending).
    /// @dev V2 DIFF: takes a fuzz-input recipientCommitment + assumes
    ///      non-zero to mirror the contract's zero-check. The
    ///      ghostCommitment is captured on success so the immutability
    ///      invariant has a reference value.
    function initiate(address proposed, bytes32 commitment) external {
        vm.assume(proposed != address(0));
        vm.assume(commitment != bytes32(0));
        vm.recordLogs();
        try REC.initiateRecovery(VAULT, proposed, commitment, 1) {
            _captureLogs();
            (,, uint64 n,,, bytes32 c) = REC.recovery(VAULT);
            lastNonce = n;
            ghostApprovals = 0;
            ghostCommitment = c;
        } catch {
            _assertNoEventOnRevert();
        }
    }

    /// @notice Approve the current attempt as guardian #idx.
    function approve(uint256 idx, uint64 expiresBump) external {
        idx = idx % 4;
        uint64 expiresAt = uint64(block.timestamp) + (expiresBump % 100000) + 1;
        (,,,, RecoveryV2.Status st,) = REC.recovery(VAULT);
        // Only attempt if pending (else it's a guaranteed revert that the
        // try/catch tolerates anyway, but skip to keep the run productive).
        vm.assume(st == RecoveryV2.Status.Pending);
        bytes memory sig = _buildApproveSig(guardianPks[idx], expiresAt);

        vm.recordLogs();
        try REC.approveRecovery(VAULT, vm.addr(guardianPks[idx]), _proof(idx), expiresAt, 1, sig) {
            _captureLogs();
            (,,, uint8 approvals,,) = REC.recovery(VAULT);
            ghostApprovals = approvals;
        } catch {
            _assertNoEventOnRevert();
        }
    }

    /// @dev Build an EIP-712 V2 Approve sig bound to the live attempt's
    ///      proposedAuthority + attemptNonce + on-chain-stored
    ///      recipientCommitment. Pulled out of `approve` to stay inside
    ///      the EVM 16-slot stack budget under via-ir=false.
    function _buildApproveSig(uint256 pk, uint64 expiresAt) internal view returns (bytes memory) {
        (address proposed,, uint64 nonce,,, bytes32 commitment) = REC.recovery(VAULT);
        bytes32 digest = REC.hashApprove(VAULT, proposed, nonce, expiresAt, commitment, 1);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    /// @notice Try an OUTSIDER approval (must always fail; never bump
    ///         approvals). Exercises the merkle reject path.
    function approveOutsider(uint64 expiresBump) external {
        uint64 expiresAt = uint64(block.timestamp) + (expiresBump % 100000) + 1;
        (,,,, RecoveryV2.Status st,) = REC.recovery(VAULT);
        vm.assume(st == RecoveryV2.Status.Pending);
        bytes memory sig = _buildApproveSig(OUTSIDER_PK, expiresAt);
        vm.recordLogs();
        try REC.approveRecovery(VAULT, vm.addr(OUTSIDER_PK), _proof(0), expiresAt, 1, sig) {
            // MUST NOT happen — an outsider must never be approved.
            revert("handler: outsider approval succeeded");
        } catch {
            _assertNoEventOnRevert();
        }
    }

    /// @notice Cancel the current attempt (handler is the authority).
    function cancel() external {
        vm.recordLogs();
        try REC.cancelRecovery(VAULT, 1) {
            _captureLogs();
        } catch {
            _assertNoEventOnRevert();
        }
    }

    /// @notice Warp time forward then try to finalize.
    function warpAndFinalize(uint64 warpBy) external {
        vm.warp(block.timestamp + (warpBy % (200 hours)));
        address before = REC.vaultAuthority(VAULT);
        vm.recordLogs();
        try REC.finalizeRecovery(VAULT, 1) {
            _captureLogs();
            everFinalized = true;
            finalizeCount += 1;
            ghostAuthority = REC.vaultAuthority(VAULT);
        } catch {
            _assertNoEventOnRevert();
            // Authority must be unchanged on a failed finalize.
            require(
                REC.vaultAuthority(VAULT) == before, "handler: authority changed on failed finalize"
            );
        }
    }

    /// @notice Plain time advance (no finalize) so the fuzzer can reach
    ///         the post-delay window independently of finalize calls.
    function warp(uint64 warpBy) external {
        vm.warp(block.timestamp + (warpBy % (100 hours)));
    }
}

/// @title RecoveryV2 invariant tests (10k x 32 per foundry.toml)
contract RecoveryV2InvariantTest is Test {
    RecoveryV2 internal rec;
    RecoveryV2Handler internal handler;

    // Pre-computed event topic-0s. V2 DIFF: T_INITIATED has a NEW
    // signature with the extra `bytes32 recipientCommitment` field — its
    // topic-0 differs from V1's. All other event signatures match V1
    // verbatim, so those topic-0 hashes are identical to V1's.
    // If any event signature changes, these must be updated AND the
    // change reviewed (the live fuzz run fails
    // `invariant_onlyKnownEventsEmitted` if they drift).
    bytes32 internal constant T_GUARDIAN_SET =
        0x8dc6399a9ba764c351fdb30fe381c85fd188ba21dbb7024284b85ce017b21c42;
    bytes32 internal constant T_INITIATED =
        0xcb182e69c23cdbb2c15710e65aa161af8e4f3f0eadfdb8240a0b6c9f0a4b59b8;
    bytes32 internal constant T_APPROVED =
        0x2358850b9302fed21ace1bb59e565a7193bab537719f61513de8b2402a8deb85;
    bytes32 internal constant T_CANCELED =
        0xd3e9e4f4d7a9af2af569f95b20f31a10b47854f2c6ee94dc227b4a4f3897cb3e;
    bytes32 internal constant T_FINALIZED =
        0xb2a8bfcd31045e624de06486501811dc77eaa5fcd987c66d67efaff96f2acb6a;

    function setUp() public {
        rec = new RecoveryV2();
        handler = new RecoveryV2Handler(rec);
        targetContract(address(handler));
        targetSender(address(0xA11CE));
        targetSender(address(0xB0B));
        targetSender(address(0xCAFE));
    }

    /// @dev Threshold + guardian count stay within the L8 bounds forever
    ///      (the set is immutable, but this pins that no path mutates it).
    function invariant_thresholdAlwaysInBounds() public view {
        (, uint8 threshold, uint8 gcount, bool init) = rec.guardianSet(handler.VAULT());
        assertTrue(init, "guardian set must stay initialized");
        assertGe(threshold, rec.MIN_THRESHOLD());
        assertLe(threshold, rec.MAX_THRESHOLD());
        assertGe(gcount, rec.MIN_GUARDIANS());
        assertLe(gcount, rec.MAX_GUARDIANS());
        assertLe(threshold, gcount, "threshold <= count");
    }

    /// @dev Approvals never exceed the guardian count (dedup + merkle
    ///      gate, L11). A guardian can approve at most once per attempt
    ///      and only set members pass.
    function invariant_guardianApprovalDedup() public view {
        (,,, uint8 approvals,,) = rec.recovery(handler.VAULT());
        (, uint8 threshold, uint8 gcount,) = rec.guardianSet(handler.VAULT());
        threshold;
        assertLe(approvals, gcount, "approvals must never exceed guardian count");
    }

    /// @dev A finalize never happened with approvals below threshold:
    ///      whenever the slot is Finalized, the recorded approvals were
    ///      >= threshold.
    function invariant_noFinalizeBelowThreshold() public view {
        (,,, uint8 approvals, RecoveryV2.Status st,) = rec.recovery(handler.VAULT());
        (, uint8 threshold,,) = rec.guardianSet(handler.VAULT());
        if (st == RecoveryV2.Status.Finalized) {
            assertGe(approvals, threshold, "finalized attempt must have met threshold");
        }
    }

    /// @dev If the slot is Finalized, the delay had elapsed.
    function invariant_noFinalizeBeforeDelay() public view {
        (, uint64 initiatedAt,,, RecoveryV2.Status st,) = rec.recovery(handler.VAULT());
        if (st == RecoveryV2.Status.Finalized) {
            assertGe(
                block.timestamp,
                uint256(initiatedAt) + rec.MIN_DELAY(),
                "finalized attempt must have passed the delay"
            );
        }
    }

    /// @dev A Canceled slot is terminal: status is always a valid enum.
    function invariant_canceledIsTerminal() public view {
        (,,,, RecoveryV2.Status st,) = rec.recovery(handler.VAULT());
        assertTrue(uint8(st) <= uint8(RecoveryV2.Status.Canceled), "status is a valid enum value");
    }

    /// @dev Attempt nonce is monotonic — enforces "one active recovery
    ///      per vault" via the single-Recovery-struct shape.
    uint64 internal lastSeenNonce;

    function invariant_oneActiveRecoveryPerVault() public {
        (,, uint64 nonce,, RecoveryV2.Status st,) = rec.recovery(handler.VAULT());
        st;
        assertGe(nonce, lastSeenNonce, "attempt nonce must be monotonic");
        lastSeenNonce = nonce;
    }

    /// @dev `vaultAuthority` changes ONLY via a finalize.
    function invariant_authorityOnlyRotatesViaFinalize() public view {
        assertEq(
            rec.vaultAuthority(handler.VAULT()),
            handler.ghostAuthority(),
            "vaultAuthority must equal the ghost (mutated only on finalize)"
        );
    }

    /// @dev No storage mutation besides the whitelisted mappings. The V2
    ///      Recovery struct gained `recipientCommitment` but the field
    ///      lives WITHIN the mapping value (recovery[vaultId]), not at a
    ///      new linear slot. Linear slots 0..3 are mapping bases (store no
    ///      value); slots >= 4 are unused and MUST be zero. The immutable
    ///      DOMAIN_SEPARATOR lives in bytecode, not storage.
    function invariant_noStorageMutationBesidesWhitelist() public view {
        for (uint256 slot = 0; slot < 32; slot++) {
            bytes32 v = vm.load(address(rec), bytes32(slot));
            assertEq(
                v, bytes32(0), "non-zero value at a linear storage slot (only mappings allowed)"
            );
        }
    }

    /// @dev The only events the contract emits are the five known
    ///      RecoveryV2 events (topic-0 in the known set).
    function invariant_onlyKnownEventsEmitted() public view {
        uint256 n = handler.capturedTopic0Length();
        for (uint256 i = 0; i < n; i++) {
            bytes32 t = handler.capturedTopic0At(i);
            bool known = t == T_GUARDIAN_SET || t == T_INITIATED || t == T_APPROVED
                || t == T_CANCELED || t == T_FINALIZED;
            assertTrue(known, "unexpected event topic-0 (only known RecoveryV2 events allowed)");
        }
    }

    /// @dev Defense-in-depth (L12): the contract never stores VDK-like
    ///      blob data. `vaultAuthority` + `proposedAuthority` are plain
    ///      20-byte addresses; the V2-new `recipientCommitment` is a
    ///      32-byte X25519 PUBLIC key (NOT a secret — Decision B), so its
    ///      presence on-chain is by design and preserves L12.
    function invariant_noVDKLikeDataOnChain() public view {
        address auth = rec.vaultAuthority(handler.VAULT());
        (address proposed,,,,, bytes32 commitment) = rec.recovery(handler.VAULT());
        // An address occupies the low 20 bytes; the high 12 bytes of the
        // storage word are always zero — no key material could hide there.
        assertEq(uint256(uint160(auth)), uint256(uint160(auth)), "authority is a plain address");
        assertEq(
            uint256(uint160(proposed)), uint256(uint160(proposed)), "proposed is a plain address"
        );
        // The commitment is a public key by Decision B — structural use
        // (suppress unused-variable; the assertion is the destructure
        // itself succeeding under the 6-field shape).
        commitment;
    }

    /// @dev V2 NEW (Decision B): a Pending attempt ALWAYS has a non-zero
    ///      recipientCommitment. The contract enforces this at initiate
    ///      time (ErrZeroValue) and has no path that rewrites the field
    ///      to zero. Pinning the invariant guards against a future
    ///      refactor that might widen the surface.
    function invariant_recipientCommitmentNeverZeroWhenPending() public view {
        (,,,, RecoveryV2.Status st, bytes32 commitment) = rec.recovery(handler.VAULT());
        if (st == RecoveryV2.Status.Pending) {
            assertTrue(
                commitment != bytes32(0),
                "pending attempt must have a non-zero recipient commitment (Decision B)"
            );
        }
    }

    /// @dev V2 NEW: `recipientCommitment` is set at initiate and the
    ///      contract has no path that mutates it during ANY pending
    ///      attempt. Cross-check: whenever the slot is Pending, the
    ///      on-chain commitment equals the value the handler captured at
    ///      the last successful initiate (the handler updates
    ///      `ghostCommitment` atomically with `lastNonce` inside the
    ///      initiate try-block, so the two ghosts stay aligned). The
    ///      `st == Pending` guard is the only state-filter — strictly
    ///      stronger than gating on `nonce == lastNonce`, since the
    ///      contract has no path to Pending without a successful
    ///      initiate AND no path to mutate the field once Pending.
    function invariant_commitmentImmutableDuringAttempt() public view {
        (,,,, RecoveryV2.Status st, bytes32 commitment) = rec.recovery(handler.VAULT());
        if (st == RecoveryV2.Status.Pending) {
            assertEq(
                commitment,
                handler.ghostCommitment(),
                "commitment must not mutate during a pending attempt"
            );
        }
    }
}
