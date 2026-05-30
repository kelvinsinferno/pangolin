// SPDX-License-Identifier: AGPL-3.0-or-later
// @dev Exact-pinned pragma (NOT `^0.8.24`): RecoveryV1's L3 discipline
//      carries forward — the contract must build with the exact compiler
//      version it is audited against. RecoveryV2 is external-audit-gated
//      before mainnet (D-011); the exact pin is what the auditor signs
//      off on.
pragma solidity 0.8.24;

/// @title RecoveryV2
/// @notice MVP-4-L L-0a-1: RecoveryV1 with an on-chain RECIPIENT
///         COMMITMENT (the recovering user's ephemeral X25519 pubkey, used
///         in the off-chain share-transport re-seal). The guardian's
///         on-chain Approve EIP-712 now signs over the commitment, so a
///         guardian's client refuses to release a share off-chain to any
///         key not matching the chain — the strongest available
///         anti-redirect binding (locked in
///         docs/issue-plans/mvp4-l-share-transport-design.md Decision B).
///
/// @dev DIFF FROM RecoveryV1 (verbatim everywhere else; RecoveryV1.sol is
///      immutable historical and is NOT edited):
///        - `struct Recovery` gains `bytes32 recipientCommitment` (the
///          recovering user's per-attempt X25519 pubkey, written at
///          initiate time, read by `_hashApprove`).
///        - `initiateRecovery` gains a `bytes32 recipientCommitment`
///          parameter (rejected if zero — a zero commitment would defeat
///          the anti-redirect binding by accepting any recipient).
///        - `APPROVE_TYPEHASH` literal gains `bytes32 recipientCommitment`
///          (a NEW typehash — a V1-shape approval signature cannot match
///          a V2 digest, closing cross-version replay).
///        - `_hashApprove` / `hashApprove` accept `recipientCommitment`;
///          `approveRecovery` reads the stored commitment from the
///          attempt's storage slot so the guardian's signed digest must
///          cover the on-chain-recorded recipient.
///        - `RecoveryInitiated` event carries `recipientCommitment` for
///          off-chain observability (clients can verify the chain commits
///          to the same recipient their UI showed).
///
/// @dev CARDINAL CONTRACT DESIGN RULES (inherited VERBATIM from V1):
///      no admin keys, no upgrades, no pause, no external calls, never
///      touches the VDK / any secret (L12). The commitment is the
///      RECOVERING USER'S PUBLIC KEY (not a secret), so adding it to
///      storage + the Approve digest preserves L12.
///
/// @dev Deployment & migration: RecoveryV2 is a NEW deploy at a NEW
///      address (V1 is hard-immutable by design; no upgrade path). On
///      Base Sepolia this is the FIRST recovery deploy (V1 was never
///      deployed there — anvil-only); on Anvil dev, V2 supersedes V1
///      under a new `dev.json` `RecoveryV2` entry.
///
/// @dev Cross-chain portability: same Shanghai-or-later EVM contract as
///      V1; `ecrecover` precompile-only; no Base-specific opcodes.
contract RecoveryV2 {
    // -----------------------------------------------------------------
    // Types
    // -----------------------------------------------------------------

    /// @notice Lifecycle status of a vault's recovery slot. Verbatim from
    ///         V1 (None / Pending / Finalized / Canceled). `uint8`-backed.
    enum Status {
        None,
        Pending,
        Finalized,
        Canceled
    }

    /// @notice Immutable per-vault guardian commitment. Verbatim from V1.
    struct GuardianSet {
        bytes32 root;
        uint8 threshold;
        uint8 guardianCount;
        bool initialized;
    }

    /// @notice Per-vault active recovery attempt.
    ///
    /// @dev V2 DIFF: gains `recipientCommitment` (the recovering user's
    ///      ephemeral X25519 pubkey for this attempt, per the locked
    ///      share-transport design). Read by `_hashApprove` so each
    ///      guardian's signature binds the on-chain-committed recipient.
    ///      Field widths per L7: initiatedAt uint64, attemptNonce uint64,
    ///      approvals uint8, recipientCommitment bytes32.
    struct Recovery {
        address proposedAuthority;
        uint64 initiatedAt;
        uint64 attemptNonce;
        uint8 approvals;
        Status status;
        bytes32 recipientCommitment;
    }

    // -----------------------------------------------------------------
    // Events (every transition carries a uint16 schemaVersion — L5)
    // -----------------------------------------------------------------

    event GuardianSetInitialized(
        bytes32 indexed vaultId,
        bytes32 root,
        uint8 threshold,
        uint8 guardianCount,
        address initialAuthority,
        uint16 schemaVersion
    );

    /// @notice V2 DIFF: gains `recipientCommitment` so off-chain
    ///         observers can verify the chain commits to the recipient
    ///         their UI shows.
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

    // -----------------------------------------------------------------
    // Errors (verbatim from V1)
    // -----------------------------------------------------------------

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

    // -----------------------------------------------------------------
    // Constants
    // -----------------------------------------------------------------

    uint16 public constant MAX_KNOWN_SCHEMA_VERSION = 1;
    uint64 public constant MIN_DELAY = 72 hours;
    uint8 public constant MIN_THRESHOLD = 2;
    uint8 public constant MAX_THRESHOLD = 9;
    uint8 public constant MIN_GUARDIANS = 3;
    uint8 public constant MAX_GUARDIANS = 15;

    bytes32 private constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    /// @notice V2 DIFF: Approve typehash gains `bytes32 recipientCommitment`.
    ///         The new typehash differs from V1's, so a V1-shape approval
    ///         cannot replay against a V2 attempt (cross-version replay
    ///         closed by typehash mismatch). Six fields bind the guardian's
    ///         signature to the SPECIFIC attempt:
    ///         - `vaultId`             (bytes32)
    ///         - `proposedAuthority`   (address; the attempt's target)
    ///         - `attemptNonce`        (uint64; per-attempt scope)
    ///         - `expiresAt`           (uint64; anti-stale)
    ///         - `recipientCommitment` (bytes32; anti-redirect, NEW in V2)
    ///         - `schemaVersion`       (uint16)
    bytes32 private constant APPROVE_TYPEHASH = keccak256(
        "Approve(bytes32 vaultId,address proposedAuthority,uint64 attemptNonce,uint64 expiresAt,bytes32 recipientCommitment,uint16 schemaVersion)"
    );

    // -----------------------------------------------------------------
    // Immutable state
    // -----------------------------------------------------------------

    /// @notice EIP-712 v4 domain separator. Domain name is **"Pangolin
    ///         Recovery"** (same as V1), version **"1"**. Each deployed
    ///         contract has a unique separator (its address is bound in),
    ///         so V1 + V2 deployed on the same chain still produce
    ///         distinct digests (separator + typehash both differ).
    bytes32 public immutable DOMAIN_SEPARATOR;

    // -----------------------------------------------------------------
    // Mutable storage
    // -----------------------------------------------------------------

    mapping(bytes32 vaultId => GuardianSet) public guardianSet;
    mapping(bytes32 vaultId => address) public vaultAuthority;
    mapping(bytes32 vaultId => Recovery) public recovery;
    mapping(bytes32 vaultId => mapping(uint64 attemptNonce => mapping(address guardian => bool)))
        public hasApproved;

    // -----------------------------------------------------------------
    // Constructor
    // -----------------------------------------------------------------

    constructor() {
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes("Pangolin Recovery")),
                keccak256(bytes("1")),
                block.chainid,
                address(this)
            )
        );
    }

    // -----------------------------------------------------------------
    // External API
    // -----------------------------------------------------------------

    /// @notice Establish the immutable guardian set + initial authority
    ///         for a vault. Verbatim from V1 (no commitment surface here).
    function setGuardianSet(
        bytes32 vaultId,
        bytes32 root,
        uint8 threshold,
        uint8 guardianCount,
        uint16 schemaVersion
    ) external {
        if (schemaVersion > MAX_KNOWN_SCHEMA_VERSION) {
            revert ErrUnsupportedSchemaVersion();
        }
        if (guardianSet[vaultId].initialized) {
            revert ErrGuardianSetAlreadyInitialized();
        }
        if (root == bytes32(0)) {
            revert ErrZeroValue();
        }
        if (guardianCount < MIN_GUARDIANS || guardianCount > MAX_GUARDIANS) {
            revert ErrGuardianCountOutOfBounds();
        }
        if (threshold < MIN_THRESHOLD || threshold > MAX_THRESHOLD || threshold > guardianCount) {
            revert ErrThresholdOutOfBounds();
        }

        guardianSet[vaultId] = GuardianSet({
            root: root,
            threshold: threshold,
            guardianCount: guardianCount,
            initialized: true
        });
        vaultAuthority[vaultId] = msg.sender;

        emit GuardianSetInitialized(
            vaultId, root, threshold, guardianCount, msg.sender, schemaVersion
        );
    }

    /// @notice Begin a recovery attempt: None/terminal -> PENDING.
    ///
    /// @dev V2 DIFF: gains `recipientCommitment` — the recovering user's
    ///      ephemeral X25519 pubkey for this attempt (32 bytes, must be
    ///      non-zero). Written to storage so the guardian's on-chain
    ///      Approve signature can bind it via `_hashApprove`.
    ///
    /// @param vaultId             Vault to recover.
    /// @param proposedAuthority   Address authority rotates to on finalize.
    /// @param recipientCommitment 32-byte X25519 pubkey of the recovering
    ///                            device for this attempt (NEW in V2).
    ///                            Rejected if zero.
    /// @param schemaVersion       Event-schema version. <= MAX_KNOWN.
    function initiateRecovery(
        bytes32 vaultId,
        address proposedAuthority,
        bytes32 recipientCommitment,
        uint16 schemaVersion
    ) external {
        if (schemaVersion > MAX_KNOWN_SCHEMA_VERSION) {
            revert ErrUnsupportedSchemaVersion();
        }
        if (!guardianSet[vaultId].initialized) {
            revert ErrGuardianSetNotInitialized();
        }
        if (proposedAuthority == address(0)) {
            revert ErrZeroValue();
        }
        // V2 DIFF: a zero commitment would defeat the anti-redirect
        // binding by accepting ANY recipient on the off-chain release
        // path. Reject so the guardian's signed digest always covers a
        // non-degenerate recipient.
        if (recipientCommitment == bytes32(0)) {
            revert ErrZeroValue();
        }

        Recovery storage rec = recovery[vaultId];
        if (rec.status == Status.Pending) {
            revert ErrRecoveryAlreadyPending();
        }

        uint64 newNonce;
        unchecked {
            newNonce = rec.attemptNonce + 1;
        }
        rec.proposedAuthority = proposedAuthority;
        rec.initiatedAt = uint64(block.timestamp);
        rec.attemptNonce = newNonce;
        rec.approvals = 0;
        rec.status = Status.Pending;
        rec.recipientCommitment = recipientCommitment;

        emit RecoveryInitiated(
            vaultId,
            newNonce,
            proposedAuthority,
            uint64(block.timestamp),
            recipientCommitment,
            schemaVersion
        );
    }

    /// @notice Record a guardian's approval of the current PENDING
    ///         attempt.
    ///
    /// @dev V2 DIFF: the EIP-712 digest now binds the stored
    ///      `recipientCommitment` (read from `rec.recipientCommitment`),
    ///      so a guardian's signature attests to BOTH the proposed
    ///      authority AND the on-chain-committed recipient. A V1-shape
    ///      signature can never validate (different typehash, different
    ///      field count). The function signature is unchanged from V1 —
    ///      the commitment travels via the digest, not calldata.
    function approveRecovery(
        bytes32 vaultId,
        address guardian,
        bytes32[] calldata proof,
        uint64 expiresAt,
        uint16 schemaVersion,
        bytes calldata signature
    ) external {
        if (schemaVersion > MAX_KNOWN_SCHEMA_VERSION) {
            revert ErrUnsupportedSchemaVersion();
        }

        Recovery storage rec = recovery[vaultId];

        if (rec.status != Status.Pending) {
            revert ErrNoActiveRecovery();
        }
        if (block.timestamp > expiresAt) {
            revert ErrApprovalExpired();
        }

        bytes32 leaf = keccak256(abi.encode(guardian));
        if (!_verifyMerkleProof(proof, guardianSet[vaultId].root, leaf)) {
            revert ErrInvalidMerkleProof();
        }

        // V2 DIFF: bind the stored recipientCommitment into the digest.
        bytes32 digest = _hashApprove(
            vaultId,
            rec.proposedAuthority,
            rec.attemptNonce,
            expiresAt,
            rec.recipientCommitment,
            schemaVersion
        );
        address signer = _recover(digest, signature);
        if (signer == address(0)) {
            revert ErrInvalidSignature();
        }
        if (signer != guardian) {
            revert ErrInvalidSignature();
        }

        if (hasApproved[vaultId][rec.attemptNonce][guardian]) {
            revert ErrDuplicateApproval();
        }

        hasApproved[vaultId][rec.attemptNonce][guardian] = true;
        unchecked {
            rec.approvals = rec.approvals + 1;
        }

        emit RecoveryApproved(vaultId, rec.attemptNonce, guardian, rec.approvals, schemaVersion);
    }

    /// @notice Cancel the current PENDING attempt: PENDING -> CANCELED.
    ///         Verbatim from V1 (authority-only; no commitment surface).
    function cancelRecovery(bytes32 vaultId, uint16 schemaVersion) external {
        if (schemaVersion > MAX_KNOWN_SCHEMA_VERSION) {
            revert ErrUnsupportedSchemaVersion();
        }

        Recovery storage rec = recovery[vaultId];

        if (rec.status != Status.Pending) {
            revert ErrNoActiveRecovery();
        }
        if (msg.sender != vaultAuthority[vaultId]) {
            revert ErrNotAuthorizedToCancel();
        }

        uint64 attemptNonce = rec.attemptNonce;
        rec.status = Status.Canceled;

        emit RecoveryCanceled(vaultId, attemptNonce, schemaVersion);
    }

    /// @notice Finalize the current PENDING attempt: PENDING ->
    ///         FINALIZED. Verbatim from V1 (no commitment surface).
    function finalizeRecovery(bytes32 vaultId, uint16 schemaVersion) external {
        if (schemaVersion > MAX_KNOWN_SCHEMA_VERSION) {
            revert ErrUnsupportedSchemaVersion();
        }

        Recovery storage rec = recovery[vaultId];

        if (rec.status != Status.Pending) {
            revert ErrNoActiveRecovery();
        }
        if (rec.approvals < guardianSet[vaultId].threshold) {
            revert ErrThresholdNotMet();
        }
        if (block.timestamp < uint256(rec.initiatedAt) + MIN_DELAY) {
            revert ErrDelayNotElapsed();
        }

        address oldAuthority = vaultAuthority[vaultId];
        address newAuthority = rec.proposedAuthority;
        uint64 attemptNonce = rec.attemptNonce;

        rec.status = Status.Finalized;
        vaultAuthority[vaultId] = newAuthority;

        emit RecoveryFinalized(vaultId, attemptNonce, oldAuthority, newAuthority, schemaVersion);
    }

    // -----------------------------------------------------------------
    // View functions / digest oracles
    // -----------------------------------------------------------------

    /// @notice Compute the EIP-712 v4 digest the contract verifies for an
    ///         `Approve` attestation.
    ///
    /// @dev V2 DIFF: gains `recipientCommitment` so off-chain guardians
    ///      can pre-compute the digest matching the on-chain-stored value
    ///      (the same value `initiateRecovery` wrote at attempt start).
    function hashApprove(
        bytes32 vaultId,
        address proposedAuthority,
        uint64 attemptNonce,
        uint64 expiresAt,
        bytes32 recipientCommitment,
        uint16 schemaVersion
    ) external view returns (bytes32) {
        return _hashApprove(
            vaultId, proposedAuthority, attemptNonce, expiresAt, recipientCommitment, schemaVersion
        );
    }

    /// @notice Forward-compatible Cancel digest oracle. Verbatim from V1
    ///         (cancel auth is msg.sender; this binds nothing per-V2-new).
    function hashCancel(bytes32 vaultId, uint64 attemptNonce, uint16 schemaVersion)
        external
        view
        returns (bytes32)
    {
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256("Cancel(bytes32 vaultId,uint64 attemptNonce,uint16 schemaVersion)"),
                vaultId,
                attemptNonce,
                schemaVersion
            )
        );
        return keccak256(abi.encodePacked(hex"1901", DOMAIN_SEPARATOR, structHash));
    }

    /// @notice Forward-compatible Initiate digest oracle.
    ///
    /// @dev V2 DIFF: gains `recipientCommitment` for completeness — a
    ///      future relayer-style initiation would attest to the
    ///      commitment alongside the proposed authority.
    function hashInitiate(
        bytes32 vaultId,
        address proposedAuthority,
        uint64 attemptNonce,
        bytes32 recipientCommitment,
        uint16 schemaVersion
    ) external view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256(
                    "Initiate(bytes32 vaultId,address proposedAuthority,uint64 attemptNonce,bytes32 recipientCommitment,uint16 schemaVersion)"
                ),
                vaultId,
                proposedAuthority,
                attemptNonce,
                recipientCommitment,
                schemaVersion
            )
        );
        return keccak256(abi.encodePacked(hex"1901", DOMAIN_SEPARATOR, structHash));
    }

    // -----------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------

    /// @dev V2 DIFF: typed-data struct hash now covers
    ///      `recipientCommitment`. Six abi-encoded fields under the new
    ///      `APPROVE_TYPEHASH`. The "\x19\x01 || domainSeparator ||
    ///      structHash" envelope is verbatim EIP-712 v4.
    function _hashApprove(
        bytes32 vaultId,
        address proposedAuthority,
        uint64 attemptNonce,
        uint64 expiresAt,
        bytes32 recipientCommitment,
        uint16 schemaVersion
    ) internal view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                APPROVE_TYPEHASH,
                vaultId,
                proposedAuthority,
                attemptNonce,
                expiresAt,
                recipientCommitment,
                schemaVersion
            )
        );
        return keccak256(abi.encodePacked(hex"1901", DOMAIN_SEPARATOR, structHash));
    }

    /// @dev Sorted-pair-keccak merkle verification. Verbatim from V1.
    function _verifyMerkleProof(bytes32[] calldata proof, bytes32 root, bytes32 leaf)
        internal
        pure
        returns (bool)
    {
        bytes32 computed = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 p = proof[i];
            if (computed <= p) {
                computed = keccak256(abi.encodePacked(computed, p));
            } else {
                computed = keccak256(abi.encodePacked(p, computed));
            }
        }
        return computed == root;
    }

    /// @dev Path B ecrecover (canonical v ∈ {27,28}, low-s, len-65,
    ///      reject signer == address(0)). Verbatim from V1.
    function _recover(bytes32 digest, bytes calldata signature) internal pure returns (address) {
        if (signature.length != 65) {
            return address(0);
        }
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly ("memory-safe") {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        if (v != 27 && v != 28) {
            return address(0);
        }
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            return address(0);
        }
        return ecrecover(digest, v, r, s);
    }

    // No receive() / fallback(). Non-payable; no selfdestruct /
    // delegatecall / external call anywhere.
}
