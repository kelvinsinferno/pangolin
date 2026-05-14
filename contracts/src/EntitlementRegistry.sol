// SPDX-License-Identifier: AGPL-3.0-or-later
// @dev Exact-pinned pragma (NOT `^0.8.24`): per docs/issue-plans/2.2.md L3
//      + the v0 audit-fix L-3 lesson — the contract must build with the
//      exact compiler version it was audited against. A future
//      contributor MUST NOT relax this to a caret range.
pragma solidity 0.8.24;

/// @title EntitlementRegistry
/// @notice Paid-balance ledger for Pangolin's funder service. Records
///         per-user paid credit balance + per-user replay nonce.
///         Credits are added via signed payment-proofs from the
///         `PAYMENT_AUTHORITY` key (off-chain Pangolin payment-processor);
///         redemptions are decremented via signed redemption-attestations
///         from the `REDEMPTION_AUTHORITY` key (off-chain Pangolin funder
///         service). MVP-2 issue 2.2.
///
/// @dev Cardinal contract design rules (docs/issue-plans/2.2.md L2,
///      inherited verbatim from 2.1's L2 + v0's cardinal-rules block —
///      master plan §0 cardinal principles 3 + 4, Whitepaper §D1,
///      master plan §2 locked decision):
///        - **No admin keys.** No owner. No role. No multisig.
///        - **No upgrades.** No proxy. No `selfdestruct`. Deploy v2 if v1
///          turns out to be broken.
///        - **No pause / freeze.** Liveness is monotonic.
///        - **No signer rotation.** The two signing authorities
///          (`PAYMENT_AUTHORITY`, `REDEMPTION_AUTHORITY`) are
///          constructor-immutable per L8 + R-d. A compromised key is
///          fixed by deploying a v2 contract with new authorities,
///          NOT by an in-place setter.
///        - **Append/decrement-only mutable state via the two typed
///          entry points.** The only mutating slots are
///          (a) `balance[userId]` — written exclusively from `credit`'s
///          and `redeem`'s success paths; (b) `nonce[userId]` — written
///          exclusively from the same two paths. There is no admin-keyed
///          setter, zero-out, or reset.
///
/// @dev Cross-chain portability (docs/issue-plans/2.2.md L3 +
///      DECISIONS.md D-005):
///        - Compiled with `evm_version = "shanghai"` so the bytecode
///          runs unchanged on Base, Arbitrum, OP, Polygon, and Ethereum
///          mainnet at Shanghai-or-later. No Base-specific opcodes.
///        - `ecrecover` (precompile 0x01) has identical behaviour on
///          every EVM chain at every fork >= Frontier — the contract
///          is L1-viable, not L2-only.
///        - Privacy-chain optionality (D-005) preserved: a future zk-
///          rollup target compiles this contract unchanged.
///
/// @dev Relationship to RevisionLogV0 / RevisionLogV1:
///        - Sibling, not a derived contract. The registry tracks money-
///          balance state; the revision log tracks revision-event state.
///          Two contracts, two authorities, one chain (D-008).
///        - Reuses the EIP-712 v4 typed-data discipline + `_recover`
///          helper from `RevisionLogV1.sol` verbatim (R-a Path B).
contract EntitlementRegistry {
    // -----------------------------------------------------------------
    // Events
    // -----------------------------------------------------------------

    /// @notice Emitted on every successful `credit` call.
    ///
    /// @dev `userId` is the only indexed topic (one of Solidity's 3 max
    ///      per-event topic slots; the event signature consumes a 4th).
    ///      `newBalance` is emitted unindexed so off-chain consumers
    ///      (the `pangolin-funder-client` Rust crate in issue 3.4, the
    ///      payment-processor service's reconciliation pipeline) don't
    ///      have to query state — same gas-pattern as v1 emitting
    ///      `signer`. `schemaVersion` unindexed per L10.
    event Credited(
        bytes32 indexed userId,
        uint256 amount,
        uint256 newBalance,
        uint64 nonce,
        uint16 schemaVersion
    );

    /// @notice Emitted on every successful `redeem` call.
    event Redeemed(
        bytes32 indexed userId,
        uint256 amount,
        uint256 newBalance,
        uint64 nonce,
        uint16 schemaVersion
    );

    // -----------------------------------------------------------------
    // Errors (custom; Solidity 0.8.4+; gas-cheaper than string reverts)
    // -----------------------------------------------------------------

    /// @notice `ecrecover` returned `address(0)` — the signature was
    ///         malformed or shape-degenerate (e.g. r=0,s=0).
    ///         Per L6: revert path emits NO event, bumps NO nonce,
    ///         touches NO balance.
    error ErrInvalidSignature();

    /// @notice The recovered signer is not the authority expected for
    ///         this call path. For `credit`, the authority is
    ///         `PAYMENT_AUTHORITY`. For `redeem`, the authority is
    ///         `REDEMPTION_AUTHORITY`. Per R-a: split-signer trust
    ///         model — a compromise of one key has a narrow blast
    ///         radius (inflate-only OR deflate-only, never both).
    error ErrUnauthorizedSigner();

    /// @notice Redemption amount exceeds the user's current balance.
    ///         Checked BEFORE state writes; no balance is ever burned
    ///         on a failed redemption.
    error ErrInsufficientBalance();

    /// @notice Attestation nonce does not equal the contract's
    ///         expected `nonce[userId]`. Per R-c: strict equality —
    ///         forces in-order submission; one signed attestation per
    ///         slot. The error name is "TooLow" for parity with
    ///         common ERC-20 / EIP-2612 naming, but the contract
    ///         enforces strict equality, so an attestationNonce
    ///         GREATER than the expected nonce also triggers this
    ///         error.
    error ErrNonceTooLow();

    /// @notice `schemaVersion` exceeds `MAX_KNOWN_SCHEMA_VERSION`. The
    ///         contract refuses to record events under unknown future
    ///         schema versions; clients enforce the reciprocal
    ///         "reject reads with `schemaVersion > MAX_KNOWN_CLIENT`"
    ///         rule per THREAT_MODEL.md invariant #11 (§18.7 ladder).
    error ErrUnsupportedSchemaVersion();

    /// @notice Attestation `expiresAt` is strictly less than the
    ///         current block timestamp. Per R-e: anti-stale-signature
    ///         defence-in-depth (the nonce ratchet handles in-flight
    ///         replay; `expiresAt` handles long-term-leak replay).
    error ErrAttestationExpired();

    /// @notice Constructor was passed `address(0)` for one of the
    ///         signer authorities. Fails the deploy fast so no
    ///         contract instance with a missing authority ever lands.
    error ErrZeroAuthority();

    // -----------------------------------------------------------------
    // Constants
    // -----------------------------------------------------------------

    /// @notice Maximum supported event-schema version. Per L10: the
    ///         initial v1 events are tagged `schemaVersion = 1`, so
    ///         `MAX_KNOWN_SCHEMA_VERSION = 1`. A future v1.1 schema
    ///         requires deploying v2 (no in-place setter — that would
    ///         violate L2's "no admin" rule).
    uint16 public constant MAX_KNOWN_SCHEMA_VERSION = 1;

    /// @notice EIP-712 v4 domain typehash. The four-field domain
    ///         (`name`, `version`, `chainId`, `verifyingContract`) is
    ///         the canonical EIP-712 v4 layout — every standard signer
    ///         (hardware wallet, MetaMask, WalletConnect) speaks this
    ///         natively.
    bytes32 private constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    /// @notice EIP-712 typehash for the `Credit` struct. Five fields,
    ///         per R-a + R-b + R-e:
    ///         - `userId` (bytes32, opaque per R-b)
    ///         - `amount` (uint256)
    ///         - `nonce` (uint64; the attestation's nonce field)
    ///         - `schemaVersion` (uint16)
    ///         - `expiresAt` (uint64; anti-stale-signature per R-e)
    bytes32 private constant CREDIT_TYPEHASH = keccak256(
        "Credit(bytes32 userId,uint256 amount,uint64 nonce,uint16 schemaVersion,uint64 expiresAt)"
    );

    /// @notice EIP-712 typehash for the `Redemption` struct. Same
    ///         shape as Credit but distinct typehash — a signed
    ///         Credit cannot be submitted as a Redemption (different
    ///         typehash bytes → different struct hash → different
    ///         digest → ecrecover yields a pseudo-random address →
    ///         not equal to either authority → `ErrUnauthorizedSigner`).
    bytes32 private constant REDEMPTION_TYPEHASH = keccak256(
        "Redemption(bytes32 userId,uint256 amount,uint64 nonce,uint16 schemaVersion,uint64 expiresAt)"
    );

    // -----------------------------------------------------------------
    // Immutable state (set at deploy time; cannot change)
    // -----------------------------------------------------------------

    /// @notice The single address authorized to sign `Credit`
    ///         attestations. Set in the constructor; CANNOT be changed.
    ///         Compromised key → deploy v2 (R-d).
    address public immutable PAYMENT_AUTHORITY;

    /// @notice The single address authorized to sign `Redemption`
    ///         attestations. Set in the constructor; CANNOT be changed.
    ///         Per R-a (split-signer trust model), distinct from
    ///         `PAYMENT_AUTHORITY`. Compromised key → deploy v2.
    address public immutable REDEMPTION_AUTHORITY;

    /// @notice EIP-712 v4 domain separator, computed once at
    ///         construction. Binds the contract address + chain ID
    ///         into every signature, defeating cross-contract and
    ///         cross-chain replay.
    bytes32 public immutable DOMAIN_SEPARATOR;

    // -----------------------------------------------------------------
    // Mutable storage
    // -----------------------------------------------------------------

    /// @notice Per-user paid credit balance. Unit is abstract "credits";
    ///         the off-chain funder service maps credits → revisions
    ///         per the pricing spec (5,000 credits per $30 today;
    ///         future repricing doesn't touch the contract).
    ///
    /// @dev Storage slot 0 base. Mapping slots are address-hashed via
    ///      `keccak256(abi.encode(userId, 0))`. Mutated only on
    ///      `credit` and `redeem` success paths.
    mapping(bytes32 userId => uint256) public balance;

    /// @notice Per-user monotonic nonce. Increments by exactly 1 on
    ///         every successful `credit` OR `redeem`. Replay-protection
    ///         primitive: each signed attestation embeds the nonce the
    ///         contract requires; on success, the contract advances the
    ///         counter by 1. Per R-c: strict equality enforcement.
    ///
    /// @dev Storage slot 1 base. uint64 wide — 2^64 transactions per
    ///      user is implausible (well past hardware-lifetime of any
    ///      device).
    mapping(bytes32 userId => uint64) public nonce;

    // -----------------------------------------------------------------
    // Constructor
    // -----------------------------------------------------------------

    /// @notice Deploy with two distinct signer authorities. Both must
    ///         be non-zero. Per R-a + L8.
    /// @param paymentAuthority_ Address that signs `Credit` attestations.
    /// @param redemptionAuthority_ Address that signs `Redemption`
    ///                              attestations.
    constructor(address paymentAuthority_, address redemptionAuthority_) {
        if (paymentAuthority_ == address(0)) revert ErrZeroAuthority();
        if (redemptionAuthority_ == address(0)) revert ErrZeroAuthority();
        PAYMENT_AUTHORITY = paymentAuthority_;
        REDEMPTION_AUTHORITY = redemptionAuthority_;
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes("Pangolin EntitlementRegistry")),
                keccak256(bytes("1")),
                block.chainid,
                address(this)
            )
        );
    }

    // -----------------------------------------------------------------
    // External entry points
    // -----------------------------------------------------------------

    /// @notice Credit a user's balance, gated by a `PAYMENT_AUTHORITY`-
    ///         signed EIP-712 Credit attestation.
    ///
    /// @param userId           Opaque user identifier (per R-b).
    /// @param amount           Credits to add. uint256.
    /// @param attestationNonce Nonce embedded in the signed attestation.
    ///                         Must equal the contract's current
    ///                         `nonce[userId]` exactly (per R-c).
    /// @param schemaVersion    Event-schema version. Must be
    ///                         `<= MAX_KNOWN_SCHEMA_VERSION`.
    /// @param expiresAt        Unix timestamp after which the signature
    ///                         is rejected (per R-e). Anti-stale-
    ///                         signature defence-in-depth.
    /// @param signature        65-byte secp256k1 signature (r ‖ s ‖ v)
    ///                         over the EIP-712 v4 typed-data digest of
    ///                         the `Credit` struct.
    /// @return newBalance      The user's new balance after the credit.
    ///
    /// @dev Order of checks (revert BEFORE any state change):
    ///        1. schemaVersion bound
    ///        2. expiry
    ///        3. signature recover (`address(0)` → invalid)
    ///        4. authority match
    ///        5. nonce strict equality
    ///      All checks pass → state writes: nonce bump (unchecked;
    ///      uint64 overflow infeasible), balance add (CHECKED; uint256
    ///      overflow is finite-but-large — default checked arithmetic
    ///      protects), event emit.
    ///
    /// @dev Non-`payable`: ETH sends revert at the dispatcher.
    function credit(
        bytes32 userId,
        uint256 amount,
        uint64 attestationNonce,
        uint16 schemaVersion,
        uint64 expiresAt,
        bytes calldata signature
    ) external returns (uint256 newBalance) {
        // 1. Reject unknown future schema versions (L10).
        if (schemaVersion > MAX_KNOWN_SCHEMA_VERSION) {
            revert ErrUnsupportedSchemaVersion();
        }

        // 2. Anti-stale-signature expiry check (R-e). A non-expired
        //    attestation requires `block.timestamp <= expiresAt`.
        if (block.timestamp > expiresAt) {
            revert ErrAttestationExpired();
        }

        // 3. EIP-712 digest + signature recover.
        bytes32 digest = _hashCredit(userId, amount, attestationNonce, schemaVersion, expiresAt);
        address signer = _recover(digest, signature);
        if (signer == address(0)) {
            revert ErrInvalidSignature();
        }

        // 4. Authority match (R-a split-signer model).
        if (signer != PAYMENT_AUTHORITY) {
            revert ErrUnauthorizedSigner();
        }

        // 5. Strict-equality nonce check (R-c).
        if (attestationNonce != nonce[userId]) {
            revert ErrNonceTooLow();
        }

        // 6. State change. Nonce bump uses `unchecked` because uint64
        //    overflow at 2^64 calls is infeasible. Balance add uses
        //    DEFAULT checked arithmetic — uint256 overflow is finite-
        //    but-large; cheap belt-and-braces.
        unchecked {
            nonce[userId] = attestationNonce + 1;
        }
        newBalance = balance[userId] + amount;
        balance[userId] = newBalance;
        emit Credited(userId, amount, newBalance, attestationNonce, schemaVersion);
    }

    /// @notice Decrement a user's balance, gated by a
    ///         `REDEMPTION_AUTHORITY`-signed EIP-712 Redemption
    ///         attestation. Per R-c funder-push direction: the
    ///         message reads as "I (funder) just dispensed X credits'
    ///         worth of gas to user U — please decrement their
    ///         balance".
    ///
    /// @param userId           Opaque user identifier (per R-b).
    /// @param amount           Credits to decrement. uint256.
    /// @param attestationNonce Nonce embedded in the signed attestation.
    /// @param schemaVersion    Event-schema version. Must be
    ///                         `<= MAX_KNOWN_SCHEMA_VERSION`.
    /// @param expiresAt        Unix timestamp after which the signature
    ///                         is rejected (per R-e).
    /// @param signature        65-byte secp256k1 signature (r ‖ s ‖ v)
    ///                         over the EIP-712 v4 typed-data digest of
    ///                         the `Redemption` struct.
    /// @return newBalance      The user's new balance after the
    ///                         redemption.
    ///
    /// @dev Order of checks mirrors `credit` plus an extra balance
    ///      sufficiency check (`balance[userId] >= amount`) BEFORE
    ///      state writes. The balance subtraction uses DEFAULT checked
    ///      arithmetic (NOT `unchecked`) as belt-and-braces — the
    ///      explicit pre-check already excludes underflow, but if a
    ///      future refactor drops the explicit check the default
    ///      arithmetic catches it.
    function redeem(
        bytes32 userId,
        uint256 amount,
        uint64 attestationNonce,
        uint16 schemaVersion,
        uint64 expiresAt,
        bytes calldata signature
    ) external returns (uint256 newBalance) {
        // 1. Reject unknown future schema versions.
        if (schemaVersion > MAX_KNOWN_SCHEMA_VERSION) {
            revert ErrUnsupportedSchemaVersion();
        }

        // 2. Expiry check.
        if (block.timestamp > expiresAt) {
            revert ErrAttestationExpired();
        }

        // 3. EIP-712 digest + signature recover.
        bytes32 digest = _hashRedemption(userId, amount, attestationNonce, schemaVersion, expiresAt);
        address signer = _recover(digest, signature);
        if (signer == address(0)) {
            revert ErrInvalidSignature();
        }

        // 4. Authority match (R-a split-signer).
        if (signer != REDEMPTION_AUTHORITY) {
            revert ErrUnauthorizedSigner();
        }

        // 5. Strict-equality nonce check.
        if (attestationNonce != nonce[userId]) {
            revert ErrNonceTooLow();
        }

        // 6. Balance sufficiency (BEFORE state writes; no burn on fail).
        uint256 oldBalance = balance[userId];
        if (oldBalance < amount) {
            revert ErrInsufficientBalance();
        }

        // 7. State change. Nonce bump `unchecked` (2^64 infeasible).
        //    Balance sub uses DEFAULT checked arithmetic for belt-and-
        //    braces against a future refactor dropping the explicit
        //    pre-check above.
        unchecked {
            nonce[userId] = attestationNonce + 1;
        }
        newBalance = oldBalance - amount;
        balance[userId] = newBalance;
        emit Redeemed(userId, amount, newBalance, attestationNonce, schemaVersion);
    }

    // -----------------------------------------------------------------
    // View helpers (off-chain digest oracle for the signing services)
    // -----------------------------------------------------------------

    /// @notice Compute the EIP-712 v4 typed-data digest the contract
    ///         verifies for a given `Credit` attestation. Off-chain
    ///         signers (the payment processor) compute the same digest
    ///         and sign it under their secp256k1 key.
    function hashCredit(
        bytes32 userId,
        uint256 amount,
        uint64 attestationNonce,
        uint16 schemaVersion,
        uint64 expiresAt
    ) external view returns (bytes32) {
        return _hashCredit(userId, amount, attestationNonce, schemaVersion, expiresAt);
    }

    /// @notice Compute the EIP-712 v4 typed-data digest the contract
    ///         verifies for a given `Redemption` attestation. Off-chain
    ///         signers (the funder service) compute the same digest and
    ///         sign it under their secp256k1 key.
    function hashRedemption(
        bytes32 userId,
        uint256 amount,
        uint64 attestationNonce,
        uint16 schemaVersion,
        uint64 expiresAt
    ) external view returns (bytes32) {
        return _hashRedemption(userId, amount, attestationNonce, schemaVersion, expiresAt);
    }

    // -----------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------

    /// @dev EIP-712 v4 typed-data digest for a `Credit` struct:
    ///      `keccak256("\x19\x01" || domainSeparator || structHash)`.
    function _hashCredit(
        bytes32 userId,
        uint256 amount,
        uint64 attestationNonce,
        uint16 schemaVersion,
        uint64 expiresAt
    ) internal view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(CREDIT_TYPEHASH, userId, amount, attestationNonce, schemaVersion, expiresAt)
        );
        return keccak256(abi.encodePacked(hex"1901", DOMAIN_SEPARATOR, structHash));
    }

    /// @dev EIP-712 v4 typed-data digest for a `Redemption` struct.
    function _hashRedemption(
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
        return keccak256(abi.encodePacked(hex"1901", DOMAIN_SEPARATOR, structHash));
    }

    /// @dev Recover a secp256k1 signer from a 65-byte `r ‖ s ‖ v`
    ///      signature over `digest`. Returns `address(0)` on any
    ///      failure path (malformed length, malformed `v`, the
    ///      `ecrecover` precompile's own sentinel for invalid sigs).
    ///
    ///      We accept `v` values of 27 or 28 only — the canonical
    ///      Ethereum signature encoding. EIP-155 chain-id-embedded
    ///      `v` values are NOT accepted because EIP-712 typed-data
    ///      signatures use the bare `v` (the chain id is bound into
    ///      the domain separator already). This matches what every
    ///      EIP-712 signer produces.
    ///
    ///      Copied verbatim from `RevisionLogV1.sol::_recover`
    ///      (docs/issue-plans/2.2.md L4 — same Path B ecrecover
    ///      malleability discipline).
    function _recover(bytes32 digest, bytes calldata signature) internal pure returns (address) {
        if (signature.length != 65) {
            return address(0);
        }
        bytes32 r;
        bytes32 s;
        uint8 v;
        // Calldata layout: [r (32)] [s (32)] [v (1)]. Read each piece
        // out by offset.
        assembly ("memory-safe") {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            // `v` is a single byte at offset 64; calldataload returns
            // 32 bytes, so we shr by 31*8 = 248 to take the high byte.
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        if (v != 27 && v != 28) {
            return address(0);
        }
        // EIP-2 / EIP-2098 low-s discipline: reject "high-s"
        // signatures so the signature is not malleable. Without this
        // a third party could flip s -> n-s and v -> v^1 to produce a
        // second-valid-signature for the same (digest, signer) — not
        // a verification break, but a bytewise non-uniqueness an
        // off-chain indexer would have to handle. Cheap to add now.
        //
        // secp256k1 curve order n (half):
        //   0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            return address(0);
        }
        return ecrecover(digest, v, r, s);
    }

    // No receive() / fallback() — same as v0/v1. Non-payable means ETH
    // sends revert at the dispatcher's CALLVALUE guard.
}
