// SPDX-License-Identifier: AGPL-3.0-or-later
// @dev Exact-pinned pragma (NOT `^0.8.24`): per docs/issue-plans/2.1.md L3
//      + the v0 audit-fix L-3 lesson — the contract must build with the
//      exact compiler version it was audited against. A future
//      contributor MUST NOT relax this to a caret range.
pragma solidity 0.8.24;

/// @title RevisionLogV1
/// @notice Append-only log of encrypted vault revisions with on-chain
///         signature verification + a per-vault registered-device gate.
///         v1 augments v0's `publishRevision` with an `ecrecover`-based
///         EIP-712 signature check (R-a Path B) and a self-bootstrapping
///         per-vault device registry (R-b).
///
/// @dev Cardinal contract design rules (docs/issue-plans/2.1.md L2,
///      inherited from v0 verbatim — master plan §0 cardinal principles
///      3 + 4, Whitepaper §D1, master plan §2 locked decision):
///        - **No admin keys.** No owner. No role. No multisig.
///        - **No upgrades.** No proxy. No `selfdestruct`. Deploy v2 if v1
///          turns out to be broken.
///        - **No pause / freeze.** Liveness is monotonic.
///        - **No revocation in v1.** The device registry is write-only
///          additive; per-vault device removal lands on the recovery
///          contract in MVP-3 (issue 2.2 reused). See L9 + L10 + R-c.
///        - **Append-only mutable state**: the only mutating slots are
///          (a) the global `_nextSequence` counter and (b) the
///          `isRegisteredDevice` / `registeredDeviceCount` mappings,
///          both written exclusively from `publishRevision`'s success
///          path. There is no admin-keyed setter, zero-out, or reset.
///
/// @dev Cross-chain portability (docs/issue-plans/2.1.md L3 + R-e +
///      DECISIONS.md D-005):
///        - Compiled with `evm_version = "shanghai"` so the bytecode
///          runs unchanged on Base, Arbitrum, OP, Polygon, and Ethereum
///          mainnet at Shanghai-or-later. No Base-specific opcodes.
///        - `ecrecover` (precompile 0x01) has identical behaviour on
///          every EVM chain at every fork >= Frontier — the contract
///          is L1-viable, not L2-only.
///
/// @dev Relationship to v0:
///        - v0 (`RevisionLogV0`) is NOT modified by this issue (L1).
///          v0's deployed instances (D-014, D-015) stay where they are.
///        - v1 is a brand-new file at a fresh deployment address; the
///          two contracts coexist per master-plan §0 cardinal principle
///          4 + Whitepaper §D1 ("Versioned deployments allowed").
///        - v1's `RevisionPublished` event has a DIFFERENT topic-0 hash
///          than v0's (8 fields vs 6, plus the added `signer` field).
///          A v0-only client filtering by v0's topic-0 will NOT see v1
///          events — this is CORRECT behaviour per R-d.
contract RevisionLogV1 {
    // -----------------------------------------------------------------
    // Events
    // -----------------------------------------------------------------

    /// @notice Emitted on every successful `publishRevision` call.
    ///
    /// @dev Topic-0 differs from v0's `RevisionPublished` — see contract
    ///      docstring. Three indexed topics is Solidity's per-event
    ///      maximum (the event signature consumes the fourth topic).
    ///      We pick `sequence`, `vaultId`, and `accountId` as the
    ///      indexed dimensions because those are the filter axes
    ///      off-chain clients (the `pangolin-chain` adapter, the
    ///      indexer 4.2) need most:
    ///        - sequence: range queries / catch-up reads
    ///        - vaultId: "all revisions in this vault"
    ///        - accountId: "all revisions for this account"
    ///
    /// @dev `signer` is included as an unindexed event field (R-a
    ///      Implementation impact (5)) so off-chain clients can filter
    ///      by signer without re-running `ecrecover`. `schemaVersion`
    ///      is unindexed per L11.
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

    // -----------------------------------------------------------------
    // Errors (custom; Solidity 0.8.4+; gas-cheaper than string reverts)
    // -----------------------------------------------------------------

    /// @notice `ecrecover` returned `address(0)` — the signature did
    ///         not recover to any valid signer, OR the recovered
    ///         signer does not match the one this caller expected.
    ///         Per L6: revert path emits NO event, bumps NO sequence.
    error ErrInvalidSignature();

    /// @notice The recovered signer is not in `isRegisteredDevice` for
    ///         this `vaultId`, AND the vault already has at least one
    ///         registered device (so self-bootstrap does not apply).
    error ErrSignerNotRegistered();

    /// @notice `schemaVersion` exceeds `MAX_KNOWN_SCHEMA_VERSION`. The
    ///         contract refuses to record events under unknown future
    ///         schema versions; clients enforce the reciprocal
    ///         "reject reads with `schemaVersion > MAX_KNOWN_CLIENT`"
    ///         rule per THREAT_MODEL.md invariant #11 (§18.7 ladder).
    error ErrUnsupportedSchemaVersion();

    // -----------------------------------------------------------------
    // Constants
    // -----------------------------------------------------------------

    /// @notice Maximum supported event-schema version. Per R-d the
    ///         initial v1 events are tagged `schemaVersion = 1`, so
    ///         `MAX_KNOWN_SCHEMA_VERSION = 1`. A future v1.1 schema
    ///         requires deploying v2 (no in-place setter — that would
    ///         violate L2's "no admin" rule).
    uint16 public constant MAX_KNOWN_SCHEMA_VERSION = 1;

    /// @notice EIP-712 v4 domain typehash. The four-field domain
    ///         (`name`, `version`, `chainId`, `verifyingContract`) is
    ///         the canonical EIP-712 v4 layout and the one any standard
    ///         signer (hardware wallet, MetaMask, WalletConnect) speaks
    ///         natively.
    bytes32 private constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    /// @notice EIP-712 typehash for the `Revision` struct. Six fields,
    ///         matching the canonical-hash body in
    ///         `crates/pangolin-chain/src/signing.rs` byte-for-byte
    ///         (R-a Implementation impact (4)). The off-chain signer
    ///         hashes `encPayload` to 32 bytes BEFORE EIP-712 encoding
    ///         it as a `bytes32 encPayloadHash` field — same reduction
    ///         as `signing.rs`.
    bytes32 private constant REVISION_TYPEHASH = keccak256(
        "Revision(bytes32 vaultId,bytes32 accountId,bytes32 parentRevision,bytes32 deviceId,uint16 schemaVersion,bytes32 encPayloadHash)"
    );

    // -----------------------------------------------------------------
    // Immutable state
    // -----------------------------------------------------------------

    /// @notice EIP-712 domain separator, computed once at construction.
    ///         Binds the contract address + chain ID into every
    ///         signature, defeating cross-contract and cross-chain
    ///         replay.
    ///
    /// @dev Held as a private immutable so the slot cost is zero (the
    ///      compiler inlines the value into bytecode). The view
    ///      function `domainSeparator()` exposes it for off-chain
    ///      digest construction.
    bytes32 private immutable _DOMAIN_SEPARATOR;

    // -----------------------------------------------------------------
    // Mutable storage
    // -----------------------------------------------------------------

    /// @notice Monotonically increasing global sequence counter. The
    ///         pre-increment value is assigned to the publishing
    ///         revision and emitted as the indexed `sequence` topic.
    ///
    /// @dev Storage slot 0. Bumped only inside `publishRevision`'s
    ///      success path (L6: revert paths leave the counter
    ///      untouched).
    uint256 private _nextSequence;

    /// @notice Per-vault device-key registry. `signer` is the secp256k1
    ///         Ethereum address recovered from the EIP-712 signature
    ///         (R-a Path B). A `true` entry means "this address is
    ///         authorised to publish revisions for this vault".
    ///
    /// @dev Storage slot 1 base (mapping slots are address-hashed via
    ///      `keccak256(abi.encode(key, slotIndex))`). Mutated only on
    ///      `publishRevision`'s success path:
    ///        - if `registeredDeviceCount[vaultId] == 0` (self-bootstrap
    ///          per R-b), the recovered signer is registered;
    ///        - otherwise the recovered signer MUST already be true,
    ///          else revert with `ErrSignerNotRegistered()`.
    ///      v1 has NO removal path (L10 + R-c).
    mapping(bytes32 vaultId => mapping(address signer => bool)) public isRegisteredDevice;

    /// @notice Count of registered devices per vault. Used to drive
    ///         the self-bootstrap branch (R-b Implementation impact
    ///         (3)): `count == 0` means "no devices registered yet,
    ///         register the recovered signer"; `count > 0` means
    ///         "verify the recovered signer is already registered".
    ///
    /// @dev Storage slot 2 base. The width `uint32` is generous: a
    ///      vault is unlikely to have >4 billion devices in its
    ///      lifetime, and the narrower width nudges the compiler
    ///      toward tighter packing if v2 ever adds adjacent fields.
    mapping(bytes32 vaultId => uint32 count) public registeredDeviceCount;

    // -----------------------------------------------------------------
    // Constructor
    // -----------------------------------------------------------------

    /// @notice Compute the EIP-712 domain separator from the current
    ///         chain ID and contract address. The `name` and `version`
    ///         strings are fixed at construction.
    ///
    /// @dev Per L2: no constructor arguments. The contract has no
    ///      configurable surface; every parameter is hardcoded so
    ///      auditors can verify the deployment is the audited build.
    constructor() {
        _DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes("Pangolin RevisionLog")),
                keccak256(bytes("1")),
                block.chainid,
                address(this)
            )
        );
    }

    // -----------------------------------------------------------------
    // External API
    // -----------------------------------------------------------------

    /// @notice Publish a new signed encrypted revision to the log.
    ///
    /// @param vaultId         Application-defined vault identifier
    ///                        (32 bytes; opaque to the contract).
    /// @param accountId       Application-defined per-account
    ///                        identifier within `vaultId` (opaque).
    /// @param parentRevision  The revision id this one descends from
    ///                        (or `bytes32(0)` for a vault genesis).
    /// @param deviceId        Application-defined device identifier
    ///                        (opaque to the contract; the *signer*
    ///                        address recovered from `signature` is
    ///                        the gating identity, not `deviceId`).
    /// @param schemaVersion   Application-defined payload-schema tag.
    ///                        Must be `<= MAX_KNOWN_SCHEMA_VERSION`.
    /// @param encPayload      Opaque ciphertext + AEAD metadata. The
    ///                        contract performs no plaintext
    ///                        validation; `keccak256(encPayload)` is
    ///                        bound into the signed digest, so a
    ///                        tamper-after-signing will fail
    ///                        verification.
    /// @param signature       65-byte secp256k1 signature (r ‖ s ‖ v)
    ///                        over the EIP-712 v4 typed-data digest of
    ///                        the `Revision` struct. Per R-a
    ///                        Implementation impact (2).
    ///
    /// @return sequence       The global sequence number assigned to
    ///                        this revision. Equals `_nextSequence` at
    ///                        the time of the call (pre-increment).
    ///
    /// @dev v1 has no `payable` modifier: calls with `value > 0`
    ///      revert automatically. There is no `receive()` or
    ///      `fallback()`. This contract cannot accept ETH through
    ///      normal means.
    ///
    /// @dev `unchecked` increment matches v0; overflow at 2^256 calls
    ///      is not a real-world failure mode. Per L6 the bump is
    ///      AFTER every check — so a revert never burns a sequence
    ///      number.
    function publishRevision(
        bytes32 vaultId,
        bytes32 accountId,
        bytes32 parentRevision,
        bytes32 deviceId,
        uint16 schemaVersion,
        bytes calldata encPayload,
        bytes calldata signature
    ) external returns (uint256 sequence) {
        // 1. Reject unknown future schema versions (L5 / L11 / R-d).
        if (schemaVersion > MAX_KNOWN_SCHEMA_VERSION) {
            revert ErrUnsupportedSchemaVersion();
        }

        // 2. Recover signer + run the per-vault registry gate. Both
        //    are extracted into a helper so the local-variable count
        //    here stays inside Solidity 0.8.24's 16-slot stack budget.
        address signer = _verifyAndRegister(
            vaultId, accountId, parentRevision, deviceId, schemaVersion, encPayload, signature
        );

        // 3. Bump the sequence ONLY on success (L6).
        sequence = _nextSequence;
        unchecked {
            _nextSequence = sequence + 1;
        }

        // 4. Emit the revision event. `signer` is included so off-chain
        //    clients can filter by signer without re-running ecrecover.
        emit RevisionPublished(
            sequence,
            vaultId,
            accountId,
            parentRevision,
            deviceId,
            schemaVersion,
            encPayload,
            signer
        );
    }

    /// @dev Helper for `publishRevision`: builds the EIP-712 digest,
    ///      recovers the signer, then applies the R-b self-bootstrap
    ///      OR the registered-device gate. Pulled out of
    ///      `publishRevision` to keep the latter's local-variable
    ///      count inside the EVM's 16-slot stack budget under
    ///      `--via-ir = false`.
    function _verifyAndRegister(
        bytes32 vaultId,
        bytes32 accountId,
        bytes32 parentRevision,
        bytes32 deviceId,
        uint16 schemaVersion,
        bytes calldata encPayload,
        bytes calldata signature
    ) internal returns (address signer) {
        bytes32 digest = _hashRevision(
            vaultId, accountId, parentRevision, deviceId, schemaVersion, keccak256(encPayload)
        );
        signer = _recover(digest, signature);
        if (signer == address(0)) {
            revert ErrInvalidSignature();
        }
        if (registeredDeviceCount[vaultId] == 0) {
            isRegisteredDevice[vaultId][signer] = true;
            registeredDeviceCount[vaultId] = 1;
        } else if (!isRegisteredDevice[vaultId][signer]) {
            revert ErrSignerNotRegistered();
        }
    }

    // -----------------------------------------------------------------
    // View functions
    // -----------------------------------------------------------------

    /// @notice Current value of the monotonic sequence counter — i.e.,
    ///         the sequence the NEXT successful `publishRevision`
    ///         will assign.
    function nextSequence() external view returns (uint256) {
        return _nextSequence;
    }

    /// @notice EIP-712 domain separator. Exposed so off-chain tooling
    ///         can construct the same digest the contract verifies.
    function domainSeparator() external view returns (bytes32) {
        return _DOMAIN_SEPARATOR;
    }

    /// @notice Compute the EIP-712 v4 typed-data digest the contract
    ///         verifies for a given revision. Off-chain signers
    ///         compute the same digest and sign it under their
    ///         secp256k1 device key.
    ///
    /// @dev `encPayload` is the raw bytes; this function hashes it to
    ///      32 bytes before EIP-712-encoding, exactly as
    ///      `publishRevision` does.
    function hashRevision(
        bytes32 vaultId,
        bytes32 accountId,
        bytes32 parentRevision,
        bytes32 deviceId,
        uint16 schemaVersion,
        bytes calldata encPayload
    ) external view returns (bytes32) {
        return _hashRevision(
            vaultId, accountId, parentRevision, deviceId, schemaVersion, keccak256(encPayload)
        );
    }

    // -----------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------

    /// @dev EIP-712 v4 typed-data digest: `keccak256("\x19\x01" ||
    ///      domainSeparator || structHash)`. Standard layout; same
    ///      construction every EIP-712-aware tool produces.
    function _hashRevision(
        bytes32 vaultId,
        bytes32 accountId,
        bytes32 parentRevision,
        bytes32 deviceId,
        uint16 schemaVersion,
        bytes32 encPayloadHash
    ) internal view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                REVISION_TYPEHASH,
                vaultId,
                accountId,
                parentRevision,
                deviceId,
                schemaVersion,
                encPayloadHash
            )
        );
        return keccak256(abi.encodePacked(hex"1901", _DOMAIN_SEPARATOR, structHash));
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

    // No receive() / fallback() — same as v0. Non-payable means ETH
    // sends revert at the dispatcher's CALLVALUE guard.
}
