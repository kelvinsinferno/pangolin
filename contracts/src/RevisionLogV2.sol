// SPDX-License-Identifier: AGPL-3.0-or-later
// @dev Exact-pinned pragma (NOT `^0.8.24`): per docs/issue-plans/106a-revisionlogv2-contract.md
//      L3 + the v0 audit-fix L-3 lesson — the contract must build with the
//      exact compiler version it was audited against. A future contributor
//      MUST NOT relax this to a caret range. RevisionLogV2 is
//      external-audit-gated before mainnet (D-011); the exact pin is what
//      the auditor signs off on.
pragma solidity 0.8.24;

/// @notice Minimal cross-read view RevisionLogV2 staticcalls on RecoveryV1.
///         Pinned to the immutable RECOVERY_V1 address; the only
///         cross-contract surface in this contract (Q-h / L15). A
///         `staticcall` cannot mutate state, so it adds zero reentrancy
///         surface.
interface IRecoveryV1 {
    /// @notice The current on-chain authority for a vault. `address(0)`
    ///         means "no recovery authority established for this vault".
    function vaultAuthority(bytes32 vaultId) external view returns (address);
}

/// @title RevisionLogV2
/// @notice Append-only log of encrypted vault revisions with on-chain
///         signature verification + a per-vault **authorized-device SET**
///         (the multi-device honor rule), a single per-vault
///         `deviceManager` (the primary), manager-signed device add/remove,
///         and a delayed + vetoable survivor-promotion path.
///
///         v2 supersedes RevisionLogV1's single self-bootstrap gate
///         (`registeredDeviceCount == 0` -> register, else
///         `ErrSignerNotRegistered`) with a live authorized SET established
///         by an explicit `bootstrapVault` genesis and governed thereafter
///         by the device manager. The EIP-712 `Revision` signing
///         (`_hashRevision`/`_recover`), the `publishRevision` shape, the
///         global sequence counter, the custom-error/`schemaVersion`
///         discipline, and ALL cardinal rules are reused from V1 verbatim,
///         retargeted to a new EIP-712 domain (`version = "2"`).
///
/// @dev CARDINAL CONTRACT DESIGN RULES (docs/issue-plans/106a-revisionlogv2-contract.md
///      L2, inherited VERBATIM from v0/v1/RecoveryV1 — master plan §0
///      cardinal principles 3 + 4, Whitepaper §D1):
///        - **No admin keys.** No owner. No role. No multisig. No
///          `setManager` / `forceAddDevice` / `forceRemoveDevice` /
///          `adminPromote` / `pause`. add/remove/promote are
///          SELF-SOVEREIGN authority-gated mutations (the vault's own
///          authority signs them), NOT admin paths — there is no
///          privileged deployer/owner anywhere.
///        - **No upgrades.** No proxy. No `selfdestruct`. No
///          `delegatecall`. A bug is fixed by deploying RevisionLogV3 and
///          new-vault opt-in, NEVER by patching v2 (D-011 / Q-g).
///        - **No pause / freeze.** Liveness is monotonic; the only time
///          gate is the mandatory `PROMOTION_DELAY`, which no party can
///          skip or shorten.
///        - **No external calls except a read-only `staticcall`.** The
///          contract makes ZERO `call` / `transfer` / `send` /
///          `delegatecall`. The single cross-contract surface is a
///          `staticcall` to `RECOVERY_V1.vaultAuthority` (Q-h / L15) — a
///          read; it cannot mutate state and has zero reentrancy surface.
///        - **Never touches the VDK or any secret (L12).** The contract
///          stores addresses + flags + counters + timestamps ONLY. No
///          `bytes` key blob, no ciphertext, no share. There is no slot a
///          VDK could live in.
///        - **State writes AFTER all revertable checks (L6).** Every
///          mutating entry point validates fully before touching storage;
///          a revert burns no nonce, mutates no set, emits no event.
///        - **Custom errors, revert-on-failure, no event on failure.**
///
/// @dev Cross-chain portability (L3 + DECISIONS.md D-005):
///        - Compiled with `evm_version = "shanghai"` so the bytecode runs
///          unchanged on Base, Arbitrum, OP, Polygon, and Ethereum mainnet
///          at Shanghai-or-later. No Base-specific opcodes.
///        - `ecrecover` (precompile 0x01) has identical behaviour on every
///          EVM chain at every fork >= Frontier — L1-viable.
///
/// @dev Authority model (Q-a Option B): RevisionLogV2 owns its OWN
///      per-vault `deviceManager` (the primary). It is seeded at genesis
///      from `RecoveryV1.vaultAuthority(vaultId)` if set, else from the
///      first authorized signer; and the manager-auth check LIVE-READS
///      `RecoveryV1.vaultAuthority` (Q-k) so a guardian recovery that
///      rotated the authority re-aligns the manager with zero drift. The
///      *honor* rule stays on the SET (not on either authority), so a
///      manager-vs-authority disagreement can never silently honor a wrong
///      signer (L8).
contract RevisionLogV2 {
    // -----------------------------------------------------------------
    // Types
    // -----------------------------------------------------------------

    /// @notice A pending survivor-promotion of `candidate` to manager
    ///         (Q-c). `readyAt == 0` means "no promotion pending".
    ///
    /// @dev Packs into a single 32-byte slot: `candidate` (20 bytes) +
    ///      `readyAt` (8 bytes) = 28 bytes. `readyAt` is `uint64` (seconds;
    ///      good past year 584942417355) per L7.
    struct Promotion {
        address candidate;
        uint64 readyAt;
    }

    // -----------------------------------------------------------------
    // Events (every event carries a uint16 schemaVersion — L5)
    // -----------------------------------------------------------------

    /// @notice Emitted on every successful `publishRevision` call. Verbatim
    ///         field shape from RevisionLogV1 (the new EIP-712 domain gives
    ///         it a different topic-0, which is correct: a v1 client must
    ///         not consume v2 events and vice-versa).
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

    /// @notice Emitted when a vault's authorized SET + manager are
    ///         established for the first time (`bootstrapVault`).
    event VaultBootstrapped(
        bytes32 indexed vaultId, address firstSigner, address manager, uint16 schemaVersion
    );

    /// @notice Emitted when the manager adds `signer` to the authorized
    ///         SET. `manager` is the recovered EIP-712 signer that
    ///         authorized the add (NOT msg.sender). `nonce` is the
    ///         per-vault `deviceNonce` value bound into the signature.
    event DeviceAdded(
        bytes32 indexed vaultId, address signer, address manager, uint64 nonce, uint16 schemaVersion
    );

    /// @notice Emitted when the manager removes `signer` from the SET.
    event DeviceRemoved(
        bytes32 indexed vaultId, address signer, address manager, uint64 nonce, uint16 schemaVersion
    );

    /// @notice Emitted when a current set member proposes itself for
    ///         promotion. THE client's "notify your other devices" trigger
    ///         (locked-arch requirement). `readyAt` is the earliest time
    ///         `finalizePromotion` can succeed.
    event PromotionProposed(
        bytes32 indexed vaultId, address candidate, uint64 readyAt, uint16 schemaVersion
    );

    /// @notice Emitted when a promotion finalizes; `deviceManager` rotated
    ///         from `oldManager` to `newManager`.
    event PromotionFinalized(
        bytes32 indexed vaultId, address oldManager, address newManager, uint16 schemaVersion
    );

    /// @notice Emitted when the current manager vetoes a pending promotion
    ///         within the delay window.
    event PromotionCanceled(bytes32 indexed vaultId, address candidate, uint16 schemaVersion);

    // -----------------------------------------------------------------
    // Errors (custom; Solidity 0.8.4+; gas-cheaper than string reverts)
    // -----------------------------------------------------------------

    /// @notice `ecrecover` returned `address(0)` — the signature was
    ///         malformed or shape-degenerate (bad length, bad v, high-s,
    ///         r=0/s=0). Per L6: revert path emits NO event, mutates NO
    ///         state. Reused verbatim from V1.
    error ErrInvalidSignature();

    /// @notice `publishRevision` recovered a signer that is NOT in the
    ///         vault's authorized SET (L8 honor gate). A former manager,
    ///         never-added device, or removed device hits this.
    error ErrSignerNotAuthorized();

    /// @notice An add/remove/cancel was authorized by a signature that did
    ///         NOT recover to the current device manager (L9). The current
    ///         manager is reconciled with `RecoveryV1.vaultAuthority` via a
    ///         live staticcall (Q-k).
    error ErrNotDeviceManager();

    /// @notice `addDevice` target is already in the SET.
    error ErrAlreadyAuthorized();

    /// @notice `removeDevice` target is not in the SET.
    error ErrNotAuthorized();

    /// @notice `bootstrapVault` called a second time for a vault. The SET
    ///         is established once at genesis (Q-f); after that the manager
    ///         governs membership.
    error ErrVaultAlreadyBootstrapped();

    /// @notice An operation referenced a vault with no SET established.
    ///         `publishRevision` / `addDevice` / `removeDevice` /
    ///         promotion all require a bootstrapped vault (Q-f: prevents a
    ///         publish racing an unbootstrapped vault).
    error ErrVaultNotBootstrapped();

    /// @notice `removeDevice` would drop the SET below 1 device OR remove
    ///         the current manager (L10 no-brick). The contract is
    ///         immutable; a brick is unrecoverable.
    error ErrWouldBrickVault();

    /// @notice A promotion candidate is not a current member of the
    ///         authorized SET (L11: a non-device cannot promote itself).
    error ErrNotSetMember();

    /// @notice `proposePromotion` while a promotion is already pending.
    error ErrPromotionPending();

    /// @notice `finalizePromotion` / `cancelPromotion` with no pending
    ///         promotion.
    error ErrNoPromotionPending();

    /// @notice `finalizePromotion` before `block.timestamp >= readyAt`
    ///         (L11). The mandatory delay is not skippable by any party.
    error ErrPromotionDelayNotElapsed();

    /// @notice `cancelPromotion` by anyone other than the current manager
    ///         (the veto is manager-only).
    error ErrNotAuthorizedToCancel();

    /// @notice An add/remove/promote signature carried a `nonce` that does
    ///         not equal the current per-vault `deviceNonce` (anti-replay,
    ///         Q-d). The nonce strictly increments on each successful
    ///         set-mutation.
    error ErrBadNonce();

    /// @notice `addDevice` would push the SET above `MAX_DEVICES` (Q-i
    ///         bound — caps the off-chain set-fold DoS surface).
    error ErrSetSizeExceeded();

    /// @notice `schemaVersion` exceeds `MAX_KNOWN_SCHEMA_VERSION` (L5;
    ///         §18.7 ladder).
    error ErrUnsupportedSchemaVersion();

    /// @notice A load-bearing field was `address(0)` (first signer / new
    ///         device / promotion candidate). Fails fast so no degenerate
    ///         vault ever lands.
    error ErrZeroValue();

    // -----------------------------------------------------------------
    // Constants
    // -----------------------------------------------------------------

    /// @notice Maximum supported event-schema version (L5). Initial v2
    ///         events are tagged `schemaVersion = 1`. A future v2.1 schema
    ///         requires deploying v3 (no in-place setter — L2 no-admin).
    uint16 public constant MAX_KNOWN_SCHEMA_VERSION = 1;

    /// @notice Maximum authorized-device set size per vault (Q-i / L16).
    ///         Bounds the off-chain set-fold + any future on-chain
    ///         enumeration against unbounded griefing.
    uint32 public constant MAX_DEVICES = 32;

    /// @notice Mandatory survivor-promotion delay (Q-c / L11). FIXED; NOT
    ///         per-vault-configurable. Shorter than RecoveryV1's 72h
    ///         guardian-recovery delay because promotion ALSO requires the
    ///         promoting device's own biometric (client-side, #106c) — a
    ///         surviving device is a stronger signal than a guardian
    ///         quorum, but the window is long enough for a heads-up so the
    ///         current manager can veto a hostile promotion.
    uint64 public constant PROMOTION_DELAY = 48 hours;

    /// @notice EIP-712 v4 domain typehash (canonical four-field layout).
    bytes32 private constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    /// @notice EIP-712 typehash for the `Revision` struct. Identical body
    ///         to RevisionLogV1 (the client's `pangolin-chain` signer
    ///         produces the same struct hash); only the domain separator
    ///         differs (version "2"), so a v1 signature can never replay
    ///         against v2 and vice-versa.
    bytes32 private constant REVISION_TYPEHASH = keccak256(
        "Revision(bytes32 vaultId,bytes32 accountId,bytes32 parentRevision,bytes32 deviceId,uint16 schemaVersion,bytes32 encPayloadHash)"
    );

    /// @notice EIP-712 typehash for an `AddDevice` authorization (Q-d). The
    ///         manager signs this; the recovered signer must be the current
    ///         manager. `nonce` binds the signature to one action.
    bytes32 private constant ADD_DEVICE_TYPEHASH =
        keccak256("AddDevice(bytes32 vaultId,address newSigner,uint64 nonce,uint16 schemaVersion)");

    /// @notice EIP-712 typehash for a `RemoveDevice` authorization (Q-d).
    bytes32 private constant REMOVE_DEVICE_TYPEHASH =
        keccak256("RemoveDevice(bytes32 vaultId,address signer,uint64 nonce,uint16 schemaVersion)");

    /// @notice EIP-712 typehash for a `Promote` proposal (Q-c/Q-d). The
    ///         candidate (a current set member) signs this to propose
    ///         itself.
    bytes32 private constant PROMOTE_TYPEHASH =
        keccak256("Promote(bytes32 vaultId,address candidate,uint64 nonce,uint16 schemaVersion)");

    // -----------------------------------------------------------------
    // Immutable state (set at deploy time; cannot change)
    // -----------------------------------------------------------------

    /// @notice EIP-712 v4 domain separator, computed once at construction.
    ///         Binds the contract address + chain ID + version "2" into
    ///         every signature, defeating cross-contract, cross-chain, and
    ///         cross-version (v1<->v2) replay (Q-j / L4).
    bytes32 public immutable DOMAIN_SEPARATOR;

    /// @notice Pinned RecoveryV1 address (the ONE configurable field,
    ///         justified by the cross-bind, Q-h / L15). The manager-auth
    ///         check live-reads `vaultAuthority` here via staticcall.
    address public immutable RECOVERY_V1;

    // -----------------------------------------------------------------
    // Mutable storage
    //
    // Slot layout (L7):
    //   slot 0: _nextSequence       uint256
    //   slot 1: authorizedDevice    mapping(bytes32 => mapping(address => bool))
    //   slot 2: authorizedDeviceCount mapping(bytes32 => uint32)
    //   slot 3: deviceManager       mapping(bytes32 => address)
    //   slot 4: deviceNonce         mapping(bytes32 => uint64)
    //   slot 5: pendingPromotion    mapping(bytes32 => Promotion)
    //   slot 6: _bootstrapped       mapping(bytes32 => bool)
    // Mapping base slots store no value; data lives at keccak-hashed
    // addresses. The only mutating writes are inside the success paths of
    // bootstrapVault / publishRevision / addDevice / removeDevice /
    // proposePromotion / finalizePromotion / cancelPromotion. There is no
    // admin-keyed setter, zero-out, or reset (L2).
    // -----------------------------------------------------------------

    /// @notice Monotonically increasing global sequence counter (verbatim
    ///         from V1). Bumped only inside `publishRevision`'s success
    ///         path (L6).
    uint256 private _nextSequence;

    /// @notice The live authorized-device SET — the honor source of truth
    ///         (L8). A `true` entry means "this address may publish
    ///         revisions for this vault". Mutated only by bootstrap / add /
    ///         remove success paths.
    mapping(bytes32 vaultId => mapping(address signer => bool)) public authorizedDevice;

    /// @notice Count of authorized devices per vault. Drives the no-brick
    ///         floor (L10) + the `MAX_DEVICES` cap (L16).
    mapping(bytes32 vaultId => uint32 count) public authorizedDeviceCount;

    /// @notice Per-vault current device manager (the "primary"; Q-a Option
    ///         B). Seeded at `bootstrapVault`, rotated by
    ///         `finalizePromotion`. The authoritative manager for the
    ///         add/remove auth check is reconciled with
    ///         `RecoveryV1.vaultAuthority` live (Q-k) — see
    ///         `_currentManager`.
    mapping(bytes32 vaultId => address) public deviceManager;

    /// @notice Per-vault monotonic nonce binding each add/remove/promote
    ///         signature to one action (anti-replay, Q-d). Increments on
    ///         each successful set-mutation (add / remove / propose).
    mapping(bytes32 vaultId => uint64 nonce) public deviceNonce;

    /// @notice Per-vault pending survivor-promotion (Q-c). `readyAt == 0`
    ///         means none pending.
    mapping(bytes32 vaultId => Promotion) public pendingPromotion;

    /// @notice Per-vault once-only bootstrap flag (Q-f). Distinguishes
    ///         "never bootstrapped" from "bootstrapped" unambiguously
    ///         (a vault could in principle have count 0 only transiently;
    ///         the no-brick guard means count never returns to 0, but this
    ///         flag makes the once-only guard explicit + cheap).
    mapping(bytes32 vaultId => bool) public bootstrapped;

    // -----------------------------------------------------------------
    // Constructor
    // -----------------------------------------------------------------

    /// @notice Compute the EIP-712 domain separator (version "2") from the
    ///         current chain ID + contract address, and pin the RecoveryV1
    ///         address.
    ///
    /// @param recoveryV1 The deployed RecoveryV1 address this V2 cross-reads
    ///                   `vaultAuthority` from (Q-h). The ONLY constructor
    ///                   argument — justified by the cross-bind; it is NOT
    ///                   an owner/admin (it cannot mutate this contract).
    ///
    /// @dev `recoveryV1 == address(0)` is rejected: a zero cross-read
    ///      target would make every genesis seed + manager reconcile
    ///      degenerate (a staticcall to address(0) returns empty and would
    ///      be decoded as `address(0)`).
    constructor(address recoveryV1) {
        if (recoveryV1 == address(0)) {
            revert ErrZeroValue();
        }
        RECOVERY_V1 = recoveryV1;
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes("Pangolin RevisionLog")),
                keccak256(bytes("2")),
                block.chainid,
                address(this)
            )
        );
    }

    // -----------------------------------------------------------------
    // External API — bootstrap
    // -----------------------------------------------------------------

    /// @notice Establish a vault's genesis authorized device + manager.
    ///         ONCE per vault (Q-f). The recovered first signer is added to
    ///         the SET; the manager is seeded from
    ///         `RecoveryV1.vaultAuthority(vaultId)` if set (so the device
    ///         control plane starts aligned with the recovery authority,
    ///         Q-h), else from the recovered first signer.
    ///
    /// @param vaultId       Opaque vault identifier (32 bytes).
    /// @param firstSigner   The expected genesis device address. The
    ///                       EIP-712 `AddDevice` signature MUST recover to
    ///                       this exact address (matches V1's
    ///                       recovered-signer model, Q-d; relayer-friendly).
    /// @param schemaVersion Event-schema version. <= MAX_KNOWN.
    /// @param signature     65-byte secp256k1 sig over the EIP-712
    ///                       `AddDevice(vaultId, firstSigner, nonce=0, sv)`
    ///                       digest, signed by `firstSigner`.
    ///
    /// @dev The genesis signature reuses the `AddDevice` typehash with
    ///      `nonce == 0` (the vault's initial `deviceNonce`). The recovered
    ///      signer must equal `firstSigner` — neither a relayer nor a third
    ///      party can bootstrap a vault into a device they do not control.
    ///
    /// @dev Non-`payable`.
    function bootstrapVault(
        bytes32 vaultId,
        address firstSigner,
        uint16 schemaVersion,
        bytes calldata signature
    ) external {
        // 1. Schema bound (L5).
        if (schemaVersion > MAX_KNOWN_SCHEMA_VERSION) {
            revert ErrUnsupportedSchemaVersion();
        }

        // 2. Once-only guard (Q-f).
        if (bootstrapped[vaultId]) {
            revert ErrVaultAlreadyBootstrapped();
        }

        // 3. Zero-value guard.
        if (firstSigner == address(0)) {
            revert ErrZeroValue();
        }

        // 4. Recover the genesis signer over the AddDevice digest at
        //    nonce 0 and require it equals firstSigner (Q-d: gate on the
        //    recovered signer, not msg.sender).
        bytes32 digest = _hashAddDevice(vaultId, firstSigner, 0, schemaVersion);
        address recovered = _recover(digest, signature);
        if (recovered == address(0)) {
            revert ErrInvalidSignature();
        }
        if (recovered != firstSigner) {
            revert ErrInvalidSignature();
        }

        // 5. Seed the manager: prefer RecoveryV1's vaultAuthority (one
        //    authority at birth, Q-h); else the first signer.
        address authority = _recoveryAuthority(vaultId);
        address manager = authority == address(0) ? firstSigner : authority;

        // 6. State writes (after all checks). Register the first device +
        //    the manager + bump the nonce so the next set-mutation uses
        //    nonce 1.
        authorizedDevice[vaultId][firstSigner] = true;
        authorizedDeviceCount[vaultId] = 1;
        deviceManager[vaultId] = manager;
        bootstrapped[vaultId] = true;
        unchecked {
            deviceNonce[vaultId] = 1;
        }

        emit VaultBootstrapped(vaultId, firstSigner, manager, schemaVersion);
    }

    // -----------------------------------------------------------------
    // External API — publish
    // -----------------------------------------------------------------

    /// @notice Publish a new signed encrypted revision to the log. V1's
    ///         body, EXCEPT the gate is "recovered signer is in the
    ///         vault's authorized SET" (L8) — there is NO self-bootstrap;
    ///         the SET is established by `bootstrapVault` (Q-f).
    ///
    /// @param vaultId         Opaque vault identifier (32 bytes).
    /// @param accountId       Opaque per-account identifier (within vault).
    /// @param parentRevision  The revision id this one descends from (or
    ///                        `bytes32(0)` for a vault genesis).
    /// @param deviceId        Opaque device identifier; the recovered
    ///                        signer is the gating identity, not deviceId.
    /// @param schemaVersion   Payload-schema tag. <= MAX_KNOWN.
    /// @param encPayload      Opaque ciphertext + AEAD metadata;
    ///                        `keccak256(encPayload)` is bound into the
    ///                        signed digest (tamper-after-signing fails).
    /// @param signature       65-byte secp256k1 sig (r||s||v) over the
    ///                        EIP-712 `Revision` digest.
    ///
    /// @return sequence       The global sequence number assigned (equals
    ///                        `_nextSequence` at call time; pre-increment).
    ///
    /// @dev Non-`payable`. `unchecked` increment matches V1; the bump is
    ///      AFTER every check (L6), so a revert never burns a sequence.
    function publishRevision(
        bytes32 vaultId,
        bytes32 accountId,
        bytes32 parentRevision,
        bytes32 deviceId,
        uint16 schemaVersion,
        bytes calldata encPayload,
        bytes calldata signature
    ) external returns (uint256 sequence) {
        // 1. Reject unknown future schema versions (L5).
        if (schemaVersion > MAX_KNOWN_SCHEMA_VERSION) {
            revert ErrUnsupportedSchemaVersion();
        }

        // 2. Recover + gate on SET membership. Extracted into a helper so
        //    the local-variable count here stays inside the 16-slot stack
        //    budget under via-ir = false (same shape as V1).
        address signer = _verifyAndGate(
            vaultId, accountId, parentRevision, deviceId, schemaVersion, encPayload, signature
        );

        // 3. Bump the sequence ONLY on success (L6).
        sequence = _nextSequence;
        unchecked {
            _nextSequence = sequence + 1;
        }

        // 4. Emit. `signer` lets off-chain clients filter without
        //    re-running ecrecover.
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
    ///      recovers the signer, then applies the SET-membership gate (L8).
    ///      Pulled out to keep `publishRevision`'s local-variable count
    ///      inside the EVM 16-slot stack budget under via-ir = false.
    function _verifyAndGate(
        bytes32 vaultId,
        bytes32 accountId,
        bytes32 parentRevision,
        bytes32 deviceId,
        uint16 schemaVersion,
        bytes calldata encPayload,
        bytes calldata signature
    ) internal view returns (address signer) {
        // The vault must be bootstrapped (Q-f: a publish cannot race an
        // unestablished SET). bootstrapped == false also implies an empty
        // SET, but we surface the precise error.
        if (!bootstrapped[vaultId]) {
            revert ErrVaultNotBootstrapped();
        }
        bytes32 digest = _hashRevision(
            vaultId, accountId, parentRevision, deviceId, schemaVersion, keccak256(encPayload)
        );
        signer = _recover(digest, signature);
        if (signer == address(0)) {
            revert ErrInvalidSignature();
        }
        if (!authorizedDevice[vaultId][signer]) {
            revert ErrSignerNotAuthorized();
        }
    }

    // -----------------------------------------------------------------
    // External API — device set management (manager-signed, Q-d / L9)
    // -----------------------------------------------------------------

    /// @notice Add `newSigner` to the vault's authorized SET. Authorized by
    ///         an EIP-712 signature that recovers to the CURRENT device
    ///         manager (L9; NOT msg.sender — relayer-friendly, matches V1's
    ///         Path B). The current manager is reconciled with
    ///         `RecoveryV1.vaultAuthority` live (Q-k).
    ///
    /// @param vaultId       Vault to mutate. Must be bootstrapped.
    /// @param newSigner     The device address to authorize.
    /// @param nonce         Must equal the vault's current `deviceNonce`
    ///                      (anti-replay, Q-d).
    /// @param schemaVersion Event-schema version. <= MAX_KNOWN.
    /// @param authoritySig  65-byte secp256k1 sig over the EIP-712
    ///                      `AddDevice` digest, signed by the manager.
    ///
    /// @dev Non-`payable`. Order of checks (L6): schema -> bootstrapped ->
    ///      zero-value -> nonce -> set-size cap -> not-already-in-set ->
    ///      manager-auth. State writes (set + count + nonce + event) only
    ///      after all pass.
    function addDevice(
        bytes32 vaultId,
        address newSigner,
        uint64 nonce,
        uint16 schemaVersion,
        bytes calldata authoritySig
    ) external {
        if (schemaVersion > MAX_KNOWN_SCHEMA_VERSION) {
            revert ErrUnsupportedSchemaVersion();
        }
        if (!bootstrapped[vaultId]) {
            revert ErrVaultNotBootstrapped();
        }
        if (newSigner == address(0)) {
            revert ErrZeroValue();
        }
        if (nonce != deviceNonce[vaultId]) {
            revert ErrBadNonce();
        }
        if (authorizedDeviceCount[vaultId] >= MAX_DEVICES) {
            revert ErrSetSizeExceeded();
        }
        if (authorizedDevice[vaultId][newSigner]) {
            revert ErrAlreadyAuthorized();
        }

        // Manager-auth: the signature must recover to the current manager
        // (live-reconciled with RecoveryV1). Reverts ErrNotDeviceManager
        // or ErrInvalidSignature.
        address manager = _requireManagerSig(
            vaultId, _hashAddDevice(vaultId, newSigner, nonce, schemaVersion), authoritySig
        );

        // State writes (after all checks).
        authorizedDevice[vaultId][newSigner] = true;
        unchecked {
            authorizedDeviceCount[vaultId] = authorizedDeviceCount[vaultId] + 1;
            deviceNonce[vaultId] = nonce + 1;
        }

        emit DeviceAdded(vaultId, newSigner, manager, nonce, schemaVersion);
    }

    /// @notice Remove `signer` from the vault's authorized SET. Authorized
    ///         by a manager-recovered EIP-712 signature (L9). Forbids
    ///         removing the LAST device OR the current manager (L10
    ///         no-brick): the manager must promote a replacement before it
    ///         can be removed, and the set can never empty.
    ///
    /// @param vaultId       Vault to mutate. Must be bootstrapped.
    /// @param signer        The device address to revoke.
    /// @param nonce         Must equal the vault's current `deviceNonce`.
    /// @param schemaVersion Event-schema version. <= MAX_KNOWN.
    /// @param authoritySig  65-byte sig over the EIP-712 `RemoveDevice`
    ///                      digest, signed by the manager.
    ///
    /// @dev Non-`payable`. Order of checks (L6): schema -> bootstrapped ->
    ///      in-set -> no-brick (manager / last device) -> manager-auth.
    ///      State writes only after all pass.
    function removeDevice(
        bytes32 vaultId,
        address signer,
        uint64 nonce,
        uint16 schemaVersion,
        bytes calldata authoritySig
    ) external {
        if (schemaVersion > MAX_KNOWN_SCHEMA_VERSION) {
            revert ErrUnsupportedSchemaVersion();
        }
        if (!bootstrapped[vaultId]) {
            revert ErrVaultNotBootstrapped();
        }
        if (nonce != deviceNonce[vaultId]) {
            revert ErrBadNonce();
        }
        if (!authorizedDevice[vaultId][signer]) {
            revert ErrNotAuthorized();
        }

        // No-brick (L10): cannot remove the manager (it must promote a
        // replacement first) and cannot drop below 1 device. Removing the
        // current manager is forbidden regardless of count; removing a
        // non-manager device when count == 1 is impossible (the lone device
        // IS the manager), so the manager check subsumes the floor, but we
        // keep both for defence-in-depth + explicitness.
        if (signer == _currentManager(vaultId) || authorizedDeviceCount[vaultId] <= 1) {
            revert ErrWouldBrickVault();
        }

        address manager = _requireManagerSig(
            vaultId, _hashRemoveDevice(vaultId, signer, nonce, schemaVersion), authoritySig
        );

        // State writes (after all checks).
        authorizedDevice[vaultId][signer] = false;
        unchecked {
            authorizedDeviceCount[vaultId] = authorizedDeviceCount[vaultId] - 1;
            deviceNonce[vaultId] = nonce + 1;
        }

        emit DeviceRemoved(vaultId, signer, manager, nonce, schemaVersion);
    }

    // -----------------------------------------------------------------
    // External API — survivor promotion (Q-a Option B / Q-c / L11)
    // -----------------------------------------------------------------

    /// @notice A currently-authorized device proposes ITSELF as the new
    ///         manager. Starts the `PROMOTION_DELAY` clock; the current
    ///         manager may `cancelPromotion` during the window;
    ///         `finalizePromotion` rotates the manager after the delay.
    ///
    /// @param vaultId       Vault to mutate. Must be bootstrapped.
    /// @param candidate     The proposing device. MUST be a current set
    ///                      member (L11) and the recovered signer.
    /// @param nonce         Must equal the vault's current `deviceNonce`.
    /// @param schemaVersion Event-schema version. <= MAX_KNOWN.
    /// @param candidateSig  65-byte sig over the EIP-712 `Promote` digest,
    ///                      signed by `candidate` (self-proposal: the
    ///                      candidate authorizes its own promotion; the
    ///                      biometric gate is client-side, #106c).
    ///
    /// @dev Non-`payable`. Order of checks (L6): schema -> bootstrapped ->
    ///      zero-value -> nonce -> no-pending -> candidate-in-set ->
    ///      signature recovers to candidate. State writes only after all
    ///      pass.
    function proposePromotion(
        bytes32 vaultId,
        address candidate,
        uint64 nonce,
        uint16 schemaVersion,
        bytes calldata candidateSig
    ) external {
        if (schemaVersion > MAX_KNOWN_SCHEMA_VERSION) {
            revert ErrUnsupportedSchemaVersion();
        }
        if (!bootstrapped[vaultId]) {
            revert ErrVaultNotBootstrapped();
        }
        if (candidate == address(0)) {
            revert ErrZeroValue();
        }
        if (nonce != deviceNonce[vaultId]) {
            revert ErrBadNonce();
        }
        if (pendingPromotion[vaultId].readyAt != 0) {
            revert ErrPromotionPending();
        }
        if (!authorizedDevice[vaultId][candidate]) {
            revert ErrNotSetMember();
        }

        // The candidate must sign its own promotion (recovered signer ==
        // candidate). A relayer can broadcast, but cannot promote a device
        // it does not control.
        bytes32 digest = _hashPromote(vaultId, candidate, nonce, schemaVersion);
        address recovered = _recover(digest, candidateSig);
        if (recovered == address(0) || recovered != candidate) {
            revert ErrInvalidSignature();
        }

        // State writes (after all checks). readyAt is uint64; block
        // timestamp + 48h is far inside uint64 range for any realistic
        // chain.
        uint64 readyAt;
        unchecked {
            readyAt = uint64(block.timestamp) + PROMOTION_DELAY;
            deviceNonce[vaultId] = nonce + 1;
        }
        pendingPromotion[vaultId] = Promotion({candidate: candidate, readyAt: readyAt});

        emit PromotionProposed(vaultId, candidate, readyAt, schemaVersion);
    }

    /// @notice Finalize a pending promotion after `PROMOTION_DELAY` has
    ///         elapsed: rotate `deviceManager` to the candidate (L11).
    ///         Permissionless to call — the outcome is fixed by the pending
    ///         promotion's own state, so who submits the tx is irrelevant
    ///         (no `forceFinalize` admin path, L2). The candidate must
    ///         still be a set member at finalize (a concurrent
    ///         `removeDevice` of the candidate would have been blocked by
    ///         no-brick only if it were the manager; a non-manager
    ///         candidate could be removed, so we re-check membership).
    ///
    /// @param vaultId       Vault to mutate.
    /// @param schemaVersion Event-schema version. <= MAX_KNOWN.
    ///
    /// @dev Non-`payable`. Order of checks (L6): schema -> pending-exists ->
    ///      delay-elapsed -> candidate-still-in-set. State writes only after
    ///      all pass.
    function finalizePromotion(bytes32 vaultId, uint16 schemaVersion) external {
        if (schemaVersion > MAX_KNOWN_SCHEMA_VERSION) {
            revert ErrUnsupportedSchemaVersion();
        }
        Promotion memory p = pendingPromotion[vaultId];
        if (p.readyAt == 0) {
            revert ErrNoPromotionPending();
        }
        if (block.timestamp < p.readyAt) {
            revert ErrPromotionDelayNotElapsed();
        }
        // Defence-in-depth: the candidate must still be in the SET (it
        // could have been removed by the manager during the window if it
        // was not itself the manager). A removed candidate cannot become
        // manager.
        if (!authorizedDevice[vaultId][p.candidate]) {
            revert ErrNotSetMember();
        }

        // State writes (after all checks). Rotate the manager + clear the
        // pending promotion.
        address oldManager = _currentManager(vaultId);
        deviceManager[vaultId] = p.candidate;
        delete pendingPromotion[vaultId];

        emit PromotionFinalized(vaultId, oldManager, p.candidate, schemaVersion);
    }

    /// @notice The current manager vetoes a pending promotion within the
    ///         delay window. Authorized by `msg.sender == current manager`
    ///         (the manager is a hot device the user holds; a direct tx is
    ///         the natural UX, mirroring RecoveryV1's `cancelRecovery`
    ///         msg.sender model). The current manager is reconciled with
    ///         `RecoveryV1.vaultAuthority` live (Q-k).
    ///
    /// @param vaultId       Vault to mutate.
    /// @param schemaVersion Event-schema version. <= MAX_KNOWN.
    ///
    /// @dev Non-`payable`. Order of checks (L6): schema -> pending-exists ->
    ///      caller-is-manager. State write (clear pending + event) only
    ///      after all pass.
    function cancelPromotion(bytes32 vaultId, uint16 schemaVersion) external {
        if (schemaVersion > MAX_KNOWN_SCHEMA_VERSION) {
            revert ErrUnsupportedSchemaVersion();
        }
        Promotion memory p = pendingPromotion[vaultId];
        if (p.readyAt == 0) {
            revert ErrNoPromotionPending();
        }
        if (msg.sender != _currentManager(vaultId)) {
            revert ErrNotAuthorizedToCancel();
        }

        delete pendingPromotion[vaultId];

        emit PromotionCanceled(vaultId, p.candidate, schemaVersion);
    }

    // -----------------------------------------------------------------
    // View functions / digest oracles
    // -----------------------------------------------------------------

    /// @notice Current value of the monotonic sequence counter — the
    ///         sequence the NEXT successful `publishRevision` will assign.
    function nextSequence() external view returns (uint256) {
        return _nextSequence;
    }

    /// @notice The authoritative current manager for the add/remove/cancel
    ///         auth check: the live `RecoveryV1.vaultAuthority(vaultId)` if
    ///         set, else the V2-local `deviceManager` (Q-k / Q-a Option B).
    ///         Exposed so off-chain tooling can predict the auth check.
    function currentManager(bytes32 vaultId) external view returns (address) {
        return _currentManager(vaultId);
    }

    /// @notice EIP-712 v4 typed-data digest for a `Revision` (parity oracle;
    ///         off-chain signers compute the same digest). `encPayload` is
    ///         hashed to 32 bytes here exactly as `publishRevision` does.
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

    /// @notice EIP-712 digest the contract verifies for an `AddDevice`
    ///         authorization (parity oracle, L14). `bootstrapVault` uses
    ///         this with `nonce == 0`.
    function hashAddDevice(bytes32 vaultId, address newSigner, uint64 nonce, uint16 schemaVersion)
        external
        view
        returns (bytes32)
    {
        return _hashAddDevice(vaultId, newSigner, nonce, schemaVersion);
    }

    /// @notice EIP-712 digest the contract verifies for a `RemoveDevice`
    ///         authorization (parity oracle, L14).
    function hashRemoveDevice(bytes32 vaultId, address signer, uint64 nonce, uint16 schemaVersion)
        external
        view
        returns (bytes32)
    {
        return _hashRemoveDevice(vaultId, signer, nonce, schemaVersion);
    }

    /// @notice EIP-712 digest the contract verifies for a `Promote`
    ///         self-proposal (parity oracle, L14).
    function hashPromote(bytes32 vaultId, address candidate, uint64 nonce, uint16 schemaVersion)
        external
        view
        returns (bytes32)
    {
        return _hashPromote(vaultId, candidate, nonce, schemaVersion);
    }

    // -----------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------

    /// @dev The authoritative manager: live `RecoveryV1.vaultAuthority` if
    ///      set, else the V2-local `deviceManager` (Q-k / Q-a Option B). A
    ///      guardian recovery that rotated the authority re-aligns who may
    ///      manage devices with zero drift, at the cost of a staticcall per
    ///      manager check + per cancel. The honor rule (publish) stays on
    ///      the SET, NOT on this manager, so a manager/authority
    ///      disagreement can never silently honor a wrong signer (L8).
    function _currentManager(bytes32 vaultId) internal view returns (address) {
        address authority = _recoveryAuthority(vaultId);
        return authority == address(0) ? deviceManager[vaultId] : authority;
    }

    /// @dev Read-only `staticcall` of `RECOVERY_V1.vaultAuthority(vaultId)`
    ///      (Q-h / L15). A `staticcall` cannot mutate state — zero
    ///      reentrancy surface. Returns `address(0)` only when the vault has
    ///      NO recovery authority set (the `vaultAuthority` mapping getter's
    ///      default), in which case `_currentManager` falls back to the
    ///      V2-local `deviceManager`. The pinned RecoveryV1's getter never
    ///      reverts; were the cross-call ever to revert it bubbles up here
    ///      (fail-closed — no mutation proceeds), it does NOT silently
    ///      degrade to `address(0)`.
    function _recoveryAuthority(bytes32 vaultId) internal view returns (address) {
        return IRecoveryV1(RECOVERY_V1).vaultAuthority(vaultId);
    }

    /// @dev Recover the manager from `authoritySig` over `digest` and
    ///      require it equals the current manager (L9). Reverts
    ///      `ErrInvalidSignature` on a degenerate signature, or
    ///      `ErrNotDeviceManager` if the recovered signer is not the
    ///      current manager.
    function _requireManagerSig(bytes32 vaultId, bytes32 digest, bytes calldata authoritySig)
        internal
        view
        returns (address manager)
    {
        address recovered = _recover(digest, authoritySig);
        if (recovered == address(0)) {
            revert ErrInvalidSignature();
        }
        manager = _currentManager(vaultId);
        if (recovered != manager) {
            revert ErrNotDeviceManager();
        }
    }

    /// @dev EIP-712 v4 typed-data digest for a `Revision` struct:
    ///      `keccak256("\x19\x01" || domainSeparator || structHash)`.
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
        return keccak256(abi.encodePacked(hex"1901", DOMAIN_SEPARATOR, structHash));
    }

    /// @dev EIP-712 v4 digest for an `AddDevice` authorization.
    function _hashAddDevice(bytes32 vaultId, address newSigner, uint64 nonce, uint16 schemaVersion)
        internal
        view
        returns (bytes32)
    {
        bytes32 structHash =
            keccak256(abi.encode(ADD_DEVICE_TYPEHASH, vaultId, newSigner, nonce, schemaVersion));
        return keccak256(abi.encodePacked(hex"1901", DOMAIN_SEPARATOR, structHash));
    }

    /// @dev EIP-712 v4 digest for a `RemoveDevice` authorization.
    function _hashRemoveDevice(bytes32 vaultId, address signer, uint64 nonce, uint16 schemaVersion)
        internal
        view
        returns (bytes32)
    {
        bytes32 structHash =
            keccak256(abi.encode(REMOVE_DEVICE_TYPEHASH, vaultId, signer, nonce, schemaVersion));
        return keccak256(abi.encodePacked(hex"1901", DOMAIN_SEPARATOR, structHash));
    }

    /// @dev EIP-712 v4 digest for a `Promote` self-proposal.
    function _hashPromote(bytes32 vaultId, address candidate, uint64 nonce, uint16 schemaVersion)
        internal
        view
        returns (bytes32)
    {
        bytes32 structHash =
            keccak256(abi.encode(PROMOTE_TYPEHASH, vaultId, candidate, nonce, schemaVersion));
        return keccak256(abi.encodePacked(hex"1901", DOMAIN_SEPARATOR, structHash));
    }

    /// @dev Recover a secp256k1 signer from a 65-byte `r || s || v`
    ///      signature over `digest`. Returns `address(0)` on any failure
    ///      path (malformed length, malformed `v`, high-s, the ecrecover
    ///      precompile's own sentinel for invalid sigs).
    ///
    ///      We accept `v` values of 27 or 28 only — the canonical Ethereum
    ///      EIP-712 encoding (the chain id is bound into the domain
    ///      separator already). Copied VERBATIM from
    ///      `RevisionLogV1.sol::_recover` / `RecoveryV1.sol::_recover` (same
    ///      Path B ecrecover malleability discipline, L4).
    function _recover(bytes32 digest, bytes calldata signature) internal pure returns (address) {
        if (signature.length != 65) {
            return address(0);
        }
        bytes32 r;
        bytes32 s;
        uint8 v;
        // Calldata layout: [r (32)] [s (32)] [v (1)].
        assembly ("memory-safe") {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        if (v != 27 && v != 28) {
            return address(0);
        }
        // EIP-2 / EIP-2098 low-s discipline: reject "high-s" signatures so
        // the signature is not malleable.
        //   secp256k1 curve order n (half):
        //   0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            return address(0);
        }
        return ecrecover(digest, v, r, s);
    }

    // No receive() / fallback() — same as v0/v1/RecoveryV1. Non-payable
    // means ETH sends revert at the dispatcher's CALLVALUE guard. No
    // selfdestruct / delegatecall / value-bearing external call anywhere;
    // the only external surface is a read-only staticcall to RECOVERY_V1.
}
