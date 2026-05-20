// SPDX-License-Identifier: AGPL-3.0-or-later
// @dev Exact-pinned pragma (NOT `^0.8.24`): per docs/issue-plans/102-recovery-v1-contract.md
//      L3 + the v0 audit-fix L-3 lesson — the contract must build with
//      the exact compiler version it was audited against. A future
//      contributor MUST NOT relax this to a caret range. RecoveryV1 is
//      external-audit-gated before mainnet (D-011); the exact pin is
//      what the auditor signs off on.
pragma solidity 0.8.24;

/// @title RecoveryV1
/// @notice Social-recovery state machine for Pangolin vaults. The
///         project's FIRST stateful on-chain contract: a per-vault
///         lifecycle (None -> PENDING -> FINALIZED | CANCELED) that
///         rotates a vault's `vaultAuthority` after an N-of-M guardian
///         quorum approves AND a mandatory 72-hour observation delay
///         elapses. MVP-3 issue #102 (master plan §6 row `2.2 Recovery
///         contract v1`, Whitepaper §D2).
///
/// @dev CARDINAL CONTRACT DESIGN RULES (docs/issue-plans/102-recovery-v1-contract.md
///      L2, inherited VERBATIM from v0/v1/EntitlementRegistry +
///      STRICTER for the highest-risk EPIC — master plan §0 cardinal
///      principles 3 + 4, Whitepaper §D1, DECISIONS.md Issue #102):
///        - **No admin keys.** No owner. No role. No multisig. No
///          `forceFinalize` / `adminCancel` / `setAuthority` /
///          `setThreshold` / `pauseRecovery` / `removeGuardian` /
///          `updateGuardianSet`. An admin override here would BE a
///          hostile-recovery primitive by construction — the single
///          most dangerous thing this contract could contain.
///        - **No upgrades.** No proxy. No `selfdestruct`. No
///          `delegatecall`. A bug is fixed by deploying RecoveryV2 and
///          migrating, NEVER by patching v1 (D-011).
///        - **No pause / freeze.** Liveness is monotonic; the only
///          time gate is the mandatory MIN_DELAY, which no party
///          (there is no privileged party) can skip or shorten.
///        - **No external calls.** The contract makes ZERO `call` /
///          `transfer` / `send` / `delegatecall` — it only verifies
///          signatures (the `ecrecover` precompile is not a message
///          call) and mutates its own storage. Zero reentrancy surface
///          by construction.
///        - **Never touches the VDK or any secret (L12).** The contract
///          rotates a `vaultAuthority` address ONLY. It stores no
///          `bytes` blob, no ciphertext, no key material. "Guardians
///          never see the VDK" is structurally true: there is no slot
///          a VDK could live in. VDK re-wrap is client-side, out of
///          #102.
///        - **State writes AFTER all revertable checks (L6).** Every
///          mutating entry point validates fully before touching
///          storage; a revert burns no nonce, rotates no authority,
///          emits no event.
///        - **Custom errors, revert-on-failure, no event on failure.**
///
/// @dev Cross-chain portability (docs/issue-plans/102-recovery-v1-contract.md
///      L3 + DECISIONS.md D-005):
///        - Compiled with `evm_version = "shanghai"` so the bytecode
///          runs unchanged on Base, Arbitrum, OP, Polygon, and Ethereum
///          mainnet at Shanghai-or-later. No Base-specific opcodes.
///        - `ecrecover` (precompile 0x01) has identical behaviour on
///          every EVM chain at every fork >= Frontier — L1-viable.
///
/// @dev Relationship to RevisionLogV0/V1 + EntitlementRegistry:
///        - Sibling, not derived. RevisionLogV1 (D-017) is IMMUTABLE
///          with no revocation; "authority" must therefore be a NEW
///          concept RecoveryV1 owns (R-d). #102 makes authority rotation
///          observable + authoritative ON-CHAIN; enforcement-on-read
///          (clients honouring `vaultAuthority` and ignoring stale
///          device-registry entries that predate a finalized rotation)
///          is CLIENT-SIDE read-policy, DEFERRED to issue 6.5. This is
///          the most important cross-issue dependency.
///        - Reuses the EIP-712 v4 typed-data discipline + the `_recover`
///          helper from `RevisionLogV1.sol` VERBATIM (Path B ecrecover
///          malleability discipline: len-65, v in {27,28}, canonical-s,
///          reject signer == address(0)).
contract RecoveryV1 {
    // -----------------------------------------------------------------
    // Types
    // -----------------------------------------------------------------

    /// @notice Lifecycle status of a vault's recovery slot.
    ///
    /// @dev `uint8`-backed (Solidity enums are `uint8` under the hood)
    ///      so the field width is future-proofed per L7 — a v2 can add
    ///      statuses without forcing a storage-layout migration.
    ///        - `None`      : no recovery has ever been initiated for
    ///                        this attempt slot (the zero value).
    ///        - `Pending`   : a recovery attempt is in flight; guardians
    ///                        may approve, the authority may cancel,
    ///                        finalize is gated on threshold + delay.
    ///        - `Finalized` : the attempt rotated `vaultAuthority`
    ///                        (terminal for the attempt).
    ///        - `Canceled`  : the authority aborted the attempt
    ///                        (terminal for the attempt).
    enum Status {
        None,
        Pending,
        Finalized,
        Canceled
    }

    /// @notice Immutable per-vault guardian commitment (R-a + R-e).
    ///
    /// @dev `root` is the merkle root of the guardian address set
    ///      (sorted-pair keccak leaves) — NOT the plaintext guardian
    ///      addresses (L13: chain observers learn a recovery is
    ///      happening, never who guards whom). `threshold` /
    ///      `guardianCount` are bounds-checked at `setGuardianSet` time
    ///      (L8). `initialized` distinguishes "never set" from "set with
    ///      a zero root" so the once-only guard (R-e) is unambiguous.
    ///      Packs into a single 32-byte slot after `root`:
    ///      threshold (1) + guardianCount (1) + initialized (1) = 3 bytes.
    struct GuardianSet {
        bytes32 root;
        uint8 threshold;
        uint8 guardianCount;
        bool initialized;
    }

    /// @notice Per-vault active recovery attempt (R-f one-active).
    ///
    /// @dev `proposedAuthority` is the address `finalizeRecovery` will
    ///      rotate to. `initiatedAt` stamps the MIN_DELAY clock (L9).
    ///      `attemptNonce` scopes guardian approvals to THIS attempt
    ///      (L11) — it bumps on every `initiateRecovery` so a stale
    ///      approval signed for a prior attempt can never carry into a
    ///      fresh one. `approvals` counts deduplicated guardian
    ///      approvals for the current attempt. `status` drives the
    ///      state machine. Field widths per L7:
    ///        - initiatedAt  uint64 (seconds; good past year 584942417355)
    ///        - attemptNonce uint64 (2^64 attempts infeasible)
    ///        - approvals    uint8  (bounded by MAX_GUARDIANS = 15)
    struct Recovery {
        address proposedAuthority;
        uint64 initiatedAt;
        uint64 attemptNonce;
        uint8 approvals;
        Status status;
    }

    // -----------------------------------------------------------------
    // Events (every transition carries a uint16 schemaVersion — L5)
    // -----------------------------------------------------------------

    /// @notice Emitted when a guardian set is established for a vault.
    ///         The root is NOT indexed (it is not a useful filter axis
    ///         and indexing it would leak nothing extra given L13). The
    ///         initial authority is emitted so off-chain tooling can
    ///         track the authority lineage from genesis.
    event GuardianSetInitialized(
        bytes32 indexed vaultId,
        bytes32 root,
        uint8 threshold,
        uint8 guardianCount,
        address initialAuthority,
        uint16 schemaVersion
    );

    /// @notice Emitted on `initiateRecovery` (None/terminal -> Pending).
    ///         `attemptNonce` is indexed so a client can correlate all
    ///         approvals for a specific attempt off-chain.
    event RecoveryInitiated(
        bytes32 indexed vaultId,
        uint64 indexed attemptNonce,
        address proposedAuthority,
        uint64 initiatedAt,
        uint16 schemaVersion
    );

    /// @notice Emitted on each successful (deduplicated) guardian
    ///         approval. `guardian` is the recovered + merkle-proven
    ///         guardian address; emitted unindexed because the privacy
    ///         model (L13) makes a per-guardian filter axis undesirable,
    ///         but it is observable for transparency / countdown UX.
    event RecoveryApproved(
        bytes32 indexed vaultId,
        uint64 indexed attemptNonce,
        address guardian,
        uint8 approvals,
        uint16 schemaVersion
    );

    /// @notice Emitted on `cancelRecovery` (Pending -> Canceled).
    event RecoveryCanceled(
        bytes32 indexed vaultId, uint64 indexed attemptNonce, uint16 schemaVersion
    );

    /// @notice Emitted on `finalizeRecovery` (Pending -> Finalized);
    ///         `vaultAuthority` rotated to `newAuthority`.
    event RecoveryFinalized(
        bytes32 indexed vaultId,
        uint64 indexed attemptNonce,
        address oldAuthority,
        address newAuthority,
        uint16 schemaVersion
    );

    // -----------------------------------------------------------------
    // Errors (custom; Solidity 0.8.4+; gas-cheaper than string reverts)
    // -----------------------------------------------------------------

    /// @notice `setGuardianSet` called a second time for a vault (R-e:
    ///         guardian sets are immutable in v1; mutation is the
    ///         second-most-dangerous primitive after finalize and is
    ///         deferred to a separately-audited later version).
    error ErrGuardianSetAlreadyInitialized();

    /// @notice `setGuardianSet` `threshold` outside [MIN_THRESHOLD,
    ///         MAX_THRESHOLD] OR `threshold > guardianCount` (L8). A
    ///         contract-enforced floor means an attacker cannot deploy
    ///         a 1-of-N or 0-of-N vault.
    error ErrThresholdOutOfBounds();

    /// @notice `setGuardianSet` `guardianCount` outside [MIN_GUARDIANS,
    ///         MAX_GUARDIANS] (L8).
    error ErrGuardianCountOutOfBounds();

    /// @notice `setGuardianSet` passed `address(0)` or `bytes32(0)` for
    ///         a load-bearing field (initial authority / merkle root).
    ///         Fails fast so no degenerate vault ever lands.
    error ErrZeroValue();

    /// @notice An operation referenced a vault with no guardian set
    ///         established. `initiateRecovery` / `cancelRecovery` /
    ///         `finalizeRecovery` all require an initialized set.
    error ErrGuardianSetNotInitialized();

    /// @notice `initiateRecovery` while a PENDING attempt already exists
    ///         (R-f: one active recovery per vault — prevents an
    ///         attacker spamming concurrent attempts to confuse the user
    ///         about which to cancel).
    error ErrRecoveryAlreadyPending();

    /// @notice An operation that requires a PENDING attempt
    ///         (`approveRecovery` / `cancelRecovery` / `finalizeRecovery`)
    ///         found no active recovery.
    error ErrNoActiveRecovery();

    /// @notice `ecrecover` returned `address(0)` — the signature was
    ///         malformed or shape-degenerate (bad length, bad v, high-s,
    ///         r=0/s=0). Per L6: revert path emits NO event, mutates NO
    ///         state.
    error ErrInvalidSignature();

    /// @notice The supplied merkle proof did not prove the approving
    ///         guardian's address is a leaf of the vault's guardian-set
    ///         root (R-a). The recovered signer + the proven leaf must
    ///         BOTH match: the EIP-712 signature recovers an address,
    ///         and that exact address must be the proof's leaf.
    error ErrInvalidMerkleProof();

    /// @notice This guardian already approved the current attempt
    ///         (L11 dedup). Keyed on
    ///         `hasApproved[vaultId][attemptNonce][guardian]`.
    error ErrDuplicateApproval();

    /// @notice `finalizeRecovery` before `block.timestamp >=
    ///         initiatedAt + MIN_DELAY` (R-b / L9). The mandatory
    ///         observation window is not skippable by any party.
    error ErrDelayNotElapsed();

    /// @notice `finalizeRecovery` with `approvals < threshold` (L8).
    error ErrThresholdNotMet();

    /// @notice `cancelRecovery` by anyone other than the current
    ///         `vaultAuthority` (R-g: authority-only cancel; the
    ///         still-held device aborts a hostile recovery). No
    ///         guardian-quorum cancel in v1.
    error ErrNotAuthorizedToCancel();

    /// @notice An approval signature's `expiresAt` is strictly less than
    ///         the current block timestamp (R-c anti-stale-signature
    ///         defence-in-depth; the attempt-scoped dedup handles
    ///         in-flight replay, `expiresAt` handles long-term-leak
    ///         replay).
    error ErrApprovalExpired();

    /// @notice `schemaVersion` exceeds `MAX_KNOWN_SCHEMA_VERSION`. The
    ///         contract refuses to record events under unknown future
    ///         schema versions (L5; §18.7 ladder).
    error ErrUnsupportedSchemaVersion();

    // -----------------------------------------------------------------
    // Constants
    // -----------------------------------------------------------------

    /// @notice Maximum supported event-schema version. Per L5 the
    ///         initial v1 events are tagged `schemaVersion = 1`, so
    ///         `MAX_KNOWN_SCHEMA_VERSION = 1`. A future v1.1 schema
    ///         requires deploying v2 (no in-place setter — L2 no-admin).
    uint16 public constant MAX_KNOWN_SCHEMA_VERSION = 1;

    /// @notice Mandatory recovery observation delay (R-b / L9). FIXED;
    ///         NOT per-vault-configurable in v1. This is the user's
    ///         window to notice + cancel a hostile recovery; a fixed
    ///         constant is the smallest attack surface. Configurable
    ///         delay deferred to v2. Miner timestamp skew (a few seconds)
    ///         is negligible against 72 hours.
    uint64 public constant MIN_DELAY = 72 hours;

    /// @notice Threshold lower bound (L8 / D-009): no 1-of-N or 0-of-N
    ///         vault can be established.
    uint8 public constant MIN_THRESHOLD = 2;

    /// @notice Threshold upper bound (L8 / D-009).
    uint8 public constant MAX_THRESHOLD = 9;

    /// @notice Guardian-count lower bound (L8 / D-009).
    uint8 public constant MIN_GUARDIANS = 3;

    /// @notice Guardian-count upper bound (L8 / D-009). Caps `approvals`
    ///         (uint8) and the merkle-tree size.
    uint8 public constant MAX_GUARDIANS = 15;

    /// @notice EIP-712 v4 domain typehash. The four-field domain
    ///         (`name`, `version`, `chainId`, `verifyingContract`) is
    ///         the canonical EIP-712 v4 layout — every standard signer
    ///         (hardware wallet, MetaMask, WalletConnect) speaks this
    ///         natively.
    bytes32 private constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    /// @notice EIP-712 typehash for an `Approve` attestation (R-c). Five
    ///         fields bind the guardian's signature to the SPECIFIC
    ///         attempt so it cannot replay into another attempt or vault
    ///         or chain:
    ///         - `vaultId`           (bytes32, opaque)
    ///         - `proposedAuthority` (address; the attempt's target)
    ///         - `attemptNonce`      (uint64; per-attempt scope, L11)
    ///         - `expiresAt`         (uint64; anti-stale, R-c)
    ///         - `schemaVersion`     (uint16)
    bytes32 private constant APPROVE_TYPEHASH = keccak256(
        "Approve(bytes32 vaultId,address proposedAuthority,uint64 attemptNonce,uint64 expiresAt,uint16 schemaVersion)"
    );

    // -----------------------------------------------------------------
    // Immutable state (set at deploy time; cannot change)
    // -----------------------------------------------------------------

    /// @notice EIP-712 v4 domain separator, computed once at
    ///         construction. Binds the contract address + chain ID into
    ///         every approval signature, defeating cross-contract and
    ///         cross-chain replay (R-h / L4).
    bytes32 public immutable DOMAIN_SEPARATOR;

    // -----------------------------------------------------------------
    // Mutable storage
    //
    // Slot layout (L7):
    //   slot 0: guardianSet   mapping(bytes32 => GuardianSet)
    //   slot 1: vaultAuthority mapping(bytes32 => address)
    //   slot 2: recovery      mapping(bytes32 => Recovery)
    //   slot 3: hasApproved   mapping(bytes32 => mapping(uint64 => mapping(address => bool)))
    // Mapping base slots themselves store no value; the data lives at
    // keccak-hashed addresses. The only mutating writes are inside the
    // success paths of setGuardianSet / initiateRecovery /
    // approveRecovery / cancelRecovery / finalizeRecovery. There is no
    // admin-keyed setter, zero-out, or reset (L2).
    // -----------------------------------------------------------------

    /// @notice Per-vault immutable-in-v1 guardian commitment (R-a/R-e).
    ///         Written exactly once per vault in `setGuardianSet`.
    mapping(bytes32 vaultId => GuardianSet) public guardianSet;

    /// @notice Per-vault current authority (R-d). Self-bootstrapped in
    ///         `setGuardianSet` to the caller; thereafter mutated ONLY
    ///         by `finalizeRecovery`'s success path
    ///         (`vaultAuthority[vaultId] = proposedAuthority`).
    mapping(bytes32 vaultId => address) public vaultAuthority;

    /// @notice Per-vault active/last recovery attempt (R-f).
    mapping(bytes32 vaultId => Recovery) public recovery;

    /// @notice Per-(vault, attempt, guardian) approval dedup flag (L11).
    ///         Keyed on `attemptNonce` so a fresh attempt starts with a
    ///         clean approval set and a stale approval cannot carry over.
    mapping(bytes32 vaultId => mapping(uint64 attemptNonce => mapping(address guardian => bool)))
        public hasApproved;

    // -----------------------------------------------------------------
    // Constructor
    // -----------------------------------------------------------------

    /// @notice Compute the EIP-712 domain separator from the current
    ///         chain ID and contract address. No constructor arguments
    ///         (L2): the contract has no configurable surface; every
    ///         parameter is hardcoded so auditors can verify the
    ///         deployment is the audited build. Unlike EntitlementRegistry
    ///         there are no signer authorities — guardian identity is
    ///         per-vault and lives in the merkle commitment.
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
    ///         for a vault. ONCE per vault (R-e); a second call reverts
    ///         `ErrGuardianSetAlreadyInitialized`.
    ///
    /// @dev SELF-BOOTSTRAP CHOICE (the one detail the spec leaves to the
    ///      builder; see #102 prompt + R-e): the caller (`msg.sender`)
    ///      becomes the vault's initial `vaultAuthority`. This mirrors
    ///      RevisionLogV1's R-b self-bootstrap (first publisher
    ///      registers itself) and EntitlementRegistry's constructor
    ///      authority pattern, adapted to a per-vault model. Rationale:
    ///        - The bootstrapping device is, by definition, currently in
    ///          the user's control, so `msg.sender == genesis authority`
    ///          is the right trust anchor (no chicken-and-egg "who signs
    ///          the first authority" problem, no extra EIP-712 surface).
    ///        - It is NOT a security-significant fork: any model needs
    ///          SOME genesis authority, and `msg.sender` is the
    ///          minimal-surface choice. There is no admin path to change
    ///          it afterwards except a full recovery (R-d/R-g), which is
    ///          exactly the intent.
    ///      A relayer model (genesis authority via EIP-712 sig) is a
    ///      possible v2 refinement but adds surface for no v1 benefit.
    ///
    /// @param vaultId        Opaque vault identifier (32 bytes).
    /// @param root           Merkle root of the guardian address set
    ///                       (sorted-pair keccak leaves; R-a / L13).
    /// @param threshold      N-of-M approval threshold. Bounds-checked.
    /// @param guardianCount  M (set size). Bounds-checked.
    /// @param schemaVersion  Event-schema version. <= MAX_KNOWN.
    ///
    /// @dev Order of checks (revert BEFORE any state change, L6):
    ///        1. schemaVersion bound
    ///        2. once-only guard (R-e)
    ///        3. zero-value guard (root / authority)
    ///        4. count bounds (L8)
    ///        5. threshold bounds + threshold <= count (L8)
    ///      Then writes guardianSet + vaultAuthority + emits.
    ///
    /// @dev Non-`payable`: ETH sends revert at the dispatcher.
    function setGuardianSet(
        bytes32 vaultId,
        bytes32 root,
        uint8 threshold,
        uint8 guardianCount,
        uint16 schemaVersion
    ) external {
        // 1. Reject unknown future schema versions (L5).
        if (schemaVersion > MAX_KNOWN_SCHEMA_VERSION) {
            revert ErrUnsupportedSchemaVersion();
        }

        // 2. Once-only guard (R-e: immutable guardian set in v1).
        if (guardianSet[vaultId].initialized) {
            revert ErrGuardianSetAlreadyInitialized();
        }

        // 3. Zero-value guards: a zero root would make every merkle
        //    proof trivially forgeable for an empty tree; a zero
        //    authority would leave the vault un-cancelable.
        if (root == bytes32(0)) {
            revert ErrZeroValue();
        }

        // 4. Guardian-count bounds (L8).
        if (guardianCount < MIN_GUARDIANS || guardianCount > MAX_GUARDIANS) {
            revert ErrGuardianCountOutOfBounds();
        }

        // 5. Threshold bounds + threshold <= count (L8).
        if (threshold < MIN_THRESHOLD || threshold > MAX_THRESHOLD || threshold > guardianCount) {
            revert ErrThresholdOutOfBounds();
        }

        // 6. State writes (after all checks). Self-bootstrap the
        //    authority to msg.sender.
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

    /// @notice Begin a recovery attempt: None/terminal -> PENDING. Stamps
    ///         `initiatedAt` (starts the MIN_DELAY clock) and bumps
    ///         `attemptNonce` (scopes the new attempt's approvals, L11).
    ///         One active recovery per vault (R-f).
    ///
    /// @dev Permissionless to call (matches the lost-all-devices use
    ///      case: the recovering party need not already hold authority).
    ///      Security comes from the guardian quorum + the cancelable
    ///      delay, NOT from gating who may initiate. An attacker who
    ///      initiates with an attacker-controlled `proposedAuthority`
    ///      still cannot finalize without a guardian quorum AND the user
    ///      gets 72h to cancel (R-g).
    ///
    /// @param vaultId           Vault to recover. Guardian set must exist.
    /// @param proposedAuthority Address authority rotates to on finalize.
    /// @param schemaVersion     Event-schema version. <= MAX_KNOWN.
    ///
    /// @dev Non-`payable`.
    function initiateRecovery(bytes32 vaultId, address proposedAuthority, uint16 schemaVersion)
        external
    {
        // 1. Schema bound.
        if (schemaVersion > MAX_KNOWN_SCHEMA_VERSION) {
            revert ErrUnsupportedSchemaVersion();
        }

        // 2. Guardian set must be established.
        if (!guardianSet[vaultId].initialized) {
            revert ErrGuardianSetNotInitialized();
        }

        // 3. Zero proposed authority is nonsensical (would rotate the
        //    vault into an unrecoverable null authority on finalize).
        if (proposedAuthority == address(0)) {
            revert ErrZeroValue();
        }

        // 4. One-active-recovery guard (R-f). A finalized/canceled
        //    slot may be re-initiated (a new attempt); only an
        //    in-flight PENDING attempt blocks.
        Recovery storage rec = recovery[vaultId];
        if (rec.status == Status.Pending) {
            revert ErrRecoveryAlreadyPending();
        }

        // 5. State writes (after checks). Bump the attempt nonce so the
        //    new attempt's approval set is fresh (L11). uint64 overflow
        //    at 2^64 attempts is infeasible; unchecked saves gas.
        uint64 newNonce;
        unchecked {
            newNonce = rec.attemptNonce + 1;
        }
        rec.proposedAuthority = proposedAuthority;
        rec.initiatedAt = uint64(block.timestamp);
        rec.attemptNonce = newNonce;
        rec.approvals = 0;
        rec.status = Status.Pending;

        emit RecoveryInitiated(
            vaultId, newNonce, proposedAuthority, uint64(block.timestamp), schemaVersion
        );
    }

    /// @notice Record a guardian's approval of the current PENDING
    ///         attempt. Verifies (a) the guardian's address is a leaf of
    ///         the vault's merkle root via `proof` (R-a), and (b) an
    ///         EIP-712 `Approve` signature from that exact guardian over
    ///         the attempt-scoped digest (R-c). Deduplicated (L11).
    ///
    /// @param vaultId       Vault under recovery.
    /// @param guardian      The approving guardian's address. MUST be the
    ///                      merkle leaf AND the recovered signer.
    /// @param proof         Merkle proof that `keccak256(abi.encode(guardian))`
    ///                      is a leaf under `guardianSet[vaultId].root`.
    /// @param expiresAt     Unix ts after which the signature is rejected.
    /// @param schemaVersion Event-schema version. <= MAX_KNOWN.
    /// @param signature     65-byte secp256k1 sig over the EIP-712
    ///                      `Approve` digest, signed by `guardian`.
    ///
    /// @dev The digest binds `proposedAuthority` + `attemptNonce` (read
    ///      from the live PENDING attempt), so a signature cannot replay
    ///      into a different attempt, a different proposed authority, a
    ///      different vault, or a different chain.
    ///
    /// @dev Order of checks (L6): schema -> active recovery -> expiry ->
    ///      merkle membership -> signature recover -> signer == leaf ->
    ///      dedup. State write (flag + count + event) only after all pass.
    ///
    /// @dev Non-`payable`.
    function approveRecovery(
        bytes32 vaultId,
        address guardian,
        bytes32[] calldata proof,
        uint64 expiresAt,
        uint16 schemaVersion,
        bytes calldata signature
    ) external {
        // 1. Schema bound.
        if (schemaVersion > MAX_KNOWN_SCHEMA_VERSION) {
            revert ErrUnsupportedSchemaVersion();
        }

        Recovery storage rec = recovery[vaultId];

        // 2. Must be an in-flight attempt.
        if (rec.status != Status.Pending) {
            revert ErrNoActiveRecovery();
        }

        // 3. Anti-stale-signature expiry (R-c). Non-expired requires
        //    block.timestamp <= expiresAt.
        if (block.timestamp > expiresAt) {
            revert ErrApprovalExpired();
        }

        // 4. Merkle membership (R-a / L13). The leaf is the hash of the
        //    guardian address; reject if not in the committed set.
        bytes32 leaf = keccak256(abi.encode(guardian));
        if (!_verifyMerkleProof(proof, guardianSet[vaultId].root, leaf)) {
            revert ErrInvalidMerkleProof();
        }

        // 5. EIP-712 signature recover, bound to THIS attempt (R-c /
        //    L11). The digest reads proposedAuthority + attemptNonce
        //    from the live attempt.
        bytes32 digest =
            _hashApprove(vaultId, rec.proposedAuthority, rec.attemptNonce, expiresAt, schemaVersion);
        address signer = _recover(digest, signature);
        if (signer == address(0)) {
            revert ErrInvalidSignature();
        }

        // 6. The recovered signer MUST be the proven guardian. This is
        //    the join between "is in the set" (merkle) and "actually
        //    signed" (ecrecover) — neither alone is sufficient.
        if (signer != guardian) {
            revert ErrInvalidSignature();
        }

        // 7. Dedup (L11): one approval per guardian per attempt.
        if (hasApproved[vaultId][rec.attemptNonce][guardian]) {
            revert ErrDuplicateApproval();
        }

        // 8. State writes (after all checks). Mark + count. `approvals`
        //    can never exceed guardianCount (<= MAX_GUARDIANS = 15)
        //    because each guardian dedups and only set members pass the
        //    merkle check; the increment is safe within uint8.
        hasApproved[vaultId][rec.attemptNonce][guardian] = true;
        unchecked {
            rec.approvals = rec.approvals + 1;
        }

        emit RecoveryApproved(vaultId, rec.attemptNonce, guardian, rec.approvals, schemaVersion);
    }

    /// @notice Cancel the current PENDING attempt: PENDING -> CANCELED.
    ///         Authority-only (R-g): the still-held device aborts a
    ///         hostile recovery. Callable any time before finalize
    ///         (L10). No guardian-quorum cancel in v1.
    ///
    /// @dev Authorization is `msg.sender == vaultAuthority[vaultId]` —
    ///      the cleaner of the two spec-allowed options (a direct
    ///      msg.sender check vs an EIP-712 cancel sig). The authority is
    ///      a hot device the user holds, so a direct tx from it is the
    ///      natural UX and avoids an extra signature surface. A digest
    ///      oracle `hashCancel` is provided for symmetry / future
    ///      relayer use, but v1 cancel auth is msg.sender.
    ///
    /// @param vaultId       Vault under recovery.
    /// @param schemaVersion Event-schema version. <= MAX_KNOWN.
    ///
    /// @dev Non-`payable`.
    function cancelRecovery(bytes32 vaultId, uint16 schemaVersion) external {
        // 1. Schema bound.
        if (schemaVersion > MAX_KNOWN_SCHEMA_VERSION) {
            revert ErrUnsupportedSchemaVersion();
        }

        Recovery storage rec = recovery[vaultId];

        // 2. Must be an in-flight attempt.
        if (rec.status != Status.Pending) {
            revert ErrNoActiveRecovery();
        }

        // 3. Authority-only (R-g).
        if (msg.sender != vaultAuthority[vaultId]) {
            revert ErrNotAuthorizedToCancel();
        }

        // 4. State write (after checks). Terminal for this attempt.
        uint64 attemptNonce = rec.attemptNonce;
        rec.status = Status.Canceled;

        emit RecoveryCanceled(vaultId, attemptNonce, schemaVersion);
    }

    /// @notice Finalize the current PENDING attempt: PENDING ->
    ///         FINALIZED. Requires `approvals >= threshold` (L8) AND
    ///         `block.timestamp >= initiatedAt + MIN_DELAY` (R-b / L9).
    ///         Rotates `vaultAuthority[vaultId] = proposedAuthority`
    ///         (R-d) — the ONLY place authority changes.
    ///
    /// @dev Permissionless to call (anyone can poke a fully-approved,
    ///      delay-elapsed attempt across the line; the outcome is fixed
    ///      by the attempt's own state, so who submits the tx is
    ///      irrelevant). No `forceFinalize` admin path exists (L2).
    ///
    /// @param vaultId       Vault under recovery.
    /// @param schemaVersion Event-schema version. <= MAX_KNOWN.
    ///
    /// @dev Order of checks (L6): schema -> active recovery -> threshold
    ///      -> delay. State write (status + authority + event) only
    ///      after all pass.
    ///
    /// @dev Non-`payable`.
    function finalizeRecovery(bytes32 vaultId, uint16 schemaVersion) external {
        // 1. Schema bound.
        if (schemaVersion > MAX_KNOWN_SCHEMA_VERSION) {
            revert ErrUnsupportedSchemaVersion();
        }

        Recovery storage rec = recovery[vaultId];

        // 2. Must be an in-flight attempt.
        if (rec.status != Status.Pending) {
            revert ErrNoActiveRecovery();
        }

        // 3. Threshold met (L8).
        if (rec.approvals < guardianSet[vaultId].threshold) {
            revert ErrThresholdNotMet();
        }

        // 4. Mandatory delay elapsed (R-b / L9). Not skippable.
        if (block.timestamp < uint256(rec.initiatedAt) + MIN_DELAY) {
            revert ErrDelayNotElapsed();
        }

        // 5. State writes (after all checks). Rotate authority — the
        //    ONLY mutation of vaultAuthority anywhere in the contract.
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

    /// @notice Compute the EIP-712 v4 digest the contract verifies for
    ///         an `Approve` attestation. Off-chain guardians compute the
    ///         same digest and sign it under their secp256k1 key.
    function hashApprove(
        bytes32 vaultId,
        address proposedAuthority,
        uint64 attemptNonce,
        uint64 expiresAt,
        uint16 schemaVersion
    ) external view returns (bytes32) {
        return _hashApprove(vaultId, proposedAuthority, attemptNonce, expiresAt, schemaVersion);
    }

    /// @notice Convenience oracle: the digest a relayer would sign for a
    ///         cancel, should a future version move cancel to an EIP-712
    ///         sig. v1 cancel auth is msg.sender (R-g), so this is NOT
    ///         consumed by `cancelRecovery`; it is a forward-compatible
    ///         view that binds vaultId + attemptNonce + schemaVersion.
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

    /// @notice Convenience oracle: a digest binding an initiation's
    ///         fields. v1 `initiateRecovery` is permissionless (no sig),
    ///         so this is NOT consumed by the contract; it is a
    ///         forward-compatible view for clients that wish to attest
    ///         an initiation off-chain.
    function hashInitiate(
        bytes32 vaultId,
        address proposedAuthority,
        uint64 attemptNonce,
        uint16 schemaVersion
    ) external view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256(
                    "Initiate(bytes32 vaultId,address proposedAuthority,uint64 attemptNonce,uint16 schemaVersion)"
                ),
                vaultId,
                proposedAuthority,
                attemptNonce,
                schemaVersion
            )
        );
        return keccak256(abi.encodePacked(hex"1901", DOMAIN_SEPARATOR, structHash));
    }

    // -----------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------

    /// @dev EIP-712 v4 typed-data digest for an `Approve` struct:
    ///      `keccak256("\x19\x01" || domainSeparator || structHash)`.
    function _hashApprove(
        bytes32 vaultId,
        address proposedAuthority,
        uint64 attemptNonce,
        uint64 expiresAt,
        uint16 schemaVersion
    ) internal view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                APPROVE_TYPEHASH, vaultId, proposedAuthority, attemptNonce, expiresAt, schemaVersion
            )
        );
        return keccak256(abi.encodePacked(hex"1901", DOMAIN_SEPARATOR, structHash));
    }

    /// @dev Standard OZ-style merkle-proof verification with sorted-pair
    ///      keccak hashing (R-a). Computes the root from `leaf` + `proof`
    ///      and returns whether it equals `root`. Sorting each pair
    ///      before hashing makes the proof order-independent and means
    ///      the tree needs no left/right index bits. An empty proof
    ///      verifies iff `leaf == root` (a single-leaf tree); the
    ///      contract's MIN_GUARDIANS = 3 floor means real proofs are
    ///      never empty, and the `root != 0` guard at set time prevents
    ///      a degenerate `leaf == root == 0` acceptance.
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
    ///      Copied VERBATIM from `RevisionLogV1.sol::_recover`
    ///      (docs/issue-plans/102-recovery-v1-contract.md L4 — same
    ///      Path B ecrecover malleability discipline).
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

    // No receive() / fallback() — same as v0/v1/EntitlementRegistry.
    // Non-payable means ETH sends revert at the dispatcher's CALLVALUE
    // guard. No selfdestruct / delegatecall / external call anywhere.
}
