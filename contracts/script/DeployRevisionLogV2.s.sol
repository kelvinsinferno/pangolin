// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity 0.8.24;

import {Script} from "forge-std/Script.sol";
import {RevisionLogV2} from "../src/RevisionLogV2.sol";
import {RecoveryV1} from "../src/RecoveryV1.sol";

/// @title DeployRevisionLogV2
/// @notice Foundry deployment script for `RevisionLogV2`.
///
/// @dev Per docs/issue-plans/106a-revisionlogv2-contract.md L18: issue
///      #106a only requires this script to compile + dry-run cleanly under
///      `forge script`; the actual testnet broadcast is a follow-on, and
///      MAINNET is gated on the external audit (D-011) + explicit Kelvin
///      authorization.
///
/// @dev `RevisionLogV2` takes ONE constructor argument — the deployed
///      RecoveryV1 address it cross-reads `vaultAuthority` from (Q-h /
///      L15). This is NOT an owner/admin: it cannot mutate V2; it is the
///      pinned read target for the genesis manager seed + the live
///      manager-auth reconcile.
///
///      The address is read from the `RECOVERY_V1_ADDRESS` env var. When
///      that var is UNSET (the CI build dry-run + the anvil-ci.sh harness
///      before RecoveryV1's address is known to this process), the script
///      deploys a fresh RecoveryV1 in the SAME broadcast and wires V2 to
///      it — so the dry-run exercises the real two-contract construction
///      path. A real testnet deploy passes the already-deployed RecoveryV1
///      address via the env var (so V2 binds the canonical RecoveryV1).
///
/// @dev Usage examples:
///
///        # Bind to an already-deployed RecoveryV1 (testnet path):
///        RECOVERY_V1_ADDRESS=0x... \
///        forge script contracts/script/DeployRevisionLogV2.s.sol \
///            --rpc-url $BASE_SEPOLIA_RPC_URL \
///            --private-key $DEPLOY_KEY \
///            --broadcast --verify
///
///        # Dry-run / fresh-pair (CI build dry-run, no env var):
///        forge script contracts/script/DeployRevisionLogV2.s.sol \
///            --sig "run()" --tc DeployRevisionLogV2
contract DeployRevisionLogV2 is Script {
    function run() external returns (RevisionLogV2 deployed) {
        address recoveryV1 = vm.envOr("RECOVERY_V1_ADDRESS", address(0));
        vm.startBroadcast();
        if (recoveryV1 == address(0)) {
            // No pinned RecoveryV1 supplied: deploy a fresh one so the
            // two-contract construction path is exercised end-to-end.
            recoveryV1 = address(new RecoveryV1());
        }
        deployed = new RevisionLogV2(recoveryV1);
        vm.stopBroadcast();
    }
}
