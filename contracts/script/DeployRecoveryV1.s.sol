// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity 0.8.24;

import {Script} from "forge-std/Script.sol";
import {RecoveryV1} from "../src/RecoveryV1.sol";

/// @title DeployRecoveryV1
/// @notice Foundry deployment script for `RecoveryV1`.
///
/// @dev Per docs/issue-plans/102-recovery-v1-contract.md L14: issue #102
///      only requires this script to compile + dry-run cleanly under
///      `forge script`; actual broadcasts (testnet) are a follow-on, and
///      MAINNET is gated on an external audit (D-011) + explicit Kelvin
///      authorization.
///
/// @dev No constructor arguments — `RecoveryV1` has no configurable
///      surface (L2). Guardian identity is per-vault and lives in each
///      vault's merkle commitment, established post-deploy via
///      `setGuardianSet`; there are no deploy-time signer authorities
///      (unlike EntitlementRegistry).
///
/// @dev Usage example (the testnet-deploy follow-on will document fully):
///
///        forge script contracts/script/DeployRecoveryV1.s.sol \
///            --rpc-url $BASE_SEPOLIA_RPC_URL \
///            --private-key $DEPLOY_KEY \
///            --broadcast --verify
contract DeployRecoveryV1 is Script {
    function run() external returns (RecoveryV1 deployed) {
        vm.startBroadcast();
        deployed = new RecoveryV1();
        vm.stopBroadcast();
    }
}
