// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity 0.8.24;

import {Script} from "forge-std/Script.sol";
import {RecoveryV2} from "../src/RecoveryV2.sol";

/// @title DeployRecoveryV2
/// @notice Foundry deployment script for `RecoveryV2` (MVP-4-L L-0a-1 —
///         the first recovery deploy that ships to Base Sepolia, per the
///         locked share-transport design Decision D + L-0 build plan §3).
///
/// @dev RecoveryV1 is hard-immutable and was anvil-only — V2 is NOT an
///      upgrade; it is a fresh deploy at a NEW address. No mainnet state
///      to migrate (recovery is testnet-only until D-011).
///
/// @dev No constructor arguments — `RecoveryV2` has no configurable
///      surface (the cardinal-design no-admin rule); guardian identity is
///      per-vault and lives in each vault's merkle commitment, established
///      post-deploy via `setGuardianSet`.
///
/// @dev Usage:
///
///        forge script contracts/script/DeployRecoveryV2.s.sol \
///            --rpc-url $BASE_SEPOLIA_RPC_URL \
///            --private-key $DEPLOY_KEY \
///            --broadcast --verify
contract DeployRecoveryV2 is Script {
    function run() external returns (RecoveryV2 deployed) {
        vm.startBroadcast();
        deployed = new RecoveryV2();
        vm.stopBroadcast();
    }
}
