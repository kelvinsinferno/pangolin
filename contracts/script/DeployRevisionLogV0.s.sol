// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.24;

import {Script} from "forge-std/Script.sol";
import {RevisionLogV0} from "../src/RevisionLogV0.sol";

/// @title DeployRevisionLogV0
/// @notice Foundry deployment script for `RevisionLogV0`.
///
/// @dev Used by issue P5-4 to deploy to Base Sepolia (and, in the
///      future, to mainnet). P5-1 only requires this script to
///      compile cleanly; actual deploys are out of scope.
///
/// @dev Usage example (P5-4 will document this fully):
///
///        forge script contracts/script/DeployRevisionLogV0.s.sol \
///            --rpc-url $BASE_SEPOLIA_RPC_URL \
///            --private-key $DEPLOY_KEY \
///            --broadcast --verify
contract DeployRevisionLogV0 is Script {
    function run() external returns (RevisionLogV0 deployed) {
        vm.startBroadcast();
        deployed = new RevisionLogV0();
        vm.stopBroadcast();
    }
}
