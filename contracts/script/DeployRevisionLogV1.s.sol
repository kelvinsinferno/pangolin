// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity 0.8.24;

import {Script} from "forge-std/Script.sol";
import {RevisionLogV1} from "../src/RevisionLogV1.sol";

/// @title DeployRevisionLogV1
/// @notice Foundry deployment script for `RevisionLogV1`.
///
/// @dev Used by MVP-2 issue 2.3 to deploy to Base Sepolia (and, after
///      D-011 external audit, to mainnet). Per docs/issue-plans/2.1.md
///      L12, issue 2.1 only requires this script to compile + dry-run
///      cleanly under `forge script`; actual broadcasts are out of
///      scope for 2.1.
///
/// @dev Usage example (issue 2.3 will document this fully):
///
///        forge script contracts/script/DeployRevisionLogV1.s.sol \
///            --rpc-url $BASE_SEPOLIA_RPC_URL \
///            --private-key $DEPLOY_KEY \
///            --broadcast --verify
contract DeployRevisionLogV1 is Script {
    function run() external returns (RevisionLogV1 deployed) {
        vm.startBroadcast();
        deployed = new RevisionLogV1();
        vm.stopBroadcast();
    }
}
