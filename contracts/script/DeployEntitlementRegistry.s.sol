// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity 0.8.24;

import {Script} from "forge-std/Script.sol";
import {EntitlementRegistry} from "../src/EntitlementRegistry.sol";

/// @title DeployEntitlementRegistry
/// @notice Foundry deployment script for `EntitlementRegistry`.
///
/// @dev Per docs/issue-plans/2.2.md L11: issue 2.2 only requires this
///      script to compile + dry-run cleanly under `forge script`;
///      actual broadcasts happen in MVP-2 issue 2.3 (which ships v1 +
///      the registry together to Base Sepolia testnet).
///
/// @dev Reads two authority addresses from env. In CI dry-run mode
///      the workflow passes dummy values
///      (`PAYMENT_AUTHORITY = 0x...01`, `REDEMPTION_AUTHORITY = 0x...02`).
///      For the real deploy (issue 2.3) the env vars hold the actual
///      payment-processor + funder service signer addresses.
///
/// @dev Usage example (issue 2.3 will document this fully):
///
///        PAYMENT_AUTHORITY=0x... REDEMPTION_AUTHORITY=0x... \
///        forge script contracts/script/DeployEntitlementRegistry.s.sol \
///            --rpc-url $BASE_SEPOLIA_RPC_URL \
///            --private-key $DEPLOY_KEY \
///            --broadcast --verify
contract DeployEntitlementRegistry is Script {
    function run() external returns (EntitlementRegistry deployed) {
        address paymentAuthority = vm.envAddress("PAYMENT_AUTHORITY");
        address redemptionAuthority = vm.envAddress("REDEMPTION_AUTHORITY");
        vm.startBroadcast();
        deployed = new EntitlementRegistry(paymentAuthority, redemptionAuthority);
        vm.stopBroadcast();
    }
}
