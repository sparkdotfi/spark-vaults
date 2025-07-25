// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.21;

import { UsdcVaultInstance } from "../deploy/UsdcVaultInstance.sol";
import { UsdcVaultL2Deploy } from "../deploy/UsdcVaultL2Deploy.sol";

import { console, Script } from "forge-std/Script.sol";

contract DeployUsdcVaultL2 is Script {

    function run() external {
        // Read the config file
        string memory config = vm.readFile("./script/config.json");

        // Parse the JSON file vars
        address deployer = vm.parseJsonAddress(config, ".deployer");
        address owner    = vm.parseJsonAddress(config, ".owner");
        address psm      = vm.parseJsonAddress(config, ".psm");

        console.log("Deploying USDC Vault L2 contract with the following parameters:");
        console.log("Deployer:", deployer);
        console.log("Owner:", owner);
        console.log("PSM:", psm);

        vm.startBroadcast();

        UsdcVaultInstance memory instance = UsdcVaultL2Deploy.deploy(
            deployer,
            owner,
            psm
        );

        vm.stopBroadcast();

        console.log("USDC Vault Proxy:", instance.usdcVault);
        console.log("USDC Vault Implementation:", instance.usdcVaultImp);
    }

}
