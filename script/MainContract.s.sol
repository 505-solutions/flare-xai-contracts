// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Script} from "forge-std/Script.sol";

import {MainContract} from "../contracts/MainContract.sol";

contract DeployMainContractScript is Script {
    function run() external returns (MainContract) {
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");

        address flareVtpm = vm.envAddress("VTPM_CONTRACT_ADDRESS");
        address wcflr = 0xC67DCE33D7A8efA5FfEB961899C73fe01bCe9273;
        string memory imageDigest = vm.envString("IMAGE_DIGEST");

        vm.startBroadcast(deployerKey);
        MainContract mainContract = new MainContract(flareVtpm, wcflr, imageDigest);

        vm.stopBroadcast();

        return (mainContract);
    }
}
