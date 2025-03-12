// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Script} from "forge-std/Script.sol";

import {MainContract} from "../contracts/MainContract.sol";

contract DeployMainContractScript is Script {
    function run() external returns (MainContract) {
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        
        address flareVtpm = 0x135d393dB118383626B98f6e169E5bBAb3F41cB5;
        address wcflr = 0xC67DCE33D7A8efA5FfEB961899C73fe01bCe9273;

        vm.startBroadcast(deployerKey);
        MainContract mainContract = new MainContract(flareVtpm, wcflr);

        vm.stopBroadcast();

        return (mainContract);
    }
}


